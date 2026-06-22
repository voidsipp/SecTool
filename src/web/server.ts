/**
 * Local web dashboard (zero-dependency Node http server).
 *
 * Serves the SPA and a small JSON API:
 *   GET  /                          -> dashboard HTML
 *   GET  /api/status                -> service/watcher/ssh status
 *   GET  /api/alerts?hours=48       -> alerts pulled from the UDM (+ stored summaries)
 *   GET  /api/alerts/:id            -> single alert detail
 *   POST /api/alerts/:id/summarize  -> generate + store a Claude summary
 *   POST /api/alerts/:id/capture    -> live tcpdump for the alert's hosts
 *   POST /api/alerts/:id/connections-> active conntrack sessions
 *   POST /api/alerts/:id/surrounding-> all events/flows around the event
 *
 * Bound to 127.0.0.1 by default — it can run privileged investigation commands
 * on the gateway, so do not expose it on the LAN without adding authentication.
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import type { Config } from "../config.ts";
import type { SecurityAlert } from "../types.ts";
import { log } from "../logger.ts";
import { loadSshTarget, pullMapped } from "../ingest/sshPull.ts";
import { Summarizer } from "../summarize/claude.ts";
import { correlate } from "../enrich/correlate.ts";
import { LogBuffer } from "../ingest/logBuffer.ts";
import { isIP } from "node:net";
import { alertStore } from "../store/alertStore.ts";
import { capture, connections, surrounding, relatedActivity } from "../investigate/udm.ts";
import { enrichIp } from "../investigate/enrich.ts";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const INDEX_HTML = join(HERE, "public", "index.html");

export interface WebServer {
  close: () => Promise<void>;
}

function send(res: ServerResponse, status: number, body: unknown, type = "application/json"): void {
  const payload = type === "application/json" ? JSON.stringify(body) : String(body);
  res.writeHead(status, { "content-type": type, "cache-control": "no-store" });
  res.end(payload);
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    let buf = "";
    req.on("data", (c) => {
      buf += c;
      if (buf.length > 1_000_000) req.destroy();
    });
    req.on("end", () => {
      try {
        resolve(buf ? (JSON.parse(buf) as Record<string, unknown>) : {});
      } catch {
        resolve({});
      }
    });
    req.on("error", () => resolve({}));
  });
}

export async function startWebServer(cfg: Config): Promise<WebServer> {
  const summarizer = new Summarizer(cfg);
  // In-memory cache of the most recently pulled alerts, keyed by id, so the
  // investigation endpoints can resolve a request id back to its hosts/time
  // (rather than trusting client-supplied IPs).
  const cache = new Map<string, SecurityAlert>();

  const refreshAlerts = async (hours: number) => {
    const mapped = await pullMapped(cfg, hours, Date.now());
    cache.clear();
    for (const m of mapped) cache.set(m.alert.id, m.alert);
    return mapped;
  };

  const handler = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;
    const method = req.method ?? "GET";

    try {
      // --- static ---
      if (method === "GET" && (path === "/" || path === "/index.html")) {
        if (existsSync(INDEX_HTML)) return send(res, 200, readFileSync(INDEX_HTML, "utf8"), "text/html; charset=utf-8");
        return send(res, 500, "index.html missing", "text/plain");
      }

      // --- status ---
      if (method === "GET" && path === "/api/status") {
        return send(res, 200, {
          sshConfigured: !!loadSshTarget(),
          watchEnabled: cfg.watch.enabled,
          model: cfg.claude.model,
          dryRun: cfg.runtime.dryRun,
          stored: alertStore.all().length,
        });
      }

      // --- alert list ---
      if (method === "GET" && path === "/api/alerts") {
        if (!loadSshTarget()) return send(res, 409, { error: "No SSH connection configured. Run --setup-ssh." });
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const mapped = await refreshAlerts(hours);
        const list = mapped
          .map((m) => {
            const a = m.alert;
            const stored = alertStore.get(a.id);
            return {
              id: a.id,
              time: a.event.timestamp ?? a.event.receivedAt,
              severity: a.severity,
              category: a.category,
              signature: a.signature,
              srcIp: a.srcIp,
              dstIp: a.dstIp,
              action: a.action,
              classification: a.classification,
              raw: a.event.raw,
              hasSummary: !!stored?.summary,
              notifiedAt: stored?.notifiedAt,
            };
          })
          .sort((x, y) => y.time - x.time);
        return send(res, 200, { hours, count: list.length, alerts: list });
      }

      // --- per-alert routes: /api/alerts/:id[/action] ---
      const m = path.match(/^\/api\/alerts\/([a-f0-9]{6,32})(?:\/(\w+))?$/);
      if (m) {
        const id = m[1]!;
        const action = m[2];
        const alert = cache.get(id);

        if (method === "GET" && !action) {
          const stored = alertStore.get(id);
          if (!alert && !stored) return send(res, 404, { error: "Unknown alert id (refresh the list)." });
          return send(res, 200, { alert: alert ? publicAlert(alert) : stored, summary: alertStore.getSummary(id) });
        }

        if (!alert) return send(res, 404, { error: "Alert not in cache — refresh the alert list first." });

        if (method === "POST" && action === "summarize") {
          const buffer = new LogBuffer(cache.size + 1, 0);
          for (const a of cache.values()) buffer.push(a.event);
          const ctx = correlate(alert, buffer, cfg);
          const summary = await summarizer.summarize(ctx);
          alertStore.record(alert, summary, false);
          return send(res, 200, { summary });
        }

        if (method === "POST" && action === "capture") {
          const body = await readJson(req);
          const seconds = Number(body["seconds"]) || 8;
          const ips = [alert.srcIp, alert.dstIp].filter((x): x is string => !!x);
          const result = await capture(ips, seconds);
          return send(res, 200, result);
        }

        if (method === "POST" && action === "connections") {
          const ip = alert.srcIp ?? alert.dstIp;
          if (!ip) return send(res, 400, { error: "Alert has no IP to inspect." });
          return send(res, 200, await connections(ip));
        }

        if (method === "POST" && action === "surrounding") {
          const body = await readJson(req);
          const windowMin = Number(body["windowMin"]) || 15;
          const t = alert.event.timestamp ?? alert.event.receivedAt;
          const ips = [alert.srcIp, alert.dstIp].filter((x): x is string => !!x);
          return send(res, 200, await surrounding(t, ips, windowMin));
        }

        if (method === "POST" && action === "enrich") {
          const ip = externalIp(alert);
          if (!ip) return send(res, 400, { error: "No external IP on this alert to enrich." });
          return send(res, 200, await enrichIp(cfg, ip));
        }

        if (method === "POST" && action === "related") {
          const body = await readJson(req);
          const hours = body["hours"] === 0 || body["hours"] === "0" ? 0 : Number(body["hours"]) || 24;
          const ip = externalIp(alert);
          if (!ip) return send(res, 400, { error: "No external IP on this alert." });
          const t = alert.event.timestamp ?? alert.event.receivedAt;
          return send(res, 200, await relatedActivity(ip, t, hours));
        }
      }

      send(res, 404, { error: "Not found" });
    } catch (err) {
      log.warn(`Web request error (${path}): ${(err as Error).message}`);
      send(res, 500, { error: (err as Error).message });
    }
  };

  const server = createServer((req, res) => void handler(req, res));
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(cfg.web.port, cfg.web.host, () => {
      server.removeListener("error", reject);
      log.info(`Web dashboard: http://${cfg.web.host}:${cfg.web.port}`);
      resolve();
    });
  });

  return { close: () => new Promise((r) => server.close(() => r())) };
}

function isPrivate(ip: string): boolean {
  return (
    /^10\./.test(ip) || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^127\./.test(ip) || /^169\.254\./.test(ip) || /^(::1|fe80|fc|fd)/i.test(ip)
  );
}

/** The externally-routable IP of an alert (the "detected" host), preferring src. */
function externalIp(a: SecurityAlert): string | undefined {
  for (const ip of [a.srcIp, a.dstIp]) {
    if (ip && isIP(ip) > 0 && !isPrivate(ip)) return ip;
  }
  return [a.srcIp, a.dstIp].find((ip) => ip && isIP(ip) > 0);
}

function publicAlert(a: SecurityAlert) {
  return {
    id: a.id,
    time: a.event.timestamp ?? a.event.receivedAt,
    severity: a.severity,
    category: a.category,
    signature: a.signature,
    srcIp: a.srcIp,
    dstIp: a.dstIp,
    action: a.action,
    classification: a.classification,
    raw: a.event.raw,
  };
}
