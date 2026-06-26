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
 *   GET  /api/trends?hours=N        -> aggregate stats from the stored alert history
 *   GET  /api/discovery[?subnet=]   -> active LAN sweep: all devices on the local network
 *   POST /api/discovery/deploy      -> push the endpoint agent onto a discovered host (SSH)
 *   POST /api/discovery/deploy-all  -> push the agent to every SSH-eligible discovered host
 *   GET  /api/agents/traffic?host=  -> a device's flow footprint (peers/ports/alerts)
 *   GET  /api/agents/listeners?host=-> a device's listening sockets + owning process
 *   GET  /api/agents/egress?host=   -> a device's public peers + threat-intel reputation
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
import { dismissStore } from "../store/dismissed.ts";
import { triageStore, isTriageStatus, TRIAGE_STATUSES, type TriageStatus } from "../store/triage.ts";
import { capture, connections, surrounding, relatedActivity } from "../investigate/udm.ts";
import { enrichIp } from "../investigate/enrich.ts";
import { computeHostRisks } from "../investigate/hosts.ts";
import { recentAnomalies } from "../anomaly/baseline.ts";
import { safeStore } from "../store/safelist.ts";
import { watchStore, canonicalizeTarget } from "../store/watchlist.ts";
import { suppressionStore, describeMatch, type SuppressionInput } from "../store/suppressions.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";
import { getActiveFlowStore } from "../netflow/flowAccess.ts";
import { askAnalyst } from "../analyst/analyst.ts";
import { buildGeoMap, buildCountryFlows } from "../investigate/geomap.ts";
import { agentLookup, agentHealth, agentConnections } from "../agent/agentClient.ts";
import { trafficProfile, listenerAudit, egressAudit } from "../investigate/device.ts";
import { discoverDevices } from "../investigate/discovery.ts";
import { deployAgent, deployToAllEligible, assessDeploy } from "../investigate/agentPush.ts";
import { blockIp, unblockIp, listBlocksWithStats } from "../respond/blocker.ts";
import { buildTrends } from "../analytics/trends.ts";

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
          dismissed: dismissStore.count(),
          watched: watchStore.count(),
          triage: triageStore.counts(),
          suppressions: suppressionStore.count(),
        });
      }

      // --- restore all dismissed ---
      if (method === "POST" && path === "/api/dismissed/clear") {
        const n = dismissStore.clear();
        return send(res, 200, { cleared: n });
      }

      // --- war map: traffic + threats by country ---
      if (method === "GET" && path === "/api/geomap") {
        const hours = Number(url.searchParams.get("hours")) || 24;
        return send(res, 200, await buildGeoMap(cfg, hours, Date.now()));
      }
      if (method === "GET" && path === "/api/geomap/country") {
        const code = (url.searchParams.get("code") ?? "").replace(/[^A-Za-z]/g, "").slice(0, 3).toUpperCase();
        const hours = Number(url.searchParams.get("hours")) || 24;
        if (!code) return send(res, 400, { error: "Missing country code." });
        return send(res, 200, await buildCountryFlows(code, hours, Date.now()));
      }

      // --- endpoint agent: attribute a connection to a process ---
      if (method === "GET" && path === "/api/agent/lookup") {
        const host = url.searchParams.get("host") ?? "";
        const r = await agentLookup(cfg, host, {
          remoteIp: url.searchParams.get("remoteIp") ?? undefined,
          remotePort: Number(url.searchParams.get("remotePort")) || undefined,
          localPort: Number(url.searchParams.get("localPort")) || undefined,
          proto: url.searchParams.get("proto") ?? undefined,
        });
        return send(res, r.ok ? 200 : 502, r);
      }
      if (method === "GET" && path === "/api/agent/health") {
        return send(res, 200, await agentHealth(cfg, url.searchParams.get("host") ?? ""));
      }

      // --- active LAN sweep: discover every device on the local network ---
      if (method === "GET" && path === "/api/discovery") {
        const subnetParam = (url.searchParams.get("subnet") ?? "").trim();
        const subnets = subnetParam
          ? subnetParam.split(",").map((s) => s.trim()).filter(Boolean)
          : undefined;
        const r = await discoverDevices(cfg, subnets ? { subnets } : {});
        // Annotate each device with whether the agent can be auto-pushed to it.
        if (r.ok) {
          for (const d of r.devices) d.deploy = assessDeploy(cfg, d);
        }
        const deployable = r.ok ? r.devices.filter((d) => d.deploy?.eligible).length : 0;
        return send(res, r.ok ? 200 : 502, { ...r, deployEnabled: cfg.deploy.enabled, deployable });
      }

      // --- push the endpoint agent onto a discovered host (over SSH) ---
      if (method === "POST" && path === "/api/discovery/deploy") {
        const body = await readJson(req);
        const host = String(body["host"] ?? "").trim();
        if (isIP(host) === 0) return send(res, 400, { error: "Invalid or missing host IP." });
        const r = await deployAgent(cfg, host, {
          user: typeof body["user"] === "string" && body["user"] ? String(body["user"]) : undefined,
          port: Number(body["port"]) || undefined,
          password: typeof body["password"] === "string" && body["password"] ? String(body["password"]) : undefined,
          force: body["force"] === true,
        });
        return send(res, r.ok ? 200 : 502, r);
      }

      // --- push the agent to every eligible discovered host at once ---
      if (method === "POST" && path === "/api/discovery/deploy-all") {
        const body = await readJson(req);
        const subnetRaw = String(body["subnet"] ?? "").trim();
        const r = await deployToAllEligible(cfg, {
          subnets: subnetRaw ? subnetRaw.split(",").map((s) => s.trim()).filter(Boolean) : undefined,
          user: typeof body["user"] === "string" && body["user"] ? String(body["user"]) : undefined,
          port: Number(body["port"]) || undefined,
          password: typeof body["password"] === "string" && body["password"] ? String(body["password"]) : undefined,
        });
        return send(res, r.ok ? 200 : 502, r);
      }

      // --- discover agents: probe internal hosts (seen in flows) for a live agent ---
      if (method === "GET" && path === "/api/agents") {
        if (!cfg.agent.enabled) return send(res, 200, { enabled: false, port: cfg.agent.port, agents: [] });
        const isPrivate = (ip: string) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);
        const candidates = new Set<string>();
        if (cfg.netflow.advertiseIp && isPrivate(cfg.netflow.advertiseIp)) candidates.add(cfg.netflow.advertiseIp);
        const flowStore = getActiveFlowStore();
        if (flowStore) {
          for (const f of flowStore.query([], Date.now() - 24 * 3600_000, Date.now(), 200_000)) {
            if (f.srcIp && isPrivate(f.srcIp)) candidates.add(f.srcIp);
            if (f.dstIp && isPrivate(f.dstIp)) candidates.add(f.dstIp);
          }
        }
        // also include any host an operator has explicitly probed before
        const extra = (url.searchParams.get("hosts") ?? "").split(",").map((s) => s.trim()).filter((s) => isIP(s) > 0 && isPrivate(s));
        for (const h of extra) candidates.add(h);
        const list = [...candidates].slice(0, 64);
        const probed = await Promise.all(
          list.map(async (ip) => {
            const r = await agentHealth(cfg, ip, 1500);
            if (!r.ok || !r.data) return null;
            const d = r.data as Record<string, unknown>;
            return { ip, online: true, version: d["version"], hostname: d["host"], platform: d["platform"], tracked: d["tracked"], auth: d["auth"], retentionMin: d["retentionMin"] };
          }),
        );
        const agents = probed.filter((a): a is NonNullable<typeof a> => a !== null);
        return send(res, 200, { enabled: true, port: cfg.agent.port, scanned: list.length, agents });
      }

      // --- a single agent's live connections -> processes ---
      if (method === "GET" && path === "/api/agents/connections") {
        const host = url.searchParams.get("host") ?? "";
        const r = await agentConnections(cfg, host);
        return send(res, r.ok ? 200 : 502, r);
      }

      // --- device investigation: traffic footprint from collected flows (no agent needed) ---
      if (method === "GET" && path === "/api/agents/traffic") {
        const host = url.searchParams.get("host") ?? "";
        const hours = Number(url.searchParams.get("hours")) || 24;
        const r = trafficProfile(host, hours);
        return send(res, r.ok ? 200 : 502, r);
      }

      // --- device investigation: listening sockets / open-port attack surface ---
      if (method === "GET" && path === "/api/agents/listeners") {
        const host = url.searchParams.get("host") ?? "";
        const r = await listenerAudit(cfg, host);
        return send(res, r.ok ? 200 : 502, r);
      }

      // --- device investigation: egress to public IPs + threat-intel reputation ---
      if (method === "GET" && path === "/api/agents/egress") {
        const host = url.searchParams.get("host") ?? "";
        const r = await egressAudit(cfg, host);
        return send(res, r.ok ? 200 : 502, r);
      }

      // --- conversational analyst ---
      if (method === "POST" && path === "/api/ask") {
        const body = await readJson(req);
        const question = String(body["question"] ?? "").slice(0, 1000);
        if (!question.trim()) return send(res, 400, { error: "Empty question." });
        const result = await askAnalyst(cfg, question);
        return send(res, 200, result);
      }

      // --- internal host risk + behavioral anomalies ---
      if (method === "GET" && path === "/api/hosts") {
        const hosts = computeHostRisks();
        return send(res, 200, { count: hosts.length, hosts, anomalies: recentAnomalies().slice(0, 50), safeCount: safeStore.count() });
      }

      // --- mark a peer IP safe / un-safe ---
      if (method === "POST" && (path === "/api/safe" || path === "/api/unsafe")) {
        const body = await readJson(req);
        const ip = String(body["ip"] ?? "");
        if (isIP(ip) === 0) return send(res, 400, { error: "Invalid IP." });
        if (path === "/api/safe") safeStore.add(ip, typeof body["note"] === "string" ? body["note"] : undefined);
        else safeStore.remove(ip);
        return send(res, 200, { ok: true, safe: path === "/api/safe" });
      }

      // --- watchlist (operator-curated IPs/CIDRs to monitor) ---
      if (method === "GET" && path === "/api/watchlist") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const entries = watchStore.all();
        const since = Date.now() - hours * 3_600_000;
        const flowStore = getActiveFlowStore();
        const allFlows = flowStore ? flowStore.query([], since, Date.now(), 200_000) : [];
        const allAlerts = alertStore.all();

        const items = entries.map((e) => {
          let flowHits = 0;
          let bytesIn = 0;
          let bytesOut = 0;
          let lastSeen: number | null = null;
          const peers = new Set<string>();
          for (const f of allFlows) {
            const src = f.srcIp;
            const dst = f.dstIp;
            const matchSrc = src ? watchStore.match(src)?.target === e.target : false;
            const matchDst = dst ? watchStore.match(dst)?.target === e.target : false;
            if (!matchSrc && !matchDst) continue;
            flowHits++;
            const fe = f.end ?? f.receivedAt;
            if (lastSeen === null || fe > lastSeen) lastSeen = fe;
            if (matchSrc && !matchDst) {
              bytesOut += f.bytes ?? 0;
              if (dst) peers.add(dst);
            } else if (matchDst && !matchSrc) {
              bytesIn += f.bytes ?? 0;
              if (src) peers.add(src);
            } else {
              bytesIn += f.bytes ?? 0;
            }
          }
          let alertHits = 0;
          let lastAlertId: string | undefined;
          let lastAlertTime: number | undefined;
          for (const a of allAlerts) {
            if (a.time < since) continue;
            const matchSrc = a.srcIp ? watchStore.match(a.srcIp)?.target === e.target : false;
            const matchDst = a.dstIp ? watchStore.match(a.dstIp)?.target === e.target : false;
            if (!matchSrc && !matchDst) continue;
            alertHits++;
            if (lastAlertTime === undefined || a.time > lastAlertTime) {
              lastAlertTime = a.time;
              lastAlertId = a.id;
            }
          }
          return {
            ...e,
            flowHits,
            bytesIn,
            bytesOut,
            peers: peers.size,
            lastSeen,
            alertHits,
            lastAlertId,
            lastAlertTime,
          };
        });
        return send(res, 200, { hours, count: items.length, items });
      }
      if (method === "POST" && path === "/api/watch") {
        const body = await readJson(req);
        const raw = String(body["ip"] ?? body["target"] ?? "");
        const note = typeof body["note"] === "string" ? body["note"].slice(0, 200) : undefined;
        const c = canonicalizeTarget(raw);
        if (!c) return send(res, 400, { error: "Invalid IP or CIDR." });
        const entry = watchStore.add(raw, note);
        return send(res, 200, { ok: true, entry });
      }
      if (method === "POST" && path === "/api/unwatch") {
        const body = await readJson(req);
        const raw = String(body["ip"] ?? body["target"] ?? "");
        const removed = watchStore.remove(raw);
        return send(res, 200, { ok: true, removed });
      }

      // --- suppression rules (pattern-based mute of future alerts) ---
      if (method === "GET" && path === "/api/suppressions") {
        const rules = suppressionStore.all().map((r) => ({
          ...r,
          summary: describeMatch(r.match),
        }));
        return send(res, 200, { count: rules.length, rules });
      }
      if (method === "POST" && path === "/api/suppress") {
        const body = await readJson(req);
        const str = (k: string): string | undefined =>
          typeof body[k] === "string" ? (body[k] as string) : undefined;
        const num = (k: string): number | undefined =>
          typeof body[k] === "number" && Number.isFinite(body[k]) ? (body[k] as number) : undefined;
        const rawSev = body["maxSeverity"];
        const maxSeverity: Severity | undefined =
          typeof rawSev === "string" && (SEVERITY_ORDER as readonly string[]).includes(rawSev)
            ? (rawSev as Severity)
            : undefined;
        const input: SuppressionInput = {
          signature: str("signature"),
          category: str("category"),
          srcIp: str("srcIp"),
          dstIp: str("dstIp"),
          maxSeverity,
          reason: str("reason"),
          ttlMs: num("ttlMs"),
        };
        const rule = suppressionStore.add(input);
        if (!rule) {
          return send(res, 400, {
            error: "Provide at least one of: signature, category, srcIp, dstIp, maxSeverity.",
          });
        }
        return send(res, 200, { ok: true, rule: { ...rule, summary: describeMatch(rule.match) } });
      }
      if (method === "POST" && path === "/api/unsuppress") {
        const body = await readJson(req);
        const id = String(body["id"] ?? "");
        const removed = suppressionStore.remove(id);
        return send(res, 200, { ok: true, removed });
      }

      // --- alert trends (historical stats from the local alert store) ---
      if (method === "GET" && path === "/api/trends") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const limitRaw = Number(url.searchParams.get("limit"));
        const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(50, Math.floor(limitRaw)) : 10;
        return send(res, 200, buildTrends(hours, limit, Date.now()));
      }

      // --- firewall blocklist ---
      if (method === "GET" && path === "/api/blocklist") {
        const blocks = await listBlocksWithStats();
        return send(res, 200, { count: blocks.length, blocks });
      }
      if (method === "POST" && path === "/api/block") {
        const body = await readJson(req);
        const ip = String(body["ip"] ?? "");
        try {
          const entry = await blockIp(cfg, ip, typeof body["reason"] === "string" ? body["reason"] : undefined);
          return send(res, 200, { ok: true, entry });
        } catch (err) {
          return send(res, 400, { error: (err as Error).message });
        }
      }
      if (method === "POST" && path === "/api/unblock") {
        const body = await readJson(req);
        const ip = String(body["ip"] ?? "");
        await unblockIp(ip);
        return send(res, 200, { ok: true });
      }

      // --- alert list ---
      if (method === "GET" && path === "/api/alerts") {
        if (!loadSshTarget()) return send(res, 409, { error: "No SSH connection configured. Run --setup-ssh." });
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const includeDismissed = url.searchParams.get("includeDismissed") === "1";
        const statusFilterRaw = url.searchParams.get("status") ?? "";
        const statusFilter = isTriageStatus(statusFilterRaw) ? statusFilterRaw : null;
        const mapped = await refreshAlerts(hours);
        const list = mapped
          .map((m) => {
            const a = m.alert;
            const stored = alertStore.get(a.id);
            const triage = triageStore.get(a.id);
            const supp = suppressionStore.matchAlert(a);
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
              dismissed: dismissStore.has(a.id),
              watched: !!(watchStore.match(a.srcIp) || watchStore.match(a.dstIp)),
              triageStatus: triage?.status ?? "open",
              noteCount: triage?.notes.length ?? 0,
              suppressedBy: supp ? { id: supp.id, summary: describeMatch(supp.match) } : null,
            };
          })
          .filter((a) => includeDismissed || !a.dismissed)
          .filter((a) => !statusFilter || a.triageStatus === statusFilter)
          .sort((x, y) => y.time - x.time);
        return send(res, 200, {
          hours,
          count: list.length,
          dismissedCount: dismissStore.count(),
          triageCounts: triageStore.counts(),
          alerts: list,
        });
      }

      // --- per-alert routes: /api/alerts/:id[/action] ---
      const m = path.match(/^\/api\/alerts\/([a-f0-9]{6,32})(?:\/(\w+))?$/);
      if (m) {
        const id = m[1]!;
        const action = m[2];
        const alert = cache.get(id);

        // Dismiss/restore work by id alone (no cache entry required).
        if (method === "POST" && action === "dismiss") {
          const body = await readJson(req);
          dismissStore.dismiss(id, typeof body["reason"] === "string" ? body["reason"] : undefined);
          return send(res, 200, { dismissed: true });
        }
        if (method === "POST" && action === "restore") {
          dismissStore.restore(id);
          return send(res, 200, { dismissed: false });
        }

        if (method === "GET" && !action) {
          const stored = alertStore.get(id);
          if (!alert && !stored) return send(res, 404, { error: "Unknown alert id (refresh the list)." });
          return send(res, 200, {
            alert: alert ? publicAlert(alert) : stored,
            summary: alertStore.getSummary(id),
            triage: triageStore.view(id),
          });
        }

        // Triage works on any known alert id, with or without a cache entry.
        if (method === "POST" && action === "status") {
          const body = await readJson(req);
          const next = body["status"];
          if (!isTriageStatus(next)) {
            return send(res, 400, { error: `status must be one of: ${TRIAGE_STATUSES.join(", ")}` });
          }
          const entry = triageStore.setStatus(id, next as TriageStatus);
          return send(res, 200, { ok: true, triage: entry });
        }

        if (method === "POST" && action === "note") {
          const body = await readJson(req);
          const note = triageStore.addNote(id, String(body["text"] ?? ""));
          if (!note) return send(res, 400, { error: "Note text is empty." });
          return send(res, 200, { ok: true, note, triage: triageStore.view(id) });
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

        if (method === "POST" && action === "block") {
          const ip = externalIp(alert);
          if (!ip) return send(res, 400, { error: "No external IP on this alert to block." });
          try {
            const entry = await blockIp(cfg, ip, `alert ${alert.signature ?? alert.category}`);
            return send(res, 200, { ok: true, ip, entry });
          } catch (err) {
            return send(res, 400, { error: (err as Error).message });
          }
        }

        if (method === "POST" && action === "watch") {
          const ip = externalIp(alert);
          if (!ip) return send(res, 400, { error: "No external IP on this alert to watch." });
          const body = await readJson(req);
          const note = typeof body["note"] === "string"
            ? body["note"].slice(0, 200)
            : `alert ${alert.signature ?? alert.category ?? alert.id}`;
          const entry = watchStore.add(ip, note);
          return send(res, 200, { ok: true, ip, entry });
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
