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
 *   GET  /api/campaigns?hours=N     -> cluster stored alerts by external attacker IP
 *   GET  /api/report?hours=N        -> offline incident report (model + Markdown)
 *   GET  /api/report.md?hours=N     -> the same report as a downloadable .md file
 *   GET  /api/compare?hours=N       -> period-over-period comparison vs the previous window
 *   GET  /api/compare.md?hours=N    -> the same comparison as a downloadable .md file
 *   GET  /api/profile?ip=&hours=N   -> single-entity deep-dive for one IP (model + Markdown)
 *   GET  /api/profile.md?ip=&hours=N-> the same profile as a downloadable .md file
 *   GET  /api/assets?hours=N        -> internal-asset exposure scoreboard (model + Markdown)
 *   GET  /api/assets.md?hours=N     -> the same scoreboard as a downloadable .md file
 *   GET  /api/tuning?hours=N        -> signature tuning / noise-reduction recommendations
 *   GET  /api/tuning.md?hours=N     -> the same tuning report as a downloadable .md file
 *   GET  /api/watchlist-activity?hours=N    -> per-watchlist-entry activity report (model + Markdown)
 *   GET  /api/watchlist-activity.md?hours=N -> the same watchlist activity report as a downloadable .md file
 *   GET  /api/rhythm?hours=N&tz=M   -> temporal activity rhythm (hour/day heat-map; model + Markdown)
 *   GET  /api/rhythm.md?hours=N&tz=M -> the same rhythm report as a downloadable .md file
 *   GET  /api/backlog?hours=N       -> triage SLA backlog (open/overdue queue + throughput; model + Markdown)
 *   GET  /api/backlog.md?hours=N    -> the same backlog report as a downloadable .md file
 *   GET  /api/novelty?hours=N       -> first-seen / novelty report (new src/dst/signatures; model + Markdown)
 *   GET  /api/novelty.md?hours=N    -> the same novelty report as a downloadable .md file
 *   GET  /api/killchain?hours=N     -> kill-chain / attack-stage coverage + per-host progression (model + Markdown)
 *   GET  /api/killchain.md?hours=N  -> the same kill-chain report as a downloadable .md file
 *   GET  /api/beacon?hours=N        -> beaconing / periodicity (regular-cadence src→dst pairs, i.e. C2; model + Markdown)
 *   GET  /api/beacon.md?hours=N     -> the same beaconing report as a downloadable .md file
 *   GET  /api/efficacy?hours=N      -> IPS enforcement-gap / efficacy (block rate + detect-only gaps; model + Markdown)
 *   GET  /api/efficacy.md?hours=N   -> the same efficacy report as a downloadable .md file
 *   GET  /api/iocs?hours=N&format=  -> threat-indicator export (json|csv|plain|markdown) for blocklists/SIEM
 *   GET  /api/intel?hours=N         -> known-bad feed IPs seen touching the network
 *   GET  /api/intel/check?ip=       -> check a single IP against the loaded feeds
 *   GET  /api/search?q=&sev=&...    -> filtered search over the stored alert history (no SSH)
 *   GET  /api/search.csv?q=&...     -> same query, downloaded as CSV
 *   GET  /api/discovery[?subnet=]   -> active LAN sweep: all devices on the local network
 *   POST /api/discovery/deploy      -> push the endpoint agent onto a discovered host (SSH or WinRM)
 *   POST /api/discovery/deploy-all  -> push the agent to every eligible discovered host (SSH/WinRM)
 *   GET  /api/agents/traffic?host=  -> a device's flow footprint (peers/ports/alerts)
 *   GET  /api/agents/ports?host=    -> a device's live port activity (gateway conntrack)
 *   GET  /api/agents/listeners?host=-> a device's listening sockets + owning process
 *   GET  /api/agents/egress?host=   -> a device's public peers + threat-intel reputation
 *   POST /api/ask                   -> read-only conversational analyst (queries telemetry)
 *   POST /api/agent/act             -> action-capable automation agent (creates suppressions,
 *                                      manages safelist/watchlist/blocklist/triage); supports dryRun
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
import { runAgent } from "../analyst/agent.ts";
import { conversationStore } from "../store/conversation.ts";
import { buildGeoMap, buildCountryFlows } from "../investigate/geomap.ts";
import { agentLookup, agentHealth, agentConnections } from "../agent/agentClient.ts";
import { trafficProfile, listenerAudit, egressAudit } from "../investigate/device.ts";
import { livePortActivity } from "../investigate/liveports.ts";
import { discoverDevices } from "../investigate/discovery.ts";
import { deployAgent, deployToAllEligible, assessDeploy } from "../investigate/agentPush.ts";
import { blockIp, unblockIp, listBlocksWithStats } from "../respond/blocker.ts";
import { buildTrends } from "../analytics/trends.ts";
import { buildCampaigns, type Campaign } from "../analytics/campaigns.ts";
import { geolocate } from "../investigate/geo.ts";
import { buildReport, reportFilename } from "../analytics/report.ts";
import { buildComparison, comparisonFilename } from "../analytics/compare.ts";
import { buildProfile, profileFilename } from "../analytics/profile.ts";
import { buildAssets, assetsFilename } from "../analytics/assets.ts";
import { buildTuning, tuningFilename } from "../analytics/tuning.ts";
import { buildWatchlist, watchlistFilename } from "../analytics/watchlist.ts";
import { buildRhythm, rhythmFilename } from "../analytics/rhythm.ts";
import { buildBacklog, backlogFilename } from "../analytics/backlog.ts";
import { buildNovelty, noveltyFilename } from "../analytics/novelty.ts";
import { buildKillChain, killChainFilename } from "../analytics/killchain.ts";
import { buildBeacon, beaconFilename } from "../analytics/beacon.ts";
import { buildEfficacy, efficacyFilename } from "../analytics/efficacy.ts";
import {
  buildIocExport,
  renderIoc,
  iocFilename,
  parseIocFormat,
  parseSeverityFloor,
  type IocFormat,
} from "../analytics/iocExport.ts";
import { buildIntelReport, checkIntelIp } from "../analytics/intel.ts";
import { searchAlerts, hitsToCsv, MAX_EXPORT, type SearchQuery, type SortMode } from "../analytics/search.ts";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const INDEX_HTML = join(HERE, "public", "index.html");

export interface WebServer {
  close: () => Promise<void>;
}

/**
 * Validate a client-supplied chat session id. Keeps only opaque, bounded tokens
 * (the UUIDs the dashboard generates) so the conversation-memory map can't be
 * polluted with huge or hostile keys. Returns undefined for anything invalid,
 * which transparently disables memory for that request.
 */
function chatSessionId(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;
  const s = raw.trim();
  return s && s.length <= 128 && /^[A-Za-z0-9_-]+$/.test(s) ? s : undefined;
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

      // --- push the endpoint agent onto a discovered host (SSH, or WinRM if no SSH) ---
      if (method === "POST" && path === "/api/discovery/deploy") {
        const body = await readJson(req);
        const host = String(body["host"] ?? "").trim();
        if (isIP(host) === 0) return send(res, 400, { error: "Invalid or missing host IP." });
        const str = (k: string) => (typeof body[k] === "string" && body[k] ? String(body[k]) : undefined);
        const deployMethod = body["method"] === "winrm" ? "winrm" : body["method"] === "ssh" ? "ssh" : undefined;
        const r = await deployAgent(cfg, host, {
          method: deployMethod,
          user: str("user"),
          port: Number(body["port"]) || undefined,
          password: str("password"),
          winUser: str("winUser"),
          winPassword: str("winPassword"),
          winPort: Number(body["winPort"]) || undefined,
          force: body["force"] === true,
        });
        return send(res, r.ok ? 200 : 502, r);
      }

      // --- push the agent to every eligible discovered host at once ---
      if (method === "POST" && path === "/api/discovery/deploy-all") {
        const body = await readJson(req);
        const str = (k: string) => (typeof body[k] === "string" && body[k] ? String(body[k]) : undefined);
        const subnetRaw = String(body["subnet"] ?? "").trim();
        const r = await deployToAllEligible(cfg, {
          subnets: subnetRaw ? subnetRaw.split(",").map((s) => s.trim()).filter(Boolean) : undefined,
          user: str("user"),
          port: Number(body["port"]) || undefined,
          password: str("password"),
          winUser: str("winUser"),
          winPassword: str("winPassword"),
          winPort: Number(body["winPort"]) || undefined,
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

      // --- device investigation: real-time port activity from the gateway's
      //     conntrack table (agent-independent; works for any LAN host) ---
      if (method === "GET" && path === "/api/agents/ports") {
        const host = url.searchParams.get("host") ?? "";
        const r = await livePortActivity(host);
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
        const sessionId = chatSessionId(body["sessionId"]);
        const result = await askAnalyst(cfg, question, { sessionId });
        return send(res, 200, result);
      }

      // --- action-capable automation agent (creates suppressions, manages
      //     safelist/watchlist/blocklist/triage on a natural-language instruction) ---
      if (method === "POST" && path === "/api/agent/act") {
        const body = await readJson(req);
        const instruction = String(body["instruction"] ?? body["question"] ?? "").slice(0, 1000);
        if (!instruction.trim()) return send(res, 400, { error: "Empty instruction." });
        const dryRun = body["dryRun"] === true || body["dryRun"] === "1";
        const sessionId = chatSessionId(body["sessionId"]);
        const result = await runAgent(cfg, instruction, { dryRun, sessionId });
        return send(res, 200, result);
      }

      // --- forget a chat session's conversational memory ("new chat") ---
      if (method === "POST" && path === "/api/chat/reset") {
        const body = await readJson(req);
        const sessionId = chatSessionId(body["sessionId"]);
        const cleared = sessionId ? conversationStore.clear(sessionId) : false;
        return send(res, 200, { ok: true, cleared });
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

      // --- attack campaigns (cluster stored alerts by external attacker IP) ---
      if (method === "GET" && path === "/api/campaigns") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const limitRaw = Number(url.searchParams.get("limit"));
        const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(200, Math.floor(limitRaw)) : 50;
        const report = buildCampaigns(hours, limit, Date.now());
        // Optional geo enrichment: attach country/code to each attacker IP. Best
        // effort — failures (offline / rate-limited) just leave geo undefined.
        if (url.searchParams.get("geo") === "1" && report.campaigns.length) {
          try {
            const locs = await geolocate(report.campaigns.map((c) => c.ip));
            for (const c of report.campaigns as Array<Campaign & { country?: string; countryCode?: string }>) {
              const g = locs.get(c.ip);
              if (g) {
                c.country = g.country;
                c.countryCode = g.code;
              }
            }
          } catch {
            /* enrichment is optional */
          }
        }
        return send(res, 200, report);
      }

      // --- offline incident report (structured model + Markdown) ---
      if (method === "GET" && path === "/api/report") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        return send(res, 200, buildReport(hours, Date.now()));
      }
      // --- downloadable Markdown report ---
      if (method === "GET" && path === "/api/report.md") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const now = Date.now();
        const { markdown } = buildReport(hours, now);
        res.writeHead(200, {
          "content-type": "text/markdown; charset=utf-8",
          "cache-control": "no-store",
          "content-disposition": `attachment; filename="${reportFilename(now)}"`,
        });
        res.end(markdown);
        return;
      }

      // --- period-over-period comparison (this window vs the previous one) ---
      if (method === "GET" && path === "/api/compare") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        return send(res, 200, buildComparison(hours, 12, Date.now()));
      }
      // --- downloadable Markdown comparison ---
      if (method === "GET" && path === "/api/compare.md") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const now = Date.now();
        const { markdown } = buildComparison(hours, 12, now);
        res.writeHead(200, {
          "content-type": "text/markdown; charset=utf-8",
          "cache-control": "no-store",
          "content-disposition": `attachment; filename="${comparisonFilename(now)}"`,
        });
        res.end(markdown);
        return;
      }

      // --- single-entity (IP) profile: everything about one address, offline ---
      if (method === "GET" && (path === "/api/profile" || path === "/api/profile.md")) {
        const ip = (url.searchParams.get("ip") ?? "").trim();
        if (isIP(ip) === 0) return send(res, 400, { error: "Invalid or missing IP (use ?ip=...)." });
        const hours = Number(url.searchParams.get("hours")) || 0; // 0 = entire history
        const now = Date.now();
        const model = buildProfile(ip, hours, now);
        if (path === "/api/profile.md") {
          res.writeHead(200, {
            "content-type": "text/markdown; charset=utf-8",
            "cache-control": "no-store",
            "content-disposition": `attachment; filename="${profileFilename(ip, now)}"`,
          });
          res.end(model.markdown);
          return;
        }
        return send(res, 200, model);
      }

      // --- internal-asset exposure scoreboard (ranks YOUR hosts by risk) ---
      if (method === "GET" && path === "/api/assets") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const limit = Number(url.searchParams.get("limit")) || 50;
        return send(res, 200, buildAssets(hours, limit, Date.now()));
      }
      if (method === "GET" && path === "/api/assets.md") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const limit = Number(url.searchParams.get("limit")) || 50;
        const now = Date.now();
        const { markdown } = buildAssets(hours, limit, now);
        res.writeHead(200, {
          "content-type": "text/markdown; charset=utf-8",
          "cache-control": "no-store",
          "content-disposition": `attachment; filename="${assetsFilename(now)}"`,
        });
        res.end(markdown);
        return;
      }

      // --- signature tuning: which noisy signatures are safe to suppress ---
      if (method === "GET" && path === "/api/tuning") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const limit = Number(url.searchParams.get("limit")) || 40;
        return send(res, 200, buildTuning(hours, limit, Date.now()));
      }
      if (method === "GET" && path === "/api/tuning.md") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const limit = Number(url.searchParams.get("limit")) || 40;
        const now = Date.now();
        const { markdown } = buildTuning(hours, limit, now);
        res.writeHead(200, {
          "content-type": "text/markdown; charset=utf-8",
          "cache-control": "no-store",
          "content-disposition": `attachment; filename="${tuningFilename(now)}"`,
        });
        res.end(markdown);
        return;
      }

      // --- watchlist activity (how active each watched target has been) ---
      if (method === "GET" && path === "/api/watchlist-activity") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const limit = Number(url.searchParams.get("limit")) || 100;
        return send(res, 200, buildWatchlist(hours, limit, Date.now()));
      }
      if (method === "GET" && path === "/api/watchlist-activity.md") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const limit = Number(url.searchParams.get("limit")) || 100;
        const now = Date.now();
        const { markdown } = buildWatchlist(hours, limit, now);
        res.writeHead(200, {
          "content-type": "text/markdown; charset=utf-8",
          "cache-control": "no-store",
          "content-disposition": `attachment; filename="${watchlistFilename(now)}"`,
        });
        res.end(markdown);
        return;
      }

      // --- temporal activity rhythm (when does activity happen: hour × day) ---
      if (method === "GET" && path === "/api/rhythm") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const tz = Number(url.searchParams.get("tz")) || 0;
        return send(res, 200, buildRhythm(hours, tz, Date.now()));
      }
      if (method === "GET" && path === "/api/rhythm.md") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const tz = Number(url.searchParams.get("tz")) || 0;
        const now = Date.now();
        const { markdown } = buildRhythm(hours, tz, now);
        res.writeHead(200, {
          "content-type": "text/markdown; charset=utf-8",
          "cache-control": "no-store",
          "content-disposition": `attachment; filename="${rhythmFilename(now)}"`,
        });
        res.end(markdown);
        return;
      }

      // --- triage SLA backlog (what is still open / overdue, and throughput) ---
      if (method === "GET" && path === "/api/backlog") {
        const hours = Number(url.searchParams.get("hours")) || 720;
        const limit = Number(url.searchParams.get("limit")) || 25;
        return send(res, 200, buildBacklog(hours, { limit, nowMs: Date.now() }));
      }
      if (method === "GET" && path === "/api/backlog.md") {
        const hours = Number(url.searchParams.get("hours")) || 720;
        const limit = Number(url.searchParams.get("limit")) || 25;
        const now = Date.now();
        const { markdown } = buildBacklog(hours, { limit, nowMs: now });
        res.writeHead(200, {
          "content-type": "text/markdown; charset=utf-8",
          "cache-control": "no-store",
          "content-disposition": `attachment; filename="${backlogFilename(now)}"`,
        });
        res.end(markdown);
        return;
      }

      // --- first-seen / novelty (what is genuinely NEW vs all retained history) ---
      if (method === "GET" && path === "/api/novelty") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const limit = Number(url.searchParams.get("limit")) || 25;
        return send(res, 200, buildNovelty(hours, { limit, nowMs: Date.now() }));
      }
      if (method === "GET" && path === "/api/novelty.md") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const limit = Number(url.searchParams.get("limit")) || 25;
        const now = Date.now();
        const { markdown } = buildNovelty(hours, { limit, nowMs: now });
        res.writeHead(200, {
          "content-type": "text/markdown; charset=utf-8",
          "cache-control": "no-store",
          "content-disposition": `attachment; filename="${noveltyFilename(now)}"`,
        });
        res.end(markdown);
        return;
      }

      // --- kill-chain / attack-stage coverage + per-host progression ---
      if (method === "GET" && path === "/api/killchain") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const limit = Number(url.searchParams.get("limit")) || 25;
        return send(res, 200, buildKillChain(hours, { limit, nowMs: Date.now() }));
      }
      if (method === "GET" && path === "/api/killchain.md") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const limit = Number(url.searchParams.get("limit")) || 25;
        const now = Date.now();
        const { markdown } = buildKillChain(hours, { limit, nowMs: now });
        res.writeHead(200, {
          "content-type": "text/markdown; charset=utf-8",
          "cache-control": "no-store",
          "content-disposition": `attachment; filename="${killChainFilename(now)}"`,
        });
        res.end(markdown);
        return;
      }

      // --- beaconing / periodicity (regular-cadence src→dst pairs, i.e. C2) ---
      if (method === "GET" && path === "/api/beacon") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const limit = Number(url.searchParams.get("limit")) || 25;
        const minHits = Number(url.searchParams.get("minHits")) || 4;
        return send(res, 200, buildBeacon(hours, { limit, minHits, nowMs: Date.now() }));
      }
      if (method === "GET" && path === "/api/beacon.md") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const limit = Number(url.searchParams.get("limit")) || 25;
        const minHits = Number(url.searchParams.get("minHits")) || 4;
        const now = Date.now();
        const { markdown } = buildBeacon(hours, { limit, minHits, nowMs: now });
        res.writeHead(200, {
          "content-type": "text/markdown; charset=utf-8",
          "cache-control": "no-store",
          "content-disposition": `attachment; filename="${beaconFilename(now)}"`,
        });
        res.end(markdown);
        return;
      }

      // --- IPS enforcement-gap / efficacy (block rate + detect-only gaps) ---
      if (method === "GET" && path === "/api/efficacy") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const limit = Number(url.searchParams.get("limit")) || 25;
        return send(res, 200, buildEfficacy(hours, { limit, nowMs: Date.now() }));
      }
      if (method === "GET" && path === "/api/efficacy.md") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const limit = Number(url.searchParams.get("limit")) || 25;
        const now = Date.now();
        const { markdown } = buildEfficacy(hours, { limit, nowMs: now });
        res.writeHead(200, {
          "content-type": "text/markdown; charset=utf-8",
          "cache-control": "no-store",
          "content-disposition": `attachment; filename="${efficacyFilename(now)}"`,
        });
        res.end(markdown);
        return;
      }

      // --- threat-indicator (IOC) export for blocklists / SIEM / TI feeds ---
      // ?format=json (default) | csv | plain | markdown · ?hours=N · ?minSeverity=medium
      if (method === "GET" && path === "/api/iocs") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        const format: IocFormat = parseIocFormat(url.searchParams.get("format"));
        const minSeverity = parseSeverityFloor(url.searchParams.get("minSeverity"));
        const includeSafe = url.searchParams.get("includeSafe") === "1";
        const now = Date.now();
        const model = buildIocExport(hours, { minSeverity, includeSafe, nowMs: now });
        if (format === "json") return send(res, 200, model);
        const body = renderIoc(model, format);
        const contentType =
          format === "csv"
            ? "text/csv; charset=utf-8"
            : format === "markdown"
              ? "text/markdown; charset=utf-8"
              : "text/plain; charset=utf-8";
        res.writeHead(200, {
          "content-type": contentType,
          "cache-control": "no-store",
          "content-disposition": `attachment; filename="${iocFilename(now, format)}"`,
        });
        res.end(body);
        return;
      }

      // --- threat-intel exposure (known-bad IPs touching the network) ---
      if (method === "GET" && path === "/api/intel") {
        const hours = Number(url.searchParams.get("hours")) || cfg.web.defaultHours;
        return send(res, 200, buildIntelReport(hours, Date.now()));
      }
      if (method === "GET" && path === "/api/intel/check") {
        const ip = (url.searchParams.get("ip") ?? "").trim();
        if (isIP(ip) === 0) return send(res, 400, { error: "Invalid or missing IP." });
        return send(res, 200, checkIntelIp(ip));
      }

      // --- full-history alert search (offline; no SSH) ---
      if (method === "GET" && (path === "/api/search" || path === "/api/search.csv")) {
        const q = parseSearchQuery(url.searchParams);
        if (path === "/api/search.csv") {
          // Export the full match set (ignore pagination) up to the store cap.
          const result = searchAlerts({ ...q, offset: 0, limit: MAX_EXPORT }, Date.now(), { maxLimit: MAX_EXPORT });
          const csv = hitsToCsv(result.items);
          res.writeHead(200, {
            "content-type": "text/csv; charset=utf-8",
            "content-disposition": `attachment; filename="sectool-alerts-${result.items.length}.csv"`,
            "cache-control": "no-store",
          });
          res.end(csv);
          return;
        }
        return send(res, 200, searchAlerts(q));
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

/** Map the `/api/search` query string onto a normalized SearchQuery. */
function parseSearchQuery(p: URLSearchParams): SearchQuery {
  const str = (k: string): string | undefined => {
    const v = (p.get(k) ?? "").trim();
    return v ? v : undefined;
  };
  const bool = (k: string): boolean | undefined => {
    const v = p.get(k);
    if (v === null || v === "") return undefined;
    return v === "1" || v === "true" || v === "yes";
  };
  const sevRaw = str("sev") ?? str("minSeverity");
  const minSeverity = sevRaw && (SEVERITY_ORDER as readonly string[]).includes(sevRaw) ? (sevRaw as Severity) : undefined;
  const sortRaw = str("sort");
  const sort: SortMode | undefined =
    sortRaw === "time-asc" || sortRaw === "severity" || sortRaw === "time-desc" ? sortRaw : undefined;
  const statusRaw = str("status");
  const status = statusRaw && isTriageStatus(statusRaw) ? statusRaw : statusRaw === "open" ? "open" : undefined;
  return {
    q: str("q"),
    minSeverity,
    category: str("category") ?? str("cat"),
    action: str("action"),
    ip: str("ip"),
    status,
    hours: Number(p.get("hours")) || 0,
    hasSummary: bool("hasSummary"),
    notified: bool("notified"),
    includeDismissed: bool("includeDismissed"),
    sort,
    limit: Number(p.get("limit")) || undefined,
    offset: Number(p.get("offset")) || undefined,
  };
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
