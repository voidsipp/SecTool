/**
 * Device-level investigations for the Devices page. Three on-demand tools that
 * give a more thorough picture of an internal host than its raw connection list:
 *
 *   - trafficProfile : the device's network footprint from the gateway's
 *                      collected NetFlow (top peers, bytes, ports, recent
 *                      alerts). Works from flow data alone — no agent required.
 *   - listenerAudit  : the device's listening/open sockets mapped to the owning
 *                      process — its local attack surface — via the endpoint agent.
 *   - egressAudit    : the device's connections to *public* IPs, enriched with
 *                      geolocation + threat-intel reputation, via the agent.
 *
 * All three only accept private/LAN hosts (enforced again in agentClient for the
 * agent-backed tools); we never let the dashboard pivot SecTool onto the WAN.
 */
import { isIP } from "node:net";
import type { Config } from "../config.ts";
import { agentConnections, type AgentMatch } from "../agent/agentClient.ts";
import { enrichIp, type Enrichment } from "./enrich.ts";
import { protoName } from "./udm.ts";
import { getActiveFlowStore } from "../netflow/flowAccess.ts";
import { alertStore } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";

function isPrivateIp(ip: string): boolean {
  return (
    /^10\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^127\./.test(ip) ||
    /^169\.254\./.test(ip) ||
    /^0\./.test(ip) ||
    /^(::1|fe80|fc|fd)/i.test(ip)
  );
}

const WILDCARD = new Set(["", "*", "0.0.0.0", "::", "[::]"]);

// ---------------------------------------------------------------------------
// Tool 1 — Traffic profile (from collected NetFlow; no agent needed)
// ---------------------------------------------------------------------------

export interface TrafficPeer {
  ip: string;
  external: boolean;
  bytesIn: number;
  bytesOut: number;
  flows: number;
  ports: number[];
  protos: string[];
  lastSeen: number;
}

export interface TrafficPort {
  port: number;
  proto: string;
  flows: number;
  bytes: number;
}

export interface TrafficAlert {
  id: string;
  time: number;
  severity: string;
  signature: string;
  direction: "to" | "from";
}

export interface TrafficProfile {
  ok: boolean;
  host?: string;
  hours?: number;
  error?: string;
  summary?: {
    flows: number;
    bytesIn: number;
    bytesOut: number;
    peers: number;
    externalPeers: number;
  };
  topPeers?: TrafficPeer[];
  topPorts?: TrafficPort[];
  alerts?: TrafficAlert[];
}

export function trafficProfile(host: string, hours: number): TrafficProfile {
  if (isIP(host) === 0 || !isPrivateIp(host)) {
    return { ok: false, error: "Traffic profiling is only available for internal LAN hosts." };
  }
  const store = getActiveFlowStore();
  if (!store) return { ok: false, host, error: "Flow collector is not enabled/running (set NETFLOW_ENABLED=true)." };

  const win = Math.min(Math.max(1, Math.floor(hours) || 24), 168);
  const now = Date.now();
  const since = now - win * 3_600_000;
  const flows = store.query([host], since, now, 200_000);

  const peers = new Map<string, TrafficPeer>();
  const ports = new Map<string, TrafficPort>();
  let bytesIn = 0;
  let bytesOut = 0;

  for (const f of flows) {
    const outbound = f.srcIp === host;
    const peerIp = outbound ? f.dstIp : f.srcIp;
    if (!peerIp || peerIp === host) continue;
    const bytes = f.bytes ?? 0;
    const end = f.end ?? f.receivedAt;
    const proto = protoName(f.proto);

    let p = peers.get(peerIp);
    if (!p) {
      p = { ip: peerIp, external: !isPrivateIp(peerIp), bytesIn: 0, bytesOut: 0, flows: 0, ports: [], protos: [], lastSeen: 0 };
      peers.set(peerIp, p);
    }
    p.flows++;
    if (end > p.lastSeen) p.lastSeen = end;
    if (!p.protos.includes(proto)) p.protos.push(proto);
    if (outbound) {
      bytesOut += bytes;
      p.bytesOut += bytes;
      if (f.dstPort && !p.ports.includes(f.dstPort) && p.ports.length < 8) p.ports.push(f.dstPort);
      // The remote service contacted — most telling for "what is this host reaching".
      if (f.dstPort) {
        const key = `${f.proto ?? "?"}:${f.dstPort}`;
        const tp = ports.get(key) ?? { port: f.dstPort, proto, flows: 0, bytes: 0 };
        tp.flows++;
        tp.bytes += bytes;
        ports.set(key, tp);
      }
    } else {
      bytesIn += bytes;
      p.bytesIn += bytes;
      if (f.dstPort && !p.ports.includes(f.dstPort) && p.ports.length < 8) p.ports.push(f.dstPort);
    }
  }

  const topPeers = [...peers.values()]
    .sort((a, b) => b.bytesIn + b.bytesOut - (a.bytesIn + a.bytesOut))
    .slice(0, 15);
  topPeers.forEach((p) => p.ports.sort((a, b) => a - b));
  const topPorts = [...ports.values()].sort((a, b) => b.flows - a.flows).slice(0, 12);

  const alerts: TrafficAlert[] = [];
  for (const a of alertStore.all()) {
    if (a.time < since) continue;
    const to = a.dstIp === host;
    const from = a.srcIp === host;
    if (!to && !from) continue;
    alerts.push({
      id: a.id,
      time: a.time,
      severity: a.severity,
      signature: a.signature ?? a.category ?? "—",
      direction: from ? "from" : "to",
    });
    if (alerts.length >= 20) break;
  }

  return {
    ok: true,
    host,
    hours: win,
    summary: {
      flows: flows.length,
      bytesIn,
      bytesOut,
      peers: peers.size,
      externalPeers: [...peers.values()].filter((p) => p.external).length,
    },
    topPeers,
    topPorts,
    alerts,
  };
}

// ---------------------------------------------------------------------------
// Tool 2 — Listener / open-port audit (the host's local attack surface)
// ---------------------------------------------------------------------------

export interface Listener {
  proto: string;
  port: number;
  process: string;
  pids: number[];
  path: string;
  exposure: "all-interfaces" | "localhost" | "specific" | "unknown";
}

export interface ListenerAudit {
  ok: boolean;
  host?: string;
  error?: string;
  count?: number;
  exposed?: number;
  listeners?: Listener[];
  note?: string;
}

function classifyExposure(localAddr: string | undefined): Listener["exposure"] {
  if (localAddr === undefined) return "unknown";
  const a = localAddr.trim().toLowerCase();
  if (WILDCARD.has(a)) return "all-interfaces";
  if (a.startsWith("127.") || a === "::1" || a === "[::1]") return "localhost";
  return "specific";
}

export async function listenerAudit(cfg: Config, host: string): Promise<ListenerAudit> {
  const r = await agentConnections(cfg, host);
  if (!r.ok) return { ok: false, error: r.error };
  const conns = r.connections ?? [];

  // A socket is "listening" when the agent reports a Listen state or there is no
  // established remote peer (remotePort 0 / wildcard remote address).
  const isListener = (c: AgentMatch): boolean =>
    /listen/i.test(c.state ?? "") || (!c.remotePort && (WILDCARD.has((c.remoteIp ?? "").toLowerCase())));

  const byKey = new Map<string, Listener>();
  let sawLocalAddr = false;
  for (const c of conns) {
    if (!isListener(c) || !c.localPort) continue;
    if (c.localAddr !== undefined) sawLocalAddr = true;
    const proc = c.process || "?";
    const key = `${c.proto}|${c.localPort}|${proc}`;
    let l = byKey.get(key);
    if (!l) {
      l = { proto: c.proto || "?", port: c.localPort, process: proc, pids: [], path: c.path || "", exposure: classifyExposure(c.localAddr) };
      byKey.set(key, l);
    }
    if (c.pid && !l.pids.includes(c.pid)) l.pids.push(c.pid);
    // Widen exposure to the most-open binding seen for this service.
    const rank = { unknown: 0, localhost: 1, specific: 2, "all-interfaces": 3 } as const;
    const next = classifyExposure(c.localAddr);
    if (rank[next] > rank[l.exposure]) l.exposure = next;
  }

  const listeners = [...byKey.values()].sort(
    (a, b) => a.port - b.port || a.proto.localeCompare(b.proto),
  );
  return {
    ok: true,
    host: r.host,
    count: listeners.length,
    exposed: listeners.filter((l) => l.exposure === "all-interfaces").length,
    listeners,
    note: sawLocalAddr ? undefined : "Update the agent (v1.0.2+) to see which interface each port is bound to.",
  };
}

// ---------------------------------------------------------------------------
// Tool 3 — Egress audit (connections to public IPs + threat-intel reputation)
// ---------------------------------------------------------------------------

const MAX_ENRICH = 12;

export interface EgressPeer {
  ip: string;
  conns: number;
  ports: number[];
  processes: string[];
  lastSeen: number;
  blocked: boolean;
  risk: boolean;
  riskReasons: string[];
  geo?: Enrichment["geo"];
  virustotal?: Enrichment["virustotal"];
  abuseipdb?: Enrichment["abuseipdb"];
  feeds: string[];
}

export interface EgressAudit {
  ok: boolean;
  host?: string;
  error?: string;
  distinctRemote?: number;
  audited?: number;
  riskyCount?: number;
  peers?: EgressPeer[];
  note?: string;
}

export async function egressAudit(cfg: Config, host: string): Promise<EgressAudit> {
  const r = await agentConnections(cfg, host);
  if (!r.ok) return { ok: false, error: r.error };
  const conns = r.connections ?? [];

  interface Agg {
    ip: string;
    conns: number;
    ports: Set<number>;
    processes: Set<string>;
    lastSeen: number;
  }
  const byIp = new Map<string, Agg>();
  for (const c of conns) {
    const ip = c.remoteIp;
    if (!ip || isIP(ip) === 0 || isPrivateIp(ip)) continue;
    let a = byIp.get(ip);
    if (!a) {
      a = { ip, conns: 0, ports: new Set(), processes: new Set(), lastSeen: 0 };
      byIp.set(ip, a);
    }
    a.conns++;
    if (c.remotePort) a.ports.add(c.remotePort);
    if (c.process) a.processes.add(c.process);
    if (c.lastSeen > a.lastSeen) a.lastSeen = c.lastSeen;
  }

  const distinctRemote = byIp.size;
  const top = [...byIp.values()].sort((a, b) => b.conns - a.conns).slice(0, MAX_ENRICH);

  const peers: EgressPeer[] = await Promise.all(
    top.map(async (a): Promise<EgressPeer> => {
      let e: Enrichment | undefined;
      try {
        e = await enrichIp(cfg, a.ip);
      } catch {
        /* enrichment best-effort */
      }
      const reasons: string[] = [];
      const vtBad = (e?.virustotal?.malicious ?? 0) + (e?.virustotal?.suspicious ?? 0);
      const abuse = e?.abuseipdb?.score ?? 0;
      if (vtBad > 0) reasons.push(`VT ${e!.virustotal!.malicious} malicious`);
      if (abuse >= 50) reasons.push(`AbuseIPDB ${abuse}%`);
      if (e?.feeds.length) reasons.push(`on ${e.feeds.length} threat feed(s)`);
      if (e?.geo?.hosting) reasons.push("hosting/VPS");
      if (e?.geo?.proxy) reasons.push("proxy/anon");
      const blocked = blockStore.has(a.ip);
      // hosting/proxy alone are weak signals — only flag risk on a real verdict.
      const risk = vtBad > 0 || abuse >= 50 || (e?.feeds.length ?? 0) > 0 || blocked;
      return {
        ip: a.ip,
        conns: a.conns,
        ports: [...a.ports].sort((x, y) => x - y),
        processes: [...a.processes],
        lastSeen: a.lastSeen,
        blocked,
        risk,
        riskReasons: reasons,
        geo: e?.geo,
        virustotal: e?.virustotal,
        abuseipdb: e?.abuseipdb,
        feeds: e?.feeds ?? [],
      };
    }),
  );

  peers.sort((a, b) => Number(b.risk) - Number(a.risk) || b.conns - a.conns);
  return {
    ok: true,
    host: r.host,
    distinctRemote,
    audited: peers.length,
    riskyCount: peers.filter((p) => p.risk).length,
    peers,
    note: distinctRemote > MAX_ENRICH ? `Showing the ${MAX_ENRICH} busiest of ${distinctRemote} external peers.` : undefined,
  };
}
