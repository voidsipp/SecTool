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
  /** True when this is a known-sensitive service reachable off-host. */
  risk: boolean;
  /** Human-readable reasons the listener was flagged (empty when not risky). */
  riskReasons: string[];
}

export interface ListenerAudit {
  ok: boolean;
  host?: string;
  error?: string;
  count?: number;
  exposed?: number;
  /** Listeners flagged as a dangerous, network-reachable attack surface. */
  risky?: number;
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

// Well-known services that should rarely — if ever — be reachable from the
// network. Exposing any of these off-host is a classic lateral-movement,
// credential-theft or data-exfiltration foothold, so we surface them as the
// listener equivalent of the egress audit's threat-intel "risk" flag. Keyed by
// port; the reason fragment is shown verbatim to the operator.
const RISKY_SERVICES: Record<number, { name: string; why: string }> = {
  21: { name: "FTP", why: "plaintext file transfer" },
  23: { name: "Telnet", why: "plaintext remote shell" },
  69: { name: "TFTP", why: "unauthenticated file transfer" },
  111: { name: "rpcbind", why: "RPC portmapper" },
  135: { name: "MSRPC", why: "Windows RPC endpoint mapper" },
  139: { name: "NetBIOS", why: "legacy SMB session service" },
  161: { name: "SNMP", why: "device management, weak community strings" },
  389: { name: "LDAP", why: "directory service, often unencrypted" },
  445: { name: "SMB", why: "file sharing, ransomware vector" },
  512: { name: "rexec", why: "plaintext remote execution" },
  513: { name: "rlogin", why: "plaintext remote login" },
  514: { name: "rsh", why: "plaintext remote shell" },
  873: { name: "rsync", why: "unauthenticated file sync" },
  1433: { name: "MSSQL", why: "database, should not face the network" },
  1521: { name: "Oracle DB", why: "database, should not face the network" },
  2049: { name: "NFS", why: "network file share" },
  2375: { name: "Docker API", why: "unauthenticated container root" },
  2376: { name: "Docker API", why: "container control plane" },
  2379: { name: "etcd", why: "cluster key/value store" },
  3306: { name: "MySQL", why: "database, should not face the network" },
  3389: { name: "RDP", why: "remote desktop, brute-force target" },
  5432: { name: "PostgreSQL", why: "database, should not face the network" },
  5900: { name: "VNC", why: "remote desktop, often weak auth" },
  5984: { name: "CouchDB", why: "database, default-open in old versions" },
  5985: { name: "WinRM", why: "Windows remote management" },
  5986: { name: "WinRM", why: "Windows remote management" },
  6379: { name: "Redis", why: "database, no auth by default" },
  6443: { name: "Kubernetes API", why: "cluster control plane" },
  9200: { name: "Elasticsearch", why: "search index, default-open" },
  10250: { name: "kubelet", why: "node API, can exec into pods" },
  11211: { name: "memcached", why: "cache, no auth, DDoS amplifier" },
  27017: { name: "MongoDB", why: "database, default-open in old versions" },
};

// A listener is risky when a sensitive service is bound somewhere reachable from
// off the host. Localhost-only bindings are safe regardless of the service.
function classifyListenerRisk(l: Listener): string[] {
  if (l.exposure === "localhost") return [];
  const svc = RISKY_SERVICES[l.port];
  if (!svc) return [];
  const where =
    l.exposure === "all-interfaces"
      ? "exposed on all interfaces"
      : l.exposure === "specific"
        ? "bound to a network interface"
        : "possibly network-exposed (agent can't confirm the bind address)";
  return [`${svc.name} (${svc.why}) ${where}`];
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
      l = { proto: c.proto || "?", port: c.localPort, process: proc, pids: [], path: c.path || "", exposure: classifyExposure(c.localAddr), risk: false, riskReasons: [] };
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
  // Flag dangerous, network-reachable services now that each listener's
  // exposure is final, then surface them first so they can't be missed.
  for (const l of listeners) {
    l.riskReasons = classifyListenerRisk(l);
    l.risk = l.riskReasons.length > 0;
  }
  listeners.sort(
    (a, b) =>
      Number(b.risk) - Number(a.risk) ||
      a.port - b.port ||
      a.proto.localeCompare(b.proto),
  );
  return {
    ok: true,
    host: r.host,
    count: listeners.length,
    exposed: listeners.filter((l) => l.exposure === "all-interfaces").length,
    risky: listeners.filter((l) => l.risk).length,
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
