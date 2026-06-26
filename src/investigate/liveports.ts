/**
 * Live port-activity for any internal host, read straight from the gateway's
 * connection-tracking table over SSH.
 *
 * This closes a real visibility gap: the Devices page only lists hosts running
 * the endpoint agent, and its traffic view depends on collected NetFlow (which
 * is sampled and forward-only). So when an IDS/IPS alert fires for an outbound
 * port on a host that has no agent and little/no sampled flow, the dashboard has
 * nothing to show for that port. The UDM's conntrack table, however, knows every
 * connection it is currently routing for that host — no agent, no sampling gap —
 * which makes it the authoritative *real-time* source of a host's port activity.
 *
 * We parse both `conntrack -L` and the procfs `/proc/net/nf_conntrack` fallback
 * into structured connections and aggregate them into outbound/inbound port
 * groups. Every IP is validated with net.isIP before it touches the remote shell,
 * and only private/LAN hosts are accepted, so the dashboard can never pivot
 * SecTool's gateway access onto an arbitrary WAN address.
 */
import { isIP } from "node:net";
import { sshExec, loadSshTarget } from "../ingest/sshPull.ts";

function isPrivateIp(ip: string): boolean {
  return (
    /^10\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^127\./.test(ip) ||
    /^169\.254\./.test(ip) ||
    /^(::1|fe80|fc|fd)/i.test(ip)
  );
}

// L4 protocols conntrack labels by name (the token that precedes its proto
// number). Used to locate the protocol column in both output formats.
const L4_NAMES = new Set([
  "tcp",
  "udp",
  "udplite",
  "icmp",
  "icmpv6",
  "sctp",
  "dccp",
  "gre",
  "unknown",
]);

export type FlowDirection = "outbound" | "inbound" | "local";

export interface LiveConn {
  proto: string;
  /** TCP connection state (ESTABLISHED, TIME_WAIT, …); absent for UDP/ICMP. */
  state?: string;
  direction: FlowDirection;
  /** The host's own port (source port for outbound, listening port for inbound). */
  localPort?: number;
  remoteIp?: string;
  remoteExternal?: boolean;
  /** The peer's port — the remote *service* port for an outbound connection. */
  remotePort?: number;
  bytes?: number;
  packets?: number;
  /** Remaining conntrack timeout in seconds (rough "freshness" of the entry). */
  ttl?: number;
}

export interface PortGroup {
  proto: string;
  /** Service port: the remote port for outbound, the local port for inbound. */
  port: number;
  connections: number;
  peers: string[];
  externalPeers: number;
  states: string[];
  bytes: number;
}

export interface LivePortActivity {
  ok: boolean;
  host?: string;
  error?: string;
  source?: "conntrack" | "nf_conntrack" | "none";
  capturedAt?: number;
  summary?: {
    connections: number;
    outboundConns: number;
    inboundConns: number;
    distinctOutboundPorts: number;
    distinctInboundPorts: number;
    externalPeers: number;
  };
  outbound?: PortGroup[];
  inbound?: PortGroup[];
  conns?: LiveConn[];
  note?: string;
}

interface ParsedLine {
  proto: string;
  state?: string;
  ttl?: number;
  src?: string;
  dst?: string;
  sport?: number;
  dport?: number;
  bytes?: number;
  packets?: number;
}

/**
 * Parse a single conntrack / nf_conntrack line. Only the *original* direction
 * tuple (the first src/dst/sport/dport set) is used to attribute the connection;
 * byte/packet counters from both directions are summed when present.
 */
function parseConntrackLine(line: string): ParsedLine | null {
  const tokens = line.trim().split(/\s+/);
  if (tokens.length < 4) return null;

  // Locate the L4 protocol column (handles both the "tcp 6 …" form from
  // `conntrack -L` and the "ipv4 2 tcp 6 …" form from /proc/net/nf_conntrack).
  let l4 = -1;
  for (let i = 0; i < tokens.length; i++) {
    if (L4_NAMES.has(tokens[i]!.toLowerCase())) {
      l4 = i;
      break;
    }
  }
  if (l4 === -1) return null;
  const proto = tokens[l4]!.toLowerCase();

  // Token after the proto number is the timeout (seconds); the next bare
  // UPPERCASE word (for TCP) is the connection state.
  const ttlTok = tokens[l4 + 2];
  const ttl = ttlTok && /^\d+$/.test(ttlTok) ? Number(ttlTok) : undefined;

  const out: ParsedLine = { proto, ttl };
  for (let i = l4 + 1; i < tokens.length; i++) {
    const t = tokens[i]!;
    if (out.state === undefined && /^[A-Z][A-Z_]+$/.test(t)) {
      // Bare uppercase word before any key=value -> TCP state.
      out.state = t;
      continue;
    }
    const eq = t.indexOf("=");
    if (eq <= 0) continue;
    const key = t.slice(0, eq);
    const val = t.slice(eq + 1);
    switch (key) {
      // Original-direction tuple wins (first occurrence only).
      case "src": if (out.src === undefined && isIP(val) > 0) out.src = val; break;
      case "dst": if (out.dst === undefined && isIP(val) > 0) out.dst = val; break;
      case "sport": if (out.sport === undefined) out.sport = Number(val) || undefined; break;
      case "dport": if (out.dport === undefined) out.dport = Number(val) || undefined; break;
      // Counters appear once per direction when accounting is enabled; sum them.
      case "bytes": { const n = Number(val); if (Number.isFinite(n)) out.bytes = (out.bytes ?? 0) + n; break; }
      case "packets": { const n = Number(val); if (Number.isFinite(n)) out.packets = (out.packets ?? 0) + n; break; }
      default: break;
    }
  }
  return out.src || out.dst ? out : null;
}

function pushGroup(map: Map<string, PortGroup>, proto: string, port: number, peer: string | undefined, state: string | undefined, bytes: number): void {
  const key = `${proto}:${port}`;
  let g = map.get(key);
  if (!g) {
    g = { proto, port, connections: 0, peers: [], externalPeers: 0, states: [], bytes: 0 };
    map.set(key, g);
  }
  g.connections++;
  g.bytes += bytes;
  if (state && !g.states.includes(state)) g.states.push(state);
  if (peer && !g.peers.includes(peer)) {
    g.peers.push(peer);
    if (!isPrivateIp(peer)) g.externalPeers++;
  }
}

const MAX_CONNS = 600;

/**
 * Live port activity for an internal host from the gateway's conntrack table.
 * Real-time and agent-independent — works for any LAN host the UDM routes.
 */
export async function livePortActivity(host: string, capturedAt: number = Date.now()): Promise<LivePortActivity> {
  if (isIP(host) === 0 || !isPrivateIp(host)) {
    return { ok: false, error: "Live port activity is only available for internal LAN hosts." };
  }
  if (!loadSshTarget()) {
    return { ok: false, host, error: "No SSH connection to the gateway is configured. Run --setup-ssh." };
  }

  // conntrack -L is preferred; fall back to procfs. grep narrows to lines that
  // mention the host (the parser re-checks exact tuple equality afterwards, so
  // an over-broad substring match never mis-attributes a connection).
  const remote =
    `(conntrack -L 2>/dev/null || cat /proc/net/nf_conntrack 2>/dev/null) | grep -F '${host}' | head -4000 || true`;
  let out: string;
  try {
    out = await sshExec(remote, { timeoutMs: 15000 });
  } catch (err) {
    return { ok: false, host, error: `conntrack query failed: ${(err as Error).message}` };
  }

  const lines = out.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const source: LivePortActivity["source"] =
    lines.length === 0 ? "none" : lines.some((l) => /^ipv[46]\b/i.test(l)) ? "nf_conntrack" : "conntrack";

  const conns: LiveConn[] = [];
  const outbound = new Map<string, PortGroup>();
  const inbound = new Map<string, PortGroup>();
  let outboundConns = 0;
  let inboundConns = 0;
  const externalPeers = new Set<string>();

  for (const line of lines) {
    const p = parseConntrackLine(line);
    if (!p) continue;

    let direction: FlowDirection;
    let localPort: number | undefined;
    let remoteIp: string | undefined;
    let remotePort: number | undefined;
    if (p.src === host) {
      direction = "outbound";
      localPort = p.sport;
      remoteIp = p.dst;
      remotePort = p.dport;
    } else if (p.dst === host) {
      direction = "inbound";
      localPort = p.dport;
      remoteIp = p.src;
      remotePort = p.sport;
    } else {
      // Host only appears in the reply tuple (NAT) or as a substring match we
      // don't care about — skip rather than guess.
      continue;
    }
    if (remoteIp === host) direction = "local";
    const remoteExternal = remoteIp ? !isPrivateIp(remoteIp) : false;
    if (remoteExternal && remoteIp) externalPeers.add(remoteIp);

    const bytes = p.bytes ?? 0;
    if (direction === "outbound") {
      outboundConns++;
      if (remotePort) pushGroup(outbound, p.proto, remotePort, remoteIp, p.state, bytes);
    } else if (direction === "inbound") {
      inboundConns++;
      if (localPort) pushGroup(inbound, p.proto, localPort, remoteIp, p.state, bytes);
    }

    if (conns.length < MAX_CONNS) {
      conns.push({
        proto: p.proto,
        state: p.state,
        direction,
        localPort,
        remoteIp,
        remoteExternal,
        remotePort,
        bytes: p.bytes,
        packets: p.packets,
        ttl: p.ttl,
      });
    }
  }

  // Busiest service ports first; external-facing ports surface above LAN ones.
  const sortGroups = (g: PortGroup[]): PortGroup[] =>
    g.sort((a, b) => b.externalPeers - a.externalPeers || b.connections - a.connections || a.port - b.port).slice(0, 50);
  const outGroups = sortGroups([...outbound.values()]);
  const inGroups = sortGroups([...inbound.values()]);

  return {
    ok: true,
    host,
    source,
    capturedAt,
    summary: {
      connections: outboundConns + inboundConns,
      outboundConns,
      inboundConns,
      distinctOutboundPorts: outbound.size,
      distinctInboundPorts: inbound.size,
      externalPeers: externalPeers.size,
    },
    outbound: outGroups,
    inbound: inGroups,
    conns,
    note:
      lines.length === 0
        ? `No active connections involving ${host} on the gateway right now. conntrack is a live snapshot — the flagged port may be idle at the moment, or this host routes through a different gateway.`
        : "Live snapshot of the gateway's connection-tracking table (current sessions only; no agent required).",
  };
}
