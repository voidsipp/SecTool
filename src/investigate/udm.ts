/**
 * Investigation tools that run on the UDM over SSH:
 *  - capture:     a live tcpdump of current traffic involving a host
 *  - connections: active conntrack sessions involving a host
 *  - surrounding: all logged events + flows in a time window around the alert
 *
 * Every IP is validated with net.isIP before being placed in a shell command,
 * so nothing user/DB-derived can inject into the remote shell.
 */
import { isIP } from "node:net";
import { sshExec, mongoQuery } from "../ingest/sshPull.ts";
import { getActiveFlowStore } from "../netflow/flowAccess.ts";
import type { Flow } from "../netflow/ipfix.ts";

function assertIp(ip: string): string {
  if (isIP(ip) === 0) throw new Error(`Invalid IP: ${ip}`);
  return ip;
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, Number.isFinite(n) ? n : lo));
}

export interface CaptureResult {
  ips: string[];
  seconds: number;
  command: string;
  packets: number;
  lines: string[];
  /**
   * Human-readable triage line for the capture. For the failure cases this
   * explains why nothing was captured (tcpdump missing or unprivileged, an
   * interface error, or a genuinely quiet host); when
   * packets *were* seen it summarizes the live conversation — distinct peers,
   * in/out direction balance, and the busiest service ports — so the operator
   * gets the shape of the traffic without scanning the raw tcpdump dump.
   */
  note?: string;
}

/** Split a tcpdump `addr.port` token into its IP and (optional) port. */
function splitEndpoint(token: string): { ip?: string; port?: number } {
  const dot = token.lastIndexOf(".");
  if (dot > 0) {
    const portStr = token.slice(dot + 1);
    const ip = token.slice(0, dot);
    // tcpdump renders both IPv4 (1.2.3.4.443) and IPv6 (2001:db8::1.443) this way.
    if (/^\d+$/.test(portStr) && isIP(ip) > 0) return { ip, port: Number(portStr) };
  }
  // No trailing port (e.g. ICMP) — the whole token is the address.
  return isIP(token) > 0 ? { ip: token } : {};
}

/**
 * Summarize parsed tcpdump lines into a one-line triage note: how many IP
 * packets were seen, across how many distinct peers, the inbound/outbound
 * balance relative to the captured host(s), and the busiest service ports.
 * Returns undefined if nothing parseable (e.g. ARP-only traffic) so the
 * caller can fall back to its generic phrasing.
 */
function summarizeCapture(lines: string[], hosts: Set<string>): string | undefined {
  // `IP[6] <src> > <dst>:` is the common prefix for v4/v6 tcp/udp/icmp lines,
  // optionally preceded by an `-i any` interface + In/Out direction field. The
  // dst group is greedy so it backtracks to the colon-before-space, keeping
  // IPv6 addresses (whose internal colons would trip a lazy match) intact.
  const wire = /\bIP6?\s+(\S+)\s+>\s+(\S+):/;
  let parsed = 0;
  let inbound = 0;
  let outbound = 0;
  const peers = new Set<string>();
  const portCounts = new Map<number, number>();

  for (const line of lines) {
    const m = wire.exec(line);
    if (!m) continue;
    const src = splitEndpoint(m[1]);
    const dst = splitEndpoint(m[2]);
    if (!src.ip || !dst.ip) continue;
    parsed++;

    const srcLocal = hosts.has(src.ip);
    const dstLocal = hosts.has(dst.ip);
    if (srcLocal && !dstLocal) {
      outbound++;
      peers.add(dst.ip);
    } else if (dstLocal && !srcLocal) {
      inbound++;
      peers.add(src.ip);
    } else {
      // Both or neither are our host(s) — still count the far side as a peer.
      peers.add(srcLocal ? dst.ip : src.ip);
    }

    // The lower of the two ports is almost always the service/well-known port,
    // the higher being an ephemeral client port — count that as the signal.
    const ports = [src.port, dst.port].filter((p): p is number => p !== undefined);
    if (ports.length) {
      const service = Math.min(...ports);
      portCounts.set(service, (portCounts.get(service) ?? 0) + 1);
    }
  }

  if (parsed === 0) return undefined;

  const topPorts = [...portCounts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0] - b[0])
    .slice(0, 4)
    .map(([port, count]) => `${port}×${count}`);

  const peerWord = peers.size === 1 ? "peer" : "peers";
  let note = `${parsed} IP packet${parsed === 1 ? "" : "s"} across ${peers.size} ${peerWord}`;
  if (outbound || inbound) note += ` (${outbound} out / ${inbound} in)`;
  if (topPorts.length) note += `; busiest ports ${topPorts.join(", ")}`;
  return note + ".";
}

/**
 * Classify why a tcpdump capture yielded no usable packet lines by reading the
 * raw remote output (stderr is folded in via `2>&1`). Returns an actionable
 * triage note for a recognized failure mode, or undefined when the run looks
 * healthy — letting the caller distinguish "the tool failed" from "the host was
 * simply quiet", which the old `not found` substring test silently conflated.
 */
function classifyCaptureFailure(out: string): string | undefined {
  // Missing binary — phrased differently per shell: busybox/ash on the UDM says
  // `sh: tcpdump: not found`, fuller distros `tcpdump: command not found`. Anchor
  // on the command name immediately before the message so tcpdump's own output —
  // which can legitimately contain a bare "not found" (e.g. a reverse-DNS "host
  // not found" line) — isn't misread as the binary being absent.
  if (/tcpdump:?\s*(?:command )?not found/i.test(out)) {
    return "tcpdump is not installed on the UDM — use the conntrack/NetFlow views for this host instead.";
  }

  // tcpdump ran but printed a diagnostic instead of packets. Its error lines are
  // `tcpdump:`-prefixed; the only benign such lines are the `listening on …`
  // startup banner and `reading from …`, so anything else is a real failure
  // worth surfacing verbatim rather than reporting a misleading "host was quiet".
  // (These lines are stripped from `lines` before the empty-capture check, so
  // without this they'd vanish into the generic no-packets note.)
  const errLine = out
    .split(/\r?\n/)
    .map((l) => l.trim())
    .find(
      (l) =>
        /^tcpdump:\s*\S/i.test(l) &&
        !/^tcpdump:\s*(?:listening on|reading from|verbose output)/i.test(l),
    );
  if (errLine) {
    const detail = errLine.replace(/^tcpdump:\s*/i, "").replace(/\s+/g, " ").trim();
    if (/permission|not permitted|privile/i.test(detail)) {
      return `tcpdump could not capture (insufficient privileges on the UDM): ${detail}`;
    }
    if (/no suitable device|SIOC|no such device|bad interface|that device/i.test(detail)) {
      return `tcpdump could not open a capture interface on the UDM: ${detail}`;
    }
    return `tcpdump failed on the UDM: ${detail}`;
  }

  return undefined;
}

/** Live tcpdump of current traffic to/from the given host(s). */
export async function capture(ips: string[], seconds: number): Promise<CaptureResult> {
  const valid = [...new Set(ips.filter((ip) => ip && isIP(ip) > 0))];
  if (valid.length === 0) throw new Error("No valid IP to capture.");
  const sec = clamp(seconds, 3, 20);
  const hostExpr = valid.map((ip) => `host ${assertIp(ip)}`).join(" or ");
  // Exclude our own SSH session (port 22) from the capture; cap packet count.
  const remote = `timeout ${sec} tcpdump -ni any -tttt -c 400 '(${hostExpr}) and not port 22' 2>&1 || true`;
  const out = await sshExec(remote, { timeoutMs: (sec + 12) * 1000 });

  const lines = out
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !/^tcpdump:|listening on|packets (captured|received|dropped)|^\d+ packets/i.test(l));

  let note: string | undefined;
  const failure = classifyCaptureFailure(out);
  if (failure) {
    note = failure;
  } else if (lines.length === 0) {
    note = `No packets involving ${valid.join(", ")} during the ${sec}s window (the threat may be historical / not currently active).`;
  } else {
    note = summarizeCapture(lines, new Set(valid));
  }

  return {
    ips: valid,
    seconds: sec,
    command: remote,
    packets: lines.length,
    lines: lines.slice(0, 300),
    note,
  };
}

export interface ConnectionsResult {
  ip: string;
  count: number;
  lines: string[];
  note?: string;
}

/** Active conntrack sessions involving the host. */
export async function connections(ip: string): Promise<ConnectionsResult> {
  assertIp(ip);
  // Prefer the conntrack tool; fall back to the procfs table.
  const remote =
    `(conntrack -L 2>/dev/null || cat /proc/net/nf_conntrack 2>/dev/null) | grep -F '${ip}' | head -200 || true`;
  const out = await sshExec(remote, { timeoutMs: 15000 });
  const lines = out.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  return {
    ip,
    count: lines.length,
    lines: lines.slice(0, 200),
    note: lines.length === 0 ? `No active connections involving ${ip} right now.` : undefined,
  };
}

export interface DnsResult {
  windowMinutes: number;
  total: number;
  domains: Array<{ domain: string; count: number }>;
  note?: string;
}

/**
 * DNS resolutions logged on the UDM within ±windowMinutes of the event. The
 * dnscrypt-proxy query log is in the UDM's local timezone, so we let the UDM's
 * own `date` build the bounds; awk filters by the fixed-width timestamp prefix.
 */
export async function dnsActivity(timeMs: number, windowMinutes: number): Promise<DnsResult> {
  const win = clamp(windowMinutes, 1, 720);
  const lo = Math.round((timeMs - win * 60_000) / 1000);
  const hi = Math.round((timeMs + win * 60_000) / 1000);
  const logFile = "/var/log/query-dnscrypt-proxy.log";
  const remote =
    `LO=$(date -d @${lo} '+%Y-%m-%d %H:%M:%S'); HI=$(date -d @${hi} '+%Y-%m-%d %H:%M:%S'); ` +
    `awk -v lo="$LO" -v hi="$HI" 'substr($0,2,19)>=lo && substr($0,2,19)<=hi' ${logFile} 2>/dev/null | tail -3000`;
  const out = await sshExec(remote, { timeoutMs: 20000 });

  const counts = new Map<string, number>();
  let total = 0;
  for (const line of out.split(/\r?\n/)) {
    const parts = line.split("\t");
    const domain = parts[2]?.trim();
    if (parts.length >= 3 && domain) {
      counts.set(domain, (counts.get(domain) ?? 0) + 1);
      total++;
    }
  }
  const domains = [...counts.entries()]
    .map(([domain, count]) => ({ domain, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 100);
  return {
    windowMinutes: win,
    total,
    domains,
    note:
      total === 0
        ? "No DNS queries in this window (log may have rotated, or queries weren't via the UDM resolver)."
        : "DNS is logged network-wide via the UDM resolver (per-client attribution isn't available in this log).",
  };
}

export interface EventRow {
  time: number;
  key?: string;
  severity?: string;
  src?: string;
  dst?: string;
}

export interface FirewallBlocksResult {
  windowHours: number;
  count: number;
  events: EventRow[];
}

/**
 * Firewall / IPS block events (TRAFFIC_BLOCKED / DROP / DENY) involving the given
 * host(s) within ±windowHours — so you can see whether a threat IP was blocked
 * around (or outside) the alert window.
 */
export async function firewallBlocks(
  ips: string[],
  timeMs: number,
  windowHours: number,
): Promise<FirewallBlocksResult> {
  const valid = [...new Set(ips.filter((ip) => isIP(ip) > 0))];
  const win = clamp(windowHours, 1, 168);
  const lo = Math.round(timeMs - win * 3_600_000);
  const hi = Math.round(timeMs + win * 3_600_000);
  const ipList = JSON.stringify(valid); // validated IPs only
  const js =
    `var ips=${ipList}; var orc=[]; ips.forEach(function(ip){['SRC_IP','DST_IP','SRC_CLIENT','DST_CLIENT']` +
    `.forEach(function(f){var o={}; o['parameters.'+f+'.target_id']=ip; orc.push(o);});}); ` +
    `var q={time:{$gte:${lo},$lte:${hi}},key:/BLOCK|DROP|DENY/i}; if(orc.length)q.$or=orc; ` +
    `print(JSON.stringify(db.alert.find(q).sort({time:-1}).limit(200).toArray().map(function(d){` +
    `var p=d.parameters||{};function ip(o){return o&&(o.target_id||o.name);}` +
    `return {time:(d.time&&d.time.valueOf?d.time.valueOf():d.time),key:d.key,severity:d.severity,` +
    `src:ip(p.SRC_IP)||ip(p.SRC_CLIENT),dst:ip(p.DST_IP)||ip(p.DST_CLIENT)};})))`;
  const out = await mongoQuery(js, { timeoutMs: 20000 });
  let events: EventRow[] = [];
  try {
    const a = out.indexOf("[");
    const b = out.lastIndexOf("]");
    if (a !== -1 && b > a) events = JSON.parse(out.slice(a, b + 1)) as EventRow[];
  } catch {
    /* ignore */
  }
  return { windowHours: win, count: events.length, events };
}

export interface FlowRow {
  start: number;
  end: number;
  srcIp?: string;
  srcPort?: number;
  dstIp?: string;
  dstPort?: number;
  proto?: number;
  bytes?: number;
  packets?: number;
  blocked?: boolean;
}

export interface FlowsResult {
  available: boolean;
  windowMinutes: number;
  count: number;
  flows: FlowRow[];
  note?: string;
}

const PROTO_NAMES: Record<number, string> = { 1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6" };

export function protoName(p: number | undefined): string {
  return p === undefined ? "?" : (PROTO_NAMES[p] ?? String(p));
}

/** Collected NetFlow/IPFIX flows involving the host(s) within ±windowMinutes. */
export function flowsAround(timeMs: number, ips: string[], windowMinutes: number): FlowsResult {
  const store = getActiveFlowStore();
  const win = clamp(windowMinutes, 1, 720);
  if (!store) {
    return { available: false, windowMinutes: win, count: 0, flows: [], note: "Flow collector is not enabled/running." };
  }
  const lo = timeMs - win * 60_000;
  const hi = timeMs + win * 60_000;
  const raw = store.query(ips.filter((ip) => isIP(ip) > 0), lo, hi, 500);
  const flows: FlowRow[] = raw.map((f: Flow) => ({
    start: f.start ?? f.receivedAt,
    end: f.end ?? f.receivedAt,
    srcIp: f.srcIp,
    srcPort: f.srcPort,
    dstIp: f.dstIp,
    dstPort: f.dstPort,
    proto: f.proto,
    bytes: f.bytes,
    packets: f.packets,
    blocked: f.fwdStatus !== undefined ? f.fwdStatus >= 128 : undefined,
  }));
  return {
    available: true,
    windowMinutes: win,
    count: flows.length,
    flows,
    note:
      flows.length === 0
        ? "No collected flows for this host in the window (flows are collected going forward; older events predate collection, and 1:512 sampling means low-volume hosts may not appear)."
        : undefined,
  };
}

export interface RelatedActivityResult {
  ip: string;
  windowHours: number;
  totalFlows: number;
  bytesIn: number;
  bytesOut: number;
  peers: Array<{ peer: string; flows: number; bytes: number; ports: number[] }>;
  flows: FlowRow[];
  events: EventRow[];
  dataRange: { earliest: number | null; latest: number | null };
  note?: string;
}

/**
 * All collected flows to/from `ip` within ±windowHours (0 = all retained data),
 * aggregated by peer, plus logged events involving the IP. `dataRange` tells the
 * UI how far back collection actually goes, so the window can be expanded to it.
 */
export async function relatedActivity(
  ip: string,
  timeMs: number,
  windowHours: number,
): Promise<RelatedActivityResult> {
  if (isIP(ip) === 0) throw new Error(`Invalid IP: ${ip}`);
  const store = getActiveFlowStore();
  const win = clamp(windowHours, 0, 24 * 90);
  const dataRange = store ? store.dataRange() : { earliest: null, latest: null };

  let raw: Flow[] = [];
  if (store) {
    raw =
      win === 0
        ? store.queryAll([ip], 5000)
        : store.query([ip], timeMs - win * 3_600_000, timeMs + win * 3_600_000, 5000);
  }

  let bytesIn = 0;
  let bytesOut = 0;
  const peerMap = new Map<string, { flows: number; bytes: number; ports: Set<number> }>();
  for (const f of raw) {
    const b = f.bytes ?? 0;
    let peer: string | undefined;
    let port: number | undefined;
    if (f.srcIp === ip) {
      bytesOut += b;
      peer = f.dstIp;
      port = f.dstPort;
    } else if (f.dstIp === ip) {
      bytesIn += b;
      peer = f.srcIp;
      port = f.dstPort;
    }
    if (peer) {
      const e = peerMap.get(peer) ?? { flows: 0, bytes: 0, ports: new Set<number>() };
      e.flows++;
      e.bytes += b;
      if (port !== undefined) e.ports.add(port);
      peerMap.set(peer, e);
    }
  }
  const peers = [...peerMap.entries()]
    .map(([peer, e]) => ({ peer, flows: e.flows, bytes: e.bytes, ports: [...e.ports].slice(0, 12) }))
    .sort((a, b) => b.bytes - a.bytes || b.flows - a.flows)
    .slice(0, 100);

  const flows: FlowRow[] = raw
    .slice(0, 500)
    .map((f) => ({
      start: f.start ?? f.receivedAt,
      end: f.end ?? f.receivedAt,
      srcIp: f.srcIp,
      srcPort: f.srcPort,
      dstIp: f.dstIp,
      dstPort: f.dstPort,
      proto: f.proto,
      bytes: f.bytes,
      packets: f.packets,
      blocked: f.fwdStatus !== undefined ? f.fwdStatus >= 128 : undefined,
    }))
    .sort((a, b) => b.start - a.start);

  // Logged events (threats/blocks/etc.) involving the IP in the window.
  const lo = win === 0 ? 0 : Math.round(timeMs - win * 3_600_000);
  const hi = win === 0 ? Date.now() + 3_600_000 : Math.round(timeMs + win * 3_600_000);
  const js =
    `print(JSON.stringify(db.alert.find({time:{$gte:${lo},$lte:${hi}},$or:[` +
    `{'parameters.SRC_IP.target_id':${JSON.stringify(ip)}},{'parameters.DST_IP.target_id':${JSON.stringify(ip)}}]})` +
    `.sort({time:-1}).limit(200).toArray().map(function(d){var p=d.parameters||{};function i(o){return o&&(o.target_id||o.name);}` +
    `return {time:(d.time&&d.time.valueOf?d.time.valueOf():d.time),key:d.key,severity:d.severity,src:i(p.SRC_IP)||i(p.SRC_CLIENT),dst:i(p.DST_IP)||i(p.DST_CLIENT)};})))`;
  let events: EventRow[] = [];
  try {
    const out = await mongoQuery(js, { timeoutMs: 20000 });
    const a = out.indexOf("[");
    const b = out.lastIndexOf("]");
    if (a !== -1 && b > a) events = JSON.parse(out.slice(a, b + 1)) as EventRow[];
  } catch {
    /* ignore */
  }

  return {
    ip,
    windowHours: win,
    totalFlows: raw.length,
    bytesIn,
    bytesOut,
    peers,
    flows,
    events,
    dataRange,
    note: !store
      ? "Flow collector is not running — only logged events are shown."
      : raw.length === 0
        ? "No collected flows to/from this IP yet (collection is forward-only; expand the window or wait for traffic)."
        : undefined,
  };
}

export interface SurroundingResult {
  windowMinutes: number;
  events: EventRow[];
  connections: ConnectionsResult | null;
  dns: DnsResult | null;
  firewallBlocks: FirewallBlocksResult | null;
  flows: FlowsResult;
}

/**
 * All logged alert/activity events within ±windowMinutes of the event time,
 * plus a current connection snapshot for the involved hosts.
 */
export async function surrounding(
  timeMs: number,
  ips: string[],
  windowMinutes: number,
): Promise<SurroundingResult> {
  const win = clamp(windowMinutes, 1, 720);
  const lo = Math.round(timeMs - win * 60_000);
  const hi = Math.round(timeMs + win * 60_000);
  const js =
    `print(JSON.stringify(db.alert.find({time:{$gte:${lo},$lte:${hi}}}).sort({time:1}).limit(500).toArray()` +
    `.map(function(d){var p=d.parameters||{};function ip(o){return o&&(o.target_id||o.name);}` +
    `return {time:(d.time&&d.time.valueOf?d.time.valueOf():d.time),key:d.key,severity:d.severity,` +
    `src:ip(p.SRC_IP)||ip(p.SRC_CLIENT),dst:ip(p.DST_IP)||ip(p.DST_CLIENT)};})))`;
  const out = await mongoQuery(js, { timeoutMs: 20000 });

  let events: SurroundingResult["events"] = [];
  try {
    const start = out.indexOf("[");
    const end = out.lastIndexOf("]");
    if (start !== -1 && end > start) {
      events = JSON.parse(out.slice(start, end + 1)) as SurroundingResult["events"];
    }
  } catch {
    /* leave events empty on parse failure */
  }

  // Snapshot current connections, DNS resolutions, and firewall blocks (±24h)
  // involving the host — all in parallel.
  const primary = ips.find((ip) => isIP(ip) > 0);
  const [conn, dns, blocks] = await Promise.all([
    primary ? connections(primary).catch(() => null) : Promise.resolve(null),
    dnsActivity(timeMs, win).catch(() => null),
    firewallBlocks(ips, timeMs, 24).catch(() => null),
  ]);

  return {
    windowMinutes: win,
    events,
    connections: conn,
    dns,
    firewallBlocks: blocks,
    flows: flowsAround(timeMs, ips, win),
  };
}
