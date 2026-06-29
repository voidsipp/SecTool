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
    const src = splitEndpoint(m[1]!);
    const dst = splitEndpoint(m[2]!);
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
    .map(([port, count]) => `${portLabel(port)}×${count}`);

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
  /**
   * Human-readable triage line for the connection snapshot. When there are no
   * sessions it says so (the threat may be historical / not currently active);
   * when sessions *are* present it summarizes them — session count, distinct
   * peers, in/out balance relative to the host, the protocol mix, the TCP
   * connection states (the sharpest signal: ESTABLISHED vs SYN_SENT vs
   * TIME_WAIT), and the busiest destination ports — so the operator gets the
   * shape of the host's live conversations without scanning raw conntrack rows.
   */
  note?: string;
}

const TCP_STATE_RE =
  /\b(ESTABLISHED|SYN_SENT|SYN_RECV|FIN_WAIT|CLOSE_WAIT|LAST_ACK|TIME_WAIT|CLOSING|CLOSE|LISTEN)\b/;
const L4_PROTO_RE = /\b(tcp|udp|udplite|icmpv6|icmp|gre|esp|sctp|dccp)\b/i;

/**
 * Summarize parsed conntrack / nf_conntrack rows into a one-line triage note for
 * `host`. Both formats expose the connection's original direction as the first
 * `src=/dst=/dport=` tuple, so we read that to attribute each session to a peer
 * and a service port; the uppercase TCP state token (and `tcp`/`udp`/… proto
 * name) appear inline in both. Returns undefined when nothing was parseable so
 * the caller can fall back to its generic phrasing.
 */
function summarizeConnections(lines: string[], host: string): string | undefined {
  let parsed = 0;
  let inbound = 0;
  let outbound = 0;
  const peers = new Set<string>();
  const protoCounts = new Map<string, number>();
  const stateCounts = new Map<string, number>();
  const portCounts = new Map<number, number>();

  for (const line of lines) {
    // First src=/dst= is the original direction (the session initiator), which
    // is what we want to attribute regardless of any NAT in the reply tuple.
    const src = /\bsrc=(\S+)/.exec(line)?.[1];
    const dst = /\bdst=(\S+)/.exec(line)?.[1];
    if (!src || !dst) continue;
    parsed++;

    const proto = L4_PROTO_RE.exec(line)?.[1]?.toLowerCase();
    if (proto) protoCounts.set(proto, (protoCounts.get(proto) ?? 0) + 1);

    const state = TCP_STATE_RE.exec(line)?.[1];
    if (state) stateCounts.set(state, (stateCounts.get(state) ?? 0) + 1);

    // Attribute direction relative to the host: src=host → the host reached out
    // (outbound), otherwise treat the far end as the peer (inbound / best effort
    // when the host only appears in the reply tuple under NAT).
    if (src === host) {
      outbound++;
      peers.add(dst);
    } else {
      inbound++;
      peers.add(src);
    }

    // Original-direction dport is the service/well-known port being contacted.
    const dport = /\bdport=(\d+)/.exec(line)?.[1];
    if (dport) {
      const p = Number(dport);
      portCounts.set(p, (portCounts.get(p) ?? 0) + 1);
    }
  }

  if (parsed === 0) return undefined;

  const protoMix = [...protoCounts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([proto, count]) => `${proto}×${count}`);
  const topStates = [...stateCounts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 4)
    .map(([state, count]) => `${state}×${count}`);
  const topPorts = [...portCounts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0] - b[0])
    .slice(0, 4)
    .map(([port, count]) => `${portLabel(port)}×${count}`);

  const peerWord = peers.size === 1 ? "peer" : "peers";
  let note = `${parsed} active session${parsed === 1 ? "" : "s"} across ${peers.size} ${peerWord}`;
  if (outbound || inbound) note += ` (${outbound} out / ${inbound} in)`;
  if (protoMix.length > 1) note += `; ${protoMix.join(", ")}`;
  if (topStates.length) note += `; states ${topStates.join(", ")}`;
  if (topPorts.length) note += `; busiest dports ${topPorts.join(", ")}`;
  return note + ".";
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
    note:
      lines.length === 0
        ? `No active connections involving ${ip} right now (the threat may be historical / not currently active).`
        : summarizeConnections(lines, ip),
  };
}

export interface DnsResult {
  windowMinutes: number;
  total: number;
  domains: Array<{ domain: string; count: number }>;
  /**
   * Human-readable triage line for the DNS snapshot. When there are no queries
   * it says so (the log may have rotated, or resolution didn't go via the UDM
   * resolver); when queries *are* present it summarizes them — total volume,
   * the breadth of distinct domains, and the busiest domains — and, because DNS
   * is a common exfiltration / C2 channel, flags the two indicators that stand
   * out in a flat query log: an unusually long label (data smuggled into the
   * name) and one parent domain fanning out into many distinct subdomains (the
   * footprint of DNS tunneling or DGA beaconing). The network-wide attribution
   * caveat is always appended, since this log isn't per-client.
   */
  note?: string;
}

/** The registrable-ish parent of a hostname: its last two dot-labels. */
function dnsParent(domain: string): string {
  const labels = domain.replace(/\.$/, "").split(".").filter(Boolean);
  return labels.length <= 2 ? labels.join(".") : labels.slice(-2).join(".");
}

// Per-client attribution isn't available in the UDM's network-wide resolver log,
// so every populated DNS note carries this caveat to keep the operator honest
// about what the data can and can't pin to a single host.
const DNS_ATTRIBUTION_CAVEAT =
  "DNS is logged network-wide via the UDM resolver (per-client attribution isn't available in this log).";

/**
 * Summarize the DNS query log into a one-line triage note. Surfaces query
 * volume, distinct-domain breadth and the busiest domains, then flags the two
 * sharpest compromise signals visible in a flat query log: an unusually long
 * DNS label (possible data exfiltration via the name) and a parent domain with
 * an abnormal number of distinct subdomains (possible DNS tunneling / DGA
 * beaconing). `counts` is the full per-domain tally (not the truncated top-N)
 * so the tunneling fan-out is measured across every domain seen in the window.
 */
function summarizeDns(counts: Map<string, number>, total: number): string {
  const distinct = counts.size;
  const top = [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 4)
    .map(([domain, count]) => `${domain}×${count}`);

  // Tunneling/DGA indicators, computed over every distinct domain:
  //  - the longest single dot-label (encoded payloads inflate label length);
  //  - the parent domain answering the most distinct subdomains (a tunnel or
  //    DGA fans one registrable domain out into many one-off names).
  let longestLabel = 0;
  const fanout = new Map<string, Set<string>>();
  for (const domain of counts.keys()) {
    for (const label of domain.replace(/\.$/, "").split(".")) {
      if (label.length > longestLabel) longestLabel = label.length;
    }
    const parent = dnsParent(domain);
    let subs = fanout.get(parent);
    if (!subs) fanout.set(parent, (subs = new Set()));
    subs.add(domain);
  }
  let topFanout: { parent: string; subs: number } | undefined;
  for (const [parent, subs] of fanout) {
    if (!topFanout || subs.size > topFanout.subs) topFanout = { parent, subs: subs.size };
  }

  const domainWord = distinct === 1 ? "domain" : "domains";
  let note = `${total} DNS quer${total === 1 ? "y" : "ies"} across ${distinct} distinct ${domainWord}`;
  if (top.length) note += `; busiest ${top.join(", ")}`;
  note += ".";

  const flags: string[] = [];
  if (longestLabel >= 40) {
    flags.push(`unusually long DNS label (${longestLabel} chars) — possible exfiltration/tunneling`);
  }
  if (topFanout && topFanout.subs >= 20) {
    flags.push(
      `${topFanout.subs} distinct subdomains under ${topFanout.parent} — possible DNS tunneling / DGA beaconing`,
    );
  }
  if (flags.length) note += ` Watch: ${flags.join("; ")}.`;

  return `${note} ${DNS_ATTRIBUTION_CAVEAT}`;
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
        : summarizeDns(counts, total),
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
  /**
   * Human-readable triage line for the block snapshot. When there are no blocks
   * it says so (this host wasn't dropped by a firewall/IPS rule in the window);
   * when blocks *are* present it summarizes them — block count, distinct peers,
   * in/out balance relative to the host, the rule-verb and severity mix, and —
   * the sharpest signal — how the blocks sit in *time* relative to the alert
   * (nearest block, and how many fell before vs after it). That tells the
   * operator whether the gateway was actively dropping this threat *around* the
   * alert (corroborating a live event) or only well outside the window (stale /
   * unrelated), without scanning the raw event rows.
   */
  note?: string;
}

/** Phrase a signed millisecond offset from the alert time in compact, human terms. */
function relativeToAlert(deltaMs: number): string {
  if (deltaMs === 0) return "at the alert time";
  const abs = Math.abs(deltaMs);
  const dir = deltaMs < 0 ? "before" : "after";
  if (abs < 60_000) return `just ${dir} the alert`;
  const mins = Math.round(abs / 60_000);
  if (mins < 90) return `${mins}m ${dir} the alert`;
  const hrs = abs / 3_600_000;
  return `${hrs < 10 ? hrs.toFixed(1) : Math.round(hrs)}h ${dir} the alert`;
}

/**
 * Summarize firewall/IPS block events into a one-line triage note for `hosts`.
 * Each event carries src/dst/key/severity/time; we attribute direction relative
 * to the host(s), tally the distinct peers blocked, fold the rule key down to its
 * block verb (BLOCK/DROP/DENY) plus the severity mix, and — most usefully —
 * locate the blocks in time around `timeMs` (the alert). Returns undefined when
 * there are no events so the caller can fall back to its generic phrasing.
 */
function summarizeFirewallBlocks(
  events: EventRow[],
  hosts: Set<string>,
  timeMs: number,
): string | undefined {
  if (events.length === 0) return undefined;

  let inbound = 0;
  let outbound = 0;
  let before = 0;
  let after = 0;
  let nearest: number | undefined;
  const peers = new Set<string>();
  const verbCounts = new Map<string, number>();
  const sevCounts = new Map<string, number>();

  for (const e of events) {
    const srcLocal = e.src !== undefined && hosts.has(e.src);
    const dstLocal = e.dst !== undefined && hosts.has(e.dst);
    if (srcLocal && !dstLocal) {
      outbound++;
      if (e.dst) peers.add(e.dst);
    } else if (dstLocal && !srcLocal) {
      inbound++;
      if (e.src) peers.add(e.src);
    } else {
      // Both/neither are our host(s) — still credit the far side as a peer.
      const peer = srcLocal ? e.dst : e.src;
      if (peer) peers.add(peer);
    }

    // Collapse the rule key to its block verb so TRAFFIC_BLOCKED, FW_DROP, etc.
    // group together; keep the raw key only when no verb is recognizable.
    const verb = /BLOCK|DROP|DENY/i.exec(e.key ?? "")?.[0]?.toUpperCase() ?? e.key;
    if (verb) verbCounts.set(verb, (verbCounts.get(verb) ?? 0) + 1);

    if (e.severity) sevCounts.set(e.severity, (sevCounts.get(e.severity) ?? 0) + 1);

    if (typeof e.time === "number") {
      const delta = e.time - timeMs;
      if (delta < 0) before++;
      else after++;
      if (nearest === undefined || Math.abs(delta) < Math.abs(nearest)) nearest = delta;
    }
  }

  const verbMix = [...verbCounts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 4)
    .map(([verb, count]) => `${verb}×${count}`);
  const sevMix = [...sevCounts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 4)
    .map(([sev, count]) => `${sev}×${count}`);

  const peerWord = peers.size === 1 ? "peer" : "peers";
  let note = `${events.length} firewall block${events.length === 1 ? "" : "s"} across ${peers.size} ${peerWord}`;
  if (outbound || inbound) note += ` (${outbound} out / ${inbound} in)`;
  if (verbMix.length) note += `; ${verbMix.join(", ")}`;
  if (sevMix.length) note += `; severity ${sevMix.join(", ")}`;
  if (nearest !== undefined) {
    note += `; nearest ${relativeToAlert(nearest)}`;
    if (before && after) note += ` (${before} before / ${after} after)`;
  }
  return note + ".";
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
  return {
    windowHours: win,
    count: events.length,
    events,
    note:
      events.length === 0
        ? `No firewall/IPS blocks involving ${valid.join(", ") || "this host"} in the ±${win}h window.`
        : summarizeFirewallBlocks(events, new Set(valid), timeMs),
  };
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
  /**
   * Human-readable triage line for the flow snapshot. When the collector is off
   * or no flows matched it says so (collection is forward-only and 1:512 sampled,
   * so older or low-volume traffic may be absent); when flows *are* present it
   * summarizes them — flow count, distinct peers, in/out balance relative to the
   * host, the bytes moved each way (the sharpest exfiltration signal in flow
   * data), the protocol mix, the busiest destination ports, and how many flows
   * the gateway marked blocked — so the operator gets the shape of the host's
   * traffic without scanning the raw flow rows.
   */
  note?: string;
}

const PROTO_NAMES: Record<number, string> = { 1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6" };

export function protoName(p: number | undefined): string {
  return p === undefined ? "?" : (PROTO_NAMES[p] ?? String(p));
}

// Well-known / triage-relevant TCP-UDP service ports. Curated for security
// review rather than exhaustive: the common application protocols an operator
// recognizes at a glance, plus the management/database/remote-access ports whose
// presence in a host's busiest-port list is itself a signal. Names follow the
// short IANA service identifiers so they read uniformly next to a port number.
const SERVICE_NAMES: Record<number, string> = {
  20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 37: "time",
  43: "whois", 49: "tacacs", 53: "domain", 67: "dhcp", 68: "dhcp", 69: "tftp",
  79: "finger", 80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
  119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
  139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmp-trap", 179: "bgp",
  389: "ldap", 443: "https", 445: "smb", 465: "smtps", 500: "isakmp",
  514: "syslog", 515: "printer", 520: "rip", 523: "ibm-db2", 540: "uucp",
  554: "rtsp", 587: "submission", 593: "msrpc-http", 623: "ipmi", 631: "ipp",
  636: "ldaps", 873: "rsync", 902: "vmware", 989: "ftps-data", 990: "ftps",
  993: "imaps", 995: "pop3s", 1080: "socks", 1194: "openvpn", 1433: "mssql",
  1434: "mssql-mon", 1521: "oracle", 1701: "l2tp", 1723: "pptp", 1883: "mqtt",
  1900: "ssdp", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl", 2222: "ssh-alt",
  2375: "docker", 2376: "docker-tls", 3128: "squid", 3268: "ldap-gc",
  3306: "mysql", 3389: "rdp", 3478: "stun", 4444: "metasploit", 4500: "ipsec-nat",
  4789: "vxlan", 5000: "upnp", 5060: "sip", 5061: "sips", 5222: "xmpp",
  5353: "mdns", 5432: "postgres", 5555: "adb", 5601: "kibana", 5672: "amqp",
  5683: "coap", 5800: "vnc-http", 5900: "vnc", 5938: "teamviewer", 5985: "winrm",
  5986: "winrm-ssl", 6000: "x11", 6379: "redis", 6443: "kube-api", 6660: "irc",
  6667: "irc", 7547: "tr-069", 8000: "http-alt", 8008: "http-alt", 8080: "http-proxy",
  8086: "influxdb", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
  9001: "tor-orport", 9090: "prometheus", 9100: "jdwp", 9200: "elasticsearch",
  9300: "elasticsearch", 10000: "webmin", 11211: "memcached", 15672: "rabbitmq",
  27017: "mongodb", 32400: "plex", 49152: "upnp", 51413: "bittorrent",
  51820: "wireguard",
};

/**
 * Annotate a port number with its well-known service name for triage notes —
 * e.g. 443 → "443/https", 53 → "53/domain". Returns the bare number when the
 * port isn't in the curated table, so unrecognized ports stay readable. Mirrors
 * `protoName`: a small, security-relevant lookup that keeps the raw value when no
 * label applies.
 */
export function portLabel(port: number): string {
  const name = SERVICE_NAMES[port];
  return name ? `${port}/${name}` : String(port);
}

/** Render a byte count in compact human terms (B / KB / MB / GB / TB, base 1024). */
function humanBytes(n: number): string {
  if (!Number.isFinite(n) || n < 1024) return `${Math.max(0, Math.round(n) || 0)} B`;
  const units = ["KB", "MB", "GB", "TB", "PB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

/**
 * Summarize collected NetFlow/IPFIX flows into a one-line triage note for
 * `hosts`. Each flow carries src/dst IP+port, an L4 proto number, byte/packet
 * counts and a blocked flag; we attribute direction relative to the host(s),
 * tally the distinct peers and the bytes moved each way (the sharpest
 * exfiltration signal in flow data), the protocol mix, the busiest destination
 * ports, and how many flows the gateway marked blocked. Returns undefined when
 * nothing is parseable so the caller can fall back to its generic phrasing.
 */
function summarizeFlows(flows: FlowRow[], hosts: Set<string>): string | undefined {
  let parsed = 0;
  let inbound = 0;
  let outbound = 0;
  let bytesIn = 0;
  let bytesOut = 0;
  let blocked = 0;
  const peers = new Set<string>();
  const protoCounts = new Map<string, number>();
  const portCounts = new Map<number, number>();

  for (const f of flows) {
    const src = f.srcIp;
    const dst = f.dstIp;
    if (!src || !dst) continue;
    parsed++;

    const bytes = f.bytes ?? 0;
    const srcLocal = hosts.has(src);
    const dstLocal = hosts.has(dst);
    if (srcLocal && !dstLocal) {
      outbound++;
      bytesOut += bytes;
      peers.add(dst);
    } else if (dstLocal && !srcLocal) {
      inbound++;
      bytesIn += bytes;
      peers.add(src);
    } else {
      // Both/neither are our host(s) — still credit the far side as a peer.
      peers.add(srcLocal ? dst : src);
    }

    const proto = protoName(f.proto);
    if (proto !== "?") protoCounts.set(proto, (protoCounts.get(proto) ?? 0) + 1);

    // The destination port is the service/well-known port being contacted.
    if (f.dstPort !== undefined) {
      portCounts.set(f.dstPort, (portCounts.get(f.dstPort) ?? 0) + 1);
    }

    if (f.blocked) blocked++;
  }

  if (parsed === 0) return undefined;

  const protoMix = [...protoCounts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 4)
    .map(([proto, count]) => `${proto}×${count}`);
  const topPorts = [...portCounts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0] - b[0])
    .slice(0, 4)
    .map(([port, count]) => `${portLabel(port)}×${count}`);

  const peerWord = peers.size === 1 ? "peer" : "peers";
  let note = `${parsed} flow${parsed === 1 ? "" : "s"} across ${peers.size} ${peerWord}`;
  if (outbound || inbound) note += ` (${outbound} out / ${inbound} in)`;
  if (bytesOut || bytesIn) note += `; ${humanBytes(bytesOut)} out / ${humanBytes(bytesIn)} in`;
  if (protoMix.length) note += `; ${protoMix.join(", ")}`;
  if (topPorts.length) note += `; busiest dports ${topPorts.join(", ")}`;
  if (blocked) note += `; ${blocked} blocked`;
  return note + ".";
}

/** Collected NetFlow/IPFIX flows involving the host(s) within ±windowMinutes. */
export function flowsAround(timeMs: number, ips: string[], windowMinutes: number): FlowsResult {
  const store = getActiveFlowStore();
  const win = clamp(windowMinutes, 1, 720);
  if (!store) {
    // Collector-off branch: distinct from "ran but matched nothing" below. Name
    // the remediation (the NETFLOW_ENABLED env var, mirroring device.ts) and the
    // forward-only nature of collection, so the operator knows this is a config
    // gap they can close — not evidence the host was quiet — and that enabling it
    // captures traffic going forward, not retroactively for this past event.
    return {
      available: false,
      windowMinutes: win,
      count: 0,
      flows: [],
      note:
        "Flow collector is not enabled/running, so no NetFlow was captured for this host — " +
        "set NETFLOW_ENABLED=true and restart to begin forward-only collection (it won't recover traffic from before it was enabled).",
    };
  }
  const lo = timeMs - win * 60_000;
  const hi = timeMs + win * 60_000;
  const validIps = ips.filter((ip) => isIP(ip) > 0);
  const raw = store.query(validIps, lo, hi, 500);
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
        : summarizeFlows(flows, new Set(validIps)),
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
  /**
   * Human-readable triage line for the related-activity snapshot. This view is
   * unique in joining collected flows with logged alert/block events for one IP
   * over a potentially long window, so the note reports both: the flow shape —
   * flow count, distinct peers, the bytes moved each way (the sharpest
   * exfiltration signal in flow data) and the heaviest correspondents by volume
   * (likely exfil destinations) — and the logged-event tail (count and severity
   * mix). The collector-state caveats are preserved, so "no flows" still reads
   * as collector-off vs forward-only-collection rather than vanishing, and any
   * logged events are summarized even when no flows were captured.
   */
  note?: string;
}

/**
 * Compose the human-readable triage note for a related-activity snapshot from
 * the already-aggregated flow tallies and the logged events. Reports the flow
 * shape (count, distinct peers, bytes each way, heaviest peers by volume) and
 * the logged-event tail (count + severity mix), while preserving the collector
 * caveats so the operator can tell "collector off" / "nothing collected yet"
 * apart from a genuinely quiet host. `peers` is expected pre-sorted by bytes
 * descending (as produced by `relatedActivity`).
 */
function summarizeRelatedActivity(
  storeRunning: boolean,
  totalFlows: number,
  bytesOut: number,
  bytesIn: number,
  distinctPeers: number,
  peers: Array<{ peer: string; bytes: number }>,
  events: EventRow[],
): string {
  const clauses: string[] = [];

  if (!storeRunning) {
    clauses.push("Flow collector is not running — only logged events are shown");
  } else if (totalFlows === 0) {
    clauses.push(
      "No collected flows to/from this IP yet (collection is forward-only; expand the window or wait for traffic)",
    );
  } else {
    const peerWord = distinctPeers === 1 ? "peer" : "peers";
    let flowClause = `${totalFlows} flow${totalFlows === 1 ? "" : "s"} across ${distinctPeers} ${peerWord}`;
    if (bytesOut || bytesIn) flowClause += `; ${humanBytes(bytesOut)} out / ${humanBytes(bytesIn)} in`;
    // Name the heaviest correspondents by bytes — "who is this host talking to
    // most", and the most likely exfiltration destinations. `peers` is already
    // sorted by bytes descending; skip zero-byte peers so the list stays signal.
    const topPeers = peers
      .filter((p) => p.bytes > 0)
      .slice(0, 3)
      .map((p) => `${p.peer} (${humanBytes(p.bytes)})`);
    if (topPeers.length) flowClause += `; heaviest ${topPeers.join(", ")}`;
    clauses.push(flowClause);
  }

  if (events.length > 0) {
    const sevCounts = new Map<string, number>();
    for (const e of events) {
      const sev = (e.severity ?? "").toString().trim().toLowerCase() || "unknown";
      sevCounts.set(sev, (sevCounts.get(sev) ?? 0) + 1);
    }
    const sevMix = [...sevCounts.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .map(([sev, count]) => `${sev}×${count}`);
    clauses.push(`${events.length} logged event${events.length === 1 ? "" : "s"} (${sevMix.join(", ")})`);
  }

  return clauses.join(". ") + ".";
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
    note: summarizeRelatedActivity(!!store, raw.length, bytesOut, bytesIn, peerMap.size, peers, events),
  };
}

export interface SurroundingResult {
  windowMinutes: number;
  events: EventRow[];
  connections: ConnectionsResult | null;
  dns: DnsResult | null;
  firewallBlocks: FirewallBlocksResult | null;
  flows: FlowsResult;
  /**
   * Top-level triage line for the investigation overview. `surrounding` joins the
   * window's logged alert events with the live per-host snapshots (connections,
   * DNS, firewall blocks, flows), each of which carries its own note — but the
   * composite had none, forcing the operator to open every sub-view to learn
   * whether it held anything. This rolls the picture into one line: the
   * logged-event tail (count, severity mix, and how the nearest event sits in
   * time relative to the alert) plus a compact "live snapshot" of which sub-views
   * actually have content, so the operator knows where to look first.
   */
  note?: string;
}

/**
 * Compose the top-level triage note for a `surrounding` snapshot from the
 * window's logged events and the already-collected per-host sub-snapshots.
 * Summarizes the event tail (count, severity mix, nearest-to-alert timing) and
 * appends a compact pointer at which live snapshots hold content. The collector
 * caveat is preserved so "flow collector off" reads distinctly from a host with
 * zero flows.
 */
function summarizeSurrounding(
  events: EventRow[],
  timeMs: number,
  windowMinutes: number,
  conn: ConnectionsResult | null,
  dns: DnsResult | null,
  blocks: FirewallBlocksResult | null,
  flows: FlowsResult,
): string {
  const clauses: string[] = [];

  if (events.length === 0) {
    clauses.push(`No other logged events in the ±${windowMinutes}m window`);
  } else {
    const sevCounts = new Map<string, number>();
    let nearest: number | undefined;
    for (const e of events) {
      const sev = (e.severity ?? "").toString().trim().toLowerCase() || "unknown";
      sevCounts.set(sev, (sevCounts.get(sev) ?? 0) + 1);
      if (typeof e.time === "number") {
        const delta = e.time - timeMs;
        if (nearest === undefined || Math.abs(delta) < Math.abs(nearest)) nearest = delta;
      }
    }
    const sevMix = [...sevCounts.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .map(([sev, count]) => `${sev}×${count}`);
    let clause = `${events.length} logged event${events.length === 1 ? "" : "s"} in the ±${windowMinutes}m window (${sevMix.join(", ")})`;
    if (nearest !== undefined) clause += `; nearest ${relativeToAlert(nearest)}`;
    clauses.push(clause);
  }

  // Point at which live per-host snapshots actually hold content, so the operator
  // knows which sub-view to open first. Omit a sub-view entirely when it failed
  // to collect (null), but keep the flow collector's off-state explicit.
  const snapshot: string[] = [];
  if (conn) snapshot.push(`${conn.count} active session${conn.count === 1 ? "" : "s"}`);
  if (blocks) snapshot.push(`${blocks.count} firewall block${blocks.count === 1 ? "" : "s"}`);
  if (!flows.available) snapshot.push("flow collector off");
  else snapshot.push(`${flows.count} flow${flows.count === 1 ? "" : "s"}`);
  if (dns) snapshot.push(`${dns.total} DNS quer${dns.total === 1 ? "y" : "ies"}`);
  if (snapshot.length) clauses.push(`live snapshot: ${snapshot.join(", ")}`);

  return clauses.join(". ") + ".";
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

  const flows = flowsAround(timeMs, ips, win);
  return {
    windowMinutes: win,
    events,
    connections: conn,
    dns,
    firewallBlocks: blocks,
    flows,
    note: summarizeSurrounding(events, timeMs, win, conn, dns, blocks, flows),
  };
}
