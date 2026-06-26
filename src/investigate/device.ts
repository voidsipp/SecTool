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
import { SEVERITY_ORDER, type Severity } from "../types.ts";
import { agentConnections, agentHealth, type AgentMatch } from "../agent/agentClient.ts";
import { enrichIp, type Enrichment } from "./enrich.ts";
import { protoName } from "./udm.ts";
import { getActiveFlowStore } from "../netflow/flowAccess.ts";
import { alertStore } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";

// Collapse the IPv6 wrappers a host's socket/flow source can emit so address
// matching sees a single canonical form. Strips "[::1]" brackets and unwraps
// IPv4-mapped IPv6 ("::ffff:192.168.1.5" -> "192.168.1.5"), mirroring the same
// normalisation done in classifyExposure for listener bind addresses.
function normalizeIp(ip: string): string {
  let a = ip.trim().toLowerCase();
  if (a.startsWith("[") && a.endsWith("]")) a = a.slice(1, -1); // strip "[::1]" brackets
  const mapped = a.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/); // unwrap IPv4-mapped IPv6
  return mapped ? mapped[1] : a;
}

// Normalise first so the IPv4 private-range checks also catch LAN hosts reported
// in IPv4-mapped IPv6 form. Without this an internal peer arriving as
// "::ffff:10.0.0.5" slips past the gate and is mis-audited as a public/external
// egress destination (then needlessly enriched and risk-scored).
function isPrivateIp(ip: string): boolean {
  const a = normalizeIp(ip);
  return (
    /^10\./.test(a) ||
    /^192\.168\./.test(a) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(a) ||
    /^127\./.test(a) ||
    /^169\.254\./.test(a) ||
    /^0\./.test(a) ||
    /^(::1|fe80|fc|fd)/.test(a)
  );
}

const WILDCARD = new Set(["", "*", "0.0.0.0", "::", "[::]"]);

// Position of a severity on the info→critical scale (-1 if unknown), mirroring
// the sevRank helper used across the analytics modules so ordering stays
// consistent wherever severities are compared.
function sevRank(s: string | undefined): number {
  return (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
}

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
  /**
   * True when this peer's IP is on the operator's firewall blocklist. Seeing a
   * blocked IP still exchanging flows with the host is a red flag — a routing
   * leak or an endpoint reaching the peer over a path that bypasses the gateway.
   */
  blocked?: boolean;
  /** True when this peer's IP matches the operator's watchlist (IP or CIDR). */
  watched?: boolean;
  /** The watchlist entry's free-form note, when the peer is watched and one exists. */
  watchNote?: string;
  /**
   * Destination ports this host reached this (external) peer on that are
   * suspicious as outbound targets — remote-control backdoors, botnet C2, or
   * services that should never traverse the WAN. The no-agent mirror of
   * `egressAudit`'s check: a host beaconing to one of these on a public IP is a
   * compromise signal even at trivial volume. Only set for external peers, and
   * only when one matched. See `SUSPICIOUS_EGRESS_PORTS`.
   */
  suspiciousPorts?: number[];
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
    /** Peers whose IP is on the firewall blocklist (see `flagged`). */
    blockedPeers: number;
    /** Peers whose IP matches the watchlist (see `flagged`). */
    watchedPeers: number;
    /**
     * External peers this host reached on a suspicious outbound destination port
     * (backdoor/C2/should-not-traverse-WAN) — see `flagged` and each peer's
     * `suspiciousPorts`.
     */
    suspiciousEgressPeers: number;
  };
  topPeers?: TrafficPeer[];
  topPorts?: TrafficPort[];
  alerts?: TrafficAlert[];
  /**
   * Peers that matched the operator's blocklist and/or watchlist, ranked by
   * total bytes. Surfaced separately from `topPeers` so a flagged-but-low-volume
   * peer is never lost to the top-N byte cut. Empty/omitted when nothing matched.
   */
  flagged?: TrafficPeer[];
  /**
   * Human-readable caveat over this host's activity, leading with the strongest
   * signal: fired IDS/IPS detections first (peak severity + direction), then
   * suspicious outbound ports, then firewall-blocklist hits, then watchlist
   * matches (naming the operator's own notes for *why* each address is watched).
   * Undefined when nothing notable was found.
   */
  note?: string;
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
      // Flag suspicious *outbound* destination ports on external peers — the
      // no-agent mirror of egressAudit's SUSPICIOUS_EGRESS_PORTS check. A host
      // beaconing to a backdoor/C2 port on a public IP is a compromise signal
      // even at trivial volume, and this NetFlow view is the only host-level
      // signal available when the endpoint agent is offline. Pure local lookup.
      if (p.external && f.dstPort && SUSPICIOUS_EGRESS_PORTS[f.dstPort]) {
        if (!p.suspiciousPorts) p.suspiciousPorts = [];
        if (!p.suspiciousPorts.includes(f.dstPort)) p.suspiciousPorts.push(f.dstPort);
      }
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

  // Offline threat correlation: cross-reference every peer against the operator's
  // own firewall blocklist and watchlist. This is a pure local join — no agent,
  // no external API — yet it surfaces the most actionable signal a flow view can
  // give: this host is still trading traffic with an IP you've already blocked
  // (a routing leak or an endpoint reaching it off-gateway) or one you're
  // explicitly watching. We tag each peer and tally the matches.
  let blockedPeers = 0;
  let watchedPeers = 0;
  let suspiciousEgressPeers = 0;
  for (const p of peers.values()) {
    if (blockStore.has(p.ip)) {
      p.blocked = true;
      blockedPeers++;
    }
    const w = watchStore.match(p.ip);
    if (w) {
      p.watched = true;
      if (w.note) p.watchNote = w.note;
      watchedPeers++;
    }
    if (p.suspiciousPorts?.length) {
      p.suspiciousPorts.sort((a, b) => a - b);
      suspiciousEgressPeers++;
    }
  }

  const topPeers = [...peers.values()]
    .sort((a, b) => b.bytesIn + b.bytesOut - (a.bytesIn + a.bytesOut))
    .slice(0, 15);
  topPeers.forEach((p) => p.ports.sort((a, b) => a - b));
  // Flagged peers get their own list (ranked by volume) so a blocked/watched peer
  // — or one reached on a suspicious outbound port — is never hidden below the
  // 15-peer byte cut above (a low-volume C2 beacon is exactly what to surface).
  const flagged = [...peers.values()]
    .filter((p) => p.blocked || p.watched || (p.suspiciousPorts?.length ?? 0) > 0)
    .sort((a, b) => b.bytesIn + b.bytesOut - (a.bytesIn + a.bytesOut))
    .slice(0, 20);
  flagged.forEach((p) => p.ports.sort((a, b) => a - b));
  const topPorts = [...ports.values()].sort((a, b) => b.flows - a.flows).slice(0, 12);

  // Collect this host's recent IDS/IPS detections. The displayed list is capped
  // at 20 (most-recent-first, since alertStore.all() is time-descending), but we
  // tally severity and direction across *every* matching alert in the window so
  // the summary note below reflects the true picture, not just the first 20.
  const alerts: TrafficAlert[] = [];
  let alertCount = 0;
  let alertPeak: Severity = "info";
  let alertsFromHost = 0; // host was the source (outbound — possible beaconing/scanning)
  let alertsToHost = 0; // host was the target (inbound — being attacked)
  for (const a of alertStore.all()) {
    if (a.time < since) continue;
    const to = a.dstIp === host;
    const from = a.srcIp === host;
    if (!to && !from) continue;
    alertCount++;
    if (sevRank(a.severity) > sevRank(alertPeak)) alertPeak = a.severity as Severity;
    if (from) alertsFromHost++;
    else alertsToHost++;
    if (alerts.length < 20) {
      alerts.push({
        id: a.id,
        time: a.time,
        severity: a.severity,
        signature: a.signature ?? a.category ?? "—",
        direction: from ? "from" : "to",
      });
    }
  }

  const notes: string[] = [];
  // Lead with the most concrete compromise evidence: a fired IDS/IPS signature is
  // a confirmed detection, not an inference from flow shape. Name the peak
  // severity and whether the host was the source (likely beaconing/scanning out)
  // or the target (being attacked) so the takeaway is actionable without opening
  // the alerts list. Tallied across the full window above, not just the shown 20.
  if (alertCount > 0) {
    const peakNote = alertPeak === "info" ? "all informational" : `peak severity ${alertPeak}`;
    let dir: string;
    if (alertsFromHost > 0 && alertsToHost > 0) {
      dir = `${alertsFromHost} originated from the host, ${alertsToHost} targeted it`;
    } else if (alertsFromHost > 0) {
      dir = "all originated from the host — possible outbound beaconing or scanning";
    } else {
      dir = "all targeted the host";
    }
    notes.push(
      `${alertCount} IDS/IPS alert(s) involve this host in this window (${peakNote}); ${dir}. Review the alerts list.`,
    );
  }
  // Next, the strongest flow-derived compromise signal: an internal host reaching
  // a public IP on a backdoor/C2/should-not-traverse-WAN port. Name the actual
  // ports so the takeaway is actionable without scanning the flagged list.
  if (suspiciousEgressPeers > 0) {
    const susPorts = [
      ...new Set(
        [...peers.values()].flatMap((p) => p.suspiciousPorts ?? []),
      ),
    ].sort((a, b) => a - b);
    notes.push(
      `${suspiciousEgressPeers} external peer(s) were reached on suspicious outbound port(s) ` +
        `(${susPorts.join(", ")}) — remote-control backdoors, botnet C2, or services that should ` +
        `never traverse the WAN; a classic compromised-host signal even at low volume. Review the flagged peers.`,
    );
  }
  if (blockedPeers > 0) {
    notes.push(
      `${blockedPeers} peer(s) on the firewall blocklist are still exchanging traffic with this host — ` +
        `a routing leak or an endpoint reaching them off-gateway; investigate the flagged peers.`,
    );
  }
  if (watchedPeers > 0) {
    // Surface the operator's own annotations on the matched watchlist entries so
    // the takeaway says *why* these addresses are watched (mirroring egressAudit),
    // not just how many matched. Distinct, ordered, and length-capped so a long
    // or noisy free-form note can't dominate the summary line.
    const watchNotes = [
      ...new Set(
        [...peers.values()]
          .filter((p) => p.watched && p.watchNote)
          .map((p) => p.watchNote!.replace(/\s+/g, " ").trim())
          .filter((n) => n.length > 0),
      ),
    ];
    let detail = "";
    if (watchNotes.length > 0) {
      const shown = watchNotes.slice(0, 3).map((n) => (n.length > 80 ? `${n.slice(0, 79)}…` : n));
      const more = watchNotes.length - shown.length;
      detail = ` (note: ${shown.join("; ")}${more > 0 ? `; +${more} more` : ""})`;
    }
    notes.push(`${watchedPeers} watchlisted peer(s) seen in this window${detail}.`);
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
      blockedPeers,
      watchedPeers,
      suspiciousEgressPeers,
    },
    topPeers,
    topPorts,
    alerts,
    flagged: flagged.length > 0 ? flagged : undefined,
    note: notes.length > 0 ? notes.join(" ") : undefined,
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
  /**
   * Set only when the agent couldn't report this port's bind address (so
   * `exposure` is "unknown") but the gateway's collected NetFlow shows the port
   * accepted at least one off-host connection — hard proof it's network-reachable
   * regardless of the missing bind data. `external` is true when one of those
   * peers was a public IP; `peers` is the distinct off-host source count.
   */
  observedInbound?: { external: boolean; peers: number };
}

export interface ListenerAudit {
  ok: boolean;
  host?: string;
  error?: string;
  count?: number;
  /**
   * Listeners bound to *all* interfaces (a wildcard bind, exposure
   * "all-interfaces") — the most-open binding and a strict subset of
   * `networkReachable`. A listener bound to a single network interface is also
   * reachable off-host but is *not* counted here; see `networkReachable` for the
   * full externally-reachable surface.
   */
  exposed?: number;
  /**
   * Total listeners reachable from off this host — the device's externally
   * facing attack surface. Counts every listener bound to a network interface
   * (exposure "all-interfaces" or "specific") plus any whose bind address was
   * missing but the gateway's NetFlow proves accepted an off-host connection
   * (exposure "unknown" with `observedInbound`). Localhost-only bindings and
   * unknown bindings with no corroborating flow are excluded — we only ever
   * count positive reachability evidence. A superset of both `exposed` and
   * `risky`. Present (and > 0) only when at least one reachable listener exists.
   */
  networkReachable?: number;
  /** Listeners flagged as a dangerous, network-reachable attack surface. */
  risky?: number;
  listeners?: Listener[];
  /** Installed agent version, resolved from /health when bind data was missing. */
  agentVersion?: string;
  /**
   * Number of listeners whose exposure was unknown (no bind address) but which
   * collected NetFlow proves are network-reachable, by showing an off-host peer
   * connecting into the port. Present (and > 0) only when that corroboration
   * fired; see each listener's `observedInbound`.
   */
  corroborated?: number;
  /**
   * Number of network-reachable sensitive services the gateway's NetFlow proves
   * were reached from a *public* peer (each such listener has
   * `observedInbound.external === true`). This is the hardest internet-exposure
   * signal the audit can produce — a sensitive service with a recorded public
   * connection — so it leads the `note`. Present (and > 0) only when at least one
   * fired; a subset of `risky`.
   */
  internetExposed?: number;
  /**
   * Human-readable caveats about this audit, joined into one string. Leads with
   * any sensitive services NetFlow proves were reached from a public peer (the
   * hardest internet-exposure signal; see `internetExposed`), then a summary of
   * all network-reachable sensitive services found (so the operator sees what to
   * lock down without scanning the list), and/or notes that the
   * agent couldn't report bind addresses — in which case exposure is "unknown" and
   * the note suggests how to recover it (upgrade the agent, or, for a current agent
   * hitting a platform limitation, a platform-appropriate on-host check command).
   * When bind data is missing, the note also reports what the gateway's NetFlow
   * could (or couldn't) corroborate about those ports' reachability, so an
   * "unknown" exposure still yields an actionable takeaway (see `agentVersion`
   * and `corroborated`). Undefined when there is nothing to flag.
   */
  note?: string;
}

// Agents at this version or newer report each socket's bind address (localAddr),
// letting us classify exposure precisely. Older agents omit it, so every listener
// falls back to "unknown" exposure and risk classification is degraded.
const MIN_BIND_ADDR_VERSION = "1.0.2";

/** True when dotted version `a` is strictly older than `b` (e.g. 1.0.1 < 1.0.2). */
function versionLt(a: string, b: string): boolean {
  const pa = a.split(".");
  const pb = b.split(".");
  for (let i = 0; i < 3; i++) {
    const x = Number(pa[i] ?? 0) || 0;
    const y = Number(pb[i] ?? 0) || 0;
    if (x < y) return true;
    if (x > y) return false;
  }
  return false;
}

// Manual command an operator can run *on the host* to read each listener's bind
// address directly, for the case where even a current agent's snapshot omits it (a
// platform/socket-API limitation an upgrade won't fix). Keyed by the value the
// agent's /health reports for `platform` (Node's process.platform). Falls back to a
// portable suggestion for anything unrecognised so the note stays actionable.
function manualBindCheckHint(platform: string | undefined): string {
  switch (platform) {
    case "win32":
      return "run `netstat -ano` (or `Get-NetTCPConnection -State Listen`) on the host";
    case "linux":
      return "run `ss -tulpn` on the host";
    case "darwin":
      return "run `lsof -nP -iTCP -sTCP:LISTEN` (and `lsof -nP -iUDP`) on the host";
    case "freebsd":
    case "openbsd":
    case "netbsd":
      return "run `sockstat -l` on the host";
    default:
      return "run the host's socket-listing tool (e.g. `ss -tulpn` or `netstat -an`)";
  }
}

// When no listener reported a bind address, exposure is shown as "unknown" and we
// can't tell a safe localhost-only service from a network-exposed one. Rather than
// blindly telling the operator to upgrade, query the agent's /health to name the
// exact installed version so the note is precise and actionable.
async function bindExposureNote(
  cfg: Config,
  host: string,
): Promise<{ note: string; agentVersion?: string }> {
  const h = await agentHealth(cfg, host);
  const version =
    h.ok && h.data && typeof (h.data as { version?: unknown }).version === "string"
      ? (h.data as { version: string }).version
      : undefined;
  if (!version) {
    return {
      note:
        `This agent didn't report which interface each port is bound to, so exposure is shown as "unknown". ` +
        `Update the agent to v${MIN_BIND_ADDR_VERSION}+ (re-run the installer) to map every port to its bind address.`,
    };
  }
  if (versionLt(version, MIN_BIND_ADDR_VERSION)) {
    return {
      agentVersion: version,
      note:
        `Agent on this host is v${version}, which can't report port bind addresses — exposure is shown as "unknown" ` +
        `and risk classification can't distinguish localhost-only from network-exposed services. ` +
        `Update to v${MIN_BIND_ADDR_VERSION}+ (re-run the installer) for accurate results.`,
    };
  }
  // A current-enough agent that still surfaced no bind address (e.g. a platform
  // whose snapshot omits local addresses): an upgrade won't fix this, so instead of
  // a dead-end "unknown", point the operator at a direct on-host check — using the
  // platform /health reports to name the exact command (mirroring how we name the
  // exact version above so the note stays precise and actionable).
  const platform =
    h.ok && h.data && typeof (h.data as { platform?: unknown }).platform === "string"
      ? (h.data as { platform: string }).platform
      : undefined;
  return {
    agentVersion: version,
    note:
      `Agent v${version} is current but didn't report a bind address for any listener — likely a ` +
      `platform limitation an upgrade won't resolve — so exposure is shown as "unknown" for this host. ` +
      `To confirm which ports face the network, ${manualBindCheckHint(platform)}.`,
  };
}

function classifyExposure(localAddr: string | undefined): Listener["exposure"] {
  if (localAddr === undefined) return "unknown";
  let a = localAddr.trim().toLowerCase();
  // Normalise IPv6 spellings before matching. Agents report bind addresses in
  // whatever form the host's socket API emits, so the same loopback/wildcard
  // can arrive several ways. Without this, a dual-stack service bound to mapped
  // loopback (e.g. "::ffff:127.0.0.1") is misread as "specific" — a network
  // interface — and then false-flagged as a risky, off-host attack surface.
  if (a.startsWith("[") && a.endsWith("]")) a = a.slice(1, -1); // strip "[::1]" brackets
  const mapped = a.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/); // unwrap IPv4-mapped IPv6
  if (mapped) a = mapped[1];
  if (WILDCARD.has(a)) return "all-interfaces";
  if (a.startsWith("127.") || a === "::1") return "localhost";
  return "specific";
}

/**
 * Traffic-based fallback for when the agent can't report bind addresses. The
 * gateway's collected NetFlow records connections crossing it, so any flow *into*
 * host:port is proof the port accepted an off-host connection — loopback traffic
 * never reaches the gateway. That lets us recover exposure the agent couldn't
 * surface. We only ever read this as positive evidence: NetFlow is packet-sampled
 * and blind to intra-subnet L2 traffic, so the *absence* of a flow never proves a
 * port is private. Returns the set of reachable ports keyed by port number, plus
 * whether a flow store was even available to consult.
 */
function flowExposureEvidence(
  host: string,
  hours = 24,
): { storeActive: boolean; reachablePorts: Map<number, { external: boolean; peers: number }> } {
  const reachablePorts = new Map<number, { external: boolean; peers: number }>();
  const store = getActiveFlowStore();
  if (!store) return { storeActive: false, reachablePorts };

  const target = normalizeIp(host);
  const now = Date.now();
  const since = now - Math.min(Math.max(1, Math.floor(hours) || 24), 168) * 3_600_000;
  const flows = store.query([host], since, now, 200_000);

  // Collect the distinct off-host source IPs seen reaching each local port.
  const peersByPort = new Map<number, Set<string>>();
  for (const f of flows) {
    if (!f.dstPort || normalizeIp(f.dstIp ?? "") !== target) continue; // inbound to this host's port
    const peer = normalizeIp(f.srcIp ?? "");
    if (!peer || peer === target) continue; // ignore self / unlabelled flows
    let set = peersByPort.get(f.dstPort);
    if (!set) {
      set = new Set();
      peersByPort.set(f.dstPort, set);
    }
    set.add(peer);
  }

  for (const [port, peers] of peersByPort) {
    const external = [...peers].some((p) => isIP(p) !== 0 && !isPrivateIp(p));
    reachablePorts.set(port, { external, peers: peers.size });
  }
  return { storeActive: true, reachablePorts };
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

// True when a listener is reachable from off this host — bound to a network
// interface (all-interfaces or a specific non-loopback address), or, when the
// bind address was missing, proven reachable by an off-host NetFlow connection.
// Localhost-only and unknown-without-evidence bindings are not counted: we only
// ever treat positive evidence as reachability (mirroring flowExposureEvidence).
function isNetworkReachable(l: Listener): boolean {
  return (
    l.exposure === "all-interfaces" ||
    l.exposure === "specific" ||
    (l.exposure === "unknown" && l.observedInbound !== undefined)
  );
}

// A listener is risky when a sensitive service is bound somewhere reachable from
// off the host. Localhost-only bindings are safe regardless of the service.
function classifyListenerRisk(l: Listener): string[] {
  if (l.exposure === "localhost") return [];
  const svc = RISKY_SERVICES[l.port];
  if (!svc) return [];
  // Prefer NetFlow-corroborated wording: when the bind address was missing but
  // observed traffic proves the port is reachable, say so concretely instead of
  // hedging with "possibly". Include the distinct off-host peer breadth the flow
  // evidence already counted — a sensitive port probed by one peer is a very
  // different threat than one reached by dozens, so the operator can triage by
  // how widely it is actually being hit rather than just whether it's reachable.
  let where: string;
  if (l.observedInbound) {
    const n = l.observedInbound.peers;
    const breadth = `${n} distinct off-host peer${n === 1 ? "" : "s"}`;
    where = l.observedInbound.external
      ? `confirmed reached from a public peer, by ${breadth} (seen in gateway NetFlow)`
      : `confirmed reachable off-host, by ${breadth} (seen in gateway NetFlow)`;
  } else if (l.exposure === "all-interfaces") {
    where = "exposed on all interfaces";
  } else if (l.exposure === "specific") {
    where = "bound to a network interface";
  } else {
    where = "possibly network-exposed (agent can't confirm the bind address)";
  }
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
  // When the agent couldn't report any bind address, recover what exposure we
  // can from observed traffic: a recorded inbound flow to host:port proves the
  // port is network-reachable. Do this before risk classification so risky
  // services inherit the corroborated, evidence-based wording.
  let corroborated = 0;
  let corroboratedExternal = 0;
  // Peak distinct off-host peer count on any single corroborated port. A peak
  // (not a sum) so the figure stays accurate even when one peer reaches several
  // ports — summing per-port counts would double-count that peer.
  let corroboratedPeerPeak = 0;
  // The actual port numbers NetFlow corroborated, so the note can name them
  // instead of only counting them — on an unknown-bind host the operator has no
  // bind data to cross-reference, so a bare count isn't directly actionable.
  const corroboratedPorts: number[] = [];
  let flowStoreActive = false;
  if (!sawLocalAddr && listeners.length > 0) {
    const evidence = flowExposureEvidence(host);
    flowStoreActive = evidence.storeActive;
    for (const l of listeners) {
      const hit = evidence.reachablePorts.get(l.port);
      if (!hit) continue;
      l.observedInbound = hit;
      corroborated++;
      corroboratedPorts.push(l.port);
      if (hit.external) corroboratedExternal++;
      if (hit.peers > corroboratedPeerPeak) corroboratedPeerPeak = hit.peers;
    }
  }
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
  // Build the operator-facing caveats. Only chase the agent's version when bind
  // data is genuinely missing AND there is something to report — a host with no
  // listeners needs no upgrade nag.
  const notes: string[] = [];
  let agentVersion: string | undefined;
  if (!sawLocalAddr && listeners.length > 0) {
    const info = await bindExposureNote(cfg, host);
    agentVersion = info.agentVersion;
    // Turn the "exposure is unknown" dead-end into an actionable takeaway by
    // reporting what the gateway's NetFlow could corroborate about these ports.
    let note = info.note;
    if (corroborated > 0) {
      // Name the exact ports so the operator can go check them directly, and only
      // point at "the flagged listeners" when a corroborated port is actually a
      // known-sensitive service — otherwise that reference dangles (nothing is
      // flagged) and we instead prompt a generic exposure review.
      const portList = corroboratedPorts
        .slice()
        .sort((a, b) => a - b)
        .join(", ");
      const corroboratedRisky = listeners.filter((l) => l.observedInbound && l.risk).length;
      note +=
        ` However, the gateway's NetFlow recorded off-host connections to ${corroborated} of these port(s) (${portList})` +
        (corroboratedExternal > 0 ? `, ${corroboratedExternal} from a public peer,` : "") +
        (corroboratedPeerPeak > 1
          ? ` reached by as many as ${corroboratedPeerPeak} distinct peers on a single port,`
          : "") +
        ` confirming they are network-reachable regardless` +
        (corroboratedRisky > 0
          ? ` — see the flagged listeners.`
          : `; none match a known-sensitive service, but review whether each should be reachable off-host.`);
    } else if (flowStoreActive) {
      note +=
        ` Collected NetFlow shows no off-host connections to these ports, but flow data is` +
        ` packet-sampled and blind to intra-subnet traffic, so that is not proof they are private.`;
    }
    notes.push(note);
  }
  // Lead with the actionable takeaway: name the dangerous, network-reachable
  // services so they can't be lost among a long listener list.
  const risky = listeners.filter((l) => l.risk);
  // The sharpest subset: sensitive services the gateway's NetFlow proves were
  // reached from a *public* peer (not just bound to a network interface). That is
  // concrete evidence of internet exposure — the listener-audit equivalent of the
  // egress audit's bypassed-blocklist hit — so it must lead the note, ahead of the
  // broader "network-reachable" set, and it's also exported structurally.
  const internetExposed = risky.filter((l) => l.observedInbound?.external);
  // The host's full externally-reachable surface: everything bound to a network
  // interface plus any NetFlow-corroborated "unknown" port (superset of risky
  // and exposed). Reported so the summary isn't limited to the all-interfaces count.
  const networkReachable = listeners.filter(isNetworkReachable).length;
  if (risky.length > 0) {
    const names = [
      ...new Set(risky.map((l) => RISKY_SERVICES[l.port]?.name ?? `port ${l.port}`)),
    ];
    notes.unshift(
      `${risky.length} network-reachable sensitive service(s) detected (${names.join(", ")}) — ` +
        `review whether each should be exposed off-host.`,
    );
  }
  if (internetExposed.length > 0) {
    const exposedNames = [
      ...new Set(internetExposed.map((l) => RISKY_SERVICES[l.port]?.name ?? `port ${l.port}`)),
    ];
    notes.unshift(
      `${internetExposed.length} sensitive service(s) confirmed reached from a public peer ` +
        `in gateway NetFlow (${exposedNames.join(", ")}) — treat as internet-exposed and lock down immediately.`,
    );
  }

  return {
    ok: true,
    host: r.host,
    count: listeners.length,
    exposed: listeners.filter((l) => l.exposure === "all-interfaces").length,
    networkReachable: networkReachable > 0 ? networkReachable : undefined,
    risky: risky.length,
    listeners,
    agentVersion,
    corroborated: corroborated > 0 ? corroborated : undefined,
    internetExposed: internetExposed.length > 0 ? internetExposed.length : undefined,
    note: notes.length > 0 ? notes.join(" ") : undefined,
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
  /**
   * True when this public peer matches the operator's watchlist (IP or CIDR).
   * An internal host reaching a watchlisted external address is exactly the
   * activity the watchlist exists to catch, so we flag it as risk — mirroring
   * the block/watch correlation the sibling `trafficProfile` tool performs.
   */
  watched: boolean;
  /** The watchlist entry's free-form note, when the peer is watched and one exists. */
  watchNote?: string;
  /**
   * Destination ports this peer was reached on that are suspicious as outbound
   * targets (remote-control backdoors, botnet C2, or services that should never
   * traverse the WAN). Empty when none matched. See `SUSPICIOUS_EGRESS_PORTS`.
   */
  suspiciousPorts: number[];
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
  /**
   * Audited peers whose IP is on the operator's firewall blocklist. The agent
   * reports the host's *actual* socket connections, so a connection to a blocked
   * address means the host is still reaching an IP the firewall is meant to drop
   * — the block is being bypassed (an off-gateway path/VPN, or a rule that isn't
   * catching this traffic). The strongest egress signal here: an explicit
   * operator decision being violated, not a heuristic.
   */
  blockedCount?: number;
  /** Audited peers whose IP matches the operator's watchlist (IP or CIDR). */
  watchedCount?: number;
  /**
   * True when at least one authoritative reputation source (VirusTotal,
   * AbuseIPDB) was unavailable, so peers were scored only against the local
   * blocklist and keyless threat feeds. A low `riskyCount` is then a coverage
   * gap, not a clean bill of health — see `note` for specifics.
   */
  reputationDegraded?: boolean;
  peers?: EgressPeer[];
  /**
   * Human-readable caveats over this audit, leading with the strongest signals:
   * firewall-blocklist egress (a bypassed block), then suspicious outbound ports
   * (naming the actual destination port numbers), then watchlist matches (naming
   * the operator's own notes for *why* each address is watched), then result
   * truncation and/or degraded enrichment. Undefined when there is nothing to flag.
   */
  note?: string;
  /**
   * Audited peers reached on a destination port that is suspicious as an
   * *outbound* target (remote-control backdoor, botnet C2, or a service that
   * should never traverse the WAN). See each peer's `suspiciousPorts`.
   */
  suspiciousPortCount?: number;
}

// Destination ports that are strongly suspicious as the *target* of an outbound
// connection from an internal host to a public IP. This is the egress mirror of
// the listener `RISKY_SERVICES` table: that one flags dangerous services
// *exposed on* the host, while this flags the host *reaching out* to a port that
// legitimate client software rarely contacts across the open internet —
// remote-control backdoors, botnet C2 rendezvous, and services that should stay
// on the LAN. A host beaconing to one of these is a classic compromise/exfil
// signal even at trivial volume, so matching peers are always enriched (never
// lost to the busiest-N cut) and risk-flagged. Purely offline: a local lookup on
// already-collected port numbers, no agent round-trip or external API call.
// Keyed by port; the value is the operator-facing reason fragment.
const SUSPICIOUS_EGRESS_PORTS: Record<number, string> = {
  23: "Telnet — IoT-worm (Mirai-class) propagation",
  2323: "Telnet alt-port — IoT-worm propagation",
  139: "NetBIOS to the internet — legacy SMB exposure",
  445: "SMB to the internet — worm spread / data exfiltration",
  1080: "SOCKS proxy — common malware relay",
  1337: "common backdoor port",
  3389: "RDP out to the internet — remote-desktop pivot",
  4444: "Metasploit/Meterpreter default callback",
  4445: "Metasploit alt callback",
  5555: "Android Debug Bridge / RAT control",
  5900: "VNC out to the internet — remote-desktop pivot",
  6667: "IRC — classic botnet C2 channel",
  6697: "IRC over TLS — botnet C2 channel",
  31337: '"elite" backdoor port (Back Orifice-class)',
};

/** The subset of `ports` that are suspicious outbound targets, paired with why. */
function suspiciousEgressPorts(ports: Iterable<number>): { port: number; why: string }[] {
  const out: { port: number; why: string }[] = [];
  for (const p of ports) {
    const why = SUSPICIOUS_EGRESS_PORTS[p];
    if (why) out.push({ port: p, why });
  }
  return out.sort((a, b) => a.port - b.port);
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
    if (!c.remoteIp || isIP(c.remoteIp) === 0 || isPrivateIp(c.remoteIp)) continue;
    // Collapse IPv4-mapped IPv6 to its dotted form so a peer reached both ways
    // aggregates into one entry and is enriched as a plain IPv4 address.
    const ip = normalizeIp(c.remoteIp);
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
  const all = [...byIp.values()];

  // Peers of interest are enriched and surfaced regardless of connection volume:
  // those on the firewall blocklist/watchlist, and those reached on a suspicious
  // outbound destination port (backdoor/C2/should-not-traverse-WAN). A low-traffic
  // beacon to a watched, blocked, or backdoor-port address is precisely the egress
  // that must never be lost to the busiest-N enrichment cut — and all three checks
  // are pure local joins (no agent/API call), so always including these peers costs
  // nothing extra and keeps `watchedCount`/`blocked`/`suspiciousPorts` accurate
  // across the whole peer set rather than just the top slice. The remaining bounded
  // enrichment budget then goes to the busiest peers that aren't already of interest.
  const isFlagged = (a: Agg): boolean => blockStore.has(a.ip) || watchStore.match(a.ip) !== undefined;
  const isOfInterest = (a: Agg): boolean => isFlagged(a) || suspiciousEgressPorts(a.ports).length > 0;
  const interestAggs = all.filter(isOfInterest);
  const busiest = all
    .filter((a) => !isOfInterest(a))
    .sort((a, b) => b.conns - a.conns)
    .slice(0, Math.max(0, MAX_ENRICH - interestAggs.length));
  const top = [...interestAggs, ...busiest];

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
      if (blocked) reasons.push("on firewall blocklist");
      // Offline watchlist correlation — a pure local join (no agent/API). The
      // operator flagged this address for close monitoring; an internal host
      // reaching it is precisely the egress we want surfaced.
      const watch = watchStore.match(a.ip);
      const watched = watch !== undefined;
      if (watched) reasons.push(watch!.note ? `on watchlist: ${watch!.note}` : "on watchlist");
      // Suspicious outbound destination ports — a pure local join (no agent/API).
      // A host reaching a public IP on a backdoor/C2/should-not-traverse-WAN port
      // is a strong compromise signal independent of the peer's reputation.
      const susPorts = suspiciousEgressPorts(a.ports);
      for (const s of susPorts) reasons.push(`outbound to :${s.port} (${s.why})`);
      // hosting/proxy alone are weak signals — only flag risk on a real verdict
      // or an explicit operator/behavioral signal (blocklist/watchlist/bad port).
      const risk =
        vtBad > 0 || abuse >= 50 || (e?.feeds.length ?? 0) > 0 || blocked || watched || susPorts.length > 0;
      return {
        ip: a.ip,
        conns: a.conns,
        ports: [...a.ports].sort((x, y) => x - y),
        processes: [...a.processes],
        lastSeen: a.lastSeen,
        blocked,
        watched,
        watchNote: watch?.note,
        suspiciousPorts: susPorts.map((s) => s.port),
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

  // Reputation-source coverage. The two authoritative verdict sources need API
  // keys; without them — or when every lookup is rate-limited/unreachable — a
  // peer can only be scored against the local blocklist and keyless threat
  // feeds. In that case a low `riskyCount` means "not actually checked", not
  // "clean", so we say so explicitly rather than implying an all-clear.
  const degraded: string[] = [];
  if (peers.length > 0) {
    if (!cfg.enrich.vtApiKey) degraded.push("VirusTotal (set VT_API_KEY)");
    else if (!peers.some((p) => p.virustotal))
      degraded.push("VirusTotal (no verdicts returned — rate-limited or unreachable)");
    if (!cfg.enrich.abuseKey) degraded.push("AbuseIPDB (set ABUSEIPDB_API_KEY)");
    else if (!peers.some((p) => p.abuseipdb))
      degraded.push("AbuseIPDB (no verdicts returned — rate-limited or unreachable)");
  }

  // Every blocked peer is "of interest" (isFlagged) and therefore always
  // enriched, so this count is accurate across the full external peer set, not
  // just the busiest-N enriched slice.
  const blockedCount = peers.filter((p) => p.blocked).length;
  const watchedCount = peers.filter((p) => p.watched).length;
  const suspiciousPortCount = peers.filter((p) => p.suspiciousPorts.length > 0).length;

  const notes: string[] = [];
  // Lead with a blocklisted egress destination: the operator already decided
  // this address is hostile and blocked it, yet the host is still connecting to
  // it — a firewall bypass, the most actionable signal an egress view can give.
  if (blockedCount > 0) {
    notes.push(
      `${blockedCount} audited peer(s) are on the firewall blocklist — this host is still establishing ` +
        `connections to address(es) the firewall is meant to drop, so the block is being bypassed ` +
        `(an off-gateway path/VPN, or a rule not catching this traffic); review the flagged peers.`,
    );
  }
  if (suspiciousPortCount > 0) {
    // Name the actual destination ports (mirroring trafficProfile's egress note)
    // so the takeaway is actionable without scanning the flagged-peer list — the
    // operator can recognise the protocol straight away. Distinct and ordered so
    // the same port reached by several peers is listed once.
    const susPorts = [...new Set(peers.flatMap((p) => p.suspiciousPorts))].sort(
      (a, b) => a - b,
    );
    notes.push(
      `${suspiciousPortCount} audited peer(s) are being contacted on suspicious destination port(s) ` +
        `(${susPorts.join(", ")}) — remote-control backdoors, botnet C2, or services that should never ` +
        `traverse the WAN; a classic compromised-host signal. Review the flagged peers.`,
    );
  }
  if (watchedCount > 0) {
    // Surface the operator's own annotations on the matched watchlist entries so
    // the takeaway says *why* these addresses are watched (mirroring trafficProfile),
    // not just how many matched. Distinct, ordered, and length-capped so a long
    // or noisy free-form note can't dominate the summary line.
    const watchNotes = [
      ...new Set(
        peers
          .filter((p) => p.watched && p.watchNote)
          .map((p) => p.watchNote!.replace(/\s+/g, " ").trim())
          .filter((n) => n.length > 0),
      ),
    ];
    let detail = "";
    if (watchNotes.length > 0) {
      const shown = watchNotes.slice(0, 3).map((n) => (n.length > 80 ? `${n.slice(0, 79)}…` : n));
      const more = watchNotes.length - shown.length;
      detail = ` (note: ${shown.join("; ")}${more > 0 ? `; +${more} more` : ""})`;
    }
    notes.push(
      `${watchedCount} audited peer(s) are on the operator watchlist — this host is reaching an address ` +
        `you flagged for close monitoring${detail}; review the flagged peers.`,
    );
  }
  if (distinctRemote > peers.length) {
    notes.push(
      `Audited ${peers.length} of ${distinctRemote} external peers (every block/watch-listed peer and ` +
        `every peer reached on a suspicious destination port, plus the busiest of the rest); ` +
        `lower-volume unflagged peers were not enriched.`,
    );
  }
  if (degraded.length > 0) {
    notes.push(
      `Reputation enrichment is degraded — ${degraded.join(" and ")} unavailable; ` +
        `peers were scored only against the local blocklist and keyless threat feeds, so risk flags may undercount.`,
    );
  }

  return {
    ok: true,
    host: r.host,
    distinctRemote,
    audited: peers.length,
    riskyCount: peers.filter((p) => p.risk).length,
    blockedCount: blockedCount > 0 ? blockedCount : undefined,
    watchedCount: watchedCount > 0 ? watchedCount : undefined,
    suspiciousPortCount: suspiciousPortCount > 0 ? suspiciousPortCount : undefined,
    reputationDegraded: degraded.length > 0,
    peers,
    note: notes.length > 0 ? notes.join(" ") : undefined,
  };
}
