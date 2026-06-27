/**
 * Protocol-mix / transport & application-layer breakdown report — "what is
 * actually coming over the wire, by *protocol*, and is any of it the kind of
 * traffic that shouldn't be hitting my edge at all?"
 *
 * Every exposure report in this project already pivots on a *port* or a *service
 * derived from a port*:
 *
 *   - ports.ts ranks the individual **destination ports** under attack (3389,
 *     445, 22…) and which host exposes each.
 *   - services.ts rolls those ports up into curated **service classes**
 *     (remote-access, database, file-share, ICS/IoT) — still a port→service map.
 *   - scan.ts / spread.ts describe the *shape* of a source's probing across hosts
 *     and ports; classify.ts splits volume across Suricata's *threat taxonomy*.
 *
 * None of them answer the orthogonal, lower-layer question a network defender
 * asks when triaging a feed: **how does the traffic divide across the L3/L4
 * transport protocol (TCP / UDP / ICMP / …) and, where the feed carries it, the
 * L7 application protocol (http / dns / tls / ssh / smb / …)?** That axis is
 * independent of the port — UDP/53 and TCP/53 are both "DNS" by port yet are very
 * different beasts on the wire, and an ICMP flood or a GRE/ESP tunnelling attempt
 * has *no service port at all* and is therefore invisible to every port-based
 * report. The protocol mix is the first thing a packet-level analyst reads:
 *
 *   - a sudden **ICMP** share is reconnaissance (ping sweeps) or covert tunnelling;
 *   - a **UDP** spike with a tiny source-port set is amplification / reflection
 *     DDoS or DNS/NTP/SSDP abuse;
 *   - **GRE / ESP / SCTP / IGMP** appearing at the edge is almost always tunnelling,
 *     VPN probing or an outright misconfiguration — protocols that should never
 *     reach a normal Internet-facing gateway.
 *
 * For every recovered protocol this module rolls up, from the stored history:
 *
 *   - alert volume and its share of the analysable (protocol-bearing) stream,
 *   - the severity profile (worst severity, medium-or-worse count, critical count)
 *     and a severity-weighted score — the **ranking key**, so a dangerous-but-quiet
 *     protocol is not buried under recon noise (mirrors classify.ts),
 *   - enforcement posture — blocked vs only-detected and the resulting block rate,
 *     so a *high-severity, low-block* protocol surfaces as a control gap,
 *   - breadth — distinct attacker sources and distinct internal targets, so a
 *     protocol driven by one noisy host reads differently from one hitting many,
 *   - the dominant signature for context and a recent-vs-older split so a protocol
 *     that is **accelerating** (most of its hits land in the recent half of the
 *     window) is flagged.
 *
 * The transport breakdown is the headline and works on any feed. A second
 * **application-layer** breakdown is rendered only when the feed actually carries
 * `app_proto` (eve.json); fast.log feeds omit it, and the report says so rather
 * than inventing app-layer data from port numbers (that would just duplicate
 * services.ts).
 *
 * Honest caveats baked into the output:
 *
 *   - **Protocol is re-parsed, not stored.** SecTool's alert store keeps no
 *     protocol column, so — exactly like priority.ts (priority) and ruleset.ts
 *     (gid:sid:rev) — every figure is recovered from each alert's raw line: the
 *     fast.log `{PROTO}` flow token or a JSON `proto`/`app_proto` field. Alerts
 *     whose raw line no longer carries either are counted as *unresolved* and
 *     excluded; the resolvable fraction is shown so the sample is auditable.
 *   - **Application protocol depends on the feed.** Only structured eve.json
 *     carries `app_proto`; a fast.log-only deployment will show an empty L7
 *     section. That is a feed limitation, not an absence of L7 traffic.
 *   - **Volume ≠ risk.** Recon (ICMP) and chatty UDP dominate by count on most
 *     edges; the report ranks by severity-weighted score and calls out the
 *     dangerous-but-quiet protocols separately so they are not lost in the noise.
 *   - **Window-bounded & store-capped.** A long look-back can hit the alert
 *     store's history cap and clip the earliest alerts.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network. Output is
 * both a structured model and a ready-to-paste Markdown document, mirroring
 * classify.ts, dwell.ts, ruleset.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Blocked / passed / unknown disposition split for a protocol. */
export interface DispositionSplit {
  /** Alerts the gateway actively blocked / dropped. */
  blocked: number;
  /** Alerts the gateway logged but let through (detected / allowed). */
  passed: number;
  /** Alerts with no recorded action (excluded from {@link blockRate}). */
  unknown: number;
  /**
   * Fraction of *actioned* (blocked + passed) alerts that were blocked, 0..1
   * (4dp), or null when nothing was actioned. A low rate on a high-severity
   * protocol is an enforcement gap.
   */
  blockRate: number | null;
}

/** One protocol (transport or application layer) rolled up over the window. */
export interface ProtocolEntry {
  /** The protocol label, e.g. "TCP", "UDP", "ICMP", "http", "dns", "tls". */
  label: string;
  /** Total windowed alerts attributed to this protocol. */
  alerts: number;
  /** Share of all resolved alerts in this layer, 0..1 (4dp). */
  share: number;
  /** Distinct attacker source IPs that drove this protocol. */
  distinctSources: number;
  /** Distinct internal destination hosts this protocol reached. */
  distinctTargets: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Alerts at critical severity. */
  critical: number;
  /** Severity-weighted score (Σ SEVERITY_WEIGHT) — the ranking key. */
  score: number;
  /** Worst severity seen for this protocol. */
  severityMax: Severity;
  /** Blocked / passed / unknown disposition split. */
  disposition: DispositionSplit;
  /** ms epoch of the first alert in the window for this protocol. */
  firstSeenMs: number;
  /** ms epoch of the last alert in the window for this protocol. */
  lastSeenMs: number;
  /** Alerts whose timestamp fell in the recent half of the window. */
  recentHalf: number;
  /**
   * Share of this protocol's alerts in the recent half, 0..1 (4dp). > 0.6 means
   * the protocol is accelerating; < 0.4 means it is fading.
   */
  recentShare: number;
  /** The most-frequent signature for this protocol, if any. */
  topSignature?: string;
  /** Distinct signatures seen on this protocol. */
  distinctSignatures: number;
  /** How many of this protocol's source IPs are currently on the blocklist. */
  blockedSources: number;
}

export interface ProtocolReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts from which a transport protocol could be recovered. */
  resolvedTransport: number;
  /** Of those, alerts from which an application protocol could be recovered. */
  resolvedApp: number;
  /** Alerts whose raw line carried no recoverable protocol at all. */
  unresolved: number;
  /** Distinct transport protocols seen. */
  distinctTransport: number;
  /** Distinct application protocols seen. */
  distinctApp: number;
  /** Per-transport-protocol rows, most dangerous (weighted) first. */
  transport: ProtocolEntry[];
  /** Per-application-protocol rows, most dangerous (weighted) first. */
  application: ProtocolEntry[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface ProtocolOptions {
  /** Max rows in each per-protocol table (clamped to [1, 100]). */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const MS_PER_HOUR = 3_600_000;

/** Transport protocols an edge defender should rarely, if ever, see inbound. */
const UNUSUAL_TRANSPORT = new Set(["GRE", "ESP", "AH", "SCTP", "IGMP", "OSPF", "PIM", "IPIP"]);

/**
 * IANA L4 protocol numbers → canonical names, for feeds that log the numeric
 * `proto` rather than the mnemonic. Only the handful that realistically appear
 * in IDS flow records.
 */
const PROTO_NUMBERS: Record<string, string> = {
  "1": "ICMP",
  "2": "IGMP",
  "6": "TCP",
  "17": "UDP",
  "41": "IPv6",
  "47": "GRE",
  "50": "ESP",
  "51": "AH",
  "58": "IPv6-ICMP",
  "89": "OSPF",
  "103": "PIM",
  "132": "SCTP",
};

// ----- protocol recovery ----------------------------------------------------

/**
 * fast.log flow token: `... [Priority: 2] {TCP} a.b.c.d:1 -> e.f.g.h:3389`. The
 * brace is anchored to an actual flow (an IP-ish endpoint + an arrow) so a stray
 * `{...}` in a JSON payload can't be mistaken for a protocol.
 */
const FAST_FLOW_PROTO =
  /\{([A-Za-z][A-Za-z0-9-]*)\}\s*[0-9a-fA-F.:]+(?::\d+)?\s*(?:->|<->|<-)/;

/** Strings Suricata uses for "couldn't determine the app layer" — not real L7. */
const APP_PROTO_NOISE = new Set(["failed", "unknown", "none", "", "-"]);

/** The recovered protocol pair for one alert. */
export interface RecoveredProtocol {
  /** Canonical transport protocol (upper-case), or undefined if unrecoverable. */
  transport?: string;
  /** Canonical application protocol (lower-case), or undefined if absent. */
  appProto?: string;
}

/** Normalise a transport token: upper-case, map IANA numbers, canonicalise ICMP. */
function normTransport(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const t = String(raw).trim();
  if (!t) return undefined;
  if (/^\d+$/.test(t)) return PROTO_NUMBERS[t] ?? `proto-${t}`;
  const u = t.toUpperCase();
  if (u === "ICMPV6" || u === "IPV6ICMP" || u === "IPV6-ICMP") return "IPv6-ICMP";
  if (u === "IPV6") return "IPv6";
  return u;
}

/** Normalise an app-layer token: lower-case, drop Suricata's "failed"/"unknown". */
function normAppProto(raw: string | undefined): string | undefined {
  if (raw === undefined || raw === null) return undefined;
  const a = String(raw).trim().toLowerCase();
  if (APP_PROTO_NOISE.has(a)) return undefined;
  // Collapse the common TLS aliases so ssl/tls don't split the row.
  if (a === "ssl") return "tls";
  return a;
}

function firstString(obj: Record<string, unknown>, keys: string[]): string | undefined {
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === "string" && v.trim()) return v.trim();
    if (typeof v === "number" && Number.isFinite(v)) return String(v);
  }
  return undefined;
}

/**
 * Recover the transport and application protocol from a stored alert's raw line,
 * using the same two shapes the detector understands: a JSON payload carrying
 * `proto` / `app_proto` (eve.json, which wins when present), or the fast.log
 * `{PROTO}` flow token. Returns an empty object when nothing is recoverable.
 */
export function recoverProtocol(raw: string | undefined): RecoveredProtocol {
  if (!raw) return {};
  let transport: string | undefined;
  let appProto: string | undefined;

  // 1) JSON payload (eve.json) — authoritative when present, matching the detector.
  const start = raw.indexOf("{");
  const end = raw.lastIndexOf("}");
  if (start !== -1 && end > start) {
    try {
      const obj = JSON.parse(raw.slice(start, end + 1)) as Record<string, unknown>;
      if (obj && typeof obj === "object") {
        transport = normTransport(firstString(obj, ["proto", "protocol", "ip_proto"]));
        appProto = normAppProto(firstString(obj, ["app_proto", "app_layer", "appproto"]));
      }
    } catch {
      // not JSON — fall through to fast.log parsing
    }
  }

  // 2) fast.log flow token — only when JSON didn't already yield a transport.
  if (!transport) {
    const m = FAST_FLOW_PROTO.exec(raw);
    if (m?.[1]) transport = normTransport(m[1]);
  }

  return { transport, appProto };
}

// ----- classifiers / helpers (mirror classify.ts / dwell.ts) ----------------

/** RFC1918 / loopback / link-local / ULA — an address treated as one of ours. */
function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
}

/** A valid, non-empty IP, or undefined if the field is missing/garbage. */
function validIp(ip: string | undefined): string | undefined {
  return ip && isIP(ip) !== 0 ? ip : undefined;
}

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? (b as Severity) : a;
}

function isSevere(s: string | undefined): boolean {
  return sevRank(s) >= 2; // medium or worse
}

function isCritical(s: string | undefined): boolean {
  return sevRank(s) >= 4;
}

function weightOf(s: string | undefined): number {
  return SEVERITY_WEIGHT[(s as Severity) ?? "info"] ?? SEVERITY_WEIGHT.info;
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

function pct(frac: number | null): string {
  return frac === null ? "—" : `${Math.round(frac * 100)}%`;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function clip(s: string, max = 40): string {
  const t = s.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

function mdTable(headers: string[], rows: string[][]): string {
  if (!rows.length) return "_None._";
  const head = `| ${headers.join(" | ")} |`;
  const sep = `| ${headers.map(() => "---").join(" | ")} |`;
  const body = rows.map((r) => `| ${r.join(" | ")} |`).join("\n");
  return `${head}\n${sep}\n${body}`;
}

function topOf(counts: Map<string, number>): string | undefined {
  let key: string | undefined;
  let count = -1;
  for (const [k, c] of counts) {
    if (c > count || (c === count && key !== undefined && k < key)) {
      key = k;
      count = c;
    }
  }
  return key;
}

/** Short risk hint for a transport protocol, shown inline in the table. */
function transportHint(label: string): string {
  switch (label) {
    case "TCP":
      return "connection-oriented (services, exploits)";
    case "UDP":
      return "stateless (amplification / DNS / DDoS)";
    case "ICMP":
      return "recon / ping-sweep / tunnelling";
    case "IPv6-ICMP":
      return "IPv6 recon / neighbour abuse";
    default:
      return UNUSUAL_TRANSPORT.has(label) ? "tunnelling / VPN — rare at the edge" : "—";
  }
}

// ----- aggregation ----------------------------------------------------------

interface ProtoAcc {
  alerts: number;
  sources: Set<string>;
  targets: Set<string>;
  severe: number;
  critical: number;
  score: number;
  severityMax: Severity;
  blocked: number;
  passed: number;
  unknown: number;
  firstSeenMs: number;
  lastSeenMs: number;
  recentHalf: number;
  sigCounts: Map<string, number>;
  blockedSources: Set<string>;
}

function newAcc(): ProtoAcc {
  return {
    alerts: 0,
    sources: new Set(),
    targets: new Set(),
    severe: 0,
    critical: 0,
    score: 0,
    severityMax: "info",
    blocked: 0,
    passed: 0,
    unknown: 0,
    firstSeenMs: Number.POSITIVE_INFINITY,
    lastSeenMs: Number.NEGATIVE_INFINITY,
    recentHalf: 0,
    sigCounts: new Map(),
    blockedSources: new Set(),
  };
}

function tally(acc: ProtoAcc, a: StoredAlert, midMs: number): void {
  acc.alerts++;
  acc.score += weightOf(a.severity);
  acc.severityMax = maxSeverity(acc.severityMax, a.severity);
  if (isSevere(a.severity)) acc.severe++;
  if (isCritical(a.severity)) acc.critical++;

  const src = validIp(a.srcIp);
  if (src) {
    acc.sources.add(src);
    if (blockStore.has(src)) acc.blockedSources.add(src);
  }
  const dst = validIp(a.dstIp);
  if (dst && isPrivate(dst)) acc.targets.add(dst);

  const disp = classifyDisposition(a.action);
  if (disp === "blocked") acc.blocked++;
  else if (disp === "passed") acc.passed++;
  else acc.unknown++;

  if (a.time < acc.firstSeenMs) acc.firstSeenMs = a.time;
  if (a.time > acc.lastSeenMs) acc.lastSeenMs = a.time;
  if (a.time >= midMs) acc.recentHalf++;

  const sig = (a.signature ?? "").trim();
  if (sig) acc.sigCounts.set(sig, (acc.sigCounts.get(sig) ?? 0) + 1);
}

function finalize(label: string, acc: ProtoAcc, resolvedTotal: number): ProtocolEntry {
  const actioned = acc.blocked + acc.passed;
  return {
    label,
    alerts: acc.alerts,
    share: resolvedTotal ? round4(acc.alerts / resolvedTotal) : 0,
    distinctSources: acc.sources.size,
    distinctTargets: acc.targets.size,
    severe: acc.severe,
    critical: acc.critical,
    score: round4(acc.score),
    severityMax: acc.severityMax,
    disposition: {
      blocked: acc.blocked,
      passed: acc.passed,
      unknown: acc.unknown,
      blockRate: actioned ? round4(acc.blocked / actioned) : null,
    },
    firstSeenMs: Number.isFinite(acc.firstSeenMs) ? acc.firstSeenMs : 0,
    lastSeenMs: Number.isFinite(acc.lastSeenMs) ? acc.lastSeenMs : 0,
    recentHalf: acc.recentHalf,
    recentShare: acc.alerts ? round4(acc.recentHalf / acc.alerts) : 0,
    topSignature: topOf(acc.sigCounts),
    distinctSignatures: acc.sigCounts.size,
    blockedSources: acc.blockedSources.size,
  } satisfies ProtocolEntry;
}

/** Rank: most dangerous (weighted) first, then volume, then label for stability. */
function rank(a: ProtocolEntry, b: ProtocolEntry): number {
  return (
    b.score - a.score ||
    b.alerts - a.alerts ||
    (a.label < b.label ? -1 : a.label > b.label ? 1 : 0)
  );
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  m: { resolvedTransport: number; unresolved: number; totalWindowAlerts: number },
  transport: ProtocolEntry[],
  application: ProtocolEntry[],
): string[] {
  const out: string[] = [];
  if (!transport.length) return out;

  const lead = transport[0]!;
  const byVolume = [...transport].sort((a, b) => b.alerts - a.alerts);
  const topVol = byVolume[0]!;
  out.push(
    `📡 Over the last ${hours}h, **${m.resolvedTransport} protocol-bearing alert(s)** span ` +
      `**${transport.length} transport protocol(s)**. Most traffic is **${topVol.label}** ` +
      `(${pct(topVol.share)} of resolved alerts); ranked by risk the most dangerous is **${lead.label}** ` +
      `(score ${lead.score}, worst severity ${lead.severityMax}).`,
  );

  // ICMP presence — recon / tunnelling tell.
  const icmp = transport.find((t) => t.label === "ICMP" || t.label === "IPv6-ICMP");
  if (icmp && icmp.alerts > 0) {
    out.push(
      `📶 **${icmp.label} is present** (${icmp.alerts} alert(s), ${pct(icmp.share)} of the stream, ` +
        `${icmp.distinctSources} source(s)) — ICMP carries no service port, so it is invisible to the ` +
        `port/service reports: classic ping-sweep reconnaissance, or covert ICMP tunnelling if the volume is high.`,
    );
  }

  // UDP at notable volume — amplification / reflection tell.
  const udp = transport.find((t) => t.label === "UDP");
  if (udp && udp.share >= 0.15) {
    out.push(
      `🌊 **UDP is ${pct(udp.share)} of the stream** (${udp.alerts} alert(s) from ${udp.distinctSources} ` +
        `source(s)). A heavy stateless-UDP share is the signature of amplification / reflection DDoS or ` +
        `DNS/NTP/SSDP abuse — confirm whether you are a *target* or an unwitting *reflector*.`,
    );
  }

  // Unusual / tunnelling protocols at the edge.
  const unusual = transport.filter((t) => UNUSUAL_TRANSPORT.has(t.label));
  if (unusual.length) {
    const names = unusual.map((u) => `${u.label} (${u.alerts})`).join(", ");
    out.push(
      `🚇 **Tunnelling / VPN protocol(s) seen at the edge: ${names}.** ${unusual[0]!.label} and its kin should ` +
        `rarely reach an Internet-facing gateway — investigate for VPN probing, GRE/ESP tunnelling or a ` +
        `routing misconfiguration leaking internal traffic.`,
    );
  }

  // High-severity, low-block protocol — an enforcement gap.
  const gap = transport
    .filter((t) => t.severe > 0 && t.disposition.blockRate !== null && t.disposition.blockRate < 0.5)
    .sort((a, b) => b.severe - a.severe)[0];
  if (gap) {
    out.push(
      `⚠️ **${gap.label}** carries **${gap.severe} medium-or-worse** alert(s) but only **${pct(
        gap.disposition.blockRate,
      )}** of its actioned traffic is blocked (${gap.disposition.passed} passed) — serious ${gap.label} ` +
        `traffic is reaching your hosts. Tighten the IPS policy for this protocol.`,
    );
  }

  // An accelerating protocol — most of its hits are recent.
  const rising = transport
    .filter((t) => t.alerts >= 5 && t.recentShare >= 0.6)
    .sort((a, b) => b.recentShare - a.recentShare)[0];
  if (rising) {
    out.push(
      `📈 **${rising.label} is accelerating** — ${pct(rising.recentShare)} of its ${rising.alerts} alert(s) ` +
        `landed in the recent half of the window. A protocol mix shifting under you is worth a second look.`,
    );
  }

  // Application-layer headline (only when the feed carries it).
  if (application.length) {
    const a = application[0]!;
    out.push(
      `🔬 **Application layer:** ${application.length} L7 protocol(s) recovered; the riskiest is **${a.label}** ` +
        `(${a.alerts} alert(s), ${pct(a.share)}, worst severity ${a.severityMax}). ` +
        `_(App-layer is only present on eve.json feeds.)_`,
    );
  } else {
    out.push(
      `🔬 **No application-layer (\`app_proto\`) data in this window** — the feed is fast.log-style or carried ` +
        `no L7 label. The transport breakdown above is unaffected; for L7 service exposure see the \`services\` report.`,
    );
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function protoTable(rows: ProtocolEntry[], showHint: boolean): string {
  const headers = [
    "#",
    "Protocol",
    ...(showHint ? ["Typical use"] : []),
    "Alerts",
    "Share",
    "Sources",
    "Targets",
    "Worst",
    "Severe",
    "Block rate",
    "Recent½",
    "Top signature",
  ];
  return mdTable(
    headers,
    rows.map((p, i) => [
      String(i + 1),
      cell(p.label),
      ...(showHint ? [cell(transportHint(p.label))] : []),
      String(p.alerts),
      pct(p.share),
      String(p.distinctSources),
      String(p.distinctTargets),
      cell(p.severityMax),
      String(p.severe),
      pct(p.disposition.blockRate),
      pct(p.recentShare),
      p.topSignature ? cell(clip(p.topSignature)) : "—",
    ]),
  );
}

function renderMarkdown(m: ProtocolReport): string {
  const lines: string[] = [];
  lines.push(`# 📡 SecTool Protocol-Mix (Transport & Application-Layer) Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** transport (L3/L4) and application (L7) protocol **re-parsed from each alert's raw line** ` +
      `(fast.log \`{PROTO}\` token or JSON \`proto\`/\`app_proto\`), then ranked by **severity-weighted score, not ` +
      `volume** · **Resolved:** ${m.resolvedTransport} of ${m.totalWindowAlerts} alert(s) carried a transport ` +
      `protocol (${m.unresolved} unresolved)`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.transport.length) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but **none carried a recoverable ` +
          `protocol** — no fast.log \`{PROTO}\` flow token and no JSON \`proto\` field survived in the raw lines. ` +
          `Protocol is re-parsed, not stored, so a feed that strips the flow token leaves nothing to break down here.`,
      );
    }
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Transport protocols (L3/L4)`);
  lines.push("");
  lines.push(protoTable(m.transport, true));
  lines.push("");
  lines.push(
    `**Legend:** _Share_ is of the ${m.resolvedTransport} protocol-bearing alerts. _Severe_ = medium-or-worse. ` +
      `_Block rate_ = blocked ÷ actioned (blocked + passed); a low rate on a high-severity row is an enforcement ` +
      `gap. _Recent½_ = share of the protocol's alerts in the recent half of the window (> 60% = accelerating). ` +
      `Rows are ranked by **severity-weighted score**, so a dangerous-but-quiet protocol outranks a loud benign one.`,
  );
  lines.push("");

  lines.push(`## Application protocols (L7)`);
  lines.push("");
  if (m.application.length) {
    lines.push(protoTable(m.application, false));
    lines.push("");
    lines.push(
      `_Recovered from \`app_proto\` on ${m.resolvedApp} alert(s). Absent on fast.log-only feeds; for ` +
        `port-derived service exposure (which does not need \`app_proto\`) see the \`services\` report._`,
    );
  } else {
    lines.push(
      `_No \`app_proto\` data in this window — the feed is fast.log-style or carried no L7 label. This is a feed ` +
        `limitation, not an absence of L7 traffic; the transport breakdown above is unaffected._`,
    );
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Protocol is **re-parsed from each alert's raw line**, not a stored column, so ` +
      `every figure is drawn from the ${m.resolvedTransport} of ${m.totalWindowAlerts} alert(s) that still carried a ` +
      `\`{PROTO}\` flow token or JSON \`proto\` field; ${m.unresolved} alert(s) were unresolved and excluded. ` +
      `Application-layer data depends on the feed (eve.json only). Volume ≠ risk: recon (ICMP) and chatty UDP ` +
      `dominate by count, so rows are ranked by severity-weighted score. A long look-back can hit the store's ` +
      `history cap and clip the earliest alerts. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the protocol-mix (transport & application-layer) report from the stored
 * alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link ProtocolOptions}: `limit` per table and a `nowMs` pin for
 *              deterministic tests.
 */
export function buildProtocols(hours: number, opts: ProtocolOptions = {}): ProtocolReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(100, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;
  const midMs = windowStartMs + (windowEndMs - windowStartMs) / 2;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const transportAcc = new Map<string, ProtoAcc>();
  const appAcc = new Map<string, ProtoAcc>();
  let resolvedTransport = 0;
  let resolvedApp = 0;
  let unresolved = 0;

  for (const a of windowed) {
    const { transport, appProto } = recoverProtocol(a.raw);

    if (transport) {
      resolvedTransport++;
      const acc = transportAcc.get(transport) ?? newAcc();
      if (!transportAcc.has(transport)) transportAcc.set(transport, acc);
      tally(acc, a, midMs);
    } else {
      unresolved++;
    }

    if (appProto) {
      resolvedApp++;
      const acc = appAcc.get(appProto) ?? newAcc();
      if (!appAcc.has(appProto)) appAcc.set(appProto, acc);
      tally(acc, a, midMs);
    }
  }

  const transport = [...transportAcc.entries()]
    .map(([label, acc]) => finalize(label, acc, resolvedTransport))
    .sort(rank)
    .slice(0, limit);

  const application = [...appAcc.entries()]
    .map(([label, acc]) => finalize(label, acc, resolvedApp))
    .sort(rank)
    .slice(0, limit);

  const highlights = writeHighlights(
    safeHours,
    { resolvedTransport, unresolved, totalWindowAlerts: windowed.length },
    transport,
    application,
  );

  const model: ProtocolReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    resolvedTransport,
    resolvedApp,
    unresolved,
    distinctTransport: transportAcc.size,
    distinctApp: appAcc.size,
    transport,
    application,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded protocol-mix report. */
export function protocolsFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-protocols-${stamp}.md`;
}
