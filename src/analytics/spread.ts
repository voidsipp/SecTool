/**
 * Spread / fan-out report — "who is talking to *many* peers, instead of one?"
 *
 * Most malicious network shapes are defined not by *what* an endpoint says but by
 * *how many* other endpoints it says it to. Two complementary topology anomalies
 * dominate real incidents, and neither shows up in any existing report:
 *
 *   1. **Fan-out (a sweeping source).** One source IP that touches *many distinct
 *      destinations* is the signature of horizontal scanning, network recon, a
 *      worm spreading, or an already-owned host doing lateral movement. A pure
 *      sweep touches each destination once or twice and moves on, so its
 *      hits-per-peer ratio is near 1. This is the single most important "an
 *      internal host has gone bad" tell a defender has.
 *
 *   2. **Fan-in (a sprayed destination).** One destination IP contacted by *many
 *      distinct sources* is the signature of a distributed brute-force, a
 *      credential-spray, a DDoS, or simply a juicy exposed service everyone is
 *      poking. Knowing which of *your* assets the internet is converging on tells
 *      you where to harden first.
 *
 * No existing offline report captures either shape:
 *
 *   - beacon.ts scores a *single* src→dst pair for timing regularity — it is blind
 *     to a source that hits a hundred different destinations once each.
 *   - watchlist.ts / profile.ts pivot on a *named* IP you already suspect; this
 *     report surfaces the spreaders you didn't know to name.
 *   - killchain.ts groups by attack *stage*, assets.ts by *asset*, rhythm.ts by
 *     *time-of-day* — none rank by peer *breadth*.
 *
 * This module folds the windowed alert history twice — once keyed by source, once
 * by destination — counts the distinct peers on the other side of each, and ranks
 * by that breadth. It classifies each endpoint internal vs. external (RFC1918 /
 * loopback / link-local) and counts how many of its peers were *external*, because
 * an **internal** host fanning out to **internal** peers (lateral movement) and an
 * internal host fanning out to the **internet** (data exfil / C2 discovery / a
 * compromised box scanning out) are very different fires.
 *
 * Honest caveats baked into the output:
 *
 *   - **Alerts, not flows.** SecTool stores IPS *alerts*, not every connection. A
 *     peer only counts here if the conversation tripped a signature, so the true
 *     fan-out is a lower bound on the real one — the report says so.
 *   - **Breadth ≠ malice.** A DNS resolver, an update server, or a busy gateway
 *     legitimately talks to many peers. The report ranks and flags; it does not
 *     convict. Internal-to-internal sweeps and severe-signature spread are called
 *     out separately precisely because they are the rows worth a human's time.
 *
 * It is pure in-memory math over alertStore — no SSH, no Claude, no network — so
 * it is safe to call from the dashboard or CLI at any time. Output is both a
 * structured model and a ready-to-paste Markdown document, mirroring report.ts,
 * compare.ts, profile.ts, assets.ts, tuning.ts, watchlist.ts, rhythm.ts,
 * novelty.ts, killchain.ts, beacon.ts and efficacy.ts.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Which side of the conversation an entry indexes, and which side it counts. */
export type SpreadKind = "fan-out" | "fan-in";

/**
 * One endpoint ranked by how many *distinct peers* it touched. For a `fan-out`
 * entry `ip` is a source and `peers` are the destinations it reached; for a
 * `fan-in` entry `ip` is a destination and `peers` are the sources that reached
 * it. The two are otherwise symmetric so the renderer can share one table shape.
 */
export interface SpreadEntry {
  kind: SpreadKind;
  /** The endpoint this row is about (source for fan-out, destination for fan-in). */
  ip: string;
  /** Distinct peers on the other side of the conversation — the ranking signal. */
  peers: number;
  /** Total windowed alerts involving this endpoint on its indexed side. */
  hits: number;
  /**
   * Hits per distinct peer, rounded to 2dp. ≈1 means "touch each peer once and
   * move on" (a sweep); a high value means repeated conversations with the same
   * few peers (more beacon-like / less scan-like).
   */
  hitsPerPeer: number;
  /** How many of the distinct peers were *external* (public, non-RFC1918). */
  externalPeers: number;
  /** True when this endpoint itself is internal (RFC1918 / loopback / link-local). */
  internal: boolean;
  /** Distinct signatures seen across this endpoint's alerts. */
  distinctSignatures: number;
  /** The dominant signature for context (may be empty). */
  topSignature: string;
  /** Worst severity observed across this endpoint's alerts. */
  severityMax: Severity;
  /** Alerts at medium severity or above. */
  severeCount: number;
  /** Alerts whose action was an active block. */
  blockedCount: number;
  /** ms epoch of the first occurrence inside the window. */
  firstSeenMs: number;
  /** ms epoch of the most recent occurrence inside the window. */
  lastSeenMs: number;
  /** True when this endpoint clears the spread bar (enough distinct peers). */
  spreadLike: boolean;
}

export interface SpreadReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Distinct source IPs observed in the window. */
  distinctSources: number;
  /** Distinct destination IPs observed in the window. */
  distinctDestinations: number;
  /** Sources flagged as fan-out spreaders (≥ the distinct-peer bar). */
  fanOutCount: number;
  /** Destinations flagged as fan-in sprayed targets (≥ the distinct-peer bar). */
  fanInCount: number;
  /** Fan-out sources, ranked broadest-first, truncated to the report limit. */
  fanOut: SpreadEntry[];
  /** Fan-in destinations, ranked broadest-first, truncated to the report limit. */
  fanIn: SpreadEntry[];
  /** True when either table was truncated by the limit. */
  truncated: boolean;
  /** Plain-language call-outs about the report as a whole. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface SpreadOptions {
  /** Max rows per table (clamped to [1, 500]). */
  limit?: number;
  /** Min distinct peers for an endpoint to be flagged spread-like (clamped to [2, 10000]). */
  minPeers?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 25;
const DEFAULT_MIN_PEERS = 8;

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? (b as Severity) : a;
}

/** Medium or above is worth promoting / hunting. */
function isSevere(s: string | undefined): boolean {
  return sevRank(s) >= 2;
}

function isBlocked(action: string | undefined): boolean {
  return (action ?? "").toLowerCase() === "blocked";
}

/** RFC1918 / loopback / link-local / ULA — mirrors profile.ts's classifier. */
function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
}

// ----- formatting helpers (mirror beacon.ts / rhythm.ts / novelty.ts) -----

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** A compact relative-age label like "3h" / "2d" for the most-recent column. */
function fmtAge(ms: number, nowMs: number): string {
  const sec = Math.max(0, Math.round((nowMs - ms) / 1000));
  if (sec < 90) return `${sec}s`;
  const min = Math.round(sec / 60);
  if (min < 90) return `${min}m`;
  const hr = Math.round(min / 60);
  if (hr < 48) return `${hr}h`;
  return `${Math.round(hr / 24)}d`;
}

function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function mdTable(headers: string[], rows: string[][]): string {
  if (!rows.length) return "_None._";
  const head = `| ${headers.join(" | ")} |`;
  const sep = `| ${headers.map(() => "---").join(" | ")} |`;
  const body = rows.map((r) => `| ${r.join(" | ")} |`).join("\n");
  return `${head}\n${sep}\n${body}`;
}

/** Truncate a long free-form string for a table cell. */
function clip(s: string, max = 44): string {
  const t = s.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

/**
 * Internal accumulator for one endpoint while we fold the window. Holds the set
 * of distinct peers (the breadth signal) plus the small tallies needed to render
 * severity, blocking, signature context, and first/last seen.
 */
interface Accum {
  ip: string;
  internal: boolean;
  peers: Set<string>;
  externalPeers: Set<string>;
  hits: number;
  severityMax: Severity;
  severeCount: number;
  blockedCount: number;
  sigCounts: Map<string, number>;
  firstSeenMs: number;
  lastSeenMs: number;
}

function bump(map: Map<string, number>, key: string | undefined): void {
  if (!key) return;
  map.set(key, (map.get(key) ?? 0) + 1);
}

/** Most frequent key in a tally, ties broken by lexical order for stability. */
function topKey(map: Map<string, number>): string {
  let best = "";
  let bestN = -1;
  for (const [k, n] of map) {
    if (n > bestN || (n === bestN && k < best)) {
      best = k;
      bestN = n;
    }
  }
  return best;
}

/** Fold one alert into the accumulator keyed by `ip`, counting `peer` on the other side. */
function fold(
  map: Map<string, Accum>,
  ip: string,
  peer: string,
  a: StoredAlert,
): void {
  let e = map.get(ip);
  if (!e) {
    e = {
      ip,
      internal: isPrivate(ip),
      peers: new Set(),
      externalPeers: new Set(),
      hits: 0,
      severityMax: "info",
      severeCount: 0,
      blockedCount: 0,
      sigCounts: new Map(),
      firstSeenMs: a.time,
      lastSeenMs: a.time,
    };
    map.set(ip, e);
  }
  e.hits++;
  e.peers.add(peer);
  if (!isPrivate(peer)) e.externalPeers.add(peer);
  e.severityMax = maxSeverity(e.severityMax, a.severity);
  if (isSevere(a.severity)) e.severeCount++;
  if (isBlocked(a.action)) e.blockedCount++;
  bump(e.sigCounts, a.signature);
  if (a.time < e.firstSeenMs) e.firstSeenMs = a.time;
  if (a.time > e.lastSeenMs) e.lastSeenMs = a.time;
}

function toEntry(e: Accum, kind: SpreadKind, minPeers: number): SpreadEntry {
  const peers = e.peers.size;
  return {
    kind,
    ip: e.ip,
    peers,
    hits: e.hits,
    hitsPerPeer: Math.round((e.hits / Math.max(1, peers)) * 100) / 100,
    externalPeers: e.externalPeers.size,
    internal: e.internal,
    distinctSignatures: e.sigCounts.size,
    topSignature: topKey(e.sigCounts),
    severityMax: e.severityMax,
    severeCount: e.severeCount,
    blockedCount: e.blockedCount,
    firstSeenMs: e.firstSeenMs,
    lastSeenMs: e.lastSeenMs,
    spreadLike: peers >= minPeers,
  };
}

/**
 * Rank entries: flagged spreaders first, then by raw breadth, then by severity,
 * then by recency — so the most dangerous, broadest rows float to the top.
 */
function rank(items: SpreadEntry[]): SpreadEntry[] {
  return items.sort((x, y) => {
    if (x.spreadLike !== y.spreadLike) return x.spreadLike ? -1 : 1;
    if (y.peers !== x.peers) return y.peers - x.peers;
    if (sevRank(y.severityMax) !== sevRank(x.severityMax)) return sevRank(y.severityMax) - sevRank(x.severityMax);
    if (y.hits !== x.hits) return y.hits - x.hits;
    return y.lastSeenMs - x.lastSeenMs;
  });
}

/** "internal", "external", or "→internet" descriptor for an entry's spread. */
function scopeLabel(e: SpreadEntry): string {
  if (!e.internal) return "ext src";
  return e.externalPeers > 0 ? "int→internet" : "int→int";
}

function writeHighlights(m: Omit<SpreadReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (!m.totalWindowAlerts) return out;

  if (!m.fanOutCount && !m.fanInCount) {
    out.push(
      `No source or destination touched ≥ the distinct-peer bar over the last ${m.hours}h — ` +
        `traffic is point-to-point, with no broad scanning or spraying shape. Nothing flagged.`,
    );
    return out;
  }

  if (m.fanOutCount) {
    const top = m.fanOut.find((e) => e.spreadLike);
    out.push(
      `🛰️ ${m.fanOutCount} source(s) fan out to many destinations (horizontal scan / lateral movement shape).` +
        (top
          ? ` Broadest: \`${top.ip}\` reached ${top.peers} distinct dest(s)` +
            `${top.externalPeers ? ` (${top.externalPeers} external)` : ""} over ${top.hits} hits.`
          : ""),
    );
    // The sharpest fire: an *internal* host sweeping — it is already on your LAN.
    const lateral = m.fanOut.filter((e) => e.spreadLike && e.internal);
    if (lateral.length) {
      const internet = lateral.filter((e) => e.externalPeers > 0).length;
      out.push(
        `⚠️ ${lateral.length} of those spreaders are **internal** hosts` +
          (internet ? ` (${internet} reaching the public internet — possible exfil / C2 discovery)` : "") +
          ` — internal hosts fanning out is the classic compromised-box / worm tell. Investigate first.`,
      );
    }
  }

  if (m.fanInCount) {
    const top = m.fanIn.find((e) => e.spreadLike);
    out.push(
      `🎯 ${m.fanInCount} destination(s) are converged upon by many sources (distributed brute-force / spray / DDoS shape).` +
        (top
          ? ` Most-sprayed: \`${top.ip}\` hit by ${top.peers} distinct source(s) over ${top.hits} alerts` +
            `${top.severityMax !== "info" ? `, peak ${top.severityMax}` : ""}.`
          : ""),
    );
  }

  const severeSpread = [...m.fanOut, ...m.fanIn].filter((e) => e.spreadLike && isSevere(e.severityMax)).length;
  if (severeSpread) {
    out.push(`${severeSpread} flagged endpoint(s) carry a medium-or-worse signature — treat their spread as likely hostile.`);
  }
  return out;
}

function spreadTable(entries: SpreadEntry[], nowMs: number, peerHeader: string): string {
  return mdTable(
    ["", "Endpoint", peerHeader, "Hits", "Hits/peer", "Ext peers", "Scope", "Sigs", "Peak", "Last", "Top signature"],
    entries.map((e) => [
      e.spreadLike ? "🚩" : "·",
      cell(e.ip),
      String(e.peers),
      String(e.hits),
      e.hitsPerPeer.toFixed(2),
      String(e.externalPeers),
      scopeLabel(e),
      String(e.distinctSignatures),
      cell(e.severityMax),
      fmtAge(e.lastSeenMs, nowMs),
      e.topSignature ? cell(clip(e.topSignature)) : "—",
    ]),
  );
}

function renderMarkdown(m: SpreadReport): string {
  const lines: string[] = [];
  lines.push(`# 🕸️ SecTool Spread / Fan-out Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Topology:** ${m.distinctSources} distinct source(s) · ${m.distinctDestinations} distinct dest(s) · ` +
      `**${m.fanOutCount} fan-out** · **${m.fanInCount} fan-in** · **Window alerts:** ${m.totalWindowAlerts}`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.totalWindowAlerts) {
    lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Fan-out — sources reaching many destinations (scan / lateral movement)`);
  lines.push("");
  if (!m.fanOut.length) {
    lines.push(`_None — no source had more than one distinct destination this window._`);
    lines.push("");
  } else {
    lines.push(spreadTable(m.fanOut, m.windowEndMs, "Dests"));
    lines.push("");
  }

  lines.push(`## Fan-in — destinations contacted by many sources (spray / brute-force / DDoS)`);
  lines.push("");
  if (!m.fanIn.length) {
    lines.push(`_None — no destination had more than one distinct source this window._`);
    lines.push("");
  } else {
    lines.push(spreadTable(m.fanIn, m.windowEndMs, "Sources"));
    lines.push("");
  }

  if (m.truncated) {
    lines.push(`_One or more tables were truncated to the row limit — raise \`limit\` to see more._`);
    lines.push("");
  }

  lines.push(
    `**Legend:** 🚩 = flagged spreader (≥ the distinct-peer bar). _Hits/peer_ ≈1 means a touch-and-move *sweep*; ` +
      `high means repeated talk with the same few peers. _Scope_: \`int→int\` = internal host reaching internal ` +
      `peers (lateral-movement shape); \`int→internet\` = internal host reaching the public internet (exfil / C2 ` +
      `shape); \`ext src\` = the endpoint itself is external.`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from stored **IPS-alert** topology, not full flow data — a peer only counts if ` +
      `the conversation tripped a signature, so the true fan-out/fan-in is a lower bound. Breadth ranks attention; ` +
      `it does not by itself prove malice (resolvers, update servers and gateways talk to many peers legitimately). ` +
      `No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the spread / fan-out report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link SpreadOptions}: `limit`, `minPeers`, and a `nowMs` pin.
 */
export function buildSpread(hours: number, opts: SpreadOptions = {}): SpreadReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(500, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minPeers = Math.max(2, Math.min(10000, Math.floor(opts.minPeers ?? DEFAULT_MIN_PEERS)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * 3_600_000;

  const all = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time));

  // Fold the window twice: once by source (counting distinct dests) and once by
  // destination (counting distinct sources). A row needs a valid IP on each side.
  const bySource = new Map<string, Accum>();
  const byDest = new Map<string, Accum>();
  let totalWindowAlerts = 0;
  for (const a of all) {
    if (a.time < windowStartMs || a.time > windowEndMs) continue;
    totalWindowAlerts++;
    const src = a.srcIp && isIP(a.srcIp) > 0 ? a.srcIp : "";
    const dst = a.dstIp && isIP(a.dstIp) > 0 ? a.dstIp : "";
    if (!src || !dst || src === dst) continue;
    fold(bySource, src, dst, a);
    fold(byDest, dst, src, a);
  }

  const distinctSources = bySource.size;
  const distinctDestinations = byDest.size;

  // Only endpoints with at least two distinct peers are interesting at all — a
  // single-peer talker is point-to-point and belongs to beacon.ts, not here.
  const fanOutAll = rank(
    [...bySource.values()].filter((e) => e.peers.size >= 2).map((e) => toEntry(e, "fan-out", minPeers)),
  );
  const fanInAll = rank(
    [...byDest.values()].filter((e) => e.peers.size >= 2).map((e) => toEntry(e, "fan-in", minPeers)),
  );

  const fanOutCount = fanOutAll.filter((e) => e.spreadLike).length;
  const fanInCount = fanInAll.filter((e) => e.spreadLike).length;
  const fanOut = fanOutAll.slice(0, limit);
  const fanIn = fanInAll.slice(0, limit);

  const base: Omit<SpreadReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts,
    distinctSources,
    distinctDestinations,
    fanOutCount,
    fanInCount,
    fanOut,
    fanIn,
    truncated: fanOutAll.length > fanOut.length || fanInAll.length > fanIn.length,
  };
  const highlights = writeHighlights(base);
  const model: SpreadReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded spread report. */
export function spreadFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-spread-${stamp}.md`;
}
