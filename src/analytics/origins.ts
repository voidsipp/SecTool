/**
 * Regional / RIR origin attribution — "**where in the world is my attack traffic
 * coming from?**"
 *
 * SecTool can already tell you *who* (`profile`, `persist`, `clusters`), *whose
 * infrastructure* (`cloud` — the hosting provider), *whether the source is even
 * valid* (`bogon`) and *which /24 it sits in* (`netblocks`). The one axis none of
 * them covers is the one every operator reaches for first when a public scanner
 * shows up: **geography.** "Is this an Asia-Pacific flood, a European VPS, a Latin
 * American botnet?" There is no GeoIP database here (and no network to fetch one),
 * so this report does the next best, fully-offline thing: it attributes every
 * public source IP to the **Regional Internet Registry (RIR)** that administers
 * its address block, using the authoritative IANA allocation tables:
 *
 *   - **IPv4** — the IANA IPv4 /8 address-space registry: each of the 256 `a.0.0.0`
 *     blocks is allocated to exactly one of the five RIRs (or is special-use). A
 *     single byte — the first octet — decides the region, so the lookup is a
 *     constant-time table read with zero ambiguity.
 *   - **IPv6** — the IANA global-unicast (`2000::/3`) /12 sub-delegations:
 *     `2400::/12` APNIC, `2600::/12` ARIN, `2800::/12` LACNIC, `2a00::/12` RIPE
 *     NCC, `2c00::/12` AFRINIC. Older `2001::/16` allocations fall to *unknown*.
 *
 * The five RIRs map cleanly onto continents, so the rollup is a continental-grade
 * geographic picture:
 *
 *   - 🌎 **ARIN** — North America (US, Canada, some Caribbean)
 *   - 🌍 **RIPE NCC** — Europe, the Middle East and Central Asia
 *   - 🌏 **APNIC** — Asia-Pacific
 *   - 🌎 **LACNIC** — Latin America and the Caribbean
 *   - 🌍 **AFRINIC** — Africa
 *
 * For every region, rolled up from the stored history:
 *
 *   - alert volume and its share of the (public-source) stream — the headline
 *     "X% of my attacks originate from APNIC space" number;
 *   - breadth — distinct source addresses and distinct internal targets reached;
 *   - the severity profile (worst, medium-or-worse, critical) and a
 *     severity-weighted score, so a quiet-but-dangerous region is not buried under
 *     a noisy-but-harmless one (mirrors `cloud.ts` / `classify.ts`);
 *   - enforcement posture — blocked vs detected and the resulting block rate;
 *   - a recent-vs-older split, so an *emerging* regional push (most hits in the
 *     recent half) is flagged;
 *   - the dominant signature, and the **RIR WHOIS server** to query for ownership
 *     — the actionable pivot into attribution / abuse follow-up.
 *
 * It then lists the individual top offending source addresses, each tagged with
 * its region and the WHOIS host to look it up in — a ready-to-pivot worklist.
 *
 * Honest caveats baked into the output:
 *
 *   - **RIR ≠ geolocation.** A region is the registry that *allocated* the block,
 *     a coarse continental proxy — not a city, not even reliably a country. A
 *     multinational ISP, an anycast service or a VPN exit can announce
 *     RIPE-allocated space from anywhere. Trust the ordering, not pinpoint claims.
 *   - **Legacy & transferred blocks drift.** Pre-RIR "legacy" /8s and inter-RIR
 *     transfers can sit in a region other than where they are used; at /8
 *     granularity a handful of blocks are mis-continental. The bulk modern
 *     allocations are accurate.
 *   - **Unknown ≠ nowhere.** An unallocated/IPv6-legacy source falls to *unknown*;
 *     that is "registry not resolved", not "no origin".
 *   - **Internal/bogon sources are excluded** from the denominator (see `bogon`),
 *     as are source-less alerts (see `coverage`). This covers only public sources.
 *   - **Window-bounded & store-capped.** A long look-back can hit the alert
 *     store's history cap and clip the earliest alerts.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network, no GeoIP
 * DB. Output is both a structured model and a ready-to-paste Markdown document,
 * mirroring cloud.ts, bogon.ts, classify.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** The five Regional Internet Registries, plus the catch-all bucket. */
export type RirKey = "arin" | "ripe" | "apnic" | "lacnic" | "afrinic" | "unknown";

/** Static description of one RIR — continent, glyph and WHOIS pivot. */
export interface RirDef {
  /** Stable key, e.g. "apnic". */
  key: RirKey;
  /** Registry short name, e.g. "RIPE NCC". */
  label: string;
  /** Continental region the registry serves. */
  region: string;
  /** A leading glyph for the region. */
  glyph: string;
  /** Authoritative WHOIS host to look an address up in (empty for unknown). */
  whois: string;
}

/** Blocked / passed / unknown disposition split for a region. */
export interface DispositionSplit {
  /** Alerts the gateway actively blocked / dropped. */
  blocked: number;
  /** Alerts the gateway logged but let through (detected / allowed). */
  passed: number;
  /** Alerts with no recorded action (excluded from {@link blockRate}). */
  unknown: number;
  /**
   * Fraction of *actioned* (blocked + passed) alerts that were blocked, 0..1
   * (4dp), or null when nothing was actioned.
   */
  blockRate: number | null;
}

/** One top offending source address, tagged with its region. */
export interface OffendingSource {
  /** The source IP, verbatim. */
  ip: string;
  /** RIR key this address resolved to. */
  rir: RirKey;
  /** Registry label, for display. */
  rirLabel: string;
  /** WHOIS host to look this address up in. */
  whois: string;
  /** Windowed alerts from this address. */
  alerts: number;
  /** Distinct internal hosts this address reached. */
  distinctTargets: number;
  /** Worst severity seen from this address. */
  severityMax: Severity;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Whether this address is currently on the blocklist. */
  blocked: boolean;
  /** The most-frequent signature from this address, if any. */
  topSignature?: string;
}

/** One region (or the unknown bucket) rolled up over the window. */
export interface RegionEntry {
  /** Stable key, e.g. "apnic", "unknown". */
  key: RirKey;
  /** Registry label, e.g. "APNIC". */
  label: string;
  /** Continental region served. */
  region: string;
  /** Leading glyph. */
  glyph: string;
  /** WHOIS host (empty for the unknown bucket). */
  whois: string;
  /** Total windowed alerts whose source resolved to this region. */
  alerts: number;
  /** Share of all public-source alerts, 0..1 (4dp). */
  share: number;
  /** Distinct source addresses attributed to this region. */
  distinctSources: number;
  /** Distinct internal destination hosts this region's sources reached. */
  distinctTargets: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Alerts at critical severity. */
  critical: number;
  /** Severity-weighted score (Σ SEVERITY_WEIGHT) — the secondary risk lens. */
  score: number;
  /** Worst severity seen for this region. */
  severityMax: Severity;
  /** Blocked / passed / unknown disposition split. */
  disposition: DispositionSplit;
  /** Alerts whose timestamp fell in the recent half of the window. */
  recentHalf: number;
  /** Share of this region's alerts in the recent half, 0..1 (4dp). */
  recentShare: number;
  /** The most-frequent signature for this region, if any. */
  topSignature?: string;
  /** Distinct signatures seen from this region. */
  distinctSignatures: number;
  /** How many of this region's source addresses are currently blocked. */
  blockedSources: number;
}

export interface OriginsReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts with a parseable *public* source IP (the denominator). */
  publicSources: number;
  /** Alerts excluded for having no parseable source IP. */
  unresolved: number;
  /** Alerts excluded for an internal / bogon / non-public source. */
  nonPublic: number;
  /** Public-source alerts resolved to one of the five RIRs (not unknown). */
  resolvedAlerts: number;
  /** Distinct source addresses resolved to a known RIR. */
  distinctResolvedSources: number;
  /** Count of distinct regions (RIRs) seen, excluding the unknown bucket. */
  regionsSeen: number;
  /** Per-region rows, most alerts first. */
  regions: RegionEntry[];
  /** The individual top offending source addresses. */
  offenders: OffendingSource[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface OriginsOptions {
  /** Max rows in the offending-source table (clamped to [1, 200]). */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 25;
const MS_PER_HOUR = 3_600_000;

// ----- RIR registry ----------------------------------------------------------

const RIRS: Record<RirKey, RirDef> = {
  arin: {
    key: "arin",
    label: "ARIN",
    region: "North America",
    glyph: "🌎",
    whois: "whois.arin.net",
  },
  ripe: {
    key: "ripe",
    label: "RIPE NCC",
    region: "Europe / Middle East / Central Asia",
    glyph: "🌍",
    whois: "whois.ripe.net",
  },
  apnic: {
    key: "apnic",
    label: "APNIC",
    region: "Asia-Pacific",
    glyph: "🌏",
    whois: "whois.apnic.net",
  },
  lacnic: {
    key: "lacnic",
    label: "LACNIC",
    region: "Latin America & Caribbean",
    glyph: "🌎",
    whois: "whois.lacnic.net",
  },
  afrinic: {
    key: "afrinic",
    label: "AFRINIC",
    region: "Africa",
    glyph: "🌍",
    whois: "whois.afrinic.net",
  },
  unknown: {
    key: "unknown",
    label: "Unknown / unallocated",
    region: "—",
    glyph: "❓",
    whois: "",
  },
};

/**
 * The IANA IPv4 /8 address-space registry, encoded as `[startOctet, endOctet,
 * rir]` runs over the first octet. Each `a.0.0.0/8` block is administered by
 * exactly one RIR; special-use blocks (0, 10, 127, 224–255 etc.) are marked
 * `special` and never reach this table — they are filtered as non-public sources
 * before lookup. Built from the published IANA registry; legacy "administered by"
 * blocks are attributed to their administering RIR's region (the standard coarse
 * convention). A handful of legacy/transferred /8s may sit out-of-region — see
 * the report caveats; this is continental-grade, not geolocation.
 */
type OctetRir = RirKey | "special";
const IPV4_OCTET_RUNS: ReadonlyArray<readonly [number, number, OctetRir]> = [
  [0, 0, "special"],
  [1, 1, "apnic"],
  [2, 2, "ripe"],
  [3, 4, "arin"],
  [5, 5, "ripe"],
  [6, 9, "arin"],
  [10, 10, "special"],
  [11, 13, "arin"],
  [14, 14, "apnic"],
  [15, 24, "arin"],
  [25, 25, "ripe"],
  [26, 26, "arin"],
  [27, 27, "apnic"],
  [28, 30, "arin"],
  [31, 31, "ripe"],
  [32, 35, "arin"],
  [36, 36, "apnic"],
  [37, 37, "ripe"],
  [38, 38, "arin"],
  [39, 39, "apnic"],
  [40, 40, "arin"],
  [41, 41, "afrinic"],
  [42, 43, "apnic"],
  [44, 45, "arin"],
  [46, 46, "ripe"],
  [47, 48, "arin"],
  [49, 49, "apnic"],
  [50, 50, "arin"],
  [51, 51, "ripe"],
  [52, 52, "arin"],
  [53, 53, "ripe"],
  [54, 57, "arin"],
  [58, 61, "apnic"],
  [62, 62, "ripe"],
  [63, 76, "arin"],
  [77, 95, "ripe"],
  [96, 100, "arin"],
  [101, 101, "apnic"],
  [102, 102, "afrinic"],
  [103, 103, "apnic"],
  [104, 104, "arin"],
  [105, 105, "afrinic"],
  [106, 106, "apnic"],
  [107, 108, "arin"],
  [109, 109, "ripe"],
  [110, 126, "apnic"],
  [127, 127, "special"],
  [128, 132, "arin"],
  [133, 133, "apnic"],
  [134, 140, "arin"],
  [141, 141, "ripe"],
  [142, 144, "arin"],
  [145, 145, "ripe"],
  [146, 149, "arin"],
  [150, 150, "apnic"],
  [151, 151, "ripe"],
  [152, 152, "arin"],
  [153, 153, "apnic"],
  [154, 154, "afrinic"],
  [155, 162, "arin"],
  [163, 163, "apnic"],
  [164, 170, "arin"],
  [171, 171, "apnic"],
  [172, 174, "arin"],
  [175, 175, "apnic"],
  [176, 176, "ripe"],
  [177, 177, "lacnic"],
  [178, 178, "ripe"],
  [179, 179, "lacnic"],
  [180, 180, "apnic"],
  [181, 181, "lacnic"],
  [182, 183, "apnic"],
  [184, 184, "arin"],
  [185, 185, "ripe"],
  [186, 187, "lacnic"],
  [188, 188, "ripe"],
  [189, 191, "lacnic"],
  [192, 192, "arin"],
  [193, 195, "ripe"],
  [196, 197, "afrinic"],
  [198, 199, "arin"],
  [200, 201, "lacnic"],
  [202, 203, "apnic"],
  [204, 209, "arin"],
  [210, 211, "apnic"],
  [212, 213, "ripe"],
  [214, 216, "arin"],
  [217, 217, "ripe"],
  [218, 223, "apnic"],
  [224, 255, "special"],
];

/** Expand the runs into a 256-entry first-octet → RIR lookup once, at load. */
const IPV4_OCTET: OctetRir[] = (() => {
  const out: OctetRir[] = new Array(256).fill("unknown");
  for (const [lo, hi, rir] of IPV4_OCTET_RUNS) {
    for (let o = lo; o <= hi; o++) out[o] = rir;
  }
  return out;
})();

/**
 * IANA IPv6 global-unicast (`2000::/3`) /12 RIR sub-delegations, keyed by the top
 * 12 bits of the first hextet (i.e. `firstHextet >> 4`). Older `2001::/16`
 * allocations are intentionally absent → they resolve to `unknown`.
 */
const IPV6_TOP12: Record<number, RirKey> = {
  0x240: "apnic", // 2400::/12
  0x260: "arin", // 2600::/12
  0x280: "lacnic", // 2800::/12
  0x2a0: "ripe", // 2a00::/12
  0x2c0: "afrinic", // 2c00::/12
};

/** First hextet of an IPv6 literal as a number, or null if unparseable. */
function ipv6FirstHextet(ip: string): number | null {
  // The leading group runs up to the first ":" (or "::"). "::1" → "" (zero).
  const head = ip.split(":")[0] ?? "";
  if (head === "") return 0; // address begins with "::" → 0x0000, not unicast
  const v = parseInt(head, 16);
  return Number.isFinite(v) ? v & 0xffff : null;
}

/**
 * Resolve a (already known-public) source IP to its administering RIR, or
 * "unknown" when the registry cannot be determined offline. Exported so sibling
 * reports can reuse the single source of regional truth.
 */
export function classifyRir(ip: string): RirKey {
  const kind = isIP(ip);
  if (kind === 4) {
    const first = Number(ip.split(".")[0]);
    if (!Number.isInteger(first) || first < 0 || first > 255) return "unknown";
    const r = IPV4_OCTET[first];
    return r === "special" || r === undefined ? "unknown" : r;
  }
  if (kind === 6) {
    const hx = ipv6FirstHextet(ip);
    if (hx === null) return "unknown";
    return IPV6_TOP12[hx >> 4] ?? "unknown";
  }
  return "unknown";
}

// ----- shared helpers (mirror cloud.ts / bogon.ts) ---------------------------

/** RFC1918 / loopback / link-local / ULA / CGN / multicast — non-public. */
function isPrivate(ip: string): boolean {
  return /^(0\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|22[4-9]\.|23\d\.|24\d\.|25[0-5]\.|::1|::$|fe80|fc|fd|ff)/i.test(
    ip,
  );
}

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

/** A tiny unicode share-bar for the at-a-glance distribution. */
function bar(frac: number, width = 16): string {
  const filled = Math.max(0, Math.min(width, Math.round(frac * width)));
  return "█".repeat(filled) + "·".repeat(width - filled);
}

// ----- aggregation -----------------------------------------------------------

interface RegionAcc {
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
  recentHalf: number;
  sigCounts: Map<string, number>;
  blockedSources: Set<string>;
}

function newRegionAcc(): RegionAcc {
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
    recentHalf: 0,
    sigCounts: new Map(),
    blockedSources: new Set(),
  };
}

interface SrcAcc {
  ip: string;
  rir: RirKey;
  alerts: number;
  targets: Set<string>;
  severityMax: Severity;
  severe: number;
  sigCounts: Map<string, number>;
}

function tallyRegion(acc: RegionAcc, a: StoredAlert, src: string, midMs: number): void {
  acc.alerts++;
  acc.score += weightOf(a.severity);
  acc.severityMax = maxSeverity(acc.severityMax, a.severity);
  if (isSevere(a.severity)) acc.severe++;
  if (isCritical(a.severity)) acc.critical++;

  acc.sources.add(src);
  if (blockStore.has(src)) acc.blockedSources.add(src);

  const dst = validIp(a.dstIp);
  if (dst && isPrivate(dst)) acc.targets.add(dst);

  const disp = classifyDisposition(a.action);
  if (disp === "blocked") acc.blocked++;
  else if (disp === "passed") acc.passed++;
  else acc.unknown++;

  if (a.time >= midMs) acc.recentHalf++;

  const sig = (a.signature ?? "").trim();
  if (sig) acc.sigCounts.set(sig, (acc.sigCounts.get(sig) ?? 0) + 1);
}

function tallySource(acc: SrcAcc, a: StoredAlert): void {
  acc.alerts++;
  acc.severityMax = maxSeverity(acc.severityMax, a.severity);
  if (isSevere(a.severity)) acc.severe++;
  const dst = validIp(a.dstIp);
  if (dst && isPrivate(dst)) acc.targets.add(dst);
  const sig = (a.signature ?? "").trim();
  if (sig) acc.sigCounts.set(sig, (acc.sigCounts.get(sig) ?? 0) + 1);
}

function finalizeRegion(key: RirKey, acc: RegionAcc, publicTotal: number): RegionEntry {
  const meta = RIRS[key];
  const actioned = acc.blocked + acc.passed;
  return {
    key,
    label: meta.label,
    region: meta.region,
    glyph: meta.glyph,
    whois: meta.whois,
    alerts: acc.alerts,
    share: publicTotal ? round4(acc.alerts / publicTotal) : 0,
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
    recentHalf: acc.recentHalf,
    recentShare: acc.alerts ? round4(acc.recentHalf / acc.alerts) : 0,
    topSignature: topOf(acc.sigCounts),
    distinctSignatures: acc.sigCounts.size,
    blockedSources: acc.blockedSources.size,
  } satisfies RegionEntry;
}

/** Rank regions: known RIRs (by alerts, then score) before the unknown bucket. */
function rankRegion(a: RegionEntry, b: RegionEntry): number {
  const au = a.key === "unknown" ? 1 : 0;
  const bu = b.key === "unknown" ? 1 : 0;
  return (
    au - bu ||
    b.alerts - a.alerts ||
    b.score - a.score ||
    (a.label < b.label ? -1 : a.label > b.label ? 1 : 0)
  );
}

/** Rank offending sources by volume, then severity, then address. */
function rankSource(a: OffendingSource, b: OffendingSource): number {
  return (
    b.alerts - a.alerts ||
    sevRank(b.severityMax) - sevRank(a.severityMax) ||
    (a.ip < b.ip ? -1 : a.ip > b.ip ? 1 : 0)
  );
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(
  m: {
    hours: number;
    publicSources: number;
    unresolved: number;
    nonPublic: number;
    resolvedAlerts: number;
    distinctResolvedSources: number;
    regionsSeen: number;
  },
  regions: RegionEntry[],
): string[] {
  const out: string[] = [];
  if (!regions.length) return out;

  const known = regions.filter((r) => r.key !== "unknown");
  const unknown = regions.find((r) => r.key === "unknown");

  // The headline: the dominant origin region and how concentrated it is.
  const top = known[0];
  if (top) {
    const conc =
      m.publicSources > 0 && known.length > 1
        ? ` Of the ${m.regionsSeen} region(s) seen, this one alone is ${pct(top.share)} of the public-source stream`
        : "";
    out.push(
      `${top.glyph} **${top.label} (${top.region}) is your top attack origin** — ${top.alerts} alert(s) ` +
        `(${pct(top.share)} of public sources) from ${top.distinctSources} distinct address(es), worst ` +
        `\`${top.severityMax}\`, **${pct(top.disposition.blockRate)}** of actioned traffic blocked.${conc}. ` +
        `Look ownership up in \`${top.whois}\`.`,
    );
  }

  // Volume ≠ risk: the region whose *average* alert is nastiest (by score-per-alert).
  const byDensity = known
    .filter((r) => r.alerts >= 3)
    .map((r) => ({ r, density: r.alerts ? r.score / r.alerts : 0 }))
    .sort((a, b) => b.density - a.density)[0];
  if (byDensity && (!top || byDensity.r.key !== top.key) && byDensity.r.severe > 0) {
    out.push(
      `⚠️ **Quiet but nasty:** ${byDensity.r.glyph} **${byDensity.r.label}** carries the heaviest *per-alert* ` +
        `severity (${byDensity.r.severe} medium-or-worse of ${byDensity.r.alerts}, worst \`${byDensity.r.severityMax}\`) ` +
        `even though it is not the loudest region. Volume rankings bury it — treat its sources as priority pivots.`,
    );
  }

  // An emerging regional push (front-loaded into the recent half of the window).
  const rising = known
    .filter((r) => r.alerts >= 5 && r.recentShare >= 0.6)
    .sort((a, b) => b.recentShare - a.recentShare)[0];
  if (rising) {
    out.push(
      `📈 **Emerging push from ${rising.label}:** ${pct(rising.recentShare)} of its ${rising.alerts} alert(s) landed ` +
        `in the recent half of the window — a building campaign from ${rising.region}, not a stale artefact.`,
    );
  }

  // Geographic spread vs concentration — one-region vs world-wide pressure.
  if (m.regionsSeen >= 4) {
    out.push(
      `🌐 **Globally distributed:** attack pressure spans ${m.regionsSeen} of the 5 RIRs — a broad, internet-wide ` +
        `posture (commodity scanning / botnet) rather than a single-region adversary. Per-IP blocking will not dent ` +
        `the regional picture; lean on signature tuning and rate controls (see \`tuning\`, \`netblocks\`).`,
    );
  } else if (top && top.share >= 0.6) {
    out.push(
      `🎯 **Concentrated origin:** ${pct(top.share)} of public-source alerts come from a single region (${top.label}). ` +
        `A region-aware control (or escalated scrutiny of ${top.whois} space) covers most of the pressure at once.`,
    );
  }

  // Attribution honesty: the unknown share.
  if (unknown && unknown.alerts > 0) {
    out.push(
      `❓ **${pct(unknown.share)}** of public-source alerts (${unknown.alerts}) could not be resolved to a registry ` +
        `(unallocated, IPv6-legacy or table gap) — "registry unknown", not "no origin". Pivot these through ` +
        `\`netblocks\` / \`clusters\`.`,
    );
  }

  // What was excluded from the denominator, for honesty.
  if (m.nonPublic > 0 || m.unresolved > 0) {
    out.push(
      `🔍 Excluded from the denominator: **${m.nonPublic}** internal/bogon-source alert(s) (see \`bogon\`) and ` +
        `**${m.unresolved}** with no parseable source IP (see \`coverage\`). This report covers only the ` +
        `${m.publicSources} alert(s) with a public source address.`,
    );
  }

  return out;
}

// ----- markdown --------------------------------------------------------------

function regionTable(rows: RegionEntry[]): string {
  const headers = [
    "#",
    "Region",
    "Registry",
    "Alerts",
    "Share",
    "Distribution",
    "Sources",
    "Targets",
    "Worst",
    "Severe",
    "Block rate",
    "Recent½",
    "WHOIS",
  ];
  return mdTable(
    headers,
    rows.map((r, i) => [
      String(i + 1),
      `${r.glyph} ${cell(r.region)}`,
      cell(r.label),
      String(r.alerts),
      pct(r.share),
      `\`${bar(r.share)}\``,
      String(r.distinctSources),
      String(r.distinctTargets),
      cell(r.severityMax),
      String(r.severe),
      pct(r.disposition.blockRate),
      pct(r.recentShare),
      r.whois ? `\`${cell(r.whois)}\`` : "—",
    ]),
  );
}

function offenderTable(rows: OffendingSource[]): string {
  const headers = [
    "#",
    "Source address",
    "Region",
    "Alerts",
    "Targets",
    "Worst",
    "Severe",
    "Blocked?",
    "WHOIS",
    "Top signature",
  ];
  return mdTable(
    headers,
    rows.map((o, i) => [
      String(i + 1),
      cell(o.ip),
      cell(`${RIRS[o.rir].glyph} ${o.rirLabel}`),
      String(o.alerts),
      String(o.distinctTargets),
      cell(o.severityMax),
      String(o.severe),
      o.blocked ? "yes" : "no",
      o.whois ? `\`${cell(o.whois)}\`` : "—",
      o.topSignature ? cell(clip(o.topSignature)) : "—",
    ]),
  );
}

function renderMarkdown(m: OriginsReport): string {
  const lines: string[] = [];
  lines.push(`# 🌐 SecTool Regional / RIR Origin Attribution`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** each alert's **public source IP** is attributed offline to the Regional Internet Registry that ` +
      `administers its block — IPv4 by the IANA /8 registry (first octet), IPv6 by the \`2000::/3\` /12 ` +
      `sub-delegations — and rolled up per continental region · **Public sources:** ${m.publicSources} of ` +
      `${m.totalWindowAlerts} alert(s) (${m.nonPublic} internal/bogon, ${m.unresolved} no source — excluded)`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.regions.length) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to attribute.`);
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but **none carried a parseable public ` +
          `source IP** — without a public source address there is no region to attribute. See \`bogon\` for ` +
          `internal/spoofed sources and \`coverage\` for field completeness.`,
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

  lines.push(`## Regions`);
  lines.push("");
  lines.push(regionTable(m.regions));
  lines.push("");
  lines.push(
    `**Legend:** _Share_ and the _Distribution_ bar are of the ${m.publicSources} public-source alerts. ` +
      `🌎 ARIN = North America · 🌍 RIPE NCC = Europe/Middle East/Central Asia · 🌏 APNIC = Asia-Pacific · ` +
      `🌎 LACNIC = Latin America/Caribbean · 🌍 AFRINIC = Africa · ❓ unknown = registry unresolved. _Severe_ = ` +
      `medium-or-worse. _Block rate_ = blocked ÷ actioned. _Recent½_ = share of the region's alerts in the recent ` +
      `half of the window (> 60% = emerging). _WHOIS_ is the registry host to query for ownership. Rows are ranked ` +
      `by alert volume (unknown last).`,
  );
  lines.push("");

  lines.push(`## Top offending source addresses`);
  lines.push("");
  if (m.offenders.length) {
    lines.push(offenderTable(m.offenders));
    lines.push("");
    lines.push(
      `_The busiest individual public sources, each tagged with its administering registry and the WHOIS host to ` +
        `look it up in. Region is a continental hint for triage and reporting — pair it with \`cloud\` (hosting ` +
        `provider + abuse desk) and \`abuse\` (ready-to-send complaint) to action a takedown._`,
    );
  } else {
    lines.push(`_No public source address in this window — nothing to list._`);
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Sources are attributed to a **Regional Internet Registry** purely by the ` +
      `authoritative IANA allocation tables (IPv4 /8 registry · IPv6 \`2000::/3\` /12 sub-delegations) — no GeoIP ` +
      `database, no WHOIS query, no network. **A region is the registry that allocated the block, a continental ` +
      `proxy — not a geolocation:** a multinational ISP, anycast service or VPN exit can announce a region's space ` +
      `from anywhere, and a handful of legacy/transferred /8s sit out-of-region. Trust the ordering, not pinpoint ` +
      `claims. **Unknown** = registry unresolved (unallocated / IPv6-legacy / table gap), *not* "no origin". Figures ` +
      `are drawn from the ${m.publicSources} of ${m.totalWindowAlerts} alert(s) with a public source IP ` +
      `(${m.nonPublic} internal/bogon and ${m.unresolved} source-less were excluded). A long look-back can hit the ` +
      `store's history cap and clip the earliest alerts. The hosting-provider lens is \`cloud\`; address validity is ` +
      `\`bogon\`; CIDR rollup is \`netblocks\`. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the regional / RIR origin-attribution report from the stored alert
 * history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link OriginsOptions}: `limit` for the offender table and a
 *              `nowMs` pin for deterministic tests.
 */
export function buildOrigins(hours: number, opts: OriginsOptions = {}): OriginsReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;
  const midMs = windowStartMs + (windowEndMs - windowStartMs) / 2;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const regionAcc = new Map<RirKey, RegionAcc>();
  const srcAcc = new Map<string, SrcAcc>();
  const rirCache = new Map<string, RirKey>(); // ip -> rir key (memoised)
  let publicSources = 0;
  let unresolved = 0;
  let nonPublic = 0;
  let resolvedAlerts = 0;

  for (const a of windowed) {
    const src = validIp(a.srcIp);
    if (!src) {
      unresolved++;
      continue;
    }
    if (isPrivate(src)) {
      nonPublic++;
      continue;
    }
    publicSources++;

    let key = rirCache.get(src);
    if (key === undefined) {
      key = classifyRir(src);
      rirCache.set(src, key);
    }

    const acc = regionAcc.get(key) ?? newRegionAcc();
    if (!regionAcc.has(key)) regionAcc.set(key, acc);
    tallyRegion(acc, a, src, midMs);

    if (key !== "unknown") resolvedAlerts++;

    // Enumerate every public source for the worklist — unknown-region sources are
    // still worth listing as pivot targets; they simply carry no WHOIS host.
    const sa =
      srcAcc.get(src) ??
      {
        ip: src,
        rir: key,
        alerts: 0,
        targets: new Set<string>(),
        severityMax: "info" as Severity,
        severe: 0,
        sigCounts: new Map<string, number>(),
      };
    if (!srcAcc.has(src)) srcAcc.set(src, sa);
    tallySource(sa, a);
  }

  const regions = [...regionAcc.entries()]
    .map(([key, acc]) => finalizeRegion(key, acc, publicSources))
    .sort(rankRegion);

  const offenders: OffendingSource[] = [...srcAcc.values()]
    .map((sa) => {
      const meta = RIRS[sa.rir];
      return {
        ip: sa.ip,
        rir: sa.rir,
        rirLabel: meta.label,
        whois: meta.whois,
        alerts: sa.alerts,
        distinctTargets: sa.targets.size,
        severityMax: sa.severityMax,
        severe: sa.severe,
        blocked: blockStore.has(sa.ip),
        topSignature: topOf(sa.sigCounts),
      } satisfies OffendingSource;
    })
    .sort(rankSource)
    .slice(0, limit);

  const regionsSeen = regions.filter((r) => r.key !== "unknown").length;

  const base = {
    hours: safeHours,
    publicSources,
    unresolved,
    nonPublic,
    resolvedAlerts,
    distinctResolvedSources: [...srcAcc.values()].filter((s) => s.rir !== "unknown").length,
    regionsSeen,
  };

  const highlights = writeHighlights(base, regions);

  const model: OriginsReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    publicSources,
    unresolved,
    nonPublic,
    resolvedAlerts,
    distinctResolvedSources: base.distinctResolvedSources,
    regionsSeen,
    regions,
    offenders,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded regional-origins report. */
export function originsFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-origins-${stamp}.md`;
}
