/**
 * Source-netblock / infrastructure-aggregation report — "are these many attacking
 * IPs *adjacent*? Do they collapse into a handful of network blocks I can block
 * with one CIDR rule instead of chasing each address?"
 *
 * Every other source-oriented report in this project ranks or scores *individual*
 * IPs (persistence, campaigns), *pairs* of IPs (edges), or the *shape* of the IP
 * distribution (focus, spread). None of them looks at the structure that sits one
 * level *above* the address: the network block it lives in. That gap matters,
 * because the single most common evasion against per-IP defence is **rotation** —
 * a botnet, a compromised hosting range, or a cloud subnet sprays from dozens of
 * neighbouring addresses, each tripping just a few alerts so none of them clears a
 * per-IP threshold, while the *block as a whole* is hammering the perimeter. To a
 * report that ranks individual IPs the campaign is invisible; to one that rolls
 * IPs up into their /24 and /16 prefixes it is a single, obvious, high-leverage row.
 *
 * This report folds every **external** source IP in the window into two CIDR
 * groupings and ranks the resulting blocks:
 *
 *   - `/24` blocks (256 addresses) — the "tight" grouping. A /24 that spans
 *     several distinct attacking IPs is almost always one operator / one piece of
 *     infrastructure; blocking the /24 replaces N individual blocks and pre-empts
 *     the *next* address in the range before it ever fires.
 *   - `/16` blocks (65 536 addresses) — the "wide" grouping, roughly the size of
 *     a small provider allocation. Useful for spotting a whole hostile network /
 *     AS-ish region, but far blunter: a /16 can legitimately hold thousands of
 *     unrelated tenants, so it is shown for situational awareness, not as a
 *     one-click block recommendation.
 *
 * For each block it reports, from the windowed alerts:
 *
 *   - total alerts and **distinct source IPs** (the diversity that distinguishes
 *     "one noisy host" from "coordinated rotation"),
 *   - distinct internal targets hit and distinct signatures fired,
 *   - the block's share of all external-source alerts,
 *   - first/last seen, and a `coordinated` flag (≥ {@link COORD_MIN_IPS} distinct
 *     IPs) marking blocks where a CIDR rule is genuinely higher-leverage than
 *     per-IP blocking,
 *   - how many of the block's IPs are *already* on the blocklist / watchlist /
 *     safelist, so the "still on the table" quick win is explicit,
 *   - the busiest member IPs, for the coordinated blocks, so the operator can see
 *     the rotation directly.
 *
 * Honest caveats baked into the output:
 *
 *   - **A /24 is a heuristic, not a real boundary.** Allocation boundaries follow
 *     BGP/whois, not octet math; a /24 can straddle two tenants or sit inside a
 *     larger single allocation. Treat "coordinated" as a strong hint to *look*,
 *     not an automatic block — especially for shared-hosting / CDN ranges.
 *   - **Alerts, not flows.** SecTool stores IPS *detections*; a block whose hosts
 *     never trip a rule is invisible here.
 *   - **IPv4 only.** Source IPs that are IPv6 are counted and reported separately
 *     but not CIDR-aggregated (prefix math on compressed v6 is error-prone; an
 *     honest exclusion beats a buggy grouping). Internal/RFC1918 sources are
 *     excluded entirely — this is an external-attacker lens.
 *   - **Window-bounded & store-capped.** A long look-back can hit the store's
 *     history cap and under-count older blocks.
 *
 * Pure in-memory math over alertStore (plus blocklist/watchlist/safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring report.ts, focus.ts,
 * persistence.ts, edges.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { SEVERITY_ORDER } from "../types.ts";

/** CIDR prefix length for the two groupings this report ranks. */
export type BlockPrefix = 24 | 16;

/** A single member IP inside a netblock, with its weight and list membership. */
export interface MemberIp {
  ip: string;
  /** Windowed alert count attributed to this IP. */
  alerts: number;
  /** IP is on the blocklist. */
  blocked: boolean;
  /** IP is on the watchlist. */
  watched: boolean;
  /** IP is marked safe. */
  safe: boolean;
}

/** Aggregated metrics for one CIDR block over the window. */
export interface NetblockStat {
  /** Canonical CIDR string, e.g. "203.0.113.0/24". */
  cidr: string;
  /** Prefix length (24 or 16). */
  prefix: BlockPrefix;
  /** Total alerts attributed to IPs in this block. */
  alerts: number;
  /** Distinct source IPs seen in this block — the rotation/coordination signal. */
  distinctIps: number;
  /** Distinct internal targets these sources hit. */
  distinctTargets: number;
  /** Distinct signatures fired by this block. */
  distinctSignatures: number;
  /** The dominant signature driving the block (may be empty). */
  topSignature: string;
  /** Highest severity seen from the block ("info".."critical"). */
  maxSeverity: string;
  /** alerts / all external-source alerts, 0..1 (4dp). */
  share: number;
  /** Earliest alert time from the block (ms). */
  firstSeenMs: number;
  /** Latest alert time from the block (ms). */
  lastSeenMs: number;
  /** How many of the block's distinct IPs are already on the blocklist. */
  blockedIps: number;
  /** How many of the block's distinct IPs are on the watchlist. */
  watchedIps: number;
  /** How many of the block's distinct IPs are marked safe. */
  safeIps: number;
  /** True when distinctIps ≥ {@link COORD_MIN_IPS}: a CIDR rule beats per-IP. */
  coordinated: boolean;
  /** Busiest member IPs, most-frequent first (only populated for the tables shown). */
  topIps: MemberIp[];
}

export interface NetblockReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Alerts whose source was a valid external IPv4 (the aggregation denominator). */
  externalIpv4Alerts: number;
  /** Distinct external IPv4 source addresses in the window. */
  distinctExternalIps: number;
  /** External source alerts that were IPv6 (counted, not aggregated). */
  ipv6SourceAlerts: number;
  /** Distinct external IPv6 source addresses (counted, not aggregated). */
  distinctIpv6Sources: number;
  /** Ranked /24 blocks, most alerts first, truncated to the limit. */
  blocks24: NetblockStat[];
  /** Ranked /16 blocks, most alerts first, truncated to the limit. */
  blocks16: NetblockStat[];
  /** Distinct /24 blocks observed (before truncation). */
  total24: number;
  /** Distinct /16 blocks observed (before truncation). */
  total16: number;
  /** How many /24 blocks are coordinated (≥ {@link COORD_MIN_IPS} distinct IPs). */
  coordinated24: number;
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface NetblockOptions {
  /** Max rows per block table (clamped to [1, 500]). */
  limit?: number;
  /** Min distinct IPs for a /24 to be flagged "coordinated" (clamped to [2, 256]). */
  coordMinIps?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const MS_PER_HOUR = 3_600_000;
/** Member IPs shown per coordinated /24 in the detail section. */
const MEMBER_ROWS = 6;
/** Default: a /24 spanning this many distinct attacking IPs reads as coordinated. */
const COORD_MIN_IPS = 3;

// ----- formatting helpers (mirror focus.ts / persistence.ts / edges.ts) -----

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** A 0..1 fraction as a whole-number percent string, e.g. 0.823 -> "82%". */
function pct(frac: number): string {
  return `${Math.round(frac * 100)}%`;
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
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
function clip(s: string, max = 40): string {
  const t = s.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

/** A short relative-age phrase for a "last seen" timestamp. */
function ago(ms: number, nowMs: number): string {
  const d = Math.max(0, nowMs - ms);
  const h = d / MS_PER_HOUR;
  if (h < 1) return `${Math.round(d / 60000)}m ago`;
  if (h < 48) return `${Math.round(h)}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

// ----- IP / CIDR helpers ----------------------------------------------------

/** RFC1918 / loopback / link-local / ULA — mirrors persistence.ts / spread.ts. */
function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
}

/** Parse a dotted IPv4 into its four octets, or undefined if not a clean IPv4. */
function ipv4Octets(ip: string): [number, number, number, number] | undefined {
  if (isIP(ip) !== 4) return undefined;
  const parts = ip.split(".");
  if (parts.length !== 4) return undefined;
  const o = parts.map((p) => Number(p));
  if (o.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return undefined;
  return [o[0]!, o[1]!, o[2]!, o[3]!];
}

/** Canonical CIDR string for the given octets at the given prefix. */
function cidrFor(o: [number, number, number, number], prefix: BlockPrefix): string {
  return prefix === 24 ? `${o[0]}.${o[1]}.${o[2]}.0/24` : `${o[0]}.${o[1]}.0.0/16`;
}

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf((s ?? "").toLowerCase());
  return i < 0 ? 0 : i;
}

function bumpMap(map: Map<string, number>, key: string | undefined): void {
  if (!key) return;
  map.set(key, (map.get(key) ?? 0) + 1);
}

// ----- aggregation ----------------------------------------------------------

/** Mutable per-block accumulator used while folding the alert window. */
interface Accum {
  cidr: string;
  prefix: BlockPrefix;
  alerts: number;
  ipCounts: Map<string, number>;
  targets: Set<string>;
  sigCounts: Map<string, number>;
  maxSev: number;
  firstSeenMs: number;
  lastSeenMs: number;
}

function newAccum(cidr: string, prefix: BlockPrefix): Accum {
  return {
    cidr,
    prefix,
    alerts: 0,
    ipCounts: new Map(),
    targets: new Set(),
    sigCounts: new Map(),
    maxSev: 0,
    firstSeenMs: Number.POSITIVE_INFINITY,
    lastSeenMs: 0,
  };
}

function fold(acc: Accum, a: StoredAlert, ip: string): void {
  acc.alerts++;
  acc.ipCounts.set(ip, (acc.ipCounts.get(ip) ?? 0) + 1);
  const dst = a.dstIp?.trim();
  if (dst) acc.targets.add(dst);
  bumpMap(acc.sigCounts, a.signature?.trim() || undefined);
  acc.maxSev = Math.max(acc.maxSev, sevRank(a.severity));
  if (a.time < acc.firstSeenMs) acc.firstSeenMs = a.time;
  if (a.time > acc.lastSeenMs) acc.lastSeenMs = a.time;
}

/** Most-frequent key in a count map (ties broken lexicographically), or "". */
function topKey(m: Map<string, number>): string {
  let best = "";
  let bestN = -1;
  for (const [k, n] of m) {
    if (n > bestN || (n === bestN && k < best)) {
      best = k;
      bestN = n;
    }
  }
  return best;
}

/** Finalize an accumulator into a {@link NetblockStat}, computing list membership. */
function finalize(
  acc: Accum,
  externalAlerts: number,
  coordMinIps: number,
  memberRows: number,
): NetblockStat {
  const ips = [...acc.ipCounts.entries()];
  let blockedIps = 0;
  let watchedIps = 0;
  let safeIps = 0;
  for (const [ip] of ips) {
    if (blockStore.has(ip)) blockedIps++;
    if (watchStore.has(ip)) watchedIps++;
    if (safeStore.has(ip)) safeIps++;
  }
  const topIps: MemberIp[] = ips
    .sort((x, y) => (y[1] - x[1]) || (x[0] < y[0] ? -1 : 1))
    .slice(0, memberRows)
    .map(([ip, alerts]) => ({
      ip,
      alerts,
      blocked: blockStore.has(ip),
      watched: watchStore.has(ip),
      safe: safeStore.has(ip),
    }));

  const distinctIps = acc.ipCounts.size;
  return {
    cidr: acc.cidr,
    prefix: acc.prefix,
    alerts: acc.alerts,
    distinctIps,
    distinctTargets: acc.targets.size,
    distinctSignatures: acc.sigCounts.size,
    topSignature: topKey(acc.sigCounts),
    maxSeverity: SEVERITY_ORDER[acc.maxSev] ?? "info",
    share: externalAlerts ? round4(acc.alerts / externalAlerts) : 0,
    firstSeenMs: Number.isFinite(acc.firstSeenMs) ? acc.firstSeenMs : acc.lastSeenMs,
    lastSeenMs: acc.lastSeenMs,
    blockedIps,
    watchedIps,
    safeIps,
    coordinated: distinctIps >= coordMinIps,
    topIps,
  };
}

/**
 * Rank order for both tables: most alerts first, then most distinct IPs (a wide
 * rotation outranks a single chatty host at equal volume), then most recent.
 */
function rank(a: NetblockStat, b: NetblockStat): number {
  return (b.alerts - a.alerts) || (b.distinctIps - a.distinctIps) || (b.lastSeenMs - a.lastSeenMs);
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(m: Omit<NetblockReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (!m.externalIpv4Alerts) return out;

  const coord = m.blocks24.filter((b) => b.coordinated);
  const top24 = m.blocks24[0];

  // Headline: how much of the noise is adjacent / collapsible.
  if (coord.length) {
    const ipsCovered = coord.reduce((s, b) => s + b.distinctIps, 0);
    const alertsCovered = coord.reduce((s, b) => s + b.alerts, 0);
    const shareCovered = m.externalIpv4Alerts ? alertsCovered / m.externalIpv4Alerts : 0;
    out.push(
      `🧱 **${coord.length} /24 block${coord.length === 1 ? "" : "s"}** each span ≥${COORD_MIN_IPS} distinct attacking ` +
        `IPs — together ${ipsCovered} addresses and ${pct(shareCovered)} of all external alerts. These read as ` +
        `*coordinated infrastructure / rotation*: one CIDR rule per block replaces ${ipsCovered} individual blocks ` +
        `and pre-empts the next address in each range.`,
    );
  } else if (m.total24) {
    out.push(
      `🧱 No /24 block spans ≥${COORD_MIN_IPS} distinct attacking IPs — the external sources are *scattered* across ` +
        `${m.total24} different /24s with little adjacency. CIDR-level blocking buys little here; treat sources ` +
        `individually (see the persistence / focus reports).`,
    );
  }

  // The single worst /24 — the highest-leverage block to action.
  if (top24) {
    const still = top24.distinctIps - top24.blockedIps;
    const stillNote =
      top24.blockedIps > 0
        ? ` (${top24.blockedIps} of its ${top24.distinctIps} IPs already blocked; ${still} still open)`
        : "";
    out.push(
      `🎯 Busiest block is \`${top24.cidr}\` — ${top24.alerts} alert(s) from ${top24.distinctIps} distinct IP(s) ` +
        `(${pct(top24.share)} of external volume), top rule \`${clip(top24.topSignature || "—")}\`${stillNote}.`,
    );
  }

  // Rotation tell: a coordinated block whose per-IP volume is low and even — many
  // short-lived addresses, the classic per-IP-threshold evasion.
  const rotators = coord
    .filter((b) => b.distinctIps >= COORD_MIN_IPS && b.alerts / b.distinctIps < 4)
    .sort((a, b) => b.distinctIps - a.distinctIps);
  if (rotators.length) {
    const r = rotators[0]!;
    out.push(
      `🔁 \`${r.cidr}\` is *rotating* — ${r.distinctIps} IPs averaging only ` +
        `${(r.alerts / r.distinctIps).toFixed(1)} alert(s) each, so no single address looks important while the ` +
        `block as a whole is busy. This is the pattern per-IP thresholds miss; block the /24.`,
    );
  }

  // Safelist guard — don't recommend CIDR-blocking a range that holds known-good IPs.
  const withSafe = m.blocks24.filter((b) => b.safeIps > 0);
  if (withSafe.length) {
    out.push(
      `✅ ${withSafe.length} ranked /24${withSafe.length === 1 ? "" : "s"} contain at least one *safelisted* IP — ` +
        `do **not** blanket-block these CIDRs; a /24 rule would also catch the known-good address. Block the ` +
        `offending IPs individually instead.`,
    );
  }

  // IPv6 transparency.
  if (m.ipv6SourceAlerts) {
    out.push(
      `ℹ️ ${m.ipv6SourceAlerts} external alert(s) from ${m.distinctIpv6Sources} IPv6 source(s) were counted but **not** ` +
        `CIDR-aggregated (IPv4 only). Review those addresses directly.`,
    );
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function blockTable(blocks: NetblockStat[], nowMs: number): string {
  return mdTable(
    ["#", "CIDR", "Alerts", "Share", "IPs", "Targets", "Sigs", "Top signature", "Sev", "On lists", "Last seen"],
    blocks.map((b, i) => {
      const lists =
        (b.blockedIps ? `⛔${b.blockedIps}` : "") +
        (b.watchedIps ? `👁${b.watchedIps}` : "") +
        (b.safeIps ? `✅${b.safeIps}` : "");
      return [
        String(i + 1),
        cell(b.cidr) + (b.coordinated ? " ⚑" : ""),
        String(b.alerts),
        pct(b.share),
        String(b.distinctIps),
        String(b.distinctTargets),
        String(b.distinctSignatures),
        cell(clip(b.topSignature || "—")),
        cell(b.maxSeverity),
        lists || "—",
        ago(b.lastSeenMs, nowMs),
      ];
    }),
  );
}

/** Member-IP detail for the top coordinated /24 blocks, so rotation is visible. */
function coordinatedDetail(blocks24: NetblockStat[], nowMs: number): string {
  const coord = blocks24.filter((b) => b.coordinated).slice(0, 8);
  if (!coord.length) return "";
  const parts: string[] = [];
  for (const b of coord) {
    parts.push(
      `**\`${b.cidr}\`** — ${b.alerts} alert(s), ${b.distinctIps} distinct IP(s), ` +
        `${b.distinctTargets} target(s), last seen ${ago(b.lastSeenMs, nowMs)}:`,
    );
    parts.push("");
    parts.push(
      mdTable(
        ["IP", "Alerts", "Flags"],
        b.topIps.map((ip) => {
          const flags = (ip.blocked ? "⛔" : "") + (ip.watched ? "👁" : "") + (ip.safe ? "✅" : "");
          return [cell(ip.ip), String(ip.alerts), flags || "—"];
        }),
      ),
    );
    if (b.distinctIps > b.topIps.length) {
      parts.push("");
      parts.push(`_…and ${b.distinctIps - b.topIps.length} more IP(s) in this block._`);
    }
    parts.push("");
  }
  return parts.join("\n");
}

function renderMarkdown(m: NetblockReport): string {
  const lines: string[] = [];
  lines.push(`# 🧱 SecTool Source-Netblock / Infrastructure Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** external IPv4 source IPs rolled up into /24 and /16 CIDR blocks over stored IPS alerts · ` +
      `**External alerts:** ${m.externalIpv4Alerts} from ${m.distinctExternalIps} distinct IP(s)`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.externalIpv4Alerts) {
    lines.push(
      `No external IPv4 source alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to aggregate.` +
        (m.ipv6SourceAlerts ? ` (${m.ipv6SourceAlerts} IPv6-source alert(s) were seen but are not CIDR-aggregated.)` : ""),
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(
    `Aggregated ${m.distinctExternalIps} external IPv4 source(s) into **${m.total24} /24** and **${m.total16} /16** ` +
      `block(s); **${m.coordinated24}** /24 block(s) span ≥${COORD_MIN_IPS} distinct IPs (⚑ coordinated).`,
  );
  lines.push("");

  lines.push(`## Top /24 source blocks (tight — CIDR-block candidates)`);
  lines.push("");
  lines.push(blockTable(m.blocks24, m.windowEndMs));
  lines.push("");
  lines.push(
    `**Legend:** _IPs_ = distinct source addresses in the block (the rotation/coordination signal) · ` +
      `_⚑_ = coordinated (≥${COORD_MIN_IPS} distinct IPs) · _On lists_ = how many of the block's IPs are already ` +
      `⛔ blocked / 👁 watched / ✅ safelisted. A coordinated block is a candidate for a single CIDR rule in place ` +
      `of N per-IP blocks — **unless** it carries a ✅, in which case block its IPs individually.`,
  );
  lines.push("");

  const detail = coordinatedDetail(m.blocks24, m.windowEndMs);
  if (detail) {
    lines.push(`## Coordinated /24 blocks — member IPs`);
    lines.push("");
    lines.push(detail);
  }

  lines.push(`## Top /16 source blocks (wide — situational awareness)`);
  lines.push("");
  lines.push(blockTable(m.blocks16, m.windowEndMs));
  lines.push("");
  lines.push(
    `_A /16 holds 65 536 addresses and can legitimately span thousands of unrelated tenants — use this table to ` +
      `recognise a broadly hostile provider / region, **not** as a one-click block list._`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from stored **IPS-alert** source IPs. CIDR grouping is octet math, not a real ` +
      `allocation boundary (which follows BGP/whois) — "coordinated" is a strong hint to *look*, not an automatic ` +
      `block, especially for shared-hosting / CDN ranges. Only external IPv4 sources are aggregated; IPv6 and ` +
      `internal sources are excluded (IPv6 is counted separately). A long look-back can hit the store's history cap ` +
      `and under-count older blocks. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the source-netblock / infrastructure report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link NetblockOptions}: `limit` (rows per table), `coordMinIps`
 *              (coordination threshold) and a `nowMs` pin for deterministic tests.
 */
export function buildNetblock(hours: number, opts: NetblockOptions = {}): NetblockReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(500, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const coordMinIps = Math.max(2, Math.min(256, Math.floor(opts.coordMinIps ?? COORD_MIN_IPS)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const map24 = new Map<string, Accum>();
  const map16 = new Map<string, Accum>();
  const externalIpv4 = new Set<string>();
  const ipv6Sources = new Set<string>();
  let externalIpv4Alerts = 0;
  let ipv6SourceAlerts = 0;

  for (const a of windowed) {
    const ip = a.srcIp?.trim();
    if (!ip) continue;
    const fam = isIP(ip);
    if (fam === 0 || isPrivate(ip)) continue; // external attackers only
    if (fam === 6) {
      ipv6SourceAlerts++;
      ipv6Sources.add(ip);
      continue; // counted, not aggregated
    }
    const octets = ipv4Octets(ip);
    if (!octets) continue;

    externalIpv4Alerts++;
    externalIpv4.add(ip);

    const c24 = cidrFor(octets, 24);
    let a24 = map24.get(c24);
    if (!a24) {
      a24 = newAccum(c24, 24);
      map24.set(c24, a24);
    }
    fold(a24, a, ip);

    const c16 = cidrFor(octets, 16);
    let a16 = map16.get(c16);
    if (!a16) {
      a16 = newAccum(c16, 16);
      map16.set(c16, a16);
    }
    fold(a16, a, ip);
  }

  const all24 = [...map24.values()]
    .map((acc) => finalize(acc, externalIpv4Alerts, coordMinIps, MEMBER_ROWS))
    .sort(rank);
  const all16 = [...map16.values()]
    .map((acc) => finalize(acc, externalIpv4Alerts, coordMinIps, MEMBER_ROWS))
    .sort(rank);

  const coordinated24 = all24.filter((b) => b.coordinated).length;

  const model: NetblockReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    externalIpv4Alerts,
    distinctExternalIps: externalIpv4.size,
    ipv6SourceAlerts,
    distinctIpv6Sources: ipv6Sources.size,
    blocks24: all24.slice(0, limit),
    blocks16: all16.slice(0, limit),
    total24: all24.length,
    total16: all16.length,
    coordinated24,
    highlights: [],
    markdown: "",
  };
  model.highlights = writeHighlights(model);
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded source-netblock report. */
export function netblockFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-netblock-${stamp}.md`;
}
