/**
 * Burstiness / temporal-clustering report — "does this source fire in tight
 * machine-gun bursts, drip steadily like background weather, or tick like a
 * clock?"
 *
 * Every attacker leaves a *timing texture*. A scripted scanner or exploit tool
 * empties its magazine in a few seconds — fifty hits in ten seconds, then hours
 * of silence — and does it again later. Background internet noise arrives as an
 * irregular, memoryless drizzle. A C2 implant or a cron job ticks on a fixed
 * cadence. Those three shapes are statistically distinct, and which one a source
 * wears tells you *what it is* far more reliably than its raw alert count: a
 * "1,000 alert" source that fired them all in one 8-second burst is one push of
 * a button; the same 1,000 spread evenly over a week is a persistent presence.
 *
 * This report measures that texture with two well-established network-science
 * statistics computed over each source's inter-arrival times (the gaps between
 * its consecutive alerts):
 *
 *   - **Burstiness B** (Goh & Barabási, 2008): `B = (σ − μ) / (σ + μ)`, where μ
 *     and σ are the mean and standard deviation of the inter-arrival gaps. B is
 *     bounded to [−1, +1] and is scale-free (independent of how *often* the
 *     source fires):
 *       B → +1  extremely bursty   — tight clusters separated by long silences
 *       B ≈  0  random / Poisson   — memoryless drizzle (σ ≈ μ ⇒ CV ≈ 1)
 *       B → −1  perfectly regular   — evenly spaced, metronome / beacon-like
 *
 *   - **Memory coefficient M** (Goh & Barabási): the lag-1 autocorrelation of the
 *     gap sequence — do *long gaps follow long gaps*? M > 0 means the cadence has
 *     momentum (slow phases and fast phases cluster together, the signature of an
 *     on/off duty cycle); M ≈ 0 means each gap is independent of the last.
 *
 * Together (B, M) place every active source in a behavioural plane that no other
 * SecTool report draws:
 *
 *   - beacon.ts flags a single src→dst *pair* as periodic when its jitter is low
 *     — it lives at the B → −1 corner and only there. This report scores *every*
 *     source across its whole footprint and is mostly interested in the opposite
 *     corner (B → +1), where automated tooling lives.
 *   - surge.ts finds spikes in the *aggregate* stream and attributes them; it
 *     never asks whether an individual source's own timeline is clustered.
 *   - dwell.ts sessionises a source on an idle-gap threshold and measures sitting
 *     length; burstiness is the parameter-free statistic *underneath* that — it
 *     needs no threshold and captures the shape, not the session boundaries.
 *   - rhythm.ts / patterns.ts fold the timeline onto hour-of-day / day-of-week
 *     axes, deliberately destroying the fine inter-arrival structure B measures.
 *
 * For each scored source it also reports the **tightest burst** — the largest
 * number of that source's alerts seen inside any sliding window of
 * `burstWindowSec` (default 60s) — which turns the abstract B into a concrete
 * "37 hits in 60s" an operator can picture, plus the usual context (distinct
 * targets/signatures, peak severity, block share, external-vs-internal).
 *
 * Honest caveats baked into the output:
 *
 *   - **Alerts, not packets.** SecTool stores IPS *alerts*, so the texture is the
 *     texture of *detections*. A burst can be a real machine-gun scan or a noisy
 *     rule firing many times on one flow; the report ranks and classifies, it
 *     does not convict.
 *   - **Coarse clock.** Syslog timestamps are second-resolution, so sub-second
 *     structure and very fast cadences collapse to zero-length gaps (which the
 *     math treats, correctly, as maximal burstiness).
 *   - **Few samples lie.** B and especially M are unstable on a handful of gaps,
 *     so a source needs a minimum number of alerts to be scored, and M is only
 *     reported once there are enough gaps to make it meaningful.
 *
 * It is pure in-memory math over alertStore — no SSH, no Claude, no network — so
 * it is safe to call from the dashboard or CLI at any time. Output is both a
 * structured model and a ready-to-paste Markdown document, mirroring report.ts,
 * compare.ts, profile.ts, assets.ts, tuning.ts, watchlist.ts, rhythm.ts,
 * novelty.ts, killchain.ts, beacon.ts, surge.ts and dwell.ts.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Coarse temporal-texture class derived from the burstiness parameter B. */
export type BurstClass = "bursty" | "random" | "regular";

/** One source IP scored for the temporal texture of its alert timeline. */
export interface BurstinessSource {
  srcIp: string;
  /** Total windowed alerts from this source (≥ {@link BurstinessOptions.minEvents}). */
  count: number;
  /** True when the source is a public (non-RFC1918) address. */
  external: boolean;
  /** ms epoch of the first occurrence inside the window. */
  firstSeenMs: number;
  /** ms epoch of the most recent occurrence inside the window. */
  lastSeenMs: number;
  /** Active span (last − first) in seconds. */
  spanSeconds: number;
  /** Mean inter-arrival gap in seconds. */
  meanGapSeconds: number;
  /** Median inter-arrival gap in seconds (robust contrast to the mean). */
  medianGapSeconds: number;
  /** Longest silence between two consecutive alerts, in seconds. */
  maxGapSeconds: number;
  /** Coefficient of variation of the gaps (σ/μ): ≈1 Poisson, >1 bursty, <1 regular. */
  cv: number;
  /**
   * Goh-Barabási burstiness `B = (σ − μ)/(σ + μ)`, in [−1, +1]. +1 = extremely
   * bursty, 0 = random/Poisson, −1 = perfectly regular.
   */
  burstiness: number;
  /**
   * Memory coefficient (lag-1 autocorrelation of the gap sequence) in [−1, +1],
   * or `null` when there are too few gaps to estimate it. >0 ⇒ long gaps follow
   * long gaps (an on/off duty cycle).
   */
  memory: number | null;
  /** Coarse class derived from {@link burstiness}. */
  klass: BurstClass;
  /** Largest alert count from this source inside any `burstWindowSec` sliding window. */
  tightestBurst: number;
  /** ms epoch where {@link tightestBurst} starts (the first alert of that window). */
  tightestBurstStartMs: number;
  /** Distinct destination IPs this source touched. */
  distinctTargets: number;
  /** Distinct signatures this source tripped. */
  distinctSignatures: number;
  /** The dominant signature for context (may be empty). */
  topSignature: string;
  /** Worst severity observed across this source's alerts. */
  severityMax: Severity;
  /** Alerts at medium severity or above. */
  severeCount: number;
  /** Alerts whose action was an active block. */
  blockedCount: number;
}

export interface BurstinessReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Distinct source IPs seen in the window (with a valid IP), scored or not. */
  distinctSources: number;
  /** Minimum alerts a source needed to be scored. */
  minEvents: number;
  /** Sliding-window width (seconds) used for the tightest-burst measurement. */
  burstWindowSec: number;
  /** How many sources cleared {@link minEvents} and were scored. */
  scoredSources: number;
  /** Population counts by class across all scored sources. */
  classCounts: Record<BurstClass, number>;
  /** Median burstiness B across all scored sources (population texture at a glance). */
  medianBurstiness: number;
  /** Most-bursty sources first, truncated to the report limit. */
  bursty: BurstinessSource[];
  /** Most-regular (clock-like) sources first, truncated to the report limit. */
  regular: BurstinessSource[];
  /** True when the bursty table was truncated by the limit. */
  truncatedBursty: boolean;
  /** True when the regular table was truncated by the limit. */
  truncatedRegular: boolean;
  /** Plain-language call-outs about the report as a whole. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface BurstinessOptions {
  /** Max rows in each table (clamped to [1, 500]). */
  limit?: number;
  /** Minimum alerts for a source to be scored (clamped to [4, 100000]). */
  minEvents?: number;
  /** Sliding-window width in seconds for the tightest-burst metric (clamped to [5, 86400]). */
  burstWindowSec?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const DEFAULT_MIN_EVENTS = 6;
const DEFAULT_BURST_WINDOW_SEC = 60;

/** B at/above this is "bursty"; at/below its negation is "regular"; between is "random". */
const B_BURSTY = 0.3;
const B_REGULAR = -0.3;
/** Strong-tier thresholds used only for the display descriptor. */
const B_VERY_BURSTY = 0.6;
const B_METRONOME = -0.6;
/** A memory coefficient this far from zero is worth calling out as a duty cycle. */
const MEMORY_NOTABLE = 0.2;
/** Need at least this many gaps (count − 1) before the memory coefficient is meaningful. */
const MIN_GAPS_FOR_MEMORY = 3;

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

/** RFC1918 / loopback / link-local / ULA — mirrors spread.ts / surge.ts / profile.ts. */
function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
}

// ----- formatting helpers (mirror surge.ts / beacon.ts / dwell.ts) -----

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** A compact relative-age label like "3h" / "2d" for the recency column. */
function fmtAge(ms: number, nowMs: number): string {
  const sec = Math.max(0, Math.round((nowMs - ms) / 1000));
  if (sec < 90) return `${sec}s`;
  const min = Math.round(sec / 60);
  if (min < 90) return `${min}m`;
  const hr = Math.round(min / 60);
  if (hr < 48) return `${hr}h`;
  return `${Math.round(hr / 24)}d`;
}

/** A human duration like "8s" / "45m" / "2h 10m" / "3d" for a span or gap. */
function fmtDuration(sec: number): string {
  const s = Math.max(0, Math.round(sec));
  if (s < 90) return `${s}s`;
  const min = Math.round(s / 60);
  if (min < 90) return `${min}m`;
  const hr = Math.floor(min / 60);
  if (hr < 48) {
    const rem = min % 60;
    return rem ? `${hr}h ${rem}m` : `${hr}h`;
  }
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
function clip(s: string, max = 40): string {
  const t = s.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

function bump(map: Map<string, number>, key: string | undefined): void {
  if (!key) return;
  map.set(key, (map.get(key) ?? 0) + 1);
}

/** Most frequent key in a tally, ties broken by lexical order for stability. */
function topKey(map: Map<string, number>): { key: string; count: number } {
  let best = "";
  let bestN = -1;
  for (const [k, n] of map) {
    if (n > bestN || (n === bestN && k < best)) {
      best = k;
      bestN = n;
    }
  }
  return { key: best, count: Math.max(0, bestN) };
}

/** Median of a numeric array (sorted copy). Empty → 0. */
function median(values: number[]): number {
  if (!values.length) return 0;
  const s = [...values].sort((a, b) => a - b);
  const mid = s.length >> 1;
  return s.length % 2 ? s[mid]! : (s[mid - 1]! + s[mid]!) / 2;
}

/** Per-source accumulator while folding the window. */
interface Accum {
  times: number[];
  targets: Set<string>;
  signatures: Map<string, number>;
  severityMax: Severity;
  severeCount: number;
  blockedCount: number;
  external: boolean;
}

function newAccum(): Accum {
  return {
    times: [],
    targets: new Set(),
    signatures: new Map(),
    severityMax: "info",
    severeCount: 0,
    blockedCount: 0,
    external: false,
  };
}

function foldAlert(e: Accum, a: StoredAlert): void {
  e.times.push(a.time);
  if (a.dstIp && isIP(a.dstIp) > 0) e.targets.add(a.dstIp);
  bump(e.signatures, a.signature);
  e.severityMax = maxSeverity(e.severityMax, a.severity);
  if (isSevere(a.severity)) e.severeCount++;
  if (isBlocked(a.action)) e.blockedCount++;
}

/**
 * Largest alert count inside any sliding window of `windowMs`, computed with a
 * two-pointer sweep over the sorted timestamps. Returns the count and the start
 * time of the densest window so the operator can locate the burst.
 */
function tightestBurst(sortedTimes: number[], windowMs: number): { count: number; startMs: number } {
  let best = 0;
  let bestStart = sortedTimes[0] ?? 0;
  let lo = 0;
  for (let hi = 0; hi < sortedTimes.length; hi++) {
    while (sortedTimes[hi]! - sortedTimes[lo]! > windowMs) lo++;
    const span = hi - lo + 1;
    if (span > best) {
      best = span;
      bestStart = sortedTimes[lo]!;
    }
  }
  return { count: best, startMs: bestStart };
}

/**
 * Burstiness B and the memory coefficient M from a sorted timestamp series.
 * Gaps are in seconds. B is undefined for <2 gaps (returns 0 = "random"); M is
 * null until there are enough gaps to estimate a lag-1 autocorrelation.
 */
function temporalStats(sortedTimes: number[]): {
  meanGap: number;
  medianGap: number;
  maxGap: number;
  cv: number;
  burstiness: number;
  memory: number | null;
} {
  const gaps: number[] = [];
  for (let i = 1; i < sortedTimes.length; i++) {
    gaps.push(Math.max(0, (sortedTimes[i]! - sortedTimes[i - 1]!) / 1000));
  }
  if (gaps.length === 0) {
    return { meanGap: 0, medianGap: 0, maxGap: 0, cv: 0, burstiness: 0, memory: null };
  }
  const n = gaps.length;
  const mean = gaps.reduce((s, g) => s + g, 0) / n;
  const variance = gaps.reduce((s, g) => s + (g - mean) * (g - mean), 0) / n;
  const sigma = Math.sqrt(Math.max(0, variance));
  const maxGap = Math.max(...gaps);
  const cv = mean > 0 ? sigma / mean : 0;
  // Goh-Barabási burstiness; guard the degenerate σ+μ = 0 (all-simultaneous) case.
  const burstiness = sigma + mean > 0 ? (sigma - mean) / (sigma + mean) : 0;

  // Lag-1 autocorrelation (memory coefficient). Needs enough gaps and non-zero
  // variance in both the leading and trailing sub-series to be defined.
  let memory: number | null = null;
  if (n - 1 >= MIN_GAPS_FOR_MEMORY) {
    const a = gaps.slice(0, n - 1);
    const b = gaps.slice(1);
    const m = a.length;
    const meanA = a.reduce((s, g) => s + g, 0) / m;
    const meanB = b.reduce((s, g) => s + g, 0) / m;
    let cov = 0;
    let varA = 0;
    let varB = 0;
    for (let i = 0; i < m; i++) {
      const da = a[i]! - meanA;
      const db = b[i]! - meanB;
      cov += da * db;
      varA += da * da;
      varB += db * db;
    }
    const denom = Math.sqrt(varA * varB);
    if (denom > 0) memory = Math.max(-1, Math.min(1, cov / denom));
  }

  return {
    meanGap: Math.round(mean * 10) / 10,
    medianGap: Math.round(median(gaps) * 10) / 10,
    maxGap: Math.round(maxGap),
    cv: Math.round(cv * 100) / 100,
    burstiness: Math.round(burstiness * 1000) / 1000,
    memory: memory === null ? null : Math.round(memory * 1000) / 1000,
  };
}

function classify(b: number): BurstClass {
  if (b >= B_BURSTY) return "bursty";
  if (b <= B_REGULAR) return "regular";
  return "random";
}

/** A finer descriptor for the table cell, splitting out the strong tiers. */
function classLabel(s: BurstinessSource): string {
  if (s.burstiness >= B_VERY_BURSTY) return "very bursty";
  if (s.burstiness >= B_BURSTY) return "bursty";
  if (s.burstiness <= B_METRONOME) return "metronome";
  if (s.burstiness <= B_REGULAR) return "regular";
  return "random";
}

/** Rank most-bursty first: B desc, then volume, then severity, then recency. */
function rankBursty(items: BurstinessSource[]): BurstinessSource[] {
  return [...items].sort((x, y) => {
    if (y.burstiness !== x.burstiness) return y.burstiness - x.burstiness;
    if (y.count !== x.count) return y.count - x.count;
    if (sevRank(y.severityMax) !== sevRank(x.severityMax)) return sevRank(y.severityMax) - sevRank(x.severityMax);
    return y.lastSeenMs - x.lastSeenMs;
  });
}

/** Rank most-regular first: B asc (toward −1), then volume, then recency. */
function rankRegular(items: BurstinessSource[]): BurstinessSource[] {
  return [...items].sort((x, y) => {
    if (x.burstiness !== y.burstiness) return x.burstiness - y.burstiness;
    if (y.count !== x.count) return y.count - x.count;
    return y.lastSeenMs - x.lastSeenMs;
  });
}

function fmtMemory(m: number | null): string {
  return m === null ? "—" : (m >= 0 ? `+${m.toFixed(2)}` : m.toFixed(2));
}

function writeHighlights(m: Omit<BurstinessReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (!m.scoredSources) {
    if (m.totalWindowAlerts) {
      out.push(
        `No source had at least ${m.minEvents} alerts in the last ${m.hours}h, so none could be scored for ` +
          `temporal texture — burstiness needs several inter-arrival gaps to be meaningful. Lower \`minEvents\` ` +
          `to inspect thinner sources.`,
      );
    }
    return out;
  }

  out.push(
    `🧬 Scored ${m.scoredSources} source(s) over the last ${m.hours}h for timing texture (≥ ${m.minEvents} alerts ` +
      `each) — **${m.classCounts.bursty} bursty · ${m.classCounts.random} random · ${m.classCounts.regular} regular** ` +
      `(population median B = ${m.medianBurstiness.toFixed(2)}).`,
  );

  const top = m.bursty[0];
  if (top && top.klass === "bursty") {
    out.push(
      `🔥 Burstiest source \`${top.srcIp}\`${top.external ? "" : " (internal)"} — **B = ${top.burstiness.toFixed(2)}**, ` +
        `${top.count} alerts with a tightest cluster of **${top.tightestBurst} in ${fmtDuration(m.burstWindowSec)}** ` +
        `then long silences (longest gap ${fmtDuration(top.maxGapSeconds)})` +
        (top.topSignature ? `, driven by \`${clip(top.topSignature)}\`` : "") +
        `. Tight machine-gun clusters are the signature of scripted tooling, not a human.`,
    );
  }

  const severeBursty = m.bursty.filter((s) => s.klass === "bursty" && isSevere(s.severityMax));
  if (severeBursty.length) {
    out.push(
      `⚠️ ${severeBursty.length} bursty source(s) carry a medium-or-worse signature — automated bursts hitting ` +
        `you with real exploit/scan tooling; the burst window is the moment to investigate, not the daily average.`,
    );
  }

  const duty = m.bursty.filter((s) => s.memory !== null && s.memory >= MEMORY_NOTABLE);
  if (duty.length) {
    out.push(
      `🔁 ${duty.length} source(s) show positive memory (long gaps follow long gaps) — an on/off **duty cycle** ` +
        `(burst, sleep, burst), typical of a tool run repeatedly on a loose schedule rather than one continuous run.`,
    );
  }

  const reg = m.regular[0];
  if (reg && (reg.klass === "regular" || reg.burstiness <= B_REGULAR)) {
    out.push(
      `🕒 Most regular source \`${reg.srcIp}\` is near-metronome (**B = ${reg.burstiness.toFixed(2)}**, ` +
        `CV ${reg.cv.toFixed(2)}, median gap ${fmtDuration(reg.medianGapSeconds)}) — evenly-spaced cadence is the ` +
        `beaconing/cron shape. Cross-check it against the beaconing report (\`--beacon\`) for a C2 read.`,
    );
  }

  const internalBursty = m.bursty.filter((s) => s.klass === "bursty" && !s.external);
  if (internalBursty.length) {
    out.push(
      `🏠 ${internalBursty.length} **internal** source(s) are bursty — an internal host firing in clusters is a ` +
        `worm/compromised-box tell (loud, then quiet); the rest are inbound from the internet.`,
    );
  }
  return out;
}

function sourceTable(rows: BurstinessSource[], nowMs: number, burstWindowSec: number): string {
  return mdTable(
    ["Source", "Alerts", "Span", "B", "CV", "Mem", "Class", `Burst/${fmtDuration(burstWindowSec)}`, "Max gap", "Tgts", "Peak sev", "Blocked", "Last", "Top sig"],
    rows.map((s) => [
      cell(s.srcIp) + (s.external ? "" : " 🏠"),
      String(s.count),
      fmtDuration(s.spanSeconds),
      s.burstiness.toFixed(2),
      s.cv.toFixed(2),
      fmtMemory(s.memory),
      classLabel(s),
      String(s.tightestBurst),
      fmtDuration(s.maxGapSeconds),
      String(s.distinctTargets),
      cell(s.severityMax),
      s.blockedCount ? `${s.blockedCount}/${s.count}` : "0",
      fmtAge(s.lastSeenMs, nowMs),
      s.topSignature ? cell(clip(s.topSignature, 34)) : "—",
    ]),
  );
}

function renderMarkdown(m: BurstinessReport): string {
  const lines: string[] = [];
  lines.push(`# 🧬 SecTool Burstiness / Temporal-Texture Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Scope:** ${m.distinctSources} distinct source(s) · **${m.scoredSources} scored** (≥ ${m.minEvents} alerts) · ` +
      `burst window **${fmtDuration(m.burstWindowSec)}** · population median **B = ${m.medianBurstiness.toFixed(2)}** · ` +
      `**Window alerts:** ${m.totalWindowAlerts}`,
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
  if (!m.highlights.length) {
    lines.push(
      `No source reached the ${m.minEvents}-alert floor needed to score timing texture this window. ` +
        `Lower \`minEvents\` to inspect thinner sources.`,
    );
    lines.push("");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  if (m.scoredSources) {
    const total = m.scoredSources;
    const pct = (n: number) => `${Math.round((n / total) * 100)}%`;
    lines.push(`## Population texture`);
    lines.push("");
    lines.push(
      mdTable(
        ["Class", "Sources", "Share", "Means"],
        [
          ["🔥 bursty (B ≥ " + B_BURSTY + ")", String(m.classCounts.bursty), pct(m.classCounts.bursty), "tight clusters + long silences — scripted tooling / scanners"],
          ["🌊 random (|B| < " + B_BURSTY + ")", String(m.classCounts.random), pct(m.classCounts.random), "memoryless drizzle — background internet weather"],
          ["🕒 regular (B ≤ " + B_REGULAR + ")", String(m.classCounts.regular), pct(m.classCounts.regular), "evenly spaced — beacon / cron / heartbeat"],
        ],
      ),
    );
    lines.push("");
  }

  lines.push(`## Burstiest sources — tight clusters, then silence`);
  lines.push("");
  if (!m.bursty.length) {
    lines.push(`_None scored._`);
    lines.push("");
  } else {
    lines.push(sourceTable(m.bursty, m.windowEndMs, m.burstWindowSec));
    lines.push("");
    if (m.truncatedBursty) {
      lines.push(`_Truncated to the row limit — raise \`limit\` to see more._`);
      lines.push("");
    }
  }

  // Only worth a second table when some sources actually sit at the regular end;
  // otherwise it would just repeat the least-bursty rows from the table above.
  const hasRegular = m.regular.some((s) => s.burstiness <= B_REGULAR);
  if (hasRegular) {
    lines.push(`## Most regular sources — metronome / beacon-like cadence`);
    lines.push("");
    lines.push(sourceTable(m.regular, m.windowEndMs, m.burstWindowSec));
    lines.push("");
    if (m.truncatedRegular) {
      lines.push(`_Truncated to the row limit — raise \`limit\` to see more._`);
      lines.push("");
    }
    lines.push(
      `_These sit at the **B → −1** corner: evenly-spaced alerts. That is the beaconing / scheduled-job shape — ` +
        `cross-check them against the beaconing report (\`--beacon\`), which scores individual src→dst pairs for C2 cadence._`,
    );
    lines.push("");
  }

  lines.push(
    `**Legend:** _B_ = Goh-Barabási burstiness in [−1,+1] (**+1** clustered bursts · **0** random/Poisson · ` +
      `**−1** perfectly regular). _CV_ = gap σ/μ (≈1 ⇒ Poisson). _Mem_ = lag-1 autocorrelation of the gaps ` +
      `(**+** ⇒ long gaps follow long gaps, an on/off duty cycle; **—** ⇒ too few gaps to estimate). ` +
      `_Burst/${fmtDuration(m.burstWindowSec)}_ = most alerts inside any ${fmtDuration(m.burstWindowSec)} sliding window. ` +
      `_Max gap_ = longest silence between two alerts. 🏠 = internal (RFC1918) source.`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from stored **IPS-alert** timestamps, not full flow data — the texture is the ` +
      `texture of *detections*, so a burst can be a real machine-gun scan or a chatty rule firing many times on one ` +
      `flow. Syslog timestamps are second-resolution, so sub-second structure collapses to zero-length gaps (treated, ` +
      `correctly, as maximal burstiness). Burstiness and especially the memory coefficient are unstable on a handful ` +
      `of gaps, hence the \`minEvents\` floor. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the burstiness / temporal-texture report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link BurstinessOptions}: `limit`, `minEvents`, `burstWindowSec`, and a `nowMs` pin.
 */
export function buildBurstiness(hours: number, opts: BurstinessOptions = {}): BurstinessReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(500, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minEvents = Math.max(4, Math.min(100000, Math.floor(opts.minEvents ?? DEFAULT_MIN_EVENTS)));
  const burstWindowSec = Math.max(5, Math.min(86400, Math.floor(opts.burstWindowSec ?? DEFAULT_BURST_WINDOW_SEC)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * 3_600_000;
  const burstWindowMs = burstWindowSec * 1000;

  const all = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time));

  // Group windowed alerts by source IP.
  const bySource = new Map<string, Accum>();
  let totalWindowAlerts = 0;
  for (const a of all) {
    if (a.time < windowStartMs || a.time > windowEndMs) continue;
    totalWindowAlerts++;
    const ip = a.srcIp;
    if (!ip || isIP(ip) === 0) continue;
    let acc = bySource.get(ip);
    if (!acc) {
      acc = newAccum();
      acc.external = !isPrivate(ip);
      bySource.set(ip, acc);
    }
    foldAlert(acc, a);
  }

  const scored: BurstinessSource[] = [];
  for (const [srcIp, acc] of bySource) {
    if (acc.times.length < minEvents) continue;
    const times = acc.times.sort((x, y) => x - y);
    const firstSeenMs = times[0]!;
    const lastSeenMs = times[times.length - 1]!;
    const stats = temporalStats(times);
    const burst = tightestBurst(times, burstWindowMs);
    const sig = topKey(acc.signatures);
    scored.push({
      srcIp,
      count: times.length,
      external: acc.external,
      firstSeenMs,
      lastSeenMs,
      spanSeconds: Math.round((lastSeenMs - firstSeenMs) / 1000),
      meanGapSeconds: stats.meanGap,
      medianGapSeconds: stats.medianGap,
      maxGapSeconds: stats.maxGap,
      cv: stats.cv,
      burstiness: stats.burstiness,
      memory: stats.memory,
      klass: classify(stats.burstiness),
      tightestBurst: burst.count,
      tightestBurstStartMs: burst.startMs,
      distinctTargets: acc.targets.size,
      distinctSignatures: acc.signatures.size,
      topSignature: sig.key,
      severityMax: acc.severityMax,
      severeCount: acc.severeCount,
      blockedCount: acc.blockedCount,
    });
  }

  const classCounts: Record<BurstClass, number> = { bursty: 0, random: 0, regular: 0 };
  for (const s of scored) classCounts[s.klass]++;
  const medianBurstiness = Math.round(median(scored.map((s) => s.burstiness)) * 1000) / 1000;

  const burstyAll = rankBursty(scored);
  const regularAll = rankRegular(scored);
  const bursty = burstyAll.slice(0, limit);
  const regular = regularAll.slice(0, limit);

  const base: Omit<BurstinessReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts,
    distinctSources: bySource.size,
    minEvents,
    burstWindowSec,
    scoredSources: scored.length,
    classCounts,
    medianBurstiness,
    bursty,
    regular,
    truncatedBursty: burstyAll.length > bursty.length,
    truncatedRegular: regularAll.length > regular.length,
  };
  const highlights = writeHighlights(base);
  const model: BurstinessReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded burstiness report. */
export function burstinessFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-burstiness-${stamp}.md`;
}
