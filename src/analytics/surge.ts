/**
 * Surge / burst report — "when did the alert volume *spike*, and what drove it?"
 *
 * Steady background noise is one thing; a sudden **storm** of alerts is another. A
 * burst is the temporal signature of the events a defender most wants surfaced:
 *
 *   - a horizontal scan or vuln-sweep that lights up a signature hundreds of times
 *     in a couple of minutes,
 *   - a brute-force / credential-spray hammering a service,
 *   - a worm or compromised host suddenly going loud,
 *   - or, more prosaically, a misfiring rule that floods the console (noise that
 *     should be tuned, not chased).
 *
 * The point of a surge report is to compress a long, flat timeline into the few
 * *moments that were not normal* and tell you, for each, what was responsible —
 * so the morning question changes from "scroll 2,000 alerts" to "three storms
 * happened overnight; here is the driver of each."
 *
 * No existing offline report captures this shape:
 *
 *   - trends.ts renders a flat 24-bin volume histogram but never *flags* a spike,
 *     never computes a baseline, and never attributes a bucket to its driver.
 *   - rhythm.ts folds the whole window onto hour-of-day / day-of-week *aggregates*
 *     — it deliberately destroys the absolute timeline a burst lives on.
 *   - beacon.ts scores a single src→dst pair for *regular* cadence — the opposite
 *     of a one-off burst.
 *   - spread.ts ranks by peer *breadth*, killchain.ts by attack *stage* — neither
 *     looks at volume-over-time at all.
 *
 * Method (pure in-memory math over alertStore — no SSH, no Claude, no network):
 *
 *   1. Slice the window into fixed-width buckets (default 15 min, auto-widened so
 *      a very long window never produces an unbounded number of bins).
 *   2. Establish a **robust baseline**: the *median* bucket count. Median, not
 *      mean, because the very spikes we are hunting would inflate a mean and hide
 *      themselves. A bucket is a surge when it clears both an absolute floor
 *      (`minCount`, so a near-empty window can't manufacture a "spike" out of two
 *      alerts) and a relative bar (`factor` × baseline).
 *   3. **Merge adjacent surge buckets into episodes** — a storm that spans four
 *      consecutive buckets is one incident, not four — and attribute each episode
 *      to its dominant signature, source, category, peak severity and block share.
 *
 * Honest caveats baked into the output:
 *
 *   - **Alerts, not flows.** SecTool stores IPS *alerts*, not every packet, so a
 *     surge is a spike in *detections* — it can be a real attack or a chatty rule.
 *     The report ranks and attributes; it does not convict. A flat-but-severe
 *     stream produces no surge here and is the job of the other reports.
 *   - **Baseline needs history.** With only a handful of populated buckets the
 *     median is a weak floor; the report says so and leans on `minCount`.
 *
 * Output is both a structured model and a ready-to-paste Markdown document,
 * mirroring report.ts, compare.ts, profile.ts, assets.ts, tuning.ts, watchlist.ts,
 * rhythm.ts, novelty.ts, killchain.ts, beacon.ts, efficacy.ts, spread.ts and
 * cooccurrence.ts.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/**
 * One contiguous run of surge buckets, attributed to its dominant drivers. A storm
 * that spans several adjacent buckets collapses into a single episode so the
 * operator reads "one incident", not "N rows of the same incident".
 */
export interface SurgeEpisode {
  /** ms epoch of the start of the first surge bucket in the run. */
  startMs: number;
  /** ms epoch of the end of the last surge bucket in the run. */
  endMs: number;
  /** How many consecutive surge buckets the episode spans. */
  bucketSpan: number;
  /** Total alerts across the episode's buckets. */
  totalAlerts: number;
  /** The single busiest bucket's alert count inside the episode. */
  peakBucketAlerts: number;
  /** Peak bucket count ÷ baseline, rounded to 1dp — "how many× normal at its worst". */
  peakRatio: number;
  /** Distinct source IPs seen across the episode. */
  distinctSources: number;
  /** Distinct signatures seen across the episode. */
  distinctSignatures: number;
  /** The dominant signature driving the episode (may be empty). */
  topSignature: string;
  /** Alert count for {@link topSignature} inside the episode. */
  topSignatureCount: number;
  /** The dominant source IP driving the episode (may be empty). */
  topSource: string;
  /** Alert count for {@link topSource} inside the episode. */
  topSourceCount: number;
  /** The dominant category driving the episode (may be empty). */
  topCategory: string;
  /** Worst severity observed across the episode. */
  severityMax: Severity;
  /** Episode alerts at medium severity or above. */
  severeCount: number;
  /** Episode alerts whose action was an active block. */
  blockedCount: number;
  /** How many of the episode's distinct sources were *external* (public, non-RFC1918). */
  externalSources: number;
  /**
   * Shape hint: ratio of total alerts to distinct sources, rounded to 1dp. A high
   * value with one dominant source reads as a single noisy talker / scanner; a
   * value near 1 across many sources reads as a distributed spray.
   */
  alertsPerSource: number;
}

export interface SurgeReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Bucket width actually used, in ms (may exceed the requested width if auto-widened). */
  bucketMs: number;
  /** Number of buckets the window was sliced into. */
  bucketCount: number;
  /** Robust baseline: the median bucket count across the window. */
  baselinePerBucket: number;
  /** Arithmetic mean bucket count, for context against the median. */
  meanPerBucket: number;
  /** The relative bar applied (a bucket must reach `factor` × baseline). */
  factor: number;
  /** The absolute floor applied (a bucket must also reach this many alerts). */
  minCount: number;
  /** The effective per-bucket surge threshold, max(minCount, factor × baseline). */
  threshold: number;
  /** How many individual buckets cleared the surge bar. */
  surgeBucketCount: number;
  /** How many distinct episodes (merged runs of surge buckets) were found. */
  episodeCount: number;
  /** Episodes, ranked most-intense-first, truncated to the report limit. */
  episodes: SurgeEpisode[];
  /** True when the episode table was truncated by the limit. */
  truncated: boolean;
  /** A compact unicode sparkline of bucket volume across the whole window. */
  sparkline: string;
  /** Plain-language call-outs about the report as a whole. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface SurgeOptions {
  /** Max episode rows in the table (clamped to [1, 500]). */
  limit?: number;
  /** Requested bucket width in minutes (clamped to [1, 1440]; may be auto-widened). */
  bucketMinutes?: number;
  /** Relative bar: a bucket must reach this multiple of the baseline (clamped to [1.5, 100]). */
  factor?: number;
  /** Absolute floor: a bucket must also reach this many alerts (clamped to [2, 100000]). */
  minCount?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 25;
const DEFAULT_BUCKET_MINUTES = 15;
const DEFAULT_FACTOR = 3;
const DEFAULT_MIN_COUNT = 5;
/** Hard ceiling on bucket count — a long window auto-widens its bucket to stay under this. */
const MAX_BUCKETS = 5000;
/** Sparkline width in columns; the bucket series is down-sampled to fit. */
const SPARK_WIDTH = 72;
const SPARK_CHARS = "▁▂▃▄▅▆▇█";

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

/** RFC1918 / loopback / link-local / ULA — mirrors spread.ts / profile.ts. */
function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
}

// ----- formatting helpers (mirror beacon.ts / rhythm.ts / spread.ts) -----

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** A compact clock-time label like "03:42" (UTC) for the start-of-episode column. */
function fmtClock(ms: number): string {
  return new Date(ms).toISOString().slice(11, 16);
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

/** A human duration like "45m" / "2h 10m" for an episode's span. */
function fmtDuration(ms: number): string {
  const min = Math.max(1, Math.round(ms / 60000));
  if (min < 60) return `${min}m`;
  const hr = Math.floor(min / 60);
  const rem = min % 60;
  return rem ? `${hr}h ${rem}m` : `${hr}h`;
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

/**
 * Down-sample a bucket-count series to `width` columns and render a unicode
 * sparkline. Each column takes the *max* over the buckets it covers so a sharp
 * spike survives the down-sampling rather than being averaged away.
 */
function sparkline(counts: number[], width = SPARK_WIDTH): string {
  if (!counts.length) return "";
  const cols = Math.min(width, counts.length);
  const per = counts.length / cols;
  const peaks: number[] = [];
  for (let c = 0; c < cols; c++) {
    const from = Math.floor(c * per);
    const to = Math.min(counts.length, Math.floor((c + 1) * per));
    let m = 0;
    for (let i = from; i < Math.max(from + 1, to); i++) m = Math.max(m, counts[i] ?? 0);
    peaks.push(m);
  }
  const max = Math.max(1, ...peaks);
  return peaks
    .map((v) => {
      if (v <= 0) return SPARK_CHARS[0];
      const idx = Math.min(SPARK_CHARS.length - 1, Math.ceil((v / max) * (SPARK_CHARS.length - 1)));
      return SPARK_CHARS[idx];
    })
    .join("");
}

/**
 * Internal accumulator for one episode while we merge adjacent surge buckets. Holds
 * the tallies needed to attribute the storm to a dominant signature / source /
 * category plus severity, blocking and external-source breakdown.
 */
interface Accum {
  startMs: number;
  endMs: number;
  bucketSpan: number;
  totalAlerts: number;
  peakBucketAlerts: number;
  sources: Map<string, number>;
  externalSources: Set<string>;
  signatures: Map<string, number>;
  categories: Map<string, number>;
  severityMax: Severity;
  severeCount: number;
  blockedCount: number;
}

function newAccum(startMs: number): Accum {
  return {
    startMs,
    endMs: startMs,
    bucketSpan: 0,
    totalAlerts: 0,
    peakBucketAlerts: 0,
    sources: new Map(),
    externalSources: new Set(),
    signatures: new Map(),
    categories: new Map(),
    severityMax: "info",
    severeCount: 0,
    blockedCount: 0,
  };
}

function foldAlert(e: Accum, a: StoredAlert): void {
  e.totalAlerts++;
  if (a.srcIp && isIP(a.srcIp) > 0) {
    bump(e.sources, a.srcIp);
    if (!isPrivate(a.srcIp)) e.externalSources.add(a.srcIp);
  }
  bump(e.signatures, a.signature);
  bump(e.categories, a.category);
  e.severityMax = maxSeverity(e.severityMax, a.severity);
  if (isSevere(a.severity)) e.severeCount++;
  if (isBlocked(a.action)) e.blockedCount++;
}

function toEpisode(e: Accum, baseline: number, bucketMs: number): SurgeEpisode {
  const sig = topKey(e.signatures);
  const src = topKey(e.sources);
  const cat = topKey(e.categories);
  const sources = e.sources.size;
  return {
    startMs: e.startMs,
    endMs: e.endMs + bucketMs, // episodes are half-open; extend to the end of the last bucket
    bucketSpan: e.bucketSpan,
    totalAlerts: e.totalAlerts,
    peakBucketAlerts: e.peakBucketAlerts,
    peakRatio: Math.round((e.peakBucketAlerts / Math.max(1, baseline)) * 10) / 10,
    distinctSources: sources,
    distinctSignatures: e.signatures.size,
    topSignature: sig.key,
    topSignatureCount: sig.count,
    topSource: src.key,
    topSourceCount: src.count,
    topCategory: cat.key,
    severityMax: e.severityMax,
    severeCount: e.severeCount,
    blockedCount: e.blockedCount,
    externalSources: e.externalSources.size,
    alertsPerSource: Math.round((e.totalAlerts / Math.max(1, sources)) * 10) / 10,
  };
}

/**
 * Rank episodes: most intense (peak ratio) first, then by raw volume, then by
 * severity, then by recency — so the biggest, most dangerous storms float up.
 */
function rank(items: SurgeEpisode[]): SurgeEpisode[] {
  return items.sort((x, y) => {
    if (y.peakRatio !== x.peakRatio) return y.peakRatio - x.peakRatio;
    if (y.totalAlerts !== x.totalAlerts) return y.totalAlerts - x.totalAlerts;
    if (sevRank(y.severityMax) !== sevRank(x.severityMax)) return sevRank(y.severityMax) - sevRank(x.severityMax);
    return y.endMs - x.endMs;
  });
}

/** "1 src", "internal", "spray" descriptor summarising an episode's source shape. */
function shapeLabel(e: SurgeEpisode): string {
  if (e.distinctSources <= 1) return "single src";
  if (e.distinctSources >= 8 && e.alertsPerSource <= 3) return "spray";
  if (e.externalSources === 0) return "internal";
  return `${e.distinctSources} srcs`;
}

function writeHighlights(m: Omit<SurgeReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (!m.totalWindowAlerts) return out;

  if (!m.episodeCount) {
    out.push(
      `No volume surge over the last ${m.hours}h — alert flow stayed within ${m.factor}× of its ` +
        `baseline of ${m.baselinePerBucket}/bucket (${fmtDuration(m.bucketMs)} buckets). Nothing flagged.`,
    );
    return out;
  }

  out.push(
    `📈 ${m.episodeCount} surge episode(s) over the last ${m.hours}h — moments where alert volume cleared ` +
      `${m.threshold}/bucket (${m.factor}× the ${m.baselinePerBucket}/bucket baseline, floor ${m.minCount}).`,
  );

  const top = m.episodes[0];
  if (top) {
    out.push(
      `🔥 Biggest storm peaked at **${top.peakBucketAlerts} alerts/bucket (${top.peakRatio}× normal)** ` +
        `starting ${fmtTime(top.startMs)}, lasting ${fmtDuration(top.endMs - top.startMs)} — ` +
        (top.topSignature
          ? `driven by \`${clip(top.topSignature)}\` (${top.topSignatureCount} hits)`
          : `${top.totalAlerts} alerts`) +
        (top.topSource ? ` from \`${top.topSource}\`` : "") +
        `${top.severityMax !== "info" ? `, peak ${top.severityMax}` : ""}.`,
    );
  }

  const severe = m.episodes.filter((e) => isSevere(e.severityMax));
  if (severe.length) {
    out.push(
      `⚠️ ${severe.length} episode(s) carry a medium-or-worse signature — treat these spikes as likely ` +
        `attacks (scan / brute-force / exploitation), not just noisy rules.`,
    );
  }

  const internal = m.episodes.filter((e) => e.externalSources === 0 && e.distinctSources >= 1);
  if (internal.length) {
    out.push(
      `🏠 ${internal.length} episode(s) were driven entirely by **internal** sources — an internal host going ` +
        `loud is a compromised-box / worm tell; the rest are inbound from the internet.`,
    );
  }

  // A storm that is overwhelmingly one signature with little severity is the classic
  // "tune this rule" candidate rather than a real incident — call it out gently.
  const noisy = m.episodes.filter(
    (e) => !isSevere(e.severityMax) && e.distinctSignatures === 1 && e.totalAlerts >= m.minCount * 2,
  );
  if (noisy.length) {
    out.push(
      `🔧 ${noisy.length} episode(s) are a single low-severity signature firing in bulk — likely a noisy rule to ` +
        `tune (see the tuning report) rather than an incident to chase.`,
    );
  }
  return out;
}

function episodeTable(episodes: SurgeEpisode[], nowMs: number): string {
  return mdTable(
    ["Start", "Dur", "Alerts", "Peak", "×base", "Shape", "Sigs", "Peak sev", "Blocked", "Last", "Top driver"],
    episodes.map((e) => {
      const driver = e.topSignature
        ? `${clip(e.topSignature)} (${e.topSignatureCount})`
        : e.topCategory || "—";
      const src = e.topSource ? ` ← ${e.topSource}` : "";
      return [
        fmtClock(e.startMs),
        fmtDuration(e.endMs - e.startMs),
        String(e.totalAlerts),
        String(e.peakBucketAlerts),
        e.peakRatio.toFixed(1),
        shapeLabel(e),
        String(e.distinctSignatures),
        cell(e.severityMax),
        e.blockedCount ? `${e.blockedCount}/${e.totalAlerts}` : "0",
        fmtAge(e.endMs, nowMs),
        cell(clip(driver + src, 52)),
      ];
    }),
  );
}

function renderMarkdown(m: SurgeReport): string {
  const lines: string[] = [];
  lines.push(`# 📈 SecTool Surge / Burst Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Cadence:** ${fmtDuration(m.bucketMs)} buckets × ${m.bucketCount} · ` +
      `baseline **${m.baselinePerBucket}/bucket** (mean ${m.meanPerBucket}) · ` +
      `surge bar **${m.threshold}/bucket** (${m.factor}× baseline, floor ${m.minCount}) · ` +
      `**${m.episodeCount} episode(s)** · **Window alerts:** ${m.totalWindowAlerts}`,
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

  if (m.sparkline) {
    lines.push(`## Volume timeline`);
    lines.push("");
    lines.push("```");
    lines.push(`${m.sparkline}`);
    lines.push(
      `${fmtClock(m.windowStartMs)}${" ".repeat(Math.max(1, m.sparkline.length - 10))}${fmtClock(m.windowEndMs)}`,
    );
    lines.push("```");
    lines.push(
      `_Each column is the busiest ${fmtDuration(Math.max(m.bucketMs, Math.round((m.windowEndMs - m.windowStartMs) / Math.max(1, Math.min(SPARK_WIDTH, m.bucketCount)))))} ` +
        `slice; height is alerts relative to the window peak._`,
    );
    lines.push("");
  }

  lines.push(`## Surge episodes — when volume spiked above baseline`);
  lines.push("");
  if (!m.episodes.length) {
    lines.push(
      `_None — alert volume never cleared ${m.threshold}/bucket this window. Flow was within ${m.factor}× of ` +
        `its ${m.baselinePerBucket}/bucket baseline throughout._`,
    );
    lines.push("");
  } else {
    lines.push(episodeTable(m.episodes, m.windowEndMs));
    lines.push("");
  }

  if (m.truncated) {
    lines.push(`_The episode table was truncated to the row limit — raise \`limit\` to see more._`);
    lines.push("");
  }

  lines.push(
    `**Legend:** _Peak_ = busiest single bucket in the episode; _×base_ = that peak ÷ baseline. _Shape_: ` +
      `\`single src\` = one talker (scanner / noisy host); \`spray\` = many sources, few hits each ` +
      `(distributed brute-force / DDoS); \`internal\` = driven by RFC1918 sources only (lateral / compromised ` +
      `host). _Top driver_ names the dominant signature and (← ) source.`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from stored **IPS-alert** volume, not full flow data — a surge is a spike in ` +
      `*detections*, which can be a real attack or a chatty rule. The baseline is the median bucket count, robust ` +
      `to the spikes themselves; with little history it is a weak floor and the absolute \`minCount\` carries more ` +
      `weight. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the surge / burst report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link SurgeOptions}: `limit`, `bucketMinutes`, `factor`, `minCount`, and a `nowMs` pin.
 */
export function buildSurge(hours: number, opts: SurgeOptions = {}): SurgeReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(500, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const factor = Math.max(1.5, Math.min(100, opts.factor ?? DEFAULT_FACTOR));
  const minCount = Math.max(2, Math.min(100000, Math.floor(opts.minCount ?? DEFAULT_MIN_COUNT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * 3_600_000;
  const windowMs = windowEndMs - windowStartMs;

  // Resolve the bucket width, auto-widening so a long window stays under MAX_BUCKETS.
  const reqMinutes = Math.max(1, Math.min(1440, Math.floor(opts.bucketMinutes ?? DEFAULT_BUCKET_MINUTES)));
  let bucketMs = reqMinutes * 60_000;
  if (windowMs / bucketMs > MAX_BUCKETS) bucketMs = Math.ceil(windowMs / MAX_BUCKETS);
  const bucketCount = Math.max(1, Math.ceil(windowMs / bucketMs));

  const all = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time));

  // Bucket the window, keeping per-bucket alert lists so a flagged bucket can be
  // attributed to its drivers without a second pass over the whole store.
  const buckets: StoredAlert[][] = Array.from({ length: bucketCount }, () => []);
  const counts = new Array<number>(bucketCount).fill(0);
  let totalWindowAlerts = 0;
  for (const a of all) {
    if (a.time < windowStartMs || a.time > windowEndMs) continue;
    totalWindowAlerts++;
    const idx = Math.min(bucketCount - 1, Math.max(0, Math.floor((a.time - windowStartMs) / bucketMs)));
    buckets[idx]!.push(a);
    counts[idx]!++;
  }

  const baselinePerBucket = Math.round(median(counts) * 10) / 10;
  const meanPerBucket = Math.round((totalWindowAlerts / bucketCount) * 10) / 10;
  const threshold = Math.max(minCount, Math.ceil(factor * baselinePerBucket));

  // Walk the buckets, merging adjacent surge buckets into episodes.
  const episodesAcc: Accum[] = [];
  let cur: Accum | null = null;
  for (let i = 0; i < bucketCount; i++) {
    const n = counts[i]!;
    const bucketStart = windowStartMs + i * bucketMs;
    if (n >= threshold && n > 0) {
      if (!cur) cur = newAccum(bucketStart);
      cur.bucketSpan++;
      cur.endMs = bucketStart;
      cur.peakBucketAlerts = Math.max(cur.peakBucketAlerts, n);
      for (const a of buckets[i]!) foldAlert(cur, a);
    } else if (cur) {
      episodesAcc.push(cur);
      cur = null;
    }
  }
  if (cur) episodesAcc.push(cur);

  const surgeBucketCount = episodesAcc.reduce((s, e) => s + e.bucketSpan, 0);
  const episodesAll = rank(episodesAcc.map((e) => toEpisode(e, baselinePerBucket, bucketMs)));
  const episodes = episodesAll.slice(0, limit);

  const base: Omit<SurgeReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts,
    bucketMs,
    bucketCount,
    baselinePerBucket,
    meanPerBucket,
    factor,
    minCount,
    threshold,
    surgeBucketCount,
    episodeCount: episodesAll.length,
    episodes,
    truncated: episodesAll.length > episodes.length,
    sparkline: sparkline(counts),
  };
  const highlights = writeHighlights(base);
  const model: SurgeReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded surge report. */
export function surgeFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-surge-${stamp}.md`;
}
