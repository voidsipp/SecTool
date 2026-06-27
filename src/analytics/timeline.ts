/**
 * Daily timeline ledger report — "**walk the calendar with me: how did each day
 * actually go, what changed from the day before, and which day was the bad one?**"
 *
 * The morning question a defender most often has is not "what is the all-time top
 * source" or "what's hot right now" — it is the plain chronological one: *show me
 * each day in order. Was last night quiet? Did Tuesday spike? When did the new
 * campaign start?* Surprisingly, none of SecTool's ~60 reports answer that
 * directly. They each deliberately destroy or never build the **absolute,
 * gap-free, per-calendar-day timeline**:
 *
 *   - **rhythm.ts** folds the whole window onto an hour-of-day × day-of-week
 *     heat-map — a *cyclical* aggregate that throws away which actual Tuesday a
 *     spike landed on. It answers "when in a typical week", not "what happened on
 *     the 14th".
 *   - **surge.ts** hunts *sub-hour* bursts against a rolling baseline and
 *     attributes each storm to a driver — it surfaces the few abnormal *moments*,
 *     not a steady ledger of *every* day including the calm ones.
 *   - **trends.ts** renders a flat fixed-bin volume histogram with no per-bin
 *     attribution, no day-over-day delta, no unique-source or new-arrival column.
 *   - **compare.ts** diffs exactly *two* equal windows (this period vs the prior
 *     one) — a single before/after, never the running day-by-day curve between.
 *   - **forecast.ts** projects *forward*; **briefing.ts** summarises a *single*
 *     window. Neither lets you scroll the recent past day by day.
 *
 * This report is the missing chronological ledger. It slices the look-back window
 * into fixed buckets (UTC calendar days by default; any width via `--bucket H`),
 * emits **one row per bucket in time order including empty ones** (so quiet days
 * are visible, not silently skipped), and for each bucket carries the numbers an
 * analyst flips through a calendar for:
 *
 *   - **total** alerts and a day-over-day **delta** (▲/▼ %), so a jump or a
 *     collapse reads at a glance;
 *   - **serious** (high + critical) count and the **worst severity** seen;
 *   - **unique sources / targets / signatures** that day — breadth, not just
 *     volume (10 000 alerts from one IP is a very different day from 10 000 across
 *     500 IPs);
 *   - **new sources** — addresses appearing for the first time relative to the
 *     retained history *before* the window (the same baseline novelty.ts uses), so
 *     the row that opens a fresh campaign stands out from steady background;
 *   - the **busiest source**, **top signature** and **dominant category** that
 *     day — a one-glance "what drove it";
 *
 * plus a volume **sparkline** across the whole window and headline call-outs: the
 * busiest day, the worst day by serious volume, the biggest day-over-day jump
 * (campaign onset), the biggest influx of new sources, and the first-half →
 * second-half **trend** (is the daily average rising or falling?).
 *
 * Honest caveats baked into the output:
 *
 *   - **Buckets are UTC.** A "day" is a UTC calendar day, so activity near local
 *     midnight can fall either side of a boundary — for timezone-of-the-attacker
 *     attribution see `--patterns`, and for the cyclical view `--rhythm`.
 *   - **New-source count is history-bounded.** "New" means not seen in the
 *     retained store before the window opened; alertStore is capped/rotated, so a
 *     long-quiet returning source can read as new (the same limit novelty.ts
 *     states).
 *   - **Edge buckets are partial.** The first and last bucket usually cover only
 *     part of their period (the window rarely starts/ends on a bucket boundary),
 *     so their totals are not directly comparable to a full interior day — the
 *     report flags both.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network. Output is
 * both a structured model and a ready-to-paste Markdown document, mirroring
 * silence.ts, surge.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** One time-bucket (a UTC calendar day by default) in the chronological ledger. */
export interface TimelineBucket {
  /** Bucket start (ms epoch, aligned to the bucket grid). */
  startMs: number;
  /** Bucket end (ms epoch, exclusive). */
  endMs: number;
  /** Human label: `YYYY-MM-DD` for daily buckets, else an ISO datetime. */
  label: string;
  /** True when the window clips this bucket so it covers less than a full period. */
  partial: boolean;
  /** Total alerts (with a usable timestamp) in the bucket. */
  total: number;
  /** High + critical alerts in the bucket. */
  serious: number;
  /** Distinct source IPs seen in the bucket. */
  uniqueSources: number;
  /** Distinct destination IPs seen in the bucket. */
  uniqueTargets: number;
  /** Distinct signatures seen in the bucket. */
  uniqueSignatures: number;
  /** Sources appearing for the first time vs the pre-window baseline + earlier buckets. */
  newSources: number;
  /** Worst severity observed in the bucket. */
  severityMax: Severity;
  /** Dominant Suricata category that day, or undefined if none carried one. */
  topCategory?: string;
  /** Busiest source IP that day (by alert count), or undefined. */
  topSource?: string;
  /** Busiest signature that day (by alert count), or undefined. */
  topSignature?: string;
  /** Percent change in {@link total} vs the previous bucket; null for the first. */
  deltaPct: number | null;
}

export interface TimelineReport {
  hours: number;
  /** Bucket width actually used, in hours (after clamping). */
  bucketHours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Start (ms epoch) of the retained history used to seed the new-source baseline. */
  baselineStartMs: number | null;
  /** Distinct source IPs seen strictly before the window (the new-source baseline). */
  baselineSources: number;
  /** Total alerts (with a usable timestamp) inside the window. */
  totalAlerts: number;
  /** Buckets generated across the window (including empty ones). */
  bucketCount: number;
  /** Chronological buckets, oldest first (capped to the row limit — see truncated). */
  buckets: TimelineBucket[];
  /** True when more buckets exist than were shown (only the most recent are kept). */
  truncated: boolean;
  /** Mean alerts per full (non-partial) bucket, rounded. */
  avgPerBucket: number;
  /** First-half → second-half daily-average change, as a percent (null if undefined). */
  trendPct: number | null;
  /** Coarse direction of {@link trendPct}. */
  trend: "rising" | "falling" | "flat";
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** A volume sparkline across every (un-truncated) bucket in the window. */
  sparkline: string;
  /** The finished Markdown document. */
  markdown: string;
}

export interface TimelineOptions {
  /** Max bucket rows shown (most recent kept); clamped to [1, 366]. Default 60. */
  limit?: number;
  /** Bucket width in hours (clamped to [1, window]). Defaults to 24 (UTC days). */
  bucketHours?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 60;
const DEFAULT_BUCKET_HOURS = 24;
const MS_PER_HOUR = 3_600_000;
const MS_PER_DAY = 86_400_000;

/** A day-over-day change beyond this magnitude (%) counts as a real move, not noise. */
const TREND_THRESHOLD_PCT = 15;
/** Unicode bars for the volume sparkline, smallest → largest. */
const SPARK_BARS = "▁▂▃▄▅▆▇█";

// ----- helpers (mirror silence.ts / surge.ts) --------------------------------

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

/** High or critical — the "serious" band every report counts. */
function isSerious(s: string | undefined): boolean {
  return sevRank(s) >= sevRank("high");
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** `YYYY-MM-DD` UTC date stamp. */
function fmtDate(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function clip(s: string, max = 38): string {
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

/** A ▲+X% / ▼-X% / – delta label for a percent change (null → first bucket). */
function deltaLabel(pct: number | null): string {
  if (pct === null) return "—";
  if (pct === 0) return "± 0%";
  const arrow = pct > 0 ? "▲" : "▼";
  const mag = Math.abs(pct);
  return `${arrow} ${mag >= 1000 ? "≥1000" : Math.round(mag)}%`;
}

/** Block-character sparkline; "·" marks a genuinely empty bucket. */
function sparkline(values: number[]): string {
  const max = Math.max(0, ...values);
  if (max <= 0) return "·".repeat(values.length || 1);
  return values
    .map((v) => {
      if (v <= 0) return "·";
      const idx = Math.min(SPARK_BARS.length - 1, Math.max(0, Math.round((v / max) * (SPARK_BARS.length - 1))));
      return SPARK_BARS[idx];
    })
    .join("");
}

/** The keyed mode (most frequent value) of a count map, or undefined if empty. */
function topKey(counts: Map<string, number>): string | undefined {
  let best: string | undefined;
  let bestN = -1;
  for (const [k, n] of counts) {
    // Deterministic tie-break on the key so output is stable run-to-run.
    if (n > bestN || (n === bestN && best !== undefined && k < best)) {
      best = k;
      bestN = n;
    }
  }
  return best;
}

// ----- aggregation -----------------------------------------------------------

interface BucketAcc {
  startMs: number;
  endMs: number;
  total: number;
  serious: number;
  sources: Set<string>;
  targets: Set<string>;
  signatures: Set<string>;
  newSources: Set<string>;
  severityMax: Severity;
  categoryCounts: Map<string, number>;
  sourceCounts: Map<string, number>;
  signatureCounts: Map<string, number>;
}

function newBucketAcc(startMs: number, endMs: number): BucketAcc {
  return {
    startMs,
    endMs,
    total: 0,
    serious: 0,
    sources: new Set(),
    targets: new Set(),
    signatures: new Set(),
    newSources: new Set(),
    severityMax: "info",
    categoryCounts: new Map(),
    sourceCounts: new Map(),
    signatureCounts: new Map(),
  };
}

function bumpCount(m: Map<string, number>, k: string): void {
  m.set(k, (m.get(k) ?? 0) + 1);
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(
  report: Omit<TimelineReport, "highlights" | "markdown" | "sparkline">,
  full: TimelineBucket[],
): string[] {
  const out: string[] = [];
  const { bucketHours } = report;
  const unit = bucketHours === 24 ? "day" : `${bucketHours}h bucket`;

  if (report.totalAlerts === 0) return out; // handled in the Markdown empty branch

  const active = full.filter((b) => b.total > 0);
  const quiet = full.length - active.length;

  // Busiest bucket overall.
  const busiest = [...full].sort((a, b) => b.total - a.total || a.startMs - b.startMs)[0];
  if (busiest && busiest.total > 0) {
    out.push(
      `📈 Busiest ${unit}: **${busiest.label}** with **${busiest.total}** alert(s) from ${busiest.uniqueSources} ` +
        `source(s)${busiest.topSignature ? ` — led by \`${clip(busiest.topSignature, 50)}\`` : ""}.`,
    );
  }

  // Worst bucket by serious (high+critical) volume — different from sheer count.
  const worst = [...full]
    .filter((b) => b.serious > 0)
    .sort((a, b) => b.serious - a.serious || a.startMs - b.startMs)[0];
  if (worst) {
    out.push(
      `🚨 Most serious ${unit}: **${worst.label}** carried **${worst.serious}** high/critical alert(s) ` +
        `(worst severity \`${worst.severityMax}\`)${worst.topSource ? ` — top source \`${worst.topSource}\`` : ""}.`,
    );
  }

  // Biggest day-over-day jump — the campaign-onset / something-changed tell.
  const jump = full
    .filter((b) => b.deltaPct !== null && b.deltaPct > 0 && b.total > 0)
    .sort((a, b) => (b.deltaPct ?? 0) - (a.deltaPct ?? 0))[0];
  if (jump && (jump.deltaPct ?? 0) >= TREND_THRESHOLD_PCT) {
    out.push(
      `⚡ Biggest jump: **${jump.label}** rose **${deltaLabel(jump.deltaPct).replace(/^▲ /, "")}** over the prior ${unit} ` +
        `(to ${jump.total} alert(s)). Worth a look for a fresh campaign or a newly-loud source.`,
    );
  }

  // Biggest influx of brand-new sources.
  const influx = [...full].sort((a, b) => b.newSources - a.newSources || a.startMs - b.startMs)[0];
  if (influx && influx.newSources > 0) {
    out.push(
      `🆕 Most new attackers: **${influx.label}** saw **${influx.newSources}** first-seen source(s) ` +
        `(never observed before the window) — see \`--novelty\` for the full first-seen breakdown.`,
    );
  }

  // Direction of travel.
  const tp = report.trendPct;
  if (tp !== null) {
    const verb = report.trend === "rising" ? "rising 📈" : report.trend === "falling" ? "falling 📉" : "flat ➖";
    out.push(
      `📊 Trend: per-${unit} volume is **${verb}** — second half of the window averaged ` +
        `**${deltaLabel(tp).replace(/^[▲▼] /, tp >= 0 ? "+" : "−")}** versus the first half ` +
        `(mean **${report.avgPerBucket}**/${unit}).`,
    );
  }

  // Quiet stretch / coverage note.
  if (quiet > 0) {
    out.push(
      `🌙 **${quiet}** of ${full.length} ${unit}(s) were completely silent — either genuinely quiet, or a gap in ` +
        `forwarding worth confirming against \`--coverage\`.`,
    );
  }

  return out;
}

// ----- markdown --------------------------------------------------------------

function ledgerTable(buckets: TimelineBucket[], bucketHours: number): string {
  const periodHeader = bucketHours === 24 ? "Day (UTC)" : "Bucket start (UTC)";
  return mdTable(
    [periodHeader, "Alerts", "Δ", "Serious", "Worst", "Srcs", "New", "Dsts", "Sigs", "Top source", "Top signature", "Top category"],
    buckets.map((b) => [
      cell(b.label) + (b.partial ? " ⚠" : ""),
      String(b.total),
      deltaLabel(b.deltaPct),
      b.serious > 0 ? `**${b.serious}**` : "0",
      cell(b.severityMax),
      String(b.uniqueSources),
      b.newSources > 0 ? `🆕 ${b.newSources}` : "0",
      String(b.uniqueTargets),
      String(b.uniqueSignatures),
      cell(b.topSource ? `\`${b.topSource}\`` : "—"),
      cell(b.topSignature ? clip(b.topSignature) : "—"),
      cell(b.topCategory ?? "—"),
    ]),
  );
}

function renderMarkdown(m: TimelineReport): string {
  const lines: string[] = [];
  const unit = m.bucketHours === 24 ? "day" : `${m.bucketHours}h bucket`;
  lines.push(`# 🗓️ SecTool Daily Timeline Ledger`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** the window is split into **${m.bucketCount}** ${unit}(s)` +
      `${m.bucketHours === 24 ? " (UTC calendar days)" : ""}, one chronological row each (empty ones included). ` +
      `Offline, deterministic · **Total alerts:** ${m.totalAlerts} · **Mean:** ${m.avgPerBucket}/${unit}.`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (m.totalAlerts === 0) {
    lines.push(
      `No alerts with a usable timestamp landed in the last ${m.hours}h — there is nothing to lay out on a timeline. ` +
        `Widen the window (\`--timeline <more hours>\`) or confirm forwarding with \`--coverage\`.`,
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  // The at-a-glance volume sparkline across the whole window.
  lines.push(`## Volume at a glance`);
  lines.push("");
  lines.push(`\`\`\``);
  lines.push(`${m.sparkline}`);
  lines.push(`\`\`\``);
  const sparkCaption =
    `One mark per ${unit}, oldest → newest; \`·\` is a silent ${unit}, \`█\` the busiest.` +
    (m.truncated ? ` The ledger table below shows the most recent ${m.buckets.length} ${unit}(s).` : ``);
  lines.push(`_${sparkCaption}_`);
  lines.push("");

  // The chronological ledger.
  lines.push(`## Day-by-day ledger`);
  lines.push("");
  if (m.truncated) {
    lines.push(
      `_${m.bucketCount} ${unit}(s) in the window; showing the most recent **${m.buckets.length}**. ` +
        `Raise \`--limit\` to see more._`,
    );
    lines.push("");
  }
  lines.push(ledgerTable(m.buckets, m.bucketHours));
  lines.push("");
  lines.push(
    `**Legend:** _Δ_ = change in total vs the previous ${unit} (▲ up / ▼ down). _Serious_ = high + critical. ` +
      `_New_ = 🆕 sources first seen vs the retained history *before* the window. _⚠_ on a label marks a **partial** ` +
      `${unit} (the window clips it — its total is not comparable to a full interior ${unit}).`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Buckets are **UTC** — activity near local midnight can fall either side of a ` +
      `boundary (see \`--patterns\` for attacker-timezone attribution and \`--rhythm\` for the cyclical hour×day view). ` +
      `"New" sources are bounded by the retained store (${m.baselineSources} source(s) of pre-window baseline back to ` +
      `${m.baselineStartMs !== null ? fmtTime(m.baselineStartMs) : "the start of history"}), so a long-quiet returning ` +
      `source can read as new (see \`--novelty\`). This is the chronological companion to \`--surge\` (sub-hour spikes), ` +
      `\`--rhythm\` (cyclical heat-map) and \`--compare\` (two-window diff). No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the daily timeline ledger from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [2, 180 days]).
 * @param opts  {@link TimelineOptions}: `limit`, `bucketHours`, and a `nowMs` pin
 *              for deterministic tests.
 */
export function buildTimeline(hours: number, opts: TimelineOptions = {}): TimelineReport {
  const safeHours = Math.max(2, Math.min(24 * 180, Math.floor(hours)));
  const limit = Math.max(1, Math.min(366, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  // Bucket width: default UTC days, clamped so at least one bucket spans the window.
  const reqBucket = opts.bucketHours ?? DEFAULT_BUCKET_HOURS;
  const bucketHours = Math.max(1, Math.min(safeHours, Math.round(reqBucket)));
  const bucketMs = bucketHours * MS_PER_HOUR;

  const all = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time));

  // New-source baseline: every source seen strictly before the window opened
  // (mirrors novelty.ts so "new" means first-seen in retained history, not just
  // first-seen in-window). Also note how far back that memory reaches.
  const baselineSources = new Set<string>();
  let baselineStartMs: number | null = null;
  for (const a of all) {
    if (a.time >= windowStartMs) continue;
    if (baselineStartMs === null || a.time < baselineStartMs) baselineStartMs = a.time;
    const src = validIp(a.srcIp);
    if (src) baselineSources.add(src);
  }

  const windowed = all
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs)
    .sort((a, b) => a.time - b.time);

  // Pre-generate every bucket in [windowStart, windowEnd], including empty ones,
  // aligned to the bucket grid (bucketMs that divides a day lands daily buckets on
  // UTC midnight). Partial edge buckets are clipped to the window bounds.
  const firstStart = Math.floor(windowStartMs / bucketMs) * bucketMs;
  const accs: BucketAcc[] = [];
  const indexOfStart = new Map<number, number>();
  // Strictly `< windowEndMs` so a window ending exactly on a grid boundary does not
  // emit a spurious zero-width trailing bucket.
  for (let s = firstStart; s < windowEndMs; s += bucketMs) {
    const start = Math.max(s, windowStartMs);
    const end = Math.min(s + bucketMs, windowEndMs);
    indexOfStart.set(s, accs.length);
    accs.push(newBucketAcc(start, end));
  }

  // The new-source frontier carries the baseline forward through the buckets so a
  // source counts as "new" only on the first bucket it ever appears in.
  const seenSources = new Set(baselineSources);
  let totalAlerts = 0;

  for (const a of windowed) {
    const gridStart = Math.floor(a.time / bucketMs) * bucketMs;
    const idx = indexOfStart.get(gridStart);
    if (idx === undefined) continue; // outside the generated range (e.g. exactly on the end boundary)
    const acc = accs[idx]!;
    totalAlerts++; // count only alerts that land in a materialised bucket, so the header matches the ledger
    acc.total++;
    if (isSerious(a.severity)) acc.serious++;
    acc.severityMax = maxSeverity(acc.severityMax, a.severity);

    const src = validIp(a.srcIp);
    if (src) {
      acc.sources.add(src);
      bumpCount(acc.sourceCounts, src);
      if (!seenSources.has(src)) {
        seenSources.add(src);
        acc.newSources.add(src);
      }
    }
    const dst = validIp(a.dstIp);
    if (dst) acc.targets.add(dst);

    const sig = (a.signature ?? "").trim();
    if (sig) {
      acc.signatures.add(sig);
      bumpCount(acc.signatureCounts, sig);
    }
    const cat = (a.category ?? "").trim();
    if (cat) bumpCount(acc.categoryCounts, cat);
  }

  // Materialise every bucket into the public model, computing day-over-day deltas.
  const full: TimelineBucket[] = accs.map((acc, i) => {
    const prevTotal = i > 0 ? accs[i - 1]!.total : null;
    let deltaPct: number | null = null;
    if (i > 0) {
      if (prevTotal === 0) deltaPct = acc.total > 0 ? 1000 : 0; // 0 → N reads as a large jump
      else deltaPct = Math.round(((acc.total - prevTotal!) / prevTotal!) * 100);
    }
    return {
      startMs: acc.startMs,
      endMs: acc.endMs,
      label: bucketHours === 24 ? fmtDate(acc.startMs) : fmtTime(acc.startMs),
      partial: acc.endMs - acc.startMs < bucketMs,
      total: acc.total,
      serious: acc.serious,
      uniqueSources: acc.sources.size,
      uniqueTargets: acc.targets.size,
      uniqueSignatures: acc.signatures.size,
      newSources: acc.newSources.size,
      severityMax: acc.severityMax,
      topCategory: topKey(acc.categoryCounts),
      topSource: topKey(acc.sourceCounts),
      topSignature: topKey(acc.signatureCounts),
      deltaPct,
    };
  });

  // Mean over *full* buckets only, so partial edges don't drag the average down.
  const fullBuckets = full.filter((b) => !b.partial);
  const avgBase = fullBuckets.length ? fullBuckets : full;
  const avgPerBucket = avgBase.length
    ? Math.round(avgBase.reduce((s, b) => s + b.total, 0) / avgBase.length)
    : 0;

  // First-half → second-half daily-average trend (interior buckets, even split).
  let trendPct: number | null = null;
  let trend: TimelineReport["trend"] = "flat";
  if (full.length >= 2) {
    const mid = Math.floor(full.length / 2);
    const firstHalf = full.slice(0, mid);
    const secondHalf = full.slice(mid);
    const avg = (xs: TimelineBucket[]) => (xs.length ? xs.reduce((s, b) => s + b.total, 0) / xs.length : 0);
    const a1 = avg(firstHalf);
    const a2 = avg(secondHalf);
    if (a1 > 0) {
      trendPct = Math.round(((a2 - a1) / a1) * 100);
      trend = trendPct > TREND_THRESHOLD_PCT ? "rising" : trendPct < -TREND_THRESHOLD_PCT ? "falling" : "flat";
    } else if (a2 > 0) {
      trendPct = 1000;
      trend = "rising";
    }
  }

  const sparkLine = sparkline(full.map((b) => b.total));

  // Keep the most recent `limit` rows for the table (the ledger reads newest-context
  // first when long); the sparkline and aggregates still cover every bucket.
  const truncated = full.length > limit;
  const shown = truncated ? full.slice(full.length - limit) : full;

  const base: Omit<TimelineReport, "highlights" | "markdown" | "sparkline"> = {
    hours: safeHours,
    bucketHours,
    windowStartMs,
    windowEndMs,
    baselineStartMs,
    baselineSources: baselineSources.size,
    totalAlerts,
    bucketCount: full.length,
    buckets: shown,
    truncated,
    avgPerBucket,
    trendPct,
    trend,
  };

  const highlights = writeHighlights(base, full);

  const model: TimelineReport = { ...base, highlights, sparkline: sparkLine, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded timeline ledger. */
export function timelineFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-timeline-${stamp}.md`;
}
