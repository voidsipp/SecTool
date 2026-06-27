/**
 * Attack-momentum / rate-trend report — "which sources are *ramping up* right
 * now, and which are winding down?"
 *
 * Every source-centric report in this project measures a *static* property of an
 * attacker's activity — how much, how varied, how clustered — but not the one
 * thing a responder triaging a noisy overnight window most needs: **direction**.
 * A source that fired 200 alerts is interesting; a source that fired 10 yesterday
 * and 190 in the last hour is an *incident in progress*, and a flat "top sources
 * by count" ranking buries it under the steady floods. The neighbouring temporal
 * reports each look at a different axis and deliberately *destroy* the directional
 * trend this report is about:
 *
 *   - surge.ts flags **global** volume spikes against a median baseline and
 *     attributes each spike to its driver — it answers "when did the *whole
 *     stream* storm", not "is *this source* on a rising slope of its own".
 *   - escalation.ts tracks a source's **severity** trajectory (is it getting
 *     *worse*) — orthogonal to *volume* momentum: a source can hammer ever harder
 *     at a constant low severity, or de-escalate while its rate climbs.
 *   - burstiness.ts measures **clumpiness** (Goh–Barabási B over inter-arrival
 *     gaps) — a scale-free texture that is by construction blind to whether the
 *     clumps are getting bigger or smaller over the window.
 *   - persist/dwell/cohort measure **longevity / retention**, not the local
 *     gradient of the rate. trends.ts renders one flat global histogram.
 *
 * None of them fit a *trend line to each source's own volume-over-time*. That
 * gradient is the sharpest "act now vs ignore" signal the stream holds.
 *
 * Method (pure in-memory math over alertStore — no SSH, no Claude, no network):
 *
 *   1. Slice the look-back window into `buckets` equal time bins (default 12,
 *      anchored to the absolute window so every source shares the same time axis
 *      and "recent" means the same thing for all of them).
 *   2. For each source with enough alerts, count alerts per bin and fit an
 *      ordinary **least-squares line** to (binIndex, count). The slope `b` is the
 *      per-bin change in rate; its **R²** is how cleanly the points follow that
 *      line (trend confidence).
 *   3. Normalise the slope to a scale-free **trend** in roughly [−1, +1] by
 *      dividing by the mean bin count and scaling by `(n+1)/6` — the value that
 *      maps "all alerts in the final bin" to +1 and "all in the first bin" to −1
 *      (the algebraic extremes of the fit), so the number is comparable across
 *      sources of wildly different volume.
 *   4. From `trend` (plus a single-bin guard) assign a one-word **direction**:
 *
 *        - 🚀 **surging**  trend ≥ +0.6  — heavily back-loaded, rate climbing fast
 *        - 📈 **rising**   trend ≥ +0.2  — clearly trending up
 *        - ➡️ **steady**   |trend| < 0.2 — roughly constant rate
 *        - 📉 **fading**   trend ≤ −0.2  — winding down
 *        - 💤 **spent**    trend ≤ −0.6  — front-loaded, effectively gone quiet
 *        - ⚡ **spike**    all activity in a *single* bin — a one-off burst with
 *                          no sustained trend to fit (direction is undefined; the
 *                          sparkline + recency show whether it was recent or old)
 *
 *   5. A 0–100 **momentum score** = `round(50 · (1 + clamp(trend)))` (50 = flat)
 *      is the ranking key, so the steepest *risers* float to the top regardless of
 *      raw volume — the opposite of a count ranking. A compact **sparkline**
 *      (▁▂▃▄▅▆▇█ over the bins) shows the actual shape so a low-R² "steady" that
 *      is really a mid-window hump is never hidden behind the label.
 *
 * Each row also carries recency (share of the source's alerts in the back half of
 * the window), first/last seen, worst severity, the blocked-vs-passed split (a
 * *surging* source whose traffic is being *let through* is the worst case), the
 * top signature, and blocklist / watchlist / safelist membership.
 *
 * Honest caveats baked into the output:
 *
 *   - **A trend is not a forecast.** The slope describes the window that already
 *     happened; a surging source may stop the moment you read this, and a spent
 *     one may return. Treat momentum as a triage *order*, not a prediction.
 *   - **Low R² ⇒ low confidence.** A noisy, humped, or U-shaped timeline can wear
 *     a small slope label; the fit quality is reported per row and the sparkline
 *     is always shown so the shape can be eyeballed.
 *   - **Bucket-width sensitive.** Too few bins blur a late spike into "steady";
 *     too many over a sparse window make every source a string of 0/1 noise. The
 *     chosen bin count and width are stated, and `--buckets` tunes it.
 *   - **Alerts, not flows; window-bounded & store-capped.** SecTool stores IPS
 *     *detections*; a long look-back can hit the store's history cap and clip the
 *     early bins, flattering the trend upward.
 *
 * Output is both a structured model and a ready-to-paste Markdown document,
 * mirroring repertoire.ts, escalation.ts, surge.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** The momentum direction a source's volume trend falls into. */
export type MomentumDirection = "surging" | "rising" | "steady" | "fading" | "spent" | "spike";

/** Blocked / passed / unknown disposition split for a source. */
export interface DispositionSplit {
  /** Alerts the gateway actively blocked / dropped. */
  blocked: number;
  /** Alerts the gateway logged but let through (detected / allowed). */
  passed: number;
  /** Alerts with no recorded action (excluded from {@link passRate}). */
  unknown: number;
  /**
   * Fraction of *actioned* (blocked + passed) alerts let through, 0..1 (4dp), or
   * null when nothing was actioned. High on a *surging* source means its rising
   * activity is reaching your hosts unblocked — the worst case.
   */
  passRate: number | null;
}

/** Per-source momentum / rate-trend metrics over the window. */
export interface MomentumSource {
  /** The source IP. */
  ip: string;
  /** True when the source is one of our own hosts (RFC1918 / loopback / …). */
  internal: boolean;
  /** The assigned momentum direction (see {@link MomentumDirection}). */
  direction: MomentumDirection;
  /** 0–100 momentum score (50 = flat) — the ranking key. */
  momentum: number;
  /** Scale-free trend in roughly [−1, +1] (the normalised least-squares slope). */
  trend: number;
  /** Raw least-squares slope (alerts per bin), unnormalised. */
  slope: number;
  /** R² of the linear fit, 0..1 — trend confidence. */
  r2: number;
  /** Per-bin alert counts across the window, oldest bin first. */
  buckets: number[];
  /** Number of bins with at least one alert. */
  activeBuckets: number;
  /** Index of the busiest bin (0-based, oldest first). */
  peakBucket: number;
  /** Share of this source's alerts in the back half of the window, 0..1 (4dp). */
  recency: number;
  /** Total alerts attributed to this source in the window. */
  count: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Severity-weighted score (Σ SEVERITY_WEIGHT) — a secondary signal. */
  score: number;
  /** Worst severity seen from this source. */
  severityMax: Severity;
  /** Distinct destination hosts this source touched. */
  distinctHosts: number;
  /** Distinct signatures this source fired. */
  distinctSignatures: number;
  /** The most-frequent signature for this source, if any. */
  topSignature?: string;
  /** First alert time (ms epoch) in the window. */
  firstSeenMs: number;
  /** Last alert time (ms epoch) in the window. */
  lastSeenMs: number;
  /** Blocked / passed / unknown disposition split. */
  disposition: DispositionSplit;
  /** The source is on the blocklist. */
  blocked: boolean;
  /** The source is on the watchlist. */
  watched: boolean;
  /** The source is marked safe. */
  safe: boolean;
}

/** Count of sources falling into each momentum direction (the headline shape). */
export interface DirectionCounts {
  surging: number;
  rising: number;
  steady: number;
  fading: number;
  spent: number;
  spike: number;
}

export interface MomentumReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Number of equal time bins the window was sliced into. */
  buckets: number;
  /** Width of each bin in minutes. */
  bucketMinutes: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts carrying a valid source IP (the analysable set). */
  sourcedAlerts: number;
  /** Global per-bin alert counts across all sources (the whole-stream shape). */
  globalBuckets: number[];
  /** Whole-stream trend in roughly [−1, +1] (is the *overall* rate climbing?). */
  globalTrend: number;
  /** Distinct source IPs analysed (passed the min-alerts floor). */
  distinctSources: number;
  /** How many sources fell into each direction. */
  directionCounts: DirectionCounts;
  /** Per-source momentum rows, steepest risers first. */
  sources: MomentumSource[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface MomentumOptions {
  /** Max rows in the per-source table (clamped to [1, 200]). */
  limit?: number;
  /** Minimum alerts a source needs before it is analysed (drops one-off noise). */
  minAlerts?: number;
  /** Number of time bins to slice the window into (clamped to [3, 96]). */
  buckets?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const DEFAULT_MIN_ALERTS = 3;
const DEFAULT_BUCKETS = 12;
const MS_PER_HOUR = 3_600_000;

// Direction thresholds on the normalised trend (see file header).
const SURGE_T = 0.6;
const RISE_T = 0.2;

const SPARK = "▁▂▃▄▅▆▇█";

// ----- classifiers / helpers (mirror repertoire.ts / scan.ts) ----------------

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

function weightOf(s: string | undefined): number {
  return SEVERITY_WEIGHT[(s as Severity) ?? "info"] ?? SEVERITY_WEIGHT.info;
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, n));
}

function pct(frac: number): string {
  return `${Math.round(frac * 100)}%`;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function clip(s: string, max = 36): string {
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

/** Render a bin-count array as a unicode sparkline scaled to its own max. */
function sparkline(buckets: number[]): string {
  const max = Math.max(0, ...buckets);
  if (max === 0) return "·".repeat(buckets.length);
  return buckets
    .map((c) => {
      if (c === 0) return "·";
      const level = Math.max(0, Math.min(SPARK.length - 1, Math.round((c / max) * (SPARK.length - 1))));
      return SPARK[level] ?? "█";
    })
    .join("");
}

/** Human label + emoji for a direction, ordered hottest → coldest. */
function directionLabel(d: MomentumDirection): string {
  switch (d) {
    case "surging":
      return "🚀 surging";
    case "rising":
      return "📈 rising";
    case "steady":
      return "➡️ steady";
    case "fading":
      return "📉 fading";
    case "spent":
      return "💤 spent";
    case "spike":
      return "⚡ spike";
  }
}

/**
 * Ordinary least-squares fit of `y` against its own index 0..n-1. Returns the
 * slope (per-step change), intercept, and R² (coefficient of determination, 0
 * when the series is flat). Pure arithmetic — no dependencies.
 */
function linearFit(y: number[]): { slope: number; intercept: number; r2: number } {
  const n = y.length;
  if (n < 2) return { slope: 0, intercept: y[0] ?? 0, r2: 0 };
  const meanX = (n - 1) / 2;
  const meanY = y.reduce((s, v) => s + v, 0) / n;
  let sxy = 0;
  let sxx = 0;
  let syy = 0;
  for (let i = 0; i < n; i++) {
    const dx = i - meanX;
    const dy = y[i]! - meanY;
    sxy += dx * dy;
    sxx += dx * dx;
    syy += dy * dy;
  }
  const slope = sxx === 0 ? 0 : sxy / sxx;
  const intercept = meanY - slope * meanX;
  // R² = (explained variance) / (total variance); 0 when the series is flat.
  const r2 = syy === 0 ? 0 : clamp((sxy * sxy) / (sxx * syy), 0, 1);
  return { slope, intercept, r2 };
}

/**
 * Normalise a raw least-squares slope into a scale-free trend in roughly
 * [−1, +1]: divide by the mean bin count (so it is independent of volume) and
 * scale by (n+1)/6, the factor that maps the algebraic extreme "all alerts in
 * the final bin" to +1 and "all in the first bin" to −1.
 */
function normaliseTrend(slope: number, mean: number, n: number): number {
  if (mean <= 0 || n < 2) return 0;
  return (slope / mean) * ((n + 1) / 6);
}

/** Assign a direction from the normalised trend, with a single-bin guard. */
function classifyDirection(trend: number, activeBuckets: number): MomentumDirection {
  if (activeBuckets <= 1) return "spike";
  if (trend >= SURGE_T) return "surging";
  if (trend >= RISE_T) return "rising";
  if (trend > -RISE_T) return "steady";
  if (trend > -SURGE_T) return "fading";
  return "spent";
}

// ----- aggregation ----------------------------------------------------------

interface SourceAcc {
  count: number;
  score: number;
  severe: number;
  buckets: number[];
  hosts: Set<string>;
  signatures: Set<string>;
  sigCounts: Map<string, number>;
  blocked: number;
  passed: number;
  unknown: number;
  severityMax: Severity;
  firstSeenMs: number;
  lastSeenMs: number;
  backHalf: number; // alerts in the back half of the window (for recency)
}

function newSourceAcc(buckets: number): SourceAcc {
  return {
    count: 0,
    score: 0,
    severe: 0,
    buckets: new Array<number>(buckets).fill(0),
    hosts: new Set(),
    signatures: new Set(),
    sigCounts: new Map(),
    blocked: 0,
    passed: 0,
    unknown: 0,
    severityMax: "info",
    firstSeenMs: Number.POSITIVE_INFINITY,
    lastSeenMs: Number.NEGATIVE_INFINITY,
    backHalf: 0,
  };
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  m: { distinctSources: number; globalTrend: number },
  directionCounts: DirectionCounts,
  sources: MomentumSource[],
): string[] {
  const out: string[] = [];
  if (!sources.length) return out;

  // Whole-stream direction — is the night getting louder or quieter overall?
  const climbing = m.globalTrend >= RISE_T;
  const cooling = m.globalTrend <= -RISE_T;
  const streamWord = climbing ? "climbing 📈" : cooling ? "cooling 📉" : "flat ➡️";
  out.push(
    `🌊 Over the last ${hours}h the **overall alert rate is ${streamWord}** (stream trend ` +
      `${m.globalTrend >= 0 ? "+" : ""}${round4(m.globalTrend)}). **${m.distinctSources} source(s)** had enough ` +
      `volume to trend: ${directionCounts.surging} surging · ${directionCounts.rising} rising · ` +
      `${directionCounts.steady} steady · ${directionCounts.fading} fading · ${directionCounts.spent} spent · ` +
      `${directionCounts.spike} one-off spike(s).`,
  );

  // The hottest riser — what to triage first.
  const lead = sources[0]!;
  out.push(
    `🥇 Steepest momentum is \`${lead.ip}\`${lead.internal ? " *(internal!)*" : ""} — **${directionLabel(lead.direction)}**, ` +
      `score **${lead.momentum}/100** (trend ${lead.trend >= 0 ? "+" : ""}${round4(lead.trend)}, R²=${round4(lead.r2)}): ` +
      `${lead.count} alert(s), \`${sparkline(lead.buckets)}\`, ${pct(lead.recency)} of them in the back half.`,
  );

  // Surging / rising sources reaching your hosts unblocked — the worst case.
  const leaky = sources
    .filter(
      (s) =>
        (s.direction === "surging" || s.direction === "rising") &&
        s.disposition.passRate !== null &&
        s.disposition.passed >= 3,
    )
    .sort((a, b) => (b.disposition.passRate ?? 0) - (a.disposition.passRate ?? 0))[0];
  if (leaky && (leaky.disposition.passRate ?? 0) >= 0.5) {
    out.push(
      `⚠️ \`${leaky.ip}\` is **${directionLabel(leaky.direction)}** and **${pct(leaky.disposition.passRate!)} let ` +
        `through** (${leaky.disposition.passed} actioned alerts passed). A rising attacker reaching your hosts ` +
        `unblocked is the worst case — block it now before the slope continues.`,
    );
  }

  // Internal hosts on the way up — a compromise / exfil ramp tell.
  const insiders = sources.filter(
    (s) => s.internal && (s.direction === "surging" || s.direction === "rising"),
  );
  if (insiders.length) {
    const i = insiders[0]!;
    out.push(
      `🚨 **${insiders.length} *internal* host(s)** are trending **up** — a rising rate from one of your own boxes ` +
        `is a beaconing / exfil / worm ramp, not an inbound probe. Investigate \`${i.ip}\` ` +
        `(${directionLabel(i.direction)}, ${i.count} alerts) first.`,
    );
  }

  // Spent sources — safe to deprioritise this morning.
  if (directionCounts.spent > 0) {
    out.push(
      `💤 **${directionCounts.spent} source(s)** are *spent* (front-loaded, now quiet) — they drove earlier noise but ` +
        `have effectively stopped; safe to deprioritise unless they return.`,
    );
  }

  // Honesty: how many leading rows are low-confidence fits.
  const noisy = sources.filter((s) => s.direction !== "spike" && s.r2 < 0.3).length;
  if (noisy >= Math.ceil(sources.length / 2)) {
    out.push(
      `ℹ️ **${noisy} of ${sources.length}** shown rows have a **low-confidence fit** (R²<0.3) — bumpy, humped or ` +
        `U-shaped timelines wearing a weak slope label. Read the sparkline, not just the direction word.`,
    );
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function sourceTable(rows: MomentumSource[]): string {
  return mdTable(
    ["#", "Source", "Direction", "Score", "Trend", "R²", "Shape", "Alerts", "Recent", "Hosts", "Sigs", "Top signature", "Passed", "Flags"],
    rows.map((s, i) => {
      const flags =
        (s.internal ? "🏠" : "") +
        (s.blocked ? "⛔" : "") +
        (s.watched ? "👁" : "") +
        (s.safe ? "✅" : "");
      return [
        String(i + 1),
        cell(s.ip),
        cell(directionLabel(s.direction)),
        String(s.momentum),
        `${s.trend >= 0 ? "+" : ""}${round4(s.trend)}`,
        s.direction === "spike" ? "—" : round4(s.r2).toFixed(2),
        `\`${sparkline(s.buckets)}\``,
        String(s.count),
        pct(s.recency),
        String(s.distinctHosts),
        String(s.distinctSignatures),
        cell(clip(s.topSignature ?? "—")),
        String(s.disposition.passed),
        flags || "—",
      ];
    }),
  );
}

function renderMarkdown(m: MomentumReport): string {
  const lines: string[] = [];
  lines.push(`# 🚀 SecTool Attack-Momentum / Rate-Trend Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** per source, alerts folded into **${m.buckets} time bins** of ~${m.bucketMinutes} min each, then an ` +
      `ordinary least-squares line fit to the per-bin counts; the normalised slope (**trend**, ~[−1,+1]) is ranked, ` +
      `**not volume**, so the steepest risers float to the top · **Sourced alerts:** ${m.sourcedAlerts} of ` +
      `${m.totalWindowAlerts} · **Stream trend:** ${m.globalTrend >= 0 ? "+" : ""}${round4(m.globalTrend)} ` +
      `\`${sparkline(m.globalBuckets)}\``,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.sources.length) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but none had a usable source IP and ` +
          `enough volume to fit a trend (min ${DEFAULT_MIN_ALERTS} alerts/source by default).`,
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

  lines.push(`## Sources by momentum`);
  lines.push("");
  lines.push(sourceTable(m.sources));
  lines.push("");
  lines.push(
    `**Legend:** _Direction_ — **🚀 surging** (trend ≥ +${SURGE_T}: rate climbing fast) · **📈 rising** ` +
      `(≥ +${RISE_T}) · **➡️ steady** (|trend| < ${RISE_T}) · **📉 fading** (≤ −${RISE_T}) · **💤 spent** ` +
      `(≤ −${SURGE_T}: front-loaded, now quiet) · **⚡ spike** (all activity in one bin: a one-off burst, no trend). ` +
      `_Score_ 0–100 (50 = flat) = ranking key, **volume excluded** so a small fast riser outranks a steady flood. ` +
      `_Trend_ is the scale-free slope; _R²_ its fit confidence (low ⇒ read the _Shape_ sparkline ▁▂▃▄▅▆▇█, oldest ` +
      `bin left). _Recent_ = share of the source's alerts in the back half of the window. **Flags:** 🏠 internal ` +
      `source · ⛔ blocked · 👁 watched · ✅ safe.`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. **A trend is a description of the window that already happened, not a ` +
      `forecast** — a surging source may stop the moment you read this and a spent one may return; use momentum as a ` +
      `triage order, not a prediction. A noisy, humped or U-shaped timeline can wear a small slope label, so the fit ` +
      `R² is shown per row and the sparkline is always rendered. The result is sensitive to bin width (${m.buckets} ` +
      `bins of ~${m.bucketMinutes} min here; tune with \`--buckets\`). These are IPS **detections**, not full flows, ` +
      `and a long look-back can hit the store's history cap and clip the early bins — flattering the trend upward. No ` +
      `live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the attack-momentum / rate-trend report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link MomentumOptions}: `limit`, `minAlerts`, `buckets`, and a
 *              `nowMs` pin for deterministic tests.
 */
export function buildMomentum(hours: number, opts: MomentumOptions = {}): MomentumReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minAlerts = Math.max(2, Math.floor(opts.minAlerts ?? DEFAULT_MIN_ALERTS));
  const buckets = Math.max(3, Math.min(96, Math.floor(opts.buckets ?? DEFAULT_BUCKETS)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;
  const spanMs = windowEndMs - windowStartMs;
  const bucketMs = spanMs / buckets;
  const bucketMinutes = Math.max(1, Math.round(bucketMs / 60_000));
  const midMs = windowStartMs + spanMs / 2;

  /** Map an absolute timestamp to its bin index, clamped to [0, buckets-1]. */
  const binOf = (t: number): number => {
    const idx = Math.floor((t - windowStartMs) / bucketMs);
    return idx < 0 ? 0 : idx >= buckets ? buckets - 1 : idx;
  };

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const sources = new Map<string, SourceAcc>();
  const globalBuckets = new Array<number>(buckets).fill(0);
  let sourced = 0;

  for (const a of windowed) {
    const bin = binOf(a.time);
    globalBuckets[bin]!++;

    const src = validIp(a.srcIp);
    if (!src) continue;
    sourced++;

    const acc = sources.get(src) ?? newSourceAcc(buckets);
    if (!sources.has(src)) sources.set(src, acc);
    acc.count++;
    acc.buckets[bin]!++;
    acc.score += weightOf(a.severity);
    acc.severityMax = maxSeverity(acc.severityMax, a.severity);
    if (isSevere(a.severity)) acc.severe++;
    if (a.time >= midMs) acc.backHalf++;
    if (a.time < acc.firstSeenMs) acc.firstSeenMs = a.time;
    if (a.time > acc.lastSeenMs) acc.lastSeenMs = a.time;

    const dst = validIp(a.dstIp);
    if (dst) acc.hosts.add(dst);

    const sig = (a.signature ?? "").trim();
    if (sig) {
      acc.signatures.add(sig);
      acc.sigCounts.set(sig, (acc.sigCounts.get(sig) ?? 0) + 1);
    }

    const disp = classifyDisposition(a.action);
    if (disp === "blocked") acc.blocked++;
    else if (disp === "passed") acc.passed++;
    else acc.unknown++;
  }

  const directionCounts: DirectionCounts = {
    surging: 0,
    rising: 0,
    steady: 0,
    fading: 0,
    spent: 0,
    spike: 0,
  };

  const sourceList: MomentumSource[] = [...sources.entries()]
    .filter(([, acc]) => acc.count >= minAlerts)
    .map(([ip, acc]) => {
      const mean = acc.count / buckets;
      const fit = linearFit(acc.buckets);
      const trend = round4(clamp(normaliseTrend(fit.slope, mean, buckets), -1, 1));
      const activeBuckets = acc.buckets.filter((c) => c > 0).length;
      const direction = classifyDirection(trend, activeBuckets);
      directionCounts[direction]++;
      let peakBucket = 0;
      for (let i = 1; i < acc.buckets.length; i++) {
        if (acc.buckets[i]! > acc.buckets[peakBucket]!) peakBucket = i;
      }
      const actioned = acc.blocked + acc.passed;
      // Momentum score: 50 = flat; volume deliberately excluded. A one-off spike
      // has no trend, so it sits at the neutral midpoint regardless of size.
      const momentum =
        direction === "spike" ? 50 : Math.round(50 * (1 + clamp(trend, -1, 1)));
      return {
        ip,
        internal: isPrivate(ip),
        direction,
        momentum,
        trend,
        slope: round4(fit.slope),
        r2: round4(fit.r2),
        buckets: acc.buckets,
        activeBuckets,
        peakBucket,
        recency: round4(acc.backHalf / acc.count),
        count: acc.count,
        severe: acc.severe,
        score: acc.score,
        severityMax: acc.severityMax,
        distinctHosts: acc.hosts.size,
        distinctSignatures: acc.signatures.size,
        topSignature: topOf(acc.sigCounts),
        firstSeenMs: acc.firstSeenMs,
        lastSeenMs: acc.lastSeenMs,
        disposition: {
          blocked: acc.blocked,
          passed: acc.passed,
          unknown: acc.unknown,
          passRate: actioned ? round4(acc.passed / actioned) : null,
        },
        blocked: blockStore.has(ip),
        watched: watchStore.has(ip),
        safe: safeStore.has(ip),
      } satisfies MomentumSource;
    })
    // Steepest risers first: momentum score, then trend, then severity-weighted
    // magnitude, then volume, then IP for a stable order.
    .sort(
      (x, y) =>
        y.momentum - x.momentum ||
        y.trend - x.trend ||
        y.score - x.score ||
        y.count - x.count ||
        (x.ip < y.ip ? -1 : x.ip > y.ip ? 1 : 0),
    );

  // directionCounts is accumulated across *all* qualifying sources above; the
  // table is then capped to `limit` rows for display without disturbing totals.
  const cappedSources = sourceList.slice(0, limit);

  const globalFit = linearFit(globalBuckets);
  const globalMean = globalBuckets.reduce((s, v) => s + v, 0) / buckets;
  const globalTrend = round4(clamp(normaliseTrend(globalFit.slope, globalMean, buckets), -1, 1));

  const highlights = writeHighlights(
    safeHours,
    { distinctSources: sourceList.length, globalTrend },
    directionCounts,
    cappedSources,
  );

  const model: MomentumReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    buckets,
    bucketMinutes,
    totalWindowAlerts: windowed.length,
    sourcedAlerts: sourced,
    globalBuckets,
    globalTrend,
    distinctSources: sourceList.length,
    directionCounts,
    sources: cappedSources,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded momentum report. */
export function momentumFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-momentum-${stamp}.md`;
}
