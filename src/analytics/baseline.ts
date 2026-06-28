/**
 * Self-baseline anomaly scorecard — "**is right now abnormal compared to my own
 * normal?**"
 *
 * Every threshold in security is really a question about *normal*. "200 alerts an
 * hour" means nothing until you know whether your normal is 20 or 2 000. SecTool
 * already ranks *who* and *what* exhaustively, and it has three time-aware lenses
 * — but none of them answers the smoke-alarm question an on-call analyst actually
 * starts the day with: **"is anything off right now, versus how this network
 * usually behaves?"**
 *
 *   - **surge** flags *within-window* sub-hour spikes against the window's own
 *     median bucket — it is blind to a window that is *uniformly* 3× too busy
 *     (no single bucket stands out, yet the whole period is abnormal).
 *   - **compare** diffs this window against the **single** previous one — one
 *     noisy prior period and the comparison is meaningless; it has no notion of
 *     variance, so it can't tell a +40% that happens every Tuesday from a +40%
 *     that has never happened before.
 *   - **forecast** projects *forward* from the hour-of-day rhythm — it predicts,
 *     it doesn't grade the present.
 *
 * This report fills that gap with the simplest honest statistic: a **z-score
 * against the network's own recent history**. It slices the immediate past into a
 * **recent window** (default 24 h) and the **K equal-length windows before it**
 * (default 14 — i.e. a fortnight of trailing days when the window is 24 h), then
 * for each headline metric computes how many standard deviations the recent value
 * sits from the trailing baseline mean:
 *
 *     z = (recent − mean(baseline)) ÷ stdev(baseline)
 *
 * Metrics graded (each tagged with which direction is *bad*):
 *
 *   - **Alerts**, **serious** (high+critical), **total risk weight** and **mean
 *     risk density** (the `--risk` ladder: severity × disposition) — louder /
 *     nastier than usual is worse.
 *   - **Distinct sources**, **distinct targets**, **distinct signatures** — a
 *     sudden broadening of the attack surface is worse.
 *   - **Block rate** — here *lower* than usual is the worry (enforcement slipping
 *     while volume holds).
 *
 * Each metric is read **normal / elevated / anomalous** off |z| (< 1.5 / < 3 /
 * ≥ 3), folded — in the *concerning* direction only — into a single posture
 * verdict (🟢 normal · 🟡 elevated · 🔴 anomalous · ⚪ insufficient baseline). To
 * make an anomaly *actionable* rather than just flagged, the headline metric is
 * decomposed into the **signatures that drove it** (recent count vs trailing
 * mean, biggest risers first) and the report separately surfaces **brand-new
 * sources** — addresses active in the recent window that appear *nowhere* in the
 * trailing baseline, the classic "never seen this attacker before" tell that a
 * z-score on aggregate counts averages away.
 *
 * Honest caveats baked into the output:
 *
 *   - **A z-score needs a populated baseline.** With too few non-empty trailing
 *     windows the variance estimate is junk, so the report needs `--baselines N`
 *     (default 14, min 2) windows of history; if the examined span has no alerts
 *     at all it says so rather than inventing an anomaly.
 *   - **Zero-variance baselines.** If every trailing window held the identical
 *     value, stdev is 0 and any deviation is technically infinite — shown as a
 *     "novel" ▲/▼ marker, not a fake giant number.
 *   - **Ratio metrics (density, block rate) only average windows that had
 *     alerts**, so a quiet 0-alert day can't drag a rate baseline to zero; their
 *     effective sample size is reported.
 *   - **Seasonality is not modelled.** A 24 h window compared to trailing 24 h
 *     windows naturally controls for time-of-day, but a weekly pattern (quiet
 *     weekends) will read as a recurring "anomaly". This is a *relative* alarm,
 *     not a forecast — pair it with `--rhythm` / `--forecast` for the cyclical view.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network. Output is
 * both a structured model and a ready-to-paste Markdown document, mirroring
 * risk.ts, potency.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { classifyDisposition, type Disposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT, DISPOSITION_FACTOR } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** How abnormal a single metric is, read off |z|. */
export type AnomalyLevel = "normal" | "elevated" | "anomalous";

/** Overall posture for the recent window. */
export type BaselinePosture = "normal" | "elevated" | "anomalous" | "insufficient";

/** The metrics the scorecard grades. */
export type MetricKey =
  | "alerts"
  | "serious"
  | "riskWeight"
  | "density"
  | "sources"
  | "targets"
  | "signatures"
  | "blockRate";

/** One graded metric: recent value versus the trailing baseline distribution. */
export interface MetricScore {
  key: MetricKey;
  /** Human label for the metric. */
  label: string;
  /** The value observed in the recent window. */
  recent: number;
  /** Mean of this metric across the (qualifying) baseline windows. */
  baselineMean: number;
  /** Sample standard deviation across the baseline windows. */
  baselineStdev: number;
  /** How many baseline windows fed the mean/stdev (ratio metrics skip empty ones). */
  baselineN: number;
  /** Standard-score of {@link recent} against the baseline; null if undefined. */
  z: number | null;
  /** Share of baseline windows whose value was ≤ {@link recent}, 0..1. */
  percentile: number;
  /** True when stdev was 0 but recent differs — a "novel" reading, z is ±∞. */
  novel: boolean;
  /** Whether a *higher* value is the concerning direction (false ⇒ lower is). */
  higherIsWorse: boolean;
  /**
   * Signed deviation in the *concerning* direction: `z` for higher-is-worse
   * metrics, `−z` otherwise. The number the posture verdict folds over.
   */
  concernZ: number | null;
  /** Anomaly bucket read off |z|. */
  level: AnomalyLevel;
}

/** A signature that drove the headline anomaly (recent count vs trailing mean). */
export interface SignatureDriver {
  signature: string;
  /** Times this signature fired in the recent window. */
  recent: number;
  /** Mean times per window across the trailing baseline. */
  baselineMean: number;
  /** recent − baselineMean (positive ⇒ rising). */
  delta: number;
}

/** A source seen in the recent window but in none of the baseline windows. */
export interface NewSource {
  ip: string;
  /** Alerts this fresh source raised in the recent window. */
  alerts: number;
  /** Worst severity observed from it. */
  severityMax: Severity;
  /** Whether it is already enforced. */
  blocked: boolean;
}

export interface BaselineReport {
  /** Recent-window width in hours. */
  windowHours: number;
  /** Number of trailing baseline windows requested. */
  baselineWindows: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Oldest ms epoch examined (start of the earliest baseline window). */
  historyStartMs: number;
  /** Alerts (with a parseable time) in the recent window. */
  recentAlerts: number;
  /** Alerts across all trailing baseline windows. */
  baselineAlertsTotal: number;
  /** Count of baseline windows that held at least one alert. */
  baselineActiveWindows: number;
  /** Overall posture for the recent window. */
  posture: BaselinePosture;
  /** The most concerning metric (max concernZ), if any qualified. */
  headline?: MetricScore;
  /** Every graded metric, in display order. */
  metrics: MetricScore[];
  /** Per-window total-alert counts, oldest → newest (last entry is recent). */
  alertSeries: number[];
  /** Signatures that drove the headline anomaly, biggest risers first. */
  drivers: SignatureDriver[];
  /** Distinct sources active in the recent window. */
  recentSources: number;
  /** Sources active in the recent window but absent from the whole baseline. */
  newSources: NewSource[];
  /** Total count of new sources (newSources may be capped for display). */
  newSourceCount: number;
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface BaselineOptions {
  /** Trailing baseline windows to compare against; clamped to [2, 90]. Default 14. */
  baselineWindows?: number;
  /** Max new-source rows shown; clamped to [1, 200]. Default 15. */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_BASELINE_WINDOWS = 14;
const DEFAULT_LIMIT = 15;
const MS_PER_HOUR = 3_600_000;

/** |z| at/above which a metric is "elevated". */
const ELEVATED_Z = 1.5;
/** |z| at/above which a metric is "anomalous". */
const ANOMALOUS_Z = 3;

const POSTURE_LABEL: Record<BaselinePosture, string> = {
  normal: "🟢 Normal",
  elevated: "🟡 Elevated",
  anomalous: "🔴 Anomalous",
  insufficient: "⚪ Insufficient baseline",
};

const LEVEL_LABEL: Record<AnomalyLevel, string> = {
  normal: "🟢 normal",
  elevated: "🟡 elevated",
  anomalous: "🔴 anomalous",
};

// ----- helpers (mirror risk.ts / potency.ts) ---------------------------------

function validIp(ip: string | undefined): string | undefined {
  return ip && isIP(ip) !== 0 ? ip : undefined;
}

function asSeverity(s: string | undefined): Severity {
  return (SEVERITY_ORDER as readonly string[]).includes(s ?? "") ? (s as Severity) : "info";
}

function sevRank(s: Severity): number {
  return (SEVERITY_ORDER as readonly string[]).indexOf(s);
}

function maxSeverity(a: Severity, b: Severity): Severity {
  return sevRank(b) > sevRank(a) ? b : a;
}

function isSerious(s: Severity): boolean {
  return sevRank(s) >= sevRank("high");
}

function alertWeight(sev: Severity, disp: Disposition): number {
  return SEVERITY_WEIGHT[sev] * DISPOSITION_FACTOR[disp];
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

function pct(share: number): string {
  return `${Math.round(share * 100)}%`;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function clip(s: string, max = 44): string {
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

/** A compact unicode bar sparkline scaled to the series' own max. */
const SPARK = "▁▂▃▄▅▆▇█";
function sparkline(series: number[]): string {
  if (!series.length) return "";
  const max = Math.max(...series);
  if (max <= 0) return SPARK[0]!.repeat(series.length);
  return series
    .map((v) => {
      const idx = Math.min(SPARK.length - 1, Math.round((v / max) * (SPARK.length - 1)));
      return SPARK[idx];
    })
    .join("");
}

/** Mean of a numeric list (0 for empty). */
function mean(xs: number[]): number {
  if (!xs.length) return 0;
  return xs.reduce((a, b) => a + b, 0) / xs.length;
}

/** Sample standard deviation (n−1); 0 for fewer than two points. */
function stdev(xs: number[], mu: number): number {
  if (xs.length < 2) return 0;
  const variance = xs.reduce((a, x) => a + (x - mu) ** 2, 0) / (xs.length - 1);
  return Math.sqrt(variance);
}

/** Share of baseline values ≤ recent, in 0..1 (0.5 for an empty baseline). */
function percentileRank(baseline: number[], recent: number): number {
  if (!baseline.length) return 0.5;
  const below = baseline.filter((v) => v <= recent).length;
  return below / baseline.length;
}

function levelFor(z: number | null, novel: boolean): AnomalyLevel {
  if (novel) return "anomalous";
  if (z === null) return "normal";
  const a = Math.abs(z);
  if (a >= ANOMALOUS_Z) return "anomalous";
  if (a >= ELEVATED_Z) return "elevated";
  return "normal";
}

// ----- per-window aggregation ------------------------------------------------

interface WindowAcc {
  alerts: number;
  serious: number;
  weight: number;
  blocked: number;
  sources: Set<string>;
  targets: Set<string>;
  signatures: Set<string>;
}

function newWindowAcc(): WindowAcc {
  return {
    alerts: 0,
    serious: 0,
    weight: 0,
    blocked: 0,
    sources: new Set(),
    targets: new Set(),
    signatures: new Set(),
  };
}

const METRIC_LABEL: Record<MetricKey, string> = {
  alerts: "Alerts",
  serious: "Serious (high+critical)",
  riskWeight: "Total risk weight",
  density: "Mean risk density",
  sources: "Distinct sources",
  targets: "Distinct targets",
  signatures: "Distinct signatures",
  blockRate: "Block rate",
};

/** Whether a higher value is the concerning direction for each metric. */
const HIGHER_IS_WORSE: Record<MetricKey, boolean> = {
  alerts: true,
  serious: true,
  riskWeight: true,
  density: true,
  sources: true,
  targets: true,
  signatures: true,
  blockRate: false,
};

/** Metrics computed as a per-window ratio (skip empty windows in the baseline). */
const RATIO_METRICS: ReadonlySet<MetricKey> = new Set<MetricKey>(["density", "blockRate"]);

function windowValue(key: MetricKey, w: WindowAcc): number {
  switch (key) {
    case "alerts":
      return w.alerts;
    case "serious":
      return w.serious;
    case "riskWeight":
      return w.weight;
    case "density":
      return w.alerts > 0 ? w.weight / w.alerts : 0;
    case "sources":
      return w.sources.size;
    case "targets":
      return w.targets.size;
    case "signatures":
      return w.signatures.size;
    case "blockRate":
      return w.alerts > 0 ? w.blocked / w.alerts : 0;
  }
}

function scoreMetric(key: MetricKey, recentW: WindowAcc, baselineWs: WindowAcc[]): MetricScore {
  const recent = windowValue(key, recentW);
  // Ratio metrics only average windows that actually had alerts, so a quiet day
  // can't drag the rate baseline to a meaningless zero.
  const pool = RATIO_METRICS.has(key) ? baselineWs.filter((w) => w.alerts > 0) : baselineWs;
  const values = pool.map((w) => windowValue(key, w));
  const mu = mean(values);
  const sd = stdev(values, mu);

  // A ratio metric (density, block rate) is undefined when the recent window had
  // no alerts at all — scoring its "0" against the baseline would manufacture a
  // false low-block-rate / low-density anomaly out of a simply quiet period.
  const ratioNotApplicable = RATIO_METRICS.has(key) && recentW.alerts === 0;

  let z: number | null = null;
  let novel = false;
  if (!ratioNotApplicable && values.length >= 2) {
    if (sd > 0) {
      z = (recent - mu) / sd;
    } else if (recent !== mu) {
      // Zero-variance baseline but the recent value moved — technically infinite.
      novel = true;
    } else {
      z = 0;
    }
  }

  const higherIsWorse = HIGHER_IS_WORSE[key];
  const level = levelFor(z, novel);
  const concernZ = novel ? (recent > mu === higherIsWorse ? Infinity : -Infinity) : z === null ? null : higherIsWorse ? z : -z;

  return {
    key,
    label: METRIC_LABEL[key],
    recent: RATIO_METRICS.has(key) ? round2(recent) : round1(recent),
    baselineMean: RATIO_METRICS.has(key) ? round2(mu) : round1(mu),
    baselineStdev: round2(sd),
    baselineN: values.length,
    z: z === null ? null : round2(z),
    percentile: round2(percentileRank(values, recent)),
    novel,
    higherIsWorse,
    concernZ: concernZ === null ? null : Number.isFinite(concernZ) ? round2(concernZ) : concernZ,
    level,
  } satisfies MetricScore;
}

const METRIC_ORDER: readonly MetricKey[] = [
  "alerts",
  "serious",
  "riskWeight",
  "density",
  "sources",
  "targets",
  "signatures",
  "blockRate",
];

// ----- highlights ------------------------------------------------------------

function fmtZ(s: MetricScore): string {
  if (s.novel) return s.recent > s.baselineMean ? "▲ novel" : "▼ novel";
  if (s.z === null) return "—";
  const sign = s.z >= 0 ? "+" : "";
  return `${sign}${s.z.toFixed(2)}σ`;
}

function writeHighlights(m: Omit<BaselineReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (m.posture === "insufficient") {
    out.push(
      `⚪ Not enough trailing history to baseline: only **${m.baselineActiveWindows}** of ${m.baselineWindows} ` +
        `prior window(s) held alerts. Let SecTool collect more, or shorten the window (\`--baseline <hours>\`).`,
    );
    return out;
  }

  out.push(
    `${POSTURE_LABEL[m.posture]} — the last ${m.windowHours}h carried **${m.recentAlerts}** alert(s) ` +
      `(trailing ${m.baselineWindows}-window mean ${m.metrics.find((x) => x.key === "alerts")?.baselineMean ?? 0}).`,
  );

  // The headline anomaly, decomposed into its drivers.
  if (m.headline && m.headline.level !== "normal") {
    const h = m.headline;
    const dir = h.recent >= h.baselineMean ? "above" : "below";
    out.push(
      `${LEVEL_LABEL[h.level]} **${h.label}**: ${h.recent} vs typical ${h.baselineMean}` +
        `${h.baselineStdev > 0 ? `±${h.baselineStdev}` : ""} (**${fmtZ(h)}** ${dir} baseline, ` +
        `${pct(h.percentile)} percentile).` +
        (m.drivers.length
          ? ` Driven by ${m.drivers
              .slice(0, 3)
              .map((d) => `\`${clip(d.signature, 36)}\` (${d.recent} vs ~${round1(d.baselineMean)})`)
              .join(", ")}.`
          : ""),
    );
  } else if (m.headline) {
    out.push(
      `✅ Every graded metric is within ${ELEVATED_Z}σ of normal — quietest standout is **${m.headline.label}** ` +
        `at ${fmtZ(m.headline)}. Nothing demands attention from a baseline perspective.`,
    );
  }

  // Brand-new sources — the "never seen this attacker before" tell.
  if (m.newSourceCount > 0) {
    const worst = m.newSources[0];
    out.push(
      `🆕 **${m.newSourceCount}** source(s) active this window appear **nowhere** in the trailing ` +
        `${m.baselineWindows}-window baseline` +
        (worst
          ? ` — busiest is \`${worst.ip}\` (${worst.alerts} alert(s), worst \`${worst.severityMax}\`` +
            `${worst.blocked ? ", already blocked" : ""})`
          : "") +
        `. Cross-check with \`--novelty\` and \`--pivot\`.`,
    );
  }

  // Block-rate slippage gets its own call-out — it's the one "lower is worse" axis.
  const br = m.metrics.find((x) => x.key === "blockRate");
  if (br && br.level !== "normal" && br.recent < br.baselineMean) {
    out.push(
      `🛡️ Enforcement is slipping: block rate **${pct(br.recent)}** vs usual **${pct(br.baselineMean)}** ` +
        `(${fmtZ(br)}). More is getting through than your baseline — see \`--efficacy\` and \`--priority\`.`,
    );
  }

  return out;
}

// ----- markdown --------------------------------------------------------------

function metricTable(metrics: MetricScore[]): string {
  return mdTable(
    ["Metric", "Recent", "Baseline (mean±σ)", "n", "z-score", "Pctile", "Reading", "Bad when"],
    metrics.map((s) => [
      cell(s.label),
      cell(s.recent),
      cell(`${s.baselineMean}${s.baselineStdev > 0 ? ` ± ${s.baselineStdev}` : ""}`),
      String(s.baselineN),
      `**${fmtZ(s)}**`,
      pct(s.percentile),
      LEVEL_LABEL[s.level],
      s.higherIsWorse ? "↑ high" : "↓ low",
    ]),
  );
}

function driverTable(drivers: SignatureDriver[]): string {
  return mdTable(
    ["Signature", "Recent", "Baseline mean/window", "Δ"],
    drivers.map((d) => [
      cell(`\`${clip(d.signature)}\``),
      String(d.recent),
      String(round1(d.baselineMean)),
      `${d.delta >= 0 ? "+" : ""}${round1(d.delta)}`,
    ]),
  );
}

function newSourceTable(sources: NewSource[]): string {
  return mdTable(
    ["Source", "Alerts", "Worst severity", "Enforced"],
    sources.map((s) => [cell(`\`${s.ip}\``), String(s.alerts), cell(s.severityMax), s.blocked ? "🚫 blocked" : "—"]),
  );
}

function renderMarkdown(m: BaselineReport): string {
  const lines: string[] = [];
  lines.push(`# 📊 SecTool Self-Baseline Anomaly Scorecard`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Recent window:** last ${m.windowHours}h — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`,
  );
  lines.push(
    `**Baseline:** ${m.baselineWindows} × ${m.windowHours}h trailing window(s) ` +
      `(${fmtTime(m.historyStartMs)} → ${fmtTime(m.windowStartMs)}), ` +
      `${m.baselineActiveWindows} with alerts · **Posture:** ${POSTURE_LABEL[m.posture]}`,
  );
  lines.push(
    `**Method:** z = (recent − baseline mean) ÷ baseline σ per metric; |z| ≥ ${ELEVATED_Z} elevated, ` +
      `≥ ${ANOMALOUS_Z} anomalous. Risk weight uses the \`--risk\` ladder (severity × disposition). ` +
      `Offline, deterministic.`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (m.posture === "insufficient") {
    for (const h of m.highlights) lines.push(`- ${h}`);
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  if (m.alertSeries.length > 1) {
    lines.push(
      `**Alert volume per window** (oldest → newest, last bar is the recent window): ` +
        `\`${sparkline(m.alertSeries)}\` — ${m.alertSeries.join(" · ")}`,
    );
    lines.push("");
  }

  lines.push(`## Metric scorecard`);
  lines.push("");
  lines.push(
    `_Each metric's recent value graded against the trailing baseline's own mean and spread. The **z-score** is ` +
      `how many standard deviations away it sits; **Bad when** marks the concerning direction._`,
  );
  lines.push("");
  lines.push(metricTable(m.metrics));
  lines.push("");
  lines.push(
    `**Legend:** _n_ = baseline windows that fed the stat (ratio metrics skip alert-free windows). ` +
      `_Pctile_ = share of baseline windows at or below the recent value. ` +
      `_▲/▼ novel_ = the baseline never varied, so any move is off-scale. ` +
      `Thresholds: |z| < ${ELEVATED_Z} ${LEVEL_LABEL.normal} · < ${ANOMALOUS_Z} ${LEVEL_LABEL.elevated} · ` +
      `≥ ${ANOMALOUS_Z} ${LEVEL_LABEL.anomalous}.`,
  );
  lines.push("");

  if (m.headline && m.headline.level !== "normal" && m.drivers.length) {
    lines.push(`## What drove the headline (${m.headline.label})`);
    lines.push("");
    lines.push(
      `_Signatures ranked by how far their recent count exceeds their trailing per-window mean — the concrete ` +
        `detections behind the aggregate spike._`,
    );
    lines.push("");
    lines.push(driverTable(m.drivers));
    lines.push("");
  }

  lines.push(`## Brand-new sources`);
  lines.push("");
  if (m.newSourceCount === 0) {
    lines.push(`_No source in the recent window was absent from the entire trailing baseline._`);
  } else {
    lines.push(
      `**${m.newSourceCount}** of ${m.recentSources} recent source(s) never appeared in the trailing ` +
        `${m.baselineWindows}-window baseline — the first-contact signal a z-score on totals averages away.`,
    );
    lines.push("");
    if (m.newSources.length < m.newSourceCount) {
      lines.push(`_Showing the ${m.newSources.length} busiest. Raise \`--limit\` to see more._`);
      lines.push("");
    }
    lines.push(newSourceTable(m.newSources));
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. This is a **relative** alarm against the network's own recent history, not a ` +
      `forecast — it controls for time-of-day by comparing equal-length windows but does **not** model weekly ` +
      `seasonality, so a recurring quiet weekend can read as an "anomaly". Pair it with \`--surge\` (within-window ` +
      `spikes), \`--compare\` (single prior window), \`--forecast\` (forward projection) and \`--rhythm\` (cyclical ` +
      `heat-map). No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the self-baseline anomaly scorecard from the stored alert history.
 *
 * @param hours Recent-window width in hours (clamped to [1, 90 days]).
 * @param opts  {@link BaselineOptions}: `baselineWindows`, `limit`, and a `nowMs`
 *              pin for deterministic tests.
 */
export function buildBaseline(hours: number, opts: BaselineOptions = {}): BaselineReport {
  const windowHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const baselineWindows = Math.max(2, Math.min(90, Math.floor(opts.baselineWindows ?? DEFAULT_BASELINE_WINDOWS)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowMs = windowHours * MS_PER_HOUR;
  const windowStartMs = windowEndMs - windowMs;
  const historyStartMs = windowEndMs - windowMs * (baselineWindows + 1);

  // One accumulator per slot: index 0 = recent window, 1..K = trailing baseline.
  const slots: WindowAcc[] = Array.from({ length: baselineWindows + 1 }, () => newWindowAcc());

  // Signature counts: recent window, and per-window totals across the baseline.
  const sigRecent = new Map<string, number>();
  const sigBaselineTotal = new Map<string, number>();

  // Source presence: which sources fired in the recent window vs anywhere in the
  // baseline (for the new-source detector), plus recent-source detail rows.
  const baselineSources = new Set<string>();
  interface RecentSrc {
    alerts: number;
    severityMax: Severity;
  }
  const recentSourceDetail = new Map<string, RecentSrc>();

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time > historyStartMs && a.time <= windowEndMs);

  for (const a of windowed) {
    // Slot 0 is the most recent window; higher slots are progressively older.
    const slot = Math.floor((windowEndMs - a.time) / windowMs);
    if (slot < 0 || slot > baselineWindows) continue;
    const w = slots[slot]!;

    const severity = asSeverity(a.severity);
    const disp = classifyDisposition(a.action);

    w.alerts++;
    w.weight += alertWeight(severity, disp);
    if (disp === "blocked") w.blocked++;
    if (isSerious(severity)) w.serious++;

    const ip = validIp(a.srcIp);
    if (ip) w.sources.add(ip);
    const dst = validIp(a.dstIp);
    if (dst) w.targets.add(dst);
    const sig = a.signature?.trim();
    if (sig) w.signatures.add(sig);

    if (slot === 0) {
      if (sig) sigRecent.set(sig, (sigRecent.get(sig) ?? 0) + 1);
      if (ip) {
        let d = recentSourceDetail.get(ip);
        if (!d) {
          d = { alerts: 0, severityMax: "info" };
          recentSourceDetail.set(ip, d);
        }
        d.alerts++;
        d.severityMax = maxSeverity(d.severityMax, severity);
      }
    } else {
      if (sig) sigBaselineTotal.set(sig, (sigBaselineTotal.get(sig) ?? 0) + 1);
      if (ip) baselineSources.add(ip);
    }
  }

  const recentW = slots[0]!;
  const baselineWs = slots.slice(1);
  const baselineActiveWindows = baselineWs.filter((w) => w.alerts > 0).length;
  const baselineAlertsTotal = baselineWs.reduce((n, w) => n + w.alerts, 0);

  const metrics = METRIC_ORDER.map((key) => scoreMetric(key, recentW, baselineWs));

  // Headline = the metric with the largest concerning deviation (∞ novels win).
  let headline: MetricScore | undefined;
  for (const s of metrics) {
    if (s.concernZ === null) continue;
    if (!headline || (headline.concernZ ?? -Infinity) < (s.concernZ ?? -Infinity)) headline = s;
  }

  // Posture: fold the *concerning* direction across metrics. Need a real baseline.
  let posture: BaselinePosture;
  if (baselineActiveWindows < 2) {
    posture = "insufficient";
  } else {
    const concerns = metrics.map((s) => s.concernZ).filter((z): z is number => z !== null);
    const maxConcern = concerns.length ? Math.max(...concerns) : 0;
    if (maxConcern >= ANOMALOUS_Z) posture = "anomalous";
    else if (maxConcern >= ELEVATED_Z) posture = "elevated";
    else posture = "normal";
  }

  // Drivers of the headline: signatures whose recent count most exceeds their
  // trailing per-window mean. Only meaningful for count-shaped anomalies.
  const drivers: SignatureDriver[] = [];
  const headlineIsCountShaped =
    headline !== undefined && headline.level !== "normal" && headline.key !== "blockRate" && headline.key !== "density";
  if (headlineIsCountShaped) {
    const all = new Set<string>([...sigRecent.keys(), ...sigBaselineTotal.keys()]);
    for (const sig of all) {
      const recent = sigRecent.get(sig) ?? 0;
      const baselineMean = (sigBaselineTotal.get(sig) ?? 0) / baselineWindows;
      const delta = recent - baselineMean;
      if (delta > 0) drivers.push({ signature: sig, recent, baselineMean: round2(baselineMean), delta: round2(delta) });
    }
    drivers.sort((a, b) => b.delta - a.delta || b.recent - a.recent || (a.signature < b.signature ? -1 : 1));
    drivers.length = Math.min(drivers.length, 8);
  }

  // New sources: active in the recent window, absent from the whole baseline.
  const newAll: NewSource[] = [];
  for (const [ip, d] of recentSourceDetail) {
    if (!baselineSources.has(ip)) {
      newAll.push({ ip, alerts: d.alerts, severityMax: d.severityMax, blocked: blockStore.has(ip) });
    }
  }
  newAll.sort(
    (a, b) => b.alerts - a.alerts || sevRank(b.severityMax) - sevRank(a.severityMax) || (a.ip < b.ip ? -1 : 1),
  );
  const newSourceCount = newAll.length;
  const newSources = newAll.slice(0, limit);

  // Alert series oldest → newest for the sparkline (reverse of the slot order).
  const alertSeries = slots.map((w) => w.alerts).reverse();

  const base: Omit<BaselineReport, "highlights" | "markdown"> = {
    windowHours,
    baselineWindows,
    windowStartMs,
    windowEndMs,
    historyStartMs,
    recentAlerts: recentW.alerts,
    baselineAlertsTotal,
    baselineActiveWindows,
    posture,
    headline,
    metrics,
    alertSeries,
    drivers,
    recentSources: recentSourceDetail.size,
    newSources,
    newSourceCount,
  };

  const highlights = writeHighlights(base);
  const model: BaselineReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded baseline report. */
export function baselineFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-baseline-${stamp}.md`;
}
