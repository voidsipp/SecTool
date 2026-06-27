/**
 * Severity-mix drift / threat-quality-trend report — "is the *quality* of the
 * attacks landing on me getting **worse over time**, independent of how *many*
 * there are?"
 *
 * Every temporal report in this project tracks **volume**, and every severity
 * report collapses the window into a **static** number:
 *
 *   - surge.ts / momentum.ts / trends.ts watch the alert *rate* rise and fall —
 *     they answer "how *much* is happening", and a flood of `info` port-scans
 *     reads identically to a flood of `critical` exploits.
 *   - risk.ts collapses the whole window into a single severity-weighted
 *     **magnitude** (and a posture grade). It is volume-coupled by design: ten
 *     thousand blocked scans outweigh one passed critical, and a quiet-but-nasty
 *     window scores low. It tells you *how bad the total is*, not *which way the
 *     mix is moving*.
 *   - escalation.ts measures the severity trajectory of **one source over its own
 *     timeline** (front-half vs back-half), then ranks sources. It is the
 *     per-actor view; it never rolls the *whole stream's* severity composition up
 *     onto a single clock.
 *   - classify.ts / focus.ts / concentration.ts describe the *shape* of the mix
 *     (by class, by entity) at a point in time — a snapshot, with no time axis.
 *
 * None of them answer the one question a defender asks when the volume looks flat
 * but their gut says something changed:
 *
 *   **"Holding count aside, is the *average alert getting more severe* across this
 *   window — are the probes turning into exploits?"**
 *
 * That drift is a leading indicator a raw count hides completely. A window can
 * carry the same 1,000 alerts an hour all week while the *composition* silently
 * rotates from `info`/`low` reconnaissance toward `high`/`critical` exploitation —
 * the textbook recon→weaponise arc, but seen at the **fleet** level rather than
 * per-source. Conversely a scary-looking volume spike that is *all* low-severity
 * scan noise is the opposite of an emergency, and a falling average severity is a
 * quiet win worth knowing about.
 *
 * ## What it measures
 *
 * The window is split into `buckets` equal time slices (default ≈ 12, override
 * with `--buckets`). For each slice the report computes, over only the alerts
 * that actually landed in it (so an empty slice is "no data", never "zero
 * severity"):
 *
 *   - the **severity mix** — counts of info / low / medium / high / critical,
 *   - the **mean severity level** on a bounded linear ladder (info 0 … critical
 *     4) — the headline trend metric, intuitive and immune to one outlier,
 *   - a geometric **quality index** = mean severity *weight* per alert (info 1 ·
 *     low 3 · medium 9 · high 27 · critical 81, matching risk.ts) — the same idea
 *     on the order-of-magnitude scale risk.ts uses, for the sparkline shape, and
 *   - the **severe share** — fraction of the slice that is medium-or-worse.
 *
 * From the per-bucket mean levels it then derives the drift itself:
 *
 *   - a **front-half vs back-half delta** in severity levels (the robust headline
 *     "+0.8 levels nastier" number — splits the window by *time*, not by count,
 *     so both halves cover equal wall-clock),
 *   - an ordinary **least-squares slope** (levels per bucket) plus its **R²** so
 *     the trend comes with a confidence, fitted over the *active* buckets against
 *     their real time index (gaps respected, empty slices skipped — they are
 *     missing data, not zero), and
 *   - a one-word **direction** — 🔴 **escalating** / 🟠 **rising** / ⚪ **stable**
 *     / 🟢 **easing** / 🟢 **receding** — classified from the front/back delta with
 *     a single-active-bucket guard.
 *
 * It also flags the single sharpest **step change** between adjacent active
 * buckets (where the mix moved most), and contrasts the drift in *mean* severity
 * with the drift in *volume* so the output can say the genuinely useful thing:
 * "volume is flat but the mix is escalating" — the case no other report surfaces.
 *
 * ## Honest caveats baked into the output
 *
 *   - **Drift ≠ magnitude.** A rising average over five alerts is statistically
 *     thin; the per-bucket counts and the fit R² are shown so a confident-looking
 *     slope over a near-empty window is visibly weak. Pair with risk.ts for the
 *     absolute level.
 *   - **Severity is the gateway's label.** The ladder reflects how SecTool graded
 *     each alert from the IPS signature, not ground-truth impact; a noisy rule
 *     mis-rated `high` will tug the average up.
 *   - **Window- & store-bounded.** A long look-back can hit the alert store's
 *     history cap and clip the oldest buckets, biasing the earliest slices.
 *   - **Disposition-blind.** This measures *detected* severity, not what the
 *     gateway blocked — a window can escalate in severity while the IPS still
 *     stops all of it. Cross-read efficacy.ts / risk.ts for the enforcement side.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network. Output is
 * both a structured model and a ready-to-paste Markdown document, mirroring
 * momentum.ts, escalation.ts, concentration.ts and the other offline reports.
 */
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Which way the average alert severity is moving across the window. */
export type DriftDirection = "escalating" | "rising" | "stable" | "easing" | "receding";

/** Severity composition of a single time slice. */
export interface SeverityMix {
  info: number;
  low: number;
  medium: number;
  high: number;
  critical: number;
}

/** One equal time slice of the window. */
export interface DriftBucket {
  /** 0-based slice index, oldest first. */
  index: number;
  startMs: number;
  endMs: number;
  /** Alerts that landed in this slice. */
  count: number;
  /** Per-severity counts. */
  mix: SeverityMix;
  /** Mean severity on the linear ladder (info 0 … critical 4), 4dp; 0 if empty. */
  meanLevel: number;
  /** Geometric mean severity weight per alert (info 1 … critical 81), 4dp. */
  qualityIndex: number;
  /** Medium-or-worse share of the slice, 0..1 (4dp). */
  severeShare: number;
}

/** The sharpest single jump in mean severity between two adjacent active slices. */
export interface DriftStep {
  fromIndex: number;
  toIndex: number;
  /** Change in mean severity level across the step (signed, 4dp). */
  delta: number;
  /** Wall-clock start of the later slice. */
  atMs: number;
}

export interface DriftReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Number of equal time slices the window was cut into. */
  buckets: number;
  /** Slice width in milliseconds. */
  bucketMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Slices that carried at least one alert. */
  activeBuckets: number;
  /** Mean severity level across the whole window (info 0 … critical 4), 4dp. */
  overallMeanLevel: number;
  /** Mean severity level of the time-first-half / time-second-half, 4dp. */
  firstHalfMeanLevel: number;
  secondHalfMeanLevel: number;
  /** secondHalf − firstHalf, in severity levels (the headline drift), 4dp. */
  halfDelta: number;
  /** Least-squares slope of mean level vs bucket index (levels/bucket), 4dp. */
  slope: number;
  /** R² of that fit, 0..1 (trend confidence), 4dp. */
  r2: number;
  /** The one-word direction verdict. */
  direction: DriftDirection;
  /** Front/back volume delta as a share, 0-centred (e.g. +0.5 = back half 50% busier), 4dp. */
  volumeHalfDelta: number;
  /** The sharpest adjacent-slice step change, if there were ≥2 active slices. */
  sharpestStep?: DriftStep;
  /** The per-slice timeline, oldest first. */
  timeline: DriftBucket[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface DriftOptions {
  /** Number of equal time slices (clamped to [2, 96]); defaults to ~12. */
  buckets?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const MS_PER_HOUR = 3_600_000;
const DEFAULT_BUCKETS = 12;
const MIN_BUCKETS = 2;
const MAX_BUCKETS = 96;

/** Geometric severity weight, matching risk.ts (each step ≈ ×3). */
const SEVERITY_WEIGHT: Record<Severity, number> = {
  info: 1,
  low: 3,
  medium: 9,
  high: 27,
  critical: 81,
};

/** Front/back delta (in severity levels) at/above which the mix is escalating. */
const ESCALATE_DELTA = 0.75;
/** Delta at/above which the mix is clearly rising. */
const RISE_DELTA = 0.25;

const SPARK = "▁▂▃▄▅▆▇█";

// ----- helpers (mirror momentum.ts / concentration.ts) -----------------------

/** Linear ladder position of a severity (info 0 … critical 4); −1 if unknown. */
function sevLevel(s: string | undefined): number {
  return (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

function pct(frac: number, dp = 0): string {
  return `${(frac * 100).toFixed(dp)}%`;
}

function signed(n: number, dp = 2): string {
  return `${n >= 0 ? "+" : ""}${n.toFixed(dp)}`;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** Compact "MM-DD HH:MM" stamp for dense per-bucket rows. */
function fmtShort(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").slice(5, 16);
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

/** Render a numeric series as a unicode sparkline scaled to its own max. */
function sparkline(values: number[]): string {
  const max = Math.max(0, ...values);
  if (max <= 0) return "▁".repeat(values.length);
  return values
    .map((v) => {
      if (v <= 0) return SPARK[0]!;
      const level = Math.max(0, Math.min(SPARK.length - 1, Math.round((v / max) * (SPARK.length - 1))));
      return SPARK[level] ?? "█";
    })
    .join("");
}

/**
 * Ordinary least-squares fit of `ys` against arbitrary `xs` (here the real
 * bucket indices of the *active* slices, so gaps are respected). Returns slope
 * (levels per bucket-index step), intercept and R² (0 when flat). Pure math.
 */
function linearFitXY(xs: number[], ys: number[]): { slope: number; intercept: number; r2: number } {
  const n = xs.length;
  if (n < 2) return { slope: 0, intercept: ys[0] ?? 0, r2: 0 };
  const meanX = xs.reduce((s, v) => s + v, 0) / n;
  const meanY = ys.reduce((s, v) => s + v, 0) / n;
  let sxy = 0;
  let sxx = 0;
  let syy = 0;
  for (let i = 0; i < n; i++) {
    const dx = xs[i]! - meanX;
    const dy = ys[i]! - meanY;
    sxy += dx * dy;
    sxx += dx * dx;
    syy += dy * dy;
  }
  const slope = sxx === 0 ? 0 : sxy / sxx;
  const intercept = meanY - slope * meanX;
  const r2 = syy === 0 || sxx === 0 ? 0 : Math.max(0, Math.min(1, (sxy * sxy) / (sxx * syy)));
  return { slope, intercept, r2 };
}

/** Human label + emoji for a drift direction. */
function directionLabel(d: DriftDirection): string {
  switch (d) {
    case "escalating":
      return "🔴 escalating";
    case "rising":
      return "🟠 rising";
    case "stable":
      return "⚪ stable";
    case "easing":
      return "🟢 easing";
    case "receding":
      return "🟢 receding";
  }
}

/** Classify the direction from the front/back severity-level delta. */
function classifyDirection(halfDelta: number, activeBuckets: number): DriftDirection {
  if (activeBuckets <= 1) return "stable";
  if (halfDelta >= ESCALATE_DELTA) return "escalating";
  if (halfDelta >= RISE_DELTA) return "rising";
  if (halfDelta > -RISE_DELTA) return "stable";
  if (halfDelta > -ESCALATE_DELTA) return "easing";
  return "receding";
}

// ----- aggregation -----------------------------------------------------------

interface BucketAcc {
  count: number;
  mix: SeverityMix;
  /** Σ linear severity levels (for the mean level). */
  levelSum: number;
  /** Σ geometric severity weights (for the quality index). */
  weightSum: number;
  /** Medium-or-worse alerts. */
  severe: number;
}

function newBucketAcc(): BucketAcc {
  return {
    count: 0,
    mix: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
    levelSum: 0,
    weightSum: 0,
    severe: 0,
  };
}

function bump(acc: BucketAcc, severity: string | undefined): void {
  const lvl = sevLevel(severity);
  const sev = (lvl >= 0 ? severity : "info") as Severity;
  acc.count++;
  acc.mix[sev]++;
  acc.levelSum += lvl >= 0 ? lvl : 0;
  acc.weightSum += SEVERITY_WEIGHT[sev];
  if (sevLevel(sev) >= sevLevel("medium")) acc.severe++;
}

function finishBucket(acc: BucketAcc, index: number, startMs: number, endMs: number): DriftBucket {
  return {
    index,
    startMs,
    endMs,
    count: acc.count,
    mix: acc.mix,
    meanLevel: acc.count > 0 ? round4(acc.levelSum / acc.count) : 0,
    qualityIndex: acc.count > 0 ? round4(acc.weightSum / acc.count) : 0,
    severeShare: acc.count > 0 ? round4(acc.severe / acc.count) : 0,
  };
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(m: DriftReport): string[] {
  const out: string[] = [];
  if (m.activeBuckets === 0) return out;

  // Headline: the direction and the magnitude of the drift.
  if (m.activeBuckets <= 1) {
    out.push(
      `⚪ Only one time slice carried alerts in the last ${m.hours}h — there is no spread of time to measure ` +
        `drift over. Mean severity was **${m.overallMeanLevel.toFixed(2)}** ` +
        `(${levelName(m.overallMeanLevel)}).`,
    );
    return out;
  }

  const dirWord = m.direction === "stable" ? "held roughly steady" : `is **${m.direction}**`;
  out.push(
    `${directionLabel(m.direction).split(" ")[0]} Over the last ${m.hours}h the **average alert severity** ` +
      `${dirWord}: the time-first half averaged **${m.firstHalfMeanLevel.toFixed(2)}** ` +
      `(${levelName(m.firstHalfMeanLevel)}) and the second half **${m.secondHalfMeanLevel.toFixed(2)}** ` +
      `(${levelName(m.secondHalfMeanLevel)}) — a **${signed(m.halfDelta)}**-level shift ` +
      `(slope ${signed(m.slope, 3)}/slice, R² ${m.r2.toFixed(2)}).`,
  );

  // The genuinely novel contrast: severity mix versus volume.
  const volWord =
    Math.abs(m.volumeHalfDelta) < 0.15
      ? "flat"
      : m.volumeHalfDelta > 0
        ? `up ${pct(m.volumeHalfDelta)}`
        : `down ${pct(Math.abs(m.volumeHalfDelta))}`;
  if ((m.direction === "escalating" || m.direction === "rising") && Math.abs(m.volumeHalfDelta) < 0.15) {
    out.push(
      `🎯 **Volume is ${volWord} but the mix is ${m.direction}** — the same amount of traffic is turning ` +
        `*nastier*. This is the recon→exploitation drift a raw alert count hides; treat it as a leading ` +
        `indicator and pull the recent high/critical detections forward in triage.`,
    );
  } else if (m.direction === "escalating" || m.direction === "rising") {
    out.push(
      `📈 Severity is ${m.direction} **and** volume is ${volWord} over the window — both the amount and the ` +
        `seriousness of traffic are climbing. Cross-read risk.ts (magnitude) and escalation.ts (which sources).`,
    );
  } else if ((m.direction === "easing" || m.direction === "receding") && m.volumeHalfDelta > 0.15) {
    out.push(
      `🌫 Volume is ${volWord} but severity is **${m.direction}** — the surge is mostly low-severity scan ` +
        `noise, not an escalation. A volume-only alarm here would be a false sense of emergency.`,
    );
  }

  // The sharpest step change — a concrete "look here" timestamp.
  if (m.sharpestStep && Math.abs(m.sharpestStep.delta) >= 0.5) {
    const s = m.sharpestStep;
    out.push(
      `⚡ Sharpest shift: mean severity ${s.delta >= 0 ? "jumped" : "dropped"} **${signed(s.delta)}** levels ` +
        `into the slice starting **${fmtTime(s.atMs)}** — the inflection point worth correlating against the ` +
        `signature timeline.`,
    );
  }

  // A severe-share callout when the back of the window is heavy with serious alerts.
  const lastActive = [...m.timeline].reverse().find((b) => b.count > 0);
  if (lastActive && lastActive.severeShare >= 0.5 && (m.direction === "escalating" || m.direction === "rising")) {
    out.push(
      `🚨 The most recent active slice ran **${pct(lastActive.severeShare)}** medium-or-worse ` +
        `(${lastActive.count} alert(s)) — the escalation is landing *now*, not earlier in the window.`,
    );
  }

  return out;
}

/** Coarse name for a position on the 0..4 ladder (for prose). */
function levelName(level: number): string {
  const idx = Math.max(0, Math.min(SEVERITY_ORDER.length - 1, Math.round(level)));
  return SEVERITY_ORDER[idx]!;
}

// ----- markdown --------------------------------------------------------------

function mixCell(mix: SeverityMix): string {
  const parts: string[] = [];
  if (mix.critical) parts.push(`C${mix.critical}`);
  if (mix.high) parts.push(`H${mix.high}`);
  if (mix.medium) parts.push(`M${mix.medium}`);
  if (mix.low) parts.push(`L${mix.low}`);
  if (mix.info) parts.push(`I${mix.info}`);
  return parts.length ? parts.join(" ") : "—";
}

function timelineTable(m: DriftReport): string {
  return mdTable(
    ["#", "Slice start", "Alerts", "Mean lvl", "Mix (C/H/M/L/I)", "Severe%", "Quality"],
    m.timeline.map((b) => [
      String(b.index + 1),
      cell(fmtShort(b.startMs)),
      String(b.count),
      b.count > 0 ? `${b.meanLevel.toFixed(2)} (${levelName(b.meanLevel)})` : "—",
      cell(mixCell(b.mix)),
      b.count > 0 ? pct(b.severeShare) : "—",
      b.count > 0 ? b.qualityIndex.toFixed(1) : "—",
    ]),
  );
}

function renderMarkdown(m: DriftReport): string {
  const lines: string[] = [];
  lines.push(`# 📐 SecTool Severity-Mix Drift (Threat-Quality Trend) Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** the window is cut into **${m.buckets}** equal time slices (~${(m.bucketMs / MS_PER_HOUR).toFixed(1)}h ` +
      `each); per slice the *mean severity level* (info 0 … critical 4) is measured, then a front-half/back-half ` +
      `delta and a least-squares slope describe how the **average alert severity moves over time — independent of ` +
      `volume**. Offline, deterministic · **Window alerts:** ${m.totalWindowAlerts} (across ${m.activeBuckets} ` +
      `active slice(s))`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (m.totalWindowAlerts === 0) {
    lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  // At-a-glance drift verdict.
  lines.push(`## Drift at a glance`);
  lines.push("");
  lines.push(
    mdTable(
      ["Direction", "First half", "Second half", "Δ levels", "Slope/slice", "R²", "Volume Δ"],
      [
        [
          cell(directionLabel(m.direction)),
          `${m.firstHalfMeanLevel.toFixed(2)} (${levelName(m.firstHalfMeanLevel)})`,
          `${m.secondHalfMeanLevel.toFixed(2)} (${levelName(m.secondHalfMeanLevel)})`,
          signed(m.halfDelta),
          signed(m.slope, 3),
          m.r2.toFixed(2),
          m.activeBuckets > 1 ? signed(m.volumeHalfDelta * 100, 0) + "%" : "—",
        ],
      ],
    ),
  );
  lines.push("");
  lines.push(
    `**Severity sparkline (mean level / slice):** \`${sparkline(m.timeline.map((b) => b.meanLevel))}\` · ` +
      `**Volume sparkline:** \`${sparkline(m.timeline.map((b) => b.count))}\``,
  );
  lines.push("");
  lines.push(
    `**Legend:** mean level — info 0 · low 1 · medium 2 · high 3 · critical 4. _Direction_ from the ` +
      `front-half→back-half level delta: **🔴 escalating** (≥ +${ESCALATE_DELTA}) · **🟠 rising** ` +
      `(≥ +${RISE_DELTA}) · **⚪ stable** (±${RISE_DELTA}) · **🟢 easing** (≤ −${RISE_DELTA}) · ` +
      `**🟢 receding** (≤ −${ESCALATE_DELTA}). _Volume Δ_ is the back-half vs front-half count change.`,
  );
  lines.push("");

  // The per-slice timeline.
  lines.push(`## Per-slice timeline`);
  lines.push("");
  lines.push(timelineTable(m));
  lines.push("");
  lines.push(
    `_Mix legend: **C**ritical / **H**igh / **M**edium / **L**ow / **I**nfo counts. Quality = geometric ` +
      `severity weight per alert (info 1 … critical 81). Empty slices (—) are missing data, not zero severity, ` +
      `and are excluded from the trend fit._`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. This report measures the **drift of detected severity over time**, not ` +
      `magnitude (pair with risk.ts) or which actor is escalating (escalation.ts). A rising average over very ` +
      `few alerts is statistically thin — read the slope alongside the per-slice counts and the fit R². ` +
      `Severity is the gateway's signature label, not ground-truth impact, and a long look-back can hit the ` +
      `alert store's history cap and clip the oldest slices. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the severity-mix drift / threat-quality-trend report from the stored
 * alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link DriftOptions}: `buckets` (slice count) and a `nowMs` pin
 *              for deterministic tests.
 */
export function buildDrift(hours: number, opts: DriftOptions = {}): DriftReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const buckets = Math.max(MIN_BUCKETS, Math.min(MAX_BUCKETS, Math.floor(opts.buckets ?? DEFAULT_BUCKETS)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;
  const bucketMs = (safeHours * MS_PER_HOUR) / buckets;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const accs: BucketAcc[] = Array.from({ length: buckets }, () => newBucketAcc());
  for (const a of windowed) {
    // Clamp to the last bucket so an alert exactly at windowEndMs is included.
    const idx = Math.min(buckets - 1, Math.max(0, Math.floor((a.time - windowStartMs) / bucketMs)));
    bump(accs[idx]!, a.severity);
  }

  const timeline: DriftBucket[] = accs.map((acc, i) =>
    finishBucket(acc, i, windowStartMs + i * bucketMs, windowStartMs + (i + 1) * bucketMs),
  );

  const activeBuckets = timeline.filter((b) => b.count > 0).length;

  // Overall mean level (volume-weighted across all alerts).
  let totalLevel = 0;
  let totalCount = 0;
  for (const b of timeline) {
    totalLevel += b.meanLevel * b.count;
    totalCount += b.count;
  }
  const overallMeanLevel = totalCount > 0 ? round4(totalLevel / totalCount) : 0;

  // Front-half vs back-half split *by time* (the bucket midpoint of the window).
  const midIdx = buckets / 2;
  let firstLevel = 0;
  let firstCount = 0;
  let secondLevel = 0;
  let secondCount = 0;
  for (const b of timeline) {
    if (b.index < midIdx) {
      firstLevel += b.meanLevel * b.count;
      firstCount += b.count;
    } else {
      secondLevel += b.meanLevel * b.count;
      secondCount += b.count;
    }
  }
  const firstHalfMeanLevel = firstCount > 0 ? round4(firstLevel / firstCount) : 0;
  const secondHalfMeanLevel = secondCount > 0 ? round4(secondLevel / secondCount) : 0;
  // Only a meaningful delta when both halves carried alerts.
  const halfDelta =
    firstCount > 0 && secondCount > 0 ? round4(secondHalfMeanLevel - firstHalfMeanLevel) : 0;

  // Volume drift as a 0-centred share: (back − front) / max(front, back).
  const volBase = Math.max(firstCount, secondCount);
  const volumeHalfDelta = volBase > 0 ? round4((secondCount - firstCount) / volBase) : 0;

  // Least-squares slope of mean level vs *real* bucket index, over active slices.
  const active = timeline.filter((b) => b.count > 0);
  const fit = linearFitXY(
    active.map((b) => b.index),
    active.map((b) => b.meanLevel),
  );

  // Sharpest adjacent-active-slice step change.
  let sharpestStep: DriftStep | undefined;
  for (let i = 1; i < active.length; i++) {
    const prev = active[i - 1]!;
    const cur = active[i]!;
    const delta = round4(cur.meanLevel - prev.meanLevel);
    if (!sharpestStep || Math.abs(delta) > Math.abs(sharpestStep.delta)) {
      sharpestStep = { fromIndex: prev.index, toIndex: cur.index, delta, atMs: cur.startMs };
    }
  }

  const direction = classifyDirection(halfDelta, activeBuckets);

  const model: DriftReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    buckets,
    bucketMs,
    totalWindowAlerts: windowed.length,
    activeBuckets,
    overallMeanLevel,
    firstHalfMeanLevel,
    secondHalfMeanLevel,
    halfDelta,
    slope: round4(fit.slope),
    r2: round4(fit.r2),
    direction,
    volumeHalfDelta,
    sharpestStep,
    timeline,
    highlights: [],
    markdown: "",
  };
  model.highlights = writeHighlights(model);
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded drift report. */
export function driftFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-drift-${stamp}.md`;
}
