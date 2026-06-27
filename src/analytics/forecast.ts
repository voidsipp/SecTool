/**
 * Threat-forecast / next-window projection report — "**how many alerts should I
 * expect over the coming hours, when is the next busy stretch, and how much of it
 * will be serious?**"
 *
 * Every temporal report in this project looks *backwards*. rhythm.ts folds history
 * into an hour-of-day × day-of-week heat-map (when you *have been* busy);
 * surge.ts finds where the volume *already* spiked; momentum.ts fits a per-source
 * rate slope (who *has been* ramping up); burstiness.ts measures the texture of a
 * timeline that already happened; recurrence.ts is the one forward-looking report
 * but it forecasts a *single per-source return event* ("IP X is statistically due
 * back"), not the aggregate load on the sensor. None of them answer the question a
 * shift lead actually asks before going off-rota: *what does the next 24 hours look
 * like — roughly how many alerts, what's the peak window, and how many of them will
 * be high/critical?* That is a **forward projection of network-wide load**, and it
 * is the gap this report fills.
 *
 * The method is a classic, defensible time-series decomposition — deliberately
 * simple, fully offline and explainable rather than a black box:
 *
 *   - **Baseline rate.** Over the look-back window, `overallRate` = alerts ÷ hours
 *     of history actually covered (alerts/hour).
 *   - **Diurnal seasonality.** A multiplicative **hour-of-day factor** (24 buckets)
 *     and **day-of-week factor** (7 buckets), each normalized to a mean of 1, so a
 *     factor of 1.8 means "this hour/day historically runs 80% busier than average".
 *     Share-based, so it doesn't matter how many whole days the window spans.
 *   - **Recent-trend adjustment.** A single multiplier comparing the *most recent*
 *     window's actual volume against what the seasonal baseline alone predicted for
 *     that same window — captures "the network is running hotter/cooler than its own
 *     rhythm right now" (a live campaign, or a quiet lull), clamped to a sane range.
 *
 * For each upcoming hour the expected count is
 * `λ = overallRate × hourFactor[h] × dowFactor[d] × recentMultiplier`, carried with
 * an **approximate 90% prediction interval** from the Poisson normal approximation
 * (`λ ± 1.645·√λ`, floored at 0). Those hourly λ's roll up into a **per-day** table,
 * a **peak hour**, the **next busy stretch** (the first contiguous run of hours
 * above 1.5× the horizon mean) and an **expected severity split** (applying the
 * historical severity mix to the projected total) so the high/critical load — the
 * part that drives staffing — is called out explicitly.
 *
 * Honest caveats baked into the output:
 *
 *   - **It assumes the recent past persists.** The model extrapolates the existing
 *     rhythm and trend; it cannot see a *new* campaign that hasn't started, a
 *     holiday, or a sudden takedown. Treat it as a planning baseline, not a promise.
 *   - **Detections, not ground truth.** These are IPS *alerts*: a forecast of how
 *     noisy the sensor will be, not of how much real attacking will happen. Tuning a
 *     loud rule changes the forecast without changing the threat.
 *   - **The interval is approximate.** The 90% band is the Poisson normal
 *     approximation, which is loose for very small λ; it is a guide to spread, not an
 *     exact quantile. Forecast skill also decays the further out the horizon runs.
 *   - **Needs a few days of history.** With less than ~2–3 days the seasonal factors
 *     are estimated from very few samples and the projection is little better than a
 *     flat average — the report says so when the window is thin.
 *   - **Window- & store-bounded.** A long look-back can hit the alert store's history
 *     cap and clip the baseline, biasing the rate estimate.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network. Output is
 * both a structured model and a ready-to-paste Markdown document, mirroring
 * dwell.ts, concentration.ts, heat.ts and the other offline reports.
 */
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** One projected future hour. */
export interface ForecastHour {
  /** 1-based hours from now (1 = the hour beginning at the window end). */
  offsetHours: number;
  /** ms epoch of the start of this projected hour. */
  startMs: number;
  /** Day-of-week of the hour start (0 = Sunday … 6 = Saturday, UTC). */
  dow: number;
  /** Hour-of-day of the hour start (0–23, UTC). */
  hour: number;
  /** Expected alert count for the hour (λ, 2dp). */
  expected: number;
  /** Lower bound of the ~90% prediction interval (1dp, floored at 0). */
  lo: number;
  /** Upper bound of the ~90% prediction interval (1dp). */
  hi: number;
}

/** A per-calendar-day rollup of the hourly forecast. */
export interface ForecastDay {
  /** "Mon 2026-06-28" — UTC date label of the day. */
  label: string;
  /** ms epoch of the first projected hour falling in this day. */
  startMs: number;
  /** Number of projected hours that fell in this day (≤ 24). */
  hours: number;
  /** Σ expected over the day's hours (2dp). */
  expected: number;
  /** Lower bound of the day's ~90% interval (1dp, floored at 0). */
  lo: number;
  /** Upper bound of the day's ~90% interval (1dp). */
  hi: number;
}

/** One hour-of-day bucket of the historical seasonality profile. */
export interface HourProfile {
  /** Hour of day, 0–23 (UTC). */
  hour: number;
  /** Alerts observed in this hour-of-day across the window. */
  count: number;
  /** Share of all windowed alerts, 0..1 (4dp). */
  share: number;
  /** Multiplicative seasonal factor (mean across hours ≈ 1, 3dp). */
  factor: number;
}

/** Expected count for one severity tier over the horizon. */
export interface SeverityForecast {
  severity: Severity;
  /** Historical share of this tier in the window, 0..1 (4dp). */
  share: number;
  /** Expected count over the whole horizon (2dp). */
  expected: number;
}

/** The first contiguous run of upcoming hours above the busy threshold. */
export interface SurgeWindow {
  startMs: number;
  endMs: number;
  /** Number of hours in the run. */
  hours: number;
  /** Σ expected over the run (2dp). */
  expected: number;
}

export interface ForecastReport {
  /** Look-back window (hours) used to build the baseline. */
  hours: number;
  /** Projection horizon (hours) into the future. */
  horizonHours: number;
  /** Recent window (hours) used for the trend multiplier. */
  recentHours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the look-back window. */
  totalWindowAlerts: number;
  /** Hours of history actually covered (earliest alert → window end), ≥1. */
  coveredHours: number;
  /** Baseline rate, alerts/hour, over the covered history (3dp). */
  overallRate: number;
  /** Recent-trend multiplier applied to every projected hour (3dp). */
  recentMultiplier: number;
  /** Actual alert count in the trailing `horizonHours` (for comparison). */
  trailingActual: number;
  /** Σ expected over the whole horizon (2dp). */
  totalExpected: number;
  /** Lower / upper ~90% interval for the horizon total (1dp). */
  totalLo: number;
  totalHi: number;
  /** Hour-of-day seasonality profile (24 buckets, hour 0→23). */
  hourProfile: HourProfile[];
  /** Per-hour projection across the horizon. */
  hourly: ForecastHour[];
  /** Per-day rollup of the hourly projection. */
  daily: ForecastDay[];
  /** The single busiest projected hour, if any alerts are expected. */
  peakHour?: ForecastHour;
  /** First upcoming busy stretch (≥1.5× horizon mean), if any. */
  nextSurge?: SurgeWindow;
  /** Expected count per severity tier over the horizon (critical→info). */
  bySeverity: SeverityForecast[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface ForecastOptions {
  /** Projection horizon in hours (clamped to [1, 168]). */
  horizonHours?: number;
  /** Recent window (hours) for the trend multiplier (clamped to [1, look-back]). */
  recentHours?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_HORIZON = 24;
const DEFAULT_RECENT = 24;
const MS_PER_HOUR = 3_600_000;

/** z for an ~90% two-sided interval (normal approximation). */
const Z90 = 1.645;
/** Trend multiplier is clamped here so a thin recent window can't run wild. */
const MULT_MIN = 0.2;
const MULT_MAX = 5;
/** A projected hour is "busy" when it exceeds this × the horizon's mean λ. */
const SURGE_FACTOR = 1.5;
/** Below this many hours of covered history the seasonal factors are unreliable. */
const THIN_HISTORY_HOURS = 48;

const DOW_NAMES = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"] as const;

// ----- helpers (mirror dwell.ts / concentration.ts) --------------------------

function round1(n: number): number {
  return Math.round(n * 10) / 10;
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

function round3(n: number): number {
  return Math.round(n * 1000) / 1000;
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

function pct(frac: number, dp = 0): string {
  return `${(frac * 100).toFixed(dp)}%`;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** "Mon 2026-06-28" — UTC date label. */
function fmtDate(ms: number): string {
  const d = new Date(ms);
  const day = DOW_NAMES[d.getUTCDay()]!;
  return `${day} ${d.toISOString().slice(0, 10)}`;
}

/** "14:00" — UTC hour-of-day label for the start of a projected hour. */
function fmtHourLabel(ms: number): string {
  return `${new Date(ms).toISOString().slice(11, 13)}:00`;
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

/** An 8-step unicode bar scaled to `max` (for the seasonality profile). */
function bar(value: number, max: number, width = 16): string {
  if (max <= 0 || value <= 0) return "";
  const filled = Math.max(1, Math.round((value / max) * width));
  return "█".repeat(Math.min(filled, width));
}

// ----- the forecast model ----------------------------------------------------

/**
 * Build the threat-forecast / next-window projection from the stored alert
 * history.
 *
 * @param hours Look-back window in hours used to estimate the baseline rhythm
 *              (clamped to [1, 90 days]).
 * @param opts  {@link ForecastOptions}: `horizonHours`, `recentHours`, and a
 *              `nowMs` pin for deterministic tests.
 */
export function buildForecast(hours: number, opts: ForecastOptions = {}): ForecastReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const horizonHours = Math.max(1, Math.min(168, Math.floor(opts.horizonHours ?? DEFAULT_HORIZON)));
  const recentHours = Math.max(1, Math.min(safeHours, Math.floor(opts.recentHours ?? DEFAULT_RECENT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;
  const recentStartMs = windowEndMs - recentHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const total = windowed.length;

  // --- seasonality histograms (hour-of-day, day-of-week) + severity mix ------
  const hourCounts = new Array(24).fill(0) as number[];
  const dowCounts = new Array(7).fill(0) as number[];
  const sevCounts = new Map<string, number>();
  let earliestMs = windowEndMs;
  let recentActual = 0;

  for (const a of windowed) {
    const d = new Date(a.time);
    const hh = d.getUTCHours();
    const dd = d.getUTCDay();
    hourCounts[hh] = (hourCounts[hh] ?? 0) + 1;
    dowCounts[dd] = (dowCounts[dd] ?? 0) + 1;
    sevCounts.set(a.severity, (sevCounts.get(a.severity) ?? 0) + 1);
    if (a.time < earliestMs) earliestMs = a.time;
    if (a.time >= recentStartMs) recentActual++;
  }

  // Hours of history actually covered — using the earliest alert, not the nominal
  // window start, so a short history isn't divided by an empty look-back.
  const coveredHours = total > 0 ? Math.max(1, (windowEndMs - earliestMs) / MS_PER_HOUR) : safeHours;
  const overallRate = total > 0 ? total / coveredHours : 0;

  // Normalized multiplicative factors (mean ≈ 1). Share-based so the number of
  // whole days in the window doesn't bias them; flat (1.0) when there is no data.
  const hourFactor = hourCounts.map((c) => (total > 0 ? (c / total) * 24 : 1));
  const dowFactor = dowCounts.map((c) => (total > 0 ? (c / total) * 7 : 1));

  // --- recent-trend multiplier ------------------------------------------------
  // What the seasonal baseline alone predicts for the recent window, vs what
  // actually happened there. >1 ⇒ running hotter than its own rhythm; <1 ⇒ cooler.
  let recentBaseline = 0;
  for (let h = 0; h < recentHours; h++) {
    const ms = windowEndMs - (h + 1) * MS_PER_HOUR;
    const d = new Date(ms);
    recentBaseline += overallRate * hourFactor[d.getUTCHours()]! * dowFactor[d.getUTCDay()]!;
  }
  let recentMultiplier = 1;
  if (recentBaseline > 0 && total > 0) {
    recentMultiplier = Math.max(MULT_MIN, Math.min(MULT_MAX, recentActual / recentBaseline));
  }

  // --- per-hour projection ----------------------------------------------------
  const hourly: ForecastHour[] = [];
  for (let t = 0; t < horizonHours; t++) {
    const startMs = windowEndMs + t * MS_PER_HOUR;
    const d = new Date(startMs);
    const hh = d.getUTCHours();
    const dd = d.getUTCDay();
    const lambda = Math.max(0, overallRate * hourFactor[hh]! * dowFactor[dd]! * recentMultiplier);
    const spread = Z90 * Math.sqrt(lambda);
    hourly.push({
      offsetHours: t + 1,
      startMs,
      dow: dd,
      hour: hh,
      expected: round2(lambda),
      lo: round1(Math.max(0, lambda - spread)),
      hi: round1(lambda + spread),
    });
  }

  // --- horizon total + interval ----------------------------------------------
  const totalExpectedRaw = hourly.reduce((s, h) => s + h.expected, 0);
  const totalSpread = Z90 * Math.sqrt(totalExpectedRaw);
  const totalExpected = round2(totalExpectedRaw);
  const totalLo = round1(Math.max(0, totalExpectedRaw - totalSpread));
  const totalHi = round1(totalExpectedRaw + totalSpread);

  // Actual count in the trailing horizon-length window, for a like-for-like compare.
  const trailingStartMs = windowEndMs - horizonHours * MS_PER_HOUR;
  const trailingActual = windowed.filter((a) => a.time >= trailingStartMs).length;

  // --- per-day rollup ---------------------------------------------------------
  const dayMap = new Map<string, { startMs: number; hours: number; expected: number }>();
  for (const h of hourly) {
    const key = new Date(h.startMs).toISOString().slice(0, 10);
    const acc = dayMap.get(key);
    if (acc) {
      acc.hours++;
      acc.expected += h.expected;
    } else {
      dayMap.set(key, { startMs: h.startMs, hours: 1, expected: h.expected });
    }
  }
  const daily: ForecastDay[] = [...dayMap.values()]
    .sort((a, b) => a.startMs - b.startMs)
    .map((d) => {
      const spread = Z90 * Math.sqrt(d.expected);
      return {
        label: fmtDate(d.startMs),
        startMs: d.startMs,
        hours: d.hours,
        expected: round2(d.expected),
        lo: round1(Math.max(0, d.expected - spread)),
        hi: round1(d.expected + spread),
      } satisfies ForecastDay;
    });

  // --- hour-of-day profile ----------------------------------------------------
  const hourProfile: HourProfile[] = hourCounts.map((c, h) => ({
    hour: h,
    count: c,
    share: total > 0 ? round4(c / total) : 0,
    factor: round3(hourFactor[h]!),
  }));

  // --- peak hour + next busy stretch -----------------------------------------
  let peakHour: ForecastHour | undefined;
  for (const h of hourly) {
    if (h.expected > 0 && (!peakHour || h.expected > peakHour.expected)) peakHour = h;
  }

  const meanLambda = horizonHours > 0 ? totalExpectedRaw / horizonHours : 0;
  const surgeThreshold = meanLambda * SURGE_FACTOR;
  let nextSurge: SurgeWindow | undefined;
  if (surgeThreshold > 0) {
    let runStart = -1;
    let runExpected = 0;
    for (let i = 0; i < hourly.length; i++) {
      const hot = hourly[i]!.expected >= surgeThreshold;
      if (hot) {
        if (runStart < 0) {
          runStart = i;
          runExpected = 0;
        }
        runExpected += hourly[i]!.expected;
      }
      const runEnds = !hot || i === hourly.length - 1;
      if (runStart >= 0 && runEnds) {
        const lastIdx = hot ? i : i - 1;
        nextSurge = {
          startMs: hourly[runStart]!.startMs,
          endMs: hourly[lastIdx]!.startMs + MS_PER_HOUR,
          hours: lastIdx - runStart + 1,
          expected: round2(runExpected),
        };
        break; // first stretch only
      }
    }
  }

  // --- expected severity split ------------------------------------------------
  const bySeverity: SeverityForecast[] = [...SEVERITY_ORDER]
    .slice()
    .reverse()
    .map((sev) => {
      const c = sevCounts.get(sev) ?? 0;
      const share = total > 0 ? c / total : 0;
      return {
        severity: sev,
        share: round4(share),
        expected: round2(totalExpectedRaw * share),
      } satisfies SeverityForecast;
    });

  const model: ForecastReport = {
    hours: safeHours,
    horizonHours,
    recentHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: total,
    coveredHours: round2(coveredHours),
    overallRate: round3(overallRate),
    recentMultiplier: round3(recentMultiplier),
    trailingActual,
    totalExpected,
    totalLo,
    totalHi,
    hourProfile,
    hourly,
    daily,
    peakHour,
    nextSurge,
    bySeverity,
    highlights: [],
    markdown: "",
  };
  model.highlights = writeHighlights(model);
  model.markdown = renderMarkdown(model);
  return model;
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(m: ForecastReport): string[] {
  const out: string[] = [];
  if (m.totalWindowAlerts === 0) return out;

  // Headline: projected total ± band, vs the trailing like-for-like window.
  const delta = m.totalExpected - m.trailingActual;
  const dir =
    m.trailingActual > 0 && Math.abs(delta) / Math.max(1, m.trailingActual) >= 0.15
      ? delta > 0
        ? "**up**"
        : "**down**"
      : "roughly flat";
  out.push(
    `🔮 Next **${m.horizonHours}h** project **~${m.totalExpected.toFixed(0)} alert(s)** ` +
      `(90% range ${m.totalLo.toFixed(0)}–${m.totalHi.toFixed(0)}) — ${dir} versus the **${m.trailingActual}** ` +
      `seen in the trailing ${m.horizonHours}h. Baseline **${m.overallRate.toFixed(2)}/h** over ` +
      `${Math.round(m.coveredHours)}h of history.`,
  );

  // Recent-trend read.
  if (m.recentMultiplier >= 1.25) {
    out.push(
      `📈 The network is running **${m.recentMultiplier.toFixed(2)}× hotter** than its own rhythm predicts right ` +
        `now (last ${m.recentHours}h) — a live campaign or surge is in progress and the forecast is scaled up to ` +
        `match. Re-run after it cools for a cleaner baseline.`,
    );
  } else if (m.recentMultiplier <= 0.75) {
    out.push(
      `📉 The network is running **${m.recentMultiplier.toFixed(2)}× cooler** than its rhythm predicts (last ` +
        `${m.recentHours}h) — a lull; the projection is scaled down accordingly.`,
    );
  }

  // Peak hour + next busy stretch — the staffing call.
  if (m.peakHour && m.peakHour.expected > 0) {
    out.push(
      `🏔 Busiest projected hour is **${fmtHourLabel(m.peakHour.startMs)} UTC ` +
        `(${DOW_NAMES[m.peakHour.dow]}, +${m.peakHour.offsetHours}h)** at **~${m.peakHour.expected.toFixed(1)} ` +
        `alert(s)** (up to ${m.peakHour.hi.toFixed(0)}).`,
    );
  }
  if (m.nextSurge && m.nextSurge.hours >= 2) {
    out.push(
      `⏰ Next busy stretch: **${fmtTime(m.nextSurge.startMs)} → ${fmtTime(m.nextSurge.endMs)}** ` +
        `(${m.nextSurge.hours}h, ~${m.nextSurge.expected.toFixed(0)} alert(s)) — the window to keep eyes on the console.`,
    );
  }

  // Expected serious load — the part that drives escalation staffing.
  const serious = m.bySeverity
    .filter((s) => s.severity === "high" || s.severity === "critical")
    .reduce((s, x) => s + x.expected, 0);
  if (serious >= 1) {
    const crit = m.bySeverity.find((s) => s.severity === "critical");
    out.push(
      `🚨 Expect **~${serious.toFixed(0)} high/critical alert(s)** over the horizon` +
        (crit && crit.expected >= 0.5 ? ` (≈${crit.expected.toFixed(1)} critical)` : "") +
        ` — size the on-call escalation budget to that, not to the raw total.`,
    );
  }

  // Hottest hour-of-day historically — the standing pattern behind the projection.
  const hottest = [...m.hourProfile].sort((a, b) => b.factor - a.factor)[0];
  if (hottest && hottest.factor > 1.3) {
    out.push(
      `🕓 Historically the **${String(hottest.hour).padStart(2, "0")}:00 UTC** hour is the heaviest ` +
        `(**${hottest.factor.toFixed(1)}×** the daily average, ${pct(hottest.share, 1)} of all alerts) — the ` +
        `recurring daily peak the projection leans on.`,
    );
  }

  // Thin-history honesty.
  if (m.coveredHours < THIN_HISTORY_HOURS) {
    out.push(
      `⚠️ Only **${Math.round(m.coveredHours)}h** of history available — under ~2 days the hourly/day-of-week ` +
        `seasonality is estimated from very few samples, so this is closer to a flat average than a true ` +
        `rhythm-aware forecast. Treat the shape with caution.`,
    );
  }

  return out;
}

// ----- markdown --------------------------------------------------------------

function hourlyTable(rows: ForecastHour[]): string {
  return mdTable(
    ["+h", "When (UTC)", "Day", "Expected", "90% range"],
    rows.map((h) => [
      String(h.offsetHours),
      `${fmtDate(h.startMs).slice(4)} ${fmtHourLabel(h.startMs)}`,
      cell(DOW_NAMES[h.dow]),
      h.expected.toFixed(1),
      `${h.lo.toFixed(0)}–${h.hi.toFixed(0)}`,
    ]),
  );
}

function dailyTable(rows: ForecastDay[]): string {
  return mdTable(
    ["Day", "Hours", "Expected", "90% range"],
    rows.map((d) => [
      cell(d.label),
      String(d.hours),
      d.expected.toFixed(1),
      `${d.lo.toFixed(0)}–${d.hi.toFixed(0)}`,
    ]),
  );
}

function profileTable(rows: HourProfile[]): string {
  const maxFactor = rows.reduce((mx, r) => Math.max(mx, r.factor), 0);
  return mdTable(
    ["Hour (UTC)", "Alerts", "Share", "Factor", "Shape"],
    rows.map((r) => [
      `${String(r.hour).padStart(2, "0")}:00`,
      String(r.count),
      pct(r.share, 1),
      `${r.factor.toFixed(2)}×`,
      bar(r.factor, maxFactor),
    ]),
  );
}

function severityTable(rows: SeverityForecast[]): string {
  return mdTable(
    ["Severity", "Hist. share", "Expected"],
    rows.map((s) => [cell(s.severity), pct(s.share, 1), s.expected.toFixed(1)]),
  );
}

function renderMarkdown(m: ForecastReport): string {
  const lines: string[] = [];
  lines.push(`# 🔮 SecTool Threat-Forecast / Next-Window Projection`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Baseline window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`,
  );
  lines.push(
    `**Horizon:** next ${m.horizonHours} hour(s) — ${fmtTime(m.windowEndMs)} → ` +
      `${fmtTime(m.windowEndMs + m.horizonHours * MS_PER_HOUR)}`,
  );
  lines.push(
    `**Method:** baseline rate × hour-of-day factor × day-of-week factor × recent-trend multiplier; ` +
      `~90% interval via the Poisson normal approximation (λ ± 1.645·√λ). Offline, deterministic · ` +
      `**Baseline alerts:** ${m.totalWindowAlerts} over ${Math.round(m.coveredHours)}h ` +
      `(${m.overallRate.toFixed(2)}/h) · **Trend ×${m.recentMultiplier.toFixed(2)}**`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (m.totalWindowAlerts === 0) {
    lines.push(
      `No alerts with a usable timestamp in the last ${m.hours} hour(s) — there is no history to project from.`,
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  // Headline projection box.
  lines.push(`## Projected load — next ${m.horizonHours}h`);
  lines.push("");
  lines.push(
    `**~${m.totalExpected.toFixed(0)} alert(s)** expected (90% range **${m.totalLo.toFixed(0)}–` +
      `${m.totalHi.toFixed(0)}**). The trailing ${m.horizonHours}h actually saw **${m.trailingActual}**.`,
  );
  lines.push("");
  lines.push(severityTable(m.bySeverity));
  lines.push("");
  lines.push(
    `_Severity split applies the window's historical mix to the projected total — a guide to how much of the ` +
      `load will be serious, the figure to size escalation cover against._`,
  );
  lines.push("");

  // Per-day rollup (always shown; the staffing-friendly view).
  lines.push(`## By day`);
  lines.push("");
  lines.push(dailyTable(m.daily));
  lines.push("");

  // Hourly detail — first 24h (or the whole horizon if shorter) to stay readable.
  const HOURLY_SHOWN = 24;
  const shown = m.hourly.slice(0, HOURLY_SHOWN);
  lines.push(`## Hour by hour${m.hourly.length > HOURLY_SHOWN ? ` (first ${HOURLY_SHOWN}h)` : ""}`);
  lines.push("");
  lines.push(hourlyTable(shown));
  if (m.hourly.length > HOURLY_SHOWN) {
    lines.push("");
    lines.push(`_… ${m.hourly.length - HOURLY_SHOWN} further hour(s) folded into the per-day table above._`);
  }
  lines.push("");

  // The seasonality the projection rests on.
  lines.push(`## Daily rhythm (hour-of-day baseline)`);
  lines.push("");
  lines.push(profileTable(m.hourProfile));
  lines.push("");
  lines.push(
    `**Legend:** _Factor_ is the multiplicative seasonal weight — **1.0×** = an average hour, **2.0×** = twice ` +
      `as busy as the daily mean. This is the standing pattern the forecast scales by, then nudges with the ` +
      `recent-trend multiplier (currently **×${m.recentMultiplier.toFixed(2)}**).`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. This is a **planning baseline, not a promise**: it extrapolates the existing ` +
      `rhythm and recent trend and cannot see a *new* campaign that hasn't started, a holiday or a takedown. These ` +
      `are IPS **detections** — a forecast of sensor noise, not of real attacking (tuning a loud rule changes the ` +
      `forecast without changing the threat). The 90% band is the Poisson normal approximation (loose for very ` +
      `small λ), and forecast skill decays the further out the horizon runs. With under ~2 days of history the ` +
      `seasonal factors rest on very few samples. A long look-back can hit the store's history cap and clip the ` +
      `baseline. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/** A filesystem-safe filename for a downloaded forecast report. */
export function forecastFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-forecast-${stamp}.md`;
}
