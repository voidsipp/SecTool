/**
 * Maintenance / change-window recommender — "**I need to take the network down
 * for N hours to patch / reboot / deploy. When this week is historically the
 * calmest, lowest-risk slot to do it — and which slot must I avoid?**"
 *
 * This is the one *prescriptive scheduling* question SecTool's temporal reports
 * dance around but never answer directly. They are all either descriptive or
 * forward-curve, none of them rank concrete, bookable change windows:
 *
 *   - **rhythm.ts** folds history into a 7×24 heat-map and mentions a single
 *     "quietest window" as a derived stat. It tells you *when you have been busy*;
 *     it does not take a change *duration*, slide a window of that width across
 *     the whole week, rank the calmest **contiguous** slots, weight them by
 *     severity-risk, or tell you the **next calendar date** such a slot recurs.
 *   - **forecast.ts** projects network-wide load *forward* and surfaces the "next
 *     busy stretch" — the opposite of what change management needs. It answers
 *     "how noisy will the sensor be", not "give me a recurring quiet slot of
 *     length W I can book a maintenance window in".
 *   - **offhours.ts** measures attack pressure during a *fixed* business-hours
 *     shift (a coverage-gap audit). It does not search for the best slot of an
 *     arbitrary duration anywhere in the week.
 *
 * This report is the change-manager's tool. It builds an **hour-of-week** risk
 * profile (168 cells, Mon 00:00 → Sun 23:00) from the retained history, *averaged
 * per week-occurrence* so a slot that recurred 12 times isn't penalised against
 * one that recurred 13, then slides a window of the requested **duration** across
 * the week (circularly, so Sunday-night → Monday-morning is a candidate) and
 * ranks every start position by expected **severity-weighted risk** (the
 * `--risk` ladder: info 1·low 3·medium 9·high 27·critical 81), tie-broken by raw
 * expected volume.
 *
 * It returns the top **non-overlapping** calmest windows (a greedy pass, so the
 * recommendations are genuinely distinct slots rather than five copies of the
 * same trough shifted by an hour), each carried with:
 *
 *   - the **expected alerts / serious / risk** during a future instance of the
 *     slot, and how that compares to an **average** window (`riskVsAverage`), so
 *     "12% of a normal window's risk" reads as decisively-calm at a glance;
 *   - the **worst severity** ever seen in any of its hours (a calm-on-average slot
 *     that has historically hosted a lone critical is flagged, not hidden);
 *   - the **next concrete UTC datetime** the recurring local slot begins, so the
 *     output is a change ticket you can paste a date from; and
 *   - the **sample depth** (`minOccurrences`) backing it — a recommendation built
 *     on one week of data is labelled thin.
 *
 * It also names the single **busiest** window — the one to *avoid* — for contrast.
 *
 * Times are wall-clock UTC by default (matching every other report's stamp) but a
 * `--tz <minutes>` offset reads the recommendations in local time, because a
 * maintenance window is booked on a local calendar. The chosen zone is labelled
 * on every slot so a pasted ticket is never ambiguous.
 *
 * Honest caveats baked into the output:
 *
 *   - **It assumes the past rhythm holds.** A historically-quiet slot is only a
 *     *probabilistic* bet; a fresh campaign, a holiday, or a one-off does not
 *     respect your calendar. Treat it as a planning default, not a guarantee.
 *   - **Detections, not ground truth.** Risk is scored from IPS *alert* severity
 *     — it ranks slots by how noisy/serious the sensor has been, which is a good
 *     proxy for "least likely to mask a real incident behind your change", not a
 *     measure of actual attacking. Tuning a loud rule changes the ranking.
 *   - **Needs a couple of weeks.** With under ~2 full weeks back each hour-of-week
 *     cell, the per-occurrence average rests on one or two samples and the
 *     ranking is little better than chance — the report says so when it is thin.
 *   - **Window- & store-bounded.** A long look-back can hit the alert store's
 *     history cap and clip the profile.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network. Output is
 * both a structured model and a ready-to-paste Markdown document, mirroring
 * rhythm.ts, forecast.ts, offhours.ts and the other offline reports.
 */
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** One recommended (or rejected) contiguous change window. */
export interface MaintenanceWindow {
  /** Hour-of-week start index, Mon-first (0 = Mon 00:00 … 167 = Sun 23:00). */
  startHow: number;
  /** Day label of the start (Mon…Sun). */
  startDay: string;
  /** Start hour-of-day (0–23) in the report's timezone. */
  startHour: number;
  /** Day label of the (exclusive) end hour. */
  endDay: string;
  /** End hour-of-day (0–23, exclusive) in the report's timezone. */
  endHour: number;
  /** Window duration in hours. */
  durationHours: number;
  /** Expected alerts during a future instance of this window (per-occurrence mean). */
  expectedAlerts: number;
  /** Expected severity-weighted risk during the window (the ranking key). */
  expectedRisk: number;
  /** Expected high+critical alerts during the window. */
  expectedSerious: number;
  /** Worst severity ever observed in any hour-cell of this window. */
  severityMax: Severity;
  /** This window's expected risk as a share of the average window's risk (0..1+). */
  riskVsAverage: number;
  /** Fewest week-occurrences backing any cell in the window (sample depth). */
  minOccurrences: number;
  /** Next UTC instant (ms epoch) this recurring local window next begins, from now. */
  nextOccurrenceMs: number;
}

export interface MaintenanceReport {
  hours: number;
  /** Change-window duration actually used, in hours (after clamping). */
  durationHours: number;
  tzOffsetMinutes: number;
  /** "UTC" / "UTC±HH:MM" label for the chosen zone. */
  tzLabel: string;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) folded into the hour-of-week profile. */
  totalAlerts: number;
  /** Summed severity-weighted risk across those alerts. */
  totalRisk: number;
  /** Whole weeks of history the window spans (safeHours ÷ 168), rounded to 1 dp. */
  weeksCovered: number;
  /** Mean expected risk across all 168 candidate windows — the comparison base. */
  avgWindowRisk: number;
  /** Recommended calmest, non-overlapping windows, calmest first (capped at limit). */
  recommendations: MaintenanceWindow[];
  /** The single busiest window — the one to AVOID. */
  worst?: MaintenanceWindow;
  /** True when fewer than 2 full weeks back the thinnest recommended cell. */
  thin: boolean;
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface MaintenanceOptions {
  /** Change-window length in hours; clamped to [1, 24] and ≤ the look-back. Default 2. */
  durationHours?: number;
  /** Max recommended windows shown; clamped to [1, 24]. Default 5. */
  limit?: number;
  /** Minutes to add to UTC before bucketing onto the clock (e.g. -300 = US EST). */
  tzOffsetMinutes?: number;
  /** Pins the window end / "now" for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_DURATION = 2;
const DEFAULT_LIMIT = 5;
const MS_PER_HOUR = 3_600_000;
const HOURS_PER_WEEK = 168;

/** Mon-first day labels; index 0 = Mon … 6 = Sun. */
const DAY_LABELS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"] as const;
/** getUTCDay() indices in Mon→Sun order (JS week starts on Sunday = 0). */
const DAY_ORDER = [1, 2, 3, 4, 5, 6, 0] as const;

// ----- helpers (mirror rhythm.ts / potency.ts / timeline.ts) -----------------

function asSeverity(s: string | undefined): Severity {
  return (SEVERITY_ORDER as readonly string[]).includes(s ?? "") ? (s as Severity) : "info";
}

function sevRank(s: Severity): number {
  return (SEVERITY_ORDER as readonly string[]).indexOf(s);
}

function maxSeverity(a: Severity, b: Severity): Severity {
  return sevRank(b) > sevRank(a) ? b : a;
}

/** High or critical — the "serious" band every report counts. */
function isSerious(s: Severity): boolean {
  return sevRank(s) >= sevRank("high");
}

/** Mon-first index (0..6) for a JS getUTCDay() value (0=Sun..6=Sat). */
function mondayIndex(dow: number): number {
  return (DAY_ORDER as readonly number[]).indexOf(dow);
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

/** Format a tz offset in minutes as a "UTC"/"UTC±HH:MM" label. */
function tzLabelFor(offsetMinutes: number): string {
  if (offsetMinutes === 0) return "UTC";
  const sign = offsetMinutes > 0 ? "+" : "-";
  const abs = Math.abs(offsetMinutes);
  const hh2 = String(Math.floor(abs / 60)).padStart(2, "0");
  const mm2 = String(abs % 60).padStart(2, "0");
  return `UTC${sign}${hh2}:${mm2}`;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** Render an hour-of-day index as a 2-digit "HH" string. */
function hh(hour: number): string {
  return String(hour).padStart(2, "0");
}

/** Local wall-clock stamp ("YYYY-MM-DD ddd HH:00 TZ") for a UTC instant in the chosen zone. */
function fmtLocal(ms: number, tzShiftMs: number, tzLabel: string): string {
  const d = new Date(ms + tzShiftMs);
  const day = DAY_LABELS[mondayIndex(d.getUTCDay())]!;
  return `${d.toISOString().slice(0, 10)} ${day} ${hh(d.getUTCHours())}:00 ${tzLabel}`;
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

/** Day + time range label for a window, e.g. "Sun 02:00 → Sun 04:00 UTC". */
function rangeLabel(w: MaintenanceWindow, tzLabel: string): string {
  return `${w.startDay} ${hh(w.startHour)}:00 → ${w.endDay} ${hh(w.endHour)}:00 ${tzLabel}`;
}

// ----- per-cell aggregation --------------------------------------------------

interface CellAcc {
  alerts: number;
  risk: number;
  serious: number;
  severityMax: Severity;
}

/** Circular distance (in hour-cells) between two hour-of-week starts. */
function ringDistance(a: number, b: number): number {
  const d = Math.abs(a - b);
  return Math.min(d, HOURS_PER_WEEK - d);
}

/**
 * Next UTC instant (ms) that the recurring local slot starting at `startHow`
 * (Mon-first hour-of-week, top of the hour) next begins at or after `nowMs`.
 */
function nextOccurrence(startHow: number, tzShiftMs: number, nowMs: number): number {
  const nowShifted = nowMs + tzShiftMs;
  const topOfHour = Math.floor(nowShifted / MS_PER_HOUR) * MS_PER_HOUR;
  const d = new Date(topOfHour);
  const nowHow = mondayIndex(d.getUTCDay()) * 24 + d.getUTCHours();
  const delta = (startHow - nowHow + HOURS_PER_WEEK) % HOURS_PER_WEEK;
  let candidate = topOfHour + delta * MS_PER_HOUR;
  // delta === 0 means "this very hour"; if we are already past its top, the slot
  // has started — roll to next week so the recommendation is always in the future.
  if (candidate <= nowShifted) candidate += HOURS_PER_WEEK * MS_PER_HOUR;
  return candidate - tzShiftMs;
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(
  m: Omit<MaintenanceReport, "highlights" | "markdown">,
  tzShiftMs: number,
): string[] {
  const out: string[] = [];
  if (m.totalAlerts === 0) return out;

  const best = m.recommendations[0];
  if (best) {
    out.push(
      `🟢 Best ${m.durationHours}h change window: **${rangeLabel(best, m.tzLabel)}** — expected ` +
        `**${best.expectedAlerts}** alert(s) (${best.expectedSerious} serious, risk ${best.expectedRisk}), ` +
        `just **${pct(best.riskVsAverage)}** of an average window's risk. Next slot: ` +
        `**${fmtLocal(best.nextOccurrenceMs, tzShiftMs, m.tzLabel)}** (${fmtTime(best.nextOccurrenceMs)}).`,
    );
    if (best.severityMax && isSerious(best.severityMax)) {
      out.push(
        `⚠️ Even your calmest slot has hosted a \`${best.severityMax}\`-severity alert at least once — calm *on ` +
          `average* is not the same as never. Have an eyes-on plan for the change regardless.`,
      );
    }
  }

  if (m.worst) {
    out.push(
      `🔴 Avoid: **${rangeLabel(m.worst, m.tzLabel)}** is the busiest ${m.durationHours}h window — expected ` +
        `**${m.worst.expectedAlerts}** alert(s) (risk ${m.worst.expectedRisk}, ${pct(m.worst.riskVsAverage)} of average). ` +
        `Scheduling a change here risks burying a real incident under the noise.`,
    );
  }

  if (m.recommendations.length > 1) {
    const alts = m.recommendations
      .slice(1)
      .map((w) => `${w.startDay} ${hh(w.startHour)}:00`)
      .join(", ");
    out.push(`🗓️ Backup slots (next calmest, non-overlapping): ${alts} ${m.tzLabel}.`);
  }

  if (m.thin) {
    out.push(
      `🔬 Thin profile: under **2 full weeks** of history back the recommended slot(s) (${m.weeksCovered} week(s) ` +
        `covered) — the per-occurrence averages rest on one or two samples, so treat the ranking as indicative. ` +
        `Widen the window (\`--maintenance <more hours>\`) once more history accrues.`,
    );
  }

  return out;
}

// ----- markdown --------------------------------------------------------------

function recommendationTable(windows: MaintenanceWindow[], tzShiftMs: number, tzLabel: string): string {
  return mdTable(
    ["#", "Window", "Exp. alerts", "Exp. serious", "Exp. risk", "vs avg", "Worst sev", "Samples", "Next occurrence (UTC)"],
    windows.map((w, i) => [
      String(i + 1),
      cell(rangeLabel(w, tzLabel)),
      String(w.expectedAlerts),
      w.expectedSerious > 0 ? `**${w.expectedSerious}**` : "0",
      String(w.expectedRisk),
      pct(w.riskVsAverage),
      cell(w.severityMax),
      `${w.minOccurrences}×`,
      `${fmtLocal(w.nextOccurrenceMs, tzShiftMs, tzLabel)} _(${fmtTime(w.nextOccurrenceMs)})_`,
    ]),
  );
}

function renderMarkdown(m: MaintenanceReport, tzShiftMs: number): string {
  const lines: string[] = [];
  lines.push(`# 🛠️ SecTool Maintenance / Change-Window Recommender`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** an **hour-of-week** risk profile (168 cells, Mon→Sun, ${m.tzLabel}) built from history and averaged ` +
      `per week-occurrence, then a **${m.durationHours}h** window slid across the week and ranked by expected ` +
      `severity-weighted risk (the \`--risk\` ladder: info 1·low 3·medium 9·high 27·critical 81). Offline, ` +
      `deterministic · **Alerts:** ${m.totalAlerts} · **Weeks covered:** ${m.weeksCovered} · ` +
      `**Avg window risk:** ${m.avgWindowRisk}.`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (m.totalAlerts === 0) {
    lines.push(
      `No alerts with a usable timestamp landed in the last ${m.hours}h — there is no rhythm to recommend a change ` +
        `window from. Widen the window (\`--maintenance <more hours>\`) or confirm forwarding with \`--coverage\`.`,
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Recommended change windows`);
  lines.push("");
  lines.push(
    `_The calmest **non-overlapping** ${m.durationHours}h slots, calmest first. "vs avg" is this slot's expected risk ` +
      `as a share of a typical window's — lower is quieter. "Next occurrence" is the next time the recurring local slot ` +
      `comes round._`,
  );
  lines.push("");
  lines.push(recommendationTable(m.recommendations, tzShiftMs, m.tzLabel));
  lines.push("");

  if (m.worst) {
    lines.push(`## Window to avoid`);
    lines.push("");
    lines.push(
      `The busiest ${m.durationHours}h slot is **${rangeLabel(m.worst, m.tzLabel)}** — expected **${m.worst.expectedAlerts}** ` +
        `alert(s) (${m.worst.expectedSerious} serious, risk ${m.worst.expectedRisk}, **${pct(m.worst.riskVsAverage)}** of ` +
        `average). Avoid scheduling a change here: peak noise is exactly when a real incident hides behind your own work.`,
    );
    lines.push("");
  }

  lines.push(
    `**Legend:** _Exp. alerts/serious/risk_ = expected load during one future instance of the slot (per-occurrence ` +
      `mean; serious = high + critical). _vs avg_ = expected risk ÷ the average window's risk. _Samples_ = fewest ` +
      `week-occurrences backing any hour in the slot (sample depth). All times are **${m.tzLabel}**.`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Recommendations are a **probabilistic** bet on the past rhythm holding — a fresh ` +
      `campaign, a holiday or a one-off does not respect your calendar, so keep an eyes-on plan for any change. Risk is ` +
      `scored from IPS *alert* severity (a proxy for "least likely to mask a real incident", not a measure of actual ` +
      `attacking); tuning a loud rule shifts the ranking. With under ~2 full weeks of history the per-occurrence ` +
      `averages are thin. This is the prescriptive scheduling companion to \`--rhythm\` (descriptive hour×day ` +
      `heat-map), \`--forecast\` (forward load projection) and \`--offhours\` (fixed-shift coverage gap). No live ` +
      `gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the maintenance / change-window recommendation report from the stored
 * alert history.
 *
 * @param hours Look-back window in hours (clamped to [24, 90 days]).
 * @param opts  {@link MaintenanceOptions}: `durationHours`, `limit`,
 *              `tzOffsetMinutes`, and a `nowMs` pin for deterministic tests.
 */
export function buildMaintenance(hours: number, opts: MaintenanceOptions = {}): MaintenanceReport {
  const safeHours = Math.max(24, Math.min(24 * 90, Math.floor(hours)));
  const durationHours = Math.max(1, Math.min(24, Math.min(safeHours, Math.floor(opts.durationHours ?? DEFAULT_DURATION))));
  const limit = Math.max(1, Math.min(24, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  // Real-world offsets span UTC-12 … UTC+14 (mirror rhythm.ts).
  const tzOffsetMinutes = Math.max(-14 * 60, Math.min(14 * 60, Math.round(opts.tzOffsetMinutes ?? 0)));
  const tzShiftMs = tzOffsetMinutes * 60_000;
  const tzLabel = tzLabelFor(tzOffsetMinutes);

  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  // 168 hour-of-week cells (Mon-first), each accumulating volume + severity-risk.
  const cells: CellAcc[] = Array.from({ length: HOURS_PER_WEEK }, () => ({
    alerts: 0,
    risk: 0,
    serious: 0,
    severityMax: "info" as Severity,
  }));

  let totalAlerts = 0;
  let totalRisk = 0;
  for (const a of windowed) {
    const shifted = new Date(a.time + tzShiftMs);
    const how = mondayIndex(shifted.getUTCDay()) * 24 + shifted.getUTCHours();
    const sev = asSeverity(a.severity);
    const w = SEVERITY_WEIGHT[sev];
    const c = cells[how]!;
    c.alerts++;
    c.risk += w;
    if (isSerious(sev)) c.serious++;
    c.severityMax = maxSeverity(c.severityMax, sev);
    totalAlerts++;
    totalRisk += w;
  }

  // Count how many times each wall-clock hour-of-week slot actually occurred in
  // the look-back window, by walking the hour grid. This normalises per slot so a
  // cell seen 13 times is not ranked busier than one seen 12 times purely for it.
  const occ = new Array<number>(HOURS_PER_WEEK).fill(0);
  const firstTop = Math.ceil(windowStartMs / MS_PER_HOUR) * MS_PER_HOUR;
  for (let t = firstTop; t < windowEndMs; t += MS_PER_HOUR) {
    const shifted = new Date(t + tzShiftMs);
    const how = mondayIndex(shifted.getUTCDay()) * 24 + shifted.getUTCHours();
    occ[how]!++;
  }

  // Per-cell per-occurrence expectations. A cell with zero occurrences (only the
  // degenerate sub-hour window) contributes nothing.
  const expAlerts = new Array<number>(HOURS_PER_WEEK).fill(0);
  const expRisk = new Array<number>(HOURS_PER_WEEK).fill(0);
  const expSerious = new Array<number>(HOURS_PER_WEEK).fill(0);
  for (let i = 0; i < HOURS_PER_WEEK; i++) {
    const o = occ[i]!;
    if (o <= 0) continue;
    expAlerts[i] = cells[i]!.alerts / o;
    expRisk[i] = cells[i]!.risk / o;
    expSerious[i] = cells[i]!.serious / o;
  }

  // Slide a duration-wide window across the 168-cell ring; one candidate per start.
  interface Cand {
    start: number;
    alerts: number;
    risk: number;
    serious: number;
    severityMax: Severity;
    minOcc: number;
  }
  const candidates: Cand[] = [];
  for (let start = 0; start < HOURS_PER_WEEK; start++) {
    let alerts = 0;
    let risk = 0;
    let serious = 0;
    let severityMax: Severity = "info";
    let minOcc = Infinity;
    for (let k = 0; k < durationHours; k++) {
      const idx = (start + k) % HOURS_PER_WEEK;
      alerts += expAlerts[idx]!;
      risk += expRisk[idx]!;
      serious += expSerious[idx]!;
      severityMax = maxSeverity(severityMax, cells[idx]!.severityMax);
      minOcc = Math.min(minOcc, occ[idx]!);
    }
    candidates.push({
      start,
      alerts,
      risk,
      serious,
      severityMax,
      minOcc: Number.isFinite(minOcc) ? minOcc : 0,
    });
  }

  const avgWindowRisk = candidates.reduce((s, c) => s + c.risk, 0) / (candidates.length || 1);

  const toWindow = (c: Cand): MaintenanceWindow => {
    const endHow = (c.start + durationHours) % HOURS_PER_WEEK;
    return {
      startHow: c.start,
      startDay: DAY_LABELS[Math.floor(c.start / 24)]!,
      startHour: c.start % 24,
      endDay: DAY_LABELS[Math.floor(endHow / 24)]!,
      endHour: endHow % 24,
      durationHours,
      expectedAlerts: round1(c.alerts),
      expectedRisk: round1(c.risk),
      expectedSerious: round1(c.serious),
      severityMax: c.severityMax,
      riskVsAverage: avgWindowRisk > 0 ? round2(c.risk / avgWindowRisk) : 0,
      minOccurrences: c.minOcc,
      nextOccurrenceMs: nextOccurrence(c.start, tzShiftMs, windowEndMs),
    };
  };

  // Calmest first: lowest risk, then lowest volume, then earliest start (stable).
  const ascending = [...candidates].sort(
    (a, b) => a.risk - b.risk || a.alerts - b.alerts || a.start - b.start,
  );

  // Greedy non-overlapping pick so the recommendations are genuinely distinct
  // slots, not the same trough nudged an hour either way.
  const picked: Cand[] = [];
  for (const c of ascending) {
    if (picked.length >= limit) break;
    if (picked.some((p) => ringDistance(p.start, c.start) < durationHours)) continue;
    picked.push(c);
  }
  const recommendations = picked.map(toWindow);

  // Busiest single window (highest risk) for the "avoid" contrast.
  const worstCand = [...candidates].sort(
    (a, b) => b.risk - a.risk || b.alerts - a.alerts || a.start - b.start,
  )[0];
  const worst = worstCand && worstCand.risk > 0 ? toWindow(worstCand) : undefined;

  // Thin when fewer than 2 full weeks back the thinnest recommended slot.
  const minSamples = recommendations.length
    ? Math.min(...recommendations.map((w) => w.minOccurrences))
    : 0;
  const thin = minSamples < 2;

  const base: Omit<MaintenanceReport, "highlights" | "markdown"> = {
    hours: safeHours,
    durationHours,
    tzOffsetMinutes,
    tzLabel,
    windowStartMs,
    windowEndMs,
    totalAlerts,
    totalRisk: round1(totalRisk),
    weeksCovered: round1(safeHours / HOURS_PER_WEEK),
    avgWindowRisk: round1(avgWindowRisk),
    recommendations,
    worst,
    thin,
  };

  const highlights = writeHighlights(base, tzShiftMs);
  const model: MaintenanceReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model, tzShiftMs);
  return model;
}

/** A filesystem-safe filename for a downloaded maintenance-window report. */
export function maintenanceFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-maintenance-${stamp}.md`;
}
