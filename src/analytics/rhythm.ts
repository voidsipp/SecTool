/**
 * Temporal activity rhythm report — "when am I under attack?"
 *
 * Every other offline report in this project slices the alert history by some
 * *entity* or *property*: profile.ts by one IP, assets.ts by internal host,
 * campaigns.ts by external attacker, tuning.ts by signature, watchlist.ts by
 * watched target, report.ts/compare.ts by the window as a whole. None of them
 * answer the orthogonal, purely **temporal** question a SOC asks when it plans
 * coverage and hunts for automation: *at what times of day and days of the week
 * does activity actually happen?*
 *
 * This module folds the stored alert history onto two clock axes and crosses
 * them:
 *
 *   - **Hour-of-day** (0–23) — a 24-bucket histogram of when alerts land,
 *   - **Day-of-week** (Mon–Sun) — a 7-bucket histogram, and
 *   - a **7×24 heat-map** of the two together, rendered as an ASCII intensity
 *     grid that reads at a glance.
 *
 * From those it derives the findings an analyst actually acts on:
 *
 *   - the **peak hour** and **peak day**, and how concentrated activity is in
 *     that single hour (a high share is a fingerprint of an automated, clock-
 *     aligned scanner / C2 beacon rather than organic human traffic),
 *   - a **business-hours vs off-hours** split (Mon–Fri 09:00–17:00 by default) —
 *     and crucially how many **medium-or-worse** detections fired **off-hours**,
 *     when nobody is watching the console: an off-hours critical is materially
 *     more dangerous than the same alert at 2 p.m., and
 *   - the **quietest** window, useful for scheduling noisy maintenance.
 *
 * Wall-clock interpretation is timezone-sensitive, so the report is computed in
 * UTC by default (matching every other report's stamp) but accepts an optional
 * `tzOffsetMinutes` so an operator can read the rhythm in their own local time
 * (e.g. `-300` for US Eastern Standard). The chosen zone is labelled on every
 * axis so a pasted report is never ambiguous.
 *
 * It is pure in-memory math over alertStore — no SSH, no Claude, no network — so
 * it is safe to call from the dashboard or CLI at any time. Output is both a
 * structured model and a ready-to-paste Markdown document, mirroring report.ts,
 * compare.ts, profile.ts, assets.ts, tuning.ts and watchlist.ts.
 *
 * This complements:
 *   - report.ts   (a chronological volume sparkline — absolute time, not folded
 *                  onto the clock, so it can't reveal a daily rhythm), and
 *   - trends.ts   (aggregate top-N tables — no temporal dimension at all).
 */
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** One hour-of-day bucket (0–23) folded across the whole window. */
export interface HourBucket {
  /** Hour of day in the report's timezone, 0–23. */
  hour: number;
  /** Total alerts that landed in this hour across all days. */
  count: number;
  /** Highest severity seen in this hour. */
  severityMax: Severity;
  /** Alerts at medium severity or above in this hour. */
  severeCount: number;
}

/** One day-of-week bucket folded across the whole window. */
export interface DayBucket {
  /** Day index, 0 = Sunday … 6 = Saturday (JS `getUTCDay` convention). */
  day: number;
  /** Short label, e.g. "Mon". */
  label: string;
  /** Total alerts on this weekday across the window. */
  count: number;
  /** Highest severity seen on this weekday. */
  severityMax: Severity;
  /** Alerts at medium severity or above on this weekday. */
  severeCount: number;
}

export interface RhythmReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Offset (minutes) applied to UTC before bucketing; 0 = UTC. */
  tzOffsetMinutes: number;
  /** Human label for the zone, e.g. "UTC" or "UTC-05:00". */
  tzLabel: string;
  /** Alerts with a usable timestamp inside the window (the bucketed population). */
  totalAlerts: number;
  /** Hour-of-day histogram, always 24 entries ordered 0 → 23. */
  byHour: HourBucket[];
  /** Day-of-week histogram, always 7 entries ordered Mon → Sun. */
  byDay: DayBucket[];
  /**
   * 7×24 count matrix. Row order matches {@link byDay} (Mon → Sun); column index
   * is hour-of-day 0 → 23. `heatmap[d][h]` is the alert count for that cell.
   */
  heatmap: number[][];
  /** Largest single cell value, for scaling the rendered intensity grid. */
  heatmapMax: number;
  /** The busiest hour-of-day, or null when there are no alerts. */
  peakHour: HourBucket | null;
  /** The busiest weekday, or null when there are no alerts. */
  peakDay: DayBucket | null;
  /** The quietest NON-EMPTY hour-of-day, or null when there are no alerts. */
  quietestHour: HourBucket | null;
  /** Share of all alerts that fell in {@link peakHour}, 0–100 (concentration signal). */
  peakHourSharePct: number;
  /** Alerts that fired during business hours (Mon–Fri, business window). */
  businessHoursCount: number;
  /** Alerts that fired outside business hours (nights + weekends). */
  offHoursCount: number;
  /** Of {@link offHoursCount}, how many were medium severity or worse. */
  offHoursSevereCount: number;
  /** {@link offHoursCount} as a percentage of {@link totalAlerts}. */
  offHoursPct: number;
  /** Inclusive start hour of the business window (local), default 9. */
  businessStartHour: number;
  /** Exclusive end hour of the business window (local), default 17. */
  businessEndHour: number;
  /** Plain-language call-outs about the report as a whole. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

/** Mon-first day labels; index here maps to {@link DAY_ORDER}. */
const DAY_LABELS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"] as const;
/** getUTCDay() indices in Mon→Sun order (JS week starts on Sunday = 0). */
const DAY_ORDER = [1, 2, 3, 4, 5, 6, 0] as const;
/** Weekend day indices in getUTCDay() convention (Sat, Sun). */
const WEEKEND = new Set<number>([6, 0]);
/** Default business window: 09:00 (inclusive) → 17:00 (exclusive), Mon–Fri. */
const DEFAULT_BUSINESS_START = 9;
const DEFAULT_BUSINESS_END = 17;

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? (b as Severity) : a;
}

/** A severity counts as "severe" (worth off-hours escalation) at medium or above. */
function isSevere(s: string | undefined): boolean {
  return sevRank(s) >= 2;
}

/** Format a tz offset in minutes as a "UTC"/"UTC±HH:MM" label. */
function tzLabelFor(offsetMinutes: number): string {
  if (offsetMinutes === 0) return "UTC";
  const sign = offsetMinutes > 0 ? "+" : "-";
  const abs = Math.abs(offsetMinutes);
  const hh = String(Math.floor(abs / 60)).padStart(2, "0");
  const mm = String(abs % 60).padStart(2, "0");
  return `UTC${sign}${hh}:${mm}`;
}

// ----- formatting helpers (mirror assets.ts / tuning.ts / watchlist.ts) -----

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** Render an hour-of-day index as a 2-digit "HH" string. */
function hh(hour: number): string {
  return String(hour).padStart(2, "0");
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

/** A short horizontal bar (block chars) scaled to `max`, for the histograms. */
function bar(count: number, max: number, width = 24): string {
  if (count <= 0 || max <= 0) return "";
  const filled = Math.max(1, Math.round((count / max) * width));
  return "█".repeat(Math.min(width, filled));
}

/** Heat-map intensity glyphs, blank/low → high. */
const HEAT_GLYPHS = [" ", "·", "░", "▒", "▓", "█"] as const;

/** Map a cell count to an intensity glyph relative to the grid max. */
function heatGlyph(count: number, max: number): string {
  if (count <= 0) return HEAT_GLYPHS[0]!;
  if (max <= 0) return HEAT_GLYPHS[1]!;
  // Buckets 1..5 of HEAT_GLYPHS for the non-zero range.
  const frac = count / max;
  const idx = Math.min(HEAT_GLYPHS.length - 1, 1 + Math.floor(frac * (HEAT_GLYPHS.length - 1)));
  return HEAT_GLYPHS[idx]!;
}

/** Render the 7×24 matrix as a fixed-width ASCII heat-map inside a code block. */
function renderHeatmap(model: RhythmReport): string {
  const lines: string[] = [];
  // Hour ruler: a tens row and a units row so 0–23 reads cleanly above the grid.
  const tens = Array.from({ length: 24 }, (_, h) => (h >= 10 ? String(Math.floor(h / 10)) : " ")).join("");
  const units = Array.from({ length: 24 }, (_, h) => String(h % 10)).join("");
  lines.push("```");
  lines.push(`      ${tens}   (hour of day, ${model.tzLabel})`);
  lines.push(`      ${units}`);
  for (let d = 0; d < DAY_ORDER.length; d++) {
    const row = model.heatmap[d]!;
    const glyphs = row.map((c) => heatGlyph(c, model.heatmapMax)).join("");
    lines.push(`${DAY_LABELS[d]!.padEnd(4)}  ${glyphs}`);
  }
  lines.push("");
  lines.push(`legend: '${HEAT_GLYPHS.slice(1).join("")}' = low → high · ' ' = none · peak cell = ${model.heatmapMax}`);
  lines.push("```");
  return lines.join("\n");
}

/** Compose the report-level highlight bullets. */
function writeHighlights(model: Omit<RhythmReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (!model.totalAlerts) return out;

  if (model.peakHour) {
    out.push(
      `Busiest hour: **${hh(model.peakHour.hour)}:00–${hh((model.peakHour.hour + 1) % 24)}:00 ${model.tzLabel}** — ` +
        `${model.peakHour.count} alert(s) (${model.peakHourSharePct}% of all activity), peak severity ${model.peakHour.severityMax}.`,
    );
    if (model.peakHourSharePct >= 25) {
      out.push(
        `⚠️ ${model.peakHourSharePct}% of all alerts land in that single hour — a tight clock concentration is a ` +
          `fingerprint of automated scanning or fixed-interval beaconing rather than organic traffic.`,
      );
    }
  }
  if (model.peakDay) {
    out.push(`Busiest day: **${model.peakDay.label}** — ${model.peakDay.count} alert(s), peak ${model.peakDay.severityMax}.`);
  }

  out.push(
    `Off-hours load: ${model.offHoursCount} of ${model.totalAlerts} alert(s) (${model.offHoursPct}%) fired outside ` +
      `business hours (Mon–Fri ${hh(model.businessStartHour)}:00–${hh(model.businessEndHour)}:00 ${model.tzLabel}).`,
  );
  if (model.offHoursSevereCount) {
    out.push(
      `🚨 ${model.offHoursSevereCount} medium-or-worse detection(s) fired OFF-HOURS, when the console is least likely ` +
        `to be watched — prioritise these for review or an automated response.`,
    );
  }
  if (model.quietestHour && model.quietestHour.count > 0) {
    out.push(
      `Quietest active hour: ${hh(model.quietestHour.hour)}:00 ${model.tzLabel} (${model.quietestHour.count} alert(s)) — ` +
        `a good slot for noisy maintenance.`,
    );
  }
  return out;
}

function renderMarkdown(model: RhythmReport): string {
  const lines: string[] = [];
  lines.push(`# 🕒 SecTool Activity Rhythm Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(model.windowEndMs)}`);
  lines.push(`**Window:** last ${model.hours} hour(s) — ${fmtTime(model.windowStartMs)} → ${fmtTime(model.windowEndMs)}`);
  lines.push(`**Timezone:** ${model.tzLabel} · **Alerts analysed:** ${model.totalAlerts}`);
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!model.totalAlerts) {
    lines.push(`No alerts with a usable timestamp in the last ${model.hours} hour(s) — nothing to chart.`);
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of model.highlights) lines.push(`- ${h}`);
  lines.push("");

  // The 7×24 heat-map — the centrepiece, reads at a glance.
  lines.push(`## When activity happens (day × hour)`);
  lines.push("");
  lines.push(renderHeatmap(model));
  lines.push("");

  // Hour-of-day histogram.
  lines.push(`## By hour of day (${model.tzLabel})`);
  lines.push("");
  const hourMax = model.byHour.reduce((m, b) => Math.max(m, b.count), 0);
  lines.push(
    mdTable(
      ["Hour", "Alerts", "Severe", "Peak", "Volume"],
      model.byHour
        .filter((b) => b.count > 0)
        .map((b) => [
          `${hh(b.hour)}:00`,
          String(b.count),
          b.severeCount ? String(b.severeCount) : "·",
          cell(b.severityMax),
          bar(b.count, hourMax),
        ]),
    ),
  );
  lines.push("");

  // Day-of-week histogram.
  lines.push(`## By day of week`);
  lines.push("");
  const dayMax = model.byDay.reduce((m, b) => Math.max(m, b.count), 0);
  lines.push(
    mdTable(
      ["Day", "Alerts", "Severe", "Peak", "Volume"],
      model.byDay.map((b) => [
        b.label,
        String(b.count),
        b.severeCount ? String(b.severeCount) : "·",
        b.count ? cell(b.severityMax) : "·",
        bar(b.count, dayMax),
      ]),
    ),
  );
  lines.push("");

  // Business vs off-hours split — the security-relevant cut.
  lines.push(`## Business hours vs off-hours`);
  lines.push("");
  lines.push(
    `Business window: **Mon–Fri ${hh(model.businessStartHour)}:00–${hh(model.businessEndHour)}:00 ${model.tzLabel}**. ` +
      `Everything else (nights + weekends) counts as off-hours.`,
  );
  lines.push("");
  lines.push(
    mdTable(
      ["Window", "Alerts", "Share", "Severe (med+)"],
      [
        [
          "Business hours",
          String(model.businessHoursCount),
          `${100 - model.offHoursPct}%`,
          String(model.byHour.reduce((n, b) => n + b.severeCount, 0) - model.offHoursSevereCount),
        ],
        ["Off-hours", String(model.offHoursCount), `${model.offHoursPct}%`, String(model.offHoursSevereCount)],
      ],
    ),
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from ${model.totalAlerts} stored alert(s), bucketed in ${model.tzLabel}. ` +
      `Times are wall-clock in the stated zone; pass a timezone offset to view in local time. ` +
      `No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the temporal activity rhythm report from the stored alert history.
 *
 * @param hours          Look-back window in hours (clamped to [1, 90 days]).
 *                       A week (168) or more is recommended so the day-of-week
 *                       axis has every weekday represented.
 * @param tzOffsetMinutes Minutes to add to UTC before bucketing onto the clock
 *                        (e.g. -300 for US Eastern Standard, 60 for CET).
 *                        Clamped to ±14h. Defaults to 0 (UTC).
 * @param nowMs          Pins the window end for deterministic tests; defaults to now.
 */
export function buildRhythm(hours: number, tzOffsetMinutes = 0, nowMs = Date.now()): RhythmReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const windowEndMs = nowMs;
  const windowStartMs = windowEndMs - safeHours * 3_600_000;
  // Real-world offsets span UTC-12 … UTC+14.
  const safeTz = Math.max(-14 * 60, Math.min(14 * 60, Math.round(tzOffsetMinutes)));
  const tzLabel = tzLabelFor(safeTz);
  const tzShiftMs = safeTz * 60_000;

  const businessStartHour = DEFAULT_BUSINESS_START;
  const businessEndHour = DEFAULT_BUSINESS_END;

  // Seed empty buckets so absent hours/days still render (silence is meaningful).
  const hourAgg = Array.from({ length: 24 }, (_, hour) => ({
    hour,
    count: 0,
    severityMax: "info" as Severity,
    severeCount: 0,
  }));
  // Day buckets keyed by getUTCDay() index (0=Sun..6=Sat); reordered Mon-first later.
  const dayAgg = Array.from({ length: 7 }, () => ({
    count: 0,
    severityMax: "info" as Severity,
    severeCount: 0,
  }));
  // heatmapRaw[getUTCDay()][hour] — reordered to Mon-first for the model.
  const heatRaw: number[][] = Array.from({ length: 7 }, () => Array<number>(24).fill(0));

  let totalAlerts = 0;
  let businessHoursCount = 0;
  let offHoursCount = 0;
  let offHoursSevereCount = 0;

  const inWindow: StoredAlert[] = alertStore
    .all()
    .filter((a) => typeof a.time === "number" && a.time >= windowStartMs && a.time <= windowEndMs);

  for (const a of inWindow) {
    // Shift into the requested zone, then read the wall-clock fields via the UTC
    // getters (the classic "fake-local" trick — deterministic, no host tz).
    const shifted = new Date(a.time + tzShiftMs);
    const hour = shifted.getUTCHours();
    const dow = shifted.getUTCDay(); // 0=Sun..6=Sat
    const sev = (a.severity as Severity) ?? "info";
    const severe = isSevere(sev);

    totalAlerts++;

    const hb = hourAgg[hour]!;
    hb.count++;
    hb.severityMax = maxSeverity(hb.severityMax, sev);
    if (severe) hb.severeCount++;

    const db = dayAgg[dow]!;
    db.count++;
    db.severityMax = maxSeverity(db.severityMax, sev);
    if (severe) db.severeCount++;

    const heatRow = heatRaw[dow]!;
    heatRow[hour] = (heatRow[hour] ?? 0) + 1;

    const isBusiness = !WEEKEND.has(dow) && hour >= businessStartHour && hour < businessEndHour;
    if (isBusiness) {
      businessHoursCount++;
    } else {
      offHoursCount++;
      if (severe) offHoursSevereCount++;
    }
  }

  const byHour: HourBucket[] = hourAgg.map((b) => ({ ...b }));

  // Reorder day buckets + heat-map rows into Mon→Sun for presentation.
  const byDay: DayBucket[] = DAY_ORDER.map((dow, i) => ({
    day: dow,
    label: DAY_LABELS[i]!,
    count: dayAgg[dow]!.count,
    severityMax: dayAgg[dow]!.severityMax,
    severeCount: dayAgg[dow]!.severeCount,
  }));
  const heatmap: number[][] = DAY_ORDER.map((dow) => [...heatRaw[dow]!]);
  const heatmapMax = heatmap.reduce((m, row) => Math.max(m, ...row), 0);

  // Peaks / quietest (ties resolved by earliest hour / Mon-first day for stability).
  let peakHour: HourBucket | null = null;
  let quietestHour: HourBucket | null = null;
  for (const b of byHour) {
    if (b.count === 0) continue;
    if (!peakHour || b.count > peakHour.count) peakHour = b;
    if (!quietestHour || b.count < quietestHour.count) quietestHour = b;
  }
  let peakDay: DayBucket | null = null;
  for (const b of byDay) {
    if (b.count === 0) continue;
    if (!peakDay || b.count > peakDay.count) peakDay = b;
  }

  const peakHourSharePct = peakHour && totalAlerts ? Math.round((peakHour.count / totalAlerts) * 100) : 0;
  const offHoursPct = totalAlerts ? Math.round((offHoursCount / totalAlerts) * 100) : 0;

  const base: Omit<RhythmReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    tzOffsetMinutes: safeTz,
    tzLabel,
    totalAlerts,
    byHour,
    byDay,
    heatmap,
    heatmapMax,
    peakHour,
    peakDay,
    quietestHour,
    peakHourSharePct,
    businessHoursCount,
    offHoursCount,
    offHoursSevereCount,
    offHoursPct,
    businessStartHour,
    businessEndHour,
  };
  const highlights = writeHighlights(base);
  const model: RhythmReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded activity rhythm report. */
export function rhythmFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-rhythm-${stamp}.md`;
}
