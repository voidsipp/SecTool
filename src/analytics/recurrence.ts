/**
 * Recurrence / return-forecast report — "which attackers come back on a
 * schedule, and *when* should I expect the next wave?"
 *
 * Every other offline report in this project is **retrospective**: it ranks what
 * already happened — the worst source (focus, persistence), the worst target
 * (targets, assets), the worst signature (tuning, lifecycle), the busiest hour
 * (rhythm), the biggest spike (surge). The closest neighbours still look
 * backward or sideways:
 *
 *   - persistence.ts ranks repeat offenders by **longevity** (how long they have
 *     been coming back) — a backward-looking score, not a forward prediction.
 *   - escalation.ts ranks who is **getting worse** (severity trajectory).
 *   - beacon.ts scores one src→dst **pair** for tick-like regularity *within*
 *     its bursts (micro-periodicity, for C2 detection).
 *   - surge.ts finds aggregate **volume spikes** after the fact.
 *
 * None of them answer the operator's planning question:
 *
 *   **"This source has hit me again and again — does its return follow a
 *    predictable cadence, and if so, when is it due back, so I can block or
 *    watch *ahead* of the next wave instead of after it?"**
 *
 * This report fills that gap. For each source IP it:
 *
 *   1. **Sessionizes** the alert stream — collapses a flurry of alerts separated
 *      by less than a gap threshold (default 30 min) into one *activity session*
 *      (a single "wave"), so 50 alerts in a 5-minute scan count as one return,
 *      not fifty. The gaps that matter are the ones *between* waves.
 *   2. Measures the **inter-session intervals** (wave-start to wave-start) and
 *      summarizes them: the **typical return interval** (median, robust to one
 *      odd gap) and the **regularity** of the cadence (coefficient of variation —
 *      low CV = clockwork = automation; high CV = sporadic = opportunistic).
 *   3. **Forecasts the next return** = last wave start + median interval, then
 *      classifies it against *now*:
 *        - **imminent** — due back within the next quarter-cycle (act now),
 *        - **overdue**  — the predicted return has passed but by less than a full
 *                         cycle (it is late — watch, it may be mid-wave),
 *        - **scheduled**— a future return further out than a quarter-cycle,
 *        - **lapsed**   — a full cycle past due with no return (likely stopped or
 *                         already blocked — reassuring, surfaced last).
 *      A **confidence** grade (from CV and session count) says how much to trust
 *      the forecast.
 *
 * The operational payoff is pre-emptive: a regular, high-confidence "imminent"
 * attacker that is **not yet on the blocklist** is the single most actionable row
 * in the toolkit — block it *before* the wave lands. A clockwork cadence is also
 * a strong tell of automation (a permanent block removes a predictable recurring
 * load), and a "lapsed" once-regular heavy hitter is quiet confirmation that an
 * earlier block or takedown is holding.
 *
 * Honest caveats baked into the output:
 *
 *   - **Alerts, not flows.** A "return" is a *detection* wave, not the attacker's
 *     total activity; a quiet source is not proof it is gone, only that it stopped
 *     tripping rules.
 *   - **Forecast, not prophecy.** The prediction assumes the past cadence holds.
 *     Attackers change tooling, rotate IPs, and pause; read the ETA as a planning
 *     hint graded by **confidence**, never a guarantee.
 *   - **Sessionization is a heuristic.** The gap threshold draws the line between
 *     "same wave" and "new return"; a very different attacker tempo may want a
 *     different `sessionGapMinutes`.
 *   - **Needs history.** A cadence needs at least a few waves to exist; sources
 *     with fewer than `minSessions` sessions are counted but not forecast.
 *   - **Window- & store-bounded.** A short look-back sees too few waves to call a
 *     cadence; a long one can hit the store's history cap and drop old waves,
 *     skewing the interval. Pair with the coverage report when in doubt.
 *
 * Pure in-memory math over alertStore (plus blocklist/watchlist/safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring risk.ts, targets.ts,
 * escalation.ts, cluster.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Where the predicted next return sits relative to *now*. */
export type ReturnStatus = "imminent" | "overdue" | "scheduled" | "lapsed";

/** How much to trust a forecast, graded from cadence regularity and sample size. */
export type ForecastConfidence = "high" | "medium" | "low";

/** One recurring source IP, with its cadence summarized and next return forecast. */
export interface RecurrenceEntry {
  /** The source IP this row aggregates. */
  ip: string;
  /** Distinct activity sessions (waves) this source produced in the window. */
  sessions: number;
  /** Total alerts attributed to this source in the window. */
  alerts: number;
  /** Distinct destination IPs this source hit. */
  targets: number;
  /** Distinct signatures this source tripped. */
  signatures: number;
  /** Worst severity any of this source's alerts reached. */
  severityMax: Severity;
  /** Of {@link alerts}, those at medium severity or worse. */
  severe: number;
  /** Severity-weighted pressure (Σ severity weight) across this source's alerts. */
  pressure: number;
  /** Of {@link alerts}, those the gateway blocked. */
  blocked: number;
  /** Of {@link alerts}, those the gateway let through. */
  passed: number;
  /** Of {@link alerts}, those with no recorded action. */
  unknown: number;
  /** Epoch ms of this source's first alert in the window. */
  firstSeenMs: number;
  /** Epoch ms of this source's most recent alert in the window. */
  lastSeenMs: number;
  /** Epoch ms of the start of this source's most recent session (wave). */
  lastSessionStartMs: number;
  /** Typical (median) return interval between consecutive sessions, ms. */
  medianIntervalMs: number;
  /** Mean return interval between consecutive sessions, ms. */
  meanIntervalMs: number;
  /** Coefficient of variation of the intervals (std/mean) — low = clockwork (2dp). */
  cv: number;
  /** Cadence regularity = 1 / (1 + cv), 0..1 (4dp) — higher = steadier return. */
  regularity: number;
  /** Forecast next return = last session start + median interval, epoch ms. */
  predictedNextMs: number;
  /** predictedNextMs − now, ms (negative = the predicted return is already past). */
  etaMs: number;
  /** Where {@link predictedNextMs} sits relative to now. */
  status: ReturnStatus;
  /** Trust grade for the forecast. */
  confidence: ForecastConfidence;
  /** The source IP is already on the blocklist. */
  blocklisted: boolean;
  /** The source IP is on the watchlist. */
  watched: boolean;
  /** The source IP is marked safe. */
  safe: boolean;
}

export interface RecurrenceReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** The gap (minutes) below which consecutive alerts are folded into one session. */
  sessionGapMinutes: number;
  /** Min sessions a source needs before its cadence is forecast. */
  minSessions: number;
  /** Alerts (with a usable timestamp AND a valid source) inside the window. */
  totalWindowAlerts: number;
  /** Distinct source IPs seen this window. */
  distinctSources: number;
  /** Of {@link distinctSources}, those with ≥ {@link minSessions} sessions (forecastable). */
  recurringSources: number;
  /** Forecast rows whose next return is imminent (due within a quarter-cycle). */
  imminentCount: number;
  /** Forecast rows whose predicted return is past but by less than a full cycle. */
  overdueCount: number;
  /** Recurring sources, ranked most-actionable-first, truncated to the limit. */
  entries: RecurrenceEntry[];
  /** True when the entry table was truncated by the limit. */
  truncated: boolean;
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface RecurrenceOptions {
  /** Max rows in the forecast table (clamped to [1, 200]). */
  limit?: number;
  /** Gap in minutes that separates one session from the next (clamped to [1, 1440]). */
  sessionGapMinutes?: number;
  /** Min sessions before a source is forecast (clamped to [3, 100]). */
  minSessions?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const DEFAULT_SESSION_GAP_MIN = 30;
const DEFAULT_MIN_SESSIONS = 3;
const MS_PER_HOUR = 3_600_000;
const MS_PER_MIN = 60_000;

/** A forecast counts as "imminent" if it lands within this fraction of a cycle. */
const IMMINENT_FRACTION = 0.25;

// ----- formatting helpers (mirror targets.ts / cluster.ts / escalation.ts) ----

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** A compact duration label like "30s" / "45m" / "6h" / "3d". */
function fmtDur(ms: number): string {
  const sec = Math.max(0, Math.round(ms / 1000));
  if (sec < 90) return `${sec}s`;
  const min = Math.round(sec / 60);
  if (min < 90) return `${min}m`;
  const hr = Math.round(min / 60);
  if (hr < 48) return `${hr}h`;
  return `${Math.round(hr / 24)}d`;
}

/** A past-tense relative-age label like "3h" / "2d" — mirrors targets.ts. */
function fmtAge(ms: number, nowMs: number): string {
  return fmtDur(Math.max(0, nowMs - ms));
}

/** A signed forecast label: "in 3h" (future) / "now" / "6h late" (past due). */
function fmtEta(etaMs: number): string {
  if (etaMs > 30_000) return `in ${fmtDur(etaMs)}`;
  if (etaMs < -30_000) return `${fmtDur(-etaMs)} late`;
  return "now";
}

/** A 0..1 fraction as a whole-number percent string, e.g. 0.823 -> "82%". */
function pct(frac: number): string {
  return `${Math.round(frac * 100)}%`;
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
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

// ----- classifiers / small math --------------------------------------------

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

/** Coerce a stored severity string to a known band, defaulting to "info". */
function asSeverity(s: string | undefined): Severity {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? "info" : (s as Severity);
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? asSeverity(b) : a;
}

function isSevere(s: string | undefined): boolean {
  return sevRank(s) >= 2; // medium or worse
}

/** A valid, non-empty IP, or undefined if the field is missing/garbage. */
function validIp(ip: string | undefined): string | undefined {
  return ip && isIP(ip) !== 0 ? ip : undefined;
}

/** Median of a numeric array (0 for empty); does not mutate the input. */
function median(values: number[]): number {
  if (!values.length) return 0;
  const sorted = [...values].sort((x, y) => x - y);
  const mid = sorted.length >> 1;
  return sorted.length % 2 ? sorted[mid]! : Math.round((sorted[mid - 1]! + sorted[mid]!) / 2);
}

function mean(values: number[]): number {
  if (!values.length) return 0;
  return values.reduce((s, v) => s + v, 0) / values.length;
}

/** Population standard deviation of a numeric array (0 for <2 values). */
function stddev(values: number[], mu: number): number {
  if (values.length < 2) return 0;
  const variance = values.reduce((s, v) => s + (v - mu) * (v - mu), 0) / values.length;
  return Math.sqrt(variance);
}

const STATUS_RANK: Record<ReturnStatus, number> = {
  imminent: 0,
  overdue: 1,
  scheduled: 2,
  lapsed: 3,
};

const CONFIDENCE_RANK: Record<ForecastConfidence, number> = {
  high: 0,
  medium: 1,
  low: 2,
};

/** Classify a forecast's timing relative to now, scaled by the source's own cycle. */
function classifyStatus(etaMs: number, medianIntervalMs: number): ReturnStatus {
  if (etaMs <= -medianIntervalMs) return "lapsed";
  if (etaMs <= 0) return "overdue";
  if (etaMs <= medianIntervalMs * IMMINENT_FRACTION) return "imminent";
  return "scheduled";
}

/** Grade forecast trust from cadence regularity (CV) and the number of waves seen. */
function gradeConfidence(cv: number, sessions: number): ForecastConfidence {
  if (cv <= 0.25 && sessions >= 5) return "high";
  if (cv <= 0.5 && sessions >= 3) return "medium";
  return "low";
}

// ----- per-source aggregation -----------------------------------------------

interface SourceAcc {
  /** Sorted alert times (ascending) for sessionization. */
  times: number[];
  alerts: number;
  targets: Set<string>;
  signatures: Set<string>;
  severityMax: Severity;
  severe: number;
  pressure: number;
  blocked: number;
  passed: number;
  unknown: number;
}

function newSourceAcc(): SourceAcc {
  return {
    times: [],
    alerts: 0,
    targets: new Set(),
    signatures: new Set(),
    severityMax: "info",
    severe: 0,
    pressure: 0,
    blocked: 0,
    passed: 0,
    unknown: 0,
  };
}

/**
 * Fold one source's sorted alert times into session **start** timestamps: a new
 * session begins whenever the gap from the previous alert exceeds `gapMs`.
 */
function sessionStarts(times: number[], gapMs: number): number[] {
  const starts: number[] = [];
  let prev = -Infinity;
  for (const t of times) {
    if (t - prev > gapMs) starts.push(t);
    prev = t;
  }
  return starts;
}

function finishSource(
  ip: string,
  a: SourceAcc,
  gapMs: number,
  minSessions: number,
  nowMs: number,
): RecurrenceEntry | null {
  const times = a.times.sort((x, y) => x - y);
  const starts = sessionStarts(times, gapMs);
  if (starts.length < minSessions) return null; // not enough waves to forecast

  const intervals: number[] = [];
  for (let i = 1; i < starts.length; i++) intervals.push(starts[i]! - starts[i - 1]!);

  const med = median(intervals);
  const mu = mean(intervals);
  const sd = stddev(intervals, mu);
  const cv = mu > 0 ? sd / mu : 0;
  const lastSessionStartMs = starts[starts.length - 1]!;
  const predictedNextMs = lastSessionStartMs + med;
  const etaMs = predictedNextMs - nowMs;

  return {
    ip,
    sessions: starts.length,
    alerts: a.alerts,
    targets: a.targets.size,
    signatures: a.signatures.size,
    severityMax: a.severityMax,
    severe: a.severe,
    pressure: round1(a.pressure),
    blocked: a.blocked,
    passed: a.passed,
    unknown: a.unknown,
    firstSeenMs: times[0]!,
    lastSeenMs: times[times.length - 1]!,
    lastSessionStartMs,
    medianIntervalMs: med,
    meanIntervalMs: Math.round(mu),
    cv: round2(cv),
    regularity: round4(1 / (1 + cv)),
    predictedNextMs,
    etaMs,
    status: classifyStatus(etaMs, med),
    confidence: gradeConfidence(cv, starts.length),
    blocklisted: blockStore.has(ip),
    watched: watchStore.has(ip),
    safe: safeStore.has(ip),
  } satisfies RecurrenceEntry;
}

/**
 * Rank for actionability: soonest-and-surest first. imminent → overdue →
 * scheduled → lapsed, then higher confidence, steadier cadence, heavier
 * pressure, more waves, then IP — so the order is fully deterministic.
 */
function rankEntries(rows: RecurrenceEntry[], limit: number): RecurrenceEntry[] {
  return [...rows]
    .sort(
      (x, y) =>
        STATUS_RANK[x.status] - STATUS_RANK[y.status] ||
        CONFIDENCE_RANK[x.confidence] - CONFIDENCE_RANK[y.confidence] ||
        y.regularity - x.regularity ||
        y.pressure - x.pressure ||
        y.sessions - x.sessions ||
        (x.ip < y.ip ? -1 : x.ip > y.ip ? 1 : 0),
    )
    .slice(0, limit);
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  m: Omit<RecurrenceReport, "highlights" | "markdown">,
  nowMs: number,
): string[] {
  const out: string[] = [];
  if (!m.totalWindowAlerts) return out;

  if (!m.recurringSources) {
    out.push(
      `ℹ️ No source produced ${m.minSessions}+ distinct activity sessions over the last ${m.hours}h ` +
        `(gap threshold ${m.sessionGapMinutes}m) — nothing has returned often enough to forecast a cadence. ` +
        `Widen the window or lower the session gap to catch slower-tempo repeat offenders.`,
    );
    return out;
  }

  out.push(
    `🔁 **${m.recurringSources.toLocaleString("en-US")} of ${m.distinctSources.toLocaleString("en-US")} source(s) ` +
      `returned ${m.minSessions}+ times** over the last ${m.hours}h (sessions split on a ${m.sessionGapMinutes}m gap). ` +
      `This report predicts *when each comes back* — ${m.imminentCount} imminent, ${m.overdueCount} overdue — so you can ` +
      `block or watch **ahead** of the next wave, not after it.`,
  );

  // The single most actionable row: a soon, trustworthy return not yet blocked.
  const actNow = m.entries.find(
    (e) => (e.status === "imminent" || e.status === "overdue") && e.confidence !== "low" && !e.blocklisted && !e.safe,
  );
  if (actNow) {
    out.push(
      `⏰ \`${actNow.ip}\` returns about every **${fmtDur(actNow.medianIntervalMs)}** ` +
        `(${actNow.confidence} confidence, ${actNow.sessions} waves, last seen ${fmtAge(actNow.lastSeenMs, nowMs)} ago) — ` +
        `next wave expected **${fmtEta(actNow.etaMs)}**, peak ${actNow.severityMax}, and it is **not on the blocklist**. ` +
        `Block or pre-stage a watch now to get ahead of it.`,
    );
  }

  // Batch of imminent returns worth pre-staging coverage for.
  const imminent = m.entries.filter((e) => e.status === "imminent");
  if (imminent.length > 1) {
    out.push(
      `📥 **${imminent.length} attacker(s) are due back within their next quarter-cycle**: ` +
        imminent
          .slice(0, 5)
          .map((e) => `\`${e.ip}\` (${fmtEta(e.etaMs)}${e.blocklisted ? ", ⛔" : ""})`)
          .join(", ") +
        `. Schedule coverage / blocks around these windows.`,
    );
  }

  // Clockwork cadence = automation worth a permanent block.
  const clockwork = m.entries
    .filter((e) => e.confidence === "high")
    .sort((a, b) => a.cv - b.cv)[0];
  if (clockwork) {
    out.push(
      `🤖 \`${clockwork.ip}\` returns like clockwork **every ${fmtDur(clockwork.medianIntervalMs)}** ` +
        `(CV ${clockwork.cv.toFixed(2)}, ${pct(clockwork.regularity)} regular across ${clockwork.sessions} waves) — ` +
        `that steadiness is automation, not a human. A permanent block removes a predictable recurring load` +
        (clockwork.blocklisted ? " (already blocklisted)." : "."),
    );
  }

  // A once-regular heavy hitter that has gone quiet = a block/takedown holding.
  const lapsed = m.entries
    .filter((e) => e.status === "lapsed" && e.confidence !== "low")
    .sort((a, b) => b.pressure - a.pressure)[0];
  if (lapsed) {
    out.push(
      `✅ \`${lapsed.ip}\` was a regular (every ${fmtDur(lapsed.medianIntervalMs)}) but is now ` +
        `**${fmtDur(-lapsed.etaMs)} past due with no return**` +
        (lapsed.blocklisted ? " — its block appears to be holding." : " — it may have stopped or rotated IPs.") +
        ` Worth confirming rather than assuming.`,
    );
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

const STATUS_ICON: Record<ReturnStatus, string> = {
  imminent: "⏰",
  overdue: "⚠️",
  scheduled: "📅",
  lapsed: "💤",
};

function entryTable(rows: RecurrenceEntry[], nowMs: number): string {
  return mdTable(
    [
      "#",
      "Source",
      "Status",
      "ETA",
      "Every",
      "Conf",
      "Waves",
      "Last seen",
      "Pressure",
      "Targets",
      "Sigs",
      "Peak",
      "Flags",
    ],
    rows.map((r, i) => {
      const flags =
        (r.blocklisted ? "⛔" : "") + (r.watched ? "👁" : "") + (r.safe ? "✅" : "");
      return [
        String(i + 1),
        cell(r.ip),
        `${STATUS_ICON[r.status]} ${r.status}`,
        fmtEta(r.etaMs),
        fmtDur(r.medianIntervalMs),
        r.confidence,
        String(r.sessions),
        fmtAge(r.lastSeenMs, nowMs),
        String(r.pressure),
        String(r.targets),
        String(r.signatures),
        cell(r.severityMax),
        flags || "—",
      ];
    }),
  );
}

function renderMarkdown(m: RecurrenceReport, nowMs: number): string {
  const lines: string[] = [];
  lines.push(`# 🔁 SecTool Recurrence / Return-Forecast Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`,
  );
  lines.push(
    `**Method:** per-source alerts sessionized on a **${m.sessionGapMinutes}m** gap; sources with ` +
      `**≥ ${m.minSessions} sessions** get a cadence (median inter-wave interval + regularity) and a ` +
      `**next-return forecast** = last wave + median interval · **Window alerts:** ${m.totalWindowAlerts}`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.totalWindowAlerts) {
    lines.push(
      `No alerts with a usable timestamp and source in the last ${m.hours} hour(s) — no cadence to forecast.`,
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  lines.push(`| Metric | Value |`);
  lines.push(`| --- | --- |`);
  lines.push(`| Distinct sources | ${m.distinctSources.toLocaleString("en-US")} |`);
  lines.push(
    `| Recurring (≥ ${m.minSessions} sessions) | ${m.recurringSources.toLocaleString("en-US")} |`,
  );
  lines.push(`| Imminent returns | ${m.imminentCount.toLocaleString("en-US")} |`);
  lines.push(`| Overdue returns | ${m.overdueCount.toLocaleString("en-US")} |`);
  lines.push("");

  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Return forecast — recurring sources, soonest-and-surest first`);
  lines.push("");
  if (!m.entries.length) {
    lines.push(
      `_No source produced ${m.minSessions}+ distinct sessions this window — nothing recurs often enough to forecast._`,
    );
  } else {
    lines.push(
      `Sources that have come back ${m.minSessions}+ times, ranked by how soon and how trustworthy their next ` +
        `return is. _ETA_ is the forecast next wave; _Every_ is the typical (median) gap between waves; _Conf_ grades ` +
        `the cadence (regularity × sample size). _Status_: ⏰ imminent (due within a quarter-cycle) · ⚠️ overdue (late, ` +
        `< one cycle) · 📅 scheduled (further out) · 💤 lapsed (a full cycle past due — likely stopped/blocked). ` +
        `Flags: ⛔ blocklisted · 👁 watchlisted · ✅ safelisted.`,
    );
    lines.push("");
    lines.push(entryTable(m.entries, nowMs));
  }
  lines.push("");

  if (m.truncated) {
    lines.push(`_The forecast table was truncated to the row limit — raise \`limit\` to see more._`);
    lines.push("");
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from stored **IPS-alert** timestamps per source. A "return" is a detection ` +
      `**wave** (alerts within ${m.sessionGapMinutes}m are one session), not the attacker's total traffic — these are ` +
      `detections, not flows, so a quiet source is not proof it is gone. The forecast assumes the **past cadence ` +
      `holds**; attackers change tooling, rotate IPs and pause, so read the ETA as a planning hint graded by ` +
      `**confidence**, never a guarantee. Sessionization and the ${m.minSessions}-session floor are heuristics; a long ` +
      `look-back can hit the store's history cap and drop old waves, skewing the interval. No live gateway query was ` +
      `performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the recurrence / return-forecast report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link RecurrenceOptions}: `limit`, `sessionGapMinutes`,
 *              `minSessions`, and a `nowMs` pin.
 */
export function buildRecurrence(hours: number, opts: RecurrenceOptions = {}): RecurrenceReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const sessionGapMinutes = Math.max(
    1,
    Math.min(1440, Math.floor(opts.sessionGapMinutes ?? DEFAULT_SESSION_GAP_MIN)),
  );
  const minSessions = Math.max(3, Math.min(100, Math.floor(opts.minSessions ?? DEFAULT_MIN_SESSIONS)));
  const gapMs = sessionGapMinutes * MS_PER_MIN;
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const sources = new Map<string, SourceAcc>();
  let countedAlerts = 0;

  for (const a of windowed) {
    const src = validIp(a.srcIp);
    if (!src) continue;
    countedAlerts++;

    let acc = sources.get(src);
    if (!acc) {
      acc = newSourceAcc();
      sources.set(src, acc);
    }
    acc.times.push(a.time);
    acc.alerts++;

    const severity = asSeverity(a.severity);
    acc.pressure += SEVERITY_WEIGHT[severity];
    acc.severityMax = maxSeverity(acc.severityMax, severity);
    if (isSevere(severity)) acc.severe++;

    const disp = classifyDisposition(a.action);
    if (disp === "blocked") acc.blocked++;
    else if (disp === "passed") acc.passed++;
    else acc.unknown++;

    const dst = validIp(a.dstIp);
    if (dst) acc.targets.add(dst);
    const sig = a.signature?.trim();
    if (sig) acc.signatures.add(sig);
  }

  const forecastable: RecurrenceEntry[] = [];
  for (const [ip, acc] of sources) {
    const entry = finishSource(ip, acc, gapMs, minSessions, windowEndMs);
    if (entry) forecastable.push(entry);
  }

  const ranked = rankEntries(forecastable, limit);

  const base: Omit<RecurrenceReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    sessionGapMinutes,
    minSessions,
    totalWindowAlerts: countedAlerts,
    distinctSources: sources.size,
    recurringSources: forecastable.length,
    imminentCount: forecastable.filter((e) => e.status === "imminent").length,
    overdueCount: forecastable.filter((e) => e.status === "overdue").length,
    entries: ranked,
    truncated: forecastable.length > ranked.length,
  };

  const highlights = writeHighlights(base, windowEndMs);
  const model: RecurrenceReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model, windowEndMs);
  return model;
}

/** A filesystem-safe filename for a downloaded recurrence / return-forecast report. */
export function recurrenceFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-recurrence-${stamp}.md`;
}
