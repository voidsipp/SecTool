/**
 * Attacker patterns-of-life / operating-hours (timezone-attribution) report —
 * "is this attacker a 24/7 robot, or a human clocking in on a shift — and if a
 * human, what timezone do they work in?"
 *
 * Every persistent attacker leaves a *clock fingerprint*: the distribution of
 * *when* — at which hours of the (UTC) day, and on which days of the week — their
 * detections land. That fingerprint is one of the oldest tools in attribution
 * ("pattern-of-life" / "working-hours" analysis): automated infrastructure runs
 * around the clock, every day, with no respect for human sleep or weekends; a
 * *person* at a keyboard concentrates their activity into a contiguous ~8–12 hour
 * band and tends to go quiet on weekends. The shape of that band, projected back
 * onto the globe, even estimates the operator's *local timezone* — because humans
 * mostly work daytime hours, an actor whose UTC activity peaks at 05:00 is
 * probably awake mid-afternoon somewhere ~UTC+8.
 *
 * None of the existing offline reports surface this:
 *
 *   - rhythm.ts folds the **whole** alert history onto hour-of-day / day-of-week
 *     axes — it answers "when is *my network* busiest?", a single global clock.
 *     It cannot tell you that source A is a round-the-clock botnet while source B
 *     only ever fires 06:00–15:00 UTC: both just add to the same global heat-map.
 *   - beacon.ts hunts **fixed-interval periodicity** (a 5-minute C2 heartbeat) per
 *     src→dst pair — a within-the-hour cadence, orthogonal to which *hours of the
 *     day* an actor is awake. A human operator who works 9-to-5 has no beacon
 *     period at all; a 24/7 beacon has no human working-hours shape.
 *   - dwell.ts sessionises a source's timeline on idle gaps (how long each visit
 *     lasts); persistence.ts / recurrence.ts measure longevity and return cadence.
 *     None of them fold a source onto the **clock** to ask whether it sleeps.
 *
 * This report groups the windowed history by external **source IP**, and for each
 * source that clears a minimum-evidence bar (enough alerts, seen on enough
 * distinct days that a daily rhythm is even measurable) computes:
 *
 *   - a **24-bucket UTC hour-of-day histogram** and the **circular concentration**
 *     R of that histogram (0 = evenly smeared across the whole clock → automation;
 *     → 1 = tightly clustered in a few adjacent hours → a human shift). Circular
 *     statistics are used so the midnight wrap (23:00 next to 00:00) is handled
 *     correctly — a naive linear mean would mis-place any actor straddling
 *     midnight.
 *   - the **circular mean hour** and **modal peak hour** (UTC),
 *   - a **weekend fraction** — what share of the activity lands on Sat/Sun. A
 *     near-zero weekend share over a multi-week window is a strong human tell;
 *     genuine automation does not know it is the weekend.
 *   - a one-word **classification** — **🤖 automation** (round-the-clock, every
 *     day), **🧑 operator** (a concentrated daytime shift), **▥ mixed**, or
 *     **transient** (too little evidence to call), and
 *   - for operator-class sources, an **estimated UTC offset** and coarse **region
 *     hint**, derived by sliding the actor's activity band so its centre lands on
 *     a typical local mid-afternoon. This is a *hypothesis*, not geolocation — but
 *     a cheap, IP-independent one that corroborates or contradicts GeoIP.
 *
 * It then rolls the operator-class sources up into a **timezone histogram**: which
 * UTC offsets your human adversaries appear to work from. "Most of your hands-on-
 * keyboard activity clusters around UTC+3 (E. Europe / Middle East)" is a genuinely
 * strategic, board-level sentence that no per-IP leaderboard yields.
 *
 * Honest caveats baked into the output:
 *
 *   - **A hypothesis, not geolocation.** The timezone estimate assumes the actor
 *     is a daytime worker; night-shift operators, follow-the-sun teams, and
 *     deliberately time-shifted campaigns will fool it. It corroborates GeoIP /
 *     ASN data, it does not replace it.
 *   - **Detections, not presence.** SecTool stores IPS *alerts*; a source only
 *     appears "awake" at an hour if it tripped a signature then. Quiet
 *     reconnaissance is invisible, so the active band is a lower bound.
 *   - **NAT & shared egress.** One IP can be many real actors (over-smearing the
 *     clock toward "automation"); a rotating botnet can split one operator across
 *     many IPs (hiding the human shape). The report says so.
 *   - **Window- & store-bounded.** A short window can't separate "only active by
 *     day" from "only happened to fire by day"; a long look-back can hit the alert
 *     store's history cap and clip the tail.
 *
 * Pure in-memory math over alertStore (plus blocklist / watchlist membership
 * flags) — no SSH, no Claude, no network. Output is both a structured model and a
 * ready-to-paste Markdown document, mirroring concentration.ts, dwell.ts and the
 * other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** A one-word verdict on what drives a source's clock. */
export type OperatorClass = "automation" | "operator" | "mixed" | "transient";

/** The clock fingerprint of a single source IP. */
export interface SourceClock {
  ip: string;
  /** Alerts attributed to this source in the window. */
  count: number;
  firstSeenMs: number;
  lastSeenMs: number;
  /** Distinct UTC calendar days the source was active on. */
  activeDays: number;
  /** lastSeen − firstSeen, in whole hours. */
  spanHours: number;
  /** 24-bucket UTC hour-of-day histogram (index = hour). */
  hourHistogram: number[];
  /** Hours (0–23) with at least one alert. */
  distinctHours: number;
  /** Alerts that landed on a Saturday or Sunday (UTC). */
  weekendCount: number;
  /** Weekend alerts as a fraction of the source's alerts, 0..1 (4dp). */
  weekendFrac: number;
  /** Circular concentration R of the hour histogram, 0..1 (4dp). */
  concentration: number;
  /** Circular mean hour of activity, 0..24 (UTC, 1dp). */
  meanHourUtc: number;
  /** Modal (busiest) hour, 0–23 (UTC). */
  peakHourUtc: number;
  /** The verdict. */
  classification: OperatorClass;
  /** 0..1 — how operator-like (clustered daytime band + weekday skew). */
  humanScore: number;
  /** Operator/mixed only: estimated local UTC offset in whole hours [-12, 11]. */
  estUtcOffset?: number;
  /** Operator/mixed only: the peak hour shifted into estimated local time, 0–23. */
  estLocalPeakHour?: number;
  /** Operator/mixed only: a coarse region label for {@link estUtcOffset}. */
  regionHint?: string;
  severityMax: Severity;
  blocked: boolean;
  watched: boolean;
  /** The source's most frequent signature, for context. */
  signatureTop?: string;
}

/** Operator-class sources rolled up by estimated UTC offset. */
export interface TimezoneBucket {
  /** Estimated UTC offset in whole hours [-12, 11]. */
  utcOffset: number;
  /** Coarse region label for the offset. */
  regionHint: string;
  /** Operator-class sources estimated at this offset. */
  operators: number;
  /** Their combined alert volume. */
  alerts: number;
}

export interface PatternsReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Distinct external sources seen in the window (any volume). */
  distinctSources: number;
  /** Sources that cleared the minimum-evidence bar and were classified. */
  analysedSources: number;
  /** The assumed local mid-activity hour used for the timezone estimate. */
  assumedMiddayHour: number;
  /** Per-class counts across the analysed sources. */
  classCounts: Record<OperatorClass, number>;
  /** Operator-class sources, most human-like first (capped to the row limit). */
  operators: SourceClock[];
  /** Automation-class sources, heaviest first (capped to the row limit). */
  automation: SourceClock[];
  /** Operator-class sources rolled up by estimated UTC offset, busiest first. */
  timezoneHistogram: TimezoneBucket[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface PatternsOptions {
  /** Min alerts for a source to be classified (clamped to [3, 1000]). */
  minAlerts?: number;
  /** Min distinct active UTC days for a source to be classified (clamped to [1, 31]). */
  minActiveDays?: number;
  /** Max rows in each leaderboard / the timezone table (clamped to [1, 200]). */
  limit?: number;
  /** Assumed local hour an operator's activity centres on (clamped to [9, 17]). */
  assumedMiddayHour?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_MIN_ALERTS = 12;
const DEFAULT_MIN_ACTIVE_DAYS = 2;
const DEFAULT_LIMIT = 15;
/** Mid-point of a canonical 09:00–17:00 working day — the operator's local "centre". */
const DEFAULT_MIDDAY_HOUR = 13;
const MS_PER_HOUR = 3_600_000;
const MS_PER_DAY = 86_400_000;

/** R at/above which an hour distribution is "clustered" enough to be a human shift. */
const OPERATOR_R = 0.55;
/** R below which (or with enough distinct hours) the clock is "smeared" → automation. */
const AUTOMATION_R = 0.3;
/** Distinct-hour count at/above which a source is considered round-the-clock. */
const ROUND_THE_CLOCK_HOURS = 18;
/** Distinct-hour count at/below which a clustered source is a clean daytime shift. */
const SHIFT_HOURS = 14;
/** Baseline weekend share if activity were day-agnostic (2 of 7 days). */
const WEEKEND_BASELINE = 2 / 7;

// ----- classifiers / helpers (mirror concentration.ts / dwell.ts) ------------

/** RFC1918 / loopback / link-local / ULA — an address treated as one of ours. */
function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
}

/** A valid, external (non-private) IP, or undefined. Source clocks are about adversaries. */
function externalIp(ip: string | undefined): string | undefined {
  if (!ip || isIP(ip) === 0) return undefined;
  return isPrivate(ip) ? undefined : ip;
}

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? (b as Severity) : a;
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

/** Two-digit hour label, e.g. 5 → "05". */
function hh(h: number): string {
  return String(((h % 24) + 24) % 24).padStart(2, "0");
}

/** A signed UTC-offset label, e.g. 0 → "UTC", 3 → "UTC+3", -5 → "UTC−5". */
function offsetLabel(off: number): string {
  if (off === 0) return "UTC";
  return `UTC${off > 0 ? "+" : "−"}${Math.abs(off)}`;
}

function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function clip(s: string, max = 40): string {
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

/** Human label + emoji for an operator class. */
function classLabel(c: OperatorClass): string {
  switch (c) {
    case "automation":
      return "🤖 automation";
    case "operator":
      return "🧑 operator";
    case "mixed":
      return "▥ mixed";
    case "transient":
      return "· transient";
  }
}

/**
 * Coarse region hint for a whole-hour UTC offset. Deliberately broad — the offset
 * is a hypothesis, so the label names the *band of longitudes*, not a country.
 */
function regionForOffset(off: number): string {
  switch (off) {
    case -12:
    case -11:
    case -10:
      return "Pacific";
    case -9:
    case -8:
      return "US/Canada Pacific";
    case -7:
      return "US/Canada Mountain";
    case -6:
      return "US/Canada Central / C. America";
    case -5:
      return "US/Canada Eastern / W. S. America";
    case -4:
      return "Atlantic / W. S. America";
    case -3:
      return "E. S. America";
    case -2:
    case -1:
      return "Mid-Atlantic";
    case 0:
      return "UK / Iceland / W. Africa";
    case 1:
      return "W. & C. Europe / W. Africa";
    case 2:
      return "E. Europe / C. Africa";
    case 3:
      return "E. Europe / Moscow / Middle East";
    case 4:
      return "Caucasus / Gulf";
    case 5:
      return "W. & C. Asia / Pakistan";
    case 6:
      return "C. Asia / Bangladesh";
    case 7:
      return "SE Asia (Indochina) / W. Indonesia";
    case 8:
      return "China / Singapore / W. Australia";
    case 9:
      return "Japan / Korea";
    case 10:
      return "E. Australia / W. Pacific";
    case 11:
      return "Solomon Is. / E. Australia";
    default:
      return "—";
  }
}

// ----- circular statistics ---------------------------------------------------

/**
 * Mean resultant length R and circular mean hour of a 24-bucket hour histogram.
 * Each hour h is an angle θ = 2π·h/24 on the clock; R = |Σ e^{iθ}| / n is the
 * concentration (0 = perfectly smeared across the clock, 1 = a single hour),
 * computed circularly so the 23↔00 midnight wrap is handled correctly. Returns
 * the mean hour in [0, 24).
 */
function circularStats(hist: number[]): { r: number; meanHour: number } {
  let c = 0;
  let s = 0;
  let n = 0;
  for (let h = 0; h < 24; h++) {
    const w = hist[h] ?? 0;
    if (w <= 0) continue;
    const theta = (2 * Math.PI * h) / 24;
    c += w * Math.cos(theta);
    s += w * Math.sin(theta);
    n += w;
  }
  if (n === 0) return { r: 0, meanHour: 0 };
  const r = Math.sqrt(c * c + s * s) / n;
  let mean = (Math.atan2(s, c) * 24) / (2 * Math.PI);
  if (mean < 0) mean += 24;
  return { r: round4(Math.max(0, Math.min(1, r))), meanHour: mean };
}

/**
 * Classify a source's clock. Clustered into a daytime band → operator; smeared
 * across the clock or active round-the-clock → automation; in between → mixed.
 */
function classify(r: number, distinctHours: number): OperatorClass {
  if (r >= OPERATOR_R && distinctHours <= SHIFT_HOURS) return "operator";
  if (r < AUTOMATION_R || distinctHours >= ROUND_THE_CLOCK_HOURS) return "automation";
  return "mixed";
}

/**
 * Estimate the operator's whole-hour UTC offset by sliding their activity centre
 * (circular mean hour) onto the assumed local mid-activity hour. Normalised to
 * [-12, 11].
 */
function estimateOffset(meanHourUtc: number, middayHour: number): number {
  let o = Math.round(middayHour - meanHourUtc) % 24;
  if (o < 0) o += 24;
  if (o >= 12) o -= 24;
  return o;
}

// ----- aggregation -----------------------------------------------------------

interface SrcAcc {
  count: number;
  firstSeenMs: number;
  lastSeenMs: number;
  hourHistogram: number[];
  days: Set<number>;
  weekendCount: number;
  severityMax: Severity;
  signatures: Map<string, number>;
}

function newSrcAcc(timeMs: number): SrcAcc {
  return {
    count: 0,
    firstSeenMs: timeMs,
    lastSeenMs: timeMs,
    hourHistogram: new Array(24).fill(0),
    days: new Set(),
    weekendCount: 0,
    severityMax: "info",
    signatures: new Map(),
  };
}

function bump(acc: SrcAcc, a: StoredAlert): void {
  acc.count++;
  if (a.time < acc.firstSeenMs) acc.firstSeenMs = a.time;
  if (a.time > acc.lastSeenMs) acc.lastSeenMs = a.time;
  const d = new Date(a.time);
  const hour = d.getUTCHours();
  acc.hourHistogram[hour] = (acc.hourHistogram[hour] ?? 0) + 1;
  acc.days.add(Math.floor(a.time / MS_PER_DAY));
  const dow = d.getUTCDay(); // 0 = Sun … 6 = Sat
  if (dow === 0 || dow === 6) acc.weekendCount++;
  acc.severityMax = maxSeverity(acc.severityMax, a.severity);
  const sig = (a.signature ?? "").trim();
  if (sig) acc.signatures.set(sig, (acc.signatures.get(sig) ?? 0) + 1);
}

/** Resolve the most frequent signature for context (deterministic tie-break). */
function topSignature(sigs: Map<string, number>): string | undefined {
  let best: string | undefined;
  let bestN = 0;
  for (const [s, n] of sigs) {
    if (n > bestN || (n === bestN && best !== undefined && s < best)) {
      best = s;
      bestN = n;
    }
  }
  return best;
}

/** Build the finished {@link SourceClock} from a raw accumulator. */
function summariseSource(ip: string, acc: SrcAcc, middayHour: number): SourceClock {
  const { r, meanHour } = circularStats(acc.hourHistogram);
  const distinctHours = acc.hourHistogram.filter((x) => x > 0).length;
  let peakHourUtc = 0;
  let peakN = -1;
  for (let h = 0; h < 24; h++) {
    if ((acc.hourHistogram[h] ?? 0) > peakN) {
      peakN = acc.hourHistogram[h] ?? 0;
      peakHourUtc = h;
    }
  }
  const classification = classify(r, distinctHours);
  const weekendFrac = acc.count > 0 ? round4(acc.weekendCount / acc.count) : 0;

  // Weekday skew: 1 when activity wholly avoids weekends, 0 once it meets the
  // day-agnostic baseline. A human tell, blended with the clustering concentration.
  const weekdayBias = Math.max(0, Math.min(1, (WEEKEND_BASELINE - weekendFrac) / WEEKEND_BASELINE));
  const humanScore = round4(0.65 * r + 0.35 * weekdayBias);

  const clock: SourceClock = {
    ip,
    count: acc.count,
    firstSeenMs: acc.firstSeenMs,
    lastSeenMs: acc.lastSeenMs,
    activeDays: acc.days.size,
    spanHours: Math.max(0, Math.round((acc.lastSeenMs - acc.firstSeenMs) / MS_PER_HOUR)),
    hourHistogram: acc.hourHistogram,
    distinctHours,
    weekendCount: acc.weekendCount,
    weekendFrac,
    concentration: r,
    meanHourUtc: Math.round(meanHour * 10) / 10,
    peakHourUtc,
    classification,
    humanScore,
    severityMax: acc.severityMax,
    blocked: blockStore.has(ip),
    watched: watchStore.has(ip),
    signatureTop: topSignature(acc.signatures),
  };

  // A timezone hypothesis is only meaningful for a daytime-shaped actor.
  if (classification === "operator" || classification === "mixed") {
    const off = estimateOffset(meanHour, middayHour);
    clock.estUtcOffset = off;
    clock.estLocalPeakHour = (((peakHourUtc + off) % 24) + 24) % 24;
    clock.regionHint = regionForOffset(off);
  }

  return clock;
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(
  hours: number,
  analysed: number,
  classCounts: Record<OperatorClass, number>,
  operators: SourceClock[],
  tzHistogram: TimezoneBucket[],
): string[] {
  const out: string[] = [];
  if (analysed === 0) return out;

  const auto = classCounts.automation;
  const ops = classCounts.operator;

  out.push(
    `🕑 Over the last ${hours}h, **${analysed}** source(s) had enough multi-day evidence to fingerprint a ` +
      `clock — **${auto}** look like **🤖 round-the-clock automation**, **${ops}** like **🧑 human operators** ` +
      `on a shift, ${classCounts.mixed} mixed.`,
  );

  // Lead human operator: the strongest attribution signal.
  const lead = operators[0];
  if (lead && lead.estUtcOffset !== undefined) {
    out.push(
      `🧑 Most human-like source \`${lead.ip}\`${lead.watched ? " 👁" : ""}${lead.blocked ? " ⛔" : ""} ` +
        `concentrates ${lead.count} alert(s) into a daytime band (concentration **${lead.concentration.toFixed(2)}**, ` +
        `peak ${hh(lead.peakHourUtc)}:00 UTC) — consistent with an operator around **${offsetLabel(lead.estUtcOffset)} ` +
        `(${lead.regionHint})**, local peak ≈ ${hh(lead.estLocalPeakHour ?? 0)}:00.`,
    );
  }

  // Timezone cluster: the board-level "where are my humans?" line.
  const topTz = tzHistogram[0];
  if (topTz && topTz.operators >= 2) {
    out.push(
      `🌍 Hands-on-keyboard activity clusters at **${offsetLabel(topTz.utcOffset)} (${topTz.regionHint})** — ` +
        `**${topTz.operators}** operator-class source(s), ${topTz.alerts} alert(s). Corroborate against GeoIP / ASN ` +
        `before acting; this is a working-hours hypothesis, not geolocation.`,
    );
  }

  // Weekend-quiet operators: a strong, intuitive human tell.
  const weekendQuiet = operators.filter((o) => o.weekendFrac < 0.05 && o.activeDays >= 5).length;
  if (weekendQuiet > 0) {
    out.push(
      `📅 **${weekendQuiet}** operator-class source(s) go effectively silent on weekends (<5% of activity) — a ` +
        `classic human working-pattern tell that automation does not exhibit.`,
    );
  }

  return out;
}

// ----- markdown --------------------------------------------------------------

/** A compact 24-cell ASCII sparkline of an hour histogram (UTC). */
function hourSparkline(hist: number[]): string {
  const blocks = "▁▂▃▄▅▆▇█";
  const max = Math.max(1, ...hist);
  return hist
    .map((v) =>
      v <= 0 ? "·" : blocks[Math.min(blocks.length - 1, Math.floor((v / max) * (blocks.length - 1)))] ?? "█",
    )
    .join("");
}

function operatorTable(rows: SourceClock[]): string {
  return mdTable(
    ["#", "Source", "Alerts", "Days", "Conc.", "Human", "Peak (UTC)", "Est. TZ", "Local pk", "Wknd", "Flags"],
    rows.map((o, i) => [
      String(i + 1),
      cell(o.ip),
      String(o.count),
      String(o.activeDays),
      o.concentration.toFixed(2),
      o.humanScore.toFixed(2),
      `${hh(o.peakHourUtc)}:00`,
      o.estUtcOffset !== undefined ? `${offsetLabel(o.estUtcOffset)} (${clip(o.regionHint ?? "", 22)})` : "—",
      o.estLocalPeakHour !== undefined ? `${hh(o.estLocalPeakHour)}:00` : "—",
      pct(o.weekendFrac, 0),
      (o.blocked ? "⛔" : "") + (o.watched ? "👁" : "") || "—",
    ]),
  );
}

function automationTable(rows: SourceClock[]): string {
  return mdTable(
    ["#", "Source", "Alerts", "Days", "Hrs/24", "Conc.", "Clock (UTC 00→23)", "Worst", "Flags"],
    rows.map((o, i) => [
      String(i + 1),
      cell(o.ip),
      String(o.count),
      String(o.activeDays),
      String(o.distinctHours),
      o.concentration.toFixed(2),
      "`" + hourSparkline(o.hourHistogram) + "`",
      cell(o.severityMax),
      (o.blocked ? "⛔" : "") + (o.watched ? "👁" : "") || "—",
    ]),
  );
}

function timezoneTable(buckets: TimezoneBucket[]): string {
  const maxOps = Math.max(1, ...buckets.map((b) => b.operators));
  return mdTable(
    ["UTC offset", "Region (hypothesis)", "Operators", "Alerts", ""],
    buckets.map((b) => [
      cell(offsetLabel(b.utcOffset)),
      cell(b.regionHint),
      String(b.operators),
      String(b.alerts),
      "█".repeat(Math.max(1, Math.round((b.operators / maxOps) * 12))),
    ]),
  );
}

function renderMarkdown(m: PatternsReport): string {
  const lines: string[] = [];
  lines.push(`# 🕑 SecTool Attacker Patterns-of-Life / Operating-Hours Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** each external source's detections are folded onto a **24-hour UTC clock**; the **circular ` +
      `concentration** R (0 = smeared across the clock → automation, → 1 = a tight daytime band → a human shift), ` +
      `the **weekend share**, and the **active-day count** classify it. For operator-shaped sources a **UTC offset** ` +
      `is estimated by sliding the activity centre onto local ~${hh(m.assumedMiddayHour)}:00. Offline, deterministic, ` +
      `time-of-day based · **Window alerts:** ${m.totalWindowAlerts} · **Sources:** ${m.distinctSources} ` +
      `(${m.analysedSources} with enough multi-day evidence to fingerprint)`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (m.analysedSources === 0) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) from ${m.distinctSources} external source(s) in the last ${m.hours} ` +
          `hour(s), but none were active on enough distinct days (or carried enough volume) for a daily clock ` +
          `to be measurable. Widen the window — a working-hours rhythm needs several days to emerge.`,
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

  // Class breakdown at a glance.
  lines.push(`## Classification at a glance`);
  lines.push("");
  lines.push(
    mdTable(
      ["Class", "Sources", "What it means"],
      [
        [classLabel("automation"), String(m.classCounts.automation), "Round-the-clock / every day — block & rate-limit; profiling the clock won't help."],
        [classLabel("operator"), String(m.classCounts.operator), "A concentrated daytime shift — a person at a keyboard; timezone is estimable."],
        [classLabel("mixed"), String(m.classCounts.mixed), "A daytime lean over a broad base — semi-automated or a shared IP."],
        [classLabel("transient"), String(m.classCounts.transient), "Too little multi-day evidence to call (excluded from the tables)."],
      ],
    ),
  );
  lines.push("");

  // Human operators.
  lines.push(`## 🧑 Human-operator candidates`);
  lines.push("");
  if (m.operators.length) {
    lines.push(
      `Sources whose activity clusters into a daytime band — the most attributable adversaries. _Conc._ = circular ` +
        `concentration (→1 = tighter shift); _Human_ = clustering + weekday-skew score; _Est. TZ_ = the UTC offset ` +
        `that lands their activity centre on a typical work day; _Wknd_ = share of activity on Sat/Sun.`,
    );
    lines.push("");
    lines.push(operatorTable(m.operators));
  } else {
    lines.push(`_No source's clock was concentrated enough into a daytime band to look operator-driven._`);
  }
  lines.push("");

  // Automation.
  lines.push(`## 🤖 Automation / round-the-clock sources`);
  lines.push("");
  if (m.automation.length) {
    lines.push(
      `Sources smeared across the whole clock — bots and infrastructure with no human rhythm. The sparkline is the ` +
        `24-hour UTC histogram (\`·\` = idle hour, taller = busier). These are **block / rate-limit / geo-policy** ` +
        `targets, not attribution targets.`,
    );
    lines.push("");
    lines.push(automationTable(m.automation));
  } else {
    lines.push(`_No round-the-clock automation sources in this window._`);
  }
  lines.push("");

  // Timezone histogram.
  lines.push(`## 🌍 Estimated operator timezones`);
  lines.push("");
  if (m.timezoneHistogram.length) {
    lines.push(
      `Operator-class sources rolled up by estimated UTC offset — *where your hands-on-keyboard adversaries appear ` +
        `to work from*. A **hypothesis** from working-hours shape, not geolocation: corroborate against GeoIP / ASN.`,
    );
    lines.push("");
    lines.push(timezoneTable(m.timezoneHistogram));
  } else {
    lines.push(`_No operator-class sources to attribute a timezone to._`);
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. The timezone estimate **assumes a daytime worker** — night-shift operators, ` +
      `follow-the-sun teams and deliberately time-shifted campaigns will fool it; it corroborates GeoIP / ASN, it ` +
      `does not replace them. These are IPS **detections**, not presence: a source only looks "awake" at an hour if ` +
      `it tripped a signature then, so the active band is a lower bound. NAT / shared egress can smear many real ` +
      `actors onto one clock (over-stating "automation"); a rotating botnet can split one operator across many IPs ` +
      `(hiding the human shape). A long look-back can hit the alert store's history cap and clip the tail. No live ` +
      `gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the attacker patterns-of-life / operating-hours report from the stored
 * alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]). A multi-day
 *              window is required for a daily rhythm to be measurable at all.
 * @param opts  {@link PatternsOptions}: evidence bars (`minAlerts`,
 *              `minActiveDays`), row `limit`, the `assumedMiddayHour` anchor, and
 *              a `nowMs` pin for deterministic tests.
 */
export function buildPatterns(hours: number, opts: PatternsOptions = {}): PatternsReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const minAlerts = Math.max(3, Math.min(1000, Math.floor(opts.minAlerts ?? DEFAULT_MIN_ALERTS)));
  const minActiveDays = Math.max(1, Math.min(31, Math.floor(opts.minActiveDays ?? DEFAULT_MIN_ACTIVE_DAYS)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const middayHour = Math.max(9, Math.min(17, Math.floor(opts.assumedMiddayHour ?? DEFAULT_MIDDAY_HOUR)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  // Aggregate per external source.
  const bySrc = new Map<string, SrcAcc>();
  for (const a of windowed) {
    const ip = externalIp(a.srcIp);
    if (!ip) continue;
    let acc = bySrc.get(ip);
    if (!acc) {
      acc = newSrcAcc(a.time);
      bySrc.set(ip, acc);
    }
    bump(acc, a);
  }

  // Classify the sources that clear the evidence bar.
  const clocks: SourceClock[] = [];
  for (const [ip, acc] of bySrc) {
    if (acc.count < minAlerts || acc.days.size < minActiveDays) continue;
    clocks.push(summariseSource(ip, acc, middayHour));
  }

  const classCounts: Record<OperatorClass, number> = {
    automation: 0,
    operator: 0,
    mixed: 0,
    // Sources seen in the window but below the evidence bar — excluded from the
    // tables but surfaced here so the breakdown reconciles to distinctSources.
    transient: Math.max(0, bySrc.size - clocks.length),
  };
  for (const c of clocks) classCounts[c.classification]++;

  // Operator leaderboard: most human-like first.
  const operators = clocks
    .filter((c) => c.classification === "operator")
    .sort((a, b) => b.humanScore - a.humanScore || b.count - a.count || (a.ip < b.ip ? -1 : 1))
    .slice(0, limit);

  // Automation leaderboard: heaviest first.
  const automation = clocks
    .filter((c) => c.classification === "automation")
    .sort((a, b) => b.count - a.count || (a.ip < b.ip ? -1 : 1))
    .slice(0, limit);

  // Timezone histogram over ALL operator-class sources (not just the capped table).
  const tzAcc = new Map<number, { operators: number; alerts: number }>();
  for (const c of clocks) {
    if (c.classification !== "operator" || c.estUtcOffset === undefined) continue;
    const e = tzAcc.get(c.estUtcOffset) ?? { operators: 0, alerts: 0 };
    e.operators++;
    e.alerts += c.count;
    tzAcc.set(c.estUtcOffset, e);
  }
  const timezoneHistogram: TimezoneBucket[] = [...tzAcc.entries()]
    .map(([utcOffset, e]) => ({
      utcOffset,
      regionHint: regionForOffset(utcOffset),
      operators: e.operators,
      alerts: e.alerts,
    }))
    .sort((a, b) => b.operators - a.operators || b.alerts - a.alerts || a.utcOffset - b.utcOffset)
    .slice(0, limit);

  const highlights = writeHighlights(safeHours, clocks.length, classCounts, operators, timezoneHistogram);

  const model: PatternsReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    distinctSources: bySrc.size,
    analysedSources: clocks.length,
    assumedMiddayHour: middayHour,
    classCounts,
    operators,
    automation,
    timezoneHistogram,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded patterns-of-life report. */
export function patternsFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-patterns-${stamp}.md`;
}
