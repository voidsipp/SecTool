/**
 * Beaconing / periodicity report — "which talkers tick like a clock?"
 *
 * Command-and-control malware almost never streams traffic; it *checks in*. An
 * implant wakes on a fixed cadence — every 60s, every 5m, every hour — asks its
 * controller for orders, and goes quiet. That regular heartbeat is one of the
 * most reliable behavioural tells in network defence: humans and legitimate apps
 * produce bursty, irregular traffic, while a beacon produces evenly-spaced events
 * with very little jitter. RITA, Zeek, and most SOC playbooks hunt for exactly
 * this shape.
 *
 * None of the existing offline reports surface it:
 *
 *   - rhythm.ts folds the whole alert history onto *hour-of-day / day-of-week*
 *     axes. That answers "when are we busy?", not "is this one src→dst pair
 *     firing on a fixed interval?". A 5-minute beacon is invisible in a 24-bucket
 *     hour histogram — it just looks like steady all-day activity.
 *   - trends.ts / report.ts rank by raw volume; a low-and-slow beacon that fires
 *     12 times a day is buried under a noisy scanner.
 *   - campaigns.ts / killchain.ts group by actor and stage, not by *timing
 *     regularity*.
 *
 * This module groups the windowed alert history into src→dst conversations,
 * computes the inter-arrival intervals for each, and scores how *regular* those
 * intervals are. A conversation is flagged **beacon-like** when it has enough
 * repetitions, a sane period, and low jitter (its intervals cluster tightly
 * around their median). For each candidate it reports the estimated period, the
 * jitter, a 0–100 regularity score, the worst severity seen, and the dominant
 * signature for context.
 *
 * Honest caveats it bakes into the output:
 *
 *   - **Alert times, not flow times.** SecTool stores IPS *alerts*, not every
 *     packet. A pair only beacons "visibly" here if each check-in trips a
 *     signature. The cadence is therefore a lower bound on the true beacon rate,
 *     and the report says so.
 *   - **Coarse clock.** Syslog timestamps are second-resolution at best, so very
 *     fast beacons (<~10s) and jitter below that floor can't be distinguished.
 *   - **Few samples lie.** Three evenly-spaced events can be coincidence. The
 *     report needs a minimum repetition count and discounts thin candidates in
 *     its confidence wording rather than crying "C2" on a handful of hits.
 *
 * It is pure in-memory math over alertStore — no SSH, no Claude, no network — so
 * it is safe to call from the dashboard or CLI at any time. Output is both a
 * structured model and a ready-to-paste Markdown document, mirroring report.ts,
 * compare.ts, profile.ts, assets.ts, tuning.ts, watchlist.ts, rhythm.ts and
 * novelty.ts.
 */
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** One src→dst conversation scored for periodic (beacon-like) behaviour. */
export interface BeaconCandidate {
  srcIp: string;
  dstIp: string;
  /** Total windowed alerts between this pair (≥ {@link BeaconOptions.minHits}). */
  count: number;
  /** ms epoch of the first occurrence inside the window. */
  firstSeenMs: number;
  /** ms epoch of the most recent occurrence inside the window. */
  lastSeenMs: number;
  /** Estimated beacon period in seconds (the median inter-arrival interval). */
  periodSeconds: number;
  /** Mean inter-arrival interval in seconds (sensitive to gaps; for contrast). */
  meanSeconds: number;
  /**
   * Jitter as a percentage: the median absolute deviation of intervals divided
   * by the median interval, ×100. 0% = a perfect metronome; high = irregular.
   */
  jitterPct: number;
  /**
   * Regularity score 0–100 (100 = perfectly periodic). Derived from jitter and
   * discounted when there are few intervals to judge.
   */
  regularityScore: number;
  /** True when this pair clears the beacon-like bar (regular + enough samples). */
  beaconLike: boolean;
  /** Worst severity observed across this pair's occurrences. */
  severityMax: Severity;
  /** Occurrences at medium severity or above. */
  severeCount: number;
  /** Occurrences whose action was an active block. */
  blockedCount: number;
  /** The dominant signature for this pair, for context (may be empty). */
  topSignature: string;
}

export interface BeaconReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Distinct src→dst pairs observed in the window. */
  distinctPairs: number;
  /** Pairs with enough repetitions to assess periodicity at all. */
  assessablePairs: number;
  /** How many assessable pairs were flagged beacon-like. */
  beaconCount: number;
  /** Candidates, ranked best-beacon-first and truncated to the report limit. */
  candidates: BeaconCandidate[];
  /** True when {@link candidates} was truncated by the limit. */
  truncated: boolean;
  /** Plain-language call-outs about the report as a whole. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface BeaconOptions {
  /** Max candidates to list (clamped to [1, 500]). */
  limit?: number;
  /** Min occurrences for a pair to be assessable (clamped to [3, 1000]). */
  minHits?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 25;
const DEFAULT_MIN_HITS = 4;
/** Regularity at/above this is "beacon-like" (jitter roughly ≤ a quarter period). */
const BEACON_SCORE_THRESHOLD = 70;
/** Periods outside this band are usually noise (too fast) or too sparse to trust. */
const MIN_SANE_PERIOD_SEC = 10;
const MAX_SANE_PERIOD_SEC = 24 * 3600;

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

// ----- statistics helpers -----

/** Median of a numeric array (assumed non-empty); does not mutate the input. */
function median(values: number[]): number {
  const s = [...values].sort((a, b) => a - b);
  const mid = s.length >> 1;
  return s.length % 2 ? s[mid]! : (s[mid - 1]! + s[mid]!) / 2;
}

function mean(values: number[]): number {
  return values.reduce((n, v) => n + v, 0) / values.length;
}

/** Median absolute deviation about the median — a robust jitter measure. */
function mad(values: number[], med: number): number {
  return median(values.map((v) => Math.abs(v - med)));
}

// ----- formatting helpers (mirror rhythm.ts / novelty.ts / assets.ts) -----

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** A compact relative-age label like "3h" / "2d" for the most-recent column. */
function fmtAge(ms: number, nowMs: number): string {
  const sec = Math.max(0, Math.round((nowMs - ms) / 1000));
  if (sec < 90) return `${sec}s`;
  const min = Math.round(sec / 60);
  if (min < 90) return `${min}m`;
  const hr = Math.round(min / 60);
  if (hr < 48) return `${hr}h`;
  return `${Math.round(hr / 24)}d`;
}

/** A human period label like "45s" / "5m" / "1h2m" / "2h" for the cadence column. */
function fmtPeriod(sec: number): string {
  if (sec < 1) return "<1s";
  if (sec < 90) return `${Math.round(sec)}s`;
  const totalMin = Math.round(sec / 60);
  if (totalMin < 90) return `${totalMin}m`;
  const hr = Math.floor(totalMin / 60);
  const min = totalMin % 60;
  return min ? `${hr}h${min}m` : `${hr}h`;
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
function clip(s: string, max = 48): string {
  const t = s.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

/**
 * Internal accumulator for one src→dst pair while we fold the window. Holds the
 * occurrence timestamps (for interval analysis) plus the small tallies needed to
 * render severity, blocking, and a dominant-signature context cell.
 */
interface Accum {
  srcIp: string;
  dstIp: string;
  times: number[];
  severityMax: Severity;
  severeCount: number;
  blockedCount: number;
  sigCounts: Map<string, number>;
}

function bump(map: Map<string, number>, key: string | undefined): void {
  if (!key) return;
  map.set(key, (map.get(key) ?? 0) + 1);
}

/** Most frequent key in a tally, ties broken by lexical order for stability. */
function topKey(map: Map<string, number>): string {
  let best = "";
  let bestN = -1;
  for (const [k, n] of map) {
    if (n > bestN || (n === bestN && k < best)) {
      best = k;
      bestN = n;
    }
  }
  return best;
}

/**
 * Score how beacon-like a series of timestamps is. Returns the period (median
 * interval), mean interval, jitter%, and a 0–100 regularity score.
 *
 * Regularity is driven by the robust jitter ratio `mad/median`: a metronome has
 * ratio 0 → score 100, while ratio ≥ 1 (deviation as large as the period) → 0.
 * The raw score is then multiplied by a confidence factor that ramps from a thin
 * `minIntervals` sample up to full trust once there are plenty of intervals, so a
 * lucky run of three evenly-spaced events can't masquerade as a hardened beacon.
 */
function scoreSeries(
  sortedTimes: number[],
  minIntervals: number,
): { periodSeconds: number; meanSeconds: number; jitterPct: number; regularityScore: number } {
  const intervalsMs: number[] = [];
  for (let i = 1; i < sortedTimes.length; i++) intervalsMs.push(sortedTimes[i]! - sortedTimes[i - 1]!);
  const medMs = median(intervalsMs);
  const meanMs = mean(intervalsMs);
  const periodSeconds = Math.round((medMs / 1000) * 100) / 100;
  const meanSeconds = Math.round((meanMs / 1000) * 100) / 100;

  // Jitter ratio: robust deviation relative to the period. Guard a zero median
  // (≥2 identical sub-second timestamps) by treating it as maximally jittery.
  const madMs = mad(intervalsMs, medMs);
  const jitterRatio = medMs > 0 ? madMs / medMs : 1;
  const jitterPct = Math.round(Math.min(jitterRatio, 9.99) * 100);

  const tightness = Math.max(0, 1 - Math.min(jitterRatio, 1));
  // Confidence ramps from the minimum interval count to a comfortable sample of
  // ~12 intervals (≈13 hits) before we fully trust the regularity signal.
  const confidence = Math.max(0, Math.min(1, (intervalsMs.length - (minIntervals - 1)) / (12 - (minIntervals - 1))));
  const blended = 0.5 + 0.5 * confidence; // never discount a clean signal below half
  const regularityScore = Math.round(tightness * 100 * blended);

  return { periodSeconds, meanSeconds, jitterPct, regularityScore };
}

/** Sort candidates: beacon-like first, then by regularity, then by volume. */
function rankCandidates(items: BeaconCandidate[]): BeaconCandidate[] {
  return items.sort((x, y) => {
    if (x.beaconLike !== y.beaconLike) return x.beaconLike ? -1 : 1;
    if (y.regularityScore !== x.regularityScore) return y.regularityScore - x.regularityScore;
    if (y.count !== x.count) return y.count - x.count;
    return x.firstSeenMs - y.firstSeenMs;
  });
}

function writeHighlights(m: Omit<BeaconReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (!m.totalWindowAlerts) return out;

  if (!m.assessablePairs) {
    out.push(
      `No src→dst pair fired enough times in the last ${m.hours}h to assess periodicity ` +
        `(need ≥ the minimum repetition count). Nothing to score.`,
    );
    return out;
  }

  if (!m.beaconCount) {
    out.push(
      `Assessed ${m.assessablePairs} repeating pair(s) over the last ${m.hours}h — none show a regular, ` +
        `low-jitter cadence. No beacon-like behaviour detected.`,
    );
    return out;
  }

  out.push(
    `🚨 ${m.beaconCount} of ${m.assessablePairs} repeating pair(s) tick on a regular cadence (≥ ${BEACON_SCORE_THRESHOLD}/100 ` +
      `regularity) — the classic shape of C2 beaconing. Investigate the top rows first.`,
  );

  const top = m.candidates.find((c) => c.beaconLike);
  if (top) {
    out.push(
      `Strongest beacon: \`${top.srcIp}\` → \`${top.dstIp}\` every ~${fmtPeriod(top.periodSeconds)} ` +
        `(±${top.jitterPct}% jitter, ${top.count} hits, score ${top.regularityScore}/100` +
        `${top.severityMax !== "info" ? `, peak ${top.severityMax}` : ""}).`,
    );
  }

  const severe = m.candidates.filter((c) => c.beaconLike && isSevere(c.severityMax)).length;
  if (severe) {
    out.push(`${severe} beacon-like pair(s) also carry a medium-or-worse signature — treat as likely active C2.`);
  }
  return out;
}

function renderMarkdown(m: BeaconReport): string {
  const lines: string[] = [];
  lines.push(`# 📡 SecTool Beaconing / Periodicity Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Pairs:** ${m.distinctPairs} distinct · ${m.assessablePairs} repeating · **${m.beaconCount} beacon-like** · ` +
      `**Window alerts:** ${m.totalWindowAlerts}`,
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

  lines.push(`## Candidates (ranked)`);
  lines.push("");
  if (!m.candidates.length) {
    lines.push(`_None — no repeating src→dst pair met the minimum repetition count this window._`);
    lines.push("");
  } else {
    lines.push(
      mdTable(
        ["", "Source → Dest", "Hits", "Period", "Jitter", "Score", "First seen", "Last", "Peak", "Top signature"],
        m.candidates.map((c) => [
          c.beaconLike ? "📡" : "·",
          `${cell(c.srcIp)} → ${cell(c.dstIp)}`,
          String(c.count),
          fmtPeriod(c.periodSeconds),
          `${c.jitterPct}%`,
          String(c.regularityScore),
          fmtTime(c.firstSeenMs),
          fmtAge(c.lastSeenMs, m.windowEndMs),
          cell(c.severityMax),
          c.topSignature ? cell(clip(c.topSignature)) : "—",
        ]),
      ),
    );
    if (m.truncated) {
      lines.push("");
      lines.push(`_…and ${m.assessablePairs - m.candidates.length} more pair(s) not shown (raise \`limit\`)._`);
    }
    lines.push("");
    lines.push(
      `**Legend:** 📡 = beacon-like (regularity ≥ ${BEACON_SCORE_THRESHOLD}/100). _Period_ is the median interval between ` +
        `hits; _Jitter_ is how much intervals wander around it (0% = a perfect metronome); _Score_ blends low jitter with ` +
        `having enough samples to trust it.`,
    );
    lines.push("");
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Cadence is measured from stored **IPS-alert** timestamps (second-resolution), not ` +
      `from every packet, so the true beacon rate may be faster than shown and very fast beacons (<~10s) cannot be ` +
      `distinguished. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the beaconing / periodicity report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link BeaconOptions}: `limit`, `minHits`, and a `nowMs` pin.
 */
export function buildBeacon(hours: number, opts: BeaconOptions = {}): BeaconReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(500, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minHits = Math.max(3, Math.min(1000, Math.floor(opts.minHits ?? DEFAULT_MIN_HITS)));
  const minIntervals = minHits - 1;
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * 3_600_000;

  const all = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time));

  // Fold the window into src→dst conversations. A pair needs both endpoints.
  const pairs = new Map<string, Accum>();
  let totalWindowAlerts = 0;
  for (const a of all) {
    if (a.time < windowStartMs || a.time > windowEndMs) continue;
    totalWindowAlerts++;
    if (!a.srcIp || !a.dstIp) continue;
    const key = `${a.srcIp}|${a.dstIp}`;
    let e = pairs.get(key);
    if (!e) {
      e = {
        srcIp: a.srcIp,
        dstIp: a.dstIp,
        times: [],
        severityMax: "info",
        severeCount: 0,
        blockedCount: 0,
        sigCounts: new Map(),
      };
      pairs.set(key, e);
    }
    e.times.push(a.time);
    e.severityMax = maxSeverity(e.severityMax, a.severity);
    if (isSevere(a.severity)) e.severeCount++;
    if (isBlocked(a.action)) e.blockedCount++;
    bump(e.sigCounts, a.signature);
  }

  const distinctPairs = pairs.size;
  let assessablePairs = 0;
  let beaconCount = 0;
  const candidates: BeaconCandidate[] = [];

  for (const e of pairs.values()) {
    if (e.times.length < minHits) continue;
    assessablePairs++;
    const times = [...e.times].sort((x, y) => x - y);
    const { periodSeconds, meanSeconds, jitterPct, regularityScore } = scoreSeries(times, minIntervals);

    const saneCadence = periodSeconds >= MIN_SANE_PERIOD_SEC && periodSeconds <= MAX_SANE_PERIOD_SEC;
    const beaconLike = saneCadence && regularityScore >= BEACON_SCORE_THRESHOLD;
    if (beaconLike) beaconCount++;

    candidates.push({
      srcIp: e.srcIp,
      dstIp: e.dstIp,
      count: e.times.length,
      firstSeenMs: times[0]!,
      lastSeenMs: times[times.length - 1]!,
      periodSeconds,
      meanSeconds,
      jitterPct,
      regularityScore,
      beaconLike,
      severityMax: e.severityMax,
      severeCount: e.severeCount,
      blockedCount: e.blockedCount,
      topSignature: topKey(e.sigCounts),
    });
  }

  const ranked = rankCandidates(candidates);

  const base: Omit<BeaconReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts,
    distinctPairs,
    assessablePairs,
    beaconCount,
    candidates: ranked.slice(0, limit),
    truncated: ranked.length > limit,
  };
  const highlights = writeHighlights(base);
  const model: BeaconReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded beaconing report. */
export function beaconFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-beacon-${stamp}.md`;
}
