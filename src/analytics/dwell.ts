/**
 * Source dwell-time & engagement-session report — "how long is each attacker
 * *camped* on me, and is its activity one sustained sitting or many separate
 * visits?"
 *
 * Every temporal report in this project already exists, yet none answers the
 * *engagement-structure* question:
 *
 *   - rhythm.ts folds all alerts into a **global** hour-of-day / day-of-week
 *     heatmap — when the *network as a whole* is busy, blind to any single actor.
 *   - surge.ts finds **volume spikes** — the moments the firehose widened, not how
 *     long any one source stuck around.
 *   - beacon.ts hunts **regular fixed-interval** pings (a C2 heartbeat's *cadence
 *     regularity*) — it rewards metronomic timing, and an attacker that camps hard
 *     for an hour then leaves is invisible to it because nothing is periodic.
 *   - persistence.ts counts the **distinct days** a source reappears across a long
 *     look-back ("who keeps coming back?") — day-granularity longevity, not the
 *     fine structure of a single window's engagement.
 *   - recurrence.ts **forecasts** the next return; novelty.ts flags **first-seen**.
 *
 * None of them segment a single source's alert timeline into **sessions** and ask
 * the responder's first triage question about an active actor: *is this one
 * sustained sitting (camped, hands-on, working a target right now) or a thin
 * scatter of drive-by touches across the week (background noise)?* Two sources
 * with the **same alert count and the same first/last timestamps** can be a solid
 * three-hour intrusion or twelve one-second pokes spread over six days — opposite
 * threats that every count- and span-based report renders identically. The
 * difference lives in the **gaps**, which no existing report measures.
 *
 * For every source IP over the window this report sorts its alert timestamps and
 * **sessionises** them: a new session begins whenever the idle gap from the prior
 * alert exceeds a threshold (default 30 min). From the sessions it derives:
 *
 *   - **Dwell span** — first-seen → last-seen elapsed (how wide a footprint in
 *     time the source holds).
 *   - **Sessions** — how many distinct sittings the activity breaks into.
 *   - **Longest / mean session** — the depth of the deepest sitting.
 *   - **Active time & duty cycle** — Σ session durations, and that as a fraction
 *     of the dwell span. A high duty cycle means the source was *present* for most
 *     of the span (a continuous camp); a low one means it touched briefly and
 *     vanished, again and again, across a long quiet stretch.
 *   - **Max idle gap** — the longest silence between sittings.
 *
 * From those it assigns a one-word **engagement pattern**:
 *
 *   - **🔥 sustained** — one long continuous sitting, or many tightly-packed ones
 *     covering most of a non-trivial span (duty cycle ≥ 50%): camped on you *now*,
 *     the single highest-priority thing to look at.
 *   - **🔁 intermittent** — three or more separated sittings: a returner that keeps
 *     coming back through the window (low-and-slow, or a scheduled job / beacon
 *     whose interval is too ragged for the beacon report).
 *   - **• sporadic** — a couple of touches spread thin across a wide span: present
 *     in name only, occasional drive-by contact.
 *   - **⚡ transient** — a single short burst then gone: a one-off scan or probe.
 *
 * Sources are ranked by a 0–100 **engagement score** (dwell span as a fraction of
 * the window, duty cycle, number of return sittings, worst severity) so the source
 * most *entrenched in time* floats to the top — deliberately a different axis from
 * the volume-, reach- and breadth-ranked reports, surfacing the quiet long camp
 * that a top-by-count table buries.
 *
 * Honest caveats baked into the output:
 *
 *   - **Detections, not presence.** SecTool stores IPS *detections*. A gap is a
 *     gap in *alerting*, not proof the source was absent — it may have been active
 *     but tripping no rule. Dwell span is therefore a lower bound and the duty
 *     cycle an under-estimate; a quiet, careful operator can read as "sporadic".
 *   - **The gap threshold is a heuristic.** 30 min is a reasonable default for
 *     splitting sittings, but it is a knob (`--gap`); a different value re-segments
 *     the timeline, so the raw span and alert count are always shown alongside.
 *   - **Single-alert sources have zero-duration sessions.** One alert is a point in
 *     time, not a sitting; such sources read as `transient` with a 0s span.
 *   - **Window-bounded & store-capped.** A long look-back can hit the alert store's
 *     history cap and clip the earliest sessions, shrinking the measured dwell.
 *
 * Pure in-memory math over alertStore (plus blocklist / watchlist / safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring repertoire.ts, scan.ts,
 * killchain.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** The four engagement patterns a source's session structure can fall into. */
export type DwellPattern = "sustained" | "intermittent" | "sporadic" | "transient";

/** A single contiguous sitting (run of alerts with no gap longer than the threshold). */
export interface DwellSession {
  /** ms epoch of the first alert in the sitting. */
  startMs: number;
  /** ms epoch of the last alert in the sitting. */
  endMs: number;
  /** Sitting duration in ms (`endMs - startMs`, 0 for a single-alert sitting). */
  durationMs: number;
  /** Alerts that fell inside this sitting. */
  count: number;
}

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
   * null when nothing was actioned. High on a long-camping source means its
   * sustained activity is reaching your hosts unblocked.
   */
  passRate: number | null;
}

/** Per-source dwell / engagement metrics over the window. */
export interface DwellSource {
  /** The source IP. */
  ip: string;
  /** True when the source is one of our own hosts (RFC1918 / loopback / …). */
  internal: boolean;
  /** The assigned engagement pattern (see {@link DwellPattern}). */
  pattern: DwellPattern;
  /** 0–100 engagement score — the ranking key. */
  engagement: number;
  /** ms epoch of the source's first alert in the window. */
  firstSeenMs: number;
  /** ms epoch of the source's last alert in the window. */
  lastSeenMs: number;
  /** Dwell span: `lastSeenMs - firstSeenMs` (0 when all alerts share an instant). */
  dwellMs: number;
  /** Number of distinct sittings the timeline broke into. */
  sessionCount: number;
  /** Duration of the longest single sitting, ms. */
  longestSessionMs: number;
  /** Mean sitting duration, ms. */
  meanSessionMs: number;
  /** Σ of all sitting durations (time the source was demonstrably engaged), ms. */
  activeMs: number;
  /**
   * Duty cycle: `activeMs / dwellMs`, 0..1 (4dp) — how much of the dwell span the
   * source was present for. Null when the span is zero (a single instant).
   */
  dutyCycle: number | null;
  /** Longest idle gap between successive sittings, ms (0 with a single sitting). */
  maxGapMs: number;
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
  /** The most-frequent signature for this source, if any. */
  topSignature?: string;
  /** Blocked / passed / unknown disposition split. */
  disposition: DispositionSplit;
  /** The source is on the blocklist. */
  blocked: boolean;
  /** The source is on the watchlist. */
  watched: boolean;
  /** The source is marked safe. */
  safe: boolean;
}

/** Count of sources falling into each pattern (the headline distribution). */
export interface PatternCounts {
  sustained: number;
  intermittent: number;
  sporadic: number;
  transient: number;
}

export interface DwellReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** The idle-gap threshold (ms) used to split sittings. */
  gapMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts carrying a valid source IP (the analysable set). */
  sourcedAlerts: number;
  /** Distinct source IPs analysed (passed the min-alerts floor). */
  distinctSources: number;
  /** How many sources fell into each pattern. */
  patternCounts: PatternCounts;
  /** Per-source dwell rows, most entrenched first. */
  sources: DwellSource[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface DwellOptions {
  /** Max rows in the per-source table (clamped to [1, 200]). */
  limit?: number;
  /** Minimum alerts a source needs before it is analysed (drops one-off noise). */
  minAlerts?: number;
  /** Idle-gap threshold in minutes that splits sittings (clamped to [1, 1440]). */
  gapMinutes?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const DEFAULT_MIN_ALERTS = 2;
const DEFAULT_GAP_MINUTES = 30;
const MS_PER_HOUR = 3_600_000;
const MS_PER_MIN = 60_000;

/** Duty cycle at/above which a multi-sitting source counts as a continuous camp. */
const SUSTAINED_DUTY = 0.5;
/** Sittings at/above which a low-duty source counts as a repeat returner. */
const INTERMITTENT_MIN_SESSIONS = 3;

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

function pct(frac: number): string {
  return `${Math.round(frac * 100)}%`;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/**
 * Compact human duration, e.g. "0s", "45s", "8m", "5h 12m", "3d 4h". Shows the two
 * most significant units so the table stays narrow but readable.
 */
function fmtDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return "0s";
  const s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (d > 0) return h > 0 ? `${d}d ${h}h` : `${d}d`;
  if (h > 0) return m > 0 ? `${h}h ${m}m` : `${h}h`;
  if (m > 0) return sec > 0 ? `${m}m ${sec}s` : `${m}m`;
  return `${sec}s`;
}

/** Relative "… ago" for a past instant, anchored to the window end. */
function fmtAgo(ms: number, nowMs: number): string {
  const delta = nowMs - ms;
  if (delta < 0) return "just now";
  return `${fmtDuration(delta)} ago`;
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

/** Human label + emoji for a pattern, ordered by engagement intensity. */
function patternLabel(p: DwellPattern): string {
  switch (p) {
    case "sustained":
      return "🔥 sustained";
    case "intermittent":
      return "🔁 intermittent";
    case "sporadic":
      return "• sporadic";
    case "transient":
      return "⚡ transient";
  }
}

/**
 * Assign an engagement pattern from the session structure. A single sitting is
 * `sustained` only when it spans more than the gap threshold (a genuine camp),
 * else `transient`. Multiple sittings are `sustained` when the source was present
 * for most of the span (duty ≥ 50%), `intermittent` when it keeps returning
 * (≥3 sittings), else `sporadic` (a thin scatter across a wide span).
 */
function classifyPattern(
  sessionCount: number,
  dwellMs: number,
  dutyCycle: number | null,
  gapMs: number,
): DwellPattern {
  if (sessionCount <= 1) return dwellMs > gapMs ? "sustained" : "transient";
  if (dutyCycle !== null && dutyCycle >= SUSTAINED_DUTY) return "sustained";
  if (sessionCount >= INTERMITTENT_MIN_SESSIONS) return "intermittent";
  return "sporadic";
}

/**
 * Compute the 0–100 engagement score. Weights (max contribution): dwell span as a
 * fraction of the whole window 40, duty cycle 30, number of return sittings 20,
 * worst severity 10 — summing to 100 at full saturation. Volume is deliberately
 * absent so a quiet long camp outranks a loud single burst; this is the
 * time-entrenchment axis, distinct from the count/reach/breadth rankings.
 */
function engagementScore(
  dwellMs: number,
  windowMs: number,
  dutyCycle: number | null,
  sessionCount: number,
  severityMax: Severity,
): number {
  const spanPts = (windowMs > 0 ? Math.min(dwellMs / windowMs, 1) : 0) * 40;
  const dutyPts = (dutyCycle ?? 0) * 30;
  const returnPts = Math.min(sessionCount / 10, 1) * 20;
  const sevPts = (sevRank(severityMax) / (SEVERITY_ORDER.length - 1)) * 10;
  return Math.max(0, Math.min(100, Math.round(spanPts + dutyPts + returnPts + sevPts)));
}

// ----- aggregation ----------------------------------------------------------

interface SourceAcc {
  times: number[];
  count: number;
  score: number;
  severe: number;
  hosts: Set<string>;
  sigCounts: Map<string, number>;
  blocked: number;
  passed: number;
  unknown: number;
  severityMax: Severity;
}

function newSourceAcc(): SourceAcc {
  return {
    times: [],
    count: 0,
    score: 0,
    severe: 0,
    hosts: new Set(),
    sigCounts: new Map(),
    blocked: 0,
    passed: 0,
    unknown: 0,
    severityMax: "info",
  };
}

/**
 * Break a sorted ascending list of alert timestamps into sittings, splitting on
 * any idle gap longer than `gapMs`, and reduce them to the dwell metrics used by
 * the report.
 */
function sessionize(
  sortedTimes: number[],
  gapMs: number,
): {
  sessions: DwellSession[];
  longestSessionMs: number;
  meanSessionMs: number;
  activeMs: number;
  maxGapMs: number;
} {
  const sessions: DwellSession[] = [];
  if (!sortedTimes.length) {
    return { sessions, longestSessionMs: 0, meanSessionMs: 0, activeMs: 0, maxGapMs: 0 };
  }

  let start = sortedTimes[0]!;
  let prev = sortedTimes[0]!;
  let countInSession = 1;
  let maxGapMs = 0;

  const flush = (end: number) => {
    sessions.push({ startMs: start, endMs: end, durationMs: end - start, count: countInSession });
  };

  for (let i = 1; i < sortedTimes.length; i++) {
    const t = sortedTimes[i]!;
    const gap = t - prev;
    if (gap > gapMs) {
      flush(prev);
      if (gap > maxGapMs) maxGapMs = gap;
      start = t;
      countInSession = 1;
    } else {
      countInSession++;
    }
    prev = t;
  }
  flush(prev);

  let activeMs = 0;
  let longestSessionMs = 0;
  for (const s of sessions) {
    activeMs += s.durationMs;
    if (s.durationMs > longestSessionMs) longestSessionMs = s.durationMs;
  }
  const meanSessionMs = sessions.length ? Math.round(activeMs / sessions.length) : 0;

  return { sessions, longestSessionMs, meanSessionMs, activeMs, maxGapMs };
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  gapMs: number,
  windowEndMs: number,
  m: { distinctSources: number; sourcedAlerts: number },
  patternCounts: PatternCounts,
  sources: DwellSource[],
): string[] {
  const out: string[] = [];
  if (!sources.length) return out;

  const camped = patternCounts.sustained + patternCounts.intermittent;
  out.push(
    `🕒 Over the last ${hours}h, **${m.distinctSources} source(s)** were active; **${camped}** show *real ` +
      `engagement* (${patternCounts.sustained} sustained · ${patternCounts.intermittent} intermittent), ` +
      `${patternCounts.sporadic} sporadic and ${patternCounts.transient} transient one-off(s). ` +
      `_(sittings split on a ${Math.round(gapMs / MS_PER_MIN)}-min idle gap.)_`,
  );

  const lead = sources[0]!;
  out.push(
    `🥇 Most time-entrenched is \`${lead.ip}\`${lead.internal ? " *(internal!)*" : ""} — ` +
      `**${patternLabel(lead.pattern)}**, score **${lead.engagement}/100**: dwelt **${fmtDuration(lead.dwellMs)}** ` +
      `across ${lead.sessionCount} sitting(s)${
        lead.dutyCycle !== null ? ` at ${pct(lead.dutyCycle)} duty cycle` : ""
      } (${lead.count} alert(s), last seen ${fmtAgo(lead.lastSeenMs, windowEndMs)}).`,
  );

  // The longest continuous camp — a source sitting on you right now.
  const sustained = sources
    .filter((s) => s.pattern === "sustained")
    .sort((a, b) => b.longestSessionMs - a.longestSessionMs);
  if (sustained.length) {
    const s = sustained[0]!;
    out.push(
      `🔥 **${sustained.length} sustained camp(s).** \`${s.ip}\` held a single continuous sitting of ` +
        `**${fmtDuration(s.longestSessionMs)}** — a hands-on, present-now actor, not a drive-by. Treat its dwell ` +
        `as live engagement and confirm what it is reaching.`,
    );
  }

  // The most-returning intermittent source — low-and-slow / ragged beacon.
  const returners = sources
    .filter((s) => s.pattern === "intermittent")
    .sort((a, b) => b.sessionCount - a.sessionCount);
  if (returners.length) {
    const r = returners[0]!;
    out.push(
      `🔁 \`${r.ip}\` came back **${r.sessionCount} times** over a ${fmtDuration(r.dwellMs)} span (longest idle ` +
        `${fmtDuration(r.maxGapMs)}) — a persistent returner: low-and-slow probing or a scheduled job / beacon too ` +
        `ragged for the beacon report. Worth a watchlist entry.`,
    );
  }

  // Internal hosts with real engagement — a beaconing / compromise tell.
  const insiders = sources.filter(
    (s) => s.internal && (s.pattern === "sustained" || s.pattern === "intermittent"),
  );
  if (insiders.length) {
    const i = insiders[0]!;
    out.push(
      `🚨 **${insiders.length} *internal* host(s)** show sustained/intermittent engagement — an inside box that keeps ` +
        `re-engaging an external peer is a beaconing / data-staging tell, not an inbound attacker. ` +
        `Investigate \`${i.ip}\` first.`,
    );
  }

  // A long-camping source whose traffic is being let through — the worst case.
  const leaky = sources
    .filter(
      (s) =>
        (s.pattern === "sustained" || s.pattern === "intermittent") &&
        s.disposition.passRate !== null &&
        s.disposition.passed >= 3,
    )
    .sort((a, b) => (b.disposition.passRate ?? 0) - (a.disposition.passRate ?? 0))[0];
  if (leaky && (leaky.disposition.passRate ?? 0) >= 0.5) {
    out.push(
      `⚠️ \`${leaky.ip}\` has been engaged for **${fmtDuration(leaky.dwellMs)}** and **${pct(
        leaky.disposition.passRate!,
      )} of its actioned alerts are let through** (${leaky.disposition.passed} passed). A source camped this long and ` +
        `reaching your hosts unblocked is the worst case — block it and confirm exposure.`,
    );
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function sourceTable(rows: DwellSource[], windowEndMs: number): string {
  return mdTable(
    ["#", "Source", "Pattern", "Score", "First seen", "Dwell", "Sittings", "Longest", "Duty", "Max idle", "Alerts", "Worst", "Flags"],
    rows.map((s, i) => {
      const flags =
        (s.internal ? "🏠" : "") +
        (s.blocked ? "⛔" : "") +
        (s.watched ? "👁" : "") +
        (s.safe ? "✅" : "");
      return [
        String(i + 1),
        cell(s.ip),
        cell(patternLabel(s.pattern)),
        String(s.engagement),
        cell(fmtAgo(s.firstSeenMs, windowEndMs)),
        fmtDuration(s.dwellMs),
        String(s.sessionCount),
        fmtDuration(s.longestSessionMs),
        s.dutyCycle !== null ? pct(s.dutyCycle) : "—",
        fmtDuration(s.maxGapMs),
        String(s.count),
        cell(s.severityMax),
        flags || "—",
      ];
    }),
  );
}

function renderMarkdown(m: DwellReport): string {
  const gapMin = Math.round(m.gapMs / MS_PER_MIN);
  const lines: string[] = [];
  lines.push(`# 🕒 SecTool Source Dwell-Time & Engagement-Session Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** per source, alert timestamps split into **sittings** on a **${gapMin}-min** idle gap, then dwell span ` +
      `× duty cycle × return count scored 0–100 and ranked by *time-entrenchment*, **not volume** · ` +
      `**Sourced alerts:** ${m.sourcedAlerts} of ${m.totalWindowAlerts}`,
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
          `enough volume to profile dwell (min ${DEFAULT_MIN_ALERTS} alerts/source by default).`,
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

  lines.push(`## Sources by time-entrenchment`);
  lines.push("");
  lines.push(sourceTable(m.sources, m.windowEndMs));
  lines.push("");
  lines.push(
    `**Legend:** _Pattern_ — **🔥 sustained** (one long sitting, or many covering ≥50% of the span: camped *now*) · ` +
      `**🔁 intermittent** (≥3 separated sittings: a returner) · **• sporadic** (a thin scatter across a wide span) · ` +
      `**⚡ transient** (a single short burst then gone). _Score_ 0–100 weights dwell span (fraction of the window), ` +
      `duty cycle, return count and worst severity — **volume is deliberately excluded** so a quiet long camp ` +
      `outranks a loud one-off. _Dwell_ = first→last span; _Duty_ = active time ÷ dwell span; _Max idle_ = longest ` +
      `silence between sittings. **Flags:** 🏠 internal source · ⛔ blocked · 👁 watched · ✅ safe.`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. These are IPS **detections**, not presence: a gap is a gap in *alerting*, not ` +
      `proof the source was absent — so dwell span is a lower bound and the duty cycle an under-estimate (a quiet, ` +
      `careful operator can read as "sporadic"). The **${gapMin}-min sitting threshold is a heuristic** (\`--gap\`); a ` +
      `different value re-segments the timeline, so the raw span and alert count are shown so the call can be ` +
      `second-guessed. Single-alert sources are points in time (0s span, \`transient\`). A long look-back can hit the ` +
      `store's history cap and clip the earliest sittings, shrinking the measured dwell. No live gateway query was ` +
      `performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the source dwell-time / engagement-session report from the stored alert
 * history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link DwellOptions}: `limit`, `minAlerts`, `gapMinutes`, and a
 *              `nowMs` pin for deterministic tests.
 */
export function buildDwell(hours: number, opts: DwellOptions = {}): DwellReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minAlerts = Math.max(1, Math.floor(opts.minAlerts ?? DEFAULT_MIN_ALERTS));
  const gapMinutes = Math.max(1, Math.min(1440, Math.floor(opts.gapMinutes ?? DEFAULT_GAP_MINUTES)));
  const gapMs = gapMinutes * MS_PER_MIN;
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;
  const windowMs = windowEndMs - windowStartMs;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const sources = new Map<string, SourceAcc>();
  let sourced = 0;

  for (const a of windowed) {
    const src = validIp(a.srcIp);
    if (!src) continue;
    sourced++;

    const acc = sources.get(src) ?? newSourceAcc();
    if (!sources.has(src)) sources.set(src, acc);
    acc.times.push(a.time);
    acc.count++;
    acc.score += weightOf(a.severity);
    acc.severityMax = maxSeverity(acc.severityMax, a.severity);
    if (isSevere(a.severity)) acc.severe++;

    const dst = validIp(a.dstIp);
    if (dst) acc.hosts.add(dst);

    const sig = (a.signature ?? "").trim();
    if (sig) acc.sigCounts.set(sig, (acc.sigCounts.get(sig) ?? 0) + 1);

    const disp = classifyDisposition(a.action);
    if (disp === "blocked") acc.blocked++;
    else if (disp === "passed") acc.passed++;
    else acc.unknown++;
  }

  const patternCounts: PatternCounts = { sustained: 0, intermittent: 0, sporadic: 0, transient: 0 };

  const sourceList: DwellSource[] = [...sources.entries()]
    .filter(([, acc]) => acc.count >= minAlerts)
    .map(([ip, acc]) => {
      const times = acc.times.slice().sort((x, y) => x - y);
      const firstSeenMs = times[0]!;
      const lastSeenMs = times[times.length - 1]!;
      const dwellMs = lastSeenMs - firstSeenMs;
      const { sessions, longestSessionMs, meanSessionMs, activeMs, maxGapMs } = sessionize(times, gapMs);
      const dutyCycle = dwellMs > 0 ? round4(Math.min(1, activeMs / dwellMs)) : null;
      const pattern = classifyPattern(sessions.length, dwellMs, dutyCycle, gapMs);
      patternCounts[pattern]++;
      const actioned = acc.blocked + acc.passed;
      return {
        ip,
        internal: isPrivate(ip),
        pattern,
        engagement: engagementScore(dwellMs, windowMs, dutyCycle, sessions.length, acc.severityMax),
        firstSeenMs,
        lastSeenMs,
        dwellMs,
        sessionCount: sessions.length,
        longestSessionMs,
        meanSessionMs,
        activeMs,
        dutyCycle,
        maxGapMs,
        count: acc.count,
        severe: acc.severe,
        score: acc.score,
        severityMax: acc.severityMax,
        distinctHosts: acc.hosts.size,
        topSignature: topOf(acc.sigCounts),
        disposition: {
          blocked: acc.blocked,
          passed: acc.passed,
          unknown: acc.unknown,
          passRate: actioned ? round4(acc.passed / actioned) : null,
        },
        blocked: blockStore.has(ip),
        watched: watchStore.has(ip),
        safe: safeStore.has(ip),
      } satisfies DwellSource;
    })
    // Most time-entrenched first: engagement score, then dwell span, then volume,
    // then IP for a stable order.
    .sort(
      (x, y) =>
        y.engagement - x.engagement ||
        y.dwellMs - x.dwellMs ||
        y.count - x.count ||
        (x.ip < y.ip ? -1 : x.ip > y.ip ? 1 : 0),
    );

  // patternCounts is accumulated across *all* qualifying sources above; the table
  // is then capped to `limit` rows for display without disturbing the totals.
  const cappedSources = sourceList.slice(0, limit);

  const highlights = writeHighlights(
    safeHours,
    gapMs,
    windowEndMs,
    { distinctSources: sourceList.length, sourcedAlerts: sourced },
    patternCounts,
    cappedSources,
  );

  const model: DwellReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    gapMs,
    totalWindowAlerts: windowed.length,
    sourcedAlerts: sourced,
    distinctSources: sourceList.length,
    patternCounts,
    sources: cappedSources,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded dwell report. */
export function dwellFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-dwell-${stamp}.md`;
}
