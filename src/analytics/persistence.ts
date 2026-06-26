/**
 * Persistence / repeat-offender longevity report — "who keeps coming back?"
 *
 * Most alert reports reward *intensity*: a volume spike (surge.ts), a wide
 * fan-out (spread.ts), the biggest footprint by threat score (campaigns.ts).
 * But the adversary a defender most often *under*-reacts to is the quiet,
 * patient one: a source that fires a handful of alerts, goes dark for hours or
 * days, then returns — again and again — never loud enough to top any volume
 * chart, yet present across the whole window. That recurrence is itself the
 * signal. A scanner that probes once is noise; a scanner that probes every
 * night for a week has *chosen* you.
 *
 * This report ranks external (attacker-side) source IPs by **temporal
 * persistence** rather than volume. For each source it measures, purely from
 * the stored alert timeline:
 *
 *   - **Span / coverage** — how much of the window separates its first and last
 *     alert. A source active edge-to-edge has staying power a one-off lacks.
 *   - **Active days / hours** — on how many distinct UTC days (and hour-of-day
 *     slots) it showed up. Presence on many days beats a single busy afternoon.
 *   - **Sessions & gaps** — runs of activity separated by a quiet gap collapse
 *     into "sessions"; many sessions means deliberate *return*, not one sitting.
 *     The longest quiet gap tells you how patient it is between visits.
 *   - **Recency** — is it still active, or did it stop?
 *
 * These fold into a 0-100 **persistence score** that weights window coverage,
 * session recurrence and day-breadth — with a severity nudge — so the slow,
 * deliberate, long-lived sources float to the top regardless of raw count.
 *
 * Why this is a distinct lens from the existing offline reports:
 *
 *   - surge.ts ranks *moments* of high volume; a persistent low-and-slow source
 *     never trips it. They are opposites: burst vs. duration.
 *   - beacon.ts scores a single src→dst pair for *regular* (clock-like) cadence
 *     — C2 callbacks from an internal host. Persistence cares about *irregular*
 *     return across the whole window from an external attacker, not metronomic
 *     intervals to one destination.
 *   - campaigns.ts clusters by attacker but ranks by footprint/threat score; a
 *     huge one-day campaign outranks a tiny seven-day stalker there. Here the
 *     stalker wins.
 *   - novelty.ts flags what is *new*; persistence flags what *won't leave*.
 *
 * Honest caveats baked into the output:
 *
 *   - **Alerts, not flows.** SecTool stores IPS *detections*, not every packet,
 *     so persistence measures recurrence of *detections*. A source can be busy
 *     between alerts without tripping a rule.
 *   - **DHCP / NAT churn.** An external IP can change hands; long spans assume
 *     the IP maps to one actor, which is usually but not always true.
 *   - **Window-bounded.** First/last seen are clamped to the look-back window,
 *     so a source active before the window looks younger than it is.
 *
 * Pure in-memory math over alertStore (plus blocklist/watchlist/safelist
 * membership flags, like campaigns.ts / assets.ts) — no SSH, no Claude, no
 * network. Output is both a structured model and a ready-to-paste Markdown
 * document, mirroring report.ts, compare.ts, profile.ts, assets.ts, surge.ts,
 * spread.ts, beacon.ts and cooccurrence.ts.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** One external source ranked by how persistently it recurs across the window. */
export interface PersistentSource {
  /** The external (attacker-side) source IP. */
  ip: string;
  /** Total alerts attributed to this source inside the window. */
  alertCount: number;
  /** ms epoch of the source's first alert in the window. */
  firstSeenMs: number;
  /** ms epoch of the source's last alert in the window. */
  lastSeenMs: number;
  /** lastSeen − firstSeen, in ms — the source's active span. */
  spanMs: number;
  /** spanMs ÷ window length, rounded to 2dp — how much of the window it straddles. */
  coverage: number;
  /** Distinct UTC calendar days the source was seen on. */
  activeDays: number;
  /** Distinct UTC hour-of-window slots the source was seen in. */
  activeHours: number;
  /**
   * Number of activity *sessions* — runs of alerts separated by a quiet gap
   * larger than the session-gap threshold. >1 means the source returned after
   * going dark; this is the core "repeat offender" signal.
   */
  sessions: number;
  /** The longest quiet gap (ms) between two consecutive alerts from this source. */
  longestGapMs: number;
  /** Mean gap (ms) between consecutive alerts — texture for the cadence. */
  meanGapMs: number;
  /** Worst severity observed across the source's alerts. */
  severityMax: Severity;
  /** Alerts at medium severity or above. */
  severeCount: number;
  /** Alerts whose action was an active block. */
  blockedCount: number;
  /** Distinct signatures this source tripped. */
  distinctSignatures: number;
  /** The dominant signature driving the source (may be empty). */
  topSignature: string;
  /** Distinct internal hosts this source touched. */
  distinctTargets: number;
  /** Whether the IP is already on the blocklist. */
  isBlocked: boolean;
  /** Whether the IP is already on the watchlist. */
  isWatched: boolean;
  /** Whether the IP is marked safe (suppresses it from highlights). */
  isSafe: boolean;
  /** Composite 0-100 persistence score (coverage + recurrence + day-breadth + severity). */
  score: number;
  /** One-word posture: persistent / recurring / sustained / burst / one-off. */
  posture: string;
  /** A compact per-day presence bar across the window ("▓" active, "░" quiet). */
  presence: string;
}

export interface PersistenceReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Distinct external sources seen at all in the window. */
  distinctSources: number;
  /** The session-gap threshold (ms) that splits one source's alerts into sessions. */
  sessionGapMs: number;
  /** The minimum alert count a source needs to be considered (clamped floor). */
  minAlerts: number;
  /** How many sources cleared {@link minAlerts} and were ranked. */
  rankedCount: number;
  /** Ranked sources, most-persistent first, truncated to the report limit. */
  sources: PersistentSource[];
  /** True when the source table was truncated by the limit. */
  truncated: boolean;
  /** Plain-language call-outs about the report as a whole. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface PersistenceOptions {
  /** Max source rows in the table (clamped to [1, 500]). */
  limit?: number;
  /** Minimum alerts for a source to be ranked (clamped to [2, 100000]). */
  minAlerts?: number;
  /** Quiet gap (minutes) that starts a new session (clamped to [5, 10080]). */
  sessionGapMinutes?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 25;
const DEFAULT_MIN_ALERTS = 3;
/** Default quiet gap that separates sessions: 6 hours. A source that goes dark
 *  for longer than this and returns is "coming back", not one continuous sitting. */
const DEFAULT_SESSION_GAP_MINUTES = 360;
const MS_PER_DAY = 86_400_000;
const MS_PER_HOUR = 3_600_000;
/** Width of the per-source day-presence bar (the window's days are down-sampled to fit). */
const PRESENCE_WIDTH = 28;

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

/** RFC1918 / loopback / link-local / ULA — mirrors surge.ts / spread.ts / profile.ts. */
function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
}

// ----- formatting helpers (mirror surge.ts / beacon.ts / spread.ts) -----

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** A compact relative-age label like "3h" / "2d" for the recency column. */
function fmtAge(ms: number, nowMs: number): string {
  const sec = Math.max(0, Math.round((nowMs - ms) / 1000));
  if (sec < 90) return `${sec}s`;
  const min = Math.round(sec / 60);
  if (min < 90) return `${min}m`;
  const hr = Math.round(min / 60);
  if (hr < 48) return `${hr}h`;
  return `${Math.round(hr / 24)}d`;
}

/** A human duration like "45m" / "2h 10m" / "3d 4h" for a span or gap. */
function fmtDuration(ms: number): string {
  const min = Math.max(0, Math.round(ms / 60000));
  if (min < 60) return `${min}m`;
  const hr = Math.floor(min / 60);
  if (hr < 24) {
    const rem = min % 60;
    return rem ? `${hr}h ${rem}m` : `${hr}h`;
  }
  const days = Math.floor(hr / 24);
  const remHr = hr % 24;
  return remHr ? `${days}d ${remHr}h` : `${days}d`;
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
function clip(s: string, max = 40): string {
  const t = s.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

function bump(map: Map<string, number>, key: string | undefined): void {
  if (!key) return;
  map.set(key, (map.get(key) ?? 0) + 1);
}

/** Most frequent key in a tally, ties broken by lexical order for stability. */
function topKey(map: Map<string, number>): { key: string; count: number } {
  let best = "";
  let bestN = -1;
  for (const [k, n] of map) {
    if (n > bestN || (n === bestN && k < best)) {
      best = k;
      bestN = n;
    }
  }
  return { key: best, count: Math.max(0, bestN) };
}

/**
 * Internal accumulator for one source while we fold its alerts. Timestamps are
 * collected so sessions, gaps and day/hour presence can be derived in one pass
 * at the end rather than threaded through every alert.
 */
interface Accum {
  ip: string;
  alertCount: number;
  times: number[];
  days: Set<number>;
  hours: Set<number>;
  signatures: Map<string, number>;
  targets: Set<string>;
  severityMax: Severity;
  severeCount: number;
  blockedCount: number;
}

function newAccum(ip: string): Accum {
  return {
    ip,
    alertCount: 0,
    times: [],
    days: new Set(),
    hours: new Set(),
    signatures: new Map(),
    targets: new Set(),
    severityMax: "info",
    severeCount: 0,
    blockedCount: 0,
  };
}

function foldAlert(e: Accum, a: StoredAlert): void {
  e.alertCount++;
  e.times.push(a.time);
  e.days.add(Math.floor(a.time / MS_PER_DAY));
  e.hours.add(Math.floor(a.time / MS_PER_HOUR));
  bump(e.signatures, a.signature);
  if (a.dstIp && isIP(a.dstIp) > 0) e.targets.add(a.dstIp);
  e.severityMax = maxSeverity(e.severityMax, a.severity);
  if (isSevere(a.severity)) e.severeCount++;
  if (isBlocked(a.action)) e.blockedCount++;
}

/**
 * Render a per-day presence bar: one cell per down-sampled slice of the window,
 * "▓" if the source was active in that slice and "░" if it was quiet. Lets the
 * eye spot edge-to-edge stalkers vs. clustered one-offs at a glance.
 */
function presenceBar(days: Set<number>, startDay: number, endDay: number, width = PRESENCE_WIDTH): string {
  const total = Math.max(1, endDay - startDay + 1);
  const cols = Math.min(width, total);
  const per = total / cols;
  const out: string[] = [];
  for (let c = 0; c < cols; c++) {
    const from = startDay + Math.floor(c * per);
    const to = startDay + Math.min(total, Math.floor((c + 1) * per));
    let active = false;
    for (let d = from; d < Math.max(from + 1, to); d++) {
      if (days.has(d)) {
        active = true;
        break;
      }
    }
    out.push(active ? "▓" : "░");
  }
  return out.join("");
}

/**
 * Split a sorted timestamp series into sessions and measure gaps. A gap larger
 * than `gapMs` ends one session and starts the next.
 */
function analyzeSessions(times: number[], gapMs: number): {
  sessions: number;
  longestGapMs: number;
  meanGapMs: number;
} {
  if (times.length <= 1) return { sessions: times.length, longestGapMs: 0, meanGapMs: 0 };
  const sorted = [...times].sort((a, b) => a - b);
  let sessions = 1;
  let longest = 0;
  let gapSum = 0;
  for (let i = 1; i < sorted.length; i++) {
    const gap = sorted[i]! - sorted[i - 1]!;
    gapSum += gap;
    if (gap > longest) longest = gap;
    if (gap > gapMs) sessions++;
  }
  return {
    sessions,
    longestGapMs: longest,
    meanGapMs: Math.round(gapSum / (sorted.length - 1)),
  };
}

/**
 * Composite 0-100 persistence score. Coverage (how much of the window the
 * source straddles) carries the most weight, then session recurrence (returning
 * after gaps), then day-breadth (present on many distinct days), with a small
 * severity nudge so a persistent *and* dangerous source edges out a persistent
 * benign one. Tuned so a true low-and-slow stalker scores high even with a
 * modest alert count.
 */
function scoreSource(
  coverage: number,
  sessions: number,
  activeDays: number,
  windowDays: number,
  severe: boolean,
): number {
  const coverageScore = coverage * 45; // 0..45 — edge-to-edge presence
  const recurrenceScore = Math.min(1, (sessions - 1) / 5) * 30; // 0..30 — deliberate return
  const breadthScore = Math.min(1, activeDays / Math.max(1, windowDays)) * 15; // 0..15 — many days
  const severityBump = severe ? 10 : 0; // 0..10 — danger nudge
  return Math.max(0, Math.min(100, Math.round(coverageScore + recurrenceScore + breadthScore + severityBump)));
}

/** One-word posture from the temporal shape, prioritising the worst reading. */
function postureLabel(s: {
  sessions: number;
  coverage: number;
  spanMs: number;
  activeDays: number;
}): string {
  // Returns across many sessions over a wide window → the patient stalker.
  if (s.sessions >= 3 && s.coverage >= 0.5) return "persistent";
  // Returns repeatedly but doesn't straddle the whole window.
  if (s.sessions >= 3) return "recurring";
  // One long continuous sitting that covers much of the window.
  if (s.sessions <= 2 && s.coverage >= 0.5) return "sustained";
  // Lots of alerts crammed into a very short span → one-and-done burst.
  if (s.spanMs < 2 * MS_PER_HOUR) return "burst";
  return "one-off";
}

/** Rank: most persistent (score) first, then coverage, then recurrence, then recency. */
function rank(items: PersistentSource[]): PersistentSource[] {
  return items.sort((x, y) => {
    if (y.score !== x.score) return y.score - x.score;
    if (y.coverage !== x.coverage) return y.coverage - x.coverage;
    if (y.sessions !== x.sessions) return y.sessions - x.sessions;
    return y.lastSeenMs - x.lastSeenMs;
  });
}

function writeHighlights(m: Omit<PersistenceReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (!m.totalWindowAlerts) return out;

  if (!m.rankedCount) {
    out.push(
      `No repeat offenders over the last ${m.hours}h — no external source produced ≥${m.minAlerts} alerts, so ` +
        `there is nothing with enough history to judge persistence. Quiet window.`,
    );
    return out;
  }

  out.push(
    `🕒 Ranked ${m.rankedCount} external source(s) by persistence (recurrence over time, not volume) across the ` +
      `last ${m.hours}h — ${m.distinctSources} distinct source(s) seen in total.`,
  );

  const top = m.sources[0];
  if (top) {
    out.push(
      `🎯 Most persistent: \`${top.ip}\` — **${top.posture}**, score ${top.score}/100, active across ` +
        `${fmtDuration(top.spanMs)} (${Math.round(top.coverage * 100)}% of the window) over ${top.activeDays} ` +
        `day(s) in ${top.sessions} session(s)` +
        (top.topSignature ? `, mostly \`${clip(top.topSignature)}\`` : "") +
        (top.severityMax !== "info" ? `, peak ${top.severityMax}` : "") +
        `${top.isBlocked ? " (already blocked)" : ""}.`,
    );
  }

  const stalkers = m.sources.filter((s) => s.posture === "persistent" && !s.isSafe);
  if (stalkers.length) {
    out.push(
      `🚨 ${stalkers.length} source(s) are **persistent** — they keep returning after going dark across most of ` +
        `the window. These low-and-slow actors rarely top a volume chart but have deliberately stuck around; ` +
        `prioritise blocking/​watchlisting them.`,
    );
  }

  const unblockedSevere = m.sources.filter((s) => isSevere(s.severityMax) && !s.isBlocked && !s.isSafe);
  if (unblockedSevere.length) {
    out.push(
      `⚠️ ${unblockedSevere.length} persistent source(s) carry a medium-or-worse signature yet are **not blocked** ` +
        `— recurring + dangerous + unmitigated is the worst combination here.`,
    );
  }

  const longGap = m.sources.filter((s) => s.sessions >= 2 && s.longestGapMs >= MS_PER_DAY);
  if (longGap.length) {
    out.push(
      `😴 ${longGap.length} source(s) returned after a quiet gap of a day or more — patient actors that a short ` +
        `look-back window would miss entirely.`,
    );
  }
  return out;
}

function sourceTable(sources: PersistentSource[], nowMs: number): string {
  return mdTable(
    ["Source", "Score", "Posture", "Presence", "Span", "Cov%", "Days", "Sess", "Longest gap", "Alerts", "Sev", "Last", "Top signature"],
    sources.map((s) => {
      const flags =
        (s.isBlocked ? " ⛔" : "") + (s.isWatched ? " 👁" : "") + (s.isSafe ? " ✅" : "");
      return [
        cell(s.ip + flags),
        String(s.score),
        s.posture,
        cell(s.presence),
        fmtDuration(s.spanMs),
        String(Math.round(s.coverage * 100)),
        String(s.activeDays),
        String(s.sessions),
        s.longestGapMs ? fmtDuration(s.longestGapMs) : "—",
        String(s.alertCount),
        cell(s.severityMax),
        fmtAge(s.lastSeenMs, nowMs),
        cell(clip(s.topSignature || "—", 44)),
      ];
    }),
  );
}

function renderMarkdown(m: PersistenceReport): string {
  const lines: string[] = [];
  lines.push(`# 🕒 SecTool Persistence / Repeat-Offender Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** ranked by temporal persistence (window coverage + session recurrence + day-breadth) · ` +
      `session gap **${fmtDuration(m.sessionGapMs)}** · floor **≥${m.minAlerts} alerts** · ` +
      `**${m.rankedCount} ranked** of ${m.distinctSources} source(s) · **Window alerts:** ${m.totalWindowAlerts}`,
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

  lines.push(`## Most persistent sources — who keeps coming back`);
  lines.push("");
  if (!m.sources.length) {
    lines.push(
      `_None — no external source produced ≥${m.minAlerts} alerts this window, so there is no recurrence to rank._`,
    );
    lines.push("");
  } else {
    lines.push(sourceTable(m.sources, m.windowEndMs));
    lines.push("");
  }

  if (m.truncated) {
    lines.push(`_The source table was truncated to the row limit — raise \`limit\` to see more._`);
    lines.push("");
  }

  lines.push(
    `**Legend:** _Score_ = 0-100 persistence (coverage 45 + recurrence 30 + day-breadth 15 + severity 10). ` +
      `_Presence_ is a per-day bar across the window (\`▓\` active day, \`░\` quiet). _Cov%_ = how much of the ` +
      `window separates first/last alert. _Sess_ = activity sessions (runs split by a >${fmtDuration(m.sessionGapMs)} ` +
      `gap); more sessions = deliberate return. _Postures_: \`persistent\` = returns across most of the window ` +
      `(the patient stalker); \`recurring\` = returns repeatedly in a narrower span; \`sustained\` = one long ` +
      `continuous presence; \`burst\` = crammed into a short span; \`one-off\` = brief. Flags: ⛔ blocked, ` +
      `👁 watched, ✅ safe.`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from stored **IPS-alert** recurrence, not full flow data — persistence measures ` +
      `how often a source's *detections* recur, and an external IP can change hands (DHCP/NAT), so a long span ` +
      `assumes one actor. First/last seen are clamped to the look-back window. No live gateway query was ` +
      `performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the persistence / repeat-offender report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link PersistenceOptions}: `limit`, `minAlerts`, `sessionGapMinutes`, and a `nowMs` pin.
 */
export function buildPersistence(hours: number, opts: PersistenceOptions = {}): PersistenceReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(500, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minAlerts = Math.max(2, Math.min(100000, Math.floor(opts.minAlerts ?? DEFAULT_MIN_ALERTS)));
  const sessionGapMs = Math.max(5, Math.min(10080, Math.floor(opts.sessionGapMinutes ?? DEFAULT_SESSION_GAP_MINUTES))) * 60_000;
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * 3_600_000;
  const windowMs = Math.max(1, windowEndMs - windowStartMs);
  const windowDays = Math.max(1, Math.ceil(windowMs / MS_PER_DAY));
  const startDay = Math.floor(windowStartMs / MS_PER_DAY);
  const endDay = Math.floor(windowEndMs / MS_PER_DAY);

  const all = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time));

  // Fold external-source alerts inside the window into per-source accumulators.
  const bySource = new Map<string, Accum>();
  let totalWindowAlerts = 0;
  for (const a of all) {
    if (a.time < windowStartMs || a.time > windowEndMs) continue;
    totalWindowAlerts++;
    const ip = a.srcIp;
    // Persistence is an attacker-side lens: only external (public) sources qualify.
    if (!ip || isIP(ip) === 0 || isPrivate(ip)) continue;
    let acc = bySource.get(ip);
    if (!acc) {
      acc = newAccum(ip);
      bySource.set(ip, acc);
    }
    foldAlert(acc, a);
  }

  const ranked: PersistentSource[] = [];
  for (const acc of bySource.values()) {
    if (acc.alertCount < minAlerts) continue;
    const firstSeenMs = Math.min(...acc.times);
    const lastSeenMs = Math.max(...acc.times);
    const spanMs = lastSeenMs - firstSeenMs;
    const coverage = Math.round((spanMs / windowMs) * 100) / 100;
    const { sessions, longestGapMs, meanGapMs } = analyzeSessions(acc.times, sessionGapMs);
    const severe = isSevere(acc.severityMax);
    const score = scoreSource(coverage, sessions, acc.days.size, windowDays, severe);
    const posture = postureLabel({ sessions, coverage, spanMs, activeDays: acc.days.size });
    const sig = topKey(acc.signatures);
    ranked.push({
      ip: acc.ip,
      alertCount: acc.alertCount,
      firstSeenMs,
      lastSeenMs,
      spanMs,
      coverage,
      activeDays: acc.days.size,
      activeHours: acc.hours.size,
      sessions,
      longestGapMs,
      meanGapMs,
      severityMax: acc.severityMax,
      severeCount: acc.severeCount,
      blockedCount: acc.blockedCount,
      distinctSignatures: acc.signatures.size,
      topSignature: sig.key,
      distinctTargets: acc.targets.size,
      isBlocked: blockStore.has(acc.ip),
      isWatched: watchStore.has(acc.ip),
      isSafe: safeStore.has(acc.ip),
      score,
      posture,
      presence: presenceBar(acc.days, startDay, endDay),
    });
  }

  const rankedAll = rank(ranked);
  const sources = rankedAll.slice(0, limit);

  const base: Omit<PersistenceReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts,
    distinctSources: bySource.size,
    sessionGapMs,
    minAlerts,
    rankedCount: rankedAll.length,
    sources,
    truncated: rankedAll.length > sources.length,
  };
  const highlights = writeHighlights(base);
  const model: PersistenceReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded persistence report. */
export function persistenceFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-persistence-${stamp}.md`;
}
