/**
 * Attacker cohort-retention / churn report — "is my threat surface a revolving
 * door of one-and-done scanners, or a committed adversary base that keeps coming
 * back day after day — and how fast does a fresh attacker stop showing up?"
 *
 * This is **product-style retention analytics applied to attackers.** A growth
 * team never asks only "how many users did we have this week"; it asks how many
 * are *new*, how many *stuck around* from last week, how many *came back* after
 * going quiet, and how many *churned out* — and it tracks each weekly cohort's
 * retention curve over time. That same decomposition is exactly what a defender
 * wants for the attacker population, and **no existing report computes it**:
 *
 *   - persistence.ts ranks the single most *entrenched* source IPs — a
 *     leaderboard of the worst returners. It never measures the *population*: what
 *     fraction of all attackers are transient vs. loyal.
 *   - novelty.ts surfaces what is *first-seen* tonight as an anomaly lead; it does
 *     not follow those first-timers forward to ask whether they *retain*.
 *   - compare.ts diffs two adjacent windows as aggregate totals; recurrence.ts
 *     forecasts when one repeat IP is due back. Neither builds a cohort triangle or
 *     a retention curve over the whole attacker base.
 *   - lifecycle.ts measures a *signature's* temporal shape (chronic vs. acute), not
 *     the *attacker population's* new/retained/resurrected/churned flow.
 *
 * The distinction this report draws is strategic. Two networks logging the same
 * alert volume can have opposite threat surfaces:
 *
 *   - **Churny / revolving-door** — almost every source appears once and never
 *     returns. This is internet background radiation: mass scanners, botnet sweeps,
 *     research crawlers. Blocklisting individuals buys almost nothing durable
 *     (tomorrow's IPs are different); the right lever is category / geo / ASN policy
 *     and rule tuning.
 *   - **Sticky / committed** — a meaningful slice of attackers come back bucket
 *     after bucket. Someone has *chosen* you. The sticky core is a small, concrete,
 *     blockable set worth escalating, and rising retention is an early warning a raw
 *     volume count hides.
 *
 * The retention *curve* — what fraction of a cohort is still active 1, 2, 3 …
 * buckets after first sighting — is the single number that separates those worlds,
 * and it is invisible in every volume- or leaderboard-shaped report.
 *
 * For each equal-width **time bucket** (default one UTC day) the report computes the
 * classic engagement decomposition over external (attacker-side) source IPs:
 *
 *   - **active** — distinct sources seen in the bucket.
 *   - **new** — sources making their *first* appearance in the window here.
 *   - **retained** — active here *and* in the immediately previous bucket (stayed).
 *   - **resurrected** — active here, quiet last bucket, but seen in an earlier one
 *     (came back after a gap).
 *   - **churned** — active in the *previous* bucket but absent here (left).
 *
 * Then, treating each bucket's first-timers as a **cohort**, it builds the cohort
 * retention triangle and the population-average **retention curve** (lag-0 = 100%
 * by definition; lag-1 = "probability an active attacker returns the next bucket").
 * It also profiles **stickiness** (how many buckets each source spans), surfaces the
 * **sticky core** (the persistent returners, flagged by blocklist / watchlist /
 * safelist state so the call is actionable), and splits the window's attackers into
 * **brand-new-to-history** vs. **returning-from-before-the-window** faces.
 *
 * Honest caveats baked into the output:
 *
 *   - **Detections, not actors.** Counts are over source IPs as the IPS logged
 *     them. NAT / shared egress collapses many real attackers into one IP
 *     (over-stating stickiness); a rotating botnet inflates the newcomer count
 *     (over-stating churn). Retention reflects *address* reuse, not human intent.
 *   - **Window- & store-bounded.** "New" means first-seen in the retained history;
 *     a long look-back that hits the alert store's history cap clips the oldest
 *     buckets and biases early cohorts. The pre-window baseline is only as deep as
 *     the store.
 *   - **Bucket-edge sensitivity.** A source straddling a bucket boundary can read
 *     as two buckets of presence; coarse (daily) buckets smooth this, fine (hourly)
 *     ones sharpen it. The bucket width is reported alongside every metric.
 *
 * Pure in-memory math over alertStore (plus blocklist / watchlist / safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring concentration.ts,
 * dwell.ts, persistence.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** A one-word verdict on the population's return behaviour. */
export type CohortShape = "churny" | "mixed" | "sticky";

/** The new/retained/resurrected/churned decomposition for one time bucket. */
export interface CohortBucketStat {
  /** Bucket index, 0 = oldest in the window. */
  index: number;
  /** Bucket start (inclusive) in epoch ms. */
  startMs: number;
  /** Bucket end (exclusive, clamped to the window end) in epoch ms. */
  endMs: number;
  /** Distinct external sources active in this bucket. */
  active: number;
  /** Sources making their first window appearance in this bucket. */
  fresh: number;
  /** Active here *and* in the immediately previous bucket. */
  retained: number;
  /** Active here, quiet last bucket, seen in an earlier bucket (came back). */
  resurrected: number;
  /** Active in the previous bucket but absent here (count of leavers). */
  churned: number;
}

/** A single point on the population-average retention curve. */
export interface RetentionPoint {
  /** Buckets after first sighting (0 = the cohort's own bucket). */
  lag: number;
  /** Cohort members eligible to be measured at this lag (had a later bucket). */
  cohortBase: number;
  /** Of those, how many were active `lag` buckets after first sighting. */
  retainedCount: number;
  /** retainedCount / cohortBase, 0..1 (4dp); lag 0 is 1 by definition. */
  retention: number;
}

/** One cohort row (sources first seen in a given bucket) for the triangle. */
export interface CohortRow {
  /** The bucket index the cohort was born in. */
  index: number;
  startMs: number;
  /** Cohort size (sources first seen in this bucket). */
  size: number;
  /** retainedAt[k] = members still active k buckets later (k = 0..). */
  retainedAt: number[];
}

/** A persistent returner — part of the sticky core, with handling state. */
export interface StickyAttacker {
  ip: string;
  /** Total alerts in the window. */
  count: number;
  /** Distinct buckets the source appeared in. */
  activeBuckets: number;
  /** activeBuckets / total buckets, 0..1 (4dp). */
  presence: number;
  /** First → last alert span in ms. */
  spanMs: number;
  severityMax: Severity;
  /** First appearance is genuinely new to the retained history (not pre-window). */
  newToHistory: boolean;
  blocked: boolean;
  watched: boolean;
  safe: boolean;
}

/** Distribution of how many buckets sources span (the stickiness histogram). */
export interface StickinessBand {
  /** Inclusive lower bound on bucket count. */
  minBuckets: number;
  /** Inclusive upper bound, or null for "and up". */
  maxBuckets: number | null;
  label: string;
  sources: number;
  /** Share of all analysed sources, 0..1 (4dp). */
  share: number;
}

export interface CohortReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Width of each bucket in hours. */
  bucketHours: number;
  /** Number of buckets the window was divided into. */
  bucketCount: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Distinct external source IPs analysed (the attacker population). */
  totalSources: number;
  /** Window alerts dropped because the source was internal/invalid/missing. */
  excludedAlerts: number;
  /** Of {@link totalSources}, sources never seen before the window in history. */
  newToHistory: number;
  /** Of {@link totalSources}, sources also seen before the window (returning faces). */
  returningFromBefore: number;
  /** Sources appearing in exactly one bucket (one-and-done). */
  oneAndDone: number;
  /** oneAndDone / totalSources, 0..1 (4dp). */
  oneAndDoneRate: number;
  /** Sources appearing in ≥2 buckets / totalSources, 0..1 (4dp). */
  repeatRate: number;
  /** Population-average retention at lag 1 (return-next-bucket probability), 0..1. */
  lag1Retention: number;
  /** The one-word population verdict. */
  shape: CohortShape;
  /** Per-bucket new/retained/resurrected/churned flow. */
  buckets: CohortBucketStat[];
  /** Population-average retention curve, lag 0..maxLag. */
  retentionCurve: RetentionPoint[];
  /** Cohort retention triangle (one row per birth bucket). */
  cohorts: CohortRow[];
  /** Stickiness histogram bands. */
  stickiness: StickinessBand[];
  /** The persistent core, most buckets first (capped to the row limit). */
  stickyCore: StickyAttacker[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface CohortOptions {
  /** Max rows in the sticky-core table (clamped to [1, 200]). */
  limit?: number;
  /** Bucket width in hours (clamped to [1, 720]); defaults to 24 (one day). */
  bucketHours?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 15;
const DEFAULT_BUCKET_HOURS = 24;
const MS_PER_HOUR = 3_600_000;
const MAX_BUCKETS = 366;
/** Cap on how many lags the retention curve / triangle renders. */
const MAX_DISPLAY_LAG = 14;

/** Repeat-rate at/above which the population is called sticky. */
const STICKY_REPEAT = 0.35;
/** Repeat-rate below which the population is called churny. */
const CHURNY_REPEAT = 0.15;

// ----- classifiers / helpers (mirror concentration.ts / dwell.ts) ------------

/** RFC1918 / loopback / link-local / ULA — an address treated as one of ours. */
function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
}

/** A valid, external (public) IP, or undefined if missing/garbage/internal. */
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

/** Compact human duration for a span (e.g. "3d 4h", "5h", "12m"). */
function fmtDuration(ms: number): string {
  if (ms <= 0) return "0m";
  const mins = Math.round(ms / 60000);
  const d = Math.floor(mins / 1440);
  const h = Math.floor((mins % 1440) / 60);
  const m = mins % 60;
  if (d > 0) return h > 0 ? `${d}d ${h}h` : `${d}d`;
  if (h > 0) return m > 0 ? `${h}h ${m}m` : `${h}h`;
  return `${m}m`;
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

/** Human label + emoji for a population shape verdict. */
function shapeLabel(shape: CohortShape): string {
  switch (shape) {
    case "sticky":
      return "🪨 sticky";
    case "mixed":
      return "▥ mixed";
    case "churny":
      return "🌀 churny";
  }
}

function classifyShape(repeatRate: number): CohortShape {
  if (repeatRate >= STICKY_REPEAT) return "sticky";
  if (repeatRate < CHURNY_REPEAT) return "churny";
  return "mixed";
}

// ----- aggregation -----------------------------------------------------------

interface SourceAcc {
  /** Distinct bucket indices this source was active in. */
  buckets: Set<number>;
  count: number;
  severityMax: Severity;
  firstMs: number;
  lastMs: number;
}

/**
 * Build the attacker cohort-retention / churn report from the stored alert
 * history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link CohortOptions}: `limit`, `bucketHours`, and a `nowMs` pin
 *              for deterministic tests.
 */
export function buildCohort(hours: number, opts: CohortOptions = {}): CohortReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const bucketHours = Math.max(1, Math.min(720, Math.floor(opts.bucketHours ?? DEFAULT_BUCKET_HOURS)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const bucketMs = bucketHours * MS_PER_HOUR;
  const bucketCount = Math.max(1, Math.min(MAX_BUCKETS, Math.ceil(safeHours / bucketHours)));

  const all = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time));

  // Pre-window baseline: which external sources were already known before the
  // window opened — so a window-bucket-0 source is not miscounted as "new to
  // history" when it is really a returning face (mirrors novelty.ts).
  const seenBefore = new Set<string>();
  for (const a of all) {
    if (a.time >= windowStartMs) continue;
    const ip = externalIp(a.srcIp);
    if (ip) seenBefore.add(ip);
  }

  const windowed = all.filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const sources = new Map<string, SourceAcc>();
  let excludedAlerts = 0;
  for (const a of windowed) {
    const ip = externalIp(a.srcIp);
    if (!ip) {
      excludedAlerts++;
      continue;
    }
    // Bucket index, clamped so an alert exactly on the window end lands in the last.
    const idx = Math.max(0, Math.min(bucketCount - 1, Math.floor((a.time - windowStartMs) / bucketMs)));
    const acc = sources.get(ip);
    if (acc) {
      acc.buckets.add(idx);
      acc.count++;
      acc.severityMax = maxSeverity(acc.severityMax, a.severity);
      if (a.time < acc.firstMs) acc.firstMs = a.time;
      if (a.time > acc.lastMs) acc.lastMs = a.time;
    } else {
      sources.set(ip, {
        buckets: new Set([idx]),
        count: 1,
        severityMax: maxSeverity("info", a.severity),
        firstMs: a.time,
        lastMs: a.time,
      });
    }
  }

  const totalSources = sources.size;

  // Per-source derived facts: cohort (first active bucket), sorted bucket list.
  interface SourceFact {
    ip: string;
    acc: SourceAcc;
    sortedBuckets: number[];
    cohort: number;
    newToHistory: boolean;
  }
  const facts: SourceFact[] = [];
  for (const [ip, acc] of sources) {
    const sortedBuckets = [...acc.buckets].sort((a, b) => a - b);
    facts.push({
      ip,
      acc,
      sortedBuckets,
      cohort: sortedBuckets[0]!,
      newToHistory: !seenBefore.has(ip),
    });
  }

  // ----- per-bucket new/retained/resurrected/churned flow -------------------
  const buckets: CohortBucketStat[] = [];
  for (let i = 0; i < bucketCount; i++) {
    const startMs = windowStartMs + i * bucketMs;
    const endMs = Math.min(windowEndMs, startMs + bucketMs);
    let active = 0;
    let fresh = 0;
    let retained = 0;
    let resurrected = 0;
    let churned = 0;
    for (const f of facts) {
      const here = f.acc.buckets.has(i);
      const prev = i > 0 && f.acc.buckets.has(i - 1);
      if (here) {
        active++;
        if (f.cohort === i) fresh++;
        else if (prev) retained++;
        else resurrected++; // active before, quiet last bucket, back now
      } else if (prev) {
        churned++; // present last bucket, gone now
      }
    }
    buckets.push({ index: i, startMs, endMs, active, fresh, retained, resurrected, churned });
  }

  // ----- cohort triangle + population-average retention curve ---------------
  const maxLag = Math.max(0, bucketCount - 1);
  const cohorts: CohortRow[] = [];
  for (let c = 0; c < bucketCount; c++) {
    const members = facts.filter((f) => f.cohort === c);
    if (!members.length) continue;
    const retainedAt: number[] = [];
    for (let k = 0; c + k < bucketCount; k++) {
      retainedAt.push(members.filter((m) => m.acc.buckets.has(c + k)).length);
    }
    cohorts.push({ index: c, startMs: windowStartMs + c * bucketMs, size: members.length, retainedAt });
  }

  const retentionCurve: RetentionPoint[] = [];
  for (let k = 0; k <= maxLag; k++) {
    let base = 0;
    let kept = 0;
    for (const row of cohorts) {
      if (k < row.retainedAt.length) {
        base += row.size;
        kept += row.retainedAt[k]!;
      }
    }
    if (base === 0) break;
    retentionCurve.push({
      lag: k,
      cohortBase: base,
      retainedCount: kept,
      retention: round4(kept / base),
    });
  }
  const lag1Retention = retentionCurve.find((p) => p.lag === 1)?.retention ?? 0;

  // ----- stickiness histogram + population rates ----------------------------
  let oneAndDone = 0;
  let newToHistory = 0;
  for (const f of facts) {
    if (f.acc.buckets.size === 1) oneAndDone++;
    if (f.newToHistory) newToHistory++;
  }
  const oneAndDoneRate = totalSources > 0 ? round4(oneAndDone / totalSources) : 0;
  const repeatRate = totalSources > 0 ? round4((totalSources - oneAndDone) / totalSources) : 0;
  const returningFromBefore = totalSources - newToHistory;

  const stickiness = buildStickiness(facts, totalSources, bucketCount);

  // ----- sticky core: persistent returners, with handling state -------------
  const stickyCore: StickyAttacker[] = facts
    .filter((f) => f.acc.buckets.size >= 2)
    .sort(
      (a, b) =>
        b.acc.buckets.size - a.acc.buckets.size ||
        b.acc.count - a.acc.count ||
        (a.ip < b.ip ? -1 : a.ip > b.ip ? 1 : 0),
    )
    .slice(0, limit)
    .map((f) => ({
      ip: f.ip,
      count: f.acc.count,
      activeBuckets: f.acc.buckets.size,
      presence: bucketCount > 0 ? round4(f.acc.buckets.size / bucketCount) : 0,
      spanMs: f.acc.lastMs - f.acc.firstMs,
      severityMax: f.acc.severityMax,
      newToHistory: f.newToHistory,
      blocked: blockStore.has(f.ip),
      watched: watchStore.has(f.ip),
      safe: safeStore.has(f.ip),
    }));

  const shape = classifyShape(repeatRate);

  const model: CohortReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    bucketHours,
    bucketCount,
    totalWindowAlerts: windowed.length,
    totalSources,
    excludedAlerts,
    newToHistory,
    returningFromBefore,
    oneAndDone,
    oneAndDoneRate,
    repeatRate,
    lag1Retention,
    shape,
    buckets,
    retentionCurve,
    cohorts,
    stickiness,
    stickyCore,
    highlights: [],
    markdown: "",
  };
  model.highlights = writeHighlights(model);
  model.markdown = renderMarkdown(model);
  return model;
}

// ----- stickiness histogram --------------------------------------------------

function buildStickiness(
  facts: { acc: SourceAcc }[],
  total: number,
  bucketCount: number,
): StickinessBand[] {
  // Bands adapt to how many buckets exist so they stay meaningful for short
  // windows: 1 (one-and-done), 2-3, 4-7, 8+, capped at the bucket count.
  const raw: { min: number; max: number | null; label: string }[] = [
    { min: 1, max: 1, label: "1 bucket (one-and-done)" },
    { min: 2, max: 3, label: "2–3 buckets" },
    { min: 4, max: 7, label: "4–7 buckets" },
    { min: 8, max: null, label: "8+ buckets" },
  ];
  const bands = raw.filter((b) => b.min <= bucketCount);
  const counts = new Map<string, number>();
  for (const f of facts) {
    const n = f.acc.buckets.size;
    for (const b of bands) {
      if (n >= b.min && (b.max === null || n <= b.max)) {
        counts.set(b.label, (counts.get(b.label) ?? 0) + 1);
        break;
      }
    }
  }
  return bands.map((b) => {
    const sources = counts.get(b.label) ?? 0;
    return {
      minBuckets: b.min,
      maxBuckets: b.max,
      label: b.label,
      sources,
      share: total > 0 ? round4(sources / total) : 0,
    };
  });
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(m: CohortReport): string[] {
  const out: string[] = [];
  if (m.totalSources === 0) return out;

  const bucketUnit = m.bucketHours === 24 ? "day" : `${m.bucketHours}h bucket`;

  // Headline: population shape + the one-and-done / repeat split.
  out.push(
    `🧭 Over the last ${m.hours}h, **${m.totalSources} external attacker(s)** across ` +
      `**${m.bucketCount} ${bucketUnit}(s)** form a **${shapeLabel(m.shape)}** population — ` +
      `**${pct(m.oneAndDoneRate)}** appeared in just one ${bucketUnit} and never returned, ` +
      `**${pct(m.repeatRate)}** came back at least once.`,
  );

  // Strategy implied by the shape.
  if (m.shape === "churny") {
    out.push(
      `🌀 **Revolving door:** the surface is dominated by transient, one-shot sources — ` +
        `internet background radiation (mass scanners / botnet sweeps). Blocklisting individuals buys ` +
        `little durable relief (tomorrow's IPs differ); reach for category / geo / ASN policy and rule tuning.`,
    );
  } else if (m.shape === "sticky") {
    out.push(
      `🪨 **Committed base:** a large share of attackers return ${bucketUnit}-after-${bucketUnit} — someone has ` +
        `*chosen* you. The persistent core is a small, concrete, blockable set; escalate it before raw volume does.`,
    );
  } else {
    out.push(
      `▥ **Mixed:** a churny tail of one-off scanners over a returning core. Tune away the noise, then ` +
        `treat the repeat offenders as the durable threat.`,
    );
  }

  // Retention curve headline: probability of returning the next bucket.
  if (m.retentionCurve.some((p) => p.lag === 1)) {
    out.push(
      `📉 **Return-next-${bucketUnit} retention is ${pct(m.lag1Retention)}** — of attackers active in any ` +
        `${bucketUnit}, ~${pct(m.lag1Retention)} are still active the following one. ` +
        (m.lag1Retention >= 0.5
          ? `That is high — adversaries are sticking around, not passing through.`
          : m.lag1Retention <= 0.1
            ? `That is very low — almost everyone is a one-time visitor.`
            : `A moderate hold; the returning slice is your real adversary.`),
    );
  }

  // The sticky core, made actionable by handling state.
  if (m.stickyCore.length) {
    const unhandled = m.stickyCore.filter((s) => !s.blocked && !s.safe);
    const top = m.stickyCore[0]!;
    out.push(
      `🎯 **Sticky core:** **${m.stickyCore.length} source(s)** returned across multiple ${bucketUnit}s` +
        (unhandled.length
          ? ` — **${unhandled.length} not yet blocked/safelisted**.`
          : ` — all already blocked or safelisted.`) +
        ` Most persistent: \`${top.ip}\` (${top.activeBuckets}/${m.bucketCount} ${bucketUnit}s, ` +
        `${top.count} alert(s), worst ${top.severityMax}` +
        `${top.blocked ? ", ⛔ blocked" : top.watched ? ", 👁 watched" : ""}).`,
    );
  }

  // New-to-history vs returning faces — is the surface refreshing or recycling?
  if (m.newToHistory > 0 || m.returningFromBefore > 0) {
    const newFrac = m.totalSources > 0 ? m.newToHistory / m.totalSources : 0;
    out.push(
      `🆕 **${m.newToHistory}** of the window's **${m.totalSources}** attackers (**${pct(newFrac)}**) are ` +
        `brand new to your recorded history; the remaining **${m.returningFromBefore}** are returning faces ` +
        `last seen *before* this window. ` +
        (newFrac >= 0.7
          ? `A heavily refreshing surface — most threats are first-timers.`
          : newFrac <= 0.3
            ? `A recycling surface — you mostly face the same addresses over and over.`
            : `A balanced mix of fresh and familiar.`),
    );
  }

  // A fresh wave landing in the most recent bucket is worth a direct call-out.
  const last = m.buckets[m.buckets.length - 1];
  if (last && last.active > 0 && last.fresh / last.active >= 0.6 && m.bucketCount >= 2) {
    out.push(
      `🌊 **Fresh wave:** in the most recent ${bucketUnit}, **${last.fresh}/${last.active}** active sources ` +
        `(${pct(last.fresh / last.active)}) are first-timers — an influx of new attackers, not the usual returners.`,
    );
  }

  return out;
}

// ----- markdown --------------------------------------------------------------

function bucketLabel(m: CohortReport, startMs: number): string {
  if (m.bucketHours === 24) return new Date(startMs).toISOString().slice(0, 10); // YYYY-MM-DD
  return fmtTime(startMs).replace(" UTC", "");
}

function flowTable(m: CohortReport): string {
  return mdTable(
    ["#", "Bucket start (UTC)", "Active", "New", "Retained", "Resurrected", "Churned"],
    m.buckets.map((b) => [
      String(b.index + 1),
      cell(bucketLabel(m, b.startMs)),
      String(b.active),
      String(b.fresh),
      b.index === 0 ? "—" : String(b.retained),
      b.index === 0 ? "—" : String(b.resurrected),
      b.index === 0 ? "—" : String(b.churned),
    ]),
  );
}

function retentionCurveTable(m: CohortReport): string {
  const pts = m.retentionCurve.filter((p) => p.lag <= MAX_DISPLAY_LAG);
  return mdTable(
    ["Lag (buckets)", "Cohort base", "Still active", "Retention"],
    pts.map((p) => [
      String(p.lag),
      String(p.cohortBase),
      String(p.retainedCount),
      pct(p.retention, 1),
    ]),
  );
}

function cohortTriangle(m: CohortReport): string {
  const lagCols = Math.min(MAX_DISPLAY_LAG, Math.max(0, m.bucketCount - 1));
  const headers = ["Cohort (born)", "Size"];
  for (let k = 0; k <= lagCols; k++) headers.push(`+${k}`);
  const rows = m.cohorts.map((row) => {
    const cells = [cell(bucketLabel(m, row.startMs)), String(row.size)];
    for (let k = 0; k <= lagCols; k++) {
      if (k < row.retainedAt.length) {
        const frac = row.size > 0 ? row.retainedAt[k]! / row.size : 0;
        cells.push(`${row.retainedAt[k]} (${pct(frac)})`);
      } else {
        cells.push("·");
      }
    }
    return cells;
  });
  return mdTable(headers, rows);
}

function stickyTable(m: CohortReport): string {
  return mdTable(
    ["#", "Source", "Alerts", "Buckets", "Presence", "Span", "Worst", "First seen", "Flags"],
    m.stickyCore.map((s, i) => {
      const flags =
        (s.blocked ? "⛔" : "") +
        (s.watched ? "👁" : "") +
        (s.safe ? "✅" : "") +
        (s.newToHistory ? "🆕" : "");
      return [
        String(i + 1),
        cell(s.ip),
        String(s.count),
        `${s.activeBuckets}/${m.bucketCount}`,
        pct(s.presence, 0),
        cell(fmtDuration(s.spanMs)),
        cell(s.severityMax),
        s.newToHistory ? "new" : "prior",
        flags || "—",
      ];
    }),
  );
}

function stickinessTable(m: CohortReport): string {
  return mdTable(
    ["Span", "Sources", "Share"],
    m.stickiness.map((b) => [cell(b.label), String(b.sources), pct(b.share, 1)]),
  );
}

function renderMarkdown(m: CohortReport): string {
  const lines: string[] = [];
  const bucketUnit = m.bucketHours === 24 ? "day" : `${m.bucketHours}h bucket`;
  lines.push(`# 🔁 SecTool Attacker Cohort-Retention / Churn Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** external (attacker-side) source IPs folded onto **${m.bucketCount}** ${bucketUnit}-wide ` +
      `bucket(s); decomposed into **new / retained / resurrected / churned** per bucket, then followed forward ` +
      `as **cohorts** to build the retention curve. Offline, deterministic, count-based · ` +
      `**Window alerts:** ${m.totalWindowAlerts}` +
      (m.excludedAlerts ? ` · **excluded (internal/invalid src):** ${m.excludedAlerts}` : ""),
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (m.totalSources === 0) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but none carried a usable **external** ` +
          `source IP to build attacker cohorts from (all were internal, invalid or missing).`,
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

  // At-a-glance population scoreboard.
  lines.push(`## Population at a glance`);
  lines.push("");
  lines.push(
    mdTable(
      ["Attackers", "Shape", "One-and-done", "Repeat rate", `Return-next-${bucketUnit}`, "New to history"],
      [
        [
          String(m.totalSources),
          cell(shapeLabel(m.shape)),
          `${m.oneAndDone} (${pct(m.oneAndDoneRate)})`,
          pct(m.repeatRate),
          pct(m.lag1Retention),
          `${m.newToHistory} (${pct(m.totalSources > 0 ? m.newToHistory / m.totalSources : 0)})`,
        ],
      ],
    ),
  );
  lines.push("");
  lines.push(
    `**Legend:** _Shape_ — **🪨 sticky** (≥${pct(STICKY_REPEAT)} of attackers return: a committed base) · ` +
      `**▥ mixed** · **🌀 churny** (<${pct(CHURNY_REPEAT)} return: a revolving door of one-off scanners). ` +
      `_Repeat rate_ = sources seen in ≥2 ${bucketUnit}s. _Return-next-${bucketUnit}_ = population-average lag-1 retention.`,
  );
  lines.push("");

  // Per-bucket flow.
  lines.push(`## Per-${bucketUnit} flow (new / retained / resurrected / churned)`);
  lines.push("");
  lines.push(flowTable(m));
  lines.push("");
  lines.push(
    `_**New** = first window appearance · **Retained** = active here and the previous ${bucketUnit} · ` +
      `**Resurrected** = back after a quiet ${bucketUnit} · **Churned** = active the previous ${bucketUnit}, ` +
      `gone now. The first ${bucketUnit} has no predecessor, so retained/resurrected/churned are n/a._`,
  );
  lines.push("");

  // Retention curve.
  lines.push(`## Retention curve`);
  lines.push("");
  if (m.retentionCurve.length > 1) {
    lines.push(retentionCurveTable(m));
    lines.push("");
    lines.push(
      `_Of every attacker cohort (grouped by the ${bucketUnit} they were first seen), the share still active ` +
        `N ${bucketUnit}s later — averaged across cohorts and weighted by cohort size. Lag 0 is 100% by ` +
        `definition._`,
    );
  } else {
    lines.push(
      `_Only ${m.bucketCount} ${bucketUnit}(s) of data — at least two are needed to measure a retention curve._`,
    );
  }
  lines.push("");

  // Cohort triangle.
  if (m.cohorts.length > 1 && m.bucketCount > 1) {
    lines.push(`## Cohort triangle`);
    lines.push("");
    lines.push(cohortTriangle(m));
    lines.push("");
    lines.push(
      `_Each row is the cohort of attackers **first seen** in that ${bucketUnit}; columns are ${bucketUnit}s ` +
        `since (+0 = the cohort's own ${bucketUnit}). Cells show survivors and their share of the cohort. ` +
        `\`·\` = beyond the window._`,
    );
    lines.push("");
  }

  // Stickiness histogram.
  lines.push(`## Stickiness distribution`);
  lines.push("");
  lines.push(stickinessTable(m));
  lines.push("");

  // Sticky core.
  lines.push(`## Sticky core (persistent returners)`);
  lines.push("");
  if (m.stickyCore.length) {
    lines.push(stickyTable(m));
    lines.push("");
    lines.push(
      `_Sources active in ≥2 ${bucketUnit}s, most persistent first. Flags: ⛔ blocked · 👁 watched · ` +
        `✅ safelisted · 🆕 new to recorded history. The unblocked rows are your durable, concrete blocklist ` +
        `targets — these addresses keep choosing you._`,
    );
  } else {
    lines.push(
      `No source returned across more than one ${bucketUnit} — the entire attacker population is one-and-done ` +
        `(a pure revolving door). There is no persistent core to block; favour policy / tuning over per-IP blocks.`,
    );
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Cohorts are built from source IPs **as the IPS logged them** — NAT / shared ` +
      `egress can collapse many real attackers into one address (over-stating stickiness) and a rotating botnet ` +
      `inflates the newcomer count (over-stating churn); retention reflects **address** reuse, not human intent. ` +
      `"New to history" is bounded by the rolling alert store — a long look-back that hits the store's cap clips ` +
      `the oldest buckets and biases early cohorts. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/** A filesystem-safe filename for a downloaded cohort report. */
export function cohortFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-cohort-${stamp}.md`;
}
