/**
 * Signature co-occurrence / attack-chain report — "which detections travel
 * together, and in what order?"
 *
 * A single IDS/IPS signature is a fragment. Real intrusions, tools, and campaigns
 * leave a *fingerprint*: a recurring **set** of signatures that the same actor
 * trips together. A port scan that is reliably followed by an exploit attempt and
 * then a C2 check-in is far more telling — and far more actionable — than any one
 * of those alerts read alone. Surfacing those recurring combinations turns a flat
 * alert stream into a map of the techniques that co-occur in *your* environment.
 *
 * This module treats each **actor** (source IP) as a market-basket "transaction"
 * holding the distinct signatures that actor tripped in the window, then runs a
 * classic association analysis over those baskets:
 *
 *   - **Support / co-actors.** How many distinct actors tripped *both* signatures
 *     of a pair. Repetition across actors is what separates a real technique
 *     pairing from one host's coincidence.
 *   - **Lift.** How much more often the two signatures co-occur than chance would
 *     predict (`P(A∧B) / (P(A)·P(B))`). Lift > 1 means the pair is positively
 *     associated — they genuinely travel together; ≈1 means independent.
 *   - **Confidence.** Given the antecedent fired, how often the consequent did
 *     too (`co-actors / actors-with-A`) — the strength of the implication A ⇒ B.
 *   - **Sequencing.** Per co-actor we compare the *first-seen* time of each
 *     signature, so the report can tell whether A reliably **precedes** B (an
 *     attack *chain*, e.g. scan → exploit) rather than merely accompanying it,
 *     and reports the median lag between the two stages.
 *
 * How this differs from the existing reports — there is no overlap:
 *
 *   - killchain.ts maps each signature onto a *fixed* five-stage taxonomy; this
 *     report *learns* the orderings actually present in your data, with no preset.
 *   - campaigns.ts rolls up one attacker IP's whole footprint; this report works
 *     *across* actors to find signature pairings that recur between them.
 *   - beacon.ts scores a src→dst pair for timing regularity; spread.ts ranks peer
 *     breadth; tuning.ts ranks single noisy signatures. None relate two distinct
 *     *signatures* to each other.
 *
 * Honest caveats baked into the output:
 *
 *   - **Alerts, not flows.** Only conversations that tripped a signature appear,
 *     so absence of a pair is not absence of the behaviour.
 *   - **Co-occurrence ≠ causation.** Two signatures sharing an actor does not
 *     prove one caused the other; lift and sequencing rank attention, they do not
 *     convict.
 *   - **Small-sample lift is noisy.** A pair seen in one or two actors can show a
 *     huge lift by accident; the report flags only pairs that clear a distinct-
 *     actor bar as *notable* and says so.
 *
 * It is pure in-memory math over alertStore — no SSH, no Claude, no network — so
 * it is safe to call from the dashboard or CLI at any time. Output is both a
 * structured model and a ready-to-paste Markdown document, mirroring report.ts,
 * compare.ts, profile.ts, assets.ts, tuning.ts, watchlist.ts, rhythm.ts,
 * novelty.ts, killchain.ts, beacon.ts, efficacy.ts and spread.ts.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Dominant temporal relationship between the two signatures of a pair. */
export type ChainDirection = "A→B" | "B→A" | "≈";

/**
 * One pair of distinct signatures that co-occurred across one or more actors.
 * `a` is oriented to be the *antecedent* of the dominant temporal direction
 * (the signature that tends to fire first); `b` is the consequent. When the
 * ordering is indecisive the pair is left in lexical order and `direction` is
 * `"≈"`.
 */
export interface SignaturePairEntry {
  /** Antecedent signature (tends to fire first in the dominant direction). */
  a: string;
  /** Consequent signature (tends to fire second). */
  b: string;
  /** Distinct actors (source IPs) that tripped BOTH signatures in the window. */
  coActors: number;
  /** Distinct actors that tripped the antecedent signature `a` (with or without `b`). */
  actorsA: number;
  /** Distinct actors that tripped the consequent signature `b` (with or without `a`). */
  actorsB: number;
  /** Total alerts of either signature attributed to the co-actors. */
  hits: number;
  /** Worst severity observed across the two signatures. */
  severityMax: Severity;
  /** Support = co-actors / total actors, rounded to 4dp. */
  support: number;
  /**
   * Lift = how much more often the pair co-occurs than independence predicts:
   * `coActors · N / (actorsA · actorsB)`. >1 = positively associated (travel
   * together); ≈1 = independent; <1 = mutually avoidant.
   */
  lift: number;
  /** Confidence of A ⇒ B = co-actors / actors-with-A, 0..1 (rounded 2dp). */
  confidence: number;
  /** Co-actors whose antecedent `a` first-seen preceded consequent `b`. */
  aBeforeB: number;
  /** Co-actors whose consequent `b` first-seen preceded antecedent `a`. */
  bBeforeA: number;
  /** Dominant temporal direction across co-actors. */
  direction: ChainDirection;
  /**
   * Directionality strength = dominant-order co-actors / ordered co-actors,
   * 0.5 (a coin-flip) .. 1 (always the same order). Higher = a firmer *chain*.
   */
  directionStrength: number;
  /** Median lag in ms between the two signatures' first-seen among co-actors. */
  medianLagMs: number;
  /** ms epoch of the earliest involvement across co-actors. */
  firstSeenMs: number;
  /** ms epoch of the most recent involvement across co-actors. */
  lastSeenMs: number;
  /** True when the pair clears the distinct-actor bar AND is positively associated. */
  notable: boolean;
}

export interface CooccurrenceReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp and signature) inside the window. */
  totalWindowAlerts: number;
  /** Distinct actors (source IPs with ≥1 signature) — the basket population N. */
  totalActors: number;
  /** Actors holding ≥2 distinct signatures — the only ones that yield pairs. */
  multiSigActors: number;
  /** Distinct signatures observed in the window. */
  distinctSignatures: number;
  /** Distinct signature pairs that co-occurred in ≥1 actor. */
  pairCount: number;
  /** Pairs that cleared the distinct-actor bar and are positively associated. */
  notableCount: number;
  /** Ranked pairs, strongest-first, truncated to the report limit. */
  pairs: SignaturePairEntry[];
  /** True when the pair table was truncated by the limit. */
  truncated: boolean;
  /** Plain-language call-outs about the report as a whole. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface CooccurrenceOptions {
  /** Max rows in the pair table (clamped to [1, 500]). */
  limit?: number;
  /** Min distinct co-actors for a pair to be flagged notable (clamped to [1, 10000]). */
  minActors?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 25;
const DEFAULT_MIN_ACTORS = 2;
/**
 * Cap distinct signatures considered per actor so a pathologically noisy host
 * cannot explode the O(k²) pair generation. The busiest signatures are kept.
 */
const MAX_SIGS_PER_ACTOR = 40;
/**
 * Ordering is only called decisive when the dominant order holds for clearly more
 * than half of the ordered co-actors; below this it is reported as "≈".
 */
const DIRECTION_THRESHOLD = 0.6;

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

// ----- formatting helpers (mirror spread.ts / beacon.ts / rhythm.ts) -----

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

/** A compact duration label for the median-lag column ("0s" when simultaneous). */
function fmtLag(ms: number): string {
  const sec = Math.round(ms / 1000);
  if (sec <= 0) return "0s";
  if (sec < 90) return `${sec}s`;
  const min = Math.round(sec / 60);
  if (min < 90) return `${min}m`;
  const hr = Math.round(min / 60);
  if (hr < 48) return `${hr}h`;
  return `${Math.round(hr / 24)}d`;
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

/** Truncate a long free-form signature for a table cell. */
function clip(s: string, max = 40): string {
  const t = s.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

/** Median of a numeric array (0 for empty); does not mutate the input. */
function median(values: number[]): number {
  if (!values.length) return 0;
  const sorted = [...values].sort((x, y) => x - y);
  const mid = sorted.length >> 1;
  return sorted.length % 2 ? sorted[mid]! : Math.round((sorted[mid - 1]! + sorted[mid]!) / 2);
}

/** Per-signature globals used to compute marginal probabilities and severity. */
interface SigStat {
  actors: Set<string>;
  alerts: number;
  severityMax: Severity;
}

/** First/last/count of one signature as tripped by one actor (one basket cell). */
interface BasketCell {
  first: number;
  last: number;
  count: number;
}

/** Accumulator for one unordered signature pair while we fold the baskets. */
interface PairAccum {
  s1: string;
  s2: string;
  coActors: number;
  /** Co-actors where s1's first-seen preceded s2's. */
  s1First: number;
  /** Co-actors where s2's first-seen preceded s1's. */
  s2First: number;
  hits: number;
  severityMax: Severity;
  lags: number[];
  firstSeenMs: number;
  lastSeenMs: number;
}

/**
 * Separator byte for {@link pairKey}: an ASCII NUL (U+0000), written as an explicit
 * `\0` escape rather than a literal control character so it survives editors,
 * copy-paste, and encoding round-trips and stays visible to readers of this source.
 */
const PAIR_KEY_SEP = "\0";

/** Stable, collision-free key for an unordered pair (signatures are lexically sorted). */
function pairKey(s1: string, s2: string): string {
  // NUL cannot occur inside a text-based IDS signature, so `"A" + SEP + "B C"` and
  // `"A B" + SEP + "C"` stay distinct keys. A plain space would collide here,
  // because signatures are free-form text that routinely contain spaces.
  return `${s1}${PAIR_KEY_SEP}${s2}`;
}

/**
 * Turn a folded pair accumulator into a presentation entry, orienting `a`/`b` so
 * `a` is the antecedent of the dominant temporal direction.
 */
function toEntry(p: PairAccum, sigStats: Map<string, SigStat>, totalActors: number, minActors: number): SignaturePairEntry {
  const ordered = p.s1First + p.s2First;
  const dominant = Math.max(p.s1First, p.s2First);
  const strength = ordered > 0 ? dominant / ordered : 0;
  const decisive = ordered > 0 && strength >= DIRECTION_THRESHOLD && p.s1First !== p.s2First;

  // Orient: antecedent first. Default to lexical (s1,s2) when indecisive.
  const aIsS1 = decisive ? p.s1First > p.s2First : true;
  const a = aIsS1 ? p.s1 : p.s2;
  const b = aIsS1 ? p.s2 : p.s1;
  const aBeforeB = aIsS1 ? p.s1First : p.s2First;
  const bBeforeA = aIsS1 ? p.s2First : p.s1First;
  const direction: ChainDirection = !decisive ? "≈" : "A→B";

  const actorsA = sigStats.get(a)?.actors.size ?? 0;
  const actorsB = sigStats.get(b)?.actors.size ?? 0;
  const denom = actorsA * actorsB;
  const lift = denom > 0 ? (p.coActors * totalActors) / denom : 0;
  const confidence = actorsA > 0 ? p.coActors / actorsA : 0;

  return {
    a,
    b,
    coActors: p.coActors,
    actorsA,
    actorsB,
    hits: p.hits,
    severityMax: p.severityMax,
    support: Math.round((p.coActors / Math.max(1, totalActors)) * 10000) / 10000,
    lift: Math.round(lift * 100) / 100,
    confidence: Math.round(confidence * 100) / 100,
    aBeforeB,
    bBeforeA,
    direction,
    directionStrength: Math.round(strength * 100) / 100,
    medianLagMs: median(p.lags),
    firstSeenMs: p.firstSeenMs,
    lastSeenMs: p.lastSeenMs,
    notable: p.coActors >= minActors && lift > 1,
  };
}

/**
 * Rank pairs: notable first, then by distinct co-actors (breadth of the pattern),
 * then by association strength (lift), then severity, then recency — so the most
 * widespread, strongly-coupled, dangerous chains float to the top.
 */
function rank(items: SignaturePairEntry[]): SignaturePairEntry[] {
  return items.sort((x, y) => {
    if (x.notable !== y.notable) return x.notable ? -1 : 1;
    if (y.coActors !== x.coActors) return y.coActors - x.coActors;
    if (y.lift !== x.lift) return y.lift - x.lift;
    if (sevRank(y.severityMax) !== sevRank(x.severityMax)) return sevRank(y.severityMax) - sevRank(x.severityMax);
    return y.lastSeenMs - x.lastSeenMs;
  });
}

/** A short human label for a pair's relationship, used in highlights. */
function chainLabel(e: SignaturePairEntry): string {
  if (e.direction === "≈") return `\`${clip(e.a)}\` ↔ \`${clip(e.b)}\``;
  return `\`${clip(e.a)}\` → \`${clip(e.b)}\` (median lag ${fmtLag(e.medianLagMs)})`;
}

function writeHighlights(m: Omit<CooccurrenceReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (!m.totalWindowAlerts) return out;

  if (m.multiSigActors === 0) {
    out.push(
      `No actor tripped more than one distinct signature over the last ${m.hours}h — ` +
        `every source is a single-technique talker, so there are no co-occurrence chains to learn.`,
    );
    return out;
  }
  if (!m.pairCount) {
    out.push(`No two distinct signatures shared an actor this window — nothing to correlate.`);
    return out;
  }

  if (m.notableCount) {
    const top = m.pairs.find((e) => e.notable);
    out.push(
      `🔗 ${m.notableCount} signature pair(s) recur across multiple actors (a learned technique pairing).` +
        (top
          ? ` Strongest: ${chainLabel(top)} — seen in ${top.coActors} actor(s), lift ${top.lift.toFixed(2)}×.`
          : ""),
    );
  } else {
    out.push(
      `No pair cleared the ${DEFAULT_MIN_ACTORS}+ distinct-actor bar — the co-occurrences below come from ` +
        `single actors, so treat them as one host's behaviour, not a population-wide pattern.`,
    );
  }

  // The sharpest signal: a decisive, severe chain (one stage reliably precedes a
  // worse one) — that is an attack playbook unfolding in your environment.
  const severeChain = m.pairs.find((e) => e.notable && e.direction === "A→B" && isSevere(e.severityMax));
  if (severeChain) {
    out.push(
      `⚠️ A medium-or-worse chain fires in a consistent order: ${chainLabel(severeChain)} ` +
        `holds for ${Math.round(severeChain.directionStrength * 100)}% of its actors — ` +
        `the antecedent is an early-warning predictor of the consequent. Alert on \`${clip(severeChain.a)}\` to get ahead of it.`,
    );
  }

  // High-confidence implications are good candidates for a correlation rule.
  const strongImpl = m.pairs.find((e) => e.notable && e.confidence >= 0.8);
  if (strongImpl) {
    out.push(
      `📐 When \`${clip(strongImpl.a)}\` fires, \`${clip(strongImpl.b)}\` follows for ` +
        `${Math.round(strongImpl.confidence * 100)}% of the actors that tripped it — a strong candidate for a ` +
        `SIEM correlation rule.`,
    );
  }

  return out;
}

function pairTable(entries: SignaturePairEntry[], nowMs: number): string {
  return mdTable(
    ["", "Antecedent", "Dir", "Consequent", "Actors", "Lift", "Conf", "Med. lag", "Peak", "Last"],
    entries.map((e) => [
      e.notable ? "🔗" : "·",
      cell(clip(e.a)),
      e.direction === "A→B" ? "→" : "↔",
      cell(clip(e.b)),
      String(e.coActors),
      e.lift ? `${e.lift.toFixed(2)}×` : "—",
      `${Math.round(e.confidence * 100)}%`,
      e.direction === "A→B" ? fmtLag(e.medianLagMs) : "—",
      cell(e.severityMax),
      fmtAge(e.lastSeenMs, nowMs),
    ]),
  );
}

function renderMarkdown(m: CooccurrenceReport): string {
  const lines: string[] = [];
  lines.push(`# 🔗 SecTool Signature Co-occurrence / Attack-Chain Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Baskets:** ${m.totalActors} actor(s) · ${m.multiSigActors} multi-signature · ` +
      `${m.distinctSignatures} distinct signature(s) · **${m.pairCount} pair(s)** ` +
      `(**${m.notableCount} notable**) · **Window alerts:** ${m.totalWindowAlerts}`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.totalWindowAlerts) {
    lines.push(`No alerts with a usable timestamp and signature in the last ${m.hours} hour(s) — nothing to analyse.`);
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Co-occurring signature pairs — which detections travel together`);
  lines.push("");
  if (!m.pairs.length) {
    lines.push(`_None — no two distinct signatures shared an actor this window._`);
    lines.push("");
  } else {
    lines.push(pairTable(m.pairs, m.windowEndMs));
    lines.push("");
  }

  if (m.truncated) {
    lines.push(`_The pair table was truncated to the row limit — raise \`limit\` to see more._`);
    lines.push("");
  }

  lines.push(
    `**Legend:** 🔗 = notable pair (≥ the distinct-actor bar **and** positively associated). _Dir_: \`→\` = the ` +
      `antecedent reliably fires *before* the consequent (an attack *chain*); \`↔\` = they co-occur with no ` +
      `decisive order. _Lift_ = how many times more often the pair co-occurs than chance predicts (>1 = coupled). ` +
      `_Conf_ = of the actors that tripped the antecedent, the share that also tripped the consequent. _Med. lag_ = ` +
      `median time between the two stages' first sighting per actor.`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from stored **IPS-alert** baskets (one per source IP), not full flow data — a ` +
      `signature only appears if the conversation tripped it, so missing pairs are not proof of absence. ` +
      `Co-occurrence and ordering rank attention; they do not prove causation, and lift on a pair seen in only one ` +
      `or two actors is statistically noisy (such pairs are left un-flagged). No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the signature co-occurrence / attack-chain report from the stored alert
 * history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link CooccurrenceOptions}: `limit`, `minActors`, and a `nowMs` pin.
 */
export function buildCooccurrence(hours: number, opts: CooccurrenceOptions = {}): CooccurrenceReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(500, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minActors = Math.max(1, Math.min(10000, Math.floor(opts.minActors ?? DEFAULT_MIN_ACTORS)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * 3_600_000;

  const all = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time));

  // First pass: build per-actor baskets of distinct signatures (with first/last/
  // count per cell) plus per-signature globals for the marginal probabilities.
  const baskets = new Map<string, Map<string, BasketCell>>();
  const sigStats = new Map<string, SigStat>();
  let totalWindowAlerts = 0;
  for (const a of all) {
    if (a.time < windowStartMs || a.time > windowEndMs) continue;
    const sig = (a.signature ?? "").trim();
    const actor = a.srcIp && isIP(a.srcIp) > 0 ? a.srcIp : "";
    if (!sig || !actor) continue;
    totalWindowAlerts++;

    let basket = baskets.get(actor);
    if (!basket) {
      basket = new Map();
      baskets.set(actor, basket);
    }
    const existing = basket.get(sig);
    if (!existing) {
      basket.set(sig, { first: a.time, last: a.time, count: 1 });
    } else {
      existing.count++;
      if (a.time < existing.first) existing.first = a.time;
      if (a.time > existing.last) existing.last = a.time;
    }

    let stat = sigStats.get(sig);
    if (!stat) {
      stat = { actors: new Set(), alerts: 0, severityMax: "info" };
      sigStats.set(sig, stat);
    }
    stat.actors.add(actor);
    stat.alerts++;
    stat.severityMax = maxSeverity(stat.severityMax, a.severity);
  }

  const totalActors = baskets.size;
  const distinctSignatures = sigStats.size;

  // Second pass: fold every actor's basket into unordered pair accumulators.
  const pairs = new Map<string, PairAccum>();
  let multiSigActors = 0;
  for (const basket of baskets.values()) {
    if (basket.size < 2) continue;
    multiSigActors++;

    // Bound the combinatorics: keep only this actor's busiest signatures.
    let sigs = [...basket.entries()];
    if (sigs.length > MAX_SIGS_PER_ACTOR) {
      sigs = sigs.sort((x, y) => y[1].count - x[1].count).slice(0, MAX_SIGS_PER_ACTOR);
    }
    // Lexical order so the pair key is canonical regardless of basket order.
    sigs.sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0));

    for (let i = 0; i < sigs.length; i++) {
      for (let j = i + 1; j < sigs.length; j++) {
        const [s1, c1] = sigs[i]!;
        const [s2, c2] = sigs[j]!;
        const key = pairKey(s1, s2);
        let p = pairs.get(key);
        if (!p) {
          p = {
            s1,
            s2,
            coActors: 0,
            s1First: 0,
            s2First: 0,
            hits: 0,
            severityMax: "info",
            lags: [],
            firstSeenMs: Math.min(c1.first, c2.first),
            lastSeenMs: Math.max(c1.last, c2.last),
          };
          pairs.set(key, p);
        }
        p.coActors++;
        p.hits += c1.count + c2.count;
        p.severityMax = maxSeverity(maxSeverity(p.severityMax, sigStats.get(s1)?.severityMax), sigStats.get(s2)?.severityMax);
        p.lags.push(Math.abs(c1.first - c2.first));
        if (c1.first < c2.first) p.s1First++;
        else if (c2.first < c1.first) p.s2First++;
        p.firstSeenMs = Math.min(p.firstSeenMs, c1.first, c2.first);
        p.lastSeenMs = Math.max(p.lastSeenMs, c1.last, c2.last);
      }
    }
  }

  const entriesAll = rank([...pairs.values()].map((p) => toEntry(p, sigStats, totalActors, minActors)));
  const notableCount = entriesAll.filter((e) => e.notable).length;
  const pairList = entriesAll.slice(0, limit);

  const base: Omit<CooccurrenceReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts,
    totalActors,
    multiSigActors,
    distinctSignatures,
    pairCount: entriesAll.length,
    notableCount,
    pairs: pairList,
    truncated: entriesAll.length > pairList.length,
  };
  const highlights = writeHighlights(base);
  const model: CooccurrenceReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded co-occurrence report. */
export function cooccurrenceFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-cooccurrence-${stamp}.md`;
}
