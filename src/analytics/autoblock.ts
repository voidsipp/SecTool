/**
 * Auto-block threshold simulator / preventable-volume curve — "**if I auto-blocked
 * any source after it tripped N alerts, how much noise would I prevent, and how
 * many firewall entries would that cost me?**"
 *
 * SecTool already ships the *worklist* side of blocking: blockplan.ts ranks the
 * specific IPs to add next, recidivism.ts checks whether an existing block held,
 * mttb.ts measures how fast each attacker was contained, efficacy.ts finds the
 * per-signature detect-only gap, hygiene.ts prunes stale entries. Every one of
 * those answers a question about *individual* addresses or rules.
 *
 * None of them answer the **policy** question that sits one level up: *"at what
 * volume should an auto-block fire at all?"* A threshold of 1 blocks every source
 * the instant it trips a rule — maximal prevention, but a firewall table that
 * explodes with one-shot scanners and a real false-positive risk. A threshold of
 * 50 only ever blocks the handful of relentless hammerers — tiny blast radius, but
 * it lets a mountain of mid-volume noise through. The right answer is somewhere on
 * the curve between, and it is *deployment-specific* — it depends on the actual
 * shape of your source-volume distribution, which only your stored history knows.
 *
 * This report draws that curve. Over the candidate population — every **external,
 * routable, non-safelisted** source in the window (the set an automatic edge-block
 * could legitimately act on) — it sweeps a ladder of thresholds `T` and, for each:
 *
 *   - **sources blocked** = sources with at least `T` alerts (the cost: every one
 *     is a firewall entry and a potential false positive),
 *   - **alerts prevented** = Σ over those sources of `max(0, alerts − T)` — the
 *     volume that would never have reached the detection stream, because a block
 *     fires *on* the `T`-th alert and everything after it is dropped at the edge,
 *   - **prevented %** of the candidate alert volume,
 *   - **leverage** = alerts prevented per source blocked — how much silence each
 *     firewall entry buys (a high-leverage threshold is efficient: few blocks, lots
 *     of noise removed),
 *   - **severe coverage** — how many of the blocked sources had ever sent a
 *     medium-or-worse alert, so a threshold is not judged on raw volume alone.
 *
 * From the swept curve it picks a **recommended threshold** by the classic
 * "knee" / closest-to-ideal heuristic: normalise each point to *(blocks issued ÷
 * max blocks, prevented fraction)* and choose the `T` nearest the ideal corner
 * **(0 blocks, 100% prevented)** — i.e. the best trade of a small blocklist for a
 * large drop in noise. Ties resolve toward the *larger* threshold (fewer blocks,
 * the more conservative auto-action). The sources that policy would actually
 * block are then listed, ranked by the noise each removes and flagged with their
 * current control state, so the recommendation is immediately actionable — and so
 * a source that policy would auto-block but an analyst has **already** blocked
 * reads as confirmation, while a brand-new one reads as a candidate.
 *
 * Honest caveats baked into the output:
 *
 *   - **A counterfactual on *fixed* arrivals.** It replays the alerts that actually
 *     landed and asks which a block would have suppressed; it assumes the attacker
 *     keeps the *same source IP*. A determined actor who rotates IPs defeats any
 *     volume threshold — so "prevented" is an upper bound on a rotating adversary
 *     and an honest estimate on the commodity scanners that dominate the volume.
 *   - **One-shot sources are unreachable by design.** A source seen once can never
 *     be auto-blocked by any `T ≥ 2`; threshold policy structurally misses the
 *     long tail of single-hit probes. The count of them is surfaced, not hidden.
 *   - **Safelisted & internal sources are excluded** from the candidate set — you
 *     never auto-block a vetted-benign IP or one of your own RFC1918 hosts (an
 *     internal host tripping rules is a *compromise* tell to investigate, not an
 *     edge-block; their count is called out so they are never silently dropped).
 *   - **Detections, not flows; window-bounded & store-capped.** SecTool stores IPS
 *     *detections*, so a noisy source that never trips a rule is invisible and the
 *     prevented volume is a lower bound on real traffic. A long look-back can hit
 *     the store's history cap.
 *
 * Pure in-memory math over alertStore (plus blocklist / watchlist / safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring report.ts, rarity.ts,
 * blockplan.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** One row of the swept threshold curve. */
export interface ThresholdPoint {
  /** The auto-block trigger: block a source on its `threshold`-th alert. */
  threshold: number;
  /** Candidate sources with ≥ `threshold` alerts (the blocks this policy issues). */
  sourcesBlocked: number;
  /** Σ max(0, alerts − threshold) over blocked sources — alerts a block prevents. */
  alertsPrevented: number;
  /** Fraction of candidate alert volume prevented, 0..1 (4dp). */
  preventedFraction: number;
  /** Alerts prevented per source blocked (leverage), or 0 when nothing blocks. */
  leverage: number;
  /** Of the blocked sources, how many ever sent a medium-or-worse alert. */
  severeSourcesBlocked: number;
  /** Distance to the ideal (0 blocks, 100% prevented) corner — lower is better. */
  kneeDistance: number;
  /** True for the threshold the report recommends (the knee). */
  recommended: boolean;
}

/** A candidate source the recommended policy would auto-block. */
export interface BlockedSource {
  /** The source IP. */
  ip: string;
  /** Alerts attributed to this source in the window. */
  alerts: number;
  /** Alerts a block at the recommended threshold would prevent (alerts − T). */
  prevented: number;
  /** Distinct internal hosts this source reached. */
  hostsReached: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Worst severity seen from this source. */
  severityMax: Severity;
  /** Alerts the gateway actively blocked at the signature level. */
  alreadyBlockedAtIps: number;
  /** First alert (ms epoch) in the window. */
  firstMs: number;
  /** Last alert (ms epoch) in the window. */
  lastMs: number;
  /** The source is already on the firewall blocklist (policy agrees with you). */
  blocked: boolean;
  /** The source is on the watchlist (an analyst already flagged it). */
  watched: boolean;
}

export interface AutoblockReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts carrying a valid source IP. */
  sourcedAlerts: number;
  /** Alerts from the candidate (external, routable, non-safelisted) population. */
  candidateAlerts: number;
  /** Distinct candidate sources (the auto-block-eligible population). */
  candidateSources: number;
  /** Candidate sources seen exactly once (unreachable by any threshold ≥ 2). */
  oneShotSources: number;
  /** Internal (RFC1918/…) sources excluded from candidacy — surfaced, not hidden. */
  internalSourcesExcluded: number;
  /** Safelisted sources excluded from candidacy. */
  safelistedSourcesExcluded: number;
  /** The recommended auto-block threshold (the knee of the curve), or null. */
  recommendedThreshold: number | null;
  /** The full swept curve, threshold ascending. */
  curve: ThresholdPoint[];
  /** Sources the recommended threshold would block, most noise-removed first. */
  blockedSources: BlockedSource[];
  /** How many of {@link blockedSources} are already on the firewall blocklist. */
  blockedAlreadyOnList: number;
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface AutoblockOptions {
  /** Max rows in the would-be-blocked source table (clamped to [1, 200]). */
  limit?: number;
  /**
   * Override the swept threshold ladder. Values are sanitised: deduped, sorted,
   * and any < 1 dropped. Defaults to {@link DEFAULT_THRESHOLDS}.
   */
  thresholds?: number[];
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const MS_PER_HOUR = 3_600_000;
/**
 * The default threshold ladder. Roughly geometric so the curve has resolution
 * where it bends (the low end) without an unreadable row per integer at the top.
 */
const DEFAULT_THRESHOLDS = [1, 2, 3, 4, 5, 7, 10, 15, 20, 30, 50, 100] as const;

// ----- classifiers / helpers (mirror rarity.ts / blockplan.ts) ---------------

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

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

function pct(frac: number): string {
  return `${Math.round(frac * 100)}%`;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function fmtDur(ms: number): string {
  if (ms <= 0) return "0m";
  const m = Math.round(ms / 60000);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h${m % 60 ? ` ${m % 60}m` : ""}`;
  const d = Math.floor(h / 24);
  return `${d}d${h % 24 ? ` ${h % 24}h` : ""}`;
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

/** A tiny inline sparkline-ish bar for the prevented fraction. */
function bar(frac: number, width = 10): string {
  const filled = Math.max(0, Math.min(width, Math.round(frac * width)));
  return "█".repeat(filled) + "░".repeat(width - filled);
}

// ----- aggregation -----------------------------------------------------------

interface SourceAcc {
  alerts: number;
  severe: number;
  hosts: Set<string>;
  blockedAtIps: number;
  firstMs: number;
  lastMs: number;
  severityMax: Severity;
}

function newSourceAcc(t: number): SourceAcc {
  return {
    alerts: 0,
    severe: 0,
    hosts: new Set(),
    blockedAtIps: 0,
    firstMs: t,
    lastMs: t,
    severityMax: "info",
  };
}

/** Sanitise an arbitrary threshold ladder into a sorted, deduped, positive list. */
function sanitiseThresholds(input: readonly number[]): number[] {
  const set = new Set<number>();
  for (const raw of input) {
    const n = Math.floor(raw);
    if (Number.isFinite(n) && n >= 1) set.add(n);
  }
  return [...set].sort((a, b) => a - b);
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(
  hours: number,
  m: {
    candidateSources: number;
    candidateAlerts: number;
    oneShotSources: number;
    internalSourcesExcluded: number;
    recommendedThreshold: number | null;
  },
  curve: ThresholdPoint[],
  blockedSources: BlockedSource[],
  blockedAlreadyOnList: number,
): string[] {
  const out: string[] = [];
  if (!m.candidateSources || !curve.length) return out;

  const rec = curve.find((p) => p.recommended);
  if (rec) {
    out.push(
      `🎯 Recommended auto-block threshold: **block a source on its ${rec.threshold}${ordinal(rec.threshold)} alert**. ` +
        `That blocks **${rec.sourcesBlocked} source(s)** and prevents **${rec.alertsPrevented} alert(s)** ` +
        `(**${pct(rec.preventedFraction)}** of candidate volume) — leverage **${round2(rec.leverage)}** alerts silenced ` +
        `per firewall entry. This is the knee of the curve: the best trade of a small blocklist for a big drop in noise.`,
    );
  }

  // The aggressive end of the curve — what perfect-recall blocking would cost.
  const t1 = curve[0];
  if (t1 && rec && t1.threshold < rec.threshold) {
    out.push(
      `📉 Blocking on the *first* alert would prevent ${pct(t1.preventedFraction)} of volume but cost ` +
        `**${t1.sourcesBlocked} firewall entries** — ${t1.sourcesBlocked - (rec.sourcesBlocked)} more than the ` +
        `recommendation for only ${pct(Math.max(0, t1.preventedFraction - rec.preventedFraction))} extra prevention. ` +
        `The long tail of one-shot probes (${m.oneShotSources} source(s)) is what inflates that cost.`,
    );
  }

  // Watchlist promotion — the cleanest possible auto-block.
  const watched = blockedSources.filter((s) => s.watched && !s.blocked);
  if (watched.length) {
    const w = watched[0]!;
    out.push(
      `👁 **${watched.length} source(s)** the policy would block are already on your *watchlist* but not yet blocked — ` +
        `the cleanest possible action. Top: \`${w.ip}\` (${w.alerts} alert(s), ${w.severityMax}). An analyst already ` +
        `flagged it and the volume now agrees.`,
    );
  }

  // Agreement with the existing blocklist — validation the threshold is sane.
  if (blockedAlreadyOnList > 0 && blockedSources.length) {
    out.push(
      `✅ **${blockedAlreadyOnList} of ${blockedSources.length}** source(s) the policy picks are *already* blocklisted — ` +
        `the threshold agrees with actions you have already taken by hand, a good sign it is calibrated to your traffic.`,
    );
  }

  // Severe sources caught — the prevention that actually matters.
  const recSevere = rec?.severeSourcesBlocked ?? 0;
  if (recSevere > 0) {
    out.push(
      `🔴 Of the ${rec!.sourcesBlocked} source(s) blocked at the recommended threshold, **${recSevere}** have sent ` +
        `medium-or-worse traffic — auto-blocking is not just silencing scanner noise, it is cutting off real threats.`,
    );
  }

  // The honest structural blind spot.
  if (m.oneShotSources > 0) {
    out.push(
      `ℹ️ **${m.oneShotSources} candidate source(s) were seen exactly once** and cannot be caught by any threshold ≥ 2 — ` +
        `volume-based auto-blocking structurally misses the single-hit tail. Pair this policy with reputation/feed ` +
        `blocking for those.`,
    );
  }

  if (m.internalSourcesExcluded > 0) {
    out.push(
      `🏠 **${m.internalSourcesExcluded} internal source(s)** tripped rules and were excluded from candidacy — you do not ` +
        `auto-block your own hosts. An RFC1918 host firing alerts is a *compromise* tell: investigate, do not firewall it.`,
    );
  }

  return out;
}

function ordinal(n: number): string {
  const r = n % 100;
  if (r >= 11 && r <= 13) return "th";
  switch (n % 10) {
    case 1:
      return "st";
    case 2:
      return "nd";
    case 3:
      return "rd";
    default:
      return "th";
  }
}

// ----- markdown --------------------------------------------------------------

function curveTable(rows: ThresholdPoint[]): string {
  return mdTable(
    ["Block on Nth alert", "Sources blocked", "Alerts prevented", "Prevented", "", "Leverage", "Severe srcs", ""],
    rows.map((p) => [
      `${p.threshold}${ordinal(p.threshold)}`,
      String(p.sourcesBlocked),
      String(p.alertsPrevented),
      pct(p.preventedFraction),
      bar(p.preventedFraction),
      String(round2(p.leverage)),
      String(p.severeSourcesBlocked),
      p.recommended ? "⭐ recommended" : "",
    ]),
  );
}

function blockedTable(rows: BlockedSource[]): string {
  return mdTable(
    ["#", "Source", "Alerts", "Prevented", "Hosts", "Severe", "Sev", "Active span", "State"],
    rows.map((s, i) => {
      const state =
        (s.blocked ? "⛔ blocked" : "") +
        (s.watched ? `${s.blocked ? " " : ""}👁 watched` : "") +
        (!s.blocked && !s.watched ? "🆕 new" : "");
      return [
        String(i + 1),
        cell(s.ip),
        String(s.alerts),
        String(s.prevented),
        String(s.hostsReached),
        String(s.severe),
        cell(s.severityMax),
        cell(fmtDur(s.lastMs - s.firstMs)),
        state,
      ];
    }),
  );
}

function renderMarkdown(m: AutoblockReport): string {
  const lines: string[] = [];
  lines.push(`# 🚧 SecTool Auto-block Threshold Simulator`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** sweep "auto-block a source on its N-th alert" over the candidate population (external, routable, ` +
      `non-safelisted sources); for each N count blocks issued and alerts prevented (Σ max(0, alerts − N)); recommend ` +
      `the knee of the curve · **Candidates:** ${m.candidateSources} source(s) / ${m.candidateAlerts} alert(s)`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.candidateSources || !m.curve.length) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to simulate.`);
    } else if (!m.sourcedAlerts) {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but none carried a usable source IP, so no ` +
          `auto-block policy can be simulated.`,
      );
    } else {
      lines.push(
        `${m.sourcedAlerts} sourced alert(s) in the last ${m.hours} hour(s), but none came from an external, routable, ` +
          `non-safelisted source — there is no auto-block-eligible population to simulate. ` +
          (m.internalSourcesExcluded
            ? `(${m.internalSourcesExcluded} internal source(s) were excluded — you do not auto-block your own hosts.)`
            : ""),
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

  lines.push(`## Threshold curve`);
  lines.push("");
  lines.push(
    `Each row is a candidate auto-block policy. **Sources blocked** is the cost (firewall entries / false-positive ` +
      `surface); **alerts prevented** is the noise a block removes from the detection stream; **leverage** is ` +
      `prevention per block (higher = more efficient). The ⭐ row is the knee — nearest the ideal of *few blocks, lots ` +
      `prevented*.`,
  );
  lines.push("");
  lines.push(curveTable(m.curve));
  lines.push("");

  lines.push(`## Sources the recommended policy would block`);
  lines.push("");
  if (m.recommendedThreshold === null || !m.blockedSources.length) {
    lines.push(`_No source meets the recommended threshold._`);
  } else {
    lines.push(
      `At the recommended threshold (**block on the ${m.recommendedThreshold}${ordinal(m.recommendedThreshold)} ` +
        `alert**), these sources would be auto-blocked — ranked by the alert volume each removes. ` +
        `**${m.blockedAlreadyOnList}** are already blocklisted (the policy agrees with you); the rest are net-new.`,
    );
    lines.push("");
    lines.push(blockedTable(m.blockedSources));
    lines.push("");
    lines.push(
      `**Legend:** _Prevented_ = alerts a block would have removed (alerts − threshold). _State_ — **⛔ blocked** ` +
        `(already on the firewall list) · **👁 watched** (an analyst flagged it) · **🆕 new** (a fresh candidate).`,
    );
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. This is a **counterfactual on fixed arrivals**: it replays the alerts that landed ` +
      `and asks which a block would have suppressed, assuming the attacker keeps the same source IP — a determined ` +
      `actor who rotates IPs defeats any volume threshold, so prevention is an upper bound for rotators and an honest ` +
      `estimate for the commodity scanners that dominate the volume. **One-shot sources** (${m.oneShotSources} this ` +
      `window) cannot be caught by any threshold ≥ 2. **Safelisted (${m.safelistedSourcesExcluded}) and internal ` +
      `(${m.internalSourcesExcluded}) sources are excluded** from candidacy. These are IPS **detections**, not full ` +
      `flows, and a long look-back can hit the store's history cap — so the prevented volume is a lower bound. No live ` +
      `gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the auto-block threshold simulator report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link AutoblockOptions}: `limit`, a custom `thresholds` ladder,
 *              and a `nowMs` pin for deterministic tests.
 */
export function buildAutoblock(hours: number, opts: AutoblockOptions = {}): AutoblockReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const thresholds = sanitiseThresholds(opts.thresholds ?? DEFAULT_THRESHOLDS);
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const candidates = new Map<string, SourceAcc>();
  let sourced = 0;
  let internalExcluded = 0;
  let safelistedExcluded = 0;
  const internalSeen = new Set<string>();
  const safeSeen = new Set<string>();

  // Pass 1 — fold the candidate (external, routable, non-safelisted) population.
  for (const a of windowed) {
    const src = validIp(a.srcIp);
    if (!src) continue;
    sourced++;

    if (isPrivate(src)) {
      internalSeen.add(src);
      continue;
    }
    if (safeStore.has(src)) {
      safeSeen.add(src);
      continue;
    }

    const acc = candidates.get(src) ?? newSourceAcc(a.time);
    if (!candidates.has(src)) candidates.set(src, acc);
    acc.alerts++;
    acc.severityMax = maxSeverity(acc.severityMax, a.severity);
    if (isSevere(a.severity)) acc.severe++;
    if (a.time < acc.firstMs) acc.firstMs = a.time;
    if (a.time > acc.lastMs) acc.lastMs = a.time;
    const dst = validIp(a.dstIp);
    if (dst) acc.hosts.add(dst);
    if (classifyDisposition(a.action) === "blocked") acc.blockedAtIps++;
  }

  internalExcluded = internalSeen.size;
  safelistedExcluded = safeSeen.size;

  const candidateSources = candidates.size;
  const candidateAlerts = [...candidates.values()].reduce((n, c) => n + c.alerts, 0);
  const oneShotSources = [...candidates.values()].filter((c) => c.alerts === 1).length;

  // Sweep the threshold ladder. maxBlocks anchors the knee normalisation — it is
  // the most sources any threshold could block (threshold 1 = every candidate).
  const maxBlocks = candidateSources;
  const accList = [...candidates.values()];

  const rawCurve: ThresholdPoint[] = thresholds.map((threshold) => {
    let sourcesBlocked = 0;
    let alertsPrevented = 0;
    let severeSourcesBlocked = 0;
    for (const c of accList) {
      if (c.alerts >= threshold) {
        sourcesBlocked++;
        alertsPrevented += c.alerts - threshold;
        if (c.severe > 0) severeSourcesBlocked++;
      }
    }
    const preventedFraction = candidateAlerts ? round4(alertsPrevented / candidateAlerts) : 0;
    const leverage = sourcesBlocked ? round2(alertsPrevented / sourcesBlocked) : 0;
    // Distance to the ideal corner (0 blocks, 1.0 prevented), both axes in [0,1].
    const bNorm = maxBlocks ? sourcesBlocked / maxBlocks : 0;
    const kneeDistance = round4(Math.hypot(bNorm, 1 - preventedFraction));
    return {
      threshold,
      sourcesBlocked,
      alertsPrevented,
      preventedFraction,
      leverage,
      severeSourcesBlocked,
      kneeDistance,
      recommended: false,
    } satisfies ThresholdPoint;
  });

  // Recommend the knee: minimum distance to ideal. Ties → the larger threshold
  // (fewer blocks / the more conservative auto-action). Require at least one
  // block, so we never "recommend" a threshold no source can reach.
  const reachable = rawCurve.filter((p) => p.sourcesBlocked > 0);
  let recommendedThreshold: number | null = null;
  if (reachable.length) {
    const best = reachable.reduce((acc, p) =>
      p.kneeDistance < acc.kneeDistance ||
      (p.kneeDistance === acc.kneeDistance && p.threshold > acc.threshold)
        ? p
        : acc,
    );
    best.recommended = true;
    recommendedThreshold = best.threshold;
  }

  // The sources the recommended policy would block, ranked by noise removed.
  const blockedSources: BlockedSource[] =
    recommendedThreshold === null
      ? []
      : [...candidates.entries()]
          .filter(([, c]) => c.alerts >= recommendedThreshold!)
          .map(([ip, c]) => ({
            ip,
            alerts: c.alerts,
            prevented: c.alerts - recommendedThreshold!,
            hostsReached: c.hosts.size,
            severe: c.severe,
            severityMax: c.severityMax,
            alreadyBlockedAtIps: c.blockedAtIps,
            firstMs: c.firstMs,
            lastMs: c.lastMs,
            blocked: blockStore.has(ip),
            watched: watchStore.has(ip),
          }) satisfies BlockedSource)
          // Most noise removed first, then volume, then severity, then IP for stability.
          .sort(
            (x, y) =>
              y.prevented - x.prevented ||
              y.alerts - x.alerts ||
              sevRank(y.severityMax) - sevRank(x.severityMax) ||
              (x.ip < y.ip ? -1 : x.ip > y.ip ? 1 : 0),
          );

  const blockedAlreadyOnList = blockedSources.filter((s) => s.blocked).length;
  const cappedBlocked = blockedSources.slice(0, limit);

  const highlights = writeHighlights(
    safeHours,
    {
      candidateSources,
      candidateAlerts,
      oneShotSources,
      internalSourcesExcluded: internalExcluded,
      recommendedThreshold,
    },
    rawCurve,
    blockedSources,
    blockedAlreadyOnList,
  );

  const model: AutoblockReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    sourcedAlerts: sourced,
    candidateAlerts,
    candidateSources,
    oneShotSources,
    internalSourcesExcluded: internalExcluded,
    safelistedSourcesExcluded: safelistedExcluded,
    recommendedThreshold,
    curve: rawCurve,
    blockedSources: cappedBlocked,
    blockedAlreadyOnList,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded auto-block simulator report. */
export function autoblockFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-autoblock-${stamp}.md`;
}
