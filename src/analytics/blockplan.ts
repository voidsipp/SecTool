/**
 * Block-recommendation / candidate-blocklist worklist — "given everything the
 * gateway has detected, *which sources should I block next*, ranked by the
 * impact I'd actually gain by blocking them?"
 *
 * Every enforcement-flavoured report in this project so far points at a control
 * that already **exists**:
 *
 *   - efficacy.ts measures the per-*signature* enforcement gap (detect-only
 *     rules), not which *source* to act on,
 *   - recidivism.ts asks whether an existing **blocklist** entry actually stopped
 *     traffic (post-block re-offending),
 *   - hygiene.ts asks which existing **blocklist** entries are stale and prunable
 *     (the *remove* side),
 *   - safelist.ts audits the **allow** side, watchlist.ts shows already-watched
 *     activity, suppaudit.ts/noise.ts audit suppression.
 *
 * Nothing produces the single most operational artefact a defender wants from an
 * alert stream: a **ranked, copy-pasteable list of new IPs to block**, with an
 * honest estimate of what each block buys. A leaderboard (risk.ts / focus.ts)
 * ranks *threat*, but it happily re-lists addresses you have already blocked,
 * already vetted as safe, or your own internal hosts — none of which belongs on
 * a "block these next" worklist. This report is the **add** side of the blocklist
 * lifecycle, the mirror of hygiene.ts.
 *
 * For every **external, routable** source IP in the window that is **not already
 * blocklisted and not safelisted**, it folds the windowed alerts and computes a
 * severity-weighted **impact score**, the distinct internal hosts reached (a
 * source hitting your assets outranks one banging on a closed port), the
 * disposition split, the active span, and the per-day rate. From the worst
 * severity, the severe (≥ medium) volume, the score and the host breadth it
 * assigns a one-word **recommendation**:
 *
 *   - **⛔ block** — high/critical severity reaching an internal host, *or*
 *     sustained severe volume, *or* a high impact score. The clear-cut worklist:
 *     these are doing real, repeated harm and nothing currently stops them.
 *   - **🤔 consider** — medium severity, a notable score, or broad host reach
 *     (a scanner). Worth a human glance before committing an edge block.
 *   - **👁 monitor** — low/info noise only. Surfaced for completeness, never
 *     recommended for blocking; a candidate for the watchlist instead.
 *
 * The crucial honesty axis is **preventability**. A source-level firewall block
 * drops *everything* from that IP at the edge — but the IPS may already be
 * dropping some of it at the signature level (`action: blocked`). So the report
 * separates two numbers per source: the **let-through** alerts (gateway detected
 * but passed) that a block would *newly* prevent, and the total volume a block
 * removes from the detection stream regardless. The headline sums the
 * let-through volume across the block tier — the genuine security gain — rather
 * than inflating the number with traffic already being dropped.
 *
 * Deliberately **excluded** from recommendations (each is the wrong tool):
 *
 *   - **Already-blocklisted** sources — the action is already taken (recidivism.ts
 *     audits whether it held).
 *   - **Safelisted** sources — vetted benign; recommending a block would fight the
 *     operator's own curation (safelist.ts audits whether that trust still holds).
 *   - **Internal** sources — an RFC1918 host tripping rules is a *compromise* tell,
 *     not an edge-block candidate; you isolate and investigate it, you do not add
 *     your own host to the firewall drop list. Their count is surfaced as a
 *     call-out so they are never silently dropped.
 *
 * **Watchlist promotion** is called out specially: a block-tier source already on
 * the watchlist is the cleanest possible block — an analyst already flagged it,
 * and the data now says it has earned an edge drop.
 *
 * Honest caveats baked into the output:
 *
 *   - **Recommendation, not auto-action.** This never blocks anything; it ranks
 *     candidates for a human. Reactive/auto blocking lives elsewhere (respond/*).
 *   - **Detections, not flows.** SecTool stores IPS *detections*. A noisy source
 *     that never trips a rule is invisible here, so a quiet attacker can be
 *     under-ranked; the score is a lower bound.
 *   - **Disposition fidelity.** The let-through / blocked split leans on the
 *     gateway's `action` field; alerts with no recorded action are counted as
 *     *unknown* and never silently treated as either, so preventability is
 *     conservative.
 *   - **Exact source IP.** Scoring is per-address; an attacker rotating across a
 *     netblock is split into separate rows (netblock.ts / clusters.ts aggregate
 *     that view). A CIDR block is therefore out of scope here.
 *   - **Window-bounded & store-capped.** A long look-back can hit the alert
 *     store's history cap and undercount a slow-burn source.
 *
 * Pure in-memory math over alertStore (plus block / safe / watch membership) — no
 * SSH, no Claude, no network, and no mutation of any store. Output is both a
 * structured model and a ready-to-paste Markdown document, mirroring scan.ts,
 * safelist.ts, efficacy.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { triageStore } from "../store/triage.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** The three recommendation tiers a candidate source can fall into. */
export type BlockRecommendation = "block" | "consider" | "monitor";

/** Blocked / let-through / unknown disposition split for a candidate source. */
export interface DispositionSplit {
  /** Alerts the gateway already actively blocked/dropped at the signature level. */
  blocked: number;
  /** Alerts the gateway logged but let through — what a source block newly stops. */
  passed: number;
  /** Alerts with no recorded action (excluded from {@link passRate}). */
  unknown: number;
  /**
   * Fraction of *actioned* (blocked + passed) alerts that were let through,
   * 0..1 (4dp), or null when nothing was actioned. High means the IPS is mostly
   * watching this source land — a source block is the missing enforcement.
   */
  passRate: number | null;
}

/** Per-source block-candidate metrics over the window. */
export interface BlockCandidate {
  /** The external source IP being scored. */
  ip: string;
  /** The recommendation tier (see {@link BlockRecommendation}). */
  recommendation: BlockRecommendation;
  /** Severity-weighted impact score (Σ SEVERITY_WEIGHT) — the ranking key. */
  score: number;
  /** Total alerts attributed to this source in the window. */
  count: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Worst severity seen from this source. */
  severityMax: Severity;
  /** Per-severity counts, info → critical (zeros omitted). */
  bySeverity: Array<{ severity: Severity; count: number }>;
  /** Distinct destination hosts this source touched. */
  distinctHosts: number;
  /** Of {@link distinctHosts}, how many are internal (your assets). */
  internalTargets: number;
  /** Distinct signatures this source tripped. */
  distinctSignatures: number;
  /** The most-targeted internal host, if any (the asset most at risk). */
  topInternalTarget?: string;
  /** The most-tripped signature, for context. */
  topSignature?: string;
  /** Blocked / let-through / unknown disposition split. */
  disposition: DispositionSplit;
  /**
   * Alerts a source-level block would *newly* prevent (the let-through volume) —
   * the genuine security gain, distinct from traffic already being dropped.
   */
  preventable: number;
  /** Open (un-triaged) alerts from this source. */
  openCount: number;
  /** Earliest / latest alert times for this source (ms epoch). */
  firstSeen: number;
  lastSeen: number;
  /** Normalized alerts-per-day over the window. */
  perDay: number;
  /** The source is already on the watchlist — a clean promotion candidate. */
  watched: boolean;
}

/** Headline counts per recommendation tier. */
export interface TierCounts {
  block: number;
  consider: number;
  monitor: number;
}

export interface BlockPlanReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts carrying a valid source IP. */
  sourcedAlerts: number;
  /** Distinct external, routable, un-blocked, un-safelisted sources analysed. */
  candidateSources: number;
  /** External sources skipped because they are already blocklisted. */
  alreadyBlocked: number;
  /** External sources skipped because they are safelisted (vetted benign). */
  safelisted: number;
  /** Internal sources seen attacking — investigate, never edge-block (excluded). */
  internalSourcesExcluded: number;
  /** How many candidates fell into each tier. */
  tierCounts: TierCounts;
  /** Total alerts the block-tier sources accounted for this window. */
  blockTierAlerts: number;
  /** Of those, the let-through volume a block would *newly* prevent. */
  blockTierPreventable: number;
  /** Distinct internal hosts the block-tier sources are reaching. */
  blockTierInternalTargets: number;
  /** Block-tier sources already on the watchlist (cleanest promotions). */
  watchlistPromotions: number;
  /** The copy-paste worklist: block-tier source IPs, worst first. */
  recommendedBlocks: string[];
  /** Per-source candidate rows, highest impact first. */
  candidates: BlockCandidate[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface BlockPlanOptions {
  /** Max rows in the candidate table (clamped to [1, 500]). */
  limit?: number;
  /** Minimum alerts a source needs before it is scored (drops one-off noise). */
  minAlerts?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 30;
const DEFAULT_MIN_ALERTS = 2;
const MS_PER_HOUR = 3_600_000;
const TOP_BLOCKS = 50;

// --- recommendation thresholds (tunable knobs of the tiering heuristic) ------
/** Severe (≥ medium) alerts at/above which a source is a clear block. */
const BLOCK_MIN_SEVERE = 3;
/** Severity-weighted impact score at/above which a source is a clear block. */
const BLOCK_MIN_SCORE = 60;
/** Score at/above which a source is at least worth considering. */
const CONSIDER_MIN_SCORE = 12;
/** Distinct hosts at/above which a source reads as a broad scanner (consider). */
const BROAD_HOSTS = 5;

// ----- classifiers / helpers (mirror scan.ts / safelist.ts conventions) ------

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

function round1(n: number): number {
  return Math.round(n * 10) / 10;
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

function fmtAgo(ms: number, now: number): string {
  const s = Math.max(0, Math.round((now - ms) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function clip(s: string, max = 44): string {
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
  let count = 0;
  for (const [k, c] of counts) {
    if (c > count || (c === count && key !== undefined && k < key)) {
      key = k;
      count = c;
    }
  }
  return key;
}

const REC_LABEL: Record<BlockRecommendation, string> = {
  block: "⛔ Block",
  consider: "🤔 Consider",
  monitor: "👁 Monitor",
};

/** Tier ordering for ranking (block worst → monitor best). */
const TIER_RANK: Record<BlockRecommendation, number> = { block: 2, consider: 1, monitor: 0 };

/**
 * Assign a recommendation tier from a candidate's threat shape. A high/critical
 * signature actually reaching one of our assets is the clearest block; sustained
 * severe volume or a high impact score also qualify. Medium severity, a notable
 * score, or broad host reach warrant a look; everything else is monitor-only.
 */
function recommend(
  severityMax: Severity,
  severe: number,
  score: number,
  distinctHosts: number,
  internalTargets: number,
): BlockRecommendation {
  if (sevRank(severityMax) >= 3 && internalTargets > 0) return "block";
  if (severe >= BLOCK_MIN_SEVERE) return "block";
  if (score >= BLOCK_MIN_SCORE) return "block";
  if (sevRank(severityMax) >= 2 || score >= CONSIDER_MIN_SCORE || distinctHosts >= BROAD_HOSTS) {
    return "consider";
  }
  return "monitor";
}

// ----- aggregation -----------------------------------------------------------

interface SourceAcc {
  count: number;
  score: number;
  severe: number;
  severityMax: Severity;
  bySev: Map<Severity, number>;
  hosts: Set<string>;
  internalHosts: Set<string>;
  signatures: Set<string>;
  internalHostCounts: Map<string, number>;
  sigCounts: Map<string, number>;
  blocked: number;
  passed: number;
  unknown: number;
  openCount: number;
  firstSeen: number;
  lastSeen: number;
}

function newSourceAcc(): SourceAcc {
  return {
    count: 0,
    score: 0,
    severe: 0,
    severityMax: "info",
    bySev: new Map(),
    hosts: new Set(),
    internalHosts: new Set(),
    signatures: new Set(),
    internalHostCounts: new Map(),
    sigCounts: new Map(),
    blocked: 0,
    passed: 0,
    unknown: 0,
    openCount: 0,
    firstSeen: 0,
    lastSeen: 0,
  };
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(model: Omit<BlockPlanReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (!model.candidateSources) return out;

  if (model.tierCounts.block > 0) {
    const lead = model.candidates.find((c) => c.recommendation === "block");
    out.push(
      `⛔ **${model.tierCounts.block} source(s) are recommended for blocking** — together they account for ` +
        `${model.blockTierAlerts} alert(s) this window, **${model.blockTierPreventable} of which the gateway let ` +
        `through** (a source block stops those at the edge). Worst is \`${lead?.ip}\` ` +
        `(peak **${lead?.severityMax}**, ${lead?.count} alert(s), score ${lead ? Math.round(lead.score) : 0}).`,
    );
  } else {
    out.push(
      `✅ No source crossed the block threshold this window — nothing currently merits a new edge block ` +
        `(high/critical reaching an asset, sustained severe volume, or a high impact score).`,
    );
  }

  if (model.blockTierInternalTargets > 0) {
    out.push(
      `🎯 The block-tier sources are reaching **${model.blockTierInternalTargets} distinct internal host(s)** — ` +
        `blocking them removes active pressure on your own assets, not just inbound noise.`,
    );
  }

  if (model.watchlistPromotions > 0) {
    const promos = model.candidates
      .filter((c) => c.recommendation === "block" && c.watched)
      .slice(0, 5)
      .map((c) => `\`${c.ip}\``);
    out.push(
      `👁→⛔ **${model.watchlistPromotions} block candidate(s) are already on your watchlist** ` +
        `(${promos.join(", ")}) — the cleanest possible promotion: an analyst already flagged them and the data ` +
        `now says block.`,
    );
  }

  if (model.tierCounts.consider > 0) {
    out.push(
      `🤔 ${model.tierCounts.consider} further source(s) are *consider*-tier — medium severity, a notable score, ` +
        `or broad host reach. Worth a glance before an edge block.`,
    );
  }

  if (model.safelisted > 0) {
    out.push(
      `🟢 ${model.safelisted} active external source(s) were **excluded as safelisted** — vetted benign, so never ` +
        `recommended here. If one is misbehaving, the safelist audit (\`--safelist\`) is the report that surfaces it.`,
    );
  }

  if (model.internalSourcesExcluded > 0) {
    out.push(
      `🏠 ${model.internalSourcesExcluded} *internal* host(s) tripped rules as a **source** and were excluded — an ` +
        `internal box attacking is a compromise tell to isolate and investigate, not an edge-block candidate.`,
    );
  }

  if (model.alreadyBlocked > 0) {
    out.push(
      `🔁 ${model.alreadyBlocked} active source(s) are **already blocklisted** (excluded). Use \`--recidivism\` to ` +
        `confirm those blocks are actually holding.`,
    );
  }

  return out;
}

// ----- markdown --------------------------------------------------------------

function candidateTable(rows: BlockCandidate[], now: number): string {
  return mdTable(
    ["#", "Source", "Rec", "Score", "Alerts", "Severe", "Peak", "Hosts (int)", "Sigs", "Let-through", "Pass rate", "/day", "Last"],
    rows.map((c, i) => [
      String(i + 1),
      cell(c.ip) + (c.watched ? " 👁" : ""),
      cell(REC_LABEL[c.recommendation]),
      String(Math.round(c.score)),
      String(c.count),
      String(c.severe),
      cell(c.severityMax),
      `${c.distinctHosts} (${c.internalTargets})`,
      String(c.distinctSignatures),
      String(c.preventable),
      c.disposition.passRate === null ? "—" : pct(c.disposition.passRate),
      round1(c.perDay).toFixed(1),
      c.lastSeen ? fmtAgo(c.lastSeen, now) : "—",
    ]),
  );
}

function renderMarkdown(model: BlockPlanReport): string {
  const lines: string[] = [];
  lines.push(`# ⛔ SecTool Block-Recommendation / Candidate-Blocklist Worklist`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(model.windowEndMs)}`);
  lines.push(`**Window:** last ${model.hours} hour(s) — ${fmtTime(model.windowStartMs)} → ${fmtTime(model.windowEndMs)}`);
  lines.push(
    `**Candidates:** ${model.candidateSources} external source(s) · ` +
      `⛔ ${model.tierCounts.block} block · 🤔 ${model.tierCounts.consider} consider · 👁 ${model.tierCounts.monitor} monitor`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!model.candidateSources) {
    if (!model.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${model.hours} hour(s) — nothing to recommend.`);
    } else {
      lines.push(
        `${model.totalWindowAlerts} alert(s) in the last ${model.hours} hour(s), but no external, routable source ` +
          `(that is not already blocklisted or safelisted) had enough volume to score ` +
          `(min ${DEFAULT_MIN_ALERTS} alerts/source by default). Nothing to recommend blocking.`,
      );
    }
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed; nothing was blocked._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of model.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(
    `**Method:** every external, routable source IP that is **not already blocklisted and not safelisted** is folded ` +
      `from windowed alerts into a severity-weighted impact score (info=1 · low=3 · medium=9 · high=27 · critical=81), ` +
      `then tiered: **⛔ block** (high/critical reaching an asset, ≥${BLOCK_MIN_SEVERE} severe alerts, or score ` +
      `≥${BLOCK_MIN_SCORE}) · **🤔 consider** (medium severity, score ≥${CONSIDER_MIN_SCORE}, or ≥${BROAD_HOSTS} hosts) · ` +
      `**👁 monitor** (low/info only). Ranked by impact score · **Sourced alerts:** ${model.sourcedAlerts} of ` +
      `${model.totalWindowAlerts}. Offline, deterministic, read-only — nothing is blocked.`,
  );
  lines.push("");

  // The copy-paste worklist first — the whole point of the report.
  if (model.recommendedBlocks.length) {
    lines.push(`## Recommended blocks (copy-paste worklist)`);
    lines.push("");
    lines.push(
      `The ${model.recommendedBlocks.length} block-tier source(s), worst first. Blocking them would have stopped ` +
        `**${model.blockTierPreventable} let-through alert(s)** this window (of ${model.blockTierAlerts} total from ` +
        `these sources). Review before applying — this is a recommendation, not an action.`,
    );
    lines.push("");
    lines.push("```");
    for (const ip of model.recommendedBlocks) lines.push(ip);
    lines.push("```");
    lines.push("");
  }

  lines.push(`## Candidate sources by impact`);
  lines.push("");
  lines.push(candidateTable(model.candidates, model.windowEndMs));
  lines.push("");
  lines.push(
    `**Legend:** _Rec_ — **⛔ block** / **🤔 consider** / **👁 monitor**. _Score_ = severity-weighted impact ` +
      `(the ranking key). _Hosts (int)_ = distinct destination hosts touched (of which internal/your assets). ` +
      `_Let-through_ = alerts the gateway detected but **passed** — what a source block newly prevents (traffic the ` +
      `IPS already drops is excluded). _Pass rate_ = share of *actioned* alerts let through. **👁** = already on the ` +
      `watchlist (a clean promotion).`,
  );
  lines.push("");

  // Per-candidate detail for the block tier, so the doc stands alone.
  const blockTier = model.candidates.filter((c) => c.recommendation === "block");
  if (blockTier.length) {
    const detailLimit = Math.min(blockTier.length, 10);
    lines.push(`## Detail — top ${detailLimit} block candidate(s)`);
    lines.push("");
    for (let i = 0; i < detailLimit; i++) {
      const c = blockTier[i]!;
      lines.push(`### ${i + 1}. ${c.ip} — ${REC_LABEL[c.recommendation]}` + (c.watched ? " (👁 already watchlisted)" : ""));
      lines.push("");
      lines.push(
        `- **Impact:** score ${Math.round(c.score)} · ${c.count} alert(s) (${round1(c.perDay).toFixed(1)}/day) · ` +
          `peak **${c.severityMax}** · ${c.severe} severe (≥ medium)`,
      );
      lines.push(
        `- **Reach:** ${c.distinctHosts} distinct host(s)` +
          (c.internalTargets ? `, **${c.internalTargets} internal**` : "") +
          (c.topInternalTarget ? ` (most-hit asset \`${c.topInternalTarget}\`)` : "") +
          ` · ${c.distinctSignatures} signature(s)`,
      );
      if (c.bySeverity.length) {
        lines.push(`- **Severity mix:** ${c.bySeverity.map((s) => `${s.severity} ×${s.count}`).join(" · ")}`);
      }
      if (c.topSignature) lines.push(`- **Top signature:** ${clip(c.topSignature, 64)}`);
      lines.push(
        `- **Disposition:** ${c.disposition.blocked} already blocked / **${c.disposition.passed} let through** / ` +
          `${c.disposition.unknown} unknown · ${c.openCount} open in triage`,
      );
      lines.push(
        `- **Span:** ${c.firstSeen ? fmtTime(c.firstSeen) : "—"} → ${c.lastSeen ? fmtTime(c.lastSeen) : "—"} ` +
          `(${c.lastSeen ? fmtAgo(c.lastSeen, model.windowEndMs) : "—"})`,
      );
      lines.push("");
    }
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from ${model.sourcedAlerts} sourced alert(s). This is a **recommendation engine**, ` +
      `not an actuator — it never blocks anything (reactive/auto blocking lives in respond/*). Already-blocklisted, ` +
      `safelisted, and **internal** sources are deliberately excluded (the action is taken, vetted benign, or a ` +
      `compromise to investigate respectively). Scoring is per-**exact-IP** over IPS **detections** — an attacker ` +
      `rotating across a netblock is split into rows (see \`--netblocks\`), and a source that never trips a rule is ` +
      `invisible, so the score is a lower bound. The let-through / blocked split leans on the gateway's \`action\` ` +
      `field; unrecorded actions are counted as unknown, never silently enforced. A long look-back can hit the ` +
      `store's history cap. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the block-recommendation / candidate-blocklist worklist from the stored
 * alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link BlockPlanOptions}: `limit`, `minAlerts`, and a `nowMs` pin
 *              for deterministic tests.
 */
export function buildBlockPlan(hours: number, opts: BlockPlanOptions = {}): BlockPlanReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(500, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minAlerts = Math.max(1, Math.floor(opts.minAlerts ?? DEFAULT_MIN_ALERTS));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;
  const windowDays = safeHours / 24;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const sources = new Map<string, SourceAcc>();
  let sourced = 0;
  // Counts of active external sources we *excluded* from candidacy, for honesty.
  const excludedBlocked = new Set<string>();
  const excludedSafe = new Set<string>();
  const excludedInternal = new Set<string>();

  for (const a of windowed) {
    const src = validIp(a.srcIp);
    if (!src) continue;
    sourced++;

    // Exclusions: internal hosts, already-blocked, and safelisted addresses are
    // each the wrong target for a *new* edge block. Track them for the call-outs
    // but never accumulate a candidate row.
    if (isPrivate(src)) {
      excludedInternal.add(src);
      continue;
    }
    if (blockStore.has(src)) {
      excludedBlocked.add(src);
      continue;
    }
    if (safeStore.has(src)) {
      excludedSafe.add(src);
      continue;
    }

    const acc = sources.get(src) ?? newSourceAcc();
    if (!sources.has(src)) sources.set(src, acc);
    acc.count++;
    acc.score += weightOf(a.severity);
    acc.severityMax = maxSeverity(acc.severityMax, a.severity);
    const sev = (a.severity as Severity) ?? "info";
    acc.bySev.set(sev, (acc.bySev.get(sev) ?? 0) + 1);
    if (isSevere(a.severity)) acc.severe++;
    if (acc.firstSeen === 0 || a.time < acc.firstSeen) acc.firstSeen = a.time;
    if (a.time > acc.lastSeen) acc.lastSeen = a.time;

    const dst = validIp(a.dstIp);
    if (dst) {
      acc.hosts.add(dst);
      if (isPrivate(dst)) {
        acc.internalHosts.add(dst);
        acc.internalHostCounts.set(dst, (acc.internalHostCounts.get(dst) ?? 0) + 1);
      }
    }

    if (a.signature) {
      acc.signatures.add(a.signature);
      acc.sigCounts.set(a.signature, (acc.sigCounts.get(a.signature) ?? 0) + 1);
    }

    const disp = classifyDisposition(a.action);
    if (disp === "blocked") acc.blocked++;
    else if (disp === "passed") acc.passed++;
    else acc.unknown++;

    if ((triageStore.get(a.id)?.status ?? "open") === "open") acc.openCount++;
  }

  const tierCounts: TierCounts = { block: 0, consider: 0, monitor: 0 };

  const built: BlockCandidate[] = [...sources.entries()]
    .filter(([, acc]) => acc.count >= minAlerts)
    .map(([ip, acc]) => {
      const distinctHosts = acc.hosts.size;
      const internalTargets = acc.internalHosts.size;
      const recommendation = recommend(acc.severityMax, acc.severe, acc.score, distinctHosts, internalTargets);
      tierCounts[recommendation]++;
      const actioned = acc.blocked + acc.passed;
      const bySeverity = SEVERITY_ORDER.map((severity) => ({ severity, count: acc.bySev.get(severity) ?? 0 })).filter(
        (x) => x.count > 0,
      );
      return {
        ip,
        recommendation,
        score: acc.score,
        count: acc.count,
        severe: acc.severe,
        severityMax: acc.severityMax,
        bySeverity,
        distinctHosts,
        internalTargets,
        distinctSignatures: acc.signatures.size,
        topInternalTarget: topOf(acc.internalHostCounts),
        topSignature: topOf(acc.sigCounts),
        disposition: {
          blocked: acc.blocked,
          passed: acc.passed,
          unknown: acc.unknown,
          passRate: actioned ? round4(acc.passed / actioned) : null,
        },
        preventable: acc.passed,
        openCount: acc.openCount,
        firstSeen: acc.firstSeen,
        lastSeen: acc.lastSeen,
        perDay: acc.count / Math.max(windowDays, 1 / 24),
        watched: watchStore.has(ip),
      } satisfies BlockCandidate;
    })
    // Highest impact first: tier, then score, then severe volume, then recency.
    .sort(
      (x, y) =>
        TIER_RANK[y.recommendation] - TIER_RANK[x.recommendation] ||
        y.score - x.score ||
        y.severe - x.severe ||
        y.count - x.count ||
        y.lastSeen - x.lastSeen ||
        (x.ip < y.ip ? -1 : x.ip > y.ip ? 1 : 0),
    );

  const blockTier = built.filter((c) => c.recommendation === "block");
  const blockTierIps = new Set(blockTier.map((c) => c.ip));
  const blockTierInternalTargets = new Set<string>();
  for (const [ip, acc] of sources) {
    if (blockTierIps.has(ip)) for (const h of acc.internalHosts) blockTierInternalTargets.add(h);
  }

  const base: Omit<BlockPlanReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    sourcedAlerts: sourced,
    candidateSources: built.length,
    alreadyBlocked: excludedBlocked.size,
    safelisted: excludedSafe.size,
    internalSourcesExcluded: excludedInternal.size,
    tierCounts,
    blockTierAlerts: blockTier.reduce((n, c) => n + c.count, 0),
    blockTierPreventable: blockTier.reduce((n, c) => n + c.preventable, 0),
    blockTierInternalTargets: blockTierInternalTargets.size,
    watchlistPromotions: blockTier.filter((c) => c.watched).length,
    recommendedBlocks: blockTier.slice(0, TOP_BLOCKS).map((c) => c.ip),
    candidates: built.slice(0, limit),
  };
  const highlights = writeHighlights(base);
  const model: BlockPlanReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded block-recommendation worklist. */
export function blockPlanFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-blockplan-${stamp}.md`;
}
