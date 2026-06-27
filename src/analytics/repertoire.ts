/**
 * Attacker repertoire / sophistication report — "which sources are running a
 * *toolkit* (recon → access → exploit → C2, many techniques), and which are
 * one-trick noise?"
 *
 * Almost every attacker-centric report in this project ranks a source by *how
 * much* it does, never by *how many different things* it does:
 *
 *   - persistence.ts / focus.ts / netblock.ts rank a source by **longevity** or
 *     **footprint** — a scanner that fires the same single signature ten thousand
 *     times tops them, even though it only knows one trick.
 *   - spread.ts / scan.ts rank a source by **reach** (how many hosts/ports it
 *     touches) — breadth across *targets*, but blind to breadth across the
 *     *attack lifecycle*: a horizontal SMB sweep and a full recon→exploit→C2
 *     intrusion both look like "wide" there.
 *   - escalation.ts ranks a source by its **severity trajectory** over time —
 *     whether it is getting *worse*, not how *varied* its methods are.
 *   - cooccurrence.ts finds which **signatures co-fire** across actors (pairwise
 *     association rules); classify.ts rolls the **classification** taxonomy up
 *     *globally* (the whole window's threat mix); killchain.ts maps alerts to
 *     stages and tracks the **internal host's** progression. None of them rank
 *     the **external attacker** by the *breadth of its own offensive repertoire*.
 *
 * That breadth is the sharpest sophistication signal the IPS stream holds. A
 * source that trips one classtype five hundred times is automated background
 * noise — a botnet member doing the one thing it was built for. A source that
 * walks **reconnaissance → delivery → exploitation → command-and-control**,
 * tripping a dozen distinct signatures across several threat classes, is a
 * *hands-on operator running a toolkit* — far more dangerous at a fraction of the
 * volume, and exactly what raw-count rankings bury. When that source is one of
 * *your own* hosts, a wide outbound repertoire (especially reaching the
 * exploit/C2/objective stages) is a compromise-in-progress, not an inbound probe.
 *
 * For every source IP over the window this report folds the windowed alerts and
 * measures three orthogonal breadth axes:
 *
 *   - **Stage breadth** — distinct *kill-chain stages* the source reaches
 *     (recon / access / exploit / c2 / objective), mapped with the very same
 *     {@link classifyStage} heuristic that powers killchain.ts, plus the
 *     **furthest** stage on the chain. Spanning multiple successive stages is the
 *     textbook intrusion arc and the strongest sophistication tell.
 *   - **Class breadth** — distinct Suricata *classifications* (threat classes)
 *     the source trips, resolved exactly as classify.ts resolves them
 *     (classification → category → "(unclassified)").
 *   - **Technique breadth** — distinct *signatures* fired (the concrete tools /
 *     exploits), a finer-grained view of how many different methods are in play.
 *
 * From those it computes a 0–100 **sophistication score** (stage breadth weighted
 * heaviest, then class and technique breadth, then how far down the chain it
 * reached, with a small worst-severity nudge) and assigns a one-word **tier**:
 *
 *   - **operator** — reaches **≥3 distinct kill-chain stages**: a multi-stage
 *     intrusion in motion, the single highest-priority thing to act on.
 *   - **toolkit** — spans **2 stages** or **≥3 threat classes**: more than one
 *     trick, a varied attacker worth a closer look.
 *   - **specialist** — a single stage but **multiple signatures / classes**: knows
 *     one thing and does it many ways (a dedicated brute-forcer, a vuln-specific
 *     exploiter).
 *   - **probe** — minimal breadth: the long tail of one-signature scanners and
 *     one-off noise.
 *
 * Sources are ranked by sophistication score (not volume) so the quiet,
 * many-method operator floats above the loud one-trick flood. Each row also
 * carries a compact **stage strip** (①②③④⑤ lit for the stages reached), the
 * blocked-vs-passed split (a sophisticated source whose traffic is *let through*
 * is the worst case), worst severity, the top class / signature, and blocklist /
 * watchlist / safelist membership.
 *
 * Honest caveats baked into the output:
 *
 *   - **Stage & class are heuristics.** The kill-chain stage is a regex over
 *     classification + category + signature text (shared with killchain.ts); the
 *     threat class is Suricata's own `classification` (or the coarser `category`
 *     when absent). Both can mis-bucket an oddly-named rule, so the raw distinct
 *     counts are always shown alongside the derived tier.
 *   - **Breadth needs labels.** A source whose alerts carry no classification and
 *     map only to off-chain `other` will read as a low-breadth "probe" even if it
 *     is doing something nasty under an unhelpful rule name. Coverage of the
 *     labelling fields is reported so a thin taxonomy is visible, not silent.
 *   - **Alerts, not full flows.** SecTool stores IPS *detections*; a stage a
 *     source executed without tripping a rule is invisible, so repertoire breadth
 *     is a lower bound and a surgical operator can under-read.
 *   - **Window-bounded & store-capped.** A long look-back can hit the store's
 *     history cap and undercount breadth.
 *
 * Pure in-memory math over alertStore (plus blocklist / watchlist / safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring scan.ts, killchain.ts,
 * classify.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { classifyStage, STAGES, type StageKey } from "./killchain.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** The four sophistication tiers a source's repertoire can fall into. */
export type RepertoireTier = "operator" | "toolkit" | "specialist" | "probe";

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
   * null when nothing was actioned. High on a sophisticated source means its
   * multi-stage activity is reaching your hosts unblocked — the worst case.
   */
  passRate: number | null;
}

/** Per-source repertoire / sophistication metrics over the window. */
export interface RepertoireSource {
  /** The source IP. */
  ip: string;
  /** True when the source is one of our own hosts (RFC1918 / loopback / …). */
  internal: boolean;
  /** The assigned sophistication tier (see {@link RepertoireTier}). */
  tier: RepertoireTier;
  /** 0–100 sophistication score — the ranking key. */
  sophistication: number;
  /** Distinct on-chain kill-chain stages this source reached (0–5). */
  distinctStages: number;
  /** The on-chain stage keys reached, in kill-chain order. */
  stages: StageKey[];
  /** The furthest stage reached (highest chain position), or null if only off-chain. */
  furthestStage: StageKey | null;
  /** Distinct threat classifications (classes) this source tripped. */
  distinctClasses: number;
  /** Distinct signatures (techniques / tools) this source fired. */
  distinctSignatures: number;
  /** Distinct destination hosts this source touched. */
  distinctHosts: number;
  /** Total alerts attributed to this source in the window. */
  count: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Severity-weighted score (Σ SEVERITY_WEIGHT) — a secondary signal. */
  score: number;
  /** Worst severity seen from this source. */
  severityMax: Severity;
  /** The most-frequent threat class for this source, if any. */
  topClass?: string;
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

/** Count of sources falling into each tier (the headline distribution). */
export interface TierCounts {
  operator: number;
  toolkit: number;
  specialist: number;
  probe: number;
}

export interface RepertoireReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts carrying a valid source IP (the analysable set). */
  sourcedAlerts: number;
  /** Of those, alerts that mapped to a real on-chain kill-chain stage. */
  onChainAlerts: number;
  /** Of those, alerts carrying a first-class `classification` (not derived). */
  classifiedAlerts: number;
  /** Distinct source IPs analysed (passed the min-alerts floor). */
  distinctSources: number;
  /** How many sources fell into each tier. */
  tierCounts: TierCounts;
  /** Per-source repertoire rows, most sophisticated first. */
  sources: RepertoireSource[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface RepertoireOptions {
  /** Max rows in the per-source table (clamped to [1, 200]). */
  limit?: number;
  /** Minimum alerts a source needs before it is analysed (drops one-off noise). */
  minAlerts?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const DEFAULT_MIN_ALERTS = 2;
const MS_PER_HOUR = 3_600_000;

/** On-chain stages in kill-chain order (excludes the off-chain `other` bucket). */
const ON_CHAIN = STAGES.filter((s) => s.chainIndex >= 0).sort((a, b) => a.chainIndex - b.chainIndex);
const STAGE_INDEX = new Map<StageKey, number>(ON_CHAIN.map((s, i) => [s.key, i]));

// ----- classifiers / helpers (mirror scan.ts / classify.ts) ------------------

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

/**
 * Resolve the threat-class label for an alert. Prefers the Suricata
 * `classification`; falls back to the coarser event `category`; failing both an
 * explicit "(unclassified)" bucket so nothing is silently dropped. Mirrors the
 * resolution in classify.ts so the two reports agree on what a "class" is.
 */
function classOf(a: StoredAlert): { label: string; derived: boolean } {
  const cls = (a.classification ?? "").trim();
  if (cls) return { label: cls, derived: false };
  const cat = (a.category ?? "").trim();
  if (cat) return { label: cat, derived: true };
  return { label: "(unclassified)", derived: true };
}

/** Title of an on-chain stage key, for prose. */
function stageTitle(k: StageKey | null): string {
  if (!k) return "—";
  return STAGES.find((s) => s.key === k)?.title ?? k;
}

/**
 * Render the stage strip: the five on-chain glyphs (①..⑤) with the ones the
 * source reached lit and the rest dimmed to a middle dot — a kill-chain reach
 * bar that reads at a glance, mirroring killchain.ts's per-host strip.
 */
function stageStrip(reached: Set<StageKey>): string {
  return ON_CHAIN.map((s) => (reached.has(s.key) ? s.glyph : "·")).join("");
}

/** Human label + emoji for a tier, ordered by sophistication. */
function tierLabel(t: RepertoireTier): string {
  switch (t) {
    case "operator":
      return "🎯 operator";
    case "toolkit":
      return "🧰 toolkit";
    case "specialist":
      return "🔧 specialist";
    case "probe":
      return "• probe";
  }
}

/**
 * Assign a sophistication tier from the three breadth axes. Stage breadth is the
 * decisive axis (an attacker walking the chain is the textbook intrusion); class
 * and technique breadth refine the rest.
 */
function classifyTier(stages: number, classes: number, signatures: number): RepertoireTier {
  if (stages >= 3) return "operator";
  if (stages === 2 || classes >= 3) return "toolkit";
  if (signatures >= 3 || classes >= 2) return "specialist";
  return "probe";
}

/**
 * Compute the 0–100 sophistication score from the breadth axes + worst severity.
 * Weights (max contribution): stage breadth 45, chain depth 15, class breadth 20,
 * technique breadth 12, severity 8 — summing to 100 at full saturation. Stage
 * breadth dominates because spanning the lifecycle is the strongest tell; volume
 * is deliberately absent so a quiet many-method operator outranks a loud flood.
 */
function sophisticationScore(
  distinctStages: number,
  furthestIndex: number,
  distinctClasses: number,
  distinctSignatures: number,
  severityMax: Severity,
): number {
  const stagePts = Math.min(distinctStages, ON_CHAIN.length) * (45 / ON_CHAIN.length); // 9 / stage
  const depthPts = furthestIndex < 0 ? 0 : (furthestIndex / (ON_CHAIN.length - 1)) * 15;
  const classPts = (Math.min(distinctClasses, 5) / 5) * 20;
  const techPts = (Math.min(distinctSignatures, 8) / 8) * 12;
  const sevPts = (sevRank(severityMax) / (SEVERITY_ORDER.length - 1)) * 8;
  return Math.max(0, Math.min(100, Math.round(stagePts + depthPts + classPts + techPts + sevPts)));
}

// ----- aggregation ----------------------------------------------------------

interface SourceAcc {
  count: number;
  score: number;
  severe: number;
  hosts: Set<string>;
  stages: Set<StageKey>;
  classes: Set<string>;
  signatures: Set<string>;
  classCounts: Map<string, number>;
  sigCounts: Map<string, number>;
  blocked: number;
  passed: number;
  unknown: number;
  severityMax: Severity;
}

function newSourceAcc(): SourceAcc {
  return {
    count: 0,
    score: 0,
    severe: 0,
    hosts: new Set(),
    stages: new Set(),
    classes: new Set(),
    signatures: new Set(),
    classCounts: new Map(),
    sigCounts: new Map(),
    blocked: 0,
    passed: 0,
    unknown: 0,
    severityMax: "info",
  };
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  m: { distinctSources: number; onChainAlerts: number; sourcedAlerts: number },
  tierCounts: TierCounts,
  sources: RepertoireSource[],
): string[] {
  const out: string[] = [];
  if (!sources.length) return out;

  // Overall tier distribution — how much of the traffic is sophisticated.
  const varied = tierCounts.operator + tierCounts.toolkit;
  out.push(
    `🧠 Over the last ${hours}h, **${m.distinctSources} source(s)** were active; **${varied}** show a *varied* ` +
      `repertoire (${tierCounts.operator} operator · ${tierCounts.toolkit} toolkit), ${tierCounts.specialist} ` +
      `specialist and ${tierCounts.probe} one-trick probe(s).`,
  );

  // The most sophisticated source overall — the lead to triage first.
  const lead = sources[0]!;
  out.push(
    `🥇 Most sophisticated is \`${lead.ip}\`${lead.internal ? " *(internal!)*" : ""} — **${tierLabel(lead.tier)}**, ` +
      `score **${lead.sophistication}/100**: ${lead.distinctStages} kill-chain stage(s) ` +
      `(furthest: ${stageTitle(lead.furthestStage)}), ${lead.distinctClasses} threat class(es), ` +
      `${lead.distinctSignatures} signature(s) across ${lead.count} alert(s).`,
  );

  // Multi-stage operators — the textbook intrusion arc, top priority.
  const operators = sources.filter((s) => s.tier === "operator");
  if (operators.length) {
    const o = operators[0]!;
    out.push(
      `🎯 **${operators.length} operator(s)** are walking ≥3 kill-chain stages — a multi-stage intrusion, not a ` +
        `scan. \`${o.ip}\` reached **${stageTitle(o.furthestStage)}** spanning ${o.distinctStages} stage(s); ` +
        `treat it as an incident, not noise.`,
    );
  }

  // Internal hosts with a wide outbound repertoire — a compromise tell.
  const insiders = sources.filter((s) => s.internal && s.tier !== "probe");
  if (insiders.length) {
    const i = insiders[0]!;
    out.push(
      `🚨 **${insiders.length} *internal* host(s)** show a varied repertoire (${tierLabel(i.tier)}) — an internal ` +
        `box reaching multiple attack stages is a lateral-movement / compromise tell, not an inbound attacker. ` +
        `Investigate \`${i.ip}\` first.`,
    );
  }

  // A sophisticated source whose activity is being let through — worst case.
  const leaky = sources
    .filter((s) => s.tier !== "probe" && s.disposition.passRate !== null && s.disposition.passed >= 3)
    .sort((a, b) => (b.disposition.passRate ?? 0) - (a.disposition.passRate ?? 0))[0];
  if (leaky && (leaky.disposition.passRate ?? 0) >= 0.5) {
    out.push(
      `⚠️ \`${leaky.ip}\`'s multi-method activity is **${pct(leaky.disposition.passRate!)} let through** ` +
        `(${leaky.disposition.passed} actioned alerts passed). A varied attacker reaching your hosts unblocked is ` +
        `the worst case — block the source and confirm exposure.`,
    );
  }

  // Labelling-coverage honesty — how much of the stream carried a stage at all.
  if (m.sourcedAlerts > 0) {
    const frac = m.onChainAlerts / m.sourcedAlerts;
    if (frac < 0.5) {
      out.push(
        `ℹ️ Only **${pct(frac)} of sourced alerts mapped to a kill-chain stage** — stage breadth (and the tier that ` +
          `leans on it) is a lower bound; a source under unhelpful rule names can under-read as a "probe".`,
      );
    }
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function sourceTable(rows: RepertoireSource[]): string {
  return mdTable(
    ["#", "Source", "Tier", "Score", "Stages", "Reach", "Classes", "Sigs", "Hosts", "Alerts", "Top class", "Passed", "Flags"],
    rows.map((s, i) => {
      const reached = new Set(s.stages);
      const flags =
        (s.internal ? "🏠" : "") +
        (s.blocked ? "⛔" : "") +
        (s.watched ? "👁" : "") +
        (s.safe ? "✅" : "");
      return [
        String(i + 1),
        cell(s.ip),
        cell(tierLabel(s.tier)),
        String(s.sophistication),
        String(s.distinctStages),
        stageStrip(reached),
        String(s.distinctClasses),
        String(s.distinctSignatures),
        String(s.distinctHosts),
        String(s.count),
        cell(clip(s.topClass ?? "—")),
        String(s.disposition.passed),
        flags || "—",
      ];
    }),
  );
}

function renderMarkdown(m: RepertoireReport): string {
  const lines: string[] = [];
  lines.push(`# 🧠 SecTool Attacker Repertoire / Sophistication Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** per source, distinct kill-chain **stages** (${ON_CHAIN.map((s) => s.glyph).join("")} = ` +
      `${ON_CHAIN.map((s) => s.title.toLowerCase()).join(" → ")}) × distinct threat **classes** × distinct ` +
      `**signatures**, scored 0–100 (stage breadth weighted heaviest) and ranked by sophistication, **not volume** · ` +
      `**Sourced alerts:** ${m.sourcedAlerts} of ${m.totalWindowAlerts} (${m.onChainAlerts} mapped to a stage, ` +
      `${m.classifiedAlerts} carried a classification)`,
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
          `enough volume to profile a repertoire (min ${DEFAULT_MIN_ALERTS} alerts/source by default).`,
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

  lines.push(`## Sources by repertoire sophistication`);
  lines.push("");
  lines.push(sourceTable(m.sources));
  lines.push("");
  lines.push(
    `**Legend:** _Tier_ — **🎯 operator** (≥3 kill-chain stages: a multi-stage intrusion) · **🧰 toolkit** ` +
      `(2 stages or ≥3 threat classes: a varied attacker) · **🔧 specialist** (one stage, many signatures/classes: ` +
      `one thing done many ways) · **• probe** (minimal breadth: one-trick noise). _Score_ 0–100 weights stage ` +
      `breadth heaviest, then class & technique breadth, chain depth and worst severity — **volume is deliberately ` +
      `excluded** so a quiet many-method operator outranks a loud flood. _Reach_ lights the stages reached ` +
      `(${ON_CHAIN.map((s) => `${s.glyph} ${s.title.toLowerCase()}`).join(" · ")}). **Flags:** 🏠 internal source · ` +
      `⛔ blocked · 👁 watched · ✅ safe.`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. **Tier and stage are heuristics**: the kill-chain stage is a regex over each ` +
      `alert's classification + category + signature text (shared with the kill-chain report), and the threat class ` +
      `is Suricata's own \`classification\` (or the coarser \`category\` when absent) — both can mis-bucket an ` +
      `oddly-named rule, so the raw distinct counts are shown so the call can be second-guessed. Breadth needs ` +
      `labels: a source whose alerts carry no classification and map only off-chain reads as a low-breadth "probe" ` +
      `even if it is doing harm under an unhelpful rule name (labelling coverage is reported above). These are IPS ` +
      `**detections**, not full flows — a stage executed without tripping a rule is invisible, so repertoire breadth ` +
      `is a lower bound. A long look-back can hit the store's history cap and undercount breadth. No live gateway ` +
      `query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the attacker repertoire / sophistication report from the stored alert
 * history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link RepertoireOptions}: `limit`, `minAlerts`, and a `nowMs` pin
 *              for deterministic tests.
 */
export function buildRepertoire(hours: number, opts: RepertoireOptions = {}): RepertoireReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minAlerts = Math.max(1, Math.floor(opts.minAlerts ?? DEFAULT_MIN_ALERTS));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const sources = new Map<string, SourceAcc>();
  let sourced = 0;
  let onChain = 0;
  let classified = 0;

  for (const a of windowed) {
    const src = validIp(a.srcIp);
    if (!src) continue;
    sourced++;

    const acc = sources.get(src) ?? newSourceAcc();
    if (!sources.has(src)) sources.set(src, acc);
    acc.count++;
    acc.score += weightOf(a.severity);
    acc.severityMax = maxSeverity(acc.severityMax, a.severity);
    if (isSevere(a.severity)) acc.severe++;

    const dst = validIp(a.dstIp);
    if (dst) acc.hosts.add(dst);

    const stage = classifyStage(a);
    if (STAGE_INDEX.has(stage)) {
      onChain++;
      acc.stages.add(stage);
    }

    const cls = classOf(a);
    if (!cls.derived) classified++;
    acc.classes.add(cls.label);
    acc.classCounts.set(cls.label, (acc.classCounts.get(cls.label) ?? 0) + 1);

    const sig = (a.signature ?? "").trim();
    if (sig) {
      acc.signatures.add(sig);
      acc.sigCounts.set(sig, (acc.sigCounts.get(sig) ?? 0) + 1);
    }

    const disp = classifyDisposition(a.action);
    if (disp === "blocked") acc.blocked++;
    else if (disp === "passed") acc.passed++;
    else acc.unknown++;
  }

  const tierCounts: TierCounts = { operator: 0, toolkit: 0, specialist: 0, probe: 0 };

  const sourceList: RepertoireSource[] = [...sources.entries()]
    .filter(([, acc]) => acc.count >= minAlerts)
    .map(([ip, acc]) => {
      const orderedStages = [...acc.stages].sort(
        (x, y) => (STAGE_INDEX.get(x) ?? 0) - (STAGE_INDEX.get(y) ?? 0),
      );
      const furthestStage = orderedStages.length ? orderedStages[orderedStages.length - 1]! : null;
      const furthestIndex = furthestStage ? (STAGE_INDEX.get(furthestStage) ?? -1) : -1;
      const distinctStages = orderedStages.length;
      const distinctClasses = acc.classes.size;
      const distinctSignatures = acc.signatures.size;
      const tier = classifyTier(distinctStages, distinctClasses, distinctSignatures);
      tierCounts[tier]++;
      const actioned = acc.blocked + acc.passed;
      return {
        ip,
        internal: isPrivate(ip),
        tier,
        sophistication: sophisticationScore(
          distinctStages,
          furthestIndex,
          distinctClasses,
          distinctSignatures,
          acc.severityMax,
        ),
        distinctStages,
        stages: orderedStages,
        furthestStage,
        distinctClasses,
        distinctSignatures,
        distinctHosts: acc.hosts.size,
        count: acc.count,
        severe: acc.severe,
        score: acc.score,
        severityMax: acc.severityMax,
        topClass: topOf(acc.classCounts),
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
      } satisfies RepertoireSource;
    })
    // Most sophisticated first: score, then stage breadth, then severity-weighted
    // magnitude, then volume, then IP for a stable order.
    .sort(
      (x, y) =>
        y.sophistication - x.sophistication ||
        y.distinctStages - x.distinctStages ||
        y.score - x.score ||
        y.count - x.count ||
        (x.ip < y.ip ? -1 : x.ip > y.ip ? 1 : 0),
    );

  // tierCounts is accumulated across *all* qualifying sources above; the table is
  // then capped to `limit` rows for display without disturbing the totals.
  const cappedSources = sourceList.slice(0, limit);

  const highlights = writeHighlights(
    safeHours,
    { distinctSources: sourceList.length, onChainAlerts: onChain, sourcedAlerts: sourced },
    tierCounts,
    cappedSources,
  );

  const model: RepertoireReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    sourcedAlerts: sourced,
    onChainAlerts: onChain,
    classifiedAlerts: classified,
    distinctSources: sourceList.length,
    tierCounts,
    sources: cappedSources,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded repertoire report. */
export function repertoireFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-repertoire-${stamp}.md`;
}
