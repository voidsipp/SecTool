/**
 * Attack-sequence / signature-transition ("playbook") report — "**when a source
 * fires signature A, what does it fire *next* — and is the follow-on step more
 * dangerous?**"
 *
 * Several existing reports look at which signatures a source uses, but every one
 * of them throws away the single most operationally useful dimension: **order**.
 *
 *   - **cooccurrence.ts** pairs signatures that fire *together* inside a window.
 *     It is symmetric and unordered — it can tell you A and B co-occur, but not
 *     that A reliably comes *before* B, so it can never say "A is the early
 *     warning for B".
 *   - **killchain.ts** buckets each signature into a *fixed* Lockheed-Martin stage
 *     (recon → delivery → exploitation …). It is a coarse, pre-defined taxonomy
 *     applied per-alert; it does not learn the actual transitions an attacker
 *     walks, and two different recon rules collapse into one stage.
 *   - **repertoire.ts** counts the *breadth* of distinct signatures a source uses
 *     (a sophistication proxy). Breadth is a set; this report is about the
 *     *sequence* — the directed edges between those signatures.
 *
 * The unit of analysis here is the **ordered transition** `A → B`: a source fired
 * signature A and then, within a session-gap bound, fired a *different* signature
 * B. For every source the report sorts its alerts by time, collapses runs of the
 * same signature (A,A,A,B is one A→B step, not three), and emits a transition
 * each time the signature changes — *unless* the time gap exceeds the session
 * bound, in which case the chain is cut and B starts a fresh engagement rather
 * than being chained onto a day-old A. Folding all sources' transitions together
 * yields a directed weighted graph of attacker behaviour from which the report
 * derives:
 *
 *   - **Top transitions** — the most-trodden A→B edges, with how many distinct
 *     sources walk each one (a transition many independent attackers repeat is a
 *     genuine playbook, not one noisy host).
 *   - **Early-warning edges** — escalating transitions whose *destination* reaches
 *     high/critical severity and whose conditional probability `P(B | A)` is high
 *     with real support. These are the actionable gold: *"when you see A, the
 *     serious step B usually follows within ~M — alert or auto-block on A."* The
 *     **median lead time** between A and B is the warning window the defender has.
 *   - **Predictable pivots** — per source-signature, the conditional-next
 *     distribution and its Shannon entropy. A low-entropy, high-top-probability
 *     pivot is a deterministic fork in the attacker's logic; a high-entropy one
 *     is a spray with no consistent follow-on.
 *   - **Recurring playbooks** — the most common 3-step sequences (A→B→C) seen
 *     across independent sources, the closest thing to a reusable attack script.
 *
 * The headline **verdict** is the share of transition volume that flows along
 * *dominant* edges (where `P(B | A) ≥ 0.5`): a high share means attackers behave
 * like scripts (playbook-driven, predictable, easy to pre-empt); a low share
 * means opportunistic, ad-hoc probing with little consistent ordering.
 *
 * Honest caveats baked into the output:
 *
 *   - **Source IP ≠ actor.** NAT / shared egress chains two unrelated attackers'
 *     signatures into one bogus sequence; a rotating botnet splits one actor's
 *     playbook across many IPs so no single source shows the full chain.
 *     Sequences are built over addresses exactly as the IPS logged them.
 *   - **A→B is correlation, not causation.** That B follows A does not mean A
 *     caused B or that they are the same operation — it is a statistical regularity
 *     in the stream, surfaced for a human to judge.
 *   - **Session- & store-bounded.** Transitions are only chained within the
 *     session-gap bound, and history older than the rolling alert store's cap is
 *     invisible, so every count is a lower bound on the true behaviour.
 *
 * Pure in-memory math over alertStore (plus blocklist / watchlist / safelist
 * membership flags for context) — no SSH, no Claude, no network. Output is both a
 * structured model and a ready-to-paste Markdown document, mirroring noise.ts,
 * cooccurrence.ts, repertoire.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** A one-word verdict on how scripted (vs opportunistic) attacker behaviour is. */
export type SequenceVerdict = "playbook-driven" | "mixed" | "opportunistic";

/** One directed signature transition A → B aggregated across all sources. */
export interface Transition {
  /** The signature that fired first. */
  from: string;
  /** The signature that fired next (different from {@link from}). */
  to: string;
  /** Number of times this exact ordered step was observed. */
  count: number;
  /** Distinct source IPs that walked this edge at least once. */
  sources: number;
  /** P(to | from) — share of all transitions *out of* `from` that go to `to`, 0..1 (4dp). */
  probability: number;
  /** Median gap between the `from` event and the `to` event (epoch-ms delta). */
  medianLeadMs: number;
  /** Worst severity seen on the `from` side of this edge. */
  fromSeverity: Severity;
  /** Worst severity seen on the `to` side of this edge. */
  toSeverity: Severity;
  /** Share of occurrences where the `to` event outranked the `from` event in severity, 0..1 (4dp). */
  escalateShare: number;
  /** True when this edge predominantly escalates AND reaches high/critical on the `to` side. */
  earlyWarning: boolean;
  /** A representative source IP that walked this edge (for the analyst to pivot on). */
  sampleSource: string;
  /** The sample source is on the blocklist. */
  blocked: boolean;
  /** The sample source is on the watchlist. */
  watched: boolean;
}

/** One source-signature and the distribution of what it transitions *to*. */
export interface Pivot {
  /** The originating signature. */
  signature: string;
  /** Total transitions observed out of this signature. */
  outgoing: number;
  /** Distinct downstream signatures it leads to. */
  distinctNext: number;
  /** The single most likely next signature. */
  topNext: string;
  /** P(topNext | signature), 0..1 (4dp) — the pivot's predictability. */
  topProbability: number;
  /** Shannon entropy of the next-signature distribution, in bits (2dp). */
  entropyBits: number;
  /** True when the most likely next step reaches high/critical severity. */
  leadsToSerious: boolean;
}

/** One recurring 3-step sequence A → B → C seen across sources. */
export interface Playbook {
  /** The three ordered signatures. */
  steps: [string, string, string];
  /** Times this exact 3-step sequence was observed. */
  count: number;
  /** Distinct source IPs that walked the full 3-step sequence. */
  sources: number;
}

export interface SequenceReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Alerts that carried a usable signature (others cannot enter a sequence). */
  analysableAlerts: number;
  /** Sources with ≥2 distinct signatures that produced at least one transition. */
  sourcesAnalysed: number;
  /** Total ordered transitions observed across all sources. */
  totalTransitions: number;
  /** Distinct ordered (from,to) pairs. */
  distinctTransitions: number;
  /** Transitions whose destination outranked their origin in severity. */
  escalatingTransitions: number;
  /** Edges flagged as early-warning (escalate to high/critical with real support). */
  earlyWarningEdges: number;
  /** Session-gap bound in hours: transitions only chain within this idle gap. */
  maxGapHours: number;
  /** Minimum occurrences for an edge to qualify as an early-warning candidate. */
  minSupport: number;
  /** Share of transition volume flowing along dominant (P≥0.5) edges, 0..1 (4dp). */
  determinismShare: number;
  /** The one-word scripted-vs-opportunistic verdict. */
  verdict: SequenceVerdict;
  /** The most-trodden transitions, most-frequent first (capped to the row limit). */
  topTransitions: Transition[];
  /** Escalating, high-confidence early-warning edges, best-lead first. */
  earlyWarnings: Transition[];
  /** The most predictable source-signatures (lowest-entropy pivots first). */
  pivots: Pivot[];
  /** The most common 3-step playbooks. */
  playbooks: Playbook[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface SequenceOptions {
  /** Max rows per table (clamped to [1, 200]). */
  limit?: number;
  /** Session-gap bound in hours; transitions only chain within this idle gap (clamped to [0.05, 168]). */
  maxGapHours?: number;
  /** Minimum occurrences for an early-warning edge (clamped to [2, 1000]). */
  minSupport?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const DEFAULT_MAX_GAP_HOURS = 6;
const DEFAULT_MIN_SUPPORT = 3;
const MS_PER_HOUR = 3_600_000;

/** Determinism share at/above which attackers are called scripted. */
const HIGH_DETERMINISM = 0.5;
/** Determinism share below which attackers are called opportunistic. */
const LOW_DETERMINISM = 0.25;
/** Conditional probability at/above which an edge is "dominant" out of its source. */
const DOMINANT_PROB = 0.5;

// ----- classifiers / helpers (mirror noise.ts / cooccurrence.ts) -------------

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

function sevLabel(rank: number): Severity {
  return (SEVERITY_ORDER[Math.max(0, Math.min(SEVERITY_ORDER.length - 1, rank))] ?? "info") as Severity;
}

/** True when a severity rank is high or critical. */
function isSerious(rank: number): boolean {
  return rank >= 3;
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

function pct(frac: number, dp = 0): string {
  return `${(frac * 100).toFixed(dp)}%`;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** Compact human duration for a span (e.g. "3d 4h", "5h", "12m", "8s"). */
function fmtDuration(ms: number): string {
  if (ms <= 0) return "0s";
  if (ms < 60000) return `${Math.round(ms / 1000)}s`;
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

/** Truncate a long signature so it fits a table cell. */
function truncate(s: string, max = 40): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function mdTable(headers: string[], rows: string[][]): string {
  if (!rows.length) return "_None._";
  const head = `| ${headers.join(" | ")} |`;
  const sep = `| ${headers.map(() => "---").join(" | ")} |`;
  const body = rows.map((r) => `| ${r.join(" | ")} |`).join("\n");
  return `${head}\n${sep}\n${body}`;
}

/** Human label + emoji for a verdict. */
function verdictLabel(v: SequenceVerdict): string {
  switch (v) {
    case "playbook-driven":
      return "🤖 playbook-driven";
    case "mixed":
      return "▥ mixed";
    case "opportunistic":
      return "🎲 opportunistic";
  }
}

function classifyVerdict(determinismShare: number): SequenceVerdict {
  if (determinismShare >= HIGH_DETERMINISM) return "playbook-driven";
  if (determinismShare < LOW_DETERMINISM) return "opportunistic";
  return "mixed";
}

/** Median of a numeric array (returns 0 for empty). */
function median(xs: number[]): number {
  if (!xs.length) return 0;
  const sorted = [...xs].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid]! : Math.round((sorted[mid - 1]! + sorted[mid]!) / 2);
}

/** Shannon entropy (bits) of a count distribution. */
function entropyBits(counts: number[]): number {
  const total = counts.reduce((s, c) => s + c, 0);
  if (total <= 0) return 0;
  let h = 0;
  for (const c of counts) {
    if (c <= 0) continue;
    const p = c / total;
    h -= p * Math.log2(p);
  }
  return h;
}

// ----- aggregation -----------------------------------------------------------

/** A single chain step inside one source's session. */
interface ChainStep {
  sig: string;
  time: number;
  sevRank: number;
}

/** Accumulator for one directed (from → to) edge. */
interface EdgeAcc {
  from: string;
  to: string;
  count: number;
  sources: Set<string>;
  leads: number[];
  escalateCount: number;
  fromSevMax: number;
  toSevMax: number;
  sampleSource: string;
}

/** Accumulator for one 3-step playbook. */
interface PlaybookAcc {
  steps: [string, string, string];
  count: number;
  sources: Set<string>;
}

const STEP_SEP = ""; // control char that cannot appear in a signature

/** The display signature for an alert (rule name, falling back to category). */
function sigOf(a: StoredAlert): string | undefined {
  const sig = a.signature?.trim();
  if (sig) return sig;
  const cat = a.category?.trim();
  return cat || undefined;
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(m: SequenceReport): string[] {
  const out: string[] = [];
  if (m.totalTransitions === 0) return out;

  // Headline: the scripted-vs-opportunistic verdict + the graph size.
  out.push(
    `🔀 Over the last ${m.hours}h, **${m.sourcesAnalysed} source(s)** produced **${m.totalTransitions} ordered ` +
      `signature transition(s)** across **${m.distinctTransitions} distinct edge(s)** — attacker behaviour is ` +
      `**${verdictLabel(m.verdict)}** (${pct(m.determinismShare)} of steps follow a dominant, ≥${pct(DOMINANT_PROB)}-` +
      `likely path).`,
  );

  // The single most-walked transition.
  const top = m.topTransitions[0];
  if (top) {
    out.push(
      `🛤️ Most-walked step: **${truncate(top.from, 44)}** → **${truncate(top.to, 44)}** seen **${top.count}×** ` +
        `across **${top.sources} source(s)** (P=${pct(top.probability)}, typical lead ${fmtDuration(top.medianLeadMs)}).`,
    );
  }

  // The actionable payload: early-warning edges.
  if (m.earlyWarnings.length) {
    const ew = m.earlyWarnings[0]!;
    out.push(
      `🚨 **${m.earlyWarningEdges} early-warning edge(s)**: a benign-looking step reliably precedes a high/critical ` +
        `one. Strongest — when **${truncate(ew.from, 40)}** fires, **${truncate(ew.to, 40)}** (${ew.toSeverity}) follows ` +
        `**${pct(ew.probability)}** of the time within ~${fmtDuration(ew.medianLeadMs)}. Alert or auto-block on the ` +
        `*first* step to buy that lead time.`,
    );
  }

  // The most predictable pivot — a deterministic fork in the attacker logic.
  const pivot = m.pivots.find((p) => p.topProbability >= DOMINANT_PROB);
  if (pivot) {
    out.push(
      `🎯 Most predictable pivot: after **${truncate(pivot.signature, 44)}** the next move is **${truncate(pivot.topNext, 40)}** ` +
        `**${pct(pivot.topProbability)}** of the time (entropy ${pivot.entropyBits.toFixed(2)} bits over ${pivot.distinctNext} ` +
        `option(s)) — a near-deterministic step worth a detection rule.`,
    );
  }

  // A recurring multi-step playbook across independent sources.
  const pb = m.playbooks.find((p) => p.sources >= 2) ?? m.playbooks[0];
  if (pb) {
    out.push(
      `📖 Recurring playbook (${pb.count}×, ${pb.sources} source(s)): ` +
        `**${truncate(pb.steps[0], 30)}** → **${truncate(pb.steps[1], 30)}** → **${truncate(pb.steps[2], 30)}**.`,
    );
  }

  return out;
}

// ----- markdown --------------------------------------------------------------

function transitionTable(rows: Transition[]): string {
  return mdTable(
    ["#", "From", "To", "Count", "Sources", "P(to|from)", "Lead", "Sev", "Esc", "Flags"],
    rows.map((t, i) => {
      const flags = (t.earlyWarning ? "🚨" : "") + (t.blocked ? "⛔" : "") + (t.watched ? "👁" : "");
      return [
        String(i + 1),
        cell(truncate(t.from)),
        cell(truncate(t.to)),
        String(t.count),
        String(t.sources),
        pct(t.probability, 1),
        cell(fmtDuration(t.medianLeadMs)),
        `${cell(t.fromSeverity)}→${cell(t.toSeverity)}`,
        pct(t.escalateShare, 0),
        flags || "—",
      ];
    }),
  );
}

function earlyWarningTable(rows: Transition[]): string {
  return mdTable(
    ["#", "Warning signal (from)", "Imminent threat (to)", "Reaches", "P", "Lead", "Count", "Sources", "Sample"],
    rows.map((t, i) => [
      String(i + 1),
      cell(truncate(t.from, 44)),
      cell(truncate(t.to, 44)),
      cell(t.toSeverity),
      pct(t.probability, 0),
      cell(fmtDuration(t.medianLeadMs)),
      String(t.count),
      String(t.sources),
      cell(t.sampleSource) + (t.blocked ? " ⛔" : t.watched ? " 👁" : ""),
    ]),
  );
}

function pivotTable(rows: Pivot[]): string {
  return mdTable(
    ["#", "Signature", "Out", "Next opts", "Top next", "P(top)", "Entropy", "Serious"],
    rows.map((p, i) => [
      String(i + 1),
      cell(truncate(p.signature, 44)),
      String(p.outgoing),
      String(p.distinctNext),
      cell(truncate(p.topNext, 40)),
      pct(p.topProbability, 0),
      `${p.entropyBits.toFixed(2)} b`,
      p.leadsToSerious ? "🔴" : "—",
    ]),
  );
}

function playbookTable(rows: Playbook[]): string {
  return mdTable(
    ["#", "Step 1", "Step 2", "Step 3", "Count", "Sources"],
    rows.map((p, i) => [
      String(i + 1),
      cell(truncate(p.steps[0], 34)),
      cell(truncate(p.steps[1], 34)),
      cell(truncate(p.steps[2], 34)),
      String(p.count),
      String(p.sources),
    ]),
  );
}

function renderMarkdown(m: SequenceReport): string {
  const lines: string[] = [];
  lines.push(`# 🔀 SecTool Attack-Sequence / Signature-Transition (Playbook) Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** per-source alerts ordered by time, runs of one signature collapsed, an **ordered transition** ` +
      `A→B emitted on each signature change within a **${m.maxGapHours}h** session gap · ` +
      `**Analysable alerts:** ${m.analysableAlerts} of ${m.totalWindowAlerts} · **Sources:** ${m.sourcesAnalysed}`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (m.totalTransitions === 0) {
    lines.push(
      `No ordered signature transitions in the last ${m.hours} hour(s) — every source either fired a single ` +
        `signature or its alerts were too far apart to chain within the ${m.maxGapHours}h session gap. Nothing to sequence.`,
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  // At-a-glance scoreboard.
  lines.push(`## Sequence at a glance`);
  lines.push("");
  lines.push(
    mdTable(
      ["Transitions", "Edges", "Sources", "Escalating", "Early-warning", "Determinism", "Verdict"],
      [
        [
          String(m.totalTransitions),
          String(m.distinctTransitions),
          String(m.sourcesAnalysed),
          `${m.escalatingTransitions} (${pct(m.totalTransitions > 0 ? m.escalatingTransitions / m.totalTransitions : 0)})`,
          String(m.earlyWarningEdges),
          pct(m.determinismShare, 1),
          cell(verdictLabel(m.verdict)),
        ],
      ],
    ),
  );
  lines.push("");
  lines.push(
    `**Legend:** _Determinism_ = share of transition volume flowing along dominant (P≥${pct(DOMINANT_PROB)}) edges ` +
      `(**🤖 playbook-driven** ≥${pct(HIGH_DETERMINISM)} · **▥ mixed** · **🎲 opportunistic** <${pct(LOW_DETERMINISM)}). ` +
      `_Escalating_ = transitions whose destination outranks their origin in severity.`,
  );
  lines.push("");

  // Early-warning edges — the actionable section, first.
  lines.push(`## 🚨 Early-warning edges`);
  lines.push("");
  if (m.earlyWarnings.length) {
    lines.push(
      `_Escalating transitions whose destination reaches high/critical with ≥${m.minSupport} observations. The **from** ` +
        `signature is a leading indicator: detecting or blocking it buys you the **lead** window before the **to** ` +
        `signature (the real threat) lands._`,
    );
    lines.push("");
    lines.push(earlyWarningTable(m.earlyWarnings));
  } else {
    lines.push(
      `_No escalating transition reached high/critical with ≥${m.minSupport} observations in this window — no reliable ` +
        `early-warning signal to encode yet._`,
    );
  }
  lines.push("");

  // Top transitions.
  lines.push(`## Most-walked transitions`);
  lines.push("");
  lines.push(transitionTable(m.topTransitions));
  lines.push("");
  lines.push(
    `**P(to|from)** = how often, of all steps leaving _from_, the next step is _to_. **Lead** = median time between ` +
      `the two events. **Esc** = share of occurrences where severity rose. **Flags:** 🚨 early-warning · ⛔ sample ` +
      `source blocked · 👁 watched.`,
  );
  lines.push("");

  // Predictable pivots.
  lines.push(`## Most predictable pivots`);
  lines.push("");
  lines.push(pivotTable(m.pivots));
  lines.push("");
  lines.push(
    `_For each originating signature: how many distinct next-steps it leads to, its most likely follow-on, and the ` +
      `Shannon **entropy** of that distribution. Low entropy + high P(top) = a deterministic fork worth a rule; high ` +
      `entropy = a spray with no consistent next move. 🔴 = the top next step is high/critical._`,
  );
  lines.push("");

  // Recurring playbooks.
  if (m.playbooks.length) {
    lines.push(`## Recurring 3-step playbooks`);
    lines.push("");
    lines.push(playbookTable(m.playbooks));
    lines.push("");
    lines.push(
      `_The most common ordered 3-signature sequences. A playbook walked by **multiple independent sources** is a ` +
        `reusable attack script, not one host's quirk — prioritise detections that catch its earliest step._`,
    );
    lines.push("");
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Sequences are built over source IPs **as the IPS logged them** — NAT / shared ` +
      `egress chains unrelated attackers into one bogus sequence, and a rotating botnet splits one actor's playbook ` +
      `across many IPs. A→B is a statistical regularity (correlation), **not** proof that A caused B or that they are ` +
      `the same operation. Transitions only chain within the ${m.maxGapHours}h session gap, and history older than the ` +
      `rolling alert store's cap is invisible, so every count is a lower bound. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the attack-sequence / signature-transition report from stored alerts.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link SequenceOptions}: `limit`, `maxGapHours`, `minSupport`, and
 *              a `nowMs` pin for deterministic tests.
 */
export function buildSequence(hours: number, opts: SequenceOptions = {}): SequenceReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const maxGapHours = Math.max(0.05, Math.min(168, opts.maxGapHours ?? DEFAULT_MAX_GAP_HOURS));
  const minSupport = Math.max(2, Math.min(1000, Math.floor(opts.minSupport ?? DEFAULT_MIN_SUPPORT)));
  const maxGapMs = maxGapHours * MS_PER_HOUR;
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  // Group analysable (signature-bearing, valid-source) alerts by source IP.
  const bySource = new Map<string, { time: number; sig: string; sevRank: number }[]>();
  let analysable = 0;
  for (const a of windowed) {
    const src = validIp(a.srcIp);
    const sig = sigOf(a);
    if (!src || !sig) continue;
    analysable++;
    let arr = bySource.get(src);
    if (!arr) {
      arr = [];
      bySource.set(src, arr);
    }
    arr.push({ time: a.time, sig, sevRank: sevRank(a.severity) });
  }

  const edges = new Map<string, EdgeAcc>();
  const playbooks = new Map<string, PlaybookAcc>();
  // Outgoing total per "from" signature, and the per-next breakdown for pivots.
  const outgoing = new Map<string, Map<string, number>>();
  let totalTransitions = 0;
  let escalatingTransitions = 0;
  const sourcesAnalysed = new Set<string>();

  for (const [src, eventsRaw] of bySource) {
    // Chronological order; stable tie-break keeps determinism for equal timestamps.
    const events = eventsRaw.sort((a, b) => a.time - b.time);
    // Rolling chain of the last few *distinct* steps within an unbroken session.
    let chain: ChainStep[] = [];

    for (const ev of events) {
      if (chain.length === 0) {
        chain.push({ sig: ev.sig, time: ev.time, sevRank: ev.sevRank });
        continue;
      }
      const last = chain[chain.length - 1]!;
      if (ev.sig === last.sig) {
        // Collapse a run of the same signature; advance its time / worst severity
        // so the next transition's lead is measured from the most recent A.
        last.time = ev.time;
        if (ev.sevRank > last.sevRank) last.sevRank = ev.sevRank;
        continue;
      }
      const gap = ev.time - last.time;
      if (gap > maxGapMs) {
        // Session break — start a fresh chain, no transition across the gap.
        chain = [{ sig: ev.sig, time: ev.time, sevRank: ev.sevRank }];
        continue;
      }

      // Record the A → B transition.
      totalTransitions++;
      sourcesAnalysed.add(src);
      const escalates = ev.sevRank > last.sevRank;
      if (escalates) escalatingTransitions++;

      const ekey = `${last.sig}${STEP_SEP}${ev.sig}`;
      let edge = edges.get(ekey);
      if (!edge) {
        edge = {
          from: last.sig,
          to: ev.sig,
          count: 0,
          sources: new Set(),
          leads: [],
          escalateCount: 0,
          fromSevMax: 0,
          toSevMax: 0,
          sampleSource: src,
        };
        edges.set(ekey, edge);
      }
      edge.count++;
      edge.sources.add(src);
      edge.leads.push(gap);
      if (escalates) edge.escalateCount++;
      if (last.sevRank > edge.fromSevMax) edge.fromSevMax = last.sevRank;
      if (ev.sevRank > edge.toSevMax) edge.toSevMax = ev.sevRank;

      // Outgoing breakdown for the pivot / probability math.
      let nexts = outgoing.get(last.sig);
      if (!nexts) {
        nexts = new Map();
        outgoing.set(last.sig, nexts);
      }
      nexts.set(ev.sig, (nexts.get(ev.sig) ?? 0) + 1);

      // Advance the chain and, once 3 deep, emit the trigram playbook.
      chain.push({ sig: ev.sig, time: ev.time, sevRank: ev.sevRank });
      if (chain.length >= 3) {
        const s0 = chain[chain.length - 3]!.sig;
        const s1 = chain[chain.length - 2]!.sig;
        const s2 = chain[chain.length - 1]!.sig;
        const pkey = `${s0}${STEP_SEP}${s1}${STEP_SEP}${s2}`;
        let pb = playbooks.get(pkey);
        if (!pb) {
          pb = { steps: [s0, s1, s2], count: 0, sources: new Set() };
          playbooks.set(pkey, pb);
        }
        pb.count++;
        pb.sources.add(src);
        // Keep only the tail needed for the next trigram.
        if (chain.length > 3) chain = chain.slice(chain.length - 3);
      }
    }
  }

  const outgoingTotal = (sig: string): number => {
    const nexts = outgoing.get(sig);
    if (!nexts) return 0;
    let t = 0;
    for (const c of nexts.values()) t += c;
    return t;
  };

  // Finalise edges into the public Transition shape.
  const allTransitions: Transition[] = [...edges.values()].map((e) => {
    const fromTotal = outgoingTotal(e.from);
    const probability = fromTotal > 0 ? round4(e.count / fromTotal) : 0;
    const escalateShare = e.count > 0 ? round4(e.escalateCount / e.count) : 0;
    const earlyWarning =
      isSerious(e.toSevMax) && e.toSevMax > e.fromSevMax && escalateShare >= 0.5 && e.count >= minSupport;
    const sample = e.sampleSource;
    return {
      from: e.from,
      to: e.to,
      count: e.count,
      sources: e.sources.size,
      probability,
      medianLeadMs: median(e.leads),
      fromSeverity: sevLabel(e.fromSevMax),
      toSeverity: sevLabel(e.toSevMax),
      escalateShare,
      earlyWarning,
      sampleSource: sample,
      blocked: blockStore.has(sample),
      watched: watchStore.has(sample),
    } satisfies Transition;
  });

  // Determinism: share of transition volume on dominant (P≥0.5) edges.
  let dominantVolume = 0;
  for (const t of allTransitions) if (t.probability >= DOMINANT_PROB) dominantVolume += t.count;
  const determinismShare = totalTransitions > 0 ? round4(dominantVolume / totalTransitions) : 0;
  const verdict = classifyVerdict(determinismShare);

  const byFrequency = (a: Transition, b: Transition): number =>
    b.count - a.count ||
    b.sources - a.sources ||
    b.probability - a.probability ||
    (a.from < b.from ? -1 : a.from > b.from ? 1 : a.to < b.to ? -1 : a.to > b.to ? 1 : 0);

  const topTransitions = [...allTransitions].sort(byFrequency).slice(0, limit);

  const earlyWarnings = allTransitions
    .filter((t) => t.earlyWarning)
    // Highest confidence first, then most support, then severity reached.
    .sort(
      (a, b) =>
        b.probability - a.probability ||
        b.count - a.count ||
        sevRank(b.toSeverity) - sevRank(a.toSeverity) ||
        (a.from < b.from ? -1 : a.from > b.from ? 1 : 0),
    )
    .slice(0, limit);

  // Pivots: per "from" signature, the next-step distribution.
  const pivots: Pivot[] = [...outgoing.entries()]
    .map(([sig, nexts]) => {
      const counts = [...nexts.values()];
      const total = counts.reduce((s, c) => s + c, 0);
      let topNext = "";
      let topCount = 0;
      let topRank = 0;
      for (const [next, c] of nexts) {
        // Deterministic top pick: count, then severity reached, then name.
        const edge = edges.get(`${sig}${STEP_SEP}${next}`);
        const nr = edge ? edge.toSevMax : 0;
        if (c > topCount || (c === topCount && (nr > topRank || (nr === topRank && next < topNext)))) {
          topNext = next;
          topCount = c;
          topRank = nr;
        }
      }
      const topEdge = edges.get(`${sig}${STEP_SEP}${topNext}`);
      return {
        signature: sig,
        outgoing: total,
        distinctNext: nexts.size,
        topNext,
        topProbability: total > 0 ? round4(topCount / total) : 0,
        entropyBits: round2(entropyBits(counts)),
        leadsToSerious: topEdge ? isSerious(topEdge.toSevMax) : false,
      } satisfies Pivot;
    })
    // Only pivots with real support are interesting; rank the most predictable
    // (lowest entropy) first, then by how much traffic they carry.
    .filter((p) => p.outgoing >= 2 && p.distinctNext >= 2)
    .sort(
      (a, b) =>
        a.entropyBits - b.entropyBits ||
        b.outgoing - a.outgoing ||
        b.topProbability - a.topProbability ||
        (a.signature < b.signature ? -1 : a.signature > b.signature ? 1 : 0),
    )
    .slice(0, limit);

  const topPlaybooks: Playbook[] = [...playbooks.values()]
    .map((p) => ({ steps: p.steps, count: p.count, sources: p.sources.size }))
    .sort(
      (a, b) =>
        b.count - a.count ||
        b.sources - a.sources ||
        (a.steps.join(STEP_SEP) < b.steps.join(STEP_SEP) ? -1 : 1),
    )
    .filter((p) => p.count >= 2)
    .slice(0, limit);

  const model: SequenceReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    analysableAlerts: analysable,
    sourcesAnalysed: sourcesAnalysed.size,
    totalTransitions,
    distinctTransitions: edges.size,
    escalatingTransitions,
    earlyWarningEdges: allTransitions.filter((t) => t.earlyWarning).length,
    maxGapHours,
    minSupport,
    determinismShare,
    verdict,
    topTransitions,
    earlyWarnings,
    pivots,
    playbooks: topPlaybooks,
    highlights: [],
    markdown: "",
  };
  model.highlights = writeHighlights(model);
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded attack-sequence report. */
export function sequenceFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-sequence-${stamp}.md`;
}
