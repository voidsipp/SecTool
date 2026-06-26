/**
 * AI Analyst-Insight digest — "what did the *analysis layer* conclude, across
 * the whole window?"
 *
 * Every other offline report in this project mines the raw IPS telemetry: the
 * worst source (persistence, netblock), the worst signature (lifecycle, focus,
 * tuning), the time shape (rhythm, surge, beacon), the direction (direction),
 * the enforcement gap (efficacy), the severity-weighted magnitude (risk). None
 * of them read the one field SecTool spends real money to produce: the **Claude
 * summary** stored alongside each alert (`StoredAlert.summary`). Every processed
 * alert carries an `AlertSummary` — a re-assessed severity, a risk narrative, and
 * a list of recommended actions — and until now that analysis evaporated into the
 * dashboard one alert at a time, never rolled up.
 *
 * This report audits that analysis layer in aggregate and answers three
 * operator questions the raw reports cannot:
 *
 *   1. **Is the AI actually covering the alert stream?** It splits the window
 *      into AI-backed summaries, non-AI *fallback* summaries (the heuristic path
 *      taken when Claude is unreachable / rate-limited / disabled), and
 *      un-analysed alerts. A low coverage or a high fallback share means the
 *      dashboard's "AI analysis" is mostly heuristics — worth knowing before you
 *      trust it.
 *
 *   2. **Where does Claude DISAGREE with the rule?** For every AI-backed alert it
 *      compares the rule's severity against Claude's re-assessed severity and
 *      buckets the alert as **downgraded** (Claude rated it *lower* — a
 *      false-positive / over-noisy-rule signal), **agreed**, or **upgraded**
 *      (Claude rated it *higher* — an under-graded rule worth escalating). It then
 *      ranks the signatures Claude most often downgrades (your tuning backlog) and
 *      most often upgrades (your escalation backlog). This is the sharpest, most
 *      actionable thing the AI layer produces and it was previously invisible.
 *
 *   3. **What is Claude telling you to DO?** It normalises and tallies every
 *      `recommendedActions` entry across the window, so the single most-repeated
 *      remediation ("block the source at the firewall", "patch the exposed
 *      service") rises to the top with the count of distinct alerts and
 *      signatures it was advised for — a ready-made, frequency-ranked work list.
 *
 * It also attributes summaries to the model that produced them, so a silent
 * model swap or a flood of fallbacks is visible.
 *
 * Honest caveats baked into the output:
 *
 *   - **This audits opinions, not ground truth.** A downgrade is Claude's
 *     judgement that a rule over-fired, not proof it did. Treat the FP-candidate
 *     list as *leads to review*, not auto-tuning input.
 *   - **Coverage is historical.** A summary is written when an alert is processed;
 *     alerts ingested before summarisation was enabled (or via a path that skips
 *     it) show as un-analysed and are excluded from the divergence math, never
 *     counted as "agreed".
 *   - **Fallback severities are not Claude's.** The heuristic fallback copies the
 *     rule severity, so it would always read as "agreed"; fallback summaries are
 *     therefore excluded from divergence and only contribute to coverage and the
 *     action roll-up (where their advice is generic — flagged as such).
 *   - **Window-bounded & store-capped.** The store keeps a bounded history; a long
 *     look-back can hit that cap and skew every count below.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude call, no network.
 * Output is both a structured model and a ready-to-paste Markdown document,
 * mirroring report.ts, direction.ts, risk.ts and the other offline reports.
 */
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Which way Claude re-graded an alert relative to the rule's severity. */
export type SeverityDelta = "downgraded" | "agreed" | "upgraded";

/** AI-analysis coverage of the alert window. */
export interface InsightCoverage {
  /** Alerts (with a usable timestamp) in the window. */
  total: number;
  /** Alerts carrying any summary (AI-backed or fallback). */
  analyzed: number;
  /** Of {@link analyzed}, summaries produced by Claude (`fallback` unset). */
  aiBacked: number;
  /** Of {@link analyzed}, non-AI heuristic fallback summaries. */
  fallback: number;
  /** Alerts with no summary at all. */
  unanalyzed: number;
  /** analyzed / total, 0..1 (4dp). */
  coverage: number;
  /** aiBacked / analyzed, 0..1 (4dp), or null when nothing was analysed. */
  aiShare: number | null;
}

/** Rule-vs-Claude severity re-grading over the AI-backed alerts. */
export interface InsightDivergence {
  /** AI-backed alerts compared (denominator for the shares below). */
  compared: number;
  /** Claude rated the alert *lower* than the rule (false-positive signal). */
  downgraded: number;
  /** Claude agreed with the rule's severity. */
  agreed: number;
  /** Claude rated the alert *higher* than the rule (under-graded rule). */
  upgraded: number;
  /** downgraded / compared, 0..1 (4dp), or null when nothing was compared. */
  downgradeRate: number | null;
  /** upgraded / compared, 0..1 (4dp), or null when nothing was compared. */
  upgradeRate: number | null;
}

/** Per-signature re-grading roll-up (a tuning or escalation candidate). */
export interface SignatureDivergence {
  signature: string;
  /** AI-backed alerts seen for this signature. */
  samples: number;
  downgraded: number;
  agreed: number;
  upgraded: number;
  /** Sum of (Claude rank − rule rank) over samples; <0 net-down, >0 net-up. */
  netDelta: number;
  /** A representative rule severity for the signature. */
  ruleSeverity: Severity;
  /** A representative Claude severity for the signature. */
  claudeSeverity: Severity;
}

/** One normalised recommended action and how widely Claude advised it. */
export interface ActionStat {
  /** A representative original (first-seen) phrasing of the action. */
  action: string;
  /** Total times the action was recommended across all summaries. */
  count: number;
  /** Distinct alerts the action was attached to. */
  alerts: number;
  /** Distinct signatures the action was advised for. */
  signatures: number;
  /** True when *every* occurrence came from a heuristic fallback summary. */
  fallbackOnly: boolean;
}

/** Summaries grouped by the model that produced them. */
export interface ModelStat {
  /** Model id, or "(heuristic fallback)" / "(unknown model)" sentinels. */
  model: string;
  /** Summaries attributed to this model. */
  count: number;
  /** True for the synthetic fallback bucket. */
  fallback: boolean;
}

export interface InsightReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  coverage: InsightCoverage;
  divergence: InsightDivergence;
  /** Signatures Claude most often *downgraded* — false-positive / tuning leads. */
  fpCandidates: SignatureDivergence[];
  /** Signatures Claude most often *upgraded* — under-graded / escalation leads. */
  escalationCandidates: SignatureDivergence[];
  /** Most-recommended actions across the window, most frequent first. */
  topActions: ActionStat[];
  /** Summary attribution by model, most common first. */
  models: ModelStat[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface InsightOptions {
  /** Max rows in each ranked table (clamped to [1, 100]). */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 15;
const MS_PER_HOUR = 3_600_000;
const FALLBACK_MODEL = "(heuristic fallback)";
const UNKNOWN_MODEL = "(unknown model)";

// ----- formatting helpers (mirror direction.ts / risk.ts / efficacy.ts) -----

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** A 0..1 fraction as a whole-number percent string, e.g. 0.823 -> "82%". */
function pct(frac: number): string {
  return `${Math.round(frac * 100)}%`;
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
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

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

/** Render a signed delta as "↓2" / "↑1" / "0" for a table cell. */
function fmtDelta(n: number): string {
  if (n < 0) return `↓${-n}`;
  if (n > 0) return `↑${n}`;
  return "0";
}

// ----- action normalisation -------------------------------------------------

/**
 * Collapse a free-form recommended action to a stable grouping key: lower-cased,
 * whitespace-collapsed, trailing punctuation stripped. Two phrasings that differ
 * only in case or a trailing period group together; deliberately conservative so
 * genuinely different advice is never merged.
 */
function normAction(s: string): string {
  return s.trim().toLowerCase().replace(/\s+/g, " ").replace(/[.;:,\s]+$/, "");
}

// ----- aggregation accumulators ---------------------------------------------

interface SigAcc {
  samples: number;
  downgraded: number;
  agreed: number;
  upgraded: number;
  netDelta: number;
  ruleSeverity: Severity;
  claudeSeverity: Severity;
}

interface ActionAcc {
  action: string;
  count: number;
  alerts: Set<string>;
  signatures: Set<string>;
  fallbackOnly: boolean;
}

function deltaOf(rule: string | undefined, claude: string | undefined): SeverityDelta {
  const d = sevRank(claude) - sevRank(rule);
  if (d < 0) return "downgraded";
  if (d > 0) return "upgraded";
  return "agreed";
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  cov: InsightCoverage,
  div: InsightDivergence,
  fpCandidates: SignatureDivergence[],
  escalationCandidates: SignatureDivergence[],
  topActions: ActionStat[],
): string[] {
  const out: string[] = [];
  if (!cov.total) return out;

  // Coverage read — is the AI layer actually doing the work?
  if (!cov.analyzed) {
    out.push(
      `📭 None of the ${cov.total} alert(s) in the last ${hours}h carry a stored summary — the AI analysis layer ` +
        `produced nothing for this window (summaries may pre-date this window, or summarisation was disabled). The ` +
        `divergence and action sections below are therefore empty; everything here is a coverage finding.`,
    );
    return out;
  }
  const fallbackShare = cov.analyzed ? cov.fallback / cov.analyzed : 0;
  if (cov.aiShare !== null && cov.aiShare >= 0.8) {
    out.push(
      `🤖 **${pct(cov.coverage)} of alerts analysed**, ${pct(cov.aiShare)} of those by Claude itself ` +
        `(${cov.aiBacked} AI-backed, ${cov.fallback} heuristic fallback, ${cov.unanalyzed} un-analysed). The AI ` +
        `layer is carrying the stream — the re-grading below reflects real model judgement.`,
    );
  } else {
    out.push(
      `⚠️ Only **${cov.aiBacked} of ${cov.analyzed} summaries are AI-backed** (${pct(fallbackShare)} are heuristic ` +
        `fallbacks); ${cov.unanalyzed} alert(s) have no summary at all. The dashboard's "AI analysis" is mostly ` +
        `heuristics this window — likely Claude was unreachable, rate-limited, or disabled. Treat the verdicts cautiously.`,
    );
  }

  // Divergence — the headline tuning / escalation signal.
  if (div.compared > 0) {
    out.push(
      `⚖️ Over ${div.compared} AI-backed alert(s) Claude **downgraded ${div.downgraded}** ` +
        `(${div.downgradeRate !== null ? pct(div.downgradeRate) : "—"} — false-positive signal), agreed on ` +
        `${div.agreed}, and **upgraded ${div.upgraded}** ` +
        `(${div.upgradeRate !== null ? pct(div.upgradeRate) : "—"} — under-graded rules). Disagreement is where the ` +
        `value is: it is the rule set telling you, in Claude's words, where it is wrong.`,
    );
  }
  if (fpCandidates.length) {
    const top = fpCandidates[0]!;
    out.push(
      `🔧 Top false-positive candidate: \`${clip(top.signature, 60)}\` — Claude downgraded it ` +
        `${top.downgraded}/${top.samples} time(s) (rule \`${top.ruleSeverity}\` → Claude \`${top.claudeSeverity}\`). ` +
        `Review it in the tuning report before it keeps burning triage time.`,
    );
  }
  if (escalationCandidates.length) {
    const top = escalationCandidates[0]!;
    out.push(
      `🔺 Top escalation candidate: \`${clip(top.signature, 60)}\` — Claude upgraded it ` +
        `${top.upgraded}/${top.samples} time(s) (rule \`${top.ruleSeverity}\` → Claude \`${top.claudeSeverity}\`). ` +
        `An under-graded rule firing for real — raise its priority and make sure it is reaching a human.`,
    );
  }

  // Action roll-up — the ready-made work list.
  if (topActions.length) {
    const top = topActions[0]!;
    out.push(
      `✅ Most-recommended action (${top.count}×, across ${top.alerts} alert(s) / ${top.signatures} signature(s)): ` +
        `"${clip(top.action, 70)}"${top.fallbackOnly ? " _(from heuristic fallbacks — generic)_" : ""}. The full ` +
        `frequency-ranked list below is a remediation backlog you can work top-down.`,
    );
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function coverageTable(c: InsightCoverage): string {
  return mdTable(
    ["Bucket", "Count", "Share of total"],
    [
      ["AI-backed (Claude)", String(c.aiBacked), c.total ? pct(c.aiBacked / c.total) : "—"],
      ["Heuristic fallback", String(c.fallback), c.total ? pct(c.fallback / c.total) : "—"],
      ["Un-analysed (no summary)", String(c.unanalyzed), c.total ? pct(c.unanalyzed / c.total) : "—"],
      ["**Total alerts**", `**${c.total}**`, "**100%**"],
    ],
  );
}

function divergenceTable(d: InsightDivergence): string {
  return mdTable(
    ["Verdict", "Count", "Share of AI-backed"],
    [
      ["⬇️ Downgraded (FP signal)", String(d.downgraded), d.downgradeRate !== null ? pct(d.downgradeRate) : "—"],
      ["➡️ Agreed with rule", String(d.agreed), d.compared ? pct(d.agreed / d.compared) : "—"],
      ["⬆️ Upgraded (escalation)", String(d.upgraded), d.upgradeRate !== null ? pct(d.upgradeRate) : "—"],
      ["**Compared (AI-backed)**", `**${d.compared}**`, "**100%**"],
    ],
  );
}

function sigTable(rows: SignatureDivergence[]): string {
  return mdTable(
    ["#", "Signature", "Samples", "↓", "=", "↑", "Net", "Rule sev", "Claude sev"],
    rows.map((s, i) => [
      String(i + 1),
      cell(clip(s.signature, 56)),
      String(s.samples),
      String(s.downgraded),
      String(s.agreed),
      String(s.upgraded),
      fmtDelta(s.netDelta),
      cell(s.ruleSeverity),
      cell(s.claudeSeverity),
    ]),
  );
}

function actionTable(rows: ActionStat[]): string {
  return mdTable(
    ["#", "Recommended action", "Times", "Alerts", "Signatures", "Source"],
    rows.map((a, i) => [
      String(i + 1),
      cell(clip(a.action, 64)),
      String(a.count),
      String(a.alerts),
      String(a.signatures),
      a.fallbackOnly ? "heuristic" : "AI",
    ]),
  );
}

function modelTable(rows: ModelStat[]): string {
  return mdTable(
    ["Model", "Summaries"],
    rows.map((m) => [cell(m.model), String(m.count)]),
  );
}

function renderMarkdown(m: InsightReport): string {
  const lines: string[] = [];
  lines.push(`# 🧠 SecTool AI Analyst-Insight Digest`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** aggregates the stored Claude summary on each alert — coverage, rule-vs-Claude severity re-grading, ` +
      `and recommended-action frequency · **Window alerts:** ${m.coverage.total}`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.coverage.total) {
    lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query or Claude call was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## AI-analysis coverage`);
  lines.push("");
  lines.push(coverageTable(m.coverage));
  lines.push("");
  lines.push(
    `**Coverage** = ${pct(m.coverage.coverage)} of alerts carry a summary; **AI share** = ` +
      `${m.coverage.aiShare !== null ? pct(m.coverage.aiShare) : "—"} of those are Claude-produced. A high *fallback* ` +
      `or *un-analysed* share means the AI verdicts below cover only part of the stream.`,
  );
  lines.push("");

  lines.push(`## Rule vs Claude — severity re-grading`);
  lines.push("");
  if (!m.divergence.compared) {
    lines.push(
      `_No AI-backed summaries this window, so there is nothing to compare._ Re-grading is computed only over ` +
        `Claude-produced summaries (heuristic fallbacks copy the rule severity and would always read as "agreed").`,
    );
  } else {
    lines.push(divergenceTable(m.divergence));
    lines.push("");
    lines.push(
      `_Downgraded_ = Claude rated the alert below the rule (a false-positive / over-noisy-rule signal); _Upgraded_ = ` +
        `Claude rated it above the rule (an under-graded rule worth escalating). Computed over AI-backed summaries only.`,
    );
  }
  lines.push("");

  lines.push(`## False-positive candidates (Claude downgrades)`);
  lines.push("");
  if (!m.fpCandidates.length) {
    lines.push(`_No signature was downgraded by Claude this window._`);
  } else {
    lines.push(
      `Signatures Claude most often rated *below* the rule — your tuning backlog. Each is a lead to review, not a ` +
        `verdict; cross-check in the tuning report before suppressing.`,
    );
    lines.push("");
    lines.push(sigTable(m.fpCandidates));
  }
  lines.push("");

  lines.push(`## Escalation candidates (Claude upgrades)`);
  lines.push("");
  if (!m.escalationCandidates.length) {
    lines.push(`_No signature was upgraded by Claude this window._`);
  } else {
    lines.push(
      `Signatures Claude most often rated *above* the rule — under-graded rules firing for real. Raise their priority ` +
        `and confirm they are reaching a human.`,
    );
    lines.push("");
    lines.push(sigTable(m.escalationCandidates));
  }
  lines.push("");

  lines.push(`## Recommended-action roll-up`);
  lines.push("");
  if (!m.topActions.length) {
    lines.push(`_No recommended actions were recorded on any summary this window._`);
  } else {
    lines.push(
      `Every \`recommendedActions\` entry, normalised and tallied — a frequency-ranked remediation backlog. _Source_ ` +
        `marks whether the advice came from Claude or a heuristic fallback (generic).`,
    );
    lines.push("");
    lines.push(actionTable(m.topActions));
  }
  lines.push("");

  lines.push(`## Model attribution`);
  lines.push("");
  lines.push(modelTable(m.models));
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from the **stored Claude summaries** on each alert. This audits the AI analysis ` +
      `layer's *opinions*, not ground truth: a downgrade is Claude's judgement that a rule over-fired, not proof it ` +
      `did — treat the false-positive list as leads to review. Re-grading is computed over AI-backed summaries only ` +
      `(heuristic fallbacks copy the rule severity). Alerts processed before summarisation was enabled show as ` +
      `un-analysed and are excluded from the divergence math. A long look-back can hit the store's history cap and ` +
      `skew every count. No live gateway query or Claude call was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the AI Analyst-Insight digest from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link InsightOptions}: `limit` (ranked-table rows) and a `nowMs` pin.
 */
export function buildInsight(hours: number, opts: InsightOptions = {}): InsightReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(100, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  let aiBacked = 0;
  let fallback = 0;
  let unanalyzed = 0;

  let downgraded = 0;
  let agreed = 0;
  let upgraded = 0;

  const sigAccs = new Map<string, SigAcc>();
  const actionAccs = new Map<string, ActionAcc>();
  const modelCounts = new Map<string, { count: number; fallback: boolean }>();

  for (const a of windowed) {
    const s = a.summary;
    if (!s) {
      unanalyzed++;
      continue;
    }
    const isFallback = s.fallback === true;
    if (isFallback) fallback++;
    else aiBacked++;

    // Model attribution: fallbacks share one synthetic bucket; AI-backed use the
    // recorded model id (or an unknown-model sentinel when absent).
    const modelKey = isFallback ? FALLBACK_MODEL : (s.model?.trim() || UNKNOWN_MODEL);
    const mc = modelCounts.get(modelKey);
    if (mc) mc.count++;
    else modelCounts.set(modelKey, { count: 1, fallback: isFallback });

    // Severity re-grading: AI-backed only (fallback copies the rule severity).
    if (!isFallback) {
      const delta = deltaOf(a.severity, s.severity);
      if (delta === "downgraded") downgraded++;
      else if (delta === "upgraded") upgraded++;
      else agreed++;

      const sig = a.signature?.trim();
      if (sig) {
        let acc = sigAccs.get(sig);
        if (!acc) {
          acc = {
            samples: 0,
            downgraded: 0,
            agreed: 0,
            upgraded: 0,
            netDelta: 0,
            ruleSeverity: a.severity as Severity,
            claudeSeverity: s.severity,
          };
          sigAccs.set(sig, acc);
        }
        acc.samples++;
        acc.netDelta += sevRank(s.severity) - sevRank(a.severity);
        if (delta === "downgraded") acc.downgraded++;
        else if (delta === "upgraded") acc.upgraded++;
        else acc.agreed++;
      }
    }

    // Recommended-action roll-up: over every summary (AI + fallback), so the list
    // is never empty when only fallbacks exist; the source is tracked per action.
    const sig = a.signature?.trim();
    for (const raw of s.recommendedActions ?? []) {
      const key = normAction(raw);
      if (!key) continue;
      let acc = actionAccs.get(key);
      if (!acc) {
        acc = { action: raw.trim(), count: 0, alerts: new Set(), signatures: new Set(), fallbackOnly: true };
        actionAccs.set(key, acc);
      }
      acc.count++;
      acc.alerts.add(a.id);
      if (sig) acc.signatures.add(sig);
      if (!isFallback) acc.fallbackOnly = false;
    }
  }

  const analyzed = aiBacked + fallback;
  const total = windowed.length;
  const compared = downgraded + agreed + upgraded;

  const coverage: InsightCoverage = {
    total,
    analyzed,
    aiBacked,
    fallback,
    unanalyzed,
    coverage: total ? round4(analyzed / total) : 0,
    aiShare: analyzed ? round4(aiBacked / analyzed) : null,
  };

  const divergence: InsightDivergence = {
    compared,
    downgraded,
    agreed,
    upgraded,
    downgradeRate: compared ? round4(downgraded / compared) : null,
    upgradeRate: compared ? round4(upgraded / compared) : null,
  };

  const sigList: SignatureDivergence[] = [...sigAccs.entries()].map(([signature, acc]) => ({
    signature,
    samples: acc.samples,
    downgraded: acc.downgraded,
    agreed: acc.agreed,
    upgraded: acc.upgraded,
    netDelta: acc.netDelta,
    ruleSeverity: acc.ruleSeverity,
    claudeSeverity: acc.claudeSeverity,
  }));

  // FP candidates: most downgrades first, then most-negative net delta, then
  // sample count, then signature for a stable order. Only signatures Claude
  // actually downgraded at least once qualify.
  const fpCandidates = sigList
    .filter((s) => s.downgraded > 0)
    .sort(
      (x, y) =>
        y.downgraded - x.downgraded ||
        x.netDelta - y.netDelta ||
        y.samples - x.samples ||
        (x.signature < y.signature ? -1 : x.signature > y.signature ? 1 : 0),
    )
    .slice(0, limit);

  // Escalation candidates: most upgrades first, then most-positive net delta.
  const escalationCandidates = sigList
    .filter((s) => s.upgraded > 0)
    .sort(
      (x, y) =>
        y.upgraded - x.upgraded ||
        y.netDelta - x.netDelta ||
        y.samples - x.samples ||
        (x.signature < y.signature ? -1 : x.signature > y.signature ? 1 : 0),
    )
    .slice(0, limit);

  const topActions: ActionStat[] = [...actionAccs.values()]
    .map((a) => ({
      action: a.action,
      count: a.count,
      alerts: a.alerts.size,
      signatures: a.signatures.size,
      fallbackOnly: a.fallbackOnly,
    }))
    .sort(
      (x, y) =>
        y.count - x.count ||
        y.alerts - x.alerts ||
        (x.action < y.action ? -1 : x.action > y.action ? 1 : 0),
    )
    .slice(0, limit);

  const models: ModelStat[] = [...modelCounts.entries()]
    .map(([model, v]) => ({ model, count: v.count, fallback: v.fallback }))
    .sort((x, y) => y.count - x.count || (x.model < y.model ? -1 : x.model > y.model ? 1 : 0));

  const highlights = writeHighlights(safeHours, coverage, divergence, fpCandidates, escalationCandidates, topActions);
  const model: InsightReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    coverage,
    divergence,
    fpCandidates,
    escalationCandidates,
    topActions,
    models,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded AI analyst-insight digest. */
export function insightFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-insight-${stamp}.md`;
}
