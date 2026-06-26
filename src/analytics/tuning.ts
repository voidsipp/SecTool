/**
 * Signature tuning / noise-reduction report.
 *
 * Every IDS/IPS deployment drowns in low-value chatter: policy hits, benign
 * scanners, protocol-anomaly noise that fires hundreds of times and never once
 * turns into a real incident. That noise is what causes alert fatigue — the
 * operator stops reading Discord because 90% of it is the same harmless
 * signature. The other reports in this project answer "what happened?"; this one
 * answers the operational follow-up every analyst eventually asks: **"what can I
 * safely silence so the signal stands out?"**
 *
 * For each distinct signature in the stored history it rolls up:
 *
 *   - total volume and a normalized alerts-per-day rate,
 *   - the severity ceiling it ever reached and the per-severity split,
 *   - how many distinct source / destination hosts it touched (broad scanner
 *     noise vs. a single repeating pair),
 *   - operator signals that prove value or the lack of it — how many of its
 *     alerts were manually dismissed, marked false-positive, left open in
 *     triage, or resolved as genuine incidents,
 *   - whether the gateway already blocked them, and
 *   - whether an existing suppression rule already covers them.
 *
 * From that it computes a 0-100 **noise score** (high volume + low severity +
 * dismissed/false-positive history pushes it up; medium+ severity, open triage,
 * and resolved-real incidents pull it down) and emits a concrete, conservative
 * **recommendation**: `suppress` (safe to mute), `review` (probably noise, eyeball
 * it first), or `keep` (carries signal — leave it alone). Each actionable row
 * carries a ready-to-apply suppression rule whose `maxSeverity` is pinned to the
 * observed ceiling, so a future escalation above that level still pages you.
 *
 * It is pure in-memory math over alertStore + the dismiss / triage / block /
 * suppression stores — no SSH, no Claude, no network — so it is safe to call from
 * the dashboard or CLI at any time. Output is both a structured model and a
 * ready-to-paste Markdown document, mirroring report.ts, compare.ts, profile.ts
 * and assets.ts.
 *
 * This complements:
 *   - trends.ts    (top signatures by raw count — no value judgement), and
 *   - the Suppressions view (where the recommended rules are one-click applied).
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { dismissStore } from "../store/dismissed.ts";
import { triageStore } from "../store/triage.ts";
import { suppressionStore } from "../store/suppressions.ts";
import { SEVERITY_ORDER, type Severity, type SecurityAlert } from "../types.ts";

/** Per-recommendation action a row resolves to. */
export type TuningRecommendation = "suppress" | "review" | "keep";

/** A suppression rule SecTool would apply for a noisy signature. */
export interface SuggestedRule {
  /** Exact signature text to match (substring match in the suppression engine). */
  signature: string;
  /**
   * Cap the rule at the observed severity ceiling so that if this signature ever
   * escalates ABOVE this level in future, it still notifies instead of being
   * silently swallowed. This is the key safety property of the recommendation.
   */
  maxSeverity: Severity;
  /** Human-readable reason stamped onto the rule when applied. */
  reason: string;
}

export interface TuningSignature {
  signature: string;
  /** Most common category this signature appeared under. */
  category?: string;
  /** Total alerts for this signature in the window. */
  count: number;
  /** Per-severity counts, ordered info → critical (zeros omitted). */
  bySeverity: Array<{ severity: Severity; count: number }>;
  /** Highest severity this signature ever reached. */
  severityMax: Severity;
  /** Distinct source IPs that tripped it. */
  distinctSources: number;
  /** Distinct destination IPs it targeted. */
  distinctDests: number;
  /** Alerts at medium severity or above — the "this might be real" count. */
  escalatedCount: number;
  /** Alerts the operator manually dismissed. */
  dismissedCount: number;
  /** Alerts triaged as false-positive — the strongest "this is noise" proof. */
  falsePositiveCount: number;
  /** Alerts still open in triage. */
  openTriageCount: number;
  /** Alerts under active investigation. */
  investigatingCount: number;
  /** Alerts resolved as genuine incidents. */
  resolvedCount: number;
  /** Alerts the gateway actually blocked. */
  blockedCount: number;
  firstSeen: number;
  lastSeen: number;
  spanMs: number;
  /** Normalized alerts-per-day rate over the window. */
  perDay: number;
  /** Alerts already silenced by an existing suppression rule. */
  coveredCount: number;
  /** Whether every alert for this signature is already suppressed. */
  alreadyCovered: boolean;
  /** Composite 0-100 noise score (see scoreNoise). Higher = noisier. */
  noiseScore: number;
  /** The action SecTool recommends. */
  recommendation: TuningRecommendation;
  /** One-line plain-language justification for the recommendation. */
  rationale: string;
  /** A ready-to-apply suppression rule, or null when no action is advised. */
  suggestedRule: SuggestedRule | null;
  /** Most-recent alert ids for drill-in, newest first. */
  sampleAlertIds: string[];
}

export interface TuningReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts in the window that carry a signature (the tunable population). */
  totalAlerts: number;
  /** Alerts with no signature — can't be tuned by signature, reported for context. */
  unsignedAlerts: number;
  /** Distinct signatures seen. */
  signatureCount: number;
  /** Signatures recommended for suppression. */
  suppressCandidates: number;
  /** Signatures recommended for manual review. */
  reviewCandidates: number;
  /** Alerts that WOULD be silenced if every `suppress` recommendation were applied. */
  estimatedSilenced: number;
  /** {@link estimatedSilenced} as a percentage of {@link totalAlerts}. */
  estimatedSilencedPct: number;
  /** Alerts already silenced by existing suppression rules. */
  alreadyCoveredAlerts: number;
  /** Plain-language call-outs about the report as a whole. */
  highlights: string[];
  /** Signatures ranked noisiest-first. */
  signatures: TuningSignature[];
  /** The finished Markdown document. */
  markdown: string;
}

const SAMPLE_IDS = 8;
const DEFAULT_TOP = 40;
/** Below this volume a dedicated suppression rule isn't worth the maintenance. */
const MIN_SUPPRESS_COUNT = 4;
const MIN_REVIEW_COUNT = 3;
/** Noise-score thresholds for the two actionable tiers. */
const SUPPRESS_SCORE = 55;
const REVIEW_SCORE = 30;

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? (b as Severity) : a;
}

function normalizeAction(a: string | undefined): string {
  const v = (a ?? "").toLowerCase().trim();
  if (v === "blocked" || v === "detected" || v === "allowed") return v;
  return "unknown";
}

/**
 * Composite 0-100 noise score for a signature. High = lots of low-value chatter
 * the operator can safely mute. The model deliberately leans CONSERVATIVE: any
 * proof of real value (medium+ severity, open triage, resolved-real incidents)
 * pulls the score down hard so we never recommend silencing something that
 * matters.
 */
function scoreNoise(p: {
  count: number;
  severityMax: Severity;
  dismissedCount: number;
  falsePositiveCount: number;
  escalatedCount: number;
  openTriageCount: number;
  investigatingCount: number;
  resolvedCount: number;
}): number {
  if (p.count === 0) return 0;
  let score = 0;
  // Volume: noisy signatures fire a lot. Log-scaled so a 10× jump isn't 10× score.
  score += Math.min(34, Math.log2(p.count + 1) * 7);
  // Severity ceiling: the lower the worst severity, the more it reads as noise.
  score += (4 - sevRank(p.severityMax)) * 9; // info → +36, critical → +0
  // Operator hand-dismissed these → real evidence it's noise.
  score += Math.min(20, (p.dismissedCount / p.count) * 30);
  // Explicitly triaged false-positive → the strongest possible noise signal.
  score += Math.min(26, (p.falsePositiveCount / p.count) * 45);

  // ---- penalties: anything proving the signature carries signal ----
  score -= Math.min(40, p.escalatedCount * 6); // medium+ alerts look real
  score -= Math.min(50, (p.openTriageCount + p.investigatingCount) * 12); // operator is on it
  score -= Math.min(20, p.resolvedCount * 4); // confirmed genuine incidents

  return Math.max(0, Math.min(100, Math.round(score)));
}

/** Resolve the recommendation tier + suggested rule from the rolled-up signals. */
function recommend(s: {
  count: number;
  noiseScore: number;
  severityMax: Severity;
  openTriageCount: number;
  investigatingCount: number;
  resolvedCount: number;
  alreadyCovered: boolean;
}): TuningRecommendation {
  if (s.alreadyCovered) return "keep";
  // Never recommend touching anything the operator is actively working or that
  // ever escalated past "low" — that's signal, not noise.
  const sev = sevRank(s.severityMax);
  const busy = s.openTriageCount > 0 || s.investigatingCount > 0 || s.resolvedCount > 0;
  if (busy) return "keep";
  if (s.count >= MIN_SUPPRESS_COUNT && s.noiseScore >= SUPPRESS_SCORE && sev <= 1) return "suppress";
  if (s.count >= MIN_REVIEW_COUNT && s.noiseScore >= REVIEW_SCORE && sev <= 2) return "review";
  return "keep";
}

// ----- formatting helpers (mirror report.ts / assets.ts conventions) -----

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function fmtDate(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
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

function mdTable(headers: string[], rows: string[][]): string {
  if (!rows.length) return "_None._";
  const head = `| ${headers.join(" | ")} |`;
  const sep = `| ${headers.map(() => "---").join(" | ")} |`;
  const body = rows.map((r) => `| ${r.join(" | ")} |`).join("\n");
  return `${head}\n${sep}\n${body}`;
}

const REC_LABEL: Record<TuningRecommendation, string> = {
  suppress: "🔕 Suppress",
  review: "👀 Review",
  keep: "· Keep",
};

/** Compose the report-level highlight bullets. */
function writeHighlights(model: Omit<TuningReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (!model.signatures.length) return out;

  if (model.suppressCandidates) {
    out.push(
      `${model.suppressCandidates} signature(s) look safe to suppress — applying them would mute ` +
        `~${model.estimatedSilenced} alert(s) (${model.estimatedSilencedPct}% of signed volume) ` +
        `without losing any medium+ severity events.`,
    );
  } else {
    out.push(`No signatures cleared the bar for automatic suppression — your alert stream is already fairly tight.`);
  }
  if (model.reviewCandidates) {
    out.push(`${model.reviewCandidates} additional signature(s) are probably noise but worth an eyeball first.`);
  }
  if (model.alreadyCoveredAlerts) {
    out.push(`${model.alreadyCoveredAlerts} alert(s) are already silenced by your existing suppression rules.`);
  }
  const top = model.signatures[0]!;
  out.push(
    `Noisiest signature: "${top.signature}" — ${top.count} alert(s) ` +
      `(${top.perDay.toFixed(1)}/day), peak ${top.severityMax}, noise score ${top.noiseScore}/100.`,
  );
  out.push(`${model.signatureCount} distinct signature(s) across ${model.totalAlerts} signed alert(s) this window.`);
  return out;
}

function renderMarkdown(model: TuningReport): string {
  const lines: string[] = [];
  lines.push(`# 🔧 SecTool Signature Tuning Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(model.windowEndMs)}`);
  lines.push(`**Window:** last ${model.hours} hour(s) — ${fmtTime(model.windowStartMs)} → ${fmtTime(model.windowEndMs)}`);
  lines.push(
    `**Signed alerts:** ${model.totalAlerts} · **Signatures:** ${model.signatureCount}` +
      (model.unsignedAlerts ? ` · ${model.unsignedAlerts} unsigned alert(s) (not tunable by signature)` : ""),
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!model.signatures.length) {
    lines.push(`No signed alerts in the last ${model.hours} hour(s) — nothing to tune.`);
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of model.highlights) lines.push(`- ${h}`);
  lines.push("");

  // Suppression candidates first — the actionable part.
  const suppress = model.signatures.filter((s) => s.recommendation === "suppress");
  if (suppress.length) {
    lines.push(`## 🔕 Recommended suppressions`);
    lines.push("");
    lines.push(
      `Each suggested rule is pinned to the observed severity ceiling, so a future escalation above ` +
        `that level still notifies you.`,
    );
    lines.push("");
    lines.push(
      mdTable(
        ["Signature", "Alerts", "/day", "Peak", "Score", "Suggested rule"],
        suppress.map((s) => [
          cell(s.signature),
          String(s.count),
          s.perDay.toFixed(1),
          cell(s.severityMax),
          String(s.noiseScore),
          s.suggestedRule ? cell(`sig~"${s.suggestedRule.signature}" & sev<=${s.suggestedRule.maxSeverity}`) : "—",
        ]),
      ),
    );
    lines.push("");
  }

  const review = model.signatures.filter((s) => s.recommendation === "review");
  if (review.length) {
    lines.push(`## 👀 Worth reviewing`);
    lines.push("");
    lines.push(
      mdTable(
        ["Signature", "Alerts", "/day", "Peak", "Dismissed", "Score", "Why"],
        review.map((s) => [
          cell(s.signature),
          String(s.count),
          s.perDay.toFixed(1),
          cell(s.severityMax),
          String(s.dismissedCount),
          String(s.noiseScore),
          cell(s.rationale),
        ]),
      ),
    );
    lines.push("");
  }

  // Full ranked board for completeness.
  lines.push(`## All signatures (noisiest first)`);
  lines.push("");
  lines.push(
    mdTable(
      ["#", "Signature", "Rec", "Alerts", "Peak", "Srcs", "Dsts", "Dismissed", "FP", "Open", "Blocked", "Score", "Last"],
      model.signatures.map((s, i) => [
        String(i + 1),
        cell(s.signature),
        cell(REC_LABEL[s.recommendation]),
        String(s.count),
        cell(s.severityMax),
        String(s.distinctSources),
        String(s.distinctDests),
        String(s.dismissedCount),
        String(s.falsePositiveCount),
        String(s.openTriageCount),
        String(s.blockedCount),
        String(s.noiseScore),
        fmtAgo(s.lastSeen, model.windowEndMs),
      ]),
    ),
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from ${model.totalAlerts} stored alert(s) across ${model.signatureCount} ` +
      `signature(s). Recommendations are conservative — anything with medium+ severity or active triage is left ` +
      `untouched. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the signature-tuning report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param limit Cap on how many signatures are returned (the noisiest ones).
 * @param nowMs Pins the window end for deterministic tests; defaults to now.
 */
export function buildTuning(hours: number, limit = DEFAULT_TOP, nowMs = Date.now()): TuningReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const windowEndMs = nowMs;
  const windowStartMs = windowEndMs - safeHours * 3_600_000;
  const safeLimit = Math.max(1, Math.min(500, Math.floor(limit)));
  const windowDays = safeHours / 24;

  const all: StoredAlert[] = alertStore.all();
  // NB: unlike the other reports we deliberately KEEP dismissed alerts — an
  // operator dismissing a signature is exactly the noise signal we want to learn
  // from. Whether each alert was dismissed is tracked per-signature below.
  const inWindow = all.filter(
    (a) => typeof a.time === "number" && a.time >= windowStartMs && a.time <= windowEndMs,
  );

  interface Agg {
    signature: string;
    count: number;
    severityMax: Severity;
    bySev: Map<Severity, number>;
    catCounts: Map<string, number>;
    sources: Set<string>;
    dests: Set<string>;
    escalatedCount: number;
    dismissedCount: number;
    falsePositiveCount: number;
    openTriageCount: number;
    investigatingCount: number;
    resolvedCount: number;
    blockedCount: number;
    coveredCount: number;
    firstSeen: number;
    lastSeen: number;
    samples: Array<{ id: string; time: number }>;
  }

  const bySig = new Map<string, Agg>();
  let totalAlerts = 0;
  let unsignedAlerts = 0;

  for (const a of inWindow) {
    const sig = (a.signature ?? "").trim();
    if (!sig) {
      unsignedAlerts++;
      continue;
    }
    totalAlerts++;
    const sev = (a.severity as Severity) ?? "info";
    let agg = bySig.get(sig);
    if (!agg) {
      agg = {
        signature: sig,
        count: 0,
        severityMax: "info",
        bySev: new Map(),
        catCounts: new Map(),
        sources: new Set(),
        dests: new Set(),
        escalatedCount: 0,
        dismissedCount: 0,
        falsePositiveCount: 0,
        openTriageCount: 0,
        investigatingCount: 0,
        resolvedCount: 0,
        blockedCount: 0,
        coveredCount: 0,
        firstSeen: a.time,
        lastSeen: a.time,
        samples: [],
      };
      bySig.set(sig, agg);
    }
    agg.count++;
    agg.severityMax = maxSeverity(agg.severityMax, sev);
    agg.bySev.set(sev, (agg.bySev.get(sev) ?? 0) + 1);
    if (a.category) agg.catCounts.set(a.category, (agg.catCounts.get(a.category) ?? 0) + 1);
    if (a.srcIp && isIP(a.srcIp) > 0) agg.sources.add(a.srcIp);
    if (a.dstIp && isIP(a.dstIp) > 0) agg.dests.add(a.dstIp);
    if (sevRank(sev) >= 2) agg.escalatedCount++;
    if (dismissStore.has(a.id)) agg.dismissedCount++;
    // Only count triage signals when the operator actually engaged — an alert
    // with no triage entry is untouched, NOT implicitly "open". (Treating
    // untriaged alerts as open would mark every signature "busy" and suppress
    // all recommendations.)
    const entry = triageStore.get(a.id);
    if (entry) {
      if (entry.status === "false-positive") agg.falsePositiveCount++;
      else if (entry.status === "investigating") agg.investigatingCount++;
      else if (entry.status === "resolved") agg.resolvedCount++;
      else agg.openTriageCount++; // explicitly left open by the operator
    }
    if (normalizeAction(a.action) === "blocked") agg.blockedCount++;

    // Is this alert already silenced by an active suppression rule? matchAlert
    // only reads signature/category/src/dst/severity, so a minimal projection
    // of the stored alert is sufficient.
    const probe = {
      id: a.id,
      category: a.category,
      signature: a.signature,
      srcIp: a.srcIp,
      dstIp: a.dstIp,
      severity: sev,
    } as unknown as SecurityAlert;
    if (suppressionStore.matchAlert(probe, windowEndMs)) agg.coveredCount++;

    agg.lastSeen = Math.max(agg.lastSeen, a.time);
    agg.firstSeen = Math.min(agg.firstSeen, a.time);
    agg.samples.push({ id: a.id, time: a.time });
  }

  const signatures: TuningSignature[] = [...bySig.values()].map((agg) => {
    const bySeverity = SEVERITY_ORDER.map((severity) => ({ severity, count: agg.bySev.get(severity) ?? 0 })).filter(
      (x) => x.count > 0,
    );
    const category = [...agg.catCounts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
    const spanMs = agg.lastSeen - agg.firstSeen;
    const perDay = agg.count / Math.max(windowDays, 1 / 24);
    const alreadyCovered = agg.coveredCount >= agg.count && agg.count > 0;
    const noiseScore = scoreNoise({
      count: agg.count,
      severityMax: agg.severityMax,
      dismissedCount: agg.dismissedCount,
      falsePositiveCount: agg.falsePositiveCount,
      escalatedCount: agg.escalatedCount,
      openTriageCount: agg.openTriageCount,
      investigatingCount: agg.investigatingCount,
      resolvedCount: agg.resolvedCount,
    });
    const recommendation = recommend({
      count: agg.count,
      noiseScore,
      severityMax: agg.severityMax,
      openTriageCount: agg.openTriageCount,
      investigatingCount: agg.investigatingCount,
      resolvedCount: agg.resolvedCount,
      alreadyCovered,
    });

    let rationale: string;
    if (alreadyCovered) {
      rationale = "Already silenced by an existing suppression rule.";
    } else if (recommendation === "suppress") {
      const bits = [`${agg.count} alert(s) at ${perDay.toFixed(1)}/day`];
      if (agg.falsePositiveCount) bits.push(`${agg.falsePositiveCount} marked false-positive`);
      if (agg.dismissedCount) bits.push(`${agg.dismissedCount} dismissed`);
      bits.push(`peak only ${agg.severityMax}`);
      rationale = `${bits.join(", ")} — safe to mute.`;
    } else if (recommendation === "review") {
      rationale = `High volume (${agg.count}) with peak ${agg.severityMax}; likely noise but confirm before muting.`;
    } else if (agg.escalatedCount || agg.resolvedCount || agg.openTriageCount > 0 || agg.investigatingCount > 0) {
      rationale = `Carries signal — ${agg.escalatedCount} medium+ alert(s), ${agg.openTriageCount} open / ${agg.resolvedCount} resolved in triage.`;
    } else {
      rationale = `Low volume (${agg.count}) — not worth a dedicated rule yet.`;
    }

    const suggestedRule: SuggestedRule | null =
      recommendation === "suppress" || recommendation === "review"
        ? {
            signature: agg.signature,
            maxSeverity: agg.severityMax,
            reason:
              `Auto-tuning: noisy signature (${agg.count} alert(s) @ ${perDay.toFixed(1)}/day, ` +
              `peak ${agg.severityMax}) — SecTool tuning ${fmtDate(windowEndMs)}`,
          }
        : null;

    const sampleAlertIds = agg.samples
      .sort((x, y) => y.time - x.time)
      .slice(0, SAMPLE_IDS)
      .map((s) => s.id);

    return {
      signature: agg.signature,
      category,
      count: agg.count,
      bySeverity,
      severityMax: agg.severityMax,
      distinctSources: agg.sources.size,
      distinctDests: agg.dests.size,
      escalatedCount: agg.escalatedCount,
      dismissedCount: agg.dismissedCount,
      falsePositiveCount: agg.falsePositiveCount,
      openTriageCount: agg.openTriageCount,
      investigatingCount: agg.investigatingCount,
      resolvedCount: agg.resolvedCount,
      blockedCount: agg.blockedCount,
      firstSeen: agg.firstSeen,
      lastSeen: agg.lastSeen,
      spanMs,
      perDay,
      coveredCount: agg.coveredCount,
      alreadyCovered,
      noiseScore,
      recommendation,
      rationale,
      suggestedRule,
      sampleAlertIds,
    };
  });

  // Actionable, then noisiest. Suppress > review > keep; ties by score, volume, recency.
  const recRank: Record<TuningRecommendation, number> = { suppress: 2, review: 1, keep: 0 };
  signatures.sort(
    (a, b) =>
      recRank[b.recommendation] - recRank[a.recommendation] ||
      b.noiseScore - a.noiseScore ||
      b.count - a.count ||
      b.lastSeen - a.lastSeen,
  );

  const ranked = signatures.slice(0, safeLimit);
  const suppressCandidates = signatures.filter((s) => s.recommendation === "suppress").length;
  const reviewCandidates = signatures.filter((s) => s.recommendation === "review").length;
  const estimatedSilenced = signatures
    .filter((s) => s.recommendation === "suppress")
    .reduce((n, s) => n + (s.count - s.coveredCount), 0);
  const alreadyCoveredAlerts = signatures.reduce((n, s) => n + s.coveredCount, 0);

  const base: Omit<TuningReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalAlerts,
    unsignedAlerts,
    signatureCount: signatures.length,
    suppressCandidates,
    reviewCandidates,
    estimatedSilenced,
    estimatedSilencedPct: totalAlerts > 0 ? Math.round((estimatedSilenced / totalAlerts) * 100) : 0,
    alreadyCoveredAlerts,
    signatures: ranked,
  };
  const highlights = writeHighlights(base);
  const model: TuningReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded tuning report. */
export function tuningFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-tuning-${stamp}.md`;
}
