/**
 * Dismissal audit — "of the alerts I *hid*, which should I not have hidden — and
 * which kept firing after I made them disappear?"
 *
 * SecTool audits both deny-side and allow-side controls, but the **hide** control
 * has had no review of its own:
 *
 *   - safelist.ts audits the **allowlist** (a vetted-benign IP still attacking),
 *   - suppressions.ts (suppaudit) audits the **suppression rules** (a silenced
 *     signature still hiding live, serious traffic),
 *   - recidivism.ts / hygiene.ts audit the **blocklist** (did a block hold; is it
 *     stale), and
 *   - backlog.ts joins triage state for the **SLA queue**.
 *
 * Nothing audits the **dismiss store** (see store/dismissed.ts). Dismissing an
 * alert from the dashboard hides it from the live list — a per-*alert* "I've
 * looked at this, make it go away" action, distinct from the per-IP safelist and
 * the per-rule suppression. It is the fastest, lowest-friction way to quiet noise,
 * which is exactly why it is the easiest place to make a mistake: a hurried
 * dismissal of a genuinely serious alert removes it from view with **no severity
 * gate and no second look**, and unlike a suppression rule it leaves no standing
 * artifact to re-examine later. The dismissal is silent and individual; the only
 * way to know it was wrong is to go back and check.
 *
 * That is what this report does. It takes every current dismissal, rejoins it to
 * the stored alert it hid (`alertStore`), and asks two questions a leaderboard
 * can never answer because the dismissed alerts are precisely the ones the
 * operator removed from every other view:
 *
 *   1. **Was the dismissed alert itself serious?** Dismissing a high/critical
 *      detection is inherently risky — you hid the kind of thing the tool exists
 *      to surface. Severity of the hidden alert is the first axis.
 *
 *   2. **Did the threat keep coming *after* you hid it?** The sharp, novel axis.
 *      For each dismissed alert with a usable `srcIp + signature` fingerprint, the
 *      report scans the window for *later* alerts sharing that fingerprint
 *      (`time > dismissedAt`). If the same source keeps tripping the same rule
 *      after you dismissed it, the dismissal didn't make the threat go away — it
 *      just blinded you to it. Worse, if a later occurrence is at a **higher**
 *      severity than the alert you dismissed, the threat **escalated after you
 *      stopped watching** — the strongest possible "this was premature" signal.
 *
 * Each dismissal earns a one-word verdict:
 *
 *   - **🔴 risky** — the hidden alert was high/critical, OR it recurred
 *     post-dismissal at high/critical, OR it escalated after dismissal. You hid
 *     something that mattered (and, often, is still happening). Restore and
 *     investigate.
 *   - **🟠 questionable** — medium-severity hidden alert, OR any post-dismissal
 *     recurrence, OR a medium+ alert dismissed with **no reason** recorded. Not
 *     alarming on its own, but the hide is hard to justify from the record.
 *   - **🟢 sound** — a low/info alert with no notable recurrence: a justified
 *     noise dismissal, the action working as intended.
 *
 * Two hygiene axes ride alongside the verdict: dismissals recorded with **no
 * reason** (an audit-trail gap — nobody can later tell *why* it was hidden), and
 * dismissals whose alert is **no longer in the store** (evicted by the history cap
 * or never recorded) and therefore cannot be assessed at all — surfaced honestly
 * as a coverage caveat rather than silently dropped.
 *
 * Honest caveats baked into the output:
 *
 *   - **Detections, not ground truth.** A dismissed alert that recurs may still be
 *     genuine noise (a chronic benign scanner). A verdict is a prompt to *look*,
 *     not an automatic restore — pair "risky" with the per-IP profile.
 *   - **Recurrence needs a fingerprint.** It is keyed on `srcIp + signature`; an
 *     alert missing either can't be matched, so its recurrence reads as "n/a", not
 *     "none". A source that rotates IPs evades the match (under-counts recurrence).
 *   - **Window- & store-bounded.** Every current dismissal is audited regardless
 *     of when it was made, but the recurrence search only sees alerts inside the
 *     look-back; widen the window for a slow burner. A long look-back can hit the
 *     alert store's history cap and clip older recurrences.
 *
 * Pure in-memory math over alertStore + the dismiss / block / watch / safe / triage
 * stores — no SSH, no Claude, no network. Output is both a structured model and a
 * ready-to-paste Markdown document, mirroring safelist.ts, suppressions.ts and the
 * other offline audit reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { dismissStore } from "../store/dismissed.ts";
import { triageStore } from "../store/triage.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Risk verdict for a single dismissal, driven by severity + post-dismissal recurrence. */
export type DismissalVerdict = "risky" | "questionable" | "sound";

/** A later alert sharing a dismissed alert's `srcIp + signature` fingerprint. */
export interface RecurrenceInfo {
  /** Alerts sharing the fingerprint that fired strictly after the dismissal. */
  count: number;
  /** Worst severity across those later alerts. */
  severityMax: Severity;
  /** Most recent recurrence time (ms epoch); 0 when none. */
  lastSeen: number;
  /** A later occurrence was more severe than the dismissed alert. */
  escalated: boolean;
}

export interface DismissalAudit {
  /** The dismissed alert's stable id. */
  id: string;
  /** When the alert was dismissed (ms epoch; 0 if unknown). */
  dismissedAt: number;
  /** Operator-supplied dismissal reason, if any. */
  reason?: string;
  /** True when the dismissal carried no reason (an audit-trail gap). */
  noReason: boolean;
  /** False when the hidden alert is no longer in the store (cannot be assessed). */
  resolved: boolean;

  // --- recovered alert facts (only meaningful when `resolved`) ---
  /** Alert timestamp (ms epoch); 0 when unresolved. */
  alertTime: number;
  severity: Severity;
  signature?: string;
  category?: string;
  srcIp?: string;
  dstIp?: string;
  /** Normalized gateway disposition: blocked / detected / allowed / unknown. */
  action: string;
  /** Current triage status of the hidden alert. */
  triageStatus: string;

  /** Post-dismissal recurrence of the same `srcIp + signature` fingerprint. */
  recurrence: RecurrenceInfo;
  /** True when a fingerprint (srcIp + signature) was available to search on. */
  hasFingerprint: boolean;

  /** The source IP is currently on the blocklist (context). */
  blocked: boolean;
  /** The source IP is on the watchlist (context). */
  watched: boolean;
  /** The source IP is on the safelist (context). */
  safe: boolean;

  /** The risk verdict. */
  verdict: DismissalVerdict;
}

export interface DismissalReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Total dismissal entries in the store. */
  totalDismissals: number;
  /** Dismissals whose hidden alert is still in the store (assessable). */
  resolvedCount: number;
  /** Dismissals whose hidden alert is gone (evicted / never recorded). */
  unresolvedCount: number;
  riskyCount: number;
  questionableCount: number;
  soundCount: number;
  /** Resolved dismissals whose hidden alert was medium severity or worse. */
  severeDismissedCount: number;
  /** Dismissals that recurred (any severity) after being hidden. */
  recurredCount: number;
  /** Dismissals that escalated (a later occurrence was more severe). */
  escalatedCount: number;
  /** Dismissals recorded with no reason. */
  noReasonCount: number;
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** Audited dismissals ranked riskiest-first (capped to the row limit). */
  entries: DismissalAudit[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface DismissalOptions {
  /** Max entries returned (riskiest first); clamped to [1, 2000]. */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 100;
const MS_PER_HOUR = 3_600_000;

// ----- classifiers / helpers (mirror safelist.ts conventions) ----------------

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

function normalizeAction(a: string | undefined): string {
  const v = (a ?? "").toLowerCase().trim();
  if (v === "blocked" || v === "detected" || v === "allowed") return v;
  return "unknown";
}

/**
 * Verdict for a single dismissal. Driven first by the severity of the hidden
 * alert, then by what happened *after* it was hidden (recurrence / escalation),
 * with a hygiene nudge for unexplained dismissals of non-trivial alerts.
 */
function classifyVerdict(
  severity: Severity,
  rec: RecurrenceInfo,
  hasReason: boolean,
): DismissalVerdict {
  // Hid something serious, or it came back / escalated at a serious level.
  if (sevRank(severity) >= 3) return "risky"; // high / critical hidden
  if (rec.escalated && sevRank(rec.severityMax) >= 3) return "risky";
  if (rec.count > 0 && sevRank(rec.severityMax) >= 3) return "risky";

  // Medium hidden, or any recurrence, or an unexplained medium+ dismissal.
  if (sevRank(severity) === 2) return "questionable";
  if (rec.count > 0) return "questionable";
  if (rec.escalated) return "questionable";
  if (!hasReason && sevRank(severity) >= 2) return "questionable";

  return "sound";
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

const VERDICT_LABEL: Record<DismissalVerdict, string> = {
  risky: "🔴 Risky",
  questionable: "🟠 Questionable",
  sound: "🟢 Sound",
};

const VERDICT_RANK: Record<DismissalVerdict, number> = { risky: 3, questionable: 2, sound: 1 };

// ----- recurrence index ------------------------------------------------------

/** One occurrence of a fingerprint in the window: when it fired and how bad. */
interface Occurrence {
  time: number;
  severity: Severity;
}

/** The `srcIp + signature` key a recurrence is matched on, or null if unusable. */
function fingerprint(srcIp: string | undefined, signature: string | undefined): string | null {
  const ip = srcIp && isIP(srcIp) > 0 ? srcIp : undefined;
  const sig = (signature ?? "").trim();
  if (!ip || !sig) return null;
  return `${ip} ${sig}`;
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(model: Omit<DismissalReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (!model.totalDismissals) return out;

  const risky = model.entries.filter((e) => e.verdict === "risky");
  if (risky.length) {
    const lead = risky[0]!;
    const sevPart = sevRank(lead.severity) >= 3 ? `a **${lead.severity}** alert` : `an alert`;
    const recPart = lead.recurrence.count
      ? ` that **recurred ${lead.recurrence.count}×** after dismissal (peak ${lead.recurrence.severityMax}${lead.recurrence.escalated ? ", escalated" : ""})`
      : "";
    out.push(
      `🔴 **${risky.length} dismissal(s) hid something that mattered.** Worst: ${sevPart} from ` +
        `\`${lead.srcIp ?? "?"}\`${recPart}${lead.reason ? `, dismissed "${clip(lead.reason, 32)}"` : ", dismissed with no reason"}. ` +
        `These were removed from every other view — **restore and investigate.**`,
    );
  } else {
    out.push(
      `🟢 No dismissal hid a high/critical alert or one that recurred at a serious level this window — the ` +
        `hide control looks like it is being used on genuine noise.`,
    );
  }

  if (model.escalatedCount) {
    out.push(
      `📈 **${model.escalatedCount} dismissed threat(s) escalated after being hidden** — a later occurrence of the ` +
        `same source+signature was *more severe* than the alert you dismissed. Dismissing it stopped you watching ` +
        `exactly as it got worse.`,
    );
  } else if (model.recurredCount) {
    out.push(
      `🔁 **${model.recurredCount} dismissed threat(s) kept firing after dismissal** (same source + signature). ` +
        `Hiding the alert did not stop the activity — consider a block or a scoped suppression instead of a dismiss.`,
    );
  }

  if (model.severeDismissedCount) {
    out.push(
      `🙈 **${model.severeDismissedCount} medium-or-worse alert(s) were dismissed** outright. The dismiss action has ` +
        `no severity gate — this is the only view that surfaces serious traffic that was hidden by hand.`,
    );
  }

  if (model.noReasonCount) {
    out.push(
      `📝 ${model.noReasonCount} dismissal(s) carry **no reason** — an audit-trail gap. Nobody reviewing later can ` +
        `tell why the alert was hidden; prefer a one-line justification so the decision is defensible.`,
    );
  }

  if (model.unresolvedCount) {
    out.push(
      `❓ ${model.unresolvedCount} dismissal(s) reference an alert no longer in the store (evicted by the history ` +
        `cap, or never recorded) and **cannot be assessed** — counted here for honesty, excluded from the verdicts.`,
    );
  }

  return out;
}

// ----- markdown --------------------------------------------------------------

function recurrenceCell(e: DismissalAudit): string {
  if (!e.hasFingerprint) return "n/a";
  if (!e.recurrence.count) return "—";
  return `${e.recurrence.count}× ${e.recurrence.severityMax}${e.recurrence.escalated ? " ⬆" : ""}`;
}

function auditTable(rows: DismissalAudit[], now: number): string {
  return mdTable(
    ["#", "Verdict", "Sev", "Source", "Signature", "Recurred", "Disp.", "Triage", "Dismissed", "Reason"],
    rows.map((e, i) => [
      String(i + 1),
      cell(VERDICT_LABEL[e.verdict]),
      cell(e.severity),
      cell(e.srcIp ?? "—") + (e.blocked ? " ⛔" : "") + (e.watched ? " 👁" : "") + (e.safe ? " ✅" : ""),
      cell(e.signature ? clip(e.signature, 40) : "—"),
      recurrenceCell(e),
      e.action === "blocked" ? "blocked" : e.action === "detected" ? "detect-only" : e.action,
      cell(e.triageStatus),
      e.dismissedAt ? fmtAgo(e.dismissedAt, now) : "unknown",
      cell(e.reason ? clip(e.reason, 28) : "—"),
    ]),
  );
}

function renderMarkdown(model: DismissalReport): string {
  const lines: string[] = [];
  lines.push(`# 🙈 SecTool Dismissal Audit`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(model.windowEndMs)}`);
  lines.push(`**Window (recurrence search):** last ${model.hours} hour(s) — ${fmtTime(model.windowStartMs)} → ${fmtTime(model.windowEndMs)}`);
  lines.push(
    `**Dismissals:** ${model.totalDismissals} · ` +
      `🔴 ${model.riskyCount} risky · 🟠 ${model.questionableCount} questionable · 🟢 ${model.soundCount} sound` +
      (model.unresolvedCount ? ` · ❓ ${model.unresolvedCount} unassessable` : ""),
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!model.totalDismissals) {
    lines.push(
      `Nothing has been dismissed — there is nothing to audit. Dismiss an alert from the dashboard (it hides ` +
        `the alert from the live list, restorably) to populate this report.`,
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of model.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(
    `**Method:** every current dismissal is rejoined to the alert it hid, then scored on two axes — the ` +
      `**severity of the hidden alert** and its **post-dismissal recurrence** (later alerts sharing the same ` +
      `\`source + signature\` that fired *after* the dismissal, with escalation when a later one is more severe). ` +
      `The dismiss action has no severity gate and leaves no standing rule, so this is the only review of it. ` +
      `Offline, deterministic · **Assessable dismissals:** ${model.resolvedCount} of ${model.totalDismissals}`,
  );
  lines.push("");

  const assessable = model.entries.filter((e) => e.resolved);
  if (assessable.length) {
    lines.push(`## Dismissals (riskiest first)`);
    lines.push("");
    lines.push(auditTable(assessable, model.windowEndMs));
    lines.push("");
    lines.push(
      `**Legend:** _Sev_ = severity of the hidden alert. _Recurred_ = later alerts with the same ` +
        `source+signature after the dismissal (\`⬆\` = escalated above the dismissed severity; _n/a_ = no usable ` +
        `fingerprint to search on). _Disp._ = the gateway's action on the hidden alert. ⛔ source blocklisted · ` +
        `👁 watchlisted · ✅ safelisted.`,
    );
    lines.push("");

    // Per-entry detail for the riskiest, so the doc stands alone.
    const risky = assessable.filter((e) => e.verdict === "risky");
    const detail = risky.length ? risky : assessable;
    const detailLimit = Math.min(detail.length, 10);
    if (detailLimit > 0) {
      lines.push(`## Detail — ${risky.length ? "riskiest" : "top"} ${detailLimit}`);
      lines.push("");
      for (let i = 0; i < detailLimit; i++) {
        const e = detail[i]!;
        const flags: string[] = [];
        if (e.blocked) flags.push("⛔ source blocklisted");
        if (e.watched) flags.push("👁 watchlisted");
        if (e.safe) flags.push("✅ safelisted");
        lines.push(
          `### ${i + 1}. ${VERDICT_LABEL[e.verdict]} — ${e.severity} · \`${e.srcIp ?? "?"}\` → \`${e.dstIp ?? "?"}\``,
        );
        lines.push("");
        lines.push(`- **Signature:** ${e.signature ? cell(e.signature) : "—"}${e.category ? ` _(${cell(e.category)})_` : ""}`);
        lines.push(
          `- **Dismissed:** ${e.dismissedAt ? `${fmtTime(e.dismissedAt)} (${fmtAgo(e.dismissedAt, model.windowEndMs)})` : "unknown"}` +
            ` · reason: ${e.reason ? `"${cell(e.reason)}"` : "**none recorded**"}`,
        );
        lines.push(
          `- **Hidden alert:** fired ${e.alertTime ? fmtTime(e.alertTime) : "unknown"} · gateway ` +
            `${e.action === "blocked" ? "blocked" : e.action === "detected" ? "**detected-only (not blocked)**" : e.action} · ` +
            `triage \`${e.triageStatus}\``,
        );
        if (e.hasFingerprint) {
          if (e.recurrence.count) {
            lines.push(
              `- **Post-dismissal recurrence:** ${e.recurrence.count}× more (peak **${e.recurrence.severityMax}**` +
                `${e.recurrence.escalated ? ", ⬆ **escalated** above the dismissed severity" : ""}, last ` +
                `${fmtAgo(e.recurrence.lastSeen, model.windowEndMs)}). The activity you hid is still happening.`,
            );
          } else {
            lines.push(`- **Post-dismissal recurrence:** none in window — the source+signature has not fired again.`);
          }
        } else {
          lines.push(`- **Post-dismissal recurrence:** n/a — the alert lacks a usable source+signature fingerprint.`);
        }
        if (flags.length) lines.push(`- **Flags:** ${flags.join(", ")}`);
        lines.push("");
      }
    }
  } else {
    lines.push(
      `_None of the ${model.totalDismissals} dismissal(s) could be matched to an alert still in the store — they ` +
        `predate the retained history. Nothing to assess._`,
    );
    lines.push("");
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from ${model.totalDismissals} dismissal(s) (${model.resolvedCount} assessable). ` +
      `A "risky"/"questionable" verdict is a prompt to **look**, not an automatic restore — a recurring dismissed ` +
      `alert can still be genuine noise (a chronic benign scanner). Recurrence is keyed on **source + signature**: ` +
      `an alert missing either reads as "n/a" (not "none"), and a source that rotates IPs evades the match. Every ` +
      `current dismissal is audited, but the recurrence search only sees alerts inside the look-back, and a long ` +
      `window can hit the store's history cap. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the dismissal audit from the dismiss store + stored alert history.
 *
 * @param hours Look-back window for the recurrence search, in hours (clamped to
 *              [1, 90 days]). Every current dismissal is audited regardless of its
 *              age; the window only bounds which later alerts count as recurrences.
 * @param opts  {@link DismissalOptions}: `limit` and a `nowMs` test pin.
 */
export function buildDismissals(hours: number, opts: DismissalOptions = {}): DismissalReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(2000, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const dismissals = dismissStore.all();

  // Index of every windowed alert's fingerprint → its occurrences, so recurrence
  // is a single map lookup per dismissal rather than a full re-scan each time.
  const occByFp = new Map<string, Occurrence[]>();
  const allAlerts = alertStore.all();
  for (const a of allAlerts) {
    if (typeof a.time !== "number" || a.time < windowStartMs || a.time > windowEndMs) continue;
    const fp = fingerprint(a.srcIp, a.signature);
    if (!fp) continue;
    const sev = (a.severity as Severity) ?? "info";
    const list = occByFp.get(fp);
    if (list) list.push({ time: a.time, severity: sev });
    else occByFp.set(fp, [{ time: a.time, severity: sev }]);
  }

  const built: DismissalAudit[] = dismissals.map((d) => {
    const dismissedAt = Number.isFinite(d.at) ? d.at : 0;
    const reason = d.reason?.trim() || undefined;
    const noReason = !reason;
    const alert: StoredAlert | undefined = alertStore.get(d.id);

    if (!alert) {
      // Hidden alert is gone — record the dismissal honestly but unassessed.
      return {
        id: d.id,
        dismissedAt,
        reason,
        noReason,
        resolved: false,
        alertTime: 0,
        severity: "info",
        action: "unknown",
        triageStatus: triageStore.view(d.id).status,
        recurrence: { count: 0, severityMax: "info", lastSeen: 0, escalated: false },
        hasFingerprint: false,
        blocked: false,
        watched: false,
        safe: false,
        verdict: "sound",
      };
    }

    const severity = (alert.severity as Severity) ?? "info";
    const fp = fingerprint(alert.srcIp, alert.signature);
    const hasFingerprint = fp !== null;

    // Recurrence = same-fingerprint alerts strictly *after* the dismissal time.
    const rec: RecurrenceInfo = { count: 0, severityMax: "info", lastSeen: 0, escalated: false };
    if (fp) {
      for (const occ of occByFp.get(fp) ?? []) {
        if (occ.time <= dismissedAt) continue;
        rec.count++;
        rec.severityMax = maxSeverity(rec.severityMax, occ.severity);
        if (occ.time > rec.lastSeen) rec.lastSeen = occ.time;
        if (sevRank(occ.severity) > sevRank(severity)) rec.escalated = true;
      }
    }

    const srcIp = alert.srcIp;
    return {
      id: d.id,
      dismissedAt,
      reason,
      noReason,
      resolved: true,
      alertTime: alert.time,
      severity,
      signature: alert.signature,
      category: alert.category,
      srcIp,
      dstIp: alert.dstIp,
      action: normalizeAction(alert.action),
      triageStatus: triageStore.view(d.id).status,
      recurrence: rec,
      hasFingerprint,
      blocked: srcIp ? blockStore.has(srcIp) : false,
      watched: srcIp ? watchStore.has(srcIp) : false,
      safe: srcIp ? safeStore.has(srcIp) : false,
      verdict: classifyVerdict(severity, rec, !noReason),
    };
  });

  // Risky → questionable → sound; within a tier by hidden severity, recurrence
  // (escalated first, then volume / worst), recency of dismissal, then id.
  built.sort(
    (a, b) =>
      VERDICT_RANK[b.verdict] - VERDICT_RANK[a.verdict] ||
      sevRank(b.severity) - sevRank(a.severity) ||
      Number(b.recurrence.escalated) - Number(a.recurrence.escalated) ||
      b.recurrence.count - a.recurrence.count ||
      sevRank(b.recurrence.severityMax) - sevRank(a.recurrence.severityMax) ||
      b.dismissedAt - a.dismissedAt ||
      (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
  );

  const resolved = built.filter((e) => e.resolved);
  const ranked = built.slice(0, limit);

  const base: Omit<DismissalReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalDismissals: built.length,
    resolvedCount: resolved.length,
    unresolvedCount: built.length - resolved.length,
    // Verdict tallies cover only assessable (resolved) dismissals; unassessable
    // ones are counted separately as unresolvedCount, not folded into "sound".
    riskyCount: resolved.filter((e) => e.verdict === "risky").length,
    questionableCount: resolved.filter((e) => e.verdict === "questionable").length,
    soundCount: resolved.filter((e) => e.verdict === "sound").length,
    severeDismissedCount: resolved.filter((e) => isSevere(e.severity)).length,
    recurredCount: resolved.filter((e) => e.recurrence.count > 0).length,
    escalatedCount: resolved.filter((e) => e.recurrence.escalated).length,
    noReasonCount: built.filter((e) => e.noReason).length,
    entries: ranked,
  };
  const highlights = writeHighlights(base);
  const model: DismissalReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded dismissal audit. */
export function dismissalsFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-dismissals-${stamp}.md`;
}
