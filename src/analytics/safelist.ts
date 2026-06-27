/**
 * Safelist / allowlist risk audit — "of the external IPs I vetted as *benign*,
 * which are still attacking me — and did that happen *after* I trusted them?"
 *
 * Every audit-style report in this project so far points at the **deny side** of
 * the controls:
 *
 *   - recidivism.ts asks whether a **blocklist** entry actually stopped traffic
 *     (post-block re-offending),
 *   - hygiene.ts asks which **blocklist** entries are stale and prunable,
 *   - suppaudit.ts asks which **suppression** rules are effective / dead / risky,
 *   - noise.ts asks which redundant streams are **suppression candidates**.
 *
 * Nothing audits the **allow side**. The safelist (see store/safelist.ts) is the
 * operator's set of external IPs vetted as benign — a vendor CDN, a monitoring
 * service, a sanctioned scanner. Marking an IP safe **removes it from host-risk
 * scoring and protects it from any auto-blocking**. That is a powerful, *silent*
 * trust grant: a safelisted address that later turns hostile is invisible to every
 * risk-ranked report (its score is suppressed) and immune to reactive blocking
 * (the responder is told to leave it alone) — yet the IPS keeps *detecting* its
 * traffic, because the safelist changes scoring, not ingestion. That detection
 * stream is exactly the evidence this audit reads.
 *
 * The single sharp question a safelist must answer is: **"is the trust I granted
 * still justified?"** A leaderboard of attackers can never answer it, because the
 * worst offenders are precisely the ones the safelist *erased* from the rankings.
 *
 * This report takes every safelist entry, folds the windowed alerts whose source
 * **or** destination is that IP, and — the crucial axis no other report reads —
 * splits them on the entry's **vetting timestamp** (`at`):
 *
 *   - `time < at`  → **pre-safelist** activity: the history *before* you vetted it.
 *     Often the very noise the safelist was created to silence; expected, context.
 *   - `time >= at` → **post-safelist** activity: the audit signal. A "benign" IP
 *     still tripping IPS rules *after* you trusted it. This drives the verdict.
 *
 * Each entry gets a one-word verdict from its **post-safelist** behaviour:
 *
 *   - **🔴 dangerous** — post-safelist alerts at **high/critical** (or medium with
 *     sustained volume): the trust decision is demonstrably wrong. A vetted-benign
 *     address is attacking you while excused from scoring and shielded from
 *     blocking — the report's headline finding. Un-safelist and investigate.
 *   - **🟠 suspect** — post-safelist alerts at **medium**, or a notable volume of
 *     low/info: the safelist is silencing something at least noisy. Worth a look.
 *   - **🟢 benign** — little or no post-safelist activity (or only sparse info):
 *     the vetting still looks justified.
 *   - **· dormant** — no alerts at all this window: a stale entry and a safe
 *     prune candidate, mirroring hygiene.ts / watchlist.ts dormancy.
 *
 * A **conflict** flag marks any IP that is *both* safelisted and on the blocklist
 * — a contradictory curation (you simultaneously allow and block it) that should
 * be resolved one way or the other. Watchlist membership is shown for context.
 *
 * Honest caveats baked into the output:
 *
 *   - **Detections, not ground truth.** The safelist suppresses *scoring*, not
 *     *ingestion*, so detections still flow and this audit can see them — but a
 *     genuinely benign vendor can still trip a noisy rule. A verdict is a prompt
 *     to *look*, not an automatic un-safelist. Pair "dangerous" with the per-IP
 *     profile before acting.
 *   - **Exact IPs only.** The safelist holds individual addresses (no CIDR), so
 *     matching is exact — a safelisted host that rotates to a neighbour is not
 *     attributed here.
 *   - **The vetting time is not windowed.** Every current safelist entry is
 *     audited regardless of when it was added, but post-safelist *activity* older
 *     than the look-back can be missed; widen the window for a slow burner.
 *   - **Store-capped.** A long look-back can hit the alert store's history cap and
 *     clip older activity.
 *
 * Pure in-memory math over alertStore + the safe / block / watch / triage stores
 * — no SSH, no Claude, no network. Output is both a structured model and a
 * ready-to-paste Markdown document, mirroring watchlist.ts, recidivism.ts,
 * suppressions.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { triageStore } from "../store/triage.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** A signature one safelisted entry tripped, with its severity ceiling. */
export interface SafeSignature {
  signature: string;
  count: number;
  severityMax: Severity;
}

/** A counterpart endpoint a safelisted address exchanged alerts with. */
export interface SafeCounterpart {
  /** The "other side" of the alert (usually one of your internal hosts). */
  ip: string;
  /** Number of post-safelist alerts shared with this counterpart. */
  count: number;
  /** Whether the counterpart is an internal (RFC1918 / loopback / link-local) host. */
  internal: boolean;
  /** Highest severity seen across alerts with this counterpart. */
  severityMax: Severity;
  /** Most recent alert time with this counterpart, ms epoch. */
  lastSeen: number;
}

/** Risk verdict for a safelist entry, driven by its post-safelist activity. */
export type SafelistVerdict = "dangerous" | "suspect" | "benign" | "dormant";

export interface SafelistEntryAudit {
  /** The safelisted external IP. */
  ip: string;
  /** Operator note justifying the trust, if any. */
  note?: string;
  /** When the IP was vetted / added to the safelist (ms epoch; 0 if unknown). */
  addedAt: number;
  /** Total alerts touching this IP in the window (pre + post). */
  hitCount: number;
  /** Alerts that fired *before* the vetting timestamp (expected context). */
  preHitCount: number;
  /** Alerts that fired *at or after* the vetting timestamp — the audit signal. */
  postHitCount: number;
  /** Worst severity across all windowed alerts for this IP. */
  severityMax: Severity;
  /** Worst severity across *post-safelist* alerts (drives the verdict). */
  postSeverityMax: Severity;
  /** Per-severity counts of post-safelist alerts, info → critical (zeros omitted). */
  postBySeverity: Array<{ severity: Severity; count: number }>;
  /** Post-safelist alerts where the safe IP was the SOURCE (it reached toward us). */
  asSrc: number;
  /** Post-safelist alerts where the safe IP was the DESTINATION (we reached it). */
  asDst: number;
  /** Counterpart endpoints (post-safelist), most-contacted first (capped). */
  counterparts: SafeCounterpart[];
  /** Of {@link counterparts}, how many are internal hosts. */
  internalCounterpartCount: number;
  /** Distinct signatures tripped post-safelist, most-seen first (capped). */
  signatures: SafeSignature[];
  /** Distinct Suricata categories tripped post-safelist. */
  categories: string[];
  /** Post-safelist alerts the gateway actually blocked. */
  blockedCount: number;
  /** Post-safelist detected-only (seen but not stopped) alerts. */
  detectedCount: number;
  /** Post-safelist alerts still open in triage. */
  openCount: number;
  /** Earliest / latest alert times across the window (ms epoch); 0 when dormant. */
  firstSeen: number;
  lastSeen: number;
  /** Earliest post-safelist alert time (ms epoch); 0 when none. */
  firstPostSeen: number;
  /** Normalized post-safelist alerts-per-day rate over the window. */
  perDay: number;
  /** The IP is also on the blocklist — a contradictory allow+deny curation. */
  conflicted: boolean;
  /** The IP is also on the watchlist (shown for context). */
  watched: boolean;
  /** The risk verdict. */
  verdict: SafelistVerdict;
  /** Most-recent post-safelist alert ids (for drill-in), newest first. */
  sampleAlertIds: string[];
}

export interface SafelistAuditReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Total safelist entries audited. */
  entryCount: number;
  /** Entries with high/critical (or sustained medium) post-safelist activity. */
  dangerousCount: number;
  /** Entries with medium or noisy-but-low post-safelist activity. */
  suspectCount: number;
  /** Entries whose vetting still looks justified. */
  benignCount: number;
  /** Entries with no activity this window (prune candidates). */
  dormantCount: number;
  /** Entries that are also blocklisted (contradictory curation). */
  conflictedCount: number;
  /** Sum of all windowed hits across every safelist entry. */
  totalHits: number;
  /** Sum of post-safelist hits across every entry. */
  totalPostHits: number;
  /** Post-safelist alerts at medium severity or worse — the blind-spot volume. */
  postSevereAlerts: number;
  /** Distinct alerts that touched at least one safelist entry. */
  matchedAlerts: number;
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** Entries ranked dangerous-first. */
  entries: SafelistEntryAudit[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface SafelistAuditOptions {
  /** Max entries returned (dangerous first); clamped to [1, 2000]. */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 100;
const MS_PER_HOUR = 3_600_000;
const TOP_COUNTERPARTS = 10;
const TOP_SIGS = 6;
const SAMPLE_IDS = 8;

/** Sustained post-safelist medium-severity hits at/above which → dangerous. */
const DANGEROUS_MIN_MEDIUM_HITS = 3;
/** Post-safelist low/info hits at/above which a quiet entry becomes suspect. */
const SUSPECT_MIN_HITS = 5;

// ----- classifiers / helpers (mirror watchlist.ts conventions) ---------------

function isPrivate(ip: string): boolean {
  return (
    /^10\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^127\./.test(ip) ||
    /^169\.254\./.test(ip) ||
    /^(::1|fe80|fc|fd)/i.test(ip)
  );
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

function normalizeAction(a: string | undefined): string {
  const v = (a ?? "").toLowerCase().trim();
  if (v === "blocked" || v === "detected" || v === "allowed") return v;
  return "unknown";
}

/**
 * Verdict from an entry's *post-safelist* activity. Pre-safelist noise is the
 * context the entry exists to silence and never raises the verdict on its own.
 */
function classifyVerdict(
  hitCount: number,
  postHitCount: number,
  postSeverityMax: Severity,
  postMediumPlusHits: number,
): SafelistVerdict {
  if (hitCount === 0) return "dormant";
  if (postHitCount === 0) return "benign"; // only pre-safelist activity — vetting held
  if (sevRank(postSeverityMax) >= 3) return "dangerous"; // high / critical since vetting
  if (sevRank(postSeverityMax) === 2 && postMediumPlusHits >= DANGEROUS_MIN_MEDIUM_HITS) {
    return "dangerous"; // sustained medium — too much to excuse
  }
  if (sevRank(postSeverityMax) === 2 || postHitCount >= SUSPECT_MIN_HITS) return "suspect";
  return "benign";
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
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

const VERDICT_LABEL: Record<SafelistVerdict, string> = {
  dangerous: "🔴 Dangerous",
  suspect: "🟠 Suspect",
  benign: "🟢 Benign",
  dormant: "· Dormant",
};

// ----- aggregation -----------------------------------------------------------

interface Agg {
  ip: string;
  addedAt: number;
  note?: string;
  hitCount: number;
  preHitCount: number;
  postHitCount: number;
  severityMax: Severity;
  postSeverityMax: Severity;
  postBySev: Map<Severity, number>;
  postMediumPlus: number;
  asSrc: number;
  asDst: number;
  counterparts: Map<string, { count: number; internal: boolean; severityMax: Severity; lastSeen: number }>;
  sigCounts: Map<string, number>;
  sigMaxSev: Map<string, Severity>;
  categories: Set<string>;
  blockedCount: number;
  detectedCount: number;
  openCount: number;
  firstSeen: number;
  lastSeen: number;
  firstPostSeen: number;
  samples: Array<{ id: string; time: number }>;
}

function newAgg(ip: string, addedAt: number, note: string | undefined): Agg {
  return {
    ip,
    addedAt,
    note,
    hitCount: 0,
    preHitCount: 0,
    postHitCount: 0,
    severityMax: "info",
    postSeverityMax: "info",
    postBySev: new Map(),
    postMediumPlus: 0,
    asSrc: 0,
    asDst: 0,
    counterparts: new Map(),
    sigCounts: new Map(),
    sigMaxSev: new Map(),
    categories: new Set(),
    blockedCount: 0,
    detectedCount: 0,
    openCount: 0,
    firstSeen: 0,
    lastSeen: 0,
    firstPostSeen: 0,
    samples: [],
  };
}

/**
 * Fold one observation of an alert touching the safelisted IP into its aggregate.
 * `counterpart` is the other endpoint; `role` is "src" when the safe IP was the
 * alert source. Pre/post is decided against the entry's vetting timestamp.
 */
function applyHit(
  agg: Agg,
  a: StoredAlert,
  counterpart: string | undefined,
  role: "src" | "dst",
  sev: Severity,
  action: string,
): void {
  agg.hitCount++;
  agg.severityMax = maxSeverity(agg.severityMax, sev);
  if (agg.firstSeen === 0 || a.time < agg.firstSeen) agg.firstSeen = a.time;
  if (a.time > agg.lastSeen) agg.lastSeen = a.time;

  const post = a.time >= agg.addedAt;
  if (!post) {
    agg.preHitCount++;
    return; // pre-safelist context only — does not feed the verdict / detail
  }

  agg.postHitCount++;
  agg.postSeverityMax = maxSeverity(agg.postSeverityMax, sev);
  agg.postBySev.set(sev, (agg.postBySev.get(sev) ?? 0) + 1);
  if (isSevere(sev)) agg.postMediumPlus++;
  if (role === "src") agg.asSrc++;
  else agg.asDst++;
  if (agg.firstPostSeen === 0 || a.time < agg.firstPostSeen) agg.firstPostSeen = a.time;

  if (a.signature) {
    agg.sigCounts.set(a.signature, (agg.sigCounts.get(a.signature) ?? 0) + 1);
    agg.sigMaxSev.set(a.signature, maxSeverity(agg.sigMaxSev.get(a.signature) ?? "info", sev));
  }
  if (a.category) agg.categories.add(a.category);

  if (counterpart && counterpart !== agg.ip && isIP(counterpart) > 0) {
    const acc = agg.counterparts.get(counterpart) ?? {
      count: 0,
      internal: isPrivate(counterpart),
      severityMax: "info" as Severity,
      lastSeen: a.time,
    };
    acc.count++;
    acc.severityMax = maxSeverity(acc.severityMax, sev);
    if (a.time > acc.lastSeen) acc.lastSeen = a.time;
    agg.counterparts.set(counterpart, acc);
  }

  if (action === "blocked") agg.blockedCount++;
  else if (action === "detected") agg.detectedCount++;
  if ((triageStore.get(a.id)?.status ?? "open") === "open") agg.openCount++;

  agg.samples.push({ id: a.id, time: a.time });
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(model: Omit<SafelistAuditReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (!model.entryCount) return out;

  const dangerous = model.entries.filter((e) => e.verdict === "dangerous");
  if (dangerous.length) {
    const lead = dangerous[0]!;
    out.push(
      `🔴 **${dangerous.length} safelisted IP(s) are attacking you *after* you vetted them** — the trust grant ` +
        `is now wrong. Worst is \`${lead.ip}\` (${lead.postHitCount} post-safelist alert(s), peak ` +
        `**${lead.postSeverityMax}**${lead.note ? `, noted "${clip(lead.note, 36)}"` : ""}). These are excused ` +
        `from host-risk scoring and shielded from auto-blocking — **un-safelist and investigate.**`,
    );
  } else {
    out.push(
      `🟢 No safelisted IP produced a high/critical (or sustained medium) alert since it was vetted — every ` +
        `trust grant still looks justified this window.`,
    );
  }

  if (model.postSevereAlerts > 0) {
    out.push(
      `🙈 **${model.postSevereAlerts} medium-or-worse alert(s) were hidden from risk scoring** by the safelist ` +
        `this window (post-vetting). That is the blind spot the allowlist creates — this audit is the only view ` +
        `that surfaces it.`,
    );
  }

  if (model.suspectCount) {
    out.push(
      `🟠 ${model.suspectCount} safelisted IP(s) are *suspect* — medium-severity or notably noisy since vetting. ` +
        `Not yet alarming, but the safelist is silencing something worth a glance.`,
    );
  }

  if (model.conflictedCount) {
    const conflicts = model.entries.filter((e) => e.conflicted).slice(0, 5).map((e) => `\`${e.ip}\``);
    out.push(
      `⚠️ ${model.conflictedCount} IP(s) are **both safelisted and blocklisted** (${conflicts.join(", ")}) — a ` +
        `contradictory allow+deny curation. Decide which control wins and remove the other.`,
    );
  }

  if (model.dormantCount) {
    out.push(
      `· ${model.dormantCount} safelist entr(y/ies) saw no activity at all this window — stale prune candidates ` +
        `keeping the allowlist (and the trust surface) larger than it needs to be.`,
    );
  }

  const open = model.entries.reduce((n, e) => n + e.openCount, 0);
  if (open) out.push(`📋 ${open} post-safelist alert(s) across these IPs are still open in triage.`);
  return out;
}

// ----- markdown --------------------------------------------------------------

function activeTable(rows: SafelistEntryAudit[], now: number): string {
  return mdTable(
    ["#", "Safe IP", "Verdict", "Post", "Pre", "/day", "it→us / us→it", "Peak", "Hosts", "Blk/Det", "Open", "Last", "Note"],
    rows.map((e, i) => [
      String(i + 1),
      cell(e.ip) + (e.conflicted ? " ⛔" : "") + (e.watched ? " 👁" : ""),
      cell(VERDICT_LABEL[e.verdict]),
      String(e.postHitCount),
      String(e.preHitCount),
      round1(e.perDay).toFixed(1),
      `${e.asSrc} / ${e.asDst}`,
      cell(e.postSeverityMax),
      String(e.internalCounterpartCount),
      `${e.blockedCount}/${e.detectedCount}`,
      String(e.openCount),
      e.lastSeen ? fmtAgo(e.lastSeen, now) : "—",
      cell(e.note ? clip(e.note, 30) : ""),
    ]),
  );
}

function renderMarkdown(model: SafelistAuditReport): string {
  const lines: string[] = [];
  lines.push(`# 🔍 SecTool Safelist / Allowlist Risk Audit`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(model.windowEndMs)}`);
  lines.push(`**Window:** last ${model.hours} hour(s) — ${fmtTime(model.windowStartMs)} → ${fmtTime(model.windowEndMs)}`);
  lines.push(
    `**Safelisted IPs:** ${model.entryCount} · ` +
      `🔴 ${model.dangerousCount} dangerous · 🟠 ${model.suspectCount} suspect · ` +
      `🟢 ${model.benignCount} benign · · ${model.dormantCount} dormant`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!model.entryCount) {
    lines.push(
      `Your safelist is empty — nothing to audit. Mark an external IP safe from the Hosts page (or ` +
        `\`safeStore.add()\`) to populate this report.`,
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
    `**Method:** every safelist entry is matched against windowed alerts on its IP, then split on the entry's ` +
      `**vetting timestamp** — \`time < at\` is pre-safelist context, \`time >= at\` is the **post-safelist** ` +
      `signal that drives the verdict. The safelist suppresses *scoring*, not *ingestion*, so these detections ` +
      `still flow; this is the only report that reads them. Offline, deterministic · **Window alerts touching a ` +
      `safe IP:** ${model.matchedAlerts}`,
  );
  lines.push("");

  // Entries that moved (anything non-dormant), verdict-ranked.
  const moved = model.entries.filter((e) => e.verdict !== "dormant");
  if (moved.length) {
    lines.push(`## Active safelist entries (riskiest first)`);
    lines.push("");
    lines.push(activeTable(moved, model.windowEndMs));
    lines.push("");
    lines.push(
      `**Legend:** _Post_ / _Pre_ = alerts after / before vetting. _Peak_ is the worst **post-safelist** ` +
        `severity (the verdict driver). _it→us / us→it_ = the safe IP as source / destination. _Hosts_ = distinct ` +
        `internal counterparts touched. _Blk/Det_ = post-safelist blocked / detected-only. ⛔ = also blocklisted ` +
        `(conflict) · 👁 = also watchlisted.`,
    );
    lines.push("");

    // Per-entry detail for the riskiest, so the doc stands alone.
    const detailLimit = Math.min(moved.length, 10);
    lines.push(`## Detail — riskiest ${detailLimit}`);
    lines.push("");
    for (let i = 0; i < detailLimit; i++) {
      const e = moved[i]!;
      const flags: string[] = [];
      if (e.conflicted) flags.push("⛔ also blocklisted");
      if (e.watched) flags.push("👁 also watchlisted");
      lines.push(
        `### ${i + 1}. ${e.ip} — ${VERDICT_LABEL[e.verdict]}` + (flags.length ? ` (${flags.join(", ")})` : ""),
      );
      lines.push("");
      if (e.note) lines.push(`> Vetted as: ${cell(e.note)}`);
      lines.push(
        `- **Vetted:** ${e.addedAt ? `${fmtTime(e.addedAt)} (${fmtAgo(e.addedAt, model.windowEndMs)})` : "unknown"}`,
      );
      lines.push(
        `- **Post-safelist:** ${e.postHitCount} alert(s) (${round1(e.perDay).toFixed(1)}/day) · peak ` +
          `**${e.postSeverityMax}** · ${e.asSrc} inbound (it→us) / ${e.asDst} outbound (us→it) · ` +
          `${e.preHitCount} pre-safelist for context`,
      );
      if (e.firstPostSeen) {
        lines.push(
          `- **First/last (post):** ${fmtTime(e.firstPostSeen)} → ${fmtTime(e.lastSeen)} ` +
            `(${fmtAgo(e.lastSeen, model.windowEndMs)})`,
        );
      }
      if (e.postBySeverity.length) {
        lines.push(`- **Severity (post):** ${e.postBySeverity.map((s) => `${s.severity} ×${s.count}`).join(" · ")}`);
      }
      if (e.counterparts.length) {
        const cp = e.counterparts
          .slice(0, TOP_COUNTERPARTS)
          .map((c) => `${c.ip}${c.internal ? "" : " (ext)"} ×${c.count}`)
          .join(", ");
        lines.push(`- **Touched hosts:** ${cp}`);
      }
      if (e.signatures.length) {
        lines.push(`- **Signatures (post):** ${e.signatures.map((s) => `${clip(s.signature, 48)} ×${s.count}`).join("; ")}`);
      }
      if (e.categories.length) lines.push(`- **Categories (post):** ${e.categories.join(", ")}`);
      lines.push(
        `- **Disposition (post):** ${e.blockedCount} blocked / ${e.detectedCount} detected-only · ` +
          `${e.openCount} open in triage`,
      );
      lines.push("");
    }
  } else {
    lines.push(`_Every safelisted IP was dormant this window — no alert touched any of them._`);
    lines.push("");
  }

  // Dormant prune-candidate roll-up — silence is itself a finding.
  const dormant = model.entries.filter((e) => e.verdict === "dormant");
  if (dormant.length) {
    lines.push(`## Dormant entries (no activity this window — prune candidates)`);
    lines.push("");
    lines.push(
      mdTable(
        ["Safe IP", "Vetted", "Blocklisted", "Watchlisted", "Note"],
        dormant.map((e) => [
          cell(e.ip),
          e.addedAt ? fmtAgo(e.addedAt, model.windowEndMs) : "unknown",
          e.conflicted ? "⛔ yes" : "—",
          e.watched ? "👁 yes" : "—",
          cell(e.note ? clip(e.note, 40) : ""),
        ]),
      ),
    );
    lines.push("");
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from ${model.matchedAlerts} alert(s) touching ${model.entryCount} safelisted ` +
      `IP(s). The safelist suppresses **scoring and auto-blocking**, not detection — so a "dangerous" verdict means ` +
      `a vetted-benign IP is still tripping IPS rules while excused from the rankings; treat it as a prompt to look, ` +
      `not an automatic un-safelist (a real vendor can still trip a noisy rule). Matching is **exact-IP** (the ` +
      `safelist holds no CIDR), the vetting time is not windowed but post-vetting activity older than the look-back ` +
      `can be missed, and a long look-back can hit the store's history cap. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the safelist / allowlist risk audit from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link SafelistAuditOptions}: `limit` and a `nowMs` test pin.
 */
export function buildSafelistAudit(hours: number, opts: SafelistAuditOptions = {}): SafelistAuditReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(2000, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;
  const windowDays = safeHours / 24;

  // Seed an aggregate for every safelist entry so dormant ones still appear.
  const entries = safeStore.all();
  const byIp = new Map<string, Agg>();
  for (const e of entries) {
    const addedAt = Number.isFinite(e.at) ? e.at : 0;
    byIp.set(e.ip, newAgg(e.ip, addedAt, e.note));
  }

  const matchedAlertIds = new Set<string>();

  if (byIp.size) {
    const inWindow = alertStore
      .all()
      .filter((a) => typeof a.time === "number" && a.time >= windowStartMs && a.time <= windowEndMs);

    for (const a of inWindow) {
      const sev = (a.severity as Severity) ?? "info";
      const action = normalizeAction(a.action);

      // The safe IP can be on either side. Count at most ONE observation per
      // entry per alert (src takes precedence for direction/counterpart).
      let matchedTarget: string | undefined;
      if (a.srcIp && byIp.has(a.srcIp)) {
        applyHit(byIp.get(a.srcIp)!, a, a.dstIp, "src", sev, action);
        matchedTarget = a.srcIp;
      }
      if (a.dstIp && byIp.has(a.dstIp) && a.dstIp !== matchedTarget) {
        applyHit(byIp.get(a.dstIp)!, a, a.srcIp, "dst", sev, action);
        matchedTarget = matchedTarget ?? a.dstIp;
      }
      if (matchedTarget !== undefined) matchedAlertIds.add(a.id);
    }
  }

  const built: SafelistEntryAudit[] = [...byIp.values()].map((agg) => {
    const postBySeverity = SEVERITY_ORDER.map((severity) => ({ severity, count: agg.postBySev.get(severity) ?? 0 }))
      .filter((x) => x.count > 0);
    const counterparts: SafeCounterpart[] = [...agg.counterparts.entries()]
      .map(([ip, acc]) => ({ ip, count: acc.count, internal: acc.internal, severityMax: acc.severityMax, lastSeen: acc.lastSeen }))
      .sort((x, y) => y.count - x.count || y.lastSeen - x.lastSeen)
      .slice(0, TOP_COUNTERPARTS);
    const internalCounterpartCount = [...agg.counterparts.values()].filter((c) => c.internal).length;
    const signatures: SafeSignature[] = [...agg.sigCounts.entries()]
      .map(([signature, count]) => ({ signature, count, severityMax: agg.sigMaxSev.get(signature) ?? "info" }))
      .sort((x, y) => y.count - x.count || x.signature.localeCompare(y.signature))
      .slice(0, TOP_SIGS);
    const perDay = agg.postHitCount / Math.max(windowDays, 1 / 24);
    const verdict = classifyVerdict(agg.hitCount, agg.postHitCount, agg.postSeverityMax, agg.postMediumPlus);
    const sampleAlertIds = agg.samples
      .sort((x, y) => y.time - x.time)
      .slice(0, SAMPLE_IDS)
      .map((s) => s.id);

    return {
      ip: agg.ip,
      note: agg.note,
      addedAt: agg.addedAt,
      hitCount: agg.hitCount,
      preHitCount: agg.preHitCount,
      postHitCount: agg.postHitCount,
      severityMax: agg.severityMax,
      postSeverityMax: agg.postSeverityMax,
      postBySeverity,
      asSrc: agg.asSrc,
      asDst: agg.asDst,
      counterparts,
      internalCounterpartCount,
      signatures,
      categories: [...agg.categories].sort(),
      blockedCount: agg.blockedCount,
      detectedCount: agg.detectedCount,
      openCount: agg.openCount,
      firstSeen: agg.firstSeen,
      lastSeen: agg.lastSeen,
      firstPostSeen: agg.firstPostSeen,
      perDay,
      conflicted: blockStore.has(agg.ip),
      watched: watchStore.has(agg.ip),
      verdict,
      sampleAlertIds,
    };
  });

  // Dangerous → suspect → benign → dormant; within a tier by post volume,
  // post severity, recency, then vetting time.
  const rank: Record<SafelistVerdict, number> = { dangerous: 3, suspect: 2, benign: 1, dormant: 0 };
  built.sort(
    (a, b) =>
      rank[b.verdict] - rank[a.verdict] ||
      b.postHitCount - a.postHitCount ||
      sevRank(b.postSeverityMax) - sevRank(a.postSeverityMax) ||
      b.lastSeen - a.lastSeen ||
      b.addedAt - a.addedAt ||
      (a.ip < b.ip ? -1 : a.ip > b.ip ? 1 : 0),
  );

  const ranked = built.slice(0, limit);

  const base: Omit<SafelistAuditReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    entryCount: built.length,
    dangerousCount: built.filter((e) => e.verdict === "dangerous").length,
    suspectCount: built.filter((e) => e.verdict === "suspect").length,
    benignCount: built.filter((e) => e.verdict === "benign").length,
    dormantCount: built.filter((e) => e.verdict === "dormant").length,
    conflictedCount: built.filter((e) => e.conflicted).length,
    totalHits: built.reduce((n, e) => n + e.hitCount, 0),
    totalPostHits: built.reduce((n, e) => n + e.postHitCount, 0),
    postSevereAlerts: built.reduce((n, e) => n + e.postBySeverity.filter((s) => isSevere(s.severity)).reduce((m, s) => m + s.count, 0), 0),
    matchedAlerts: matchedAlertIds.size,
    entries: ranked,
  };
  const highlights = writeHighlights(base);
  const model: SafelistAuditReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded safelist risk audit. */
export function safelistAuditFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-safelist-audit-${stamp}.md`;
}
