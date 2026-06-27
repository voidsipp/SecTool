/**
 * Suppression-rule audit / silence-effectiveness & risk report — "are my
 * existing suppression rules still earning their keep, and is any one of them
 * dangerously silencing *real* threats?"
 *
 * SecTool lets an operator silence noisy detections with pattern-based
 * **suppression rules** (see store/suppressions.ts): a rule matching on any
 * combination of signature / category / src / dst / max-severity short-circuits
 * summarization + Discord notification for every future alert it matches. Over
 * time a rule set rots in three quiet, dangerous ways:
 *
 *   1. **Dead weight** — a rule was added for a signature that has since been
 *      retired or a scanner that moved on. It now matches nothing, but it still
 *      sits in the evaluation path and clutters the config.
 *   2. **Shadowing** — two rules overlap, so one silently covers everything the
 *      other does. The shadowed rule is redundant and its existence is a lie
 *      about why alerts are being silenced.
 *   3. **Over-broad silence** — the worst failure mode. A rule written to mute
 *      `info`-level scan chatter is broad enough (e.g. `cat=IDS/IPS` with no
 *      severity ceiling, or a loose signature substring) that it is now
 *      swallowing **medium / high / critical** detections too. The operator
 *      thinks they are quiet because nothing is wrong; in fact they are quiet
 *      because the page was muted. A suppression that hides a real threat is far
 *      more expensive than the noise it was meant to remove.
 *
 * No existing offline report looks at the rule set itself. `tuning.ts` does the
 * *opposite* job — it scans the alert stream for noisy signatures and *proposes
 * new* suppressions; `report.ts` merely prints a count of active rules. Neither
 * ever asks the maintenance question this report answers: **of the rules I
 * already have, which are working, which are dead, which are redundant, and
 * which are quietly hiding something I needed to see?**
 *
 * Method (pure in-memory math over alertStore + suppressionStore — no SSH, no
 * Claude, no network):
 *
 *   - Replay every stored alert in the window against each rule's match
 *     predicate (the same fields the live engine uses) to get each rule's
 *     **standalone match count** and the **worst severity** it silences.
 *   - Attribute each alert to the **first-created** rule that matches it,
 *     mirroring the live engine's first-match-wins evaluation, to get each
 *     rule's **effective** (non-double-counted) suppression credit. A rule with
 *     standalone matches but zero effective credit is **shadowed**.
 *   - Fold in the rule's **live hit counters** (`hitCount` / `lastHitAt`,
 *     maintained by the running service) so a rule that silenced plenty of
 *     traffic *before* the store's retention window is not mislabelled dead.
 *   - Assign each rule a one-word **verdict** — `risky` · `shadowed` · `broad` ·
 *     `dead` · `quiet` · `untested` · `effective` — and a recommended action.
 *
 * Honest caveats baked into the output:
 *
 *   - **Store-bounded.** Standalone/effective counts only see alerts still in the
 *     rolling store; a rule can look "dead" in a short window yet have a high live
 *     `hitCount`. The verdict uses both signals to avoid that trap.
 *   - **Detections, not ground truth.** "Risky" flags that a rule *can* silence a
 *     medium+ detection, not that the detection was a true positive — but a
 *     suppression broad enough to swallow high/critical signal deserves a human
 *     look regardless.
 *   - **First-match attribution is an approximation** of the live Map-iteration
 *     order; it is exact when rules were added oldest-first and never reordered,
 *     which is the normal case.
 *
 * Output is both a structured model and a ready-to-paste Markdown document,
 * mirroring concentration.ts, dwell.ts and the other offline reports.
 */
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import {
  suppressionStore,
  describeMatch,
  type SuppressionRule,
  type SuppressionMatch,
} from "../store/suppressions.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** A one-word verdict on a suppression rule's health. */
export type RuleVerdict =
  | "risky" // silences medium+ severity detections — review before it hides a real incident
  | "shadowed" // fully redundant: an earlier rule already covers every alert it matches
  | "broad" // structurally broad scope (no signature/src/dst anchor) with material reach
  | "dead" // matches nothing in-window and never recorded a live hit — prune candidate
  | "quiet" // nothing in-window but has historical live hits — keep, just dormant now
  | "untested" // too new to judge (within the grace period) and no data yet
  | "effective"; // working as intended: silences a healthy volume of low-severity noise

/** Per-rule audit result. */
export interface RuleAudit {
  id: string;
  /** Compact human description of the rule's match criteria (e.g. `sig~"nmap" & sev<=low`). */
  match: string;
  reason?: string;
  createdAt: number;
  /** Age of the rule in hours at report time. */
  ageHours: number;
  expiresAt?: number;
  /** Hours until expiry, if the rule has a TTL (negative = already expired). */
  expiresInHours?: number;
  /** Alerts in the window this rule matches *in isolation* (may overlap other rules). */
  standaloneMatches: number;
  /** Alerts for which this rule is the *first-created* matching rule (real credit). */
  effectiveMatches: number;
  /** Of the standalone matches, how many were medium-or-worse (the risk surface). */
  mediumPlusMatches: number;
  /** Worst severity this rule silences in-window (undefined when it matched nothing). */
  worstSilenced?: Severity;
  /** Lifetime hit counter maintained by the live service. */
  liveHitCount: number;
  lastHitAt?: number;
  /** True when the match has no signature/src/dst anchor (only category and/or maxSeverity). */
  broadScope: boolean;
  verdict: RuleVerdict;
  /** A short, imperative recommended action. */
  action: string;
}

export interface SuppressionAuditReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Suppression rules currently configured (after the store's own expiry prune). */
  totalRules: number;
  /** Rules with a TTL expiring within {@link EXPIRING_SOON_HOURS}. */
  expiringSoon: number;
  /** Distinct window alerts silenced by *at least one* rule (no double-count). */
  suppressedAlerts: number;
  /** suppressedAlerts / totalWindowAlerts, 0..1 (4dp). */
  suppressionRatio: number;
  /** Distinct medium-or-worse window alerts silenced by at least one rule. */
  suppressedMediumPlus: number;
  /** Count of rules per verdict. */
  verdictCounts: Record<RuleVerdict, number>;
  /** Every rule, audited, ordered worst-news-first (risky → … → effective). */
  rules: RuleAudit[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface SuppressionAuditOptions {
  /** Max rule rows to render in the detail table (clamped to [1, 500]). */
  limit?: number;
  /** A rule younger than this with no data is "untested", not "dead" (hours, clamped). */
  graceHours?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 100;
const DEFAULT_GRACE_HOURS = 24;
const MS_PER_HOUR = 3_600_000;
/** A TTL rule with less than this left is flagged as "expiring soon". */
const EXPIRING_SOON_HOURS = 24;
/** Match share at/above which a structurally-broad rule is called "broad". */
const BROAD_SHARE = 0.25;
/** Severity index at/above which a silenced alert counts as a risk (medium). */
const RISK_SEV_IDX = SEVERITY_ORDER.indexOf("medium");

// ----- helpers (mirror concentration.ts / dwell.ts) --------------------------

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

function maxSeverity(a: Severity | undefined, b: string | undefined): Severity | undefined {
  if (!b) return a;
  if (!a) return sevRank(b) >= 0 ? (b as Severity) : a;
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

/** Compact relative-age label, e.g. "3h", "2d", "5d 4h". */
function fmtAge(hours: number): string {
  const h = Math.max(0, Math.round(hours));
  if (h < 48) return `${h}h`;
  const d = Math.floor(h / 24);
  const rem = h % 24;
  return rem ? `${d}d ${rem}h` : `${d}d`;
}

function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function clip(s: string, max = 40): string {
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

/** Emoji + word for a verdict, for the at-a-glance column. */
function verdictLabel(v: RuleVerdict): string {
  switch (v) {
    case "risky":
      return "🚨 risky";
    case "shadowed":
      return "🔁 shadowed";
    case "broad":
      return "🌐 broad";
    case "dead":
      return "💀 dead";
    case "quiet":
      return "🌙 quiet";
    case "untested":
      return "🌱 untested";
    case "effective":
      return "✅ effective";
  }
}

/** Worst-news-first ordering so the rules that need attention sort to the top. */
const VERDICT_RANK: Record<RuleVerdict, number> = {
  risky: 0,
  shadowed: 1,
  broad: 2,
  dead: 3,
  quiet: 4,
  untested: 5,
  effective: 6,
};

// ----- matching (replicates store/suppressions.ts ruleMatches over StoredAlert) ---

/**
 * Whether a stored alert satisfies a rule's match predicate. Field-for-field
 * identical to the live engine's `ruleMatches`, but operating on the persisted
 * {@link StoredAlert} shape (which carries exactly the fields a rule keys on).
 * Expiry is handled by the caller (expired rules are pruned by the store before
 * we ever see them), so this is purely the criteria test.
 */
function storedMatches(m: SuppressionMatch, a: StoredAlert): boolean {
  if (m.signature) {
    const sig = (a.signature ?? "").toLowerCase();
    if (!sig.includes(m.signature.toLowerCase())) return false;
  }
  if (m.category) {
    if ((a.category ?? "").toLowerCase() !== m.category.toLowerCase()) return false;
  }
  if (m.srcIp && a.srcIp !== m.srcIp) return false;
  if (m.dstIp && a.dstIp !== m.dstIp) return false;
  if (m.maxSeverity) {
    if (sevRank(a.severity) > sevRank(m.maxSeverity)) return false;
  }
  return true;
}

/** A match with no signature / src / dst anchor is structurally broad. */
function isBroadScope(m: SuppressionMatch): boolean {
  return !m.signature && !m.srcIp && !m.dstIp;
}

// ----- verdict + action ------------------------------------------------------

function decideVerdict(
  a: Omit<RuleAudit, "verdict" | "action">,
  windowAlerts: number,
  graceHours: number,
): RuleVerdict {
  // Hiding real signal is the headline failure — it wins regardless of anything else.
  if (a.mediumPlusMatches > 0) return "risky";
  // No in-window matches: distinguish dormant-but-proven from genuinely dead from too-new.
  if (a.standaloneMatches === 0) {
    if (a.liveHitCount > 0) return "quiet";
    if (a.ageHours < graceHours) return "untested";
    return "dead";
  }
  // Matches exist but another rule already absorbs every one of them.
  if (a.effectiveMatches === 0) return "shadowed";
  // Structurally broad and pulling material volume — worth a scope review.
  const share = windowAlerts > 0 ? a.standaloneMatches / windowAlerts : 0;
  if (a.broadScope && share >= BROAD_SHARE) return "broad";
  return "effective";
}

function recommendedAction(a: Omit<RuleAudit, "action">): string {
  switch (a.verdict) {
    case "risky":
      return `Review: silences ${a.mediumPlusMatches} medium+ detection(s) (worst ${a.worstSilenced ?? "?"}). Narrow the match or add a sev<=low ceiling.`;
    case "shadowed":
      return `Redundant — an earlier rule already covers all ${a.standaloneMatches} match(es). Safe to delete.`;
    case "broad":
      return `Broad scope (no signature/IP anchor) absorbing a large share of volume. Confirm intent; consider a tighter anchor.`;
    case "dead":
      return `No matches in-window and no recorded live hits${a.ageHours >= 24 ? ` in ${fmtAge(a.ageHours)}` : ""}. Prune candidate.`;
    case "quiet":
      return `Dormant this window but ${a.liveHitCount} lifetime hit(s) — keep; it earned its place.`;
    case "untested":
      return `Too new (${fmtAge(a.ageHours)}) and no data yet — revisit after it sees traffic.`;
    case "effective":
      return `Working as intended: silences ${a.effectiveMatches} low-severity alert(s) cleanly.`;
  }
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(m: Omit<SuppressionAuditReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (m.totalRules === 0) {
    out.push(
      `🔕 **No suppression rules configured.** Nothing is being silenced — every detection pages. ` +
        `If Discord is noisy, run the tuning report (\`--tuning\`) to find safe candidates to suppress.`,
    );
    return out;
  }

  // Headline: overall noise-reduction the rule set delivers.
  if (m.totalWindowAlerts > 0) {
    out.push(
      `🔕 Over the last ${m.hours}h your **${m.totalRules}** suppression rule(s) silence ` +
        `**${pct(m.suppressionRatio, 1)}** of alerts (${m.suppressedAlerts} of ${m.totalWindowAlerts}) ` +
        `before they could page you.`,
    );
  } else {
    out.push(
      `🔕 **${m.totalRules}** suppression rule(s) configured, but no alerts landed in the last ${m.hours}h ` +
        `to evaluate them against — verdicts lean on lifetime hit counters.`,
    );
  }

  // The single most important signal: are any rules hiding real severity?
  const risky = m.rules.filter((r) => r.verdict === "risky");
  if (risky.length) {
    const worst = risky[0]!;
    out.push(
      `🚨 **${risky.length} rule(s) silence medium-or-worse detections** — the dangerous failure mode. ` +
        `\`${worst.match}\` alone mutes **${worst.mediumPlusMatches}** (worst **${worst.worstSilenced}**). ` +
        `A suppression that hides a real incident costs far more than the noise it removed — review these first.`,
    );
  } else if (m.suppressedMediumPlus === 0 && m.suppressedAlerts > 0) {
    out.push(
      `✅ No rule silences anything above **low** severity — the rule set is muting noise without hiding signal.`,
    );
  }

  const dead = m.verdictCounts.dead;
  const shadowed = m.verdictCounts.shadowed;
  if (dead + shadowed > 0) {
    const bits: string[] = [];
    if (dead) bits.push(`**${dead} dead** (match nothing, no live hits)`);
    if (shadowed) bits.push(`**${shadowed} shadowed** (fully redundant)`);
    out.push(
      `🧹 **${dead + shadowed} rule(s) are dead weight** — ${bits.join(" and ")}. Pruning them shrinks the ` +
        `evaluation path and stops the config lying about why alerts are quiet.`,
    );
  }

  const broad = m.rules.filter((r) => r.verdict === "broad");
  if (broad.length) {
    const b = broad[0]!;
    out.push(
      `🌐 **${broad.length} broad rule(s)** match on category/severity alone with no signature or IP anchor — ` +
        `\`${b.match}\` covers ${pct(m.totalWindowAlerts ? b.standaloneMatches / m.totalWindowAlerts : 0, 1)} ` +
        `of all alerts. Broad silences drift into over-suppression as the threat mix changes; pin them tighter.`,
    );
  }

  if (m.expiringSoon > 0) {
    out.push(
      `⏳ **${m.expiringSoon} rule(s) expire within ${EXPIRING_SOON_HOURS}h** — the noise they mute will start ` +
        `paging again when they lapse. Renew the ones still earning their keep.`,
    );
  }

  return out;
}

// ----- markdown --------------------------------------------------------------

function ruleTable(rules: RuleAudit[]): string {
  return mdTable(
    ["Verdict", "Rule", "In-win", "Effective", "Med+", "Worst", "Live hits", "Age", "Action"],
    rules.map((r) => [
      cell(verdictLabel(r.verdict)),
      cell(clip(r.match)),
      String(r.standaloneMatches),
      String(r.effectiveMatches),
      r.mediumPlusMatches > 0 ? `**${r.mediumPlusMatches}**` : "0",
      cell(r.worstSilenced ?? "—"),
      String(r.liveHitCount),
      cell(fmtAge(r.ageHours) + (r.expiresInHours !== undefined ? ` ⏳${fmtAge(r.expiresInHours)}` : "")),
      cell(clip(r.action, 64)),
    ]),
  );
}

function renderMarkdown(m: SuppressionAuditReport): string {
  const lines: string[] = [];
  lines.push(`# 🔕 SecTool Suppression-Rule Audit Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`,
  );
  lines.push(
    `**Method:** every stored alert replayed against each suppression rule's match predicate; rules scored ` +
      `for *standalone* and *first-match-effective* reach, severity silenced, live hit counters, and ` +
      `redundancy. Offline, deterministic · **Window alerts:** ${m.totalWindowAlerts} · **Rules:** ${m.totalRules}`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");

  if (m.totalRules === 0) {
    for (const h of m.highlights) lines.push(`- ${h}`);
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  // Scoreboard.
  lines.push(
    mdTable(
      ["Rules", "Silenced", "Noise cut", "Med+ silenced", "Risky", "Dead/Shadowed", "Broad", "Expiring"],
      [
        [
          String(m.totalRules),
          `${m.suppressedAlerts}/${m.totalWindowAlerts}`,
          m.totalWindowAlerts > 0 ? pct(m.suppressionRatio, 1) : "—",
          m.suppressedMediumPlus > 0 ? `**${m.suppressedMediumPlus}**` : "0",
          m.verdictCounts.risky > 0 ? `**${m.verdictCounts.risky}**` : "0",
          String(m.verdictCounts.dead + m.verdictCounts.shadowed),
          String(m.verdictCounts.broad),
          String(m.expiringSoon),
        ],
      ],
    ),
  );
  lines.push("");
  lines.push(
    `**Verdict legend:** 🚨 **risky** (silences medium+ signal — review) · 🔁 **shadowed** (redundant) · ` +
      `🌐 **broad** (no signature/IP anchor) · 💀 **dead** (no matches, no live hits — prune) · ` +
      `🌙 **quiet** (dormant but proven) · 🌱 **untested** (too new) · ✅ **effective** (muting noise cleanly).`,
  );
  lines.push("");

  // Detail table.
  lines.push(`## Rules`);
  lines.push("");
  lines.push(ruleTable(m.rules));
  lines.push("");
  lines.push(
    `_Columns: **In-win** = alerts this rule matches alone in the window · **Effective** = alerts it is the ` +
      `first-created rule to match (real, non-double-counted credit) · **Med+** = of its matches, how many ` +
      `were medium-or-worse (the risk surface) · **Live hits** = lifetime counter from the running service · ` +
      `**Age** shows rule age and, when set, ⏳ time-to-expiry._`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Standalone/effective counts only see alerts still in the rolling store, so ` +
      `a rule can read "dead" in a short window yet carry a high live hit count — the verdict weighs both. ` +
      `"Risky" means a rule *can* silence a medium+ **detection**, not that the detection was a true positive; ` +
      `but a silence broad enough to swallow high/critical signal deserves a human look. First-match attribution ` +
      `approximates the live engine's evaluation order (exact when rules were added oldest-first). No live ` +
      `gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the suppression-rule audit report from the stored alert history and the
 * configured suppression rules.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link SuppressionAuditOptions}: `limit`, `graceHours`, and a
 *              `nowMs` pin for deterministic tests.
 */
export function buildSuppressionAudit(
  hours: number,
  opts: SuppressionAuditOptions = {},
): SuppressionAuditReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(500, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const graceHours = Math.max(0, Math.min(24 * 30, Math.floor(opts.graceHours ?? DEFAULT_GRACE_HOURS)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);
  const totalWindowAlerts = windowed.length;

  // Rules in oldest-first order so first-match attribution mirrors the live engine,
  // which iterates rules in insertion (≈ creation) order.
  const rawRules = suppressionStore
    .all()
    .slice()
    .sort((a, b) => a.createdAt - b.createdAt);

  // Per-rule accumulators, keyed by rule id.
  interface Acc {
    rule: SuppressionRule;
    standalone: number;
    effective: number;
    mediumPlus: number;
    worst?: Severity;
  }
  const accs: Acc[] = rawRules.map((rule) => ({
    rule,
    standalone: 0,
    effective: 0,
    mediumPlus: 0,
  }));

  // Distinct silenced-alert tallies (union across all rules, no double-count).
  let suppressedAlerts = 0;
  let suppressedMediumPlus = 0;

  for (const alert of windowed) {
    let firstMatch = -1;
    let silenced = false;
    for (let i = 0; i < accs.length; i++) {
      if (!storedMatches(accs[i]!.rule.match, alert)) continue;
      const acc = accs[i]!;
      acc.standalone++;
      acc.worst = maxSeverity(acc.worst, alert.severity);
      if (sevRank(alert.severity) >= RISK_SEV_IDX) acc.mediumPlus++;
      silenced = true;
      if (firstMatch === -1) firstMatch = i;
    }
    if (silenced) {
      suppressedAlerts++;
      if (sevRank(alert.severity) >= RISK_SEV_IDX) suppressedMediumPlus++;
      accs[firstMatch]!.effective++;
    }
  }

  const verdictCounts: Record<RuleVerdict, number> = {
    risky: 0,
    shadowed: 0,
    broad: 0,
    dead: 0,
    quiet: 0,
    untested: 0,
    effective: 0,
  };
  let expiringSoon = 0;

  const audits: RuleAudit[] = accs.map((acc) => {
    const { rule } = acc;
    const ageHours = Math.max(0, (windowEndMs - rule.createdAt) / MS_PER_HOUR);
    const expiresInHours =
      rule.expiresAt !== undefined ? (rule.expiresAt - windowEndMs) / MS_PER_HOUR : undefined;
    if (expiresInHours !== undefined && expiresInHours >= 0 && expiresInHours <= EXPIRING_SOON_HOURS) {
      expiringSoon++;
    }

    const partial: Omit<RuleAudit, "verdict" | "action"> = {
      id: rule.id,
      match: describeMatch(rule.match),
      reason: rule.reason,
      createdAt: rule.createdAt,
      ageHours: round4(ageHours),
      expiresAt: rule.expiresAt,
      expiresInHours: expiresInHours !== undefined ? round4(expiresInHours) : undefined,
      standaloneMatches: acc.standalone,
      effectiveMatches: acc.effective,
      mediumPlusMatches: acc.mediumPlus,
      worstSilenced: acc.worst,
      liveHitCount: rule.hitCount,
      lastHitAt: rule.lastHitAt,
      broadScope: isBroadScope(rule.match),
    };
    const verdict = decideVerdict(partial, totalWindowAlerts, graceHours);
    const withVerdict = { ...partial, verdict };
    const action = recommendedAction(withVerdict);
    verdictCounts[verdict]++;
    return { ...withVerdict, action };
  });

  // Worst-news-first, then by reach so the loudest rules lead within a verdict.
  audits.sort(
    (a, b) =>
      VERDICT_RANK[a.verdict] - VERDICT_RANK[b.verdict] ||
      b.mediumPlusMatches - a.mediumPlusMatches ||
      b.standaloneMatches - a.standaloneMatches ||
      a.createdAt - b.createdAt,
  );
  const rules = audits.slice(0, limit);

  const base: Omit<SuppressionAuditReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts,
    totalRules: rawRules.length,
    expiringSoon,
    suppressedAlerts,
    suppressionRatio: totalWindowAlerts > 0 ? round4(suppressedAlerts / totalWindowAlerts) : 0,
    suppressedMediumPlus,
    verdictCounts,
    rules,
  };
  const highlights = writeHighlights(base);

  const model: SuppressionAuditReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded suppression-audit report. */
export function suppressionAuditFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-suppaudit-${stamp}.md`;
}
