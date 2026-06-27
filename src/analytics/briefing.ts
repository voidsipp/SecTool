/**
 * Morning security briefing (SITREP) — "one document an operator can read with
 * their coffee that answers *what changed, how bad is it, and what do I do
 * first* — then carries the supporting detail underneath."
 *
 * SecTool has grown a deep catalogue of sharp, single-purpose offline reports —
 * risk, efficacy, blockplan, escalation, novelty, backlog and a few dozen more.
 * Each answers one question extremely well, but none of them *composes*: an
 * operator coming back in the morning has to know which report to run, run
 * several of them, and stitch the headlines together in their head. There is no
 * single artifact that says, in order, **"here is the state of play, here is the
 * trend since yesterday, and here is your prioritised to-do list"** — the daily
 * SITREP every SOC actually opens first.
 *
 * This report is that capstone. It is deliberately *not* another analytic lens
 * on the alert stream; it is a **consolidator**, and it works in three layers:
 *
 *   1. **Executive KPIs (self-computed).** A compact scorecard of the numbers an
 *      operator glances at first — total alerts, severe (medium+) alerts, the
 *      gateway's block rate, unblocked high/critical exposure, distinct active
 *      sources, an unmitigated **risk weight**, and how many sources are brand
 *      new. Every KPI is computed *here*, directly over alertStore (reusing the
 *      shared {@link SEVERITY_WEIGHT} / {@link DISPOSITION_FACTOR} /
 *      {@link classifyDisposition} so the math agrees with risk.ts and
 *      efficacy.ts), and each is paired with the **same KPI over the immediately
 *      preceding window of equal length** to yield a trend arrow and a percent
 *      change. The trend — not the absolute — is the point: "is today worse than
 *      yesterday?"
 *
 *   2. **Prioritised action items (self-synthesised).** A deduplicated,
 *      severity-ranked to-do list derived from the same local roll-up, so the
 *      briefing is opinionated, not just descriptive:
 *        - **URGENT** — a *safelisted* (vetted-benign) IP that is firing severe
 *          alerts: a trusted address behaving badly is the worst surprise.
 *        - **HIGH** — external sources landing **unblocked high/critical** alerts:
 *          active threats reaching your hosts that the gateway is letting through.
 *        - **MEDIUM** — loud, persistent, *un-blocked, un-safelisted* repeat
 *          offenders worth a containment decision.
 *      Every item names the IP and the evidence (counts), and watch/block/safe
 *      membership is surfaced so an already-handled IP isn't re-flagged.
 *
 *   3. **Bundled detail (composed).** The full Markdown of a curated set of the
 *      "morning essential" reports (risk → efficacy → blockplan → escalation →
 *      novelty → backlog by default, selectable via `sections`) appended under a
 *      table of contents, each guarded so one failing builder degrades to a noted
 *      stub instead of breaking the whole briefing. This is the convenience
 *      layer — the supporting evidence behind the headline, in one place.
 *
 * How it differs from the things it sits near — there is no overlap:
 *
 *   - digest.ts / insight.ts both lean on **Claude** and (for digest) a Discord
 *     webhook to produce an AI narrative. This briefing is **pure, deterministic,
 *     offline** — no model, no network — so it runs anywhere, identically, and is
 *     safe in a cron or an air-gapped review.
 *   - risk.ts already grades posture and efficacy.ts already measures the
 *     enforcement gap; this report *cites* them (bundles their output) and adds
 *     the cross-report **trend + action list** none of them produces alone.
 *   - compare.ts diffs raw counts period-over-period; the briefing's KPI trend is
 *     a focused, decision-oriented subset (block rate, severe exposure, risk
 *     weight) rather than a full structural diff.
 *
 * Honest caveats baked into the output:
 *
 *   - **Trends need a comparable prior window.** When the store's history does
 *     not reach a full window before the current one, the prior side is partial
 *     and the arrows are marked as such rather than implied to be reliable.
 *   - **Alerts, not flows.** Like every SecTool report, a compromise that never
 *     tripped a rule contributes nothing; a calm briefing is not a clean network.
 *   - **Store-capped.** A long look-back can hit the alert store's retention cap
 *     and deflate both the window and its baseline; the bundled coverage-aware
 *     reports still carry their own truncation warnings.
 *
 * Pure in-memory math over alertStore (plus blocklist / watchlist / safelist
 * membership) and the existing offline builders — no SSH, no Claude, no network.
 * Output is both a structured model and a ready-to-paste Markdown document,
 * mirroring risk.ts, efficacy.ts, blockplan.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { buildEfficacy, classifyDisposition, type Disposition } from "./efficacy.ts";
import { buildRisk, SEVERITY_WEIGHT, DISPOSITION_FACTOR } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";
import { buildBlockPlan } from "./blockplan.ts";
import { buildEscalation } from "./escalation.ts";
import { buildNovelty } from "./novelty.ts";
import { buildBacklog } from "./backlog.ts";

/** Which way a KPI "wants" to move for posture to be improving. */
export type GoodDirection = "up" | "down" | "neutral";

/** The qualitative movement of a KPI versus the prior equal-length window. */
export type Trend = "up" | "down" | "flat";

/** A single executive KPI with its prior-window comparison. */
export interface BriefingKpi {
  /** Stable key. */
  key: string;
  /** Human label for the scorecard row. */
  label: string;
  /** The measured value this window. */
  value: number;
  /** Pre-formatted display string (handles %, etc.). */
  display: string;
  /** The same KPI over the prior equal-length window, or null if uncomputable. */
  prior: number | null;
  /** Direction of change vs prior (null when prior is null). */
  trend: Trend | null;
  /** Signed percent change vs prior (null when prior is null/zero-from-zero). */
  deltaPct: number | null;
  /** Which direction is "good" — drives the ✅/⚠️ read on the arrow. */
  goodDirection: GoodDirection;
  /** True when the change is in the desirable direction (null when neutral/flat). */
  improving: boolean | null;
}

/** Priority bands for a synthesised action item. */
export type ActionPriority = "urgent" | "high" | "medium" | "low";

/** One opinionated, deduplicated thing to do, ranked by priority. */
export interface BriefingAction {
  priority: ActionPriority;
  /** Short imperative title (already includes the IP when entity-scoped). */
  title: string;
  /** One-line supporting evidence. */
  detail: string;
  /** The IP this action concerns, when entity-scoped (for de-duplication). */
  ip?: string;
}

/** One bundled detail report appended under the briefing. */
export interface BriefingSection {
  /** Stable section key (the report name). */
  key: string;
  /** Human title for the TOC + heading. */
  title: string;
  /** True when the underlying builder ran cleanly. */
  ok: boolean;
  /** The report's Markdown (or a short stub when it failed). */
  markdown: string;
  /** Error message when the builder threw. */
  error?: string;
}

export interface BriefingReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Start of the prior comparison window (windowStartMs - hours). */
  priorStartMs: number;
  /** Alerts (with a usable timestamp) inside the current window. */
  totalWindowAlerts: number;
  /** Whether a full prior window of history exists (trends are reliable). */
  priorWindowComplete: boolean;
  /** The executive KPI scorecard. */
  kpis: BriefingKpi[];
  /** Prioritised, deduplicated action items. */
  actions: BriefingAction[];
  /** Plain-language headline call-outs. */
  highlights: string[];
  /** Bundled detail reports, in render order. */
  sections: BriefingSection[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface BriefingOptions {
  /** Bundled detail reports to append, in order. Defaults to the essential set. */
  sections?: BriefingSectionKey[];
  /** Row cap handed to each bundled builder (clamped to [1, 200]). */
  limit?: number;
  /** Max action items surfaced (clamped to [1, 100]). */
  maxActions?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const MS_PER_HOUR = 3_600_000;
const DEFAULT_LIMIT = 15;
const DEFAULT_MAX_ACTIONS = 12;

/** The bundled-report registry: stable key → title + builder. */
const SECTION_REGISTRY = {
  risk: { title: "Risk Index / Threat Posture", build: buildRisk },
  efficacy: { title: "IPS Enforcement Gap / Efficacy", build: buildEfficacy },
  blockplan: { title: "Block Recommendation Worklist", build: buildBlockPlan },
  escalation: { title: "Severity Escalation / Trajectory", build: buildEscalation },
  novelty: { title: "First-Seen / Novelty", build: buildNovelty },
  backlog: { title: "Triage SLA Backlog", build: buildBacklog },
} as const;

/** Keys of the bundled reports that can be appended to a briefing. */
export type BriefingSectionKey = keyof typeof SECTION_REGISTRY;

/** The default "morning essentials", in the order they make sense to read. */
const DEFAULT_SECTIONS: BriefingSectionKey[] = [
  "risk",
  "efficacy",
  "blockplan",
  "escalation",
  "novelty",
  "backlog",
];

/** Every selectable section key (exported for CLI/help/validation). */
export const ALL_SECTION_KEYS = Object.keys(SECTION_REGISTRY) as BriefingSectionKey[];

// ----- helpers (mirror repertoire.ts / risk.ts) -----------------------------

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

/** medium or worse. */
function isSevere(s: string | undefined): boolean {
  return sevRank(s) >= 2;
}

/** high or worse. */
function isHigh(s: string | undefined): boolean {
  return sevRank(s) >= 3;
}

function weightOf(s: string | undefined): number {
  return SEVERITY_WEIGHT[(s as Severity) ?? "info"] ?? SEVERITY_WEIGHT.info;
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
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

function mdTable(headers: string[], rows: string[][]): string {
  if (!rows.length) return "_None._";
  const head = `| ${headers.join(" | ")} |`;
  const sep = `| ${headers.map(() => "---").join(" | ")} |`;
  const body = rows.map((r) => `| ${r.join(" | ")} |`).join("\n");
  return `${head}\n${sep}\n${body}`;
}

/** A GitHub-anchor-safe slug for the table-of-contents links. */
function anchor(title: string): string {
  return title
    .toLowerCase()
    .replace(/[^\w\s-]/g, "")
    .trim()
    .replace(/\s+/g, "-");
}

// ----- per-window roll-up ---------------------------------------------------

interface SourceRoll {
  count: number;
  severe: number;
  high: number;
  /** high/critical alerts whose disposition was *not* blocked. */
  highUnblocked: number;
  blocked: number;
  passed: number;
  unknown: number;
  severityMax: Severity;
}

interface WindowMetrics {
  total: number;
  severe: number;
  high: number;
  highUnblocked: number;
  blocked: number;
  passed: number;
  unknown: number;
  /** Σ severityWeight × dispositionFactor over all alerts (the risk weight). */
  riskWeight: number;
  /** Distinct valid source IPs seen. */
  sources: Set<string>;
  /** Per-source roll-up (external + internal), keyed by IP. */
  bySource: Map<string, SourceRoll>;
}

function newSourceRoll(): SourceRoll {
  return {
    count: 0,
    severe: 0,
    high: 0,
    highUnblocked: 0,
    blocked: 0,
    passed: 0,
    unknown: 0,
    severityMax: "info",
  };
}

/** Fold the alerts of one window into a metrics bundle. */
function rollWindow(alerts: StoredAlert[]): WindowMetrics {
  const m: WindowMetrics = {
    total: 0,
    severe: 0,
    high: 0,
    highUnblocked: 0,
    blocked: 0,
    passed: 0,
    unknown: 0,
    riskWeight: 0,
    sources: new Set(),
    bySource: new Map(),
  };

  for (const a of alerts) {
    m.total++;
    const disp: Disposition = classifyDisposition(a.action);
    const severe = isSevere(a.severity);
    const high = isHigh(a.severity);
    if (severe) m.severe++;
    if (high) m.high++;
    if (disp === "blocked") m.blocked++;
    else if (disp === "passed") m.passed++;
    else m.unknown++;
    const highUnblocked = high && disp !== "blocked";
    if (highUnblocked) m.highUnblocked++;
    m.riskWeight += weightOf(a.severity) * (DISPOSITION_FACTOR[disp] ?? 1);

    const src = validIp(a.srcIp);
    if (!src) continue;
    m.sources.add(src);
    const roll = m.bySource.get(src) ?? newSourceRoll();
    if (!m.bySource.has(src)) m.bySource.set(src, roll);
    roll.count++;
    if (severe) roll.severe++;
    if (high) roll.high++;
    if (highUnblocked) roll.highUnblocked++;
    if (disp === "blocked") roll.blocked++;
    else if (disp === "passed") roll.passed++;
    else roll.unknown++;
    if (sevRank(a.severity) > sevRank(roll.severityMax)) roll.severityMax = a.severity as Severity;
  }

  return m;
}

// ----- KPIs -----------------------------------------------------------------

function blockRate(m: WindowMetrics): number | null {
  const actioned = m.blocked + m.passed;
  return actioned ? m.blocked / actioned : null;
}

function makeKpi(
  key: string,
  label: string,
  value: number,
  display: string,
  prior: number | null,
  goodDirection: GoodDirection,
): BriefingKpi {
  let trend: Trend | null = null;
  let deltaPct: number | null = null;
  let improving: boolean | null = null;
  if (prior !== null) {
    const diff = value - prior;
    trend = diff > 0 ? "up" : diff < 0 ? "down" : "flat";
    if (prior !== 0) deltaPct = Math.round((diff / Math.abs(prior)) * 100);
    else if (value !== 0) deltaPct = null; // 0 → n: percent is undefined/∞
    if (goodDirection === "neutral" || trend === "flat") improving = null;
    else if (goodDirection === "up") improving = diff > 0;
    else improving = diff < 0;
  }
  return { key, label, value, display, prior, trend, deltaPct, goodDirection, improving };
}

function buildKpis(cur: WindowMetrics, prior: WindowMetrics | null, newSources: number): BriefingKpi[] {
  const curRate = blockRate(cur);
  const priorRate = prior ? blockRate(prior) : null;
  const kpis: BriefingKpi[] = [];

  kpis.push(makeKpi("alerts", "Total alerts", cur.total, String(cur.total), prior ? prior.total : null, "neutral"));
  kpis.push(
    makeKpi("severe", "Severe (medium+)", cur.severe, String(cur.severe), prior ? prior.severe : null, "down"),
  );
  kpis.push(
    makeKpi(
      "blockRate",
      "Block rate",
      curRate === null ? 0 : Math.round(curRate * 1000) / 1000,
      curRate === null ? "n/a" : pct(curRate),
      priorRate === null ? null : Math.round(priorRate * 1000) / 1000,
      "up",
    ),
  );
  kpis.push(
    makeKpi(
      "highUnblocked",
      "Unblocked high/critical",
      cur.highUnblocked,
      String(cur.highUnblocked),
      prior ? prior.highUnblocked : null,
      "down",
    ),
  );
  kpis.push(
    makeKpi(
      "sources",
      "Active sources",
      cur.sources.size,
      String(cur.sources.size),
      prior ? prior.sources.size : null,
      "neutral",
    ),
  );
  kpis.push(
    makeKpi(
      "riskWeight",
      "Risk weight",
      round1(cur.riskWeight),
      String(round1(cur.riskWeight)),
      prior ? round1(prior.riskWeight) : null,
      "down",
    ),
  );
  kpis.push(makeKpi("newSources", "New sources", newSources, String(newSources), null, "down"));

  return kpis;
}

// ----- action synthesis -----------------------------------------------------

function priorityRank(p: ActionPriority): number {
  return p === "urgent" ? 3 : p === "high" ? 2 : p === "medium" ? 1 : 0;
}

/** Membership flags string for an IP. */
function flagsFor(ip: string): string {
  const f =
    (isPrivate(ip) ? "🏠" : "") +
    (blockStore.has(ip) ? "⛔" : "") +
    (watchStore.has(ip) ? "👁" : "") +
    (safeStore.has(ip) ? "✅" : "");
  return f;
}

function synthesiseActions(cur: WindowMetrics, maxActions: number): BriefingAction[] {
  const actions: BriefingAction[] = [];
  const seenIps = new Set<string>();

  const sources = [...cur.bySource.entries()];

  // URGENT — a safelisted (vetted-benign) IP firing severe alerts is the worst
  // surprise: a trusted address is behaving badly and every downstream report
  // is suppressing/trusting it.
  for (const [ip, r] of sources) {
    if (r.severe > 0 && safeStore.has(ip)) {
      actions.push({
        priority: "urgent",
        ip,
        title: `Re-examine safelist entry \`${ip}\``,
        detail: `Marked vetted-benign yet fired ${r.severe} severe (medium+) alert(s) — worst ${r.severityMax}. A trusted IP attacking is suppressed everywhere; un-safelist and investigate.`,
      });
      seenIps.add(ip);
    }
  }

  // HIGH — external sources landing unblocked high/critical alerts: active
  // threats reaching your hosts that the gateway is letting through.
  const leaky = sources
    .filter(([ip, r]) => r.highUnblocked > 0 && !seenIps.has(ip) && !safeStore.has(ip))
    .sort((a, b) => b[1].highUnblocked - a[1].highUnblocked || b[1].count - a[1].count);
  for (const [ip, r] of leaky) {
    if (seenIps.has(ip)) continue;
    const blocked = blockStore.has(ip);
    actions.push({
      priority: "high",
      ip,
      title: `${blocked ? "Verify block on" : "Block"} \`${ip}\``,
      detail: `${r.highUnblocked} high/critical alert(s) let through (${r.count} total, worst ${r.severityMax})${blocked ? " — already on the blocklist, confirm enforcement is actually dropping it" : " — active threat reaching your hosts unblocked"}.`,
    });
    seenIps.add(ip);
  }

  // MEDIUM — loud, persistent, un-blocked, un-safelisted repeat offenders worth
  // a containment decision even without a high-sev landing.
  const noisy = sources
    .filter(
      ([ip, r]) =>
        !seenIps.has(ip) &&
        !isPrivate(ip) &&
        !blockStore.has(ip) &&
        !safeStore.has(ip) &&
        r.count >= 10 &&
        r.severe > 0,
    )
    .sort((a, b) => b[1].count - a[1].count);
  for (const [ip, r] of noisy) {
    if (seenIps.has(ip)) continue;
    actions.push({
      priority: "medium",
      ip,
      title: `Consider blocking \`${ip}\``,
      detail: `Persistent un-contained source — ${r.count} alert(s) (${r.severe} severe, worst ${r.severityMax}) and not on any list.`,
    });
    seenIps.add(ip);
  }

  // Stable, priority-first ordering, then evidence weight, then IP.
  actions.sort(
    (a, b) =>
      priorityRank(b.priority) - priorityRank(a.priority) ||
      (a.ip && b.ip ? (a.ip < b.ip ? -1 : a.ip > b.ip ? 1 : 0) : 0),
  );

  return actions.slice(0, maxActions);
}

// ----- highlights -----------------------------------------------------------

function arrow(k: BriefingKpi): string {
  if (k.trend === null || k.trend === "flat") return "→";
  return k.trend === "up" ? "▲" : "▼";
}

function trendNote(k: BriefingKpi): string {
  if (k.prior === null) return "no prior window";
  if (k.trend === "flat") return "unchanged";
  const dir = k.trend === "up" ? "up" : "down";
  const mag = k.deltaPct === null ? "" : ` ${Math.abs(k.deltaPct)}%`;
  return `${dir}${mag} vs prior`;
}

function writeHighlights(
  hours: number,
  cur: WindowMetrics,
  kpis: BriefingKpi[],
  actions: BriefingAction[],
  newSources: number,
  priorComplete: boolean,
): string[] {
  const out: string[] = [];
  if (!cur.total) {
    out.push(`No alerts with a usable timestamp in the last ${hours}h — nothing to brief.`);
    return out;
  }

  const rate = blockRate(cur);
  out.push(
    `📋 Over the last ${hours}h: **${cur.total} alert(s)**, **${cur.severe} severe** (medium+), block rate ` +
      `**${rate === null ? "n/a" : pct(rate)}**, **${cur.highUnblocked} unblocked high/critical**, across ` +
      `**${cur.sources.size} source(s)** (${newSources} new).`,
  );

  // The single most-improved and most-regressed KPI, so the trend reads at a glance.
  const directional = kpis.filter((k) => k.improving !== null);
  const regressed = directional.filter((k) => k.improving === false).sort((a, b) => Math.abs(b.deltaPct ?? 0) - Math.abs(a.deltaPct ?? 0))[0];
  const improved = directional.filter((k) => k.improving === true).sort((a, b) => Math.abs(b.deltaPct ?? 0) - Math.abs(a.deltaPct ?? 0))[0];
  if (regressed) {
    out.push(
      `📉 Biggest regression: **${regressed.label}** ${arrow(regressed)} ${regressed.display} (${trendNote(regressed)}).`,
    );
  }
  if (improved) {
    out.push(
      `📈 Biggest improvement: **${improved.label}** ${arrow(improved)} ${improved.display} (${trendNote(improved)}).`,
    );
  }

  const urgent = actions.filter((a) => a.priority === "urgent").length;
  const high = actions.filter((a) => a.priority === "high").length;
  if (actions.length) {
    out.push(
      `✅ **${actions.length} action item(s)** queued${urgent ? ` — ${urgent} URGENT` : ""}${high ? `, ${high} high` : ""}. ` +
        `Top: ${actions[0]!.title.replace(/`/g, "")}.`,
    );
  } else {
    out.push(`✅ No action items — no safelisted-IP surprises, unblocked high/critical, or loud un-contained sources.`);
  }

  if (!priorComplete) {
    out.push(
      `ℹ️ The store's history does not reach a full ${hours}h before this window, so trend arrows compare against a ` +
        `**partial** prior window — read them as directional, not exact.`,
    );
  }

  return out;
}

// ----- bundled sections -----------------------------------------------------

/** The common shape every bundled builder satisfies (narrowed for a union call). */
type SectionBuilder = (hours: number, opts: { limit?: number; nowMs?: number }) => { markdown: string };

/** Run one bundled builder, guarded so a failure degrades gracefully. */
function buildSection(key: BriefingSectionKey, hours: number, limit: number, nowMs: number): BriefingSection {
  const entry = SECTION_REGISTRY[key];
  // `entry.build` is a union of the concrete builder signatures; calling that
  // union directly trips TS ("no compatible signatures"). Each builder accepts
  // `{ limit?, nowMs? }` and returns `{ markdown: string }`, so narrow to that
  // common shape before invoking.
  const build = entry.build as SectionBuilder;
  try {
    const report = build(hours, { limit, nowMs }) as { markdown?: string };
    const markdown = typeof report.markdown === "string" && report.markdown.trim() ? report.markdown : "_(report produced no output)_";
    return { key, title: entry.title, ok: true, markdown };
  } catch (err) {
    const error = (err as Error).message;
    return {
      key,
      title: entry.title,
      ok: false,
      error,
      markdown: `> ⚠️ The **${entry.title}** report could not be generated: ${error}`,
    };
  }
}

// ----- markdown -------------------------------------------------------------

function kpiTable(kpis: BriefingKpi[]): string {
  return mdTable(
    ["KPI", "Now", "Prior", "Trend", "Read"],
    kpis.map((k) => {
      const prior = k.prior === null ? "—" : String(k.prior);
      const read = k.improving === null ? "—" : k.improving ? "✅ better" : "⚠️ worse";
      return [cell(k.label), cell(k.display), cell(prior), `${arrow(k)} ${cell(trendNote(k))}`, read];
    }),
  );
}

function actionTable(actions: BriefingAction[]): string {
  const badge: Record<ActionPriority, string> = {
    urgent: "🔴 URGENT",
    high: "🟠 HIGH",
    medium: "🟡 MEDIUM",
    low: "⚪ LOW",
  };
  return mdTable(
    ["#", "Priority", "Action", "Why", "Flags"],
    actions.map((a, i) => [
      String(i + 1),
      badge[a.priority],
      cell(a.title),
      cell(a.detail),
      a.ip ? flagsFor(a.ip) || "—" : "—",
    ]),
  );
}

function renderMarkdown(m: BriefingReport): string {
  const lines: string[] = [];
  lines.push(`# 📋 SecTool Morning Security Briefing`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Prior window:** ${fmtTime(m.priorStartMs)} → ${fmtTime(m.windowStartMs)}` +
      `${m.priorWindowComplete ? "" : " _(partial — limited history)_"}`,
  );
  lines.push(
    `**Method:** self-computed KPIs + trend over alertStore, opinionated action list, and the bundled detail ` +
      `reports — pure offline, deterministic, no Claude/network.`,
  );
  lines.push("");

  lines.push(`## Headline`);
  lines.push("");
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  if (!m.totalWindowAlerts) {
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  lines.push(`## At a glance`);
  lines.push("");
  lines.push(kpiTable(m.kpis));
  lines.push("");
  lines.push(
    `**Legend:** _Trend_ compares each KPI against the immediately preceding ${m.hours}h window. _Read_ is whether ` +
      `the movement is desirable — block rate wants to rise; severe / unblocked / risk weight want to fall; alert ` +
      `and source counts are context (neutral). **Risk weight** = Σ severity-weight × disposition-factor (blocked ` +
      `discounted, passed full), the same weighting risk.ts uses.`,
  );
  lines.push("");

  lines.push(`## Action items`);
  lines.push("");
  if (m.actions.length) {
    lines.push(actionTable(m.actions));
    lines.push("");
    lines.push(`**Flags:** 🏠 internal source · ⛔ blocked · 👁 watched · ✅ safelisted.`);
  } else {
    lines.push(
      `_No action items._ No safelisted IP fired a severe alert, nothing high/critical was let through, and no loud ` +
        `un-contained repeat offender crossed the threshold.`,
    );
  }
  lines.push("");

  // Table of contents for the bundled detail.
  if (m.sections.length) {
    lines.push(`## Detail reports`);
    lines.push("");
    for (const s of m.sections) {
      lines.push(`- [${s.title}](#${anchor(s.title)})${s.ok ? "" : " ⚠️"}`);
    }
    lines.push("");
    for (const s of m.sections) {
      lines.push(`<a id="${anchor(s.title)}"></a>`);
      lines.push("");
      lines.push(`### ${s.title}${s.ok ? "" : " ⚠️"}`);
      lines.push("");
      lines.push(s.markdown);
      lines.push("");
      lines.push("---");
      lines.push("");
    }
  }

  lines.push(
    `_Generated offline by SecTool. This is a **consolidator**: the KPIs, trend and action list are computed here ` +
      `directly over the stored alert history; the detail sections are the existing offline reports, bundled. Like ` +
      `every SecTool report it sees IPS **detections, not flows**, the history is store-capped, and a partial prior ` +
      `window makes trends directional rather than exact. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the consolidated morning security briefing from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link BriefingOptions}: `sections`, `limit`, `maxActions`, and a
 *              `nowMs` pin for deterministic tests.
 */
export function buildBriefing(hours: number, opts: BriefingOptions = {}): BriefingReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const maxActions = Math.max(1, Math.min(100, Math.floor(opts.maxActions ?? DEFAULT_MAX_ACTIONS)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;
  const priorStartMs = windowStartMs - safeHours * MS_PER_HOUR;

  // Validate / default the requested bundled sections (keep order, drop unknowns).
  const requested = opts.sections && opts.sections.length ? opts.sections : DEFAULT_SECTIONS;
  const sectionKeys = requested.filter((k): k is BriefingSectionKey => k in SECTION_REGISTRY);

  const all = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time));

  const windowed = all.filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);
  const priorWindowed = all.filter((a) => a.time >= priorStartMs && a.time < windowStartMs);
  const earliest = all.length ? Math.min(...all.map((a) => a.time)) : windowStartMs;
  const priorWindowComplete = earliest <= priorStartMs;

  const cur = rollWindow(windowed);
  // Only compute a prior comparison when there is *some* history before the
  // window; an empty prior with no history would imply a misleading "0".
  const prior = all.some((a) => a.time < windowStartMs) ? rollWindow(priorWindowed) : null;

  // New sources = active in window, absent from the entire retained baseline
  // before the window (mirrors novelty.ts's first-seen definition).
  const baselineSources = new Set<string>();
  for (const a of all) {
    if (a.time >= windowStartMs) continue;
    const src = validIp(a.srcIp);
    if (src) baselineSources.add(src);
  }
  let newSources = 0;
  for (const ip of cur.sources) if (!baselineSources.has(ip)) newSources++;

  const kpis = buildKpis(cur, prior, newSources);
  const actions = synthesiseActions(cur, maxActions);
  const highlights = writeHighlights(safeHours, cur, kpis, actions, newSources, priorWindowComplete);

  // Bundle the detail reports last (heaviest work); each guarded individually.
  const sections = windowed.length
    ? sectionKeys.map((k) => buildSection(k, safeHours, limit, windowEndMs))
    : [];

  const model: BriefingReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    priorStartMs,
    totalWindowAlerts: windowed.length,
    priorWindowComplete,
    kpis,
    actions,
    highlights,
    sections,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded briefing. */
export function briefingFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-briefing-${stamp}.md`;
}
