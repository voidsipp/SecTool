/**
 * Entry-vector / first-contact ("foot in the door") report — "**when a brand-new
 * attacker shows up, what do they try *first* — and does that opening move stay a
 * one-knock probe or escalate into something serious?**"
 *
 * Every alert stream begins, per attacker, with a single first event: the *knock*.
 * That opening move is the most operationally loaded signal a defender has — it is
 * the attacker's chosen entry vector, the thing your edge sees before anything bad
 * has happened yet, and (if you can tell which openers reliably escalate) the
 * cheapest possible place to pre-empt an intrusion. Yet none of SecTool's reports
 * isolate it. They each look at the *whole* of a source's behaviour and average the
 * opener away:
 *
 *   - **novelty.ts** lists *which* sources/signatures/targets are first-seen in the
 *     window — arrivals as a set. It never asks what each fresh arrival's **first
 *     action** was, nor whether that action went anywhere.
 *   - **sequence.ts** mines *all* ordered A→B transitions and recurring 3-step
 *     playbooks across every source. It is transition-centric and whole-chain; it
 *     does not single out the **chronologically first** signature per source or
 *     measure the opener→escalation funnel as a conversion rate.
 *   - **killchain.ts** buckets every alert into a *fixed* Lockheed-Martin stage. It
 *     describes the stage mix, not which concrete opener most sources actually lead
 *     with, nor how often a "recon" opener converts to a serious later stage.
 *   - **bruteforce.ts / scan.ts** characterise a specific *kind* of opener (login
 *     attempts, probe shape) — narrow lenses, not the full first-contact census.
 *
 * The unit of analysis here is the **opener**: for every source, its alerts are
 * sorted by time and the *first in-window alert* is taken as the foot-in-the-door
 * event. Openers are aggregated by signature into a conversion funnel:
 *
 *   - **how many fresh sources lead with each opener** (its share of all openers);
 *   - the **escalation rate** — of the sources that opened with signature X, what
 *     fraction later (strictly after the opener) produced a high/critical alert;
 *   - the **median lead time** from the opener to that first serious follow-on —
 *     the warning window a defender has if they act on the opener;
 *   - the **one-and-done rate** — sources that fired the opener and never anything
 *     else (a single harmless knock, the opposite of an intrusion);
 *   - **opened-hot** — sources whose opener was *already* serious (no warning at
 *     all: the first thing you saw was the bad thing);
 *   - **average follow-on breadth** — how many distinct further signatures the
 *     opener typically precedes (a proxy for how much the engagement expands).
 *
 * The headline picks out the **most common opener** (the front door everyone uses)
 * and the **most *dangerous* opener** (the one with the highest escalation rate at
 * real support — the knock you should alert/auto-block on), plus the window-wide
 * split of new arrivals into one-and-done probes vs escalating engagements vs
 * opened-hot. A small companion table drills into the fastest fresh-arrival
 * escalations so an analyst can pivot straight to a concrete case.
 *
 * Why restrict the funnel to **new** sources (those not seen in the retained store
 * before the window)? Because only for a genuinely fresh arrival is its first
 * *in-window* alert also its true first-*ever* alert — a real opener. A returning
 * source's true opener happened earlier (possibly already evicted from the store),
 * so its first-in-window event is a *resumption*, not a foot in the door; counting
 * it would pollute the entry-vector picture. Returning sources are still counted in
 * the headline totals and called out, just excluded from the opener funnel.
 *
 * Honest caveats baked into the output:
 *
 *   - **Source IP ≠ actor.** NAT / shared egress can make one host's opener belong
 *     to a different person than its escalation; a rotating botnet spreads one
 *     actor's foot-in-the-door across many IPs so no single source shows the chain.
 *   - **"New" is history-bounded.** "New" means not seen in the retained store
 *     before the window opened; alertStore is capped/rotated, so a long-quiet
 *     returning source can read as new (the same limit novelty.ts states) and its
 *     resumption can masquerade as an opener.
 *   - **Severity is a derived field.** Escalation is measured on the same severity
 *     every other report sorts on — if that label is noisy (see `--stability`),
 *     escalation rates inherit the noise.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network. Output is
 * both a structured model and a ready-to-paste Markdown document, mirroring
 * timeline.ts, sequence.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** One opening-move signature, aggregated across the fresh sources that led with it. */
export interface VectorOpener {
  /** The opener signature text. */
  signature: string;
  /** Dominant Suricata category among sources opening with this signature. */
  category?: string;
  /** Number of new sources whose first in-window alert was this signature. */
  sources: number;
  /** {@link sources} as a fraction of all new-source openers (0–1). */
  share: number;
  /** Worst severity seen *as an opener* for this signature. */
  openerSeverityMax: Severity;
  /** New sources whose opener was already high/critical (no warning window). */
  openedHot: number;
  /** New sources that later (after the opener) produced a high/critical alert. */
  escalated: number;
  /** {@link escalated} / {@link sources} (0–1) — the conversion rate of this opener. */
  escalationRate: number;
  /** Median ms from the opener to the first serious follow-on (over escalators); null if none. */
  medianLeadMs: number | null;
  /** New sources whose only in-window alert was this single opener (one harmless knock). */
  oneAndDone: number;
  /** {@link oneAndDone} / {@link sources} (0–1). */
  oneAndDoneRate: number;
  /** Mean count of distinct *other* signatures fired after the opener, across these sources. */
  avgFollowOnSignatures: number;
}

/** A concrete fast-escalating fresh arrival, for the drill-down table. */
export interface VectorEscalation {
  source: string;
  /** The opener signature this source led with. */
  opener: string;
  /** The first high/critical signature it escalated to. */
  escalatedTo: string;
  /** Severity of that first serious follow-on. */
  escalatedSeverity: Severity;
  /** Lead time (ms) from opener to first serious follow-on. */
  leadMs: number;
  /** Total in-window alerts from this source. */
  totalAlerts: number;
}

export interface VectorReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Earliest retained alert strictly before the window (the new-source baseline reach). */
  baselineStartMs: number | null;
  /** Distinct sources seen strictly before the window (the new-source baseline). */
  baselineSources: number;
  /** Distinct valid source IPs active in the window. */
  totalSources: number;
  /** Distinct sources whose first-ever-seen (in retained history) is in the window. */
  newSources: number;
  /** Distinct sources active in the window that were already seen before it. */
  returningSources: number;
  /** New sources that escalated to serious after their opener. */
  escalatedSources: number;
  /** New sources whose opener was already serious. */
  openedHotSources: number;
  /** New sources whose only alert was their opener. */
  oneAndDoneSources: number;
  /** Median lead (ms) from opener to first serious follow-on across all escalating new sources. */
  medianLeadMs: number | null;
  /** Opening moves, busiest first (capped to the row limit — see truncated). */
  openers: VectorOpener[];
  /** True when more opener signatures exist than were shown. */
  truncated: boolean;
  /** Distinct opener signatures across all new sources (before truncation). */
  openerSignatureCount: number;
  /** Fastest fresh-arrival escalations, for the drill-down table. */
  fastEscalations: VectorEscalation[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface VectorOptions {
  /** Max opener rows shown (busiest kept); clamped to [1, 200]. Default 25. */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 25;
const MS_PER_HOUR = 3_600_000;
/** Minimum sources behind an opener before it can be crowned "most dangerous" (anti-noise). */
const MIN_DANGER_SUPPORT = 3;
/** Cap on the fast-escalation drill-down table. */
const FAST_ESCALATION_ROWS = 12;

// ----- helpers (mirror timeline.ts / sequence.ts) ----------------------------

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

/** High or critical — the "serious" band every report counts. */
function isSerious(s: string | undefined): boolean {
  return sevRank(s) >= sevRank("high");
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** Compact human duration: "45s", "12m", "3h 20m", "2d 4h". */
function fmtDuration(ms: number): string {
  if (ms < 0) ms = 0;
  const s = Math.round(ms / 1000);
  if (s < 90) return `${s}s`;
  const m = Math.round(s / 60);
  if (m < 90) return `${m}m`;
  const h = Math.floor(m / 60);
  const remM = m % 60;
  if (h < 48) return remM ? `${h}h ${remM}m` : `${h}h`;
  const d = Math.floor(h / 24);
  const remH = h % 24;
  return remH ? `${d}d ${remH}h` : `${d}d`;
}

function pct(frac: number): string {
  return `${Math.round(frac * 100)}%`;
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

/** Median of a numeric list (null for empty). */
function median(xs: number[]): number | null {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid]! : Math.round((s[mid - 1]! + s[mid]!) / 2);
}

/** The keyed mode (most frequent value) of a count map, deterministic tie-break. */
function topKey(counts: Map<string, number>): string | undefined {
  let best: string | undefined;
  let bestN = -1;
  for (const [k, n] of counts) {
    if (n > bestN || (n === bestN && best !== undefined && k < best)) {
      best = k;
      bestN = n;
    }
  }
  return best;
}

function bumpCount(m: Map<string, number>, k: string): void {
  m.set(k, (m.get(k) ?? 0) + 1);
}

// ----- per-source first-contact analysis -------------------------------------

interface SourceContact {
  source: string;
  isNew: boolean;
  opener: string;
  openerCategory?: string;
  openerSeverity: Severity;
  openerTimeMs: number;
  totalAlerts: number;
  /** First serious alert strictly after the opener, if any. */
  escalatedTo?: string;
  escalatedSeverity?: Severity;
  escalationLeadMs?: number;
  /** Distinct signatures fired strictly after the opener (excludes the opener sig). */
  followOnSignatures: number;
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(report: Omit<VectorReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (report.newSources === 0) return out; // handled in the Markdown empty branch

  const top = report.openers[0];
  if (top) {
    out.push(
      `🚪 Most common opener: **\`${clip(top.signature, 60)}\`** — **${top.sources}** fresh source(s) ` +
        `(${pct(top.share)} of new arrivals) led with it${top.category ? ` (${top.category})` : ""}. ` +
        `${top.escalated > 0 ? `**${pct(top.escalationRate)}** of them escalated.` : `None escalated — looks like background knocking.`}`,
    );
  }

  // Most dangerous opener: highest escalation rate at real support.
  const danger = [...report.openers]
    .filter((o) => o.sources >= MIN_DANGER_SUPPORT && o.escalated > 0)
    .sort((a, b) => b.escalationRate - a.escalationRate || b.escalated - a.escalated)[0];
  if (danger && danger !== top) {
    out.push(
      `⚠️ Most *dangerous* opener: **\`${clip(danger.signature, 60)}\`** converts to serious **${pct(danger.escalationRate)}** ` +
        `of the time (${danger.escalated}/${danger.sources} source(s))` +
        `${danger.medianLeadMs !== null ? `, median **${fmtDuration(danger.medianLeadMs)}** after the knock` : ""}. ` +
        `Strong candidate to alert or auto-block on first sight.`,
    );
  } else if (danger && danger === top && danger.escalated > 0) {
    out.push(
      `⚠️ The most common opener is *also* the most dangerous: it escalates **${pct(danger.escalationRate)}** of the time` +
        `${danger.medianLeadMs !== null ? ` (median **${fmtDuration(danger.medianLeadMs)}** lead)` : ""} — treat it as a high-priority knock.`,
    );
  }

  // Window-wide funnel facets (overlapping, not a strict partition).
  const n = report.newSources;
  out.push(
    `📊 Of **${n}** fresh source(s): **${pct(report.oneAndDoneSources / n)}** were one-and-done probes (a single knock, ` +
      `nothing more), **${pct(report.escalatedSources / n)}** escalated to serious *after* the knock, and ` +
      `**${pct(report.openedHotSources / n)}** opened *hot* (first alert already high/critical — no warning window). ` +
      `_(Facets overlap: an opened-hot source may also be one-and-done.)_`,
  );

  if (report.medianLeadMs !== null && report.escalatedSources > 0) {
    out.push(
      `⏱️ Median warning window across escalating arrivals is **${fmtDuration(report.medianLeadMs)}** — that is how long, ` +
        `on average, you have between the foot-in-the-door and the serious follow-on to intervene.`,
    );
  }

  if (report.openedHotSources > 0) {
    out.push(
      `🔥 **${report.openedHotSources}** fresh source(s) gave **no warning** — their very first detection was already ` +
        `high/critical. For these, prevention has to be upstream (perimeter/geo/reputation), not opener-triggered.`,
    );
  }

  if (report.returningSources > 0) {
    out.push(
      `↩️ **${report.returningSources}** active source(s) were *returning* (seen before the window) and are excluded from ` +
        `the opener funnel — their true foot-in-the-door predates this window. See \`--persist\` / \`--recidivism\`.`,
    );
  }

  return out;
}

// ----- markdown --------------------------------------------------------------

function openerTable(openers: VectorOpener[]): string {
  return mdTable(
    ["Opening move (signature)", "Category", "New srcs", "%", "Opener sev", "Escalated", "Esc %", "Med lead", "1-&-done", "Avg follow-on sigs"],
    openers.map((o) => [
      cell(`\`${clip(o.signature)}\``),
      cell(o.category ?? "—"),
      String(o.sources),
      pct(o.share),
      cell(o.openerSeverityMax),
      o.escalated > 0 ? `**${o.escalated}**` : "0",
      o.escalated > 0 ? `**${pct(o.escalationRate)}**` : "—",
      o.medianLeadMs !== null ? fmtDuration(o.medianLeadMs) : "—",
      o.oneAndDone > 0 ? `${pct(o.oneAndDoneRate)}` : "0%",
      o.avgFollowOnSignatures.toFixed(1),
    ]),
  );
}

function escalationTable(rows: VectorEscalation[]): string {
  return mdTable(
    ["Source", "Opened with", "→ Escalated to", "Sev", "Lead", "Alerts"],
    rows.map((r) => [
      cell(`\`${r.source}\``),
      cell(clip(r.opener, 34)),
      cell(clip(r.escalatedTo, 34)),
      cell(r.escalatedSeverity),
      fmtDuration(r.leadMs),
      String(r.totalAlerts),
    ]),
  );
}

function renderMarkdown(m: VectorReport): string {
  const lines: string[] = [];
  lines.push(`# 🚪 SecTool Entry-Vector / First-Contact Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** for every source, its *first in-window alert* is the foot-in-the-door event; the opener funnel covers ` +
      `the **${m.newSources}** fresh source(s) (first-seen in retained history this window) — returning sources are ` +
      `counted but excluded (their real opener predates the window). Offline, deterministic.`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (m.newSources === 0) {
    const reason =
      m.totalSources === 0
        ? `No source IPs were active in the last ${m.hours}h`
        : `All ${m.totalSources} active source(s) were already seen before this window — no fresh foot-in-the-door to analyse`;
    lines.push(
      `${reason}. There is no entry-vector funnel to draw. Widen the window (\`--vector <more hours>\`), or check ` +
        `\`--novelty\` for first-seen arrivals and \`--persist\` for the returning base.`,
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Opening moves`);
  lines.push("");
  if (m.truncated) {
    lines.push(
      `_${m.openerSignatureCount} distinct opener(s) across the fresh arrivals; showing the **${m.openers.length}** ` +
        `most common. Raise \`--limit\` to see more._`,
    );
    lines.push("");
  }
  lines.push(openerTable(m.openers));
  lines.push("");
  lines.push(
    `**Legend:** _New srcs_ = fresh sources that led with this signature. _Esc %_ = of those, the share that later ` +
      `produced a high/critical alert. _Med lead_ = median time from the opener to that first serious follow-on (your ` +
      `warning window). _1-&-done_ = share whose only alert was this opener. _Avg follow-on sigs_ = mean distinct ` +
      `further signatures the opener preceded.`,
  );
  lines.push("");

  if (m.fastEscalations.length) {
    lines.push(`## Fastest fresh-arrival escalations`);
    lines.push("");
    lines.push(
      `_Concrete cases where a brand-new source went from its opener to a serious detection quickest — the shortest ` +
        `warning windows. Pivot to \`--profile <ip>\` for the full dossier._`,
    );
    lines.push("");
    lines.push(escalationTable(m.fastEscalations));
    lines.push("");
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. The opener funnel covers **new** sources only (first-seen in the retained store, ` +
      `${m.baselineSources} source(s) of pre-window baseline back to ` +
      `${m.baselineStartMs !== null ? fmtTime(m.baselineStartMs) : "the start of history"}); a long-quiet returning ` +
      `source can read as new (see \`--novelty\`). Source IP ≠ actor — NAT and rotating botnets can split or merge ` +
      `openers and escalations across hosts. Escalation is measured on the derived severity field (\`--stability\` audits ` +
      `its trust). This is the first-event companion to \`--sequence\` (all ordered transitions / playbooks), ` +
      `\`--novelty\` (first-seen set) and \`--killchain\` (fixed stage mix). No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the entry-vector / first-contact report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [2, 180 days]).
 * @param opts  {@link VectorOptions}: `limit` and a `nowMs` pin for deterministic tests.
 */
export function buildVector(hours: number, opts: VectorOptions = {}): VectorReport {
  const safeHours = Math.max(2, Math.min(24 * 180, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const all = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time));

  // New-source baseline: every source seen strictly before the window opened
  // (mirrors novelty.ts / timeline.ts so "new" means first-seen in retained
  // history). Also note how far back that memory reaches.
  const baselineSources = new Set<string>();
  let baselineStartMs: number | null = null;
  for (const a of all) {
    if (a.time >= windowStartMs) continue;
    if (baselineStartMs === null || a.time < baselineStartMs) baselineStartMs = a.time;
    const src = validIp(a.srcIp);
    if (src) baselineSources.add(src);
  }

  // Group in-window alerts by source, chronologically.
  const bySource = new Map<string, StoredAlert[]>();
  for (const a of all) {
    if (a.time < windowStartMs || a.time > windowEndMs) continue;
    const src = validIp(a.srcIp);
    if (!src) continue;
    (bySource.get(src) ?? bySource.set(src, []).get(src)!).push(a);
  }

  const contacts: SourceContact[] = [];
  let returningSources = 0;
  for (const [src, alerts] of bySource) {
    alerts.sort((a, b) => a.time - b.time);
    const isNew = !baselineSources.has(src);
    if (!isNew) {
      returningSources++;
      continue; // funnel covers fresh arrivals only — see the doc comment
    }
    const opener = alerts[0]!;
    const openerSig = (opener.signature ?? "").trim() || "(unlabelled)";
    const openerTimeMs = opener.time;

    // Distinct follow-on signatures and the first serious follow-on strictly after
    // the opener event.
    const followOn = new Set<string>();
    let escalatedTo: string | undefined;
    let escalatedSeverity: Severity | undefined;
    let escalationLeadMs: number | undefined;
    for (let i = 1; i < alerts.length; i++) {
      const a = alerts[i]!;
      const sig = (a.signature ?? "").trim();
      if (sig && sig !== openerSig) followOn.add(sig);
      if (escalatedTo === undefined && isSerious(a.severity) && a.time > openerTimeMs) {
        escalatedTo = sig || "(unlabelled)";
        escalatedSeverity = (a.severity as Severity) ?? "high";
        escalationLeadMs = a.time - openerTimeMs;
      }
    }

    contacts.push({
      source: src,
      isNew,
      opener: openerSig,
      openerCategory: (opener.category ?? "").trim() || undefined,
      openerSeverity: (opener.severity as Severity) ?? "info",
      openerTimeMs,
      totalAlerts: alerts.length,
      escalatedTo,
      escalatedSeverity,
      escalationLeadMs,
      followOnSignatures: followOn.size,
    });
  }

  const newSources = contacts.length;

  // Aggregate openers by signature.
  interface OpenerAcc {
    sources: number;
    categoryCounts: Map<string, number>;
    openerSeverityMax: Severity;
    openedHot: number;
    escalated: number;
    leads: number[];
    oneAndDone: number;
    followOnTotal: number;
  }
  const openerAccs = new Map<string, OpenerAcc>();
  let escalatedSources = 0;
  let openedHotSources = 0;
  let oneAndDoneSources = 0;
  const allLeads: number[] = [];

  for (const c of contacts) {
    let acc = openerAccs.get(c.opener);
    if (!acc) {
      acc = {
        sources: 0,
        categoryCounts: new Map(),
        openerSeverityMax: "info",
        openedHot: 0,
        escalated: 0,
        leads: [],
        oneAndDone: 0,
        followOnTotal: 0,
      };
      openerAccs.set(c.opener, acc);
    }
    acc.sources++;
    if (c.openerCategory) bumpCount(acc.categoryCounts, c.openerCategory);
    acc.openerSeverityMax = maxSeverity(acc.openerSeverityMax, c.openerSeverity);
    acc.followOnTotal += c.followOnSignatures;

    const hot = isSerious(c.openerSeverity);
    if (hot) {
      acc.openedHot++;
      openedHotSources++;
    }
    if (c.escalationLeadMs !== undefined) {
      acc.escalated++;
      acc.leads.push(c.escalationLeadMs);
      escalatedSources++;
      allLeads.push(c.escalationLeadMs);
    }
    if (c.totalAlerts === 1) {
      acc.oneAndDone++;
      oneAndDoneSources++;
    }
  }

  const openersFull: VectorOpener[] = [...openerAccs.entries()].map(([signature, acc]) => ({
    signature,
    category: topKey(acc.categoryCounts),
    sources: acc.sources,
    share: newSources ? acc.sources / newSources : 0,
    openerSeverityMax: acc.openerSeverityMax,
    openedHot: acc.openedHot,
    escalated: acc.escalated,
    escalationRate: acc.sources ? acc.escalated / acc.sources : 0,
    medianLeadMs: median(acc.leads),
    oneAndDone: acc.oneAndDone,
    oneAndDoneRate: acc.sources ? acc.oneAndDone / acc.sources : 0,
    avgFollowOnSignatures: acc.sources ? acc.followOnTotal / acc.sources : 0,
  }));

  // Busiest opener first, deterministic tie-break on signature.
  openersFull.sort((a, b) => b.sources - a.sources || a.signature.localeCompare(b.signature));
  const truncated = openersFull.length > limit;
  const openers = truncated ? openersFull.slice(0, limit) : openersFull;

  // Fast-escalation drill-down: shortest opener→serious leads, fresh sources only.
  const fastEscalations: VectorEscalation[] = contacts
    .filter((c) => c.escalationLeadMs !== undefined && c.escalatedTo !== undefined)
    .sort((a, b) => a.escalationLeadMs! - b.escalationLeadMs! || a.source.localeCompare(b.source))
    .slice(0, FAST_ESCALATION_ROWS)
    .map((c) => ({
      source: c.source,
      opener: c.opener,
      escalatedTo: c.escalatedTo!,
      escalatedSeverity: c.escalatedSeverity ?? "high",
      leadMs: c.escalationLeadMs!,
      totalAlerts: c.totalAlerts,
    }));

  const base: Omit<VectorReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    baselineStartMs,
    baselineSources: baselineSources.size,
    totalSources: bySource.size,
    newSources,
    returningSources,
    escalatedSources,
    openedHotSources,
    oneAndDoneSources,
    medianLeadMs: median(allLeads),
    openers,
    truncated,
    openerSignatureCount: openersFull.length,
    fastEscalations,
  };

  const highlights = writeHighlights(base);
  const model: VectorReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded entry-vector report. */
export function vectorFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-vector-${stamp}.md`;
}
