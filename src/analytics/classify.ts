/**
 * Threat-classification breakdown report — "what *kinds* of attacks am I seeing?"
 *
 * Every other offline report in this project pivots on an *entity* or a *time
 * shape*: campaigns/persistence on the attacker IP, assets on the internal host,
 * edges/spread on the topology, beacon/surge/rhythm on the clock, tuning on the
 * individual signature. None of them answer the first question a SOC lead asks at
 * a glance — **"what is the threat *mix*?"** — i.e. how the traffic divides across
 * Suricata's own threat taxonomy (`classification` / classtype: "Attempted
 * Administrator Privilege Gain", "A Network Trojan was Detected", "Detection of a
 * Network Scan", policy chatter, and so on).
 *
 * Two things make the classification axis uniquely useful and uniquely absent:
 *
 *   1. **It is the IDS engine's own verdict on intent.** A signature name is a
 *      detail ("ET SCAN Nmap -sS"); the classification is the *category of harm*
 *      it rolls up to. Ten different scan signatures all collapse to one
 *      "Network Scan" class, so the breakdown shows posture an operator can act
 *      on ("60% of my volume is recon, 5% is trojan activity — but that 5% is the
 *      fire") without drowning in per-signature rows.
 *
 *   2. **The Trends view ranks top *categories* ("IDS/IPS", "Firewall") — a
 *      coarse source-of-event label — never the fine-grained `classification`.**
 *      So the threat-type mix has simply never been surfaced offline.
 *
 * For each distinct classification this module rolls up, from the stored history:
 *
 *   - alert volume and its share of the window,
 *   - the severity profile (worst severity, medium-or-worse count, critical count),
 *   - enforcement posture — how many were actively blocked vs only detected, and
 *     the resulting block rate (a *high-severity, low-block* class is a control
 *     gap worth a human's morning),
 *   - breadth — distinct attacker sources and distinct internal targets, so a
 *     class driven by one noisy host reads differently from one hitting many,
 *   - the dominant signature for context and the distinct-signature count,
 *   - first/last seen and a recent-vs-older split so a class that is *accelerating*
 *     (most of its hits land in the recent half of the window) is flagged.
 *
 * Honest caveats baked into the output:
 *
 *   - **Classification is optional.** Firewall blocks and some events carry no
 *     Suricata classtype. Rather than drop them, this report falls back to the
 *     event `category` and labels the row so the operator knows the class is
 *     engine-supplied, not taxonomy-supplied.
 *   - **Volume ≠ risk.** Recon and policy chatter dominate every IDS by count; the
 *     report ranks by a severity-weighted score, not raw volume, and calls out the
 *     dangerous-but-quiet classes separately so they are not buried under noise.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network — safe to
 * call from the dashboard or CLI at any time. Output is both a structured model
 * and a ready-to-paste Markdown document, mirroring report.ts, spread.ts,
 * efficacy.ts, beacon.ts, surge.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/**
 * One threat class rolled up over the window. A `class` is the Suricata
 * `classification` when present, otherwise the event `category` (see `derived`).
 */
export interface ClassEntry {
  /** The threat-class label this row aggregates. */
  label: string;
  /**
   * True when the label came from the event `category` fallback rather than a
   * Suricata `classification` — i.e. the IDS engine offered no classtype.
   */
  derived: boolean;
  /** Total windowed alerts in this class. */
  alerts: number;
  /** Share of all windowed alerts, 0..1 (rounded to 4dp). */
  share: number;
  /** Distinct attacker source IPs that drove this class. */
  distinctSources: number;
  /** Distinct internal/target destination IPs hit in this class. */
  distinctDestinations: number;
  /** Distinct signatures that rolled up into this class. */
  distinctSignatures: number;
  /** The dominant signature for context (may be empty). */
  topSignature: string;
  /** Worst severity observed in this class. */
  severityMax: Severity;
  /** Alerts at medium severity or above. */
  severeCount: number;
  /** Alerts at the top (critical) severity. */
  criticalCount: number;
  /** Alerts whose action was an active block. */
  blockedCount: number;
  /** Fraction of this class's alerts that were actively blocked, 0..1 (4dp). */
  blockRate: number;
  /** Alerts that landed in the recent half of the window (acceleration signal). */
  recentHalf: number;
  /** ms epoch of the first occurrence inside the window. */
  firstSeenMs: number;
  /** ms epoch of the most recent occurrence inside the window. */
  lastSeenMs: number;
  /**
   * Severity-weighted score used to rank this class — volume scaled by the worst
   * severity it reached, so a small high-severity class outranks a large benign
   * one. Not a probability; a relative attention score.
   */
  score: number;
  /**
   * True when this class is both dangerous (medium-or-worse) and largely
   * un-enforced (low block rate) — the rows that are an actual control gap.
   */
  controlGap: boolean;
}

export interface ClassifyReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Distinct threat classes observed. */
  distinctClasses: number;
  /** How many classes were derived from the category fallback (no classtype). */
  derivedClasses: number;
  /** Classes flagged as a control gap (dangerous + largely un-enforced). */
  controlGapCount: number;
  /** All classes, ranked by severity-weighted score, truncated to the limit. */
  classes: ClassEntry[];
  /** True when the class table was truncated by the limit. */
  truncated: boolean;
  /** Plain-language call-outs about the report as a whole. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface ClassifyOptions {
  /** Max rows in the class table (clamped to [1, 500]). */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 25;

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? (b as Severity) : a;
}

/** Medium or above is worth promoting / hunting. */
function isSevere(s: string | undefined): boolean {
  return sevRank(s) >= 2;
}

/** Top of the scale — a confirmed-critical detection. */
function isCritical(s: string | undefined): boolean {
  return sevRank(s) >= SEVERITY_ORDER.length - 1;
}

function isBlocked(action: string | undefined): boolean {
  return (action ?? "").toLowerCase() === "blocked";
}

// ----- formatting helpers (mirror spread.ts / beacon.ts / efficacy.ts) -----

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** A compact relative-age label like "3h" / "2d" for the most-recent column. */
function fmtAge(ms: number, nowMs: number): string {
  const sec = Math.max(0, Math.round((nowMs - ms) / 1000));
  if (sec < 90) return `${sec}s`;
  const min = Math.round(sec / 60);
  if (min < 90) return `${min}m`;
  const hr = Math.round(min / 60);
  if (hr < 48) return `${hr}h`;
  return `${Math.round(hr / 24)}d`;
}

function pct(frac: number): string {
  return `${(frac * 100).toFixed(frac >= 0.0995 ? 0 : 1)}%`;
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
function clip(s: string, max = 40): string {
  const t = s.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

/**
 * Internal accumulator for one threat class while we fold the window. Holds the
 * distinct-peer sets plus the tallies needed to render severity, enforcement,
 * signature context, acceleration, and first/last seen.
 */
interface Accum {
  label: string;
  derived: boolean;
  alerts: number;
  sources: Set<string>;
  destinations: Set<string>;
  sigCounts: Map<string, number>;
  severityMax: Severity;
  severeCount: number;
  criticalCount: number;
  blockedCount: number;
  recentHalf: number;
  firstSeenMs: number;
  lastSeenMs: number;
}

function bump(map: Map<string, number>, key: string | undefined): void {
  if (!key) return;
  map.set(key, (map.get(key) ?? 0) + 1);
}

/** Most frequent key in a tally, ties broken by lexical order for stability. */
function topKey(map: Map<string, number>): string {
  let best = "";
  let bestN = -1;
  for (const [k, n] of map) {
    if (n > bestN || (n === bestN && k < best)) {
      best = k;
      bestN = n;
    }
  }
  return best;
}

/**
 * Resolve the threat-class label for an alert. Prefers the Suricata
 * `classification`; falls back to the coarser event `category`; failing both,
 * an explicit "(unclassified)" bucket so nothing is silently dropped.
 */
function classOf(a: StoredAlert): { label: string; derived: boolean } {
  const cls = (a.classification ?? "").trim();
  if (cls) return { label: cls, derived: false };
  const cat = (a.category ?? "").trim();
  if (cat) return { label: cat, derived: true };
  return { label: "(unclassified)", derived: true };
}

/** Volume scaled by worst severity — so a small high-severity class can outrank a large benign one. */
function scoreOf(alerts: number, severityMax: Severity): number {
  // info=1 .. critical=5; a critical alert weighs 5× a bare info one.
  const weight = sevRank(severityMax) + 1;
  return alerts * weight;
}

function toEntry(e: Accum, totalWindowAlerts: number): ClassEntry {
  const alerts = e.alerts;
  const blockRate = alerts ? e.blockedCount / alerts : 0;
  const score = scoreOf(alerts, e.severityMax);
  // A control gap: the engine considers this class dangerous (medium+) yet most
  // of it sailed through un-blocked. A pure "detected"-mode sensor blocks nothing,
  // so this is honest about posture, not an accusation of misconfiguration.
  const controlGap = isSevere(e.severityMax) && e.severeCount > 0 && blockRate < 0.5;
  return {
    label: e.label,
    derived: e.derived,
    alerts,
    share: totalWindowAlerts ? Math.round((alerts / totalWindowAlerts) * 10000) / 10000 : 0,
    distinctSources: e.sources.size,
    distinctDestinations: e.destinations.size,
    distinctSignatures: e.sigCounts.size,
    topSignature: topKey(e.sigCounts),
    severityMax: e.severityMax,
    severeCount: e.severeCount,
    criticalCount: e.criticalCount,
    blockedCount: e.blockedCount,
    blockRate: Math.round(blockRate * 10000) / 10000,
    recentHalf: e.recentHalf,
    firstSeenMs: e.firstSeenMs,
    lastSeenMs: e.lastSeenMs,
    score,
    controlGap,
  };
}

/**
 * Rank classes: control gaps first (dangerous + un-enforced), then by the
 * severity-weighted score, then by raw volume, then by recency — so the rows
 * worth a human's time float to the top, not the noisiest benign chatter.
 */
function rank(items: ClassEntry[]): ClassEntry[] {
  return items.sort((x, y) => {
    if (x.controlGap !== y.controlGap) return x.controlGap ? -1 : 1;
    if (y.score !== x.score) return y.score - x.score;
    if (y.alerts !== x.alerts) return y.alerts - x.alerts;
    return y.lastSeenMs - x.lastSeenMs;
  });
}

/** A small acceleration glyph from the recent-half share of a class's volume. */
function trendGlyph(e: ClassEntry): string {
  if (e.alerts < 4) return "·"; // too few to call a trend honestly
  const recentFrac = e.recentHalf / e.alerts;
  if (recentFrac >= 0.75) return "▲▲"; // strongly front-loaded toward now
  if (recentFrac >= 0.6) return "▲";
  if (recentFrac <= 0.25) return "▼";
  return "→";
}

function writeHighlights(m: Omit<ClassifyReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (!m.totalWindowAlerts) return out;

  const top = m.classes[0];
  // Dominant class by *volume* (not score) — the posture headline.
  const byVolume = [...m.classes].sort((a, b) => b.alerts - a.alerts)[0];
  if (byVolume) {
    out.push(
      `Threat mix over the last ${m.hours}h spans **${m.distinctClasses} class(es)**. ` +
        `Most traffic is **${byVolume.label}** (${byVolume.alerts} alert(s), ${pct(byVolume.share)} of volume` +
        `${byVolume.severityMax !== "info" ? `, peak ${byVolume.severityMax}` : ""}).`,
    );
  }

  // The sharpest fire: dangerous classes that are largely un-enforced.
  const gaps = m.classes.filter((e) => e.controlGap);
  if (gaps.length) {
    const worst = gaps[0]!;
    out.push(
      `⚠️ ${gaps.length} **control-gap** class(es): medium-or-worse threats that were mostly *detected, not blocked*. ` +
        `Worst: **${worst.label}** — ${worst.severeCount}/${worst.alerts} severe, only ${pct(worst.blockRate)} blocked, ` +
        `${worst.distinctSources} source(s) → ${worst.distinctDestinations} target(s). Verify enforcement here first.`,
    );
  }

  // Confirmed-critical classes deserve a named call-out regardless of volume.
  const critical = m.classes.filter((e) => e.criticalCount > 0);
  if (critical.length) {
    const c = critical.sort((a, b) => b.criticalCount - a.criticalCount)[0]!;
    out.push(
      `🚨 ${critical.length} class(es) reached **critical** severity — top: **${c.label}** ` +
        `(${c.criticalCount} critical alert(s)). These are the engine's highest-confidence harm verdicts.`,
    );
  }

  // Accelerating classes — most of their volume landed in the recent half.
  const rising = m.classes
    .filter((e) => e.alerts >= 4 && e.recentHalf / e.alerts >= 0.75)
    .sort((a, b) => b.alerts - a.alerts);
  if (rising.length) {
    const r = rising[0]!;
    out.push(
      `📈 ${rising.length} class(es) are **accelerating** (≥75% of their volume in the recent half of the window) — ` +
        `e.g. **${r.label}** (${r.recentHalf}/${r.alerts} recent). A class that is ramping is worth watching live.`,
    );
  }

  if (m.derivedClasses) {
    out.push(
      `ℹ️ ${m.derivedClasses} class(es) carry no Suricata classtype and were grouped by event *category* instead ` +
        `(marked \`~\` below) — coarser, but nothing was dropped.`,
    );
  }

  if (top && !gaps.length && !critical.length && !rising.length) {
    out.push(`No control gaps, critical classes, or accelerating classes this window — posture is steady.`);
  }
  return out;
}

function classTable(entries: ClassEntry[], nowMs: number): string {
  return mdTable(
    ["", "Class", "Alerts", "Share", "Peak", "Severe", "Crit", "Blocked", "Srcs", "Dsts", "Sigs", "Trend", "Last", "Top signature"],
    entries.map((e) => [
      e.controlGap ? "🚩" : "·",
      cell(e.label) + (e.derived ? " `~`" : ""),
      String(e.alerts),
      pct(e.share),
      cell(e.severityMax),
      String(e.severeCount),
      String(e.criticalCount),
      `${e.blockedCount} (${pct(e.blockRate)})`,
      String(e.distinctSources),
      String(e.distinctDestinations),
      String(e.distinctSignatures),
      trendGlyph(e),
      fmtAge(e.lastSeenMs, nowMs),
      e.topSignature ? cell(clip(e.topSignature)) : "—",
    ]),
  );
}

function renderMarkdown(m: ClassifyReport): string {
  const lines: string[] = [];
  lines.push(`# 🧬 SecTool Threat-Classification Breakdown`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Mix:** ${m.distinctClasses} threat class(es) · **${m.controlGapCount} control-gap** · ` +
      `${m.derivedClasses} category-derived · **Window alerts:** ${m.totalWindowAlerts}`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.totalWindowAlerts) {
    lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Threat classes — ranked by severity-weighted attention`);
  lines.push("");
  lines.push(classTable(m.classes, m.windowEndMs));
  lines.push("");

  if (m.truncated) {
    lines.push(`_The table was truncated to the row limit — raise \`limit\` to see more classes._`);
    lines.push("");
  }

  lines.push(
    `**Legend:** 🚩 = control gap (medium-or-worse class, <50% actively blocked). \`~\` = label is the event ` +
      `*category* (no Suricata classtype). _Severe_ = medium+; _Crit_ = critical. _Blocked_ shows count and the ` +
      `class's block rate. _Trend_: ▲▲/▲ = volume front-loaded toward now (accelerating), ▼ = tailing off, ` +
      `→ = steady, · = too few to call.`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from the stored **IPS-alert** history. Classes are ranked by a ` +
      `severity-weighted score, not raw volume, so a small but dangerous class outranks benign chatter; volume ` +
      `still appears per row. A low block rate reflects detection-mode sensing as much as a real enforcement gap — ` +
      `confirm before acting. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the threat-classification breakdown report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link ClassifyOptions}: `limit` and a `nowMs` pin.
 */
export function buildClassify(hours: number, opts: ClassifyOptions = {}): ClassifyReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(500, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * 3_600_000;
  // Midpoint splits the window into "older" and "recent" halves for the trend signal.
  const midMs = windowStartMs + (windowEndMs - windowStartMs) / 2;

  const all = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time));

  const byClass = new Map<string, Accum>();
  let totalWindowAlerts = 0;
  for (const a of all) {
    if (a.time < windowStartMs || a.time > windowEndMs) continue;
    totalWindowAlerts++;
    const { label, derived } = classOf(a);
    let e = byClass.get(label);
    if (!e) {
      e = {
        label,
        derived,
        alerts: 0,
        sources: new Set(),
        destinations: new Set(),
        sigCounts: new Map(),
        severityMax: "info",
        severeCount: 0,
        criticalCount: 0,
        blockedCount: 0,
        recentHalf: 0,
        firstSeenMs: a.time,
        lastSeenMs: a.time,
      };
      byClass.set(label, e);
    }
    e.alerts++;
    if (a.srcIp && isIP(a.srcIp) > 0) e.sources.add(a.srcIp);
    if (a.dstIp && isIP(a.dstIp) > 0) e.destinations.add(a.dstIp);
    bump(e.sigCounts, a.signature);
    e.severityMax = maxSeverity(e.severityMax, a.severity);
    if (isSevere(a.severity)) e.severeCount++;
    if (isCritical(a.severity)) e.criticalCount++;
    if (isBlocked(a.action)) e.blockedCount++;
    if (a.time >= midMs) e.recentHalf++;
    if (a.time < e.firstSeenMs) e.firstSeenMs = a.time;
    if (a.time > e.lastSeenMs) e.lastSeenMs = a.time;
  }

  const allEntries = rank([...byClass.values()].map((e) => toEntry(e, totalWindowAlerts)));
  const classes = allEntries.slice(0, limit);

  const base: Omit<ClassifyReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts,
    distinctClasses: allEntries.length,
    derivedClasses: allEntries.filter((e) => e.derived).length,
    controlGapCount: allEntries.filter((e) => e.controlGap).length,
    classes,
    truncated: allEntries.length > classes.length,
  };
  const highlights = writeHighlights(base);
  const model: ClassifyReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded classification report. */
export function classifyFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-classify-${stamp}.md`;
}
