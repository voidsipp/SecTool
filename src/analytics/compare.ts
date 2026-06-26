/**
 * Period-over-period comparison ("what changed since last time").
 *
 * Takes the same stored alert history the Trends/Report views use and diffs the
 * current window against the immediately preceding window of equal length, then
 * surfaces the *deltas* an analyst actually cares about:
 *
 *   - Is total volume / risk posture rising or falling, and by how much?
 *   - Which severities and dispositions moved?
 *   - Which signatures are brand new this period (never seen last period)?
 *   - Which existing signatures are surging (sharp jump in hits)?
 *   - Which attacker source IPs appeared for the first time?
 *   - What went quiet (signatures / sources that vanished)?
 *
 * It is pure in-memory math against alertStore — no SSH, no Claude, no network —
 * so it is safe to call from the dashboard or CLI at any time. The output is both
 * a structured model and a ready-to-paste Markdown document, mirroring report.ts.
 *
 * This complements report.ts (a snapshot of *one* window) by answering the
 * orthogonal question: how does this window compare to the last one?
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { buildTrends, type Trends } from "./trends.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Severity → risk weight, identical to the report's posture math. */
const SEV_WEIGHT: Record<string, number> = { info: 0, low: 1, medium: 2, high: 4, critical: 8 };

/** How a single tracked entity (signature / IP) moved between the two windows. */
export type Trend = "new" | "gone" | "up" | "down" | "flat";

/** A numeric metric compared across the two windows. */
export interface MetricDelta {
  /** Human label for the metric (e.g. "Total alerts", "blocked"). */
  label: string;
  /** Value in the current window. */
  current: number;
  /** Value in the previous window. */
  previous: number;
  /** current − previous (signed). */
  delta: number;
  /**
   * Percentage change vs the previous window, rounded. `null` when there is no
   * meaningful baseline (previous was 0): the UI should render that as "new"
   * rather than an infinite percentage.
   */
  pctChange: number | null;
  /** Direction of the move, for quick coloring. */
  trend: Trend;
}

/** A per-key (signature / IP / category) movement between windows. */
export interface EntryDelta {
  key: string;
  current: number;
  previous: number;
  delta: number;
  trend: Trend;
}

/** Severity-weighted posture for one window (mirrors report.ts). */
export interface Posture {
  label: string;
  /** Severity-weighted score normalised to a per-day rate. */
  score: number;
}

export interface ComparisonModel {
  /** Window length in hours (clamped, applies to BOTH windows). */
  hours: number;
  /** When the comparison was generated, ms epoch. */
  generatedAt: number;
  /** Current window bounds, ms epoch. */
  currentStartMs: number;
  currentEndMs: number;
  /** Previous (baseline) window bounds, ms epoch. */
  previousStartMs: number;
  previousEndMs: number;
  /** Full trends roll-up for each window (for charts / context). */
  currentTrends: Trends;
  previousTrends: Trends;
  /** Risk posture for each window + which way it moved. */
  posture: { current: Posture; previous: Posture; direction: Trend };
  /** Total alert volume delta. */
  total: MetricDelta;
  /** Per-severity deltas, ordered info → critical. */
  bySeverity: MetricDelta[];
  /** Per-disposition deltas (blocked / detected / allowed / unknown). */
  byAction: MetricDelta[];
  /** Signatures seen this window but never in the previous one, worst/biggest first. */
  newSignatures: EntryDelta[];
  /** Signatures whose volume jumped sharply (present in both windows). */
  surgingSignatures: EntryDelta[];
  /** Signatures that were active last window but went silent this window. */
  resolvedSignatures: EntryDelta[];
  /** External source IPs that appeared for the first time this window. */
  newSources: EntryDelta[];
  /** External source IPs that were active last window but went quiet. */
  goneSources: EntryDelta[];
  /** One-line plain-language headline ("Activity up 42% …"). */
  headline: string;
  /** Bulleted call-outs for the most important movements. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

/** Per-window aggregation computed over the *full* alert set (not top-N). */
interface WindowAgg {
  total: number;
  /** Severity-weighted score, used for posture. */
  weighted: number;
  bySeverity: Map<Severity, number>;
  byAction: Map<string, number>;
  bySignature: Map<string, number>;
  bySrcIp: Map<string, number>;
}

function normalizeAction(a: string | undefined): string {
  const v = (a ?? "").toLowerCase().trim();
  if (v === "blocked" || v === "detected" || v === "allowed") return v;
  return "unknown";
}

function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|fe80|fc|fd)/i.test(ip);
}

function bump<T>(m: Map<T, number>, k: T | undefined | null): void {
  if (k === undefined || k === null || k === "") return;
  m.set(k, (m.get(k) ?? 0) + 1);
}

/** Aggregate every alert whose time falls inside [startMs, endMs]. */
function aggregate(all: StoredAlert[], startMs: number, endMs: number): WindowAgg {
  const agg: WindowAgg = {
    total: 0,
    weighted: 0,
    bySeverity: new Map(),
    byAction: new Map(),
    bySignature: new Map(),
    bySrcIp: new Map(),
  };
  for (const a of all) {
    if (typeof a.time !== "number" || a.time < startMs || a.time > endMs) continue;
    agg.total++;
    const sev = (a.severity as Severity) ?? "info";
    agg.weighted += SEV_WEIGHT[sev] ?? 0;
    bump(agg.bySeverity, sev);
    bump(agg.byAction, normalizeAction(a.action));
    if (a.signature) bump(agg.bySignature, a.signature);
    // Only count external (attacker-side) sources as "new attackers".
    if (a.srcIp && isIP(a.srcIp) > 0 && !isPrivate(a.srcIp)) bump(agg.bySrcIp, a.srcIp);
  }
  return agg;
}

/** Posture label from a severity-weighted score normalised per-day. */
function postureOf(weighted: number, hours: number): Posture {
  const perDay = hours > 0 ? (weighted / hours) * 24 : weighted;
  let label = "Quiet";
  if (perDay >= 200) label = "Critical";
  else if (perDay >= 80) label = "Elevated";
  else if (perDay >= 20) label = "Active";
  else if (perDay > 0) label = "Low";
  return { label, score: Math.round(perDay) };
}

function trendOf(current: number, previous: number): Trend {
  if (previous === 0 && current > 0) return "new";
  if (current === 0 && previous > 0) return "gone";
  if (current > previous) return "up";
  if (current < previous) return "down";
  return "flat";
}

function pctChange(current: number, previous: number): number | null {
  if (previous === 0) return null;
  return Math.round(((current - previous) / previous) * 100);
}

function metric(label: string, current: number, previous: number): MetricDelta {
  return {
    label,
    current,
    previous,
    delta: current - previous,
    pctChange: pctChange(current, previous),
    trend: trendOf(current, previous),
  };
}

/** All keys present in either map (union), so we never miss new/gone entries. */
function unionKeys(a: Map<string, number>, b: Map<string, number>): string[] {
  return [...new Set([...a.keys(), ...b.keys()])];
}

/** Build per-key deltas across both maps. */
function entryDeltas(cur: Map<string, number>, prev: Map<string, number>): EntryDelta[] {
  return unionKeys(cur, prev).map((key) => {
    const c = cur.get(key) ?? 0;
    const p = prev.get(key) ?? 0;
    return { key, current: c, previous: p, delta: c - p, trend: trendOf(c, p) };
  });
}

/** Minimum jump (in absolute hits) for a shared signature to count as "surging". */
const SURGE_MIN_DELTA = 3;
/** And the ratio it must grow by — guards against tiny noisy bumps. */
const SURGE_MIN_RATIO = 1.5;

/** Compose the one-line headline + highlight bullets from the computed deltas. */
function writeNarrative(model: Omit<ComparisonModel, "headline" | "highlights" | "markdown">): {
  headline: string;
  highlights: string[];
} {
  const { total, posture } = model;
  const highlights: string[] = [];

  // Headline: lead with the volume move, then posture direction.
  let headline: string;
  if (total.current === 0 && total.previous === 0) {
    headline = `Both periods were quiet — no alerts in the last ${model.hours}h or the prior ${model.hours}h.`;
  } else if (total.trend === "new") {
    headline = `Activity resumed: ${total.current} alert(s) this period after a silent prior window.`;
  } else if (total.trend === "gone") {
    headline = `Activity stopped: 0 alert(s) this period, down from ${total.previous}.`;
  } else if (total.pctChange === null || total.delta === 0) {
    headline = `Alert volume held steady at ${total.current} (${total.previous} previously).`;
  } else {
    const dir = total.delta > 0 ? "up" : "down";
    headline = `Alert volume ${dir} ${Math.abs(total.pctChange)}% — ${total.current} this period vs ${total.previous} previously.`;
  }

  // Posture move.
  if (posture.current.label !== posture.previous.label) {
    highlights.push(`Risk posture moved ${posture.previous.label} → ${posture.current.label} (${posture.previous.score} → ${posture.current.score}/day).`);
  }

  // Severity escalations worth a callout (high/critical going up).
  for (const s of model.bySeverity) {
    if ((s.label === "high" || s.label === "critical") && s.delta > 0) {
      highlights.push(`${s.label} severity ${s.trend === "new" ? "appeared" : "rose"}: ${s.previous} → ${s.current} (+${s.delta}).`);
    }
  }

  if (model.newSignatures.length) {
    const top = model.newSignatures[0]!;
    highlights.push(`${model.newSignatures.length} new signature(s) this period — e.g. "${top.key}" (${top.current} hit(s)).`);
  }
  if (model.surgingSignatures.length) {
    const top = model.surgingSignatures[0]!;
    highlights.push(`${model.surgingSignatures.length} signature(s) surging — "${top.key}" ${top.previous}→${top.current} (+${top.delta}).`);
  }
  if (model.newSources.length) {
    highlights.push(`${model.newSources.length} new external source IP(s) appeared this period.`);
  }
  if (model.resolvedSignatures.length) {
    highlights.push(`${model.resolvedSignatures.length} signature(s) went quiet (active last period, silent this one).`);
  }

  return { headline, highlights };
}

// ----- Markdown rendering (self-contained, mirrors report.ts conventions) -----

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

/** Signed, arrow-decorated delta for a table cell (e.g. "▲ +12 (+40%)"). */
function deltaCell(d: { delta: number; pctChange: number | null; trend: Trend }): string {
  if (d.trend === "flat" || d.delta === 0) return "—";
  const arrow = d.delta > 0 ? "▲" : "▼";
  const sign = d.delta > 0 ? "+" : "";
  const pct = d.pctChange === null ? "new" : `${sign}${d.pctChange}%`;
  return `${arrow} ${sign}${d.delta} (${pct})`;
}

function renderMarkdown(model: ComparisonModel): string {
  const lines: string[] = [];

  lines.push(`# 🛡️ SecTool Period Comparison`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(model.generatedAt)}`);
  lines.push(`**This period:** last ${model.hours}h — ${fmtTime(model.currentStartMs)} → ${fmtTime(model.currentEndMs)}`);
  lines.push(`**Prior period:** ${fmtTime(model.previousStartMs)} → ${fmtTime(model.previousEndMs)}`);
  lines.push(`**Posture:** ${model.posture.previous.label} → ${model.posture.current.label} ` +
    `(${model.posture.previous.score} → ${model.posture.current.score}/day)`);
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  lines.push(model.headline);
  if (model.highlights.length) {
    lines.push("");
    for (const h of model.highlights) lines.push(`- ${h}`);
  }
  lines.push("");

  lines.push(`## Volume & severity`);
  lines.push("");
  lines.push(
    mdTable(
      ["Metric", "This period", "Prior period", "Change"],
      [model.total, ...model.bySeverity].map((d) => [
        cell(d.label),
        String(d.current),
        String(d.previous),
        deltaCell(d),
      ]),
    ),
  );
  lines.push("");

  if (model.byAction.length) {
    lines.push(`## Disposition`);
    lines.push("");
    lines.push(
      mdTable(
        ["Action", "This period", "Prior period", "Change"],
        model.byAction.map((d) => [cell(d.label), String(d.current), String(d.previous), deltaCell(d)]),
      ),
    );
    lines.push("");
  }

  lines.push(`## New signatures this period`);
  lines.push("");
  lines.push(
    mdTable(
      ["Signature", "Hits"],
      model.newSignatures.map((d) => [cell(d.key), String(d.current)]),
    ),
  );
  lines.push("");

  lines.push(`## Surging signatures`);
  lines.push("");
  lines.push(
    mdTable(
      ["Signature", "Prior", "Now", "Change"],
      model.surgingSignatures.map((d) => [cell(d.key), String(d.previous), String(d.current), deltaCell(d)]),
    ),
  );
  lines.push("");

  lines.push(`## Went quiet`);
  lines.push("");
  lines.push(
    mdTable(
      ["Signature", "Prior hits"],
      model.resolvedSignatures.map((d) => [cell(d.key), String(d.previous)]),
    ),
  );
  lines.push("");

  lines.push(`## New external sources`);
  lines.push("");
  lines.push(
    mdTable(
      ["Source IP", "Alerts this period"],
      model.newSources.map((d) => [cell(d.key), String(d.current)]),
    ),
  );
  lines.push("");

  lines.push("---");
  lines.push(`_Generated offline by SecTool. Compared two back-to-back ${model.hours}h windows from local alert history; no live gateway query was performed._`);
  lines.push("");

  return lines.join("\n");
}

/**
 * Build the full comparison model (and its Markdown rendering) for a window.
 * Compares the last `hours` against the immediately preceding `hours`.
 * `nowMs` pins the window end for deterministic tests.
 */
export function buildComparison(hours: number, limit = 12, nowMs = Date.now()): ComparisonModel {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const windowMs = safeHours * 3_600_000;

  const currentEndMs = nowMs;
  const currentStartMs = currentEndMs - windowMs;
  const previousEndMs = currentStartMs;
  const previousStartMs = previousEndMs - windowMs;

  const all = alertStore.all();
  const cur = aggregate(all, currentStartMs, currentEndMs);
  // Use an exclusive upper bound on the previous window so the boundary alert
  // (exactly at currentStartMs) is counted once, in the current window only.
  const prev = aggregate(all, previousStartMs, previousEndMs - 1);

  // Full trends for each window (charts / top-lists for any UI consumer).
  const currentTrends = buildTrends(safeHours, limit, currentEndMs);
  const previousTrends = buildTrends(safeHours, limit, previousEndMs);

  const postureCurrent = postureOf(cur.weighted, safeHours);
  const posturePrevious = postureOf(prev.weighted, safeHours);

  const total = metric("Total alerts", cur.total, prev.total);

  const bySeverity: MetricDelta[] = SEVERITY_ORDER.map((sev) =>
    metric(sev, cur.bySeverity.get(sev) ?? 0, prev.bySeverity.get(sev) ?? 0),
  ).filter((d) => d.current > 0 || d.previous > 0);

  const ACTIONS = ["blocked", "detected", "allowed", "unknown"];
  const byAction: MetricDelta[] = ACTIONS.map((a) =>
    metric(a, cur.byAction.get(a) ?? 0, prev.byAction.get(a) ?? 0),
  ).filter((d) => d.current > 0 || d.previous > 0);

  const sigDeltas = entryDeltas(cur.bySignature, prev.bySignature);
  const newSignatures = sigDeltas
    .filter((d) => d.trend === "new")
    .sort((a, b) => b.current - a.current)
    .slice(0, limit);
  const surgingSignatures = sigDeltas
    .filter((d) => d.previous > 0 && d.delta >= SURGE_MIN_DELTA && d.current >= d.previous * SURGE_MIN_RATIO)
    .sort((a, b) => b.delta - a.delta)
    .slice(0, limit);
  const resolvedSignatures = sigDeltas
    .filter((d) => d.trend === "gone")
    .sort((a, b) => b.previous - a.previous)
    .slice(0, limit);

  const srcDeltas = entryDeltas(cur.bySrcIp, prev.bySrcIp);
  const newSources = srcDeltas
    .filter((d) => d.trend === "new")
    .sort((a, b) => b.current - a.current)
    .slice(0, limit);
  const goneSources = srcDeltas
    .filter((d) => d.trend === "gone")
    .sort((a, b) => b.previous - a.previous)
    .slice(0, limit);

  const base: Omit<ComparisonModel, "headline" | "highlights" | "markdown"> = {
    hours: safeHours,
    generatedAt: nowMs,
    currentStartMs,
    currentEndMs,
    previousStartMs,
    previousEndMs,
    currentTrends,
    previousTrends,
    posture: {
      current: postureCurrent,
      previous: posturePrevious,
      direction: trendOf(postureCurrent.score, posturePrevious.score),
    },
    total,
    bySeverity,
    byAction,
    newSignatures,
    surgingSignatures,
    resolvedSignatures,
    newSources,
    goneSources,
  };

  const { headline, highlights } = writeNarrative(base);
  const model: ComparisonModel = { ...base, headline, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for the downloaded comparison. */
export function comparisonFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-comparison-${stamp}.md`;
}
