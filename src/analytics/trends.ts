/**
 * Aggregates the stored alert history into a compact "trends" report:
 * totals, severity breakdown, top signatures / src / dst / categories, blocked
 * vs detected, and an hourly volume histogram. Pure in-memory math against
 * alertStore — needs no SSH and is safe to call from the dashboard at any time.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { dismissStore } from "../store/dismissed.ts";
import { triageStore, type TriageStatus } from "../store/triage.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

export interface TopEntry<K = string> {
  key: K;
  count: number;
}

export interface HistogramBucket {
  startMs: number;
  count: number;
}

export interface Trends {
  /** Window the report covers, in hours. */
  hours: number;
  /** Number of alerts contributing to the report. */
  total: number;
  /** End of the window, ms since epoch (typically now). */
  windowEndMs: number;
  /** Start of the window, ms since epoch. */
  windowStartMs: number;
  /** Per-severity counts, ordered from info → critical. */
  bySeverity: Array<{ severity: Severity; count: number }>;
  /** Action labels (blocked / detected / allowed / unknown) → count. */
  byAction: Array<{ action: string; count: number }>;
  /** Workflow status (open / investigating / resolved / false-positive) → count. */
  byTriage: Array<{ status: TriageStatus | "open"; count: number }>;
  /** Notification & dismissal totals (rolled up across the window). */
  notified: number;
  dismissed: number;
  withSummary: number;
  /** Most-seen signatures, descending. */
  topSignatures: Array<TopEntry & { severityMax: Severity }>;
  topSrcIps: TopEntry[];
  topDstIps: TopEntry[];
  topCategories: TopEntry[];
  topClassifications: TopEntry[];
  /** Volume buckets across the window (always ~24 evenly-sized bins). */
  histogram: HistogramBucket[];
  /** Bucket width in ms (equal across `histogram`). */
  bucketMs: number;
  /** Peak bucket count, useful as a sparkline scale. */
  histogramMax: number;
}

const DEFAULT_TOP_N = 10;
const HISTOGRAM_BUCKETS = 24;

function bump<T>(m: Map<T, number>, k: T | undefined | null): void {
  if (k === undefined || k === null || k === "") return;
  m.set(k, (m.get(k) ?? 0) + 1);
}

function topN<T>(m: Map<T, number>, n: number): Array<{ key: T; count: number }> {
  return [...m.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count || String(a.key).localeCompare(String(b.key)))
    .slice(0, n);
}

function sevRank(s: string): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s);
  return i < 0 ? -1 : i;
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
 * Build a Trends report from the alert store. `nowMs` lets callers pin the
 * window end (useful for tests); defaults to Date.now().
 */
export function buildTrends(hours: number, limit = DEFAULT_TOP_N, nowMs = Date.now()): Trends {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const windowEndMs = nowMs;
  const windowStartMs = windowEndMs - safeHours * 3_600_000;

  const all: StoredAlert[] = alertStore.all();
  const inWindow = all.filter((a) => typeof a.time === "number" && a.time >= windowStartMs && a.time <= windowEndMs);

  const bySev = new Map<Severity, number>();
  const byAct = new Map<string, number>();
  const byTri = new Map<TriageStatus | "open", number>();
  const sigCounts = new Map<string, number>();
  const sigMaxSev = new Map<string, Severity>();
  const srcCounts = new Map<string, number>();
  const dstCounts = new Map<string, number>();
  const catCounts = new Map<string, number>();
  const classCounts = new Map<string, number>();

  const bucketMs = Math.max(60_000, Math.floor((safeHours * 3_600_000) / HISTOGRAM_BUCKETS));
  const histogram: HistogramBucket[] = Array.from({ length: HISTOGRAM_BUCKETS }, (_, i) => ({
    startMs: windowStartMs + i * bucketMs,
    count: 0,
  }));

  let notified = 0;
  let dismissed = 0;
  let withSummary = 0;

  for (const a of inWindow) {
    const sev = (a.severity as Severity) ?? "info";
    bump(bySev, sev);
    bump(byAct, normalizeAction(a.action));

    const triage = triageStore.get(a.id);
    const status: TriageStatus | "open" = triage?.status ?? "open";
    bump(byTri, status);

    if (a.signature) {
      bump(sigCounts, a.signature);
      sigMaxSev.set(a.signature, maxSeverity(sigMaxSev.get(a.signature) ?? "info", sev));
    }
    if (a.srcIp && isIP(a.srcIp) > 0) bump(srcCounts, a.srcIp);
    if (a.dstIp && isIP(a.dstIp) > 0) bump(dstCounts, a.dstIp);
    bump(catCounts, a.category);
    bump(classCounts, a.classification);

    if (a.notifiedAt) notified++;
    if (a.summary) withSummary++;
    if (dismissStore.has(a.id)) dismissed++;

    const idx = Math.min(HISTOGRAM_BUCKETS - 1, Math.max(0, Math.floor((a.time - windowStartMs) / bucketMs)));
    histogram[idx]!.count++;
  }

  let histogramMax = 0;
  for (const b of histogram) if (b.count > histogramMax) histogramMax = b.count;

  const bySeverity = SEVERITY_ORDER.map((severity) => ({ severity, count: bySev.get(severity) ?? 0 }));
  const ACTIONS = ["blocked", "detected", "allowed", "unknown"];
  const byAction = ACTIONS.map((action) => ({ action, count: byAct.get(action) ?? 0 })).filter((x) => x.count > 0);
  const TRIAGE: Array<TriageStatus | "open"> = ["open", "investigating", "resolved", "false-positive"];
  const byTriage = TRIAGE.map((status) => ({ status, count: byTri.get(status) ?? 0 }));

  const topSignatures = topN(sigCounts, limit).map((x) => ({
    key: x.key,
    count: x.count,
    severityMax: sigMaxSev.get(x.key) ?? "info",
  }));

  return {
    hours: safeHours,
    total: inWindow.length,
    windowStartMs,
    windowEndMs,
    bySeverity,
    byAction,
    byTriage,
    notified,
    dismissed,
    withSummary,
    topSignatures,
    topSrcIps: topN(srcCounts, limit),
    topDstIps: topN(dstCounts, limit),
    topCategories: topN(catCounts, limit),
    topClassifications: topN(classCounts, limit),
    histogram,
    bucketMs,
    histogramMax,
  };
}
