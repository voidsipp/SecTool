/**
 * Offline incident report generator.
 *
 * Produces a shareable, SOC-style security report for a time window straight
 * from local state — no SSH, no Claude, no network. It rolls up the stored
 * alert history (via the same math as the Trends view), the operator's triage
 * workflow, the watchlist, and the active suppression rules into both a
 * structured model and a ready-to-paste Markdown document.
 *
 * This complements:
 *   - the Trends view   (interactive dashboard, not exportable)
 *   - search.csv        (raw alert rows, not a narrative)
 *   - the Discord digest (needs SSH + Claude, posts to a channel)
 *
 * Use it to hand a human-readable summary to a colleague or to keep a dated
 * record of what the network looked like — instantly and offline.
 */
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { watchStore } from "../store/watchlist.ts";
import { suppressionStore, describeMatch } from "../store/suppressions.ts";
import { safeStore } from "../store/safelist.ts";
import { triageStore } from "../store/triage.ts";
import { buildTrends, type Trends } from "./trends.ts";

export interface WatchHit {
  /** The watchlisted IP/CIDR that registered activity. */
  target: string;
  /**
   * Operator's free-form note for the entry, if any. Surfaced both in the
   * Watchlist section and inline against any Notable detection that touches
   * this target (see {@link NotableDetection.watchNote}).
   */
  note?: string;
  /** Number of distinct alerts in the window that touched this target. */
  alertHits: number;
  /** Most recent alert time for this target, ms epoch. */
  lastAlertTime?: number;
  /** Highest severity observed across this target's alerts (e.g. "high"). */
  worstSeverity?: string;
  /** The signature (or category) this target triggered most often. */
  topSignature?: string;
}

export interface NotableDetection {
  /** Stable alert id (for cross-referencing with the dashboard / search tab). */
  id: string;
  /** Alert time, ms epoch. */
  time: number;
  /** Severity label (e.g. "high", "critical"). */
  severity: string;
  /** Best human label: signature, falling back to category. */
  signature: string;
  /** Raw category, kept for context where signature was used as the label. */
  category: string;
  /** Source address, if the alert carried one. */
  srcIp?: string;
  /** Destination address, if the alert carried one. */
  dstIp?: string;
  /** Normalised disposition (blocked / detected / allowed / unknown). */
  action: string;
  /** Current triage workflow status (defaults to "open" when untouched). */
  triageStatus: string;
  /** Watchlisted IP/CIDR this detection's source or dest matched, if any. */
  watchTarget?: string;
  /** Operator's free-form watchlist note for {@link watchTarget}, if one was set. */
  watchNote?: string;
}

export interface ReportModel {
  /** Window length in hours (clamped). */
  hours: number;
  /** When the report was generated, ms epoch. */
  generatedAt: number;
  /** Window bounds, ms epoch. */
  windowStartMs: number;
  windowEndMs: number;
  /** Full trends roll-up for the window. */
  trends: Trends;
  /** Risk posture label + severity-weighted daily score. */
  posture: { label: string; score: number };
  /** Auto-written, non-AI executive summary (plain sentences). */
  executiveSummary: string;
  /** Quietest/busiest descriptive call-outs. */
  highlights: string[];
  /** Watchlist entries that registered alert hits in the window. */
  watchHits: WatchHit[];
  /** The most severe individual detections in the window (medium+), worst first. */
  notable: NotableDetection[];
  /** Number of active (non-expired) suppression rules. */
  activeSuppressions: number;
  /** Number of IPs marked safe (context for the false-positive posture). */
  safeCount: number;
  /** The finished Markdown document. */
  markdown: string;
}

const SEV_WEIGHT: Record<string, number> = { info: 0, low: 1, medium: 2, high: 4, critical: 8 };

/** Mirror of the trends action buckets so the report labels dispositions identically. */
function normalizeAction(a: string | undefined): string {
  const v = (a ?? "").toLowerCase().trim();
  if (v === "blocked" || v === "detected" || v === "allowed") return v;
  return "unknown";
}

function pct(n: number, total: number): number {
  return total > 0 ? Math.round((n / total) * 100) : 0;
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

/** A simple risk posture label derived from severity-weighted volume. */
function posture(trends: Trends): { label: string; score: number } {
  let score = 0;
  for (const s of trends.bySeverity) score += s.count * (SEV_WEIGHT[s.severity] ?? 0);
  // Normalize loosely against the window length so longer windows aren't punished.
  const perDay = trends.hours > 0 ? (score / trends.hours) * 24 : score;
  let label = "Calm";
  if (perDay >= 200) label = "Critical";
  else if (perDay >= 80) label = "Elevated";
  else if (perDay >= 20) label = "Active";
  else if (perDay > 0) label = "Low";
  else label = "Quiet";
  return { label, score: Math.round(perDay) };
}

/** Find the peak histogram bucket. */
function peakBucket(trends: Trends): { startMs: number; count: number } | null {
  let best: { startMs: number; count: number } | null = null;
  for (const b of trends.histogram) {
    if (b.count > 0 && (!best || b.count > best.count)) best = { startMs: b.startMs, count: b.count };
  }
  return best;
}

/** Internal accumulator: a WatchHit plus the running stats needed to fill it. */
interface WatchAccum {
  hit: WatchHit;
  worstWeight: number;
  sigCounts: Map<string, number>;
}

function collectWatchHits(allAlerts: StoredAlert[], windowStartMs: number): WatchHit[] {
  const entries = watchStore.all();
  if (!entries.length) return [];
  const byTarget = new Map<string, WatchAccum>();
  for (const e of entries) {
    byTarget.set(e.target, {
      hit: { target: e.target, note: e.note, alertHits: 0 },
      worstWeight: -1,
      sigCounts: new Map(),
    });
  }
  for (const a of allAlerts) {
    if (a.time < windowStartMs) continue;
    // One alert counts once per target even if both endpoints match it.
    const counted = new Set<string>();
    for (const ip of [a.srcIp, a.dstIp]) {
      const m = watchStore.match(ip);
      if (!m || counted.has(m.target)) continue;
      counted.add(m.target);
      const acc = byTarget.get(m.target);
      if (!acc) continue;
      acc.hit.alertHits++;
      if (acc.hit.lastAlertTime === undefined || a.time > acc.hit.lastAlertTime) acc.hit.lastAlertTime = a.time;
      const w = SEV_WEIGHT[a.severity] ?? 0;
      if (w > acc.worstWeight) {
        acc.worstWeight = w;
        acc.hit.worstSeverity = a.severity;
      }
      const sig = a.signature || a.category || "—";
      acc.sigCounts.set(sig, (acc.sigCounts.get(sig) ?? 0) + 1);
    }
  }
  const hits: WatchHit[] = [];
  for (const acc of byTarget.values()) {
    if (acc.hit.alertHits === 0) continue;
    let topSig: string | undefined;
    let topN = 0;
    for (const [sig, n] of acc.sigCounts) {
      if (n > topN) {
        topN = n;
        topSig = sig;
      }
    }
    acc.hit.topSignature = topSig;
    hits.push(acc.hit);
  }
  // Rank by danger first (worst severity), then by volume.
  return hits.sort((a, b) => {
    const wa = SEV_WEIGHT[a.worstSeverity ?? ""] ?? 0;
    const wb = SEV_WEIGHT[b.worstSeverity ?? ""] ?? 0;
    return wb - wa || b.alertHits - a.alertHits;
  });
}

/** Lowest severity weight that qualifies an individual alert as "notable". */
const NOTABLE_MIN_WEIGHT = SEV_WEIGHT.medium!;

/**
 * Pick the most severe individual detections in the window so the report names
 * concrete events — not just aggregates — for an analyst to action. Ranked by
 * severity, then recency; only medium-and-above alerts qualify so a quiet
 * window never pads the section with informational noise.
 */
function collectNotableDetections(
  allAlerts: StoredAlert[],
  windowStartMs: number,
  windowEndMs: number,
  limit: number,
): NotableDetection[] {
  const notable = allAlerts.filter(
    (a) =>
      typeof a.time === "number" &&
      a.time >= windowStartMs &&
      a.time <= windowEndMs &&
      (SEV_WEIGHT[a.severity] ?? 0) >= NOTABLE_MIN_WEIGHT,
  );
  notable.sort((a, b) => (SEV_WEIGHT[b.severity] ?? 0) - (SEV_WEIGHT[a.severity] ?? 0) || b.time - a.time);
  return notable.slice(0, limit).map((a) => {
    // Surface the operator's watchlist context inline: if either endpoint is on
    // the watchlist, prefer the entry that actually carries a note so the
    // analyst sees *why* it was flagged ("known C2") next to the detection.
    const src = watchStore.match(a.srcIp);
    const dst = watchStore.match(a.dstIp);
    const watch = src?.note ? src : dst?.note ? dst : (src ?? dst);
    return {
      id: a.id,
      time: a.time,
      severity: a.severity,
      signature: a.signature || a.category || "—",
      category: a.category,
      srcIp: a.srcIp,
      dstIp: a.dstIp,
      action: normalizeAction(a.action),
      triageStatus: triageStore.get(a.id)?.status ?? "open",
      watchTarget: watch?.target,
      watchNote: watch?.note,
    };
  });
}

/** Compose the plain-language executive summary from the numbers. */
function writeExecutiveSummary(trends: Trends, watchHits: WatchHit[], now: number): { summary: string; highlights: string[] } {
  const { label } = posture(trends);
  const sevMap = new Map(trends.bySeverity.map((s) => [s.severity, s.count]));
  const crit = sevMap.get("critical") ?? 0;
  const high = sevMap.get("high") ?? 0;
  const blocked = trends.byAction.find((a) => a.action === "blocked")?.count ?? 0;
  const detected = trends.byAction.find((a) => a.action === "detected")?.count ?? 0;

  const highlights: string[] = [];

  if (trends.total === 0) {
    return {
      summary: `No security alerts were recorded in the last ${trends.hours} hour(s). The network was quiet for this window.`,
      highlights,
    };
  }

  const parts: string[] = [];
  parts.push(
    `Over the last ${trends.hours} hour(s) the monitor recorded ${trends.total} alert(s) ` +
      `(posture: ${label}).`,
  );

  if (crit + high > 0) {
    parts.push(`${crit} critical and ${high} high-severity detection(s) require attention.`);
    highlights.push(`${crit + high} high-or-critical alert(s) in window.`);
  } else {
    parts.push(`No high or critical detections were seen — all activity was low or informational.`);
  }

  const actioned = blocked + detected;
  if (actioned > 0) {
    parts.push(`${blocked} were blocked at the gateway and ${detected} were detected-only (${pct(blocked, actioned)}% block rate).`);
  }

  const topSig = trends.topSignatures[0];
  if (topSig) {
    parts.push(`The most frequent signature was "${topSig.key}" (${topSig.count} hit(s)).`);
    highlights.push(`Top signature: ${topSig.key} — ${topSig.count} hit(s).`);
  }
  const topSrc = trends.topSrcIps[0];
  if (topSrc) {
    parts.push(`The busiest source address was ${topSrc.key} with ${topSrc.count} alert(s).`);
    highlights.push(`Most active source IP: ${topSrc.key} (${topSrc.count}).`);
  }

  const peak = peakBucket(trends);
  if (peak) highlights.push(`Activity peaked at ${fmtTime(peak.startMs)} (${peak.count} in one bucket).`);

  if (watchHits.length) {
    const total = watchHits.reduce((n, w) => n + w.alertHits, 0);
    parts.push(`${watchHits.length} watchlisted target(s) generated ${total} alert(s) — review the watchlist section.`);
    const worst = watchHits[0];
    if (worst?.worstSeverity && (SEV_WEIGHT[worst.worstSeverity] ?? 0) >= SEV_WEIGHT.high!) {
      highlights.push(`Watchlist alert: ${worst.target} reached ${worst.worstSeverity} severity (${worst.alertHits} hit(s)).`);
    } else {
      highlights.push(`${watchHits.length} watchlist target(s) active this window.`);
    }
  }

  if (trends.notified > 0) parts.push(`${trends.notified} alert(s) were pushed to Discord.`);
  if (trends.dismissed > 0) highlights.push(`${trends.dismissed} alert(s) dismissed by an operator.`);

  // Outstanding workflow.
  const open = trends.byTriage.find((t) => t.status === "open")?.count ?? 0;
  const investigating = trends.byTriage.find((t) => t.status === "investigating")?.count ?? 0;
  if (open + investigating > 0) {
    highlights.push(`${open} open and ${investigating} in-progress triage item(s).`);
  }

  void now;
  return { summary: parts.join(" "), highlights };
}

/** A tiny ASCII sparkline for the volume histogram. */
function sparkline(trends: Trends): string {
  const blocks = "▁▂▃▄▅▆▇█";
  const max = trends.histogramMax || 1;
  return trends.histogram
    .map((b) => {
      if (b.count === 0) return "·";
      const idx = Math.min(blocks.length - 1, Math.max(0, Math.round((b.count / max) * (blocks.length - 1))));
      return blocks[idx];
    })
    .join("");
}

function mdTable(headers: string[], rows: string[][]): string {
  if (!rows.length) return "_None._";
  const head = `| ${headers.join(" | ")} |`;
  const sep = `| ${headers.map(() => "---").join(" | ")} |`;
  const body = rows.map((r) => `| ${r.join(" | ")} |`).join("\n");
  return `${head}\n${sep}\n${body}`;
}

/** Escape Markdown table cell content (pipes break the grid). */
function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function renderMarkdown(model: ReportModel): string {
  const t = model.trends;
  const { label, score } = posture(t);
  const lines: string[] = [];

  lines.push(`# 🛡️ SecTool Security Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(model.generatedAt)}`);
  lines.push(`**Window:** last ${t.hours} hour(s) — ${fmtTime(model.windowStartMs)} → ${fmtTime(model.windowEndMs)}`);
  lines.push(`**Posture:** ${label} (severity-weighted ${score}/day)`);
  lines.push("");

  lines.push(`## Executive summary`);
  lines.push("");
  lines.push(model.executiveSummary);
  if (model.highlights.length) {
    lines.push("");
    for (const h of model.highlights) lines.push(`- ${h}`);
  }
  lines.push("");

  lines.push(`## Key metrics`);
  lines.push("");
  lines.push(
    mdTable(
      ["Metric", "Value"],
      [
        ["Total alerts", String(t.total)],
        ["Notified (Discord)", String(t.notified)],
        ["With AI summary", String(t.withSummary)],
        ["Dismissed", String(t.dismissed)],
        ["Active suppression rules", String(model.activeSuppressions)],
        ["IPs marked safe", String(model.safeCount)],
      ],
    ),
  );
  lines.push("");

  if (model.notable.length) {
    // Only show the watchlist column when something actually matched, so quiet
    // reports don't carry an all-"—" column.
    const showWatch = model.notable.some((d) => d.watchTarget);
    const headers = ["#", "When", "Severity", "Signature", "Source → Dest", "Action", "Triage"];
    if (showWatch) headers.push("Watchlist");
    lines.push(`## Notable detections`);
    lines.push("");
    lines.push(
      mdTable(
        headers,
        model.notable.map((d, i) => {
          const row = [
            String(i + 1),
            cell(`${fmtTime(d.time)} (${fmtAgo(d.time, model.generatedAt)})`),
            cell(d.severity),
            cell(d.signature),
            cell(`${d.srcIp ?? "—"} → ${d.dstIp ?? "—"}`),
            cell(d.action),
            cell(d.triageStatus),
          ];
          if (showWatch) {
            const note = d.watchNote ? ` — ${d.watchNote}` : "";
            row.push(d.watchTarget ? cell(`⚑ ${d.watchTarget}${note}`) : "—");
          }
          return row;
        }),
      ),
    );
    lines.push("");
  }

  lines.push(`## Severity breakdown`);
  lines.push("");
  lines.push(
    mdTable(
      ["Severity", "Count", "Share"],
      t.bySeverity.map((s) => [cell(s.severity), String(s.count), `${pct(s.count, t.total)}%`]),
    ),
  );
  lines.push("");

  if (t.byAction.length) {
    lines.push(`## Disposition`);
    lines.push("");
    lines.push(
      mdTable(
        ["Action", "Count"],
        t.byAction.map((a) => [cell(a.action), String(a.count)]),
      ),
    );
    lines.push("");
  }

  lines.push(`## Triage / workflow`);
  lines.push("");
  lines.push(
    mdTable(
      ["Status", "Count"],
      t.byTriage.map((x) => [cell(x.status), String(x.count)]),
    ),
  );
  lines.push("");

  lines.push(`## Volume over time`);
  lines.push("");
  lines.push("```");
  lines.push(sparkline(t));
  lines.push(`${fmtTime(t.windowStartMs)}  …  ${fmtTime(t.windowEndMs)}   (peak ${t.histogramMax}/bucket)`);
  lines.push("```");
  lines.push("");

  lines.push(`## Top signatures`);
  lines.push("");
  lines.push(
    mdTable(
      ["#", "Signature", "Max severity", "Hits"],
      t.topSignatures.map((s, i) => [String(i + 1), cell(s.key), cell(s.severityMax), String(s.count)]),
    ),
  );
  lines.push("");

  lines.push(`## Top source IPs`);
  lines.push("");
  lines.push(
    mdTable(
      ["#", "Source IP", "Alerts"],
      t.topSrcIps.map((s, i) => [String(i + 1), cell(s.key), String(s.count)]),
    ),
  );
  lines.push("");

  lines.push(`## Top destination IPs`);
  lines.push("");
  lines.push(
    mdTable(
      ["#", "Destination IP", "Alerts"],
      t.topDstIps.map((s, i) => [String(i + 1), cell(s.key), String(s.count)]),
    ),
  );
  lines.push("");

  lines.push(`## Top categories`);
  lines.push("");
  lines.push(
    mdTable(
      ["#", "Category", "Count"],
      t.topCategories.map((s, i) => [String(i + 1), cell(s.key), String(s.count)]),
    ),
  );
  lines.push("");

  if (model.watchHits.length) {
    lines.push(`## Watchlist activity`);
    lines.push("");
    lines.push(
      mdTable(
        ["Target", "Alerts", "Worst severity", "Top signature", "Last seen", "Note"],
        model.watchHits.map((w) => [
          cell(w.target),
          String(w.alertHits),
          cell(w.worstSeverity ?? "—"),
          cell(w.topSignature ?? "—"),
          w.lastAlertTime ? fmtAgo(w.lastAlertTime, model.generatedAt) : "—",
          cell(w.note ?? ""),
        ]),
      ),
    );
    lines.push("");
  }

  const suppRules = suppressionStore.all();
  if (suppRules.length) {
    lines.push(`## Active suppression rules`);
    lines.push("");
    lines.push(
      mdTable(
        ["Condition", "Hits", "Reason"],
        suppRules.map((r) => [cell(describeMatch(r.match)), String(r.hitCount ?? 0), cell(r.reason ?? "")]),
      ),
    );
    lines.push("");
  }

  lines.push("---");
  lines.push(`_Generated offline by SecTool from ${t.total} stored alert(s). No live gateway query was performed._`);
  lines.push("");

  return lines.join("\n");
}

/**
 * Build the full report model (and its Markdown rendering) for a window.
 * `nowMs` pins the window end for deterministic tests.
 */
export function buildReport(hours: number, nowMs = Date.now()): ReportModel {
  const trends = buildTrends(hours, 10, nowMs);
  const allAlerts = alertStore.all();
  const watchHits = collectWatchHits(allAlerts, trends.windowStartMs);
  const notable = collectNotableDetections(allAlerts, trends.windowStartMs, trends.windowEndMs, 12);
  const { summary, highlights } = writeExecutiveSummary(trends, watchHits, nowMs);
  const activeSuppressions = suppressionStore.count();
  const safeCount = safeStore.count();

  const model: ReportModel = {
    hours: trends.hours,
    generatedAt: nowMs,
    windowStartMs: trends.windowStartMs,
    windowEndMs: trends.windowEndMs,
    trends,
    posture: posture(trends),
    executiveSummary: summary,
    highlights,
    watchHits,
    notable,
    activeSuppressions,
    safeCount,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for the downloaded report. */
export function reportFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-report-${stamp}.md`;
}
