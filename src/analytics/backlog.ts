/**
 * Triage SLA backlog report — "is our response keeping up?"
 *
 * Every other offline report in this project is about the *threats*: report.ts /
 * compare.ts summarise the window, trends.ts ranks signatures, assets.ts ranks
 * internal hosts, campaigns.ts ranks attackers, rhythm.ts folds onto the clock,
 * watchlist.ts tracks named targets. None of them answer the orthogonal
 * *operational* question a SOC lead asks every morning: **of everything that
 * fired, what is still unhandled, how old is it, and have we blown our SLA on
 * any of it?**
 *
 * This module joins the stored alert history (`alertStore`) with the per-alert
 * workflow state (`triageStore`) and the dismissal set (`dismissStore`) to
 * produce a service-level view of the triage queue:
 *
 *   - the **open backlog** — alerts whose triage status is `open` or
 *     `investigating` (and which have not been dismissed), broken down by
 *     severity and by status,
 *   - **SLA breaches** — unresolved alerts whose age has exceeded the
 *     time-to-resolve target for their severity (critical 1h, high 4h,
 *     medium 24h, low 72h, info 7d by default), with the worst offenders listed
 *     so they can be actioned first,
 *   - **untouched** alerts — still `open` with no triage note at all, i.e.
 *     nobody has even looked, and
 *   - **throughput** over resolved items — mean / median time-to-resolve (MTTR)
 *     and the share of resolutions that landed inside SLA, so a team can tell
 *     whether the backlog is growing or shrinking.
 *
 * "Resolution time" for a closed alert is taken as its triage `updatedAt` minus
 * the alert timestamp — a close proxy, since `resolved` / `false-positive` are
 * terminal states and `updatedAt` advances on the status change. Dismissed
 * alerts are excluded entirely: the operator explicitly chose to hide them.
 *
 * It is pure in-memory math over the local stores — no SSH, no Claude, no
 * network — so it is safe to call from the dashboard or CLI at any time. Output
 * is both a structured model and a ready-to-paste Markdown document, mirroring
 * report.ts, compare.ts, profile.ts, assets.ts, tuning.ts, watchlist.ts and
 * rhythm.ts.
 */
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { triageStore, type TriageStatus } from "../store/triage.ts";
import { dismissStore } from "../store/dismissed.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/**
 * Default time-to-resolve targets per severity, in milliseconds. Tighter for
 * higher severities. Callers may override any subset via {@link BacklogOptions}.
 */
export const DEFAULT_SLA_MS: Record<Severity, number> = {
  critical: 1 * 3_600_000, // 1 hour
  high: 4 * 3_600_000, // 4 hours
  medium: 24 * 3_600_000, // 1 day
  low: 72 * 3_600_000, // 3 days
  info: 168 * 3_600_000, // 7 days
};

/** Severity ladder rendered most-urgent first (critical → info). */
const SEVERITY_URGENT_FIRST = [...SEVERITY_ORDER].reverse() as Severity[];

/** Statuses that mean an alert is still in the queue (counts toward backlog). */
const UNRESOLVED_STATUSES: ReadonlySet<TriageStatus> = new Set<TriageStatus>(["open", "investigating"]);
/** Statuses that mean an alert has left the queue (counts toward throughput). */
const RESOLVED_STATUSES: ReadonlySet<TriageStatus> = new Set<TriageStatus>(["resolved", "false-positive"]);

/** A single unresolved alert with its computed aging / SLA fields. */
export interface BacklogItem {
  id: string;
  time: number;
  severity: Severity;
  status: TriageStatus;
  signature?: string;
  srcIp?: string;
  dstIp?: string;
  /** Age of the alert (now − time), ms. */
  ageMs: number;
  /** SLA target for this severity, ms. */
  slaMs: number;
  /** True when {@link ageMs} exceeds {@link slaMs}. */
  breached: boolean;
  /** How far past SLA, ms (0 when within SLA). */
  overdueMs: number;
  /** `open` with zero triage notes — nobody has looked yet. */
  untouched: boolean;
}

/** Per-severity rollup of the open backlog. */
export interface SeverityBacklog {
  severity: Severity;
  /** Unresolved alerts at this severity. */
  open: number;
  /** Of {@link open}, how many have breached SLA. */
  breached: number;
  /** SLA target for this severity, ms (echoed for the rendered table). */
  slaMs: number;
  /** Age of the oldest unresolved alert at this severity, ms (0 when none). */
  oldestAgeMs: number;
}

/** Throughput stats over alerts that were resolved inside the window. */
export interface ThroughputStats {
  /** Count of resolved / false-positive alerts in the window. */
  resolved: number;
  /** Of {@link resolved}, how many closed within their SLA target. */
  withinSla: number;
  /** SLA compliance, 0–100 (share of resolutions inside target). */
  slaCompliancePct: number;
  /** Mean time-to-resolve across resolved items, ms (0 when none). */
  meanMs: number;
  /** Median time-to-resolve across resolved items, ms (0 when none). */
  medianMs: number;
}

export interface BacklogReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts considered (in-window, not dismissed). */
  totalConsidered: number;
  /** Dismissed alerts skipped inside the window. */
  dismissed: number;
  /** Total unresolved (open + investigating) alerts. */
  openTotal: number;
  /** Unresolved alerts in the `open` status specifically. */
  openCount: number;
  /** Unresolved alerts in the `investigating` status specifically. */
  investigatingCount: number;
  /** Total unresolved alerts past SLA. */
  breachedTotal: number;
  /** `open` alerts with no triage note — never looked at. */
  untouchedTotal: number;
  /** The oldest unresolved alert, or null when the queue is empty. */
  oldest: BacklogItem | null;
  /** Per-severity backlog rollup, most-urgent first. */
  bySeverity: SeverityBacklog[];
  /** Worst SLA offenders (most overdue first), capped to the report limit. */
  offenders: BacklogItem[];
  /** Resolution throughput over the window. */
  throughput: ThroughputStats;
  /** Plain-language call-outs about the queue as a whole. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface BacklogOptions {
  /** Max worst-offender rows to surface. Default 25. */
  limit?: number;
  /** Override any subset of the per-severity SLA targets (ms). */
  slaMs?: Partial<Record<Severity, number>>;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 25;

function isUnresolved(s: TriageStatus): boolean {
  return UNRESOLVED_STATUSES.has(s);
}

// ----- formatting helpers (mirror assets.ts / watchlist.ts / rhythm.ts) -----

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** Compact "Xd Yh" / "Xh Ym" / "Xm" duration for an age or SLA span. */
function fmtDur(ms: number): string {
  const totalMin = Math.max(0, Math.round(ms / 60_000));
  if (totalMin < 60) return `${totalMin}m`;
  const totalHr = Math.floor(totalMin / 60);
  const minRem = totalMin % 60;
  if (totalHr < 48) return minRem ? `${totalHr}h ${minRem}m` : `${totalHr}h`;
  const days = Math.floor(totalHr / 24);
  const hrRem = totalHr % 24;
  return hrRem ? `${days}d ${hrRem}h` : `${days}d`;
}

function shortIp(ip: string | undefined): string {
  return ip && ip.length ? ip : "·";
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

/** Truncate a signature for table display without breaking Markdown. */
function shortSig(sig: string | undefined): string {
  const s = (sig ?? "").trim();
  if (!s) return "·";
  return cell(s.length > 60 ? `${s.slice(0, 57)}…` : s);
}

function median(sorted: number[]): number {
  if (!sorted.length) return 0;
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid]! : Math.round((sorted[mid - 1]! + sorted[mid]!) / 2);
}

/** Compose the report-level highlight bullets. */
function writeHighlights(model: Omit<BacklogReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (!model.totalConsidered) return out;

  if (model.openTotal === 0) {
    out.push(`✅ Triage queue is clear — every alert in the window is resolved or dismissed.`);
  } else {
    out.push(
      `Open backlog: **${model.openTotal}** unresolved alert(s) — ${model.openCount} open, ` +
        `${model.investigatingCount} investigating.`,
    );
  }

  if (model.breachedTotal > 0) {
    const sevHit = model.bySeverity.filter((s) => s.breached > 0).map((s) => `${s.breached} ${s.severity}`);
    out.push(
      `🚨 **${model.breachedTotal}** unresolved alert(s) past SLA${sevHit.length ? ` (${sevHit.join(", ")})` : ""} — ` +
        `these are overdue for action.`,
    );
  } else if (model.openTotal > 0) {
    out.push(`No SLA breaches — every unresolved alert is still inside its time-to-resolve target.`);
  }

  if (model.untouchedTotal > 0) {
    out.push(
      `👀 ${model.untouchedTotal} open alert(s) have **no triage note** — nobody has looked at them yet; ` +
        `they should be acknowledged.`,
    );
  }

  if (model.oldest) {
    out.push(
      `Oldest unhandled: ${shortSig(model.oldest.signature)} (${model.oldest.severity}) — ` +
        `open for **${fmtDur(model.oldest.ageMs)}**${model.oldest.breached ? " ⚠️ past SLA" : ""}.`,
    );
  }

  const tp = model.throughput;
  if (tp.resolved > 0) {
    out.push(
      `Throughput: ${tp.resolved} alert(s) resolved in-window — ${tp.slaCompliancePct}% within SLA, ` +
        `median time-to-resolve ${fmtDur(tp.medianMs)} (mean ${fmtDur(tp.meanMs)}).`,
    );
  }
  return out;
}

function renderMarkdown(model: BacklogReport): string {
  const lines: string[] = [];
  lines.push(`# 📋 SecTool Triage SLA Backlog`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(model.windowEndMs)}`);
  lines.push(`**Window:** last ${model.hours} hour(s) — ${fmtTime(model.windowStartMs)} → ${fmtTime(model.windowEndMs)}`);
  lines.push(
    `**Alerts considered:** ${model.totalConsidered}` +
      (model.dismissed ? ` · **dismissed (excluded):** ${model.dismissed}` : ""),
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!model.totalConsidered) {
    lines.push(`No stored alerts in the last ${model.hours} hour(s) — nothing to triage.`);
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of model.highlights) lines.push(`- ${h}`);
  lines.push("");

  // Open backlog by severity — the at-a-glance triage queue.
  lines.push(`## Open backlog by severity`);
  lines.push("");
  lines.push(
    mdTable(
      ["Severity", "Open", "Past SLA", "SLA target", "Oldest open"],
      model.bySeverity
        .filter((s) => s.open > 0)
        .map((s) => [
          cell(s.severity),
          String(s.open),
          s.breached ? `⚠️ ${s.breached}` : "·",
          fmtDur(s.slaMs),
          s.oldestAgeMs ? fmtDur(s.oldestAgeMs) : "·",
        ]),
    ),
  );
  lines.push("");

  // Aging queue, most-overdue first — what to action now (breaches lead).
  lines.push(`## Oldest unresolved (most overdue first)`);
  lines.push("");
  if (!model.offenders.length) {
    lines.push(`_The triage queue is clear — no unresolved alerts._`);
  } else {
    lines.push(
      mdTable(
        ["Age", "Overdue by", "Sev", "Status", "Signature", "Src → Dst", "First seen"],
        model.offenders.map((o) => [
          fmtDur(o.ageMs),
          o.breached ? fmtDur(o.overdueMs) : "·",
          cell(o.severity),
          cell(o.untouched ? `${o.status} (untouched)` : o.status),
          shortSig(o.signature),
          `${shortIp(o.srcIp)} → ${shortIp(o.dstIp)}`,
          fmtTime(o.time),
        ]),
      ),
    );
  }
  lines.push("");

  // Resolution throughput — is the backlog shrinking?
  lines.push(`## Resolution throughput`);
  lines.push("");
  const tp = model.throughput;
  if (!tp.resolved) {
    lines.push(`_No alerts were resolved in this window._`);
  } else {
    lines.push(
      mdTable(
        ["Resolved", "Within SLA", "SLA compliance", "Median TTR", "Mean TTR"],
        [
          [
            String(tp.resolved),
            String(tp.withinSla),
            `${tp.slaCompliancePct}%`,
            fmtDur(tp.medianMs),
            fmtDur(tp.meanMs),
          ],
        ],
      ),
    );
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from ${model.totalConsidered} stored alert(s). ` +
      `"Unresolved" = triage status open or investigating and not dismissed. SLA targets: ` +
      `${SEVERITY_URGENT_FIRST.map((s) => `${s} ${fmtDur(model.bySeverity.find((b) => b.severity === s)!.slaMs)}`).join(", ")}. ` +
      `Resolution time is the triage update minus the alert time. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the triage SLA backlog report from the local stores.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]). Defaults via
 *              the CLI/API to a wide window (30 days) so genuinely stale,
 *              long-unhandled alerts still surface — the whole point of a backlog.
 * @param opts  Optional limit, SLA overrides, and a pinned `nowMs` for tests.
 */
export function buildBacklog(hours: number, opts: BacklogOptions = {}): BacklogReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(500, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const nowMs = opts.nowMs ?? Date.now();
  const windowEndMs = nowMs;
  const windowStartMs = windowEndMs - safeHours * 3_600_000;
  const sla: Record<Severity, number> = { ...DEFAULT_SLA_MS, ...(opts.slaMs ?? {}) };

  const inWindow: StoredAlert[] = alertStore
    .all()
    .filter((a) => typeof a.time === "number" && a.time >= windowStartMs && a.time <= windowEndMs);

  // Per-severity accumulators, seeded so the ladder always renders in order.
  const sevAgg = new Map<Severity, SeverityBacklog>(
    SEVERITY_URGENT_FIRST.map((severity): [Severity, SeverityBacklog] => [
      severity,
      { severity, open: 0, breached: 0, slaMs: sla[severity], oldestAgeMs: 0 },
    ]),
  );

  const openItems: BacklogItem[] = [];
  const resolveDurations: number[] = [];

  let totalConsidered = 0;
  let dismissed = 0;
  let openCount = 0;
  let investigatingCount = 0;
  let breachedTotal = 0;
  let untouchedTotal = 0;
  let resolvedCount = 0;
  let withinSla = 0;

  for (const a of inWindow) {
    if (dismissStore.has(a.id)) {
      dismissed++;
      continue;
    }
    totalConsidered++;

    const severity = (SEVERITY_ORDER as readonly string[]).includes(a.severity)
      ? (a.severity as Severity)
      : "info";
    const triage = triageStore.get(a.id);
    const status: TriageStatus = triage?.status ?? "open";
    const slaMs = sla[severity];

    if (isUnresolved(status)) {
      const ageMs = Math.max(0, windowEndMs - a.time);
      const breached = ageMs > slaMs;
      const overdueMs = breached ? ageMs - slaMs : 0;
      const untouched = status === "open" && (triage?.notes.length ?? 0) === 0;

      const item: BacklogItem = {
        id: a.id,
        time: a.time,
        severity,
        status,
        signature: a.signature,
        srcIp: a.srcIp,
        dstIp: a.dstIp,
        ageMs,
        slaMs,
        breached,
        overdueMs,
        untouched,
      };
      openItems.push(item);

      if (status === "open") openCount++;
      else investigatingCount++;
      if (breached) breachedTotal++;
      if (untouched) untouchedTotal++;

      const bucket = sevAgg.get(severity)!;
      bucket.open++;
      if (breached) bucket.breached++;
      if (ageMs > bucket.oldestAgeMs) bucket.oldestAgeMs = ageMs;
    } else if (RESOLVED_STATUSES.has(status)) {
      resolvedCount++;
      // Resolution time = last triage update − alert time (terminal state proxy).
      const dur = (triage?.updatedAt ?? 0) - a.time;
      if (dur > 0) {
        resolveDurations.push(dur);
        if (dur <= slaMs) withinSla++;
      }
    }
  }

  // Oldest-first / most-overdue-first ordering for offenders. Breached items sort
  // ahead of within-SLA ones (by overdue), then everything by raw age.
  const offenders = [...openItems]
    .sort((a, b) => b.overdueMs - a.overdueMs || b.ageMs - a.ageMs)
    .slice(0, limit);

  const oldest = openItems.reduce<BacklogItem | null>(
    (best, it) => (!best || it.ageMs > best.ageMs ? it : best),
    null,
  );

  const sortedDur = [...resolveDurations].sort((a, b) => a - b);
  const meanMs = sortedDur.length ? Math.round(sortedDur.reduce((n, d) => n + d, 0) / sortedDur.length) : 0;
  const throughput: ThroughputStats = {
    resolved: resolvedCount,
    withinSla,
    slaCompliancePct: resolvedCount ? Math.round((withinSla / resolvedCount) * 100) : 0,
    meanMs,
    medianMs: median(sortedDur),
  };

  const base: Omit<BacklogReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalConsidered,
    dismissed,
    openTotal: openItems.length,
    openCount,
    investigatingCount,
    breachedTotal,
    untouchedTotal,
    oldest,
    bySeverity: SEVERITY_URGENT_FIRST.map((s) => sevAgg.get(s)!),
    offenders,
    throughput,
  };
  const highlights = writeHighlights(base);
  const model: BacklogReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded triage backlog report. */
export function backlogFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-backlog-${stamp}.md`;
}
