/**
 * Severity-escalation / trajectory report — "which attackers are *getting worse*
 * right now, and which are winding down?"
 *
 * Every other offline report in this project treats a source IP's activity as a
 * single static lump: persistence measures *how long* it has been around, surge
 * measures *when the volume spiked*, risk measures the *severity-weighted
 * magnitude* it carries, focus measures *how concentrated* the landscape is. None
 * of them ask the one question that separates a probe from an incident:
 *
 *   **"Is this actor's severity *rising over its own timeline*?"**
 *
 * That trajectory is the sharpest early-warning signal a responder has. An actor
 * that opens with low-severity recon (port scans, info probes) and then escalates
 * to high/critical signatures is following the textbook intrusion arc — recon →
 * exploitation — and is the single most important thing to act on *before* the
 * critical alert lands. A static "top sources by count / weight" ranking hides
 * this completely: a source that fired 50 `info` hits and one `critical` looks the
 * same as one that fired 51 steady `info` hits, yet the first is an escalation and
 * the second is just noise.
 *
 * For every source IP with enough alerts to have a trajectory, this report splits
 * that source's *own* alert timeline into a front half and a back half (by count,
 * so both halves always have data and equal weight), then compares the two:
 *
 *   - **earlier vs later mean severity weight** — using the same geometric
 *     severity ladder as the risk report ({@link SEVERITY_WEIGHT}: info 1 · low 3
 *     · medium 9 · high 27 · critical 81), so a single step up the ladder is a
 *     ~3× jump and the critical tail is not under-weighted.
 *   - **earlier peak → later peak severity band** — the worst band seen in each
 *     half, the most legible "where it started → where it is now".
 *   - a **ratio** (later mean / earlier mean) and **delta** that drive a verdict:
 *       - `escalating`      — severity is climbing (ratio ≥ 2) *and* the back half
 *                             reached medium-or-worse: the priority case.
 *       - `sustained-high`  — not climbing, but both halves already carry
 *                             medium-or-worse weight: a persistently serious actor.
 *       - `de-escalating`   — severity is falling (ratio ≤ ½): winding down, or a
 *                             mitigation is working — confirm, don't celebrate.
 *       - `steady`          — flat trajectory.
 *
 * Escalating and sustained-high sources are ranked by an **escalation score**
 * (`delta × √count`) that rewards both the size of the jump and the sample support
 * behind it, so a big jump backed by many alerts outranks a fluke two-alert swing.
 * Sources are cross-referenced against the blocklist / watchlist / safelist (like
 * focus.ts / persistence.ts / risk.ts) so the headline can note how many of the
 * escalating actors are *already* contained.
 *
 * Honest caveats baked into the output:
 *
 *   - **Trajectory ≠ certainty.** A back-half severity spike can be one noisy
 *     rule, not a real escalation; pair this with the tuning / classify reports
 *     before acting, and read the per-source bands, not just the verdict.
 *   - **Severity is the gateway's.** A mis-graded alert moves the trajectory the
 *     wrong way. Garbage in, mis-trended out.
 *   - **Alerts, not flows.** A source that escalates entirely below the IPS's
 *     detection threshold is invisible here; a flat trajectory is not a safe one.
 *   - **Window-bounded & store-capped.** A long look-back can hit the store's
 *     history cap and clip a source's earliest alerts, distorting its front half.
 *
 * Pure in-memory math over alertStore (plus blocklist/watchlist/safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring report.ts, risk.ts,
 * focus.ts, persistence.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";

/**
 * Categorical read of a source's severity trajectory, in descending priority:
 *
 *   - `escalating`     — severity climbing and the back half reached medium+,
 *   - `sustained-high` — already serious in both halves, not climbing,
 *   - `steady`         — flat,
 *   - `de-escalating`  — severity falling over the source's own timeline.
 */
export type TrajectoryVerdict = "escalating" | "sustained-high" | "steady" | "de-escalating";

/** Per-source severity trajectory across the window. */
export interface SourceTrajectory {
  /** The source IP. */
  source: string;
  /** Total windowed alerts attributed to this source. */
  alerts: number;
  /** First / last alert time for this source inside the window (ms epoch). */
  firstSeenMs: number;
  lastSeenMs: number;
  /** Alerts in the front / back half of the source's own timeline. */
  earlierCount: number;
  laterCount: number;
  /** Mean severity weight of the front / back half (2dp). */
  earlierMean: number;
  laterMean: number;
  /** later mean − earlier mean (2dp). Positive = escalating. */
  delta: number;
  /** later mean / earlier mean (2dp). >1 = escalating, <1 = de-escalating. */
  ratio: number;
  /** Worst severity band seen in the front / back half. */
  earlierPeak: Severity;
  laterPeak: Severity;
  /** Worst severity band seen across the whole window for this source. */
  peak: Severity;
  /** Categorical trajectory verdict (see {@link TrajectoryVerdict}). */
  verdict: TrajectoryVerdict;
  /** Ranking score: delta × √count (2dp). Higher = more urgent escalation. */
  score: number;
  /** Source is on the blocklist. */
  blocked: boolean;
  /** Source is on the watchlist. */
  watched: boolean;
  /** Source is marked safe. */
  safe: boolean;
}

export interface EscalationReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Distinct source IPs that met the minimum-alert bar and were measured. */
  measuredSources: number;
  /** Distinct source IPs seen but below the minimum-alert bar (no trajectory). */
  skippedSources: number;
  /** Minimum alerts a source needed to be measured. */
  minAlerts: number;
  /** Count of measured sources per verdict. */
  counts: Record<TrajectoryVerdict, number>;
  /** All measured trajectories, sorted by priority then score. */
  trajectories: SourceTrajectory[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface EscalationOptions {
  /** Max rows per table (clamped to [1, 100]). */
  limit?: number;
  /** Minimum alerts a source needs to be measured (clamped to [2, 1000]). */
  minAlerts?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 15;
const DEFAULT_MIN_ALERTS = 4;
const MS_PER_HOUR = 3_600_000;
/** Ratio of later/earlier mean weight at/above which a source is "escalating". */
const ESCALATE_RATIO = 2.0;
/** Ratio at/below which a source is "de-escalating". */
const DEESCALATE_RATIO = 0.5;
/** Severity band (and above) that counts as "serious" for escalation/sustained. */
const SERIOUS_INDEX = SEVERITY_ORDER.indexOf("medium");

/** Priority order for sorting/grouping verdicts (lower = more urgent). */
const VERDICT_RANK: Record<TrajectoryVerdict, number> = {
  escalating: 0,
  "sustained-high": 1,
  steady: 2,
  "de-escalating": 3,
};

// ----- formatting helpers (mirror focus.ts / risk.ts / persistence.ts) -----

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
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

// ----- severity helpers ----------------------------------------------------

/** Normalise a stored severity string onto the ladder; unknown → "info". */
function normSeverity(raw: string | undefined): Severity {
  const s = (raw ?? "").trim().toLowerCase();
  return (SEVERITY_ORDER as readonly string[]).includes(s) ? (s as Severity) : "info";
}

/** The more severe of two bands (by ladder index). */
function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b) ? a : b;
}

function meanWeight(sevs: Severity[]): number {
  if (!sevs.length) return 0;
  const sum = sevs.reduce((s, sev) => s + SEVERITY_WEIGHT[sev], 0);
  return sum / sevs.length;
}

function peakSeverity(sevs: Severity[]): Severity {
  return sevs.reduce<Severity>((acc, s) => maxSeverity(acc, s), "info");
}

/** A short glyph + word for a verdict, used in tables and the legend. */
function verdictLabel(v: TrajectoryVerdict): string {
  switch (v) {
    case "escalating":
      return "▲ escalating";
    case "sustained-high":
      return "■ sustained-high";
    case "steady":
      return "▬ steady";
    default:
      return "▼ de-escalating";
  }
}

// ----- trajectory math -----------------------------------------------------

/**
 * Classify a source's trajectory from the later/earlier mean-weight ratio and the
 * worst band reached in each half. Heuristic and intentionally conservative — the
 * raw means, ratio and bands are always shown so the operator can overrule it.
 */
function classify(ratio: number, earlierPeak: Severity, laterPeak: Severity): TrajectoryVerdict {
  const laterSerious = SEVERITY_ORDER.indexOf(laterPeak) >= SERIOUS_INDEX;
  const earlierSerious = SEVERITY_ORDER.indexOf(earlierPeak) >= SERIOUS_INDEX;
  if (ratio >= ESCALATE_RATIO && laterSerious) return "escalating";
  if (ratio <= DEESCALATE_RATIO) return "de-escalating";
  // Not climbing/falling sharply: serious in both halves → persistently serious.
  if (earlierSerious && laterSerious) return "sustained-high";
  return "steady";
}

/**
 * Build a per-source trajectory by splitting its time-sorted alerts into a front
 * and back half *by count* (so both halves are non-empty and equally weighted),
 * then comparing the severity carried by each half.
 */
function buildTrajectory(source: string, alerts: StoredAlert[]): SourceTrajectory {
  const sorted = [...alerts].sort((a, b) => a.time - b.time);
  const sevs = sorted.map((a) => normSeverity(a.severity));
  const n = sorted.length;
  const split = Math.floor(n / 2); // front half gets the floor; back half the rest

  const earlierSevs = sevs.slice(0, split);
  const laterSevs = sevs.slice(split);

  const earlierMean = round2(meanWeight(earlierSevs));
  const laterMean = round2(meanWeight(laterSevs));
  const earlierPeak = peakSeverity(earlierSevs);
  const laterPeak = peakSeverity(laterSevs);
  // earlierMean is ≥1 (min weight is info=1) whenever the half is non-empty, so
  // the ratio is always well-defined here (split ≥1 for n≥2).
  const ratio = round2(earlierMean > 0 ? laterMean / earlierMean : 1);
  const delta = round2(laterMean - earlierMean);
  const verdict = classify(ratio, earlierPeak, laterPeak);
  // Score rewards both the size of the jump and the sample backing it; floored at
  // 0 so de-escalating/steady sources don't outrank escalating ones by sign.
  const score = round2(Math.max(0, delta) * Math.sqrt(n));

  return {
    source,
    alerts: n,
    firstSeenMs: sorted[0]!.time,
    lastSeenMs: sorted[n - 1]!.time,
    earlierCount: earlierSevs.length,
    laterCount: laterSevs.length,
    earlierMean,
    laterMean,
    delta,
    ratio,
    earlierPeak,
    laterPeak,
    peak: maxSeverity(earlierPeak, laterPeak),
    verdict,
    score,
    blocked: blockStore.has(source),
    watched: watchStore.has(source),
    safe: safeStore.has(source),
  };
}

// ----- highlights ----------------------------------------------------------

function writeHighlights(
  hours: number,
  report: Pick<
    EscalationReport,
    "totalWindowAlerts" | "measuredSources" | "counts" | "trajectories"
  >,
): string[] {
  const out: string[] = [];
  if (!report.totalWindowAlerts) return out;
  if (!report.measuredSources) {
    out.push(
      `No source IP had at least the minimum number of alerts needed to measure a trajectory over the last ` +
        `${hours}h — nothing to trend. Lower \`--min\` or widen the window if you expected escalation here.`,
    );
    return out;
  }

  const { counts } = report;
  const escalating = report.trajectories.filter((t) => t.verdict === "escalating");
  const sustained = report.trajectories.filter((t) => t.verdict === "sustained-high");

  // Headline shape across all measured sources.
  out.push(
    `📈 Of ${report.measuredSources} measured source(s) over the last ${hours}h: ` +
      `${counts.escalating} escalating, ${counts["sustained-high"]} sustained-high, ` +
      `${counts.steady} steady, ${counts["de-escalating"]} de-escalating.`,
  );

  // The priority case — escalating actors, ranked.
  if (escalating.length) {
    const lead = escalating[0]!;
    const contained = escalating.filter((t) => t.blocked).length;
    const note = contained
      ? ` ${contained} of them ${contained === 1 ? "is" : "are"} already blocked.`
      : ` None are blocked yet.`;
    out.push(
      `🚨 **${escalating.length} source(s) are escalating** — severity is climbing over their own timeline. ` +
        `Worst: \`${lead.source}\` went ${lead.earlierPeak} → ${lead.laterPeak} ` +
        `(mean weight ${lead.earlierMean} → ${lead.laterMean}, ${lead.ratio}× over ${lead.alerts} alerts).` +
        note +
        ` This is the recon→exploitation arc; act before the next step lands.`,
    );
  } else {
    out.push(
      `✅ No source is escalating this window — no actor's severity is climbing toward medium-or-worse over its ` +
        `own timeline. (A flat trajectory is not a clean network; see the caveats.)`,
    );
  }

  // Sustained-high — already serious throughout.
  if (sustained.length) {
    const lead = sustained[0]!;
    out.push(
      `🔥 **${sustained.length} source(s) are sustained-high** — already carrying medium-or-worse severity across ` +
        `their whole window (not climbing, but not stopping). Worst: \`${lead.source}\` (peak ${lead.peak}, ` +
        `${lead.alerts} alerts). Treat as active, not emerging.`,
    );
  }

  // De-escalation is good news worth surfacing (mitigation may be working).
  if (counts["de-escalating"] > 0) {
    out.push(
      `📉 ${counts["de-escalating"]} source(s) are de-escalating — severity falling over their timeline. ` +
        `That can mean a mitigation is biting or the actor moved on; confirm the drop is real, don't assume safety.`,
    );
  }

  return out;
}

// ----- markdown ------------------------------------------------------------

function summaryTable(counts: Record<TrajectoryVerdict, number>): string {
  const order: TrajectoryVerdict[] = ["escalating", "sustained-high", "steady", "de-escalating"];
  return mdTable(
    ["Trajectory", "Sources"],
    order.map((v) => [verdictLabel(v), String(counts[v])]),
  );
}

function trajectoryTable(rows: SourceTrajectory[]): string {
  return mdTable(
    ["#", "Source", "Trajectory", "Alerts", "Sev (early→late)", "Mean wt (early→late)", "Ratio", "Score", "Flags"],
    rows.map((t, i) => {
      const flags = (t.blocked ? "⛔" : "") + (t.watched ? "👁" : "") + (t.safe ? "✅" : "");
      return [
        String(i + 1),
        cell(t.source),
        verdictLabel(t.verdict),
        String(t.alerts),
        `${t.earlierPeak} → ${t.laterPeak}`,
        `${t.earlierMean} → ${t.laterMean}`,
        `${t.ratio}×`,
        String(t.score),
        flags || "—",
      ];
    }),
  );
}

function renderMarkdown(m: EscalationReport, limit: number): string {
  const lines: string[] = [];
  lines.push(`# 📈 SecTool Severity-Escalation / Trajectory Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** per-source front-half vs back-half severity comparison (geometric severity weights, ` +
      `split by alert count) over stored IPS alerts · **Window alerts:** ${m.totalWindowAlerts} · ` +
      `**Measured sources:** ${m.measuredSources} (≥${m.minAlerts} alerts) · **Skipped:** ${m.skippedSources}`,
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

  if (m.measuredSources) {
    lines.push(`## Trajectory mix`);
    lines.push("");
    lines.push(summaryTable(m.counts));
    lines.push("");
    lines.push(
      `**Legend:** \`▲ escalating\` (severity climbing ≥${ESCALATE_RATIO}× and the back half reached ` +
        `medium-or-worse — the priority case), \`■ sustained-high\` (already serious in both halves, not climbing), ` +
        `\`▬ steady\` (flat), \`▼ de-escalating\` (severity falling ≤${DEESCALATE_RATIO}×). ` +
        `_Mean wt_ uses the geometric severity ladder (info 1 · low 3 · medium 9 · high 27 · critical 81). ` +
        `_Score_ = delta × √alerts — ranks escalating actors by jump size *and* sample support. ` +
        `_Flags_: ⛔ blocked · 👁 watchlist · ✅ safelisted.`,
    );
    lines.push("");

    // Priority table — escalating + sustained-high, already sorted by priority/score.
    const priority = m.trajectories.filter(
      (t) => t.verdict === "escalating" || t.verdict === "sustained-high",
    );
    lines.push(`## Escalating & sustained-high sources`);
    lines.push("");
    if (priority.length) {
      lines.push(trajectoryTable(priority.slice(0, limit)));
      if (priority.length > limit) {
        lines.push("");
        lines.push(`_…and ${priority.length - limit} more not shown (raise \`--limit\`)._`);
      }
    } else {
      lines.push(`_No escalating or sustained-high sources this window._`);
    }
    lines.push("");

    // Full ledger — every measured source, priority then score order.
    lines.push(`## All measured trajectories`);
    lines.push("");
    lines.push(trajectoryTable(m.trajectories.slice(0, limit)));
    if (m.trajectories.length > limit) {
      lines.push("");
      lines.push(`_…and ${m.trajectories.length - limit} more not shown (raise \`--limit\`)._`);
    }
    lines.push("");
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from stored **IPS-alert** severities. A trajectory is computed only for sources ` +
      `with ≥${m.minAlerts} alerts (split into equal-count front/back halves); it describes how a source's *own* ` +
      `severity moved over the window, not absolute risk — pair it with the risk / classify / tuning reports before ` +
      `acting, since a back-half spike can be one noisy rule. Severity is the gateway's grade, so a mis-graded alert ` +
      `trends the wrong way; a source escalating below the IPS detection threshold is invisible here; and a long ` +
      `look-back can hit the store's history cap and clip a source's earliest alerts. No live gateway query was ` +
      `performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the severity-escalation / trajectory report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link EscalationOptions}: `limit` (rows per table), `minAlerts`
 *              (measurement bar) and a `nowMs` pin for deterministic tests.
 */
export function buildEscalation(hours: number, opts: EscalationOptions = {}): EscalationReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(100, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minAlerts = Math.max(2, Math.min(1000, Math.floor(opts.minAlerts ?? DEFAULT_MIN_ALERTS)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  // Group by valid source IP.
  const bySource = new Map<string, StoredAlert[]>();
  for (const a of windowed) {
    const ip = a.srcIp;
    if (!ip || isIP(ip) === 0) continue;
    const arr = bySource.get(ip);
    if (arr) arr.push(a);
    else bySource.set(ip, [a]);
  }

  let skippedSources = 0;
  const trajectories: SourceTrajectory[] = [];
  for (const [source, alerts] of bySource) {
    if (alerts.length < minAlerts) {
      skippedSources++;
      continue;
    }
    trajectories.push(buildTrajectory(source, alerts));
  }

  // Priority first (escalating → sustained → steady → de-escalating), then by
  // escalation score, then by raw volume, then by IP for a stable order.
  trajectories.sort(
    (a, b) =>
      VERDICT_RANK[a.verdict] - VERDICT_RANK[b.verdict] ||
      b.score - a.score ||
      b.alerts - a.alerts ||
      (a.source < b.source ? -1 : 1),
  );

  const counts: Record<TrajectoryVerdict, number> = {
    escalating: 0,
    "sustained-high": 0,
    steady: 0,
    "de-escalating": 0,
  };
  for (const t of trajectories) counts[t.verdict]++;

  const model: EscalationReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    measuredSources: trajectories.length,
    skippedSources,
    minAlerts,
    counts,
    trajectories,
    highlights: [],
    markdown: "",
  };
  model.highlights = writeHighlights(safeHours, model);
  model.markdown = renderMarkdown(model, limit);
  return model;
}

/** A filesystem-safe filename for a downloaded severity-escalation report. */
export function escalationFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-escalation-${stamp}.md`;
}
