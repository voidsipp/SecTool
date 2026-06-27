/**
 * Detection-to-mitigation latency / Mean-Time-To-Block (MTTB) report — "once an
 * attacker first showed up in my logs, *how long* did it take me to actually
 * block them, and how much damage landed during that exposure window?"
 *
 * Every blocklist entry carries a *block timestamp* (`BlockEntry.at`, stamped
 * when the IP was added via the responder or the dashboard). The companion
 * **recidivism.ts** report reads that timestamp to ask the *post*-block question
 * ("after I blocked it, did the traffic stop?"). This report reads the very same
 * timestamp to ask the opposite, *pre*-block question — the one no other report
 * in this project answers:
 *
 *   - **recidivism.ts** splits each blocked source's alerts on the block time and
 *     grades what happened *after* (clean / stubborn / leaking). It deliberately
 *     keeps pre-block alerts only "for context" and never measures the *gap*
 *     between first sighting and the block, nor the damage accrued inside it.
 *   - **efficacy.ts / risk.ts** score the gateway's per-alert disposition across
 *     the whole stream; they have no notion of *our* enforcement actions or when
 *     they landed, so they can't tell a five-minute containment from a five-day
 *     one.
 *   - **hygiene.ts** decides which blocks to *keep vs prune* (staleness); it
 *     looks forward from the block, never backward to how slow the block was.
 *
 * Detection-to-mitigation latency is the single most actionable measure of a
 * defensive pipeline's *responsiveness*. Two SOCs can block the exact same set
 * of attackers and have wildly different real-world exposure depending on how
 * fast each block landed. MTTB is to blocking what MTTR is to incident response.
 *
 * For every IP on the blocklist whose block landed inside the window this report:
 *
 *   - scans the **entire** stored alert history (not just the window) for that
 *     `srcIp` — we must reach back past the window to find the attacker's *first*
 *     sighting, which is what the block latency is measured from;
 *   - finds the first pre-block alert (`time <= at`) and computes
 *     **latency = at − firstAlert** — the detection-to-mitigation gap;
 *   - folds the pre-block alerts into a damage profile: total count, severe
 *     count, worst severity, a severity-weighted exposure score, and — the
 *     sharpest signal — how many of those lead-up alerts the gateway *let through*
 *     (`passed`), i.e. attack traffic that actually reached a service before the
 *     block existed;
 *   - assigns a responsiveness **grade** from the latency against two tunable
 *     thresholds:
 *       - **🟢 fast**     — latency ≤ fast threshold (default 5 min). Containment
 *         was effectively immediate; little or nothing landed.
 *       - **🟡 moderate** — latency ≤ slow threshold (default 60 min).
 *       - **🔴 slow**     — latency > slow threshold. The source attacked us for a
 *         meaningful stretch before being contained; if anything passed in that
 *         window, that exposure was real, not theoretical.
 *       - **⚪ no-lead-up** — the block has *no* pre-block alert in the store. It
 *         was placed proactively (manual / threat-intel / a reactive rule firing
 *         on the very first packet) or the source's early history has aged out of
 *         the capped store. Latency is unknowable and these are reported
 *         separately rather than scored as "instant" (which would flatter the
 *         MTTB).
 *
 * Sources are ranked **slowest-latency first** — for a responsiveness report the
 * biggest gaps are the finding; a fast block is the desired, unremarkable case.
 *
 * Honest caveats baked into the output:
 *
 *   - **Store-capped lower bound.** The alert store retains a finite, rotating
 *     history. For an old block the earliest *retained* alert may post-date the
 *     attacker's true first packet, so the measured latency is a **lower bound**
 *     (real containment was slower than shown).
 *   - **Alerts, not flows.** SecTool stores IPS *detections*. An attacker active
 *     before tripping any rule is invisible, so "first sighting" is first
 *     *detected* activity, not first contact.
 *   - **Source-side match.** Alerts are attributed to a blocked IP by `srcIp`
 *     (blocks target attacker sources), mirroring recidivism.ts.
 *   - **Block-time trust.** Latency is only as accurate as `BlockEntry.at`; a
 *     re-imported or hand-edited blocklist can carry an approximate stamp.
 *
 * Pure in-memory math over alertStore + blocklist (plus watchlist / safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring report.ts, scan.ts,
 * recidivism.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore, type BlockEntry } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Responsiveness grade for a single block (see file header). */
export type MttbGrade = "fast" | "moderate" | "slow" | "no-lead-up";

/** Blocked / passed / unknown disposition split for a source's lead-up alerts. */
export interface DispositionSplit {
  /** Lead-up alerts the gateway actively blocked / dropped. */
  blocked: number;
  /** Lead-up alerts the gateway logged but let through (reached a service). */
  passed: number;
  /** Lead-up alerts with no recorded action. */
  unknown: number;
}

/** Per-block detection-to-mitigation row. */
export interface MttbSource {
  /** The blocked source IP. */
  ip: string;
  /** Responsiveness grade derived from the latency. */
  grade: MttbGrade;
  /** When the block was applied (`BlockEntry.at`). */
  blockedAt: number;
  /** Why the block was applied, if recorded. */
  reason?: string;
  /** Who/what applied the block (responder, dashboard user, …), if recorded. */
  by?: string;
  /** First pre-block alert time for this source in the store, if any. */
  firstAlertMs?: number;
  /** Last pre-block alert time for this source in the store, if any. */
  lastPreBlockMs?: number;
  /**
   * Detection-to-mitigation latency in ms (`blockedAt − firstAlertMs`), or null
   * when there is no observed lead-up (grade "no-lead-up").
   */
  latencyMs: number | null;
  /** Total pre-block (`time <= at`) alerts for this source in the store. */
  preBlockAlerts: number;
  /** Of those, alerts at medium severity or worse. */
  preBlockSevere: number;
  /** Severity-weighted exposure score over the lead-up (Σ SEVERITY_WEIGHT). */
  exposureScore: number;
  /** Worst severity seen in the lead-up. */
  severityMax: Severity;
  /** Blocked / passed / unknown split of the lead-up alerts. */
  disposition: DispositionSplit;
  /** True when the source is one of our own hosts (RFC1918 / loopback / …). */
  internal: boolean;
  /** The source is also on the watchlist. */
  watched: boolean;
  /** The source is also marked safe (a safe IP we nonetheless blocked — odd). */
  safe: boolean;
}

/** Distribution of blocks across the four responsiveness grades. */
export interface GradeCounts {
  fast: number;
  moderate: number;
  slow: number;
  "no-lead-up": number;
}

export interface MttbReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Fast-grade latency ceiling used (ms). */
  fastThresholdMs: number;
  /** Slow-grade latency floor used (ms). */
  slowThresholdMs: number;
  /** Total IPs currently on the blocklist. */
  totalBlocks: number;
  /** Blocks whose `at` falls inside the window (the graded set). */
  windowBlocks: number;
  /** Of those, blocks with an observed pre-block lead-up (latency measurable). */
  gradedBlocks: number;
  /** Blocks with no observed lead-up (latency unknowable). */
  noLeadUpBlocks: number;
  /** Mean latency over graded blocks (ms), or null when none. */
  meanLatencyMs: number | null;
  /** Median latency over graded blocks (ms), or null when none. */
  medianLatencyMs: number | null;
  /** Fastest measured latency (ms), or null when none. */
  minLatencyMs: number | null;
  /** Slowest measured latency (ms), or null when none. */
  maxLatencyMs: number | null;
  /** Total lead-up alerts the gateway let through before any block landed. */
  totalLeakedBeforeBlock: number;
  /** How many graded/ungraded blocks fell into each grade. */
  gradeCounts: GradeCounts;
  /** Per-block rows, slowest latency first. */
  sources: MttbSource[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface MttbOptions {
  /** Max rows in the per-block table (clamped to [1, 500]). */
  limit?: number;
  /** Latency at/below which a block is "fast", in minutes (≥0; default 5). */
  fastMins?: number;
  /** Latency above which a block is "slow", in minutes (>fast; default 60). */
  slowMins?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 50;
const DEFAULT_FAST_MINS = 5;
const DEFAULT_SLOW_MINS = 60;
const MS_PER_HOUR = 3_600_000;
const MS_PER_MIN = 60_000;

// ----- classifiers / helpers (mirror scan.ts / recidivism.ts) ---------------

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

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? (b as Severity) : a;
}

function isSevere(s: string | undefined): boolean {
  return sevRank(s) >= 2; // medium or worse
}

function weightOf(s: string | undefined): number {
  return SEVERITY_WEIGHT[(s as Severity) ?? "info"] ?? SEVERITY_WEIGHT.info;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** Human-friendly duration: "3s", "12m", "4h 20m", "2d 6h". */
function fmtDuration(ms: number): string {
  if (ms < 0) ms = 0;
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.round(ms / MS_PER_MIN);
  if (m < 60) return `${m}m`;
  const totalMin = Math.round(ms / MS_PER_MIN);
  const h = Math.floor(totalMin / 60);
  if (h < 24) {
    const rm = totalMin % 60;
    return rm ? `${h}h ${rm}m` : `${h}h`;
  }
  const d = Math.floor(h / 24);
  const rh = h % 24;
  return rh ? `${d}d ${rh}h` : `${d}d`;
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

/** Median of a numeric list (returns null for empty). */
function median(values: number[]): number | null {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid]! : Math.round((sorted[mid - 1]! + sorted[mid]!) / 2);
}

/** Human label for a grade, with an emoji that reads at a glance. */
function gradeLabel(g: MttbGrade): string {
  switch (g) {
    case "fast":
      return "🟢 fast";
    case "moderate":
      return "🟡 moderate";
    case "slow":
      return "🔴 slow";
    case "no-lead-up":
      return "⚪ no-lead-up";
  }
}

/** Classify the latency into a responsiveness grade. */
function classifyGrade(latencyMs: number | null, fastMs: number, slowMs: number): MttbGrade {
  if (latencyMs === null) return "no-lead-up";
  if (latencyMs <= fastMs) return "fast";
  if (latencyMs <= slowMs) return "moderate";
  return "slow";
}

// ----- aggregation ----------------------------------------------------------

interface SourceAcc {
  preBlock: number;
  severe: number;
  exposureScore: number;
  blocked: number;
  passed: number;
  unknown: number;
  firstAlertMs?: number;
  lastPreBlockMs?: number;
  severityMax: Severity;
}

function newSourceAcc(): SourceAcc {
  return {
    preBlock: 0,
    severe: 0,
    exposureScore: 0,
    blocked: 0,
    passed: 0,
    unknown: 0,
    severityMax: "info",
  };
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  m: {
    windowBlocks: number;
    gradedBlocks: number;
    noLeadUpBlocks: number;
    meanLatencyMs: number | null;
    medianLatencyMs: number | null;
    totalLeakedBeforeBlock: number;
  },
  gradeCounts: GradeCounts,
  sources: MttbSource[],
): string[] {
  const out: string[] = [];
  if (!m.windowBlocks) return out;

  // Headline MTTB across all graded blocks.
  if (m.gradedBlocks > 0 && m.meanLatencyMs !== null) {
    out.push(
      `⏱️ Over the last ${hours}h, **${m.windowBlocks} block(s)** were applied; **MTTB (mean time to block) is ` +
        `${fmtDuration(m.meanLatencyMs)}** (median ${fmtDuration(m.medianLatencyMs ?? 0)}) across the ` +
        `${m.gradedBlocks} with an observed lead-up. Grades: ${gradeCounts.fast} fast · ` +
        `${gradeCounts.moderate} moderate · ${gradeCounts.slow} slow.`,
    );
  } else {
    out.push(
      `⏱️ Over the last ${hours}h, **${m.windowBlocks} block(s)** were applied, but none had a pre-block alert in ` +
        `the store to measure latency from — all were proactive blocks or their lead-up has aged out.`,
    );
  }

  // The slowest containment — the biggest operational gap.
  const slowest = sources.find((s) => s.latencyMs !== null);
  if (slowest && slowest.latencyMs !== null) {
    out.push(
      `🐢 Slowest containment: \`${slowest.ip}\`${slowest.internal ? " *(internal!)*" : ""} attacked for ` +
        `**${fmtDuration(slowest.latencyMs)}** before being blocked — ${slowest.preBlockAlerts} lead-up alert(s) ` +
        `(${slowest.preBlockSevere} severe, worst ${slowest.severityMax}), ${slowest.disposition.passed} let ` +
        `through. First seen ${fmtTime(slowest.firstAlertMs!)}, blocked ${fmtTime(slowest.blockedAt)}.`,
    );
  }

  // Real exposure that landed before any block — the sharpest finding.
  const leaky = sources
    .filter((s) => s.latencyMs !== null && s.disposition.passed > 0)
    .sort((a, b) => b.disposition.passed - a.disposition.passed)[0];
  if (m.totalLeakedBeforeBlock > 0 && leaky) {
    out.push(
      `🩸 **${m.totalLeakedBeforeBlock} lead-up alert(s) were let through before a block landed** — that is attack ` +
        `traffic that actually reached a service during the detection-to-mitigation gap. Worst: \`${leaky.ip}\` ` +
        `(${leaky.disposition.passed} passed over ${fmtDuration(leaky.latencyMs!)}). Faster blocking shrinks this ` +
        `exposure directly.`,
    );
  }

  // Praise / reassurance when response is fast.
  if (gradeCounts.fast > 0 && gradeCounts.slow === 0 && m.gradedBlocks > 0) {
    out.push(
      `✅ Every measurable block landed within the moderate threshold — no source attacked for long before ` +
        `containment. Keep the responder/auto-block path healthy to hold this.`,
    );
  } else if (gradeCounts.slow > 0) {
    out.push(
      `⚠️ **${gradeCounts.slow} block(s) graded *slow*** — these sources had a long detection-to-mitigation gap. ` +
        `If the responder is meant to auto-block, check why it didn't fire sooner (rate limits, severity floor, or ` +
        `manual-only blocking on these signatures).`,
    );
  }

  // Proactive / un-gradeable blocks — honesty about coverage.
  if (m.noLeadUpBlocks > 0) {
    out.push(
      `⚪ **${m.noLeadUpBlocks} block(s) have no observed lead-up** — proactive (manual / threat-intel / first-packet ` +
        `reactive) blocks, or sources whose early alerts have rotated out of the capped store. These are excluded ` +
        `from the MTTB so they don't flatter it as "instant".`,
    );
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function sourceTable(rows: MttbSource[]): string {
  return mdTable(
    ["#", "Source", "Grade", "Latency", "First seen", "Blocked at", "Lead-up", "Severe", "Passed", "Worst", "Reason", "Flags"],
    rows.map((s, i) => {
      const flags =
        (s.internal ? "🏠" : "") +
        (s.watched ? "👁" : "") +
        (s.safe ? "✅" : "");
      return [
        String(i + 1),
        cell(s.ip),
        cell(gradeLabel(s.grade)),
        s.latencyMs === null ? "—" : fmtDuration(s.latencyMs),
        s.firstAlertMs === undefined ? "—" : cell(fmtTime(s.firstAlertMs)),
        cell(fmtTime(s.blockedAt)),
        String(s.preBlockAlerts),
        String(s.preBlockSevere),
        String(s.disposition.passed),
        cell(s.severityMax),
        cell(s.reason ?? "—"),
        flags || "—",
      ];
    }),
  );
}

function renderMarkdown(m: MttbReport): string {
  const lines: string[] = [];
  lines.push(`# ⏱️ SecTool Detection-to-Mitigation Latency (MTTB) Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** blocks applied in the last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** for each block applied in the window, latency = block time − first *pre-block* alert (\`srcIp\` match) ` +
      `over the **entire** stored history; graded fast ≤ ${fmtDuration(m.fastThresholdMs)}, slow > ` +
      `${fmtDuration(m.slowThresholdMs)} · **Blocks graded:** ${m.gradedBlocks} of ${m.windowBlocks} in window ` +
      `(${m.noLeadUpBlocks} had no observed lead-up; ${m.totalBlocks} total on the blocklist)`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.windowBlocks) {
    if (!m.totalBlocks) {
      lines.push(`The blocklist is empty — no enforcement actions to grade. Nothing to report.`);
    } else {
      lines.push(
        `${m.totalBlocks} IP(s) are on the blocklist, but none were blocked in the last ${m.hours} hour(s). ` +
          `Widen the window (e.g. \`--mttb 720\`) to grade older enforcement actions.`,
      );
    }
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  // MTTB stat block.
  lines.push(`## Latency at a glance`);
  lines.push("");
  if (m.gradedBlocks > 0 && m.meanLatencyMs !== null) {
    lines.push(
      mdTable(
        ["Metric", "Value"],
        [
          ["Mean time to block (MTTB)", fmtDuration(m.meanLatencyMs)],
          ["Median time to block", fmtDuration(m.medianLatencyMs ?? 0)],
          ["Fastest block", fmtDuration(m.minLatencyMs ?? 0)],
          ["Slowest block", fmtDuration(m.maxLatencyMs ?? 0)],
          ["Blocks graded / in window", `${m.gradedBlocks} / ${m.windowBlocks}`],
          ["Lead-up alerts let through before block", String(m.totalLeakedBeforeBlock)],
        ],
      ),
    );
  } else {
    lines.push(`_No block in the window had a measurable lead-up, so no latency statistics can be computed._`);
  }
  lines.push("");

  lines.push(`## Blocks by detection-to-mitigation latency`);
  lines.push("");
  lines.push(sourceTable(m.sources));
  lines.push("");
  lines.push(
    `**Legend:** _Grade_ — **🟢 fast** (≤ ${fmtDuration(m.fastThresholdMs)}) · **🟡 moderate** (≤ ` +
      `${fmtDuration(m.slowThresholdMs)}) · **🔴 slow** (> ${fmtDuration(m.slowThresholdMs)}) · **⚪ no-lead-up** ` +
      `(no pre-block alert in the store — proactive block or aged-out history, excluded from the MTTB). ` +
      `_Latency_ = block time − first observed alert from the source. _Lead-up_ = pre-block alerts; _Passed_ = how ` +
      `many of those the gateway let through (real exposure before containment). **Flags:** 🏠 internal source · ` +
      `👁 watched · ✅ marked safe (a safe IP we nonetheless blocked — worth reconciling).`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Latency is a **lower bound**: the alert store retains a finite, rotating ` +
      `history, so for an older block the earliest *retained* alert can post-date the attacker's true first packet. ` +
      `These are IPS **detections**, not full flows — "first seen" is first *detected* activity, not first contact. ` +
      `Alerts are attributed to a blocked IP by \`srcIp\`. Latency is only as accurate as the recorded block ` +
      `timestamp. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the detection-to-mitigation latency / MTTB report from the stored alert
 * history and the blocklist.
 *
 * @param hours Look-back window in hours (clamped to [1, 365 days]) — scopes
 *              *which blocks* are graded by their `at` timestamp, not which
 *              alerts are scanned (the full history is always scanned to find
 *              each source's first sighting).
 * @param opts  {@link MttbOptions}: `limit`, `fastMins`, `slowMins`, and a
 *              `nowMs` pin for deterministic tests.
 */
export function buildMttb(hours: number, opts: MttbOptions = {}): MttbReport {
  const safeHours = Math.max(1, Math.min(24 * 365, Math.floor(hours)));
  const limit = Math.max(1, Math.min(500, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const fastMins = Math.max(0, opts.fastMins ?? DEFAULT_FAST_MINS);
  let slowMins = Math.max(0, opts.slowMins ?? DEFAULT_SLOW_MINS);
  if (slowMins < fastMins) slowMins = fastMins; // keep thresholds ordered
  const fastThresholdMs = Math.round(fastMins * MS_PER_MIN);
  const slowThresholdMs = Math.round(slowMins * MS_PER_MIN);
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const allBlocks: BlockEntry[] = blockStore.all();
  // The graded set: blocks whose timestamp lands inside the window.
  const windowBlocks = allBlocks.filter(
    (b) => typeof b.at === "number" && Number.isFinite(b.at) && b.at >= windowStartMs && b.at <= windowEndMs,
  );

  // Pre-index every stored alert by source IP once so each block is O(its alerts).
  const bySource = new Map<string, StoredAlert[]>();
  for (const a of alertStore.all()) {
    if (typeof a.time !== "number" || !Number.isFinite(a.time)) continue;
    const src = validIp(a.srcIp);
    if (!src) continue;
    const list = bySource.get(src) ?? [];
    if (!bySource.has(src)) bySource.set(src, list);
    list.push(a);
  }

  const sources: MttbSource[] = windowBlocks.map((b) => {
    const acc = newSourceAcc();
    const alerts = bySource.get(b.ip) ?? [];
    for (const a of alerts) {
      if (a.time > b.at) continue; // pre-block lead-up only
      acc.preBlock++;
      acc.exposureScore += weightOf(a.severity);
      acc.severityMax = maxSeverity(acc.severityMax, a.severity);
      if (isSevere(a.severity)) acc.severe++;
      if (acc.firstAlertMs === undefined || a.time < acc.firstAlertMs) acc.firstAlertMs = a.time;
      if (acc.lastPreBlockMs === undefined || a.time > acc.lastPreBlockMs) acc.lastPreBlockMs = a.time;
      const disp = classifyDisposition(a.action);
      if (disp === "blocked") acc.blocked++;
      else if (disp === "passed") acc.passed++;
      else acc.unknown++;
    }
    const latencyMs = acc.firstAlertMs === undefined ? null : Math.max(0, b.at - acc.firstAlertMs);
    const grade = classifyGrade(latencyMs, fastThresholdMs, slowThresholdMs);
    return {
      ip: b.ip,
      grade,
      blockedAt: b.at,
      reason: b.reason,
      by: b.by,
      firstAlertMs: acc.firstAlertMs,
      lastPreBlockMs: acc.lastPreBlockMs,
      latencyMs,
      preBlockAlerts: acc.preBlock,
      preBlockSevere: acc.severe,
      exposureScore: acc.exposureScore,
      severityMax: acc.severityMax,
      disposition: { blocked: acc.blocked, passed: acc.passed, unknown: acc.unknown },
      internal: isPrivate(b.ip),
      watched: watchStore.has(b.ip),
      safe: safeStore.has(b.ip),
    } satisfies MttbSource;
  });

  // Slowest latency first (the finding); measurable blocks always rank above
  // un-gradeable ones, ties broken by accrued exposure then block recency.
  sources.sort((x, y) => {
    const lx = x.latencyMs;
    const ly = y.latencyMs;
    if (lx === null && ly === null) {
      return y.exposureScore - x.exposureScore || y.blockedAt - x.blockedAt || (x.ip < y.ip ? -1 : 1);
    }
    if (lx === null) return 1;
    if (ly === null) return -1;
    return ly - lx || y.exposureScore - x.exposureScore || y.blockedAt - x.blockedAt || (x.ip < y.ip ? -1 : 1);
  });

  const gradeCounts: GradeCounts = { fast: 0, moderate: 0, slow: 0, "no-lead-up": 0 };
  for (const s of sources) gradeCounts[s.grade]++;

  const latencies = sources.filter((s) => s.latencyMs !== null).map((s) => s.latencyMs as number);
  const gradedBlocks = latencies.length;
  const noLeadUpBlocks = gradeCounts["no-lead-up"];
  const meanLatencyMs = gradedBlocks ? Math.round(latencies.reduce((s, v) => s + v, 0) / gradedBlocks) : null;
  const medianLatencyMs = median(latencies);
  const minLatencyMs = gradedBlocks ? Math.min(...latencies) : null;
  const maxLatencyMs = gradedBlocks ? Math.max(...latencies) : null;
  const totalLeakedBeforeBlock = sources.reduce((s, v) => s + v.disposition.passed, 0);

  const cappedSources = sources.slice(0, limit);

  const highlights = writeHighlights(
    safeHours,
    {
      windowBlocks: windowBlocks.length,
      gradedBlocks,
      noLeadUpBlocks,
      meanLatencyMs,
      medianLatencyMs,
      totalLeakedBeforeBlock,
    },
    gradeCounts,
    cappedSources,
  );

  const model: MttbReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    fastThresholdMs,
    slowThresholdMs,
    totalBlocks: allBlocks.length,
    windowBlocks: windowBlocks.length,
    gradedBlocks,
    noLeadUpBlocks,
    meanLatencyMs,
    medianLatencyMs,
    minLatencyMs,
    maxLatencyMs,
    totalLeakedBeforeBlock,
    gradeCounts,
    sources: cappedSources,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded MTTB report. */
export function mttbFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-mttb-${stamp}.md`;
}
