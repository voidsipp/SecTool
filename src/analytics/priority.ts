/**
 * Priority-inversion / IDS-urgency-vs-enforcement audit — "**when the IDS engine
 * itself screamed loudest, did the gateway actually act — or did the urgent stuff
 * sail through while block capacity was spent on noise?**"
 *
 * Suricata stamps every alert with a numeric **priority** (`[Priority: 1]` …, where
 * **1 is the most urgent** and the number climbs as urgency falls). That field is
 * the *engine's own verdict on how serious a detection is*, decided by the rule
 * author and the classtype map — it is upstream of, and finer-grained than, the
 * single five-rung `severity` ladder SecTool derives from it (`alertDetector.ts`
 * collapses priority ≤ 1 → critical, 2 → high, 3 → medium, ≥ 4 → low). Every
 * enforcement-side report SecTool ships (`efficacy.ts`, `blockplan.ts`,
 * `mttb.ts`, `recidivism.ts`) reasons in terms of that derived **severity**; not
 * one of them reads the raw Suricata **priority**, and none of them asks the one
 * question a tuning engineer asks first about enforcement quality:
 *
 *   > Is the gateway's block decision *correlated* with the engine's urgency?
 *
 * In a healthy posture, **block rate falls as the priority number climbs** — the
 * most-urgent band (P1) is blocked the hardest, routine policy chatter (P3/P4) is
 * mostly just logged. **Priority inversion** is the opposite and dangerous shape:
 * urgent P1/P2 traffic *passed* (let through) while low-priority noise is *blocked*.
 * That happens for real and mundane reasons — IPS rules in IDS/"alert" mode for the
 * scariest categories, a drop ruleset skewed toward chatty low-value signatures, a
 * mis-scoped suppression — and it is exactly the failure that volume- or
 * severity-pivoted reports hide, because the *count* of blocks can look healthy
 * while the *worst* events are the ones escaping.
 *
 * For every alert in the window this report:
 *
 *   - **re-parses the Suricata priority** from the raw line (the same `[Priority: N]`
 *     bracket and JSON `priority`/`severity` shapes `alertDetector.ts` reads — the
 *     value is *not* stored as a column, so this mirrors how `ports.ts` /
 *     `srcport.ts` recover ports), and
 *   - classifies the gateway disposition (**blocked** vs **passed** vs **unknown**)
 *     with the shared `classifyDisposition` from `efficacy.ts`.
 *
 * It then produces three layers:
 *
 *   1. a **priority × enforcement matrix** — one row per priority band with its
 *      blocked / passed / unknown split, **block rate**, and reach (distinct
 *      sources, distinct targets, internal targets);
 *   2. the **inversion headline** — block rate of the *urgent* band group (priority
 *      ≤ `urgentMax`, default 2) versus the *routine* group (priority ≥ `urgentMax`+1),
 *      and an **Inversion Index** ∈ [-1, 1] = `urgentBlockRate − routineBlockRate`.
 *      Positive (urgent blocked *more*) is healthy; **negative is true inversion**;
 *      near-zero is a flat posture that ignores urgency; and
 *   3. the **worklist** — the actionable bit — the top **sources** and top
 *      **signatures** responsible for *urgent-but-passed* alerts, so the gap has a
 *      name and an address, not just a number. Urgent alerts that slipped through to
 *      an *internal* asset are flagged hardest.
 *
 * Honest caveats baked into the output:
 *
 *   - **Priority is re-parsed, not stored.** Only alerts whose raw line still carries
 *     a `[Priority: N]` bracket or a JSON `priority`/`severity` field contribute; the
 *     priority-bearing count is always shown so a thin sample is visible rather than
 *     mistaken for "no inversion".
 *   - **"Passed" is not always a failure.** A detection in IDS/alert mode is *meant*
 *     to be logged-not-dropped; "passed" means "not enforced inline", which is only a
 *     gap when the operator *expected* a block. The report surfaces the shape, it does
 *     not assume intent.
 *   - **Unknown-disposition alerts never inflate a block rate** — they are counted and
 *     shown separately, exactly as `efficacy.ts` treats them.
 *   - **Alerts, not flows.** SecTool stores IPS *detections*, so this is a lower bound
 *     on what crossed the wire, and a long look-back can hit the store's history cap.
 *
 * Pure in-memory math over alertStore (plus blocklist / watchlist / safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring `report.ts`, `efficacy.ts`,
 * `srcport.ts` and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Which side of the urgency cut a priority band sits on. */
export type Urgency = "urgent" | "routine";

/** The overall posture of the urgency-vs-enforcement relationship. */
export type InversionPosture = "healthy" | "flat" | "inverted" | "indeterminate";

/** Per-priority-band enforcement metrics over the window. */
export interface PriorityBandStats {
  /** The Suricata priority value (1 = most urgent; higher = less). */
  priority: number;
  /** Whether this band counts as urgent (priority ≤ urgentMax) or routine. */
  urgency: Urgency;
  /** Human label, e.g. "P1 — most urgent". */
  label: string;
  /** Total priority-bearing alerts in this band. */
  total: number;
  /** Alerts the gateway actively blocked / dropped. */
  blocked: number;
  /** Alerts the gateway logged but let through (detected / allowed). */
  passed: number;
  /** Alerts with no recorded action (excluded from {@link blockRate}). */
  unknown: number;
  /**
   * Fraction of *actioned* (blocked + passed) alerts that were blocked, 0..1 (4dp),
   * or null when nothing in the band was actioned.
   */
  blockRate: number | null;
  /** Distinct source IPs seen in this band. */
  distinctSources: number;
  /** Distinct destination IPs seen in this band. */
  distinctTargets: number;
  /** Alerts in this band whose destination is one of our own (internal) hosts. */
  internalTargets: number;
}

/** A source responsible for urgent-but-passed alerts (the enforcement worklist). */
export interface UrgentGapSource {
  /** The attacking / originating address. */
  ip: string;
  /** True when the source itself is one of our own hosts. */
  internal: boolean;
  /** Urgent (priority ≤ urgentMax) alerts from this source that were *passed*. */
  urgentPassed: number;
  /** All urgent alerts from this source (passed, blocked or unknown). */
  urgentTotal: number;
  /** The most-urgent (lowest) priority this source got *passed*. */
  worstPriority: number;
  /** Distinct *internal* destinations hit by this source's urgent-passed alerts. */
  internalTargetsHit: number;
  /** The signature most often behind this source's urgent-passed alerts. */
  topSignature?: string;
  /** Worst severity seen from this source across its urgent alerts. */
  severityMax: Severity;
  /** The source is on the blocklist. */
  blocked: boolean;
  /** The source is on the watchlist. */
  watched: boolean;
  /** The source is marked safe. */
  safe: boolean;
}

/** A signature responsible for urgent-but-passed alerts (the tuning worklist). */
export interface UrgentGapSignature {
  /** The Suricata signature / rule message. */
  signature: string;
  /** Urgent alerts on this signature that were *passed*. */
  urgentPassed: number;
  /** All urgent alerts on this signature. */
  urgentTotal: number;
  /** Block rate across *actioned* urgent alerts on this signature, 0..1, or null. */
  blockRate: number | null;
  /** Distinct sources firing this signature's urgent-passed alerts. */
  distinctSources: number;
  /** The most-urgent (lowest) priority seen passed on this signature. */
  worstPriority: number;
}

export interface PriorityReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts from which a Suricata priority was recovered. */
  priorityBearingAlerts: number;
  /** Priority value at/below which a band counts as "urgent". */
  urgentMax: number;
  /** Per-band rows, most-urgent (lowest priority number) first. */
  bands: PriorityBandStats[];
  /** Actioned urgent alerts (blocked + passed). */
  urgentActioned: number;
  /** Urgent alerts the gateway blocked. */
  urgentBlocked: number;
  /** Urgent alerts the gateway passed (the headline gap). */
  urgentPassed: number;
  /** Block rate across actioned urgent alerts, 0..1 (4dp), or null. */
  urgentBlockRate: number | null;
  /** Actioned routine alerts (blocked + passed). */
  routineActioned: number;
  /** Routine alerts the gateway blocked. */
  routineBlocked: number;
  /** Routine alerts the gateway passed. */
  routinePassed: number;
  /** Block rate across actioned routine alerts, 0..1 (4dp), or null. */
  routineBlockRate: number | null;
  /**
   * Inversion Index ∈ [-1, 1] = urgentBlockRate − routineBlockRate, 4dp, or null
   * when either side has nothing actioned. Positive = healthy (urgent blocked
   * harder); negative = inverted (noise blocked harder than urgent traffic).
   */
  inversionIndex: number | null;
  /** Categorical read of {@link inversionIndex}. */
  posture: InversionPosture;
  /** Top sources behind urgent-but-passed alerts, worst first. */
  urgentGapSources: UrgentGapSource[];
  /** Top signatures behind urgent-but-passed alerts, worst first. */
  urgentGapSignatures: UrgentGapSignature[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface PriorityOptions {
  /** Max rows in each worklist table (clamped to [1, 200]). */
  limit?: number;
  /** Priority ≤ this counts as "urgent" (≥1, default 2). */
  urgentMax?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const DEFAULT_URGENT_MAX = 2;
const MS_PER_HOUR = 3_600_000;

/** Index ≥ this → urgent blocked notably harder than routine: a healthy posture. */
const HEALTHY_INDEX = 0.15;
/** Index ≤ this → urgent blocked *less* than routine: a true inversion. */
const INVERTED_INDEX = -0.05;

// ----- priority re-parsing (mirrors alertDetector.ts) -----------------------

/** Same bracket alertDetector.ts reads: `[Priority: 2]`. */
const PRIORITY_BRACKET = /\[Priority:\s*(\d+)\]/i;

function toPriority(v: unknown): number | undefined {
  const n = typeof v === "number" ? v : Number(v);
  return Number.isInteger(n) && n >= 1 && n <= 255 ? n : undefined;
}

/**
 * Re-parse the Suricata priority from a stored alert's raw line, using the same two
 * shapes `alertDetector.ts` understands: a `[Priority: N]` bracket (fast.log) or a
 * JSON payload carrying `priority` (or `severity` as a fallback, exactly as the
 * detector does). Returns undefined when no priority can be recovered.
 */
export function recoverPriority(raw: string | undefined): number | undefined {
  if (!raw) return undefined;

  // 1) fast.log bracket: ... [Priority: 2] {TCP} a.b.c.d:1 -> e.f.g.h:3389
  const bracket = PRIORITY_BRACKET.exec(raw);
  if (bracket?.[1]) {
    const p = toPriority(bracket[1]);
    if (p !== undefined) return p;
  }

  // 2) JSON payload: {"priority":2, ...} (or "severity" as the detector's fallback)
  const start = raw.indexOf("{");
  const end = raw.lastIndexOf("}");
  if (start !== -1 && end > start) {
    try {
      const obj = JSON.parse(raw.slice(start, end + 1)) as Record<string, unknown>;
      if (obj && typeof obj === "object") {
        const p = toPriority(obj["priority"]) ?? toPriority(obj["severity"]);
        if (p !== undefined) return p;
      }
    } catch {
      // not JSON — fall through
    }
  }
  return undefined;
}

// ----- classifiers / helpers (mirror efficacy.ts / srcport.ts) --------------

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

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
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

/** Human label for a priority band — "P1 — most urgent" etc. */
function bandLabel(priority: number, urgentMax: number): string {
  if (priority === 1) return "P1 — most urgent";
  if (priority <= urgentMax) return `P${priority} — urgent`;
  if (priority === 3) return "P3 — routine";
  return `P${priority} — low`;
}

/** A short block-rate cell, with an emoji read of how enforced the band is. */
function blockRateCell(rate: number | null): string {
  if (rate === null) return "—";
  const badge = rate >= 0.8 ? "🟢" : rate >= 0.4 ? "🟡" : "🔴";
  return `${badge} ${pct(rate)}`;
}

/** Categorise the index into a posture verdict. */
function classifyPosture(index: number | null): InversionPosture {
  if (index === null) return "indeterminate";
  if (index >= HEALTHY_INDEX) return "healthy";
  if (index <= INVERTED_INDEX) return "inverted";
  return "flat";
}

/** Human, emoji-led label for a posture. */
function postureLabel(p: InversionPosture): string {
  switch (p) {
    case "healthy":
      return "🟢 healthy (urgent blocked hardest)";
    case "flat":
      return "🟡 flat (enforcement ignores urgency)";
    case "inverted":
      return "🔴 inverted (noise blocked harder than urgent traffic)";
    case "indeterminate":
      return "⚪ indeterminate (too little actioned to judge)";
  }
}

// ----- aggregation ----------------------------------------------------------

interface BandAcc {
  total: number;
  blocked: number;
  passed: number;
  unknown: number;
  sources: Set<string>;
  targets: Set<string>;
  internalTargets: number;
}

function newBandAcc(): BandAcc {
  return {
    total: 0,
    blocked: 0,
    passed: 0,
    unknown: 0,
    sources: new Set(),
    targets: new Set(),
    internalTargets: 0,
  };
}

interface SrcAcc {
  urgentPassed: number;
  urgentTotal: number;
  worstPriority: number;
  internalTargets: Set<string>;
  sigCounts: Map<string, number>;
  severityMax: Severity;
}

function newSrcAcc(): SrcAcc {
  return {
    urgentPassed: 0,
    urgentTotal: 0,
    worstPriority: Number.POSITIVE_INFINITY,
    internalTargets: new Set(),
    sigCounts: new Map(),
    severityMax: "info",
  };
}

interface SigAcc {
  urgentPassed: number;
  urgentTotal: number;
  urgentBlocked: number;
  sources: Set<string>;
  worstPriority: number;
}

function newSigAcc(): SigAcc {
  return {
    urgentPassed: 0,
    urgentTotal: 0,
    urgentBlocked: 0,
    sources: new Set(),
    worstPriority: Number.POSITIVE_INFINITY,
  };
}

/** The signature behind the most of a source's urgent-passed alerts. */
function topSignature(counts: Map<string, number>): string | undefined {
  let sig: string | undefined;
  let n = 0;
  for (const [s, c] of counts) {
    if (c > n) {
      sig = s;
      n = c;
    }
  }
  return sig;
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(m: PriorityReport): string[] {
  const out: string[] = [];
  if (!m.priorityBearingAlerts) return out;

  // The posture headline — the one-line read of the whole report.
  if (m.inversionIndex !== null) {
    const sign = m.inversionIndex >= 0 ? "+" : "";
    out.push(
      `🎚️ **Posture: ${postureLabel(m.posture)}.** Urgent (P≤${m.urgentMax}) block rate ` +
        `**${m.urgentBlockRate === null ? "—" : pct(m.urgentBlockRate)}** vs routine (P>${m.urgentMax}) ` +
        `**${m.routineBlockRate === null ? "—" : pct(m.routineBlockRate)}** → Inversion Index ` +
        `**${sign}${m.inversionIndex.toFixed(2)}** (positive is healthy).`,
    );
  }

  // The headline gap — urgent traffic that was actively let through.
  if (m.urgentActioned > 0 && m.urgentPassed > 0) {
    const frac = m.urgentPassed / m.urgentActioned;
    out.push(
      `🚨 **${m.urgentPassed} urgent (P≤${m.urgentMax}) alert(s) were passed** — ${pct(frac)} of all *actioned* ` +
        `urgent traffic sailed through the gateway. These are the detections the IDS engine itself flagged as most ` +
        `serious, and they were not enforced.`,
    );
  } else if (m.urgentActioned > 0) {
    out.push(
      `✅ Every actioned urgent (P≤${m.urgentMax}) alert this window was **blocked** — no urgent traffic was let ` +
        `through. The gateway is enforcing the engine's most-serious verdicts.`,
    );
  }

  // True inversion — the dangerous case stated plainly.
  if (m.posture === "inverted") {
    out.push(
      `🔻 **Priority inversion detected:** routine noise is being blocked *harder* than urgent traffic. This is the ` +
        `classic shape of an IPS that drops chatty low-value signatures inline while the scariest categories sit in ` +
        `alert-only mode. Re-check which rule groups are in drop vs alert mode.`,
    );
  }

  // The worst single source — who to look at first.
  if (m.urgentGapSources.length) {
    const s = m.urgentGapSources[0]!;
    out.push(
      `🎯 Worst source is \`${s.ip}\`${s.internal ? " *(internal!)*" : ""}${s.safe ? " *(safe-listed!)*" : ""} — ` +
        `**${s.urgentPassed} urgent-passed alert(s)** (worst priority P${s.worstPriority}` +
        `${s.topSignature ? `, mostly "${s.topSignature}"` : ""})` +
        `${s.blocked ? " — already on the blocklist" : s.internal ? "" : ", and not yet blocked"}.`,
    );
  }

  // Urgent traffic reaching an internal asset — the worst possible escape.
  const internalHit = m.urgentGapSources.find((s) => s.internalTargetsHit > 0);
  if (internalHit) {
    out.push(
      `🏠 \`${internalHit.ip}\` got **urgent traffic passed to ${internalHit.internalTargetsHit} internal ` +
        `asset(s)** — an engine-flagged-serious detection reached one of your own hosts without being blocked. ` +
        `Treat as a live exposure, not a tuning nicety.`,
    );
  }

  // The worst signature — the tuning lever.
  if (m.urgentGapSignatures.length) {
    const sig = m.urgentGapSignatures[0]!;
    out.push(
      `🧬 Signature **"${sig.signature}"** accounts for **${sig.urgentPassed} urgent-passed alert(s)** ` +
        `(block rate ${sig.blockRate === null ? "—" : pct(sig.blockRate)} across ${sig.distinctSources} source(s)) — ` +
        `if this should be enforced, moving its rule group to drop mode closes the biggest single gap.`,
    );
  }

  // Parse-coverage honesty.
  if (m.totalWindowAlerts > 0) {
    const frac = m.priorityBearingAlerts / m.totalWindowAlerts;
    if (frac < 0.5) {
      out.push(
        `ℹ️ Only **${pct(frac)} of windowed alerts carried a recoverable Suricata priority** — every figure here is ` +
          `drawn from that sample, not the full alert stream.`,
      );
    }
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function bandTable(rows: PriorityBandStats[]): string {
  return mdTable(
    ["Band", "Alerts", "Blocked", "Passed", "Unknown", "Block rate", "Sources", "Targets", "Internal tgt"],
    rows.map((b) => [
      cell(b.label),
      String(b.total),
      String(b.blocked),
      String(b.passed),
      String(b.unknown),
      blockRateCell(b.blockRate),
      String(b.distinctSources),
      String(b.distinctTargets),
      String(b.internalTargets),
    ]),
  );
}

function sourceTable(rows: UrgentGapSource[]): string {
  return mdTable(
    ["#", "Source", "Urgent passed", "Urgent total", "Worst", "Internal tgt", "Top signature", "Flags"],
    rows.map((s, i) => {
      const flags =
        (s.internal ? "🏠" : "") +
        (s.blocked ? "⛔" : "") +
        (s.watched ? "👁" : "") +
        (s.safe ? "✅" : "");
      return [
        String(i + 1),
        cell(s.ip),
        String(s.urgentPassed),
        String(s.urgentTotal),
        `P${s.worstPriority}`,
        String(s.internalTargetsHit),
        cell(s.topSignature ?? "—"),
        flags || "—",
      ];
    }),
  );
}

function signatureTable(rows: UrgentGapSignature[]): string {
  return mdTable(
    ["#", "Signature", "Urgent passed", "Urgent total", "Block rate", "Sources", "Worst"],
    rows.map((s, i) => [
      String(i + 1),
      cell(s.signature),
      String(s.urgentPassed),
      String(s.urgentTotal),
      s.blockRate === null ? "—" : pct(s.blockRate),
      String(s.distinctSources),
      `P${s.worstPriority}`,
    ]),
  );
}

function renderMarkdown(m: PriorityReport): string {
  const lines: string[] = [];
  lines.push(`# 🎚️ SecTool Priority-Inversion / IDS-Urgency-vs-Enforcement Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** each alert's Suricata **priority** re-parsed from the raw line (1 = most urgent) and crossed ` +
      `against the gateway disposition (blocked / passed / unknown). "Urgent" = priority ≤ ${m.urgentMax}. ` +
      `**Inversion Index** = urgent block rate − routine block rate (positive is healthy) · ` +
      `**Priority-bearing alerts:** ${m.priorityBearingAlerts} of ${m.totalWindowAlerts}`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.priorityBearingAlerts) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but **none carried a recoverable Suricata ` +
          `priority** (no \`[Priority: N]\` bracket or JSON \`priority\` field survived in the raw line), so no ` +
          `urgency-vs-enforcement audit can be computed.`,
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

  lines.push(`## Priority × enforcement matrix`);
  lines.push("");
  lines.push(bandTable(m.bands));
  lines.push("");
  lines.push(
    `**Reading it:** in a healthy posture the **block rate** is highest in the top (most-urgent) row and falls as ` +
      `you go down. _Block rate_ badges: 🟢 ≥ 80% · 🟡 40–79% · 🔴 < 40% (of *actioned* alerts; unknown-action ` +
      `alerts are shown but never inflate the rate). _Internal tgt_ = alerts in that band that reached one of your ` +
      `own hosts.`,
  );
  lines.push("");

  lines.push(`## Urgent enforcement gaps — by source`);
  lines.push("");
  if (!m.urgentGapSources.length) {
    lines.push(
      `_No urgent (P≤${m.urgentMax}) alert was passed this window_ — every urgent detection was either blocked or had ` +
        `no recorded action. Nothing to chase on the source side.`,
    );
  } else {
    lines.push(
      `Sources whose **urgent (P≤${m.urgentMax}) traffic was let through**, worst first. These are the addresses the ` +
        `engine flagged as serious that the gateway did not stop.`,
    );
    lines.push("");
    lines.push(sourceTable(m.urgentGapSources));
    lines.push("");
    lines.push(
      `**Flags:** 🏠 internal source · ⛔ already blocked · 👁 watched · ✅ safe-listed. _Worst_ = the lowest ` +
        `(most-urgent) priority this source got passed. _Internal tgt_ = distinct internal assets its urgent-passed ` +
        `alerts reached.`,
    );
  }
  lines.push("");

  lines.push(`## Urgent enforcement gaps — by signature`);
  lines.push("");
  if (!m.urgentGapSignatures.length) {
    lines.push(`_No urgent signature was passed this window._`);
  } else {
    lines.push(
      `Signatures whose **urgent (P≤${m.urgentMax}) detections were passed**, worst first — the tuning lever. ` +
        `Moving a high-count signature's rule group from alert to drop mode closes the gap at the root.`,
    );
    lines.push("");
    lines.push(signatureTable(m.urgentGapSignatures));
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Suricata **priority is re-parsed from each alert's raw line**, not a stored ` +
      `column, so every figure is drawn from alerts that still carried a \`[Priority: N]\` bracket or JSON ` +
      `\`priority\` field. **"Passed" means "not enforced inline"**, which is a gap only when a block was expected — ` +
      `a detection in IDS/alert mode is *meant* to be logged, not dropped. Unknown-action alerts are counted but ` +
      `never inflate a block rate. These are IPS **detections**, not full flows, so counts are a lower bound, and a ` +
      `long look-back can hit the store's history cap and undercount. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the priority-inversion / IDS-urgency-vs-enforcement audit from the stored
 * alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link PriorityOptions}: `limit`, `urgentMax`, and a `nowMs` pin for tests.
 */
export function buildPriority(hours: number, opts: PriorityOptions = {}): PriorityReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const urgentMax = Math.max(1, Math.floor(opts.urgentMax ?? DEFAULT_URGENT_MAX));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const bands = new Map<number, BandAcc>();
  const srcGaps = new Map<string, SrcAcc>();
  const sigGaps = new Map<string, SigAcc>();

  let priorityBearing = 0;
  let urgentBlocked = 0;
  let urgentPassed = 0;
  let routineBlocked = 0;
  let routinePassed = 0;

  for (const a of windowed) {
    const priority = recoverPriority(a.raw);
    if (priority === undefined) continue;
    priorityBearing++;

    const disp = classifyDisposition(a.action);
    const isUrgent = priority <= urgentMax;
    const src = validIp(a.srcIp);
    const dst = validIp(a.dstIp);
    const dstInternal = dst ? isPrivate(dst) : false;

    // --- per-band matrix ---
    const band = bands.get(priority) ?? newBandAcc();
    if (!bands.has(priority)) bands.set(priority, band);
    band.total++;
    if (disp === "blocked") band.blocked++;
    else if (disp === "passed") band.passed++;
    else band.unknown++;
    if (src) band.sources.add(src);
    if (dst) {
      band.targets.add(dst);
      if (dstInternal) band.internalTargets++;
    }

    // --- urgent/routine block-rate tallies ---
    if (isUrgent) {
      if (disp === "blocked") urgentBlocked++;
      else if (disp === "passed") urgentPassed++;
    } else {
      if (disp === "blocked") routineBlocked++;
      else if (disp === "passed") routinePassed++;
    }

    if (!isUrgent) continue; // worklists are urgent-only

    // --- urgent worklist: by source ---
    if (src) {
      const s = srcGaps.get(src) ?? newSrcAcc();
      if (!srcGaps.has(src)) srcGaps.set(src, s);
      s.urgentTotal++;
      s.severityMax = maxSeverity(s.severityMax, a.severity);
      if (disp === "passed") {
        s.urgentPassed++;
        if (priority < s.worstPriority) s.worstPriority = priority;
        if (dst && dstInternal) s.internalTargets.add(dst);
        if (a.signature) s.sigCounts.set(a.signature, (s.sigCounts.get(a.signature) ?? 0) + 1);
      }
    }

    // --- urgent worklist: by signature ---
    if (a.signature) {
      const sig = sigGaps.get(a.signature) ?? newSigAcc();
      if (!sigGaps.has(a.signature)) sigGaps.set(a.signature, sig);
      sig.urgentTotal++;
      if (disp === "blocked") sig.urgentBlocked++;
      if (disp === "passed") {
        sig.urgentPassed++;
        if (priority < sig.worstPriority) sig.worstPriority = priority;
        if (src) sig.sources.add(src);
      }
    }
  }

  // --- band rows, most-urgent first ---
  const bandRows: PriorityBandStats[] = [...bands.entries()]
    .map(([priority, acc]) => {
      const actioned = acc.blocked + acc.passed;
      return {
        priority,
        urgency: (priority <= urgentMax ? "urgent" : "routine") as Urgency,
        label: bandLabel(priority, urgentMax),
        total: acc.total,
        blocked: acc.blocked,
        passed: acc.passed,
        unknown: acc.unknown,
        blockRate: actioned ? round4(acc.blocked / actioned) : null,
        distinctSources: acc.sources.size,
        distinctTargets: acc.targets.size,
        internalTargets: acc.internalTargets,
      } satisfies PriorityBandStats;
    })
    .sort((a, b) => a.priority - b.priority);

  // --- headline inversion ---
  const urgentActioned = urgentBlocked + urgentPassed;
  const routineActioned = routineBlocked + routinePassed;
  const urgentBlockRate = urgentActioned ? round4(urgentBlocked / urgentActioned) : null;
  const routineBlockRate = routineActioned ? round4(routineBlocked / routineActioned) : null;
  const inversionIndex =
    urgentBlockRate !== null && routineBlockRate !== null
      ? round4(urgentBlockRate - routineBlockRate)
      : null;
  const posture = classifyPosture(inversionIndex);

  // --- source worklist, worst first ---
  const urgentGapSources: UrgentGapSource[] = [...srcGaps.entries()]
    .filter(([, s]) => s.urgentPassed > 0)
    .map(([ip, s]) => ({
      ip,
      internal: isPrivate(ip),
      urgentPassed: s.urgentPassed,
      urgentTotal: s.urgentTotal,
      worstPriority: Number.isFinite(s.worstPriority) ? s.worstPriority : urgentMax,
      internalTargetsHit: s.internalTargets.size,
      topSignature: topSignature(s.sigCounts),
      severityMax: s.severityMax,
      blocked: blockStore.has(ip),
      watched: watchStore.has(ip),
      safe: safeStore.has(ip),
    }))
    // Worst first: urgency (lower = worse), then volume, then internal reach.
    .sort(
      (x, y) =>
        x.worstPriority - y.worstPriority ||
        y.urgentPassed - x.urgentPassed ||
        y.internalTargetsHit - x.internalTargetsHit ||
        (x.ip < y.ip ? -1 : x.ip > y.ip ? 1 : 0),
    )
    .slice(0, limit);

  // --- signature worklist, worst first ---
  const urgentGapSignatures: UrgentGapSignature[] = [...sigGaps.entries()]
    .filter(([, s]) => s.urgentPassed > 0)
    .map(([signature, s]) => {
      const actioned = s.urgentBlocked + s.urgentPassed;
      return {
        signature,
        urgentPassed: s.urgentPassed,
        urgentTotal: s.urgentTotal,
        blockRate: actioned ? round4(s.urgentBlocked / actioned) : null,
        distinctSources: s.sources.size,
        worstPriority: Number.isFinite(s.worstPriority) ? s.worstPriority : urgentMax,
      } satisfies UrgentGapSignature;
    })
    .sort(
      (x, y) =>
        x.worstPriority - y.worstPriority ||
        y.urgentPassed - x.urgentPassed ||
        y.distinctSources - x.distinctSources ||
        (x.signature < y.signature ? -1 : x.signature > y.signature ? 1 : 0),
    )
    .slice(0, limit);

  const model: PriorityReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    priorityBearingAlerts: priorityBearing,
    urgentMax,
    bands: bandRows,
    urgentActioned,
    urgentBlocked,
    urgentPassed,
    urgentBlockRate,
    routineActioned,
    routineBlocked,
    routinePassed,
    routineBlockRate,
    inversionIndex,
    posture,
    urgentGapSources,
    urgentGapSignatures,
    highlights: [],
    markdown: "",
  };
  model.highlights = writeHighlights(model);
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded priority-inversion report. */
export function priorityFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-priority-${stamp}.md`;
}
