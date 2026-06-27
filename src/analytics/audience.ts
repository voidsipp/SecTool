/**
 * Signature-audience / "spray vs snipe" report — "for each rule that fired, is it
 * being *sprayed* at me by a diffuse crowd of unrelated sources (internet
 * background radiation I can down-prioritise) or *sniped* by one or two actors at
 * a handful of my hosts (a focused, real signal that raw volume buries)?"
 *
 * Every signature-aware report in this project measures a *different* axis and
 * none of them measures the **source population behind each signature**:
 *
 *   - **classify.ts** rolls alerts up by Suricata's `classification` taxonomy —
 *     the threat *mix* ("what kinds of attacks"), globally. It never asks how
 *     many *distinct actors* are behind any one signature.
 *   - **tuning.ts** ranks the individual *signature* by volume / block-rate to
 *     find noisy rules — but a signature firing 10 000 times from a single IP and
 *     one firing 10 000 times from 8 000 IPs look identical to a volume ranking,
 *     even though the first is one attacker and the second is the whole internet.
 *   - **concentration.ts** measures the *shape of the whole distribution* across a
 *     single dimension at a time (one Gini/HHI number for "sources", or for
 *     "signatures", or for "targets"). It answers "can I block my way to quiet?"
 *     globally; it does **not** classify each signature by *its own* source
 *     spread.
 *   - **noise.ts** quantifies *repetition* — the same (source, rule, target)
 *     event firing over and over. A signature can be low-repetition yet still be
 *     sprayed by thousands of one-shot sources; that diffusion is invisible there.
 *   - **spread.ts / scan.ts** pivot on the *source* (how many hosts/ports one
 *     attacker touches). This report pivots on the *signature* and asks the
 *     transpose: how many distinct attackers stand behind it.
 *   - **repertoire.ts** ranks a *source* by how many distinct signatures it fires.
 *     This is the dual: it ranks a *signature* by how concentrated its source
 *     population is.
 *
 * Why the source-diffusion axis is the sharpest triage lever the IPS stream holds:
 *
 *   - A signature fired by **thousands of unrelated sources against everything**
 *     ("ET DROP Dshield", generic scanner probes, worm sprays) is *background
 *     radiation*. It is loud, it dominates the console, and it tells you almost
 *     nothing — every internet-facing host on earth sees it. These are the
 *     signatures to collapse, down-prioritise, or tune so the real signal surfaces.
 *   - A signature fired by **one or two sources at one or two of your hosts** is a
 *     *targeted* event: somebody picked a tool and pointed it at a specific box.
 *     At low volume it sits at the bottom of every volume-ranked list — exactly
 *     the alert an analyst skims past — yet it is the one most likely to be a real
 *     hands-on intrusion.
 *
 * For every signature over the window this report folds the windowed alerts and
 * computes its **source breadth** (distinct `srcIp`), a diversity-weighted
 * **effective source count** (inverse-Simpson `1 / Σ shareᵢ²`, which discounts a
 * long tail of one-shot sources so a crowd genuinely dominated by one actor reads
 * as "few"), the **dominant source's share**, the **target breadth** (distinct
 * `dstIp`), a severity-weighted score, the blocked/passed enforcement split, and
 * how many of its sources/targets are internal (a signature whose *sources* are
 * your own hosts is a compromise tell). It then classifies each signature from the
 * two diffusion axes against tunable thresholds:
 *
 *   - **🌐 spray**    — many sources × many targets: internet background radiation.
 *   - **🐝 swarm**    — many sources × few targets: a crowd converging on one box
 *                       (a popular target, or a botnet tasked specifically at you).
 *   - **🛰 scan**     — few sources × many targets: a small number of actors
 *                       sweeping wide (cross-reference scan.ts for the shape).
 *   - **🎯 targeted** — few sources × few targets: a focused, hands-on signal.
 *
 * The primary table ranks signatures by **alert volume** — what actually fills the
 * console — but annotates each with its quadrant and effective-source count, so a
 * loud row can be read at a glance as "spray → tune it away" or "swarm → act". Two
 * companion roll-ups then pull the two actionable extremes the volume ranking
 * hides: **sharpest targeted signatures** (the buried, low-volume snipes, ranked
 * by severity) and **top spray / tuning candidates** (the loudest background
 * radiation, ranked by volume).
 *
 * Honest caveats baked into the output:
 *
 *   - **Alerts, not flows.** SecTool stores IPS *detections*. A source that never
 *     trips this rule is invisible, so every source count is a lower bound.
 *   - **Diffusion is a heuristic.** The spray/swarm/scan/targeted call is a
 *     function of the (tunable) source/target thresholds; a borderline signature
 *     can sit either side of the line. The raw counts and the effective-source
 *     number are always shown so the call can be second-guessed.
 *   - **Effective sources ≠ distinct sources.** A signature with 500 distinct
 *     sources where one fires 95% of the alerts has a *low* effective count and is
 *     (correctly) read as concentrated, not diffuse — the dominant share is shown
 *     alongside so the gap is visible.
 *   - **Window-bounded & store-capped.** A long look-back can hit the store's
 *     history cap and undercount both volume and source breadth.
 *
 * Pure in-memory math over alertStore (plus blocklist / watchlist / safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring report.ts, scan.ts,
 * repertoire.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** The four source-diffusion shapes a signature's audience can take. */
export type AudienceShape = "spray" | "swarm" | "scan" | "targeted";

/** Blocked / passed / unknown disposition split for a signature. */
export interface DispositionSplit {
  /** Alerts the gateway actively blocked / dropped. */
  blocked: number;
  /** Alerts the gateway logged but let through (detected / allowed). */
  passed: number;
  /** Alerts with no recorded action (excluded from {@link passRate}). */
  unknown: number;
  /**
   * Fraction of *actioned* (blocked + passed) alerts that were let through,
   * 0..1 (4dp), or null when nothing was actioned.
   */
  passRate: number | null;
}

/** Per-signature audience metrics over the window. */
export interface SignatureAudience {
  /** The signature text (or a placeholder when the alert carried none). */
  signature: string;
  /** The classified source-diffusion shape (see {@link AudienceShape}). */
  shape: AudienceShape;
  /** Total alerts attributed to this signature in the window. */
  count: number;
  /** Distinct source IPs that fired this signature (raw audience size). */
  distinctSources: number;
  /**
   * Diversity-weighted source count — inverse-Simpson `1 / Σ shareᵢ²` over the
   * per-source alert shares (2dp). Discounts a long tail of one-shot sources, so
   * a crowd dominated by one actor reads as "few". The ranking axis for breadth.
   */
  effectiveSources: number;
  /** Herfindahl index of per-source alert share, 0..1 (4dp); 1 = one source. */
  sourceHHI: number;
  /** The single source responsible for the most of this signature, if any. */
  dominantSource?: string;
  /** {@link dominantSource}'s share of this signature's alerts, 0..1 (4dp). */
  dominantShare: number;
  /** Distinct destination hosts this signature was aimed at (target breadth). */
  distinctTargets: number;
  /** The most-hit destination host for this signature, if any. */
  topTarget?: string;
  /** Of {@link distinctSources}, how many are internal (a compromise tell). */
  internalSources: number;
  /** Of {@link distinctTargets}, how many are our own assets. */
  internalTargets: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Severity-weighted score (Σ SEVERITY_WEIGHT) — the targeted-roll-up key. */
  score: number;
  /** Worst severity seen for this signature. */
  severityMax: Severity;
  /** Blocked / passed / unknown disposition split. */
  disposition: DispositionSplit;
  /** The dominant source is on the blocklist. */
  dominantBlocked: boolean;
  /** The dominant source is on the watchlist. */
  dominantWatched: boolean;
  /** The dominant source is marked safe. */
  dominantSafe: boolean;
}

/** Count of signatures falling into each diffusion shape. */
export interface ShapeCounts {
  spray: number;
  swarm: number;
  scan: number;
  targeted: number;
}

export interface AudienceReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts carrying both a signature and a valid source IP. */
  sourcedAlerts: number;
  /** Effective-source count at/above which a signature counts as "many sources". */
  sourceThreshold: number;
  /** Distinct-target count at/above which a signature counts as "many targets". */
  targetThreshold: number;
  /** Distinct signatures analysed (after the min-alerts floor). */
  distinctSignatures: number;
  /** How many signatures fell into each shape. */
  shapeCounts: ShapeCounts;
  /** Per-signature rows, loudest (by volume) first. */
  signatures: SignatureAudience[];
  /** Targeted signatures, sharpest (by severity score) first — the buried snipes. */
  sharpestTargeted: SignatureAudience[];
  /** Spray signatures, loudest first — the tuning / down-prioritise candidates. */
  sprayCandidates: SignatureAudience[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface AudienceOptions {
  /** Max rows in the per-signature table (clamped to [1, 200]). */
  limit?: number;
  /** Effective-source count at/above which a signature is "many sources" (≥1). */
  sourceThreshold?: number;
  /** Distinct-target count at/above which a signature is "many targets" (≥1). */
  targetThreshold?: number;
  /** Minimum alerts a signature needs before it is analysed (drops one-offs). */
  minAlerts?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 25;
const DEFAULT_SOURCE_THRESHOLD = 5;
const DEFAULT_TARGET_THRESHOLD = 5;
const DEFAULT_MIN_ALERTS = 3;
const MS_PER_HOUR = 3_600_000;

// ----- classifiers / helpers (mirror scan.ts) -------------------------------

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

function round2(n: number): number {
  return Math.round(n * 100) / 100;
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

/** Truncate a long signature string for table display. */
function truncSig(s: string, max = 54): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function mdTable(headers: string[], rows: string[][]): string {
  if (!rows.length) return "_None._";
  const head = `| ${headers.join(" | ")} |`;
  const sep = `| ${headers.map(() => "---").join(" | ")} |`;
  const body = rows.map((r) => `| ${r.join(" | ")} |`).join("\n");
  return `${head}\n${sep}\n${body}`;
}

function topOf(counts: Map<string, number>): { key?: string; count: number } {
  let key: string | undefined;
  let count = 0;
  for (const [k, c] of counts) {
    if (c > count || (c === count && key !== undefined && k < key)) {
      key = k;
      count = c;
    }
  }
  return { key, count };
}

/** Human label for a diffusion shape, with an emoji that reads at a glance. */
function shapeLabel(s: AudienceShape): string {
  switch (s) {
    case "spray":
      return "🌐 spray";
    case "swarm":
      return "🐝 swarm";
    case "scan":
      return "🛰 scan";
    case "targeted":
      return "🎯 targeted";
  }
}

/**
 * Classify a signature's audience from its two diffusion axes. "Many sources" is
 * decided on the *effective* (diversity-weighted) source count, "many targets"
 * on the raw distinct-target count; the four-way split is the cross of the two.
 */
function classifyShape(
  effectiveSources: number,
  distinctTargets: number,
  sourceThreshold: number,
  targetThreshold: number,
): AudienceShape {
  const manySources = effectiveSources >= sourceThreshold;
  const manyTargets = distinctTargets >= targetThreshold;
  if (manySources && manyTargets) return "spray";
  if (manySources) return "swarm";
  if (manyTargets) return "scan";
  return "targeted";
}

// ----- aggregation ----------------------------------------------------------

interface SigAcc {
  count: number;
  score: number;
  severe: number;
  sourceCounts: Map<string, number>;
  targetCounts: Map<string, number>;
  internalSources: Set<string>;
  internalTargets: Set<string>;
  blocked: number;
  passed: number;
  unknown: number;
  severityMax: Severity;
}

function newSigAcc(): SigAcc {
  return {
    count: 0,
    score: 0,
    severe: 0,
    sourceCounts: new Map(),
    targetCounts: new Map(),
    internalSources: new Set(),
    internalTargets: new Set(),
    blocked: 0,
    passed: 0,
    unknown: 0,
    severityMax: "info",
  };
}

/** Herfindahl index (Σ shareᵢ²) of a count map's distribution, 0..1. */
function herfindahl(counts: Map<string, number>, total: number): number {
  if (total <= 0) return 0;
  let hhi = 0;
  for (const c of counts.values()) {
    const share = c / total;
    hhi += share * share;
  }
  return hhi;
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  m: { distinctSignatures: number; sourcedAlerts: number; totalWindowAlerts: number },
  shapeCounts: ShapeCounts,
  signatures: SignatureAudience[],
  sharpestTargeted: SignatureAudience[],
  sprayCandidates: SignatureAudience[],
): string[] {
  const out: string[] = [];
  if (!signatures.length) return out;

  // Overall diffusion distribution — what kind of audience dominates.
  out.push(
    `📡 Over the last ${hours}h, **${m.distinctSignatures} signature(s)** fired across ${m.sourcedAlerts} ` +
      `attributable alert(s): ${shapeCounts.spray} spray · ${shapeCounts.swarm} swarm · ${shapeCounts.scan} scan · ` +
      `${shapeCounts.targeted} targeted.`,
  );

  // The single loudest signature, with its audience read so the volume is framed.
  const lead = signatures[0]!;
  out.push(
    `🔊 Loudest signature is **${truncSig(lead.signature)}** — ${lead.count} alert(s), **${shapeLabel(lead.shape)}** ` +
      `(${lead.distinctSources} source(s), ~${lead.effectiveSources} effective; ${lead.distinctTargets} target(s)). ` +
      (lead.shape === "spray"
        ? `Diffuse crowd against many hosts — background radiation, safe to down-prioritise.`
        : lead.shape === "targeted"
          ? `Few sources at few hosts — this loud row is *focused*, not noise. Investigate.`
          : `Read the audience before triaging volume.`),
  );

  // The buried snipes — targeted signatures that volume ranking hides.
  const sharp = sharpestTargeted.filter((s) => s.severe > 0);
  if (sharp.length) {
    const s = sharp[0]!;
    out.push(
      `🎯 **${sharp.length} targeted signature(s)** carry medium+ severity from just a handful of sources — the ` +
        `sharp signals raw volume buries. Top: **${truncSig(s.signature)}** from \`${s.dominantSource ?? "?"}\`` +
        `${s.topTarget ? ` → \`${s.topTarget}\`` : ""} (${s.count} alert(s), ${s.severe} severe). Investigate before noise.`,
    );
  }

  // Internal sources firing a signature — a compromise / lateral-movement tell.
  const insider = signatures.find((s) => s.internalSources > 0);
  if (insider) {
    out.push(
      `🚨 **${truncSig(insider.signature)}** is being fired *by ${insider.internalSources} internal host(s)* — an ` +
        `IPS rule tripping on your own egress is a compromise / lateral-movement tell, not an inbound attacker. ` +
        `Investigate the internal source(s) first.`,
    );
  }

  // The loudest background radiation — tuning candidates.
  const spray = sprayCandidates[0];
  if (spray && spray.count >= 20) {
    const sprayVolume = sprayCandidates.reduce((n, s) => n + s.count, 0);
    out.push(
      `🌐 **${sprayCandidates.length} spray signature(s)** account for ${sprayVolume} alert(s) of internet ` +
        `background radiation. Loudest: **${truncSig(spray.signature)}** (${spray.count} alert(s) from ` +
        `${spray.distinctSources} diffuse sources). Collapse / down-prioritise these so the targeted signal surfaces.`,
    );
  }

  // A concentrated crowd — high distinct-source count but one actor dominates.
  const masked = signatures
    .filter((s) => s.distinctSources >= 10 && s.dominantShare >= 0.6)
    .sort((a, b) => b.count - a.count)[0];
  if (masked) {
    out.push(
      `🕵️ **${truncSig(masked.signature)}** looks crowd-sourced (${masked.distinctSources} sources) but ` +
        `\`${masked.dominantSource ?? "?"}\` fires **${pct(masked.dominantShare)}** of it — effectively a single ` +
        `actor (${masked.effectiveSources} effective sources) hiding in a noisy long tail. Block the dominant source.`,
    );
  }

  // Data-attribution honesty — how much of the stream could be attributed.
  if (m.totalWindowAlerts > 0) {
    const frac = m.sourcedAlerts / m.totalWindowAlerts;
    if (frac < 0.5) {
      out.push(
        `ℹ️ Only **${pct(frac)} of windowed alerts carried both a signature and a source IP** — every source count ` +
          `here is a lower bound; the diffusion calls lean on what could be attributed.`,
      );
    }
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function signatureRow(s: SignatureAudience, i: number): string[] {
  const flags =
    (s.internalSources ? "🏠" : "") +
    (s.dominantBlocked ? "⛔" : "") +
    (s.dominantWatched ? "👁" : "") +
    (s.dominantSafe ? "✅" : "") +
    (s.severityMax === "high" || s.severityMax === "critical" ? "🔥" : "");
  return [
    String(i + 1),
    cell(truncSig(s.signature)),
    cell(shapeLabel(s.shape)),
    String(s.count),
    String(s.distinctSources),
    String(s.effectiveSources),
    pct(s.dominantShare),
    String(s.distinctTargets),
    String(s.severe),
    s.disposition.passRate === null ? "—" : pct(s.disposition.passRate),
    flags || "—",
  ];
}

function signatureTable(rows: SignatureAudience[]): string {
  return mdTable(
    ["#", "Signature", "Shape", "Alerts", "Src", "Eff", "Top src %", "Tgt", "Severe", "Pass rate", "Flags"],
    rows.map(signatureRow),
  );
}

function targetedTable(rows: SignatureAudience[]): string {
  return mdTable(
    ["#", "Signature", "Severity", "Severe", "Alerts", "Dominant source", "Top target", "Flags"],
    rows.map((s, i) => {
      const flags =
        (s.internalSources ? "🏠" : "") +
        (s.dominantBlocked ? "⛔" : "") +
        (s.dominantWatched ? "👁" : "") +
        (s.dominantSafe ? "✅" : "");
      return [
        String(i + 1),
        cell(truncSig(s.signature)),
        cell(s.severityMax),
        String(s.severe),
        String(s.count),
        cell(s.dominantSource ?? "—"),
        cell(s.topTarget ?? "—"),
        flags || "—",
      ];
    }),
  );
}

function sprayTable(rows: SignatureAudience[]): string {
  return mdTable(
    ["#", "Signature", "Alerts", "Sources", "Eff", "Targets", "Pass rate"],
    rows.map((s, i) => [
      String(i + 1),
      cell(truncSig(s.signature)),
      String(s.count),
      String(s.distinctSources),
      String(s.effectiveSources),
      String(s.distinctTargets),
      s.disposition.passRate === null ? "—" : pct(s.disposition.passRate),
    ]),
  );
}

function renderMarkdown(m: AudienceReport): string {
  const lines: string[] = [];
  lines.push(`# 📡 SecTool Signature-Audience / Spray-vs-Snipe Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** each signature's effective source count (inverse-Simpson \`1 / Σ shareᵢ²\` over its per-source ` +
      `alert shares) × distinct target count, classified against thresholds (≥${m.sourceThreshold} eff. sources = ` +
      `"many sources", ≥${m.targetThreshold} targets = "many targets") · ` +
      `**Attributed:** ${m.sourcedAlerts} of ${m.totalWindowAlerts} alert(s) carried a signature + source IP`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.signatures.length) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but none carried both a signature and a ` +
          `valid source IP with enough volume to analyse an audience (min ${DEFAULT_MIN_ALERTS} alerts/signature by default).`,
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

  lines.push(`## Signatures by volume — annotated with their audience`);
  lines.push("");
  lines.push(signatureTable(m.signatures));
  lines.push("");
  lines.push(
    `**Legend:** _Shape_ — **🌐 spray** (many sources × many targets: background radiation) · **🐝 swarm** (many ` +
      `sources × few targets: a crowd on one box) · **🛰 scan** (few sources × many targets: cross-ref the scan ` +
      `report) · **🎯 targeted** (few sources × few targets: focused signal). _Src_ = distinct sources · _Eff_ = ` +
      `diversity-weighted effective sources (discounts one-shot tail) · _Top src %_ = dominant source's share · ` +
      `_Tgt_ = distinct targets · _Pass rate_ = share of *actioned* alerts let through. **Flags:** 🏠 fired by an ` +
      `internal source · ⛔ dominant source blocked · 👁 watched · ✅ safe · 🔥 high/critical severity.`,
  );
  lines.push("");

  lines.push(`## 🎯 Sharpest targeted signatures — the snipes volume buries`);
  lines.push("");
  if (!m.sharpestTargeted.length) {
    lines.push(`_No signature classified as targeted this window._`);
  } else {
    lines.push(
      `Few-source, few-target signatures ranked by severity — low-volume by definition, so they sit at the bottom ` +
        `of the table above. These are the most likely to be a real, hands-on event rather than internet noise.`,
    );
    lines.push("");
    lines.push(targetedTable(m.sharpestTargeted));
  }
  lines.push("");

  lines.push(`## 🌐 Top spray / tuning candidates`);
  lines.push("");
  if (!m.sprayCandidates.length) {
    lines.push(`_No signature classified as spray this window._`);
  } else {
    lines.push(
      `The loudest background radiation — diffuse crowds firing the same rule at many hosts. Collapsing, ` +
        `down-prioritising, or suppression-tuning these recovers the most console space for the least lost signal.`,
    );
    lines.push("");
    lines.push(sprayTable(m.sprayCandidates));
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Audience **shape** is a heuristic over the source/target thresholds — the raw ` +
      `counts and the effective-source number are shown so the call can be second-guessed. **Effective sources** is ` +
      `inverse-Simpson \`1 / Σ shareᵢ²\`, which discounts a long tail of one-shot sources, so a crowd dominated by one ` +
      `actor reads as concentrated; the dominant share is shown alongside. These are IPS **detections**, not full ` +
      `flows — a source that never trips a rule is invisible, so every source count is a lower bound. A long ` +
      `look-back can hit the store's history cap and undercount volume and breadth. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the signature-audience / spray-vs-snipe report from the stored alert
 * history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link AudienceOptions}: `limit`, `sourceThreshold`,
 *              `targetThreshold`, `minAlerts`, and a `nowMs` pin for tests.
 */
export function buildAudience(hours: number, opts: AudienceOptions = {}): AudienceReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const sourceThreshold = Math.max(1, Math.floor(opts.sourceThreshold ?? DEFAULT_SOURCE_THRESHOLD));
  const targetThreshold = Math.max(1, Math.floor(opts.targetThreshold ?? DEFAULT_TARGET_THRESHOLD));
  const minAlerts = Math.max(1, Math.floor(opts.minAlerts ?? DEFAULT_MIN_ALERTS));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const sigs = new Map<string, SigAcc>();
  let sourced = 0;

  for (const a of windowed) {
    const src = validIp(a.srcIp);
    if (!src) continue;
    const sig = (a.signature ?? "").trim() || "(unlabeled signature)";
    sourced++;

    const acc = sigs.get(sig) ?? newSigAcc();
    if (!sigs.has(sig)) sigs.set(sig, acc);
    acc.count++;
    acc.score += weightOf(a.severity);
    acc.severityMax = maxSeverity(acc.severityMax, a.severity);
    if (isSevere(a.severity)) acc.severe++;

    acc.sourceCounts.set(src, (acc.sourceCounts.get(src) ?? 0) + 1);
    if (isPrivate(src)) acc.internalSources.add(src);

    const dst = validIp(a.dstIp);
    if (dst) {
      acc.targetCounts.set(dst, (acc.targetCounts.get(dst) ?? 0) + 1);
      if (isPrivate(dst)) acc.internalTargets.add(dst);
    }

    const disp = classifyDisposition(a.action);
    if (disp === "blocked") acc.blocked++;
    else if (disp === "passed") acc.passed++;
    else acc.unknown++;
  }

  const shapeCounts: ShapeCounts = { spray: 0, swarm: 0, scan: 0, targeted: 0 };

  const sigList: SignatureAudience[] = [...sigs.entries()]
    .filter(([, acc]) => acc.count >= minAlerts)
    .map(([signature, acc]) => {
      const distinctSources = acc.sourceCounts.size;
      const distinctTargets = acc.targetCounts.size;
      const hhi = herfindahl(acc.sourceCounts, acc.count);
      const effectiveSources = hhi > 0 ? round2(1 / hhi) : 0;
      const shape = classifyShape(effectiveSources, distinctTargets, sourceThreshold, targetThreshold);
      shapeCounts[shape]++;
      const actioned = acc.blocked + acc.passed;
      const dom = topOf(acc.sourceCounts);
      const topTarget = topOf(acc.targetCounts);
      const dominantSource = dom.key;
      return {
        signature,
        shape,
        count: acc.count,
        distinctSources,
        effectiveSources,
        sourceHHI: round4(hhi),
        dominantSource,
        dominantShare: acc.count ? round4(dom.count / acc.count) : 0,
        distinctTargets,
        topTarget: topTarget.key,
        internalSources: acc.internalSources.size,
        internalTargets: acc.internalTargets.size,
        severe: acc.severe,
        score: acc.score,
        severityMax: acc.severityMax,
        disposition: {
          blocked: acc.blocked,
          passed: acc.passed,
          unknown: acc.unknown,
          passRate: actioned ? round4(acc.passed / actioned) : null,
        },
        dominantBlocked: dominantSource ? blockStore.has(dominantSource) : false,
        dominantWatched: dominantSource ? watchStore.has(dominantSource) : false,
        dominantSafe: dominantSource ? safeStore.has(dominantSource) : false,
      } satisfies SignatureAudience;
    });

  // shapeCounts is accumulated across *all* qualifying signatures above. The
  // roll-ups draw from the full list; the primary table is capped for display.
  const byVolume = [...sigList].sort(
    (x, y) =>
      y.count - x.count ||
      y.score - x.score ||
      (x.signature < y.signature ? -1 : x.signature > y.signature ? 1 : 0),
  );

  const sharpestTargeted = sigList
    .filter((s) => s.shape === "targeted")
    // Sharpest first: severity score, then severe count, then volume.
    .sort(
      (x, y) =>
        y.score - x.score ||
        y.severe - x.severe ||
        y.count - x.count ||
        (x.signature < y.signature ? -1 : x.signature > y.signature ? 1 : 0),
    )
    .slice(0, limit);

  const sprayCandidates = sigList
    .filter((s) => s.shape === "spray")
    // Loudest background radiation first.
    .sort(
      (x, y) =>
        y.count - x.count ||
        y.distinctSources - x.distinctSources ||
        (x.signature < y.signature ? -1 : x.signature > y.signature ? 1 : 0),
    )
    .slice(0, limit);

  const cappedSignatures = byVolume.slice(0, limit);

  const highlights = writeHighlights(
    safeHours,
    { distinctSignatures: sigList.length, sourcedAlerts: sourced, totalWindowAlerts: windowed.length },
    shapeCounts,
    cappedSignatures,
    sharpestTargeted,
    sprayCandidates,
  );

  const model: AudienceReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    sourcedAlerts: sourced,
    sourceThreshold,
    targetThreshold,
    distinctSignatures: sigList.length,
    shapeCounts,
    signatures: cappedSignatures,
    sharpestTargeted,
    sprayCandidates,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded signature-audience report. */
export function audienceFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-audience-${stamp}.md`;
}
