/**
 * Risk-index / threat-posture report — "in one number, how bad is it right
 * now, and what is driving that number?"
 *
 * Every other offline report in this project answers a *structural* question:
 * how is the alert traffic distributed (focus), what taxonomy does it fall into
 * (classify), how is it flowing (direction), who is the worst single source
 * (persistence / netblock), is it concentrated, periodic, escalating, etc. None
 * of them collapse the window into a single, severity-weighted **magnitude** —
 * the thing an operator actually glances at first in the morning:
 *
 *   **"Is today worse than yesterday, and which handful of things made it so?"**
 *
 * Raw alert counts can't answer that. A thousand blocked `info` port-scan hits
 * are operationally quieter than a single *passed* `critical` exploit. So this
 * report assigns every windowed alert a **risk weight** = `severityWeight ×
 * dispositionFactor`, where:
 *
 *   - **severityWeight** climbs geometrically (info 1 · low 3 · medium 9 ·
 *     high 27 · critical 81), because each severity step is roughly an order of
 *     magnitude more consequential than the last — a linear 1..5 ladder badly
 *     under-weights the critical tail.
 *   - **dispositionFactor** discounts what the gateway actually *stopped*
 *     (blocked ×0.2) and keeps full weight on what it let through (passed ×1.0),
 *     with unknown-action alerts in between (×0.7). A blocked critical is a win;
 *     a *passed* critical is the headline. Reuses efficacy.ts's
 *     `classifyDisposition` so "block / drop / deny" vs "detect / allow / pass"
 *     is parsed identically everywhere.
 *
 * Summing those weights gives the **Risk Index** (an absolute magnitude) and,
 * normalised by window length, a **per-day rate** so windows of different sizes
 * compare. Because an absolute index is hard to read across deployments, the
 * report also derives a scale-independent **posture grade (A–F)** from the
 * *severe-exposure ratio* — of all the risk weight carried by medium-or-worse
 * alerts, how much of it was **not** blocked. A=all serious threats stopped,
 * F=most of the serious weight got through. That ratio doesn't care whether you
 * see ten alerts or ten thousand; it cares whether the gateway is winning.
 *
 * It then attributes the index three ways, so "the number went up" always comes
 * with "…because of these":
 *
 *   - **Severity mix** — weight contributed by each severity band, with its
 *     blocked / passed / unknown split. Shows whether the index is driven by a
 *     loud-but-low long tail or a few heavy criticals.
 *   - **Top risk-driving sources** — external/internal IPs ranked by summed
 *     weight (not count), each with its unmitigated weight and per-source
 *     exposure, plus blocklist / watchlist / safelist flags (mirrors
 *     direction.ts / persistence.ts / focus.ts).
 *   - **Top risk-driving signatures** — the rules carrying the most weight, the
 *     fastest route from "the index is high" to "go tune / block this".
 *
 * Honest caveats baked into the output:
 *
 *   - **The weights are a heuristic, not physics.** The severity ladder and
 *     disposition factors are deliberate, documented choices (exported as
 *     {@link SEVERITY_WEIGHT} / {@link DISPOSITION_FACTOR}); a different shop may
 *     weight differently. The index is a *relative* gauge — track its trend, and
 *     trust the attribution tables more than the absolute number.
 *   - **Severity is the gateway's, disposition is the gateway's.** A miscategor-
 *     ised or mis-actioned alert weights wrong. Garbage in, weighted garbage out.
 *   - **Alerts, not flows.** A real compromise that never trips a rule
 *     contributes zero weight; a calm index is not a clean network.
 *   - **Window-bounded & store-capped.** A long look-back can hit the store's
 *     history cap and truncate the oldest alerts, deflating the index.
 *
 * Pure in-memory math over alertStore (plus blocklist/watchlist/safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring report.ts, direction.ts,
 * focus.ts, efficacy.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/**
 * Per-severity base weight. Geometric (×3 per step) so each severity band is
 * worth roughly an order of magnitude more than the one below it — a linear
 * 1..5 ladder under-weights the critical tail badly. Exported & documented so
 * the weighting is auditable and a different deployment can reason about (or
 * fork) it.
 */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  info: 1,
  low: 3,
  medium: 9,
  high: 27,
  critical: 81,
};

/** Machine key for an alert's enforcement disposition (mirrors efficacy.ts). */
export type Disposition = "blocked" | "passed" | "unknown";

/**
 * Multiplier applied to {@link SEVERITY_WEIGHT} by enforcement disposition. The
 * gateway *stopping* a threat should not weigh the same as it *letting the
 * threat through*: a blocked critical is a win, a passed critical is the
 * headline. `unknown` (no recorded action) sits in between. Exported so the
 * discount is auditable.
 */
export const DISPOSITION_FACTOR: Record<Disposition, number> = {
  blocked: 0.2,
  passed: 1.0,
  unknown: 0.7,
};

/** A posture grade derived from the severe-exposure ratio (scale-independent). */
export type PostureGrade = "A" | "B" | "C" | "D" | "F";

const GRADE_LABEL: Record<PostureGrade, string> = {
  A: "A — contained (serious threats blocked)",
  B: "B — mostly contained",
  C: "C — elevated exposure",
  D: "D — high exposure",
  F: "F — critical exposure (serious threats getting through)",
};

/** Weighted contribution of a single severity band over the window. */
export interface SeverityWeight {
  severity: Severity;
  /** Alerts at this severity. */
  count: number;
  /** Summed risk weight contributed by this band (severity × disposition). */
  weight: number;
  /** weight / totalWeight, 0..1 (4dp). */
  share: number;
  /** Of {@link count}, alerts the gateway blocked. */
  blocked: number;
  /** Of {@link count}, alerts the gateway let through. */
  passed: number;
  /** Of {@link count}, alerts with no recorded action. */
  unknown: number;
}

/** One IP (or signature) ranked by the risk weight it drove. */
export interface RiskDriver {
  /** The driving key — an IP for sources, the rule text for signatures. */
  key: string;
  /** Summed risk weight attributed to this driver. */
  weight: number;
  /** weight / totalWeight, 0..1 (4dp). */
  share: number;
  /** Alerts attributed to this driver. */
  count: number;
  /** Of {@link weight}, the part that was *not* blocked (passed + unknown). */
  unmitigatedWeight: number;
  /** unmitigatedWeight / weight, 0..1 (4dp) — this driver's own exposure. */
  exposure: number;
  /** Worst severity seen across this driver's alerts. */
  severityMax: Severity;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** The driver is on the blocklist (sources only; false for signatures). */
  blocked: boolean;
  /** The driver is on the watchlist (sources only). */
  watched: boolean;
  /** The driver is marked safe (sources only). */
  safe: boolean;
}

export interface RiskReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** The headline severity-weighted magnitude (sum of all alert weights). */
  riskIndex: number;
  /** {@link riskIndex} normalised to a 24h rate, so windows of any size compare. */
  perDayIndex: number;
  /** Mean risk weight per alert — how "heavy" the typical alert is. */
  avgWeightPerAlert: number;
  /** Of {@link riskIndex}, the weight carried by *unblocked* (passed+unknown) alerts. */
  unmitigatedWeight: number;
  /** unmitigatedWeight / riskIndex, 0..1 (4dp) — overall exposure of the window. */
  exposure: number;
  /** Of the medium+ weight, the unblocked share, 0..1 (4dp). Drives {@link grade}. */
  severeExposure: number;
  /** Scale-independent posture grade derived from {@link severeExposure}. */
  grade: PostureGrade;
  /** Human label for {@link grade}. */
  gradeLabel: string;
  /** Per-severity weighted breakdown, critical first. */
  severityMix: SeverityWeight[];
  /** Source IPs driving the most risk weight, heaviest first. */
  topSources: RiskDriver[];
  /** Signatures driving the most risk weight, heaviest first. */
  topSignatures: RiskDriver[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface RiskOptions {
  /** Max rows in the source / signature tables (clamped to [1, 100]). */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 15;
const MS_PER_HOUR = 3_600_000;

// ----- formatting helpers (mirror direction.ts / focus.ts / efficacy.ts) -----

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** A 0..1 fraction as a whole-number percent string, e.g. 0.823 -> "82%". */
function pct(frac: number): string {
  return `${Math.round(frac * 100)}%`;
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
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

// ----- classifiers ----------------------------------------------------------

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

/** Coerce a stored severity string to a known band, defaulting to "info". */
function asSeverity(s: string | undefined): Severity {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? "info" : (s as Severity);
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? asSeverity(b) : a;
}

function isSevere(s: string | undefined): boolean {
  return sevRank(s) >= 2; // medium or worse
}

/** A valid, non-empty IP, or undefined if the field is missing/garbage. */
function validIp(ip: string | undefined): string | undefined {
  return ip && isIP(ip) !== 0 ? ip : undefined;
}

/** The risk weight of a single alert: severity weight discounted by disposition. */
function alertWeight(severity: Severity, disp: Disposition): number {
  return SEVERITY_WEIGHT[severity] * DISPOSITION_FACTOR[disp];
}

/** Map a severe-exposure ratio (0..1) to a posture grade. */
function gradeFor(severeExposure: number, severeWeight: number): PostureGrade {
  if (severeWeight <= 0) return "A"; // no serious weight at all
  if (severeExposure <= 0) return "A"; // every serious alert was blocked
  if (severeExposure < 0.15) return "B";
  if (severeExposure < 0.4) return "C";
  if (severeExposure < 0.7) return "D";
  return "F";
}

// ----- driver aggregation ----------------------------------------------------

interface DriverAcc {
  weight: number;
  count: number;
  unmitigatedWeight: number;
  severityMax: Severity;
  severe: number;
}

function newDriverAcc(): DriverAcc {
  return { weight: 0, count: 0, unmitigatedWeight: 0, severityMax: "info", severe: 0 };
}

function addToDriver(
  map: Map<string, DriverAcc>,
  key: string,
  weight: number,
  disp: Disposition,
  severity: Severity,
): void {
  let acc = map.get(key);
  if (!acc) {
    acc = newDriverAcc();
    map.set(key, acc);
  }
  acc.weight += weight;
  acc.count++;
  if (disp !== "blocked") acc.unmitigatedWeight += weight;
  acc.severityMax = maxSeverity(acc.severityMax, severity);
  if (isSevere(severity)) acc.severe++;
}

function finishDrivers(
  map: Map<string, DriverAcc>,
  totalWeight: number,
  limit: number,
  membership: (key: string) => { blocked: boolean; watched: boolean; safe: boolean },
): RiskDriver[] {
  return [...map.entries()]
    .map(([key, a]) => {
      const m = membership(key);
      return {
        key,
        weight: round1(a.weight),
        share: totalWeight ? round4(a.weight / totalWeight) : 0,
        count: a.count,
        unmitigatedWeight: round1(a.unmitigatedWeight),
        exposure: a.weight ? round4(a.unmitigatedWeight / a.weight) : 0,
        severityMax: a.severityMax,
        severe: a.severe,
        blocked: m.blocked,
        watched: m.watched,
        safe: m.safe,
      } satisfies RiskDriver;
    })
    // Heaviest first; tie-break on unmitigated weight, then count, then key for
    // a stable deterministic order.
    .sort(
      (x, y) =>
        y.weight - x.weight ||
        y.unmitigatedWeight - x.unmitigatedWeight ||
        y.count - x.count ||
        (x.key < y.key ? -1 : x.key > y.key ? 1 : 0),
    )
    .slice(0, limit);
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(m: Omit<RiskReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (!m.totalWindowAlerts) return out;

  // Headline magnitude + grade.
  out.push(
    `📊 **Risk Index ${m.riskIndex.toLocaleString("en-US")}** over the last ${m.hours}h ` +
      `(${m.perDayIndex.toLocaleString("en-US")}/day, ${m.avgWeightPerAlert} avg weight across ` +
      `${m.totalWindowAlerts.toLocaleString("en-US")} alerts) — **posture grade ${m.gradeLabel}**. ` +
      `The index is a severity-weighted magnitude (info 1 … critical 81), discounted for what the gateway ` +
      `blocked; track its *trend* more than its absolute value.`,
  );

  // Exposure — the part that matters most: what got through, by weight.
  if (m.severeExposure > 0) {
    out.push(
      `⚠️ **${pct(m.severeExposure)} of the serious (medium+) risk weight was NOT blocked** — the gateway either ` +
        `detected-only or had no action on the alerts that carry the most consequence. This ratio, not the raw ` +
        `index, drives the grade; closing it is the highest-leverage move (see the efficacy report for the rules).`,
    );
  } else {
    out.push(
      `✅ Every medium-or-worse alert this window was blocked — the serious weight is fully mitigated. The residual ` +
        `index is low-severity noise; the grade reflects that the gateway is winning where it counts.`,
    );
  }

  // What severity band is driving the number.
  const drivingBand = [...m.severityMix].sort((a, b) => b.weight - a.weight)[0];
  if (drivingBand && drivingBand.weight > 0) {
    out.push(
      `🧮 The index is driven mostly by **${drivingBand.severity}** alerts (${pct(drivingBand.share)} of the weight, ` +
        `${drivingBand.count} alert(s), ${drivingBand.passed} passed / ${drivingBand.blocked} blocked). ` +
        (sevRank(drivingBand.severity) >= 3
          ? `A high-severity band dominating the weight is the worst shape — these are the alerts to triage first.`
          : `A low-severity band dominating the weight usually means high-volume background noise — verify before alarm.`),
    );
  }

  // Heaviest single source.
  const topSrc = m.topSources[0];
  if (topSrc) {
    const flagNote = topSrc.safe
      ? " (safelisted — expected; likely a benign weight contributor)"
      : topSrc.blocked
        ? " (already blocklisted)"
        : topSrc.watched
          ? " (already watchlisted)"
          : "";
    out.push(
      `🎯 Heaviest source \`${topSrc.key}\`${flagNote} drives **${pct(topSrc.share)} of the total weight** ` +
        `(${topSrc.weight} weight across ${topSrc.count} alert(s), peak ${topSrc.severityMax}, ` +
        `${pct(topSrc.exposure)} of its weight unblocked). ` +
        (!topSrc.blocked && !topSrc.safe && topSrc.exposure >= 0.5
          ? `Unblocked and heavy — a strong block / investigate candidate.`
          : `Work the source table top-down.`),
    );
  }

  // Heaviest signature.
  const topSig = m.topSignatures[0];
  if (topSig) {
    out.push(
      `🔖 Heaviest signature **${clip(topSig.key, 60)}** carries ${pct(topSig.share)} of the weight ` +
        `(${topSig.count} alert(s), ${pct(topSig.exposure)} unblocked) — the fastest single lever on the index, ` +
        `whether by blocking the matching traffic or tuning a noisy low-severity rule.`,
    );
  }

  // Blocked-mitigation credit — what the gateway already absorbed.
  const mitigatedWeight = round1(m.riskIndex - m.unmitigatedWeight);
  if (mitigatedWeight > 0) {
    out.push(
      `🛡️ The gateway already absorbed **${mitigatedWeight.toLocaleString("en-US")} weight** by blocking ` +
        `(${pct(1 - m.exposure)} of the total). That work is credited at the disposition discount, so the index ` +
        `you see is the *residual* exposure, not the gross threat volume.`,
    );
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function severityMixTable(rows: SeverityWeight[]): string {
  return mdTable(
    ["Severity", "Alerts", "Weight", "Share", "Blocked", "Passed", "Unknown"],
    rows.map((r) => [
      cell(r.severity),
      String(r.count),
      String(round1(r.weight)),
      pct(r.share),
      String(r.blocked),
      String(r.passed),
      String(r.unknown),
    ]),
  );
}

function sourceTable(rows: RiskDriver[]): string {
  return mdTable(
    ["#", "Source", "Weight", "Share", "Alerts", "Unblocked wt", "Exposure", "Peak sev", "Severe", "Flags"],
    rows.map((r, i) => {
      const flags = (r.blocked ? "⛔" : "") + (r.watched ? "👁" : "") + (r.safe ? "✅" : "");
      return [
        String(i + 1),
        cell(r.key),
        String(r.weight),
        pct(r.share),
        String(r.count),
        String(r.unmitigatedWeight),
        pct(r.exposure),
        cell(r.severityMax),
        String(r.severe),
        flags || "—",
      ];
    }),
  );
}

function signatureTable(rows: RiskDriver[]): string {
  return mdTable(
    ["#", "Signature", "Weight", "Share", "Alerts", "Unblocked wt", "Exposure", "Peak sev"],
    rows.map((r, i) => [
      String(i + 1),
      cell(clip(r.key, 60)),
      String(r.weight),
      pct(r.share),
      String(r.count),
      String(r.unmitigatedWeight),
      pct(r.exposure),
      cell(r.severityMax),
    ]),
  );
}

function renderMarkdown(m: RiskReport): string {
  const lines: string[] = [];
  lines.push(`# 📊 SecTool Risk-Index / Threat-Posture Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** each stored IPS alert weighted \`severity × disposition\` ` +
      `(info 1 · low 3 · medium 9 · high 27 · critical 81; blocked ×0.2 · unknown ×0.7 · passed ×1.0) · ` +
      `**Window alerts:** ${m.totalWindowAlerts}`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.totalWindowAlerts) {
    lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to weigh.`);
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  // Scorecard block — the at-a-glance numbers.
  lines.push(`| Metric | Value |`);
  lines.push(`| --- | --- |`);
  lines.push(`| **Risk Index** | **${m.riskIndex.toLocaleString("en-US")}** |`);
  lines.push(`| Per-day rate | ${m.perDayIndex.toLocaleString("en-US")} /day |`);
  lines.push(`| Avg weight / alert | ${m.avgWeightPerAlert} |`);
  lines.push(`| Overall exposure (unblocked weight) | ${pct(m.exposure)} |`);
  lines.push(`| Severe (medium+) exposure | ${pct(m.severeExposure)} |`);
  lines.push(`| **Posture grade** | **${m.gradeLabel}** |`);
  lines.push("");

  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Severity mix (what the weight is made of)`);
  lines.push("");
  lines.push(severityMixTable(m.severityMix));
  lines.push("");
  lines.push(
    `**Legend:** _Weight_ is the severity base weight after the disposition discount, so a band's weight can be ` +
      `well below \`count × base\` when most of it was blocked. _Share_ is that weight as a fraction of the whole ` +
      `index. A high-severity band owning the share is the shape to worry about; a low-severity band owning it is ` +
      `usually background noise.`,
  );
  lines.push("");

  lines.push(`## Top risk-driving sources`);
  lines.push("");
  if (!m.topSources.length) {
    lines.push(`_No source IP could be attributed a weight this window (all alerts lacked a usable source)._`);
  } else {
    lines.push(
      `IPs ranked by the risk weight they drove (not raw count), so a single heavy alert can out-rank a noisy ` +
        `low-severity flood. _Unblocked wt_ / _Exposure_ isolate the part the gateway did **not** stop — the heaviest ` +
        `unblocked, un-flagged source is the strongest block / investigate candidate.`,
    );
    lines.push("");
    lines.push(sourceTable(m.topSources));
  }
  lines.push("");

  lines.push(`## Top risk-driving signatures`);
  lines.push("");
  if (!m.topSignatures.length) {
    lines.push(`_No signature could be attributed a weight this window (alerts carried no signature text)._`);
  } else {
    lines.push(
      `Rules ranked by the weight they carry — the fastest single lever on the index. A heavy, high-exposure ` +
        `*high/critical* signature is a blocking candidate; a heavy *low/info* one with high count is a tuning ` +
        `candidate (see the tuning report).`,
    );
    lines.push("");
    lines.push(signatureTable(m.topSignatures));
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from stored **IPS-alert** severity and action. The **Risk Index** is a ` +
      `**heuristic** severity-weighted magnitude (info 1 · low 3 · medium 9 · high 27 · critical 81) discounted by ` +
      `enforcement disposition (blocked ×0.2 · unknown ×0.7 · passed ×1.0) — a *relative* gauge best read as a ` +
      `trend, not an absolute score, and the attribution tables are more trustworthy than the single number. ` +
      `Severity and disposition are the gateway's own labels; a miscategorised alert weights wrong. These are ` +
      `detections, not flows — a compromise that never trips a rule contributes zero weight, so a calm index is ` +
      `not proof of a clean network. A long look-back can hit the store's history cap and deflate the index. No ` +
      `live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the risk-index / threat-posture report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link RiskOptions}: `limit` (source/signature rows) and a `nowMs` pin.
 */
export function buildRisk(hours: number, opts: RiskOptions = {}): RiskReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(100, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  // Per-severity accumulators (count + weight + disposition split).
  const sevAcc = new Map<Severity, { count: number; weight: number; blocked: number; passed: number; unknown: number }>(
    SEVERITY_ORDER.map((s) => [s, { count: 0, weight: 0, blocked: 0, passed: 0, unknown: 0 }] as const),
  );
  const sources = new Map<string, DriverAcc>();
  const signatures = new Map<string, DriverAcc>();

  let totalWeight = 0;
  let unmitigatedWeight = 0;
  let severeWeight = 0;
  let severeUnmitigated = 0;

  for (const a of windowed) {
    const severity = asSeverity(a.severity);
    const disp = classifyDisposition(a.action);
    const weight = alertWeight(severity, disp);

    totalWeight += weight;
    if (disp !== "blocked") unmitigatedWeight += weight;
    if (isSevere(severity)) {
      severeWeight += weight;
      if (disp !== "blocked") severeUnmitigated += weight;
    }

    const sev = sevAcc.get(severity)!;
    sev.count++;
    sev.weight += weight;
    if (disp === "blocked") sev.blocked++;
    else if (disp === "passed") sev.passed++;
    else sev.unknown++;

    const src = validIp(a.srcIp);
    if (src) addToDriver(sources, src, weight, disp, severity);
    const sig = a.signature?.trim();
    if (sig) addToDriver(signatures, sig, weight, disp, severity);
  }

  // Severity mix, critical (highest) first.
  const severityMix: SeverityWeight[] = [...SEVERITY_ORDER]
    .reverse()
    .map((s) => {
      const acc = sevAcc.get(s)!;
      return {
        severity: s,
        count: acc.count,
        weight: round1(acc.weight),
        share: totalWeight ? round4(acc.weight / totalWeight) : 0,
        blocked: acc.blocked,
        passed: acc.passed,
        unknown: acc.unknown,
      } satisfies SeverityWeight;
    });

  const topSources = finishDrivers(sources, totalWeight, limit, (ip) => ({
    blocked: blockStore.has(ip),
    watched: watchStore.has(ip),
    safe: safeStore.has(ip),
  }));
  // Signatures have no IP membership; flags are always false.
  const topSignatures = finishDrivers(signatures, totalWeight, limit, () => ({
    blocked: false,
    watched: false,
    safe: false,
  }));

  const windowDays = safeHours / 24;
  const exposure = totalWeight ? round4(unmitigatedWeight / totalWeight) : 0;
  const severeExposure = severeWeight ? round4(severeUnmitigated / severeWeight) : 0;
  const grade = gradeFor(severeExposure, severeWeight);

  const base: Omit<RiskReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    riskIndex: round1(totalWeight),
    perDayIndex: windowDays > 0 ? round1(totalWeight / windowDays) : round1(totalWeight),
    avgWeightPerAlert: windowed.length ? round1(totalWeight / windowed.length) : 0,
    unmitigatedWeight: round1(unmitigatedWeight),
    exposure,
    severeExposure,
    grade,
    gradeLabel: GRADE_LABEL[grade],
    severityMix,
    topSources,
    topSignatures,
  };

  const highlights = writeHighlights(base);
  const model: RiskReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded risk-index report. */
export function riskFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-risk-${stamp}.md`;
}
