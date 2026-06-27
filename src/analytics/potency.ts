/**
 * Threat-potency / severity-density report — "**which sources are loud but
 * harmless, and which are quiet but deadly?**"
 *
 * Almost every other source-ranking report in SecTool sorts by *volume* or by a
 * *volume-inflated* magnitude, so the same handful of chatty scanners top the
 * list again and again:
 *
 *   - **persist / netblocks / spread / focus** rank by raw alert **count** (or
 *     distinct-target reach) — a 5 000-hit `info` port-sweep dwarfs a 9-hit
 *     `critical` exploit chain.
 *   - **risk** ranks by **summed** severity-weight. That is the right lens for
 *     "total damage", but a big enough flood of low-severity noise still
 *     out-totals a small, lethal burst — the quiet sniper sinks down the table.
 *   - **heat** ranks by **recency**; **momentum** by **rate-of-change**. Neither
 *     asks how *consequential the average alert from this source actually is*.
 *
 * This report flips the axis to **density**: for each source it computes the
 * **mean risk weight per alert** — `Σ(severityWeight × dispositionFactor) ÷
 * alerts` — reusing the exact ladder and enforcement discount from `risk.ts`
 * (`info 1 · low 3 · medium 9 · high 27 · critical 81`, blocked ×0.2 / unknown
 * ×0.7 / passed ×1.0). Density answers the triage question volume buries:
 *
 *   **"If I only get to look at one alert from this source, how bad is it likely
 *   to be?"**
 *
 * Crossing density against volume yields four operisationally distinct quadrants
 * (thresholds documented and exported):
 *
 *   - **🎯 Sniper** — high density, low volume. Quiet but deadly: few alerts,
 *     but every one matters. The find this report exists for — the source a
 *     volume ranking *never* surfaces. Investigate by hand.
 *   - **🔴 Brawler** — high density *and* high volume. Loud **and** lethal:
 *     the genuine heavy hitter. Block / escalate first.
 *   - **📢 Flood** — high volume, low density. Loud but harmless: commodity
 *     scan-noise inflating every other report. Safe to auto-handle, mute, or
 *     rate-limit — *not* worth a human's morning.
 *   - **· Background** — low on both. The long tail.
 *
 * The headline contrast is the punch-line: floods typically carry the bulk of
 * alert **volume** but a sliver of the **weight**, while snipers carry trivial
 * volume but disproportionate weight — so the report prints exactly that split
 * ("this quadrant is X% of your alerts but Y% of your risk weight"), turning a
 * gut feeling into a number you can defend a mute rule with.
 *
 * Honest caveats baked into the output:
 *
 *   - **Density rewards small, severe bursts — so it needs a volume floor.** A
 *     single passed `critical` scores density 81 on n=1, which is real but
 *     statistically thin. Sources below `--min N` (default 3) are held out of
 *     the quadrant ranking and summarised separately as "thin-sample
 *     singletons" so a one-off fluke never crowns the sniper list.
 *   - **Weights are a heuristic, not physics.** Severity and disposition are the
 *     gateway's; a mis-graded or mis-actioned alert weighs wrong (the same
 *     caveat `risk.ts` carries). Density is a *relative* triage gauge — trust the
 *     ordering more than the absolute number.
 *   - **Blocked weight is discounted, not removed.** A source whose criticals
 *     were all blocked still shows nonzero density (×0.2); the **unmitigated**
 *     column tells you how much of that weight actually got through.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network. Output is
 * both a structured model and a ready-to-paste Markdown document, mirroring
 * risk.ts, timeline.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { classifyDisposition, type Disposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT, DISPOSITION_FACTOR } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** The four density×volume quadrants a source can fall into. */
export type PotencyClass = "sniper" | "brawler" | "flood" | "background";

/** One ranked source in the potency table. */
export interface PotencySource {
  ip: string;
  /** Whether the address is RFC1918 / loopback / link-local (lateral) vs public. */
  internal: boolean;
  /** Total alerts from this source in the window. */
  alerts: number;
  /** Summed risk weight (severity × disposition) across those alerts. */
  weight: number;
  /** Mean weight per alert — the density metric the report ranks on. */
  density: number;
  /** Portion of {@link weight} that was NOT blocked (passed + unknown). */
  unmitigatedWeight: number;
  /** Share of {@link weight} that got through, 0..1. */
  unmitigatedShare: number;
  /** High + critical alert count. */
  serious: number;
  /** Share of alerts that were high/critical, 0..1. */
  seriousShare: number;
  /** Worst severity observed from this source. */
  severityMax: Severity;
  /** Busiest signature from this source (by alert count), or undefined. */
  topSignature?: string;
  /** Distinct destination IPs this source touched. */
  targets: number;
  /** Quadrant classification. */
  klass: PotencyClass;
  blocked: boolean;
  watched: boolean;
  safe: boolean;
}

/** Roll-up of one quadrant across all its sources. */
export interface PotencyQuadrant {
  klass: PotencyClass;
  sources: number;
  alerts: number;
  weight: number;
  /** Share of all in-window alert *volume* this quadrant carries, 0..1. */
  alertShare: number;
  /** Share of all in-window risk *weight* this quadrant carries, 0..1. */
  weightShare: number;
}

export interface PotencyReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts in the window that carried a usable source IP. */
  totalAlerts: number;
  /** Distinct sources seen (before the {@link minAlerts} floor). */
  totalSources: number;
  /** The volume floor applied to qualify for the quadrant ranking. */
  minAlerts: number;
  /** Density (mean weight/alert) at or above which a source is "potent". */
  densityThreshold: number;
  /** Alert count at or above which a source is "high volume". */
  volumeThreshold: number;
  /** Sources held out of the ranking for falling below {@link minAlerts}. */
  singletonSources: number;
  /** Summed weight carried by those held-out singletons. */
  singletonWeight: number;
  /** Highest-density single held-out source (the thin-sample tell), if any. */
  topSingleton?: { ip: string; alerts: number; density: number; severityMax: Severity };
  /** Per-quadrant roll-up, ordered sniper → brawler → flood → background. */
  quadrants: PotencyQuadrant[];
  /** Ranked qualifying sources (density desc), capped at the row limit. */
  sources: PotencySource[];
  /** True when more qualifying sources exist than were shown. */
  truncated: boolean;
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface PotencyOptions {
  /** Max source rows shown (highest density kept); clamped to [1, 200]. Default 30. */
  limit?: number;
  /** Volume floor to qualify for the ranking; clamped to [1, 1000]. Default 3. */
  minAlerts?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 30;
const DEFAULT_MIN_ALERTS = 3;
const MS_PER_HOUR = 3_600_000;

/**
 * Density at/above which a source's *average* alert is "potent". Anchored to the
 * `risk.ts` ladder at `medium` (9): a mean weight ≥ 9 means the typical alert is
 * a medium-severity-equivalent-or-worse threat after the enforcement discount.
 */
export const POTENT_DENSITY_THRESHOLD = SEVERITY_WEIGHT.medium;

const CLASS_ORDER: readonly PotencyClass[] = ["sniper", "brawler", "flood", "background"];

const CLASS_LABEL: Record<PotencyClass, string> = {
  sniper: "🎯 Sniper",
  brawler: "🔴 Brawler",
  flood: "📢 Flood",
  background: "· Background",
};

const CLASS_BLURB: Record<PotencyClass, string> = {
  sniper: "quiet but deadly — few alerts, every one matters (investigate by hand)",
  brawler: "loud **and** lethal — the genuine heavy hitter (block / escalate first)",
  flood: "loud but harmless — commodity scan-noise (safe to mute / auto-handle)",
  background: "the long tail — low volume, low severity",
};

// ----- helpers (mirror risk.ts / timeline.ts) --------------------------------

function validIp(ip: string | undefined): string | undefined {
  return ip && isIP(ip) !== 0 ? ip : undefined;
}

/** RFC1918 / loopback / link-local / ULA — a lateral source, not a public attacker. */
function isInternal(ip: string): boolean {
  if (ip.includes(":")) {
    const lc = ip.toLowerCase();
    return lc === "::1" || lc.startsWith("fe80") || lc.startsWith("fc") || lc.startsWith("fd");
  }
  const o = ip.split(".").map(Number);
  if (o.length !== 4 || o.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  if (o[0] === 10) return true;
  if (o[0] === 172 && o[1]! >= 16 && o[1]! <= 31) return true;
  if (o[0] === 192 && o[1] === 168) return true;
  if (o[0] === 127) return true;
  if (o[0] === 169 && o[1] === 254) return true;
  return false;
}

function asSeverity(s: string | undefined): Severity {
  return (SEVERITY_ORDER as readonly string[]).includes(s ?? "") ? (s as Severity) : "info";
}

function sevRank(s: Severity): number {
  return (SEVERITY_ORDER as readonly string[]).indexOf(s);
}

function maxSeverity(a: Severity, b: Severity): Severity {
  return sevRank(b) > sevRank(a) ? b : a;
}

function isSerious(s: Severity): boolean {
  return sevRank(s) >= sevRank("high");
}

function alertWeight(sev: Severity, disp: Disposition): number {
  return SEVERITY_WEIGHT[sev] * DISPOSITION_FACTOR[disp];
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

function pct(share: number): string {
  return `${Math.round(share * 100)}%`;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function clip(s: string, max = 40): string {
  const t = s.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

function mdTable(headers: string[], rows: string[][]): string {
  if (!rows.length) return "_None._";
  const head = `| ${headers.join(" | ")} |`;
  const sep = `| ${headers.map(() => "---").join(" | ")} |`;
  const body = rows.map((r) => `| ${r.join(" | ")} |`).join("\n");
  return `${head}\n${sep}\n${body}`;
}

function flagStr(s: PotencySource): string {
  const f: string[] = [];
  if (s.safe) f.push("🟢safe");
  if (s.blocked) f.push("🚫blocked");
  if (s.watched) f.push("👁watch");
  if (s.internal) f.push("🏠internal");
  return f.length ? f.join(" ") : "—";
}

/** The keyed mode (most frequent value) of a count map, deterministic tie-break. */
function topKey(counts: Map<string, number>): string | undefined {
  let best: string | undefined;
  let bestN = -1;
  for (const [k, n] of counts) {
    if (n > bestN || (n === bestN && best !== undefined && k < best)) {
      best = k;
      bestN = n;
    }
  }
  return best;
}

/** Median of a numeric list (0 for empty); used to set the volume threshold. */
function median(xs: number[]): number {
  if (!xs.length) return 0;
  const s = [...xs].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid]! : (s[mid - 1]! + s[mid]!) / 2;
}

// ----- aggregation -----------------------------------------------------------

interface SourceAcc {
  ip: string;
  alerts: number;
  weight: number;
  unmitigatedWeight: number;
  serious: number;
  severityMax: Severity;
  targets: Set<string>;
  signatureCounts: Map<string, number>;
}

function newSourceAcc(ip: string): SourceAcc {
  return {
    ip,
    alerts: 0,
    weight: 0,
    unmitigatedWeight: 0,
    serious: 0,
    severityMax: "info",
    targets: new Set(),
    signatureCounts: new Map(),
  };
}

function classify(density: number, alerts: number, densityThreshold: number, volumeThreshold: number): PotencyClass {
  const potent = density >= densityThreshold;
  const loud = alerts >= volumeThreshold;
  if (potent && loud) return "brawler";
  if (potent && !loud) return "sniper";
  if (!potent && loud) return "flood";
  return "background";
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(
  report: Omit<PotencyReport, "highlights" | "markdown">,
  ranked: PotencySource[],
): string[] {
  const out: string[] = [];
  if (report.totalAlerts === 0) return out;

  // `ranked` is the FULL qualifying list (density desc), so flood examples — which
  // rank lowest and may be truncated out of the shown table — are still available.

  // The headline find: the deadliest sniper (quiet but high density).
  const sniper = ranked.find((s) => s.klass === "sniper");
  if (sniper) {
    out.push(
      `🎯 Quiet but deadly: **\`${sniper.ip}\`** fired only **${sniper.alerts}** alert(s) but at density ` +
        `**${round1(sniper.density)}** (worst \`${sniper.severityMax}\`, ${pct(sniper.unmitigatedShare)} unmitigated)` +
        `${sniper.topSignature ? ` — led by \`${clip(sniper.topSignature, 46)}\`` : ""}. Volume rankings bury this one; ` +
        `investigate by hand${sniper.blocked ? " (already blocked)" : sniper.internal ? "" : " and consider a block"}.`,
    );
  }

  // The worst brawler — loud and lethal.
  const brawler = ranked.find((s) => s.klass === "brawler");
  if (brawler) {
    out.push(
      `🔴 Loud **and** lethal: **\`${brawler.ip}\`** — **${brawler.alerts}** alert(s) at density ` +
        `**${round1(brawler.density)}** (${brawler.serious} serious, ${pct(brawler.unmitigatedShare)} got through). ` +
        `The genuine heavy hitter — block / escalate first${brawler.blocked ? " (block in place — confirm it stuck via \`--recidivism\`)" : ""}.`,
    );
  }

  // The biggest flood — loud but harmless: the mute candidate.
  const floodQ = report.quadrants.find((q) => q.klass === "flood");
  const biggestFlood = [...ranked].filter((s) => s.klass === "flood").sort((a, b) => b.alerts - a.alerts)[0];
  if (floodQ && floodQ.sources > 0 && biggestFlood) {
    out.push(
      `📢 Loud but harmless: **${floodQ.sources}** flood source(s) carry **${pct(floodQ.alertShare)}** of your alert ` +
        `*volume* but only **${pct(floodQ.weightShare)}** of the risk *weight* — led by \`${biggestFlood.ip}\` ` +
        `(${biggestFlood.alerts} alerts, density ${round1(biggestFlood.density)}). Safe to mute / auto-handle; ` +
        `see \`--tuning\` and \`--noise\` to cut the chatter.`,
    );
  }

  // The punch-line split: snipers' weight-to-volume leverage.
  const sniperQ = report.quadrants.find((q) => q.klass === "sniper");
  if (sniperQ && sniperQ.sources > 0) {
    out.push(
      `⚖️ Density pays off: **${sniperQ.sources}** sniper source(s) are just **${pct(sniperQ.alertShare)}** of the ` +
        `volume yet **${pct(sniperQ.weightShare)}** of the risk weight — the few-alerts-that-matter your volume ` +
        `dashboards drop below the fold.`,
    );
  }

  // Thin-sample honesty: a held-out singleton that would otherwise have topped the list.
  if (report.topSingleton && report.topSingleton.density >= report.densityThreshold) {
    out.push(
      `🔬 Held out as thin-sample: \`${report.topSingleton.ip}\` scored density **${round1(report.topSingleton.density)}** ` +
        `on just **${report.topSingleton.alerts}** alert(s) (worst \`${report.topSingleton.severityMax}\`) — below the ` +
        `\`--min ${report.minAlerts}\` floor, so excluded from the ranking. Real, but watch whether it returns.`,
    );
  }

  return out;
}

// ----- markdown --------------------------------------------------------------

function quadrantTable(quadrants: PotencyQuadrant[]): string {
  return mdTable(
    ["Quadrant", "Sources", "Alerts", "% volume", "Risk weight", "% weight", "What it means"],
    quadrants.map((q) => [
      CLASS_LABEL[q.klass],
      String(q.sources),
      String(q.alerts),
      pct(q.alertShare),
      String(round1(q.weight)),
      pct(q.weightShare),
      CLASS_BLURB[q.klass],
    ]),
  );
}

function sourceTable(sources: PotencySource[]): string {
  return mdTable(
    ["Source", "Class", "Alerts", "Density", "Weight", "Unmit.", "Serious", "Worst", "Dsts", "Top signature", "Flags"],
    sources.map((s) => [
      cell(`\`${s.ip}\``),
      CLASS_LABEL[s.klass],
      String(s.alerts),
      `**${round1(s.density)}**`,
      String(round1(s.weight)),
      `${pct(s.unmitigatedShare)}`,
      s.serious > 0 ? `**${s.serious}**` : "0",
      cell(s.severityMax),
      String(s.targets),
      cell(s.topSignature ? clip(s.topSignature) : "—"),
      flagStr(s),
    ]),
  );
}

function renderMarkdown(m: PotencyReport): string {
  const lines: string[] = [];
  lines.push(`# 🎯 SecTool Threat-Potency / Severity-Density`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** each source ranked by **density** = mean risk weight per alert ` +
      `(\`severity × disposition\`, the \`--risk\` ladder: info 1·low 3·medium 9·high 27·critical 81, ` +
      `blocked ×0.2 / unknown ×0.7 / passed ×1.0). Offline, deterministic · ` +
      `**Alerts:** ${m.totalAlerts} · **Sources:** ${m.totalSources} · ` +
      `**Potent ≥** ${round1(m.densityThreshold)} density · **Loud ≥** ${m.volumeThreshold} alerts · ` +
      `**Floor:** ≥ ${m.minAlerts} alerts to rank.`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (m.totalAlerts === 0) {
    lines.push(
      `No alerts with a usable source IP landed in the last ${m.hours}h — there is nothing to rank by potency. ` +
        `Widen the window (\`--potency <more hours>\`) or confirm forwarding with \`--coverage\`.`,
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## The four quadrants`);
  lines.push("");
  lines.push(
    `_Density (punch-per-alert) on one axis, volume on the other. The whole point: **% volume** and **% weight** ` +
      `rarely match — that gap is where your triage time is being mis-spent._`,
  );
  lines.push("");
  lines.push(quadrantTable(m.quadrants));
  lines.push("");

  lines.push(`## Ranked sources by density`);
  lines.push("");
  if (m.truncated) {
    lines.push(`_Showing the **${m.sources.length}** highest-density qualifying source(s). Raise \`--limit\` to see more._`);
    lines.push("");
  }
  lines.push(sourceTable(m.sources));
  lines.push("");
  lines.push(
    `**Legend:** _Density_ = mean risk weight per alert (the ranking key). _Weight_ = summed risk weight. ` +
      `_Unmit._ = share of that weight the gateway did **not** block (passed + unknown). _Serious_ = high + critical. ` +
      `Classes: ${CLASS_ORDER.map((c) => CLASS_LABEL[c]).join(" · ")}.`,
  );
  lines.push("");

  if (m.singletonSources > 0) {
    lines.push(`## Thin-sample singletons (held out)`);
    lines.push("");
    lines.push(
      `**${m.singletonSources}** source(s) fired fewer than the \`--min ${m.minAlerts}\` floor and were kept out of ` +
        `the ranking so a one-off fluke can't crown the sniper list (combined weight ${round1(m.singletonWeight)})` +
        `${
          m.topSingleton
            ? `. The highest-density was \`${m.topSingleton.ip}\` (${m.topSingleton.alerts} alert(s), density ` +
              `${round1(m.topSingleton.density)}, worst \`${m.topSingleton.severityMax}\`)`
            : ""
        }. Lower \`--min\` to fold them in.`,
    );
    lines.push("");
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Density is a **relative** triage gauge built on the gateway's own severity and ` +
      `enforcement verdicts — a mis-graded or mis-actioned alert weighs wrong (same caveat as \`--risk\`). Blocked ` +
      `weight is **discounted ×0.2, not removed**, so a fully-blocked source still shows nonzero density; the _Unmit._ ` +
      `column is what actually got through. This is the quality-over-quantity companion to \`--risk\` (summed magnitude), ` +
      `\`--focus\` (volume Pareto), \`--heat\` (recency) and \`--rarity\` (signal surprise). No live gateway query was ` +
      `performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the threat-potency / severity-density report from the stored alert
 * history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link PotencyOptions}: `limit`, `minAlerts`, and a `nowMs` pin
 *              for deterministic tests.
 */
export function buildPotency(hours: number, opts: PotencyOptions = {}): PotencyReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minAlerts = Math.max(1, Math.min(1000, Math.floor(opts.minAlerts ?? DEFAULT_MIN_ALERTS)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const sources = new Map<string, SourceAcc>();
  let totalAlerts = 0;
  let totalWeight = 0;

  for (const a of windowed) {
    const ip = validIp(a.srcIp);
    if (!ip) continue;
    const severity = asSeverity(a.severity);
    const disp = classifyDisposition(a.action);
    const weight = alertWeight(severity, disp);

    totalAlerts++;
    totalWeight += weight;

    let acc = sources.get(ip);
    if (!acc) {
      acc = newSourceAcc(ip);
      sources.set(ip, acc);
    }
    acc.alerts++;
    acc.weight += weight;
    if (disp !== "blocked") acc.unmitigatedWeight += weight;
    if (isSerious(severity)) acc.serious++;
    acc.severityMax = maxSeverity(acc.severityMax, severity);

    const dst = validIp(a.dstIp);
    if (dst) acc.targets.add(dst);
    const sig = a.signature?.trim();
    if (sig) acc.signatureCounts.set(sig, (acc.signatureCounts.get(sig) ?? 0) + 1);
  }

  const totalSources = sources.size;

  // Split sources at the volume floor. Below it, density is statistically thin
  // (a single passed critical = density 81 on n=1) so those are summarised
  // separately rather than allowed to dominate the sniper ranking.
  const qualifying: SourceAcc[] = [];
  let singletonSources = 0;
  let singletonWeight = 0;
  let topSingleton: PotencyReport["topSingleton"];
  for (const acc of sources.values()) {
    if (acc.alerts >= minAlerts) {
      qualifying.push(acc);
    } else {
      singletonSources++;
      singletonWeight += acc.weight;
      const density = acc.weight / acc.alerts;
      if (!topSingleton || density > topSingleton.density) {
        topSingleton = { ip: acc.ip, alerts: acc.alerts, density: round1(density), severityMax: acc.severityMax };
      }
    }
  }

  // Volume threshold for "loud": the median alert-count across qualifying
  // sources (data-driven, so it adapts to a quiet vs busy window), floored at 2
  // so a degenerate all-low population still separates a relative high.
  const volumeThreshold = Math.max(2, Math.ceil(median(qualifying.map((s) => s.alerts))));
  const densityThreshold = POTENT_DENSITY_THRESHOLD;

  const ranked: PotencySource[] = qualifying
    .map((acc) => {
      const density = acc.weight / acc.alerts;
      return {
        ip: acc.ip,
        internal: isInternal(acc.ip),
        alerts: acc.alerts,
        weight: round1(acc.weight),
        density: round4(density),
        unmitigatedWeight: round1(acc.unmitigatedWeight),
        unmitigatedShare: acc.weight > 0 ? round4(acc.unmitigatedWeight / acc.weight) : 0,
        serious: acc.serious,
        seriousShare: acc.alerts > 0 ? round4(acc.serious / acc.alerts) : 0,
        severityMax: acc.severityMax,
        topSignature: topKey(acc.signatureCounts),
        targets: acc.targets.size,
        klass: classify(density, acc.alerts, densityThreshold, volumeThreshold),
        blocked: blockStore.has(acc.ip),
        watched: watchStore.has(acc.ip),
        safe: safeStore.has(acc.ip),
      } satisfies PotencySource;
    })
    // Density desc; tie-break on weight then alerts then IP for stable output.
    .sort(
      (a, b) =>
        b.density - a.density || b.weight - a.weight || b.alerts - a.alerts || (a.ip < b.ip ? -1 : a.ip > b.ip ? 1 : 0),
    );

  // Per-quadrant roll-up over ALL qualifying sources (not just the shown rows),
  // with shares taken against the full in-window totals so the volume↔weight gap
  // is honest even when the table is truncated.
  const quadrants: PotencyQuadrant[] = CLASS_ORDER.map((klass) => {
    const members = ranked.filter((s) => s.klass === klass);
    const alerts = members.reduce((n, s) => n + s.alerts, 0);
    const weight = members.reduce((n, s) => n + s.weight, 0);
    return {
      klass,
      sources: members.length,
      alerts,
      weight: round1(weight),
      alertShare: totalAlerts > 0 ? round4(alerts / totalAlerts) : 0,
      weightShare: totalWeight > 0 ? round4(weight / totalWeight) : 0,
    } satisfies PotencyQuadrant;
  });

  const truncated = ranked.length > limit;
  const shown = truncated ? ranked.slice(0, limit) : ranked;

  const base: Omit<PotencyReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalAlerts,
    totalSources,
    minAlerts,
    densityThreshold,
    volumeThreshold,
    singletonSources,
    singletonWeight: round1(singletonWeight),
    topSingleton,
    quadrants,
    sources: shown,
    truncated,
  };

  const highlights = writeHighlights(base, ranked);
  const model: PotencyReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded potency report. */
export function potencyFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-potency-${stamp}.md`;
}
