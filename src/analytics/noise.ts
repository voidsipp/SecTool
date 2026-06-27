/**
 * Alert-noise / stream-redundancy report — "how much of my alert volume is the
 * *same event firing over and over*, and which exact (attacker → victim, rule)
 * combinations should I collapse into a single line so the real signal isn't
 * buried under repetition?"
 *
 * Every other offline report in this project ranks an *entity* or measures a
 * *shape*, but none of them quantify the **repetition** in the stream itself —
 * the single biggest driver of analyst alert fatigue:
 *
 *   - **dedupe.ts** suppresses duplicate *deliveries* inside the live pipeline
 *     (the same syslog line arriving twice). It is a real-time de-bounce, not an
 *     after-the-fact measurement, and each *distinct* event (a new timestamp for
 *     the same source/rule/target) is still stored and still counts.
 *   - **concentration.ts** measures volume inequality across a *single* entity
 *     dimension at a time (sources, signatures, or targets) and answers "can I
 *     block a few heavy hitters". It never groups by the *combination* of
 *     endpoints + rule, so it cannot say "these 3 identical events are 70% of my
 *     volume and collapse to 3 lines".
 *   - **tuning.ts** ranks *noisy signatures* heuristically (volume, low severity,
 *     block pattern) to recommend rule changes. It pivots on the rule alone — it
 *     does not isolate the specific (src, dst, rule) tuples that repeat, which is
 *     what you actually aggregate or suppress.
 *   - **notify.ts** audits which alerts became Discord *notifications*; this audits
 *     the underlying detection stream regardless of whether anything was sent.
 *
 * The unit of analysis here is the **event tuple** — `source IP · destination IP ·
 * signature` (signature falling back to the event `category` when a rule name is
 * absent). Two stored alerts with the same tuple are "the same thing happening
 * again": same attacker, same victim, same rule. Folding the window onto these
 * tuples turns a flat pile of N alerts into D distinct events, and the gap
 * between them is pure repetition:
 *
 *   - **redundancy ratio** = 1 − D/N — the share of the volume that is repeats of
 *     an event already represented. 0 means every alert is a unique event; 0.9
 *     means 90% of the noise is the same handful of events echoing.
 *   - **compression factor** = N/D — average alerts per distinct event; "your
 *     5 000 alerts compress to 320 lines (15.6×)".
 *   - **collapsible alerts** = N − D — how many rows would simply vanish if every
 *     repeat folded into its first occurrence, with *zero* loss of distinct
 *     information.
 *
 * It then ranks the **noise drivers** (the tuples firing most often), bands the
 * **repetition distribution** (one-offs vs. low / medium / heavy repeaters), and
 * — crucially — separates two kinds of repeat so the operator does not suppress
 * the wrong thing:
 *
 *   - **Collapsible noise** — a tuple repeating ≥ the repeat threshold whose worst
 *     severity is only info/low: textbook fatigue. Aggregate it into one line or
 *     write a suppression rule; you lose nothing.
 *   - **Sustained pressure** — a tuple repeating just as often but reaching
 *     high/critical severity: this is *not* noise, it is the same serious attack
 *     landing again and again. Each repeat is a data point on an ongoing
 *     incident; flagged loudly so it is never folded away.
 *
 * Honest caveats baked into the output:
 *
 *   - **Same tuple ≠ same intent.** NAT / shared egress collapses many real
 *     attackers into one source IP (over-stating redundancy); a rotating botnet
 *     hitting one rule from many IPs reads as many distinct tuples (under-stating
 *     it). Repetition is measured over addresses as the IPS logged them.
 *   - **Signature falls back to category.** Firewall events without a Suricata
 *     classtype are keyed on their coarser `category`, so unrelated firewall
 *     blocks can share a tuple and look more redundant than they are; the count
 *     of category-keyed alerts is reported so the bias is visible.
 *   - **Window- & store-bounded.** A long look-back can hit the alert store's
 *     history cap; repetition older than the cap is invisible, so every metric is
 *     a lower bound on the true redundancy.
 *
 * Pure in-memory math over alertStore (plus blocklist / watchlist / safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring concentration.ts,
 * cohort.ts, scan.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** A one-word verdict on how repetitive the alert stream is. */
export type NoiseVerdict = "high" | "moderate" | "low";

/** Blocked / passed / unknown disposition split for a repeated tuple. */
export interface NoiseDisposition {
  /** Alerts the gateway actively blocked / dropped. */
  blocked: number;
  /** Alerts the gateway logged but let through. */
  passed: number;
  /** Alerts with no recorded action. */
  unknown: number;
}

/** One distinct event tuple (source · target · signature) and its repetition. */
export interface NoiseTuple {
  /** Source IP as logged, or "—" when absent/invalid. */
  srcIp: string;
  /** Destination IP as logged, or "—" when absent/invalid. */
  dstIp: string;
  /** Signature (or the fallback event category) that names the event. */
  signature: string;
  /** True when {@link signature} is an engine `category`, not a Suricata classtype. */
  categoryKeyed: boolean;
  /** Number of stored alerts collapsing onto this tuple (the repeat count). */
  count: number;
  /** count − 1: alerts that would vanish if this tuple folded to one line. */
  collapsible: number;
  /** Share of all analysable alerts this single tuple accounts for, 0..1 (4dp). */
  share: number;
  /** Worst severity across the tuple's alerts. */
  severityMax: Severity;
  /** Alerts at medium severity or worse within the tuple. */
  severe: number;
  /** Blocked / passed / unknown disposition split. */
  disposition: NoiseDisposition;
  /** First alert in the tuple (epoch ms). */
  firstMs: number;
  /** Last alert in the tuple (epoch ms). */
  lastMs: number;
  /** The source IP is a private / internal address (outbound-from-us repeats). */
  internalSource: boolean;
  /** Whether suppressing/aggregating this tuple is safe (info/low, ≥ threshold). */
  collapsibleNoise: boolean;
  /** Whether this is sustained high/critical pressure that must NOT be folded. */
  sustainedPressure: boolean;
  /** Source IP is on the blocklist. */
  blocked: boolean;
  /** Source IP is on the watchlist. */
  watched: boolean;
  /** Source IP is marked safe. */
  safe: boolean;
}

/** One band of the "how many times does an event repeat" histogram. */
export interface RepetitionBand {
  /** Inclusive lower bound on the repeat count. */
  minCount: number;
  /** Inclusive upper bound, or null for "and up". */
  maxCount: number | null;
  label: string;
  /** Distinct tuples falling in this band. */
  tuples: number;
  /** Total alerts contributed by tuples in this band. */
  alerts: number;
  /** Share of all analysable alerts contributed by this band, 0..1 (4dp). */
  alertShare: number;
}

export interface NoiseReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Analysable alerts (all timestamped alerts; none are dropped). */
  analysableAlerts: number;
  /** Of {@link analysableAlerts}, alerts keyed on `category` (no rule name). */
  categoryKeyedAlerts: number;
  /** Distinct event tuples the analysable alerts fold onto. */
  distinctTuples: number;
  /** analysableAlerts − distinctTuples — alerts removable by folding repeats. */
  collapsibleAlerts: number;
  /** 1 − distinctTuples/analysableAlerts — share of volume that is repetition, 0..1 (4dp). */
  redundancyRatio: number;
  /** analysableAlerts / distinctTuples — average alerts per distinct event (2dp). */
  compressionFactor: number;
  /** Tuples that fired more than once. */
  repeatedTuples: number;
  /** Total alerts contributed by repeated (count ≥ 2) tuples. */
  repeatedVolume: number;
  /** repeatedVolume / analysableAlerts, 0..1 (4dp). */
  repeatedVolumeShare: number;
  /** Repeat count (count ≥ this) at which a tuple is a suppression candidate. */
  repeatThreshold: number;
  /** Tuples that are safe-to-collapse noise (info/low, ≥ threshold). */
  collapsibleNoiseTuples: number;
  /** Alerts removable by collapsing just the safe noise tuples. */
  collapsibleNoiseAlerts: number;
  /** Tuples that repeat ≥ threshold AND reach high/critical (sustained attacks). */
  sustainedPressureTuples: number;
  /** The one-word stream-redundancy verdict. */
  verdict: NoiseVerdict;
  /** Repetition histogram bands. */
  distribution: RepetitionBand[];
  /** The loudest repeated tuples, most-repeated first (capped to the row limit). */
  topTuples: NoiseTuple[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface NoiseOptions {
  /** Max rows in the noise-driver table (clamped to [1, 200]). */
  limit?: number;
  /** Repeat count at/above which a tuple is a suppression candidate (clamped to [2, 1000]). */
  repeatThreshold?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const DEFAULT_REPEAT_THRESHOLD = 5;
const MS_PER_HOUR = 3_600_000;

/** Redundancy ratio at/above which the stream is called heavily repetitive. */
const HIGH_REDUNDANCY = 0.6;
/** Redundancy ratio below which the stream is called mostly-unique. */
const LOW_REDUNDANCY = 0.3;

// ----- classifiers / helpers (mirror concentration.ts / scan.ts) ------------

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

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

function pct(frac: number, dp = 0): string {
  return `${(frac * 100).toFixed(dp)}%`;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** Compact human duration for a span (e.g. "3d 4h", "5h", "12m"). */
function fmtDuration(ms: number): string {
  if (ms <= 0) return "0m";
  const mins = Math.round(ms / 60000);
  const d = Math.floor(mins / 1440);
  const h = Math.floor((mins % 1440) / 60);
  const m = mins % 60;
  if (d > 0) return h > 0 ? `${d}d ${h}h` : `${d}d`;
  if (h > 0) return m > 0 ? `${h}h ${m}m` : `${h}h`;
  return `${m}m`;
}

function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

/** Truncate a long signature so it fits a table cell. */
function truncate(s: string, max = 52): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function mdTable(headers: string[], rows: string[][]): string {
  if (!rows.length) return "_None._";
  const head = `| ${headers.join(" | ")} |`;
  const sep = `| ${headers.map(() => "---").join(" | ")} |`;
  const body = rows.map((r) => `| ${r.join(" | ")} |`).join("\n");
  return `${head}\n${sep}\n${body}`;
}

/** Human label + emoji for a redundancy verdict. */
function verdictLabel(v: NoiseVerdict): string {
  switch (v) {
    case "high":
      return "🔁 high redundancy";
    case "moderate":
      return "▥ moderate redundancy";
    case "low":
      return "🟢 low redundancy";
  }
}

function classifyVerdict(redundancyRatio: number): NoiseVerdict {
  if (redundancyRatio >= HIGH_REDUNDANCY) return "high";
  if (redundancyRatio < LOW_REDUNDANCY) return "low";
  return "moderate";
}

// ----- aggregation -----------------------------------------------------------

interface TupleAcc {
  srcIp: string;
  dstIp: string;
  signature: string;
  categoryKeyed: boolean;
  count: number;
  severe: number;
  blocked: number;
  passed: number;
  unknown: number;
  firstMs: number;
  lastMs: number;
  severityMax: Severity;
}

/** Build the canonical tuple key + its display fields from an alert. */
function tupleKeyOf(a: StoredAlert): {
  key: string;
  srcDisp: string;
  dstDisp: string;
  sigDisp: string;
  categoryKeyed: boolean;
} {
  const src = validIp(a.srcIp);
  const dst = validIp(a.dstIp);
  const sigRaw = a.signature?.trim();
  const categoryKeyed = !sigRaw;
  const sig = sigRaw || a.category?.trim() || "(unlabelled)";
  const srcDisp = src ?? "—";
  const dstDisp = dst ?? "—";
  //  is a control char that cannot appear in IPs or signature text.
  const key = `${src ?? "?"}${dst ?? "?"}${sig.toLowerCase()}`;
  return { key, srcDisp, dstDisp, sigDisp: sig, categoryKeyed };
}

// ----- repetition histogram --------------------------------------------------

function buildDistribution(tuples: TupleAcc[], analysable: number): RepetitionBand[] {
  const raw: { min: number; max: number | null; label: string }[] = [
    { min: 1, max: 1, label: "1 (unique)" },
    { min: 2, max: 5, label: "2–5" },
    { min: 6, max: 20, label: "6–20" },
    { min: 21, max: 100, label: "21–100" },
    { min: 101, max: null, label: "100+" },
  ];
  return raw
    .map((b) => {
      let nTuples = 0;
      let nAlerts = 0;
      for (const t of tuples) {
        if (t.count >= b.min && (b.max === null || t.count <= b.max)) {
          nTuples++;
          nAlerts += t.count;
        }
      }
      return {
        minCount: b.min,
        maxCount: b.max,
        label: b.label,
        tuples: nTuples,
        alerts: nAlerts,
        alertShare: analysable > 0 ? round4(nAlerts / analysable) : 0,
      };
    })
    // Drop empty high bands so a short window doesn't render a wall of zeros,
    // but always keep the "unique" band as the baseline.
    .filter((b) => b.tuples > 0 || b.minCount === 1);
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(m: NoiseReport): string[] {
  const out: string[] = [];
  if (m.analysableAlerts === 0) return out;

  // Headline: the redundancy verdict + the compression it implies.
  out.push(
    `🔁 Over the last ${m.hours}h, **${m.analysableAlerts} alert(s)** fold onto **${m.distinctTuples} distinct ` +
      `event(s)** (source · target · rule) — **${verdictLabel(m.verdict)}**, a **${m.compressionFactor.toFixed(1)}×** ` +
      `compression. **${pct(m.redundancyRatio)}** of the volume is repetition of an event already represented.`,
  );

  // The single biggest fatigue driver.
  const top = m.topTuples[0];
  if (top && top.count >= 2) {
    out.push(
      `📣 Loudest event: \`${top.srcIp}\` → \`${top.dstIp}\` on **${truncate(top.signature, 60)}** fired ` +
        `**${top.count}×** (${pct(top.share)} of all alerts, worst ${top.severityMax})` +
        `${top.blocked ? ", ⛔ source blocked" : ""}. One event, ${top.count} rows.`,
    );
  }

  // The headline action: how much noise simply collapses.
  if (m.collapsibleAlerts > 0) {
    out.push(
      `🗜️ **${m.collapsibleAlerts} of ${m.analysableAlerts} alert(s)** (${pct(m.collapsibleAlerts / m.analysableAlerts)}) ` +
        `are repeats that would vanish if every event folded to a single line — pure de-duplication, no information lost.`,
    );
  }

  // Safe-to-suppress noise: info/low repeats at/above the threshold.
  if (m.collapsibleNoiseTuples > 0) {
    out.push(
      `🧹 **${m.collapsibleNoiseTuples} repeated event(s)** are info/low severity and detected ≥${m.repeatThreshold}× ` +
        `— textbook fatigue worth **${m.collapsibleNoiseAlerts} alert(s)** (${pct(m.collapsibleNoiseAlerts / m.analysableAlerts)} ` +
        `of volume). Aggregate them into one line each or write a suppression rule; the signal is unaffected.`,
    );
  }

  // The opposite warning: heavy repeats that are NOT noise.
  if (m.sustainedPressureTuples > 0) {
    const sp = m.topTuples.find((t) => t.sustainedPressure);
    out.push(
      `🚨 **${m.sustainedPressureTuples} repeated event(s)** reach high/critical severity — this is **sustained ` +
        `pressure, not noise**: the same serious attack landing again and again. Do *not* suppress these.` +
        (sp ? ` Worst: \`${sp.srcIp}\` → \`${sp.dstIp}\` (${sp.severityMax}, ${sp.count}×).` : ""),
    );
  }

  // Internal sources repeating outbound — a beaconing / compromise texture.
  const insider = m.topTuples.find((t) => t.internalSource && t.count >= m.repeatThreshold);
  if (insider) {
    out.push(
      `🏠 Internal host \`${insider.srcIp}\` repeatedly tripped **${truncate(insider.signature, 50)}** (${insider.count}×) ` +
        `— a *your-side* event echoing this regularly can be beaconing / a misconfigured host, not an inbound scan. ` +
        `Investigate the source, not just the rule.`,
    );
  }

  // Category-keyed honesty — how much of the redundancy is coarse firewall events.
  if (m.categoryKeyedAlerts > 0) {
    const frac = m.categoryKeyedAlerts / m.analysableAlerts;
    if (frac >= 0.3) {
      out.push(
        `ℹ️ **${pct(frac)} of alerts carry no Suricata signature** and were keyed on their coarser \`category\` — ` +
          `unrelated events can share a tuple, so the measured redundancy for those is an upper bound.`,
      );
    }
  }

  return out;
}

// ----- markdown --------------------------------------------------------------

function tupleTable(rows: NoiseTuple[]): string {
  return mdTable(
    ["#", "Source", "Target", "Signature", "Count", "% vol", "Worst", "Blocked", "Span", "Type", "Flags"],
    rows.map((t, i) => {
      const flags =
        (t.internalSource ? "🏠" : "") +
        (t.blocked ? "⛔" : "") +
        (t.watched ? "👁" : "") +
        (t.safe ? "✅" : "") +
        (t.categoryKeyed ? "🏷️" : "");
      const type = t.sustainedPressure
        ? "🚨 sustained"
        : t.collapsibleNoise
          ? "🧹 collapsible"
          : t.count >= 2
            ? "repeat"
            : "unique";
      return [
        String(i + 1),
        cell(t.srcIp),
        cell(t.dstIp),
        cell(truncate(t.signature)),
        String(t.count),
        pct(t.share, 1),
        cell(t.severityMax),
        String(t.disposition.blocked),
        cell(fmtDuration(t.lastMs - t.firstMs)),
        type,
        flags || "—",
      ];
    }),
  );
}

function distributionTable(m: NoiseReport): string {
  return mdTable(
    ["Repeats", "Distinct events", "Alerts", "% of volume"],
    m.distribution.map((b) => [
      cell(b.label),
      String(b.tuples),
      String(b.alerts),
      pct(b.alertShare, 1),
    ]),
  );
}

function renderMarkdown(m: NoiseReport): string {
  const lines: string[] = [];
  lines.push(`# 🔁 SecTool Alert-Noise / Stream-Redundancy Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** alerts folded onto **event tuples** (source IP · destination IP · signature, signature falling ` +
      `back to the event \`category\`); redundancy = 1 − distinct/total · ` +
      `**Analysable alerts:** ${m.analysableAlerts} of ${m.totalWindowAlerts}` +
      (m.categoryKeyedAlerts ? ` · **category-keyed (no rule name):** ${m.categoryKeyedAlerts}` : ""),
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (m.analysableAlerts === 0) {
    lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  // At-a-glance scoreboard.
  lines.push(`## Redundancy at a glance`);
  lines.push("");
  lines.push(
    mdTable(
      ["Alerts", "Distinct events", "Redundancy", "Compression", "Collapsible", "Verdict"],
      [
        [
          String(m.analysableAlerts),
          String(m.distinctTuples),
          pct(m.redundancyRatio, 1),
          `${m.compressionFactor.toFixed(2)}×`,
          `${m.collapsibleAlerts} (${pct(m.analysableAlerts > 0 ? m.collapsibleAlerts / m.analysableAlerts : 0)})`,
          cell(verdictLabel(m.verdict)),
        ],
      ],
    ),
  );
  lines.push("");
  lines.push(
    `**Legend:** _Redundancy_ = share of volume that is repetition (**🔁 high** ≥${pct(HIGH_REDUNDANCY)} · ` +
      `**▥ moderate** · **🟢 low** <${pct(LOW_REDUNDANCY)}). _Compression_ = alerts per distinct event. ` +
      `_Collapsible_ = alerts that would vanish if every repeat folded to one line.`,
  );
  lines.push("");

  // Repetition distribution.
  lines.push(`## Repetition distribution`);
  lines.push("");
  lines.push(distributionTable(m));
  lines.push("");
  lines.push(
    `_How many distinct events fired N times, and what share of the total volume each band drives. A few rows in the ` +
      `heavy bands carrying most of the volume is the fingerprint of a noise problem._`,
  );
  lines.push("");

  // Noise drivers.
  lines.push(`## Loudest events (noise drivers)`);
  lines.push("");
  lines.push(tupleTable(m.topTuples));
  lines.push("");
  lines.push(
    `**Type:** **🚨 sustained** = repeats ≥${m.repeatThreshold}× *and* high/critical — serious attack landing again ` +
      `and again, **do not suppress** · **🧹 collapsible** = repeats ≥${m.repeatThreshold}× at info/low — safe to ` +
      `aggregate or suppress · **repeat** = fired ≥2× · **unique** = fired once. **Flags:** 🏠 internal source · ` +
      `⛔ blocked · 👁 watched · ✅ safe · 🏷️ keyed on category (no rule name).`,
  );
  lines.push("");

  // The two action buckets, spelled out.
  if (m.collapsibleNoiseTuples > 0 || m.sustainedPressureTuples > 0) {
    lines.push(`## What to do`);
    lines.push("");
    if (m.collapsibleNoiseTuples > 0) {
      lines.push(
        `- 🧹 **Collapse / suppress** the **${m.collapsibleNoiseTuples}** info/low event(s) repeating ` +
          `≥${m.repeatThreshold}× — that reclaims **${m.collapsibleNoiseAlerts} alert(s)** ` +
          `(${pct(m.collapsibleNoiseAlerts / m.analysableAlerts)} of volume) with no loss of distinct signal. ` +
          `SecTool's suppression rules (see \`--suppaudit\`) are the place to encode these.`,
      );
    }
    if (m.sustainedPressureTuples > 0) {
      lines.push(
        `- 🚨 **Investigate, never suppress** the **${m.sustainedPressureTuples}** high/critical event(s) that keep ` +
          `repeating — repetition here means an ongoing incident, not fatigue.`,
      );
    }
    lines.push("");
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Redundancy is measured over event tuples built from source IPs **as the IPS ` +
      `logged them** — NAT / shared egress collapses many real attackers into one address (over-stating redundancy) ` +
      `and a rotating botnet hitting one rule from many IPs reads as many distinct tuples (under-stating it). ` +
      `Signature-less firewall events are keyed on their coarser \`category\`, so unrelated blocks can share a tuple. ` +
      `Repetition older than the rolling alert store's cap is invisible, so every metric is a lower bound. No live ` +
      `gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the alert-noise / stream-redundancy report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link NoiseOptions}: `limit`, `repeatThreshold`, and a `nowMs` pin
 *              for deterministic tests.
 */
export function buildNoise(hours: number, opts: NoiseOptions = {}): NoiseReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const repeatThreshold = Math.max(
    2,
    Math.min(1000, Math.floor(opts.repeatThreshold ?? DEFAULT_REPEAT_THRESHOLD)),
  );
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const tuples = new Map<string, TupleAcc>();
  let categoryKeyed = 0;

  for (const a of windowed) {
    const { key, srcDisp, dstDisp, sigDisp, categoryKeyed: isCat } = tupleKeyOf(a);
    if (isCat) categoryKeyed++;
    const disp = classifyDisposition(a.action);
    let acc = tuples.get(key);
    if (!acc) {
      acc = {
        srcIp: srcDisp,
        dstIp: dstDisp,
        signature: sigDisp,
        categoryKeyed: isCat,
        count: 0,
        severe: 0,
        blocked: 0,
        passed: 0,
        unknown: 0,
        firstMs: a.time,
        lastMs: a.time,
        severityMax: "info",
      };
      tuples.set(key, acc);
    }
    acc.count++;
    if (isSevere(a.severity)) acc.severe++;
    if (disp === "blocked") acc.blocked++;
    else if (disp === "passed") acc.passed++;
    else acc.unknown++;
    if (a.time < acc.firstMs) acc.firstMs = a.time;
    if (a.time > acc.lastMs) acc.lastMs = a.time;
    acc.severityMax = maxSeverity(acc.severityMax, a.severity);
  }

  const analysable = windowed.length;
  const distinctTuples = tuples.size;
  const collapsibleAlerts = Math.max(0, analysable - distinctTuples);
  const redundancyRatio = analysable > 0 ? round4(1 - distinctTuples / analysable) : 0;
  const compressionFactor = distinctTuples > 0 ? Math.round((analysable / distinctTuples) * 100) / 100 : 0;

  const accs = [...tuples.values()];

  let repeatedTuples = 0;
  let repeatedVolume = 0;
  let collapsibleNoiseTuples = 0;
  let collapsibleNoiseAlerts = 0;
  let sustainedPressureTuples = 0;
  for (const t of accs) {
    if (t.count >= 2) {
      repeatedTuples++;
      repeatedVolume += t.count;
    }
    const sustained = t.count >= repeatThreshold && sevRank(t.severityMax) >= 3; // high/critical
    const collapsible = t.count >= repeatThreshold && sevRank(t.severityMax) <= 1; // info/low
    if (sustained) sustainedPressureTuples++;
    if (collapsible) {
      collapsibleNoiseTuples++;
      collapsibleNoiseAlerts += t.count - 1; // foldable rows for this tuple
    }
  }

  const distribution = buildDistribution(accs, analysable);
  const verdict = classifyVerdict(redundancyRatio);

  const topTuples: NoiseTuple[] = accs
    // Most-repeated first; ties broken by recency then severity for determinism.
    .sort(
      (a, b) =>
        b.count - a.count ||
        b.lastMs - a.lastMs ||
        sevRank(b.severityMax) - sevRank(a.severityMax) ||
        (a.signature < b.signature ? -1 : a.signature > b.signature ? 1 : 0),
    )
    .slice(0, limit)
    .map((t) => {
      const internalSource = t.srcIp !== "—" && isPrivate(t.srcIp);
      const sustainedPressure = t.count >= repeatThreshold && sevRank(t.severityMax) >= 3;
      const collapsibleNoise = t.count >= repeatThreshold && sevRank(t.severityMax) <= 1;
      return {
        srcIp: t.srcIp,
        dstIp: t.dstIp,
        signature: t.signature,
        categoryKeyed: t.categoryKeyed,
        count: t.count,
        collapsible: t.count - 1,
        share: analysable > 0 ? round4(t.count / analysable) : 0,
        severityMax: t.severityMax,
        severe: t.severe,
        disposition: { blocked: t.blocked, passed: t.passed, unknown: t.unknown },
        firstMs: t.firstMs,
        lastMs: t.lastMs,
        internalSource,
        collapsibleNoise,
        sustainedPressure,
        blocked: t.srcIp !== "—" && blockStore.has(t.srcIp),
        watched: t.srcIp !== "—" && watchStore.has(t.srcIp),
        safe: t.srcIp !== "—" && safeStore.has(t.srcIp),
      } satisfies NoiseTuple;
    });

  const model: NoiseReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: analysable,
    analysableAlerts: analysable,
    categoryKeyedAlerts: categoryKeyed,
    distinctTuples,
    collapsibleAlerts,
    redundancyRatio,
    compressionFactor,
    repeatedTuples,
    repeatedVolume,
    repeatedVolumeShare: analysable > 0 ? round4(repeatedVolume / analysable) : 0,
    repeatThreshold,
    collapsibleNoiseTuples,
    collapsibleNoiseAlerts,
    sustainedPressureTuples,
    verdict,
    distribution,
    topTuples,
    highlights: [],
    markdown: "",
  };
  model.highlights = writeHighlights(model);
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded alert-noise report. */
export function noiseFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-noise-${stamp}.md`;
}
