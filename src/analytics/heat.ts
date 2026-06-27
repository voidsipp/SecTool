/**
 * Decay-weighted "what's hot right now" report — "of everything in my look-back
 * window, which sources, signatures and targets are **most active in the freshest
 * part of it** — not which have the biggest all-time count, but which are heating
 * up *now*?"
 *
 * Every volume-ranked leaderboard in this project treats an alert from an hour ago
 * and an alert from six days ago as worth exactly the same: a raw count. That is
 * the right lens for "who has been the worst all week", and the wrong lens for the
 * question a morning responder actually asks — *"what should I look at first,
 * given what just happened?"* A source that hammered you on Monday and went silent
 * still tops a 7-day count leaderboard on Friday, long after it stopped mattering;
 * a source that only appeared three hours ago but is firing hard sits buried near
 * the bottom. The count hides exactly the signal a defender wants: **recency-
 * weighted intensity.**
 *
 * The adjacent temporal reports each answer a *different* question and none of them
 * answers this one:
 *
 *   - **momentum.ts** fits a least-squares *slope* to each source's rate — a
 *     direction (rising / falling), not a present-tense magnitude. A tiny actor can
 *     have a steep slope; a huge one can be flat-but-enormous. Slope ≠ "how hot".
 *   - **surge.ts** finds *anomalous spikes in time* and explains each storm — it is
 *     event-driven, blind to a steady-but-recent grind that never spikes.
 *   - **burstiness.ts** scores the *clumpiness* of inter-arrival gaps (Gini of the
 *     timeline texture) — bursty-vs-Poisson shape, independent of recency.
 *   - **concentration.ts** measures the *shape of the whole distribution* (Gini /
 *     Pareto across entities) — how lopsided, not how fresh.
 *   - the raw leaderboards (targets / netblocks / repertoire / …) rank by **total
 *     count**, weighting all of history equally.
 *
 * This report applies the one transform none of them do: an **exponential time
 * decay**. Each alert contributes `exp(-λ · age)` to its entity's *heat score*,
 * where `age` is hours before the window end and the decay constant `λ = ln 2 /
 * half-life`. An alert at the window edge is worth a full **1.0**; one a half-life
 * ago is worth **0.5**; two half-lives, **0.25**; and so on. Sum those weights per
 * entity and you get a single number that ranks by *current* activity — the same
 * exponentially-weighted-moving-average idea a trading desk or an SRE error-rate
 * dashboard uses, applied to the alert stream.
 *
 * It is computed across the same **three orthogonal dimensions** as the
 * concentration report — **sources** (attacker IPs), **signatures** (which rules
 * fire) and **targets** (destination hosts) — and for each entity it surfaces:
 *
 *   - **heat** — the decay-weighted score (the ranking key), and its share of the
 *     dimension's total heat;
 *   - **count** — the raw alert total, for contrast;
 *   - a **rank shift** — how many places the entity climbs (or falls) going from
 *     the count leaderboard to the heat leaderboard. A large positive shift is the
 *     headline: *"ranks 14th by volume but 2nd by heat"* = a fresh riser a count
 *     view would have buried;
 *   - a **trend** — comparing the recent half of the window to the older half:
 *     **🔥 heating**, **🆕 new** (nothing in the older half), **➡ steady** or
 *     **❄ cooling** (front-loaded, now fading).
 *
 * Because "hot right now" is only useful if you can act on it, the source
 * dimension carries an **act-now** view: the hottest *external, not-yet-blocked,
 * not-safe* sources — the addresses worth blocking this minute, ranked by present
 * intensity rather than stale volume.
 *
 * Honest caveats baked into the output:
 *
 *   - **Heat ≠ severity.** The score weights *recency*, not how bad each alert is —
 *     a flurry of fresh low-severity scans outscores one old critical. Pair the
 *     *what's-hot* signal with the severity-ranked reports (risk.ts, efficacy.ts)
 *     for triage priority.
 *   - **Detections, not ground truth.** NAT / shared egress can collapse many real
 *     actors into one IP and a rotating botnet can inflate the source count; the
 *     heat reflects what the IPS *logged*.
 *   - **Window- & store-bounded.** The decay is anchored to the window end, so a
 *     short look-back is mostly "now" and a long one buries old volume by design.
 *     A long look-back can also hit the alert store's history cap and clip the
 *     oldest alerts — which barely moves a recency-weighted score, the one metric
 *     that is *robust* to tail truncation.
 *
 * Pure in-memory math over alertStore (plus blocklist / watchlist / safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring concentration.ts,
 * momentum.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** The three distributions whose recency-weighted heat we measure. */
export type HeatDimensionKey = "source" | "signature" | "target";

/** A one-word verdict on whether an entity is heating, steady or cooling. */
export type HeatTrend = "heating" | "new" | "steady" | "cooling";

/** A single ranked entity row inside a dimension's heat leaderboard. */
export interface HeatEntity {
  /** The entity key (an IP for source/target, a signature string otherwise). */
  key: string;
  /** Decay-weighted heat score (the ranking key), 4dp. */
  heat: number;
  /** This entity's share of the dimension's total heat, 0..1 (4dp). */
  heatShare: number;
  /** Raw alert count attributed to this entity in the window. */
  count: number;
  /** Rank on the count leaderboard (1 = most alerts). */
  countRank: number;
  /** Rank on the heat leaderboard (1 = hottest). */
  heatRank: number;
  /** countRank − heatRank: positive = climbs on heat (a fresh riser). */
  rankShift: number;
  /** Alerts in the recent half of the window [mid, end]. */
  recentCount: number;
  /** Alerts in the older half of the window [start, mid). */
  olderCount: number;
  /** Recent-vs-older trend verdict. */
  trend: HeatTrend;
  /** Worst severity observed for this entity. */
  severityMax: Severity;
  /** Source/target only: the entity is a private/internal address. */
  internal?: boolean;
  /** Source/target only: the entity is on the blocklist. */
  blocked?: boolean;
  /** Source/target only: the entity is on the watchlist. */
  watched?: boolean;
  /** Source/target only: the entity is marked safe. */
  safe?: boolean;
}

/** Heat metrics for one dimension (sources, signatures or targets). */
export interface HeatDimension {
  key: HeatDimensionKey;
  /** Human label ("sources", "signatures", "targets"). */
  label: string;
  /** Distinct entities with at least one attributed alert. */
  distinctEntities: number;
  /** Total alerts attributed to this dimension (entities had a usable key). */
  totalAlerts: number;
  /** Σ heat across every entity in the dimension. */
  totalHeat: number;
  /** Top entities, hottest first (capped to the row limit). */
  top: HeatEntity[];
}

/** A hot external source not yet blocked — a concrete act-now candidate. */
export interface HeatActNow {
  ip: string;
  heat: number;
  /** Share of all source heat, 0..1 (4dp). */
  heatShare: number;
  count: number;
  trend: HeatTrend;
  severityMax: Severity;
  watched: boolean;
}

export interface HeatReport {
  hours: number;
  /** Decay half-life in hours actually used (after clamping/defaulting). */
  halfLifeHours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Midpoint dividing the recent half from the older half (for the trend). */
  windowMidMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** The three dimension analyses, in source → signature → target order. */
  dimensions: HeatDimension[];
  /** Hottest unblocked external sources — the act-now list. */
  actNow: HeatActNow[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface HeatOptions {
  /** Max rows in each per-dimension leaderboard (clamped to [1, 200]). */
  limit?: number;
  /** Max act-now candidates to surface (clamped to [1, 100]). */
  actNowLimit?: number;
  /**
   * Decay half-life in hours (clamped to [0.25, window]). Defaults to one seventh
   * of the window — a 168h week gives a 24h half-life, so "yesterday" counts half
   * as much as "today".
   */
  halfLifeHours?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 15;
const DEFAULT_ACTNOW_LIMIT = 10;
const MS_PER_HOUR = 3_600_000;
const LN2 = Math.log(2);

/** A meaningful rank climb worth flagging as a "riser" in the highlights. */
const RISER_SHIFT = 3;
/** Minimum alerts before a recent-vs-older trend verdict is trustworthy. */
const TREND_MIN_COUNT = 4;
/** Recent must exceed older by this ratio to read as heating (and inverse). */
const TREND_RATIO = 1.5;

// ----- classifiers / helpers (mirror concentration.ts / momentum.ts) ---------

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

function pct(frac: number, dp = 0): string {
  return `${(frac * 100).toFixed(dp)}%`;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function clip(s: string, max = 44): string {
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

/** Human label + emoji for a trend verdict. */
function trendLabel(trend: HeatTrend): string {
  switch (trend) {
    case "heating":
      return "🔥 heating";
    case "new":
      return "🆕 new";
    case "steady":
      return "➡ steady";
    case "cooling":
      return "❄ cooling";
  }
}

/** A signed rank-shift badge: "▲6" climbing, "▼3" falling, "—" unchanged. */
function shiftBadge(shift: number): string {
  if (shift > 0) return `▲${shift}`;
  if (shift < 0) return `▼${-shift}`;
  return "—";
}

// ----- aggregation -----------------------------------------------------------

interface EntityAcc {
  /** Σ exp(-λ·age) over this entity's alerts. */
  heat: number;
  count: number;
  recentCount: number;
  olderCount: number;
  severityMax: Severity;
}

interface DimAcc {
  /** key → running heat + counts + worst severity. */
  entities: Map<string, EntityAcc>;
  /** Total alerts that had a usable key for this dimension. */
  total: number;
  /** Σ heat across the dimension. */
  totalHeat: number;
}

function newDimAcc(): DimAcc {
  return { entities: new Map(), total: 0, totalHeat: 0 };
}

/**
 * Fold one alert into a dimension accumulator: add its decay weight to the
 * entity's heat, bump the raw + recent/older counts, and track worst severity.
 */
function bump(
  acc: DimAcc,
  key: string,
  weight: number,
  recent: boolean,
  severity: string | undefined,
): void {
  const e = acc.entities.get(key);
  if (e) {
    e.heat += weight;
    e.count++;
    if (recent) e.recentCount++;
    else e.olderCount++;
    e.severityMax = maxSeverity(e.severityMax, severity);
  } else {
    acc.entities.set(key, {
      heat: weight,
      count: 1,
      recentCount: recent ? 1 : 0,
      olderCount: recent ? 0 : 1,
      severityMax: maxSeverity("info", severity),
    });
  }
  acc.total++;
  acc.totalHeat += weight;
}

/**
 * Classify recent-vs-older movement. `new` when the older half was empty but the
 * recent half is non-trivial; otherwise `heating` / `cooling` when one half clearly
 * outweighs the other and there is enough volume to trust it; else `steady`.
 */
function classifyTrend(recentCount: number, olderCount: number): HeatTrend {
  if (olderCount === 0) return recentCount >= 2 ? "new" : "steady";
  const total = recentCount + olderCount;
  if (total < TREND_MIN_COUNT) return "steady";
  if (recentCount >= olderCount * TREND_RATIO) return "heating";
  if (olderCount >= recentCount * TREND_RATIO) return "cooling";
  return "steady";
}

/** Build the full {@link HeatDimension} from a raw accumulator. */
function summariseDimension(
  key: HeatDimensionKey,
  label: string,
  acc: DimAcc,
  limit: number,
  decorate: boolean,
): HeatDimension {
  const entries = [...acc.entities.entries()];

  // Count-rank lookup: rank by raw alert count (1 = most), ties broken by key for
  // determinism. This is the leaderboard the heat view is contrasted against.
  const byCount = [...entries].sort(
    (a, b) => b[1].count - a[1].count || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0),
  );
  const countRank = new Map<string, number>();
  byCount.forEach(([k], i) => countRank.set(k, i + 1));

  // Heat-rank: the report's headline ordering.
  const byHeat = [...entries].sort(
    (a, b) => b[1].heat - a[1].heat || b[1].count - a[1].count || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0),
  );

  const totalHeat = acc.totalHeat;
  const top: HeatEntity[] = byHeat.slice(0, limit).map(([k, e], i) => {
    const cRank = countRank.get(k) ?? i + 1;
    const hRank = i + 1;
    const row: HeatEntity = {
      key: k,
      heat: round4(e.heat),
      heatShare: totalHeat > 0 ? round4(e.heat / totalHeat) : 0,
      count: e.count,
      countRank: cRank,
      heatRank: hRank,
      rankShift: cRank - hRank,
      recentCount: e.recentCount,
      olderCount: e.olderCount,
      trend: classifyTrend(e.recentCount, e.olderCount),
      severityMax: e.severityMax,
    };
    if (decorate) {
      row.internal = isPrivate(k);
      row.blocked = blockStore.has(k);
      row.watched = watchStore.has(k);
      row.safe = safeStore.has(k);
    }
    return row;
  });

  return {
    key,
    label,
    distinctEntities: entries.length,
    totalAlerts: acc.total,
    totalHeat: round4(totalHeat),
    top,
  };
}

/**
 * Derive the act-now list from the (already-aggregated) source accumulator: the
 * hottest *external, not-yet-blocked, not-safe* sources, ranked by present heat
 * rather than stale volume. Internal hosts are excluded (you don't blocklist your
 * own boxes).
 */
function deriveActNow(srcAcc: DimAcc, limit: number): HeatActNow[] {
  const totalHeat = srcAcc.totalHeat;
  const ranked = [...srcAcc.entities.entries()].sort(
    (a, b) => b[1].heat - a[1].heat || b[1].count - a[1].count || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0),
  );

  const out: HeatActNow[] = [];
  for (const [ip, e] of ranked) {
    if (out.length >= limit) break;
    if (blockStore.has(ip) || isPrivate(ip) || safeStore.has(ip)) continue;
    out.push({
      ip,
      heat: round4(e.heat),
      heatShare: totalHeat > 0 ? round4(e.heat / totalHeat) : 0,
      count: e.count,
      trend: classifyTrend(e.recentCount, e.olderCount),
      severityMax: e.severityMax,
      watched: watchStore.has(ip),
    });
  }
  return out;
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(
  hours: number,
  halfLifeHours: number,
  dims: HeatDimension[],
  actNow: HeatActNow[],
): string[] {
  const out: string[] = [];
  const analysable = dims.filter((d) => d.totalAlerts > 0 && d.top.length > 0);
  if (!analysable.length) return out;

  const src = dims.find((d) => d.key === "source");
  const sig = dims.find((d) => d.key === "signature");

  // Headline: the hottest source right now, framed against its raw rank.
  if (src && src.top.length) {
    const hot = src.top[0]!;
    const climbed = hot.rankShift >= RISER_SHIFT;
    out.push(
      `🔥 Over the last ${hours}h (half-life **${halfLifeHours}h**) the hottest source right now is \`${hot.key}\`` +
        `${hot.watched ? " 👁" : ""} — **${trendLabel(hot.trend)}**, ${hot.count} alert(s), ` +
        `${pct(hot.heatShare)} of source heat` +
        (climbed
          ? `. It ranks only **#${hot.countRank} by volume** but **#1 by heat** — a fresh riser a raw count would bury.`
          : `.`),
    );
  }

  // The core value-add: a riser that the count leaderboard hides. Pick the biggest
  // positive rank-shift among the sources actually worth attention.
  if (src) {
    const riser = src.top
      .filter((e) => e.rankShift >= RISER_SHIFT && e.heatRank > 1 && !e.internal)
      .sort((a, b) => b.rankShift - a.rankShift)[0];
    if (riser) {
      out.push(
        `📈 **Riser:** \`${riser.key}\`${riser.watched ? " 👁" : ""} climbs **${riser.rankShift} place(s)** from ` +
          `#${riser.countRank} by volume to #${riser.heatRank} by heat (**${trendLabel(riser.trend)}**, ` +
          `${riser.recentCount} of ${riser.count} alert(s) in the recent half) — a count-only view would have ` +
          `missed it.`,
      );
    }

    // The inverse, equally actionable: a high-volume actor that has gone quiet.
    const cooling = src.top
      .filter((e) => e.trend === "cooling" && e.countRank <= 5 && !e.internal)
      .sort((a, b) => a.countRank - b.countRank)[0];
    if (cooling) {
      out.push(
        `❄ **Cooling:** \`${cooling.key}\` is a top-${cooling.countRank} all-window source but **front-loaded** ` +
          `(${cooling.olderCount} of ${cooling.count} alert(s) in the older half) — largely spent. It still tops a ` +
          `raw count leaderboard long after it stopped mattering.`,
      );
    }
  }

  // Hottest signature — a fresh-tuning / live-campaign tell distinct from the source story.
  if (sig && sig.top.length) {
    const hs = sig.top[0]!;
    out.push(
      `🎯 Hottest signature now: **${clip(hs.key, 70)}** (**${trendLabel(hs.trend)}**, ${hs.count} alert(s), ` +
        `${pct(hs.heatShare)} of signature heat)` +
        (hs.trend === "new" || hs.trend === "heating"
          ? ` — a live or freshly-escalating campaign, not week-old background.`
          : `.`),
    );
  }

  // Act-now: concrete, recency-ranked blocklist payoff.
  if (actNow.length) {
    const top = actNow[0]!;
    out.push(
      `⚡ **Act now:** the hottest unblocked external source is \`${top.ip}\`${top.watched ? " 👁" : ""} ` +
        `(**${trendLabel(top.trend)}**, ${top.count} alert(s), ${pct(top.heatShare)} of source heat). ` +
        `${actNow.length} unblocked external source(s) make the act-now list, ranked by present intensity.`,
    );
  }

  // An internal host topping a heat board is an anomaly worth a direct call-out.
  const internalHot = src?.top.find((e) => e.internal && e.heatRank <= 5);
  if (internalHot) {
    out.push(
      `🚨 Internal host \`${internalHot.key}\` is a top-${internalHot.heatRank} *source* by current heat ` +
        `(**${trendLabel(internalHot.trend)}**) — an inside box this active is a misconfiguration or compromise ` +
        `tell, not an inbound attacker. Investigate before treating it as noise.`,
    );
  }

  return out;
}

// ----- markdown --------------------------------------------------------------

function flagsCell(e: HeatEntity): string {
  const f =
    (e.internal ? "🏠" : "") +
    (e.blocked ? "⛔" : "") +
    (e.watched ? "👁" : "") +
    (e.safe ? "✅" : "");
  return f || "—";
}

function dimensionTable(d: HeatDimension): string {
  const isIpDim = d.key === "source" || d.key === "target";
  const entityHeader = d.key === "source" ? "Source" : d.key === "target" ? "Target" : "Signature";
  const headers = isIpDim
    ? ["#", entityHeader, "Heat", "Share", "Alerts", "Trend", "Rank Δ", "Worst", "Flags"]
    : ["#", entityHeader, "Heat", "Share", "Alerts", "Trend", "Rank Δ", "Worst"];
  return mdTable(
    headers,
    d.top.map((e, i) => {
      const base = [
        String(i + 1),
        cell(isIpDim ? e.key : clip(e.key)),
        e.heat.toFixed(2),
        pct(e.heatShare, 1),
        String(e.count),
        cell(trendLabel(e.trend)),
        shiftBadge(e.rankShift),
        cell(e.severityMax),
      ];
      return isIpDim ? [...base, flagsCell(e)] : base;
    }),
  );
}

function actNowTable(actNow: HeatActNow[]): string {
  return mdTable(
    ["#", "Source", "Heat", "Share", "Alerts", "Trend", "Worst", "Flags"],
    actNow.map((c, i) => [
      String(i + 1),
      cell(c.ip),
      c.heat.toFixed(2),
      pct(c.heatShare, 1),
      String(c.count),
      cell(trendLabel(c.trend)),
      cell(c.severityMax),
      c.watched ? "👁" : "—",
    ]),
  );
}

function renderMarkdown(m: HeatReport): string {
  const lines: string[] = [];
  lines.push(`# 🔥 SecTool Current-Heat (Decay-Weighted Activity) Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** each alert scored by **exponential time decay** \`exp(−ln2 · age / ${m.halfLifeHours}h)\` — ` +
      `worth 1.0 at the window edge, 0.5 a half-life (**${m.halfLifeHours}h**) ago, 0.25 two half-lives ago — then ` +
      `summed per entity into a recency-weighted **heat** score across **sources**, **signatures** and **targets**. ` +
      `Offline, deterministic · **Window alerts:** ${m.totalWindowAlerts}`,
  );
  lines.push("");

  const analysable = m.dimensions.filter((d) => d.totalAlerts > 0);
  lines.push(`## Summary`);
  lines.push("");
  if (!analysable.length) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but none carried a usable source, ` +
          `signature or target key to score for heat.`,
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

  // At-a-glance: the hottest entity in each dimension.
  lines.push(`## Heat at a glance`);
  lines.push("");
  lines.push(
    mdTable(
      ["Dimension", "Distinct", "Alerts", "Total heat", "Hottest now", "Trend", "Heat share"],
      m.dimensions.map((d) => {
        const hot = d.top[0];
        return [
          cell(d.label),
          String(d.distinctEntities),
          String(d.totalAlerts),
          d.totalAlerts > 0 ? d.totalHeat.toFixed(2) : "—",
          hot ? cell(d.key === "signature" ? clip(hot.key, 40) : hot.key) : "—",
          hot ? cell(trendLabel(hot.trend)) : "—",
          hot ? pct(hot.heatShare, 1) : "—",
        ];
      }),
    ),
  );
  lines.push("");
  lines.push(
    `**Legend:** _Heat_ = Σ \`exp(−ln2·age/${m.halfLifeHours}h)\` over an entity's alerts — recent alerts dominate. ` +
      `_Trend_ compares the recent half of the window to the older half: **🔥 heating** · **🆕 new** (nothing older) ` +
      `· **➡ steady** · **❄ cooling** (front-loaded, fading). _Rank Δ_ = places climbed from the **volume** ` +
      `leaderboard to the **heat** leaderboard (**▲** = hotter than its raw count suggests — a fresh riser).`,
  );
  lines.push("");

  // Per-dimension detail.
  for (const d of m.dimensions) {
    lines.push(`## ${d.label[0]!.toUpperCase()}${d.label.slice(1)} by current heat`);
    lines.push("");
    if (d.totalAlerts === 0) {
      lines.push(`_No alerts carried a usable ${d.label.replace(/s$/, "")} key in this window._`);
      lines.push("");
      continue;
    }
    lines.push(
      `${d.distinctEntities} distinct ${d.label} over ${d.totalAlerts} alert(s) · total heat ` +
        `**${d.totalHeat.toFixed(2)}**.`,
    );
    lines.push("");
    lines.push(dimensionTable(d));
    lines.push("");
  }

  // Act-now: hottest unblocked external sources.
  lines.push(`## Act now — hottest unblocked sources`);
  lines.push("");
  if (m.actNow.length) {
    lines.push(
      `The **${m.actNow.length}** external source(s) below are unblocked, not safelisted, and ranked by *present* ` +
        `intensity — the addresses worth blocking this minute rather than the ones that were loudest days ago.`,
    );
    lines.push("");
    lines.push(actNowTable(m.actNow));
    lines.push("");
    lines.push(`_Internal and safelisted addresses are excluded. 👁 = already on the watchlist._`);
  } else {
    lines.push(
      `No unblocked external sources are currently hot — either every hot source is already blocked / safelisted, ` +
        `or the source heat is too diffuse for any single block to matter right now.`,
    );
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Heat weights **recency**, not severity — a flurry of fresh low-severity scans ` +
      `outscores one old critical, so pair this *what's-hot* signal with the severity-ranked reports (risk, efficacy) ` +
      `for triage priority. These are IPS **detections**: NAT / shared egress can collapse many real actors into one ` +
      `IP and a rotating botnet can inflate the source count. The decay is anchored to the window end, so a short ` +
      `look-back is mostly "now" and a long one buries old volume by design — which also makes a recency-weighted ` +
      `score robust to the store's history-cap truncation. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the current-heat (decay-weighted activity) report from the stored alert
 * history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link HeatOptions}: `limit`, `actNowLimit`, `halfLifeHours`, and a
 *              `nowMs` pin for deterministic tests.
 */
export function buildHeat(hours: number, opts: HeatOptions = {}): HeatReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const actNowLimit = Math.max(1, Math.min(100, Math.floor(opts.actNowLimit ?? DEFAULT_ACTNOW_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;
  const windowMidMs = windowEndMs - (safeHours / 2) * MS_PER_HOUR;

  // Default half-life: a seventh of the window, clamped to [0.25h, the window].
  const requestedHalfLife = opts.halfLifeHours ?? safeHours / 7;
  const halfLifeHours = Math.max(0.25, Math.min(safeHours, requestedHalfLife));
  const lambda = LN2 / halfLifeHours; // per-hour decay constant

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const srcAcc = newDimAcc();
  const sigAcc = newDimAcc();
  const dstAcc = newDimAcc();

  for (const a of windowed) {
    // Age in hours before the window end (clamped non-negative); decay weight.
    const ageHours = Math.max(0, (windowEndMs - a.time) / MS_PER_HOUR);
    const weight = Math.exp(-lambda * ageHours);
    const recent = a.time >= windowMidMs;

    const src = validIp(a.srcIp);
    if (src) bump(srcAcc, src, weight, recent, a.severity);

    const sig = (a.signature ?? "").trim();
    if (sig) bump(sigAcc, sig, weight, recent, a.severity);

    const dst = validIp(a.dstIp);
    if (dst) bump(dstAcc, dst, weight, recent, a.severity);
  }

  const dimensions: HeatDimension[] = [
    summariseDimension("source", "sources", srcAcc, limit, true),
    summariseDimension("signature", "signatures", sigAcc, limit, false),
    summariseDimension("target", "targets", dstAcc, limit, true),
  ];

  const actNow = deriveActNow(srcAcc, actNowLimit);
  const highlights = writeHighlights(safeHours, halfLifeHours, dimensions, actNow);

  const model: HeatReport = {
    hours: safeHours,
    halfLifeHours,
    windowStartMs,
    windowEndMs,
    windowMidMs,
    totalWindowAlerts: windowed.length,
    dimensions,
    actNow,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded heat report. */
export function heatFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-heat-${stamp}.md`;
}
