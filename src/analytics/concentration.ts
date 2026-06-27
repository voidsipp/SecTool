/**
 * Threat-concentration (Pareto / Gini) report — "is my alert volume driven by a
 * *handful* of heavy hitters I can block away, or a long flat tail with no easy
 * wins — and is that concentration in the *sources*, the *signatures*, or the
 * *targets*?"
 *
 * Every other attacker-centric report in this project answers a *who/what/when*
 * question — it ranks individual entities (this IP, this signature, this host) by
 * some axis and hands you a leaderboard. None of them step back and measure the
 * **shape of the whole distribution**: the single strategic number a responder
 * wants before deciding *how* to fight back.
 *
 *   - targets.ts / netblock.ts / repertoire.ts / dwell.ts each rank entities — top
 *     source, top netblock, most sophisticated, most entrenched. A leaderboard
 *     tells you the worst offender; it does not tell you whether blocking the top
 *     five offenders buys you 90% of your quiet back or barely 8%.
 *   - efficacy.ts measures the *block rate* (how much detected traffic is actually
 *     enforced) — a coverage axis, blind to how lopsided the volume is.
 *   - surge.ts finds *volume spikes in time*; classify.ts rolls the *threat-class
 *     mix* up globally. Neither asks how *evenly* the volume is spread across the
 *     actors producing it.
 *
 * That evenness is the difference between two opposite operational worlds that a
 * raw alert count renders identically. Ten thousand alerts from **three** IPs is a
 * concentrated problem with an obvious, cheap answer (block three addresses, win).
 * Ten thousand alerts from **eight thousand** IPs is a diffuse botnet/background
 * storm where no single block moves the needle and the right response is tuning,
 * rate-limiting or geo-policy — not a blocklist. The same logic applies to
 * signatures (a few noisy rules vs. a broad campaign) and to targets (one
 * hammered host vs. an even sweep). The *shape* dictates the strategy, and the
 * shape is exactly what a leaderboard hides.
 *
 * This report measures concentration across **three orthogonal dimensions** —
 * **sources** (attacker IPs), **signatures** (which rules fire), and **targets**
 * (destination hosts) — and for each computes:
 *
 *   - **Gini coefficient (0–1)** — the classic inequality measure. 0 = perfectly
 *     even (every entity contributes the same volume); 1 = one entity owns
 *     everything. The single comparable number that says "how lopsided is this".
 *   - **Pareto top-shares** — what fraction of the alerts the top 1% / 5% / 10% /
 *     20% of entities account for (the "vital few").
 *   - **Coverage breakpoints** — the inverse: how *few* entities you must account
 *     for to cover 50% / 80% / 90% / 95% of the volume. "9 sources = 80% of
 *     alerts" is a directly actionable sentence.
 *   - A one-word **shape** — **concentrated** (a few heavy hitters: block-and-win),
 *     **mixed**, or **diffuse** (a long flat tail: tuning/policy, not blocklists).
 *
 * Then, because concentration is only useful if you can *act* on it, the source
 * dimension carries a **quick-wins** view: of the heavy-hitter sources that drive
 * the bulk of the volume, which are **not yet blocked**, and what fraction of all
 * source-attributed alerts blocking those few would have removed. That converts
 * the abstract Gini into a concrete "block these N IPs, cut X% of the noise" call.
 *
 * Honest caveats baked into the output:
 *
 *   - **Volume ≠ severity.** Concentration is measured on alert *counts*; a diffuse
 *     tail of low-severity scans can hide a single concentrated critical actor.
 *     The shape guides *strategy*, not triage priority — pair it with the
 *     severity-ranked reports (risk.ts, efficacy.ts).
 *   - **Detections, not ground truth.** A heavy hitter may be one noisy rule on one
 *     benign host; the Gini reflects what the IPS *logged*, NAT and shared egress
 *     can collapse many real actors into one IP (over-stating concentration) or a
 *     rotating botnet can inflate the source count (under-stating it).
 *   - **Window- & store-bounded.** A long look-back can hit the alert store's
 *     history cap and clip the tail, nudging every metric toward "concentrated".
 *
 * Pure in-memory math over alertStore (plus blocklist / watchlist / safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring dwell.ts, repertoire.ts,
 * scan.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** The three distributions whose concentration we measure. */
export type ConcentrationDimensionKey = "source" | "signature" | "target";

/** A one-word verdict on how lopsided a distribution is. */
export type ConcentrationShape = "concentrated" | "mixed" | "diffuse";

/** Fraction of *alerts* held by the top fraction of *entities* (a Pareto point). */
export interface ParetoPoint {
  /** Top fraction of entities, 0..1 (e.g. 0.1 = the top 10% of entities). */
  entityFrac: number;
  /** Number of entities that fraction rounds up to (≥1 when any entity exists). */
  entityCount: number;
  /** Cumulative fraction of all alerts those entities account for, 0..1 (4dp). */
  alertFrac: number;
}

/** The inverse: how few entities cover a target fraction of alerts. */
export interface CoveragePoint {
  /** Target cumulative fraction of alerts, 0..1 (e.g. 0.8 = 80%). */
  targetFrac: number;
  /** Entities needed (ranked desc) to first reach/exceed {@link targetFrac}. */
  entityCount: number;
  /** Those entities as a fraction of all entities in this dimension, 0..1 (4dp). */
  entityFrac: number;
}

/** A single ranked entity row inside a dimension's leaderboard. */
export interface ConcentrationEntity {
  /** The entity key (an IP for source/target, a signature string otherwise). */
  key: string;
  /** Alerts attributed to this entity in the window. */
  count: number;
  /** This entity's share of the dimension's alerts, 0..1 (4dp). */
  share: number;
  /** Running share including this entity and every heavier one, 0..1 (4dp). */
  cumulativeShare: number;
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

/** Concentration metrics for one dimension (sources, signatures or targets). */
export interface ConcentrationDimension {
  key: ConcentrationDimensionKey;
  /** Human label ("sources", "signatures", "targets"). */
  label: string;
  /** Distinct entities with at least one attributed alert. */
  distinctEntities: number;
  /** Total alerts attributed to this dimension (entities had a usable key). */
  totalAlerts: number;
  /** Gini coefficient of the alert distribution, 0..1 (4dp). */
  gini: number;
  /** The one-word shape verdict. */
  shape: ConcentrationShape;
  /** Pareto top-shares at 1% / 5% / 10% / 20% of entities. */
  pareto: ParetoPoint[];
  /** Coverage breakpoints at 50% / 80% / 90% / 95% of alerts. */
  coverage: CoveragePoint[];
  /** Top entities, heaviest first (capped to the row limit). */
  top: ConcentrationEntity[];
}

/** A heavy-hitter source not yet blocked — a concrete blocklist quick-win. */
export interface QuickWin {
  ip: string;
  count: number;
  /** Share of all source-attributed alerts, 0..1 (4dp). */
  share: number;
  severityMax: Severity;
  internal: boolean;
  watched: boolean;
  safe: boolean;
}

/** The blocklist quick-wins summary derived from the source dimension. */
export interface QuickWinSummary {
  /** Top unblocked external sources, heaviest first. */
  candidates: QuickWin[];
  /** Σ alerts the candidates account for. */
  coveredAlerts: number;
  /** Those alerts as a fraction of all source-attributed alerts, 0..1 (4dp). */
  coveredShare: number;
  /** Source-attributed alerts already removed by blocklisted heavy hitters. */
  alreadyBlockedAlerts: number;
  /** Already-blocked alerts as a fraction of source-attributed alerts, 0..1 (4dp). */
  alreadyBlockedShare: number;
}

export interface ConcentrationReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** The three dimension analyses, in source → signature → target order. */
  dimensions: ConcentrationDimension[];
  /** Blocklist quick-wins from the source dimension. */
  quickWins: QuickWinSummary;
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface ConcentrationOptions {
  /** Max rows in each per-dimension leaderboard (clamped to [1, 200]). */
  limit?: number;
  /** Max blocklist quick-win candidates to surface (clamped to [1, 100]). */
  quickWinLimit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 15;
const DEFAULT_QUICKWIN_LIMIT = 10;
const MS_PER_HOUR = 3_600_000;

/** Entity fractions sampled for the Pareto "vital few" view. */
const PARETO_FRACS = [0.01, 0.05, 0.1, 0.2] as const;
/** Alert fractions sampled for the coverage "how few cover X%" view. */
const COVERAGE_FRACS = [0.5, 0.8, 0.9, 0.95] as const;

/** Gini at/above which a distribution is called concentrated. */
const CONCENTRATED_GINI = 0.6;
/** Gini below which a distribution is called diffuse. */
const DIFFUSE_GINI = 0.35;

// ----- classifiers / helpers (mirror dwell.ts / repertoire.ts) ----------------

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

/** Human label + emoji for a shape verdict. */
function shapeLabel(shape: ConcentrationShape): string {
  switch (shape) {
    case "concentrated":
      return "🎯 concentrated";
    case "mixed":
      return "▥ mixed";
    case "diffuse":
      return "🌫 diffuse";
  }
}

// ----- concentration math ----------------------------------------------------

/**
 * Gini coefficient of a list of non-negative counts. 0 = perfectly even, → 1 =
 * one entity owns everything. Uses the rank-weighted form over the ascending-
 * sorted values; clamped to [0, 1] against floating-point drift.
 */
function gini(counts: number[]): number {
  const v = counts.filter((x) => x > 0).sort((a, b) => a - b);
  const n = v.length;
  if (n === 0) return 0;
  let total = 0;
  let weighted = 0;
  for (let i = 0; i < n; i++) {
    total += v[i]!;
    weighted += (i + 1) * v[i]!; // 1-indexed rank weight
  }
  if (total === 0) return 0;
  const g = (2 * weighted) / (n * total) - (n + 1) / n;
  return round4(Math.max(0, Math.min(1, g)));
}

/**
 * Cumulative alert fraction held by the top `entityFrac` of entities. `sortedDesc`
 * is the descending count list; `total` its sum. The entity count rounds *up* so a
 * non-zero fraction always covers at least one entity.
 */
function paretoPoint(sortedDesc: number[], total: number, entityFrac: number): ParetoPoint {
  const n = sortedDesc.length;
  const k = n === 0 ? 0 : Math.max(1, Math.ceil(n * entityFrac));
  let cum = 0;
  for (let i = 0; i < k; i++) cum += sortedDesc[i]!;
  return { entityFrac, entityCount: k, alertFrac: total > 0 ? round4(cum / total) : 0 };
}

/**
 * The fewest entities (ranked desc) whose cumulative alerts first reach
 * `targetFrac` of the total.
 */
function coveragePoint(sortedDesc: number[], total: number, targetFrac: number): CoveragePoint {
  const n = sortedDesc.length;
  if (n === 0 || total <= 0) return { targetFrac, entityCount: 0, entityFrac: 0 };
  let cum = 0;
  for (let i = 0; i < n; i++) {
    cum += sortedDesc[i]!;
    if (cum / total >= targetFrac) {
      return { targetFrac, entityCount: i + 1, entityFrac: round4((i + 1) / n) };
    }
  }
  return { targetFrac, entityCount: n, entityFrac: 1 };
}

/**
 * Classify the distribution shape. Concentrated when Gini is high *or* the top
 * 20% of entities already own ≥80% of alerts (the textbook Pareto threshold);
 * diffuse when Gini is low and no small head dominates; mixed otherwise.
 */
function classifyShape(giniValue: number, top20Share: number): ConcentrationShape {
  if (giniValue >= CONCENTRATED_GINI || top20Share >= 0.8) return "concentrated";
  if (giniValue < DIFFUSE_GINI) return "diffuse";
  return "mixed";
}

// ----- aggregation -----------------------------------------------------------

interface EntityAcc {
  count: number;
  severityMax: Severity;
}

interface DimAcc {
  /** key → running count + worst severity. */
  entities: Map<string, EntityAcc>;
  /** Total alerts that had a usable key for this dimension. */
  total: number;
}

function newDimAcc(): DimAcc {
  return { entities: new Map(), total: 0 };
}

function bump(acc: DimAcc, key: string, severity: string | undefined): void {
  const e = acc.entities.get(key);
  if (e) {
    e.count++;
    e.severityMax = maxSeverity(e.severityMax, severity);
  } else {
    acc.entities.set(key, { count: 1, severityMax: maxSeverity("info", severity) });
  }
  acc.total++;
}

/** Build the full {@link ConcentrationDimension} from a raw accumulator. */
function summariseDimension(
  key: ConcentrationDimensionKey,
  label: string,
  acc: DimAcc,
  limit: number,
  decorate: boolean,
): ConcentrationDimension {
  const entries = [...acc.entities.entries()].sort(
    (a, b) => b[1].count - a[1].count || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0),
  );
  const counts = entries.map(([, e]) => e.count);
  const total = acc.total;

  const giniValue = gini(counts);
  const pareto = PARETO_FRACS.map((f) => paretoPoint(counts, total, f));
  const coverage = COVERAGE_FRACS.map((f) => coveragePoint(counts, total, f));
  const top20 = paretoPoint(counts, total, 0.2).alertFrac;
  const shape = classifyShape(giniValue, top20);

  let cum = 0;
  const top: ConcentrationEntity[] = entries.slice(0, limit).map(([k, e]) => {
    cum += e.count;
    const row: ConcentrationEntity = {
      key: k,
      count: e.count,
      share: total > 0 ? round4(e.count / total) : 0,
      cumulativeShare: total > 0 ? round4(cum / total) : 0,
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
    totalAlerts: total,
    gini: giniValue,
    shape,
    pareto,
    coverage,
    top,
  };
}

/**
 * Derive blocklist quick-wins from the (already-aggregated) source accumulator:
 * the heaviest *external, not-yet-blocked, not-safe* sources, and how much of the
 * source volume blocking them would remove — plus how much is already gone to the
 * blocklist. Internal hosts are excluded (you don't blocklist your own boxes).
 */
function deriveQuickWins(srcAcc: DimAcc, limit: number): QuickWinSummary {
  const total = srcAcc.total;
  let alreadyBlockedAlerts = 0;
  const candidates: QuickWin[] = [];

  const ranked = [...srcAcc.entities.entries()].sort(
    (a, b) => b[1].count - a[1].count || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0),
  );

  for (const [ip, e] of ranked) {
    if (blockStore.has(ip)) {
      alreadyBlockedAlerts += e.count;
      continue;
    }
    if (isPrivate(ip) || safeStore.has(ip)) continue;
    if (candidates.length >= limit) continue;
    candidates.push({
      ip,
      count: e.count,
      share: total > 0 ? round4(e.count / total) : 0,
      severityMax: e.severityMax,
      internal: false,
      watched: watchStore.has(ip),
      safe: false,
    });
  }

  const coveredAlerts = candidates.reduce((s, c) => s + c.count, 0);
  return {
    candidates,
    coveredAlerts,
    coveredShare: total > 0 ? round4(coveredAlerts / total) : 0,
    alreadyBlockedAlerts,
    alreadyBlockedShare: total > 0 ? round4(alreadyBlockedAlerts / total) : 0,
  };
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(
  hours: number,
  dims: ConcentrationDimension[],
  quickWins: QuickWinSummary,
): string[] {
  const out: string[] = [];
  const analysable = dims.filter((d) => d.distinctEntities > 0 && d.totalAlerts > 0);
  if (!analysable.length) return out;

  const src = dims.find((d) => d.key === "source");
  const sig = dims.find((d) => d.key === "signature");

  // Headline: the most concentrated dimension and what it means strategically.
  const most = [...analysable].sort((a, b) => b.gini - a.gini)[0]!;
  const mostCov80 = most.coverage.find((c) => c.targetFrac === 0.8);
  out.push(
    `📊 Over the last ${hours}h the **${most.label}** distribution is the most lopsided ` +
      `(**${shapeLabel(most.shape)}**, Gini **${most.gini.toFixed(2)}**)` +
      (mostCov80 && mostCov80.entityCount > 0
        ? ` — just **${mostCov80.entityCount} ${most.label.replace(/s$/, "")}(s)** account for 80% of its ${most.totalAlerts} alerts.`
        : "."),
  );

  // Source shape → the core strategic recommendation.
  if (src && src.totalAlerts > 0) {
    const cov80 = src.coverage.find((c) => c.targetFrac === 0.8);
    if (src.shape === "concentrated") {
      out.push(
        `🎯 **Source volume is concentrated** (Gini ${src.gini.toFixed(2)}): a few addresses drive the bulk of it` +
          (cov80 && cov80.entityCount > 0
            ? ` — **${cov80.entityCount} of ${src.distinctEntities} IP(s) = 80% of alerts**`
            : "") +
          `. This is a **block-and-win** landscape: a tight blocklist removes most of the noise.`,
      );
    } else if (src.shape === "diffuse") {
      out.push(
        `🌫 **Source volume is diffuse** (Gini ${src.gini.toFixed(2)}): the load is spread across ` +
          `**${src.distinctEntities} IP(s)** with no dominant head — a botnet / background-storm shape. ` +
          `Blocking individual IPs barely helps; reach for rule tuning, rate-limiting or geo/ASN policy instead.`,
      );
    } else {
      out.push(
        `▥ **Source volume is mixed** (Gini ${src.gini.toFixed(2)}): a meaningful head of heavy hitters over a ` +
          `long tail. Block the head for a quick win, then tune for the remainder.`,
      );
    }
  }

  // Quick-wins: concrete blocklist payoff.
  if (quickWins.candidates.length) {
    const top = quickWins.candidates[0]!;
    out.push(
      `⚡ **Quick wins:** blocking the top **${quickWins.candidates.length} unblocked source(s)** would remove ` +
        `**${pct(quickWins.coveredShare)}** of source-attributed alerts. Heaviest is \`${top.ip}\`` +
        `${top.watched ? " 👁" : ""} (${top.count} alert(s), ${pct(top.share)}).`,
    );
  } else if (quickWins.alreadyBlockedShare >= 0.3) {
    out.push(
      `✅ The blocklist is already absorbing **${pct(quickWins.alreadyBlockedShare)}** of source-attributed ` +
        `alerts — the heavy hitters are largely captured; what remains is the diffuse tail.`,
    );
  }

  // Signature concentration → a tuning hint, distinct from the source story.
  if (sig && sig.totalAlerts > 0) {
    const cov50 = sig.coverage.find((c) => c.targetFrac === 0.5);
    if (sig.shape === "concentrated" && cov50 && cov50.entityCount > 0) {
      out.push(
        `🔧 **${cov50.entityCount} signature(s) generate half** of all alerts — a small set of noisy rules ` +
          `dominates the stream. Confirm they are genuine before they drown real signal; if benign, tune them.`,
      );
    }
  }

  // An internal heavy hitter is a notable anomaly worth a direct call-out.
  const internalHead = src?.top.find((e) => e.internal && e.share >= 0.05);
  if (internalHead) {
    out.push(
      `🚨 Internal host \`${internalHead.key}\` is a *source* heavy hitter (${pct(internalHead.share)} of ` +
        `source alerts) — an inside box generating this share of the volume is a misconfiguration or ` +
        `compromise tell, not an inbound attacker. Investigate before treating it as noise.`,
    );
  }

  return out;
}

// ----- markdown --------------------------------------------------------------

function paretoLine(d: ConcentrationDimension): string {
  const unit = d.label.replace(/s$/, "");
  const parts = d.pareto
    .filter((p) => p.entityCount > 0)
    .map((p) => `top ${pct(p.entityFrac)} (${p.entityCount} ${unit}) → **${pct(p.alertFrac)}**`);
  return parts.length ? parts.join(" · ") : "_n/a_";
}

function coverageLine(d: ConcentrationDimension): string {
  const unit = d.label.replace(/s$/, "");
  const parts = d.coverage
    .filter((c) => c.entityCount > 0)
    .map((c) => `${pct(c.targetFrac)} ← **${c.entityCount}** ${unit}(s)`);
  return parts.length ? parts.join(" · ") : "_n/a_";
}

function dimensionEntityTable(d: ConcentrationDimension): string {
  const isIpDim = d.key === "source" || d.key === "target";
  const headers = isIpDim
    ? ["#", d.key === "source" ? "Source" : "Target", "Alerts", "Share", "Cumul.", "Worst", "Flags"]
    : ["#", "Signature", "Alerts", "Share", "Cumul.", "Worst"];
  return mdTable(
    headers,
    d.top.map((e, i) => {
      const base = [
        String(i + 1),
        cell(isIpDim ? e.key : clip(e.key)),
        String(e.count),
        pct(e.share, 1),
        pct(e.cumulativeShare, 1),
        cell(e.severityMax),
      ];
      if (!isIpDim) return base;
      const flags =
        (e.internal ? "🏠" : "") +
        (e.blocked ? "⛔" : "") +
        (e.watched ? "👁" : "") +
        (e.safe ? "✅" : "");
      return [...base, flags || "—"];
    }),
  );
}

function quickWinTable(q: QuickWinSummary): string {
  return mdTable(
    ["#", "Source", "Alerts", "Share", "Worst", "Flags"],
    q.candidates.map((c, i) => [
      String(i + 1),
      cell(c.ip),
      String(c.count),
      pct(c.share, 1),
      cell(c.severityMax),
      c.watched ? "👁" : "—",
    ]),
  );
}

function renderMarkdown(m: ConcentrationReport): string {
  const lines: string[] = [];
  lines.push(`# 📊 SecTool Threat-Concentration (Pareto / Gini) Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** alert volume measured for *inequality* across three distributions — **sources**, ` +
      `**signatures**, **targets** — via the **Gini coefficient** (0 = perfectly even, 1 = one entity owns ` +
      `everything), **Pareto top-shares** and **coverage breakpoints**. Offline, deterministic, count-based · ` +
      `**Window alerts:** ${m.totalWindowAlerts}`,
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
          `signature or target key to measure concentration over.`,
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

  // At-a-glance concentration matrix across the three dimensions.
  lines.push(`## Concentration at a glance`);
  lines.push("");
  lines.push(
    mdTable(
      ["Dimension", "Distinct", "Alerts", "Gini", "Shape", "Top 10% hold", "80% covered by"],
      m.dimensions.map((d) => {
        const top10 = d.pareto.find((p) => p.entityFrac === 0.1);
        const cov80 = d.coverage.find((c) => c.targetFrac === 0.8);
        return [
          cell(d.label),
          String(d.distinctEntities),
          String(d.totalAlerts),
          d.totalAlerts > 0 ? d.gini.toFixed(3) : "—",
          d.totalAlerts > 0 ? cell(shapeLabel(d.shape)) : "—",
          top10 && top10.entityCount > 0 ? pct(top10.alertFrac) : "—",
          cov80 && cov80.entityCount > 0 ? `${cov80.entityCount} ${d.label.replace(/s$/, "")}(s)` : "—",
        ];
      }),
    ),
  );
  lines.push("");
  lines.push(
    `**Legend:** _Gini_ 0 = every entity contributes equally · → 1 = one entity owns all the volume. ` +
      `_Shape_ — **🎯 concentrated** (a few heavy hitters: block-and-win) · **▥ mixed** (a head over a long ` +
      `tail) · **🌫 diffuse** (flat tail: tune / rate-limit / geo-policy, not blocklists).`,
  );
  lines.push("");

  // Per-dimension detail.
  for (const d of m.dimensions) {
    lines.push(`## ${d.label[0]!.toUpperCase()}${d.label.slice(1)} concentration`);
    lines.push("");
    if (d.totalAlerts === 0) {
      lines.push(`_No alerts carried a usable ${d.label.replace(/s$/, "")} key in this window._`);
      lines.push("");
      continue;
    }
    lines.push(
      `**${shapeLabel(d.shape)}** · Gini **${d.gini.toFixed(3)}** · ${d.distinctEntities} distinct ` +
        `${d.label} over ${d.totalAlerts} alert(s).`,
    );
    lines.push("");
    lines.push(`- **Pareto (vital few):** ${paretoLine(d)}`);
    lines.push(`- **Coverage (how few cover X%):** ${coverageLine(d)}`);
    lines.push("");
    lines.push(dimensionEntityTable(d));
    lines.push("");
  }

  // Blocklist quick-wins.
  lines.push(`## Blocklist quick-wins`);
  lines.push("");
  if (m.quickWins.candidates.length) {
    lines.push(
      `Blocking the top **${m.quickWins.candidates.length}** unblocked external source(s) below would remove ` +
        `**${pct(m.quickWins.coveredShare, 1)}** of source-attributed alerts ` +
        `(${m.quickWins.coveredAlerts} alert(s)). The blocklist already absorbs ` +
        `**${pct(m.quickWins.alreadyBlockedShare, 1)}** (${m.quickWins.alreadyBlockedAlerts} alert(s)).`,
    );
    lines.push("");
    lines.push(quickWinTable(m.quickWins));
    lines.push("");
    lines.push(
      `_Internal and safelisted addresses are excluded — you don't blocklist your own hosts. 👁 = already ` +
        `on the watchlist._`,
    );
  } else {
    lines.push(
      `No unblocked external heavy hitters to surface — either every heavy source is already blocked ` +
        `(blocklist absorbs **${pct(m.quickWins.alreadyBlockedShare, 1)}** of source alerts) or the source ` +
        `volume is too diffuse for any single block to matter.`,
    );
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Concentration is measured on alert **counts**, not severity — a diffuse ` +
      `tail can still hide one concentrated critical actor, so pair the *shape* (a strategy signal) with the ` +
      `severity-ranked reports for triage. These are IPS **detections**: NAT / shared egress can collapse many ` +
      `real actors into one IP (over-stating concentration) and a rotating botnet can inflate the source count ` +
      `(under-stating it). A long look-back can hit the store's history cap and clip the tail, nudging every ` +
      `metric toward "concentrated". No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the threat-concentration (Pareto / Gini) report from the stored alert
 * history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link ConcentrationOptions}: `limit`, `quickWinLimit`, and a
 *              `nowMs` pin for deterministic tests.
 */
export function buildConcentration(hours: number, opts: ConcentrationOptions = {}): ConcentrationReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const quickWinLimit = Math.max(1, Math.min(100, Math.floor(opts.quickWinLimit ?? DEFAULT_QUICKWIN_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const srcAcc = newDimAcc();
  const sigAcc = newDimAcc();
  const dstAcc = newDimAcc();

  for (const a of windowed) {
    const src = validIp(a.srcIp);
    if (src) bump(srcAcc, src, a.severity);

    const sig = (a.signature ?? "").trim();
    if (sig) bump(sigAcc, sig, a.severity);

    const dst = validIp(a.dstIp);
    if (dst) bump(dstAcc, dst, a.severity);
  }

  const dimensions: ConcentrationDimension[] = [
    summariseDimension("source", "sources", srcAcc, limit, true),
    summariseDimension("signature", "signatures", sigAcc, limit, false),
    summariseDimension("target", "targets", dstAcc, limit, true),
  ];

  const quickWins = deriveQuickWins(srcAcc, quickWinLimit);
  const highlights = writeHighlights(safeHours, dimensions, quickWins);

  const model: ConcentrationReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    dimensions,
    quickWins,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded concentration report. */
export function concentrationFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-concentration-${stamp}.md`;
}
