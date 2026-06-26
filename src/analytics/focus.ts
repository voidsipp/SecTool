/**
 * Threat-focus / concentration report — "is my threat landscape *concentrated*
 * (a few actors dominate → block them for a quick win) or *diffuse* (spread thin
 * → distributed scanning / botnet → tuning & rate-limiting, not blocking)?"
 *
 * Every other offline report in this project either *ranks entities* (campaigns,
 * persistence, assets, edges name the worst source / host / pair), *rolls up a
 * taxonomy* (classify, tuning, killchain, cooccurrence), or *shapes time*
 * (surge, rhythm, beacon). They all answer "**which** ones?" Not one of them
 * answers the question a responder asks *before* deciding a strategy:
 *
 *   **"What is the *shape* of the distribution?"**
 *
 * That shape changes the entire response plan, and a top-N ranking actively
 * hides it — a table of "top 20 sources" looks identical whether those 20 IPs
 * are 95% of all traffic (block them, done) or 4% of it (blocking is whack-a-mole
 * against a 5,000-host botnet). The numbers that distinguish those two worlds —
 * how few values cover most of the volume, how evenly the load is spread — live
 * *between* the rows, never in them.
 *
 * This report measures concentration across four independent axes, each from the
 * stored alert history:
 *
 *   - **Source IPs** — the decisive one. If a handful of sources carry most of
 *     the volume, blocking is a high-leverage quick win and this report tells you
 *     *exactly how many* IPs to block to cut 80% of the noise. If it is diffuse,
 *     blocking will not scale and the effort belongs in rule tuning / rate limits.
 *   - **Destination IPs** — concentrated means the attacker is fixated on a few
 *     of your assets (harden / isolate them); diffuse means broad sweeping (a
 *     perimeter-wide scan, not a targeted op).
 *   - **Signatures** — one rule dominating is the classic false-positive /
 *     tuning tell; a flat spread is genuinely varied activity.
 *   - **Threat classes** — the `classification` (falling back to `category`),
 *     so the *kind*-of-harm mix's evenness is visible too.
 *
 * For each axis it computes, from the windowed counts:
 *
 *   - the share held by the single largest value, the top 5, and the top 10,
 *   - the **Pareto point** — the minimum number of values that together cover
 *     ≥80% of the volume (and that count as a fraction of all distinct values),
 *   - the **Gini coefficient** of the count distribution (0 = perfectly even,
 *     → 1 = one value holds everything) and a 0-100 concentration index from it,
 *   - a categorical verdict (`single` / `concentrated` / `moderate` / `diffuse`)
 *     derived from those metrics, with the raw numbers always shown so the
 *     operator can overrule the heuristic.
 *
 * The source axis additionally cross-references the blocklist / watchlist /
 * safelist (like edges.ts / persistence.ts / assets.ts) so the headline
 * "block N IPs to cut 80%" line can note how many of those N are *already*
 * blocked — i.e. how much of the quick win is still on the table.
 *
 * Honest caveats baked into the output:
 *
 *   - **Volume shape ≠ risk.** Concentration describes *where the noise lives*,
 *     not how dangerous it is. A diffuse landscape can still hide one critical
 *     edge; pair this with the severity-ranked reports (report / classify /
 *     edges), do not triage on shape alone.
 *   - **Alerts, not flows.** SecTool stores IPS *detections*. A source that
 *     never trips a rule is invisible here, so "diffuse" means diffuse *among
 *     alerting* actors, not across all traffic.
 *   - **Window-bounded & store-capped.** The store keeps a bounded history; a
 *     very long look-back can hit that cap and flatten the apparent shape.
 *
 * Pure in-memory math over alertStore (plus blocklist/watchlist/safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring report.ts, classify.ts,
 * edges.ts, spread.ts, beacon.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";

/** Stable machine key for each concentration axis. */
export type DimensionKey = "sources" | "destinations" | "signatures" | "classes";

/**
 * Categorical read of a distribution's shape, in descending leverage order:
 *
 *   - `single`        — only one distinct value carried this axis,
 *   - `concentrated`  — a few values dominate (blocking / tuning is high-leverage),
 *   - `moderate`      — neither sharply peaked nor flat,
 *   - `diffuse`       — load spread thin across many values (blocking won't scale).
 */
export type ConcentrationVerdict = "single" | "concentrated" | "moderate" | "diffuse";

/** One of the largest values on an axis, with its share of the axis's volume. */
export interface TopEntry {
  /** The value (an IP, signature, or threat-class label). */
  key: string;
  /** Windowed alert count attributed to this value. */
  count: number;
  /** count / axis-attributed, 0..1 (rounded to 4dp). */
  share: number;
  /** Source axis only: value is on the blocklist. */
  blocked?: boolean;
  /** Source axis only: value is on the watchlist. */
  watched?: boolean;
  /** Source axis only: value is marked safe. */
  safe?: boolean;
}

/** Concentration metrics for a single axis over the window. */
export interface DimensionConcentration {
  /** Stable machine key (see {@link DimensionKey}). */
  key: DimensionKey;
  /** Human label of the axis ("Source IPs", "Signatures", …). */
  label: string;
  /** Alerts that carried a usable value for this axis (the share denominator). */
  attributed: number;
  /** Distinct values observed on this axis inside the window. */
  distinct: number;
  /** Share held by the single largest value, 0..1 (4dp). */
  top1Share: number;
  /** Share held by the largest 5 values combined, 0..1 (4dp). */
  top5Share: number;
  /** Share held by the largest 10 values combined, 0..1 (4dp). */
  top10Share: number;
  /** Minimum number of values that together cover ≥80% of the volume. */
  pareto80Count: number;
  /** pareto80Count / distinct, 0..1 (4dp) — small = a few values carry the load. */
  pareto80Fraction: number;
  /** Gini coefficient of the count distribution, 0 (even) .. ~1 (one dominates). */
  gini: number;
  /** 0-100 concentration index — round(gini × 100), for an at-a-glance number. */
  index: number;
  /** Categorical shape verdict derived from the metrics above. */
  verdict: ConcentrationVerdict;
  /** The largest values for display, most-frequent first. */
  top: TopEntry[];
}

export interface FocusReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Per-axis concentration metrics, in the canonical axis order. */
  dimensions: DimensionConcentration[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface FocusOptions {
  /** Max rows per axis table (clamped to [1, 100]). */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 8;
const MS_PER_HOUR = 3_600_000;
/** Pareto threshold: the fraction of volume the "Pareto point" must cover. */
const PARETO_TARGET = 0.8;

// ----- formatting helpers (mirror edges.ts / classify.ts / persistence.ts) -----

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
function clip(s: string, max = 44): string {
  const t = s.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

function bump(map: Map<string, number>, key: string | undefined): void {
  if (!key) return;
  map.set(key, (map.get(key) ?? 0) + 1);
}

// ----- concentration math --------------------------------------------------

/**
 * Gini coefficient of a non-negative count distribution. 0 means every value is
 * equally frequent (perfectly even); it rises toward 1 as the mass piles onto a
 * single value. Uses the standard mean-absolute-difference formulation expressed
 * over the *sorted* counts, which is O(n) once sorted:
 *
 *   G = ( 2·Σ(i·xᵢ) − (n+1)·Σxᵢ ) / ( n·Σxᵢ )    with x sorted ascending, i=1..n
 *
 * Returns 0 for an empty or single-value distribution (no inequality to measure).
 */
function gini(countsDesc: number[]): number {
  const n = countsDesc.length;
  if (n <= 1) return 0;
  const total = countsDesc.reduce((s, c) => s + c, 0);
  if (total <= 0) return 0;
  // The formula wants ascending order; our input is descending, so walk it in
  // reverse to assign rank i = 1 (smallest) .. n (largest).
  let weighted = 0;
  for (let asc = 0; asc < n; asc++) {
    const x = countsDesc[n - 1 - asc]!; // ascending value
    weighted += (asc + 1) * x; // i · xᵢ, i is 1-based
  }
  const g = (2 * weighted - (n + 1) * total) / (n * total);
  // Clamp tiny negative drift from float error into [0, 1].
  return Math.max(0, Math.min(1, g));
}

/** Sum of the first `k` counts (already sorted descending) as a share of total. */
function topShare(countsDesc: number[], total: number, k: number): number {
  if (total <= 0) return 0;
  let s = 0;
  const upto = Math.min(k, countsDesc.length);
  for (let i = 0; i < upto; i++) s += countsDesc[i]!;
  return s / total;
}

/** Minimum number of (descending) values whose cumulative share reaches target. */
function paretoCount(countsDesc: number[], total: number, target: number): number {
  if (total <= 0) return 0;
  const need = total * target;
  let cum = 0;
  for (let i = 0; i < countsDesc.length; i++) {
    cum += countsDesc[i]!;
    if (cum >= need) return i + 1;
  }
  return countsDesc.length;
}

/**
 * Derive the categorical shape verdict from the metrics. Heuristic and
 * intentionally conservative — the raw numbers are always shown so the operator
 * can overrule it.
 *
 *   - `single`        — only one distinct value.
 *   - `concentrated`  — one value ≥90%, OR Gini ≥0.6, OR ≤20% of values cover
 *                       80% of volume, OR (when there are enough values to make
 *                       it meaningful) the top 5 cover ≥80%.
 *   - `diffuse`       — low Gini (<0.35) AND the Pareto point needs ≥50% of all
 *                       values: the load is genuinely spread thin.
 *   - `moderate`      — everything in between.
 */
function verdictFor(
  distinct: number,
  giniVal: number,
  top1Share: number,
  top5Share: number,
  pareto80Fraction: number,
): ConcentrationVerdict {
  if (distinct <= 1) return "single";
  const enoughForTopN = distinct > 5;
  if (top1Share >= 0.9 || giniVal >= 0.6 || pareto80Fraction <= 0.2 || (enoughForTopN && top5Share >= 0.8)) {
    return "concentrated";
  }
  if (giniVal < 0.35 && pareto80Fraction >= 0.5) return "diffuse";
  return "moderate";
}

/** A short glyph + word for a verdict, used in tables and the legend. */
function verdictLabel(v: ConcentrationVerdict): string {
  switch (v) {
    case "single":
      return "● single";
    case "concentrated":
      return "▰ concentrated";
    case "moderate":
      return "▱ moderate";
    default:
      return "░ diffuse";
  }
}

/**
 * Fold the alert window into a count map for one axis, using `keyOf` to extract
 * the axis value (returning undefined drops the alert from that axis), then
 * compute every concentration metric for it.
 */
function buildDimension(
  key: DimensionKey,
  label: string,
  alerts: StoredAlert[],
  keyOf: (a: StoredAlert) => string | undefined,
  limit: number,
  enrichSources: boolean,
): DimensionConcentration {
  const counts = new Map<string, number>();
  for (const a of alerts) bump(counts, keyOf(a));

  const sorted = [...counts.entries()].sort((x, y) => (y[1] - x[1]) || (x[0] < y[0] ? -1 : 1));
  const countsDesc = sorted.map(([, c]) => c);
  const attributed = countsDesc.reduce((s, c) => s + c, 0);
  const distinct = sorted.length;

  const top1Share = round4(topShare(countsDesc, attributed, 1));
  const top5Share = round4(topShare(countsDesc, attributed, 5));
  const top10Share = round4(topShare(countsDesc, attributed, 10));
  const pareto80Count = paretoCount(countsDesc, attributed, PARETO_TARGET);
  const pareto80Fraction = distinct ? round4(pareto80Count / distinct) : 0;
  const giniVal = round4(gini(countsDesc));
  const verdict = verdictFor(distinct, giniVal, top1Share, top5Share, pareto80Fraction);

  const top: TopEntry[] = sorted.slice(0, limit).map(([k, c]) => {
    const entry: TopEntry = { key: k, count: c, share: attributed ? round4(c / attributed) : 0 };
    if (enrichSources) {
      entry.blocked = blockStore.has(k);
      entry.watched = watchStore.has(k);
      entry.safe = safeStore.has(k);
    }
    return entry;
  });

  return {
    key,
    label,
    attributed,
    distinct,
    top1Share,
    top5Share,
    top10Share,
    pareto80Count,
    pareto80Fraction,
    gini: giniVal,
    index: Math.round(giniVal * 100),
    verdict,
    top,
  };
}

// ----- highlights ----------------------------------------------------------

function writeHighlights(
  hours: number,
  totalWindowAlerts: number,
  dims: DimensionConcentration[],
): string[] {
  const out: string[] = [];
  if (!totalWindowAlerts) return out;

  const byKey = new Map(dims.map((d) => [d.key, d]));
  const sources = byKey.get("sources");
  const dests = byKey.get("destinations");
  const sigs = byKey.get("signatures");

  // Overall one-line shape read across the three operational axes.
  const named = [sources, dests, sigs].filter((d): d is DimensionConcentration => !!d && d.distinct >= 2);
  if (named.length) {
    const concs = named.filter((d) => d.verdict === "concentrated").map((d) => d.label.toLowerCase());
    const diff = named.filter((d) => d.verdict === "diffuse").map((d) => d.label.toLowerCase());
    if (concs.length && !diff.length) {
      out.push(
        `📊 Threat landscape over the last ${hours}h is **concentrated** — ${concs.join(", ")} are carried by a ` +
          `small set of values. That is the high-leverage case: targeted blocking / tuning removes most of the noise.`,
      );
    } else if (diff.length && !concs.length) {
      out.push(
        `📊 Threat landscape over the last ${hours}h is **diffuse** — ${diff.join(", ")} are spread thin across many ` +
          `values. Blocking individual offenders will not scale; favour rule tuning, rate limits and perimeter posture.`,
      );
    } else {
      out.push(
        `📊 Threat landscape over the last ${hours}h is **mixed** — ` +
          (concs.length ? `${concs.join(", ")} concentrated` : "") +
          (concs.length && diff.length ? "; " : "") +
          (diff.length ? `${diff.join(", ")} diffuse` : "") +
          `. Match the response to each axis below rather than one blanket strategy.`,
      );
    }
  }

  // Source axis — the actionable "block N IPs to cut 80%" line.
  if (sources && sources.attributed > 0 && sources.distinct >= 2) {
    if (sources.verdict === "concentrated") {
      const alreadyBlocked = sources.top.filter((t) => t.blocked).length;
      const note = alreadyBlocked
        ? ` (${alreadyBlocked} of the shown top sources ${alreadyBlocked === 1 ? "is" : "are"} already blocked)`
        : "";
      out.push(
        `🎯 **Quick win:** just ${sources.pareto80Count} source IP${sources.pareto80Count === 1 ? "" : "s"} ` +
          `account for ${pct(PARETO_TARGET)} of all attributed alerts — blocking that handful cuts most of the ` +
          `volume${note}. Top source alone is ${pct(sources.top1Share)} of traffic.`,
      );
    } else if (sources.verdict === "diffuse") {
      out.push(
        `🌐 Sources are **diffuse** — it takes ${sources.pareto80Count} of ${sources.distinct} distinct IPs to reach ` +
          `${pct(PARETO_TARGET)} of volume (Gini ${sources.gini}). This pattern reads as distributed scanning / a ` +
          `botnet / spoofed sources; per-IP blocking is whack-a-mole. Tune rules and rate-limit instead.`,
      );
    }
  }

  // Destination axis — focused targeting vs broad sweeping.
  if (dests && dests.attributed > 0 && dests.distinct >= 2) {
    if (dests.verdict === "concentrated") {
      const top = dests.top[0];
      out.push(
        `🛡️ Targeting is **focused** — ${dests.pareto80Count} of your asset(s) absorb ${pct(PARETO_TARGET)} of the ` +
          `alerts` +
          (top ? `, led by \`${top.key}\` (${pct(top.share)})` : "") +
          `. Harden / isolate those hosts first; the attacker has picked favourites.`,
      );
    } else if (dests.verdict === "diffuse") {
      out.push(
        `🧹 Targeting is **broad** — alerts are spread across ${dests.distinct} destinations with no clear focus ` +
          `(Gini ${dests.gini}). That is the signature of a perimeter-wide sweep rather than a targeted operation.`,
      );
    }
  }

  // Signature axis — the false-positive / tuning tell.
  if (sigs && sigs.attributed > 0 && sigs.distinct >= 2) {
    const topSig = sigs.top[0];
    if (sigs.verdict === "concentrated" && topSig) {
      out.push(
        `🔧 One signature dominates the mix — \`${clip(topSig.key)}\` is ${pct(topSig.share)} of all ` +
          `attributed alerts. A single rule carrying the landscape is the classic false-positive / tuning tell; ` +
          `confirm it is real before it drowns everything else (see the tuning report).`,
      );
    } else if (sigs.verdict === "diffuse") {
      out.push(
        `🧩 Signatures are **varied** — ${sigs.distinct} distinct rules with no single one dominating ` +
          `(Gini ${sigs.gini}). The activity is genuinely diverse, not one noisy rule.`,
      );
    }
  }

  return out;
}

// ----- markdown ------------------------------------------------------------

/** A compact per-axis metrics block, rendered as one table row. */
function summaryTable(dims: DimensionConcentration[]): string {
  return mdTable(
    ["Axis", "Shape", "Index", "Distinct", "Top 1", "Top 5", "Pareto ≥80%", "Gini"],
    dims.map((d) => [
      cell(d.label),
      verdictLabel(d.verdict),
      `${d.index}/100`,
      String(d.distinct),
      pct(d.top1Share),
      pct(d.top5Share),
      d.distinct ? `${d.pareto80Count} / ${d.distinct} (${pct(d.pareto80Fraction)})` : "—",
      String(d.gini),
    ]),
  );
}

function topTable(d: DimensionConcentration): string {
  const sourceAxis = d.key === "sources";
  const headers = sourceAxis
    ? ["#", "Value", "Alerts", "Share", "Flags"]
    : ["#", "Value", "Alerts", "Share"];
  return mdTable(
    headers,
    d.top.map((t, i) => {
      const base = [String(i + 1), cell(clip(t.key || "—")), String(t.count), pct(t.share)];
      if (sourceAxis) {
        const flags = (t.blocked ? "⛔" : "") + (t.watched ? "👁" : "") + (t.safe ? "✅" : "");
        base.push(flags || "—");
      }
      return base;
    }),
  );
}

function renderMarkdown(m: FocusReport): string {
  const lines: string[] = [];
  lines.push(`# 📊 SecTool Threat-Focus / Concentration Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** per-axis concentration (top-N share · Pareto ≥${pct(PARETO_TARGET)} point · Gini coefficient) ` +
      `over stored IPS alerts · **Window alerts:** ${m.totalWindowAlerts}`,
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

  lines.push(`## Concentration at a glance`);
  lines.push("");
  lines.push(summaryTable(m.dimensions));
  lines.push("");
  lines.push(
    `**Legend:** _Shape_ — \`▰ concentrated\` (a few values dominate → targeted blocking / tuning is a quick win), ` +
      `\`░ diffuse\` (spread thin → blocking won't scale; tune & rate-limit), \`▱ moderate\` (in between), ` +
      `\`● single\` (one value only). _Index_ = Gini × 100 (0 even … 100 one value holds everything). ` +
      `_Pareto ≥${pct(PARETO_TARGET)}_ = how many values, of all distinct, cover ${pct(PARETO_TARGET)} of the volume — ` +
      `the smaller the count, the more leverage a few blocks / fixes give you.`,
  );
  lines.push("");

  for (const d of m.dimensions) {
    lines.push(`## ${d.label} — ${verdictLabel(d.verdict)} (index ${d.index}/100)`);
    lines.push("");
    if (!d.attributed) {
      lines.push(`_No alerts carried a usable ${d.label.toLowerCase()} value this window._`);
      lines.push("");
      continue;
    }
    lines.push(
      `${d.distinct} distinct value(s) across ${d.attributed} attributed alert(s). ` +
        `Top 1 = ${pct(d.top1Share)}, top 5 = ${pct(d.top5Share)}, top 10 = ${pct(d.top10Share)}. ` +
        `${d.pareto80Count} value(s) cover ${pct(PARETO_TARGET)} of volume (${pct(d.pareto80Fraction)} of all ` +
        `distinct). Gini ${d.gini}.`,
    );
    lines.push("");
    lines.push(topTable(d));
    lines.push("");
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from stored **IPS-alert** counts. Concentration describes the *shape* of the ` +
      `alert volume — where the noise lives — not how dangerous it is; pair it with the severity-ranked reports ` +
      `(report / classify / edges) before triaging. "Diffuse" means diffuse among *alerting* actors only, since a ` +
      `source that never trips a rule is invisible here, and a long look-back can hit the store's history cap and ` +
      `flatten the apparent shape. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the threat-focus / concentration report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link FocusOptions}: `limit` (rows per axis) and a `nowMs` pin.
 */
export function buildFocus(hours: number, opts: FocusOptions = {}): FocusReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(100, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const validIp = (ip: string | undefined): string | undefined =>
    ip && isIP(ip) !== 0 ? ip : undefined;

  const dimensions: DimensionConcentration[] = [
    buildDimension("sources", "Source IPs", windowed, (a) => validIp(a.srcIp), limit, true),
    buildDimension("destinations", "Destination IPs", windowed, (a) => validIp(a.dstIp), limit, false),
    buildDimension("signatures", "Signatures", windowed, (a) => a.signature?.trim() || undefined, limit, false),
    buildDimension(
      "classes",
      "Threat classes",
      windowed,
      // Mirror classify.ts: the Suricata classtype, falling back to category.
      (a) => a.classification?.trim() || a.category?.trim() || undefined,
      limit,
      false,
    ),
  ];

  const highlights = writeHighlights(safeHours, windowed.length, dimensions);
  const model: FocusReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    dimensions,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded threat-focus report. */
export function focusFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-focus-${stamp}.md`;
}
