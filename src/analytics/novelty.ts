/**
 * First-seen / novelty report — "what is genuinely NEW tonight?"
 *
 * Triage starts with one question above all others: *have we ever seen this
 * before?* A source IP, a destination, or an IPS signature that appears for the
 * very first time in the retained history is the sharpest, lowest-noise lead an
 * analyst has — it can't be dismissed as "the usual background", it represents a
 * change in the threat surface, and brand-new indicators are exactly what should
 * be promoted to a blocklist or a hunt first.
 *
 * None of the existing offline reports answer this cleanly:
 *
 *   - compare.ts diffs the current window against the **single immediately
 *     preceding window of equal length**. An attacker IP that hit us three weeks
 *     ago and returns today reads as "new" there — but it is a *recurrence*, not
 *     a novelty. This report's baseline is the **entire retained history before
 *     the window**, so "first-seen" means first-seen, period.
 *   - trends.ts / report.ts rank by volume — a noisy, long-known signature buries
 *     the one quiet line that has never fired before.
 *   - iocExport.ts flattens everything into a feed with no first-seen lens.
 *
 * This module splits the stored alert history at the window boundary:
 *
 *   - **baseline** = every alert strictly *before* the window — the memory we
 *     diff against, and
 *   - **window**   = alerts inside the look-back window.
 *
 * An indicator is *novel* when it appears in the window and never appeared in the
 * baseline. It computes that across three orthogonal dimensions an analyst pivots
 * on — **source IPs** (new attackers / new internal talkers), **destination IPs**
 * (newly-touched targets), and **signatures** (detections that have never fired
 * before) — and for each novel indicator surfaces when it first landed, how often
 * it has fired since, its worst severity, and a one-line context sample.
 *
 * Honest caveats it bakes into the output:
 *
 *   - **Cold start.** With little or no baseline, *everything* is trivially
 *     "first-seen" and the signal is meaningless. The report detects a thin
 *     baseline and says so loudly rather than crying wolf.
 *   - **Bounded memory.** alertStore is capped/rotated, so "first-seen" is really
 *     "first-seen in retained history". The report states the baseline's reach
 *     (its earliest stored alert) so the operator knows how far back "new" looks.
 *
 * It is pure in-memory math over alertStore — no SSH, no Claude, no network — so
 * it is safe to call from the dashboard or CLI at any time. Output is both a
 * structured model and a ready-to-paste Markdown document, mirroring report.ts,
 * compare.ts, profile.ts, assets.ts, tuning.ts, watchlist.ts and rhythm.ts.
 */
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Which axis a novel indicator lives on. */
export type NoveltyDimensionKey = "srcIp" | "dstIp" | "signature";

/** One indicator seen for the first time inside the window. */
export interface NovelItem {
  /** The indicator value (an IP, or a signature string). */
  value: string;
  /** ms epoch of its earliest occurrence inside the window (its debut). */
  firstSeenMs: number;
  /** ms epoch of its most recent occurrence inside the window. */
  lastSeenMs: number;
  /** Total occurrences inside the window. */
  count: number;
  /** Occurrences at medium severity or above. */
  severeCount: number;
  /** Worst severity observed across this indicator's window occurrences. */
  severityMax: Severity;
  /** Occurrences whose action was an active block. */
  blockedCount: number;
  /** A short, human-readable context line (e.g. top signature + a peer). */
  sample: string;
}

/** One dimension's worth of novelty findings. */
export interface NoveltyDimension {
  key: NoveltyDimensionKey;
  /** Plural title, e.g. "Source IPs". */
  title: string;
  /** Distinct indicators of this kind observed anywhere in the window. */
  distinctInWindow: number;
  /** How many of those were novel (absent from the baseline). */
  novelCount: number;
  /** Novel indicators, ranked worst-first and truncated to the report limit. */
  items: NovelItem[];
  /** True when {@link items} was truncated by the limit (more novel exist). */
  truncated: boolean;
}

export interface NoveltyReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Alerts strictly before the window — the baseline we diff against. */
  baselineAlerts: number;
  /** Earliest stored alert time overall, or null when the store is empty. */
  baselineStartMs: number | null;
  /** How many hours of history precede the window (baseline reach), rounded. */
  baselineSpanHours: number;
  /**
   * True when the baseline is too thin to trust (no prior history, so every
   * indicator is trivially "first-seen"). Highlights say so loudly.
   */
  coldStart: boolean;
  /** Per-axis findings: source IPs, destination IPs, signatures. */
  dimensions: NoveltyDimension[];
  /**
   * Window alerts that involve at least one novel indicator (novel src, dst, or
   * signature) — the share of current activity that is genuinely new.
   */
  noveltyAlertCount: number;
  /** {@link noveltyAlertCount} as a percentage of {@link totalWindowAlerts}. */
  noveltyRatePct: number;
  /** Plain-language call-outs about the report as a whole. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface NoveltyOptions {
  /** Max novel indicators to list per dimension (clamped to [1, 500]). */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 25;
/** A baseline thinner than this many alerts can't meaningfully define "new". */
const COLD_START_BASELINE = 5;

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? (b as Severity) : a;
}

/** Medium or above is worth promoting / hunting. */
function isSevere(s: string | undefined): boolean {
  return sevRank(s) >= 2;
}

function isBlocked(action: string | undefined): boolean {
  return (action ?? "").toLowerCase() === "blocked";
}

// ----- formatting helpers (mirror rhythm.ts / assets.ts / watchlist.ts) -----

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** A compact relative-age label like "3h" / "2d" for the most-recent column. */
function fmtAge(ms: number, nowMs: number): string {
  const sec = Math.max(0, Math.round((nowMs - ms) / 1000));
  if (sec < 90) return `${sec}s`;
  const min = Math.round(sec / 60);
  if (min < 90) return `${min}m`;
  const hr = Math.round(min / 60);
  if (hr < 48) return `${hr}h`;
  return `${Math.round(hr / 24)}d`;
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
function clip(s: string, max = 60): string {
  const t = s.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

/**
 * Internal accumulator for one indicator while we fold the window. Holds the raw
 * occurrence stats plus the small tallies needed to render a context sample
 * without re-scanning the window.
 */
interface Accum {
  value: string;
  firstSeenMs: number;
  lastSeenMs: number;
  count: number;
  severeCount: number;
  severityMax: Severity;
  blockedCount: number;
  /** Co-occurring values for the context sample (e.g. signatures for a src). */
  contextCounts: Map<string, number>;
  /** A representative peer (other endpoint) for IP dimensions. */
  peerCounts: Map<string, number>;
}

function newAccum(value: string, t: number): Accum {
  return {
    value,
    firstSeenMs: t,
    lastSeenMs: t,
    count: 0,
    severeCount: 0,
    severityMax: "info",
    blockedCount: 0,
    contextCounts: new Map(),
    peerCounts: new Map(),
  };
}

function bump(map: Map<string, number>, key: string | undefined): void {
  if (!key) return;
  map.set(key, (map.get(key) ?? 0) + 1);
}

/** Most frequent key in a tally, ties broken by lexical order for stability. */
function topKey(map: Map<string, number>): string | undefined {
  let best: string | undefined;
  let bestN = -1;
  for (const [k, n] of map) {
    if (n > bestN || (n === bestN && best !== undefined && k < best)) {
      best = k;
      bestN = n;
    }
  }
  return best;
}

/** Compose the one-line context sample shown alongside a novel indicator. */
function sampleFor(key: NoveltyDimensionKey, a: Accum): string {
  const topSig = topKey(a.contextCounts);
  const topPeer = topKey(a.peerCounts);
  if (key === "signature") {
    // Context is the attacker→target pair this signature most often fired on.
    return topPeer ? clip(topPeer) : "—";
  }
  // Source / destination IP: name the signature + the busiest peer endpoint.
  const parts: string[] = [];
  if (topSig) parts.push(clip(topSig, 44));
  if (topPeer) parts.push(key === "srcIp" ? `→ ${topPeer}` : `← ${topPeer}`);
  return parts.length ? parts.join(" ") : "—";
}

/** Sort novel items worst-first: severity, then volume, then earliest debut. */
function rankItems(items: NovelItem[]): NovelItem[] {
  return items.sort((x, y) => {
    const s = sevRank(y.severityMax) - sevRank(x.severityMax);
    if (s) return s;
    if (y.count !== x.count) return y.count - x.count;
    return x.firstSeenMs - y.firstSeenMs;
  });
}

function finalize(key: NoveltyDimensionKey, a: Accum): NovelItem {
  return {
    value: a.value,
    firstSeenMs: a.firstSeenMs,
    lastSeenMs: a.lastSeenMs,
    count: a.count,
    severeCount: a.severeCount,
    severityMax: a.severityMax,
    blockedCount: a.blockedCount,
    sample: sampleFor(key, a),
  };
}

function writeHighlights(m: Omit<NoveltyReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (!m.totalWindowAlerts) return out;

  if (m.coldStart) {
    out.push(
      `⚠️ Cold start: only ${m.baselineAlerts} alert(s) precede this window, so almost everything reads as ` +
        `"first-seen". Treat the novelty signal as unreliable until more history accumulates.`,
    );
  }

  const totalNovel = m.dimensions.reduce((n, d) => n + d.novelCount, 0);
  if (!totalNovel) {
    out.push(`No first-seen indicators in the last ${m.hours}h — every source, target and signature has been seen before.`);
    return out;
  }

  for (const d of m.dimensions) {
    if (!d.novelCount) continue;
    out.push(`${d.novelCount} new ${d.title.toLowerCase()} (of ${d.distinctInWindow} distinct this window).`);
  }

  out.push(
    `${m.noveltyAlertCount} of ${m.totalWindowAlerts} window alert(s) (${m.noveltyRatePct}%) involve at least one ` +
      `first-seen indicator.`,
  );

  // Surface the single worst novel indicator across every dimension.
  let worst: { item: NovelItem; dim: NoveltyDimension } | null = null;
  for (const d of m.dimensions) {
    for (const it of d.items) {
      if (!worst || sevRank(it.severityMax) > sevRank(worst.item.severityMax)) worst = { item: it, dim: d };
    }
  }
  if (worst && isSevere(worst.item.severityMax)) {
    out.push(
      `🚨 Most severe new indicator: ${worst.dim.title.replace(/s$/, "").toLowerCase()} \`${worst.item.value}\` ` +
        `(${worst.item.severityMax}, ${worst.item.count} hit(s)) — never observed before this window. Prioritise it.`,
    );
  }
  return out;
}

function renderDimension(d: NoveltyDimension, nowMs: number): string {
  const lines: string[] = [];
  lines.push(`## New ${d.title} (${d.novelCount} of ${d.distinctInWindow} distinct)`);
  lines.push("");
  if (!d.novelCount) {
    lines.push(`_None — every ${d.title.replace(/s$/, "").toLowerCase()} this window has been seen before._`);
    lines.push("");
    return lines.join("\n");
  }
  const valueHeader = d.key === "signature" ? "Signature" : d.key === "srcIp" ? "Source IP" : "Destination IP";
  const ctxHeader = d.key === "signature" ? "Top src → dst" : "Top signature / peer";
  lines.push(
    mdTable(
      [valueHeader, "First seen", "Last", "Hits", "Severe", "Blocked", "Peak", ctxHeader],
      d.items.map((it) => [
        cell(it.value),
        fmtTime(it.firstSeenMs),
        fmtAge(it.lastSeenMs, nowMs),
        String(it.count),
        it.severeCount ? String(it.severeCount) : "·",
        it.blockedCount ? String(it.blockedCount) : "·",
        cell(it.severityMax),
        cell(it.sample),
      ]),
    ),
  );
  if (d.truncated) {
    lines.push("");
    lines.push(`_…and ${d.novelCount - d.items.length} more new ${d.title.toLowerCase()} not shown (raise \`limit\`)._`);
  }
  lines.push("");
  return lines.join("\n");
}

function renderMarkdown(m: NoveltyReport): string {
  const lines: string[] = [];
  lines.push(`# 🆕 SecTool First-Seen / Novelty Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  const baselineDesc =
    m.baselineStartMs !== null
      ? `${m.baselineAlerts} alert(s) back to ${fmtTime(m.baselineStartMs)} (~${m.baselineSpanHours}h of memory)`
      : `none`;
  lines.push(`**Baseline:** ${baselineDesc} · **Window alerts:** ${m.totalWindowAlerts}`);
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.totalWindowAlerts) {
    lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to diff.`);
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  for (const d of m.dimensions) lines.push(renderDimension(d, m.windowEndMs));

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. "First-seen" is relative to the **retained** alert history (the store is capped and ` +
      `rotated), so an indicator absent from the baseline above may simply predate it. ` +
      `No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the first-seen / novelty report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]). The window is
 *              diffed against *all* retained history that precedes it.
 * @param opts  {@link NoveltyOptions}: per-dimension `limit` and a `nowMs` pin.
 */
export function buildNovelty(hours: number, opts: NoveltyOptions = {}): NoveltyReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(500, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * 3_600_000;

  const all = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time));

  // Baseline = strictly before the window; window = inside it. Anything after
  // windowEndMs (clock skew) is ignored so it can't poison either set.
  const baseline: StoredAlert[] = [];
  const window: StoredAlert[] = [];
  let baselineStartMs: number | null = null;
  for (const a of all) {
    if (a.time < windowStartMs) {
      baseline.push(a);
      if (baselineStartMs === null || a.time < baselineStartMs) baselineStartMs = a.time;
    } else if (a.time <= windowEndMs) {
      window.push(a);
    }
  }

  // Seen-before sets per dimension, built once from the baseline.
  const seenSrc = new Set<string>();
  const seenDst = new Set<string>();
  const seenSig = new Set<string>();
  for (const a of baseline) {
    if (a.srcIp) seenSrc.add(a.srcIp);
    if (a.dstIp) seenDst.add(a.dstIp);
    if (a.signature) seenSig.add(a.signature);
  }

  // Fold the window, accumulating only indicators absent from the baseline.
  const srcAcc = new Map<string, Accum>();
  const dstAcc = new Map<string, Accum>();
  const sigAcc = new Map<string, Accum>();
  const distinctSrc = new Set<string>();
  const distinctDst = new Set<string>();
  const distinctSig = new Set<string>();
  let noveltyAlertCount = 0;

  const record = (acc: Map<string, Accum>, value: string, a: StoredAlert): void => {
    let e = acc.get(value);
    if (!e) {
      e = newAccum(value, a.time);
      acc.set(value, e);
    }
    e.count++;
    if (a.time < e.firstSeenMs) e.firstSeenMs = a.time;
    if (a.time > e.lastSeenMs) e.lastSeenMs = a.time;
    e.severityMax = maxSeverity(e.severityMax, a.severity);
    if (isSevere(a.severity)) e.severeCount++;
    if (isBlocked(a.action)) e.blockedCount++;
    return;
  };

  for (const a of window) {
    if (a.srcIp) distinctSrc.add(a.srcIp);
    if (a.dstIp) distinctDst.add(a.dstIp);
    if (a.signature) distinctSig.add(a.signature);

    const novelSrc = !!a.srcIp && !seenSrc.has(a.srcIp);
    const novelDst = !!a.dstIp && !seenDst.has(a.dstIp);
    const novelSig = !!a.signature && !seenSig.has(a.signature);
    if (novelSrc || novelDst || novelSig) noveltyAlertCount++;

    if (novelSrc) {
      record(srcAcc, a.srcIp!, a);
      const e = srcAcc.get(a.srcIp!)!;
      bump(e.contextCounts, a.signature);
      bump(e.peerCounts, a.dstIp);
    }
    if (novelDst) {
      record(dstAcc, a.dstIp!, a);
      const e = dstAcc.get(a.dstIp!)!;
      bump(e.contextCounts, a.signature);
      bump(e.peerCounts, a.srcIp);
    }
    if (novelSig) {
      record(sigAcc, a.signature!, a);
      const e = sigAcc.get(a.signature!)!;
      // For a signature, the most telling context is the attacker→target pair.
      if (a.srcIp || a.dstIp) bump(e.peerCounts, `${a.srcIp ?? "?"} → ${a.dstIp ?? "?"}`);
    }
  }

  const buildDim = (
    key: NoveltyDimensionKey,
    title: string,
    acc: Map<string, Accum>,
    distinct: number,
  ): NoveltyDimension => {
    const ranked = rankItems([...acc.values()].map((a) => finalize(key, a)));
    return {
      key,
      title,
      distinctInWindow: distinct,
      novelCount: ranked.length,
      items: ranked.slice(0, limit),
      truncated: ranked.length > limit,
    };
  };

  const dimensions: NoveltyDimension[] = [
    buildDim("srcIp", "Source IPs", srcAcc, distinctSrc.size),
    buildDim("dstIp", "Destination IPs", dstAcc, distinctDst.size),
    buildDim("signature", "Signatures", sigAcc, distinctSig.size),
  ];

  const totalWindowAlerts = window.length;
  const noveltyRatePct = totalWindowAlerts ? Math.round((noveltyAlertCount / totalWindowAlerts) * 100) : 0;
  const baselineSpanHours =
    baselineStartMs !== null ? Math.max(0, Math.round((windowStartMs - baselineStartMs) / 3_600_000)) : 0;
  const coldStart = baseline.length < COLD_START_BASELINE;

  const base: Omit<NoveltyReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts,
    baselineAlerts: baseline.length,
    baselineStartMs,
    baselineSpanHours,
    coldStart,
    dimensions,
    noveltyAlertCount,
    noveltyRatePct,
  };
  const highlights = writeHighlights(base);
  const model: NoveltyReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded novelty report. */
export function noveltyFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-novelty-${stamp}.md`;
}
