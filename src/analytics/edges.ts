/**
 * Attack-edge / lateral-movement report — "which exact attacker→target *pairs*
 * are hottest, and is anything moving sideways inside the network?"
 *
 * Every other offline report collapses the alert history onto a *single* axis:
 *
 *   - campaigns.ts / persistence.ts / spread.ts / beacon.ts roll up by the
 *     EXTERNAL source ("who is attacking me?"),
 *   - assets.ts rolls up by the INTERNAL host ("which of my boxes is at risk?"),
 *   - surge.ts / rhythm.ts / trends.ts roll up by TIME,
 *   - tuning.ts / killchain.ts / cooccurrence.ts roll up by SIGNATURE.
 *
 * None of them keeps the *relationship* intact. Yet the unit a responder
 * actually triages is the **directed pair** — this source hitting that
 * destination. Two facts only the pair carries:
 *
 *   1. **Lateral movement.** An alert whose SOURCE *and* DESTINATION are both
 *      internal (RFC1918) is one internal host attacking another — the single
 *      highest-value tell in incident response (a beachhead pivoting toward the
 *      crown jewels). A source-rollup buries it among inbound noise; a
 *      target-rollup sees the victim but not that the attacker is *also* yours.
 *      Only the edge makes "10.0.0.7 → 10.0.0.12" jump off the page.
 *   2. **Direction.** The same two endpoints mean very different things by
 *      orientation: external→internal is targeting, internal→external is a
 *      compromised box calling out (exfil / beacon), internal→internal is
 *      lateral, external→external is passthrough noise.
 *
 * This report ranks the directed src→dst edges in the stored alert history,
 * classifies each by direction, and scores them so the dangerous relationships
 * — lateral first, then severe outbound/inbound — float to the top:
 *
 *   - **Direction** (lateral / outbound / inbound / external) — the dominant
 *     contributor to the score, because orientation *is* the threat model here.
 *   - **Severity** — the worst signature the pair traded.
 *   - **Volume** — log-scaled, so a relationship does not have to be loud to
 *     rank, but a hammering one still edges out a one-shot.
 *   - **Span / recurrence** — an edge active across the window (not one burst)
 *     reads as a sustained relationship.
 *   - **Mitigation** — whether every alert on the edge was actually blocked.
 *
 * Honest caveats baked into the output:
 *
 *   - **Alerts, not flows.** SecTool stores IPS *detections*, not every packet,
 *     so an edge is a relationship between *alerting* endpoints. Two hosts can
 *     talk plenty without tripping a rule; absence of an edge is not absence of
 *     a relationship.
 *   - **Directionality is the gateway's.** src/dst come from the parsed alert;
 *     a misattributed direction (NAT hairpin, asymmetric routing) mislabels the
 *     edge. The report classifies, it does not convict.
 *   - **Internal = RFC1918.** Lateral detection assumes the private-address
 *     ranges are your network. A flat/VPN topology can blur that line.
 *
 * Pure in-memory math over alertStore (plus blocklist/watchlist/safelist
 * membership flags, like persistence.ts / assets.ts / campaigns.ts) — no SSH,
 * no Claude, no network. Output is both a structured model and a ready-to-paste
 * Markdown document, mirroring report.ts, compare.ts, profile.ts, assets.ts,
 * surge.ts, spread.ts, beacon.ts, cooccurrence.ts and persistence.ts.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/**
 * Orientation of an edge relative to the local (RFC1918) network. Listed in
 * descending triage priority — `lateral` is the headline signal of this report.
 */
export type EdgeDirection = "lateral" | "outbound" | "inbound" | "external";

/** One directed source→destination relationship, rolled up across the window. */
export interface AttackEdge {
  /** The source (attacker-side) IP of the relationship. */
  srcIp: string;
  /** The destination (target-side) IP of the relationship. */
  dstIp: string;
  /** Orientation relative to the local network (see {@link EdgeDirection}). */
  direction: EdgeDirection;
  /** Total alerts traded across this exact directed pair inside the window. */
  alertCount: number;
  /** ms epoch of the first alert on this edge. */
  firstSeenMs: number;
  /** ms epoch of the last alert on this edge. */
  lastSeenMs: number;
  /** lastSeen − firstSeen, in ms — how long the relationship persisted. */
  spanMs: number;
  /** Worst severity observed across the edge's alerts. */
  severityMax: Severity;
  /** Alerts at medium severity or above. */
  severeCount: number;
  /** Alerts whose action was an active block. */
  blockedCount: number;
  /** Distinct signatures traded across the edge. */
  distinctSignatures: number;
  /** The dominant signature on the edge (may be empty). */
  topSignature: string;
  /** Alert count for {@link topSignature} on the edge. */
  topSignatureCount: number;
  /** The dominant category on the edge (may be empty). */
  topCategory: string;
  /** Whether the source IP is on the blocklist. */
  srcBlocked: boolean;
  /** Whether the source IP is on the watchlist. */
  srcWatched: boolean;
  /** Whether the source IP is marked safe (suppresses it from highlights). */
  srcSafe: boolean;
  /** Composite 0-100 edge-priority score (direction + severity + volume + span − mitigation). */
  score: number;
}

export interface EdgesReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Distinct directed src→dst edges seen at all in the window. */
  distinctEdges: number;
  /** The minimum alert count an edge needs to be ranked (clamped floor). */
  minAlerts: number;
  /** How many edges cleared {@link minAlerts} and were ranked. */
  rankedCount: number;
  /** Count of ranked edges by direction, for the at-a-glance breakdown. */
  directionCounts: Record<EdgeDirection, number>;
  /** Ranked edges, most-dangerous first, truncated to the report limit. */
  edges: AttackEdge[];
  /** True when the edge table was truncated by the limit. */
  truncated: boolean;
  /** Plain-language call-outs about the report as a whole. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface EdgesOptions {
  /** Max edge rows in the table (clamped to [1, 1000]). */
  limit?: number;
  /** Minimum alerts for an edge to be ranked (clamped to [1, 100000]). */
  minAlerts?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 30;
const DEFAULT_MIN_ALERTS = 2;
const MS_PER_HOUR = 3_600_000;

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

/** RFC1918 / loopback / link-local / ULA — mirrors persistence.ts / surge.ts / spread.ts. */
function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
}

/** Classify an edge by the orientation of its two endpoints relative to the LAN. */
function classifyDirection(srcInternal: boolean, dstInternal: boolean): EdgeDirection {
  if (srcInternal && dstInternal) return "lateral";
  if (srcInternal && !dstInternal) return "outbound";
  if (!srcInternal && dstInternal) return "inbound";
  return "external";
}

// ----- formatting helpers (mirror persistence.ts / surge.ts / beacon.ts) -----

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** A compact relative-age label like "3h" / "2d" for the recency column. */
function fmtAge(ms: number, nowMs: number): string {
  const sec = Math.max(0, Math.round((nowMs - ms) / 1000));
  if (sec < 90) return `${sec}s`;
  const min = Math.round(sec / 60);
  if (min < 90) return `${min}m`;
  const hr = Math.round(min / 60);
  if (hr < 48) return `${hr}h`;
  return `${Math.round(hr / 24)}d`;
}

/** A human duration like "45m" / "2h 10m" / "3d 4h" for an edge's span. */
function fmtDuration(ms: number): string {
  const min = Math.max(0, Math.round(ms / 60000));
  if (min < 60) return `${min}m`;
  const hr = Math.floor(min / 60);
  if (hr < 24) {
    const rem = min % 60;
    return rem ? `${hr}h ${rem}m` : `${hr}h`;
  }
  const days = Math.floor(hr / 24);
  const remHr = hr % 24;
  return remHr ? `${days}d ${remHr}h` : `${days}d`;
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

function bump(map: Map<string, number>, key: string | undefined): void {
  if (!key) return;
  map.set(key, (map.get(key) ?? 0) + 1);
}

/** Most frequent key in a tally, ties broken by lexical order for stability. */
function topKey(map: Map<string, number>): { key: string; count: number } {
  let best = "";
  let bestN = -1;
  for (const [k, n] of map) {
    if (n > bestN || (n === bestN && k < best)) {
      best = k;
      bestN = n;
    }
  }
  return { key: best, count: Math.max(0, bestN) };
}

/** A short glyph + word for an edge direction, used in the table and legend. */
function directionLabel(d: EdgeDirection): string {
  switch (d) {
    case "lateral":
      return "↔ lateral";
    case "outbound":
      return "↗ outbound";
    case "inbound":
      return "↘ inbound";
    default:
      return "· external";
  }
}

/**
 * Internal accumulator for one directed edge while we fold its alerts. The
 * src/dst direction is fixed by the key, so only the per-edge tallies vary.
 */
interface Accum {
  srcIp: string;
  dstIp: string;
  direction: EdgeDirection;
  alertCount: number;
  firstSeenMs: number;
  lastSeenMs: number;
  signatures: Map<string, number>;
  categories: Map<string, number>;
  severityMax: Severity;
  severeCount: number;
  blockedCount: number;
}

function newAccum(srcIp: string, dstIp: string, direction: EdgeDirection, t: number): Accum {
  return {
    srcIp,
    dstIp,
    direction,
    alertCount: 0,
    firstSeenMs: t,
    lastSeenMs: t,
    signatures: new Map(),
    categories: new Map(),
    severityMax: "info",
    severeCount: 0,
    blockedCount: 0,
  };
}

function foldAlert(e: Accum, a: StoredAlert): void {
  e.alertCount++;
  if (a.time < e.firstSeenMs) e.firstSeenMs = a.time;
  if (a.time > e.lastSeenMs) e.lastSeenMs = a.time;
  bump(e.signatures, a.signature);
  bump(e.categories, a.category);
  e.severityMax = maxSeverity(e.severityMax, a.severity);
  if (isSevere(a.severity)) e.severeCount++;
  if (isBlocked(a.action)) e.blockedCount++;
}

/** Direction's contribution to the score — orientation *is* the threat model. */
function directionScore(d: EdgeDirection): number {
  switch (d) {
    case "lateral":
      return 40; // internal→internal: the crown-jewel signal
    case "outbound":
      return 28; // internal→external: compromised box calling out
    case "inbound":
      return 18; // external→internal: targeting
    default:
      return 4; // external→external: passthrough noise
  }
}

/**
 * Composite 0-100 edge-priority score. Direction carries the most weight
 * because orientation decides the threat model; severity and (log-scaled)
 * volume sharpen it; a relationship sustained across time edges out a one-off;
 * and an edge that was fully blocked is discounted because it is already
 * mitigated. Tuned so a quiet-but-lateral edge still outranks a loud inbound
 * scan that the gateway already dropped.
 */
function scoreEdge(
  direction: EdgeDirection,
  severityMax: Severity,
  alertCount: number,
  spanMs: number,
  windowMs: number,
  blockedFraction: number,
): number {
  const dirScore = directionScore(direction); // 0..40
  const sevScore = (sevRank(severityMax) / 4) * 28; // 0..28
  const volScore = Math.min(1, Math.log10(alertCount + 1) / 2) * 16; // 0..16, log-scaled
  const spanScore = Math.min(1, spanMs / Math.max(1, windowMs)) * 10; // 0..10, sustained relationship
  const mitigation = blockedFraction * 12; // 0..12 discount when already blocked
  return Math.max(0, Math.min(100, Math.round(dirScore + sevScore + volScore + spanScore - mitigation)));
}

/**
 * Rank: direction priority first (lateral floats up regardless of volume), then
 * the composite score, then severity, then raw volume, then recency.
 */
const DIR_RANK: Record<EdgeDirection, number> = { lateral: 3, outbound: 2, inbound: 1, external: 0 };

function rank(items: AttackEdge[]): AttackEdge[] {
  return items.sort((x, y) => {
    if (DIR_RANK[y.direction] !== DIR_RANK[x.direction]) return DIR_RANK[y.direction] - DIR_RANK[x.direction];
    if (y.score !== x.score) return y.score - x.score;
    if (sevRank(y.severityMax) !== sevRank(x.severityMax)) return sevRank(y.severityMax) - sevRank(x.severityMax);
    if (y.alertCount !== x.alertCount) return y.alertCount - x.alertCount;
    return y.lastSeenMs - x.lastSeenMs;
  });
}

function writeHighlights(m: Omit<EdgesReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (!m.totalWindowAlerts) return out;

  if (!m.rankedCount) {
    out.push(
      `No attack edges over the last ${m.hours}h — no src→dst pair produced ≥${m.minAlerts} alerts, so there is ` +
        `no relationship with enough weight to rank. Quiet window.`,
    );
    return out;
  }

  out.push(
    `🕸️ Ranked ${m.rankedCount} attacker→target edge(s) over the last ${m.hours}h ` +
      `(${m.distinctEdges} distinct pair(s) seen) — ` +
      `${m.directionCounts.lateral} lateral · ${m.directionCounts.outbound} outbound · ` +
      `${m.directionCounts.inbound} inbound · ${m.directionCounts.external} external.`,
  );

  // Lateral movement is the headline — surface it first and loudest.
  const lateral = m.edges.filter((e) => e.direction === "lateral");
  if (lateral.length) {
    const worst = lateral[0]!;
    out.push(
      `🚨 **${lateral.length} lateral edge(s)** — internal host → internal host, the strongest lateral-movement ` +
        `tell. Hottest: \`${worst.srcIp}\` → \`${worst.dstIp}\` (${worst.alertCount} alert(s)` +
        (worst.topSignature ? `, mostly \`${clip(worst.topSignature)}\`` : "") +
        (worst.severityMax !== "info" ? `, peak ${worst.severityMax}` : "") +
        `). Treat a confirmed internal→internal attack edge as a probable in-progress compromise.`,
    );
  }

  const top = m.edges[0];
  if (top && top.direction !== "lateral") {
    out.push(
      `🎯 Top edge: \`${top.srcIp}\` → \`${top.dstIp}\` (**${directionLabel(top.direction)}**, score ${top.score}/100) ` +
        `— ${top.alertCount} alert(s) over ${fmtDuration(top.spanMs)}` +
        (top.topSignature ? `, mostly \`${clip(top.topSignature)}\`` : "") +
        (top.severityMax !== "info" ? `, peak ${top.severityMax}` : "") +
        `${top.srcBlocked ? " (source already blocked)" : ""}.`,
    );
  }

  const outbound = m.edges.filter((e) => e.direction === "outbound" && isSevere(e.severityMax) && !e.srcSafe);
  if (outbound.length) {
    out.push(
      `📤 ${outbound.length} **outbound** edge(s) carry a medium-or-worse signature — an internal host reaching ` +
        `out under a real detection is a compromise / exfil / beacon tell; pivot to the asset & beacon reports.`,
    );
  }

  const unblockedSevere = m.edges.filter(
    (e) => isSevere(e.severityMax) && e.blockedCount < e.alertCount && !e.srcSafe && e.direction !== "external",
  );
  if (unblockedSevere.length) {
    out.push(
      `⚠️ ${unblockedSevere.length} severe edge(s) were **not fully blocked** — at least one dangerous alert on the ` +
        `relationship slipped through detection-only. These are the gaps to close first.`,
    );
  }
  return out;
}

function edgeTable(edges: AttackEdge[], nowMs: number): string {
  return mdTable(
    ["Source", "→ Target", "Dir", "Score", "Alerts", "Sev", "Severe", "Blocked", "Span", "Last", "Top signature"],
    edges.map((e) => {
      const flags =
        (e.srcBlocked ? " ⛔" : "") + (e.srcWatched ? " 👁" : "") + (e.srcSafe ? " ✅" : "");
      return [
        cell(e.srcIp + flags),
        cell(e.dstIp),
        directionLabel(e.direction),
        String(e.score),
        String(e.alertCount),
        cell(e.severityMax),
        e.severeCount ? `${e.severeCount}/${e.alertCount}` : "0",
        e.blockedCount ? `${e.blockedCount}/${e.alertCount}` : "0",
        fmtDuration(e.spanMs),
        fmtAge(e.lastSeenMs, nowMs),
        cell(clip(e.topSignature || "—", 40)),
      ];
    }),
  );
}

function renderMarkdown(m: EdgesReport): string {
  const lines: string[] = [];
  lines.push(`# 🕸️ SecTool Attack-Edge / Lateral-Movement Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** ranked by directed src→dst relationship (direction + severity + volume + span − mitigation) · ` +
      `floor **≥${m.minAlerts} alerts/edge** · **${m.rankedCount} ranked** of ${m.distinctEdges} edge(s) · ` +
      `**Window alerts:** ${m.totalWindowAlerts}`,
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

  // A one-line direction breakdown so the orientation mix is visible up top.
  lines.push(
    `**Direction mix (ranked edges):** ↔ lateral ${m.directionCounts.lateral} · ` +
      `↗ outbound ${m.directionCounts.outbound} · ↘ inbound ${m.directionCounts.inbound} · ` +
      `· external ${m.directionCounts.external}`,
  );
  lines.push("");

  lines.push(`## Hottest edges — directed attacker→target relationships`);
  lines.push("");
  if (!m.edges.length) {
    lines.push(
      `_None — no src→dst pair produced ≥${m.minAlerts} alerts this window, so there is no relationship to rank._`,
    );
    lines.push("");
  } else {
    lines.push(edgeTable(m.edges, m.windowEndMs));
    lines.push("");
  }

  if (m.truncated) {
    lines.push(`_The edge table was truncated to the row limit — raise \`limit\` to see more._`);
    lines.push("");
  }

  lines.push(
    `**Legend:** _Dir_ = orientation relative to your LAN — \`↔ lateral\` (internal→internal, the lateral-movement ` +
      `signal and top priority), \`↗ outbound\` (internal→external, possible compromise / exfil / beacon), ` +
      `\`↘ inbound\` (external→internal, targeting), \`· external\` (external→external, passthrough noise). ` +
      `_Score_ = 0-100 edge priority (direction 40 + severity 28 + volume 16 + span 10 − mitigation 12). ` +
      `_Severe_ / _Blocked_ are shares of the edge's alerts at medium-or-worse / actively blocked. Flags on the ` +
      `source: ⛔ blocked, 👁 watched, ✅ safe.`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from stored **IPS-alert** relationships, not full flow data — an edge is a ` +
      `relationship between *alerting* endpoints, so two hosts can communicate without one appearing here. ` +
      `Direction comes from the gateway's src/dst attribution and "internal" means RFC1918, so a NAT hairpin or ` +
      `flat/VPN topology can mislabel an edge. The report classifies and ranks; it does not convict. No live ` +
      `gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the attack-edge / lateral-movement report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link EdgesOptions}: `limit`, `minAlerts`, and a `nowMs` pin.
 */
export function buildEdges(hours: number, opts: EdgesOptions = {}): EdgesReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(1000, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minAlerts = Math.max(1, Math.min(100000, Math.floor(opts.minAlerts ?? DEFAULT_MIN_ALERTS)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;
  const windowMs = Math.max(1, windowEndMs - windowStartMs);

  const all = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time));

  // Fold alerts that carry *both* a valid source and destination into per-edge
  // accumulators keyed by the directed pair. An alert missing either endpoint
  // has no relationship to attribute and is skipped.
  const byEdge = new Map<string, Accum>();
  let totalWindowAlerts = 0;
  for (const a of all) {
    if (a.time < windowStartMs || a.time > windowEndMs) continue;
    totalWindowAlerts++;
    const src = a.srcIp;
    const dst = a.dstIp;
    if (!src || !dst || isIP(src) === 0 || isIP(dst) === 0 || src === dst) continue;
    const direction = classifyDirection(isPrivate(src), isPrivate(dst));
    const key = `${src} ${dst}`;
    let acc = byEdge.get(key);
    if (!acc) {
      acc = newAccum(src, dst, direction, a.time);
      byEdge.set(key, acc);
    }
    foldAlert(acc, a);
  }

  const ranked: AttackEdge[] = [];
  for (const acc of byEdge.values()) {
    if (acc.alertCount < minAlerts) continue;
    const spanMs = acc.lastSeenMs - acc.firstSeenMs;
    const blockedFraction = acc.alertCount ? acc.blockedCount / acc.alertCount : 0;
    const sig = topKey(acc.signatures);
    const cat = topKey(acc.categories);
    ranked.push({
      srcIp: acc.srcIp,
      dstIp: acc.dstIp,
      direction: acc.direction,
      alertCount: acc.alertCount,
      firstSeenMs: acc.firstSeenMs,
      lastSeenMs: acc.lastSeenMs,
      spanMs,
      severityMax: acc.severityMax,
      severeCount: acc.severeCount,
      blockedCount: acc.blockedCount,
      distinctSignatures: acc.signatures.size,
      topSignature: sig.key,
      topSignatureCount: sig.count,
      topCategory: cat.key,
      srcBlocked: blockStore.has(acc.srcIp),
      srcWatched: watchStore.has(acc.srcIp),
      srcSafe: safeStore.has(acc.srcIp),
      score: scoreEdge(acc.direction, acc.severityMax, acc.alertCount, spanMs, windowMs, blockedFraction),
    });
  }

  const rankedAll = rank(ranked);
  const edges = rankedAll.slice(0, limit);

  const directionCounts: Record<EdgeDirection, number> = { lateral: 0, outbound: 0, inbound: 0, external: 0 };
  for (const e of rankedAll) directionCounts[e.direction]++;

  const base: Omit<EdgesReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts,
    distinctEdges: byEdge.size,
    minAlerts,
    rankedCount: rankedAll.length,
    directionCounts,
    edges,
    truncated: rankedAll.length > edges.length,
  };
  const highlights = writeHighlights(base);
  const model: EdgesReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded attack-edge report. */
export function edgesFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-edges-${stamp}.md`;
}
