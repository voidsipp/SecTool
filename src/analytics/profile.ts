/**
 * Single-entity (IP / host) profile report.
 *
 * Where the Trends view aggregates *everything* and Campaigns clusters *all*
 * external attackers, this module answers the orthogonal question an analyst
 * asks during an investigation: "tell me everything about THIS one address."
 *
 * Given a single IPv4/IPv6 address it rolls up — from the local alert history —
 * every alert that address appears in (as source or destination), then derives:
 *
 *   - whether it's an internal host or an external peer,
 *   - first / last seen, active span, and a volume timeline,
 *   - severity / disposition / triage breakdowns,
 *   - the signatures, categories and classifications it triggered,
 *   - every counterpart endpoint it talked to (peers), split internal/external,
 *   - its current operator state (blocked / watched / safe, with the watch note),
 *   - the most severe individual detections, and
 *   - a composite 0-100 risk score plus a plain-language narrative.
 *
 * It is pure in-memory math over alertStore — no SSH, no Claude, no network — so
 * it is safe to call from the dashboard or CLI at any time. Output is both a
 * structured model and a ready-to-paste Markdown document, mirroring report.ts
 * and compare.ts.
 *
 * This complements:
 *   - search.ts     (lists the matching alert *rows* — no roll-up or scoring),
 *   - campaigns.ts  (clusters *all* attackers — not a single-entity deep dive),
 *   - report.ts     (a whole-window snapshot — not scoped to one address).
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { dismissStore } from "../store/dismissed.ts";
import { triageStore, type TriageStatus } from "../store/triage.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Severity → risk weight, identical to the report/compare posture math. */
const SEV_WEIGHT: Record<string, number> = { info: 0, low: 1, medium: 2, high: 4, critical: 8 };

export interface TopEntry {
  key: string;
  count: number;
}

export interface ProfileSignature {
  signature: string;
  count: number;
  severityMax: Severity;
}

export interface ProfilePeer {
  /** The counterpart endpoint this IP exchanged alerts with. */
  ip: string;
  /** Number of alerts shared with this peer. */
  count: number;
  /** Whether the peer is an internal (RFC1918 / loopback / link-local) host. */
  internal: boolean;
  /** Most recent alert time with this peer, ms epoch. */
  lastSeen: number;
}

export interface ProfileTimelineBucket {
  startMs: number;
  count: number;
}

export interface ProfileNotable {
  id: string;
  time: number;
  severity: string;
  signature: string;
  category: string;
  /** The counterpart endpoint, if the alert carried one. */
  peer?: string;
  /** Whether this IP was the source ("→") or destination ("←") of the alert. */
  direction: "src" | "dst" | "self";
  action: string;
  triageStatus: string;
}

export interface ProfileModel {
  /** The address profiled (echoed back, trimmed). */
  ip: string;
  /** False when `ip` was not a valid IP — the model is then an empty stub. */
  valid: boolean;
  /** Whether the profiled address itself is internal (RFC1918 etc). */
  internal: boolean;
  /** Look-back window in hours; 0 = entire stored history. */
  hours: number;
  /** When the profile was generated, ms epoch. */
  generatedAt: number;
  /** Window bounds, ms epoch (start = -Infinity sentinel becomes 0 for full history). */
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts involving this IP in the window. */
  total: number;
  /** Of those, how many had this IP as the source / destination. */
  asSrc: number;
  asDst: number;
  /** Earliest / latest alert times and the span between them (ms). */
  firstSeen?: number;
  lastSeen?: number;
  spanMs: number;
  /** Highest severity observed. */
  severityMax: Severity;
  /** Per-severity counts, ordered info → critical (zeros included). */
  bySeverity: Array<{ severity: Severity; count: number }>;
  /** Disposition breakdown (blocked / detected / allowed / unknown), zeros omitted. */
  byAction: Array<{ action: string; count: number }>;
  /** Triage workflow breakdown (open / investigating / resolved / false-positive). */
  byTriage: Array<{ status: TriageStatus | "open"; count: number }>;
  /** Signatures this IP triggered, most-seen first. */
  topSignatures: ProfileSignature[];
  topCategories: TopEntry[];
  topClassifications: TopEntry[];
  /** Counterpart endpoints, most-contacted first. */
  peers: ProfilePeer[];
  /** Volume buckets across the window (always 24 evenly-sized bins). */
  timeline: ProfileTimelineBucket[];
  timelineBucketMs: number;
  timelineMax: number;
  /** The most severe individual detections involving this IP, worst first. */
  notable: ProfileNotable[];
  /** Current operator state for this exact IP. */
  state: { blocked: boolean; watched: boolean; safe: boolean; watchNote?: string };
  /** Composite 0-100 risk score (see scoreProfile). */
  riskScore: number;
  /** Plain-language one-line headline. */
  narrative: string;
  /** Bulleted call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

const DEFAULT_TOP_N = 10;
const TIMELINE_BUCKETS = 24;
const NOTABLE_LIMIT = 12;

function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
}

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? (b as Severity) : a;
}

function normalizeAction(a: string | undefined): string {
  const v = (a ?? "").toLowerCase().trim();
  if (v === "blocked" || v === "detected" || v === "allowed") return v;
  return "unknown";
}

function bump<T>(m: Map<T, number>, k: T | undefined | null): void {
  if (k === undefined || k === null || k === "") return;
  m.set(k, (m.get(k) ?? 0) + 1);
}

function topN(m: Map<string, number>, n: number): TopEntry[] {
  return [...m.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key))
    .slice(0, n);
}

function pct(n: number, total: number): number {
  return total > 0 ? Math.round((n / total) * 100) : 0;
}

/**
 * Composite 0-100 risk score for the entity. Rewards severity, raw volume,
 * peer fan-out and signature diversity; nudges up watched/blocked addresses and
 * down ones the gateway already stops or the operator marked safe.
 */
function scoreProfile(p: {
  severityMax: Severity;
  total: number;
  peerCount: number;
  signatureCount: number;
  blockedCount: number;
  watched: boolean;
  safe: boolean;
}): number {
  if (p.total === 0) return 0;
  let score = sevRank(p.severityMax) * 14; // up to 56 from severity
  score += Math.min(20, Math.log2(p.total + 1) * 6); // volume, diminishing
  score += Math.min(12, (p.signatureCount - 1) * 4); // signature diversity
  score += Math.min(12, (p.peerCount - 1) * 3); // fan-out across peers
  if (p.watched) score += 6; // operator already flagged it
  if (p.blockedCount === p.total) score -= 6; // gateway stopped everything
  if (p.safe) score -= 30; // explicitly trusted
  return Math.max(0, Math.min(100, Math.round(score)));
}

// ----- formatting helpers (mirror report.ts conventions) -----

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function fmtAgo(ms: number, now: number): string {
  const s = Math.max(0, Math.round((now - ms) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

function fmtSpan(ms: number): string {
  if (ms <= 0) return "—";
  const m = Math.round(ms / 60_000);
  if (m < 60) return `${m}m`;
  const h = m / 60;
  if (h < 48) return `${h.toFixed(1)}h`;
  return `${(h / 24).toFixed(1)}d`;
}

function sparkline(timeline: ProfileTimelineBucket[], max: number): string {
  const blocks = "▁▂▃▄▅▆▇█";
  const peak = max || 1;
  return timeline
    .map((b) => {
      if (b.count === 0) return "·";
      const idx = Math.min(blocks.length - 1, Math.max(0, Math.round((b.count / peak) * (blocks.length - 1))));
      return blocks[idx];
    })
    .join("");
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

/** Compose the headline + highlight bullets from the computed roll-up. */
function writeNarrative(model: Omit<ProfileModel, "narrative" | "highlights" | "markdown">): {
  narrative: string;
  highlights: string[];
} {
  const highlights: string[] = [];
  const kind = model.internal ? "internal host" : "external peer";

  if (model.total === 0) {
    return {
      narrative: `No alerts involving ${model.ip} were found${model.hours ? ` in the last ${model.hours}h` : " in the stored history"}.`,
      highlights,
    };
  }

  const windowLabel = model.hours ? `the last ${model.hours}h` : "stored history";
  const parts: string[] = [];
  parts.push(
    `${model.ip} (${kind}) appears in ${model.total} alert(s) across ${windowLabel} ` +
      `— ${model.asSrc} as source, ${model.asDst} as destination — peaking at ${model.severityMax} severity ` +
      `(risk score ${model.riskScore}/100).`,
  );

  const sevMap = new Map(model.bySeverity.map((s) => [s.severity, s.count]));
  const crit = sevMap.get("critical") ?? 0;
  const high = sevMap.get("high") ?? 0;
  if (crit + high > 0) highlights.push(`${crit} critical + ${high} high-severity detection(s).`);

  const blocked = model.byAction.find((a) => a.action === "blocked")?.count ?? 0;
  const detected = model.byAction.find((a) => a.action === "detected")?.count ?? 0;
  const actioned = blocked + detected;
  if (actioned > 0) {
    highlights.push(`${blocked} blocked, ${detected} detected-only (${pct(blocked, actioned)}% block rate).`);
  }

  const topSig = model.topSignatures[0];
  if (topSig) highlights.push(`Top signature: "${topSig.signature}" (${topSig.count} hit(s)).`);

  if (model.peers.length) {
    const internalPeers = model.peers.filter((p) => p.internal).length;
    highlights.push(
      `Touched ${model.peers.length} distinct peer(s)` +
        (model.internal ? "." : ` (${internalPeers} internal host(s)).`),
    );
  }

  if (model.firstSeen !== undefined && model.lastSeen !== undefined) {
    highlights.push(
      `Active ${fmtAgo(model.firstSeen, model.generatedAt)} → ${fmtAgo(model.lastSeen, model.generatedAt)} ` +
        `(span ${fmtSpan(model.spanMs)}).`,
    );
  }

  const stateBits: string[] = [];
  if (model.state.blocked) stateBits.push("blocked");
  if (model.state.watched) stateBits.push("watched");
  if (model.state.safe) stateBits.push("safe");
  if (stateBits.length) highlights.push(`Operator state: ${stateBits.join(", ")}.`);

  const open = model.byTriage.find((t) => t.status === "open")?.count ?? 0;
  if (open > 0) highlights.push(`${open} alert(s) still open in triage.`);

  return { narrative: parts.join(" "), highlights };
}

function renderMarkdown(model: ProfileModel): string {
  const lines: string[] = [];
  const kind = model.internal ? "Internal host" : "External peer";

  lines.push(`# 🛡️ SecTool Entity Profile — \`${model.ip}\``);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(model.generatedAt)}`);
  lines.push(`**Scope:** ${model.hours ? `last ${model.hours}h` : "entire stored history"}`);
  lines.push(`**Classification:** ${kind}`);
  lines.push(`**Risk score:** ${model.riskScore}/100 (peak severity ${model.severityMax})`);
  const stateBits: string[] = [];
  if (model.state.blocked) stateBits.push("🚫 blocked");
  if (model.state.watched) stateBits.push(`⚑ watched${model.state.watchNote ? ` — ${model.state.watchNote}` : ""}`);
  if (model.state.safe) stateBits.push("✓ safe");
  lines.push(`**Operator state:** ${stateBits.length ? stateBits.join(" · ") : "none"}`);
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  lines.push(model.narrative);
  if (model.highlights.length) {
    lines.push("");
    for (const h of model.highlights) lines.push(`- ${h}`);
  }
  lines.push("");

  if (model.total === 0) {
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  lines.push(`## Key metrics`);
  lines.push("");
  lines.push(
    mdTable(
      ["Metric", "Value"],
      [
        ["Total alerts", String(model.total)],
        ["As source", String(model.asSrc)],
        ["As destination", String(model.asDst)],
        ["Distinct peers", String(model.peers.length)],
        ["Distinct signatures", String(model.topSignatures.length)],
        ["First seen", model.firstSeen ? `${fmtTime(model.firstSeen)} (${fmtAgo(model.firstSeen, model.generatedAt)})` : "—"],
        ["Last seen", model.lastSeen ? `${fmtTime(model.lastSeen)} (${fmtAgo(model.lastSeen, model.generatedAt)})` : "—"],
        ["Active span", fmtSpan(model.spanMs)],
      ],
    ),
  );
  lines.push("");

  lines.push(`## Severity breakdown`);
  lines.push("");
  lines.push(
    mdTable(
      ["Severity", "Count", "Share"],
      model.bySeverity.map((s) => [cell(s.severity), String(s.count), `${pct(s.count, model.total)}%`]),
    ),
  );
  lines.push("");

  if (model.byAction.length) {
    lines.push(`## Disposition`);
    lines.push("");
    lines.push(
      mdTable(
        ["Action", "Count"],
        model.byAction.map((a) => [cell(a.action), String(a.count)]),
      ),
    );
    lines.push("");
  }

  lines.push(`## Triage / workflow`);
  lines.push("");
  lines.push(
    mdTable(
      ["Status", "Count"],
      model.byTriage.map((t) => [cell(t.status), String(t.count)]),
    ),
  );
  lines.push("");

  lines.push(`## Volume over time`);
  lines.push("");
  lines.push("```");
  lines.push(sparkline(model.timeline, model.timelineMax));
  lines.push(`${fmtTime(model.windowStartMs)}  …  ${fmtTime(model.windowEndMs)}   (peak ${model.timelineMax}/bucket)`);
  lines.push("```");
  lines.push("");

  if (model.notable.length) {
    lines.push(`## Notable detections`);
    lines.push("");
    lines.push(
      mdTable(
        ["#", "When", "Severity", "Signature", "Peer", "Action", "Triage"],
        model.notable.map((d, i) => {
          const arrow = d.direction === "src" ? "→" : d.direction === "dst" ? "←" : "↔";
          return [
            String(i + 1),
            cell(`${fmtTime(d.time)} (${fmtAgo(d.time, model.generatedAt)})`),
            cell(d.severity),
            cell(d.signature),
            cell(d.peer ? `${arrow} ${d.peer}` : "—"),
            cell(d.action),
            cell(d.triageStatus),
          ];
        }),
      ),
    );
    lines.push("");
  }

  lines.push(`## Top signatures`);
  lines.push("");
  lines.push(
    mdTable(
      ["#", "Signature", "Max severity", "Hits"],
      model.topSignatures.map((s, i) => [String(i + 1), cell(s.signature), cell(s.severityMax), String(s.count)]),
    ),
  );
  lines.push("");

  if (model.peers.length) {
    lines.push(`## Peers (counterpart endpoints)`);
    lines.push("");
    lines.push(
      mdTable(
        ["#", "Peer IP", "Scope", "Alerts", "Last seen"],
        model.peers.map((p, i) => [
          String(i + 1),
          cell(p.ip),
          p.internal ? "internal" : "external",
          String(p.count),
          fmtAgo(p.lastSeen, model.generatedAt),
        ]),
      ),
    );
    lines.push("");
  }

  if (model.topCategories.length) {
    lines.push(`## Top categories`);
    lines.push("");
    lines.push(
      mdTable(
        ["#", "Category", "Count"],
        model.topCategories.map((c, i) => [String(i + 1), cell(c.key), String(c.count)]),
      ),
    );
    lines.push("");
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from ${model.total} stored alert(s) involving ${model.ip}. ` +
      `No live gateway query was performed._`,
  );
  lines.push("");

  return lines.join("\n");
}

/**
 * Build a single-entity profile for `ip` from the stored alert history.
 *
 * @param ip    The IPv4/IPv6 address to profile.
 * @param hours Look-back window in hours; 0 / undefined profiles the whole history.
 * @param nowMs Pins the window end for deterministic tests; defaults to now.
 */
export function buildProfile(ip: string, hours = 0, nowMs = Date.now()): ProfileModel {
  const target = (ip ?? "").trim();
  const safeHours = Number.isFinite(hours) && hours > 0 ? Math.min(24 * 90, Math.floor(hours)) : 0;
  const windowEndMs = nowMs;
  const windowStartMs = safeHours > 0 ? windowEndMs - safeHours * 3_600_000 : 0;

  // Invalid IP → an empty, clearly-flagged stub (the web/CLI layer reports this).
  if (isIP(target) === 0) {
    const stub: ProfileModel = {
      ip: target,
      valid: false,
      internal: false,
      hours: safeHours,
      generatedAt: nowMs,
      windowStartMs,
      windowEndMs,
      total: 0,
      asSrc: 0,
      asDst: 0,
      spanMs: 0,
      severityMax: "info",
      bySeverity: SEVERITY_ORDER.map((severity) => ({ severity, count: 0 })),
      byAction: [],
      byTriage: [],
      topSignatures: [],
      topCategories: [],
      topClassifications: [],
      peers: [],
      timeline: [],
      timelineBucketMs: 0,
      timelineMax: 0,
      notable: [],
      state: { blocked: false, watched: false, safe: false },
      riskScore: 0,
      narrative: `"${target}" is not a valid IP address.`,
      highlights: [],
      markdown: "",
    };
    stub.markdown = renderMarkdown(stub);
    return stub;
  }

  const internal = isPrivate(target);
  const since = safeHours > 0 ? windowEndMs - safeHours * 3_600_000 : -Infinity;

  const all: StoredAlert[] = alertStore.all();
  const involved = all.filter(
    (a) =>
      typeof a.time === "number" &&
      a.time <= windowEndMs &&
      a.time >= since &&
      !dismissStore.has(a.id) &&
      (a.srcIp === target || a.dstIp === target),
  );

  const bySev = new Map<Severity, number>();
  const byAct = new Map<string, number>();
  const byTri = new Map<TriageStatus | "open", number>();
  const sigCounts = new Map<string, number>();
  const sigMaxSev = new Map<string, Severity>();
  const catCounts = new Map<string, number>();
  const classCounts = new Map<string, number>();

  interface PeerAccum {
    count: number;
    internal: boolean;
    lastSeen: number;
  }
  const peerMap = new Map<string, PeerAccum>();

  let asSrc = 0;
  let asDst = 0;
  let blockedCount = 0;
  let severityMax: Severity = "info";
  let firstSeen: number | undefined;
  let lastSeen: number | undefined;

  for (const a of involved) {
    const sev = (a.severity as Severity) ?? "info";
    severityMax = maxSeverity(severityMax, sev);
    bump(bySev, sev);
    bump(byAct, normalizeAction(a.action));
    if (normalizeAction(a.action) === "blocked") blockedCount++;
    bump(byTri, triageStore.get(a.id)?.status ?? "open");

    if (a.signature) {
      bump(sigCounts, a.signature);
      sigMaxSev.set(a.signature, maxSeverity(sigMaxSev.get(a.signature) ?? "info", sev));
    }
    bump(catCounts, a.category);
    bump(classCounts, a.classification);

    const isSrc = a.srcIp === target;
    const isDst = a.dstIp === target;
    if (isSrc) asSrc++;
    if (isDst) asDst++;

    // The counterpart endpoint (the "other side" of the alert).
    const peer = isSrc ? a.dstIp : a.srcIp;
    if (peer && peer !== target && isIP(peer) > 0) {
      const acc = peerMap.get(peer) ?? { count: 0, internal: isPrivate(peer), lastSeen: a.time };
      acc.count++;
      if (a.time > acc.lastSeen) acc.lastSeen = a.time;
      peerMap.set(peer, acc);
    }

    if (firstSeen === undefined || a.time < firstSeen) firstSeen = a.time;
    if (lastSeen === undefined || a.time > lastSeen) lastSeen = a.time;
  }

  // Volume timeline. For a bounded window we bin across it; for full history we
  // span first→last seen so the sparkline stays meaningful.
  const tlStart = safeHours > 0 ? windowStartMs : (firstSeen ?? windowEndMs);
  const tlEnd = safeHours > 0 ? windowEndMs : (lastSeen ?? windowEndMs);
  const tlBucketMs = Math.max(60_000, Math.floor(Math.max(1, tlEnd - tlStart) / TIMELINE_BUCKETS));
  const timeline: ProfileTimelineBucket[] = Array.from({ length: TIMELINE_BUCKETS }, (_, i) => ({
    startMs: tlStart + i * tlBucketMs,
    count: 0,
  }));
  for (const a of involved) {
    const idx = Math.min(TIMELINE_BUCKETS - 1, Math.max(0, Math.floor((a.time - tlStart) / tlBucketMs)));
    timeline[idx]!.count++;
  }
  let timelineMax = 0;
  for (const b of timeline) if (b.count > timelineMax) timelineMax = b.count;

  const peers: ProfilePeer[] = [...peerMap.entries()]
    .map(([peerIp, acc]) => ({ ip: peerIp, count: acc.count, internal: acc.internal, lastSeen: acc.lastSeen }))
    .sort((a, b) => b.count - a.count || b.lastSeen - a.lastSeen);

  const topSignatures: ProfileSignature[] = topN(sigCounts, DEFAULT_TOP_N).map((x) => ({
    signature: x.key,
    count: x.count,
    severityMax: sigMaxSev.get(x.key) ?? "info",
  }));

  // Most severe individual detections, worst first then most recent.
  const notable: ProfileNotable[] = involved
    .slice()
    .sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || b.time - a.time)
    .slice(0, NOTABLE_LIMIT)
    .map((a) => {
      const isSrc = a.srcIp === target;
      const isDst = a.dstIp === target;
      const peer = isSrc ? a.dstIp : a.srcIp;
      return {
        id: a.id,
        time: a.time,
        severity: a.severity,
        signature: a.signature || a.category || "—",
        category: a.category,
        peer: peer && peer !== target ? peer : undefined,
        direction: isSrc ? "src" : isDst ? "dst" : "self",
        action: normalizeAction(a.action),
        triageStatus: triageStore.get(a.id)?.status ?? "open",
      };
    });

  const watchEntry = watchStore.match(target);
  const state = {
    blocked: blockStore.has(target),
    watched: watchStore.has(target),
    safe: safeStore.has(target),
    watchNote: watchEntry?.note,
  };

  const riskScore = scoreProfile({
    severityMax,
    total: involved.length,
    peerCount: peers.length,
    signatureCount: sigCounts.size,
    blockedCount,
    watched: state.watched,
    safe: state.safe,
  });

  const TRIAGE: Array<TriageStatus | "open"> = ["open", "investigating", "resolved", "false-positive"];
  const ACTIONS = ["blocked", "detected", "allowed", "unknown"];

  const base: Omit<ProfileModel, "narrative" | "highlights" | "markdown"> = {
    ip: target,
    valid: true,
    internal,
    hours: safeHours,
    generatedAt: nowMs,
    windowStartMs: timeline.length ? timeline[0]!.startMs : windowStartMs,
    windowEndMs: tlEnd,
    total: involved.length,
    asSrc,
    asDst,
    firstSeen,
    lastSeen,
    spanMs: firstSeen !== undefined && lastSeen !== undefined ? lastSeen - firstSeen : 0,
    severityMax,
    bySeverity: SEVERITY_ORDER.map((severity) => ({ severity, count: bySev.get(severity) ?? 0 })),
    byAction: ACTIONS.map((action) => ({ action, count: byAct.get(action) ?? 0 })).filter((x) => x.count > 0),
    byTriage: TRIAGE.map((status) => ({ status, count: byTri.get(status) ?? 0 })),
    topSignatures,
    topCategories: topN(catCounts, DEFAULT_TOP_N),
    topClassifications: topN(classCounts, DEFAULT_TOP_N),
    peers,
    timeline,
    timelineBucketMs: tlBucketMs,
    timelineMax,
    notable,
    state,
    riskScore,
  };

  const { narrative, highlights } = writeNarrative(base);
  const model: ProfileModel = { ...base, narrative, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded profile. */
export function profileFilename(ip: string, nowMs: number): string {
  const safeIp = (ip || "unknown").replace(/[^A-Za-z0-9._-]/g, "_");
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-profile-${safeIp}-${stamp}.md`;
}
