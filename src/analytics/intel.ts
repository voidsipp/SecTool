/**
 * Threat-intel exposure report: cross-references the locally stored alert
 * history and recently collected NetFlow against the loaded blocklist feeds to
 * answer the question feeds alone can't — "which known-bad IPs are actually
 * touching my network right now?".
 *
 * Pure in-memory math against the alert store, the active flow store and the
 * in-process feed matcher. Needs no SSH and is safe to call from the dashboard
 * at any time. When no feeds are loaded yet it returns an empty (but valid)
 * report with `status.loaded === false`.
 */
import { isIP } from "node:net";
import { alertStore } from "../store/alertStore.ts";
import { feedMatch, feedsLoaded } from "../intel/feedAccess.ts";
import { feedStatus, type FeedStatus } from "../intel/feeds.ts";
import { getActiveFlowStore } from "../netflow/flowAccess.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Direction of the contact relative to the LAN (the matched IP is external). */
export type IntelDirection = "inbound" | "outbound" | "both" | "unknown";

export interface IntelMatch {
  /** The flagged external IP. */
  ip: string;
  /** Feed names listing this IP. */
  feeds: string[];
  /** Stored alerts in the window that involve this IP. */
  alertHits: number;
  /** NetFlow records in the window that involve this IP. */
  flowHits: number;
  /** Bytes exchanged with this IP across matched flows. */
  bytes: number;
  /** Distinct internal hosts that talked to this IP. */
  internalPeers: number;
  /** Most-recent activity (alert or flow) ms epoch. */
  lastSeen: number | null;
  /** Worst severity across matched alerts, or null if seen only in flows. */
  severityMax: Severity | null;
  /** A representative alert id, for deep-linking. */
  lastAlertId?: string;
  /** A representative signature/category, for context. */
  sample?: string;
  /** Contact direction relative to the LAN. */
  direction: IntelDirection;
}

export interface IntelReport {
  status: FeedStatus;
  /** Window the report covers, in hours. */
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Stored alerts examined. */
  alertsScanned: number;
  /** Flow records examined. */
  flowsScanned: number;
  /** Distinct flagged IPs found touching the network. */
  matchedIps: number;
  /** Sum of alert hits across all matches. */
  totalAlertHits: number;
  /** Sum of flow hits across all matches. */
  totalFlowHits: number;
  /** Matches ranked by severity, then activity volume. */
  matches: IntelMatch[];
}

const FLOW_QUERY_LIMIT = 200_000;
const MAX_MATCHES = 200;

function isPrivate(ip: string): boolean {
  return (
    /^10\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^127\./.test(ip) ||
    /^169\.254\./.test(ip) ||
    /^(::1|fe80|fc|fd)/i.test(ip)
  );
}

function sevRank(s: string | null | undefined): number {
  if (!s) return -1;
  return (SEVERITY_ORDER as readonly string[]).indexOf(s);
}

/** Accumulator mirroring IntelMatch while we fold over alerts + flows. */
interface Acc {
  ip: string;
  feeds: Set<string>;
  alertHits: number;
  flowHits: number;
  bytes: number;
  internalPeers: Set<string>;
  lastSeen: number | null;
  severityMax: Severity | null;
  lastAlertId?: string;
  lastAlertTime: number;
  sample?: string;
  sawInbound: boolean;
  sawOutbound: boolean;
}

function getAcc(map: Map<string, Acc>, ip: string, feeds: string[]): Acc {
  let a = map.get(ip);
  if (!a) {
    a = {
      ip,
      feeds: new Set(),
      alertHits: 0,
      flowHits: 0,
      bytes: 0,
      internalPeers: new Set(),
      lastSeen: null,
      severityMax: null,
      lastAlertTime: 0,
      sawInbound: false,
      sawOutbound: false,
    };
    map.set(ip, a);
  }
  for (const f of feeds) a.feeds.add(f);
  return a;
}

function bumpLastSeen(a: Acc, t: number): void {
  if (a.lastSeen === null || t > a.lastSeen) a.lastSeen = t;
}

function direction(a: Acc): IntelDirection {
  if (a.sawInbound && a.sawOutbound) return "both";
  if (a.sawInbound) return "inbound";
  if (a.sawOutbound) return "outbound";
  return "unknown";
}

/**
 * Build the exposure report. `nowMs` lets callers pin the window end (useful
 * for tests); defaults to Date.now().
 */
export function buildIntelReport(hours: number, nowMs = Date.now()): IntelReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const windowEndMs = nowMs;
  const windowStartMs = windowEndMs - safeHours * 3_600_000;
  const status = feedStatus();

  // Short-circuit cleanly when the matcher isn't primed — cross-referencing
  // against an empty matcher would just yield zero matches anyway.
  if (!feedsLoaded()) {
    return {
      status,
      hours: safeHours,
      windowStartMs,
      windowEndMs,
      alertsScanned: 0,
      flowsScanned: 0,
      matchedIps: 0,
      totalAlertHits: 0,
      totalFlowHits: 0,
      matches: [],
    };
  }

  const map = new Map<string, Acc>();

  // --- alerts -------------------------------------------------------------
  const alerts = alertStore.all().filter((a) => typeof a.time === "number" && a.time >= windowStartMs && a.time <= windowEndMs);
  for (const al of alerts) {
    // srcIp is the remote attacker (inbound); dstIp the remote callee (outbound).
    for (const [ip, inbound] of [
      [al.srcIp, true],
      [al.dstIp, false],
    ] as Array<[string | undefined, boolean]>) {
      if (!ip || isIP(ip) === 0 || isPrivate(ip)) continue;
      const feeds = feedMatch(ip);
      if (!feeds.length) continue;
      const acc = getAcc(map, ip, feeds);
      acc.alertHits++;
      bumpLastSeen(acc, al.time);
      if (inbound) {
        acc.sawInbound = true;
        if (al.dstIp && isPrivate(al.dstIp)) acc.internalPeers.add(al.dstIp);
      } else {
        acc.sawOutbound = true;
        if (al.srcIp && isPrivate(al.srcIp)) acc.internalPeers.add(al.srcIp);
      }
      if (sevRank(al.severity) > sevRank(acc.severityMax)) acc.severityMax = al.severity as Severity;
      if (al.time >= acc.lastAlertTime) {
        acc.lastAlertTime = al.time;
        acc.lastAlertId = al.id;
        acc.sample = al.signature ?? al.category ?? acc.sample;
      }
    }
  }

  // --- flows --------------------------------------------------------------
  let flowsScanned = 0;
  const flowStore = getActiveFlowStore();
  if (flowStore) {
    const flows = flowStore.query([], windowStartMs, windowEndMs, FLOW_QUERY_LIMIT);
    flowsScanned = flows.length;
    for (const f of flows) {
      const src = f.srcIp;
      const dst = f.dstIp;
      const when = f.end ?? f.receivedAt;
      // dst external => internal host reached out (outbound).
      if (dst && isIP(dst) > 0 && !isPrivate(dst)) {
        const feeds = feedMatch(dst);
        if (feeds.length) {
          const acc = getAcc(map, dst, feeds);
          acc.flowHits++;
          acc.bytes += f.bytes ?? 0;
          acc.sawOutbound = true;
          bumpLastSeen(acc, when);
          if (src && isPrivate(src)) acc.internalPeers.add(src);
          if (!acc.sample) acc.sample = "outbound flow";
        }
      }
      // src external => remote reached in (inbound).
      if (src && isIP(src) > 0 && !isPrivate(src)) {
        const feeds = feedMatch(src);
        if (feeds.length) {
          const acc = getAcc(map, src, feeds);
          acc.flowHits++;
          acc.bytes += f.bytes ?? 0;
          acc.sawInbound = true;
          bumpLastSeen(acc, when);
          if (dst && isPrivate(dst)) acc.internalPeers.add(dst);
          if (!acc.sample) acc.sample = "inbound flow";
        }
      }
    }
  }

  const matches: IntelMatch[] = [...map.values()].map((a) => ({
    ip: a.ip,
    feeds: [...a.feeds].sort(),
    alertHits: a.alertHits,
    flowHits: a.flowHits,
    bytes: a.bytes,
    internalPeers: a.internalPeers.size,
    lastSeen: a.lastSeen,
    severityMax: a.severityMax,
    lastAlertId: a.lastAlertId,
    sample: a.sample,
    direction: direction(a),
  }));

  // Rank: confirmed alerts first (by severity), then by total activity, then recency.
  matches.sort((x, y) => {
    const sev = sevRank(y.severityMax) - sevRank(x.severityMax);
    if (sev !== 0) return sev;
    const act = y.alertHits + y.flowHits - (x.alertHits + x.flowHits);
    if (act !== 0) return act;
    return (y.lastSeen ?? 0) - (x.lastSeen ?? 0);
  });

  const totalAlertHits = matches.reduce((s, m) => s + m.alertHits, 0);
  const totalFlowHits = matches.reduce((s, m) => s + m.flowHits, 0);

  return {
    status,
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    alertsScanned: alerts.length,
    flowsScanned,
    matchedIps: matches.length,
    totalAlertHits,
    totalFlowHits,
    matches: matches.slice(0, MAX_MATCHES),
  };
}

/** A single arbitrary-IP lookup against the loaded feeds. */
export interface IntelCheck {
  ip: string;
  listed: boolean;
  feeds: string[];
  loaded: boolean;
}

export function checkIntelIp(ip: string): IntelCheck {
  const loaded = feedsLoaded();
  const feeds = loaded ? feedMatch(ip) : [];
  return { ip, listed: feeds.length > 0, feeds, loaded };
}
