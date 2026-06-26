/**
 * Clusters the stored alert history into "attack campaigns" — groups of alerts
 * that share the same external (attacker) IP — so an operator can see the full
 * footprint of a single adversary at a glance instead of reading dozens of
 * individual alerts.
 *
 * For each external IP it rolls up: how many alerts it generated, the worst
 * severity, the distinct signatures/categories it tripped, every internal host
 * it touched, its active time span, and a composite threat score. Each campaign
 * is also annotated with whether the IP is already blocked / watched / marked
 * safe so the UI can offer the right one-click action.
 *
 * Pure in-memory math over alertStore (same source as the Trends report); needs
 * no SSH and is safe to call from the dashboard at any time. Geo enrichment is
 * optional and layered on by the caller (see the web server).
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { dismissStore } from "../store/dismissed.ts";
import { triageStore } from "../store/triage.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

export interface CampaignSignature {
  signature: string;
  count: number;
  severityMax: Severity;
}

export interface CampaignTarget {
  ip: string;
  count: number;
}

export interface Campaign {
  /** The external (attacker) IP that ties the alerts together. */
  ip: string;
  /** Total alerts attributed to this IP in the window. */
  alertCount: number;
  /** Highest severity seen across the campaign. */
  severityMax: Severity;
  /** Per-severity counts, ordered info → critical (zeros omitted). */
  bySeverity: Array<{ severity: Severity; count: number }>;
  /** Distinct signatures, most-seen first. */
  signatures: CampaignSignature[];
  /** Distinct Suricata categories tripped. */
  categories: string[];
  /** Internal hosts this IP interacted with, most-targeted first. */
  targets: CampaignTarget[];
  /** Earliest / latest alert times (ms epoch) and the span between them. */
  firstSeen: number;
  lastSeen: number;
  spanMs: number;
  /** How many of the alerts the gateway actually blocked. */
  blockedCount: number;
  /** Open-status alerts still needing triage. */
  openCount: number;
  /** Composite 0-100 threat score (see scoreCampaign). */
  threatScore: number;
  /** Current operator state for this IP. */
  blocked: boolean;
  watched: boolean;
  safe: boolean;
  /** Most-recent alert ids in this campaign (for drill-in), newest first. */
  sampleAlertIds: string[];
}

export interface CampaignsReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Number of distinct attacker IPs (campaigns) found. */
  campaignCount: number;
  /** Alerts that contributed to a campaign (had an external IP). */
  clusteredAlerts: number;
  /** In-window alerts with no external IP (internal-only) — not clustered. */
  internalOnlyAlerts: number;
  campaigns: Campaign[];
}

const SAMPLE_IDS = 8;

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

/** The external (routable) IP of an alert, preferring src; null if both sides are private. */
function externalIp(a: StoredAlert): string | null {
  for (const ip of [a.srcIp, a.dstIp]) {
    if (ip && isIP(ip) > 0 && !isPrivate(ip)) return ip;
  }
  return null;
}

/** The internal counterpart host of an alert (the victim), if any. */
function internalIp(a: StoredAlert, attacker: string): string | null {
  for (const ip of [a.srcIp, a.dstIp]) {
    if (ip && ip !== attacker && isIP(ip) > 0 && isPrivate(ip)) return ip;
  }
  return null;
}

function sevRank(s: string): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s);
  return i < 0 ? 0 : i;
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? (b as Severity) : a;
}

/**
 * Composite 0-100 threat score. Rewards severity, breadth (distinct signatures
 * and internal targets), and raw volume; gives a small bump to short, intense
 * bursts (many alerts in a short span = active attack vs. slow background noise).
 */
function scoreCampaign(c: {
  severityMax: Severity;
  alertCount: number;
  signatureCount: number;
  targetCount: number;
  spanMs: number;
  blockedCount: number;
}): number {
  const sev = sevRank(c.severityMax); // 0..4
  let score = sev * 14; // up to 56 from severity alone
  score += Math.min(20, Math.log2(c.alertCount + 1) * 6); // volume, diminishing
  score += Math.min(12, (c.signatureCount - 1) * 4); // signature diversity
  score += Math.min(12, (c.targetCount - 1) * 4); // fan-out across hosts
  // Burst bonus: >=5 alerts inside 10 minutes reads as an active attack.
  if (c.alertCount >= 5 && c.spanMs > 0 && c.spanMs <= 10 * 60_000) score += 8;
  // The gateway already stopped these — modestly lower urgency.
  if (c.blockedCount === c.alertCount && c.alertCount > 0) score -= 6;
  return Math.max(0, Math.min(100, Math.round(score)));
}

/**
 * Build the campaigns report from the alert store. `nowMs` pins the window end
 * (useful for tests); defaults to Date.now(). `limit` caps how many campaigns
 * are returned (the highest-scoring ones).
 */
export function buildCampaigns(hours: number, limit = 50, nowMs = Date.now()): CampaignsReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const windowEndMs = nowMs;
  const windowStartMs = windowEndMs - safeHours * 3_600_000;
  const safeLimit = Math.max(1, Math.min(200, Math.floor(limit)));

  const all: StoredAlert[] = alertStore.all();
  const inWindow = all.filter(
    (a) => typeof a.time === "number" && a.time >= windowStartMs && a.time <= windowEndMs && !dismissStore.has(a.id),
  );

  interface Agg {
    ip: string;
    alertCount: number;
    severityMax: Severity;
    bySev: Map<Severity, number>;
    sigCounts: Map<string, number>;
    sigMaxSev: Map<string, Severity>;
    categories: Set<string>;
    targets: Map<string, number>;
    firstSeen: number;
    lastSeen: number;
    blockedCount: number;
    openCount: number;
    samples: Array<{ id: string; time: number }>;
  }

  const byIp = new Map<string, Agg>();
  let clusteredAlerts = 0;
  let internalOnlyAlerts = 0;

  for (const a of inWindow) {
    const ip = externalIp(a);
    if (!ip) {
      internalOnlyAlerts++;
      continue;
    }
    clusteredAlerts++;
    let agg = byIp.get(ip);
    if (!agg) {
      agg = {
        ip,
        alertCount: 0,
        severityMax: "info",
        bySev: new Map(),
        sigCounts: new Map(),
        sigMaxSev: new Map(),
        categories: new Set(),
        targets: new Map(),
        firstSeen: a.time,
        lastSeen: a.time,
        blockedCount: 0,
        openCount: 0,
        samples: [],
      };
      byIp.set(ip, agg);
    }
    const sev = (a.severity as Severity) ?? "info";
    agg.alertCount++;
    agg.severityMax = maxSeverity(agg.severityMax, sev);
    agg.bySev.set(sev, (agg.bySev.get(sev) ?? 0) + 1);
    if (a.signature) {
      agg.sigCounts.set(a.signature, (agg.sigCounts.get(a.signature) ?? 0) + 1);
      agg.sigMaxSev.set(a.signature, maxSeverity(agg.sigMaxSev.get(a.signature) ?? "info", sev));
    }
    if (a.category) agg.categories.add(a.category);
    const target = internalIp(a, ip);
    if (target) agg.targets.set(target, (agg.targets.get(target) ?? 0) + 1);
    if (a.time < agg.firstSeen) agg.firstSeen = a.time;
    if (a.time > agg.lastSeen) agg.lastSeen = a.time;
    if ((a.action ?? "").toLowerCase() === "blocked") agg.blockedCount++;
    if ((triageStore.get(a.id)?.status ?? "open") === "open") agg.openCount++;
    agg.samples.push({ id: a.id, time: a.time });
  }

  const campaigns: Campaign[] = [...byIp.values()].map((agg) => {
    const signatures = [...agg.sigCounts.entries()]
      .map(([signature, count]) => ({ signature, count, severityMax: agg.sigMaxSev.get(signature) ?? "info" }))
      .sort((x, y) => y.count - x.count || x.signature.localeCompare(y.signature));
    const targets = [...agg.targets.entries()]
      .map(([ip, count]) => ({ ip, count }))
      .sort((x, y) => y.count - x.count || x.ip.localeCompare(y.ip));
    const bySeverity = SEVERITY_ORDER.map((severity) => ({ severity, count: agg.bySev.get(severity) ?? 0 })).filter(
      (x) => x.count > 0,
    );
    const spanMs = agg.lastSeen - agg.firstSeen;
    const sampleAlertIds = agg.samples
      .sort((x, y) => y.time - x.time)
      .slice(0, SAMPLE_IDS)
      .map((s) => s.id);
    const threatScore = scoreCampaign({
      severityMax: agg.severityMax,
      alertCount: agg.alertCount,
      signatureCount: agg.sigCounts.size,
      targetCount: agg.targets.size,
      spanMs,
      blockedCount: agg.blockedCount,
    });
    return {
      ip: agg.ip,
      alertCount: agg.alertCount,
      severityMax: agg.severityMax,
      bySeverity,
      signatures,
      categories: [...agg.categories].sort(),
      targets,
      firstSeen: agg.firstSeen,
      lastSeen: agg.lastSeen,
      spanMs,
      blockedCount: agg.blockedCount,
      openCount: agg.openCount,
      threatScore,
      blocked: blockStore.has(agg.ip),
      watched: watchStore.has(agg.ip),
      safe: safeStore.has(agg.ip),
      sampleAlertIds,
    };
  });

  campaigns.sort(
    (a, b) => b.threatScore - a.threatScore || b.alertCount - a.alertCount || b.lastSeen - a.lastSeen,
  );

  return {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    campaignCount: campaigns.length,
    clusteredAlerts,
    internalOnlyAlerts,
    campaigns: campaigns.slice(0, safeLimit),
  };
}
