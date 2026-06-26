/**
 * Internal host compromise scoring. Most monitoring watches inbound attackers;
 * this flips the lens to internal devices and flags signs of compromise from the
 * collected NetFlow data:
 *   - bad-outbound: internal host connecting OUT to a feed-listed/bad IP
 *   - beaconing:    regular fixed-interval outbound flows to one external IP (C2)
 *   - fan-out:      talking to an unusually large number of distinct externals
 *
 * Beaconing is detected in two passes to compensate for the UDM's 1:512 flow
 * sampling, which randomly drops beats and would otherwise hide most C2 cadences:
 *   1. strict pass  — near-constant inter-flow gaps (no/low sampling loss); high
 *                     confidence.
 *   2. sampled pass — when sampling thins the cadence, a genuine fixed interval T
 *                     survives as gaps that are integer multiples (1T, 2T, 3T…) of
 *                     a fundamental period. We recover T and verify every gap lands
 *                     on a multiple of it, tolerating the dropped beats; these hits
 *                     are labelled `confidence:"sampled"` and scored lower.
 * bad-outbound remains the highest-confidence signal.
 */
import { isIP } from "node:net";
import { getActiveFlowStore } from "../netflow/flowAccess.ts";
import { feedMatch } from "../intel/feedAccess.ts";
import { safeStore } from "../store/safelist.ts";
import type { Flow } from "../netflow/ipfix.ts";

function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/.test(ip);
}

interface PeerAgg {
  flowsOut: number;
  flowsIn: number;
  bytesOut: number;
  bytesIn: number;
  outStarts: number[];
  feeds: string[];
}

interface HostAgg {
  peers: Map<string, PeerAgg>;
  bytesOut: number;
  bytesIn: number;
}

export interface HostRisk {
  ip: string;
  score: number;
  flows: number;
  bytesOut: number;
  bytesIn: number;
  distinctPeers: number;
  badOutbound: Array<{ ip: string; feeds: string[]; flows: number; bytes: number }>;
  beacons: Array<{ peer: string; intervalSec: number; hits: number; confidence: "high" | "sampled"; missedBeats: number }>;
  topPeers: Array<{ ip: string; bytes: number; flows: number }>;
  reasons: string[];
}

interface BeaconResult {
  intervalSec: number;
  hits: number;
  /** "high" = near-constant cadence; "sampled" = recovered through 1:512 sampling loss. */
  confidence: "high" | "sampled";
  /** Beats inferred to have been dropped by sampling (0 for the strict pass). */
  missedBeats: number;
}

const BEACON_MIN_INTERVAL_MS = 5_000; // sub-5s "regularity" is just a burst, not a beacon
const STRICT_CV = 0.3; // near-constant gaps => unsampled beacon
const MULTIPLE_TOL = 0.15; // a gap counts as k*T only if within 15% of that multiple
const MAX_AVG_MULTIPLE = 12; // beyond this the cadence was thinned past recovery

function detectBeacon(starts: number[]): BeaconResult | null {
  if (starts.length < 4) return null;
  const s = [...starts].sort((a, b) => a - b);
  const gaps: number[] = [];
  for (let i = 1; i < s.length; i++) gaps.push(s[i]! - s[i - 1]!);
  const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
  if (mean < BEACON_MIN_INTERVAL_MS) return null;

  // Strict pass: gaps are already near-constant, so little/no sampling loss.
  const variance = gaps.reduce((a, g) => a + (g - mean) ** 2, 0) / gaps.length;
  const cv = Math.sqrt(variance) / mean;
  if (cv < STRICT_CV) {
    return { intervalSec: Math.round(mean / 1000), hits: s.length, confidence: "high", missedBeats: 0 };
  }

  // Sampled pass: recover a fundamental period the 1:512 sampling thinned out.
  return detectSampledBeacon(s.length, gaps);
}

/**
 * Sampling-aware periodicity check. Under 1:512 sampling a fixed-interval beacon's
 * surviving flows are spaced at integer multiples of the true period T, so the
 * gaps look like {T, 2T, 3T…} rather than a constant. We estimate T from the
 * smallest stable gap (two consecutive beats that both survived) and confirm every
 * gap sits on an integer multiple of it, allowing for the dropped beats in between.
 */
function detectSampledBeacon(hits: number, gaps: number[]): BeaconResult | null {
  // Candidate fundamental period: the smallest gap supported by another similar
  // small gap, so a single anomalously short interval can't drag the estimate down.
  const asc = [...gaps].sort((a, b) => a - b);
  let base = asc[0]!;
  for (let i = 0; i < asc.length - 1; i++) {
    if (Math.abs(asc[i + 1]! - asc[i]!) <= asc[i]! * MULTIPLE_TOL) { base = asc[i]!; break; }
  }
  if (base < BEACON_MIN_INTERVAL_MS) return null;

  let totalBeats = 0;
  let residualSum = 0;
  for (const g of gaps) {
    const k = Math.round(g / base);
    if (k < 1) return null;
    const resid = Math.abs(g - k * base) / base;
    if (resid > MULTIPLE_TOL) return null; // gap doesn't land on a multiple => not periodic
    totalBeats += k;
    residualSum += resid;
  }

  // The multiple structure must actually buy us something over the strict pass: at
  // least one inferred missed beat, a tight overall fit, and not so thinned that the
  // "cadence" is really just noise (honour the marker's best-effort caveat).
  const missedBeats = totalBeats - gaps.length;
  if (missedBeats < 1) return null;
  if (residualSum / gaps.length > MULTIPLE_TOL * 0.6) return null;
  if (totalBeats > gaps.length * MAX_AVG_MULTIPLE) return null;

  return { intervalSec: Math.round(base / 1000), hits, confidence: "sampled", missedBeats };
}

export function computeHostRisks(): HostRisk[] {
  const store = getActiveFlowStore();
  if (!store) return [];
  const flows = store.queryAll([], 1_000_000);

  const hosts = new Map<string, HostAgg>();
  const get = (ip: string) => {
    let h = hosts.get(ip);
    if (!h) { h = { peers: new Map(), bytesOut: 0, bytesIn: 0 }; hosts.set(ip, h); }
    return h;
  };

  for (const f of flows as Flow[]) {
    const src = f.srcIp;
    const dst = f.dstIp;
    if (!src || !dst || isIP(src) === 0 || isIP(dst) === 0) continue;
    const sp = isPrivate(src);
    const dp = isPrivate(dst);
    if (sp === dp) continue; // need exactly one internal + one external
    const internal = sp ? src : dst;
    const external = sp ? dst : src;
    const out = sp; // internal initiated -> outbound
    const bytes = f.bytes ?? 0;

    const h = get(internal);
    let p = h.peers.get(external);
    if (!p) { p = { flowsOut: 0, flowsIn: 0, bytesOut: 0, bytesIn: 0, outStarts: [], feeds: feedMatch(external) }; h.peers.set(external, p); }
    if (out) { p.flowsOut++; p.bytesOut += bytes; p.outStarts.push(f.start ?? f.receivedAt); h.bytesOut += bytes; }
    else { p.flowsIn++; p.bytesIn += bytes; h.bytesIn += bytes; }
  }

  const risks: HostRisk[] = [];
  for (const [ip, h] of hosts) {
    const badOutbound: HostRisk["badOutbound"] = [];
    const beacons: HostRisk["beacons"] = [];
    const topPeers: HostRisk["topPeers"] = [];
    let flows = 0;
    let distinctPeersCount = 0;

    for (const [peer, p] of h.peers) {
      if (safeStore.has(peer)) continue; // operator-vetted benign — ignore in scoring
      distinctPeersCount++;
      flows += p.flowsOut + p.flowsIn;
      topPeers.push({ ip: peer, bytes: p.bytesOut + p.bytesIn, flows: p.flowsOut + p.flowsIn });
      if (p.feeds.length && p.flowsOut > 0) badOutbound.push({ ip: peer, feeds: p.feeds, flows: p.flowsOut, bytes: p.bytesOut });
      const beacon = detectBeacon(p.outStarts);
      if (beacon) beacons.push({ peer, ...beacon });
    }
    topPeers.sort((a, b) => b.bytes - a.bytes);

    const reasons: string[] = [];
    let score = 0;
    if (badOutbound.length) { score += 50 + badOutbound.length * 10; reasons.push(`outbound to ${badOutbound.length} known-bad IP(s)`); }
    const highBeacons = beacons.filter((b) => b.confidence === "high");
    const sampledBeacons = beacons.filter((b) => b.confidence === "sampled");
    if (highBeacons.length) { score += 35 + highBeacons.length * 5; reasons.push(`${highBeacons.length} beaconing pattern(s)`); }
    if (sampledBeacons.length) { score += 20 + sampledBeacons.length * 4; reasons.push(`${sampledBeacons.length} sampling-thinned beaconing pattern(s)`); }
    const distinctPeers = distinctPeersCount;
    if (distinctPeers > 200) { score += 15; reasons.push(`high fan-out (${distinctPeers} externals)`); }
    else if (distinctPeers > 80) { score += 8; reasons.push(`elevated fan-out (${distinctPeers} externals)`); }

    if (score === 0) continue; // only surface hosts with at least one signal
    risks.push({
      ip,
      score: Math.min(100, score),
      flows,
      bytesOut: h.bytesOut,
      bytesIn: h.bytesIn,
      distinctPeers,
      badOutbound: badOutbound.sort((a, b) => b.flows - a.flows).slice(0, 20),
      beacons: beacons
        .sort((a, b) => (a.confidence === b.confidence ? b.hits - a.hits : a.confidence === "high" ? -1 : 1))
        .slice(0, 20),
      topPeers: topPeers.slice(0, 10),
      reasons,
    });
  }

  return risks.sort((a, b) => b.score - a.score);
}
