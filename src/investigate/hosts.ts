/**
 * Internal host compromise scoring. Most monitoring watches inbound attackers;
 * this flips the lens to internal devices and flags signs of compromise from the
 * collected NetFlow data:
 *   - bad-outbound: internal host connecting OUT to a feed-listed/bad IP
 *   - beaconing:    regular fixed-interval outbound flows to one external IP (C2)
 *   - fan-out:      talking to an unusually large number of distinct externals
 *
 * Note: the UDM samples flows 1:512, so beaconing is best-effort (sampling thins
 * the cadence); bad-outbound is the highest-confidence signal.
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
  beacons: Array<{ peer: string; intervalSec: number; hits: number }>;
  topPeers: Array<{ ip: string; bytes: number; flows: number }>;
  reasons: string[];
}

function detectBeacon(starts: number[]): { intervalSec: number; hits: number } | null {
  if (starts.length < 4) return null;
  const s = [...starts].sort((a, b) => a - b);
  const gaps: number[] = [];
  for (let i = 1; i < s.length; i++) gaps.push(s[i]! - s[i - 1]!);
  const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
  if (mean < 5000) return null; // sub-5s "regularity" is just a burst, not a beacon
  const variance = gaps.reduce((a, g) => a + (g - mean) ** 2, 0) / gaps.length;
  const cv = Math.sqrt(variance) / mean;
  return cv < 0.3 ? { intervalSec: Math.round(mean / 1000), hits: s.length } : null;
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
    if (beacons.length) { score += 35 + beacons.length * 5; reasons.push(`${beacons.length} beaconing pattern(s)`); }
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
      beacons: beacons.slice(0, 20),
      topPeers: topPeers.slice(0, 10),
      reasons,
    });
  }

  return risks.sort((a, b) => b.score - a.score);
}
