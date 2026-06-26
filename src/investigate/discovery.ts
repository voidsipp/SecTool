/**
 * Active LAN device auto-discovery.
 *
 * Existing discovery (/api/agents) is *passive* — it only surfaces hosts already
 * seen in collected NetFlow and probes them for the SecTool agent. This module
 * actively enumerates every device on the directly-connected LAN, agent or not:
 *
 *   1. Derive the host's own private IPv4 subnets from its interfaces.
 *   2. TCP-connect "ping" sweep every host in those subnets on a few common
 *      ports (a SYN connect, or a connection-refused, both prove liveness even
 *      when ICMP is firewalled).
 *   3. Read the OS ARP cache (`arp -a`, falling back to `ip neigh`) — the sweep
 *      populates it — to attach MAC addresses, then resolve a vendor from the
 *      MAC's OUI prefix.
 *   4. Best-effort reverse-DNS for a friendly hostname.
 *   5. Merge with NetFlow-seen hosts so devices that are quiet right now (or
 *      block our probe ports) still appear, tagged with when they were last seen.
 *
 * Safety: only RFC1918 / link-local ranges are ever scanned — the sweep can
 * never be pointed at the WAN — and the total candidate count is capped so an
 * accidentally-large netmask (e.g. a /16) can't trigger a runaway scan.
 */
import { Socket, isIP } from "node:net";
import { networkInterfaces } from "node:os";
import { spawn } from "node:child_process";
import { reverse as dnsReverse } from "node:dns/promises";
import type { Config } from "../config.ts";
import { log } from "../logger.ts";
import { getActiveFlowStore } from "../netflow/flowAccess.ts";
import { OUI_VENDORS } from "./oui.ts";

export interface DiscoveredDevice {
  ip: string;
  mac?: string;
  vendor?: string;
  hostname?: string;
  alive: boolean;
  openPorts: number[];
  /** which discovery signals contributed: scan | arp | flow | self */
  sources: string[];
  lastFlow?: number;
  isSelf: boolean;
  /** the SecTool agent port responded on this host */
  hasAgentPort: boolean;
  /**
   * Whether the agent can be auto-pushed to this host (populated by the web layer
   * via assessDeploy in agentPush.ts). Optional so the core sweep stays decoupled
   * from the deployment transport.
   */
  deploy?: { eligible: boolean; method: "ssh" | "manual" | "none"; reason: string };
}

export interface DiscoveryResult {
  ok: boolean;
  error?: string;
  subnets: string[];
  scanned: number;
  truncated: boolean;
  alive: number;
  total: number;
  durationMs: number;
  devices: DiscoveredDevice[];
}

// ---------------------------------------------------------------------------
// Address helpers
// ---------------------------------------------------------------------------

function isPrivateV4(ip: string): boolean {
  return (
    /^10\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^169\.254\./.test(ip)
  );
}

function ipToInt(ip: string): number {
  return ip.split(".").reduce((acc, o) => ((acc << 8) | (Number(o) & 0xff)) >>> 0, 0) >>> 0;
}

function intToIp(n: number): string {
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join(".");
}

/** CIDR prefix length from a dotted netmask (e.g. 255.255.255.0 -> 24). */
function maskToPrefix(mask: string): number {
  const n = ipToInt(mask);
  let count = 0;
  for (let b = 31; b >= 0; b--) {
    if ((n >>> b) & 1) count++;
    else break;
  }
  return count;
}

function normalizeMac(mac: string): string {
  return mac.replace(/-/g, ":").toLowerCase();
}

function vendorForMac(mac: string): string | undefined {
  const oui = mac.replace(/[:-]/g, "").slice(0, 6).toUpperCase();
  return OUI_VENDORS[oui];
}

/** Local non-internal IPv4 interface addresses (the SecTool host's own IPs). */
export function localIpv4(): Array<{ ip: string; prefix: number }> {
  const out: Array<{ ip: string; prefix: number }> = [];
  const ifaces = networkInterfaces();
  for (const list of Object.values(ifaces)) {
    for (const ni of list ?? []) {
      // node >=18 reports family as the string "IPv4"; older as number 4
      const isV4 = ni.family === "IPv4" || (ni.family as unknown) === 4;
      if (!isV4 || ni.internal) continue;
      const prefix = ni.netmask ? maskToPrefix(ni.netmask) : 24;
      out.push({ ip: ni.address, prefix });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Subnet planning
// ---------------------------------------------------------------------------

interface Subnet {
  cidr: string;
  hosts: string[];
}

/**
 * Expand a base address + prefix into its usable host addresses, skipping the
 * network and broadcast addresses. Refuses anything but private IPv4. Never
 * materializes more than `cap` addresses, so a wide override CIDR (e.g. /8)
 * can't allocate a multi-million-entry array — it's truncated up front.
 */
function expandSubnet(anchorIp: string, prefix: number, cap: number): { sn: Subnet; truncated: boolean } | null {
  if (isIP(anchorIp) !== 4 || !isPrivateV4(anchorIp)) return null;
  const p = Math.min(Math.max(prefix, 0), 32);
  const mask = p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0;
  const net = (ipToInt(anchorIp) & mask) >>> 0;
  const bcast = (net | (~mask >>> 0)) >>> 0;
  const hosts: string[] = [];
  let truncated = false;
  // /31 and /32 have no "usable range" in the classic sense; just scan the anchor.
  if (bcast - net <= 1) {
    hosts.push(anchorIp);
  } else {
    for (let h = net + 1; h < bcast; h++) {
      if (hosts.length >= cap) {
        truncated = true;
        break;
      }
      hosts.push(intToIp(h >>> 0));
    }
  }
  return { sn: { cidr: `${intToIp(net)}/${p}`, hosts }, truncated };
}

/**
 * Decide which subnets to sweep. An explicit override (config / query) wins;
 * otherwise auto-detect from local interfaces. Each subnet is clamped to at
 * least a /24 so a wide netmask doesn't explode into tens of thousands of hosts,
 * and the combined candidate list is capped at cfg.discovery.maxHosts.
 */
function planSubnets(cfg: Config, override?: string[]): { subnets: Subnet[]; truncated: boolean } {
  const sources: Array<{ ip: string; prefix: number }> = [];
  if (override && override.length) {
    for (const raw of override) {
      const m = /^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/.exec(raw.trim());
      if (!m) continue;
      sources.push({ ip: m[1]!, prefix: m[2] ? Number(m[2]) : 24 });
    }
  } else {
    for (const li of localIpv4()) {
      if (!isPrivateV4(li.ip)) continue;
      // Clamp very wide nets to a /24 around this host to keep the sweep bounded.
      sources.push({ ip: li.ip, prefix: Math.max(li.prefix, 24) });
    }
  }

  const seen = new Set<string>();
  const subnets: Subnet[] = [];
  let truncated = false;
  let budget = Math.max(1, cfg.discovery.maxHosts);

  for (const src of sources) {
    if (budget <= 0) {
      truncated = true;
      break;
    }
    const r = expandSubnet(src.ip, src.prefix, budget);
    if (!r) continue;
    if (r.truncated) truncated = true;
    const sn = r.sn;
    if (seen.has(sn.cidr)) continue;
    seen.add(sn.cidr);
    budget -= sn.hosts.length;
    subnets.push(sn);
  }
  return { subnets, truncated };
}

// ---------------------------------------------------------------------------
// TCP liveness sweep
// ---------------------------------------------------------------------------

type ProbeResult = "open" | "alive" | "down";

function tcpProbe(ip: string, port: number, timeoutMs: number): Promise<ProbeResult> {
  return new Promise((resolve) => {
    const sock = new Socket();
    let settled = false;
    const finish = (r: ProbeResult) => {
      if (settled) return;
      settled = true;
      sock.removeAllListeners();
      sock.destroy();
      resolve(r);
    };
    sock.setTimeout(timeoutMs);
    sock.once("connect", () => finish("open"));
    sock.once("timeout", () => finish("down"));
    sock.once("error", (err: NodeJS.ErrnoException) => {
      // A refused/reset connection still proves the host is up (port just closed).
      finish(err.code === "ECONNREFUSED" || err.code === "ECONNRESET" ? "alive" : "down");
    });
    sock.connect(port, ip);
  });
}

interface ScanHit {
  ip: string;
  openPorts: number[];
  alive: boolean;
}

async function scanHost(ip: string, ports: number[], timeoutMs: number): Promise<ScanHit> {
  const results = await Promise.all(ports.map((p) => tcpProbe(ip, p, timeoutMs)));
  const openPorts: number[] = [];
  let alive = false;
  results.forEach((r, i) => {
    if (r === "open") {
      openPorts.push(ports[i]!);
      alive = true;
    } else if (r === "alive") {
      alive = true;
    }
  });
  return { ip, openPorts: openPorts.sort((a, b) => a - b), alive };
}

/** Run `fn` over `items` with at most `limit` in flight at once. */
async function pool<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let idx = 0;
  const n = Math.max(1, Math.min(limit, items.length));
  const worker = async (): Promise<void> => {
    while (idx < items.length) {
      const cur = idx++;
      out[cur] = await fn(items[cur]!);
    }
  };
  await Promise.all(Array.from({ length: n }, worker));
  return out;
}

// ---------------------------------------------------------------------------
// ARP table
// ---------------------------------------------------------------------------

const MAC_RE = /([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})/;
const IPV4_RE = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;

function parseArp(text: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const line of text.split(/\r?\n/)) {
    const ip = IPV4_RE.exec(line)?.[1];
    const mac = MAC_RE.exec(line)?.[1];
    if (!ip || !mac || isIP(ip) !== 4) continue;
    const norm = normalizeMac(mac);
    // Skip the broadcast / null MACs ARP sometimes lists for special addresses.
    if (norm === "ff:ff:ff:ff:ff:ff" || norm === "00:00:00:00:00:00") continue;
    map.set(ip, norm);
  }
  return map;
}

function runCmd(cmd: string, args: string[], timeoutMs: number): Promise<string> {
  return new Promise((resolve) => {
    let out = "";
    const child = spawn(cmd, args, { stdio: ["ignore", "pipe", "ignore"] });
    child.stdout?.setEncoding("utf8");
    child.stdout?.on("data", (d: string) => (out += d));
    const timer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        /* ignore */
      }
      resolve(out);
    }, timeoutMs);
    child.on("error", () => {
      clearTimeout(timer);
      resolve("");
    });
    child.on("close", () => {
      clearTimeout(timer);
      resolve(out);
    });
  });
}

/** Read the OS neighbor/ARP cache. `arp -a` is cross-platform; fall back to `ip neigh`. */
async function readArpTable(timeoutMs = 4000): Promise<Map<string, string>> {
  let text = await runCmd("arp", ["-a"], timeoutMs);
  let map = parseArp(text);
  if (map.size === 0) {
    text = await runCmd("ip", ["neigh"], timeoutMs);
    map = parseArp(text);
  }
  return map;
}

// ---------------------------------------------------------------------------
// Reverse DNS (best-effort, bounded)
// ---------------------------------------------------------------------------

async function reverseDns(ip: string, timeoutMs: number): Promise<string | undefined> {
  try {
    const names = await Promise.race([
      dnsReverse(ip),
      new Promise<string[]>((_, rej) => setTimeout(() => rej(new Error("timeout")), timeoutMs)),
    ]);
    return names && names.length ? names[0] : undefined;
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

export async function discoverDevices(
  cfg: Config,
  opts: { subnets?: string[] } = {},
): Promise<DiscoveryResult> {
  const startedAt = Date.now();
  if (!cfg.discovery.enabled) {
    return {
      ok: false,
      error: "LAN discovery is disabled. Set DISCOVERY_ENABLED=true and restart SecTool.",
      subnets: [],
      scanned: 0,
      truncated: false,
      alive: 0,
      total: 0,
      durationMs: 0,
      devices: [],
    };
  }

  const { subnets, truncated } = planSubnets(cfg, opts.subnets);
  if (!subnets.length) {
    return {
      ok: false,
      error: "No private IPv4 subnet detected on this host (and no DISCOVERY_SUBNETS override set).",
      subnets: [],
      scanned: 0,
      truncated: false,
      alive: 0,
      total: 0,
      durationMs: Date.now() - startedAt,
      devices: [],
    };
  }

  const selfIps = new Set(localIpv4().map((l) => l.ip));
  const candidates = subnets.flatMap((s) => s.hosts);
  log.info(`LAN discovery sweeping ${candidates.length} hosts across ${subnets.map((s) => s.cidr).join(", ")}`);

  // 1) Active TCP sweep (also primes the ARP cache).
  const hits = await pool(candidates, cfg.discovery.concurrency, (ip) =>
    scanHost(ip, cfg.discovery.ports, cfg.discovery.timeoutMs),
  );

  // 2) Build the merged device map, seeded from live scan hits.
  const devices = new Map<string, DiscoveredDevice>();
  const ensure = (ip: string): DiscoveredDevice => {
    let d = devices.get(ip);
    if (!d) {
      d = { ip, alive: false, openPorts: [], sources: [], isSelf: selfIps.has(ip), hasAgentPort: false };
      if (d.isSelf) d.sources.push("self");
      devices.set(ip, d);
    }
    return d;
  };

  for (const hit of hits) {
    if (!hit.alive && !selfIps.has(hit.ip)) continue;
    const d = ensure(hit.ip);
    if (hit.alive) {
      d.alive = true;
      if (!d.sources.includes("scan")) d.sources.push("scan");
    }
    d.openPorts = hit.openPorts;
    if (hit.openPorts.includes(cfg.agent.port)) d.hasAgentPort = true;
  }

  // 3) ARP cache -> MAC + vendor (covers hosts that ignored every probe port).
  const arp = await readArpTable();
  for (const [ip, mac] of arp) {
    if (!isPrivateV4(ip)) continue;
    const d = ensure(ip);
    d.mac = mac;
    d.vendor = vendorForMac(mac);
    // Presence in the neighbor cache after the sweep is itself a liveness signal.
    d.alive = true;
    if (!d.sources.includes("arp")) d.sources.push("arp");
  }

  // 4) NetFlow-seen private hosts (quiet now / firewalled, but real devices).
  const store = getActiveFlowStore();
  if (store) {
    const now = Date.now();
    const since = now - 24 * 3_600_000;
    const flowLast = new Map<string, number>();
    for (const f of store.query([], since, now, 200_000)) {
      const end = f.end ?? f.receivedAt;
      for (const ip of [f.srcIp, f.dstIp]) {
        if (ip && isIP(ip) === 4 && isPrivateV4(ip)) {
          const prev = flowLast.get(ip) ?? 0;
          if (end > prev) flowLast.set(ip, end);
        }
      }
    }
    for (const [ip, last] of flowLast) {
      const d = ensure(ip);
      d.lastFlow = last;
      if (!d.sources.includes("flow")) d.sources.push("flow");
    }
  }

  // 5) Best-effort reverse-DNS for everything we found (bounded concurrency).
  const list = [...devices.values()];
  await pool(list, Math.min(32, cfg.discovery.concurrency), async (d) => {
    d.hostname = await reverseDns(d.ip, 1200);
  });

  list.sort((a, b) => ipToInt(a.ip) - ipToInt(b.ip));

  return {
    ok: true,
    subnets: subnets.map((s) => s.cidr),
    scanned: candidates.length,
    truncated,
    alive: list.filter((d) => d.alive).length,
    total: list.length,
    durationMs: Date.now() - startedAt,
    devices: list,
  };
}
