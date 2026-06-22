/**
 * Threat-intel feed integration: fetches public IP blocklists, loads them into a
 * dedicated SECTOOL_FEED ipset on the UDM (proactive drop), cross-references
 * alerts/flows against them, and tracks per-feed deltas for a daily changelog.
 */
import { isIP } from "node:net";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import type { Config } from "../config.ts";
import { sshExec, sshExecInput, loadSshTarget } from "../ingest/sshPull.ts";
import { setFeedMatcher } from "./feedAccess.ts";
import { log } from "../logger.ts";

const DATA_DIR = fileURLToPath(new URL("../../data", import.meta.url));
const STATE_PATH = join(DATA_DIR, "feeds-state.json");
const SET = "SECTOOL_FEED";

export interface FeedDef {
  name: string;
  url: string;
}

// Keyless public feeds. hash:net handles both bare IPs and CIDRs.
export const DEFAULT_FEEDS: FeedDef[] = [
  { name: "abuse.ch Feodo C2", url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" },
  { name: "ET compromised", url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt" },
  { name: "CINS Army", url: "https://cinsscore.com/list/ci-badguys.txt" },
  { name: "blocklist.de", url: "https://lists.blocklist.de/lists/all.txt" },
  { name: "FireHOL level1", url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset" },
  { name: "Spamhaus DROP", url: "https://www.spamhaus.org/drop/drop.txt" },
];

const IP_OR_CIDR = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\/(\d{1,2}))?$/;

function ip4ToInt(ip: string): number {
  return ip.split(".").reduce((a, o) => ((a << 8) >>> 0) + Number(o), 0) >>> 0;
}

// Ranges that must NEVER end up in a firewall DROP set — they cover your own LAN,
// loopback, CGNAT, link-local, multicast/reserved. A feed entry is rejected if it
// falls inside, OR (for a CIDR) contains, any of these. (FireHOL level1 ships the
// full bogon list, e.g. 192.168.0.0/16 — which previously blackholed the LAN.)
const RESERVED: Array<[number, number]> = [
  [ip4ToInt("0.0.0.0"), 8],
  [ip4ToInt("10.0.0.0"), 8],
  [ip4ToInt("100.64.0.0"), 10],
  [ip4ToInt("127.0.0.0"), 8],
  [ip4ToInt("169.254.0.0"), 16],
  [ip4ToInt("172.16.0.0"), 12],
  [ip4ToInt("192.168.0.0"), 16],
  [ip4ToInt("192.0.0.0"), 24],
  [ip4ToInt("224.0.0.0"), 3], // multicast + reserved 224.0.0.0–255.255.255.255
];

function maskOf(bits: number): number {
  return bits <= 0 ? 0 : bits >= 32 ? 0xffffffff : (~((1 << (32 - bits)) - 1)) >>> 0;
}

/** Safe to put in a DROP set? Rejects reserved/private/bogon and over-broad CIDRs. */
export function isSafeBlockEntry(ip: string, bits: number): boolean {
  if (isIP(ip) !== 4) return false;
  if (bits < 8) return false; // anything broader than a /8 is absurd for a blocklist
  const net = ip4ToInt(ip) & maskOf(bits);
  const entryMask = maskOf(bits);
  for (const [rnet, rbits] of RESERVED) {
    const rmask = maskOf(rbits);
    // overlap if either network sits inside the other's masked range
    if ((net & rmask) === (rnet & rmask)) return false; // entry inside reserved
    if ((rnet & entryMask) === net) return false; // entry (a CIDR) contains reserved
  }
  return true;
}

function parseFeed(text: string): string[] {
  const out: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    // Strip comments, then scan tokens (handles plain, whitespace, and quoted-CSV
    // feeds) for the first IP/CIDR on the line.
    const cleaned = line.split(/[#;]/)[0]!.trim();
    if (!cleaned) continue;
    for (let token of cleaned.split(/[\s,]+/)) {
      token = token.replace(/^"|"$/g, "");
      const m = IP_OR_CIDR.exec(token);
      if (m && isIP(m[1]!) === 4) {
        const bits = m[2] ? Number(m[2]) : 32;
        if (isSafeBlockEntry(m[1]!, bits)) out.push(token);
        break; // first IP-like token on the line, safe or not
      }
    }
  }
  return out;
}

function ipToInt(ip: string): number {
  return ip.split(".").reduce((a, o) => ((a << 8) >>> 0) + Number(o), 0) >>> 0;
}

interface Cidr {
  net: number;
  bits: number;
}

class FeedStore {
  exact = new Map<string, Set<string>>(); // ip -> feed names
  cidrs: Array<Cidr & { feeds: Set<string>; raw: string }> = [];

  add(entry: string, feed: string): void {
    if (entry.includes("/")) {
      const [net, bitsStr] = entry.split("/");
      this.cidrs.push({ net: ipToInt(net!), bits: Number(bitsStr), feeds: new Set([feed]), raw: entry });
    } else {
      const s = this.exact.get(entry) ?? new Set<string>();
      s.add(feed);
      this.exact.set(entry, s);
    }
  }

  /** Which feeds list this IP (exact or CIDR containment). */
  match(ip: string): string[] {
    const feeds = new Set<string>(this.exact.get(ip) ?? []);
    if (this.cidrs.length) {
      const v = ipToInt(ip);
      for (const c of this.cidrs) {
        const mask = c.bits === 0 ? 0 : c.bits >= 32 ? 0xffffffff : (~((1 << (32 - c.bits)) - 1)) >>> 0;
        if ((v & mask) === (c.net & mask)) for (const f of c.feeds) feeds.add(f);
      }
    }
    return [...feeds];
  }

  get size(): number {
    return this.exact.size + this.cidrs.length;
  }

  entries(): string[] {
    return [...this.exact.keys(), ...this.cidrs.map((c) => c.raw)];
  }
}

interface FeedState {
  fetchedAt: number;
  total: number;
  perFeed: Record<string, number>;
}

function loadState(): FeedState | null {
  try {
    if (existsSync(STATE_PATH)) return JSON.parse(readFileSync(STATE_PATH, "utf8")) as FeedState;
  } catch {
    /* ignore */
  }
  return null;
}
function saveState(s: FeedState): void {
  try {
    if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
    writeFileSync(STATE_PATH, JSON.stringify(s), { mode: 0o600 });
  } catch {
    /* ignore */
  }
}

async function fetchFeed(def: FeedDef): Promise<{ def: FeedDef; entries: string[]; error?: string }> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 25000);
  try {
    const r = await fetch(def.url, { signal: ac.signal, headers: { "user-agent": "SecTool/1.0" } });
    if (!r.ok) return { def, entries: [], error: `HTTP ${r.status}` };
    return { def, entries: parseFeed(await r.text()) };
  } catch (err) {
    return { def, entries: [], error: (err as Error).message };
  } finally {
    clearTimeout(t);
  }
}

function feedRuleCmds(): string {
  return [
    `ipset create ${SET} hash:net family inet maxelem 1048576 -exist`,
    `iptables -C FORWARD -m set --match-set ${SET} src -j DROP 2>/dev/null || iptables -I FORWARD 1 -m set --match-set ${SET} src -j DROP`,
    `iptables -C FORWARD -m set --match-set ${SET} dst -j DROP 2>/dev/null || iptables -I FORWARD 1 -m set --match-set ${SET} dst -j DROP`,
    `iptables -C INPUT -m set --match-set ${SET} src -j DROP 2>/dev/null || iptables -I INPUT 1 -m set --match-set ${SET} src -j DROP`,
  ].join("; ");
}

/** Atomically load the feed entries into the UDM ipset (build tmp + swap). */
async function loadToUdm(entries: string[]): Promise<void> {
  const lines = ["create SECTOOL_FEED_tmp hash:net family inet maxelem 1048576"];
  for (const e of entries) lines.push(`add SECTOOL_FEED_tmp ${e}`);
  lines.push("swap SECTOOL_FEED_tmp SECTOOL_FEED", "destroy SECTOOL_FEED_tmp", "");
  await sshExec(feedRuleCmds(), { timeoutMs: 15000 });
  await sshExecInput("ipset restore -!", lines.join("\n"), { timeoutMs: 60000 });
}

export interface FeedRefreshResult {
  fetchedAt: number;
  total: number;
  perFeed: Record<string, number>;
  deltas: Record<string, number>;
  totalDelta: number;
  errors: Array<{ feed: string; error: string }>;
  loaded: boolean;
}

export async function refreshFeeds(cfg: Config): Promise<FeedRefreshResult> {
  log.info("Refreshing threat-intel feeds…");
  const results = await Promise.all(DEFAULT_FEEDS.map((f) => fetchFeed(f)));
  const store = new FeedStore();
  const perFeed: Record<string, number> = {};
  const errors: Array<{ feed: string; error: string }> = [];
  for (const r of results) {
    if (r.error) errors.push({ feed: r.def.name, error: r.error });
    perFeed[r.def.name] = r.entries.length;
    for (const e of r.entries) store.add(e, r.def.name);
  }
  setFeedMatcher((ip) => store.match(ip));

  const prev = loadState();
  const deltas: Record<string, number> = {};
  for (const f of DEFAULT_FEEDS) deltas[f.name] = (perFeed[f.name] ?? 0) - (prev?.perFeed[f.name] ?? 0);
  const total = store.size;
  const totalDelta = total - (prev?.total ?? 0);

  let loaded = false;
  if (cfg.intel.block && loadSshTarget()) {
    try {
      await loadToUdm(store.entries());
      loaded = true;
      log.info(`Loaded ${total} feed entries into the ${SET} ipset.`);
    } catch (err) {
      log.warn(`Feed ipset load failed: ${(err as Error).message}`);
    }
  }

  saveState({ fetchedAt: Date.now(), total, perFeed });
  return { fetchedAt: Date.now(), total, perFeed, deltas, totalDelta, errors, loaded };
}
