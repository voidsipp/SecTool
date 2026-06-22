/**
 * Active response: block IPs at the UDM firewall via a dedicated ipset
 * (SECTOOL_BLOCK) referenced by DROP rules at the top of FORWARD and INPUT.
 *
 * The rules are re-asserted periodically because UniFi rebuilds its iptables
 * chains on provision. A safety allowlist prevents blocking private ranges, the
 * gateway, this host, or anything the operator explicitly protects.
 */
import { isIP } from "node:net";
import type { Config } from "../config.ts";
import { blockStore, type BlockEntry } from "../store/blocklist.ts";
import { safeStore } from "../store/safelist.ts";
import { sshExec, loadSshTarget } from "../ingest/sshPull.ts";
import { log } from "../logger.ts";

const SET = "SECTOOL_BLOCK";

let reassertTimer: NodeJS.Timeout | undefined;

function sh(parts: string[]): string {
  return parts.join("; ");
}

/** Idempotent commands that (re)create the ipset and the DROP rules. */
function infraCmds(): string[] {
  return [
    // `counters` tracks per-IP dropped packets/bytes for block-effectiveness.
    `ipset create ${SET} hash:ip family inet maxelem 131072 counters -exist`,
    `iptables -C FORWARD -m set --match-set ${SET} src -j DROP 2>/dev/null || iptables -I FORWARD 1 -m set --match-set ${SET} src -j DROP`,
    `iptables -C FORWARD -m set --match-set ${SET} dst -j DROP 2>/dev/null || iptables -I FORWARD 1 -m set --match-set ${SET} dst -j DROP`,
    `iptables -C INPUT -m set --match-set ${SET} src -j DROP 2>/dev/null || iptables -I INPUT 1 -m set --match-set ${SET} src -j DROP`,
  ];
}

function isPrivate(ip: string): boolean {
  return (
    /^10\./.test(ip) || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^127\./.test(ip) || /^169\.254\./.test(ip) || /^0\./.test(ip) || ip === "255.255.255.255"
  );
}

/** Returns an error string if the IP must not be blocked, else null. */
export function blockGuard(cfg: Config, ip: string): string | null {
  if (isIP(ip) === 0) return "Not a valid IP address.";
  if (isIP(ip) === 6) return "IPv6 blocking isn't supported yet (the ipset is IPv4).";
  if (isPrivate(ip)) return "Refusing to block a private/internal/reserved IP.";
  if (safeStore.has(ip)) return "IP is marked safe.";
  const udmHost = loadSshTarget()?.host;
  if (udmHost && ip === udmHost) return "Refusing to block the gateway.";
  if (cfg.block.allowlist.includes(ip)) return "IP is on the protect/allowlist.";
  if (cfg.netflow.advertiseIp && ip === cfg.netflow.advertiseIp) return "Refusing to block this host.";
  return null;
}

export async function blockIp(cfg: Config, ip: string, reason?: string, by = "dashboard"): Promise<BlockEntry> {
  const guard = blockGuard(cfg, ip);
  if (guard) throw new Error(guard);
  const entry = blockStore.add(ip, reason, by);
  await sshExec(sh([...infraCmds(), `ipset add ${SET} ${ip} -exist`]), { timeoutMs: 15000 });
  log.info(`Blocked ${ip} at the UDM firewall${reason ? ` (${reason})` : ""}.`);
  return entry;
}

export async function unblockIp(ip: string): Promise<boolean> {
  const had = blockStore.remove(ip);
  try {
    await sshExec(`ipset del ${SET} ${ip} -exist`, { timeoutMs: 12000 });
  } catch (err) {
    log.warn(`Unblock ipset del failed for ${ip}: ${(err as Error).message}`);
  }
  if (had) log.info(`Unblocked ${ip}.`);
  return had;
}

/** Push the full blocklist + rules to the UDM (startup and periodic re-assert). */
export async function applyAll(): Promise<void> {
  if (!loadSshTarget()) return;
  const ips = blockStore.ips();
  const cmds = [...infraCmds(), ...ips.map((ip) => `ipset add ${SET} ${ip} -exist`)];
  try {
    await sshExec(sh(cmds), { timeoutMs: 20000 });
  } catch (err) {
    log.warn(`Block re-assert failed: ${(err as Error).message}`);
  }
}

export function listBlocks(): Array<BlockEntry & { durationMs: number }> {
  const now = Date.now();
  return blockStore.all().map((e) => ({ ...e, durationMs: now - e.at }));
}

/** Per-IP dropped packet/byte counters from the ipset (block effectiveness). */
export async function blockStats(): Promise<Map<string, { packets: number; bytes: number }>> {
  const stats = new Map<string, { packets: number; bytes: number }>();
  if (!loadSshTarget()) return stats;
  try {
    const out = await sshExec(`ipset list ${SET} 2>/dev/null`, { timeoutMs: 12000 });
    for (const line of out.split(/\r?\n/)) {
      const m = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+packets\s+(\d+)\s+bytes\s+(\d+)/.exec(line.trim());
      if (m) stats.set(m[1]!, { packets: Number(m[2]), bytes: Number(m[3]) });
    }
  } catch {
    /* best effort */
  }
  return stats;
}

export async function listBlocksWithStats(): Promise<Array<BlockEntry & { durationMs: number; packets: number; bytes: number }>> {
  const stats = await blockStats();
  return listBlocks().map((b) => ({ ...b, packets: stats.get(b.ip)?.packets ?? 0, bytes: stats.get(b.ip)?.bytes ?? 0 }));
}

export async function startBlocker(cfg: Config): Promise<void> {
  if (!loadSshTarget()) {
    log.info("Blocker idle — no SSH connection configured.");
    return;
  }
  await applyAll();
  log.info(`Firewall blocker active (${blockStore.count()} IP(s) blocked via ipset ${SET}).`);
  reassertTimer = setInterval(() => void applyAll(), Math.max(30, cfg.block.reassertSec) * 1000);
  reassertTimer.unref();
}

export function stopBlocker(): void {
  if (reassertTimer) clearInterval(reassertTimer);
}
