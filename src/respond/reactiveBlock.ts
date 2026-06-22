/**
 * Reactive inbound blocking: instead of preemptively dropping whole threat feeds
 * (which blocks legitimate destinations you reach OUT to), this only blocks a
 * feed-listed IP once it is observed *initiating inbound traffic* to your network.
 *
 * Guards against blocking the return path of your own outbound connections:
 *   - the external IP must be the flow SOURCE into an internal host, and
 *   - its source port must be ephemeral (it's acting as a client/scanner), and
 *   - none of your internal hosts initiated a flow TO that external IP.
 * So it can never break a service you chose to connect to.
 */
import { isIP } from "node:net";
import type { Config } from "../config.ts";
import { getActiveFlowStore } from "../netflow/flowAccess.ts";
import { feedMatch } from "../intel/feedAccess.ts";
import { blockIp, blockGuard } from "./blocker.ts";
import { blockStore } from "../store/blocklist.ts";
import { log } from "../logger.ts";
import type { Flow } from "../netflow/ipfix.ts";

let timer: NodeJS.Timeout | undefined;

function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/.test(ip);
}

export async function reactiveScan(cfg: Config, now = Date.now()): Promise<{ blocked: string[]; suggested: string[] }> {
  const store = getActiveFlowStore();
  const blocked: string[] = [];
  const suggested: string[] = [];
  if (!store) return { blocked, suggested };

  const windowMs = Math.max(cfg.autoRespond.reactiveIntervalSec * 3, 300) * 1000;
  const flows = store.query([], now - windowMs, now, 20000) as Flow[];

  const solicited = new Set<string>(); // externals our hosts initiated to
  const inbound = new Map<string, number>(); // external -> inbound flow count
  for (const f of flows) {
    const s = f.srcIp;
    const d = f.dstIp;
    if (!s || !d || isIP(s) === 0 || isIP(d) === 0) continue;
    const sp = isPrivate(s);
    const dp = isPrivate(d);
    if (sp && !dp) solicited.add(d);
    else if (!sp && dp) {
      if ((f.srcPort ?? 0) < 1024) continue; // low source port => looks like return traffic
      inbound.set(s, (inbound.get(s) ?? 0) + 1);
    }
  }

  let count = 0;
  for (const [ext] of inbound) {
    if (count >= cfg.autoRespond.dailyCap) break;
    if (solicited.has(ext)) continue; // we reached out to it -> not unsolicited
    const feeds = feedMatch(ext);
    if (!feeds.length) continue;
    if (blockStore.has(ext)) continue;
    if (blockGuard(cfg, ext)) continue;

    const reason = `unsolicited inbound from feed IP (${feeds.slice(0, 3).join(", ")})`;
    if (cfg.autoRespond.dryRun) {
      log.info(`[reactive dry-run] would block ${ext} — ${reason}`);
      suggested.push(ext);
      continue;
    }
    try {
      await blockIp(cfg, ext, `reactive: ${reason}`, "reactive-inbound");
      blocked.push(ext);
      count++;
    } catch (err) {
      log.warn(`Reactive block failed for ${ext}: ${(err as Error).message}`);
    }
  }
  if (blocked.length || suggested.length) {
    log.info(`Reactive inbound scan: ${blocked.length} blocked, ${suggested.length} suggested.`);
  }
  return { blocked, suggested };
}

export function startReactiveBlocker(cfg: Config): void {
  log.info(
    `Reactive inbound blocking active${cfg.autoRespond.dryRun ? " (dry-run)" : ""} — ` +
      `every ${cfg.autoRespond.reactiveIntervalSec}s, feed-listed unsolicited inbound only.`,
  );
  timer = setInterval(() => void reactiveScan(cfg).catch((e) => log.warn(`Reactive scan error: ${(e as Error).message}`)), cfg.autoRespond.reactiveIntervalSec * 1000);
  timer.unref();
}

export function stopReactiveBlocker(): void {
  if (timer) clearInterval(timer);
}
