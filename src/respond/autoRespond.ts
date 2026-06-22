/**
 * Autonomous response policy: optionally auto-block IPs when an alert escalates
 * (damning threat-intel) or when a source becomes a repeat offender. Guarded by a
 * daily cap, the blocker's allowlist, and an optional dry-run (suggest-only) mode.
 */
import type { Config } from "../config.ts";
import { blockIp, blockGuard } from "./blocker.ts";
import { blockStore } from "../store/blocklist.ts";
import { log } from "../logger.ts";

const offenders = new Map<string, number[]>(); // ip -> hit timestamps
let capDate = "";
let capCount = 0;

function recordOffender(ip: string, windowMs: number, now: number): number {
  const arr = (offenders.get(ip) ?? []).filter((t) => now - t < windowMs);
  arr.push(now);
  offenders.set(ip, arr);
  return arr.length;
}

function capReached(cfg: Config, now: number): boolean {
  const d = new Date(now);
  const key = `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
  if (key !== capDate) {
    capDate = key;
    capCount = 0;
  }
  return capCount >= cfg.autoRespond.dailyCap;
}

export interface AutoResponse {
  blocked: boolean;
  dryRun?: boolean;
  trigger?: string;
  skipped?: string;
}

/**
 * Decide whether to auto-block `ip`. Always records the hit for repeat-offender
 * tracking; blocks when policy triggers and guards pass.
 */
export async function maybeAutoBlock(
  cfg: Config,
  ip: string,
  opts: { escalated: boolean },
  now = Date.now(),
): Promise<AutoResponse> {
  const ar = cfg.autoRespond;
  const repeatOn = ar.repeatThreshold > 0;

  let trigger: string | null = null;
  if (opts.escalated && ar.blockOnEscalation) trigger = "escalation";

  if (repeatOn) {
    const hits = recordOffender(ip, ar.repeatWindowHours * 3_600_000, now);
    if (!trigger && hits >= ar.repeatThreshold) trigger = `repeat offender (${hits} hits/${ar.repeatWindowHours}h)`;
  }

  if (!trigger) return { blocked: false };
  if (blockStore.has(ip)) return { blocked: false, trigger, skipped: "already blocked" };

  const guard = blockGuard(cfg, ip);
  if (guard) return { blocked: false, trigger, skipped: guard };

  if (capReached(cfg, now)) {
    log.warn(`Auto-block skipped (daily cap ${ar.dailyCap} reached): ${ip} [${trigger}]`);
    return { blocked: false, trigger, skipped: "daily cap reached" };
  }

  if (ar.dryRun) {
    log.info(`[auto-respond dry-run] would block ${ip} — ${trigger}`);
    return { blocked: false, dryRun: true, trigger };
  }

  try {
    await blockIp(cfg, ip, `auto: ${trigger}`, "auto-respond");
    capCount++;
    log.info(`Auto-blocked ${ip} — ${trigger}.`);
    return { blocked: true, trigger };
  } catch (err) {
    log.warn(`Auto-block failed for ${ip}: ${(err as Error).message}`);
    return { blocked: false, trigger, skipped: (err as Error).message };
  }
}

export function autoRespondEnabled(cfg: Config): boolean {
  return cfg.autoRespond.blockOnEscalation || cfg.autoRespond.repeatThreshold > 0;
}
