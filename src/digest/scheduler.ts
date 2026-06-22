/**
 * Lightweight in-service scheduler that posts the threat digest once per day at
 * the configured local hour. Checks every 15 minutes and records the last run
 * date so a restart doesn't double-post.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import type { Config } from "../config.ts";
import { runDigest } from "./digest.ts";
import { log } from "../logger.ts";

const DATA_DIR = fileURLToPath(new URL("../../data", import.meta.url));
const STATE_PATH = join(DATA_DIR, "digest-state.json");

function lastRunDate(): string | null {
  try {
    if (existsSync(STATE_PATH)) return (JSON.parse(readFileSync(STATE_PATH, "utf8")) as { date?: string }).date ?? null;
  } catch {
    /* ignore */
  }
  return null;
}
function recordRun(date: string): void {
  try {
    if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
    writeFileSync(STATE_PATH, JSON.stringify({ date }), { mode: 0o600 });
  } catch {
    /* ignore */
  }
}

export function startDigestScheduler(cfg: Config): NodeJS.Timeout {
  const tick = () => {
    const now = new Date();
    const todayKey = `${now.getFullYear()}-${now.getMonth() + 1}-${now.getDate()}`;
    if (now.getHours() === cfg.digest.hour && lastRunDate() !== todayKey) {
      recordRun(todayKey);
      log.info("Scheduled threat digest firing…");
      void runDigest(cfg, cfg.digest.periodHours, Date.now()).catch((err) =>
        log.error(`Scheduled digest failed: ${(err as Error).message}`),
      );
    }
  };
  const timer = setInterval(tick, 15 * 60_000);
  timer.unref();
  log.info(`Digest scheduler active — daily at ${String(cfg.digest.hour).padStart(2, "0")}:00 local.`);
  return timer;
}
