/**
 * Refreshes threat-intel feeds on startup and posts a highlighted "feed update"
 * changelog embed to Discord every 24 hours.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import type { Config } from "../config.ts";
import { refreshFeeds, type FeedRefreshResult } from "./feeds.ts";
import { DiscordNotifier } from "../notify/discord.ts";
import { log } from "../logger.ts";

const DATA_DIR = fileURLToPath(new URL("../../data", import.meta.url));
const STATE_PATH = join(DATA_DIR, "feeds-changelog.json");
const DAY_MS = 24 * 3_600_000;

function lastPostAt(): number {
  try {
    if (existsSync(STATE_PATH)) return (JSON.parse(readFileSync(STATE_PATH, "utf8")) as { at?: number }).at ?? 0;
  } catch {
    /* ignore */
  }
  return 0;
}
function recordPost(at: number): void {
  try {
    if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
    writeFileSync(STATE_PATH, JSON.stringify({ at }), { mode: 0o600 });
  } catch {
    /* ignore */
  }
}

function sign(n: number): string {
  return n > 0 ? `+${n}` : String(n);
}

export function changelogEmbed(r: FeedRefreshResult) {
  const rows = Object.entries(r.perFeed)
    .map(([name, count]) => {
      const d = r.deltas[name] ?? 0;
      return `${name}: **${count.toLocaleString()}**${d !== 0 ? ` (${sign(d)})` : ""}`;
    })
    .join("\n");
  const errs = r.errors.length ? `\n⚠️ ${r.errors.map((e) => `${e.feed}: ${e.error}`).join(", ")}` : "";
  return {
    title: "📋 Threat-Intel Feed Update",
    description:
      `Proactive blocklist refreshed${r.loaded ? " and loaded into the firewall" : ""}.\n\n` +
      `**${r.total.toLocaleString()}** total entries (${sign(r.totalDelta)} since last update).` +
      errs,
    color: 0x9b59b6, // highlighted purple
    fields: [{ name: "Feeds", value: rows.slice(0, 1024), inline: false }],
    footer: { text: "SecTool threat-intel · proactive IP blocklist" },
    timestamp: new Date().toISOString(),
  };
}

export async function refreshAndPostChangelog(cfg: Config): Promise<FeedRefreshResult> {
  const result = await refreshFeeds(cfg);
  await new DiscordNotifier(cfg).postEmbed(changelogEmbed(result), "📋 **Daily threat-intel feed update**");
  recordPost(Date.now());
  return result;
}

export function startFeedScheduler(cfg: Config): void {
  // Initial refresh to load the ipset immediately (no changelog post unless due).
  void refreshFeeds(cfg).catch((err) => log.error(`Initial feed refresh failed: ${(err as Error).message}`));

  const tick = () => {
    if (Date.now() - lastPostAt() >= DAY_MS) {
      log.info("Posting 24h threat-intel feed changelog…");
      void refreshAndPostChangelog(cfg).catch((err) => log.error(`Feed changelog failed: ${(err as Error).message}`));
    }
  };
  // Post the first changelog shortly after startup if one is due, then hourly checks.
  setTimeout(tick, 60_000).unref();
  const timer = setInterval(tick, 60 * 60_000);
  timer.unref();
  log.info(`Threat-intel feeds active — changelog every ${cfg.intel.refreshHours}h.`);
}
