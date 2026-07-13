/**
 * Fleet health & tamper alerting (feature #5). Remembers which agents have been
 * seen, tracks last-seen / version / kill+isolate state, and a background monitor
 * alerts when an agent that was reporting goes silent (possible malware killing it),
 * drifts below the latest version, or reports itself isolated.
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import type { Config } from "../config.ts";
import { log } from "../logger.ts";
import { agentHealth } from "./agentClient.ts";

const STORE_PATH = fileURLToPath(new URL("../../data/agent-fleet.json", import.meta.url));

export interface FleetAgent {
  ip: string;
  host?: string;
  version?: string;
  platform?: string;
  firstSeen: number;
  lastSeen: number;
  online: boolean;
  kill?: boolean;
  isolated?: boolean;
  missed: number; // consecutive failed probes
}

const fleet = new Map<string, FleetAgent>();
let loaded = false;

function load(): void {
  if (loaded) return;
  loaded = true;
  try {
    const arr = JSON.parse(readFileSync(STORE_PATH, "utf8")) as FleetAgent[];
    for (const a of arr) fleet.set(a.ip, a);
  } catch { /* fresh */ }
}
function persist(): void {
  try {
    mkdirSync(dirname(STORE_PATH), { recursive: true });
    writeFileSync(STORE_PATH, JSON.stringify([...fleet.values()], null, 2));
  } catch (err) {
    log.warn(`fleet: could not persist: ${(err as Error).message}`);
  }
}

/** Called by the /api/agents discovery whenever an agent answers /health. */
export function recordSeen(ip: string, health: Record<string, unknown>): void {
  load();
  const now = Date.now();
  const prev = fleet.get(ip);
  fleet.set(ip, {
    ip,
    host: (health["host"] as string) ?? prev?.host,
    version: (health["version"] as string) ?? prev?.version,
    platform: (health["platform"] as string) ?? prev?.platform,
    firstSeen: prev?.firstSeen ?? now,
    lastSeen: now,
    online: true,
    kill: health["kill"] === true,
    isolated: health["isolated"] === true,
    missed: 0,
  });
  persist();
}

export function knownAgents(): FleetAgent[] {
  load();
  return [...fleet.values()].sort((a, b) => b.lastSeen - a.lastSeen);
}

async function discordLite(cfg: Config, title: string, desc: string, color: number): Promise<void> {
  if (!cfg.discord.webhookUrl || cfg.runtime.dryRun) {
    if (cfg.runtime.dryRun) log.info(`[dry-run] fleet alert: ${title} — ${desc}`);
    return;
  }
  await fetch(cfg.discord.webhookUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: cfg.discord.username, embeds: [{ title, description: desc, color, timestamp: new Date().toISOString() }] }),
    signal: AbortSignal.timeout(8000),
  }).catch((err: Error) => log.warn(`fleet alert post failed: ${err.message}`));
}

const OFFLINE_AFTER = 3; // consecutive missed probes before "gone dark"
let latestVersion = "";
export function setLatestVersion(v: string): void {
  latestVersion = v;
}

/** Periodic probe of every known agent; alerts on offline / version drift. */
export function startFleetMonitor(cfg: Config, intervalSec = 180): void {
  load();
  const tick = async () => {
    for (const a of [...fleet.values()]) {
      const r = await agentHealth(cfg, a.ip, 2500);
      if (r.ok && r.data) {
        const d = r.data as Record<string, unknown>;
        const wasOffline = !a.online;
        a.online = true;
        a.missed = 0;
        a.lastSeen = Date.now();
        a.version = (d["version"] as string) ?? a.version;
        a.isolated = d["isolated"] === true;
        if (wasOffline) await discordLite(cfg, "✅ Agent back online", `**${a.host ?? a.ip}** (${a.ip}) is reporting again.`, 0x3ad29f);
        if (latestVersion && a.version && a.version !== latestVersion) {
          await discordLite(cfg, "⚠️ Agent version drift", `**${a.host ?? a.ip}** is on v${a.version}; latest is v${latestVersion}.`, 0xff9e3d);
        }
      } else {
        a.missed++;
        if (a.online && a.missed >= OFFLINE_AFTER) {
          a.online = false;
          await discordLite(cfg, "🚨 Agent went dark", `**${a.host ?? a.ip}** (${a.ip}) stopped responding after ${a.missed} checks — possible tampering, shutdown, or the agent was killed.`, 0xff5c7a);
        }
      }
    }
    persist();
  };
  setInterval(() => void tick(), Math.max(60, intervalSec) * 1000).unref();
  log.info(`Fleet monitor active — health checks every ${intervalSec}s, alerts on offline/version-drift.`);
}
