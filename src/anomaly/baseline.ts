/**
 * Behavioral baselining: learns each internal host's "normal" outbound behavior
 * from collected flows, then flags deviations that signature/feed detection can't
 * see (novel malware, exfil, scanning). Tuned for low noise — only behavioral
 * shifts relative to the host's own learned baseline, not raw "new IP" events
 * (which are constant for normal browsing).
 *
 * Signals: new outbound service port, outbound volume spike, fan-out spike.
 * Note: forward-only and 1:512-sampled, so treat as directional, not absolute.
 */
import { isIP } from "node:net";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import type { Config } from "../config.ts";
import { getActiveFlowStore } from "../netflow/flowAccess.ts";
import { DiscordNotifier } from "../notify/discord.ts";
import { log } from "../logger.ts";
import type { Flow } from "../netflow/ipfix.ts";

const DATA_DIR = fileURLToPath(new URL("../../data", import.meta.url));
const PROFILES_PATH = join(DATA_DIR, "host-profiles.json");
const ANOM_PATH = join(DATA_DIR, "anomalies.json");
const COMMON_PORTS = new Set([53, 80, 123, 443, 853, 993, 995, 5223, 8443]);

interface Profile {
  firstSeen: number;
  lastSeen: number;
  ports: number[];
  peakHourBytes: number;
  peakHourFanout: number;
}
export interface Anomaly {
  ip: string;
  type: string;
  detail: string;
  time: number;
}

function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/.test(ip);
}
function loadJson<T>(p: string, def: T): T {
  try {
    if (existsSync(p)) return JSON.parse(readFileSync(p, "utf8")) as T;
  } catch {
    /* ignore */
  }
  return def;
}
function saveJson(p: string, v: unknown): void {
  try {
    if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
    writeFileSync(p, JSON.stringify(v), { mode: 0o600 });
  } catch {
    /* ignore */
  }
}

const recentAlerts = new Map<string, number>(); // dedupe key -> ms

/** Update per-host baselines from recent flows and return fresh anomalies. */
export function updateAndDetect(cfg: Config, now = Date.now()): Anomaly[] {
  const store = getActiveFlowStore();
  if (!store) return [];
  const profiles = loadJson<Record<string, Profile>>(PROFILES_PATH, {});
  const flows = store.query([], now - 3_600_000, now, 50000) as Flow[];

  // Aggregate this hour's OUTBOUND behavior per internal host.
  const agg = new Map<string, { bytes: number; ports: Set<number>; externals: Set<string> }>();
  for (const f of flows) {
    const s = f.srcIp;
    const d = f.dstIp;
    if (!s || !d || isIP(s) === 0 || isIP(d) === 0) continue;
    if (!isPrivate(s) || isPrivate(d)) continue; // internal -> external only
    let a = agg.get(s);
    if (!a) {
      a = { bytes: 0, ports: new Set(), externals: new Set() };
      agg.set(s, a);
    }
    a.bytes += f.bytes ?? 0;
    if (f.dstPort) a.ports.add(f.dstPort);
    a.externals.add(d);
  }

  const found: Anomaly[] = [];
  const learnMs = cfg.anomaly.minLearnHours * 3_600_000;
  const factor = cfg.anomaly.volumeSpikeFactor;

  for (const [ip, a] of agg) {
    const p = profiles[ip] ?? { firstSeen: now, lastSeen: now, ports: [], peakHourBytes: 0, peakHourFanout: 0 };
    const learning = now - p.firstSeen < learnMs;
    const known = new Set(p.ports);

    if (!learning) {
      const newPorts = [...a.ports].filter((pt) => !known.has(pt) && !COMMON_PORTS.has(pt));
      if (newPorts.length) push(found, ip, "new-port", `new outbound port(s): ${newPorts.slice(0, 8).join(", ")}`, now);
      if (p.peakHourBytes > 1_000_000 && a.bytes > p.peakHourBytes * factor && a.bytes > 50_000_000)
        push(found, ip, "volume-spike", `outbound ${(a.bytes / 1e6).toFixed(0)}MB this hour vs ~${(p.peakHourBytes / 1e6).toFixed(0)}MB baseline`, now);
      if (p.peakHourFanout >= 10 && a.externals.size > p.peakHourFanout * factor && a.externals.size > 40)
        push(found, ip, "fanout-spike", `${a.externals.size} distinct externals this hour vs ~${p.peakHourFanout} baseline (possible scanning)`, now);
    }

    // Update baseline.
    profiles[ip] = {
      firstSeen: p.firstSeen,
      lastSeen: now,
      ports: [...new Set([...p.ports, ...a.ports])].slice(0, 200),
      peakHourBytes: Math.max(p.peakHourBytes, a.bytes),
      peakHourFanout: Math.max(p.peakHourFanout, a.externals.size),
    };
  }
  saveJson(PROFILES_PATH, profiles);

  // De-dupe (same host+type) for 6h, persist a rolling anomaly log.
  const fresh = found.filter((an) => {
    const key = `${an.ip}|${an.type}`;
    const last = recentAlerts.get(key);
    if (last && now - last < 6 * 3_600_000) return false;
    recentAlerts.set(key, now);
    return true;
  });
  if (fresh.length) {
    const all = [...loadJson<Anomaly[]>(ANOM_PATH, []), ...fresh].slice(-500);
    saveJson(ANOM_PATH, all);
  }
  return fresh;
}

function push(arr: Anomaly[], ip: string, type: string, detail: string, time: number): void {
  arr.push({ ip, type, detail, time });
}

export function recentAnomalies(): Anomaly[] {
  return loadJson<Anomaly[]>(ANOM_PATH, []).sort((a, b) => b.time - a.time);
}

export function startBaselineMonitor(cfg: Config): void {
  const notifier = new DiscordNotifier(cfg);
  log.info(`Behavioral baselining active — learning ${cfg.anomaly.minLearnHours}h, checks every ${cfg.anomaly.intervalSec}s.`);
  const run = async () => {
    const anomalies = updateAndDetect(cfg);
    for (const an of anomalies) {
      log.warn(`Anomaly: ${an.ip} — ${an.type}: ${an.detail}`);
      if (cfg.anomaly.alertDiscord) {
        await notifier.postEmbed({
          title: `📈 Behavioral anomaly — ${an.ip}`,
          description: `Internal host **${an.ip}** deviated from its learned baseline:\n\n**${an.detail}**`,
          color: 0xe3873c,
          footer: { text: "SecTool behavioral baselining" },
          timestamp: new Date(an.time).toISOString(),
        });
      }
    }
  };
  const timer = setInterval(() => void run().catch((e) => log.warn(`Baseline error: ${(e as Error).message}`)), cfg.anomaly.intervalSec * 1000);
  timer.unref();
}
