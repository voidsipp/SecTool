/**
 * NetFlow/IPFIX collector: a UDP listener that decodes incoming flow exports
 * into the FlowStore. Because the UDM's exporter is configured by a sysctl
 * (`net.netflow.destination`), the collector can optionally point that export at
 * this host over SSH automatically — and re-assert it periodically so it
 * survives UDM reboots/provisions.
 */
import dgram from "node:dgram";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import type { Config } from "../config.ts";
import { IpfixDecoder, type Flow } from "./ipfix.ts";
import { FlowStore } from "./flowStore.ts";
import { loadSshTarget, sshExec } from "../ingest/sshPull.ts";
import { log } from "../logger.ts";

const DATA_DIR = fileURLToPath(new URL("../../data", import.meta.url));
const FLOWS_PATH = join(DATA_DIR, "flows.json");

export interface FlowCollector {
  store: FlowStore;
  close: () => Promise<void>;
}

/** Determine the local IP this host uses to reach `targetIp` (no traffic sent). */
function localIpFor(targetIp: string): Promise<string | null> {
  return new Promise((resolve) => {
    const s = dgram.createSocket("udp4");
    try {
      s.connect(9, targetIp, () => {
        const addr = s.address().address;
        s.close();
        resolve(addr || null);
      });
    } catch {
      try { s.close(); } catch { /* ignore */ }
      resolve(null);
    }
  });
}

/** Point the UDM's IPFIX export at `ip:port` via sysctl over SSH. */
async function repointUdm(ip: string, port: number): Promise<boolean> {
  try {
    // Point the export at us and keep a moderate template refresh-rate so the
    // collector relearns templates promptly (and survives occasional UDP loss).
    const out = await sshExec(
      `sysctl -w net.netflow.destination=${ip}:${port} >/dev/null 2>&1; ` +
        `sysctl -w net.netflow.refresh-rate=20 >/dev/null 2>&1; sysctl -n net.netflow.destination`,
      { timeoutMs: 12000 },
    );
    return out.trim().startsWith(`${ip}:${port}`);
  } catch (err) {
    log.warn(`Could not repoint UDM netflow export: ${(err as Error).message}`);
    return false;
  }
}

export async function startFlowCollector(cfg: Config): Promise<FlowCollector> {
  const store = new FlowStore(cfg.netflow.maxFlows, cfg.netflow.retentionMinutes);
  const decoder = new IpfixDecoder();
  let received = 0;
  let decoded = 0;

  // Restore persisted flows so history survives restarts.
  if (cfg.netflow.persist && existsSync(FLOWS_PATH)) {
    try {
      const flows = JSON.parse(readFileSync(FLOWS_PATH, "utf8")) as Flow[];
      store.load(flows, Date.now());
      log.info(`NetFlow: restored ${store.size} flows from disk.`);
    } catch (err) {
      log.warn(`NetFlow: could not restore flows: ${(err as Error).message}`);
    }
  }
  const persist = () => {
    if (!cfg.netflow.persist) return;
    try {
      if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
      writeFileSync(FLOWS_PATH, JSON.stringify(store.snapshot()), { mode: 0o600 });
    } catch (err) {
      log.debug(`NetFlow: persist failed: ${(err as Error).message}`);
    }
  };

  const sock = dgram.createSocket({ type: "udp4", reuseAddr: true });
  sock.on("message", (msg) => {
    received++;
    try {
      const flows = decoder.decode(msg, Date.now());
      if (flows.length) {
        store.add(flows);
        decoded += flows.length;
      }
    } catch (err) {
      log.debug(`IPFIX decode error: ${(err as Error).message}`);
    }
  });
  sock.on("error", (err) => log.error(`NetFlow collector error: ${err.message}`));

  await new Promise<void>((resolve, reject) => {
    sock.once("error", reject);
    sock.bind(cfg.netflow.port, cfg.netflow.host, () => {
      sock.removeListener("error", reject);
      log.info(`NetFlow/IPFIX collector listening on ${cfg.netflow.host}:${cfg.netflow.port}`);
      resolve();
    });
  });

  // Auto-configure the UDM to export here, and keep re-asserting it.
  let repointTimer: NodeJS.Timeout | undefined;
  if (cfg.netflow.autoConfigureUdm && loadSshTarget()) {
    const udmHost = loadSshTarget()!.host;
    const apply = async () => {
      const ip = cfg.netflow.advertiseIp || (await localIpFor(udmHost));
      if (!ip) {
        log.warn("NetFlow: could not determine local IP to advertise to the UDM.");
        return;
      }
      const ok = await repointUdm(ip, cfg.netflow.port);
      if (ok) log.info(`NetFlow: UDM export pointed at ${ip}:${cfg.netflow.port}.`);
    };
    await apply();
    repointTimer = setInterval(() => void apply(), 5 * 60_000);
    repointTimer.unref();
  }

  const pruneTimer = setInterval(() => {
    store.prune(Date.now());
    persist();
  }, 60_000);
  const statsTimer = setInterval(() => {
    log.info(`NetFlow stats: ${received} packets, ${decoded} flows decoded, ${store.size} retained (templates=${decoder.templatesSeen}).`);
  }, 5 * 60_000);
  pruneTimer.unref();
  statsTimer.unref();

  return {
    store,
    close: async () => {
      if (repointTimer) clearInterval(repointTimer);
      clearInterval(pruneTimer);
      clearInterval(statsTimer);
      persist();
      await new Promise<void>((r) => sock.close(() => r()));
    },
  };
}
