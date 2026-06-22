/**
 * Persisted list of IPs blocked at the UDM firewall (data/blocklist.json).
 * The actual enforcement lives in respond/blocker.ts (an ipset + iptables DROP);
 * this is the durable record so blocks are re-applied on restart/provision.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { log } from "../logger.ts";

const DATA_DIR = fileURLToPath(new URL("../../data", import.meta.url));
const STORE_PATH = join(DATA_DIR, "blocklist.json");

export interface BlockEntry {
  ip: string;
  at: number;
  reason?: string;
  by?: string;
}

class BlockStore {
  #map = new Map<string, BlockEntry>();
  #loaded = false;

  #ensure(): void {
    if (this.#loaded) return;
    this.#loaded = true;
    if (!existsSync(STORE_PATH)) return;
    try {
      const arr = JSON.parse(readFileSync(STORE_PATH, "utf8")) as BlockEntry[];
      for (const e of arr) if (e?.ip) this.#map.set(e.ip, e);
    } catch (err) {
      log.warn(`Could not load blocklist: ${(err as Error).message}`);
    }
  }

  #persist(): void {
    try {
      if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
      writeFileSync(STORE_PATH, JSON.stringify([...this.#map.values()]), { mode: 0o600 });
    } catch (err) {
      log.warn(`Could not persist blocklist: ${(err as Error).message}`);
    }
  }

  add(ip: string, reason?: string, by?: string): BlockEntry {
    this.#ensure();
    const existing = this.#map.get(ip);
    const entry: BlockEntry = existing ?? { ip, at: Date.now(), reason, by };
    if (!existing) {
      this.#map.set(ip, entry);
      this.#persist();
    }
    return entry;
  }

  remove(ip: string): boolean {
    this.#ensure();
    const had = this.#map.delete(ip);
    if (had) this.#persist();
    return had;
  }

  has(ip: string): boolean {
    this.#ensure();
    return this.#map.has(ip);
  }

  all(): BlockEntry[] {
    this.#ensure();
    return [...this.#map.values()].sort((a, b) => b.at - a.at);
  }

  ips(): string[] {
    this.#ensure();
    return [...this.#map.keys()];
  }

  count(): number {
    this.#ensure();
    return this.#map.size;
  }
}

export const blockStore = new BlockStore();
