/**
 * Operator-vetted "safe" external IPs. Marking a peer safe (from the Hosts page)
 * removes it from host-risk scoring and protects it from any auto-blocking — it's
 * a dynamic, persisted allowlist of destinations you've confirmed are benign.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { log } from "../logger.ts";

const DATA_DIR = fileURLToPath(new URL("../../data", import.meta.url));
const STORE_PATH = join(DATA_DIR, "safelist.json");

interface SafeEntry {
  ip: string;
  at: number;
  note?: string;
}

class SafeStore {
  #map = new Map<string, SafeEntry>();
  #loaded = false;

  #ensure(): void {
    if (this.#loaded) return;
    this.#loaded = true;
    if (!existsSync(STORE_PATH)) return;
    try {
      for (const e of JSON.parse(readFileSync(STORE_PATH, "utf8")) as SafeEntry[]) if (e?.ip) this.#map.set(e.ip, e);
    } catch (err) {
      log.warn(`Could not load safelist: ${(err as Error).message}`);
    }
  }
  #persist(): void {
    try {
      if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
      writeFileSync(STORE_PATH, JSON.stringify([...this.#map.values()]), { mode: 0o600 });
    } catch (err) {
      log.warn(`Could not persist safelist: ${(err as Error).message}`);
    }
  }

  add(ip: string, note?: string): void {
    this.#ensure();
    if (!this.#map.has(ip)) {
      this.#map.set(ip, { ip, at: Date.now(), note });
      this.#persist();
    }
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
  all(): SafeEntry[] {
    this.#ensure();
    return [...this.#map.values()].sort((a, b) => b.at - a.at);
  }
  count(): number {
    this.#ensure();
    return this.#map.size;
  }
}

export const safeStore = new SafeStore();
