/**
 * Persisted set of "dismissed" alert IDs. The dashboard pulls alerts live from
 * the UDM, so we can't delete them there — instead we hide dismissed ones from
 * the list (restorable). Stored in data/dismissed.json.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { log } from "../logger.ts";

const DATA_DIR = fileURLToPath(new URL("../../data", import.meta.url));
const STORE_PATH = join(DATA_DIR, "dismissed.json");

export interface DismissEntry {
  id: string;
  at: number;
  reason?: string;
}

class DismissStore {
  #map = new Map<string, DismissEntry>();
  #loaded = false;

  #ensure(): void {
    if (this.#loaded) return;
    this.#loaded = true;
    if (!existsSync(STORE_PATH)) return;
    try {
      const arr = JSON.parse(readFileSync(STORE_PATH, "utf8")) as DismissEntry[];
      for (const e of arr) if (e?.id) this.#map.set(e.id, e);
    } catch (err) {
      log.warn(`Could not load dismissed store: ${(err as Error).message}`);
    }
  }

  #persist(): void {
    try {
      if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
      writeFileSync(STORE_PATH, JSON.stringify([...this.#map.values()]), { mode: 0o600 });
    } catch (err) {
      log.warn(`Could not persist dismissed store: ${(err as Error).message}`);
    }
  }

  dismiss(id: string, reason?: string): void {
    this.#ensure();
    this.#map.set(id, { id, at: Date.now(), reason });
    this.#persist();
  }

  restore(id: string): boolean {
    this.#ensure();
    const had = this.#map.delete(id);
    if (had) this.#persist();
    return had;
  }

  /** Remove all dismissals. */
  clear(): number {
    this.#ensure();
    const n = this.#map.size;
    this.#map.clear();
    this.#persist();
    return n;
  }

  has(id: string): boolean {
    this.#ensure();
    return this.#map.has(id);
  }

  count(): number {
    this.#ensure();
    return this.#map.size;
  }

  /**
   * A snapshot of every dismissal entry, newest dismissal first. Read-only copy
   * so callers (e.g. the offline dismissal-audit report) can enumerate the
   * hidden-alert set without reaching into the private map.
   */
  all(): DismissEntry[] {
    this.#ensure();
    return [...this.#map.values()].sort((a, b) => b.at - a.at);
  }
}

export const dismissStore = new DismissStore();
