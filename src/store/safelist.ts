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

/** Longest note we persist for a safe entry — see {@link sanitizeNote}. */
const NOTE_MAX_LEN = 500;

interface SafeEntry {
  /** The external IP the operator vetted as benign. */
  ip: string;
  /** When the entry was added (epoch ms). */
  at: number;
  /**
   * Free-form justification for trusting this address ("vendor CDN",
   * "monitoring vendor", etc.). Stored normalised and length-bounded by
   * {@link sanitizeNote}; consumers may further clamp it for display.
   */
  note?: string;
}

/**
 * Normalise a free-form operator note before persisting it. The note is raw
 * user input that flows into `safelist.json`, the agent's listings and the
 * shareable report, so we trim surrounding whitespace and cap the length to
 * keep a pathological multi-kilobyte paste from bloating the on-disk store.
 * Returns `undefined` for empty / whitespace-only input so an absent note and
 * a blank one are stored identically.
 */
function sanitizeNote(note: string | undefined): string | undefined {
  if (typeof note !== "string") return undefined;
  const trimmed = note.trim();
  if (!trimmed) return undefined;
  if (trimmed.length <= NOTE_MAX_LEN) return trimmed;
  return `${trimmed.slice(0, NOTE_MAX_LEN - 1).trimEnd()}…`;
}

class SafeStore {
  #map = new Map<string, SafeEntry>();
  #loaded = false;

  #ensure(): void {
    if (this.#loaded) return;
    this.#loaded = true;
    if (!existsSync(STORE_PATH)) return;
    try {
      for (const e of JSON.parse(readFileSync(STORE_PATH, "utf8")) as SafeEntry[]) {
        if (e?.ip) this.#map.set(e.ip, { ip: e.ip, at: e.at, note: sanitizeNote(e.note) });
      }
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
    const clean = sanitizeNote(note);
    const existing = this.#map.get(ip);
    if (existing) {
      // Already vetted — keep the original timestamp but let the operator
      // attach or amend the justification on a re-add (matches the watchlist).
      if (clean !== undefined && clean !== existing.note) {
        existing.note = clean;
        this.#persist();
      }
      return;
    }
    this.#map.set(ip, { ip, at: Date.now(), note: clean });
    this.#persist();
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
