/**
 * Operator-curated "watchlist" of IPs / CIDR ranges to monitor closely.
 *
 * Unlike the blocklist (drops traffic) or safelist (exempts from scoring), the
 * watchlist is purely observational: whenever an alert, flow, or investigation
 * touches a watched address the dashboard highlights it and the Watchlist page
 * shows recent activity hit-counts so the analyst can see how active a target
 * has been in the chosen window.
 *
 * Supports plain IPv4/IPv6 addresses and IPv4 CIDR blocks (e.g. 185.220.101.0/24).
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { isIP } from "node:net";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { log } from "../logger.ts";

const DATA_DIR = fileURLToPath(new URL("../../data", import.meta.url));
const STORE_PATH = join(DATA_DIR, "watchlist.json");

/** Longest note we persist for a watch entry — see {@link sanitizeNote}. */
const NOTE_MAX_LEN = 500;

export interface WatchEntry {
  /** The original entry as the user wrote it — IP or CIDR string. */
  target: string;
  /** Family hint: 4, 6, or 0 for CIDR. */
  family: 4 | 6 | 0;
  /** When the entry was added (epoch ms). */
  at: number;
  /**
   * Free-form note explaining why the address is watched ("known C2",
   * "vendor pen-test", etc.). Stored normalised and length-bounded by
   * {@link sanitizeNote}; consumers may further clamp it for display.
   */
  note?: string;
}

/**
 * Normalise a free-form operator note before persisting it. The note is raw
 * user input that flows into `watchlist.json`, the dashboard highlight and the
 * Watchlist page, so we trim surrounding whitespace and cap the length to keep
 * a pathological multi-kilobyte paste from bloating the on-disk store. Returns
 * `undefined` for empty / whitespace-only input so an absent note and a blank
 * one are stored identically.
 */
function sanitizeNote(note: string | undefined): string | undefined {
  if (typeof note !== "string") return undefined;
  const trimmed = note.trim();
  if (!trimmed) return undefined;
  if (trimmed.length <= NOTE_MAX_LEN) return trimmed;
  return `${trimmed.slice(0, NOTE_MAX_LEN - 1).trimEnd()}…`;
}

interface ParsedCidr {
  base: number; // 32-bit unsigned
  mask: number; // 32-bit unsigned
  bits: number;
}

function ipv4ToInt(ip: string): number | null {
  if (isIP(ip) !== 4) return null;
  const parts = ip.split(".").map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return null;
  return ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
}

function parseCidr(s: string): ParsedCidr | null {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(s);
  if (!m) return null;
  const bits = Number.parseInt(m[2]!, 10);
  if (!Number.isFinite(bits) || bits < 0 || bits > 32) return null;
  const base = ipv4ToInt(m[1]!);
  if (base === null) return null;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { base: (base & mask) >>> 0, mask, bits };
}

/** Validate an IP or CIDR. Returns canonical form, or null if invalid. */
export function canonicalizeTarget(raw: string): { canonical: string; family: 4 | 6 | 0 } | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  if (trimmed.includes("/")) {
    const parsed = parseCidr(trimmed);
    if (!parsed) return null;
    const a = (parsed.base >>> 24) & 0xff;
    const b = (parsed.base >>> 16) & 0xff;
    const c = (parsed.base >>> 8) & 0xff;
    const d = parsed.base & 0xff;
    return { canonical: `${a}.${b}.${c}.${d}/${parsed.bits}`, family: 0 };
  }
  const fam = isIP(trimmed);
  if (fam === 4) return { canonical: trimmed, family: 4 };
  if (fam === 6) return { canonical: trimmed.toLowerCase(), family: 6 };
  return null;
}

class WatchStore {
  #map = new Map<string, WatchEntry>();
  #cidrs: Array<{ key: string; cidr: ParsedCidr }> = [];
  #loaded = false;

  #ensure(): void {
    if (this.#loaded) return;
    this.#loaded = true;
    if (!existsSync(STORE_PATH)) return;
    try {
      const arr = JSON.parse(readFileSync(STORE_PATH, "utf8")) as WatchEntry[];
      for (const e of arr) {
        if (!e?.target) continue;
        this.#map.set(e.target, { ...e, note: sanitizeNote(e.note) });
        if (e.family === 0) {
          const cidr = parseCidr(e.target);
          if (cidr) this.#cidrs.push({ key: e.target, cidr });
        }
      }
    } catch (err) {
      log.warn(`Could not load watchlist: ${(err as Error).message}`);
    }
  }

  #persist(): void {
    try {
      if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
      writeFileSync(STORE_PATH, JSON.stringify([...this.#map.values()]), { mode: 0o600 });
    } catch (err) {
      log.warn(`Could not persist watchlist: ${(err as Error).message}`);
    }
  }

  /** Add an IP or CIDR. Returns the stored entry, or null if invalid. */
  add(raw: string, note?: string): WatchEntry | null {
    this.#ensure();
    const c = canonicalizeTarget(raw);
    if (!c) return null;
    const clean = sanitizeNote(note);
    const existing = this.#map.get(c.canonical);
    if (existing) {
      // Already watched — keep the original timestamp but let the operator
      // attach or amend the justification on a re-add (matches the safelist).
      if (note !== undefined && clean !== existing.note) {
        existing.note = clean;
        this.#persist();
      }
      return existing;
    }
    const entry: WatchEntry = { target: c.canonical, family: c.family, at: Date.now(), note: clean };
    this.#map.set(c.canonical, entry);
    if (c.family === 0) {
      const cidr = parseCidr(c.canonical);
      if (cidr) this.#cidrs.push({ key: c.canonical, cidr });
    }
    this.#persist();
    return entry;
  }

  remove(raw: string): boolean {
    this.#ensure();
    const c = canonicalizeTarget(raw);
    const key = c ? c.canonical : raw.trim();
    const had = this.#map.delete(key);
    if (had) {
      this.#cidrs = this.#cidrs.filter((c2) => c2.key !== key);
      this.#persist();
    }
    return had;
  }

  /** Does the given IP match a watchlisted IP or CIDR? */
  match(ip: string | undefined | null): WatchEntry | undefined {
    if (!ip) return undefined;
    this.#ensure();
    const direct = this.#map.get(ip);
    if (direct) return direct;
    if (isIP(ip) === 4 && this.#cidrs.length) {
      const n = ipv4ToInt(ip);
      if (n === null) return undefined;
      for (const c of this.#cidrs) {
        if ((n & c.cidr.mask) >>> 0 === c.cidr.base) return this.#map.get(c.key);
      }
    }
    return undefined;
  }

  has(ip: string): boolean {
    return this.match(ip) !== undefined;
  }

  all(): WatchEntry[] {
    this.#ensure();
    return [...this.#map.values()].sort((a, b) => b.at - a.at);
  }

  count(): number {
    this.#ensure();
    return this.#map.size;
  }
}

export const watchStore = new WatchStore();
