/**
 * Per-alert triage state: a workflow status and an append-only note trail.
 *
 * The dashboard exposes alerts pulled live from the UDM, so the triage state
 * lives next to (not inside) the alert — keyed by the alert's stable id. Notes
 * are append-only on purpose so the record reads as an audit trail. Stored in
 * data/triage.json alongside the other store files.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { log } from "../logger.ts";

const DATA_DIR = fileURLToPath(new URL("../../data", import.meta.url));
const STORE_PATH = join(DATA_DIR, "triage.json");

export const TRIAGE_STATUSES = ["open", "investigating", "resolved", "false-positive"] as const;
export type TriageStatus = (typeof TRIAGE_STATUSES)[number];

export function isTriageStatus(v: unknown): v is TriageStatus {
  return typeof v === "string" && (TRIAGE_STATUSES as readonly string[]).includes(v);
}

export interface TriageNote {
  noteId: string;
  at: number;
  text: string;
}

export interface TriageEntry {
  id: string;
  status: TriageStatus;
  notes: TriageNote[];
  updatedAt: number;
}

const MAX_NOTE_LEN = 2000;
const MAX_NOTES_PER_ALERT = 50;

class TriageStore {
  #map = new Map<string, TriageEntry>();
  #loaded = false;

  #ensure(): void {
    if (this.#loaded) return;
    this.#loaded = true;
    if (!existsSync(STORE_PATH)) return;
    try {
      const arr = JSON.parse(readFileSync(STORE_PATH, "utf8")) as TriageEntry[];
      for (const e of arr) {
        if (!e?.id || !isTriageStatus(e.status)) continue;
        const notes = Array.isArray(e.notes)
          ? e.notes.filter((n): n is TriageNote => !!n && typeof n.text === "string" && typeof n.at === "number")
          : [];
        this.#map.set(e.id, { id: e.id, status: e.status, notes, updatedAt: e.updatedAt ?? Date.now() });
      }
    } catch (err) {
      log.warn(`Could not load triage store: ${(err as Error).message}`);
    }
  }

  #persist(): void {
    try {
      if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
      writeFileSync(STORE_PATH, JSON.stringify([...this.#map.values()]), { mode: 0o600 });
    } catch (err) {
      log.warn(`Could not persist triage store: ${(err as Error).message}`);
    }
  }

  #getOrCreate(id: string): TriageEntry {
    this.#ensure();
    let e = this.#map.get(id);
    if (!e) {
      e = { id, status: "open", notes: [], updatedAt: Date.now() };
      this.#map.set(id, e);
    }
    return e;
  }

  get(id: string): TriageEntry | undefined {
    this.#ensure();
    return this.#map.get(id);
  }

  /** Get triage state with defaults applied (never undefined). */
  view(id: string): TriageEntry {
    this.#ensure();
    const e = this.#map.get(id);
    if (e) return e;
    return { id, status: "open", notes: [], updatedAt: 0 };
  }

  setStatus(id: string, status: TriageStatus): TriageEntry {
    const e = this.#getOrCreate(id);
    if (e.status !== status) {
      e.status = status;
      e.updatedAt = Date.now();
      this.#persist();
    }
    return e;
  }

  addNote(id: string, rawText: string): TriageNote | null {
    const text = (rawText ?? "").toString().trim().slice(0, MAX_NOTE_LEN);
    if (!text) return null;
    const e = this.#getOrCreate(id);
    const note: TriageNote = {
      noteId: randomBytes(6).toString("hex"),
      at: Date.now(),
      text,
    };
    e.notes.push(note);
    if (e.notes.length > MAX_NOTES_PER_ALERT) {
      e.notes.splice(0, e.notes.length - MAX_NOTES_PER_ALERT);
    }
    e.updatedAt = note.at;
    this.#persist();
    return note;
  }

  /** Per-status counts across the whole store (useful for header chips). */
  counts(): Record<TriageStatus, number> & { total: number } {
    this.#ensure();
    const out = { open: 0, investigating: 0, resolved: 0, "false-positive": 0, total: 0 } as Record<
      TriageStatus,
      number
    > & { total: number };
    for (const e of this.#map.values()) {
      out[e.status]++;
      out.total++;
    }
    return out;
  }
}

export const triageStore = new TriageStore();
