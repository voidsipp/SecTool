/**
 * Lightweight JSON-file store of processed alerts + their Claude summaries, so
 * the web dashboard can show AI analysis and notification history. Capped and
 * rotated; zero external dependencies.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import type { AlertSummary, SecurityAlert } from "../types.ts";
import { log } from "../logger.ts";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const DATA_DIR = join(ROOT, "data");
const STORE_PATH = join(DATA_DIR, "alerts.json");
const MAX_ENTRIES = 2000;

/**
 * The store's hard capacity. Once this many alerts accumulate the oldest are
 * evicted on the next persist (see {@link AlertStore} `#persist`), so any
 * look-back longer than the retained history is silently truncated. Exported so
 * the offline coverage / data-quality report can warn when the store is at (or
 * near) this cap and downstream reports may be reading an incomplete history.
 */
export const ALERT_STORE_CAP = MAX_ENTRIES;

export interface StoredAlert {
  id: string;
  time: number;
  severity: string;
  category: string;
  signature?: string;
  srcIp?: string;
  dstIp?: string;
  action?: string;
  classification?: string;
  raw: string;
  summary?: AlertSummary;
  notifiedAt?: number;
}

class AlertStore {
  #byId = new Map<string, StoredAlert>();
  #loaded = false;

  #ensureLoaded(): void {
    if (this.#loaded) return;
    this.#loaded = true;
    if (!existsSync(STORE_PATH)) return;
    try {
      const arr = JSON.parse(readFileSync(STORE_PATH, "utf8")) as StoredAlert[];
      for (const a of arr) if (a?.id) this.#byId.set(a.id, a);
    } catch (err) {
      log.warn(`Could not load alert store: ${(err as Error).message}`);
    }
  }

  #persist(): void {
    try {
      if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
      let all = [...this.#byId.values()].sort((a, b) => a.time - b.time);
      if (all.length > MAX_ENTRIES) {
        all = all.slice(all.length - MAX_ENTRIES);
        this.#byId = new Map(all.map((a) => [a.id, a]));
      }
      writeFileSync(STORE_PATH, JSON.stringify(all), { mode: 0o600 });
    } catch (err) {
      log.warn(`Could not persist alert store: ${(err as Error).message}`);
    }
  }

  /** Record (or update) an alert and its summary after processing. */
  record(alert: SecurityAlert, summary: AlertSummary | undefined, notified: boolean): void {
    this.#ensureLoaded();
    const existing = this.#byId.get(alert.id);
    const stored: StoredAlert = {
      id: alert.id,
      time: alert.event.timestamp ?? alert.event.receivedAt,
      severity: alert.severity,
      category: alert.category,
      signature: alert.signature,
      srcIp: alert.srcIp,
      dstIp: alert.dstIp,
      action: alert.action,
      classification: alert.classification,
      raw: alert.event.raw,
      summary: summary ?? existing?.summary,
      notifiedAt: notified ? Date.now() : existing?.notifiedAt,
    };
    this.#byId.set(alert.id, stored);
    this.#persist();
  }

  getSummary(id: string): AlertSummary | undefined {
    this.#ensureLoaded();
    return this.#byId.get(id)?.summary;
  }

  setSummary(id: string, summary: AlertSummary): void {
    this.#ensureLoaded();
    const cur = this.#byId.get(id);
    if (cur) {
      cur.summary = summary;
      this.#persist();
    }
  }

  get(id: string): StoredAlert | undefined {
    this.#ensureLoaded();
    return this.#byId.get(id);
  }

  all(): StoredAlert[] {
    this.#ensureLoaded();
    return [...this.#byId.values()].sort((a, b) => b.time - a.time);
  }
}

export const alertStore = new AlertStore();
