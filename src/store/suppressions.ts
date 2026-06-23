/**
 * Pattern-based alert suppression rules.
 *
 * Distinct from dismiss (which hides a single alert id), blocklist (firewall
 * enforcement) and triage (per-alert workflow): a suppression rule silences
 * *future* alerts matching a pattern so noisy detections do not page the
 * operator on Discord. Matched alerts are still detected and visible in the
 * dashboard (with a "suppressed" badge); only summarization + notification
 * are short-circuited.
 *
 * A rule can match on any combination of:
 *   - signature   (case-insensitive substring of alert.signature)
 *   - category    (case-insensitive exact match)
 *   - srcIp       (exact)
 *   - dstIp       (exact)
 *   - maxSeverity (alert.severity must be <= this level on SEVERITY_ORDER)
 *
 * All non-empty fields are ANDed. A rule with zero match fields is rejected.
 * Rules may carry an optional expiresAt (ms epoch) and are auto-pruned.
 *
 * Stored as data/suppressions.json alongside the other persistent stores.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { log } from "../logger.ts";
import { SEVERITY_ORDER, type Severity, type SecurityAlert } from "../types.ts";

const DATA_DIR = fileURLToPath(new URL("../../data", import.meta.url));
const STORE_PATH = join(DATA_DIR, "suppressions.json");

export interface SuppressionMatch {
  signature?: string;
  category?: string;
  srcIp?: string;
  dstIp?: string;
  maxSeverity?: Severity;
}

export interface SuppressionRule {
  id: string;
  createdAt: number;
  expiresAt?: number;
  reason?: string;
  match: SuppressionMatch;
  hitCount: number;
  lastHitAt?: number;
}

export interface SuppressionInput {
  signature?: string;
  category?: string;
  srcIp?: string;
  dstIp?: string;
  maxSeverity?: Severity;
  reason?: string;
  /** Time-to-live in ms; if positive, rule auto-expires after this many ms from creation. */
  ttlMs?: number;
}

const MAX_REASON_LEN = 200;
const MAX_FIELD_LEN = 160;

function isSeverity(v: unknown): v is Severity {
  return typeof v === "string" && (SEVERITY_ORDER as readonly string[]).includes(v);
}

function clean(s: unknown): string | undefined {
  if (typeof s !== "string") return undefined;
  const t = s.trim().slice(0, MAX_FIELD_LEN);
  return t || undefined;
}

/** Build & validate a SuppressionMatch from raw input. Returns null if nothing matchable. */
export function buildMatch(input: SuppressionInput): SuppressionMatch | null {
  const m: SuppressionMatch = {};
  const sig = clean(input.signature);
  if (sig) m.signature = sig;
  const cat = clean(input.category);
  if (cat) m.category = cat;
  const src = clean(input.srcIp);
  if (src) m.srcIp = src;
  const dst = clean(input.dstIp);
  if (dst) m.dstIp = dst;
  if (isSeverity(input.maxSeverity)) m.maxSeverity = input.maxSeverity;
  if (!m.signature && !m.category && !m.srcIp && !m.dstIp && !m.maxSeverity) return null;
  return m;
}

function severityIdx(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

function ruleMatches(rule: SuppressionRule, alert: SecurityAlert, now: number): boolean {
  if (rule.expiresAt && rule.expiresAt <= now) return false;
  const m = rule.match;
  if (m.signature) {
    const sig = (alert.signature ?? "").toLowerCase();
    if (!sig.includes(m.signature.toLowerCase())) return false;
  }
  if (m.category) {
    if ((alert.category ?? "").toLowerCase() !== m.category.toLowerCase()) return false;
  }
  if (m.srcIp && alert.srcIp !== m.srcIp) return false;
  if (m.dstIp && alert.dstIp !== m.dstIp) return false;
  if (m.maxSeverity) {
    if (severityIdx(alert.severity) > severityIdx(m.maxSeverity)) return false;
  }
  return true;
}

function describeMatch(m: SuppressionMatch): string {
  const parts: string[] = [];
  if (m.signature) parts.push(`sig~"${m.signature}"`);
  if (m.category) parts.push(`cat=${m.category}`);
  if (m.srcIp) parts.push(`src=${m.srcIp}`);
  if (m.dstIp) parts.push(`dst=${m.dstIp}`);
  if (m.maxSeverity) parts.push(`sev<=${m.maxSeverity}`);
  return parts.join(" & ");
}

class SuppressionStore {
  #map = new Map<string, SuppressionRule>();
  #loaded = false;

  #ensure(): void {
    if (this.#loaded) return;
    this.#loaded = true;
    if (!existsSync(STORE_PATH)) return;
    try {
      const arr = JSON.parse(readFileSync(STORE_PATH, "utf8")) as SuppressionRule[];
      for (const e of arr) {
        if (!e?.id || !e.match) continue;
        const m = buildMatch(e.match);
        if (!m) continue;
        this.#map.set(e.id, {
          id: e.id,
          createdAt: typeof e.createdAt === "number" ? e.createdAt : Date.now(),
          expiresAt: typeof e.expiresAt === "number" ? e.expiresAt : undefined,
          reason: typeof e.reason === "string" ? e.reason : undefined,
          match: m,
          hitCount: typeof e.hitCount === "number" ? e.hitCount : 0,
          lastHitAt: typeof e.lastHitAt === "number" ? e.lastHitAt : undefined,
        });
      }
    } catch (err) {
      log.warn(`Could not load suppression store: ${(err as Error).message}`);
    }
  }

  #persist(): void {
    try {
      if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
      writeFileSync(STORE_PATH, JSON.stringify([...this.#map.values()]), { mode: 0o600 });
    } catch (err) {
      log.warn(`Could not persist suppression store: ${(err as Error).message}`);
    }
  }

  #prune(now: number): boolean {
    let changed = false;
    for (const [id, rule] of this.#map) {
      if (rule.expiresAt && rule.expiresAt <= now) {
        this.#map.delete(id);
        changed = true;
      }
    }
    return changed;
  }

  add(input: SuppressionInput): SuppressionRule | null {
    this.#ensure();
    const match = buildMatch(input);
    if (!match) return null;
    const now = Date.now();
    const ttl = typeof input.ttlMs === "number" && input.ttlMs > 0 ? Math.floor(input.ttlMs) : undefined;
    const rule: SuppressionRule = {
      id: randomBytes(6).toString("hex"),
      createdAt: now,
      expiresAt: ttl ? now + ttl : undefined,
      reason: clean(input.reason)?.slice(0, MAX_REASON_LEN),
      match,
      hitCount: 0,
    };
    this.#map.set(rule.id, rule);
    this.#persist();
    return rule;
  }

  remove(id: string): boolean {
    this.#ensure();
    const had = this.#map.delete(id);
    if (had) this.#persist();
    return had;
  }

  /** Return the first rule that matches this alert, or undefined. Auto-prunes expired rules. */
  matchAlert(alert: SecurityAlert, now: number = Date.now()): SuppressionRule | undefined {
    this.#ensure();
    if (this.#prune(now)) this.#persist();
    for (const rule of this.#map.values()) {
      if (ruleMatches(rule, alert, now)) return rule;
    }
    return undefined;
  }

  /** Increment hit counter for a rule and persist. */
  recordHit(id: string, now: number = Date.now()): void {
    this.#ensure();
    const rule = this.#map.get(id);
    if (!rule) return;
    rule.hitCount++;
    rule.lastHitAt = now;
    this.#persist();
  }

  all(): SuppressionRule[] {
    this.#ensure();
    if (this.#prune(Date.now())) this.#persist();
    return [...this.#map.values()].sort((a, b) => b.createdAt - a.createdAt);
  }

  count(): number {
    this.#ensure();
    if (this.#prune(Date.now())) this.#persist();
    return this.#map.size;
  }
}

export const suppressionStore = new SuppressionStore();
export { describeMatch };
