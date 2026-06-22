/**
 * In-memory, time-bounded store of collected flows. Capped by count and age so
 * memory stays bounded; queryable by host + time window for investigations.
 */
import type { Flow } from "./ipfix.ts";

export class FlowStore {
  #flows: Flow[] = [];
  readonly #max: number;
  readonly #ttlMs: number;
  #total = 0;

  constructor(maxFlows: number, retentionMinutes: number) {
    this.#max = Math.max(1000, maxFlows);
    this.#ttlMs = retentionMinutes * 60_000;
  }

  add(flows: Flow[]): void {
    for (const f of flows) this.#flows.push(f);
    this.#total += flows.length;
    if (this.#flows.length > this.#max) {
      this.#flows.splice(0, this.#flows.length - this.#max);
    }
  }

  prune(now: number): void {
    if (this.#ttlMs <= 0) return;
    const cutoff = now - this.#ttlMs;
    let i = 0;
    while (i < this.#flows.length && (this.#flows[i]!.end ?? this.#flows[i]!.receivedAt) < cutoff) i++;
    if (i > 0) this.#flows.splice(0, i);
  }

  /** Flows involving any of `ips` whose lifetime overlaps [lo, hi]. */
  query(ips: string[], lo: number, hi: number, limit = 500): Flow[] {
    const set = new Set(ips.map((s) => s.toLowerCase()));
    const out: Flow[] = [];
    for (let i = this.#flows.length - 1; i >= 0 && out.length < limit; i--) {
      const f = this.#flows[i]!;
      const s = f.start ?? f.receivedAt;
      const e = f.end ?? f.receivedAt;
      if (e < lo || s > hi) continue;
      if (set.size && !(f.srcIp && set.has(f.srcIp.toLowerCase())) && !(f.dstIp && set.has(f.dstIp.toLowerCase())))
        continue;
      out.push(f);
    }
    return out;
  }

  /** All flows involving any of `ips` (no time bound) — for full-history pulls. */
  queryAll(ips: string[], limit = 5000): Flow[] {
    const set = new Set(ips.map((s) => s.toLowerCase()));
    const out: Flow[] = [];
    for (let i = this.#flows.length - 1; i >= 0 && out.length < limit; i--) {
      const f = this.#flows[i]!;
      if (!set.size || (f.srcIp && set.has(f.srcIp.toLowerCase())) || (f.dstIp && set.has(f.dstIp.toLowerCase())))
        out.push(f);
    }
    return out;
  }

  /** Time span of retained data, for "expand to as far as we have" UI. */
  dataRange(): { earliest: number | null; latest: number | null } {
    if (this.#flows.length === 0) return { earliest: null, latest: null };
    let earliest = Infinity;
    let latest = -Infinity;
    for (const f of this.#flows) {
      const s = f.start ?? f.receivedAt;
      const e = f.end ?? f.receivedAt;
      if (s < earliest) earliest = s;
      if (e > latest) latest = e;
    }
    return { earliest, latest };
  }

  snapshot(): Flow[] {
    return this.#flows;
  }

  load(flows: Flow[], now: number): void {
    this.#flows = flows;
    this.prune(now);
  }

  get size(): number {
    return this.#flows.length;
  }
  get total(): number {
    return this.#total;
  }
}
