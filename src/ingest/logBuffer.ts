/**
 * Fixed-capacity, TTL-pruned ring buffer of recent LogEvents. Used to enrich an
 * alert with the log context that surrounds it.
 */
import type { LogEvent } from "../types.ts";

export class LogBuffer {
  #events: LogEvent[] = [];
  readonly #capacity: number;
  readonly #ttlMs: number;

  constructor(capacity: number, ttlMs: number) {
    this.#capacity = Math.max(1, capacity);
    this.#ttlMs = ttlMs;
  }

  push(event: LogEvent): void {
    this.#events.push(event);
    if (this.#events.length > this.#capacity) {
      this.#events.splice(0, this.#events.length - this.#capacity);
    }
  }

  /** Drop events older than the TTL relative to `now`. */
  prune(now: number): void {
    if (this.#ttlMs <= 0) return;
    const cutoff = now - this.#ttlMs;
    let i = 0;
    while (i < this.#events.length && (this.#events[i]!.receivedAt < cutoff)) i++;
    if (i > 0) this.#events.splice(0, i);
  }

  /** Snapshot of buffered events (most-recent-last). */
  snapshot(): readonly LogEvent[] {
    return this.#events;
  }

  get size(): number {
    return this.#events.length;
  }
}
