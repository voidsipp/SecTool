/**
 * Suppresses repeat notifications for the same alert identity within a window.
 * UDM Pro / Suricata frequently re-fire the same signature for the same flow.
 */
export class Deduper {
  readonly #windowMs: number;
  readonly #lastSeen = new Map<string, number>();
  #suppressed = 0;

  constructor(windowMs: number) {
    this.#windowMs = windowMs;
  }

  /** Returns true if this id should be sent now (and records it). */
  shouldSend(id: string, now: number): boolean {
    if (this.#windowMs <= 0) return true;
    const last = this.#lastSeen.get(id);
    if (last !== undefined && now - last < this.#windowMs) {
      this.#suppressed++;
      return false;
    }
    this.#lastSeen.set(id, now);
    return true;
  }

  /** Drop expired entries to bound memory. */
  prune(now: number): void {
    for (const [id, ts] of this.#lastSeen) {
      if (now - ts >= this.#windowMs) this.#lastSeen.delete(id);
    }
  }

  get suppressedCount(): number {
    return this.#suppressed;
  }
}
