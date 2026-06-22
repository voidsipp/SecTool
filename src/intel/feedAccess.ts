/**
 * Decoupled accessor for feed cross-referencing, so enrichment/notify code can
 * check an IP against the loaded feeds without importing the (SSH-heavy) feed
 * module and creating an import cycle.
 */
import { isIP } from "node:net";

let matcher: ((ip: string) => string[]) | null = null;

export function setFeedMatcher(fn: ((ip: string) => string[]) | null): void {
  matcher = fn;
}

export function feedMatch(ip: string): string[] {
  return matcher && isIP(ip) === 4 ? matcher(ip) : [];
}

export function feedsLoaded(): boolean {
  return !!matcher;
}
