/**
 * Gathers the log context relevant to an alert: other buffered events within a
 * time window that involve the same source/destination hosts.
 */
import type { Config } from "../config.ts";
import type { CorrelatedContext, LogEvent, SecurityAlert } from "../types.ts";
import type { LogBuffer } from "../ingest/logBuffer.ts";

export function correlate(alert: SecurityAlert, buffer: LogBuffer, cfg: Config): CorrelatedContext {
  const { windowMs, maxEvents } = cfg.correlation;
  const anchor = alert.event.timestamp ?? alert.event.receivedAt;

  // IPs of interest: the alert's endpoints plus anything found in its raw line.
  const involved = new Set<string>();
  for (const ip of [alert.srcIp, alert.dstIp, ...alert.event.ips]) {
    if (ip) involved.add(ip.toLowerCase());
  }

  const related: LogEvent[] = [];
  for (const ev of buffer.snapshot()) {
    if (ev === alert.event) continue;
    const t = ev.timestamp ?? ev.receivedAt;
    if (Math.abs(t - anchor) > windowMs) continue;
    const shares = ev.ips.some((ip) => involved.has(ip.toLowerCase()));
    if (shares) related.push(ev);
  }

  // Most recent first, capped.
  related.sort((a, b) => (b.timestamp ?? b.receivedAt) - (a.timestamp ?? a.receivedAt));
  const trimmed = related.slice(0, maxEvents);

  return {
    alert,
    relatedEvents: trimmed,
    involvedIps: [...involved],
  };
}
