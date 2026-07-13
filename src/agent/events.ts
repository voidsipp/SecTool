/**
 * In-memory ring buffer of real-time events pushed by endpoint agents
 * (feature #3). The LAN-bound dist server records into it; the localhost
 * dashboard reads from it via GET /api/agent/events. Process-local (both
 * servers run in the same SecTool process).
 */
export interface AgentEvent {
  type: string; // "new-external-connection" | "new-listener"
  host: string;
  time: number;
  process?: string;
  pid?: number;
  path?: string;
  sha256?: string;
  cmdline?: string;
  parent?: string;
  localPort?: number;
  remoteIp?: string;
  remotePort?: number;
  receivedAt: number;
}

const MAX = 500;
const events: AgentEvent[] = [];

export function recordAgentEvent(e: Omit<AgentEvent, "receivedAt">): void {
  events.push({ ...e, receivedAt: Date.now() });
  if (events.length > MAX) events.splice(0, events.length - MAX);
}

export function recentAgentEvents(limit = 100): AgentEvent[] {
  return events.slice(-limit).reverse();
}

export function agentEventCount(): number {
  return events.length;
}
