/**
 * Client for the SecTool endpoint agent. Queries an agent running on an internal
 * host to attribute a connection/port to the owning process. Only LAN/private
 * hosts may be queried (we never let the dashboard make SecTool fetch arbitrary
 * external URLs).
 */
import { isIP } from "node:net";
import type { Config } from "../config.ts";

export interface AgentMatch {
  proto: string;
  localPort: number;
  remoteIp: string;
  remotePort: number;
  state: string;
  pid: number;
  process: string;
  path: string;
  firstSeen: number;
  lastSeen: number;
}

function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/.test(ip);
}

function authHeaders(cfg: Config): Record<string, string> {
  return cfg.agent.token ? { authorization: `Bearer ${cfg.agent.token}` } : {};
}

async function call(cfg: Config, host: string, path: string, timeoutMs = 6000): Promise<{ ok: boolean; data?: unknown; error?: string }> {
  if (isIP(host) === 0 || !isPrivate(host)) return { ok: false, error: "Agent lookups are only allowed for internal LAN hosts." };
  try {
    const r = await fetch(`http://${host}:${cfg.agent.port}${path}`, {
      headers: authHeaders(cfg),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (r.status === 401) return { ok: false, error: "Agent rejected the token (check AGENT_TOKEN matches)." };
    if (!r.ok) return { ok: false, error: `Agent on ${host} returned HTTP ${r.status}.` };
    return { ok: true, data: await r.json() };
  } catch (err) {
    return { ok: false, error: `No agent reachable on ${host}:${cfg.agent.port} — is it installed/running? (${(err as Error).message})` };
  }
}

export async function agentHealth(cfg: Config, host: string, timeoutMs = 2500): Promise<{ ok: boolean; data?: unknown; error?: string }> {
  return call(cfg, host, "/health", timeoutMs);
}

export async function agentConnections(cfg: Config, host: string): Promise<{ ok: boolean; host?: string; connections?: AgentMatch[]; error?: string }> {
  const r = await call(cfg, host, "/connections", 8000);
  if (!r.ok) return { ok: false, error: r.error };
  const d = r.data as { host?: string; connections?: AgentMatch[] };
  return { ok: true, host: d.host, connections: d.connections ?? [] };
}

export async function agentLookup(
  cfg: Config,
  host: string,
  params: { remoteIp?: string; remotePort?: number; localPort?: number; proto?: string },
): Promise<{ ok: boolean; host?: string; matches?: AgentMatch[]; error?: string }> {
  const qs = new URLSearchParams();
  if (params.remoteIp && isIP(params.remoteIp) > 0) qs.set("remoteIp", params.remoteIp);
  if (params.remotePort) qs.set("remotePort", String(params.remotePort));
  if (params.localPort) qs.set("localPort", String(params.localPort));
  if (params.proto) qs.set("proto", params.proto);
  const r = await call(cfg, host, `/lookup?${qs.toString()}`);
  if (!r.ok) return { ok: false, error: r.error };
  const d = r.data as { host?: string; matches?: AgentMatch[] };
  return { ok: true, host: d.host, matches: d.matches ?? [] };
}
