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
  localAddr?: string; // present on agent v1.0.2+ — which interface the socket is bound to
  localPort: number;
  remoteIp: string;
  remotePort: number;
  state: string;
  pid: number;
  process: string;
  path: string;
  sha256?: string; // agent v1.3.0+
  cmdline?: string;
  ppid?: number;
  parent?: string;
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

export async function agentSetConfig(
  cfg: Config,
  host: string,
  patch: { allowKill?: boolean },
): Promise<{ ok: boolean; host?: string; allowKill?: boolean; persisted?: boolean; error?: string }> {
  if (isIP(host) === 0 || !isPrivate(host)) return { ok: false, error: "Agent config is only allowed for internal LAN hosts." };
  if (!cfg.agent.token) return { ok: false, error: "No AGENT_TOKEN configured on the SecTool side." };
  try {
    const r = await fetch(`http://${host}:${cfg.agent.port}/config`, {
      method: "POST",
      headers: { ...authHeaders(cfg), "content-type": "application/json" },
      body: JSON.stringify(patch),
      signal: AbortSignal.timeout(6000),
    });
    const data = (await r.json().catch(() => ({}))) as Record<string, unknown>;
    if (r.status === 401) return { ok: false, error: "Agent rejected the token." };
    if (!r.ok) return { ok: false, error: (data["error"] as string) || `Agent returned HTTP ${r.status}.` };
    return { ok: true, host: data["host"] as string, allowKill: data["allowKill"] as boolean, persisted: data["persisted"] as boolean };
  } catch (err) {
    return { ok: false, error: `No agent reachable on ${host}:${cfg.agent.port} (${(err as Error).message})` };
  }
}

export interface KillResult {
  pid: number;
  process?: string;
  killed: boolean;
  error?: string;
  path?: string;
  deleted?: boolean;
  deleteError?: string;
}

export async function agentKillProcess(
  cfg: Config,
  host: string,
  params: { pid?: number; process?: string; signal?: "SIGTERM" | "SIGKILL"; deleteFile?: boolean },
): Promise<{ ok: boolean; host?: string; signal?: string; deleteFile?: boolean; results?: KillResult[]; error?: string }> {
  if (isIP(host) === 0 || !isPrivate(host)) return { ok: false, error: "Process kill is only allowed on internal LAN hosts." };
  if (!cfg.agent.token) return { ok: false, error: "Refusing to kill: no AGENT_TOKEN configured on the SecTool side." };
  const hasPid = Number.isInteger(params.pid) && (params.pid as number) > 0;
  if (!hasPid && !params.process) return { ok: false, error: "Provide a pid or a process name." };
  const signal = params.signal === "SIGKILL" ? "SIGKILL" : "SIGTERM";
  try {
    const r = await fetch(`http://${host}:${cfg.agent.port}/kill`, {
      method: "POST",
      headers: { ...authHeaders(cfg), "content-type": "application/json" },
      body: JSON.stringify({ pid: hasPid ? params.pid : undefined, process: params.process, signal, deleteFile: !!params.deleteFile }),
      signal: AbortSignal.timeout(12000),
    });
    const data = (await r.json().catch(() => ({}))) as Record<string, unknown>;
    if (r.status === 401) return { ok: false, error: "Agent rejected the token." };
    if (!r.ok) return { ok: false, error: (data["error"] as string) || `Agent returned HTTP ${r.status}.` };
    return { ok: true, host: data["host"] as string, signal: data["signal"] as string, deleteFile: data["deleteFile"] as boolean, results: (data["results"] as KillResult[]) ?? [] };
  } catch (err) {
    return { ok: false, error: `No agent reachable on ${host}:${cfg.agent.port} (${(err as Error).message})` };
  }
}

export async function agentTriage(cfg: Config, host: string): Promise<{ ok: boolean; data?: unknown; error?: string }> {
  return call(cfg, host, "/triage", 60000);
}

export async function agentDns(cfg: Config, host: string): Promise<{ ok: boolean; data?: unknown; error?: string }> {
  return call(cfg, host, "/dns", 15000);
}

export async function agentProcess(cfg: Config, host: string, pid: number): Promise<{ ok: boolean; data?: unknown; error?: string }> {
  if (!Number.isInteger(pid) || pid <= 0) return { ok: false, error: "invalid pid" };
  return call(cfg, host, `/process?pid=${pid}`, 25000);
}

export async function agentAutoruns(cfg: Config, host: string): Promise<{ ok: boolean; host?: string; autoruns?: unknown[]; error?: string }> {
  const r = await call(cfg, host, "/autoruns", 12000);
  if (!r.ok) return { ok: false, error: r.error };
  const d = r.data as { host?: string; autoruns?: unknown[] };
  return { ok: true, host: d.host, autoruns: d.autoruns ?? [] };
}

async function post(cfg: Config, host: string, path: string, body: unknown, timeoutMs = 12000): Promise<{ ok: boolean; data?: unknown; error?: string }> {
  if (isIP(host) === 0 || !isPrivate(host)) return { ok: false, error: "Action is only allowed on internal LAN hosts." };
  if (!cfg.agent.token) return { ok: false, error: "Refusing: no AGENT_TOKEN configured on the SecTool side." };
  try {
    const r = await fetch(`http://${host}:${cfg.agent.port}${path}`, {
      method: "POST",
      headers: { ...authHeaders(cfg), "content-type": "application/json" },
      body: JSON.stringify(body ?? {}),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const data = (await r.json().catch(() => ({}))) as Record<string, unknown>;
    if (r.status === 401) return { ok: false, error: "Agent rejected the token." };
    if (!r.ok) return { ok: false, error: (data["error"] as string) || `Agent returned HTTP ${r.status}.` };
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: `No agent reachable on ${host}:${cfg.agent.port} (${(err as Error).message})` };
  }
}

export async function agentIsolate(cfg: Config, host: string, release: boolean): Promise<{ ok: boolean; data?: unknown; error?: string }> {
  return post(cfg, host, release ? "/release" : "/isolate", {});
}

export async function agentRemoveAutorun(cfg: Config, host: string, entry: Record<string, unknown>): Promise<{ ok: boolean; data?: unknown; error?: string }> {
  return post(cfg, host, "/autoruns/remove", entry);
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
