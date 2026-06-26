/**
 * Agent push-deployment.
 *
 * Auto-discovery (discovery.ts) enumerates every device on the LAN and flags the
 * ones that *support* an unattended agent install — i.e. they expose SSH and are
 * not already running the agent. This module performs that install: it SSHes into
 * a discovered host and runs SecTool's own one-liner installer, which downloads
 * the agent from the dist server (distServer.ts), writes the embedded token/port
 * config, and registers it as a service. After the install it polls the device's
 * agent /health to confirm the agent came up.
 *
 * Transport is the system `ssh` client (same approach as ingest/sshPull.ts) using
 * key auth by default — fully non-interactive. A per-request password is only used
 * when `sshpass` is available on this host; otherwise key auth is required.
 *
 * Safety:
 *   - Only RFC1918 / link-local IPv4 targets are ever accepted; SecTool can never
 *     be pointed at the WAN.
 *   - Deployment is opt-in (DEPLOY_ENABLED) because it installs software remotely.
 *   - The dist server (AGENT_ENABLED) must be running so the target has something
 *     to download from, and AGENT_TOKEN should be set so the agent API is authed.
 */
import { spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { isIP } from "node:net";
import type { Config } from "../config.ts";
import { log } from "../logger.ts";
import { agentHealth } from "../agent/agentClient.ts";
import { localIpv4, discoverDevices, type DiscoveredDevice } from "./discovery.ts";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
/** The key SecTool generates for UDM pulls — reused for deploys when present. */
const SECTOOL_KEY = join(ROOT, ".ssh", "sectool_udm");

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// Address helpers (kept local; mirror discovery.ts so this module stands alone)
// ---------------------------------------------------------------------------

function isPrivateV4(ip: string): boolean {
  return (
    /^10\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^169\.254\./.test(ip)
  );
}

function ipToInt(ip: string): number {
  return ip.split(".").reduce((acc, o) => ((acc << 8) | (Number(o) & 0xff)) >>> 0, 0) >>> 0;
}

/** Pick the local IPv4 address the target can reach SecTool on (same subnet wins). */
function pickServerIp(cfg: Config, targetIp: string): string | undefined {
  if (cfg.deploy.serverIp && isIP(cfg.deploy.serverIp) === 4) return cfg.deploy.serverIp;
  if (cfg.netflow.advertiseIp && isPrivateV4(cfg.netflow.advertiseIp)) return cfg.netflow.advertiseIp;
  const locals = localIpv4().filter((l) => isPrivateV4(l.ip));
  if (!locals.length) return undefined;
  const tgt = ipToInt(targetIp);
  for (const l of locals) {
    const mask = l.prefix === 0 ? 0 : (0xffffffff << (32 - Math.min(l.prefix, 32))) >>> 0;
    if (((ipToInt(l.ip) & mask) >>> 0) === ((tgt & mask) >>> 0)) return l.ip;
  }
  return locals[0]!.ip;
}

/** Resolve the SSH identity file to use, if any (explicit override, else the UDM key). */
function resolveIdentity(cfg: Config): string | undefined {
  if (cfg.deploy.identityFile) return cfg.deploy.identityFile;
  if (existsSync(SECTOOL_KEY)) return SECTOOL_KEY;
  return undefined; // fall back to the user's ssh-agent / default keys
}

function hasSshpass(): boolean {
  try {
    const r = spawnSync("sshpass", ["-V"], { stdio: "ignore" });
    return r.status === 0 || r.status === 1; // -V prints version; some builds exit 1
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Eligibility
// ---------------------------------------------------------------------------

/** Automated push transports, in preference order. */
export type DeployMethod = "ssh" | "winrm";

export interface DeployEligibility {
  eligible: boolean;
  /** Transport we'd use. "ssh"/"winrm" are automated; "manual"/"none" are not. */
  method: DeployMethod | "manual" | "none";
  reason: string;
}

/**
 * Decide whether a discovered device supports an unattended agent push. A device
 * is eligible when it is a real LAN host, isn't this machine, isn't already
 * running the agent, and exposes a transport we can deploy over.
 *
 * SSH is preferred (cross-platform, key auth). For Windows hosts that don't run
 * an SSH server we fall back to WinRM (PowerShell Remoting on :5985/:5986), which
 * answers the common "device has no SSH" case — the dist server already serves a
 * PowerShell one-liner (/install.ps1) we can run remotely.
 */
export function assessDeploy(cfg: Config, d: DiscoveredDevice): DeployEligibility {
  if (d.isSelf) return { eligible: false, method: "none", reason: "this host" };
  if (d.hasAgentPort) return { eligible: false, method: "none", reason: "agent already installed" };
  if (!isPrivateV4(d.ip)) return { eligible: false, method: "none", reason: "not a private LAN host" };
  const sshPort = cfg.deploy.sshPort || 22;
  if (d.openPorts.includes(sshPort)) {
    return { eligible: true, method: "ssh", reason: `SSH reachable on :${sshPort}` };
  }
  const winrmPort = cfg.deploy.winrmPort || 5985;
  if (cfg.deploy.winrmEnabled && d.openPorts.includes(winrmPort)) {
    return { eligible: true, method: "winrm", reason: `no SSH — WinRM reachable on :${winrmPort}` };
  }
  if (d.alive) {
    return { eligible: false, method: "manual", reason: `no SSH/WinRM — use the one-liner installer` };
  }
  return { eligible: false, method: "none", reason: "host did not respond to the sweep" };
}

// ---------------------------------------------------------------------------
// Deploy
// ---------------------------------------------------------------------------

export interface DeployStep {
  name: string;
  ok: boolean;
  detail?: string;
}

export interface DeployResult {
  ok: boolean;
  host: string;
  method: DeployMethod;
  serverUrl?: string;
  user?: string;
  durationMs: number;
  steps: DeployStep[];
  agentVersion?: string;
  error?: string;
  /** Tail of the installer output (truncated), for troubleshooting in the UI. */
  output?: string;
}

export interface DeployOptions {
  /** Transport to use. Defaults to "ssh"; the web/batch layer derives it from assessDeploy. */
  method?: DeployMethod;
  user?: string;
  port?: number;
  /** Per-request SSH password (only used if `sshpass` is installed locally). */
  password?: string;
  /** WinRM credentials (kept separate so a mixed LAN can carry both cred sets). */
  winUser?: string;
  winPassword?: string;
  winPort?: number;
  /** Deploy even if the transport's port wasn't observed open during discovery. */
  force?: boolean;
}

function tail(text: string, max = 4000): string {
  const t = text.trim();
  return t.length > max ? `…${t.slice(-max)}` : t;
}

/** Build the remote shell command that fetches + runs the install.sh one-liner. */
function remoteInstallCommand(serverUrl: string): string {
  const url = `${serverUrl}/install.sh`;
  // serverUrl is http://<ipv4>:<port> (validated by the caller) — no shell metachars.
  return (
    `sh -c 'set -e; ` +
    `if command -v curl >/dev/null 2>&1; then curl -fsSL "${url}" | bash; ` +
    `elif command -v wget >/dev/null 2>&1; then wget -qO- "${url}" | bash; ` +
    `else echo "neither curl nor wget is available on this host" >&2; exit 3; fi'`
  );
}

function runSsh(
  cfg: Config,
  host: string,
  user: string,
  port: number,
  remote: string,
  opts: { password?: string },
): Promise<{ code: number | null; output: string }> {
  const sshArgs = [
    "-o",
    "StrictHostKeyChecking=accept-new",
    "-o",
    "ConnectTimeout=15",
    "-o",
    "ServerAliveInterval=5",
    "-o",
    "ServerAliveCountMax=3",
    "-p",
    String(port),
  ];
  let cmd: string;
  let args: string[];
  if (opts.password && hasSshpass()) {
    // sshpass feeds the password to ssh's prompt; disable key-only batch mode.
    sshArgs.push("-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password");
    cmd = "sshpass";
    args = ["-p", opts.password, "ssh", ...sshArgs, `${user}@${host}`, remote];
  } else {
    // Non-interactive key auth.
    sshArgs.unshift("-o", "BatchMode=yes");
    const identity = resolveIdentity(cfg);
    if (identity) sshArgs.push("-i", identity);
    cmd = "ssh";
    args = [...sshArgs, `${user}@${host}`, remote];
  }

  return new Promise((resolve, reject) => {
    let out = "";
    const child = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (d: string) => (out += d));
    child.stderr.on("data", (d: string) => (out += d));
    const timer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        /* ignore */
      }
      resolve({ code: null, output: out + "\n[timed out]" });
    }, cfg.deploy.timeoutMs);
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, output: out });
    });
  });
}

/** Poll the device's agent /health until it answers (or we give up). */
async function verifyAgent(cfg: Config, host: string): Promise<string | undefined> {
  for (let i = 0; i < 6; i++) {
    const h = await agentHealth(cfg, host, 2500);
    if (h.ok && h.data) {
      const v = (h.data as Record<string, unknown>)["version"];
      return typeof v === "string" ? v : "unknown";
    }
    await sleep(2000);
  }
  return undefined;
}

/**
 * Push the SecTool endpoint agent to a single discovered host. Dispatches to the
 * requested transport (SSH by default; WinRM for Windows hosts without SSH) and
 * returns a structured, UI-friendly result describing each step.
 */
export async function deployAgent(cfg: Config, host: string, opts: DeployOptions = {}): Promise<DeployResult> {
  if (opts.method === "winrm") return deployWinrm(cfg, host, opts);
  return deploySsh(cfg, host, opts);
}

/**
 * Push the SecTool endpoint agent to a single discovered host over SSH.
 * Returns a structured, UI-friendly result describing each step.
 */
export async function deploySsh(cfg: Config, host: string, opts: DeployOptions = {}): Promise<DeployResult> {
  const startedAt = Date.now();
  const steps: DeployStep[] = [];
  const fail = (error: string): DeployResult => ({
    ok: false,
    host,
    method: "ssh",
    durationMs: Date.now() - startedAt,
    steps,
    error,
  });

  if (isIP(host) !== 4 || !isPrivateV4(host)) {
    return fail("Agent deployment is only allowed for private LAN IPv4 hosts.");
  }
  if (!cfg.deploy.enabled) {
    return fail("Agent push-deploy is disabled. Set DEPLOY_ENABLED=true and restart SecTool.");
  }
  if (!cfg.agent.enabled) {
    return fail("The agent dist server is off. Set AGENT_ENABLED=true so devices have an installer to download.");
  }

  const user = (opts.user || cfg.deploy.sshUser || "root").trim();
  const port = opts.port && opts.port > 0 ? opts.port : cfg.deploy.sshPort || 22;
  const serverIp = pickServerIp(cfg, host);
  if (!serverIp) {
    return fail("Could not determine a LAN IP for SecTool's dist server. Set DEPLOY_SERVER_IP=<this host's LAN IP>.");
  }
  const serverUrl = `http://${serverIp}:${cfg.agent.distPort}`;
  steps.push({ name: "plan", ok: true, detail: `ssh ${user}@${host}:${port} → install from ${serverUrl}` });

  if (!cfg.agent.token) {
    steps.push({ name: "token", ok: false, detail: "AGENT_TOKEN is not set — the agent API will be unauthenticated." });
  }
  if (opts.password && !hasSshpass()) {
    steps.push({ name: "auth", ok: false, detail: "Password auth needs `sshpass`, which isn't installed — using key auth instead." });
  }

  log.info(`Deploying SecTool agent to ${user}@${host}:${port} from ${serverUrl}`);
  let run: { code: number | null; output: string };
  try {
    run = await runSsh(cfg, host, user, port, remoteInstallCommand(serverUrl), { password: opts.password });
  } catch (err) {
    steps.push({ name: "ssh", ok: false, detail: (err as Error).message });
    return {
      ok: false,
      host,
      method: "ssh",
      serverUrl,
      user,
      durationMs: Date.now() - startedAt,
      steps,
      error: `Could not run ssh (is the OpenSSH client installed?): ${(err as Error).message}`,
    };
  }

  const sshOk = run.code === 0;
  steps.push({
    name: "install",
    ok: sshOk,
    detail: sshOk ? "installer completed" : `ssh exited with code ${run.code ?? "timeout"}`,
  });

  // Confirm the agent actually came up (the install can succeed but the service
  // fail to start, e.g. no Node on the target).
  const version = sshOk ? await verifyAgent(cfg, host) : undefined;
  if (sshOk) {
    steps.push({
      name: "verify",
      ok: !!version,
      detail: version ? `agent v${version} responding on :${cfg.agent.port}` : "no /health response yet (it may still be starting)",
    });
  }

  const ok = sshOk && !!version;
  return {
    ok,
    host,
    method: "ssh",
    serverUrl,
    user,
    durationMs: Date.now() - startedAt,
    steps,
    agentVersion: version,
    output: tail(run.output),
    error: ok
      ? undefined
      : sshOk
        ? "Installer ran but the agent didn't report healthy. Check that Node.js 18+ is installed on the target."
        : "SSH/installer failed — see output. Verify the SSH user/key and that the target can reach the dist server.",
  };
}

// ---------------------------------------------------------------------------
// WinRM transport (Windows hosts without SSH)
// ---------------------------------------------------------------------------

/** Locate a PowerShell client on this host to drive WinRM with (Windows or pwsh). */
function resolvePwsh(): string | undefined {
  for (const cmd of ["powershell", "pwsh"]) {
    try {
      const r = spawnSync(cmd, ["-NoProfile", "-Command", "$PSVersionTable.PSVersion.Major"], { stdio: "ignore" });
      if (r.status === 0) return cmd;
    } catch {
      /* try next */
    }
  }
  return undefined;
}

/**
 * The PowerShell script we feed (via stdin) to the local client. It opens a WinRM
 * session to the target and runs the install one-liner the dist server serves.
 *
 * Connection details and credentials are passed through environment variables
 * (SECTOOL_WINRM_*) rather than command-line args so the password never appears
 * in the process table or the captured output. The remote scriptblock downloads
 * and executes /install.ps1, which embeds the agent token/port and registers the
 * SecToolAgent scheduled task (same payload the manual Windows one-liner uses).
 *
 * Before connecting we best-effort add the specific target IP to the local WinRM
 * client's TrustedHosts. Negotiate/NTLM to a bare IP with a local admin account
 * (the common workgroup case) otherwise fails with "cannot determine identity".
 * We only append the one target — existing entries and any "*" are preserved —
 * and swallow failures so a locked-down client still surfaces the real error.
 */
function winrmDriverScript(operationTimeoutMs: number): string {
  const opTimeout = Math.max(30000, operationTimeoutMs);
  return [
    `$ErrorActionPreference = 'Stop'`,
    `try {`,
    `  $sec = ConvertTo-SecureString $env:SECTOOL_WINRM_PW -AsPlainText -Force`,
    `  $cred = New-Object System.Management.Automation.PSCredential($env:SECTOOL_WINRM_USER, $sec)`,
    `  if ($env:SECTOOL_WINRM_SSL -ne '1') {`,
    `    try {`,
    `      $th = Get-Item WSMan:\\localhost\\Client\\TrustedHosts -ErrorAction Stop`,
    `      $cur = [string]$th.Value; $tgt = $env:SECTOOL_WINRM_HOST`,
    `      if ([string]::IsNullOrWhiteSpace($cur)) {`,
    `        Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value $tgt -Force -ErrorAction Stop`,
    `      } elseif ($cur -ne '*' -and (($cur -split ',' | ForEach-Object { $_.Trim() }) -notcontains $tgt)) {`,
    `        Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value ($cur + ',' + $tgt) -Force -ErrorAction Stop`,
    `      }`,
    `    } catch { }`,
    `  }`,
    `  $opt = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout ${opTimeout} -CancelTimeout 5000`,
    `  $p = @{`,
    `    ComputerName   = $env:SECTOOL_WINRM_HOST`,
    `    Port           = [int]$env:SECTOOL_WINRM_PORT`,
    `    Credential     = $cred`,
    `    Authentication = 'Negotiate'`,
    `    SessionOption  = $opt`,
    `    ErrorAction    = 'Stop'`,
    `  }`,
    `  if ($env:SECTOOL_WINRM_SSL -eq '1') { $p['UseSSL'] = $true }`,
    `  Invoke-Command @p -ArgumentList $env:SECTOOL_WINRM_URL -ScriptBlock {`,
    `    param($url)`,
    `    $ErrorActionPreference = 'Stop'`,
    `    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12`,
    `    $script = (New-Object Net.WebClient).DownloadString($url)`,
    `    Invoke-Expression $script`,
    `  }`,
    `  Write-Output 'SECTOOL_WINRM_OK'`,
    `} catch {`,
    `  Write-Output ('SECTOOL_WINRM_ERR: ' + $_.Exception.Message)`,
    `  exit 1`,
    `}`,
  ].join("\n");
}

function runWinrm(
  cfg: Config,
  pwsh: string,
  host: string,
  user: string,
  password: string,
  port: number,
  url: string,
): Promise<{ code: number | null; output: string }> {
  const args = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-"];
  const env = {
    ...process.env,
    SECTOOL_WINRM_HOST: host,
    SECTOOL_WINRM_PORT: String(port),
    SECTOOL_WINRM_USER: user,
    SECTOOL_WINRM_PW: password,
    SECTOOL_WINRM_URL: url,
    SECTOOL_WINRM_SSL: cfg.deploy.winrmUseSsl ? "1" : "0",
  };
  return new Promise((resolve, reject) => {
    let out = "";
    const child = spawn(pwsh, args, { stdio: ["pipe", "pipe", "pipe"], env });
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (d: string) => (out += d));
    child.stderr.on("data", (d: string) => (out += d));
    const timer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        /* ignore */
      }
      resolve({ code: null, output: out + "\n[timed out]" });
    }, cfg.deploy.timeoutMs);
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, output: out });
    });
    // Feed the driver script over stdin so creds stay out of argv.
    child.stdin.write(winrmDriverScript(cfg.deploy.timeoutMs));
    child.stdin.end();
  });
}

/**
 * Push the SecTool endpoint agent to a single Windows host over WinRM (PowerShell
 * Remoting) — the answer to "no SSH on the device". Requires a password (WinRM
 * has no key auth) and a local PowerShell client to drive the session.
 */
export async function deployWinrm(cfg: Config, host: string, opts: DeployOptions = {}): Promise<DeployResult> {
  const startedAt = Date.now();
  const steps: DeployStep[] = [];
  const fail = (error: string): DeployResult => ({
    ok: false,
    host,
    method: "winrm",
    durationMs: Date.now() - startedAt,
    steps,
    error,
  });

  if (isIP(host) !== 4 || !isPrivateV4(host)) {
    return fail("Agent deployment is only allowed for private LAN IPv4 hosts.");
  }
  if (!cfg.deploy.enabled) {
    return fail("Agent push-deploy is disabled. Set DEPLOY_ENABLED=true and restart SecTool.");
  }
  if (!cfg.deploy.winrmEnabled) {
    return fail("WinRM push is disabled. Set DEPLOY_WINRM_ENABLED=true to deploy to SSH-less Windows hosts.");
  }
  if (!cfg.agent.enabled) {
    return fail("The agent dist server is off. Set AGENT_ENABLED=true so devices have an installer to download.");
  }

  const pwsh = resolvePwsh();
  if (!pwsh) {
    return fail(
      "WinRM deploy needs a local PowerShell client (powershell.exe on Windows, or pwsh). " +
        "Run SecTool from a Windows host, or use the SSH transport instead.",
    );
  }

  const user = (opts.winUser || opts.user || cfg.deploy.winrmUser || "Administrator").trim();
  const password = opts.winPassword || opts.password || "";
  if (!password) {
    return fail("WinRM requires a password (it has no key auth). Enter the Windows admin password and retry.");
  }
  const port = opts.winPort && opts.winPort > 0 ? opts.winPort : cfg.deploy.winrmPort || 5985;
  const serverIp = pickServerIp(cfg, host);
  if (!serverIp) {
    return fail("Could not determine a LAN IP for SecTool's dist server. Set DEPLOY_SERVER_IP=<this host's LAN IP>.");
  }
  const serverUrl = `http://${serverIp}:${cfg.agent.distPort}`;
  const installUrl = `${serverUrl}/install.ps1`;
  steps.push({
    name: "plan",
    ok: true,
    detail: `winrm ${user}@${host}:${port}${cfg.deploy.winrmUseSsl ? " (ssl)" : ""} → install from ${serverUrl}`,
  });

  if (!cfg.agent.token) {
    steps.push({ name: "token", ok: false, detail: "AGENT_TOKEN is not set — the agent API will be unauthenticated." });
  }

  log.info(`Deploying SecTool agent to ${user}@${host}:${port} over WinRM from ${serverUrl}`);
  let run: { code: number | null; output: string };
  try {
    run = await runWinrm(cfg, pwsh, host, user, password, port, installUrl);
  } catch (err) {
    steps.push({ name: "winrm", ok: false, detail: (err as Error).message });
    return {
      ok: false,
      host,
      method: "winrm",
      serverUrl,
      user,
      durationMs: Date.now() - startedAt,
      steps,
      error: `Could not run PowerShell: ${(err as Error).message}`,
    };
  }

  const winOk = run.code === 0 && run.output.includes("SECTOOL_WINRM_OK");
  steps.push({
    name: "install",
    ok: winOk,
    detail: winOk
      ? "installer completed over WinRM"
      : run.code === null
        ? "timed out"
        : "WinRM/installer failed (is PowerShell Remoting enabled on the target? `Enable-PSRemoting -Force`)",
  });

  // Confirm the agent actually came up on the target's agent port.
  const version = winOk ? await verifyAgent(cfg, host) : undefined;
  if (winOk) {
    steps.push({
      name: "verify",
      ok: !!version,
      detail: version ? `agent v${version} responding on :${cfg.agent.port}` : "no /health response yet (it may still be starting)",
    });
  }

  const ok = winOk && !!version;
  return {
    ok,
    host,
    method: "winrm",
    serverUrl,
    user,
    durationMs: Date.now() - startedAt,
    steps,
    agentVersion: version,
    output: tail(run.output),
    error: ok
      ? undefined
      : winOk
        ? "Installer ran but the agent didn't report healthy. Check that Node.js 18+ is installed on the target."
        : "WinRM/installer failed — see output. Verify the admin credentials and that WinRM (PSRemoting) is enabled on the target.",
  };
}

// ---------------------------------------------------------------------------
// Batch deploy
// ---------------------------------------------------------------------------

export interface DeployAllResult {
  ok: boolean;
  enabled: boolean;
  attempted: number;
  succeeded: number;
  skipped: Array<{ ip: string; reason: string }>;
  results: DeployResult[];
  error?: string;
}

/**
 * Discover the LAN and push the agent to every eligible host. Eligible = a usable
 * transport is open (SSH, or WinRM for SSH-less Windows hosts), not self, and not
 * already running the agent. Each host is deployed over its own assessed transport.
 * Runs with bounded concurrency.
 */
export async function deployToAllEligible(
  cfg: Config,
  opts: DeployOptions & { subnets?: string[] } = {},
): Promise<DeployAllResult> {
  if (!cfg.deploy.enabled) {
    return { ok: false, enabled: false, attempted: 0, succeeded: 0, skipped: [], results: [], error: "Agent push-deploy is disabled (set DEPLOY_ENABLED=true)." };
  }
  const disco = await discoverDevices(cfg, opts.subnets ? { subnets: opts.subnets } : {});
  if (!disco.ok) {
    return { ok: false, enabled: true, attempted: 0, succeeded: 0, skipped: [], results: [], error: disco.error };
  }

  const eligible: Array<{ ip: string; method: DeployMethod }> = [];
  const skipped: Array<{ ip: string; reason: string }> = [];
  for (const d of disco.devices) {
    const a = assessDeploy(cfg, d);
    if (a.eligible && (a.method === "ssh" || a.method === "winrm")) eligible.push({ ip: d.ip, method: a.method });
    else if (a.method === "manual") skipped.push({ ip: d.ip, reason: a.reason });
  }

  const results: DeployResult[] = [];
  const limit = Math.max(1, Math.min(cfg.deploy.concurrency, eligible.length || 1));
  let idx = 0;
  const worker = async (): Promise<void> => {
    while (idx < eligible.length) {
      const e = eligible[idx++]!;
      // Each host uses its own transport; SSH ports/creds and WinRM creds are
      // carried separately in opts, so a mixed LAN deploys in one pass.
      results.push(await deployAgent(cfg, e.ip, { ...opts, method: e.method }));
    }
  };
  await Promise.all(Array.from({ length: limit }, worker));

  const succeeded = results.filter((r) => r.ok).length;
  return {
    ok: true,
    enabled: true,
    attempted: eligible.length,
    succeeded,
    skipped,
    results: results.sort((a, b) => ipToInt(a.host) - ipToInt(b.host)),
  };
}
