#!/usr/bin/env node
/**
 * SecTool endpoint agent — run this on a device you want to investigate (your
 * desktop, a server, etc.). It periodically snapshots the host's network
 * connections mapped to the owning process, keeps a short rolling history, and
 * exposes a tiny token-protected HTTP API so SecTool can answer "which program
 * owned port X / the connection to IP Y" when an alert fires.
 *
 * Zero dependencies — just Node 18+.
 *
 *   AGENT_TOKEN=yoursecret node sectool-agent.mjs
 *
 * Env: AGENT_TOKEN (shared secret, required for real use), AGENT_PORT (7879),
 *      AGENT_HOST (0.0.0.0), AGENT_POLL_MS (4000), AGENT_RETENTION_MIN (30),
 *      AGENT_UPDATE_CHECK_MIN (360 = 6h, 0 disables the recurring heartbeat).
 */
import http from "node:http";
import os from "node:os";
import { execFile, spawn } from "node:child_process";
import { readFileSync, writeFileSync, unlinkSync, createReadStream, statSync, readlinkSync } from "node:fs";
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const AGENT_VERSION = "1.6.0";

// Config resolves from env first, then agent.config.json next to this script
// (written by the installer), so a scheduled task/service needs no env wiring.
const SELF = fileURLToPath(import.meta.url);
const SELFDIR = dirname(SELF);
const CONFIG_PATH = join(SELFDIR, "agent.config.json");
let fileCfg = {};
try {
  // strip a UTF-8 BOM (PowerShell's Set-Content -Encoding UTF8 prepends U+FEFF) so JSON.parse doesn't choke
  let raw = readFileSync(CONFIG_PATH, "utf8");
  if (raw.charCodeAt(0) === 0xfeff) raw = raw.slice(1);
  fileCfg = JSON.parse(raw);
} catch {
  /* no config file — use env/defaults */
}

/** Merge a patch into agent.config.json (BOM-safe, no BOM out) so a remote
 *  setting change survives a restart. Returns the merged config. */
function persistConfig(patch) {
  let cur = {};
  try {
    let raw = readFileSync(CONFIG_PATH, "utf8");
    if (raw.charCodeAt(0) === 0xfeff) raw = raw.slice(1);
    cur = JSON.parse(raw);
  } catch {
    /* new file */
  }
  const next = { ...cur, ...patch };
  writeFileSync(CONFIG_PATH, JSON.stringify(next, null, 2));
  return next;
}

const PORT = Number(process.env.AGENT_PORT || fileCfg.port || 7879);
const HOST = process.env.AGENT_HOST || fileCfg.host || "0.0.0.0";
const TOKEN = process.env.AGENT_TOKEN || fileCfg.token || "";
const UPDATE_URL = (process.env.AGENT_UPDATE_URL || fileCfg.updateUrl || "").replace(/\/+$/, "");
const POLL_MS = Number(process.env.AGENT_POLL_MS || fileCfg.pollMs || 4000);
const RETENTION_MS = Number(process.env.AGENT_RETENTION_MIN || fileCfg.retentionMin || 30) * 60000;
// Destructive: allow POST /kill to terminate processes. OFF unless explicitly
// enabled AND a token is set (an unauthenticated kill endpoint is never allowed).
// `let`: the dashboard can flip this at runtime via POST /config (persisted).
// An explicit AGENT_ALLOW_KILL env var pins it and blocks remote toggling.
const KILL_ENV_PINNED = process.env.AGENT_ALLOW_KILL !== undefined;
let ALLOW_KILL = KILL_ENV_PINNED
  ? /^(1|true|yes|on)$/i.test(process.env.AGENT_ALLOW_KILL)
  : !!fileCfg.allowKill;
// Destructive: allow POST /isolate to network-quarantine this host. Same gating
// model as kill (needs a token). OFF unless explicitly enabled.
const ISO_ENV_PINNED = process.env.AGENT_ALLOW_ISOLATE !== undefined;
let ALLOW_ISOLATE = ISO_ENV_PINNED
  ? /^(1|true|yes|on)$/i.test(process.env.AGENT_ALLOW_ISOLATE)
  : !!fileCfg.allowIsolate;
let isolated = false; // current quarantine state (set by /isolate, cleared by /release)
// Real-time push: agent diffs its own snapshots and POSTs notable host events
// (new external connection / new listener) to the SecTool dist server's /event.
// On by default whenever an update URL is known (that's the LAN-reachable base).
const PUSH_ENABLED =
  process.env.AGENT_PUSH !== undefined
    ? /^(1|true|yes|on)$/i.test(process.env.AGENT_PUSH)
    : fileCfg.push !== false;
// Feature #2: pinned Ed25519 public key (base64 SPKI DER) for verifying signed
// self-updates. Installed by the one-liner installer from the dist /pubkey. When
// set, an update MUST carry a valid signature or it is rejected.
const PUBLIC_KEY = (process.env.AGENT_PUBLIC_KEY || fileCfg.publicKey || "").trim();
function verifyUpdateSignature(codeBuf, sigB64) {
  if (!PUBLIC_KEY) return { ok: true, unsigned: true }; // legacy install, no key pinned
  if (!sigB64) return { ok: false, reason: "no signature served" };
  try {
    const key = createPublicKey({ key: Buffer.from(PUBLIC_KEY, "base64"), format: "der", type: "spki" });
    const good = cryptoVerify(null, codeBuf, key, Buffer.from(sigB64, "base64"));
    return good ? { ok: true } : { ok: false, reason: "signature did not verify" };
  } catch (err) {
    return { ok: false, reason: "verify error: " + err.message };
  }
}
// Recurring update-check heartbeat. Default every 1h; 0 disables it. A 5-minute
// floor keeps a misconfigured value from hammering the update server.
const UPDATE_CHECK_RAW = Number(
  process.env.AGENT_UPDATE_CHECK_MIN ?? fileCfg.updateCheckMin ?? 60,
);
const UPDATE_CHECK_MS = UPDATE_CHECK_RAW > 0 ? Math.max(UPDATE_CHECK_RAW, 5) * 60000 : 0;

if (!TOKEN) console.warn("WARNING: AGENT_TOKEN not set — the API is unauthenticated. Set AGENT_TOKEN for real use.");

// Observable state for the update-check heartbeat, surfaced via /health so the
// SecTool dashboard can tell at a glance whether an agent is current, stale, or
// failing its checks (e.g. update server unreachable).
const updateState = {
  enabled: !!UPDATE_URL && !process.env.AGENT_NO_UPDATE,
  intervalMin: UPDATE_CHECK_MS / 60000,
  lastCheckAt: 0, // epoch ms of the last completed check (0 = never)
  lastResult: "pending", // pending | current | available | updating | error | disabled
  lastError: "",
  latestSeen: AGENT_VERSION, // newest version advertised by the update server
  checks: 0, // total checks performed since start
};

function isNewer(a, b) {
  const pa = String(a).split("."), pb = String(b).split(".");
  for (let i = 0; i < 3; i++) {
    const x = Number(pa[i] || 0), y = Number(pb[i] || 0);
    if (x > y) return true;
    if (x < y) return false;
  }
  return false;
}

/**
 * Check the SecTool server for a newer agent; if found, overwrite self + relaunch.
 * Records the outcome in `updateState` so the heartbeat is observable via /health.
 * @param {string} [reason] label for the log line ("startup" | "heartbeat").
 */
async function selfUpdate(reason = "startup") {
  if (!updateState.enabled) {
    updateState.lastResult = "disabled";
    return;
  }
  updateState.checks++;
  updateState.lastCheckAt = Date.now();
  updateState.lastError = "";
  try {
    const r = await fetch(`${UPDATE_URL}/version`, { signal: AbortSignal.timeout(5000) });
    if (!r.ok) throw new Error(`version endpoint returned HTTP ${r.status}`);
    const { version } = await r.json();
    if (version) updateState.latestSeen = version;
    if (!version || !isNewer(version, AGENT_VERSION)) {
      updateState.lastResult = "current";
      console.log(`Agent v${AGENT_VERSION} is current (${reason} check).`);
      return;
    }
    updateState.lastResult = "available";
    console.log(`Update available: v${AGENT_VERSION} -> v${version}. Downloading…`);
    const code = await (await fetch(`${UPDATE_URL}/agent`, { signal: AbortSignal.timeout(20000) })).text();
    if (!/AGENT_VERSION\s*=/.test(code) || code.length < 1000) {
      updateState.lastResult = "error";
      updateState.lastError = "update payload looked invalid";
      console.warn("Update payload looked invalid; keeping current version.");
      return;
    }
    // Feature #2: verify the update is signed by SecTool before trusting it.
    let sigB64 = "";
    try {
      const sr = await fetch(`${UPDATE_URL}/agent.sig`, { signal: AbortSignal.timeout(5000) });
      if (sr.ok) sigB64 = (await sr.text()).trim();
    } catch { /* no signature available */ }
    const v = verifyUpdateSignature(Buffer.from(code, "utf8"), sigB64);
    if (!v.ok) {
      updateState.lastResult = "error";
      updateState.lastError = `update signature rejected: ${v.reason}`;
      console.warn(`REFUSING update v${version}: ${v.reason}. Keeping v${AGENT_VERSION}.`);
      return;
    }
    if (v.unsigned) console.warn(`Applying UNSIGNED update v${version} (no public key pinned — set publicKey in config to require signatures).`);
    else console.log(`Update signature verified ✓`);
    updateState.lastResult = "updating";
    writeFileSync(SELF, code);
    console.log(`Updated to v${version}; relaunching…`);
    // Relaunch the new code independently of how we were started, then exit.
    spawn(process.execPath, [SELF], { detached: true, stdio: "ignore", env: process.env }).unref();
    process.exit(0);
  } catch (err) {
    updateState.lastResult = "error";
    updateState.lastError = err.message;
    console.warn(`Update check failed (continuing on v${AGENT_VERSION}): ${err.message}`);
  }
}

/** key -> { proto, lport, raddr, rport, state, pid, pname, ppath, firstSeen, lastSeen } */
const buffer = new Map();

function run(cmd, args, timeout = 12000) {
  return new Promise((resolve) => {
    execFile(cmd, args, { maxBuffer: 32e6, windowsHide: true, timeout }, (err, stdout) =>
      resolve(err ? "" : String(stdout)),
    );
  });
}

// --- Feature #1: background SHA-256 of process executables (cached by path) ---
// Malware masquerades by name; the hash is checked against threat intel by SecTool.
const HASH_MAX_BYTES = 256 * 1024 * 1024; // skip absurdly large files
const hashCache = new Map(); // path -> { sha256 } | { pending } | { error } | { skipped }
const hashQueue = [];
let hashingNow = false;
function queueHash(path) {
  if (!path || hashCache.has(path)) return;
  hashCache.set(path, { pending: true });
  hashQueue.push(path);
  drainHashQueue();
}
function drainHashQueue() {
  if (hashingNow) return;
  const path = hashQueue.shift();
  if (!path) return;
  hashingNow = true;
  const done = (v) => { hashCache.set(path, v); hashingNow = false; drainHashQueue(); };
  let st;
  try { st = statSync(path); } catch { return done({ error: true }); }
  if (st.size > HASH_MAX_BYTES) return done({ skipped: "too-large" });
  const h = createHash("sha256");
  const s = createReadStream(path);
  s.on("data", (d) => h.update(d));
  s.on("error", () => done({ error: true }));
  s.on("end", () => done({ sha256: h.digest("hex") }));
}
function hashOf(path) {
  const c = path && hashCache.get(path);
  return c && c.sha256 ? c.sha256 : null;
}

async function snapshotWindows() {
  const ps = [
    "$ErrorActionPreference='SilentlyContinue';",
    "$p=@{}; Get-Process | ForEach-Object { $p[[int]$_.Id]=@{n=$_.ProcessName;path=$_.Path} };",
    // Win32_Process gives the command line + parent PID (feature #2).
    "$ci=@{}; Get-CimInstance Win32_Process | ForEach-Object { $ci[[int]$_.ProcessId]=@{cmd=$_.CommandLine;ppid=[int]$_.ParentProcessId} };",
    "$r=New-Object System.Collections.ArrayList;",
    "function Row($proto,$la,$lp,$ra,$rp,$st,$pid2){ $x=$p[[int]$pid2]; $c=$ci[[int]$pid2]; $pp=if($c){$c.ppid}else{0}; [void]$r.Add([pscustomobject]@{proto=$proto;laddr=$la;lport=$lp;raddr=$ra;rport=$rp;state=[string]$st;procid=$pid2;pname=$x.n;ppath=$x.path;cmdline=$(if($c){$c.cmd}else{''});ppid=$pp;parent=$p[[int]$pp].n}) }",
    "Get-NetTCPConnection | ForEach-Object { Row 'TCP' $_.LocalAddress $_.LocalPort $_.RemoteAddress $_.RemotePort $_.State $_.OwningProcess };",
    "Get-NetUDPEndpoint | ForEach-Object { Row 'UDP' $_.LocalAddress $_.LocalPort '*' 0 'Listen' $_.OwningProcess };",
    "$r | ConvertTo-Json -Depth 3 -Compress",
  ].join("");
  const out = await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", ps]);
  try {
    const j = JSON.parse(out);
    return Array.isArray(j) ? j : [j];
  } catch {
    return [];
  }
}

async function snapshotLinux() {
  // ss -tunap gives proto, local, peer, state, and "users:(("name",pid=NNN,...))"
  const out = await run("ss", ["-tunap"]);
  const rows = [];
  for (const line of out.split(/\r?\n/).slice(1)) {
    const m = line.trim().match(/^(\w+)\s+(\S+)\s+\d+\s+\d+\s+(\S+)\s+(\S+)(?:\s+(.*))?$/);
    if (!m) continue;
    const proto = m[1].toUpperCase().startsWith("TCP") ? "TCP" : m[1].toUpperCase().startsWith("UDP") ? "UDP" : m[1].toUpperCase();
    const [laddr, lport] = splitAddr(m[3]);
    const [raddr, rport] = splitAddr(m[4]);
    const pm = (m[5] || "").match(/\(\("([^"]+)",pid=(\d+)/);
    rows.push({ proto, laddr, lport, raddr, rport, state: m[2] === "UNCONN" ? "Listen" : m[2], procid: pm ? Number(pm[2]) : 0, pname: pm ? pm[1] : "", ppath: "" });
  }
  // Enrich from /proc: exe path (also enables hashing), command line, parent.
  const nameOf = {};
  for (const r of rows) if (r.procid && r.pname) nameOf[r.procid] = r.pname;
  for (const r of rows) {
    if (!r.procid) continue;
    try {
      r.ppath = readlinkSync(`/proc/${r.procid}/exe`);
    } catch { /* permission / gone */ }
    try {
      r.cmdline = readFileSync(`/proc/${r.procid}/cmdline`, "utf8").replace(/\0/g, " ").trim();
    } catch { /* */ }
    try {
      const stat = readFileSync(`/proc/${r.procid}/stat`, "utf8");
      const ppid = Number((stat.match(/\)\s+\S+\s+(\d+)/) || [])[1]) || 0;
      r.ppid = ppid;
      r.parent = nameOf[ppid] || "";
    } catch { /* */ }
  }
  return rows;
}

async function snapshotMac() {
  const out = await run("lsof", ["-i", "-n", "-P"]);
  const rows = [];
  for (const line of out.split(/\r?\n/).slice(1)) {
    const c = line.split(/\s+/);
    if (c.length < 9) continue;
    const proto = (c[7] || "").toUpperCase();
    if (proto !== "TCP" && proto !== "UDP") continue;
    const conn = c[8];
    const arrow = conn.split("->");
    const [laddr, lport] = splitAddr(arrow[0]);
    const [raddr, rport] = arrow[1] ? splitAddr(arrow[1].replace(/\s*\(.*\)$/, "")) : ["*", 0];
    rows.push({ proto, laddr, lport, raddr, rport, state: c[9] ? c[9].replace(/[()]/g, "") : "", procid: Number(c[1]), pname: c[0], ppath: "" });
  }
  return rows;
}

function splitAddr(s) {
  if (!s) return ["*", 0];
  const i = s.lastIndexOf(":");
  if (i === -1) return [s, 0];
  return [s.slice(0, i).replace(/[[\]]/g, ""), Number(s.slice(i + 1)) || 0];
}

async function poll() {
  const plat = os.platform();
  let rows = [];
  try {
    if (plat === "win32") rows = await snapshotWindows();
    else if (plat === "linux") rows = await snapshotLinux();
    else if (plat === "darwin") rows = await snapshotMac();
  } catch {
    /* ignore one bad poll */
  }
  const now = Date.now();
  for (const r of rows) {
    if (!r || r.lport == null) continue;
    if (r.ppath) queueHash(r.ppath); // feature #1: hash new binaries in the background
    const key = `${r.proto}|${r.lport}|${r.raddr}|${r.rport}|${r.procid}`;
    const ex = buffer.get(key);
    if (ex) {
      ex.lastSeen = now;
      ex.state = r.state;
    } else {
      buffer.set(key, { ...r, firstSeen: now, lastSeen: now });
      if (!firstPoll) emitEvent(r); // feature #3: push newly-appeared connections/listeners
    }
  }
  firstPoll = false;
  const cutoff = now - RETENTION_MS;
  for (const [k, v] of buffer) if (v.lastSeen < cutoff) buffer.delete(k);
}

// --- Feature #3: real-time push of notable host events to SecTool ---
let firstPoll = true; // suppress a flood of "new" events on the very first snapshot
const pushRecent = new Map(); // dedupe key -> ts, so we don't spam the same event
function isPublic(ip) {
  if (!ip || ip === "*" || ip === "0.0.0.0" || ip === "::") return false;
  if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|127\.|::1|fe80:|f[cd])/i.test(ip)) return false;
  return /\d+\.\d+\.\d+\.\d+/.test(ip) || ip.includes(":");
}
function emitEvent(r) {
  if (!PUSH_ENABLED || !UPDATE_URL) return;
  let type = null;
  if (r.proto === "TCP" && r.state !== "Listen" && isPublic(r.raddr)) type = "new-external-connection";
  // Only TCP listeners are meaningful services. Every UDP socket reports as
  // "Listen", so counting those flooded the feed — exclude UDP.
  else if (r.proto === "TCP" && r.state === "Listen" && (r.laddr === "0.0.0.0" || r.laddr === "::" || r.laddr === "*")) type = "new-listener";
  if (!type) return;
  const dedupe = `${type}|${r.procid}|${r.raddr}|${r.rport}|${r.lport}`;
  const now = Date.now();
  if (pushRecent.has(dedupe) && now - pushRecent.get(dedupe) < 300000) return;
  pushRecent.set(dedupe, now);
  if (pushRecent.size > 500) for (const [k, t] of pushRecent) if (now - t > 600000) pushRecent.delete(k);
  const body = JSON.stringify({
    type, host: os.hostname(), time: now, proto: r.proto,
    process: r.pname, pid: r.procid, path: r.ppath, sha256: hashOf(r.ppath),
    cmdline: r.cmdline || "", parent: r.parent || "",
    localPort: r.lport, remoteIp: r.raddr, remotePort: r.rport,
  });
  fetch(`${UPDATE_URL}/event`, { method: "POST", headers: { ...(TOKEN ? { authorization: `Bearer ${TOKEN}` } : {}), "content-type": "application/json" }, body, signal: AbortSignal.timeout(5000) }).catch(() => {});
}

// Never delete OS-critical binaries or the node runtime the agent runs on.
function isProtectedPath(p) {
  if (!p) return true;
  const lp = p.replace(/\\/g, "/").toLowerCase();
  if (/^[a-z]:\/?$/.test(lp) || lp === "/") return true; // a drive root or filesystem root
  if (process.execPath && lp === process.execPath.replace(/\\/g, "/").toLowerCase()) return true; // our own node
  const guarded = ["c:/windows/", "/bin/", "/sbin/", "/usr/", "/lib/", "/lib64/", "/boot/", "/etc/", "/system/", "/library/apple/"];
  return guarded.some((g) => lp.startsWith(g));
}

// Whether the agent process holds admin/root — deletes in Program Files, HKLM
// autorun removal, and killing service/protected processes require it.
let ELEVATED = false;
async function checkElevated() {
  try {
    if (os.platform() === "win32") {
      const out = await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "[bool](([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"], 8000);
      ELEVATED = /true/i.test(out);
    } else {
      ELEVATED = typeof process.getuid === "function" && process.getuid() === 0;
    }
  } catch { ELEVATED = false; }
}

// Delete a file, escalating past permission/lock errors: take ownership + grant
// rights and retry, then a hard cmd delete, then schedule removal on next reboot
// for a still-locked file. The escalation steps only succeed when elevated.
async function forceDelete(path) {
  try { unlinkSync(path); return { deleted: true }; }
  catch (e1) {
    const code = e1.code || "";
    if (os.platform() !== "win32") {
      try { execFileSync("chmod", ["u+w", path]); unlinkSync(path); return { deleted: true, forced: true }; }
      catch { return { deleteError: (ELEVATED ? "" : "agent not elevated — ") + e1.message }; }
    }
    // Windows escalation. Tier 1 — user-level (no elevation needed for files the
    // current user owns): clear read-only/deny ACEs, take ownership to self, grant self.
    const me = process.env.USERNAME || "";
    await run("cmd.exe", ["/c", `attrib -r -s -h "${path}" >nul 2>&1`], 10000);
    if (me) await run("cmd.exe", ["/c", `icacls "${path}" /remove:d "${me}" >nul 2>&1`], 10000);
    await run("cmd.exe", ["/c", `takeown /F "${path}" >nul 2>&1`], 15000);
    if (me) await run("cmd.exe", ["/c", `icacls "${path}" /grant "${me}:F" /C >nul 2>&1`], 10000);
    try { unlinkSync(path); return { deleted: true, forced: true }; } catch { /* still blocked */ }
    // Tier 2 — admin-level (needs elevation): ownership to Administrators + grant, then hard delete.
    await run("cmd.exe", ["/c", `takeown /F "${path}" /A >nul 2>&1`], 15000);
    await run("cmd.exe", ["/c", `icacls "${path}" /grant *S-1-5-32-544:F /C >nul 2>&1`], 15000);
    try { unlinkSync(path); return { deleted: true, forced: true }; } catch { /* still blocked */ }
    await run("cmd.exe", ["/c", `del /f /q "${path}" >nul 2>&1`], 15000);
    if (!existsPath(path)) return { deleted: true, forced: true };
    // Last resort: schedule deletion on reboot via PendingFileRenameOperations (needs HKLM).
    if (code === "EBUSY" || code === "EPERM") {
      const ps = `$k='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager'; $v=(Get-ItemProperty -Path $k -Name PendingFileRenameOperations -EA SilentlyContinue).PendingFileRenameOperations; $n=@('\\??\\${path.replace(/\\/g, "\\\\")}',''); if($v){$n=$v+$n}; Set-ItemProperty -Path $k -Name PendingFileRenameOperations -Value $n -Type MultiString -EA Stop; 'SCHEDULED'`;
      const out = await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", ps], 10000);
      if (/SCHEDULED/.test(out)) return { deleteError: "locked — scheduled for deletion on next reboot" };
    }
    return { deleteError: (ELEVATED ? "" : "agent not elevated — reinstall elevated; ") + e1.message };
  }
}
function existsPath(p) { try { statSync(p); return true; } catch { return false; } }

// --- Feature #4: network isolation / quarantine ---
// Block all traffic except loopback, the agent's own port, and the SecTool
// management host, so a compromised device is cut off but still controllable.
async function applyIsolate(mgmtIp) {
  const plat = os.platform();
  if (plat === "win32") {
    const ip = /^[0-9.]+$/.test(mgmtIp || "") ? mgmtIp : null;
    const ps = [
      "$ErrorActionPreference='SilentlyContinue';",
      "Get-NetFirewallRule -DisplayName 'SecToolIsolate*' | Remove-NetFirewallRule;",
      `New-NetFirewallRule -DisplayName 'SecToolIsolate-Agent' -Direction Inbound -LocalPort ${PORT} -Protocol TCP -Action Allow | Out-Null;`,
      ip ? `New-NetFirewallRule -DisplayName 'SecToolIsolate-MgmtOut' -Direction Outbound -RemoteAddress ${ip} -Action Allow | Out-Null;` : "",
      ip ? `New-NetFirewallRule -DisplayName 'SecToolIsolate-MgmtIn' -Direction Inbound -RemoteAddress ${ip} -Action Allow | Out-Null;` : "",
      "netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound | Out-Null;",
      "'ISOLATED'",
    ].join("");
    return (await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", ps])).includes("ISOLATED");
  }
  if (plat === "linux") {
    const ip = /^[0-9.]+$/.test(mgmtIp || "") ? mgmtIp : null;
    const sh =
      `iptables -N SECTOOLISO 2>/dev/null; iptables -F SECTOOLISO; ` +
      `iptables -A SECTOOLISO -i lo -j ACCEPT; iptables -A SECTOOLISO -o lo -j ACCEPT; ` +
      `iptables -A SECTOOLISO -p tcp --dport ${PORT} -j ACCEPT; ` +
      (ip ? `iptables -A SECTOOLISO -s ${ip} -j ACCEPT; iptables -A SECTOOLISO -d ${ip} -j ACCEPT; ` : "") +
      `iptables -A SECTOOLISO -j DROP; ` +
      `iptables -I INPUT 1 -j SECTOOLISO; iptables -I OUTPUT 1 -j SECTOOLISO; echo ISOLATED`;
    return (await run("sh", ["-c", sh])).includes("ISOLATED");
  }
  return false;
}
async function applyRelease() {
  const plat = os.platform();
  if (plat === "win32") {
    const ps = [
      "$ErrorActionPreference='SilentlyContinue';",
      "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null;",
      "Get-NetFirewallRule -DisplayName 'SecToolIsolate*' | Remove-NetFirewallRule;",
      "'RELEASED'",
    ].join("");
    return (await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", ps])).includes("RELEASED");
  }
  if (plat === "linux") {
    const sh = `iptables -D INPUT -j SECTOOLISO 2>/dev/null; iptables -D OUTPUT -j SECTOOLISO 2>/dev/null; iptables -F SECTOOLISO 2>/dev/null; iptables -X SECTOOLISO 2>/dev/null; echo RELEASED`;
    return (await run("sh", ["-c", sh])).includes("RELEASED");
  }
  return false;
}

// --- Feature #5: persistence / autoruns enumeration ---
async function listAutoruns() {
  const plat = os.platform();
  if (plat === "win32") {
    const ps = [
      "$ErrorActionPreference='SilentlyContinue'; $o=New-Object System.Collections.ArrayList;",
      "foreach($h in 'HKLM','HKCU'){ foreach($k in 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run','SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'){ $p=\"$h`:\\$k\"; if(Test-Path $p){ (Get-Item $p).Property | ForEach-Object { [void]$o.Add([pscustomobject]@{type='run-key';name=$_;location=\"$h\\$k\";command=[string](Get-ItemProperty $p).$_;removable=$true}) } } } }",
      "Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.Settings.Enabled } | ForEach-Object { $a=($_.Actions | ForEach-Object { $_.Execute } ) -join ' '; if($a){ [void]$o.Add([pscustomobject]@{type='scheduled-task';name=$_.TaskName;location=$_.TaskPath;command=[string]$a;removable=$true}) } };",
      "Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' } | ForEach-Object { [void]$o.Add([pscustomobject]@{type='service';name=$_.Name;location='services';command=[string]$_.PathName;removable=$false}) };",
      "$sf=@([Environment]::GetFolderPath('Startup'),[Environment]::GetFolderPath('CommonStartup')); foreach($d in $sf){ if(Test-Path $d){ Get-ChildItem $d -File | ForEach-Object { [void]$o.Add([pscustomobject]@{type='startup-folder';name=$_.Name;location=$d;command=$_.FullName;removable=$true}) } } };",
      "$o | ConvertTo-Json -Depth 3 -Compress",
    ].join("");
    const out = await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", ps]);
    try { const j = JSON.parse(out); return Array.isArray(j) ? j : [j]; } catch { return []; }
  }
  if (plat === "linux") {
    const out = await run("sh", ["-c", "for f in /etc/cron.d/* /etc/crontab $HOME/.config/autostart/*.desktop; do echo \"::$f::\"; cat \"$f\" 2>/dev/null; done; systemctl list-unit-files --type=service --state=enabled 2>/dev/null"]);
    return [{ type: "raw", name: "linux-autoruns", location: "cron/systemd/autostart", command: out.slice(0, 8000), removable: false }];
  }
  return [];
}
// Remove a persistence entry (Windows). Gated by the same switch as kill/delete.
async function removeAutorun(entry) {
  if (os.platform() !== "win32") return { ok: false, error: "autorun removal is Windows-only for now" };
  const t = entry.type, name = String(entry.name || ""), loc = String(entry.location || "");
  if (!name) return { ok: false, error: "missing name" };
  let ps;
  if (t === "run-key") {
    const parts = loc.split("\\"); const hive = parts.shift();
    ps = `Remove-ItemProperty -Path '${hive}:\\${parts.join("\\").replace(/'/g, "''")}' -Name '${name.replace(/'/g, "''")}' -ErrorAction Stop; 'OK'`;
  } else if (t === "scheduled-task") {
    ps = `Unregister-ScheduledTask -TaskName '${name.replace(/'/g, "''")}' -TaskPath '${loc.replace(/'/g, "''")}' -Confirm:$false -ErrorAction Stop; 'OK'`;
  } else if (t === "startup-folder") {
    ps = `Remove-Item -LiteralPath '${String(entry.command || "").replace(/'/g, "''")}' -Force -ErrorAction Stop; 'OK'`;
  } else {
    return { ok: false, error: `'${t}' entries can't be auto-removed (remove the service manually)` };
  }
  const out = await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", `$ErrorActionPreference='Stop'; try { ${ps} } catch { "ERR:$($_.Exception.Message)" }`]);
  if (out.includes("OK")) return { ok: true };
  let msg = (out.match(/ERR:(.*)/) || [, "removal failed"])[1].trim();
  if (/registry access is not allowed|access is denied|requires elevation|unauthorizedaccess/i.test(msg) && !ELEVATED) {
    msg += " — the agent is not running elevated (this entry needs admin; reinstall the agent elevated).";
  }
  return { ok: false, error: msg };
}

// --- Feature #4: DNS attribution (best-effort correlation) ---
// True per-query→PID attribution needs ETW; we correlate the host DNS cache
// (what was resolved) with which processes are doing DNS (port-53 sockets).
async function collectDns() {
  const dnsProcs = {};
  for (const r of buffer.values()) {
    if (r.rport === 53 || r.lport === 53) {
      const k = r.pname || `pid ${r.procid}`;
      dnsProcs[k] = (dnsProcs[k] || 0) + 1;
    }
  }
  let cache = [];
  if (os.platform() === "win32") {
    const ps = "$ErrorActionPreference='SilentlyContinue'; Get-DnsClientCache | Select-Object -First 300 | ForEach-Object { [pscustomobject]@{name=$_.Entry;data=[string]$_.Data;type=[string]$_.Type} } | ConvertTo-Json -Compress";
    try { const j = JSON.parse(await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", ps])); cache = Array.isArray(j) ? j : [j]; } catch { /* */ }
  } else if (os.platform() === "linux") {
    const out = await run("sh", ["-c", "resolvectl statistics 2>/dev/null; getent hosts 2>/dev/null | head -50"]);
    if (out) cache = [{ name: "resolver", data: out.slice(0, 4000), type: "raw" }];
  }
  return { host: os.hostname(), dnsProcesses: Object.entries(dnsProcs).map(([process, queries]) => ({ process, queries })).sort((a, b) => b.queries - a.queries), cache };
}

// --- Process inspector: full detail for a single PID ---
// Answers "what actually is this process?" — command line, parent chain,
// signature, hash, owner, and every socket it holds.
async function processDetail(pid) {
  const detail = { pid, sockets: [...buffer.values()].filter((r) => r.procid === pid).map(shapeRec) };
  const plat = os.platform();
  if (plat === "win32") {
    const ps = [
      "$ErrorActionPreference='SilentlyContinue';",
      `$pr=Get-CimInstance Win32_Process -Filter "ProcessId=${pid}";`,
      "if(-not $pr){ 'null' } else {",
      "$chain=@(); $cur=$pr; $seen=@{}; $seen[[int]$pr.ProcessId]=$true;",
      "for($i=0;$i -lt 8 -and $cur.ParentProcessId;$i++){ if($seen[[int]$cur.ParentProcessId]){break}; $seen[[int]$cur.ParentProcessId]=$true; $par=Get-CimInstance Win32_Process -Filter \"ProcessId=$($cur.ParentProcessId)\"; if(-not $par){break}; $chain+=[pscustomobject]@{pid=$par.ProcessId;name=$par.Name}; $cur=$par }",
      "$sig=if($pr.ExecutablePath){Get-AuthenticodeSignature $pr.ExecutablePath}else{$null};",
      "$own=''; try{$o=Invoke-CimMethod -InputObject $pr -MethodName GetOwner; if($o.User){$own=\"$($o.Domain)\\$($o.User)\"}}catch{};",
      "[pscustomobject]@{name=$pr.Name;path=$pr.ExecutablePath;cmdline=$pr.CommandLine;ppid=$pr.ParentProcessId;created=[string]$pr.CreationDate;user=$own;signed=[string]$sig.Status;signer=[string]$sig.SignerCertificate.Subject;parents=$chain} | ConvertTo-Json -Depth 5 -Compress",
      "}",
    ].join("");
    try {
      const out = (await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", ps], 20000)).trim();
      if (out && out !== "null") Object.assign(detail, JSON.parse(out));
    } catch { /* leave what we have */ }
  } else if (plat === "linux") {
    try { detail.cmdline = readFileSync(`/proc/${pid}/cmdline`, "utf8").replace(/\0/g, " ").trim(); } catch { /* */ }
    try { detail.path = readlinkSync(`/proc/${pid}/exe`); } catch { /* */ }
    try {
      const st = readFileSync(`/proc/${pid}/stat`, "utf8");
      detail.name = (st.match(/\(([^)]+)\)/) || [])[1] || "";
      detail.ppid = Number((st.match(/\)\s+\S+\s+(\d+)/) || [])[1]) || 0;
    } catch { /* */ }
    const chain = [];
    let cur = detail.ppid || 0;
    for (let i = 0; i < 8 && cur > 1; i++) {
      try {
        const st = readFileSync(`/proc/${cur}/stat`, "utf8");
        chain.push({ pid: cur, name: (st.match(/\(([^)]+)\)/) || [])[1] || "" });
        cur = Number((st.match(/\)\s+\S+\s+(\d+)/) || [])[1]) || 0;
      } catch { break; }
    }
    detail.parents = chain;
    try { detail.user = "uid " + (readFileSync(`/proc/${pid}/status`, "utf8").match(/Uid:\s+(\d+)/) || [])[1]; } catch { /* */ }
  }
  detail.sha256 = hashOf(detail.path);
  return detail;
}

// --- Feature #3: on-demand IR triage bundle ---
async function collectTriage() {
  const bundle = { host: os.hostname(), platform: os.platform(), time: Date.now(), agentVersion: AGENT_VERSION };
  bundle.connections = [...buffer.values()].slice(0, 500).map(shapeRec);
  bundle.autoruns = await listAutoruns();
  bundle.dns = await collectDns();
  try {
    const hp = os.platform() === "win32" ? "C:/Windows/System32/drivers/etc/hosts" : "/etc/hosts";
    bundle.hostsFile = readFileSync(hp, "utf8").split(/\r?\n/).filter((l) => l.trim() && !l.trim().startsWith("#"));
  } catch { bundle.hostsFile = []; }
  // Process list w/ Authenticode signature status (feature #1 "unsigned"), limited
  // to processes we've seen with a live socket so the signature scan stays bounded.
  const paths = [...new Set([...buffer.values()].map((r) => r.ppath).filter(Boolean))].slice(0, 150);
  if (os.platform() === "win32" && paths.length) {
    const list = paths.map((p) => `'${p.replace(/'/g, "''")}'`).join(",");
    const ps = `$ErrorActionPreference='SilentlyContinue'; @(${list}) | ForEach-Object { $s=(Get-AuthenticodeSignature $_); [pscustomobject]@{path=$_;signed=[string]$s.Status;signer=[string]$s.SignerCertificate.Subject} } | ConvertTo-Json -Compress`;
    try {
      const j = JSON.parse(await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", ps], 45000));
      const arr = Array.isArray(j) ? j : [j];
      bundle.binaries = arr.map((b) => ({ path: b.path, signed: b.signed, signer: (b.signer || "").replace(/,.*$/, ""), sha256: hashOf(b.path) }));
    } catch { bundle.binaries = paths.map((p) => ({ path: p, sha256: hashOf(p) })); }
  } else {
    bundle.binaries = paths.map((p) => ({ path: p, sha256: hashOf(p) }));
  }
  return bundle;
}

// Shape a raw buffer record into the API connection object (module-scope so both
// the request handler and collectTriage can use it).
function shapeRec(r) {
  return { proto: r.proto, localAddr: r.laddr, localPort: r.lport, remoteIp: r.raddr, remotePort: r.rport, state: r.state, pid: r.procid, process: r.pname, path: r.ppath, sha256: hashOf(r.ppath), cmdline: r.cmdline || "", ppid: r.ppid || 0, parent: r.parent || "", firstSeen: r.firstSeen, lastSeen: r.lastSeen };
}

function readBody(req, cb) {
  let raw = "";
  req.on("data", (c) => { raw += c; if (raw.length > 20_000) req.destroy(); });
  req.on("end", () => { try { cb(JSON.parse(raw || "{}")); } catch { cb(null); } });
}

function matches(rec, q) {
  if (q.proto && rec.proto !== q.proto.toUpperCase()) return false;
  if (q.localPort && rec.lport !== Number(q.localPort)) return false;
  if (q.remotePort && rec.rport !== Number(q.remotePort)) return false;
  if (q.remoteIp && rec.raddr !== q.remoteIp) return false;
  if (q.pid && rec.procid !== Number(q.pid)) return false;
  return true;
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  const ok = !TOKEN || req.headers["authorization"] === `Bearer ${TOKEN}`;
  const json = (code, body) => {
    res.writeHead(code, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  };
  if (url.pathname === "/health") {
    return json(200, {
      ok: true,
      version: AGENT_VERSION,
      host: os.hostname(),
      platform: os.platform(),
      tracked: buffer.size,
      retentionMin: RETENTION_MS / 60000,
      auth: !!TOKEN,
      kill: ALLOW_KILL && !!TOKEN, // process-kill enabled AND safe (token present)
      isolate: ALLOW_ISOLATE && !!TOKEN, // network-quarantine enabled AND safe
      isolated, // is this host currently quarantined?
      push: PUSH_ENABLED && !!UPDATE_URL, // real-time event push active
      hashing: hashCache.size, // # of binaries fingerprinted so far
      signedUpdates: !!PUBLIC_KEY, // agent pins a key and requires signed updates
      triage: true, // exposes /triage + /dns
      elevated: ELEVATED, // admin/root — needed to delete system-path binaries + HKLM autoruns
      killPinned: KILL_ENV_PINNED, // set via env → can't be toggled from the dashboard
      update: {
        enabled: updateState.enabled,
        intervalMin: updateState.intervalMin,
        lastCheckAt: updateState.lastCheckAt || null,
        ageMs: updateState.lastCheckAt ? Date.now() - updateState.lastCheckAt : null,
        result: updateState.lastResult,
        error: updateState.lastError || undefined,
        latestSeen: updateState.latestSeen,
        upToDate: !isNewer(updateState.latestSeen, AGENT_VERSION),
        checks: updateState.checks,
      },
    });
  }
  if (!ok) return json(401, { error: "unauthorized" });
  const shape = shapeRec;
  if (url.pathname === "/lookup") {
    const q = Object.fromEntries(url.searchParams);
    const found = [...buffer.values()]
      .filter((r) => matches(r, q))
      .sort((a, b) => b.lastSeen - a.lastSeen)
      .slice(0, 50)
      .map(shape);
    return json(200, { host: os.hostname(), count: found.length, matches: found });
  }
  if (url.pathname === "/connections") {
    return json(200, { host: os.hostname(), count: buffer.size, connections: [...buffer.values()].slice(0, 500).map(shape) });
  }
  // --- destructive: terminate a process (heavily guarded) ---
  if (req.method === "POST" && url.pathname === "/kill") {
    // Defence in depth: feature must be enabled AND a token must exist. `ok`
    // above already required a valid token, but re-assert here so a kill can
    // never run on a tokenless agent even if the auth check ever changes.
    if (!ALLOW_KILL) return json(403, { error: "kill is disabled on this agent (set AGENT_ALLOW_KILL=true to enable)" });
    if (!TOKEN) return json(403, { error: "kill refused: this agent has no AGENT_TOKEN configured" });
    let raw = "";
    req.on("data", (c) => {
      raw += c;
      if (raw.length > 10_000) req.destroy(); // bound the body
    });
    req.on("end", () => {
      let body;
      try {
        body = JSON.parse(raw || "{}");
      } catch {
        return json(400, { error: "invalid JSON body" });
      }
      const pid = Number(body.pid);
      const wantName = body.process ? String(body.process) : null;
      const signal = String(body.signal || "SIGTERM").toUpperCase();
      const deleteFile = body.deleteFile === true;
      if (signal !== "SIGTERM" && signal !== "SIGKILL") return json(400, { error: "signal must be SIGTERM or SIGKILL" });

      // Resolve target processes from tracked connections only — never an arbitrary
      // PID/path. By pid (single, name-verified) or by process name (all matches).
      const entries = [...buffer.values()];
      const safe = (r) => r.procid > 4 && r.procid !== process.pid;
      let targets;
      if (Number.isInteger(pid) && pid > 0) {
        if (pid <= 4 || pid === process.pid) return json(403, { error: `refusing to kill protected pid ${pid}` });
        const known = entries.find((r) => r.procid === pid);
        if (!known) return json(404, { error: `pid ${pid} is not among this host's tracked connections` });
        if (wantName && known.pname && known.pname.toLowerCase() !== wantName.toLowerCase()) {
          return json(409, { error: `pid ${pid} is now '${known.pname}', not '${wantName}' — refusing (possible PID reuse)` });
        }
        targets = [known];
      } else if (wantName) {
        const nm = wantName.toLowerCase();
        const byPid = new Map();
        for (const r of entries) if (safe(r) && (r.pname || "").toLowerCase() === nm) byPid.set(r.procid, r);
        targets = [...byPid.values()];
        if (!targets.length) return json(404, { error: `no tracked process named '${wantName}' on this host` });
      } else {
        return json(400, { error: "provide a pid or a process name" });
      }

      // Kill first, then (optionally) delete each target's binary after a short
      // delay so the OS releases the executable lock.
      for (const t of targets) {
        try {
          process.kill(t.procid, signal);
          t._killed = true;
        } catch (err) {
          t._killErr = err.message;
        }
      }
      const finish = async () => {
        const seenPaths = new Set();
        const results = [];
        for (const t of targets) {
          const r = { pid: t.procid, process: t.pname, killed: !!t._killed };
          // ESRCH means the process was already gone — not a real failure.
          if (t._killErr && t._killErr.includes("ESRCH")) { r.killed = true; r.alreadyGone = true; }
          else if (t._killErr) r.error = t._killErr;
          if (deleteFile && t.ppath && !seenPaths.has(t.ppath)) {
            seenPaths.add(t.ppath);
            r.path = t.ppath;
            if (isProtectedPath(t.ppath)) r.deleteError = "refused: protected/system path";
            else {
              const dr = await forceDelete(t.ppath);
              if (dr.deleted) { r.deleted = true; if (dr.forced) r.forced = true; }
              else r.deleteError = dr.deleteError;
            }
          }
          console.log(`[KILL] ${new Date().toISOString()} pid=${t.procid} name=${t.pname || "?"} signal=${signal} killed=${r.killed} deleted=${r.deleted || false}${r.forced ? "(forced)" : ""}${r.deleteError ? " delErr=" + r.deleteError : ""} elevated=${ELEVATED} from=${req.socket.remoteAddress}`);
          results.push(r);
        }
        json(200, { ok: true, host: os.hostname(), signal, deleteFile, elevated: ELEVATED, results });
      };
      if (deleteFile) setTimeout(finish, 600);
      else finish();
    });
    return;
  }
  // --- feature #4: network isolation / quarantine (destructive, opt-in) ---
  if (req.method === "POST" && (url.pathname === "/isolate" || url.pathname === "/release")) {
    if (!TOKEN) return json(403, { error: "isolation requires a token" });
    const release = url.pathname === "/release";
    if (!release && !ALLOW_ISOLATE) return json(403, { error: "isolation is disabled on this agent (set AGENT_ALLOW_ISOLATE=true)" });
    readBody(req, async (body) => {
      // Keep the caller (SecTool) reachable so we don't lock ourselves out.
      const mgmtIp = (body && body.mgmtIp) || (req.socket.remoteAddress || "").replace(/^::ffff:/, "");
      try {
        const ok2 = release ? await applyRelease() : await applyIsolate(mgmtIp);
        if (ok2) isolated = !release;
        console.log(`[ISOLATE] ${new Date().toISOString()} ${release ? "release" : "isolate"} mgmt=${mgmtIp} -> ${ok2 ? "ok" : "failed"}`);
        return json(ok2 ? 200 : 500, { ok: ok2, host: os.hostname(), isolated, mgmtIp });
      } catch (err) {
        return json(500, { ok: false, error: err.message });
      }
    });
    return;
  }
  // --- feature #4: DNS attribution (read-only) ---
  if (req.method === "GET" && url.pathname === "/dns") {
    collectDns().then((d) => json(200, d));
    return;
  }
  // --- process inspector: full detail for one PID ---
  if (req.method === "GET" && url.pathname === "/process") {
    const pid = Number(url.searchParams.get("pid"));
    if (!Number.isInteger(pid) || pid <= 0) return json(400, { error: "invalid pid" });
    processDetail(pid).then((d) => json(200, d)).catch((e) => json(500, { error: e.message }));
    return;
  }
  // --- feature #3: IR triage bundle (read-only) ---
  if (req.method === "GET" && url.pathname === "/triage") {
    collectTriage().then((b) => json(200, b)).catch((e) => json(500, { error: e.message }));
    return;
  }
  // --- feature #5: persistence / autoruns enumeration (read-only) ---
  if (req.method === "GET" && url.pathname === "/autoruns") {
    listAutoruns().then((items) => json(200, { host: os.hostname(), count: items.length, autoruns: items }));
    return;
  }
  // --- feature #5: remove a persistence entry (destructive, same gate as kill) ---
  if (req.method === "POST" && url.pathname === "/autoruns/remove") {
    if (!ALLOW_KILL) return json(403, { error: "autorun removal is disabled (needs AGENT_ALLOW_KILL=true)" });
    if (!TOKEN) return json(403, { error: "autorun removal requires a token" });
    readBody(req, async (body) => {
      if (!body || !body.type || !body.name) return json(400, { error: "provide {type,name,location,command}" });
      const r = await removeAutorun(body);
      console.log(`[AUTORUN-RM] ${new Date().toISOString()} type=${body.type} name=${body.name} -> ${r.ok ? "removed" : "FAIL: " + r.error}`);
      return json(r.ok ? 200 : 500, { ...r, host: os.hostname() });
    });
    return;
  }
  // --- remotely toggle agent settings (currently: allowKill), token-gated + persisted ---
  if (req.method === "POST" && url.pathname === "/config") {
    if (!TOKEN) return json(403, { error: "config changes require a token" });
    let raw = "";
    req.on("data", (c) => {
      raw += c;
      if (raw.length > 10_000) req.destroy();
    });
    req.on("end", () => {
      let body;
      try {
        body = JSON.parse(raw || "{}");
      } catch {
        return json(400, { error: "invalid JSON body" });
      }
      const changes = {};
      if (typeof body.allowKill === "boolean") {
        if (KILL_ENV_PINNED) return json(409, { error: "allowKill is pinned by AGENT_ALLOW_KILL env var; unset it to toggle from the dashboard" });
        ALLOW_KILL = body.allowKill;
        changes.allowKill = body.allowKill;
      }
      if (!Object.keys(changes).length) return json(400, { error: "no recognized settings (expected allowKill:boolean)" });
      let persisted = true;
      try {
        persistConfig(changes);
      } catch (err) {
        persisted = false; // still applied in-memory, but won't survive a restart
        console.log(`[CONFIG] persist failed: ${err.message}`);
      }
      console.log(`[CONFIG] ${new Date().toISOString()} ${JSON.stringify(changes)} persisted=${persisted} from=${req.socket.remoteAddress}`);
      return json(200, { ok: true, host: os.hostname(), allowKill: ALLOW_KILL, kill: ALLOW_KILL && !!TOKEN, persisted });
    });
    return;
  }
  json(404, { error: "not found" });
});

await checkElevated(); // record whether we can delete system-path binaries / HKLM autoruns
await selfUpdate("startup"); // check for a newer agent on every startup
// Recurring update-check heartbeat: keep long-lived agents current without a
// restart. selfUpdate() relaunches + exits the process if it pulls a new build.
// Self-scheduling so a FAILED check (e.g. the agent started before SecTool was
// reachable) retries in minutes instead of waiting the full interval — otherwise
// one transient startup failure leaves the agent stale for up to 6h.
const UPDATE_RETRY_MS = Math.min(UPDATE_CHECK_MS || 300000, 300000); // ≤5 min on failure
function scheduleNextCheck() {
  if (!(UPDATE_CHECK_MS > 0 && updateState.enabled)) return;
  const delay = updateState.lastResult === "error" ? UPDATE_RETRY_MS : UPDATE_CHECK_MS;
  setTimeout(async () => {
    await selfUpdate("heartbeat");
    scheduleNextCheck();
  }, delay).unref();
}
scheduleNextCheck();
await poll();
setInterval(poll, POLL_MS);
server.on("error", (e) => {
  if (e.code === "EADDRINUSE") {
    console.error(`Port ${PORT} already in use (another agent instance?). Exiting.`);
    process.exit(1);
  }
  console.error(`Server error: ${e.message}`);
});
server.listen(PORT, HOST, () => {
  const beat = updateState.enabled && UPDATE_CHECK_MS > 0 ? `every ${UPDATE_CHECK_MS / 60000}min` : "off";
  console.log(`SecTool agent v${AGENT_VERSION} on ${HOST}:${PORT} (${os.hostname()}, ${os.platform()}), history ${RETENTION_MS / 60000}min, auth=${!!TOKEN}, updates=${UPDATE_URL || "off"}, update-heartbeat=${beat}`);
});
