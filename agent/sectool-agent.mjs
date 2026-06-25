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
 *      AGENT_HOST (0.0.0.0), AGENT_POLL_MS (4000), AGENT_RETENTION_MIN (30).
 */
import http from "node:http";
import os from "node:os";
import { execFile, spawn } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const AGENT_VERSION = "1.0.0";

// Config resolves from env first, then agent.config.json next to this script
// (written by the installer), so a scheduled task/service needs no env wiring.
const SELF = fileURLToPath(import.meta.url);
const SELFDIR = dirname(SELF);
let fileCfg = {};
try {
  fileCfg = JSON.parse(readFileSync(join(SELFDIR, "agent.config.json"), "utf8"));
} catch {
  /* no config file — use env/defaults */
}

const PORT = Number(process.env.AGENT_PORT || fileCfg.port || 7879);
const HOST = process.env.AGENT_HOST || fileCfg.host || "0.0.0.0";
const TOKEN = process.env.AGENT_TOKEN || fileCfg.token || "";
const UPDATE_URL = (process.env.AGENT_UPDATE_URL || fileCfg.updateUrl || "").replace(/\/+$/, "");
const POLL_MS = Number(process.env.AGENT_POLL_MS || fileCfg.pollMs || 4000);
const RETENTION_MS = Number(process.env.AGENT_RETENTION_MIN || fileCfg.retentionMin || 30) * 60000;

if (!TOKEN) console.warn("WARNING: AGENT_TOKEN not set — the API is unauthenticated. Set AGENT_TOKEN for real use.");

function isNewer(a, b) {
  const pa = String(a).split("."), pb = String(b).split(".");
  for (let i = 0; i < 3; i++) {
    const x = Number(pa[i] || 0), y = Number(pb[i] || 0);
    if (x > y) return true;
    if (x < y) return false;
  }
  return false;
}

/** Check the SecTool server for a newer agent; if found, overwrite self + relaunch. */
async function selfUpdate() {
  if (!UPDATE_URL || process.env.AGENT_NO_UPDATE) return;
  try {
    const r = await fetch(`${UPDATE_URL}/version`, { signal: AbortSignal.timeout(5000) });
    if (!r.ok) return;
    const { version } = await r.json();
    if (!version || !isNewer(version, AGENT_VERSION)) {
      console.log(`Agent v${AGENT_VERSION} is current.`);
      return;
    }
    console.log(`Update available: v${AGENT_VERSION} -> v${version}. Downloading…`);
    const code = await (await fetch(`${UPDATE_URL}/agent`, { signal: AbortSignal.timeout(20000) })).text();
    if (!/AGENT_VERSION\s*=/.test(code) || code.length < 1000) {
      console.warn("Update payload looked invalid; keeping current version.");
      return;
    }
    writeFileSync(SELF, code);
    console.log(`Updated to v${version}; relaunching…`);
    // Relaunch the new code independently of how we were started, then exit.
    spawn(process.execPath, [SELF], { detached: true, stdio: "ignore", env: process.env }).unref();
    process.exit(0);
  } catch (err) {
    console.warn(`Update check failed (continuing on v${AGENT_VERSION}): ${err.message}`);
  }
}

/** key -> { proto, lport, raddr, rport, state, pid, pname, ppath, firstSeen, lastSeen } */
const buffer = new Map();

function run(cmd, args) {
  return new Promise((resolve) => {
    execFile(cmd, args, { maxBuffer: 16e6, windowsHide: true, timeout: 12000 }, (err, stdout) =>
      resolve(err ? "" : String(stdout)),
    );
  });
}

async function snapshotWindows() {
  const ps = [
    "$ErrorActionPreference='SilentlyContinue';",
    "$p=@{}; Get-Process | ForEach-Object { $p[[int]$_.Id]=@{n=$_.ProcessName;path=$_.Path} };",
    "$r=New-Object System.Collections.ArrayList;",
    "Get-NetTCPConnection | ForEach-Object { $x=$p[[int]$_.OwningProcess]; [void]$r.Add([pscustomobject]@{proto='TCP';laddr=$_.LocalAddress;lport=$_.LocalPort;raddr=$_.RemoteAddress;rport=$_.RemotePort;state=[string]$_.State;procid=$_.OwningProcess;pname=$x.n;ppath=$x.path}) };",
    "Get-NetUDPEndpoint | ForEach-Object { $x=$p[[int]$_.OwningProcess]; [void]$r.Add([pscustomobject]@{proto='UDP';laddr=$_.LocalAddress;lport=$_.LocalPort;raddr='*';rport=0;state='Listen';procid=$_.OwningProcess;pname=$x.n;ppath=$x.path}) };",
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
    const key = `${r.proto}|${r.lport}|${r.raddr}|${r.rport}|${r.procid}`;
    const ex = buffer.get(key);
    if (ex) {
      ex.lastSeen = now;
      ex.state = r.state;
    } else {
      buffer.set(key, { ...r, firstSeen: now, lastSeen: now });
    }
  }
  const cutoff = now - RETENTION_MS;
  for (const [k, v] of buffer) if (v.lastSeen < cutoff) buffer.delete(k);
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
    return json(200, { ok: true, version: AGENT_VERSION, host: os.hostname(), platform: os.platform(), tracked: buffer.size, retentionMin: RETENTION_MS / 60000, auth: !!TOKEN });
  }
  if (!ok) return json(401, { error: "unauthorized" });
  const shape = (r) => ({ proto: r.proto, localPort: r.lport, remoteIp: r.raddr, remotePort: r.rport, state: r.state, pid: r.procid, process: r.pname, path: r.ppath, firstSeen: r.firstSeen, lastSeen: r.lastSeen });
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
  json(404, { error: "not found" });
});

await selfUpdate(); // check for a newer agent on every startup
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
  console.log(`SecTool agent v${AGENT_VERSION} on ${HOST}:${PORT} (${os.hostname()}, ${os.platform()}), history ${RETENTION_MS / 60000}min, auth=${!!TOKEN}, updates=${UPDATE_URL || "off"}`);
});
