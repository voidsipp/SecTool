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
import { readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const AGENT_VERSION = "1.2.0";

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
// Recurring update-check heartbeat. Default every 6h; 0 disables it. A 5-minute
// floor keeps a misconfigured value from hammering the update server.
const UPDATE_CHECK_RAW = Number(
  process.env.AGENT_UPDATE_CHECK_MIN ?? fileCfg.updateCheckMin ?? 360,
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

// Never delete OS-critical binaries or the node runtime the agent runs on.
function isProtectedPath(p) {
  if (!p) return true;
  const lp = p.replace(/\\/g, "/").toLowerCase();
  if (/^[a-z]:\/?$/.test(lp) || lp === "/") return true; // a drive root or filesystem root
  if (process.execPath && lp === process.execPath.replace(/\\/g, "/").toLowerCase()) return true; // our own node
  const guarded = ["c:/windows/", "/bin/", "/sbin/", "/usr/", "/lib/", "/lib64/", "/boot/", "/etc/", "/system/", "/library/apple/"];
  return guarded.some((g) => lp.startsWith(g));
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
  const shape = (r) => ({ proto: r.proto, localAddr: r.laddr, localPort: r.lport, remoteIp: r.raddr, remotePort: r.rport, state: r.state, pid: r.procid, process: r.pname, path: r.ppath, firstSeen: r.firstSeen, lastSeen: r.lastSeen });
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
      const finish = () => {
        const seenPaths = new Set();
        const results = targets.map((t) => {
          const r = { pid: t.procid, process: t.pname, killed: !!t._killed };
          if (t._killErr) r.error = t._killErr;
          if (deleteFile && t.ppath && !seenPaths.has(t.ppath)) {
            seenPaths.add(t.ppath);
            r.path = t.ppath;
            if (isProtectedPath(t.ppath)) r.deleteError = "refused: protected/system path";
            else {
              try {
                unlinkSync(t.ppath);
                r.deleted = true;
              } catch (err) {
                r.deleteError = err.message;
              }
            }
          }
          console.log(`[KILL] ${new Date().toISOString()} pid=${t.procid} name=${t.pname || "?"} signal=${signal} killed=${r.killed} deleted=${r.deleted || false}${r.deleteError ? " delErr=" + r.deleteError : ""} from=${req.socket.remoteAddress}`);
          return r;
        });
        json(200, { ok: true, host: os.hostname(), signal, deleteFile, results });
      };
      if (deleteFile) setTimeout(finish, 600);
      else finish();
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

await selfUpdate("startup"); // check for a newer agent on every startup
// Recurring update-check heartbeat: keep long-lived agents current without a
// restart. selfUpdate() relaunches + exits the process if it pulls a new build.
if (UPDATE_CHECK_MS > 0 && updateState.enabled) {
  setInterval(() => selfUpdate("heartbeat"), UPDATE_CHECK_MS).unref();
}
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
