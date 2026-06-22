/**
 * SSH-based historical pull: connect to the UDM, query its MongoDB event store,
 * and ingest the results through the standard summarize → Discord pipeline.
 *
 * Connection details are saved to `ssh-target.json` after the first run. We use
 * SSH **key** authentication (set up once) rather than storing a password — the
 * user types their password a single time while the public key is installed, and
 * every subsequent pull is passwordless. No secret is ever written to disk.
 *
 * The remote Mongo script is base64-encoded and decoded on the UDM, which avoids
 * all of the nested PowerShell/ssh/mongo quoting problems with `$gte` etc.
 */
import { spawn, spawnSync } from "node:child_process";
import { createInterface } from "node:readline/promises";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import type { Config } from "../config.ts";
import { parseEventsText, processRawEvents } from "../backfill.ts";
import { UnifiClient, type MappedEvent } from "../unifi/client.ts";
import { Summarizer } from "../summarize/claude.ts";
import { log } from "../logger.ts";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const CONFIG_PATH = join(ROOT, "ssh-target.json");
const STATE_PATH = join(ROOT, ".watch-state.json");
const KEY_DIR = join(ROOT, ".ssh");
const DEFAULT_KEY = join(KEY_DIR, "sectool_udm");

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export interface SshTarget {
  host: string;
  port: number;
  user: string;
  authMode: "key" | "password";
  identityFile?: string;
  mongoPort: number;
  db: string;
  collection: string;
  timestampField: string;
  /** Optional regex (alternation) the doc `key` must match, e.g. "THREAT_DETECTED|TRAFFIC_BLOCKED". */
  keyFilter?: string;
  useUnifiOsShell: boolean;
}

export function loadSshTarget(): SshTarget | null {
  if (!existsSync(CONFIG_PATH)) return null;
  try {
    return JSON.parse(readFileSync(CONFIG_PATH, "utf8")) as SshTarget;
  } catch (err) {
    log.warn(`Could not read ${CONFIG_PATH}: ${(err as Error).message}`);
    return null;
  }
}

function saveSshTarget(t: SshTarget): void {
  writeFileSync(CONFIG_PATH, JSON.stringify(t, null, 2), { mode: 0o600 });
  log.info(`Saved SSH connection to ${CONFIG_PATH}`);
}

function sshBaseArgs(t: SshTarget, opts: { batch: boolean }): string[] {
  const args = [
    "-o",
    "StrictHostKeyChecking=accept-new",
    "-o",
    "ConnectTimeout=15",
    "-p",
    String(t.port),
  ];
  if (opts.batch) args.push("-o", "BatchMode=yes");
  if (t.authMode === "key" && t.identityFile) args.push("-i", t.identityFile);
  return args;
}

function target(t: SshTarget): string {
  return `${t.user}@${t.host}`;
}

/** Wrap a Mongo shell script as a base64-piped remote command (quoting-safe). */
export function mongoScriptCommand(t: SshTarget, js: string): string {
  const b64 = Buffer.from(js, "utf8").toString("base64");
  const core = `echo ${b64} | base64 -d | mongo --quiet --port ${t.mongoPort} ${t.db}`;
  return t.useUnifiOsShell ? `unifi-os shell -c "${core}"` : core;
}

/** Build the remote command that emits the events as JSON on stdout. */
function buildRemoteCommand(t: SshTarget, cutoffMs: number, limit: number): string {
  const f = t.timestampField;
  // keyFilter is alphanumeric + | + _ (validated at setup), safe in a /regex/ literal.
  const filter = t.keyFilter ? `,key:/${t.keyFilter}/` : "";
  const js =
    `print(JSON.stringify(db.${t.collection}.find({${f}:{$gte:${cutoffMs}}${filter}})` +
    `.sort({${f}:1}).limit(${limit}).toArray()))`;
  return mongoScriptCommand(t, js);
}

/**
 * Run an arbitrary command on the UDM over SSH and return combined stdout+stderr.
 * Resolves even on a non-zero exit (tools like tcpdump exit non-zero on timeout);
 * rejects only on spawn error or our own timeout. Used by the investigation tools.
 */
export function sshExec(remote: string, opts: { timeoutMs?: number } = {}): Promise<string> {
  const t = requireTarget();
  return new Promise<string>((resolve, reject) => {
    const child = spawn("ssh", [...sshBaseArgs(t, { batch: true }), target(t), remote], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (d: string) => (out += d));
    child.stderr.on("data", (d: string) => (err += d));
    const timer = opts.timeoutMs
      ? setTimeout(() => {
          child.kill("SIGKILL");
          reject(new Error("SSH command timed out"));
        }, opts.timeoutMs)
      : null;
    child.on("error", (e) => {
      if (timer) clearTimeout(timer);
      reject(e);
    });
    child.on("close", () => {
      if (timer) clearTimeout(timer);
      resolve(err ? `${out}\n${err}`.trim() : out);
    });
  });
}

/** Run a Mongo shell script on the UDM and return its raw stdout. */
export function mongoQuery(js: string, opts: { timeoutMs?: number } = {}): Promise<string> {
  return sshExec(mongoScriptCommand(requireTarget(), js), opts);
}

/** Pull + map alerts for a window without any processing/posting (for the GUI). */
export async function pullMapped(cfg: Config, hours: number, nowMs: number): Promise<MappedEvent[]> {
  const t = requireTarget();
  const cutoff = nowMs - Math.max(1, hours) * 3_600_000;
  const raw = await fetchRaw(t, cutoff, cfg.backfill.maxEvents * 4);
  return raw.map((e) => UnifiClient.mapEvent(e));
}

function ensureKey(identityFile: string): void {
  if (existsSync(identityFile)) return;
  mkdirSync(dirname(identityFile), { recursive: true });
  log.info(`Generating SSH key at ${identityFile}…`);
  const r = spawnSync(
    "ssh-keygen",
    ["-t", "ed25519", "-N", "", "-f", identityFile, "-C", "sectool-udm"],
    { stdio: "inherit" },
  );
  if (r.status !== 0) throw new Error("ssh-keygen failed (is OpenSSH installed?).");
}

/** Install the public key on the UDM. Prompts for the password once. */
function installKey(t: SshTarget): boolean {
  const pub = readFileSync(`${t.identityFile}.pub`, "utf8").trim();
  // pub is "ssh-ed25519 AAAA... comment" — safe inside single quotes.
  const remote =
    `umask 077; mkdir -p ~/.ssh; ` +
    `grep -qxF '${pub}' ~/.ssh/authorized_keys 2>/dev/null || echo '${pub}' >> ~/.ssh/authorized_keys`;
  log.info("Installing the public key on the UDM — enter your UDM SSH password when prompted:");
  const r = spawnSync("ssh", [...sshBaseArgs(t, { batch: false }), target(t), remote], {
    stdio: "inherit",
  });
  return r.status === 0;
}

function testConnection(t: SshTarget): boolean {
  const r = spawnSync(
    "ssh",
    [...sshBaseArgs(t, { batch: t.authMode === "key" }), target(t), "echo SECTOOL_OK"],
    { encoding: "utf8" },
  );
  return r.status === 0 && /SECTOOL_OK/.test(r.stdout ?? "");
}

export async function setupSsh(): Promise<SshTarget> {
  if (!process.stdin.isTTY) {
    throw new Error("SSH setup must be run interactively in a terminal (no TTY detected).");
  }
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const ask = async (q: string, def: string) => {
    const a = (await rl.question(`${q}${def ? ` [${def}]` : ""}: `)).trim();
    return a || def;
  };
  try {
    log.info("First-time SSH setup for UDM event pulls.");
    const host = await ask("UDM host/IP", "192.168.0.1");
    const port = Number(await ask("SSH port", "22"));
    const user = await ask("SSH username", "root");
    const collection = await ask("Mongo collection", "alert");
    const timestampField = await ask("Timestamp field", collection === "alert" ? "time" : "timestamp");
    const keyFilter = await ask(
      "Key filter regex (blank = all)",
      collection === "alert" ? "THREAT_DETECTED|TRAFFIC_BLOCKED" : "",
    );
    const useUnifiAns = (await ask("Wrap commands in 'unifi-os shell'? (y/N)", "n")).toLowerCase();
    const useUnifiOsShell = useUnifiAns.startsWith("y");

    const keyAns = (await ask("Set up passwordless key auth now? (Y/n)", "y")).toLowerCase();
    const authMode: SshTarget["authMode"] = keyAns.startsWith("n") ? "password" : "key";

    const t: SshTarget = {
      host,
      port: Number.isFinite(port) ? port : 22,
      user,
      authMode,
      identityFile: authMode === "key" ? DEFAULT_KEY : undefined,
      mongoPort: 27117,
      db: "ace",
      collection,
      timestampField,
      keyFilter: keyFilter || undefined,
      useUnifiOsShell,
    };

    if (authMode === "key") {
      ensureKey(DEFAULT_KEY);
      const ok = installKey(t);
      if (!ok) {
        log.warn(
          "Automatic key install failed. Add this public key in the UniFi OS UI " +
            "(Settings → SSH Keys), then re-run:",
        );
        log.warn(readFileSync(`${DEFAULT_KEY}.pub`, "utf8").trim());
      }
    } else {
      log.info("Using password auth — ssh will prompt for the password on each pull.");
    }

    log.info("Testing the connection…");
    if (testConnection(t)) {
      log.info("SSH connection OK ✓");
    } else {
      log.warn("Connection test did not succeed yet — saving config anyway; verify SSH access.");
    }

    saveSshTarget(t);
    return t;
  } finally {
    rl.close();
  }
}

/** Run the remote Mongo query over SSH and return the parsed event docs. */
async function fetchRaw(t: SshTarget, cutoffMs: number, limit: number): Promise<Record<string, unknown>[]> {
  const remote = buildRemoteCommand(t, cutoffMs, limit);
  const out = await new Promise<string>((resolve, reject) => {
    // stdin inherited so a password prompt (password mode) reaches the user;
    // stdout piped to capture the JSON; stderr inherited for banners/prompts.
    const child = spawn("ssh", [...sshBaseArgs(t, { batch: t.authMode === "key" }), target(t), remote], {
      stdio: ["inherit", "pipe", "inherit"],
    });
    let buf = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (d: string) => (buf += d));
    child.on("error", reject);
    child.on("close", (code) =>
      code === 0
        ? resolve(buf)
        : reject(new Error(`ssh exited with code ${code}. Check SSH access and that 'mongo' exists on the UDM.`)),
    );
  });
  return parseEventsText(out);
}

function requireTarget(): SshTarget {
  const t = loadSshTarget();
  if (!t) {
    throw new Error(
      "No saved SSH connection. Run `node src/index.ts --setup-ssh` once (interactively) first.",
    );
  }
  return t;
}

export async function runSshPull(cfg: Config, hours: number, nowMs: number): Promise<void> {
  let t = loadSshTarget();
  if (!t) {
    if (!process.stdin.isTTY) throw new Error(requireTargetMessage);
    t = await setupSsh();
  }

  const cutoff = nowMs - Math.max(1, hours) * 3_600_000;
  log.info(`Pulling IDS/IPS events from the last ${hours}h via SSH (${target(t)})…`);
  const raw = await fetchRaw(t, cutoff, cfg.backfill.maxEvents * 4);
  log.info(`Pulled ${raw.length} event(s) from the UDM.`);
  if (raw.length === 0) {
    log.warn(
      `No events parsed. The collection may differ — re-run --setup-ssh and try 'alarm', ` +
        `or check that IDS/IPS is enabled.`,
    );
    return;
  }
  await processRawEvents(cfg, raw, nowMs);
}

const requireTargetMessage =
  "No saved SSH connection. Run `node src/index.ts --setup-ssh` once (interactively) first.";

interface WatchState {
  lastSeen: number;
}

function loadWatchState(): WatchState | null {
  if (!existsSync(STATE_PATH)) return null;
  try {
    return JSON.parse(readFileSync(STATE_PATH, "utf8")) as WatchState;
  } catch {
    return null;
  }
}

function saveWatchState(s: WatchState): void {
  try {
    writeFileSync(STATE_PATH, JSON.stringify(s), { mode: 0o600 });
  } catch (err) {
    log.warn(`Could not persist watch state: ${(err as Error).message}`);
  }
}

/**
 * Real-time watcher: polls the UDM's Mongo event store on an interval and pushes
 * any new detections through the summarize → Discord pipeline. This is the
 * reliable real-time path on firmware where UniFi's syslog forwarding is broken.
 * A high-water-mark timestamp is persisted so restarts neither miss nor duplicate.
 */
export async function runWatch(cfg: Config, nowMs: number): Promise<void> {
  const t = requireTarget();
  const summarizer = new Summarizer(cfg);
  await summarizer.preflight();

  const state = loadWatchState();
  let lastSeen = state?.lastSeen ?? nowMs - cfg.watch.lookbackMs;
  log.info(
    `Watching UDM (${target(t)}) every ${cfg.watch.pollMs / 1000}s; ` +
      `starting from ${new Date(lastSeen).toISOString()}.`,
  );

  // eslint-disable-next-line no-constant-condition
  for (;;) {
    try {
      const raw = await fetchRaw(t, lastSeen + 1, cfg.backfill.maxEvents * 4);
      if (raw.length > 0) {
        // Advance the high-water mark to the newest event time before posting,
        // so a crash mid-batch doesn't replay everything.
        const maxTime = raw.reduce((m, e) => {
          const v = e["time"] ?? e["timestamp"];
          const n = typeof v === "number" ? v : Number((v as { $numberLong?: string })?.$numberLong ?? NaN);
          return Number.isFinite(n) && n > m ? n : m;
        }, lastSeen);
        log.info(`Watch: ${raw.length} new detection(s).`);
        await processRawEvents(cfg, raw, Date.now(), summarizer);
        lastSeen = maxTime;
        saveWatchState({ lastSeen });
      }
    } catch (err) {
      log.warn(`Watch poll failed (will retry): ${(err as Error).message}`);
    }
    await sleep(cfg.watch.pollMs);
  }
}
