/**
 * SecTool launcher / startup preflight.
 *
 * This file is intentionally PLAIN JavaScript (no TypeScript syntax) so that it
 * parses and runs on every Node version SecTool might be launched with — even
 * ones too old to execute the `.ts` entrypoint. Its whole job is to make
 * "the project won't start" produce a clear, actionable message instead of a
 * cryptic `ERR_UNKNOWN_FILE_EXTENSION` crash.
 *
 * Why this exists:
 *   The app is run directly as TypeScript (`node src/index.ts ...`) using Node's
 *   native type-stripping. Flagless type-stripping is only the DEFAULT on:
 *       - Node >= 22.18.0   (backport)
 *       - Node >= 23.6.0    (and all of 24.x, 25.x, …)
 *   On Node 22.6.0–22.17.x and 23.0.0–23.5.x the capability exists but must be
 *   enabled with `--experimental-strip-types`. Below 22.6.0 it does not exist at
 *   all. Running `node src/index.ts` on those in-between versions fails with an
 *   opaque "Unknown file extension .ts" error.
 *
 * What this launcher does:
 *   - Modern Node (strip-types on by default): import the TS entrypoint directly.
 *   - In-between Node (flag available, not default): transparently re-exec the
 *     same command with `--experimental-strip-types` so it Just Works.
 *   - Too-old Node (<22.6.0): print a precise upgrade message and exit non-zero.
 *
 * All CLI arguments are forwarded unchanged, so every `npm run <script>` that
 * points here behaves identically to invoking `src/index.ts` directly.
 *
 * Usage:
 *   node src/start.mjs [--self-test | --print-config | --backfill 24 | ...]
 */
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

/** Lowest Node release that can strip types at all (behind a flag). */
const MIN_SUPPORTED = { major: 22, minor: 6, patch: 0 };

const HERE = dirname(fileURLToPath(import.meta.url));
const TS_ENTRY = join(HERE, "index.ts");

/** Parse "v24.14.0" / "22.18.0-nightly" → {major, minor, patch}. */
function parseNodeVersion(raw) {
  const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(raw);
  if (!m) return { major: 0, minor: 0, patch: 0 };
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]) };
}

/** True when `v` is >= the given {major, minor[, patch]} floor. */
function atLeast(v, major, minor, patch = 0) {
  if (v.major !== major) return v.major > major;
  if (v.minor !== minor) return v.minor > minor;
  return v.patch >= patch;
}

/** Node versions where `node file.ts` strips types WITHOUT any flag. */
function stripsTypesByDefault(v) {
  if (v.major >= 24) return true; // 24.x and newer: always on
  if (v.major === 23) return atLeast(v, 23, 6); // unflagged from 23.6.0
  if (v.major === 22) return atLeast(v, 22, 18); // backported to 22.18.0
  return false;
}

/** Node versions where type-stripping exists but needs the experimental flag. */
function stripsTypesWithFlag(v) {
  if (stripsTypesByDefault(v)) return false;
  return atLeast(v, MIN_SUPPORTED.major, MIN_SUPPORTED.minor, MIN_SUPPORTED.patch);
}

function fail(message) {
  // Use stderr directly — the TS logger isn't loadable on unsupported runtimes.
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

async function main() {
  const version = parseNodeVersion(process.version);
  const forwarded = process.argv.slice(2);

  if (stripsTypesByDefault(version)) {
    // Fast path: the running Node executes TypeScript natively.
    await import(pathToFileURL(TS_ENTRY).href);
    return;
  }

  if (stripsTypesWithFlag(version)) {
    // Capability is present but off by default — re-exec with the flag so the
    // user never has to know. Inherit stdio and propagate the exit code/signal.
    process.stderr.write(
      `SecTool: Node ${process.version} needs --experimental-strip-types to run ` +
        `TypeScript; re-launching with it. Upgrade to Node >= 22.18.0 (or >= 23.6.0) ` +
        `to drop this extra step.\n`,
    );
    const result = spawnSync(
      process.execPath,
      ["--experimental-strip-types", TS_ENTRY, ...forwarded],
      { stdio: "inherit" },
    );
    if (result.error) fail(`SecTool: failed to re-launch Node: ${result.error.message}`);
    if (typeof result.status === "number") process.exit(result.status);
    // Terminated by a signal (e.g. Ctrl-C) — exit non-zero without a stack trace.
    process.exit(1);
  }

  fail(
    `SecTool requires Node.js >= 22.18.0 (or any 23.6.0+ / 24.x) to run its ` +
      `TypeScript sources, but this is Node ${process.version}.\n` +
      `Install a current LTS from https://nodejs.org and try again, e.g.:\n` +
      `  nvm install 22 && nvm use 22   # or download the latest LTS installer`,
  );
}

main().catch((err) => {
  process.stderr.write(`SecTool: fatal startup error: ${err?.stack ?? err}\n`);
  process.exit(1);
});
