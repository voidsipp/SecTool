#!/usr/bin/env node
/**
 * Pre-commit guard. Blocks commits that would break the app at startup or build:
 *
 *   1) `node --check` on every staged .ts/.js/.mjs file — catches parse-fatal
 *      issues that crash Node's startup type-stripping before the app can boot.
 *      This is exactly the class of bug that has broken startup before:
 *        - a markdown "**​/" sequence closing a block comment early,
 *        - stray NUL / control bytes in source.
 *   2) `tsc --noEmit` — a full type check across the project.
 *
 * Exits non-zero on any failure so `git commit` aborts. Emergency bypass:
 * `git commit --no-verify` (do not make that a habit).
 *
 * Run manually any time with: `npm run check`.
 */
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";

const SRC_RE = /\.(ts|mts|cts|mjs|cjs|js)$/;

function capture(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { encoding: "utf8", ...opts });
}

// --- collect staged source files (added / copied / modified / renamed) ---
let staged = [];
try {
  staged = capture("git", ["diff", "--cached", "--name-only", "--diff-filter=ACMR"])
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean)
    .filter((f) => SRC_RE.test(f) && existsSync(f));
} catch (err) {
  console.error("preflight: failed to list staged files:", err.message);
  process.exit(1);
}

let ok = true;

// --- 1) parse-check each staged file (report all failures, don't stop at first) ---
for (const f of staged) {
  try {
    execFileSync(process.execPath, ["--check", f], { stdio: ["ignore", "ignore", "pipe"] });
  } catch (err) {
    ok = false;
    const msg = (err.stderr || err.message || "").toString().trim();
    console.error(`\n✗ parse error — ${f}\n${msg}`);
  }
}

// --- 2) full type check (skip if parsing already failed; tsc is the slow step) ---
if (ok) {
  const localTsc = "node_modules/typescript/bin/tsc";
  try {
    if (existsSync(localTsc)) {
      execFileSync(process.execPath, [localTsc, "--noEmit"], { stdio: ["ignore", "pipe", "pipe"] });
    } else {
      execFileSync("npx", ["tsc", "--noEmit"], { stdio: ["ignore", "pipe", "pipe"], shell: true });
    }
  } catch (err) {
    ok = false;
    const msg = (err.stdout || err.stderr || err.message || "").toString().trim();
    console.error(`\n✗ tsc --noEmit failed:\n${msg}`);
  }
}

if (!ok) {
  console.error("\n⛔ commit blocked by preflight (parse + typecheck). Fix the errors above.");
  console.error("   Emergency bypass (discouraged): git commit --no-verify\n");
  process.exit(1);
}
console.log(`✓ preflight OK — ${staged.length} staged source file(s) parse; typecheck clean.`);
