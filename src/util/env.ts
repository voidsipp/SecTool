/**
 * Minimal .env loader (no dependency on dotenv).
 *
 * Parses KEY=VALUE lines, ignores blanks and `#` comments, supports single and
 * double quoted values, and does NOT overwrite variables already present in the
 * real process environment (so OS env wins over the file).
 */
import { readFileSync, existsSync } from "node:fs";

export function loadEnvFile(path: string): boolean {
  if (!existsSync(path)) return false;
  const text = readFileSync(path, "utf8");
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    if (!key) continue;
    let value = line.slice(eq + 1).trim();
    // Strip surrounding matching quotes.
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
  return true;
}
