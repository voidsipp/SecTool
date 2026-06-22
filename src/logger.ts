/**
 * Tiny dependency-free leveled logger.
 */

export const LOG_LEVELS = ["debug", "info", "warn", "error"] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

const WEIGHT: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

let threshold = WEIGHT.info;

export function setLogLevel(level: LogLevel): void {
  threshold = WEIGHT[level];
}

function emit(level: LogLevel, args: unknown[]): void {
  if (WEIGHT[level] < threshold) return;
  const ts = new Date().toISOString();
  const tag = level.toUpperCase().padEnd(5);
  const line = `${ts} ${tag}`;
  // Route warn/error to stderr so they can be filtered downstream.
  const sink = level === "warn" || level === "error" ? console.error : console.log;
  sink(line, ...args);
}

export const log = {
  debug: (...args: unknown[]) => emit("debug", args),
  info: (...args: unknown[]) => emit("info", args),
  warn: (...args: unknown[]) => emit("warn", args),
  error: (...args: unknown[]) => emit("error", args),
};
