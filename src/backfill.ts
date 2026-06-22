/**
 * One-time historical backfill of stored IDS/IPS events. Two sources:
 *   - runBackfill():   pull events from the UDM controller API (needs creds).
 *   - runIngestFile(): read an exported JSON file (e.g. a mongo dump pulled over
 *                      SSH from the UDM) — no credentials needed.
 *
 * Both feed the same processing: correlate events against each other, summarize
 * each with Claude, and post (deduped, severity-filtered, rate-limited) to
 * Discord — one message per alert.
 */
import { readFileSync } from "node:fs";
import type { Config } from "./config.ts";
import { SEVERITY_ORDER } from "./types.ts";
import { LogBuffer } from "./ingest/logBuffer.ts";
import { correlate } from "./enrich/correlate.ts";
import { Summarizer } from "./summarize/claude.ts";
import { DiscordNotifier } from "./notify/discord.ts";
import { Deduper } from "./dedupe.ts";
import { UnifiClient, type MappedEvent } from "./unifi/client.ts";
import { alertStore } from "./store/alertStore.ts";
import { log } from "./logger.ts";

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** Shared pipeline: map → buffer → filter → dedupe → summarize → notify. */
export async function processRawEvents(
  cfg: Config,
  raw: Record<string, unknown>[],
  nowMs: number,
  existingSummarizer?: Summarizer,
): Promise<void> {
  if (raw.length === 0) {
    log.info("No events to process. Nothing to do.");
    return;
  }

  // Reuse a pre-built summarizer (watcher) or create one (one-shot backfill).
  const summarizer = existingSummarizer ?? new Summarizer(cfg);
  if (!existingSummarizer) await summarizer.preflight();

  // Map and build a correlation buffer from the whole batch so each alert can be
  // enriched with the other events that involve the same hosts.
  const mapped: MappedEvent[] = raw.map((e) => UnifiClient.mapEvent(e));
  const buffer = new LogBuffer(mapped.length + 1, 0 /* no TTL for a fixed batch */);
  for (const m of mapped) buffer.push(m.logEvent);

  const minIdx = SEVERITY_ORDER.indexOf(cfg.alerts.minSeverity);
  const dedupe = new Deduper(cfg.alerts.dedupeWindowMs);
  const discord = new DiscordNotifier(cfg);

  const eligible = mapped.filter((m) => SEVERITY_ORDER.indexOf(m.alert.severity) >= minIdx);
  const belowThreshold = mapped.length - eligible.length;

  // Dedupe across the batch, keeping the most recent occurrence per identity.
  const seen = new Map<string, MappedEvent>();
  for (const m of eligible) seen.set(m.alert.id, m);
  let toSend = [...seen.values()].sort(
    (a, b) => (a.logEvent.timestamp ?? 0) - (b.logEvent.timestamp ?? 0),
  );
  const duplicates = eligible.length - toSend.length;

  if (toSend.length > cfg.backfill.maxEvents) {
    log.warn(
      `Capping at BACKFILL_MAX=${cfg.backfill.maxEvents} (of ${toSend.length} unique alerts). ` +
        `Posting the most recent ${cfg.backfill.maxEvents}.`,
    );
    toSend = toSend.slice(-cfg.backfill.maxEvents);
  }

  log.info(
    `Plan: ${mapped.length} events | ${belowThreshold} below ${cfg.alerts.minSeverity} | ` +
      `${duplicates} duplicates | ${toSend.length} to post.`,
  );

  let notified = 0;
  let failed = 0;
  for (let i = 0; i < toSend.length; i++) {
    const m = toSend[i]!;
    void dedupe.shouldSend(m.alert.id, m.logEvent.timestamp ?? nowMs);
    const ctx = correlate(m.alert, buffer, cfg);
    log.info(`(${i + 1}/${toSend.length}) [${m.alert.severity}] ${m.alert.signature}`);
    try {
      const summary = await summarizer.summarize(ctx);
      const ok = await discord.send(ctx, summary);
      alertStore.record(m.alert, summary, ok);
      if (ok) notified++;
      else failed++;
    } catch (err) {
      failed++;
      log.error(`Failed to process alert: ${(err as Error).message}`);
    }
    if (i < toSend.length - 1) await sleep(cfg.backfill.postDelayMs);
  }

  log.info(`Done: notified=${notified} failed=${failed}.`);
}

export async function runBackfill(cfg: Config, hours: number, nowMs: number): Promise<void> {
  const startMs = nowMs - Math.max(1, hours) * 3_600_000;
  log.info(`Backfill: fetching IDS/IPS events from the last ${hours}h via the UDM API…`);

  const client = new UnifiClient(cfg);
  await client.login();
  let raw: Record<string, unknown>[];
  try {
    raw = await client.fetchIpsEvents(startMs, nowMs, cfg.backfill.maxEvents * 4);
  } finally {
    await client.logout();
  }
  log.info(`Fetched ${raw.length} raw event(s) from the UDM.`);
  await processRawEvents(cfg, raw, nowMs);
}

/**
 * Parse an exported events file. Accepts a JSON array, a single object, or
 * newline-delimited JSON (mongoexport without --jsonArray). Tolerates a leading
 * `[` / trailing noise from shell wrappers.
 */
export function parseEventsText(raw: string): Record<string, unknown>[] {
  const text = raw.trim();
  if (!text) return [];

  // Whole-file JSON (array or object).
  try {
    const j = JSON.parse(text);
    if (Array.isArray(j)) return j as Record<string, unknown>[];
    if (j && typeof j === "object") {
      const data = (j as { data?: unknown }).data;
      if (Array.isArray(data)) return data as Record<string, unknown>[];
      return [j as Record<string, unknown>];
    }
  } catch {
    /* fall through to NDJSON */
  }

  // Newline-delimited JSON.
  const out: Record<string, unknown>[] = [];
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim().replace(/,\s*$/, "");
    if (!t || t === "[" || t === "]") continue;
    try {
      const o = JSON.parse(t);
      if (o && typeof o === "object") out.push(o as Record<string, unknown>);
    } catch {
      /* skip non-JSON lines (e.g. shell banners) */
    }
  }
  return out;
}

export async function runIngestFile(cfg: Config, path: string, nowMs: number): Promise<void> {
  log.info(`Ingesting events from file: ${path}`);
  const raw = parseEventsText(readFileSync(path, "utf8"));
  log.info(`Parsed ${raw.length} event(s) from ${path}.`);
  await processRawEvents(cfg, raw, nowMs);
}
