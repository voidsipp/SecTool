/**
 * Orchestrates the per-event flow:
 *   buffer -> detect -> severity filter -> dedupe -> correlate -> summarize -> notify
 * Every stage is guarded so a single bad event can never crash the service.
 */
import type { Config } from "./config.ts";
import type { LogEvent } from "./types.ts";
import { SEVERITY_ORDER } from "./types.ts";
import { LogBuffer } from "./ingest/logBuffer.ts";
import { detectAlert } from "./ingest/alertDetector.ts";
import { correlate } from "./enrich/correlate.ts";
import { Summarizer } from "./summarize/claude.ts";
import { DiscordNotifier } from "./notify/discord.ts";
import { Deduper } from "./dedupe.ts";
import { alertStore } from "./store/alertStore.ts";
import { enrichIp, pickExternalIp, escalate } from "./investigate/enrich.ts";
import { log } from "./logger.ts";

export interface PipelineStats {
  received: number;
  alerts: number;
  belowThreshold: number;
  suppressed: number;
  notified: number;
  failed: number;
}

export class Pipeline {
  readonly #cfg: Config;
  readonly #buffer: LogBuffer;
  readonly #summarizer: Summarizer;
  readonly #discord: DiscordNotifier;
  readonly #dedupe: Deduper;
  readonly #minSeverityIdx: number;
  readonly stats: PipelineStats = {
    received: 0,
    alerts: 0,
    belowThreshold: 0,
    suppressed: 0,
    notified: 0,
    failed: 0,
  };

  constructor(cfg: Config, summarizer: Summarizer) {
    this.#cfg = cfg;
    this.#buffer = new LogBuffer(cfg.correlation.bufferSize, cfg.correlation.bufferTtlMs);
    this.#summarizer = summarizer;
    this.#discord = new DiscordNotifier(cfg);
    this.#dedupe = new Deduper(cfg.alerts.dedupeWindowMs);
    this.#minSeverityIdx = SEVERITY_ORDER.indexOf(cfg.alerts.minSeverity);
  }

  /** Ingest one parsed event. Always buffers; processes alerts asynchronously. */
  ingest(event: LogEvent): void {
    this.stats.received++;
    this.#buffer.push(event);

    let alert;
    try {
      alert = detectAlert(event, { customPattern: this.#cfg.alerts.customPattern });
    } catch (err) {
      log.warn(`Alert detection error: ${(err as Error).message}`);
      return;
    }
    if (!alert) return;
    this.stats.alerts++;

    if (SEVERITY_ORDER.indexOf(alert.severity) < this.#minSeverityIdx) {
      this.stats.belowThreshold++;
      log.debug(`Alert below threshold (${alert.severity}): ${alert.signature}`);
      return;
    }

    if (!this.#dedupe.shouldSend(alert.id, event.receivedAt)) {
      this.stats.suppressed++;
      log.debug(`Duplicate suppressed: ${alert.signature}`);
      return;
    }

    log.info(`Alert [${alert.severity}] ${alert.category}: ${alert.signature}`);

    // Process out-of-band so syslog ingestion is never blocked on the network.
    void this.#process(event, alert).catch((err) => {
      this.stats.failed++;
      log.error(`Pipeline error: ${(err as Error).message}`);
    });
  }

  async #process(event: LogEvent, alert: NonNullable<ReturnType<typeof detectAlert>>): Promise<void> {
    const ctx = correlate(alert, this.#buffer, this.#cfg);
    const summary = await this.#summarizer.summarize(ctx);
    let enrichment;
    if (this.#cfg.enrich.auto) {
      const ip = pickExternalIp(alert.srcIp, alert.dstIp);
      if (ip) {
        enrichment = await enrichIp(this.#cfg, ip).catch(() => undefined);
        const esc = escalate(summary.severity, enrichment, this.#cfg);
        if (esc.escalated) summary.severity = esc.severity;
      }
    }
    const ok = await this.#discord.send(ctx, summary, enrichment);
    alertStore.record(alert, summary, ok);
    if (ok) this.stats.notified++;
    else this.stats.failed++;
  }

  /** Periodic maintenance: prune buffer and dedupe table. */
  maintain(now: number): void {
    this.#buffer.prune(now);
    this.#dedupe.prune(now);
  }

  get bufferSize(): number {
    return this.#buffer.size;
  }
}
