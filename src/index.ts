/**
 * SecTool entry point.
 *
 * Usage:
 *   node src/index.ts                 # run the service
 *   node src/index.ts --self-test     # push a synthetic alert end-to-end
 *   node src/index.ts --print-config  # print the resolved config (redacted)
 */
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { loadEnvFile } from "./util/env.ts";
import { loadConfig, redactConfig, ConfigError } from "./config.ts";
import { setLogLevel, log } from "./logger.ts";
import { parseSyslog } from "./syslog/parser.ts";
import { startSyslogServer, type SyslogServer } from "./syslog/server.ts";
import { Summarizer } from "./summarize/claude.ts";
import { Pipeline } from "./pipeline.ts";
import { runBackfill, runIngestFile } from "./backfill.ts";
import { runSshPull, setupSsh, runWatch, loadSshTarget } from "./ingest/sshPull.ts";
import { startWebServer } from "./web/server.ts";
import { startFlowCollector } from "./netflow/collector.ts";
import { setActiveFlowStore } from "./netflow/flowAccess.ts";
import { startBlocker } from "./respond/blocker.ts";
import { runDigest } from "./digest/digest.ts";
import { startDigestScheduler } from "./digest/scheduler.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const STATS_INTERVAL_MS = 5 * 60_000;
const MAINTAIN_INTERVAL_MS = 60_000;

// A realistic UDM Pro / Suricata IPS line used for --self-test.
const SAMPLE_ALERT =
  "<132>Jun 21 12:34:56 UDMPRO suricata: [1:2024897:4] ET MALWARE Likely Evil EXE Download from Dotted Quad [Classification: A Network Trojan was Detected] [Priority: 1] {TCP} 10.0.0.42:51514 -> 185.220.101.7:80";
const SAMPLE_CONTEXT = [
  "<134>Jun 21 12:34:55 UDMPRO kernel: [WAN_LOCAL-default-D] IN=eth8 OUT= SRC=185.220.101.7 DST=10.0.0.42 PROTO=TCP SPT=80 DPT=51514",
  "<134>Jun 21 12:34:50 UDMPRO dnsmasq: query[A] evil-cdn.example from 10.0.0.42",
];

async function runSelfTest(): Promise<void> {
  log.info("Running self-test: injecting a synthetic IPS alert…");
  const cfg = loadConfig();
  setLogLevel(cfg.runtime.logLevel);
  const summarizer = new Summarizer(cfg);
  await summarizer.preflight();
  const pipeline = new Pipeline(cfg, summarizer);

  const now = Date.now();
  for (const line of SAMPLE_CONTEXT) pipeline.ingest(parseSyslog(line, "127.0.0.1", now - 5000));
  pipeline.ingest(parseSyslog(SAMPLE_ALERT, "127.0.0.1", now));

  // Give the async pipeline time to summarize + post.
  await new Promise((r) => setTimeout(r, 20_000));
  log.info(`Self-test stats: ${JSON.stringify(pipeline.stats)}`);
  if (pipeline.stats.notified > 0) log.info("Self-test complete ✓ — check your Discord channel.");
  else log.warn("Self-test did not notify. Review the logs above (DRY_RUN? auth? webhook?).");
}

async function runService(): Promise<void> {
  const cfg = loadConfig();
  setLogLevel(cfg.runtime.logLevel);

  log.info("Starting SecTool…");
  const summarizer = new Summarizer(cfg);
  await summarizer.preflight();

  const pipeline = new Pipeline(cfg, summarizer);
  let server: SyslogServer | undefined;

  try {
    server = await startSyslogServer(cfg, (event) => pipeline.ingest(event));
  } catch (err) {
    log.error(`Failed to bind syslog listener: ${(err as Error).message}`);
    if ((err as NodeJS.ErrnoException).code === "EACCES") {
      log.error("Port < 1024 needs admin/root. Use SYSLOG_UDP_PORT=5514 and point the UDM there.");
    }
    process.exit(1);
  }

  log.info(
    `SecTool ready. Forward UDM Pro syslog to this host on ` +
      `${cfg.syslog.protocol.toUpperCase()} ${cfg.syslog.udpPort}. ` +
      `Summaries -> Discord. (DRY_RUN=${cfg.runtime.dryRun})`,
  );

  // NetFlow/IPFIX collector (historical per-flow data for investigations).
  if (cfg.netflow.enabled) {
    try {
      const collector = await startFlowCollector(cfg);
      setActiveFlowStore(collector.store);
    } catch (err) {
      log.error(`NetFlow collector failed to start: ${(err as Error).message}`);
    }
  }

  // Firewall blocker (active response).
  if (cfg.block.enabled) {
    try {
      await startBlocker(cfg);
    } catch (err) {
      log.error(`Blocker failed to start: ${(err as Error).message}`);
    }
  }

  // Scheduled threat digest.
  if (cfg.digest.enabled) startDigestScheduler(cfg);

  // Local web dashboard (alerts + investigation tools).
  if (cfg.web.enabled) {
    try {
      await startWebServer(cfg);
    } catch (err) {
      log.error(`Web dashboard failed to start: ${(err as Error).message}`);
    }
  }

  // Real-time polling of the UDM's Mongo store (reliable path when UniFi's
  // syslog forwarding isn't working). Runs alongside the syslog listener.
  if (cfg.watch.enabled && loadSshTarget()) {
    log.info("Mongo watcher enabled (SSH connection configured).");
    void runWatch(cfg, Date.now()).catch((err) =>
      log.error(`Watcher stopped: ${(err as Error).message}`),
    );
  } else if (cfg.watch.enabled) {
    log.info("Mongo watcher idle — no ssh-target.json (run --setup-ssh to enable real-time polling).");
  }

  const maintainTimer = setInterval(() => pipeline.maintain(Date.now()), MAINTAIN_INTERVAL_MS);
  const statsTimer = setInterval(() => {
    log.info(`Stats: ${JSON.stringify(pipeline.stats)} | buffer=${pipeline.bufferSize}`);
  }, STATS_INTERVAL_MS);
  maintainTimer.unref();
  statsTimer.unref();

  const shutdown = async (signal: string) => {
    log.info(`Received ${signal}, shutting down…`);
    clearInterval(maintainTimer);
    clearInterval(statsTimer);
    await server?.close().catch(() => undefined);
    log.info(`Final stats: ${JSON.stringify(pipeline.stats)}`);
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("uncaughtException", (err) => log.error(`uncaughtException: ${err.stack ?? err}`));
  process.on("unhandledRejection", (reason) => log.error(`unhandledRejection: ${String(reason)}`));
}

async function main(): Promise<void> {
  // Load .env next to the project root (one level up from src/).
  loadEnvFile(join(HERE, "..", ".env"));

  const argv = process.argv.slice(2);
  const args = new Set(argv);

  try {
    if (args.has("--print-config")) {
      console.log(JSON.stringify(redactConfig(loadConfig()), null, 2));
      return;
    }
    if (args.has("--self-test")) {
      await runSelfTest();
      return;
    }
    if (args.has("--setup-ssh")) {
      await setupSsh();
      return;
    }
    if (args.has("--watch")) {
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      await runWatch(cfg, Date.now());
      return;
    }
    const digestIdx = argv.findIndex((a) => a === "--digest" || a.startsWith("--digest="));
    if (digestIdx !== -1) {
      const inline = argv[digestIdx]!.split("=")[1];
      const next = argv[digestIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      await runDigest(cfg, raw ? Number(raw) || cfg.digest.periodHours : cfg.digest.periodHours, Date.now());
      return;
    }
    if (args.has("--web")) {
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      if (cfg.netflow.enabled) {
        try {
          const collector = await startFlowCollector(cfg);
          setActiveFlowStore(collector.store);
        } catch (err) {
          log.error(`NetFlow collector failed to start: ${(err as Error).message}`);
        }
      }
      if (cfg.block.enabled) {
        try { await startBlocker(cfg); } catch (err) { log.error(`Blocker failed: ${(err as Error).message}`); }
      }
      await startWebServer(cfg);
      log.info("Web dashboard running. Press Ctrl+C to stop.");
      await new Promise(() => {}); // run until killed
      return;
    }
    const pullIdx = argv.findIndex((a) => a === "--pull" || a.startsWith("--pull="));
    if (pullIdx !== -1) {
      const inline = argv[pullIdx]!.split("=")[1];
      const next = argv[pullIdx + 1];
      const hoursRaw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      const hours = hoursRaw ? Number(hoursRaw) : 24;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --pull hours: "${hoursRaw}". Use e.g. --pull 24`);
        process.exit(2);
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      await runSshPull(cfg, hours, Date.now());
      return;
    }
    const ingestIdx = argv.findIndex((a) => a === "--ingest-file" || a.startsWith("--ingest-file="));
    if (ingestIdx !== -1) {
      const inline = argv[ingestIdx]!.split("=")[1];
      const next = argv[ingestIdx + 1];
      const path = inline ?? (next && !next.startsWith("--") ? next : undefined);
      if (!path) {
        log.error("Usage: --ingest-file <path-to-events.json>");
        process.exit(2);
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      await runIngestFile(cfg, path, Date.now());
      return;
    }
    const backfillIdx = argv.findIndex((a) => a === "--backfill" || a.startsWith("--backfill="));
    if (backfillIdx !== -1) {
      const inline = argv[backfillIdx]!.split("=")[1];
      const next = argv[backfillIdx + 1];
      const hoursRaw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      const hours = hoursRaw ? Number(hoursRaw) : 24;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --backfill hours: "${hoursRaw}". Use e.g. --backfill 24`);
        process.exit(2);
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      await runBackfill(cfg, hours, Date.now());
      return;
    }
    await runService();
  } catch (err) {
    if (err instanceof ConfigError) {
      log.error(`Configuration error: ${err.message}`);
      log.error("Copy .env.example to .env and fill in the required values.");
      process.exit(2);
    }
    log.error(`Fatal: ${(err as Error).stack ?? (err as Error).message}`);
    process.exit(1);
  }
}

void main();
