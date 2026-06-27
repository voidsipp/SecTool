/**
 * SecTool entry point.
 *
 * Usage:
 *   node src/index.ts                 # run the service
 *   node src/index.ts --self-test     # push a synthetic alert end-to-end
 *   node src/index.ts --print-config  # print the resolved config (redacted)
 *   node src/index.ts --compare 24    # offline period-over-period comparison (Markdown)
 *   node src/index.ts --profile <ip>  # offline single-IP profile report (Markdown)
 *   node src/index.ts --assets 24     # offline internal-asset exposure scoreboard (Markdown)
 *   node src/index.ts --tuning 168    # offline signature tuning / noise-reduction report (Markdown)
 *   node src/index.ts --watchlist 24  # offline watchlist activity report (Markdown)
 *   node src/index.ts --rhythm 168    # offline temporal activity rhythm report (Markdown)
 *   node src/index.ts --backlog 720   # offline triage SLA backlog report (Markdown)
 *   node src/index.ts --novelty 168   # offline first-seen / novelty report (Markdown)
 *   node src/index.ts --killchain 168 # offline kill-chain / attack-stage report (Markdown)
 *   node src/index.ts --beacon 168    # offline beaconing / periodicity (C2 cadence) report (Markdown)
 *   node src/index.ts --efficacy 168  # offline IPS enforcement-gap / efficacy report (Markdown)
 *   node src/index.ts --spread 168    # offline spread / fan-out (scanner & spray) report (Markdown)
 *   node src/index.ts --cooccur 168   # offline signature co-occurrence / attack-chain report (Markdown)
 *   node src/index.ts --surge 168     # offline surge / burst (volume-spike) report (Markdown)
 *   node src/index.ts --persist 168   # offline persistence / repeat-offender longevity report (Markdown)
 *   node src/index.ts --edges 168     # offline attack-edge / lateral-movement report (Markdown)
 *   node src/index.ts --notify 168    # offline notification audit / alert-fatigue report (Markdown)
 *   node src/index.ts --classify 168  # offline threat-classification breakdown report (Markdown)
 *   node src/index.ts --focus 168     # offline threat-focus / concentration (Pareto) report (Markdown)
 *   node src/index.ts --netblocks 168 # offline source-netblock / infrastructure (CIDR) report (Markdown)
 *   node src/index.ts --coverage 168  # offline data-coverage / quality (dataset-integrity) report (Markdown)
 *   node src/index.ts --direction 168 # offline traffic-direction / exposure (inbound/outbound/lateral) report (Markdown)
 *   node src/index.ts --lifecycle 168 # offline signature lifecycle / chronic-vs-acute report (Markdown)
 *   node src/index.ts --risk 168      # offline risk-index / threat-posture (severity-weighted) report (Markdown)
 *   node src/index.ts --insight 168   # offline AI analyst-insight digest (summary coverage / re-grading / actions) (Markdown)
 *   node src/index.ts --escalation 168 # offline severity-escalation / trajectory (rising-vs-falling) report (Markdown)
 *   node src/index.ts --targets 168   # offline target / victim-exposure (which of your assets is hit hardest) report (Markdown)
 *   node src/index.ts --clusters 168  # offline coordinated-infrastructure / toolkit-cluster (botnet correlation) report (Markdown)
 *   node src/index.ts --cve 168       # offline CVE-exposure / exploited-vulnerability (patch worklist) report (Markdown)
 *   node src/index.ts --hygiene 720   # offline blocklist hygiene / stale-IOC (which blocks to keep vs prune) report (Markdown)
 *   node src/index.ts --recurrence 168 # offline recurrence / return-forecast (when each repeat attacker is due back) report (Markdown)
 *   node src/index.ts --ports 168     # offline service / port-exposure (which service is attacked / exposed) report (Markdown)
 *   node src/index.ts --scan 168      # offline scan-shape / reconnaissance-pattern (horizontal vs vertical vs sweep) report (Markdown)
 *   node src/index.ts --repertoire 168 # offline attacker-repertoire / sophistication (toolkit-operator vs one-trick probe) report (Markdown)
 *   node src/index.ts --iocs 168 --format plain  # offline threat-indicator (IOC) export
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
import { startReactiveBlocker } from "./respond/reactiveBlock.ts";
import { startHoneypot } from "./deception/honeypot.ts";
import { startBaselineMonitor } from "./anomaly/baseline.ts";
import { startAgentDistServer } from "./agent/distServer.ts";
import { runDigest } from "./digest/digest.ts";
import { buildComparison } from "./analytics/compare.ts";
import { buildProfile } from "./analytics/profile.ts";
import { buildAssets } from "./analytics/assets.ts";
import { buildTuning } from "./analytics/tuning.ts";
import { buildWatchlist } from "./analytics/watchlist.ts";
import { buildRhythm } from "./analytics/rhythm.ts";
import { buildBacklog } from "./analytics/backlog.ts";
import { buildNovelty } from "./analytics/novelty.ts";
import { buildKillChain } from "./analytics/killchain.ts";
import { buildBeacon } from "./analytics/beacon.ts";
import { buildEfficacy } from "./analytics/efficacy.ts";
import { buildSpread } from "./analytics/spread.ts";
import { buildCooccurrence } from "./analytics/cooccurrence.ts";
import { buildSurge } from "./analytics/surge.ts";
import { buildPersistence } from "./analytics/persistence.ts";
import { buildEdges } from "./analytics/edges.ts";
import { buildNotify } from "./analytics/notify.ts";
import { buildClassify } from "./analytics/classify.ts";
import { buildFocus } from "./analytics/focus.ts";
import { buildNetblock } from "./analytics/netblock.ts";
import { buildCoverage } from "./analytics/coverage.ts";
import { buildDirection } from "./analytics/direction.ts";
import { buildLifecycle } from "./analytics/lifecycle.ts";
import { buildRisk } from "./analytics/risk.ts";
import { buildInsight } from "./analytics/insight.ts";
import { buildEscalation } from "./analytics/escalation.ts";
import { buildTargets } from "./analytics/targets.ts";
import { buildClusters } from "./analytics/cluster.ts";
import { buildCve } from "./analytics/cve.ts";
import { buildHygiene } from "./analytics/hygiene.ts";
import { buildRecurrence } from "./analytics/recurrence.ts";
import { buildPorts } from "./analytics/ports.ts";
import { buildScan } from "./analytics/scan.ts";
import { buildRepertoire } from "./analytics/repertoire.ts";
import { buildIocExport, renderIoc, parseIocFormat, parseSeverityFloor } from "./analytics/iocExport.ts";
import { startDigestScheduler } from "./digest/scheduler.ts";
import { startFeedScheduler, refreshAndPostChangelog } from "./intel/feedScheduler.ts";

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

  // Threat-intel feeds (cross-reference + optional proactive blocking + changelog).
  if (cfg.intel.enabled) startFeedScheduler(cfg);

  // Reactive inbound blocking: block feed-listed IPs only when they initiate
  // inbound traffic (safe — never blocks destinations you reach out to).
  if (cfg.autoRespond.reactiveInbound) startReactiveBlocker(cfg);

  // Deception: decoy services that yield zero-false-positive compromise signals.
  if (cfg.honeypot.enabled) {
    try {
      await startHoneypot(cfg);
    } catch (err) {
      log.error(`Honeypot failed to start: ${(err as Error).message}`);
    }
  }

  // Behavioral baselining: learn per-host normal, flag deviations.
  if (cfg.anomaly.enabled) startBaselineMonitor(cfg);

  // Agent distribution + update server (one-liner install for LAN devices).
  if (cfg.agent.enabled) {
    try {
      startAgentDistServer(cfg);
    } catch (err) {
      log.error(`Agent dist server failed to start: ${(err as Error).message}`);
    }
  }

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
    if (args.has("--feeds")) {
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      const r = await refreshAndPostChangelog(cfg);
      log.info(`Feeds: ${r.total} entries, loaded=${r.loaded}.`);
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
    const compareIdx = argv.findIndex((a) => a === "--compare" || a.startsWith("--compare="));
    if (compareIdx !== -1) {
      const inline = argv[compareIdx]!.split("=")[1];
      const next = argv[compareIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      const hours = raw ? Number(raw) : 24;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --compare hours: "${raw}". Use e.g. --compare 24`);
        process.exit(2);
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: just print the Markdown comparison to stdout.
      console.log(buildComparison(hours, 12, Date.now()).markdown);
      return;
    }
    const profileIdx = argv.findIndex((a) => a === "--profile" || a.startsWith("--profile="));
    if (profileIdx !== -1) {
      const inline = argv[profileIdx]!.split("=")[1];
      const next = argv[profileIdx + 1];
      const ip = (inline ?? (next && !next.startsWith("--") ? next : undefined) ?? "").trim();
      if (!ip) {
        log.error("Usage: --profile <ip> [hours]   (hours optional; default = entire history)");
        process.exit(2);
      }
      // Optional trailing hours: either a numeric positional after the IP (when
      // the IP came from the next token) or a `--hours N` flag.
      let hours = 0;
      const hoursFlagIdx = argv.findIndex((a) => a === "--hours" || a.startsWith("--hours="));
      if (hoursFlagIdx !== -1) {
        const hi = argv[hoursFlagIdx]!.split("=")[1] ?? argv[hoursFlagIdx + 1];
        hours = hi ? Number(hi) || 0 : 0;
      } else if (!inline) {
        const after = argv[profileIdx + 2];
        if (after && !after.startsWith("--") && Number.isFinite(Number(after))) hours = Number(after);
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown profile to stdout.
      const model = buildProfile(ip, hours, Date.now());
      if (!model.valid) {
        log.error(`Invalid IP: "${ip}". Use e.g. --profile 185.220.101.7`);
        process.exit(2);
      }
      console.log(model.markdown);
      return;
    }
    const assetsIdx = argv.findIndex((a) => a === "--assets" || a.startsWith("--assets="));
    if (assetsIdx !== -1) {
      const inline = argv[assetsIdx]!.split("=")[1];
      const next = argv[assetsIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      const hours = raw ? Number(raw) : 24;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --assets hours: "${raw}". Use e.g. --assets 24`);
        process.exit(2);
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown scoreboard to stdout.
      console.log(buildAssets(hours, 50, Date.now()).markdown);
      return;
    }
    const tuningIdx = argv.findIndex((a) => a === "--tuning" || a.startsWith("--tuning="));
    if (tuningIdx !== -1) {
      const inline = argv[tuningIdx]!.split("=")[1];
      const next = argv[tuningIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --tuning hours: "${raw}". Use e.g. --tuning 168`);
        process.exit(2);
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown tuning report to stdout.
      console.log(buildTuning(hours, 40, Date.now()).markdown);
      return;
    }
    const watchlistIdx = argv.findIndex((a) => a === "--watchlist" || a.startsWith("--watchlist="));
    if (watchlistIdx !== -1) {
      const inline = argv[watchlistIdx]!.split("=")[1];
      const next = argv[watchlistIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      const hours = raw ? Number(raw) : 24;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --watchlist hours: "${raw}". Use e.g. --watchlist 24`);
        process.exit(2);
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown watchlist activity report to stdout.
      console.log(buildWatchlist(hours, 100, Date.now()).markdown);
      return;
    }
    const rhythmIdx = argv.findIndex((a) => a === "--rhythm" || a.startsWith("--rhythm="));
    if (rhythmIdx !== -1) {
      const inline = argv[rhythmIdx]!.split("=")[1];
      const next = argv[rhythmIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --rhythm hours: "${raw}". Use e.g. --rhythm 168`);
        process.exit(2);
      }
      // Optional `--tz <minutes>` to bucket the clock in local time (e.g. -300 = EST).
      let tzOffsetMinutes = 0;
      const tzIdx = argv.findIndex((a) => a === "--tz" || a.startsWith("--tz="));
      if (tzIdx !== -1) {
        const tzRaw = argv[tzIdx]!.split("=")[1] ?? argv[tzIdx + 1];
        const tz = tzRaw !== undefined ? Number(tzRaw) : NaN;
        if (!Number.isFinite(tz)) {
          log.error(`Invalid --tz minutes: "${tzRaw}". Use UTC offset in minutes, e.g. --tz -300 (EST) or --tz 60 (CET).`);
          process.exit(2);
        }
        tzOffsetMinutes = tz;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown activity rhythm report to stdout.
      console.log(buildRhythm(hours, tzOffsetMinutes, Date.now()).markdown);
      return;
    }
    const backlogIdx = argv.findIndex((a) => a === "--backlog" || a.startsWith("--backlog="));
    if (backlogIdx !== -1) {
      const inline = argv[backlogIdx]!.split("=")[1];
      const next = argv[backlogIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a wide 30-day window so genuinely stale, long-unhandled alerts surface.
      const hours = raw ? Number(raw) : 720;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --backlog hours: "${raw}". Use e.g. --backlog 720`);
        process.exit(2);
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown triage SLA backlog report to stdout.
      console.log(buildBacklog(hours, { nowMs: Date.now() }).markdown);
      return;
    }
    const noveltyIdx = argv.findIndex((a) => a === "--novelty" || a.startsWith("--novelty="));
    if (noveltyIdx !== -1) {
      const inline = argv[noveltyIdx]!.split("=")[1];
      const next = argv[noveltyIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so the baseline preceding the window has real history.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --novelty hours: "${raw}". Use e.g. --novelty 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap the rows listed per dimension.
      let limit = 25;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown novelty report to stdout.
      console.log(buildNovelty(hours, { limit, nowMs: Date.now() }).markdown);
      return;
    }
    const killchainIdx = argv.findIndex((a) => a === "--killchain" || a.startsWith("--killchain="));
    if (killchainIdx !== -1) {
      const inline = argv[killchainIdx]!.split("=")[1];
      const next = argv[killchainIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so multi-stage progression has room to show up.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --killchain hours: "${raw}". Use e.g. --killchain 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap the per-host progression table.
      let limit = 25;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown kill-chain report to stdout.
      console.log(buildKillChain(hours, { limit, nowMs: Date.now() }).markdown);
      return;
    }
    const beaconIdx = argv.findIndex((a) => a === "--beacon" || a.startsWith("--beacon="));
    if (beaconIdx !== -1) {
      const inline = argv[beaconIdx]!.split("=")[1];
      const next = argv[beaconIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so a low-and-slow beacon has room to repeat many times.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --beacon hours: "${raw}". Use e.g. --beacon 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap the candidate table.
      let limit = 25;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      // Optional `--min-hits N` to set how many repetitions make a pair assessable.
      let minHits = 4;
      const minHitsIdx = argv.findIndex((a) => a === "--min-hits" || a.startsWith("--min-hits="));
      if (minHitsIdx !== -1) {
        const mh = argv[minHitsIdx]!.split("=")[1] ?? argv[minHitsIdx + 1];
        const n = mh !== undefined ? Number(mh) : NaN;
        if (Number.isFinite(n) && n > 0) minHits = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown beaconing report to stdout.
      console.log(buildBeacon(hours, { limit, minHits, nowMs: Date.now() }).markdown);
      return;
    }
    const efficacyIdx = argv.findIndex((a) => a === "--efficacy" || a.startsWith("--efficacy="));
    if (efficacyIdx !== -1) {
      const inline = argv[efficacyIdx]!.split("=")[1];
      const next = argv[efficacyIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so enforcement gaps have enough volume to rank.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --efficacy hours: "${raw}". Use e.g. --efficacy 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap the per-signature gap table.
      let limit = 25;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown efficacy report to stdout.
      console.log(buildEfficacy(hours, { limit, nowMs: Date.now() }).markdown);
      return;
    }
    const spreadIdx = argv.findIndex((a) => a === "--spread" || a.startsWith("--spread="));
    if (spreadIdx !== -1) {
      const inline = argv[spreadIdx]!.split("=")[1];
      const next = argv[spreadIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so a low-and-slow sweep has room to touch many peers.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --spread hours: "${raw}". Use e.g. --spread 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap each fan-out / fan-in table.
      let limit = 25;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      // Optional `--min-peers N` to set how many distinct peers flag a spreader.
      let minPeers = 8;
      const minPeersIdx = argv.findIndex((a) => a === "--min-peers" || a.startsWith("--min-peers="));
      if (minPeersIdx !== -1) {
        const mp = argv[minPeersIdx]!.split("=")[1] ?? argv[minPeersIdx + 1];
        const n = mp !== undefined ? Number(mp) : NaN;
        if (Number.isFinite(n) && n > 0) minPeers = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown spread report to stdout.
      console.log(buildSpread(hours, { limit, minPeers, nowMs: Date.now() }).markdown);
      return;
    }
    const cooccurIdx = argv.findIndex((a) => a === "--cooccur" || a.startsWith("--cooccur="));
    if (cooccurIdx !== -1) {
      const inline = argv[cooccurIdx]!.split("=")[1];
      const next = argv[cooccurIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so multi-stage chains have room to recur across actors.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --cooccur hours: "${raw}". Use e.g. --cooccur 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap the signature-pair table.
      let limit = 25;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      // Optional `--min-actors N` to set how many distinct actors flag a pair notable.
      let minActors = 2;
      const minActorsIdx = argv.findIndex((a) => a === "--min-actors" || a.startsWith("--min-actors="));
      if (minActorsIdx !== -1) {
        const ma = argv[minActorsIdx]!.split("=")[1] ?? argv[minActorsIdx + 1];
        const n = ma !== undefined ? Number(ma) : NaN;
        if (Number.isFinite(n) && n > 0) minActors = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown co-occurrence report to stdout.
      console.log(buildCooccurrence(hours, { limit, minActors, nowMs: Date.now() }).markdown);
      return;
    }
    const surgeIdx = argv.findIndex((a) => a === "--surge" || a.startsWith("--surge="));
    if (surgeIdx !== -1) {
      const inline = argv[surgeIdx]!.split("=")[1];
      const next = argv[surgeIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so a quiet baseline is visible and overnight storms surface.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --surge hours: "${raw}". Use e.g. --surge 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap the episode table.
      let limit = 25;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      // Optional `--bucket-minutes N` to set the time-bucket width.
      let bucketMinutes = 15;
      const bucketIdx = argv.findIndex((a) => a === "--bucket-minutes" || a.startsWith("--bucket-minutes="));
      if (bucketIdx !== -1) {
        const bm = argv[bucketIdx]!.split("=")[1] ?? argv[bucketIdx + 1];
        const n = bm !== undefined ? Number(bm) : NaN;
        if (Number.isFinite(n) && n > 0) bucketMinutes = n;
      }
      // Optional `--factor N` (× baseline) and `--min-count N` (absolute floor) for the surge bar.
      let factor = 3;
      const factorIdx = argv.findIndex((a) => a === "--factor" || a.startsWith("--factor="));
      if (factorIdx !== -1) {
        const f = argv[factorIdx]!.split("=")[1] ?? argv[factorIdx + 1];
        const n = f !== undefined ? Number(f) : NaN;
        if (Number.isFinite(n) && n > 0) factor = n;
      }
      let minCount = 5;
      const minCountIdx = argv.findIndex((a) => a === "--min-count" || a.startsWith("--min-count="));
      if (minCountIdx !== -1) {
        const mc = argv[minCountIdx]!.split("=")[1] ?? argv[minCountIdx + 1];
        const n = mc !== undefined ? Number(mc) : NaN;
        if (Number.isFinite(n) && n > 0) minCount = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown surge report to stdout.
      console.log(buildSurge(hours, { limit, bucketMinutes, factor, minCount, nowMs: Date.now() }).markdown);
      return;
    }
    const persistIdx = argv.findIndex((a) => a === "--persist" || a.startsWith("--persist="));
    if (persistIdx !== -1) {
      const inline = argv[persistIdx]!.split("=")[1];
      const next = argv[persistIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so recurrence across multiple days/sessions is visible.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --persist hours: "${raw}". Use e.g. --persist 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap the source table.
      let limit = 25;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      // Optional `--min-alerts N` to set the floor a source needs to be ranked.
      let minAlerts = 3;
      const minAlertsIdx = argv.findIndex((a) => a === "--min-alerts" || a.startsWith("--min-alerts="));
      if (minAlertsIdx !== -1) {
        const ma = argv[minAlertsIdx]!.split("=")[1] ?? argv[minAlertsIdx + 1];
        const n = ma !== undefined ? Number(ma) : NaN;
        if (Number.isFinite(n) && n > 0) minAlerts = n;
      }
      // Optional `--session-gap N` (minutes) to set when a quiet gap starts a new session.
      let sessionGapMinutes = 360;
      const gapIdx = argv.findIndex((a) => a === "--session-gap" || a.startsWith("--session-gap="));
      if (gapIdx !== -1) {
        const g = argv[gapIdx]!.split("=")[1] ?? argv[gapIdx + 1];
        const n = g !== undefined ? Number(g) : NaN;
        if (Number.isFinite(n) && n > 0) sessionGapMinutes = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown persistence report to stdout.
      console.log(buildPersistence(hours, { limit, minAlerts, sessionGapMinutes, nowMs: Date.now() }).markdown);
      return;
    }
    const edgesIdx = argv.findIndex((a) => a === "--edges" || a.startsWith("--edges="));
    if (edgesIdx !== -1) {
      const inline = argv[edgesIdx]!.split("=")[1];
      const next = argv[edgesIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so sustained relationships (not one burst) are visible.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --edges hours: "${raw}". Use e.g. --edges 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap the edge table.
      let limit = 30;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      // Optional `--min-alerts N` to set the floor an edge needs to be ranked.
      let minAlerts = 2;
      const minAlertsIdx = argv.findIndex((a) => a === "--min-alerts" || a.startsWith("--min-alerts="));
      if (minAlertsIdx !== -1) {
        const ma = argv[minAlertsIdx]!.split("=")[1] ?? argv[minAlertsIdx + 1];
        const n = ma !== undefined ? Number(ma) : NaN;
        if (Number.isFinite(n) && n > 0) minAlerts = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown attack-edge report to stdout.
      console.log(buildEdges(hours, { limit, minAlerts, nowMs: Date.now() }).markdown);
      return;
    }
    const notifyIdx = argv.findIndex((a) => a === "--notify" || a.startsWith("--notify="));
    if (notifyIdx !== -1) {
      const inline = argv[notifyIdx]!.split("=")[1];
      const next = argv[notifyIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so delivery coverage trends (not one shift) are visible.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --notify hours: "${raw}". Use e.g. --notify 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap each signature table.
      let limit = 15;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown notification-audit report to stdout.
      console.log(buildNotify(hours, { limit, nowMs: Date.now() }).markdown);
      return;
    }
    const classifyIdx = argv.findIndex((a) => a === "--classify" || a.startsWith("--classify="));
    if (classifyIdx !== -1) {
      const inline = argv[classifyIdx]!.split("=")[1];
      const next = argv[classifyIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so the threat mix reflects more than one shift's chatter.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --classify hours: "${raw}". Use e.g. --classify 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap the threat-class table.
      let limit = 25;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown classification report to stdout.
      console.log(buildClassify(hours, { limit, nowMs: Date.now() }).markdown);
      return;
    }
    const focusIdx = argv.findIndex((a) => a === "--focus" || a.startsWith("--focus="));
    if (focusIdx !== -1) {
      const inline = argv[focusIdx]!.split("=")[1];
      const next = argv[focusIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so the distribution shape reflects more than one shift.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --focus hours: "${raw}". Use e.g. --focus 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap each per-axis top table.
      let limit = 8;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown concentration report to stdout.
      console.log(buildFocus(hours, { limit, nowMs: Date.now() }).markdown);
      return;
    }
    const netblocksIdx = argv.findIndex((a) => a === "--netblocks" || a.startsWith("--netblocks="));
    if (netblocksIdx !== -1) {
      const inline = argv[netblocksIdx]!.split("=")[1];
      const next = argv[netblocksIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so adjacent-IP rotation across days is visible, not one shift.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --netblocks hours: "${raw}". Use e.g. --netblocks 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap each (/24 and /16) block table.
      let limit = 20;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown netblock report to stdout.
      console.log(buildNetblock(hours, { limit, nowMs: Date.now() }).markdown);
      return;
    }
    const coverageIdx = argv.findIndex((a) => a === "--coverage" || a.startsWith("--coverage="));
    if (coverageIdx !== -1) {
      const inline = argv[coverageIdx]!.split("=")[1];
      const next = argv[coverageIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so retention/blind-spot signals reflect more than one shift.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --coverage hours: "${raw}". Use e.g. --coverage 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap the blind-spot gap table.
      let limit = 6;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown coverage report to stdout.
      console.log(buildCoverage(hours, { limit, nowMs: Date.now() }).markdown);
      return;
    }
    const directionIdx = argv.findIndex((a) => a === "--direction" || a.startsWith("--direction="));
    if (directionIdx !== -1) {
      const inline = argv[directionIdx]!.split("=")[1];
      const next = argv[directionIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so outbound/lateral signals reflect more than one shift.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --direction hours: "${raw}". Use e.g. --direction 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap the internal-source (candidate-compromise) table.
      let limit = 15;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown direction report to stdout.
      console.log(buildDirection(hours, { limit, nowMs: Date.now() }).markdown);
      return;
    }
    const lifecycleIdx = argv.findIndex((a) => a === "--lifecycle" || a.startsWith("--lifecycle="));
    if (lifecycleIdx !== -1) {
      const inline = argv[lifecycleIdx]!.split("=")[1];
      const next = argv[lifecycleIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so chronic vs acute shape reflects more than one shift.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --lifecycle hours: "${raw}". Use e.g. --lifecycle 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap the per-signature table.
      let limit = 25;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      // Optional `--buckets N` to override the time-slice granularity.
      let buckets: number | undefined;
      const bucketsIdx = argv.findIndex((a) => a === "--buckets" || a.startsWith("--buckets="));
      if (bucketsIdx !== -1) {
        const bi = argv[bucketsIdx]!.split("=")[1] ?? argv[bucketsIdx + 1];
        const n = bi !== undefined ? Number(bi) : NaN;
        if (Number.isFinite(n) && n > 0) buckets = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown lifecycle report to stdout.
      console.log(buildLifecycle(hours, { limit, buckets, nowMs: Date.now() }).markdown);
      return;
    }
    const riskIdx = argv.findIndex((a) => a === "--risk" || a.startsWith("--risk="));
    if (riskIdx !== -1) {
      const inline = argv[riskIdx]!.split("=")[1];
      const next = argv[riskIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so the posture grade reflects more than one shift.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --risk hours: "${raw}". Use e.g. --risk 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap the source / signature driver tables.
      let limit = 15;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown risk-index report to stdout.
      console.log(buildRisk(hours, { limit, nowMs: Date.now() }).markdown);
      return;
    }
    const insightIdx = argv.findIndex((a) => a === "--insight" || a.startsWith("--insight="));
    if (insightIdx !== -1) {
      const inline = argv[insightIdx]!.split("=")[1];
      const next = argv[insightIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so coverage / re-grading reflects more than one shift.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --insight hours: "${raw}". Use e.g. --insight 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap the candidate / action tables.
      let limit = 15;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown AI analyst-insight digest to stdout.
      console.log(buildInsight(hours, { limit, nowMs: Date.now() }).markdown);
      return;
    }
    const escalationIdx = argv.findIndex((a) => a === "--escalation" || a.startsWith("--escalation="));
    if (escalationIdx !== -1) {
      const inline = argv[escalationIdx]!.split("=")[1];
      const next = argv[escalationIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so a source's trajectory reflects more than one shift.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --escalation hours: "${raw}". Use e.g. --escalation 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap each table.
      let limit = 15;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      // Optional `--min N` to set the minimum alerts a source needs to be trended.
      let minAlerts = 4;
      const minIdx = argv.findIndex((a) => a === "--min" || a.startsWith("--min="));
      if (minIdx !== -1) {
        const mi = argv[minIdx]!.split("=")[1] ?? argv[minIdx + 1];
        const n = mi !== undefined ? Number(mi) : NaN;
        if (Number.isFinite(n) && n > 0) minAlerts = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown severity-escalation report to stdout.
      console.log(buildEscalation(hours, { limit, minAlerts, nowMs: Date.now() }).markdown);
      return;
    }
    const targetsIdx = argv.findIndex((a) => a === "--targets" || a.startsWith("--targets="));
    if (targetsIdx !== -1) {
      const inline = argv[targetsIdx]!.split("=")[1];
      const next = argv[targetsIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so a target's siege reflects more than one shift.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --targets hours: "${raw}". Use e.g. --targets 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap the internal / external target tables.
      let limit = 15;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown target / victim-exposure report to stdout.
      console.log(buildTargets(hours, { limit, nowMs: Date.now() }).markdown);
      return;
    }
    const clustersIdx = argv.findIndex((a) => a === "--clusters" || a.startsWith("--clusters="));
    if (clustersIdx !== -1) {
      const inline = argv[clustersIdx]!.split("=")[1];
      const next = argv[clustersIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so a cluster's footprint reflects more than one shift.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --clusters hours: "${raw}". Use e.g. --clusters 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap the number of clusters listed.
      let limit = 15;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      // Optional `--min-jaccard F` (0..1) to tune the link similarity threshold.
      let minJaccard: number | undefined;
      const mjIdx = argv.findIndex((a) => a === "--min-jaccard" || a.startsWith("--min-jaccard="));
      if (mjIdx !== -1) {
        const mj = argv[mjIdx]!.split("=")[1] ?? argv[mjIdx + 1];
        const n = mj !== undefined ? Number(mj) : NaN;
        if (Number.isFinite(n) && n > 0) minJaccard = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown coordinated-infrastructure report to stdout.
      console.log(buildClusters(hours, { limit, minJaccard, nowMs: Date.now() }).markdown);
      return;
    }
    const cveIdx = argv.findIndex((a) => a === "--cve" || a.startsWith("--cve="));
    if (cveIdx !== -1) {
      const inline = argv[cveIdx]!.split("=")[1];
      const next = argv[cveIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so a CVE's exposure reflects more than one shift.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --cve hours: "${raw}". Use e.g. --cve 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap the CVE worklist table.
      let limit = 20;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown CVE-exposure report to stdout.
      console.log(buildCve(hours, { limit, nowMs: Date.now() }).markdown);
      return;
    }
    const hygieneIdx = argv.findIndex((a) => a === "--hygiene" || a.startsWith("--hygiene="));
    if (hygieneIdx !== -1) {
      const inline = argv[hygieneIdx]!.split("=")[1];
      const next = argv[hygieneIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to 30 days: a block needs a long quiet stretch before "dormant"
      // means the threat really moved on rather than a lull between bursts.
      const hours = raw ? Number(raw) : 720;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --hygiene hours: "${raw}". Use e.g. --hygiene 720`);
        process.exit(2);
      }
      // Optional `--limit N` to cap the active / dormant / unverified tables.
      let limit = 15;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown blocklist-hygiene report to stdout.
      console.log(buildHygiene(hours, { limit, nowMs: Date.now() }).markdown);
      return;
    }
    const recurrenceIdx = argv.findIndex((a) => a === "--recurrence" || a.startsWith("--recurrence="));
    if (recurrenceIdx !== -1) {
      const inline = argv[recurrenceIdx]!.split("=")[1];
      const next = argv[recurrenceIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so a source has room to show several return waves.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --recurrence hours: "${raw}". Use e.g. --recurrence 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap the forecast table.
      let limit = 20;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      // Optional `--session-gap M` (minutes) to tune where one wave ends and the next begins.
      let sessionGapMinutes: number | undefined;
      const gapIdx = argv.findIndex((a) => a === "--session-gap" || a.startsWith("--session-gap="));
      if (gapIdx !== -1) {
        const g = argv[gapIdx]!.split("=")[1] ?? argv[gapIdx + 1];
        const n = g !== undefined ? Number(g) : NaN;
        if (Number.isFinite(n) && n > 0) sessionGapMinutes = n;
      }
      // Optional `--min-sessions N` to set how many waves a source needs before it is forecast.
      let minSessions: number | undefined;
      const msIdx = argv.findIndex((a) => a === "--min-sessions" || a.startsWith("--min-sessions="));
      if (msIdx !== -1) {
        const ms = argv[msIdx]!.split("=")[1] ?? argv[msIdx + 1];
        const n = ms !== undefined ? Number(ms) : NaN;
        if (Number.isFinite(n) && n > 0) minSessions = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown recurrence / return-forecast report to stdout.
      console.log(buildRecurrence(hours, { limit, sessionGapMinutes, minSessions, nowMs: Date.now() }).markdown);
      return;
    }
    const portsIdx = argv.findIndex((a) => a === "--ports" || a.startsWith("--ports="));
    if (portsIdx !== -1) {
      const inline = argv[portsIdx]!.split("=")[1];
      const next = argv[portsIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so the attacked-service mix reflects more than one shift.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --ports hours: "${raw}". Use e.g. --ports 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap the per-port (and exposed-host) table.
      let limit = 20;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown service / port-exposure report to stdout.
      console.log(buildPorts(hours, { limit, nowMs: Date.now() }).markdown);
      return;
    }
    const scanIdx = argv.findIndex((a) => a === "--scan" || a.startsWith("--scan="));
    if (scanIdx !== -1) {
      const inline = argv[scanIdx]!.split("=")[1];
      const next = argv[scanIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so a slow, low-and-slow scanner has time to show breadth.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --scan hours: "${raw}". Use e.g. --scan 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap the per-source (and per-service) table.
      let limit = 20;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      // Optional `--min-hosts N` / `--min-ports N` to tune the shape thresholds.
      let hostThreshold: number | undefined;
      const mhIdx = argv.findIndex((a) => a === "--min-hosts" || a.startsWith("--min-hosts="));
      if (mhIdx !== -1) {
        const v = argv[mhIdx]!.split("=")[1] ?? argv[mhIdx + 1];
        const n = v !== undefined ? Number(v) : NaN;
        if (Number.isFinite(n) && n > 0) hostThreshold = n;
      }
      let portThreshold: number | undefined;
      const mpIdx = argv.findIndex((a) => a === "--min-ports" || a.startsWith("--min-ports="));
      if (mpIdx !== -1) {
        const v = argv[mpIdx]!.split("=")[1] ?? argv[mpIdx + 1];
        const n = v !== undefined ? Number(v) : NaN;
        if (Number.isFinite(n) && n > 0) portThreshold = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown scan-shape report to stdout.
      console.log(buildScan(hours, { limit, hostThreshold, portThreshold, nowMs: Date.now() }).markdown);
      return;
    }
    const repertoireIdx = argv.findIndex((a) => a === "--repertoire" || a.startsWith("--repertoire="));
    if (repertoireIdx !== -1) {
      const inline = argv[repertoireIdx]!.split("=")[1];
      const next = argv[repertoireIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      // Default to a week so a low-and-slow operator has time to reveal breadth.
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --repertoire hours: "${raw}". Use e.g. --repertoire 168`);
        process.exit(2);
      }
      // Optional `--limit N` to cap the per-source table.
      let limit = 20;
      const limitIdx = argv.findIndex((a) => a === "--limit" || a.startsWith("--limit="));
      if (limitIdx !== -1) {
        const li = argv[limitIdx]!.split("=")[1] ?? argv[limitIdx + 1];
        const n = li !== undefined ? Number(li) : NaN;
        if (Number.isFinite(n) && n > 0) limit = n;
      }
      // Optional `--min-alerts N` to drop one-off noise before profiling.
      let minAlerts: number | undefined;
      const maIdx = argv.findIndex((a) => a === "--min-alerts" || a.startsWith("--min-alerts="));
      if (maIdx !== -1) {
        const v = argv[maIdx]!.split("=")[1] ?? argv[maIdx + 1];
        const n = v !== undefined ? Number(v) : NaN;
        if (Number.isFinite(n) && n > 0) minAlerts = n;
      }
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the Markdown repertoire report to stdout.
      console.log(buildRepertoire(hours, { limit, minAlerts, nowMs: Date.now() }).markdown);
      return;
    }
    const iocsIdx = argv.findIndex((a) => a === "--iocs" || a.startsWith("--iocs="));
    if (iocsIdx !== -1) {
      const inline = argv[iocsIdx]!.split("=")[1];
      const next = argv[iocsIdx + 1];
      const raw = inline ?? (next && !next.startsWith("--") ? next : undefined);
      const hours = raw ? Number(raw) : 168;
      if (!Number.isFinite(hours) || hours <= 0) {
        log.error(`Invalid --iocs hours: "${raw}". Use e.g. --iocs 168`);
        process.exit(2);
      }
      // Optional `--format json|csv|plain|markdown` (default plain on the CLI for piping).
      const fmtIdx = argv.findIndex((a) => a === "--format" || a.startsWith("--format="));
      const fmtRaw = fmtIdx !== -1 ? (argv[fmtIdx]!.split("=")[1] ?? argv[fmtIdx + 1]) : undefined;
      const format = parseIocFormat(fmtRaw ?? "plain");
      // Optional `--min-severity info|low|medium|high|critical` (default medium).
      const sevIdx = argv.findIndex((a) => a === "--min-severity" || a.startsWith("--min-severity="));
      const sevRaw = sevIdx !== -1 ? (argv[sevIdx]!.split("=")[1] ?? argv[sevIdx + 1]) : undefined;
      const minSeverity = parseSeverityFloor(sevRaw);
      const cfg = loadConfig();
      setLogLevel(cfg.runtime.logLevel);
      // Offline, deterministic: print the requested export format to stdout.
      const model = buildIocExport(hours, { minSeverity, nowMs: Date.now() });
      const out = renderIoc(model, format);
      process.stdout.write(out.endsWith("\n") ? out : out + "\n");
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
