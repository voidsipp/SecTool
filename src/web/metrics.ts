/**
 * Prometheus / OpenMetrics exposition — turn SecTool's live in-memory state into
 * a **scrapeable** metrics endpoint so the deployment can be *monitored*, not
 * just *read*.
 *
 * Every other surface in this project answers a human question after the fact: a
 * Markdown report an analyst opens, a dashboard panel they glance at, a Discord
 * digest they skim in the morning. None of them close the operational loop that
 * a production security collector actually needs:
 *
 *   **"Tell my monitoring system, automatically and continuously, when SecTool
 *    itself stops seeing the world or when the threat picture changes — without
 *    a human in the loop."**
 *
 * That is exactly what a Prometheus scrape target is for. This module folds the
 * stored alert history and the control-plane stores (block / watch / safe /
 * suppress / dismiss / triage) into a flat set of gauges in the Prometheus text
 * exposition format (v0.0.4, also valid OpenMetrics), which Grafana graphs and
 * Alertmanager fires on. The high-value alarms it unlocks, none of which exist
 * today:
 *
 *   - **Sensor / pipeline down.** `sectool_last_alert_age_seconds` climbing past
 *     a threshold means the syslog feed went quiet — a collector outage, a
 *     gateway reboot, a dropped UDP stream. A "no alerts" stretch reads as "no
 *     visibility", the single most dangerous silent failure, and it is invisible
 *     from any report you have to remember to open. Alert: `... > 3600`.
 *   - **Severity spike.** `sectool_alerts_window{window="1h"}` and the per-window
 *     severity split let Alertmanager page on a sudden surge of high/critical
 *     detections the moment it happens, not at the next morning's briefing.
 *   - **Store truncation.** `sectool_alert_store_saturation_ratio` nearing 1.0
 *     warns that the bounded history is evicting the past, so every windowed
 *     report is quietly understating it (the same failure coverage.ts audits,
 *     here as a continuous gauge).
 *   - **Control-plane drift.** Blocklist / watchlist / triage-backlog sizes as
 *     gauges turn "is the open-investigation queue growing unboundedly?" into a
 *     graph and an alert.
 *
 * Design choices that keep the endpoint trustworthy and cheap:
 *
 *   - **Bounded cardinality.** Prometheus melts down on unbounded label sets, so
 *     no raw IP or signature is ever a label. Severity (5), disposition (3),
 *     triage status (4) and time-window (2) are all fixed enumerations; the only
 *     data-driven family — category — is capped to the top {@link MAX_CATEGORY}
 *     with the long tail folded into a single `other` series.
 *   - **Instantaneous gauges, not fake counters.** SecTool's store is capped and
 *     rotated, so a monotonic `_total` counter would silently reset on eviction
 *     and break `rate()`. Everything here is an honest point-in-time gauge
 *     (current store contents, current sizes, current ages); ingest *rate* is
 *     derived by the operator from the windowed gauges, which is correct.
 *   - **Pure & deterministic.** In-memory math over the same stores the reports
 *     read — no SSH, no Claude, no network — so a scrape is microseconds and
 *     safe to hit every 15s. A pinned `nowMs` makes the output reproducible in
 *     tests, mirroring every offline report in this project.
 *
 * The output is a single `text/plain; version=0.0.4` document. Wire it at
 * `GET /metrics` (the Prometheus convention) and `GET /api/metrics`; it is also
 * available offline via the CLI `--metrics` flag for a quick eyeball.
 */
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { isIP } from "node:net";
import type { Config } from "../config.ts";
import { alertStore, ALERT_STORE_CAP } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { dismissStore } from "../store/dismissed.ts";
import { suppressionStore } from "../store/suppressions.ts";
import { triageStore } from "../store/triage.ts";
import { classifyDisposition, type Disposition } from "../analytics/efficacy.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

const MS_PER_SEC = 1000;
const MS_PER_HOUR = 3_600_000;

/** Common metric prefix; every series is namespaced to avoid collisions. */
const NS = "sectool";

/** Fixed look-back windows exposed for ingest-liveness / rate derivation. */
const WINDOWS: ReadonlyArray<{ label: string; ms: number }> = [
  { label: "1h", ms: MS_PER_HOUR },
  { label: "24h", ms: 24 * MS_PER_HOUR },
];

/** The window (label) used for the richer per-severity / distinct-entity splits. */
const RICH_WINDOW = "24h";

/** Maximum distinct `category` series before the tail is folded into `other`. */
const MAX_CATEGORY = 12;

/** The three disposition buckets, fixed so each always emits (even at zero). */
const DISPOSITIONS: readonly Disposition[] = ["blocked", "passed", "unknown"];

/** Triage statuses, fixed so the backlog gauge family is stable. */
const TRIAGE_STATUSES = ["open", "investigating", "resolved", "false-positive"] as const;

/** A single emitted time-series sample: optional labels + a numeric value. */
interface Sample {
  labels?: Record<string, string | number>;
  value: number;
}

/** One Prometheus metric family (HELP + TYPE + its samples). */
interface Family {
  name: string;
  type: "gauge" | "counter";
  help: string;
  samples: Sample[];
}

// ----- formatting helpers (Prometheus text exposition, v0.0.4) ---------------

/** Escape a label *value* per the text format: backslash, double-quote, newline. */
function escLabel(v: string): string {
  return v.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}

/** Render a numeric sample value, honouring Prometheus's NaN / ±Inf spellings. */
function fmtValue(n: number): string {
  if (Number.isNaN(n)) return "NaN";
  if (n === Infinity) return "+Inf";
  if (n === -Infinity) return "-Inf";
  // Integers stay integers; ratios are rounded to 6dp to avoid float noise.
  return Number.isInteger(n) ? String(n) : String(Math.round(n * 1e6) / 1e6);
}

/** Render a label set into `{k="v",...}`, or "" when there are no labels. */
function fmtLabels(labels?: Record<string, string | number>): string {
  if (!labels) return "";
  const parts = Object.entries(labels).map(([k, v]) => `${k}="${escLabel(String(v))}"`);
  return parts.length ? `{${parts.join(",")}}` : "";
}

/** Serialise one family to its HELP/TYPE header plus one line per sample. */
function renderFamily(f: Family): string {
  const lines: string[] = [];
  lines.push(`# HELP ${NS}_${f.name} ${f.help.replace(/\n/g, " ")}`);
  lines.push(`# TYPE ${NS}_${f.name} ${f.type}`);
  for (const s of f.samples) {
    lines.push(`${NS}_${f.name}${fmtLabels(s.labels)} ${fmtValue(s.value)}`);
  }
  return lines.join("\n");
}

// ----- domain helpers --------------------------------------------------------

/** A valid, non-empty IP, or undefined if the field is missing / malformed. */
function validIp(ip: string | undefined): string | undefined {
  return ip && isIP(ip) !== 0 ? ip : undefined;
}

/** Normalise an alert's severity to one of the five canonical levels, or null. */
function canonicalSeverity(s: string | undefined): Severity | null {
  return (SEVERITY_ORDER as readonly string[]).includes(s ?? "") ? (s as Severity) : null;
}

/** Best-effort read of the package version for the build_info label. */
function readVersion(): string {
  try {
    const pkgPath = fileURLToPath(new URL("../../package.json", import.meta.url));
    if (!existsSync(pkgPath)) return "unknown";
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { version?: string };
    return typeof pkg.version === "string" && pkg.version ? pkg.version : "unknown";
  } catch {
    return "unknown";
  }
}

export interface MetricsOptions {
  /** Pins "now" for deterministic output in tests; defaults to wall-clock now. */
  nowMs?: number;
}

/**
 * Build the full Prometheus exposition document from SecTool's current state.
 *
 * @param cfg  Loaded config — used only for the static `build_info` labels
 *             (version, model, dry-run); no live query is performed.
 * @param opts {@link MetricsOptions}: a `nowMs` pin for reproducible tests.
 * @returns    A `text/plain; version=0.0.4` body, trailing newline included.
 */
export function buildMetrics(cfg: Config, opts: MetricsOptions = {}): string {
  const nowMs = opts.nowMs ?? Date.now();
  const all = alertStore.all();

  // --- timestamp-derived gauges (sensor liveness) ---------------------------
  const timed = all
    .map((a) => a.time)
    .filter((t): t is number => typeof t === "number" && Number.isFinite(t));
  const latestMs = timed.length ? Math.max(...timed) : null;
  const earliestMs = timed.length ? Math.min(...timed) : null;
  const lastAlertAgeSec = latestMs === null ? NaN : Math.max(0, (nowMs - latestMs) / MS_PER_SEC);
  const retainedSpanSec =
    latestMs === null || earliestMs === null ? NaN : Math.max(0, (latestMs - earliestMs) / MS_PER_SEC);

  // --- whole-store breakdowns ------------------------------------------------
  const sevCounts: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  const dispCounts: Record<Disposition, number> = { blocked: 0, passed: 0, unknown: 0 };
  const catCounts = new Map<string, number>();
  let summarized = 0;
  let notified = 0;

  for (const a of all) {
    const sev = canonicalSeverity(a.severity);
    if (sev) sevCounts[sev]++;
    dispCounts[classifyDisposition(a.action)]++;
    const cat = (a.category ?? "").trim() || "uncategorized";
    catCounts.set(cat, (catCounts.get(cat) ?? 0) + 1);
    if (a.summary) summarized++;
    if (typeof a.notifiedAt === "number") notified++;
  }

  // Cap category cardinality: keep the busiest MAX_CATEGORY, fold the rest.
  const sortedCats = [...catCounts.entries()].sort((x, y) => y[1] - x[1] || (x[0] < y[0] ? -1 : 1));
  const topCats = sortedCats.slice(0, MAX_CATEGORY);
  const otherCatTotal = sortedCats.slice(MAX_CATEGORY).reduce((sum, [, c]) => sum + c, 0);

  // --- windowed gauges (ingest rate + recent severity / breadth) ------------
  const windowTotals = new Map<string, number>();
  for (const w of WINDOWS) windowTotals.set(w.label, 0);
  const richSevCounts: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  const richSources = new Set<string>();
  const richTargets = new Set<string>();
  const richStartMs = nowMs - (WINDOWS.find((w) => w.label === RICH_WINDOW)?.ms ?? 24 * MS_PER_HOUR);

  for (const a of all) {
    if (typeof a.time !== "number" || !Number.isFinite(a.time)) continue;
    for (const w of WINDOWS) {
      if (a.time >= nowMs - w.ms && a.time <= nowMs) {
        windowTotals.set(w.label, (windowTotals.get(w.label) ?? 0) + 1);
      }
    }
    if (a.time >= richStartMs && a.time <= nowMs) {
      const sev = canonicalSeverity(a.severity);
      if (sev) richSevCounts[sev]++;
      const src = validIp(a.srcIp);
      if (src) richSources.add(src);
      const dst = validIp(a.dstIp);
      if (dst) richTargets.add(dst);
    }
  }

  const triage = triageStore.counts();

  // --- assemble families -----------------------------------------------------
  const families: Family[] = [];

  families.push({
    name: "build_info",
    type: "gauge",
    help: "SecTool build / runtime info; value is always 1, read the labels.",
    samples: [
      {
        labels: {
          version: readVersion(),
          model: cfg.claude.model,
          dry_run: String(cfg.runtime.dryRun),
        },
        value: 1,
      },
    ],
  });

  families.push({
    name: "alerts_stored",
    type: "gauge",
    help: "Alerts currently retained in the capped store.",
    samples: [{ value: all.length }],
  });
  families.push({
    name: "alert_store_capacity",
    type: "gauge",
    help: "Hard capacity of the alert store before the oldest are evicted.",
    samples: [{ value: ALERT_STORE_CAP }],
  });
  families.push({
    name: "alert_store_saturation_ratio",
    type: "gauge",
    help: "Retained alerts / capacity, 0..1; near 1.0 means history is being truncated.",
    samples: [{ value: ALERT_STORE_CAP > 0 ? all.length / ALERT_STORE_CAP : 0 }],
  });

  families.push({
    name: "last_alert_age_seconds",
    type: "gauge",
    help: "Seconds since the most recent stored alert; rises when the feed goes quiet (sensor/pipeline down). NaN if the store is empty.",
    samples: [{ value: lastAlertAgeSec }],
  });
  families.push({
    name: "retained_span_seconds",
    type: "gauge",
    help: "Seconds between the earliest and latest retained alert (how far back the history reaches).",
    samples: [{ value: retainedSpanSec }],
  });

  families.push({
    name: "alerts_stored_by_severity",
    type: "gauge",
    help: "Retained alerts split by severity.",
    samples: SEVERITY_ORDER.map((sev) => ({ labels: { severity: sev }, value: sevCounts[sev] })),
  });
  families.push({
    name: "alerts_stored_by_disposition",
    type: "gauge",
    help: "Retained alerts split by gateway disposition (blocked / passed / unknown).",
    samples: DISPOSITIONS.map((d) => ({ labels: { disposition: d }, value: dispCounts[d] })),
  });
  families.push({
    name: "alerts_stored_by_category",
    type: "gauge",
    help: `Retained alerts split by category (top ${MAX_CATEGORY}; the tail folded into 'other').`,
    samples: [
      ...topCats.map(([category, c]) => ({ labels: { category }, value: c })),
      ...(otherCatTotal > 0 ? [{ labels: { category: "other" }, value: otherCatTotal }] : []),
    ],
  });

  families.push({
    name: "alerts_window",
    type: "gauge",
    help: "Alerts seen within each rolling look-back window (ingest liveness / rate).",
    samples: WINDOWS.map((w) => ({ labels: { window: w.label }, value: windowTotals.get(w.label) ?? 0 })),
  });
  families.push({
    name: "alerts_window_by_severity",
    type: "gauge",
    help: `Alerts in the last ${RICH_WINDOW} split by severity (recent threat picture).`,
    samples: SEVERITY_ORDER.map((sev) => ({
      labels: { window: RICH_WINDOW, severity: sev },
      value: richSevCounts[sev],
    })),
  });
  families.push({
    name: "distinct_sources",
    type: "gauge",
    help: `Distinct source IPs seen in the last ${RICH_WINDOW} (attack breadth).`,
    samples: [{ labels: { window: RICH_WINDOW }, value: richSources.size }],
  });
  families.push({
    name: "distinct_targets",
    type: "gauge",
    help: `Distinct destination IPs seen in the last ${RICH_WINDOW} (exposed surface).`,
    samples: [{ labels: { window: RICH_WINDOW }, value: richTargets.size }],
  });

  families.push({
    name: "blocklist_size",
    type: "gauge",
    help: "IPs currently on the firewall blocklist.",
    samples: [{ value: blockStore.count() }],
  });
  families.push({
    name: "watchlist_size",
    type: "gauge",
    help: "IPs currently on the watchlist.",
    samples: [{ value: watchStore.count() }],
  });
  families.push({
    name: "safelist_size",
    type: "gauge",
    help: "IPs currently marked safe (allowlist).",
    samples: [{ value: safeStore.count() }],
  });
  families.push({
    name: "suppressions",
    type: "gauge",
    help: "Active alert-suppression rules.",
    samples: [{ value: suppressionStore.count() }],
  });
  families.push({
    name: "dismissed",
    type: "gauge",
    help: "Alerts dismissed by an analyst.",
    samples: [{ value: dismissStore.count() }],
  });

  families.push({
    name: "triage",
    type: "gauge",
    help: "Triaged alerts by status (investigation backlog).",
    samples: TRIAGE_STATUSES.map((status) => ({ labels: { status }, value: triage[status] ?? 0 })),
  });

  families.push({
    name: "alerts_summarized",
    type: "gauge",
    help: "Retained alerts carrying a Claude summary (AI enrichment coverage).",
    samples: [{ value: summarized }],
  });
  families.push({
    name: "alerts_notified",
    type: "gauge",
    help: "Retained alerts that triggered a notification (delivery coverage).",
    samples: [{ value: notified }],
  });

  // Trailing newline is required by the Prometheus text format.
  return families.map(renderFamily).join("\n") + "\n";
}
