/**
 * Threat-indicator (IOC) export — turn the stored alert history into a
 * **machine-consumable** list of attacker IPs that other security tools can
 * ingest directly: firewall blocklists (`ipset`/pf tables/UniFi), SIEM watch
 * rules, or a shared threat-intel feed.
 *
 * Every other offline report in this project is a *human narrative*: report.ts,
 * compare.ts, profile.ts, assets.ts, tuning.ts, watchlist.ts and rhythm.ts all
 * render prose + tables for an analyst to read. campaigns.ts clusters by
 * attacker IP for the dashboard's one-click actions, but it is still a UI model,
 * not an export format. None of them answer the operational question that closes
 * the loop after triage: *"give me a clean, deduplicated, confidence-ranked list
 * of the bad IPs I can paste straight into another tool."*
 *
 * This module folds the window's alerts onto each **external (routable) source
 * IP**, scores how confidently that IP looks malicious (severity, volume, how
 * often the gateway already blocked it, breadth of signatures/targets, and any
 * watchlist confirmation), and emits the result in four interchange formats:
 *
 *   - **plain** — `#`-commented header + one IP per line. Drops straight into
 *     `ipset restore`, a pf table, or a UniFi firewall group import.
 *   - **csv**   — spreadsheet/SIEM rows with full context, CSV-injection-safe
 *     (same hardening as analytics/search.ts).
 *   - **markdown** — a human review table, so the export can be eyeballed before
 *     it is trusted.
 *   - **json**  — the structured model itself, for programmatic consumers.
 *
 * Safety rails that make the output trustworthy as a *blocklist source*:
 *   - **Safelisted IPs are excluded by default.** Exporting an address the
 *     operator has explicitly trusted into a blocklist would be an outage
 *     waiting to happen; the count of excluded-safe IPs is reported so the
 *     omission is never silent.
 *   - **A minimum-severity floor (default `medium`).** Info/low noise is not an
 *     indicator of compromise and would only dilute a feed.
 *   - **Dismissed alerts are ignored**, matching campaigns.ts — an analyst who
 *     dismissed an alert has said it is not actionable.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network — so it is
 * safe to call from the dashboard or CLI at any time.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { dismissStore } from "../store/dismissed.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Interchange formats the export can render into. */
export type IocFormat = "json" | "csv" | "plain" | "markdown";

/** Distinct signatures/targets we keep per indicator before truncating. */
const MAX_SIGNATURES = 6;
const MAX_TARGETS = 6;
/** Hard ceiling on exported indicators (matches the alertStore retention cap). */
const MAX_INDICATORS = 2000;
/** Default minimum severity for an address to qualify as an indicator. */
const DEFAULT_MIN_SEVERITY: Severity = "medium";

/** One exportable threat indicator (a single attacker IP, rolled up). */
export interface IocIndicator {
  /** The external (routable) attacker IP — the indicator value. */
  ip: string;
  /** IP family, 4 or 6. */
  family: 4 | 6;
  /** Total in-window alerts attributed to this IP. */
  alertCount: number;
  /** Highest severity seen for this IP. */
  severityMax: Severity;
  /** Distinct signatures it tripped, most-seen first (truncated). */
  signatures: string[];
  /** Total distinct signatures (un-truncated count). */
  signatureCount: number;
  /** Distinct Suricata categories tripped. */
  categories: string[];
  /** Internal hosts it touched, most-targeted first (truncated). */
  targets: string[];
  /** Total distinct internal hosts touched (un-truncated count). */
  targetCount: number;
  /** Earliest / latest alert times (ms epoch). */
  firstSeen: number;
  lastSeen: number;
  /** How many of the alerts the gateway already blocked. */
  blockedCount: number;
  /** Composite 0–100 confidence that this IP belongs on a blocklist. */
  confidence: number;
  /** Already present in the firewall blocklist. */
  alreadyBlocked: boolean;
  /** Matches a watchlist entry (CIDR-aware). */
  watched: boolean;
  /** The operator's watchlist note, if any (provenance for the indicator). */
  watchNote?: string;
}

export interface IocExport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Severity floor applied to qualify as an indicator. */
  minSeverity: Severity;
  /** Distinct indicators returned (after all filters + limit). */
  totalIndicators: number;
  /** Indicators dropped because the IP is safelisted (explicitly trusted). */
  excludedSafe: number;
  /** Indicators dropped because their worst severity was below the floor. */
  excludedBelowSeverity: number;
  /** Indicators truncated by the `limit` (totalIndicators ignores these). */
  truncated: number;
  /** The ranked indicators (highest confidence first). */
  indicators: IocIndicator[];
}

// ----- IP classification (mirrors campaigns.ts; kept self-contained) ---------

function isPrivate(ip: string): boolean {
  return (
    /^10\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^127\./.test(ip) ||
    /^169\.254\./.test(ip) ||
    /^(::1|fe80|fc|fd)/i.test(ip)
  );
}

/** The external (routable) source/dest IP of an alert; null if both sides are private. */
function externalIp(a: StoredAlert): string | null {
  for (const ip of [a.srcIp, a.dstIp]) {
    if (ip && isIP(ip) > 0 && !isPrivate(ip)) return ip;
  }
  return null;
}

/** The internal counterpart host (the victim), if any. */
function internalIp(a: StoredAlert, attacker: string): string | null {
  for (const ip of [a.srcIp, a.dstIp]) {
    if (ip && ip !== attacker && isIP(ip) > 0 && isPrivate(ip)) return ip;
  }
  return null;
}

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? (b as Severity) : a;
}

/**
 * Composite 0–100 confidence that an IP belongs on a blocklist. Distinct from
 * campaigns.ts's "threat score": that ranks *urgency for an analyst*; this ranks
 * *certainty the address is hostile enough to block automatically*. So here the
 * gateway already blocking the traffic and an operator already watching the IP
 * are confidence boosts (corroboration), not urgency reductions.
 */
function scoreConfidence(c: {
  severityMax: Severity;
  alertCount: number;
  signatureCount: number;
  targetCount: number;
  blockedCount: number;
  watched: boolean;
}): number {
  const sev = sevRank(c.severityMax); // 0..4
  let score = sev * 18; // medium=36, high=54, critical=72
  score += Math.min(12, Math.log2(c.alertCount + 1) * 4); // volume, diminishing
  score += Math.min(8, (c.signatureCount - 1) * 3); // signature diversity
  score += Math.min(6, (c.targetCount - 1) * 3); // fan-out across hosts
  // The gateway itself flagged-and-dropped this traffic: strong corroboration.
  if (c.blockedCount > 0) score += Math.min(10, 4 + c.blockedCount);
  // An operator has already chosen to watch this address.
  if (c.watched) score += 8;
  return Math.max(0, Math.min(100, Math.round(score)));
}

export interface IocExportOptions {
  /** Drop indicators whose worst severity is below this (default `medium`). */
  minSeverity?: Severity;
  /** Cap on returned indicators (highest confidence first). Default = no cap. */
  limit?: number;
  /** Pin the window end (tests). Defaults to Date.now(). */
  nowMs?: number;
  /** Include safelisted IPs instead of excluding them (default false). */
  includeSafe?: boolean;
}

interface Agg {
  ip: string;
  family: 4 | 6;
  alertCount: number;
  severityMax: Severity;
  sigCounts: Map<string, number>;
  categories: Set<string>;
  targets: Map<string, number>;
  firstSeen: number;
  lastSeen: number;
  blockedCount: number;
}

/**
 * Build the IOC export model from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  Severity floor, limit, safelist handling, and a test clock.
 */
export function buildIocExport(hours: number, opts: IocExportOptions = {}): IocExport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const nowMs = opts.nowMs ?? Date.now();
  const windowEndMs = nowMs;
  const windowStartMs = windowEndMs - safeHours * 3_600_000;
  const minSeverity = opts.minSeverity && sevRank(opts.minSeverity) >= 0 ? opts.minSeverity : DEFAULT_MIN_SEVERITY;
  const minRank = sevRank(minSeverity);
  const includeSafe = opts.includeSafe === true;
  const limit = opts.limit !== undefined ? Math.max(1, Math.min(MAX_INDICATORS, Math.floor(opts.limit))) : MAX_INDICATORS;

  const inWindow = alertStore
    .all()
    .filter(
      (a) => typeof a.time === "number" && a.time >= windowStartMs && a.time <= windowEndMs && !dismissStore.has(a.id),
    );

  const byIp = new Map<string, Agg>();
  for (const a of inWindow) {
    const ip = externalIp(a);
    if (!ip) continue;
    const family = isIP(ip) as 4 | 6;
    let agg = byIp.get(ip);
    if (!agg) {
      agg = {
        ip,
        family,
        alertCount: 0,
        severityMax: "info",
        sigCounts: new Map(),
        categories: new Set(),
        targets: new Map(),
        firstSeen: a.time,
        lastSeen: a.time,
        blockedCount: 0,
      };
      byIp.set(ip, agg);
    }
    const sev = (a.severity as Severity) ?? "info";
    agg.alertCount++;
    agg.severityMax = maxSeverity(agg.severityMax, sev);
    if (a.signature) agg.sigCounts.set(a.signature, (agg.sigCounts.get(a.signature) ?? 0) + 1);
    if (a.category) agg.categories.add(a.category);
    const target = internalIp(a, ip);
    if (target) agg.targets.set(target, (agg.targets.get(target) ?? 0) + 1);
    if (a.time < agg.firstSeen) agg.firstSeen = a.time;
    if (a.time > agg.lastSeen) agg.lastSeen = a.time;
    if ((a.action ?? "").toLowerCase() === "blocked") agg.blockedCount++;
  }

  let excludedSafe = 0;
  let excludedBelowSeverity = 0;
  const indicators: IocIndicator[] = [];

  for (const agg of byIp.values()) {
    if (sevRank(agg.severityMax) < minRank) {
      excludedBelowSeverity++;
      continue;
    }
    if (!includeSafe && safeStore.has(agg.ip)) {
      excludedSafe++;
      continue;
    }
    const watch = watchStore.match(agg.ip);
    const signaturesAll = [...agg.sigCounts.entries()].sort(
      (x, y) => y[1] - x[1] || x[0].localeCompare(y[0]),
    );
    const targetsAll = [...agg.targets.entries()].sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0]));
    const confidence = scoreConfidence({
      severityMax: agg.severityMax,
      alertCount: agg.alertCount,
      signatureCount: agg.sigCounts.size,
      targetCount: agg.targets.size,
      blockedCount: agg.blockedCount,
      watched: watch !== undefined,
    });
    indicators.push({
      ip: agg.ip,
      family: agg.family,
      alertCount: agg.alertCount,
      severityMax: agg.severityMax,
      signatures: signaturesAll.slice(0, MAX_SIGNATURES).map(([s]) => s),
      signatureCount: agg.sigCounts.size,
      categories: [...agg.categories].sort(),
      targets: targetsAll.slice(0, MAX_TARGETS).map(([ip]) => ip),
      targetCount: agg.targets.size,
      firstSeen: agg.firstSeen,
      lastSeen: agg.lastSeen,
      blockedCount: agg.blockedCount,
      confidence,
      alreadyBlocked: blockStore.has(agg.ip),
      watched: watch !== undefined,
      watchNote: watch?.note,
    });
  }

  // Rank: highest confidence, then volume, then most recent.
  indicators.sort(
    (a, b) => b.confidence - a.confidence || b.alertCount - a.alertCount || b.lastSeen - a.lastSeen,
  );

  const truncated = Math.max(0, indicators.length - limit);
  const limited = indicators.slice(0, limit);

  return {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    minSeverity,
    totalIndicators: limited.length,
    excludedSafe,
    excludedBelowSeverity,
    truncated,
    indicators: limited,
  };
}

// ----- rendering -------------------------------------------------------------

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** RFC-4180 quoting + leading-character defusing against CSV injection in Excel. */
function csvCell(v: unknown): string {
  const s = v === undefined || v === null ? "" : String(v);
  const safe = /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
  return /[",\r\n]/.test(safe) ? '"' + safe.replace(/"/g, '""') + '"' : safe;
}

/** Escape a Markdown table cell. */
function mdCell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function renderPlain(model: IocExport): string {
  const lines: string[] = [];
  lines.push(`# SecTool IOC export — ${model.totalIndicators} indicator(s)`);
  lines.push(`# Window: last ${model.hours}h (${fmtTime(model.windowStartMs)} → ${fmtTime(model.windowEndMs)})`);
  lines.push(`# Minimum severity: ${model.minSeverity}`);
  if (model.excludedSafe) lines.push(`# Excluded ${model.excludedSafe} safelisted IP(s).`);
  lines.push(`# Format: one attacker IP per line. Safe to import into ipset / pf / a firewall group.`);
  lines.push(`#`);
  for (const ind of model.indicators) {
    // Inline provenance as a trailing comment so the list stays import-friendly.
    lines.push(`${ind.ip}\t# confidence=${ind.confidence} sev=${ind.severityMax} alerts=${ind.alertCount}`);
  }
  // A trailing newline keeps `ipset restore` and shell `while read` loops happy.
  return lines.join("\n") + "\n";
}

function renderCsv(model: IocExport): string {
  const headers = [
    "ip",
    "family",
    "confidence",
    "severity_max",
    "alert_count",
    "blocked_count",
    "signature_count",
    "signatures",
    "categories",
    "target_count",
    "internal_targets",
    "first_seen_iso",
    "last_seen_iso",
    "already_blocked",
    "watched",
    "watch_note",
  ];
  const lines = [headers.join(",")];
  for (const ind of model.indicators) {
    lines.push(
      [
        ind.ip,
        ind.family,
        ind.confidence,
        ind.severityMax,
        ind.alertCount,
        ind.blockedCount,
        ind.signatureCount,
        ind.signatures.join("; "),
        ind.categories.join("; "),
        ind.targetCount,
        ind.targets.join("; "),
        new Date(ind.firstSeen).toISOString(),
        new Date(ind.lastSeen).toISOString(),
        ind.alreadyBlocked ? "yes" : "no",
        ind.watched ? "yes" : "no",
        ind.watchNote ?? "",
      ]
        .map(csvCell)
        .join(","),
    );
  }
  return lines.join("\r\n");
}

function renderMarkdown(model: IocExport): string {
  const lines: string[] = [];
  lines.push(`# 🎯 SecTool Threat-Indicator (IOC) Export`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(model.windowEndMs)}`);
  lines.push(`**Window:** last ${model.hours} hour(s) — ${fmtTime(model.windowStartMs)} → ${fmtTime(model.windowEndMs)}`);
  lines.push(
    `**Indicators:** ${model.totalIndicators} · **Min severity:** ${model.minSeverity}` +
      (model.excludedSafe ? ` · **Excluded (safelisted):** ${model.excludedSafe}` : "") +
      (model.truncated ? ` · **Truncated:** ${model.truncated} more` : ""),
  );
  lines.push("");

  if (!model.totalIndicators) {
    lines.push(
      `No external attacker IPs at **${model.minSeverity}** severity or above in the last ${model.hours} hour(s).` +
        (model.excludedBelowSeverity
          ? ` (${model.excludedBelowSeverity} lower-severity IP(s) were below the floor.)`
          : ""),
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  const head = ["IP", "Conf.", "Sev", "Alerts", "Blocked", "Sigs", "Hosts", "Last seen", "State"];
  const sep = head.map(() => "---");
  const rows = model.indicators.map((ind) => {
    const state: string[] = [];
    if (ind.alreadyBlocked) state.push("🚫 blocked");
    if (ind.watched) state.push("👁 watched");
    return [
      mdCell(ind.ip),
      String(ind.confidence),
      mdCell(ind.severityMax),
      String(ind.alertCount),
      ind.blockedCount ? String(ind.blockedCount) : "·",
      String(ind.signatureCount),
      String(ind.targetCount),
      fmtTime(ind.lastSeen),
      state.length ? state.join(", ") : "·",
    ];
  });
  lines.push(`| ${head.join(" | ")} |`);
  lines.push(`| ${sep.join(" | ")} |`);
  for (const r of rows) lines.push(`| ${r.join(" | ")} |`);
  lines.push("");

  lines.push(`## Plain blocklist`);
  lines.push("");
  lines.push("Copy/paste into `ipset`, a pf table, or a UniFi firewall group:");
  lines.push("");
  lines.push("```");
  for (const ind of model.indicators) lines.push(ind.ip);
  lines.push("```");
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from the stored alert history (${model.totalIndicators} indicator(s), ` +
      `min severity ${model.minSeverity}). Confidence 0–100 reflects severity, volume, gateway corroboration, ` +
      `and watchlist confirmation. Review before trusting as an automated blocklist. ` +
      `No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/** Render a built IOC export model into the requested interchange format. */
export function renderIoc(model: IocExport, format: IocFormat): string {
  switch (format) {
    case "csv":
      return renderCsv(model);
    case "plain":
      return renderPlain(model);
    case "markdown":
      return renderMarkdown(model);
    case "json":
    default:
      return JSON.stringify(model, null, 2);
  }
}

/** A filesystem-safe filename for a downloaded IOC export in the given format. */
export function iocFilename(nowMs: number, format: IocFormat): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  const ext = format === "markdown" ? "md" : format === "plain" ? "txt" : format;
  return `sectool-iocs-${stamp}.${ext}`;
}

/** Coerce an arbitrary string into a valid {@link IocFormat}, defaulting to json. */
export function parseIocFormat(raw: string | undefined | null): IocFormat {
  const f = (raw ?? "").trim().toLowerCase();
  if (f === "csv" || f === "plain" || f === "markdown" || f === "md" || f === "txt" || f === "json") {
    if (f === "md") return "markdown";
    if (f === "txt") return "plain";
    return f as IocFormat;
  }
  return "json";
}

/** Coerce an arbitrary string into a valid {@link Severity}, or undefined. */
export function parseSeverityFloor(raw: string | undefined | null): Severity | undefined {
  const s = (raw ?? "").trim().toLowerCase();
  return (SEVERITY_ORDER as readonly string[]).includes(s) ? (s as Severity) : undefined;
}
