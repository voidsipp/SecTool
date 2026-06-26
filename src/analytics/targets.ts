/**
 * Target / victim-exposure report — "which of my hosts is taking the most fire,
 * from how many distinct attackers, and how much of it is getting through?"
 *
 * Almost every other offline report in this project is **attacker-centric**: it
 * ranks the worst source IP (persistence, netblock, focus), the worst source
 * netblock, the source that fans out the most (spread), or the source→dest
 * *pair* (edges). The few that touch the destination either bucket it into
 * coarse direction classes (direction.ts) or keep it inside a pair row
 * (edges.ts, where a single host besieged by 50 distinct sources is 50 separate
 * rows, never one). assets.ts ranks internal hosts but does it **live** over
 * SSH/UDM, not offline from the stored alert history.
 *
 * None of them answer the defender's first-person question:
 *
 *   **"Rank MY endpoints by how hard they are being hit — collapse every
 *    attacker against a given target into one row, and tell me which target is
 *    the worst place to be right now."**
 *
 * That destination rollup carries a signal no source rollup can:
 *
 *   1. **Siege breadth.** A target hit by *one* loud source is a single noisy
 *      relationship; the same volume spread across *many distinct sources* is a
 *      distributed campaign converging on one asset (a public service being
 *      brute-forced/scanned from a botnet). The count of **distinct attackers**
 *      per target is the headline this report exists to surface.
 *   2. **Technique breadth.** How many distinct *signatures* and *categories* a
 *      single target absorbed separates a one-trick scanner from a determined,
 *      multi-tool adversary working a specific box.
 *   3. **What got through, per asset.** Severity-weighted **pressure** split into
 *      blocked vs. unblocked, so the ranking floats the target whose *unmitigated*
 *      exposure is highest — the one most worth hardening or pulling a live
 *      egress/host investigation on next.
 *
 * Ranking metric — each target's rows are reduced to a **pressure** number =
 * Σ `SEVERITY_WEIGHT[severity]` (the same geometric info 1 · low 3 · medium 9 ·
 * high 27 · critical 81 ladder risk.ts uses, imported so the weighting is shared
 * and auditable). Pressure is split by enforcement disposition (reusing
 * efficacy.ts's `classifyDisposition`) into the part the gateway **blocked** and
 * the part it let **through**. Targets are ranked by *unblocked* pressure first
 * (what actually matters), tie-broken by distinct-attacker breadth, then volume —
 * so a quietly-besieged exposed asset out-ranks a loud-but-fully-blocked one.
 *
 * Each target is classified **internal** (RFC1918 / loopback / link-local — one
 * of *your* assets, the rows that matter most) vs. **external** (the gateway
 * itself or an outbound destination your hosts reached; usually lower concern,
 * surfaced separately so they never crowd out your own boxes).
 *
 * Honest caveats baked into the output:
 *
 *   - **Alerts, not flows.** SecTool stores IPS *detections*, not packets. A
 *     target's pressure reflects what *tripped a rule* against it, not its total
 *     inbound traffic; a calm target is not proof it is un-probed.
 *   - **Destination is the gateway's.** src/dst come from the parsed alert; NAT,
 *     hairpin, or asymmetric routing can mislabel which side is the target.
 *   - **Internal = RFC1918.** The internal/external split assumes the private
 *     ranges are your network; a flat/VPN topology can blur that line.
 *   - **Pressure is a heuristic.** The severity ladder is a deliberate, shared
 *     choice ({@link SEVERITY_WEIGHT}); read the ranking as relative, and trust
 *     the attacker/technique breadth columns as much as the single number.
 *   - **Window-bounded & store-capped.** A long look-back can hit the store's
 *     history cap and truncate the oldest alerts, deflating a target's pressure.
 *
 * Pure in-memory math over alertStore (plus blocklist/watchlist/safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring risk.ts, direction.ts,
 * edges.ts, spread.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Whether a target is one of *your* hosts or somewhere out on the internet. */
export type TargetScope = "internal" | "external";

/** One destination IP (an asset under attack), with every attacker collapsed in. */
export interface TargetExposure {
  /** The destination IP this row aggregates. */
  ip: string;
  /** internal (RFC1918 etc — your asset) vs external (gateway/outbound dest). */
  scope: TargetScope;
  /** Alerts whose destination was this IP, inside the window. */
  count: number;
  /** Distinct source IPs that hit this target — the "siege breadth". */
  attackers: number;
  /** Of {@link attackers}, those that are external (public, non-RFC1918). */
  externalAttackers: number;
  /** Distinct signatures fired against this target — the "technique breadth". */
  signatures: number;
  /** Distinct alert categories fired against this target. */
  categories: number;
  /** Worst severity any alert against this target reached. */
  severityMax: Severity;
  /** Alerts against this target at medium severity or worse. */
  severe: number;
  /** Of {@link count}, alerts the gateway blocked. */
  blocked: number;
  /** Of {@link count}, alerts the gateway let through. */
  passed: number;
  /** Of {@link count}, alerts with no recorded action. */
  unknown: number;
  /** Severity-weighted total pressure against this target (Σ severity weight). */
  pressure: number;
  /** Of {@link pressure}, the part on *unblocked* (passed+unknown) alerts. */
  unblockedPressure: number;
  /** unblockedPressure / pressure, 0..1 (4dp) — this target's own exposure. */
  exposure: number;
  /** This target's unblocked pressure as a share of *all* unblocked pressure, 0..1 (4dp). */
  share: number;
  /** Epoch ms of the first alert against this target in the window. */
  firstMs: number;
  /** Epoch ms of the most recent alert against this target in the window. */
  lastMs: number;
  /** The single source that hit this target most (heaviest attacker). */
  topAttacker?: string;
  /** Alerts from {@link topAttacker} against this target. */
  topAttackerCount: number;
  /** The single most frequent signature fired against this target. */
  topSignature?: string;
  /** The target IP is on the blocklist (unusual for a destination — flagged). */
  blocklisted: boolean;
  /** The target IP is on the watchlist (a watched asset taking fire is notable). */
  watched: boolean;
  /** The target IP is marked safe. */
  safe: boolean;
}

export interface TargetsReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp AND a valid destination) inside the window. */
  totalWindowAlerts: number;
  /** Windowed alerts whose destination was missing/unparseable (excluded). */
  droppedNoDest: number;
  /** Distinct destination IPs seen this window. */
  distinctTargets: number;
  /** Of {@link distinctTargets}, those that are internal (your assets). */
  internalTargets: number;
  /** Of {@link distinctTargets}, those that are external. */
  externalTargets: number;
  /** Severity-weighted pressure summed across every target. */
  totalPressure: number;
  /** Of {@link totalPressure}, the part on unblocked alerts. */
  totalUnblockedPressure: number;
  /** totalUnblockedPressure / totalPressure, 0..1 (4dp). */
  overallExposure: number;
  /** Internal targets, ranked by unblocked pressure (the rows that matter most). */
  topInternal: TargetExposure[];
  /** External targets, ranked by unblocked pressure (surfaced separately). */
  topExternal: TargetExposure[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface TargetsOptions {
  /** Max rows in each (internal / external) table (clamped to [1, 100]). */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 15;
const MS_PER_HOUR = 3_600_000;

// ----- formatting helpers (mirror risk.ts / direction.ts / spread.ts) -------

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** A compact relative-age label like "3h" / "2d" — mirrors spread.ts. */
function fmtAge(ms: number, nowMs: number): string {
  const sec = Math.max(0, Math.round((nowMs - ms) / 1000));
  if (sec < 90) return `${sec}s`;
  const min = Math.round(sec / 60);
  if (min < 90) return `${min}m`;
  const hr = Math.round(min / 60);
  if (hr < 48) return `${hr}h`;
  return `${Math.round(hr / 24)}d`;
}

/** A 0..1 fraction as a whole-number percent string, e.g. 0.823 -> "82%". */
function pct(frac: number): string {
  return `${Math.round(frac * 100)}%`;
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
}

function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function mdTable(headers: string[], rows: string[][]): string {
  if (!rows.length) return "_None._";
  const head = `| ${headers.join(" | ")} |`;
  const sep = `| ${headers.map(() => "---").join(" | ")} |`;
  const body = rows.map((r) => `| ${r.join(" | ")} |`).join("\n");
  return `${head}\n${sep}\n${body}`;
}

/** Truncate a long free-form string for a table cell. */
function clip(s: string, max = 40): string {
  const t = s.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

// ----- classifiers ----------------------------------------------------------

/** RFC1918 / loopback / link-local / ULA — mirrors spread.ts / profile.ts. */
function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
}

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

/** Coerce a stored severity string to a known band, defaulting to "info". */
function asSeverity(s: string | undefined): Severity {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? "info" : (s as Severity);
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? asSeverity(b) : a;
}

function isSevere(s: string | undefined): boolean {
  return sevRank(s) >= 2; // medium or worse
}

/** A valid, non-empty IP, or undefined if the field is missing/garbage. */
function validIp(ip: string | undefined): string | undefined {
  return ip && isIP(ip) !== 0 ? ip : undefined;
}

/** Increment a counter in a frequency map. */
function bump(map: Map<string, number>, key: string): void {
  map.set(key, (map.get(key) ?? 0) + 1);
}

/** The (key, count) with the highest count; key tie-break for determinism. */
function topOf(map: Map<string, number>): { key?: string; count: number } {
  let bestKey: string | undefined;
  let best = 0;
  for (const [k, c] of map) {
    if (c > best || (c === best && bestKey !== undefined && k < bestKey)) {
      best = c;
      bestKey = k;
    }
  }
  return { key: bestKey, count: best };
}

// ----- per-target aggregation ------------------------------------------------

interface TargetAcc {
  count: number;
  sources: Map<string, number>;
  externalSources: Set<string>;
  signatures: Map<string, number>;
  categories: Set<string>;
  severityMax: Severity;
  severe: number;
  blocked: number;
  passed: number;
  unknown: number;
  pressure: number;
  unblockedPressure: number;
  firstMs: number;
  lastMs: number;
}

function newTargetAcc(time: number): TargetAcc {
  return {
    count: 0,
    sources: new Map(),
    externalSources: new Set(),
    signatures: new Map(),
    categories: new Set(),
    severityMax: "info",
    severe: 0,
    blocked: 0,
    passed: 0,
    unknown: 0,
    pressure: 0,
    unblockedPressure: 0,
    firstMs: time,
    lastMs: time,
  };
}

function finishTarget(ip: string, a: TargetAcc, totalPressure: number): TargetExposure {
  const topAttacker = topOf(a.sources);
  const topSignature = topOf(a.signatures);
  return {
    ip,
    scope: isPrivate(ip) ? "internal" : "external",
    count: a.count,
    attackers: a.sources.size,
    externalAttackers: a.externalSources.size,
    signatures: a.signatures.size,
    categories: a.categories.size,
    severityMax: a.severityMax,
    severe: a.severe,
    blocked: a.blocked,
    passed: a.passed,
    unknown: a.unknown,
    pressure: round1(a.pressure),
    unblockedPressure: round1(a.unblockedPressure),
    exposure: a.pressure ? round4(a.unblockedPressure / a.pressure) : 0,
    share: totalPressure ? round4(a.unblockedPressure / totalPressure) : 0,
    firstMs: a.firstMs,
    lastMs: a.lastMs,
    topAttacker: topAttacker.key,
    topAttackerCount: topAttacker.count,
    topSignature: topSignature.key,
    blocklisted: blockStore.has(ip),
    watched: watchStore.has(ip),
    safe: safeStore.has(ip),
  } satisfies TargetExposure;
}

/**
 * Rank targets by *unblocked* pressure (what got through), tie-broken by siege
 * breadth (distinct attackers), then raw pressure, then volume, then IP — so the
 * order is fully deterministic.
 */
function rankTargets(rows: TargetExposure[], limit: number): TargetExposure[] {
  return [...rows]
    .sort(
      (x, y) =>
        y.unblockedPressure - x.unblockedPressure ||
        y.attackers - x.attackers ||
        y.pressure - x.pressure ||
        y.count - x.count ||
        (x.ip < y.ip ? -1 : x.ip > y.ip ? 1 : 0),
    )
    .slice(0, limit);
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  m: Omit<TargetsReport, "highlights" | "markdown">,
  nowMs: number,
): string[] {
  const out: string[] = [];
  if (!m.totalWindowAlerts) return out;

  out.push(
    `🎯 **${m.distinctTargets.toLocaleString("en-US")} distinct target(s)** absorbed ` +
      `${m.totalWindowAlerts.toLocaleString("en-US")} alert(s) over the last ${m.hours}h ` +
      `(${m.internalTargets} internal / ${m.externalTargets} external), carrying ` +
      `**${m.totalPressure.toLocaleString("en-US")} severity-weighted pressure** of which ` +
      `**${pct(m.overallExposure)} was NOT blocked**. This report ranks *your endpoints* by how hard ` +
      `they are being hit, not the attackers hitting them.`,
  );

  // The single worst internal asset — the headline a defender wants first.
  const worst = m.topInternal[0];
  if (worst) {
    const flag = worst.safe
      ? " (safelisted — expected)"
      : worst.watched
        ? " (already watchlisted)"
        : "";
    out.push(
      `🔥 Worst internal target \`${worst.ip}\`${flag} took **${worst.count} alert(s) from ` +
        `${worst.attackers} distinct attacker(s)** (${worst.externalAttackers} external), ` +
        `${worst.signatures} distinct signature(s), peak ${worst.severityMax}, ` +
        `${pct(worst.exposure)} of its pressure unblocked ` +
        `(${pct(worst.share)} of the whole siege). ` +
        (worst.attackers >= 5 && !worst.safe
          ? `Many distinct sources converging on one asset = a distributed campaign — harden/pull a live host investigation here first.`
          : `Work the internal table top-down.`),
    );
  } else if (m.internalTargets === 0) {
    out.push(
      `ℹ️ No *internal* (RFC1918) target took an alert this window — every destination was external ` +
        `(the gateway itself or an outbound dest your hosts reached). See the external table below.`,
    );
  }

  // Distributed-siege call-out: an internal asset under many distinct attackers.
  const besieged = m.topInternal.filter((t) => t.attackers >= 5 && !t.safe);
  if (besieged.length) {
    out.push(
      `🌐 **${besieged.length} internal asset(s) are under distributed siege** (≥5 distinct attackers each): ` +
        besieged
          .slice(0, 5)
          .map((t) => `\`${t.ip}\` (${t.attackers} sources, ${pct(t.exposure)} unblocked)`)
          .join(", ") +
        `. Distributed pressure on one box is the texture of a brute-force / scan campaign against an exposed service.`,
    );
  }

  // Multi-technique call-out: a single target worked with many distinct rules.
  const multi = m.topInternal
    .filter((t) => t.signatures >= 4)
    .sort((a, b) => b.signatures - a.signatures)[0];
  if (multi) {
    out.push(
      `🧰 \`${multi.ip}\` was worked with **${multi.signatures} distinct signatures** across ` +
        `${multi.categories} categor(y/ies) — breadth of technique against one box suggests a determined, ` +
        `multi-tool adversary rather than a single-purpose scanner. Top rule: ${clip(multi.topSignature ?? "—", 50)}.`,
    );
  }

  // Fully-mitigated reassurance vs open exposure.
  const exposedInternal = m.topInternal.filter((t) => t.exposure > 0 && !t.safe);
  if (m.internalTargets > 0 && exposedInternal.length === 0) {
    out.push(
      `✅ Every internal target's pressure was fully blocked this window — the gateway absorbed the siege. ` +
        `The residual numbers are mitigated detections; no internal asset has unblocked exposure.`,
    );
  } else if (exposedInternal.length) {
    out.push(
      `⚠️ **${exposedInternal.length} internal target(s) have unblocked exposure** — alerts against them the ` +
        `gateway did not stop. These are the hosts to harden, patch, or pull a live egress/host investigation on; ` +
        `the most recent was \`${exposedInternal[0]!.ip}\` ${fmtAge(exposedInternal[0]!.lastMs, nowMs)} ago.`,
    );
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function targetTable(rows: TargetExposure[], nowMs: number): string {
  return mdTable(
    [
      "#",
      "Target",
      "Pressure",
      "Unblocked",
      "Exposure",
      "Share",
      "Alerts",
      "Attackers",
      "Ext",
      "Sigs",
      "Cats",
      "Peak sev",
      "Severe",
      "Last",
      "Flags",
    ],
    rows.map((r, i) => {
      const flags =
        (r.blocklisted ? "⛔" : "") + (r.watched ? "👁" : "") + (r.safe ? "✅" : "");
      return [
        String(i + 1),
        cell(r.ip),
        String(r.pressure),
        String(r.unblockedPressure),
        pct(r.exposure),
        pct(r.share),
        String(r.count),
        String(r.attackers),
        String(r.externalAttackers),
        String(r.signatures),
        String(r.categories),
        cell(r.severityMax),
        String(r.severe),
        fmtAge(r.lastMs, nowMs),
        flags || "—",
      ];
    }),
  );
}

function renderMarkdown(m: TargetsReport, nowMs: number): string {
  const lines: string[] = [];
  lines.push(`# 🎯 SecTool Target / Victim-Exposure Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`,
  );
  lines.push(
    `**Method:** stored IPS alerts grouped by **destination** IP; pressure = Σ severity weight ` +
      `(info 1 · low 3 · medium 9 · high 27 · critical 81), split blocked vs. unblocked. ` +
      `Targets ranked by *unblocked* pressure, then distinct-attacker breadth · ` +
      `**Window alerts:** ${m.totalWindowAlerts}` +
      (m.droppedNoDest ? ` _(+${m.droppedNoDest} excluded: no usable destination)_` : ""),
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.totalWindowAlerts) {
    lines.push(
      `No alerts with a usable timestamp and destination in the last ${m.hours} hour(s) — no targets to rank.`,
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  lines.push(`| Metric | Value |`);
  lines.push(`| --- | --- |`);
  lines.push(`| Distinct targets | ${m.distinctTargets.toLocaleString("en-US")} |`);
  lines.push(`| — internal (your assets) | ${m.internalTargets.toLocaleString("en-US")} |`);
  lines.push(`| — external | ${m.externalTargets.toLocaleString("en-US")} |`);
  lines.push(`| Total pressure | ${m.totalPressure.toLocaleString("en-US")} |`);
  lines.push(
    `| Unblocked pressure | ${m.totalUnblockedPressure.toLocaleString("en-US")} (${pct(m.overallExposure)}) |`,
  );
  lines.push("");

  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Internal targets (your assets under fire)`);
  lines.push("");
  if (!m.topInternal.length) {
    lines.push(
      `_No internal (RFC1918) destination took an alert this window — every target was external._`,
    );
  } else {
    lines.push(
      `Your own hosts, ranked by *unblocked* pressure — the part the gateway let through. ` +
        `_Attackers_ is the count of distinct sources hitting that one box (siege breadth); a high value with high ` +
        `_Exposure_ is a distributed campaign on an exposed service. _Sigs_ / _Cats_ are technique breadth. ` +
        `Flags: ⛔ blocklisted · 👁 watchlisted · ✅ safelisted.`,
    );
    lines.push("");
    lines.push(targetTable(m.topInternal, nowMs));
  }
  lines.push("");

  lines.push(`## External targets (gateway / outbound destinations)`);
  lines.push("");
  if (!m.topExternal.length) {
    lines.push(`_No external destination took an alert this window._`);
  } else {
    lines.push(
      `Destinations that are **not** your RFC1918 space — usually the gateway's own WAN IP (perimeter ` +
        `background) or an outbound destination one of your hosts reached (where the row's attacker is *internal*, ` +
        `that is candidate C2 / exfil — cross-check the traffic-direction report). Surfaced separately so they ` +
        `never crowd out your own assets above.`,
    );
    lines.push("");
    lines.push(targetTable(m.topExternal, nowMs));
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from stored **IPS-alert** destinations, severity and action. **Pressure** is a ` +
      `**heuristic** severity-weighted volume (info 1 · low 3 · medium 9 · high 27 · critical 81); read the ranking ` +
      `as relative and trust the attacker/technique-breadth columns as much as the number. These are detections, ` +
      `not flows — a target's pressure reflects what *tripped a rule* against it, not its total inbound traffic, so ` +
      `a calm target is not proof it is un-probed. src/dst are the gateway's own labels (NAT / hairpin / asymmetric ` +
      `routing can mislabel which side is the target); internal = RFC1918, which a flat/VPN topology can blur. A long ` +
      `look-back can hit the store's history cap and deflate a target's pressure. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the target / victim-exposure report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link TargetsOptions}: `limit` (rows per table) and a `nowMs` pin.
 */
export function buildTargets(hours: number, opts: TargetsOptions = {}): TargetsReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(100, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const targets = new Map<string, TargetAcc>();
  let totalPressure = 0;
  let totalUnblockedPressure = 0;
  let droppedNoDest = 0;
  let countedAlerts = 0;

  for (const a of windowed) {
    const dst = validIp(a.dstIp);
    if (!dst) {
      droppedNoDest++;
      continue;
    }
    countedAlerts++;

    const severity = asSeverity(a.severity);
    const disp = classifyDisposition(a.action);
    const weight = SEVERITY_WEIGHT[severity];

    totalPressure += weight;
    if (disp !== "blocked") totalUnblockedPressure += weight;

    let acc = targets.get(dst);
    if (!acc) {
      acc = newTargetAcc(a.time);
      targets.set(dst, acc);
    }
    acc.count++;
    acc.pressure += weight;
    if (disp === "blocked") acc.blocked++;
    else {
      acc.unblockedPressure += weight;
      if (disp === "passed") acc.passed++;
      else acc.unknown++;
    }
    acc.severityMax = maxSeverity(acc.severityMax, severity);
    if (isSevere(severity)) acc.severe++;
    if (a.time < acc.firstMs) acc.firstMs = a.time;
    if (a.time > acc.lastMs) acc.lastMs = a.time;

    const src = validIp(a.srcIp);
    if (src) {
      bump(acc.sources, src);
      if (!isPrivate(src)) acc.externalSources.add(src);
    }
    const sig = a.signature?.trim();
    if (sig) bump(acc.signatures, sig);
    const cat = a.category?.trim();
    if (cat) acc.categories.add(cat);
  }

  const rows = [...targets.entries()].map(([ip, acc]) => finishTarget(ip, acc, totalUnblockedPressure || totalPressure));
  const internal = rows.filter((r) => r.scope === "internal");
  const external = rows.filter((r) => r.scope === "external");

  const base: Omit<TargetsReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: countedAlerts,
    droppedNoDest,
    distinctTargets: rows.length,
    internalTargets: internal.length,
    externalTargets: external.length,
    totalPressure: round1(totalPressure),
    totalUnblockedPressure: round1(totalUnblockedPressure),
    overallExposure: totalPressure ? round4(totalUnblockedPressure / totalPressure) : 0,
    topInternal: rankTargets(internal, limit),
    topExternal: rankTargets(external, limit),
  };

  const highlights = writeHighlights(base, windowEndMs);
  const model: TargetsReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model, windowEndMs);
  return model;
}

/** A filesystem-safe filename for a downloaded target-exposure report. */
export function targetsFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-targets-${stamp}.md`;
}
