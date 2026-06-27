/**
 * Source-port fingerprint / tooling-artifact report — "is this attacker a *tool*
 * reusing one source port, or a normal stack picking random ephemeral ports —
 * and do several different IPs share the *same* fixed source port (one toolkit,
 * many hands)?"
 *
 * Every offline report SecTool ships pivots on the *destination* side of the flow
 * — which host, which service, which port is under fire (see ports.ts, scan.ts,
 * targets.ts). Not one of them looks at the **source port** the attacker dialled
 * *from*, and that field carries a surprisingly strong signal that nothing else
 * captures:
 *
 *   - A healthy client OS picks a fresh, effectively-random **ephemeral** source
 *     port (Linux 32768–60999, Windows 49152–65535) for every new connection, so
 *     across hundreds of alerts you see hundreds of distinct, high-numbered source
 *     ports — high entropy.
 *   - A **mass-scanning tool** that crafts its own packets (zmap, masscan, many
 *     bespoke scanners) commonly pins a *single fixed* source port for its entire
 *     run for speed and stateless reply-matching. A source IP that fires 400
 *     alerts all from `:61000` is not a browser — it is a tool, and the *value* of
 *     that fixed port is a fingerprint.
 *   - A **privileged** source port (< 1024) on inbound attack traffic is abnormal
 *     for a real client (those ports need root/raw sockets) and hints at spoofing,
 *     reflection, or hand-rolled raw-socket tooling.
 *
 * The cross-source roll-up is where this earns its keep: when *several distinct
 * source IPs* all use the **same** fixed source port as their dominant port, that
 * shared artifact is a toolkit / botnet correlator — the same software (or the
 * same operator's launch script) behind otherwise-unrelated addresses. No
 * destination-pivoted report can see that, because the only thing those IPs have
 * in common is *how* they dial out, not *what* they hit.
 *
 * For every source IP over the window this report folds the windowed alerts,
 * recovers each alert's **source port** from the raw line (the same Suricata flow
 * tuple / JSON `src_port` shapes ports.ts uses for the *destination* port),
 * and computes:
 *
 *   - **distinct source ports** and the **normalised Shannon entropy** of their
 *     distribution (0 = one fixed port, 1 = perfectly uniform) — the headline
 *     "tool vs stack" axis;
 *   - the **dominant source port** and its **share** of the source's alerts;
 *   - the **privileged share** (ports < 1024) and **ephemeral share** (≥ 49152);
 *   - a severity-weighted score, the blocked/passed enforcement split, and the
 *     internal-vs-external / blocklist / watchlist / safelist membership flags
 *     every other report carries.
 *
 * Each source is then classified **🔧 fixed** (one dominant port — classic tool
 * artifact), **🎯 clustered** (a small reused set — semi-automated or a NAT pool),
 * or **🎲 varied** (broad ephemeral spread — normal stack), and sources are ranked
 * most-tool-like first so the automated scanners float to the top.
 *
 * Honest caveats baked into the output:
 *
 *   - **Source ports are re-parsed, not stored.** Only alerts whose raw line still
 *     carries a flow tuple or a `src_port` field contribute; the unparsed count is
 *     shown so a thin sample is visible rather than mistaken for "fixed".
 *   - **Low volume is not a fingerprint.** A source with two alerts on one port is
 *     trivially "fixed" — the min-alerts gate (default 4) keeps coincidence out of
 *     the tool verdict, and the raw counts are always shown.
 *   - **NAT muddies attribution.** Many hosts behind one NAT can share a source
 *     port over time; per-source figures attribute to the address SecTool saw, not
 *     the host behind it.
 *   - **Alerts, not flows.** SecTool stores IPS *detections*, so the port sample is
 *     whatever tripped a rule — a lower bound, not the full connection history.
 *   - **Window-bounded & store-capped.** A long look-back can hit the store's
 *     history cap and undercount.
 *
 * Pure in-memory math over alertStore (plus blocklist / watchlist / safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring report.ts, scan.ts,
 * ports.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** The three source-port behaviours a source can exhibit. */
export type PortShape = "fixed" | "clustered" | "varied";

/** Blocked / passed / unknown disposition split for a source. */
export interface DispositionSplit {
  /** Alerts the gateway actively blocked / dropped. */
  blocked: number;
  /** Alerts the gateway logged but let through (detected / allowed). */
  passed: number;
  /** Alerts with no recorded action (excluded from {@link passRate}). */
  unknown: number;
  /**
   * Fraction of *actioned* (blocked + passed) alerts that were let through,
   * 0..1 (4dp), or null when nothing was actioned.
   */
  passRate: number | null;
}

/** Per-source source-port fingerprint metrics over the window. */
export interface SrcPortSource {
  /** The source IP doing the dialling. */
  ip: string;
  /** True when the source is one of our own hosts (RFC1918 / loopback / …). */
  internal: boolean;
  /** The classified source-port behaviour (see {@link PortShape}). */
  shape: PortShape;
  /** Alerts attributed to this source from which a source port was recovered. */
  count: number;
  /** Total alerts attributed to this source (port-bearing or not). */
  totalAlerts: number;
  /** Distinct source ports observed for this source. */
  distinctPorts: number;
  /**
   * Normalised Shannon entropy of the source-port distribution, 0..1 (4dp).
   * 0 = a single fixed port (tool artifact); ~1 = uniform spread (normal stack).
   */
  entropy: number;
  /** The most-used source port for this source, if any was recovered. */
  topPort?: number;
  /** Fraction of {@link count} alerts using {@link topPort}, 0..1 (4dp). */
  topShare: number;
  /** Fraction of port-bearing alerts whose source port was privileged (< 1024). */
  privilegedShare: number;
  /** Fraction of port-bearing alerts whose source port was ephemeral (≥ 49152). */
  ephemeralShare: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Severity-weighted score (Σ SEVERITY_WEIGHT) — a secondary signal. */
  score: number;
  /** Blocked / passed / unknown disposition split. */
  disposition: DispositionSplit;
  /** Worst severity seen from this source. */
  severityMax: Severity;
  /** The source is on the blocklist. */
  blocked: boolean;
  /** The source is on the watchlist. */
  watched: boolean;
  /** The source is marked safe. */
  safe: boolean;
}

/** A source port shared by several distinct sources as their dominant port. */
export interface SharedFingerprint {
  /** The shared source port value. */
  port: number;
  /** A privileged port (< 1024) — abnormal for a real client. */
  privileged: boolean;
  /** An ephemeral-range port (≥ 49152) — a weaker (could be coincidence) signal. */
  ephemeral: boolean;
  /** Distinct source IPs whose dominant source port is this value. */
  distinctSources: number;
  /** Of those, how many are classified fixed/clustered (tool-like). */
  toolingSources: number;
  /** Total alerts across those sources that used this source port. */
  count: number;
  /** Up to a few example source IPs sharing this port (for the table). */
  sampleSources: string[];
}

/** Count of sources falling into each behaviour (the headline distribution). */
export interface ShapeCounts {
  fixed: number;
  clustered: number;
  varied: number;
}

export interface SrcPortReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts carrying a valid source IP (the analysable set). */
  sourcedAlerts: number;
  /** Of those, alerts from which a source port was recovered. */
  portBearingAlerts: number;
  /** Dominant-port share at/above which a source counts as "fixed". */
  fixedThreshold: number;
  /** Normalised-entropy at/below which a non-fixed source counts as "clustered". */
  clusteredEntropy: number;
  /** Minimum port-bearing alerts a source needs before it is classified. */
  minAlerts: number;
  /** Distinct source IPs analysed (after the min-alerts gate). */
  distinctSources: number;
  /** How many sources fell into each behaviour. */
  shapeCounts: ShapeCounts;
  /** Per-source rows, most-tool-like first. */
  sources: SrcPortSource[];
  /** Source ports shared across multiple sources, busiest first. */
  sharedFingerprints: SharedFingerprint[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface SrcPortOptions {
  /** Max rows in the per-source table and shared-fingerprint roll-up (clamped to [1, 200]). */
  limit?: number;
  /** Dominant-port share ≥ this marks a source "fixed" (0..1, default 0.85). */
  fixedThreshold?: number;
  /** Normalised entropy ≤ this marks a non-fixed source "clustered" (0..1, default 0.5). */
  clusteredEntropy?: number;
  /** Minimum port-bearing alerts before a source is classified (≥1, default 4). */
  minAlerts?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const DEFAULT_FIXED_THRESHOLD = 0.85;
const DEFAULT_CLUSTERED_ENTROPY = 0.5;
const DEFAULT_MIN_ALERTS = 4;
const MS_PER_HOUR = 3_600_000;

/** IANA dynamic / ephemeral range floor. */
const EPHEMERAL_FLOOR = 49152;
/** Privileged / well-known range ceiling (exclusive). */
const PRIVILEGED_CEIL = 1024;
/** How many example sources to show per shared-fingerprint row. */
const SHARED_SAMPLE_CAP = 4;

// ----- source-port re-parsing (mirrors ports.ts recoverFlow, src side) -------

// Same flow shape ports.ts keys off, but here we want the *source* port (group 3):
//   {TCP} a.b.c.d:51000 -> e.f.g.h:3389
const SRC_FLOW =
  /\{(\w+)\}\s*([0-9a-fA-F.:]+?)(?::(\d+))?\s*(?:->|<->|<-)\s*([0-9a-fA-F.:]+?)(?::(\d+))?(?:\s|$)/;

function toPort(v: unknown): number | undefined {
  const n = typeof v === "number" ? v : Number(v);
  return Number.isInteger(n) && n > 0 && n <= 65535 ? n : undefined;
}

/**
 * Re-parse the *source* port from a stored alert's raw line, using the same two
 * shapes ports.ts understands for the destination port: a Suricata flow tuple
 * (source port is group 3) or a JSON payload carrying `src_port` / `source_port`.
 * Returns undefined when no source port can be recovered.
 */
export function recoverSrcPort(raw: string | undefined): number | undefined {
  if (!raw) return undefined;

  // 1) Suricata flow tuple: {TCP} a.b.c.d:51000 -> e.f.g.h:3389  (group 3 = src port)
  const flow = SRC_FLOW.exec(raw);
  if (flow && flow[3]) {
    const p = toPort(flow[3]);
    if (p !== undefined) return p;
  }

  // 2) JSON payload: {"src_port":51000, ...}
  const start = raw.indexOf("{");
  const end = raw.lastIndexOf("}");
  if (start !== -1 && end > start) {
    try {
      const obj = JSON.parse(raw.slice(start, end + 1)) as Record<string, unknown>;
      if (obj && typeof obj === "object") {
        const p =
          toPort(obj["src_port"]) ??
          toPort(obj["srcport"]) ??
          toPort(obj["source_port"]) ??
          toPort(obj["sport"]);
        if (p !== undefined) return p;
      }
    } catch {
      // not JSON — fall through
    }
  }
  return undefined;
}

// ----- classifiers / helpers (mirror scan.ts / ports.ts) --------------------

/** RFC1918 / loopback / link-local / ULA — an address treated as one of ours. */
function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
}

/** A valid, non-empty IP, or undefined if the field is missing/garbage. */
function validIp(ip: string | undefined): string | undefined {
  return ip && isIP(ip) !== 0 ? ip : undefined;
}

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? (b as Severity) : a;
}

function isSevere(s: string | undefined): boolean {
  return sevRank(s) >= 2; // medium or worse
}

function weightOf(s: string | undefined): number {
  return SEVERITY_WEIGHT[(s as Severity) ?? "info"] ?? SEVERITY_WEIGHT.info;
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

function pct(frac: number): string {
  return `${Math.round(frac * 100)}%`;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
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

/**
 * Normalised Shannon entropy of a port-frequency distribution, 0..1.
 * 0 when a single port carries everything; 1 when k ports are perfectly uniform.
 */
function normalizedEntropy(counts: number[]): number {
  const total = counts.reduce((a, b) => a + b, 0);
  const k = counts.length;
  if (total <= 0 || k <= 1) return 0;
  let h = 0;
  for (const c of counts) {
    if (c > 0) {
      const p = c / total;
      h -= p * Math.log2(p);
    }
  }
  return round4(h / Math.log2(k));
}

/** Human label for a behaviour, with an emoji that reads at a glance. */
function shapeLabel(s: PortShape): string {
  switch (s) {
    case "fixed":
      return "🔧 fixed";
    case "clustered":
      return "🎯 clustered";
    case "varied":
      return "🎲 varied";
  }
}

/** Rank for sorting — most tool-like (fixed) first. */
function shapeRank(s: PortShape): number {
  return s === "fixed" ? 0 : s === "clustered" ? 1 : 2;
}

/** Display a port value, annotating privileged / ephemeral. */
function portWithRange(port: number | undefined): string {
  if (port === undefined) return "—";
  if (port < PRIVILEGED_CEIL) return `${port} (priv)`;
  if (port >= EPHEMERAL_FLOOR) return `${port} (ephem)`;
  return String(port);
}

/**
 * Classify a source's source-port behaviour from its dominant-port share and the
 * entropy of its port distribution.
 */
function classifyShape(
  topShare: number,
  entropy: number,
  fixedThreshold: number,
  clusteredEntropy: number,
): PortShape {
  if (topShare >= fixedThreshold) return "fixed";
  if (entropy <= clusteredEntropy) return "clustered";
  return "varied";
}

// ----- aggregation ----------------------------------------------------------

interface SourceAcc {
  total: number;
  portBearing: number;
  score: number;
  severe: number;
  privileged: number;
  ephemeral: number;
  blocked: number;
  passed: number;
  unknown: number;
  portCounts: Map<number, number>;
  severityMax: Severity;
}

function newSourceAcc(): SourceAcc {
  return {
    total: 0,
    portBearing: 0,
    score: 0,
    severe: 0,
    privileged: 0,
    ephemeral: 0,
    blocked: 0,
    passed: 0,
    unknown: 0,
    portCounts: new Map(),
    severityMax: "info",
  };
}

interface SharedAcc {
  sources: Set<string>;
  toolingSources: Set<string>;
  count: number;
}

function newSharedAcc(): SharedAcc {
  return { sources: new Set(), toolingSources: new Set(), count: 0 };
}

/** The dominant (most-used) port in a frequency map, ties broken low-first. */
function dominantPort(counts: Map<number, number>): { port?: number; n: number } {
  let port: number | undefined;
  let n = 0;
  for (const [p, c] of counts) {
    if (c > n || (c === n && port !== undefined && p < port)) {
      port = p;
      n = c;
    }
  }
  return { port, n };
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  m: { distinctSources: number; portBearingAlerts: number; sourcedAlerts: number },
  shapeCounts: ShapeCounts,
  sources: SrcPortSource[],
  shared: SharedFingerprint[],
): string[] {
  const out: string[] = [];
  if (!sources.length) return out;

  // Overall behaviour distribution — how much of the field looks automated.
  const tooling = shapeCounts.fixed + shapeCounts.clustered;
  out.push(
    `🔌 Over the last ${hours}h, **${m.distinctSources} source(s)** had a usable source-port sample; ` +
      `**${tooling}** look automated (${shapeCounts.fixed} fixed-port · ${shapeCounts.clustered} clustered), ` +
      `${shapeCounts.varied} show a normal ephemeral spread.`,
  );

  // The clearest single-tool fingerprint — a fixed source port at volume.
  const fixed = sources.filter((s) => s.shape === "fixed");
  if (fixed.length) {
    const f = fixed[0]!;
    out.push(
      `🔧 Strongest tool fingerprint is \`${f.ip}\`${f.internal ? " *(internal!)*" : ""} — **${pct(f.topShare)} of its ` +
        `${f.count} port-bearing alert(s)** came from a single source port **${portWithRange(f.topPort)}** ` +
        `(entropy ${f.entropy.toFixed(2)}). That is packet-crafting tooling, not a browser.`,
    );
  }

  // The headline: one fixed source port worn by several different IPs.
  const fleet = shared.find((s) => s.distinctSources >= 2 && s.toolingSources >= 2);
  if (fleet) {
    out.push(
      `🕸️ **Shared fingerprint:** source port **${portWithRange(fleet.port)}** is the dominant dial-out port for ` +
        `**${fleet.distinctSources} distinct source(s)** (${fleet.toolingSources} tool-like) — the same toolkit / ` +
        `launch script behind otherwise-unrelated IPs (e.g. ${fleet.sampleSources.slice(0, 3).map((s) => `\`${s}\``).join(", ")}). ` +
        `Correlate and block as one campaign.`,
    );
  }

  // Privileged source ports — spoofing / raw-socket tell.
  const priv = sources
    .filter((s) => s.privilegedShare >= 0.5 && !s.internal)
    .sort((a, b) => b.privilegedShare - a.privilegedShare)[0];
  if (priv) {
    out.push(
      `🔒 \`${priv.ip}\` dials out from a **privileged port (< 1024) on ${pct(priv.privilegedShare)} of its alerts** — ` +
        `real clients don't, so this is raw-socket tooling, reflection, or a spoofed source. Treat the address with ` +
        `suspicion even at low volume.`,
    );
  }

  // An internal host showing a fixed-port artifact — compromise / scanner inside.
  const insider = sources.find((s) => s.internal && s.shape === "fixed");
  if (insider) {
    out.push(
      `🚨 *Internal* host \`${insider.ip}\` is firing from a **fixed source port ${portWithRange(insider.topPort)}** — ` +
        `an inside box behaving like a scanner is a compromise / lateral-movement tell. Investigate it first.`,
    );
  }

  // Parse-coverage honesty — how much of the stream carried a source port at all.
  if (m.sourcedAlerts > 0) {
    const frac = m.portBearingAlerts / m.sourcedAlerts;
    if (frac < 0.5) {
      out.push(
        `ℹ️ Only **${pct(frac)} of sourced alerts carried a recoverable source port** — every figure here is a lower ` +
          `bound drawn from that sample, not the full connection history.`,
      );
    }
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function sourceTable(rows: SrcPortSource[]): string {
  return mdTable(
    ["#", "Source", "Behaviour", "Ports", "Entropy", "Top port", "Top share", "Priv%", "Alerts", "Severe", "Pass rate", "Flags"],
    rows.map((s, i) => {
      const flags =
        (s.internal ? "🏠" : "") +
        (s.blocked ? "⛔" : "") +
        (s.watched ? "👁" : "") +
        (s.safe ? "✅" : "") +
        (s.privilegedShare >= 0.5 ? "🔒" : "");
      return [
        String(i + 1),
        cell(s.ip),
        cell(shapeLabel(s.shape)),
        String(s.distinctPorts),
        s.entropy.toFixed(2),
        cell(portWithRange(s.topPort)),
        pct(s.topShare),
        pct(s.privilegedShare),
        String(s.count),
        String(s.severe),
        s.disposition.passRate === null ? "—" : pct(s.disposition.passRate),
        flags || "—",
      ];
    }),
  );
}

function sharedTable(rows: SharedFingerprint[]): string {
  return mdTable(
    ["#", "Source port", "Distinct sources", "Tool-like", "Alerts", "Example sources"],
    rows.map((s, i) => [
      String(i + 1),
      cell(portWithRange(s.port)),
      String(s.distinctSources),
      String(s.toolingSources),
      String(s.count),
      cell(s.sampleSources.map((x) => x).join(", ")),
    ]),
  );
}

function renderMarkdown(m: SrcPortReport): string {
  const lines: string[] = [];
  lines.push(`# 🔌 SecTool Source-Port Fingerprint / Tooling-Artifact Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** each source's source port re-parsed from the raw line, then the entropy of its source-port ` +
      `distribution + dominant-port share classify it **fixed** (top share ≥ ${pct(m.fixedThreshold)}), ` +
      `**clustered** (entropy ≤ ${m.clusteredEntropy.toFixed(2)}), or **varied** · ` +
      `**Sourced alerts:** ${m.sourcedAlerts} of ${m.totalWindowAlerts} (${m.portBearingAlerts} carried a source port)`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.sources.length) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    } else if (!m.portBearingAlerts) {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but **none carried a recoverable source ` +
          `port** (no flow tuple or \`src_port\` field survived in the raw line), so no source-port fingerprint can ` +
          `be computed.`,
      );
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but no source reached the ` +
          `${m.minAlerts}-port-bearing-alert floor needed to fingerprint a source-port behaviour.`,
      );
    }
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Sources by source-port fingerprint`);
  lines.push("");
  lines.push(sourceTable(m.sources));
  lines.push("");
  lines.push(
    `**Legend:** _Behaviour_ — **🔧 fixed** (one dominant source port: packet-crafting tool artifact) · ` +
      `**🎯 clustered** (a small reused set: semi-automated or a NAT pool) · **🎲 varied** (broad ephemeral spread: ` +
      `normal client stack). _Entropy_ is the normalised Shannon entropy of the source-port distribution ` +
      `(0 = one port, 1 = uniform). _Priv%_ = share of alerts dialled from a privileged (< 1024) source port. ` +
      `_Pass rate_ = share of *actioned* alerts let through. **Flags:** 🏠 internal source · ⛔ blocked · 👁 watched · ` +
      `✅ safe · 🔒 mostly-privileged source port.`,
  );
  lines.push("");

  lines.push(`## Shared source-port fingerprints`);
  lines.push("");
  if (!m.sharedFingerprints.length) {
    lines.push(
      `_No source port was the dominant dial-out port for more than one source this window_, so no cross-source ` +
        `toolkit correlation could be drawn. The per-source fingerprints above are unaffected.`,
    );
  } else {
    lines.push(
      `Source ports that are the **dominant** dial-out port for *more than one* distinct source — a shared artifact ` +
        `that points at the same tool / launch script (and often the same operator) behind unrelated addresses.`,
    );
    lines.push("");
    lines.push(sharedTable(m.sharedFingerprints));
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Source **ports are re-parsed from each alert's raw line**, not stored columns, ` +
      `so every figure is a lower bound drawn from alerts that still carried a flow tuple or \`src_port\` field. ` +
      `A **fixed** source port at volume is a strong packet-crafting-tool tell, but low volume is not — the ` +
      `${m.minAlerts}-alert floor and the raw counts let the call be second-guessed. **NAT** can make many hosts ` +
      `share a source port over time, so attribution is to the address SecTool saw. These are IPS **detections**, ` +
      `not full flows. A long look-back can hit the store's history cap and undercount. No live gateway query was ` +
      `performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the source-port fingerprint / tooling-artifact report from the stored
 * alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link SrcPortOptions}: `limit`, `fixedThreshold`,
 *              `clusteredEntropy`, `minAlerts`, and a `nowMs` pin for tests.
 */
export function buildSrcPort(hours: number, opts: SrcPortOptions = {}): SrcPortReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const fixedThreshold = Math.max(0, Math.min(1, opts.fixedThreshold ?? DEFAULT_FIXED_THRESHOLD));
  const clusteredEntropy = Math.max(0, Math.min(1, opts.clusteredEntropy ?? DEFAULT_CLUSTERED_ENTROPY));
  const minAlerts = Math.max(1, Math.floor(opts.minAlerts ?? DEFAULT_MIN_ALERTS));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const sources = new Map<string, SourceAcc>();
  let sourced = 0;
  let portBearing = 0;

  for (const a of windowed) {
    const src = validIp(a.srcIp);
    if (!src) continue;
    sourced++;

    const acc = sources.get(src) ?? newSourceAcc();
    if (!sources.has(src)) sources.set(src, acc);
    acc.total++;
    acc.score += weightOf(a.severity);
    acc.severityMax = maxSeverity(acc.severityMax, a.severity);
    if (isSevere(a.severity)) acc.severe++;

    const port = recoverSrcPort(a.raw);
    if (port !== undefined) {
      portBearing++;
      acc.portBearing++;
      acc.portCounts.set(port, (acc.portCounts.get(port) ?? 0) + 1);
      if (port < PRIVILEGED_CEIL) acc.privileged++;
      if (port >= EPHEMERAL_FLOOR) acc.ephemeral++;
    }

    const disp = classifyDisposition(a.action);
    if (disp === "blocked") acc.blocked++;
    else if (disp === "passed") acc.passed++;
    else acc.unknown++;
  }

  const shapeCounts: ShapeCounts = { fixed: 0, clustered: 0, varied: 0 };
  // dominant-port → sources whose top port is this value (the shared-fingerprint roll-up).
  const shared = new Map<number, SharedAcc>();

  const sourceList: SrcPortSource[] = [...sources.entries()]
    .filter(([, acc]) => acc.portBearing >= minAlerts)
    .map(([ip, acc]) => {
      const dom = dominantPort(acc.portCounts);
      const topShare = acc.portBearing > 0 && dom.port !== undefined ? round4(dom.n / acc.portBearing) : 0;
      const entropy = normalizedEntropy([...acc.portCounts.values()]);
      const shape = classifyShape(topShare, entropy, fixedThreshold, clusteredEntropy);
      shapeCounts[shape]++;

      // Feed the cross-source roll-up keyed on this source's dominant port.
      if (dom.port !== undefined) {
        const sh = shared.get(dom.port) ?? newSharedAcc();
        if (!shared.has(dom.port)) shared.set(dom.port, sh);
        sh.sources.add(ip);
        sh.count += dom.n;
        if (shape !== "varied") sh.toolingSources.add(ip);
      }

      const actioned = acc.blocked + acc.passed;
      return {
        ip,
        internal: isPrivate(ip),
        shape,
        count: acc.portBearing,
        totalAlerts: acc.total,
        distinctPorts: acc.portCounts.size,
        entropy,
        topPort: dom.port,
        topShare,
        privilegedShare: acc.portBearing ? round4(acc.privileged / acc.portBearing) : 0,
        ephemeralShare: acc.portBearing ? round4(acc.ephemeral / acc.portBearing) : 0,
        severe: acc.severe,
        score: acc.score,
        disposition: {
          blocked: acc.blocked,
          passed: acc.passed,
          unknown: acc.unknown,
          passRate: actioned ? round4(acc.passed / actioned) : null,
        },
        severityMax: acc.severityMax,
        blocked: blockStore.has(ip),
        watched: watchStore.has(ip),
        safe: safeStore.has(ip),
      } satisfies SrcPortSource;
    })
    // Most tool-like first: behaviour, then volume (stronger evidence), then share.
    .sort(
      (x, y) =>
        shapeRank(x.shape) - shapeRank(y.shape) ||
        y.count - x.count ||
        y.topShare - x.topShare ||
        (x.ip < y.ip ? -1 : x.ip > y.ip ? 1 : 0),
    );

  // shapeCounts/shared are accumulated across all qualifying sources above; the
  // table is then capped to `limit` rows for display without disturbing totals.
  const cappedSources = sourceList.slice(0, limit);

  const sharedFingerprints: SharedFingerprint[] = [...shared.entries()]
    .filter(([, sh]) => sh.sources.size >= 2)
    .map(([port, sh]) => ({
      port,
      privileged: port < PRIVILEGED_CEIL,
      ephemeral: port >= EPHEMERAL_FLOOR,
      distinctSources: sh.sources.size,
      toolingSources: sh.toolingSources.size,
      count: sh.count,
      sampleSources: [...sh.sources].sort().slice(0, SHARED_SAMPLE_CAP),
    }))
    // Most-shared first: distinct sources, then tool-like sources, then volume.
    .sort(
      (x, y) =>
        y.distinctSources - x.distinctSources ||
        y.toolingSources - x.toolingSources ||
        y.count - x.count ||
        x.port - y.port,
    )
    .slice(0, limit);

  const highlights = writeHighlights(
    safeHours,
    { distinctSources: sourceList.length, portBearingAlerts: portBearing, sourcedAlerts: sourced },
    shapeCounts,
    cappedSources,
    sharedFingerprints,
  );

  const model: SrcPortReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    sourcedAlerts: sourced,
    portBearingAlerts: portBearing,
    fixedThreshold,
    clusteredEntropy,
    minAlerts,
    distinctSources: sourceList.length,
    shapeCounts,
    sources: cappedSources,
    sharedFingerprints,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded source-port fingerprint report. */
export function srcportFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-srcports-${stamp}.md`;
}
