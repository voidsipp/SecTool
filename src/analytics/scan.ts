/**
 * Scan-shape / reconnaissance-pattern report — "*how* is each attacker probing
 * me — sweeping one service across the whole network, or enumerating one host
 * end-to-end?"
 *
 * Two existing reports each see one half of this picture and neither sees the
 * cross:
 *
 *   - **spread.ts** ranks a source by the number of distinct *destinations* it
 *     touches (host fan-out). It is, by its own admission, *blind to ports*: a
 *     source that hammers a hundred hosts on port 445 and one that enumerates
 *     fifty ports on a single host look the same to it.
 *   - **ports.ts** ranks the destination *port / service* under fire and which
 *     host exposes it. It pivots on the port, not the attacker, so it never says
 *     "this one source is fanning a single port across your whole /24".
 *
 * The shape of a probe is one of the most diagnostic things an IPS stream holds,
 * because the three classic recon patterns demand three different responses:
 *
 *   - **Horizontal scan** — *one (or few) destination ports across many hosts*.
 *     The attacker already knows the exploit and is hunting for *anywhere* that
 *     service is exposed (e.g. SMB/445 across the subnet, RDP/3389 sweeps). The
 *     fix is service-wide: firewall that port at the edge everywhere, not on the
 *     one host that happened to alert.
 *   - **Vertical scan** — *many ports on one (or few) hosts*. The attacker has
 *     picked a *target* and is enumerating its whole surface to find a way in.
 *     The fix is host-centric: that box is being singled out — harden it and
 *     watch it.
 *   - **Sweep** — *many ports across many hosts*. Full-spectrum reconnaissance
 *     (a mass scanner like a Shodan/zmap crawler, or a toolkit cataloguing the
 *     network). The broadest, noisiest, and usually the most automated.
 *   - **Targeted** — *few ports, few hosts*. Not recon-shaped: either an
 *     exploitation attempt against a known service or low-volume noise. Surfaced
 *     for completeness, never ranked above genuine scanning.
 *
 * For every source IP over the window this report folds the windowed alerts and
 * computes its **host breadth** (distinct destination IPs), **port breadth**
 * (distinct destination ports, re-parsed from each alert's raw line via the same
 * {@link recoverFlow} that powers ports.ts), the dominant target and probed
 * port, a severity-weighted score, the blocked/passed enforcement split, and the
 * internal-vs-external endpoint status (an **internal** source fanning out is a
 * compromise tell, not an inbound scanner). It then classifies the shape from
 * the two breadth axes against tunable thresholds and ranks sources by total
 * breadth — because for a *recon* report, reach is the signal, and a loud
 * info-level horizontal sweep is exactly what severity-weighted ranking would
 * wrongly bury.
 *
 * A companion **"most-probed services"** roll-up answers the firewall question
 * the per-source table can't: across *all* scanners, which port is the single
 * most-hunted service, and how many distinct sources are after it.
 *
 * Honest caveats baked into the output:
 *
 *   - **Ports are re-parsed, not stored.** Only alerts whose raw line still
 *     carries a flow tuple or `dest_port` contribute to *port* breadth; the
 *     unparsed count is shown so a thin port axis is visible rather than mistaken
 *     for "narrow". Host breadth uses the stored `dstIp` and is unaffected.
 *   - **Alerts, not flows.** SecTool stores IPS *detections*. A scan that probes
 *     a port without tripping a rule is invisible, so breadth is a lower bound
 *     and a quiet, surgical scanner can read as "targeted".
 *   - **Shape is a heuristic.** The horizontal/vertical/sweep call is a function
 *     of the host/port thresholds (tunable); a borderline source can sit either
 *     side of the line. The raw breadth counts are always shown so the call can
 *     be second-guessed.
 *   - **Window-bounded & store-capped.** A long look-back can hit the store's
 *     history cap and undercount breadth.
 *
 * Pure in-memory math over alertStore (plus blocklist / watchlist / safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring report.ts, ports.ts,
 * spread.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { recoverFlow, SERVICE_NAMES, HIGH_RISK_PORTS } from "./ports.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** The four reconnaissance shapes a source's probe can take. */
export type ScanShape = "horizontal" | "vertical" | "sweep" | "targeted";

/** Blocked / passed / unknown disposition split for a scanning source. */
export interface DispositionSplit {
  /** Alerts the gateway actively blocked / dropped. */
  blocked: number;
  /** Alerts the gateway logged but let through (detected / allowed). */
  passed: number;
  /** Alerts with no recorded action (excluded from {@link passRate}). */
  unknown: number;
  /**
   * Fraction of *actioned* (blocked + passed) alerts that were let through,
   * 0..1 (4dp), or null when nothing was actioned. High on a broad scanner means
   * the recon is succeeding — it is seeing your services answer.
   */
  passRate: number | null;
}

/** Per-source scan-shape metrics over the window. */
export interface ScanSource {
  /** The source IP doing the probing. */
  ip: string;
  /** True when the source is one of our own hosts (RFC1918 / loopback / …). */
  internal: boolean;
  /** The classified reconnaissance shape (see {@link ScanShape}). */
  shape: ScanShape;
  /** Distinct destination hosts this source touched (host breadth). */
  distinctHosts: number;
  /** Distinct destination ports recovered for this source (port breadth). */
  distinctPorts: number;
  /** distinctHosts + distinctPorts — the ranking key (recon reach). */
  breadth: number;
  /** Total alerts attributed to this source in the window. */
  count: number;
  /** Of {@link count}, alerts from which a destination port was recovered. */
  portBearing: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Severity-weighted score (Σ SEVERITY_WEIGHT) — a secondary signal. */
  score: number;
  /** Distinct destination hosts that are internal (your assets). */
  internalTargets: number;
  /** Distinct destination hosts that are external (outbound recon / C2 hunt). */
  externalTargets: number;
  /** Of {@link distinctPorts}, how many are high-risk admin / data-store ports. */
  highRiskPorts: number;
  /** Blocked / passed / unknown disposition split. */
  disposition: DispositionSplit;
  /** The most-probed destination port for this source, if any was recovered. */
  topPort?: number;
  /** Service label of {@link topPort}, if mapped. */
  topPortService?: string;
  /** The most-targeted destination host for this source, if any. */
  topHost?: string;
  /** Worst severity seen from this source. */
  severityMax: Severity;
  /** The source is on the blocklist. */
  blocked: boolean;
  /** The source is on the watchlist. */
  watched: boolean;
  /** The source is marked safe. */
  safe: boolean;
}

/** One destination port and how many distinct sources are hunting for it. */
export interface ProbedService {
  /** The destination port number. */
  port: number;
  /** Well-known service name, or undefined if unmapped. */
  service?: string;
  /** A remote-admin / data-store / management port (see ports.ts). */
  highRisk: boolean;
  /** Distinct source IPs that probed this port. */
  distinctScanners: number;
  /** Distinct destination hosts probed on this port. */
  distinctHosts: number;
  /** Total alerts naming this destination port. */
  count: number;
}

/** Count of sources falling into each shape (the headline distribution). */
export interface ShapeCounts {
  horizontal: number;
  vertical: number;
  sweep: number;
  targeted: number;
}

export interface ScanReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts carrying a valid source IP (the analysable set). */
  sourcedAlerts: number;
  /** Of those, alerts from which a destination port was recovered. */
  portBearingAlerts: number;
  /** Host-breadth threshold used to classify "many hosts". */
  hostThreshold: number;
  /** Port-breadth threshold used to classify "many ports". */
  portThreshold: number;
  /** Distinct source IPs analysed. */
  distinctSources: number;
  /** How many sources fell into each shape. */
  shapeCounts: ShapeCounts;
  /** Per-source scan-shape rows, broadest reach first. */
  sources: ScanSource[];
  /** The most-hunted destination ports across all sources, busiest first. */
  probedServices: ProbedService[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface ScanOptions {
  /** Max rows in the per-source table (clamped to [1, 200]). */
  limit?: number;
  /** Distinct-host count at/above which a source counts as "many hosts" (≥1). */
  hostThreshold?: number;
  /** Distinct-port count at/above which a source counts as "many ports" (≥1). */
  portThreshold?: number;
  /** Minimum alerts a source needs before it is analysed (drops one-off noise). */
  minAlerts?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const DEFAULT_HOST_THRESHOLD = 3;
const DEFAULT_PORT_THRESHOLD = 3;
const DEFAULT_MIN_ALERTS = 2;
const MS_PER_HOUR = 3_600_000;

// ----- classifiers / helpers (mirror ports.ts) ------------------------------

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

function topOf(counts: Map<string, number>): { key?: string; count: number } {
  let key: string | undefined;
  let count = 0;
  for (const [k, c] of counts) {
    if (c > count || (c === count && key !== undefined && k < key)) {
      key = k;
      count = c;
    }
  }
  return { key, count };
}

/** Human label for a shape, with an emoji that reads at a glance. */
function shapeLabel(s: ScanShape): string {
  switch (s) {
    case "horizontal":
      return "↔ horizontal";
    case "vertical":
      return "↕ vertical";
    case "sweep":
      return "▦ sweep";
    case "targeted":
      return "• targeted";
  }
}

/** Display label for a port: "3389 (RDP)" or just "51000". */
function portWithService(port: number | undefined): string {
  if (port === undefined) return "—";
  const svc = SERVICE_NAMES[port];
  return svc ? `${port} (${svc})` : String(port);
}

/**
 * Classify a source's probe shape from its two breadth axes. "Many" is decided
 * by the (tunable) host/port thresholds; the four-way split is the cross of the
 * two booleans.
 */
function classifyShape(
  distinctHosts: number,
  distinctPorts: number,
  hostThreshold: number,
  portThreshold: number,
): ScanShape {
  const manyHosts = distinctHosts >= hostThreshold;
  const manyPorts = distinctPorts >= portThreshold;
  if (manyHosts && manyPorts) return "sweep";
  if (manyHosts) return "horizontal";
  if (manyPorts) return "vertical";
  return "targeted";
}

// ----- aggregation ----------------------------------------------------------

interface SourceAcc {
  count: number;
  portBearing: number;
  score: number;
  severe: number;
  hosts: Set<string>;
  internalHosts: Set<string>;
  externalHosts: Set<string>;
  ports: Set<number>;
  highRiskPorts: Set<number>;
  blocked: number;
  passed: number;
  unknown: number;
  hostCounts: Map<string, number>;
  portCounts: Map<number, number>;
  severityMax: Severity;
}

function newSourceAcc(): SourceAcc {
  return {
    count: 0,
    portBearing: 0,
    score: 0,
    severe: 0,
    hosts: new Set(),
    internalHosts: new Set(),
    externalHosts: new Set(),
    ports: new Set(),
    highRiskPorts: new Set(),
    blocked: 0,
    passed: 0,
    unknown: 0,
    hostCounts: new Map(),
    portCounts: new Map(),
    severityMax: "info",
  };
}

interface ServiceAcc {
  scanners: Set<string>;
  hosts: Set<string>;
  count: number;
}

function newServiceAcc(): ServiceAcc {
  return { scanners: new Set(), hosts: new Set(), count: 0 };
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  m: { distinctSources: number; portBearingAlerts: number; sourcedAlerts: number },
  shapeCounts: ShapeCounts,
  sources: ScanSource[],
  probedServices: ProbedService[],
): string[] {
  const out: string[] = [];
  if (!sources.length) return out;

  // Overall shape distribution — what kind of probing dominates.
  const scanners = shapeCounts.horizontal + shapeCounts.vertical + shapeCounts.sweep;
  out.push(
    `🛰️ Over the last ${hours}h, **${m.distinctSources} source(s)** probed the network; **${scanners}** show a ` +
      `recon shape (${shapeCounts.sweep} sweep · ${shapeCounts.horizontal} horizontal · ${shapeCounts.vertical} ` +
      `vertical), the remaining ${shapeCounts.targeted} look targeted/low-breadth.`,
  );

  // The broadest reach — the loudest scanner overall.
  const lead = sources[0]!;
  out.push(
    `📡 Broadest reach is \`${lead.ip}\`${lead.internal ? " *(internal!)*" : ""} — **${shapeLabel(lead.shape)}**, ` +
      `${lead.distinctHosts} host(s) × ${lead.distinctPorts} port(s) across ${lead.count} alert(s). ` +
      `Most-probed: ${portWithService(lead.topPort)}${lead.topHost ? ` on \`${lead.topHost}\`` : ""}.`,
  );

  // Horizontal scanners hunting a single service — the firewall-everywhere fix.
  const horiz = sources.filter((s) => s.shape === "horizontal");
  if (horiz.length) {
    const h = horiz[0]!;
    out.push(
      `↔ **${horiz.length} horizontal scanner(s)** are hunting a single service across many hosts — fix at the edge ` +
        `for the whole subnet, not host-by-host. Worst: \`${h.ip}\` swept ${portWithService(h.topPort)} across ` +
        `${h.distinctHosts} host(s).`,
    );
  }

  // Vertical scanners enumerating one host — that box is being singled out.
  const vert = sources.filter((s) => s.shape === "vertical");
  if (vert.length) {
    const v = vert[0]!;
    out.push(
      `↕ **${vert.length} vertical scanner(s)** are enumerating one host's whole surface — that target is being ` +
        `singled out. Worst: \`${v.ip}\` hit ${v.distinctPorts} port(s)${v.topHost ? ` on \`${v.topHost}\`` : ""}; ` +
        `harden and watch it.`,
    );
  }

  // Internal sources fanning out — a compromise tell, not an inbound scan.
  const insiders = sources.filter((s) => s.internal && s.shape !== "targeted");
  if (insiders.length) {
    const i = insiders[0]!;
    out.push(
      `🚨 **${insiders.length} *internal* host(s)** are themselves scanning (${shapeLabel(i.shape)}) — an internal ` +
        `box probing this widely is a lateral-movement / compromise tell, not an outside attacker. Investigate ` +
        `\`${i.ip}\` first.`,
    );
  }

  // Recon that is succeeding — broad scanner mostly let through.
  const leaky = sources
    .filter((s) => s.shape !== "targeted" && s.disposition.passRate !== null && s.disposition.passed >= 3)
    .sort((a, b) => (b.disposition.passRate ?? 0) - (a.disposition.passRate ?? 0))[0];
  if (leaky && (leaky.disposition.passRate ?? 0) >= 0.5) {
    out.push(
      `⚠️ \`${leaky.ip}\`'s probing is **${pct(leaky.disposition.passRate!)} let through** ` +
        `(${leaky.disposition.passed} actioned alerts passed). The recon is reaching your services — block the ` +
        `source and confirm the exposure.`,
    );
  }

  // The single most-hunted service across everyone.
  const svc = probedServices[0];
  if (svc && svc.distinctScanners >= 2) {
    out.push(
      `🎯 Most-hunted service is **${portWithService(svc.port)}**${svc.highRisk ? " *(high-risk)*" : ""} — ` +
        `${svc.distinctScanners} distinct source(s) probed it across ${svc.distinctHosts} host(s). If it need not ` +
        `face the internet, closing it removes the prize the most scanners are after.`,
    );
  }

  // Port-coverage honesty — how much of the stream carried a port at all.
  const total = m.portBearingAlerts;
  if (m.sourcedAlerts > 0) {
    const frac = total / m.sourcedAlerts;
    if (frac < 0.5) {
      out.push(
        `ℹ️ Only **${pct(frac)} of sourced alerts carried a recoverable destination port** — port breadth (and the ` +
          `horizontal/vertical call that leans on it) is a lower bound; host breadth is unaffected.`,
      );
    }
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function sourceTable(rows: ScanSource[]): string {
  return mdTable(
    ["#", "Source", "Shape", "Hosts", "Ports", "Alerts", "Severe", "Top port", "Top host", "Passed", "Pass rate", "Flags"],
    rows.map((s, i) => {
      const flags =
        (s.internal ? "🏠" : "") +
        (s.blocked ? "⛔" : "") +
        (s.watched ? "👁" : "") +
        (s.safe ? "✅" : "") +
        (s.highRiskPorts ? "⚠️" : "");
      return [
        String(i + 1),
        cell(s.ip),
        cell(shapeLabel(s.shape)),
        String(s.distinctHosts),
        String(s.distinctPorts),
        String(s.count),
        String(s.severe),
        cell(portWithService(s.topPort)),
        cell(s.topHost ?? "—"),
        String(s.disposition.passed),
        s.disposition.passRate === null ? "—" : pct(s.disposition.passRate),
        flags || "—",
      ];
    }),
  );
}

function serviceTable(rows: ProbedService[]): string {
  return mdTable(
    ["#", "Port", "Scanners", "Hosts probed", "Alerts", "Risk"],
    rows.map((s, i) => [
      String(i + 1),
      cell(portWithService(s.port)),
      String(s.distinctScanners),
      String(s.distinctHosts),
      String(s.count),
      s.highRisk ? "⚠️" : "",
    ]),
  );
}

function renderMarkdown(m: ScanReport): string {
  const lines: string[] = [];
  lines.push(`# 🛰️ SecTool Scan-Shape / Reconnaissance-Pattern Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** each source's host breadth (distinct \`dstIp\`) × port breadth (distinct destination ports ` +
      `re-parsed from the raw line) classified against thresholds (≥${m.hostThreshold} hosts = "many hosts", ` +
      `≥${m.portThreshold} ports = "many ports"), ranked by total breadth · ` +
      `**Sourced alerts:** ${m.sourcedAlerts} of ${m.totalWindowAlerts} (${m.portBearingAlerts} carried a port)`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.sources.length) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but none had a usable source IP and ` +
          `enough volume to analyse a probe shape (min ${DEFAULT_MIN_ALERTS} alerts/source by default).`,
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

  lines.push(`## Scanning sources by reconnaissance reach`);
  lines.push("");
  lines.push(sourceTable(m.sources));
  lines.push("");
  lines.push(
    `**Legend:** _Shape_ — **↔ horizontal** (few ports, many hosts: hunting one service everywhere) · ` +
      `**↕ vertical** (many ports, few hosts: enumerating one target) · **▦ sweep** (many of both: full recon) · ` +
      `**• targeted** (narrow: exploitation or noise, not recon-shaped). Ranked by host + port breadth — for a recon ` +
      `report reach is the signal, so a loud low-severity sweep ranks above a quiet exploit. _Pass rate_ = share of ` +
      `*actioned* alerts let through. **Flags:** 🏠 internal source · ⛔ blocked · 👁 watched · ✅ safe · ⚠️ probed a ` +
      `high-risk admin/data-store port.`,
  );
  lines.push("");

  lines.push(`## Most-hunted services`);
  lines.push("");
  if (!m.probedServices.length) {
    lines.push(
      `_No destination port could be recovered from any sourced alert this window_, so the service most scanners are ` +
        `after can't be ranked. The per-source host breadth above is unaffected.`,
    );
  } else {
    lines.push(
      `Destination ports ranked by how many *distinct sources* are probing them — the single service the most ` +
        `attackers are converging on is the highest-value thing to close at the edge.`,
    );
    lines.push("");
    lines.push(serviceTable(m.probedServices));
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Probe **shape** is a heuristic over the host/port breadth thresholds — the raw ` +
      `counts are shown so the call can be second-guessed. Destination **ports are re-parsed from each alert's raw ` +
      `line**, not stored columns, so port breadth (and the horizontal/vertical split that leans on it) is a lower ` +
      `bound when alerts omit the flow tuple; host breadth uses the stored \`dstIp\` and is unaffected. These are IPS ` +
      `**detections**, not full flows — a port probed without tripping a rule is invisible, so a surgical scanner can ` +
      `read as "targeted". A long look-back can hit the store's history cap and undercount breadth. No live gateway ` +
      `query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the scan-shape / reconnaissance-pattern report from the stored alert
 * history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link ScanOptions}: `limit`, `hostThreshold`, `portThreshold`,
 *              `minAlerts`, and a `nowMs` pin for deterministic tests.
 */
export function buildScan(hours: number, opts: ScanOptions = {}): ScanReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const hostThreshold = Math.max(1, Math.floor(opts.hostThreshold ?? DEFAULT_HOST_THRESHOLD));
  const portThreshold = Math.max(1, Math.floor(opts.portThreshold ?? DEFAULT_PORT_THRESHOLD));
  const minAlerts = Math.max(1, Math.floor(opts.minAlerts ?? DEFAULT_MIN_ALERTS));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const sources = new Map<string, SourceAcc>();
  const services = new Map<number, ServiceAcc>();
  let sourced = 0;
  let portBearing = 0;

  for (const a of windowed) {
    const src = validIp(a.srcIp);
    if (!src) continue;
    sourced++;

    const acc = sources.get(src) ?? newSourceAcc();
    if (!sources.has(src)) sources.set(src, acc);
    acc.count++;
    acc.score += weightOf(a.severity);
    acc.severityMax = maxSeverity(acc.severityMax, a.severity);
    if (isSevere(a.severity)) acc.severe++;

    const dst = validIp(a.dstIp);
    if (dst) {
      acc.hosts.add(dst);
      if (isPrivate(dst)) acc.internalHosts.add(dst);
      else acc.externalHosts.add(dst);
      acc.hostCounts.set(dst, (acc.hostCounts.get(dst) ?? 0) + 1);
    }

    const flow = recoverFlow(a.raw);
    if (flow) {
      portBearing++;
      acc.portBearing++;
      const port = flow.dstPort;
      acc.ports.add(port);
      if (HIGH_RISK_PORTS.has(port)) acc.highRiskPorts.add(port);
      acc.portCounts.set(port, (acc.portCounts.get(port) ?? 0) + 1);

      const svc = services.get(port) ?? newServiceAcc();
      if (!services.has(port)) services.set(port, svc);
      svc.scanners.add(src);
      if (dst) svc.hosts.add(dst);
      svc.count++;
    }

    const disp = classifyDisposition(a.action);
    if (disp === "blocked") acc.blocked++;
    else if (disp === "passed") acc.passed++;
    else acc.unknown++;
  }

  const shapeCounts: ShapeCounts = { horizontal: 0, vertical: 0, sweep: 0, targeted: 0 };

  const sourceList: ScanSource[] = [...sources.entries()]
    .filter(([, acc]) => acc.count >= minAlerts)
    .map(([ip, acc]) => {
      const distinctHosts = acc.hosts.size;
      const distinctPorts = acc.ports.size;
      const shape = classifyShape(distinctHosts, distinctPorts, hostThreshold, portThreshold);
      shapeCounts[shape]++;
      const actioned = acc.blocked + acc.passed;
      const topHost = topOf(acc.hostCounts);
      const topPort = topOf(
        new Map([...acc.portCounts].map(([p, c]) => [String(p), c] as [string, number])),
      );
      const topPortNum = topPort.key !== undefined ? Number(topPort.key) : undefined;
      return {
        ip,
        internal: isPrivate(ip),
        shape,
        distinctHosts,
        distinctPorts,
        breadth: distinctHosts + distinctPorts,
        count: acc.count,
        portBearing: acc.portBearing,
        severe: acc.severe,
        score: acc.score,
        internalTargets: acc.internalHosts.size,
        externalTargets: acc.externalHosts.size,
        highRiskPorts: acc.highRiskPorts.size,
        disposition: {
          blocked: acc.blocked,
          passed: acc.passed,
          unknown: acc.unknown,
          passRate: actioned ? round4(acc.passed / actioned) : null,
        },
        topPort: topPortNum,
        topPortService: topPortNum !== undefined ? SERVICE_NAMES[topPortNum] : undefined,
        topHost: topHost.key,
        severityMax: acc.severityMax,
        blocked: blockStore.has(ip),
        watched: watchStore.has(ip),
        safe: safeStore.has(ip),
      } satisfies ScanSource;
    })
    // Broadest reach first: total breadth, then alert volume, then severity score.
    .sort(
      (x, y) =>
        y.breadth - x.breadth ||
        y.count - x.count ||
        y.score - x.score ||
        (x.ip < y.ip ? -1 : x.ip > y.ip ? 1 : 0),
    );

  // shapeCounts is accumulated across *all* qualifying sources above; the table
  // is then capped to `limit` rows for display without disturbing the totals.
  const cappedSources = sourceList.slice(0, limit);

  const probedServices: ProbedService[] = [...services.entries()]
    .map(([port, svc]) => ({
      port,
      service: SERVICE_NAMES[port],
      highRisk: HIGH_RISK_PORTS.has(port),
      distinctScanners: svc.scanners.size,
      distinctHosts: svc.hosts.size,
      count: svc.count,
    }))
    // Most-hunted first: distinct scanners, then hosts probed, then volume.
    .sort(
      (x, y) =>
        y.distinctScanners - x.distinctScanners ||
        y.distinctHosts - x.distinctHosts ||
        y.count - x.count ||
        x.port - y.port,
    )
    .slice(0, limit);

  const highlights = writeHighlights(
    safeHours,
    { distinctSources: sourceList.length, portBearingAlerts: portBearing, sourcedAlerts: sourced },
    shapeCounts,
    cappedSources,
    probedServices,
  );

  const model: ScanReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    sourcedAlerts: sourced,
    portBearingAlerts: portBearing,
    hostThreshold,
    portThreshold,
    distinctSources: sourceList.length,
    shapeCounts,
    sources: cappedSources,
    probedServices,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded scan-shape report. */
export function scanFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-scan-${stamp}.md`;
}
