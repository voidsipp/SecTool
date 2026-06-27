/**
 * Port-signature scanner-fingerprint report — "given the *set of ports* a source
 * probed, **what toolkit is it, and what is it hunting for?**"
 *
 * Three existing reports each see one facet of the destination-port axis and
 * none of them name the *intent* behind a port combination:
 *
 *   - **ports.ts** ranks the single destination *port / service* under fire and
 *     which host exposes it. It pivots on the port, never on the attacker, so it
 *     can say "445 is hammered" but not "this source is running the SMB+RDP
 *     lateral-movement playbook".
 *   - **scan.ts** classifies each source's probe *shape* — horizontal (one
 *     service, many hosts) vs vertical (many ports, one host) vs sweep vs
 *     targeted — purely from the *counts* of distinct hosts and ports. It tells
 *     you a source is "vertical, 9 ports on 1 host" but is blind to *which* nine
 *     ports: a database raid (3306·5432·1433·6379·27017) and a web-stack scan
 *     (80·443·8080·8443·8000) look identical to a count.
 *   - **srcport.ts** fingerprints the *source* port (the attacker's own ephemeral
 *     vs fixed stack), not the destination services it is after.
 *
 * The *set* of destination ports a source touches is one of the most diagnostic
 * things an IPS stream holds, because attacker toolkits have characteristic port
 * signatures — telnet + TR-069 + ADB is Mirai-class IoT botnet recruitment;
 * SMB + RDP + WinRM is ransomware lateral movement; MySQL + Postgres + Redis +
 * Mongo is an exposed-database raid. Knowing *which* toolkit is probing changes
 * the response: an IoT-botnet sweep wants firmware/credential hardening on cheap
 * devices, a database raid wants the data-store ports pulled off the internet
 * *now*, a lateral-movement signature *from an internal host* is a live
 * compromise. A bare port count can't make any of those calls.
 *
 * This report folds every windowed alert by source IP, recovers the set of
 * distinct destination ports it probed (via the same {@link recoverFlow} that
 * powers ports.ts / scan.ts), and matches that set against a curated library of
 * known attacker-toolkit **fingerprints** ({@link FINGERPRINTS}) — each a
 * characteristic group of ports with a one-line statement of what it hunts. A
 * source is attributed to the toolkit it best matches (most of the toolkit's
 * ports hit, with ties broken toward the *tighter* signature); a source that
 * probed several ports matching no known toolkit is surfaced as a **novel
 * combination** — possibly new tooling worth a look — and a single-port source
 * is set aside as not fingerprintable.
 *
 * For each attributed source it computes: the matched toolkit and how completely
 * the source covered its signature, distinct-port breadth, alert volume, the
 * severe (≥ medium) count, a severity-weighted score, the blocked-vs-passed
 * disposition split (reusing efficacy.ts's `classifyDisposition`) and resulting
 * pass rate, whether the source is internal (a fingerprinted *internal* host is
 * a compromise tell, not an inbound scanner), high-risk-port involvement, and
 * blocklist / watchlist / safelist membership. A companion **toolkit roll-up**
 * answers the campaign question the per-source table can't: across all sources,
 * which attacker toolkit is most active against you, over how many sources and
 * targets, and how much of it is getting through.
 *
 * Honest caveats baked into the output:
 *
 *   - **Fingerprints are heuristics, and port-sets overlap.** Port 22 belongs to
 *     both the lateral-movement and remote-admin signatures; 8080 to both web
 *     and proxy hunting. Attribution is a *best match* (most toolkit ports hit,
 *     then tightest coverage), so a borderline source can be filed under a
 *     neighbouring toolkit. The matched ports are always shown so the call can
 *     be second-guessed. Treat the toolkit label as a lead, not a verdict.
 *   - **Ports are re-parsed, not stored.** Only alerts whose raw line still
 *     carries a flow tuple or `dest_port` contribute a port; the unparsed share
 *     is shown so a thin port axis is visible rather than mistaken for a narrow
 *     toolkit.
 *   - **Alerts, not flows.** SecTool stores IPS *detections*. A port probed
 *     without tripping a rule is invisible, so a source's port-set is a lower
 *     bound and a surgical, single-service tool can read as not-fingerprintable.
 *   - **Window-bounded & store-capped.** A long look-back can hit the store's
 *     history cap and undercount a slow toolkit's port breadth.
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
import { recoverFlow, SERVICE_NAMES, HIGH_RISK_PORTS } from "./ports.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

// ----- the fingerprint library ----------------------------------------------

/** One curated attacker-toolkit port signature. */
export interface Fingerprint {
  /** Stable machine key (e.g. "ransomware-lateral"). */
  key: string;
  /** Short human label for tables / highlights. */
  label: string;
  /** A glyph that reads the toolkit at a glance. */
  emoji: string;
  /** The characteristic destination ports this toolkit probes. */
  ports: number[];
  /**
   * Minimum distinct ports from {@link ports} a source must hit before it is
   * attributed to this toolkit. Defaults to 2 — a single shared port (e.g. just
   * 445) is too ambiguous to pin on one toolkit.
   */
  min: number;
  /** One-line statement of what the toolkit is hunting / what it implies. */
  intent: string;
}

/**
 * The curated library of attacker-toolkit port signatures. Order is priority:
 * earlier = more specific / higher-concern, and is used only to break exact
 * scoring ties so attribution is deterministic. Port-sets deliberately overlap
 * (22, 445, 8080 … appear in several) — a source is filed under the toolkit it
 * matches *best* (see {@link scoreFingerprint}), not the first it touches.
 *
 * `{set}` below is precomputed in {@link FP_SETS} for O(1) membership tests.
 */
export const FINGERPRINTS: readonly Fingerprint[] = [
  {
    key: "ransomware-lateral",
    label: "SMB/RDP lateral movement",
    emoji: "🧨",
    ports: [445, 139, 135, 3389, 5985, 5986, 593, 22, 5900],
    min: 2,
    intent:
      "Windows file-share + remote-desktop + WinRM enumeration — ransomware foothold / east-west lateral movement.",
  },
  {
    key: "database-raid",
    label: "Exposed-database raid",
    emoji: "🗄️",
    ports: [3306, 5432, 1433, 1434, 1521, 6379, 27017, 27018, 9200, 9300, 11211, 5984, 9042, 5601, 9000],
    min: 2,
    intent: "Hunting internet-exposed databases / KV stores to dump or ransom — pull these off the edge now.",
  },
  {
    key: "iot-botnet",
    label: "IoT-botnet recruitment",
    emoji: "🤖",
    ports: [23, 2323, 7547, 37215, 52869, 5555, 60001, 81, 8081, 9527, 49152],
    min: 2,
    intent: "Telnet / TR-069 / ADB credential & exploit sweep — Mirai-class device-botnet recruitment.",
  },
  {
    key: "voip-fraud",
    label: "VoIP / SIP toll-fraud",
    emoji: "📞",
    ports: [5060, 5061, 5070, 4569],
    min: 2,
    intent: "SIP registrar / PBX enumeration — toll-fraud and call-pumping abuse.",
  },
  {
    key: "mail-harvest",
    label: "Mail-server / relay probing",
    emoji: "✉️",
    ports: [25, 110, 143, 465, 587, 993, 995],
    min: 3,
    intent: "SMTP/IMAP/POP enumeration — open-relay abuse, credential stuffing and mailbox harvesting.",
  },
  {
    key: "cloud-orchestration",
    label: "Container / cloud-API probing",
    emoji: "☁️",
    ports: [2375, 2376, 6443, 10250, 2379, 8001, 4243, 5000, 9000, 8500],
    min: 2,
    intent: "Unauthenticated Docker / Kubernetes / orchestration APIs — cluster takeover & crypto-mining.",
  },
  {
    key: "remote-admin",
    label: "Remote-access / mgmt sweep",
    emoji: "🛠️",
    ports: [22, 2222, 23, 3389, 5900, 5938, 10000, 623, 161, 5985, 1099, 7001],
    min: 3,
    intent: "Broad remote-access and device-management interface sweep — looking for any way in.",
  },
  {
    key: "proxy-hunt",
    label: "Open-proxy / relay hunting",
    emoji: "🕳️",
    ports: [1080, 3128, 8080, 8888, 9001, 4145, 8118, 9050],
    min: 2,
    intent: "Open-proxy / SOCKS / Tor-relay discovery — anonymisation infrastructure for onward abuse.",
  },
  {
    key: "vpn-tunnel",
    label: "VPN / tunnel discovery",
    emoji: "🔒",
    ports: [500, 4500, 1194, 1723, 1701],
    min: 2,
    intent: "IPsec / OpenVPN / PPTP / L2TP endpoint discovery — remote-access surface enumeration.",
  },
  {
    key: "web-recon",
    label: "Web-application recon",
    emoji: "🌐",
    ports: [80, 443, 8080, 8443, 8000, 8008, 8081, 8888, 9090, 5000, 7001, 9000, 3000],
    min: 3,
    intent: "HTTP-stack / web-app reconnaissance across common and alternate web ports.",
  },
  {
    key: "amplification",
    label: "UDP amplification vector",
    emoji: "📡",
    ports: [53, 123, 161, 389, 1900, 11211, 19, 17, 111, 137],
    min: 2,
    intent: "Probing UDP services abusable for reflection/amplification DDoS — DNS, NTP, SSDP, memcached, CLDAP.",
  },
];

/** Precomputed Set per fingerprint for O(1) membership tests, by index. */
const FP_SETS: ReadonlyArray<Set<number>> = FINGERPRINTS.map((f) => new Set(f.ports));

/** Quick label lookup by key (for the roll-up table / highlights). */
const FP_BY_KEY = new Map<string, Fingerprint>(FINGERPRINTS.map((f) => [f.key, f] as [string, Fingerprint]));

/** Synthetic bucket keys for sources that don't match a curated toolkit. */
export const NOVEL_KEY = "novel";
export const SINGLE_KEY = "single";

// ----- types ----------------------------------------------------------------

/** Blocked / passed / unknown disposition split for a source or toolkit. */
export interface DispositionSplit {
  /** Alerts the gateway actively blocked / dropped. */
  blocked: number;
  /** Alerts the gateway logged but let through (detected / allowed). */
  passed: number;
  /** Alerts with no recorded action (excluded from {@link passRate}). */
  unknown: number;
  /**
   * Fraction of *actioned* (blocked + passed) alerts that were let through,
   * 0..1 (4dp), or null when nothing was actioned. High on a dangerous toolkit
   * (lateral / database raid) is the alarm: the playbook is reaching its target.
   */
  passRate: number | null;
}

/** One source attributed to a toolkit fingerprint (or a novel combination). */
export interface FingerprintedSource {
  /** The source IP doing the probing. */
  ip: string;
  /** True when the source is one of our own hosts (RFC1918 / loopback / …). */
  internal: boolean;
  /** Matched toolkit key, or {@link NOVEL_KEY} for an unrecognised multi-port set. */
  fingerprintKey: string;
  /** Human label of the matched toolkit (or "novel combination"). */
  fingerprintLabel: string;
  /** Distinct destination ports recovered for this source. */
  distinctPorts: number;
  /** Of the toolkit's signature ports, how many this source hit (0 for novel). */
  matched: number;
  /** matched / |toolkit.ports| — how completely the signature was covered, 0..1. */
  coverage: number;
  /** The matched ports themselves (sorted), for transparency. */
  matchedPorts: number[];
  /** Total alerts attributed to this source in the window. */
  count: number;
  /** Of {@link count}, alerts from which a destination port was recovered. */
  portBearing: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Severity-weighted score (Σ SEVERITY_WEIGHT) — the ranking key. */
  score: number;
  /** Distinct destination hosts this source touched. */
  distinctHosts: number;
  /** Of {@link distinctPorts}, how many are high-risk admin / data-store ports. */
  highRiskPorts: number;
  /** Blocked / passed / unknown disposition split. */
  disposition: DispositionSplit;
  /** The most-probed destination port for this source, if any was recovered. */
  topPort?: number;
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

/** Campaign-level roll-up for one attacker toolkit across all its sources. */
export interface ToolkitRollup {
  key: string;
  label: string;
  emoji: string;
  intent: string;
  /** Distinct sources attributed to this toolkit. */
  sources: number;
  /** Distinct internal sources (compromise tells) attributed to it. */
  internalSources: number;
  /** Total alerts across those sources. */
  alerts: number;
  /** Distinct destination hosts those sources touched. */
  targets: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Blocked / passed / unknown disposition split across the toolkit. */
  disposition: DispositionSplit;
  /** The single most-probed destination port across the toolkit's sources. */
  topPort?: number;
}

export interface PortSigReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts carrying a valid source IP (the analysable set). */
  sourcedAlerts: number;
  /** Of those, alerts from which a destination port was recovered. */
  portBearingAlerts: number;
  /** Distinct source IPs analysed (met the min-alerts floor). */
  distinctSources: number;
  /** Min distinct toolkit ports a source needed to be attributed. */
  minMatch: number;
  /** Sources attributed to a known toolkit fingerprint. */
  attributedSources: number;
  /** Sources with ≥2 ports matching no known toolkit (possible new tooling). */
  novelSources: number;
  /** Sources that probed only a single port (not fingerprintable). */
  singlePortSources: number;
  /** Per-source rows for attributed sources, most threatening first. */
  sources: FingerprintedSource[];
  /** Novel-combination sources, most threatening first (separate table). */
  novel: FingerprintedSource[];
  /** Per-toolkit campaign roll-up, most active first. */
  toolkits: ToolkitRollup[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface PortSigOptions {
  /** Max rows in the per-source and novel tables (clamped to [1, 200]). */
  limit?: number;
  /** Minimum alerts a source needs before it is analysed (drops one-off noise). */
  minAlerts?: number;
  /** Min distinct toolkit ports to attribute a source (clamped to [1, 6]). */
  minMatch?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const DEFAULT_MIN_ALERTS = 2;
const DEFAULT_MIN_MATCH = 2;
const MS_PER_HOUR = 3_600_000;

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

/** Display label for a port: "3389 (RDP)" or just "51000". */
function portWithService(port: number | undefined): string {
  if (port === undefined) return "—";
  const svc = SERVICE_NAMES[port];
  return svc ? `${port} (${svc})` : String(port);
}

/** Compact list of matched ports for a table cell: "445 · 3389 · 22". */
function portList(ports: number[], max = 6): string {
  if (!ports.length) return "—";
  const shown = ports.slice(0, max).map((p) => String(p));
  if (ports.length > max) shown.push(`+${ports.length - max}`);
  return shown.join(" · ");
}

/**
 * Score one fingerprint against a source's port-set. Returns the count of
 * toolkit ports the source hit (`matched`), the fraction of the toolkit covered
 * (`coverage`), and a combined `score = matched + coverage` that rewards both
 * hitting many of the toolkit's ports *and* covering a tight signature — so a
 * source hitting both SIP ports (2/2) out-ranks one hitting 2 of web-recon's 13.
 */
function scoreFingerprint(
  ports: Set<number>,
  fpPorts: Set<number>,
): { matched: number; coverage: number; score: number; matchedPorts: number[] } {
  const matchedPorts: number[] = [];
  for (const p of ports) if (fpPorts.has(p)) matchedPorts.push(p);
  matchedPorts.sort((a, b) => a - b);
  const matched = matchedPorts.length;
  const coverage = fpPorts.size ? matched / fpPorts.size : 0;
  return { matched, coverage, score: matched + coverage, matchedPorts };
}

/**
 * Attribute a source's port-set to the best-matching toolkit, or null when no
 * toolkit clears its effective threshold (the larger of the toolkit's own `min`
 * and the report-wide `minMatch` floor). Ties on the combined score are broken
 * toward the higher-priority (earlier) fingerprint for determinism.
 */
function bestFingerprint(
  ports: Set<number>,
  minMatch: number,
): {
  fp: Fingerprint;
  matched: number;
  coverage: number;
  matchedPorts: number[];
} | null {
  let best: { fp: Fingerprint; matched: number; coverage: number; score: number; matchedPorts: number[] } | null = null;
  for (let i = 0; i < FINGERPRINTS.length; i++) {
    const fp = FINGERPRINTS[i]!;
    const r = scoreFingerprint(ports, FP_SETS[i]!);
    if (r.matched < Math.max(fp.min, minMatch)) continue;
    if (!best || r.score > best.score) best = { fp, ...r };
  }
  return best ? { fp: best.fp, matched: best.matched, coverage: best.coverage, matchedPorts: best.matchedPorts } : null;
}

// ----- aggregation ----------------------------------------------------------

interface SourceAcc {
  count: number;
  portBearing: number;
  score: number;
  severe: number;
  hosts: Set<string>;
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

interface ToolkitAcc {
  sources: number;
  internalSources: number;
  alerts: number;
  targets: Set<string>;
  severe: number;
  blocked: number;
  passed: number;
  unknown: number;
  portCounts: Map<number, number>;
}

function newToolkitAcc(): ToolkitAcc {
  return {
    sources: 0,
    internalSources: 0,
    alerts: 0,
    targets: new Set(),
    severe: 0,
    blocked: 0,
    passed: 0,
    unknown: 0,
    portCounts: new Map(),
  };
}

function dispositionOf(blocked: number, passed: number, unknown: number): DispositionSplit {
  const actioned = blocked + passed;
  return { blocked, passed, unknown, passRate: actioned ? round4(passed / actioned) : null };
}

function topPortOf(counts: Map<number, number>): number | undefined {
  const t = topOf(new Map([...counts].map(([p, c]) => [String(p), c] as [string, number])));
  return t.key !== undefined ? Number(t.key) : undefined;
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  m: { distinctSources: number; portBearingAlerts: number; sourcedAlerts: number },
  attributed: FingerprintedSource[],
  novel: FingerprintedSource[],
  toolkits: ToolkitRollup[],
): string[] {
  const out: string[] = [];
  if (!attributed.length && !novel.length) return out;

  // Headline: how the analysable sources split across known vs novel vs single.
  const lead = toolkits[0];
  out.push(
    `🔎 Over the last ${hours}h, **${attributed.length} source(s)** matched a known attacker toolkit and ` +
      `**${novel.length}** probed an unrecognised multi-port combination` +
      (lead ? `; the most active toolkit is **${lead.emoji} ${lead.label}** (${lead.sources} source(s), ${lead.alerts} alert(s)).` : "."),
  );

  // The single most threatening fingerprinted source overall.
  if (attributed.length) {
    const s = attributed[0]!;
    out.push(
      `${FP_BY_KEY.get(s.fingerprintKey)?.emoji ?? "🎯"} Top match is \`${s.ip}\`${s.internal ? " *(internal!)*" : ""} → ` +
        `**${s.fingerprintLabel}** (${s.matched} signature port(s), ${pct(s.coverage)} coverage: ${portList(s.matchedPorts)}), ` +
        `${s.count} alert(s), peak ${s.severityMax}.`,
    );
  }

  // Internal hosts wearing an attacker fingerprint — a compromise tell.
  const insiders = attributed.filter((s) => s.internal);
  if (insiders.length) {
    const i = insiders[0]!;
    out.push(
      `🚨 **${insiders.length} *internal* host(s)** match an attacker toolkit — an internal box running the ` +
        `**${i.fingerprintLabel}** playbook is a lateral-movement / compromise tell, not an inbound scan. Investigate ` +
        `\`${i.ip}\` first.`,
    );
  }

  // The most dangerous toolkits, called out specifically when present.
  for (const key of ["ransomware-lateral", "database-raid"]) {
    const t = toolkits.find((x) => x.key === key);
    if (t && t.sources > 0) {
      const leak = t.disposition.passRate;
      out.push(
        `${t.emoji} **${t.label}** is active: ${t.sources} source(s) across ${t.targets} target(s), ${t.alerts} alert(s)` +
          (leak !== null && leak >= 0.5 ? ` — and **${pct(leak)} is being let through**. ${t.intent}` : `. ${t.intent}`),
      );
    }
  }

  // A dangerous toolkit whose probing is mostly passing the gateway.
  const leaky = toolkits
    .filter((t) => t.disposition.passRate !== null && t.disposition.passed >= 3)
    .sort((a, b) => (b.disposition.passRate ?? 0) - (a.disposition.passRate ?? 0))[0];
  if (leaky && (leaky.disposition.passRate ?? 0) >= 0.5 && leaky.key !== "ransomware-lateral" && leaky.key !== "database-raid") {
    out.push(
      `⚠️ **${leaky.label}** probing is **${pct(leaky.disposition.passRate!)} let through** ` +
        `(${leaky.disposition.passed} actioned alerts passed across ${leaky.sources} source(s)) — the toolkit is ` +
        `reaching your services; block the sources and confirm the exposure.`,
    );
  }

  // Novel combinations — possible new tooling worth a human look.
  if (novel.length) {
    const n = novel[0]!;
    out.push(
      `🧪 **${novel.length} source(s)** probed a multi-port combination matching no known toolkit — possible new ` +
        `tooling. Broadest: \`${n.ip}\` hit ${n.distinctPorts} distinct port(s) (top ${portWithService(n.topPort)}). ` +
        `If a pattern recurs, it may deserve its own fingerprint.`,
    );
  }

  // Port-coverage honesty — how much of the stream carried a port at all.
  if (m.sourcedAlerts > 0) {
    const frac = m.portBearingAlerts / m.sourcedAlerts;
    if (frac < 0.5) {
      out.push(
        `ℹ️ Only **${pct(frac)} of sourced alerts carried a recoverable destination port** — toolkit attribution leans ` +
          `on that port-set, so a thin port axis means some sources can't be fingerprinted (counted as single-service), ` +
          `not that they ran no toolkit.`,
      );
    }
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function sourceTable(rows: FingerprintedSource[]): string {
  return mdTable(
    ["#", "Source", "Toolkit", "Match", "Coverage", "Matched ports", "Ports", "Alerts", "Severe", "Top host", "Pass rate", "Flags"],
    rows.map((s, i) => {
      const flags =
        (s.internal ? "🏠" : "") +
        (s.blocked ? "⛔" : "") +
        (s.watched ? "👁" : "") +
        (s.safe ? "✅" : "") +
        (s.highRiskPorts ? "⚠️" : "");
      const emoji = FP_BY_KEY.get(s.fingerprintKey)?.emoji ?? "🎯";
      return [
        String(i + 1),
        cell(s.ip),
        cell(`${emoji} ${s.fingerprintLabel}`),
        `${s.matched}/${FP_BY_KEY.get(s.fingerprintKey)?.ports.length ?? s.matched}`,
        pct(s.coverage),
        cell(portList(s.matchedPorts)),
        String(s.distinctPorts),
        String(s.count),
        String(s.severe),
        cell(s.topHost ?? "—"),
        s.disposition.passRate === null ? "—" : pct(s.disposition.passRate),
        flags || "—",
      ];
    }),
  );
}

function novelTable(rows: FingerprintedSource[]): string {
  return mdTable(
    ["#", "Source", "Ports", "Top port", "Alerts", "Severe", "Top host", "Pass rate", "Flags"],
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
        String(s.distinctPorts),
        cell(portWithService(s.topPort)),
        String(s.count),
        String(s.severe),
        cell(s.topHost ?? "—"),
        s.disposition.passRate === null ? "—" : pct(s.disposition.passRate),
        flags || "—",
      ];
    }),
  );
}

function toolkitTable(rows: ToolkitRollup[]): string {
  return mdTable(
    ["Toolkit", "Sources", "Internal", "Targets", "Alerts", "Severe", "Top port", "Pass rate", "What it hunts"],
    rows.map((t) => [
      cell(`${t.emoji} ${t.label}`),
      String(t.sources),
      String(t.internalSources),
      String(t.targets),
      String(t.alerts),
      String(t.severe),
      cell(portWithService(t.topPort)),
      t.disposition.passRate === null ? "—" : pct(t.disposition.passRate),
      cell(t.intent),
    ]),
  );
}

function renderMarkdown(m: PortSigReport): string {
  const lines: string[] = [];
  lines.push(`# 🔎 SecTool Port-Signature Scanner-Fingerprint Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** each source's set of probed destination ports (re-parsed from the raw line) matched against ${FINGERPRINTS.length} ` +
      `curated attacker-toolkit signatures; a source is attributed to the toolkit it best matches (≥${m.minMatch} signature ` +
      `port(s)) · **Sourced alerts:** ${m.sourcedAlerts} of ${m.totalWindowAlerts} (${m.portBearingAlerts} carried a port)`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.sources.length && !m.novel.length) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    } else if (!m.portBearingAlerts) {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but none carried a recoverable destination ` +
          `port — toolkit fingerprinting needs the flow tuple / \`dest_port\`, so there is nothing to match.`,
      );
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but no source probed enough distinct ports ` +
          `(≥2, min ${DEFAULT_MIN_ALERTS} alerts/source) to fingerprint a toolkit. Single-service probing is reported ` +
          `by the scan-shape and ports reports instead.`,
      );
    }
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  lines.push(
    `Analysed **${m.distinctSources} source(s)**: **${m.attributedSources}** matched a known toolkit, ` +
      `**${m.novelSources}** showed a novel multi-port combination, and ${m.singlePortSources} probed a single ` +
      `service (not fingerprintable).`,
  );
  lines.push("");
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Active attacker toolkits`);
  lines.push("");
  if (!m.toolkits.length) {
    lines.push(`_No source matched a known toolkit signature this window._`);
  } else {
    lines.push(
      `Each curated toolkit ranked by how many distinct sources are running it against you — the campaign view the ` +
        `per-source table can't give. A high pass rate on a dangerous toolkit (lateral movement, database raid) is the ` +
        `finding worth the most.`,
    );
    lines.push("");
    lines.push(toolkitTable(m.toolkits));
  }
  lines.push("");

  lines.push(`## Fingerprinted sources`);
  lines.push("");
  if (!m.sources.length) {
    lines.push(`_No source matched a known toolkit signature this window (see novel combinations below)._`);
  } else {
    lines.push(sourceTable(m.sources));
    lines.push("");
    lines.push(
      `**Legend:** _Toolkit_ — the best-matching attacker playbook. _Match_ — signature ports hit / signature size · ` +
        `_Coverage_ — share of the toolkit's ports the source probed · _Matched ports_ — the specific ports that drove ` +
        `the call · _Ports_ — total distinct ports the source touched · _Pass rate_ — share of *actioned* alerts let ` +
        `through. **Flags:** 🏠 internal source · ⛔ blocked · 👁 watched · ✅ safe · ⚠️ probed a high-risk admin/data-store port.`,
    );
  }
  lines.push("");

  if (m.novel.length) {
    lines.push(`## Novel combinations (no known toolkit)`);
    lines.push("");
    lines.push(
      `Sources that probed several ports but matched no curated signature — possibly new tooling, a bespoke target ` +
        `list, or a toolkit SecTool doesn't yet fingerprint. Worth a human look; a recurring pattern deserves its own ` +
        `entry in the library.`,
    );
    lines.push("");
    lines.push(novelTable(m.novel));
    lines.push("");
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Toolkit attribution is a **heuristic** over curated port-set signatures that ` +
      `deliberately overlap (port 22 is in both lateral-movement and remote-admin; 8080 in web and proxy) — a source is ` +
      `filed under its *best* match and the matched ports are shown so the call can be second-guessed. Destination ` +
      `**ports are re-parsed from each alert's raw line**, not stored columns, so a source's port-set is a lower bound ` +
      `when alerts omit the flow tuple. These are IPS **detections**, not full flows — a port probed without tripping a ` +
      `rule is invisible, so a surgical single-service tool can read as not-fingerprintable. A long look-back can hit ` +
      `the store's history cap and undercount port breadth. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the port-signature scanner-fingerprint report from the stored alert
 * history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link PortSigOptions}: `limit`, `minAlerts`, `minMatch`, and a
 *              `nowMs` pin for deterministic tests.
 */
export function buildPortSig(hours: number, opts: PortSigOptions = {}): PortSigReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minAlerts = Math.max(1, Math.floor(opts.minAlerts ?? DEFAULT_MIN_ALERTS));
  const minMatch = Math.max(1, Math.min(6, Math.floor(opts.minMatch ?? DEFAULT_MIN_MATCH)));
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
    acc.count++;
    acc.score += weightOf(a.severity);
    acc.severityMax = maxSeverity(acc.severityMax, a.severity);
    if (isSevere(a.severity)) acc.severe++;

    const dst = validIp(a.dstIp);
    if (dst) {
      acc.hosts.add(dst);
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
    }

    const disp = classifyDisposition(a.action);
    if (disp === "blocked") acc.blocked++;
    else if (disp === "passed") acc.passed++;
    else acc.unknown++;
  }

  // Build per-source rows, attributing each to a toolkit / novel / single bucket.
  const attributed: FingerprintedSource[] = [];
  const novel: FingerprintedSource[] = [];
  const toolkitAccs = new Map<string, ToolkitAcc>();
  let analysed = 0;
  let singlePort = 0;

  for (const [ip, acc] of sources) {
    if (acc.count < minAlerts) continue;
    analysed++;

    const distinctPorts = acc.ports.size;
    const internal = isPrivate(ip);
    const topHost = topOf(acc.hostCounts).key;
    const topPort = topPortOf(acc.portCounts);

    // A source needs ≥2 distinct ports to carry a multi-port signature at all.
    if (distinctPorts < 2) {
      singlePort++;
      continue;
    }

    const match = bestFingerprint(acc.ports, minMatch);

    const base = {
      ip,
      internal,
      distinctPorts,
      count: acc.count,
      portBearing: acc.portBearing,
      severe: acc.severe,
      score: acc.score,
      distinctHosts: acc.hosts.size,
      highRiskPorts: acc.highRiskPorts.size,
      disposition: dispositionOf(acc.blocked, acc.passed, acc.unknown),
      topPort,
      topHost,
      severityMax: acc.severityMax,
      blocked: blockStore.has(ip),
      watched: watchStore.has(ip),
      safe: safeStore.has(ip),
    };

    if (match) {
      const row: FingerprintedSource = {
        ...base,
        fingerprintKey: match.fp.key,
        fingerprintLabel: match.fp.label,
        matched: match.matched,
        coverage: round4(match.coverage),
        matchedPorts: match.matchedPorts,
      };
      attributed.push(row);

      const tk = toolkitAccs.get(match.fp.key) ?? newToolkitAcc();
      if (!toolkitAccs.has(match.fp.key)) toolkitAccs.set(match.fp.key, tk);
      tk.sources++;
      if (internal) tk.internalSources++;
      tk.alerts += acc.count;
      for (const h of acc.hosts) tk.targets.add(h);
      tk.severe += acc.severe;
      tk.blocked += acc.blocked;
      tk.passed += acc.passed;
      tk.unknown += acc.unknown;
      for (const [p, c] of acc.portCounts) tk.portCounts.set(p, (tk.portCounts.get(p) ?? 0) + c);
    } else {
      novel.push({
        ...base,
        fingerprintKey: NOVEL_KEY,
        fingerprintLabel: "novel combination",
        matched: 0,
        coverage: 0,
        matchedPorts: [],
      });
    }
  }

  // Rank attributed sources by threat: severity-weighted score, then match
  // strength, then volume, then IP for stability.
  const rankSource = (x: FingerprintedSource, y: FingerprintedSource): number =>
    y.score - x.score ||
    y.matched - x.matched ||
    y.count - x.count ||
    (x.ip < y.ip ? -1 : x.ip > y.ip ? 1 : 0);
  attributed.sort(rankSource);
  novel.sort(rankSource);

  // Toolkit roll-up, most active (most sources) first.
  const toolkits: ToolkitRollup[] = [...toolkitAccs.entries()]
    .map(([key, tk]) => {
      const fp = FP_BY_KEY.get(key)!;
      return {
        key,
        label: fp.label,
        emoji: fp.emoji,
        intent: fp.intent,
        sources: tk.sources,
        internalSources: tk.internalSources,
        alerts: tk.alerts,
        targets: tk.targets.size,
        severe: tk.severe,
        disposition: dispositionOf(tk.blocked, tk.passed, tk.unknown),
        topPort: topPortOf(tk.portCounts),
      } satisfies ToolkitRollup;
    })
    .sort(
      (a, b) =>
        b.sources - a.sources ||
        b.alerts - a.alerts ||
        b.severe - a.severe ||
        (a.key < b.key ? -1 : a.key > b.key ? 1 : 0),
    );

  const cappedSources = attributed.slice(0, limit);
  const cappedNovel = novel.slice(0, limit);

  const highlights = writeHighlights(
    safeHours,
    { distinctSources: analysed, portBearingAlerts: portBearing, sourcedAlerts: sourced },
    cappedSources,
    cappedNovel,
    toolkits,
  );

  const model: PortSigReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    sourcedAlerts: sourced,
    portBearingAlerts: portBearing,
    distinctSources: analysed,
    minMatch,
    attributedSources: attributed.length,
    novelSources: novel.length,
    singlePortSources: singlePort,
    sources: cappedSources,
    novel: cappedNovel,
    toolkits,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded port-signature report. */
export function portSigFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-portsig-${stamp}.md`;
}
