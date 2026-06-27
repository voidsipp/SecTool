/**
 * Attack-surface-by-service-class report — "stop reading 200 individual ports and
 * tell me which *kinds* of service my attackers are going after — remote-access,
 * databases, file-shares, ICS/IoT — and which of those crown-jewel classes are
 * still being *let through*."
 *
 * Every destination-oriented report SecTool ships pivots on a *single concrete
 * endpoint*: ports.ts ranks individual destination ports (3389, 445, 3306 …),
 * assets.ts / targets.ts rank individual internal hosts, scan.ts classifies a
 * single source's probe *shape*. All of them are one level too low for the
 * question a defender actually briefs upward:
 *
 *   **"What is being attacked — in terms a risk owner understands?"**
 *
 * "Port 3389 is hot" means nothing to a manager; "**remote-access services are
 * the #1 attacked surface and 18% of those alerts were allowed through**" is a
 * decision. This report rolls the raw destination ports up into a curated set of
 * **service classes** — Remote Access, Web, Database, File Sharing, Mail,
 * Directory/Auth, VPN, Network/Infra, ICS/IoT/Camera, Proxy/Anonymiser, and a
 * Known-Bad/Exploit bucket — so 22+23+3389+5900 collapse into one "Remote Access"
 * row, and the analyst sees the *category* distribution at a glance.
 *
 * Two things this view captures that no per-port report can:
 *
 *   - **ICMP / layer-3 traffic.** Every other destination report keys off a
 *     destination *port* and therefore silently drops ICMP entirely — yet a flood
 *     of ICMP echo/redirect is classic host-discovery recon. Here ICMP is a
 *     first-class service class, so that reconnaissance is finally visible.
 *   - **"Should-never-be-exposed" exposure.** Several classes (remote-access,
 *     database, file-share, directory, ICS/IoT, exploit) should never be reachable
 *     from the internet. The report flags every such class whose alerts the
 *     gateway *let through* (passed, not blocked) and lifts the specific exposed
 *     services into a second, close-these-first worklist.
 *
 * For every windowed alert this report recovers the destination port + transport
 * protocol from the raw line (reusing ports.ts's `recoverFlow`, so it understands
 * exactly the same Suricata flow-tuple and JSON shapes), maps the port to a
 * service class (ICMP is classed by protocol, port-less), and per class computes:
 *
 *   - **alert volume** and its **share** of the classed stream;
 *   - a **severity-weighted score** and the count of medium-or-worse alerts;
 *   - **distinct attacking sources** and **distinct internal targets** hit;
 *   - the **blocked / passed / unknown** enforcement split and the resulting
 *     **pass rate** (share of *actioned* alerts let through);
 *   - the **top individual ports** inside the class and the **top signature**.
 *
 * Classes are ranked by severity-weighted score so the most dangerous surface
 * floats to the top, and high-value classes carrying *passed* traffic are called
 * out as exposure.
 *
 * Honest caveats baked into the output:
 *
 *   - **Ports are re-parsed, not stored.** Only alerts whose raw line still carries
 *     a flow tuple or a `dest_port` field can be classed; the unparsed count is
 *     shown so a thin sample is visible rather than mistaken for "quiet".
 *   - **Class membership is heuristic.** A port maps to the service it *usually*
 *     carries; a box running something unusual on 8080 is filed under Web. The
 *     per-class top-ports column lets the mapping be sanity-checked.
 *   - **Pass ≠ success.** A "passed" alert means the gateway logged but did not
 *     drop it, not that the attack worked — it marks *exposure*, the thing to fix.
 *   - **Alerts, not flows.** SecTool stores IPS *detections*, so this is the
 *     surface that *tripped a rule*, a lower bound on what is actually reachable.
 *   - **Window-bounded & store-capped.** A long look-back can hit the store's
 *     history cap and undercount.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network. Output is
 * both a structured model and a ready-to-paste Markdown document, mirroring
 * report.ts, ports.ts, scan.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { recoverFlow, SERVICE_NAMES } from "./ports.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Stable identifier for each service class (used as the model's map key). */
export type ServiceClassId =
  | "remote-access"
  | "web"
  | "database"
  | "file-share"
  | "mail"
  | "directory"
  | "vpn"
  | "netsvc"
  | "ics-iot"
  | "proxy"
  | "exploit"
  | "icmp"
  | "other";

interface ClassMeta {
  /** Human label with a leading emoji that reads at a glance. */
  label: string;
  /**
   * A "should-never-be-exposed-to-the-internet" class — remote admin, data
   * stores, file shares, directory services, industrial/IoT, or outright
   * exploit ports. Passed (let-through) traffic to these is the headline.
   */
  highValue: boolean;
}

/** Display metadata + risk weighting for every service class. */
export const SERVICE_CLASS_META: Record<ServiceClassId, ClassMeta> = {
  "remote-access": { label: "🖥️ Remote Access", highValue: true },
  database: { label: "🗄️ Database / Datastore", highValue: true },
  "file-share": { label: "📁 File Sharing", highValue: true },
  directory: { label: "🔐 Directory / Auth", highValue: true },
  "ics-iot": { label: "🏭 ICS / IoT / Camera", highValue: true },
  exploit: { label: "💣 Known-Bad / Exploit", highValue: true },
  web: { label: "🌐 Web / HTTP", highValue: false },
  mail: { label: "✉️ Mail", highValue: false },
  vpn: { label: "🔒 VPN / Tunnel", highValue: false },
  netsvc: { label: "📡 Network / Infra", highValue: false },
  proxy: { label: "🕳️ Proxy / Anonymiser", highValue: false },
  icmp: { label: "📶 ICMP / L3 recon", highValue: false },
  other: { label: "❔ Other / Uncommon", highValue: false },
};

/**
 * Authoritative destination-port → service-class lookup. Every port appears at
 * most once; anything absent falls through to the "other" class. Kept aligned
 * with ports.ts's SERVICE_NAMES so the per-class top-ports column reads sensibly.
 */
export const PORT_CLASS: Record<number, ServiceClassId> = {
  // Remote administration / remote desktop.
  22: "remote-access", 23: "remote-access", 2222: "remote-access", 3389: "remote-access",
  5900: "remote-access", 5901: "remote-access", 5902: "remote-access", 5903: "remote-access",
  5904: "remote-access", 5905: "remote-access", 5938: "remote-access", 5985: "remote-access",
  5986: "remote-access",
  // Web / HTTP(S) and common alt-HTTP.
  80: "web", 443: "web", 5000: "web", 8000: "web", 8008: "web", 8080: "web", 8081: "web",
  8443: "web", 8888: "web", 9000: "web", 9090: "web",
  // Databases, KV stores, search, app servers exposing data.
  1433: "database", 1434: "database", 1521: "database", 3306: "database", 5432: "database",
  5601: "database", 5984: "database", 6379: "database", 7001: "database", 9200: "database",
  9300: "database", 11211: "database", 27017: "database", 27018: "database", 50000: "database",
  // File sharing / transfer.
  20: "file-share", 21: "file-share", 69: "file-share", 137: "file-share", 138: "file-share",
  139: "file-share", 445: "file-share", 873: "file-share", 2049: "file-share",
  // Mail transport / retrieval.
  25: "mail", 110: "mail", 143: "mail", 465: "mail", 587: "mail", 993: "mail", 995: "mail",
  // Directory / authentication.
  88: "directory", 389: "directory", 464: "directory", 636: "directory",
  // VPN / tunnelling.
  500: "vpn", 1194: "vpn", 1723: "vpn", 4500: "vpn", 51820: "vpn",
  // Network / infrastructure services.
  53: "netsvc", 67: "netsvc", 68: "netsvc", 79: "netsvc", 111: "netsvc", 123: "netsvc",
  135: "netsvc", 161: "netsvc", 162: "netsvc", 179: "netsvc", 514: "netsvc", 515: "netsvc",
  520: "netsvc", 593: "netsvc", 1900: "netsvc",
  // Industrial control / IoT / cameras.
  102: "ics-iot", 502: "ics-iot", 554: "ics-iot", 623: "ics-iot", 1883: "ics-iot",
  5683: "ics-iot", 20000: "ics-iot", 37215: "ics-iot", 37777: "ics-iot", 47808: "ics-iot",
  // Proxies / anonymisers.
  1080: "proxy", 3128: "proxy", 9001: "proxy", 9050: "proxy",
  // Ports synonymous with offensive tooling / classic C2.
  4444: "exploit", 6667: "exploit",
};

/** A destination endpoint contributing to a class, plus its concrete port. */
export interface ServicePortStat {
  /** The destination port (omitted for ICMP, which is port-less). */
  port?: number;
  /** Friendly service name from SERVICE_NAMES, when known. */
  service?: string;
  /** Alerts this exact port absorbed within its class. */
  count: number;
  /** Alerts the gateway let through to this port (the exposure tell). */
  passed: number;
}

/** Per-service-class roll-up over the window. */
export interface ServiceClassStat {
  /** Stable class id (see {@link ServiceClassId}). */
  id: ServiceClassId;
  /** Display label with emoji. */
  label: string;
  /** A should-never-be-exposed class (remote admin, data, file, dir, ICS, exploit). */
  highValue: boolean;
  /** Alerts classed into this service class. */
  count: number;
  /** Share of all *classed* alerts, 0..1 (4dp). */
  share: number;
  /** Severity-weighted score (Σ SEVERITY_WEIGHT). */
  score: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Distinct external/source IPs that hit this class. */
  sources: number;
  /** Distinct internal hosts targeted in this class. */
  targets: number;
  /** Alerts the gateway actively blocked. */
  blocked: number;
  /** Alerts the gateway logged but let through. */
  passed: number;
  /** Alerts with no recorded action. */
  unknown: number;
  /** Share of *actioned* (blocked+passed) alerts let through, 0..1 (4dp), or null. */
  passRate: number | null;
  /** Worst severity seen in this class. */
  severityMax: Severity;
  /** Up to a few busiest concrete ports inside the class. */
  topPorts: ServicePortStat[];
  /** The single most-frequent signature in this class, if any. */
  topSignature?: string;
  /**
   * True when this is a high-value class with at least one *passed* alert — the
   * surface that should be closed at the firewall first.
   */
  exposed: boolean;
}

/** A specific exposed high-value endpoint for the close-these-first worklist. */
export interface ExposedService {
  /** The owning service class label. */
  classLabel: string;
  /** The destination port (omitted for ICMP). */
  port?: number;
  /** Friendly service name, when known. */
  service?: string;
  /** Passed (let-through) alerts to this endpoint. */
  passed: number;
  /** Total alerts (blocked + passed + unknown) to this endpoint. */
  total: number;
  /** Distinct internal hosts behind this endpoint. */
  targets: number;
}

export interface ServicesReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts mapped to a service class (port recovered, or ICMP). */
  classedAlerts: number;
  /** Of those, alerts whose raw line carried no recoverable port and weren't ICMP. */
  unparsedAlerts: number;
  /** Distinct service classes seen. */
  distinctClasses: number;
  /** Per-class rows, most-dangerous (severity-weighted) first. */
  classes: ServiceClassStat[];
  /** Should-never-be-exposed endpoints carrying passed traffic, busiest first. */
  exposedServices: ExposedService[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface ServicesOptions {
  /** Max rows in the per-class top-ports column / exposed-service worklist (clamped [1,200]). */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const MS_PER_HOUR = 3_600_000;
/** How many concrete ports to surface per class row. */
const TOP_PORTS_PER_CLASS = 4;

// ----- classifiers / helpers (mirror ports.ts / srcport.ts) -----------------

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

/** True when a recovered flow protocol denotes ICMP (v4 or v6). */
function isIcmpProto(proto: string | undefined): boolean {
  if (!proto) return false;
  const p = proto.toUpperCase();
  return p === "ICMP" || p === "ICMP6" || p === "ICMPV6" || p === "IPV6-ICMP";
}

/** Map a recovered destination port to its service class, defaulting to "other". */
export function classifyPort(port: number): ServiceClassId {
  return PORT_CLASS[port] ?? "other";
}

/** Display label for a port: "3389 (RDP)" or just "51000". */
function portLabel(port: number | undefined, service: string | undefined): string {
  if (port === undefined) return "—";
  return service ? `${port} (${service})` : String(port);
}

/** "3389 (RDP)·112, 22 (SSH)·40" — compact top-ports cell for a class row. */
function topPortsCell(ports: ServicePortStat[]): string {
  if (!ports.length) return "—";
  return ports.map((p) => `${portLabel(p.port, p.service)}·${p.count}`).join(", ");
}

// ----- aggregation ----------------------------------------------------------

interface ClassAcc {
  count: number;
  score: number;
  severe: number;
  blocked: number;
  passed: number;
  unknown: number;
  sources: Set<string>;
  targets: Set<string>;
  severityMax: Severity;
  /** port → { count, passed } within this class. */
  portCounts: Map<number, { count: number; passed: number; targets: Set<string> }>;
  sigCounts: Map<string, number>;
}

function newClassAcc(): ClassAcc {
  return {
    count: 0,
    score: 0,
    severe: 0,
    blocked: 0,
    passed: 0,
    unknown: 0,
    sources: new Set(),
    targets: new Set(),
    severityMax: "info",
    portCounts: new Map(),
    sigCounts: new Map(),
  };
}

/** The most-frequent key in a count map, ties broken alphabetically. */
function topKey(counts: Map<string, number>): string | undefined {
  let key: string | undefined;
  let n = -1;
  for (const [k, c] of counts) {
    if (c > n || (c === n && key !== undefined && k < key)) {
      key = k;
      n = c;
    }
  }
  return key;
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  m: { classedAlerts: number; unparsedAlerts: number; totalWindowAlerts: number },
  classes: ServiceClassStat[],
  exposed: ExposedService[],
): string[] {
  const out: string[] = [];
  if (!classes.length) return out;

  // The dominant attacked surface.
  const top = classes[0]!;
  out.push(
    `🎯 Over the last ${hours}h, **${m.classedAlerts} classed alert(s)** span **${classes.length} service ` +
      `class(es)**; the busiest by weighted risk is **${top.label}** — ${top.count} alert(s) ` +
      `(${pct(top.share)} of the classed stream) from ${top.sources} source(s) against ${top.targets} ` +
      `internal host(s).`,
  );

  // The headline: a should-never-be-exposed class being let through.
  const exposedClasses = classes
    .filter((c) => c.exposed)
    .sort((a, b) => (b.passRate ?? 0) - (a.passRate ?? 0) || b.passed - a.passed);
  if (exposedClasses.length) {
    const e = exposedClasses[0]!;
    out.push(
      `🚨 **Exposure:** ${e.label} is a should-never-be-internet-facing class, yet ` +
        `**${e.passed} of its alert(s) were *let through*** (pass rate ` +
        `${e.passRate === null ? "n/a" : pct(e.passRate)}). Close this surface at the firewall before anything else.`,
    );
  } else {
    const hv = classes.filter((c) => c.highValue);
    if (hv.length) {
      out.push(
        `🛡️ All ${hv.length} high-value class(es) under attack this window were **fully blocked** — no ` +
          `remote-access, database, file-share, directory or ICS/IoT traffic was let through. Good posture; keep it.`,
      );
    }
  }

  // The single worst exposed endpoint to close first.
  if (exposed.length) {
    const x = exposed[0]!;
    out.push(
      `🔓 Close-first: **${x.classLabel} → ${portLabel(x.port, x.service)}** let **${x.passed} alert(s)** through ` +
        `to ${x.targets} internal host(s). This is the most-passed high-value endpoint in the window.`,
    );
  }

  // ICMP / layer-3 recon that every port-pivoted report misses.
  const icmp = classes.find((c) => c.id === "icmp");
  if (icmp && icmp.count > 0) {
    out.push(
      `📶 **${icmp.count} ICMP alert(s)** from ${icmp.sources} source(s) — layer-3 host-discovery / ping-sweep ` +
        `recon that every port-based report drops. Often the opening move before a targeted scan.`,
    );
  }

  // Outright exploit / C2 ports — unambiguously malicious intent.
  const exploit = classes.find((c) => c.id === "exploit");
  if (exploit && exploit.count > 0) {
    out.push(
      `💣 **${exploit.count} alert(s)** targeted known offensive-tooling / C2 ports (${topPortsCell(exploit.topPorts)}) ` +
        `— treat the sources as hostile regardless of volume.`,
    );
  }

  // Parse-coverage honesty.
  if (m.totalWindowAlerts > 0) {
    const frac = m.classedAlerts / m.totalWindowAlerts;
    if (frac < 0.5) {
      out.push(
        `ℹ️ Only **${pct(frac)} of windowed alerts carried a recoverable port (or were ICMP)** — every figure here ` +
          `is a lower bound drawn from that sample; ${m.unparsedAlerts} alert(s) could not be classed.`,
      );
    }
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function classTable(rows: ServiceClassStat[]): string {
  return mdTable(
    ["#", "Service class", "Alerts", "Share", "Score", "Severe", "Sources", "Targets", "Blocked", "Passed", "Pass rate", "Top ports", "Top signature", "Flags"],
    rows.map((c, i) => {
      const flags = (c.highValue ? "💎" : "") + (c.exposed ? "🔓" : c.highValue ? "🛡️" : "");
      return [
        String(i + 1),
        cell(c.label),
        String(c.count),
        pct(c.share),
        c.score.toFixed(1),
        String(c.severe),
        String(c.sources),
        String(c.targets),
        String(c.blocked),
        String(c.passed),
        c.passRate === null ? "—" : pct(c.passRate),
        cell(topPortsCell(c.topPorts)),
        cell(c.topSignature ?? "—"),
        flags || "—",
      ];
    }),
  );
}

function exposedTable(rows: ExposedService[]): string {
  return mdTable(
    ["#", "Service class", "Endpoint", "Passed", "Total", "Targets"],
    rows.map((x, i) => [
      String(i + 1),
      cell(x.classLabel),
      cell(portLabel(x.port, x.service)),
      String(x.passed),
      String(x.total),
      String(x.targets),
    ]),
  );
}

function renderMarkdown(m: ServicesReport): string {
  const lines: string[] = [];
  lines.push(`# 🎯 SecTool Attack-Surface-by-Service-Class Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** each alert's destination port + protocol re-parsed from the raw line, rolled up into curated ` +
      `service classes (ICMP classed by protocol) and ranked by severity-weighted score · ` +
      `**Classed alerts:** ${m.classedAlerts} of ${m.totalWindowAlerts} (${m.unparsedAlerts} had no recoverable port)`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.classes.length) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but **none carried a recoverable ` +
          `destination port** (no flow tuple or \`dest_port\` field survived in the raw line) and none were ICMP, ` +
          `so no service-class surface can be computed.`,
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

  lines.push(`## Attacked service classes`);
  lines.push("");
  lines.push(classTable(m.classes));
  lines.push("");
  lines.push(
    `**Legend:** _Score_ is the severity-weighted alert total. _Pass rate_ = share of *actioned* (blocked+passed) ` +
      `alerts the gateway let through. _Top ports_ are the busiest concrete ports inside the class (\`port·alerts\`). ` +
      `**Flags:** 💎 high-value (should never be internet-facing) · 🔓 **exposed** (high-value *and* passed traffic — ` +
      `fix first) · 🛡️ high-value but fully blocked.`,
  );
  lines.push("");

  lines.push(`## Exposed high-value services (close these first)`);
  lines.push("");
  if (!m.exposedServices.length) {
    lines.push(
      `_No should-never-be-exposed endpoint had any *passed* (let-through) traffic this window_ — every ` +
        `high-value service that was attacked was blocked at the gateway. Nothing to close here.`,
    );
  } else {
    lines.push(
      `Concrete endpoints in a high-value class that the gateway **let through** (logged but did not drop). Each is a ` +
        `live exposure: confirm the service should be internet-reachable, and if not, close it at the firewall.`,
    );
    lines.push("");
    lines.push(exposedTable(m.exposedServices));
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Destination **ports are re-parsed from each alert's raw line**, not stored ` +
      `columns, so figures are a lower bound drawn from alerts that still carried a flow tuple or \`dest_port\` field ` +
      `(${m.unparsedAlerts} could not be classed). **Class membership is heuristic** — a port maps to the service it ` +
      `*usually* carries; the per-class top-ports column lets the mapping be sanity-checked. A **passed** alert marks ` +
      `*exposure* (the gateway logged but did not drop it), not a successful breach. These are IPS **detections**, not ` +
      `full flows, so this is the surface that tripped a rule — a lower bound on what is reachable. A long look-back ` +
      `can hit the store's history cap and undercount. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the attack-surface-by-service-class report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link ServicesOptions}: `limit` and a `nowMs` pin for tests.
 */
export function buildServices(hours: number, opts: ServicesOptions = {}): ServicesReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const classes = new Map<ServiceClassId, ClassAcc>();
  let classed = 0;
  let unparsed = 0;

  for (const a of windowed) {
    const flow = recoverFlow(a.raw);
    let id: ServiceClassId | undefined;
    let port: number | undefined;

    if (flow) {
      port = flow.dstPort;
      id = classifyPort(flow.dstPort);
    } else {
      // No destination port — the only thing we can still class is ICMP, whose
      // protocol survives even though it is port-less. Recover it from the raw
      // flow token directly so layer-3 recon is not silently dropped.
      const proto = /\{(\w+)\}/.exec(a.raw ?? "")?.[1];
      if (isIcmpProto(proto)) id = "icmp";
    }

    if (!id) {
      unparsed++;
      continue;
    }
    classed++;

    const acc = classes.get(id) ?? newClassAcc();
    if (!classes.has(id)) classes.set(id, acc);

    acc.count++;
    acc.score += weightOf(a.severity);
    acc.severityMax = maxSeverity(acc.severityMax, a.severity);
    if (isSevere(a.severity)) acc.severe++;

    const src = validIp(a.srcIp);
    if (src) acc.sources.add(src);
    const dst = validIp(a.dstIp);
    if (dst && isPrivate(dst)) acc.targets.add(dst);

    const disp = classifyDisposition(a.action);
    if (disp === "blocked") acc.blocked++;
    else if (disp === "passed") acc.passed++;
    else acc.unknown++;

    if (a.signature) acc.sigCounts.set(a.signature, (acc.sigCounts.get(a.signature) ?? 0) + 1);

    if (port !== undefined) {
      const pc = acc.portCounts.get(port) ?? { count: 0, passed: 0, targets: new Set<string>() };
      if (!acc.portCounts.has(port)) acc.portCounts.set(port, pc);
      pc.count++;
      if (disp === "passed") pc.passed++;
      if (dst && isPrivate(dst)) pc.targets.add(dst);
    }
  }

  const classList: ServiceClassStat[] = [...classes.entries()]
    .map(([id, acc]) => {
      const meta = SERVICE_CLASS_META[id];
      const actioned = acc.blocked + acc.passed;
      const topPorts: ServicePortStat[] = [...acc.portCounts.entries()]
        .sort((a, b) => b[1].count - a[1].count || a[0] - b[0])
        .slice(0, TOP_PORTS_PER_CLASS)
        .map(([port, pc]) => ({
          port,
          service: SERVICE_NAMES[port],
          count: pc.count,
          passed: pc.passed,
        }));
      return {
        id,
        label: meta.label,
        highValue: meta.highValue,
        count: acc.count,
        share: 0, // filled once the classed total is known
        score: round4(acc.score),
        severe: acc.severe,
        sources: acc.sources.size,
        targets: acc.targets.size,
        blocked: acc.blocked,
        passed: acc.passed,
        unknown: acc.unknown,
        passRate: actioned ? round4(acc.passed / actioned) : null,
        severityMax: acc.severityMax,
        topPorts,
        topSignature: topKey(acc.sigCounts),
        exposed: meta.highValue && acc.passed > 0,
      } satisfies ServiceClassStat;
    })
    .map((c) => ({ ...c, share: classed > 0 ? round4(c.count / classed) : 0 }))
    // Most dangerous first: weighted score, then raw volume, then label for stability.
    .sort(
      (x, y) =>
        y.score - x.score ||
        y.count - x.count ||
        (x.label < y.label ? -1 : x.label > y.label ? 1 : 0),
    );

  // Close-these-first worklist: every concrete high-value endpoint with passed
  // (let-through) traffic, busiest-passed first.
  const exposedServices: ExposedService[] = [];
  for (const [id, acc] of classes) {
    const meta = SERVICE_CLASS_META[id];
    if (!meta.highValue) continue;
    for (const [port, pc] of acc.portCounts) {
      if (pc.passed <= 0) continue;
      exposedServices.push({
        classLabel: meta.label,
        port,
        service: SERVICE_NAMES[port],
        passed: pc.passed,
        total: pc.count,
        targets: pc.targets.size,
      });
    }
  }
  exposedServices.sort(
    (x, y) => y.passed - x.passed || y.total - x.total || (x.port ?? 0) - (y.port ?? 0),
  );
  const cappedExposed = exposedServices.slice(0, limit);

  // Cap each class row's top-ports column to `limit` is unnecessary (already
  // TOP_PORTS_PER_CLASS); the class list itself is small and shown in full.
  const highlights = writeHighlights(
    safeHours,
    { classedAlerts: classed, unparsedAlerts: unparsed, totalWindowAlerts: windowed.length },
    classList,
    cappedExposed,
  );

  const model: ServicesReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    classedAlerts: classed,
    unparsedAlerts: unparsed,
    distinctClasses: classList.length,
    classes: classList,
    exposedServices: cappedExposed,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded service-class report. */
export function servicesFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-services-${stamp}.md`;
}
