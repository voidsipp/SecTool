/**
 * Service / port-exposure report — "which of my *services* is taking fire, and
 * is anything dangerous reachable from the internet?"
 *
 * Every other offline report in this project pivots on an *entity* (source IP,
 * destination host, source→dest pair, netblock), a *signature* (focus,
 * lifecycle, tuning, cooccurrence), a *time axis* (rhythm, surge, beacon), a
 * *direction* (direction), a *severity magnitude* (risk, escalation), or the
 * *enforcement* split (efficacy). Not one of them asks the question a firewall
 * administrator asks first:
 *
 *   **"Which destination *port / service* is being attacked — and which of my
 *    hosts is exposing it?"**
 *
 * That is the most directly *actionable* axis SecTool's data holds. Knowing that
 * a single external IP is loud tells you who to block; knowing that **port 3389
 * (RDP)** is your busiest attacked service, exposed by one internal host and
 * mostly *let through*, tells you what to *close* — a far more durable fix than
 * chasing individual scanners. Attackers rotate IPs by the thousand; the service
 * they are hunting for stays put.
 *
 * The destination port and protocol are not stored as first-class columns on a
 * {@link StoredAlert} (only the raw line is), so this report **re-parses** them
 * from each alert's `raw` text using the same flow-tuple / JSON shapes the live
 * detector understands (`{TCP} 1.2.3.4:51000 -> 10.0.0.5:3389`, or a Suricata
 * JSON `dest_port`). Alerts whose raw line carries no recoverable destination
 * port are counted separately as *unparsed* and never silently dropped.
 *
 * For each attacked port the report computes, over the window:
 *
 *   - **volume & share** — alerts naming that destination port, and its share of
 *     all port-bearing alerts;
 *   - **service identity** — a well-known-port → service-name mapping (22→SSH,
 *     3389→RDP, 445→SMB, 3306→MySQL …) and the dominant transport protocol;
 *   - **a remote-admin / data-store exposure flag** — ports that should almost
 *     never face the internet (SSH, RDP, SMB, database and KV-store ports, VNC,
 *     ADB …) are called out as the highest-value things to firewall;
 *   - **breadth** — distinct external attackers hitting the port and distinct
 *     internal hosts exposing it;
 *   - **enforcement** — blocked / passed / unknown disposition (reusing
 *     efficacy.ts's `classifyDisposition`) and the resulting pass rate; a high
 *     pass rate on an exposed admin port is the alarm worth the most;
 *   - **severity** — a severe (≥ medium) count and a severity-weighted score
 *     (reusing risk.ts's {@link SEVERITY_WEIGHT}) used for ranking, so a handful
 *     of critical hits outrank a flood of info-level scans;
 *   - **the loudest signature and the loudest attacker** on that port.
 *
 * It then rolls the data up by **internal host**, ranking the hosts that expose
 * the widest set of attacked ports — your largest attack surface — with each
 * host's blocklist / watchlist / safelist membership (mirroring direction.ts /
 * edges.ts / persistence.ts).
 *
 * Honest caveats baked into the output:
 *
 *   - **Ports are re-parsed, not stored.** Only alerts whose raw line still
 *     carries a recoverable flow tuple or `dest_port` contribute; the *unparsed*
 *     count is shown so a low coverage is visible rather than mistaken for "few
 *     ports attacked". A UniFi "Threat Management" notification that never
 *     printed the port is invisible here.
 *   - **Destination port ≠ always the service.** For an *outbound* alert (your
 *     host reaching out) the destination port is the *remote* service, not one
 *     you expose. The report leans on internal-vs-external endpoint status to
 *     separate "attacked service I host" from "remote service my host dialed",
 *     and labels the exposing host only when the destination is internal.
 *   - **Alerts, not flows.** SecTool stores IPS *detections*; a port being
 *     scanned without tripping a rule is invisible. "Not attacked" means "not
 *     *alerted* on", not "not reachable".
 *   - **Window-bounded & store-capped.** A long look-back can hit the store's
 *     history cap and skew the mix.
 *
 * Pure in-memory math over alertStore (plus blocklist / watchlist / safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring report.ts, direction.ts,
 * efficacy.ts, focus.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Blocked / passed / unknown disposition split for a port or host. */
export interface DispositionSplit {
  /** Alerts the gateway actively blocked / dropped. */
  blocked: number;
  /** Alerts the gateway logged but let through (detected / allowed). */
  passed: number;
  /** Alerts with no recorded action (excluded from {@link passRate}). */
  unknown: number;
  /**
   * Fraction of *actioned* (blocked + passed) alerts that were let through,
   * 0..1 (4dp), or null when nothing was actioned. High on an exposed admin
   * port is the alarm: the service was reached and the gateway allowed it.
   */
  passRate: number | null;
}

/** Per-attacked-port metrics over the window. */
export interface PortStat {
  /** The destination port number. */
  port: number;
  /** Well-known service name (e.g. "SSH", "RDP"), or undefined if unmapped. */
  service?: string;
  /** Dominant transport protocol seen on this port (TCP/UDP/…), upper-cased. */
  protocol?: string;
  /**
   * True when this is a remote-admin / data-store / management port that should
   * almost never be reachable from the internet — the highest-value firewall
   * targets (see {@link HIGH_RISK_PORTS}).
   */
  highRisk: boolean;
  /** Alerts naming this destination port. */
  count: number;
  /** count / total port-bearing alerts, 0..1 (4dp). */
  share: number;
  /** Severity-weighted score (Σ SEVERITY_WEIGHT) — the ranking key. */
  score: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Distinct external source IPs attacking this port. */
  distinctAttackers: number;
  /** Distinct internal destination hosts exposing this port. */
  distinctTargets: number;
  /** Blocked / passed / unknown disposition split. */
  disposition: DispositionSplit;
  /** The loudest signature seen on this port, or undefined. */
  topSignature?: string;
  /** The loudest external attacker of this port, or undefined. */
  topAttacker?: string;
  /** Worst severity seen on this port. */
  severityMax: Severity;
}

/** One internal host and the attacked ports it exposes. */
export interface ExposedHost {
  /** The internal host's IP. */
  ip: string;
  /** Distinct attacked destination ports this host exposed (attack surface). */
  distinctPorts: number;
  /** Of {@link distinctPorts}, how many are high-risk admin / data-store ports. */
  highRiskPorts: number;
  /** Total alerts against this host that carried a destination port. */
  total: number;
  /** Those alerts at medium severity or worse. */
  severe: number;
  /** The busiest port on this host, with its service label for context. */
  topPort?: number;
  /** Service name of {@link topPort}, if mapped. */
  topPortService?: string;
  /** Worst severity seen against this host's exposed ports. */
  severityMax: Severity;
  /** The host is on the blocklist. */
  blocked: boolean;
  /** The host is on the watchlist. */
  watched: boolean;
  /** The host is marked safe. */
  safe: boolean;
}

export interface PortsReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts from which a destination port was recovered. */
  portBearingAlerts: number;
  /** Of those, alerts whose raw line carried no recoverable destination port. */
  unparsedAlerts: number;
  /** Distinct attacked destination ports seen. */
  distinctPorts: number;
  /** Per-port stats, highest severity-weighted score first. */
  ports: PortStat[];
  /** Internal hosts exposing the widest attacked-port surface, worst first. */
  exposedHosts: ExposedHost[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface PortsOptions {
  /** Max rows in the per-port table (clamped to [1, 200]). */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const MS_PER_HOUR = 3_600_000;

/**
 * Well-known destination port → service-name map. Deliberately security-skewed:
 * it favours the services that show up in IPS telemetry (remote admin, mail,
 * databases, file shares, IoT) over the long tail of registered ports. Used for
 * the *display* label only — ranking never depends on a port being mapped.
 */
const SERVICE_NAMES: Record<number, string> = {
  20: "FTP-data",
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  67: "DHCP",
  68: "DHCP",
  69: "TFTP",
  79: "Finger",
  80: "HTTP",
  88: "Kerberos",
  110: "POP3",
  111: "RPC",
  123: "NTP",
  135: "MSRPC",
  137: "NetBIOS-ns",
  138: "NetBIOS-dgm",
  139: "NetBIOS-ssn",
  143: "IMAP",
  161: "SNMP",
  162: "SNMP-trap",
  179: "BGP",
  389: "LDAP",
  443: "HTTPS",
  445: "SMB",
  465: "SMTPS",
  500: "IKE/IPsec",
  514: "Syslog",
  515: "LPD",
  520: "RIP",
  587: "SMTP-sub",
  593: "RPC-HTTP",
  623: "IPMI",
  636: "LDAPS",
  873: "rsync",
  993: "IMAPS",
  995: "POP3S",
  1080: "SOCKS",
  1099: "Java-RMI",
  1194: "OpenVPN",
  1433: "MSSQL",
  1434: "MSSQL-mon",
  1521: "Oracle",
  1723: "PPTP",
  1883: "MQTT",
  1900: "SSDP",
  2049: "NFS",
  2222: "SSH-alt",
  2375: "Docker",
  2376: "Docker-TLS",
  3128: "Squid-proxy",
  3306: "MySQL",
  3389: "RDP",
  4444: "Metasploit",
  4500: "IPsec-NAT",
  5000: "UPnP/HTTP",
  5060: "SIP",
  5061: "SIP-TLS",
  5432: "PostgreSQL",
  5555: "ADB",
  5601: "Kibana",
  5900: "VNC",
  5938: "TeamViewer",
  5984: "CouchDB",
  6379: "Redis",
  6443: "Kubernetes-API",
  6667: "IRC",
  7001: "WebLogic",
  8000: "HTTP-alt",
  8008: "HTTP-alt",
  8080: "HTTP-proxy",
  8081: "HTTP-alt",
  8443: "HTTPS-alt",
  8888: "HTTP-alt",
  9000: "HTTP-alt",
  9001: "Tor/Supervisor",
  9090: "HTTP-alt",
  9200: "Elasticsearch",
  9300: "Elasticsearch",
  10000: "Webmin",
  11211: "Memcached",
  27017: "MongoDB",
  27018: "MongoDB",
  50000: "SAP",
};

/**
 * Ports that should almost never be reachable from the internet: remote-admin,
 * remote-desktop, file-share, database / KV-store and device-management
 * services. An attacked high-risk port that is *exposed* and *let through* is
 * the report's headline finding — close it at the firewall.
 */
const HIGH_RISK_PORTS = new Set<number>([
  22, 23, 135, 137, 138, 139, 389, 445, 593, 623, 636, 873, 1099, 1433, 1434,
  1521, 2049, 2222, 2375, 2376, 3306, 3389, 5432, 5555, 5601, 5900, 5984, 6379,
  6443, 7001, 9200, 9300, 10000, 11211, 27017, 27018,
]);

// ----- raw flow-tuple / JSON re-parsing -------------------------------------

// {PROTO} src:port -> dst:port  — mirrors alertDetector.ts's FLOW regex, which
// is the canonical shape we want the destination port (group 5) out of.
const FLOW =
  /\{(\w+)\}\s*([0-9a-fA-F.:]+?)(?::(\d+))?\s*(?:->|<->|<-)\s*([0-9a-fA-F.:]+?)(?::(\d+))?(?:\s|$)/;

/** A recovered destination endpoint: its port and the flow's protocol. */
interface RecoveredFlow {
  dstPort: number;
  protocol?: string;
}

function toPort(v: unknown): number | undefined {
  const n = typeof v === "number" ? v : Number(v);
  return Number.isInteger(n) && n > 0 && n <= 65535 ? n : undefined;
}

/**
 * Re-parse the destination port (and protocol) from a stored alert's raw line,
 * using the same shapes the live detector understands: a Suricata flow tuple,
 * or a JSON payload carrying `dest_port` / `proto`. Returns undefined when no
 * destination port can be recovered — the alert is then counted as *unparsed*.
 */
export function recoverFlow(raw: string | undefined): RecoveredFlow | undefined {
  if (!raw) return undefined;

  // 1) Suricata flow tuple: {TCP} a.b.c.d:51000 -> e.f.g.h:3389
  const flow = FLOW.exec(raw);
  if (flow) {
    const dstPort = flow[5] ? toPort(flow[5]) : undefined;
    if (dstPort !== undefined) {
      return { dstPort, protocol: flow[1] ? flow[1].toUpperCase() : undefined };
    }
  }

  // 2) JSON payload: {"dest_port":3389,"proto":"TCP", ...}
  const start = raw.indexOf("{");
  const end = raw.lastIndexOf("}");
  if (start !== -1 && end > start) {
    try {
      const obj = JSON.parse(raw.slice(start, end + 1)) as Record<string, unknown>;
      if (obj && typeof obj === "object") {
        const dstPort =
          toPort(obj["dest_port"]) ??
          toPort(obj["dst_port"]) ??
          toPort(obj["destport"]) ??
          toPort(obj["destination_port"]);
        if (dstPort !== undefined) {
          const protoRaw = obj["proto"] ?? obj["protocol"];
          const protocol =
            typeof protoRaw === "string" && protoRaw ? protoRaw.toUpperCase() : undefined;
          return { dstPort, protocol };
        }
      }
    } catch {
      // not JSON — fall through
    }
  }

  return undefined;
}

// ----- classifiers / helpers (mirror direction.ts) --------------------------

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

function clip(s: string, max = 38): string {
  const t = s.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

function mdTable(headers: string[], rows: string[][]): string {
  if (!rows.length) return "_None._";
  const head = `| ${headers.join(" | ")} |`;
  const sep = `| ${headers.map(() => "---").join(" | ")} |`;
  const body = rows.map((r) => `| ${r.join(" | ")} |`).join("\n");
  return `${head}\n${sep}\n${body}`;
}

/** Display label for a port: "3389 (RDP)" or just "51000". */
function portLabel(p: PortStat): string {
  return p.service ? `${p.port} (${p.service})` : String(p.port);
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

// ----- aggregation ----------------------------------------------------------

interface PortAcc {
  count: number;
  score: number;
  severe: number;
  attackers: Set<string>;
  targets: Set<string>;
  blocked: number;
  passed: number;
  unknown: number;
  protoCounts: Map<string, number>;
  sigCounts: Map<string, number>;
  attackerCounts: Map<string, number>;
  severityMax: Severity;
}

function newPortAcc(): PortAcc {
  return {
    count: 0,
    score: 0,
    severe: 0,
    attackers: new Set(),
    targets: new Set(),
    blocked: 0,
    passed: 0,
    unknown: 0,
    protoCounts: new Map(),
    sigCounts: new Map(),
    attackerCounts: new Map(),
    severityMax: "info",
  };
}

interface HostAcc {
  ports: Set<number>;
  highRiskPorts: Set<number>;
  total: number;
  severe: number;
  portCounts: Map<number, number>;
  severityMax: Severity;
}

function newHostAcc(): HostAcc {
  return {
    ports: new Set(),
    highRiskPorts: new Set(),
    total: 0,
    severe: 0,
    portCounts: new Map(),
    severityMax: "info",
  };
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  m: { portBearingAlerts: number; unparsedAlerts: number; distinctPorts: number },
  ports: PortStat[],
  exposedHosts: ExposedHost[],
): string[] {
  const out: string[] = [];
  if (!m.portBearingAlerts) return out;

  // Overall shape — how concentrated the attacked surface is.
  const top = ports[0];
  if (top) {
    out.push(
      `🎯 Over the last ${hours}h, **${m.distinctPorts} distinct destination port(s)** drew alerts across ` +
        `${m.portBearingAlerts} port-bearing detection(s). The busiest is **${portLabel(top)}** ` +
        `(${top.count} alert(s), ${pct(top.share)} of the total) from ${top.distinctAttackers} external attacker(s).`,
    );
  }

  // High-risk exposed ports — the headline firewall finding.
  const risky = ports.filter((p) => p.highRisk && p.distinctTargets > 0);
  if (risky.length) {
    const lead = risky[0]!;
    const passNote =
      lead.disposition.passRate !== null && lead.disposition.passRate > 0
        ? ` and **${pct(lead.disposition.passRate)} of actioned hits were let through** — confirm the exposure and ` +
          `firewall it`
        : " (currently blocked — keep it that way)";
    out.push(
      `🚨 **${risky.length} remote-admin / data-store port(s)** are being attacked while *exposed* by an internal ` +
        `host — the highest-value things to close. Worst is **${portLabel(lead)}** on ${lead.distinctTargets} ` +
        `internal host(s)${passNote}. These services should almost never face the internet.`,
    );
  } else {
    out.push(
      `✅ No high-risk remote-admin / data-store port (SSH, RDP, SMB, database, VNC …) was attacked while exposed ` +
        `by an internal host this window — the attack surface that matters most is quiet.`,
    );
  }

  // Pass-rate alarm across all ports — a service reached and allowed through.
  const leakiest = ports
    .filter((p) => p.disposition.passRate !== null && p.disposition.passed >= 3)
    .sort((a, b) => (b.disposition.passRate ?? 0) - (a.disposition.passRate ?? 0))[0];
  if (leakiest && (leakiest.disposition.passRate ?? 0) >= 0.5) {
    out.push(
      `⚠️ Port **${portLabel(leakiest)}** has a **${pct(leakiest.disposition.passRate!)} pass rate** ` +
        `(${leakiest.disposition.passed} of its actioned alerts let through). The gateway is detecting attacks on ` +
        `this service but mostly not blocking them — see the efficacy report for the enforcement gap.`,
    );
  }

  // Attack-surface roll-up — which of my hosts expose the most.
  if (exposedHosts.length) {
    const lead = exposedHosts[0]!;
    const flagged = exposedHosts.filter((h) => h.blocked || h.watched).length;
    const note = flagged ? ` ${flagged} already blocked/watched.` : "";
    out.push(
      `🖥️ **${exposedHosts.length} internal host(s)** are exposing attacked ports. Broadest surface is \`${lead.ip}\` ` +
        `(${lead.distinctPorts} attacked port(s)${lead.highRiskPorts ? `, ${lead.highRiskPorts} high-risk` : ""}). ` +
        `Reduce each host to only the ports it must serve.${note}`,
    );
  }

  // Parse-coverage honesty — how much of the stream carried a port at all.
  const total = m.portBearingAlerts + m.unparsedAlerts;
  if (total > 0) {
    const frac = m.portBearingAlerts / total;
    if (frac < 0.5) {
      out.push(
        `ℹ️ Only **${pct(frac)} of windowed alerts carried a recoverable destination port** ` +
          `(${m.unparsedAlerts} had none — e.g. UniFi notifications that never printed the flow tuple). This view ` +
          `covers the port-bearing subset; treat the ranking as a lower bound.`,
      );
    }
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function portTable(ports: PortStat[]): string {
  return mdTable(
    ["#", "Port", "Proto", "Alerts", "Share", "Score", "Severe", "Attackers", "Targets", "Blocked", "Passed", "Pass rate", "Top signature", "Risk"],
    ports.map((p, i) => [
      String(i + 1),
      cell(portLabel(p)),
      cell(p.protocol ?? "—"),
      String(p.count),
      pct(p.share),
      String(p.score),
      String(p.severe),
      String(p.distinctAttackers),
      String(p.distinctTargets),
      String(p.disposition.blocked),
      String(p.disposition.passed),
      p.disposition.passRate === null ? "—" : pct(p.disposition.passRate),
      cell(p.topSignature ? clip(p.topSignature) : "—"),
      p.highRisk ? "⚠️" : "",
    ]),
  );
}

function exposedHostTable(rows: ExposedHost[]): string {
  return mdTable(
    ["#", "Internal host", "Attacked ports", "High-risk", "Alerts", "Severe", "Busiest port", "Peak sev", "Flags"],
    rows.map((h, i) => {
      const flags = (h.blocked ? "⛔" : "") + (h.watched ? "👁" : "") + (h.safe ? "✅" : "");
      const busy =
        h.topPort !== undefined
          ? h.topPortService
            ? `${h.topPort} (${h.topPortService})`
            : String(h.topPort)
          : "—";
      return [
        String(i + 1),
        cell(h.ip),
        String(h.distinctPorts),
        String(h.highRiskPorts),
        String(h.total),
        String(h.severe),
        cell(busy),
        cell(h.severityMax),
        flags || "—",
      ];
    }),
  );
}

function renderMarkdown(m: PortsReport): string {
  const lines: string[] = [];
  lines.push(`# 🔌 SecTool Service / Port-Exposure Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** destination port + protocol re-parsed from each stored alert's raw line ` +
      `(Suricata flow tuple / JSON \`dest_port\`), then ranked by severity-weighted score · ` +
      `**Port-bearing alerts:** ${m.portBearingAlerts} of ${m.totalWindowAlerts} ` +
      `(${m.unparsedAlerts} unparsed)`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.portBearingAlerts) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but **none carried a recoverable ` +
          `destination port** in its raw line (no flow tuple / \`dest_port\`). Port analysis needs the flow detail ` +
          `the live syslog feed provides; UniFi-only notification text often omits it.`,
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

  lines.push(`## Most-attacked services`);
  lines.push("");
  lines.push(portTable(m.ports));
  lines.push("");
  lines.push(
    `**Legend:** _Score_ is the severity-weighted sum (info 1 · low 3 · medium 9 · high 27 · critical 81), the ` +
      `ranking key — a few critical hits outrank a flood of scans. _Attackers_ = distinct external sources; ` +
      `_Targets_ = distinct internal hosts exposing the port. _Pass rate_ = share of *actioned* alerts the gateway ` +
      `let through. **⚠️ Risk** marks a remote-admin / data-store / management port that should almost never face ` +
      `the internet — the highest-value rows to firewall.`,
  );
  lines.push("");

  lines.push(`## Internal hosts by exposed attack surface`);
  lines.push("");
  if (!m.exposedHosts.length) {
    lines.push(
      `_No internal host was the destination of a port-bearing alert this window._ Every recovered destination port ` +
        `belonged to a *remote* service one of your hosts dialed out to (outbound), not a service you expose.`,
    );
  } else {
    lines.push(
      `Internal hosts ranked by the number of distinct attacked ports they expose — your largest attack surface ` +
        `first. A host serving many ports is many doors; reduce each to only what it must serve.`,
    );
    lines.push("");
    lines.push(exposedHostTable(m.exposedHosts));
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Destination ports are **re-parsed from each alert's raw line**, not stored ` +
      `columns — only alerts whose raw text still carried a flow tuple or \`dest_port\` contribute (${m.unparsedAlerts} ` +
      `were unparsed and excluded). A destination port is the *attacked service* only when the destination is one of ` +
      `your hosts; for an outbound alert it is the *remote* service your host dialed, so the exposing-host roll-up ` +
      `counts internal destinations only. These are IPS **detections**, not full flows — a port scanned without ` +
      `tripping a rule is invisible here. A long look-back can hit the store's history cap and skew the mix. No live ` +
      `gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the service / port-exposure report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link PortsOptions}: `limit` (per-port rows) and a `nowMs` pin.
 */
export function buildPorts(hours: number, opts: PortsOptions = {}): PortsReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const ports = new Map<number, PortAcc>();
  const hosts = new Map<string, HostAcc>();
  let portBearing = 0;
  let unparsed = 0;

  for (const a of windowed) {
    const flow = recoverFlow(a.raw);
    if (!flow) {
      unparsed++;
      continue;
    }
    portBearing++;
    const { dstPort, protocol } = flow;

    const src = validIp(a.srcIp);
    const dst = validIp(a.dstIp);
    const dstInternal = dst ? isPrivate(dst) : false;
    const srcExternal = src ? !isPrivate(src) : false;

    const acc = ports.get(dstPort) ?? newPortAcc();
    if (!ports.has(dstPort)) ports.set(dstPort, acc);
    acc.count++;
    acc.score += weightOf(a.severity);
    acc.severityMax = maxSeverity(acc.severityMax, a.severity);
    if (isSevere(a.severity)) acc.severe++;
    if (protocol) acc.protoCounts.set(protocol, (acc.protoCounts.get(protocol) ?? 0) + 1);
    // Attackers are external sources; targets are internal destinations exposing it.
    if (src && srcExternal) {
      acc.attackers.add(src);
      acc.attackerCounts.set(src, (acc.attackerCounts.get(src) ?? 0) + 1);
    }
    if (dst && dstInternal) acc.targets.add(dst);
    const disp = classifyDisposition(a.action);
    if (disp === "blocked") acc.blocked++;
    else if (disp === "passed") acc.passed++;
    else acc.unknown++;
    const sig = a.signature?.trim();
    if (sig) acc.sigCounts.set(sig, (acc.sigCounts.get(sig) ?? 0) + 1);

    // Internal-host attack-surface roll-up: only when the host is the target
    // (destination is internal) — that is a service this host actually exposes.
    if (dst && dstInternal) {
      const h = hosts.get(dst) ?? newHostAcc();
      if (!hosts.has(dst)) hosts.set(dst, h);
      h.total++;
      h.ports.add(dstPort);
      if (HIGH_RISK_PORTS.has(dstPort)) h.highRiskPorts.add(dstPort);
      h.portCounts.set(dstPort, (h.portCounts.get(dstPort) ?? 0) + 1);
      h.severityMax = maxSeverity(h.severityMax, a.severity);
      if (isSevere(a.severity)) h.severe++;
    }
  }

  const portList: PortStat[] = [...ports.entries()]
    .map(([port, acc]) => {
      const actioned = acc.blocked + acc.passed;
      const proto = topOf(acc.protoCounts);
      const sig = topOf(acc.sigCounts);
      const attacker = topOf(acc.attackerCounts);
      return {
        port,
        service: SERVICE_NAMES[port],
        protocol: proto.key,
        highRisk: HIGH_RISK_PORTS.has(port),
        count: acc.count,
        share: portBearing ? round4(acc.count / portBearing) : 0,
        score: acc.score,
        severe: acc.severe,
        distinctAttackers: acc.attackers.size,
        distinctTargets: acc.targets.size,
        disposition: {
          blocked: acc.blocked,
          passed: acc.passed,
          unknown: acc.unknown,
          passRate: actioned ? round4(acc.passed / actioned) : null,
        },
        topSignature: sig.key,
        topAttacker: attacker.key,
        severityMax: acc.severityMax,
      } satisfies PortStat;
    })
    // Worst first: severity-weighted score, then raw volume, then port number.
    .sort((x, y) => y.score - x.score || y.count - x.count || x.port - y.port)
    .slice(0, limit);

  const exposedHosts: ExposedHost[] = [...hosts.entries()]
    .map(([ip, h]) => {
      const top = topOf(
        new Map([...h.portCounts].map(([p, c]) => [String(p), c] as [string, number])),
      );
      const topPort = top.key !== undefined ? Number(top.key) : undefined;
      return {
        ip,
        distinctPorts: h.ports.size,
        highRiskPorts: h.highRiskPorts.size,
        total: h.total,
        severe: h.severe,
        topPort,
        topPortService: topPort !== undefined ? SERVICE_NAMES[topPort] : undefined,
        severityMax: h.severityMax,
        blocked: blockStore.has(ip),
        watched: watchStore.has(ip),
        safe: safeStore.has(ip),
      } satisfies ExposedHost;
    })
    // Broadest surface first: distinct ports, then high-risk ports, then volume.
    .sort(
      (x, y) =>
        y.distinctPorts - x.distinctPorts ||
        y.highRiskPorts - x.highRiskPorts ||
        y.total - x.total ||
        (x.ip < y.ip ? -1 : x.ip > y.ip ? 1 : 0),
    )
    .slice(0, limit);

  const highlights = writeHighlights(
    safeHours,
    { portBearingAlerts: portBearing, unparsedAlerts: unparsed, distinctPorts: ports.size },
    portList,
    exposedHosts,
  );

  const model: PortsReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    portBearingAlerts: portBearing,
    unparsedAlerts: unparsed,
    distinctPorts: ports.size,
    ports: portList,
    exposedHosts,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded service / port-exposure report. */
export function portsFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-ports-${stamp}.md`;
}
