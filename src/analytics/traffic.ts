/**
 * Traffic / top-talkers & conversation report — "**who is moving the most bytes,
 * where is it going, and is anything leaving that shouldn't?**"
 *
 * Every other offline report in SecTool pivots on the **alert** stream — IPS
 * *detections* stored in `alertStore`. That stream is signature-driven: it only
 * ever sees what a rule already names. It is structurally blind to the bulk of a
 * network's behaviour — the high-volume, perfectly-allowed conversations that no
 * signature fires on. A host quietly exfiltrating gigabytes over HTTPS, a box
 * fanning out to a thousand external IPs, a service suddenly talking on a port it
 * never used: none of these trip a signature, so none of them appear in any
 * alert-based report. They live in a completely different data source SecTool
 * already collects but has never reported on offline — the **NetFlow / IPFIX flow
 * store** (`data/flows.json`).
 *
 * This is the first offline report to read that flow store. It is the volumetric
 * counterpart to the signature world: instead of "which rule fired", it answers
 * the questions a NOC actually starts a morning with —
 *
 *   - **Top talkers.** Which hosts moved the most bytes (in + out), split by
 *     direction, with their distinct-peer and distinct-port reach. The heaviest
 *     mover is rarely the noisiest *alerter*.
 *   - **Top conversations.** The src→dst pairs carrying the most traffic — the
 *     individual links worth understanding before anything else.
 *   - **Internal-host outbound profile.** For each of *your own* hosts, estimated
 *     bytes sent out, how many distinct external destinations it reached
 *     (**fan-out** — the scan / worm / beacon-spread tell) and how many distinct
 *     destination ports it touched. A quiet workstation suddenly talking to 800
 *     external IPs is the shape of compromise that signatures miss.
 *   - **Destination services.** Which destination ports carry the volume, rolled
 *     to a service name where one is well-known.
 *   - **Direction split & dropped share.** Inbound vs outbound vs lateral vs
 *     transit byte split, plus the fraction of flows the gateway *forwarded as
 *     dropped* (IPFIX `forwardingStatus` ≥ 128) — a coarse enforcement-visibility
 *     read straight from the exporter.
 *
 * **Sampling, made honest.** UniFi / UDM NetFlow is *packet-sampled* (~1:512 by
 * default; `cfg.netflow.samplingRate`). Raw flow byte / packet counts are
 * therefore ~`rate`× *smaller* than reality. Like the behavioral baseliner
 * (`anomaly/baseline.ts`), this report scales sampled volume back up by the
 * sampling rate to an **estimated true volume** before ranking, so the numbers
 * read at the right order of magnitude — and labels every volume figure `~` to
 * keep the estimate honest. Counts that *cannot* be linearly scaled — distinct
 * peers and distinct ports — are left as **conservative lower bounds**: sampling
 * can hide a destination but never invent one, so a reported fan-out of 50 means
 * "at least 50".
 *
 * Other honest caveats baked into the output:
 *
 *   - **Flows are forward-only & gateway-observed.** The exporter reports flows it
 *     forwards; counts are per the gateway's vantage, not an endpoint's.
 *   - **Store-capped & retention-bounded.** The flow store is rotated by count and
 *     age (`cfg.netflow.maxFlows` / `retentionMinutes`), so a long look-back can
 *     silently start mid-history — counts are of what is *retained*.
 *   - **NetFlow is opt-in.** If the collector was never enabled there is no flow
 *     file; the report says so cleanly rather than implying a silent network.
 *
 * Pure in-memory math over the persisted flow file — no SSH, no Claude, no
 * network, no live gateway query. Output is both a structured model and a
 * ready-to-paste Markdown document, mirroring report.ts, rarity.ts, scan.ts and
 * the other offline reports so it plugs into the same CLI and HTTP plumbing.
 */
import { isIP } from "node:net";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { Flow } from "../netflow/ipfix.ts";

/** Where a flow sits relative to our perimeter. */
export type FlowDirection = "inbound" | "outbound" | "internal" | "transit";

/** Whether a host is one of ours or an external peer. */
export type HostRole = "internal" | "external";

/** Byte/packet/flow totals for one slice (a direction, a host, a pair…). */
export interface VolumeTotals {
  /** Flow records in this slice. */
  flows: number;
  /** Sampled bytes as exported (pre-scaling). */
  rawBytes: number;
  /** Estimated true bytes = rawBytes × samplingRate. */
  estBytes: number;
  /** Sampled packets as exported (pre-scaling). */
  rawPackets: number;
  /** Estimated true packets = rawPackets × samplingRate. */
  estPackets: number;
}

/** Per-host traffic rollup (host seen as either endpoint). */
export interface TalkerRow {
  /** The host IP. */
  ip: string;
  /** Internal (one of ours) or external peer. */
  role: HostRole;
  /** Estimated bytes sent by this host (it was the flow source). */
  estBytesOut: number;
  /** Estimated bytes received by this host (it was the flow destination). */
  estBytesIn: number;
  /** Estimated total bytes (out + in) — the ranking key. */
  estBytesTotal: number;
  /** Flow records involving this host. */
  flows: number;
  /** Distinct counterpart IPs (lower bound — sampling can hide peers). */
  distinctPeers: number;
  /** Distinct destination ports this host *initiated* to (lower bound). */
  distinctDstPorts: number;
}

/** One src→dst conversation. */
export interface ConversationRow {
  src: string;
  dst: string;
  direction: FlowDirection;
  totals: VolumeTotals;
  /** Distinct destination ports observed on this link (lower bound). */
  distinctDstPorts: number;
  /** Human label for the dominant transport protocol. */
  protoLabel: string;
  /** The single busiest destination port on this link, if any. */
  topDstPort?: number;
}

/** One destination port / service, by traffic. */
export interface ServiceRow {
  port: number;
  /** Well-known service name, or "port N". */
  service: string;
  protoLabel: string;
  totals: VolumeTotals;
  /** Distinct source hosts that reached this port (lower bound). */
  distinctSources: number;
  /** Distinct destination hosts exposing this port (lower bound). */
  distinctTargets: number;
}

/** Per-internal-host outbound profile — the exfil / scan-spread lens. */
export interface OutboundRow {
  ip: string;
  /** Estimated bytes this host pushed to external peers. */
  estBytesOut: number;
  /** Distinct *external* destinations reached (fan-out, lower bound). */
  distinctExternalPeers: number;
  /** Distinct destination ports reached externally (lower bound). */
  distinctDstPorts: number;
  /** Outbound flow records. */
  flows: number;
}

/** Byte split across the four directions (the headline shape). */
export interface DirectionBreakdown {
  inbound: VolumeTotals;
  outbound: VolumeTotals;
  internal: VolumeTotals;
  transit: VolumeTotals;
}

export interface TrafficReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** The 1:N packet-sampling rate used to scale sampled counts to estimates. */
  samplingRate: number;
  /** True when a flow store file was found on disk (NetFlow was/are collecting). */
  storeAvailable: boolean;
  /** Flows loaded from the store before windowing. */
  totalFlowsLoaded: number;
  /** Flows that fell inside the look-back window (the analysed set). */
  windowFlows: number;
  /** Flows usable for direction math (both endpoints valid IPs). */
  routableFlows: number;
  /** Window-wide volume totals across every analysed flow. */
  totals: VolumeTotals;
  /** Estimated-byte split across the four directions. */
  direction: DirectionBreakdown;
  /** Flows the gateway forwarded as *dropped* (IPFIX fwdStatus ≥ 128). */
  droppedFlows: number;
  /** Dropped flows as a fraction of routable flows, 0..1 (4dp), or null. */
  droppedShare: number | null;
  /** Distinct hosts seen as either endpoint. */
  distinctHosts: number;
  /** Top talkers by estimated total bytes. */
  talkers: TalkerRow[];
  /** Top conversations by estimated bytes. */
  conversations: ConversationRow[];
  /** Top destination services / ports by estimated bytes. */
  services: ServiceRow[];
  /** Internal hosts ranked by outbound fan-out / volume (exfil lens). */
  outbound: OutboundRow[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface TrafficOptions {
  /** Max rows per table (clamped to [1, 200]). */
  limit?: number;
  /** Packet-sampling rate (1:N) to scale sampled counts (clamped to ≥ 1). */
  samplingRate?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
  /** Injects flows directly (for tests); defaults to loading `data/flows.json`. */
  flows?: Flow[];
}

const DEFAULT_LIMIT = 20;
const DEFAULT_SAMPLING_RATE = 512;
const MS_PER_HOUR = 3_600_000;

/** Path to the persisted flow store, resolved relative to this module. */
const FLOWS_PATH = fileURLToPath(new URL("../../data/flows.json", import.meta.url));

// ----- classifiers / helpers (mirror rarity.ts / scan.ts) -------------------

/** RFC1918 / loopback / link-local / ULA — an address treated as one of ours. */
function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
}

/** A valid, non-empty IP, or undefined if the field is missing/garbage. */
function validIp(ip: string | undefined): string | undefined {
  return ip && isIP(ip) !== 0 ? ip : undefined;
}

/** Map an endpoint pair to a perimeter-relative direction. */
function directionOf(src: string, dst: string): FlowDirection {
  const si = isPrivate(src);
  const di = isPrivate(dst);
  if (si && di) return "internal";
  if (si && !di) return "outbound";
  if (!si && di) return "inbound";
  return "transit";
}

/** A flow's representative timestamp (start → end → received). */
function flowTime(f: Flow): number {
  return f.start ?? f.end ?? f.receivedAt;
}

/** Well-known destination ports, kept compact; everything else → "port N". */
const SERVICE_NAMES: Record<number, string> = {
  20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
  67: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPC", 123: "NTP",
  135: "MS-RPC", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
  161: "SNMP", 179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
  514: "Syslog", 587: "SMTP-sub", 593: "MS-RPC", 636: "LDAPS", 993: "IMAPS",
  995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 1883: "MQTT",
  1900: "SSDP", 2049: "NFS", 2222: "SSH-alt", 3128: "Proxy", 3306: "MySQL",
  3389: "RDP", 5060: "SIP", 5061: "SIP-TLS", 5432: "Postgres", 5900: "VNC",
  6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt", 9200: "Elastic",
  11211: "memcached", 27017: "MongoDB",
};

function serviceName(port: number): string {
  return SERVICE_NAMES[port] ?? `port ${port}`;
}

/** Human label for an IP protocol number. */
function protoLabel(proto: number | undefined): string {
  switch (proto) {
    case 1: return "ICMP";
    case 6: return "TCP";
    case 17: return "UDP";
    case 47: return "GRE";
    case 50: return "ESP";
    case 58: return "ICMPv6";
    case undefined: return "—";
    default: return `proto ${proto}`;
  }
}

/** Human-readable byte size (binary units), e.g. "1.4 GB". */
function fmtBytes(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  const s = v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1);
  return `${s} ${units[i]}`;
}

/** Estimated bytes, prefixed "~" to flag the sampling-scaled estimate. */
function estLabel(n: number): string {
  return `~${fmtBytes(n)}`;
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

function dirLabel(d: FlowDirection): string {
  switch (d) {
    case "inbound": return "⬇ inbound";
    case "outbound": return "⬆ outbound";
    case "internal": return "↔ internal";
    case "transit": return "⤳ transit";
  }
}

// ----- accumulators ---------------------------------------------------------

function newTotals(): VolumeTotals {
  return { flows: 0, rawBytes: 0, estBytes: 0, rawPackets: 0, estPackets: 0 };
}

function addTotals(t: VolumeTotals, bytes: number, packets: number, rate: number): void {
  t.flows++;
  t.rawBytes += bytes;
  t.estBytes += bytes * rate;
  t.rawPackets += packets;
  t.estPackets += packets * rate;
}

interface HostAcc {
  estBytesOut: number;
  estBytesIn: number;
  flows: number;
  peers: Set<string>;
  dstPortsOut: Set<number>;
}

function newHostAcc(): HostAcc {
  return { estBytesOut: 0, estBytesIn: 0, flows: 0, peers: new Set(), dstPortsOut: new Set() };
}

interface ConvAcc {
  src: string;
  dst: string;
  direction: FlowDirection;
  totals: VolumeTotals;
  dstPorts: Map<number, number>; // port -> est bytes (to pick the busiest)
  protos: Map<number, number>; // proto -> flow count (to pick the dominant)
}

interface SvcAcc {
  port: number;
  totals: VolumeTotals;
  sources: Set<string>;
  targets: Set<string>;
  protos: Map<number, number>;
}

interface OutAcc {
  estBytesOut: number;
  flows: number;
  externalPeers: Set<string>;
  dstPorts: Set<number>;
}

function newOutAcc(): OutAcc {
  return { estBytesOut: 0, flows: 0, externalPeers: new Set(), dstPorts: new Set() };
}

/** The dominant key of a count map (highest count, then lowest key). */
function topKey<K extends number>(m: Map<K, number>): K | undefined {
  let best: K | undefined;
  let bestV = -1;
  for (const [k, v] of m) {
    if (v > bestV || (v === bestV && best !== undefined && k < best)) {
      best = k;
      bestV = v;
    }
  }
  return best;
}

// ----- load -----------------------------------------------------------------

/** Read the persisted flow store, or null when NetFlow was never enabled. */
function loadFlows(): { flows: Flow[]; available: boolean } {
  if (!existsSync(FLOWS_PATH)) return { flows: [], available: false };
  try {
    const arr = JSON.parse(readFileSync(FLOWS_PATH, "utf8"));
    return { flows: Array.isArray(arr) ? (arr as Flow[]) : [], available: true };
  } catch {
    // A corrupt/partial file is treated as "store present but unreadable".
    return { flows: [], available: true };
  }
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  m: {
    samplingRate: number;
    routableFlows: number;
    distinctHosts: number;
    totals: VolumeTotals;
    direction: DirectionBreakdown;
    droppedShare: number | null;
  },
  talkers: TalkerRow[],
  outbound: OutboundRow[],
  services: ServiceRow[],
): string[] {
  const out: string[] = [];

  const lead = talkers[0];
  if (lead) {
    out.push(
      `📊 Heaviest talker is \`${lead.ip}\`${lead.role === "internal" ? " *(internal)*" : ""} — **${estLabel(lead.estBytesTotal)}** ` +
        `total (${estLabel(lead.estBytesOut)} out · ${estLabel(lead.estBytesIn)} in) across ${lead.flows} flow(s) to ` +
        `${lead.distinctPeers}+ peer(s). Volume, not signatures, is what surfaces it.`,
    );
  }

  // Direction shape — the single most orienting number.
  const d = m.direction;
  const big = ([
    ["outbound", d.outbound.estBytes],
    ["inbound", d.inbound.estBytes],
    ["internal", d.internal.estBytes],
    ["transit", d.transit.estBytes],
  ] as [string, number][]).sort((a, b) => b[1] - a[1])[0];
  if (big && m.totals.estBytes > 0) {
    out.push(
      `🧭 Traffic is **${pct(big[1] / m.totals.estBytes)} ${big[0]}** by volume ` +
        `(⬆ ${estLabel(d.outbound.estBytes)} out · ⬇ ${estLabel(d.inbound.estBytes)} in · ↔ ${estLabel(d.internal.estBytes)} ` +
        `lateral · ⤳ ${estLabel(d.transit.estBytes)} transit).`,
    );
  }

  // The exfil / spread tell — an internal host pushing out, or fanning wide.
  const exfil = outbound[0];
  if (exfil) {
    const fanout = exfil.distinctExternalPeers >= 50;
    out.push(
      `${fanout ? "🚨" : "⬆"} Top outbound internal host \`${exfil.ip}\` pushed **${estLabel(exfil.estBytesOut)}** to ` +
        `**${exfil.distinctExternalPeers}+ external destination(s)** on ${exfil.distinctDstPorts}+ port(s)` +
        `${fanout ? " — wide fan-out from one of your own boxes is the shape of scanning, worm spread or exfil; investigate." : "."}`,
    );
  }

  // The busiest destination service.
  const svc = services[0];
  if (svc) {
    out.push(
      `🔌 Most traffic lands on **${svc.service}** (${svc.protoLabel}) — ${estLabel(svc.totals.estBytes)} across ` +
        `${svc.totals.flows} flow(s), ${svc.distinctSources}+ source(s) → ${svc.distinctTargets}+ target(s).`,
    );
  }

  // Dropped share — coarse enforcement visibility from the exporter.
  if (m.droppedShare !== null && m.droppedShare > 0) {
    out.push(
      `⛔ The gateway forwarded **${pct(m.droppedShare)} of flows as dropped** (IPFIX forwardingStatus ≥ 128) — a coarse ` +
        `read on how much was actively denied at the perimeter.`,
    );
  }

  // Sampling honesty — always, so no number is mistaken for ground truth.
  out.push(
    `ℹ️ Byte / packet figures are **estimates**: NetFlow is packet-sampled at 1:${m.samplingRate}, so sampled counts are ` +
      `scaled up by ${m.samplingRate}× (marked \`~\`). Distinct peer / port counts are **lower bounds** — sampling can ` +
      `hide a destination but never invent one.`,
  );

  return out;
}

// ----- markdown -------------------------------------------------------------

function talkerTable(rows: TalkerRow[]): string {
  return mdTable(
    ["#", "Host", "Role", "Total", "Out", "In", "Flows", "Peers", "Dst ports"],
    rows.map((t, i) => [
      String(i + 1),
      cell(t.ip),
      t.role === "internal" ? "🏠 internal" : "🌐 external",
      estLabel(t.estBytesTotal),
      estLabel(t.estBytesOut),
      estLabel(t.estBytesIn),
      String(t.flows),
      `${t.distinctPeers}+`,
      `${t.distinctDstPorts}+`,
    ]),
  );
}

function conversationTable(rows: ConversationRow[]): string {
  return mdTable(
    ["#", "Source", "Destination", "Dir", "Bytes", "Flows", "Proto", "Top port", "Dst ports"],
    rows.map((c, i) => [
      String(i + 1),
      cell(c.src),
      cell(c.dst),
      cell(dirLabel(c.direction)),
      estLabel(c.totals.estBytes),
      String(c.totals.flows),
      cell(c.protoLabel),
      c.topDstPort !== undefined ? cell(serviceName(c.topDstPort)) : "—",
      `${c.distinctDstPorts}+`,
    ]),
  );
}

function serviceTable(rows: ServiceRow[]): string {
  return mdTable(
    ["#", "Service", "Proto", "Bytes", "Flows", "Sources", "Targets"],
    rows.map((s, i) => [
      String(i + 1),
      cell(s.service),
      cell(s.protoLabel),
      estLabel(s.totals.estBytes),
      String(s.totals.flows),
      `${s.distinctSources}+`,
      `${s.distinctTargets}+`,
    ]),
  );
}

function outboundTable(rows: OutboundRow[]): string {
  return mdTable(
    ["#", "Internal host", "Bytes out", "Ext. destinations", "Dst ports", "Flows"],
    rows.map((o, i) => [
      String(i + 1),
      cell(o.ip),
      estLabel(o.estBytesOut),
      `${o.distinctExternalPeers}+`,
      `${o.distinctDstPorts}+`,
      String(o.flows),
    ]),
  );
}

function renderMarkdown(m: TrafficReport): string {
  const lines: string[] = [];
  lines.push(`# 📈 SecTool Traffic / Top-Talkers Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Source:** NetFlow / IPFIX flow store (\`data/flows.json\`) — *not* the IPS alert stream · ` +
      `**Sampling:** 1:${m.samplingRate} (volume scaled ${m.samplingRate}×, marked \`~\`) · ` +
      `**Flows:** ${m.windowFlows} in-window of ${m.totalFlowsLoaded} retained`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.storeAvailable) {
    lines.push(
      `**NetFlow collection is not enabled** (no \`data/flows.json\` found), so there is no flow data to analyse. ` +
        `Enable the collector (\`NETFLOW_ENABLED=true\`) to populate volumetric traffic visibility — the signature-based ` +
        `alert reports are unaffected.`,
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  if (!m.windowFlows) {
    lines.push(
      `The flow store holds ${m.totalFlowsLoaded} flow(s), but none fell inside the last ${m.hours} hour(s). ` +
        `Widen the window, or the collector may have only recently started.`,
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");
  lines.push(
    `**Window totals:** ${estLabel(m.totals.estBytes)} across ${m.totals.flows} flow(s) and ${m.distinctHosts} ` +
      `distinct host(s).`,
  );
  lines.push("");

  lines.push(`## Top talkers`);
  lines.push("");
  lines.push(talkerTable(m.talkers));
  lines.push("");
  lines.push(
    `**Legend:** _Total/Out/In_ = estimated bytes (sampling-scaled). _Peers_ / _Dst ports_ are **lower bounds** ` +
      `(distinct counterpart IPs / destination ports this host initiated to). 🏠 internal · 🌐 external.`,
  );
  lines.push("");

  lines.push(`## Top conversations`);
  lines.push("");
  lines.push(conversationTable(m.conversations));
  lines.push("");

  lines.push(`## Internal-host outbound profile`);
  lines.push("");
  if (!m.outbound.length) {
    lines.push(`_No outbound flows from internal hosts in this window._`);
  } else {
    lines.push(
      `Your own hosts ranked by what they sent *out* of the perimeter. A high **external-destination fan-out** from a ` +
        `single box — especially a workstation — is the volumetric signature of scanning, worm spread, beaconing or ` +
        `data exfiltration that no IPS rule would name.`,
    );
    lines.push("");
    lines.push(outboundTable(m.outbound));
  }
  lines.push("");

  lines.push(`## Destination services`);
  lines.push("");
  lines.push(serviceTable(m.services));
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from the **NetFlow flow store**, not the IPS alert history. **Byte / packet figures ` +
      `are sampling-scaled estimates** (1:${m.samplingRate}); distinct peer / port counts are lower bounds. Flows are ` +
      `forward-only and observed from the **gateway's** vantage, and the store is rotated by count and age — so a long ` +
      `look-back can start mid-history. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the traffic / top-talkers report from the persisted NetFlow store.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link TrafficOptions}: `limit`, `samplingRate`, an injectable
 *              `flows` array, and a `nowMs` pin for deterministic tests.
 */
export function buildTraffic(hours: number, opts: TrafficOptions = {}): TrafficReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const samplingRate = Math.max(1, Math.floor(opts.samplingRate ?? DEFAULT_SAMPLING_RATE));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const loaded = opts.flows ? { flows: opts.flows, available: true } : loadFlows();
  const windowed = loaded.flows.filter((f) => {
    const t = flowTime(f);
    return typeof t === "number" && Number.isFinite(t) && t >= windowStartMs && t <= windowEndMs;
  });

  const totals = newTotals();
  const direction: DirectionBreakdown = {
    inbound: newTotals(),
    outbound: newTotals(),
    internal: newTotals(),
    transit: newTotals(),
  };
  const hosts = new Map<string, HostAcc>();
  const convs = new Map<string, ConvAcc>();
  const svcs = new Map<number, SvcAcc>();
  const outbound = new Map<string, OutAcc>();
  let routable = 0;
  let dropped = 0;

  for (const f of windowed) {
    const bytes = Number.isFinite(f.bytes) ? Math.max(0, f.bytes as number) : 0;
    const packets = Number.isFinite(f.packets) ? Math.max(0, f.packets as number) : 0;
    addTotals(totals, bytes, packets, samplingRate);

    const src = validIp(f.srcIp);
    const dst = validIp(f.dstIp);
    if (!src || !dst) continue;
    routable++;
    if (typeof f.fwdStatus === "number" && f.fwdStatus >= 128) dropped++;

    const est = bytes * samplingRate;
    const dir = directionOf(src, dst);
    addTotals(direction[dir], bytes, packets, samplingRate);

    // Per-host (both endpoints).
    const sAcc = hosts.get(src) ?? newHostAcc();
    if (!hosts.has(src)) hosts.set(src, sAcc);
    sAcc.estBytesOut += est;
    sAcc.flows++;
    sAcc.peers.add(dst);
    if (typeof f.dstPort === "number") sAcc.dstPortsOut.add(f.dstPort);

    const dAcc = hosts.get(dst) ?? newHostAcc();
    if (!hosts.has(dst)) hosts.set(dst, dAcc);
    dAcc.estBytesIn += est;
    dAcc.flows++;
    dAcc.peers.add(src);

    // Per-conversation.
    const ckey = `${src}|${dst}`;
    const cAcc =
      convs.get(ckey) ??
      ({ src, dst, direction: dir, totals: newTotals(), dstPorts: new Map(), protos: new Map() } satisfies ConvAcc);
    if (!convs.has(ckey)) convs.set(ckey, cAcc);
    addTotals(cAcc.totals, bytes, packets, samplingRate);
    if (typeof f.dstPort === "number") cAcc.dstPorts.set(f.dstPort, (cAcc.dstPorts.get(f.dstPort) ?? 0) + est);
    if (typeof f.proto === "number") cAcc.protos.set(f.proto, (cAcc.protos.get(f.proto) ?? 0) + 1);

    // Per-service (destination port).
    if (typeof f.dstPort === "number") {
      const vAcc =
        svcs.get(f.dstPort) ??
        ({ port: f.dstPort, totals: newTotals(), sources: new Set(), targets: new Set(), protos: new Map() } satisfies SvcAcc);
      if (!svcs.has(f.dstPort)) svcs.set(f.dstPort, vAcc);
      addTotals(vAcc.totals, bytes, packets, samplingRate);
      vAcc.sources.add(src);
      vAcc.targets.add(dst);
      if (typeof f.proto === "number") vAcc.protos.set(f.proto, (vAcc.protos.get(f.proto) ?? 0) + 1);
    }

    // Per-internal-host outbound profile (the exfil / spread lens).
    if (dir === "outbound") {
      const oAcc = outbound.get(src) ?? newOutAcc();
      if (!outbound.has(src)) outbound.set(src, oAcc);
      oAcc.estBytesOut += est;
      oAcc.flows++;
      oAcc.externalPeers.add(dst);
      if (typeof f.dstPort === "number") oAcc.dstPorts.add(f.dstPort);
    }
  }

  const talkers: TalkerRow[] = [...hosts.entries()]
    .map(([ip, a]) => ({
      ip,
      role: (isPrivate(ip) ? "internal" : "external") as HostRole,
      estBytesOut: Math.round(a.estBytesOut),
      estBytesIn: Math.round(a.estBytesIn),
      estBytesTotal: Math.round(a.estBytesOut + a.estBytesIn),
      flows: a.flows,
      distinctPeers: a.peers.size,
      distinctDstPorts: a.dstPortsOut.size,
    }))
    .sort((x, y) => y.estBytesTotal - x.estBytesTotal || y.flows - x.flows || (x.ip < y.ip ? -1 : 1))
    .slice(0, limit);

  const conversations: ConversationRow[] = [...convs.values()]
    .map((c) => {
      const top = topKey(c.dstPorts);
      const dom = topKey(c.protos);
      return {
        src: c.src,
        dst: c.dst,
        direction: c.direction,
        totals: { ...c.totals, estBytes: Math.round(c.totals.estBytes), estPackets: Math.round(c.totals.estPackets) },
        distinctDstPorts: c.dstPorts.size,
        protoLabel: protoLabel(dom),
        topDstPort: top,
      } satisfies ConversationRow;
    })
    .sort((x, y) => y.totals.estBytes - x.totals.estBytes || y.totals.flows - x.totals.flows)
    .slice(0, limit);

  const services: ServiceRow[] = [...svcs.values()]
    .map((s) => ({
      port: s.port,
      service: serviceName(s.port),
      protoLabel: protoLabel(topKey(s.protos)),
      totals: { ...s.totals, estBytes: Math.round(s.totals.estBytes), estPackets: Math.round(s.totals.estPackets) },
      distinctSources: s.sources.size,
      distinctTargets: s.targets.size,
    }))
    .sort((x, y) => y.totals.estBytes - x.totals.estBytes || y.totals.flows - x.totals.flows || x.port - y.port)
    .slice(0, limit);

  const outboundRows: OutboundRow[] = [...outbound.entries()]
    .map(([ip, o]) => ({
      ip,
      estBytesOut: Math.round(o.estBytesOut),
      distinctExternalPeers: o.externalPeers.size,
      distinctDstPorts: o.dstPorts.size,
      flows: o.flows,
    }))
    // Fan-out first (the compromise tell), then raw outbound volume.
    .sort(
      (x, y) =>
        y.distinctExternalPeers - x.distinctExternalPeers ||
        y.estBytesOut - x.estBytesOut ||
        (x.ip < y.ip ? -1 : 1),
    )
    .slice(0, limit);

  const droppedShare = routable > 0 ? round4(dropped / routable) : null;

  const highlights = loaded.available
    ? writeHighlights(
        safeHours,
        { samplingRate, routableFlows: routable, distinctHosts: hosts.size, totals, direction, droppedShare },
        talkers,
        outboundRows,
        services,
      )
    : [];

  const model: TrafficReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    samplingRate,
    storeAvailable: loaded.available,
    totalFlowsLoaded: loaded.flows.length,
    windowFlows: windowed.length,
    routableFlows: routable,
    totals,
    direction,
    droppedFlows: dropped,
    droppedShare,
    distinctHosts: hosts.size,
    talkers,
    conversations,
    services,
    outbound: outboundRows,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded traffic report. */
export function trafficFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-traffic-${stamp}.md`;
}
