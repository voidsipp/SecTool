/**
 * Forensic packet-capture filter generator — turn the worst observed attackers
 * into **ready-to-run `tcpdump` / Wireshark / `tshark` capture filters** so an
 * analyst can grab the *raw packets* of a host for deep forensic analysis: full
 * conversation reconstruction, payload inspection, malware-sample carving, TLS
 * SNI / JA3 fingerprinting — everything the alert metadata throws away.
 *
 * This is the one export surface none of the others reach: the **acquisition**
 * layer. Every existing SecTool export emits a *detection* or *enforcement*
 * artefact, several steps downstream of "show me the bytes":
 *
 *   - snort.ts (`--snort`) / sigma.ts (`--sigma`) emit IDS / SIEM *detection*
 *     rules — they fire on traffic, they do not let you *read* it.
 *   - stix.ts (`--stix`) / iocExport.ts (`--iocs`) emit *intel* indicator lists
 *     for a TI platform or a blocklist — provenance, not packets.
 *   - fwrules.ts (`--fwrules`) emits *firewall* config — it drops the traffic,
 *     the exact opposite of capturing it.
 *   - cefExport.ts (`--cef`) emits per-alert *log-forwarding* lines — the
 *     normalized event, still not the wire bytes.
 *
 * When triage says "this IP is interesting — I need to *see* what it actually
 * did", the next move is a packet capture, and the fiddly part is writing the
 * right capture filter for a worklist of a dozen-plus hosts without fat-fingering
 * an address. This module does exactly that, reusing {@link buildIocExport} as
 * its scoring engine — the *same* confidence / severity-floor / safelist /
 * dismissed-alert model that makes the IOC export trustworthy as a worklist — so
 * the hosts you are told to capture are the hosts that actually matter, ranked
 * highest-confidence first. No scoring logic is duplicated.
 *
 * Output flavours (`--format`):
 *   - **tcpdump** (default) — a single combined **BPF capture expression**
 *     (`(host A or host B or …)`) plus copy-paste `tcpdump` commands: one
 *     combined capture and one per-source capture writing a per-host `.pcap`,
 *     and a retrospective form that slices an *existing* capture file.
 *   - **wireshark** — the equivalent **display filter**
 *     (`ip.addr == A || ipv6.addr == B || …`) to paste straight into Wireshark's
 *     filter bar (or `tshark -Y`) to slice a host out of a capture you already
 *     have.
 *   - **tshark** — ready-to-run `tshark` capture / slice commands (BPF capture
 *     filter `-f`, display filter `-Y`), writing `.pcapng`.
 *   - **json** — the structured model, for programmatic consumers.
 *   - **md** — a human Markdown review twin (eyeball the worklist before you
 *     capture).
 *
 * Honest caveats baked into the output:
 *   - **SecTool cannot capture for you.** A filter is only useful run on a host
 *     that actually *sees* the traffic — a SPAN / mirror port, the gateway, or
 *     the target host itself. The commands document the interface (`--iface`,
 *     default the Linux `any` pseudo-interface).
 *   - **Filters match by IP address only, not port.** SecTool's alert store does
 *     not retain transport ports reliably, so the capture grabs the *whole*
 *     conversation with the host — which is what you want for forensics anyway
 *     (you rarely know the interesting port in advance). The BPF `host`
 *     primitive matches the address as **either endpoint** (to *or* from it).
 *   - **Captured attacker traffic can contain sensitive payloads** (your own
 *     hosts' responses included). Handle the resulting `.pcap` per your
 *     evidence-handling / privacy policy.
 *   - **Addresses get reassigned.** Capture promptly while the indicator is
 *     fresh; a stale address may now belong to a benign tenant.
 *   - **Safelisted IPs are excluded by default**, exactly as in the IOC export.
 *
 * Pure in-memory math over alertStore (via iocExport) — no SSH, no Claude, no
 * network, no live capture. Output is a structured model, a ready-to-run filter /
 * command text string and a human Markdown review twin, mirroring snort.ts and
 * the other offline exports so it plugs into the same CLI and HTTP plumbing.
 */
import { buildIocExport, type IocIndicator } from "./iocExport.ts";
import type { Severity } from "../types.ts";

/** Output flavour the export renders into. */
export type PcapFormat = "tcpdump" | "wireshark" | "tshark" | "json" | "md";

/**
 * Default cap on capture targets. A BPF / display filter spanning thousands of
 * hosts is impractical to run, so — unlike the IOC export (which defaults to no
 * cap, being a blocklist source) — this report defaults to a focused worklist of
 * the highest-confidence offenders. Override with `--limit`.
 */
const DEFAULT_LIMIT = 25;
/** Hard ceiling so a generated filter never grows unwieldy. */
const MAX_LIMIT = 200;

/** The default capture interface — the Linux `any` pseudo-interface. */
const DEFAULT_IFACE = "any";

/** Basenames for the generated capture files (kept short + filesystem-safe). */
const PCAP_PREFIX = "sectool-forensic";

/** One capture target: a single attacker IP with its forensic context + filters. */
export interface PcapTarget {
  /** The external (routable) attacker IP — the address to capture. */
  ip: string;
  /** IP family, 4 or 6. */
  family: 4 | 6;
  /** SecTool 0–100 blocklist/worklist confidence (from the IOC engine). */
  confidence: number;
  /** Highest severity seen for this IP. */
  severityMax: Severity;
  /** Total in-window alerts attributed to this IP. */
  alertCount: number;
  /** How many of those alerts the gateway already blocked. */
  blockedCount: number;
  /** Distinct signatures it tripped. */
  signatureCount: number;
  /** Its loudest signature, if any (forensic context). */
  topSignature?: string;
  /** Distinct internal hosts it touched (for scoped captures). */
  internalTargets: string[];
  /** Total distinct internal hosts touched. */
  targetCount: number;
  /** Earliest / latest alert times (ms epoch) — when to bound the capture. */
  firstSeen: number;
  lastSeen: number;
  /** Already present in the firewall blocklist (capture may need a temporary unblock). */
  alreadyBlocked: boolean;
  /** The BPF capture primitive for this IP (`host 1.2.3.4`). */
  bpf: string;
  /** The Wireshark display-filter primitive (`ip.addr == 1.2.3.4`). */
  display: string;
  /** A filesystem-safe token derived from the IP for per-host `.pcap` names. */
  fileToken: string;
}

export interface PcapReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Severity floor applied to qualify as a target (from the IOC engine). */
  minSeverity: Severity;
  /** Output flavour requested. */
  format: PcapFormat;
  /** Capture interface baked into the emitted commands. */
  iface: string;
  /** Distinct attacker IPs in the capture worklist. */
  targetCount: number;
  /** Targets dropped because the IP is safelisted (explicitly trusted). */
  excludedSafe: number;
  /** Targets dropped because their worst severity was below the floor. */
  excludedBelowSeverity: number;
  /** Targets truncated by the `limit` (worklist kept the top {@link targetCount}). */
  truncated: number;
  /** The combined BPF capture expression covering every target (or "" if none). */
  bpfExpression: string;
  /** The combined Wireshark/tshark display filter (or "" if none). */
  displayFilter: string;
  /** The ranked capture targets (highest confidence first). */
  targets: PcapTarget[];
  /** The full deliverable for the chosen format (filters + ready-to-run commands). */
  text: string;
  /** A human Markdown review twin (eyeball the worklist before capturing). */
  markdown: string;
}

export interface PcapOptions {
  /** Severity floor (default `medium`, inherited from the IOC engine). */
  minSeverity?: Severity;
  /** Cap on capture targets, highest confidence first (default {@link DEFAULT_LIMIT}). */
  limit?: number;
  /** Include safelisted IPs instead of excluding them (default false). */
  includeSafe?: boolean;
  /** Capture interface for the emitted commands (default {@link DEFAULT_IFACE}). */
  iface?: string;
  /** Output flavour (default `tcpdump`). */
  format?: PcapFormat;
  /** Pins the window end / timestamps for deterministic tests; defaults to now. */
  nowMs?: number;
}

// ----- helpers ---------------------------------------------------------------

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function mdCell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

/**
 * Sanitise a capture-interface name to a conservative charset before it is
 * spliced into an emitted shell command. The output is documentation, never
 * executed by SecTool, but an unsanitised value pasted by a hurried analyst
 * should not be able to smuggle in shell metacharacters. Falls back to the safe
 * `any` pseudo-interface.
 */
function sanitizeIface(raw: string | undefined | null): string {
  const cleaned = (raw ?? "").trim().replace(/[^A-Za-z0-9._:@-]/g, "");
  return cleaned.length ? cleaned : DEFAULT_IFACE;
}

/**
 * A filesystem-safe token for a per-host capture filename. IPv6 colons (illegal
 * in Windows filenames) and IPv4 dots collapse to `-`; redundant separators are
 * squeezed so `2001:db8::1` → `2001-db8-1`.
 */
function ipFileToken(ip: string): string {
  return ip.replace(/[.:]+/g, "-").replace(/^-+|-+$/g, "") || "host";
}

/** The BPF capture primitive matching either endpoint of a conversation. */
function bpfPrimitive(ip: string): string {
  return `host ${ip}`;
}

/** The Wireshark/tshark display-filter primitive (family-aware). */
function displayPrimitive(ip: string, family: 4 | 6): string {
  return `${family === 6 ? "ipv6.addr" : "ip.addr"} == ${ip}`;
}

/** Combine per-host BPF primitives into one parenthesised capture expression. */
function combineBpf(targets: PcapTarget[]): string {
  if (!targets.length) return "";
  return `(${targets.map((t) => t.bpf).join(" or ")})`;
}

/** Combine per-host display primitives into one Wireshark display filter. */
function combineDisplay(targets: PcapTarget[]): string {
  return targets.map((t) => t.display).join(" || ");
}

/** Single-quote a filter argument for safe inclusion in an emitted shell command. */
function shq(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

// ----- target construction ---------------------------------------------------

function toTarget(ind: IocIndicator): PcapTarget {
  return {
    ip: ind.ip,
    family: ind.family,
    confidence: ind.confidence,
    severityMax: ind.severityMax,
    alertCount: ind.alertCount,
    blockedCount: ind.blockedCount,
    signatureCount: ind.signatureCount,
    topSignature: ind.signatures[0],
    internalTargets: ind.targets,
    targetCount: ind.targetCount,
    firstSeen: ind.firstSeen,
    lastSeen: ind.lastSeen,
    alreadyBlocked: ind.alreadyBlocked,
    bpf: bpfPrimitive(ind.ip),
    display: displayPrimitive(ind.ip, ind.family),
    fileToken: ipFileToken(ind.ip),
  };
}

// ----- text deliverables -----------------------------------------------------

function header(m: Omit<PcapReport, "text" | "markdown" | "targets">, kind: string): string {
  const lines = [
    `# SecTool forensic packet-capture ${kind}`,
    `# Window: last ${m.hours}h (${fmtTime(m.windowStartMs)} -> ${fmtTime(m.windowEndMs)})`,
    `# Targets: ${m.targetCount} | Min severity: ${m.minSeverity} | Interface: ${m.iface}` +
      (m.excludedSafe ? ` | Excluded (safelisted): ${m.excludedSafe}` : "") +
      (m.truncated ? ` | Truncated: ${m.truncated} more` : ""),
    `# Run on a host that SEES the traffic (SPAN/mirror port, the gateway, or the target).`,
    `# Matches by IP only (either direction); captures the whole conversation with the host.`,
    `# Handle the resulting capture per your evidence-handling policy — payloads may be sensitive.`,
  ];
  return lines.join("\n");
}

function renderTcpdump(m: Omit<PcapReport, "text" | "markdown">): string {
  const lines = [header(m, "(tcpdump / BPF)")];
  if (!m.targets.length) {
    lines.push("# No qualifying attacker IPs in this window — nothing to capture.");
    return lines.join("\n") + "\n";
  }
  lines.push("");
  lines.push("# --- Combined live capture: all targets into one file ---");
  lines.push(
    `tcpdump -i ${m.iface} -n -s 0 -w ${PCAP_PREFIX}-all.pcap ${shq(m.bpfExpression)}`,
  );
  lines.push("");
  lines.push("# --- Retrospective: slice the same hosts out of an existing capture ---");
  lines.push(
    `tcpdump -n -r existing.pcap -w ${PCAP_PREFIX}-all.pcap ${shq(m.bpfExpression)}`,
  );
  lines.push("");
  lines.push("# --- Per-source live captures (one file per attacker) ---");
  for (const t of m.targets) {
    lines.push(
      `tcpdump -i ${m.iface} -n -s 0 -w ${PCAP_PREFIX}-${t.fileToken}.pcap ${shq(t.bpf)}` +
        `   # conf ${t.confidence} sev ${t.severityMax} alerts ${t.alertCount}`,
    );
  }
  return lines.join("\n") + "\n";
}

function renderWireshark(m: Omit<PcapReport, "text" | "markdown">): string {
  const lines = [header(m, "(Wireshark / tshark display filter)")];
  if (!m.targets.length) {
    lines.push("# No qualifying attacker IPs in this window — nothing to filter.");
    return lines.join("\n") + "\n";
  }
  lines.push("");
  lines.push("# Paste into Wireshark's display-filter bar to slice these hosts out of a capture,");
  lines.push(`# or apply non-interactively:  tshark -r existing.pcapng -Y '<filter>' -w sliced.pcapng`);
  lines.push("");
  lines.push(m.displayFilter);
  return lines.join("\n") + "\n";
}

function renderTshark(m: Omit<PcapReport, "text" | "markdown">): string {
  const lines = [header(m, "(tshark)")];
  if (!m.targets.length) {
    lines.push("# No qualifying attacker IPs in this window — nothing to capture.");
    return lines.join("\n") + "\n";
  }
  lines.push("");
  lines.push("# --- Combined live capture (BPF capture filter -f) ---");
  lines.push(
    `tshark -i ${m.iface} -n -f ${shq(m.bpfExpression)} -w ${PCAP_PREFIX}-all.pcapng`,
  );
  lines.push("");
  lines.push("# --- Retrospective slice from an existing capture (display filter -Y) ---");
  lines.push(
    `tshark -r existing.pcapng -Y ${shq(m.displayFilter)} -w ${PCAP_PREFIX}-all.pcapng`,
  );
  lines.push("");
  lines.push("# --- Per-source live captures ---");
  for (const t of m.targets) {
    lines.push(
      `tshark -i ${m.iface} -n -f ${shq(t.bpf)} -w ${PCAP_PREFIX}-${t.fileToken}.pcapng` +
        `   # conf ${t.confidence} sev ${t.severityMax}`,
    );
  }
  return lines.join("\n") + "\n";
}

function renderDeliverable(m: Omit<PcapReport, "text" | "markdown">): string {
  switch (m.format) {
    case "wireshark":
      return renderWireshark(m);
    case "tshark":
      return renderTshark(m);
    case "tcpdump":
    default:
      return renderTcpdump(m);
  }
}

// ----- markdown twin ---------------------------------------------------------

function renderMarkdown(m: PcapReport): string {
  const lines: string[] = [];
  lines.push(`# 🦈 SecTool Forensic Packet-Capture Filters`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Flavour:** ${m.format} · **Interface:** \`${m.iface}\` · **Targets:** ${m.targetCount} · ` +
      `**Min severity:** ${m.minSeverity}` +
      (m.excludedSafe ? ` · **Excluded (safelisted):** ${m.excludedSafe}` : "") +
      (m.truncated ? ` · **Truncated:** ${m.truncated} more` : ""),
  );
  lines.push("");

  if (!m.targetCount) {
    lines.push(
      `No external attacker IPs at **${m.minSeverity}** severity or above in the last ${m.hours} hour(s).` +
        (m.excludedBelowSeverity
          ? ` (${m.excludedBelowSeverity} lower-severity IP(s) were below the floor.)`
          : ""),
    );
    lines.push("");
    lines.push("Nothing to capture — no filters were generated.");
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live capture or gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  lines.push(
    `Ready-to-run capture filters for your highest-confidence attackers, so you can grab the **raw packets** ` +
      `(full conversation, payloads, samples) the alert metadata throws away. Each filter matches the address as ` +
      `**either endpoint** (traffic *to* or *from* it). Run them on a host that actually sees the traffic — a ` +
      `SPAN / mirror port, the gateway, or the target host itself; SecTool cannot capture for you.`,
  );
  lines.push("");

  // The capture worklist.
  const head = ["#", "IP", "Conf.", "Sev", "Alerts", "Blocked", "Sigs", "Hosts", "Top signature", "Last seen"];
  lines.push(`| ${head.join(" | ")} |`);
  lines.push(`| ${head.map(() => "---").join(" | ")} |`);
  m.targets.forEach((t, i) => {
    lines.push(
      `| ${i + 1} | ${mdCell(t.ip)}${t.alreadyBlocked ? " 🚫" : ""} | ${t.confidence} | ${mdCell(t.severityMax)} | ` +
        `${t.alertCount} | ${t.blockedCount || "·"} | ${t.signatureCount} | ${t.targetCount} | ` +
        `${mdCell(t.topSignature ?? "·")} | ${fmtTime(t.lastSeen)} |`,
    );
  });
  lines.push("");
  if (m.targets.some((t) => t.alreadyBlocked)) {
    lines.push(
      `> 🚫 = already in the firewall blocklist. The gateway may now be dropping its traffic before a sensor ` +
        `downstream can see it — capture at the perimeter, or temporarily unblock to observe.`,
    );
    lines.push("");
  }

  // Combined BPF.
  lines.push(`## Combined \`tcpdump\` capture (BPF)`);
  lines.push("");
  lines.push("```");
  lines.push(`tcpdump -i ${m.iface} -n -s 0 -w ${PCAP_PREFIX}-all.pcap ${shq(m.bpfExpression)}`);
  lines.push("```");
  lines.push("");

  // Wireshark display filter.
  lines.push(`## Wireshark / \`tshark\` display filter`);
  lines.push("");
  lines.push("Paste into the filter bar, or slice an existing capture non-interactively:");
  lines.push("");
  lines.push("```");
  lines.push(m.displayFilter);
  lines.push("```");
  lines.push("");
  lines.push("```");
  lines.push(`tshark -r existing.pcapng -Y ${shq(m.displayFilter)} -w ${PCAP_PREFIX}-all.pcapng`);
  lines.push("```");
  lines.push("");

  // The full chosen-flavour deliverable (per-source commands etc.). The md / json
  // flavours have no command text of their own, so they embed the tcpdump set.
  const deliverableLabel = m.format === "md" || m.format === "json" ? "tcpdump" : m.format;
  lines.push(`## Full ${deliverableLabel} command set`);
  lines.push("");
  lines.push("```");
  lines.push(m.text.trimEnd());
  lines.push("```");
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from the stored alert history (top ${m.targetCount} by confidence, ` +
      `min severity ${m.minSeverity} — the same severity/volume/corroboration model as \`--iocs\`). Filters match ` +
      `by **IP address only** (SecTool does not retain transport ports), which captures the whole conversation with ` +
      `the host — the right default for forensics. Captured payloads may be sensitive; handle the resulting pcap per ` +
      `your evidence-handling policy. Addresses get reassigned — capture promptly. Safelisted IPs are excluded by ` +
      `default. The acquisition-layer sibling of \`--snort\` / \`--sigma\` (detection), \`--iocs\` / \`--stix\` ` +
      `(intel) and \`--fwrules\` (enforcement). No live capture or gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

// ----- entry point -----------------------------------------------------------

/**
 * Build the forensic packet-capture filter export from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped by the IOC engine).
 * @param opts  {@link PcapOptions}: severity floor, target limit, safelist
 *              handling, capture interface, output flavour, and a `nowMs` pin for
 *              deterministic / reproducible output.
 */
export function buildPcap(hours: number, opts: PcapOptions = {}): PcapReport {
  const nowMs = opts.nowMs ?? Date.now();
  const format: PcapFormat = opts.format ?? "tcpdump";
  const iface = sanitizeIface(opts.iface);
  const limit = Math.max(
    1,
    Math.min(MAX_LIMIT, Math.floor(opts.limit !== undefined && opts.limit > 0 ? opts.limit : DEFAULT_LIMIT)),
  );

  // Reuse the IOC engine as the scoring source of truth — same window clamp,
  // confidence model, severity floor and safelist / dismissed handling. The IOC
  // engine ranks highest-confidence first, so the worklist truncates to the
  // attackers that matter most.
  const ioc = buildIocExport(hours, {
    minSeverity: opts.minSeverity,
    limit,
    includeSafe: opts.includeSafe,
    nowMs,
  });

  const targets = ioc.indicators.map(toTarget);
  const bpfExpression = combineBpf(targets);
  const displayFilter = combineDisplay(targets);

  const base: Omit<PcapReport, "text" | "markdown"> = {
    hours: ioc.hours,
    windowStartMs: ioc.windowStartMs,
    windowEndMs: ioc.windowEndMs,
    minSeverity: ioc.minSeverity,
    format,
    iface,
    targetCount: targets.length,
    excludedSafe: ioc.excludedSafe,
    excludedBelowSeverity: ioc.excludedBelowSeverity,
    truncated: ioc.truncated,
    bpfExpression,
    displayFilter,
    targets,
  };

  const text = renderDeliverable(base);
  const model: PcapReport = { ...base, text, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded capture-filter set in the given flavour. */
export function pcapFilename(nowMs: number, format: PcapFormat = "tcpdump"): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  const ext = format === "md" ? "md" : format === "json" ? "json" : "txt";
  return `sectool-pcap-${stamp}.${ext}`;
}

/** Coerce an arbitrary string into a valid {@link PcapFormat}, defaulting to tcpdump. */
export function parsePcapFormat(raw: string | undefined | null): PcapFormat {
  const f = (raw ?? "").trim().toLowerCase();
  if (f === "wireshark" || f === "display" || f === "ws") return "wireshark";
  if (f === "tshark") return "tshark";
  if (f === "json") return "json";
  if (f === "md" || f === "markdown") return "md";
  return "tcpdump"; // also the home of "bpf"
}
