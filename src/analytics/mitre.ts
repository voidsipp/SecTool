/**
 * MITRE ATT&CK coverage report — "expressed in the framework my SOC, my SIEM and
 * my compliance auditor already speak: which ATT&CK **tactics** and
 * **techniques** is my IPS actually observing?"
 *
 * The closest existing report is **killchain.ts**, but the two answer different
 * questions with different vocabularies and must not be confused:
 *
 *   - killchain.ts maps each alert to one of the **five ordered Lockheed-Martin
 *     Cyber Kill Chain stages** (Recon → Delivery → Exploitation → C2 → Actions)
 *     and then watches a *single host* walk that chain in sequence. Its payload
 *     is **progression** — is one box advancing stage by stage?
 *   - This report maps each alert to one of the **fourteen MITRE ATT&CK
 *     Enterprise tactics** and a specific **technique ID** (T-code). Its payload
 *     is a **coverage matrix** — the industry-standard, ATT&CK-Navigator-shaped
 *     view that drops straight into a SOC threat-coverage review, a detection-gap
 *     assessment, or a compliance pack. ATT&CK's tactic set is far finer than the
 *     kill chain's five stages (it separates Credential Access, Discovery,
 *     Lateral Movement, Defense Evasion, Impact … each of which the kill chain
 *     lumps into one bucket), so the two are complementary, not redundant.
 *
 * For the chosen window every stored alert is mapped to **one** ATT&CK technique
 * by a first-match-wins heuristic ({@link mapTechnique}) over its Suricata
 * **classification** (classtype), **signature** and **category** text — the same
 * fields the live detector already extracts. The result is rolled up two ways:
 *
 *   1. **Tactic coverage** — per ATT&CK tactic (in canonical ATT&CK order): how
 *      many distinct techniques fired under it, alert volume and share, distinct
 *      attacker sources and internal hosts touched, the severity ceiling, the
 *      blocked-vs-detected disposition split, and the busiest technique. An ASCII
 *      coverage bar reads the distribution at a glance.
 *   2. **Per-technique detail** — every observed technique ranked by a
 *      severity-weighted score: its ID + name + parent tactic, alert volume,
 *      distinct sources and targets, severity ceiling, disposition split, the
 *      dominant signature, and a flag when an **internal** host is the *source*
 *      of the technique (a strong compromise / insider tell rather than inbound
 *      noise).
 *
 * The sharpest rows are the **control gaps** (🚩): medium-or-worse techniques
 * that were mostly *detected, not blocked* — exactly the ATT&CK cells where
 * enforcement should be verified first.
 *
 * Honest about its limits, all stated in the output:
 *
 *   - **Mapping is a heuristic, not a curated ATT&CK mapping.** It keys off
 *     free-text Suricata fields, so it is a strong triage hint, not an authored
 *     rule→technique table. A real ATT&CK mapping is often many-to-one (one alert
 *     evidences several techniques); to keep the coverage math clean each alert
 *     is attributed to a *single* best-match technique, and everything that
 *     matches no rule lands in an honest **unmapped** bucket (counted, never
 *     silently dropped).
 *   - **Detections, not full telemetry.** A technique an attacker used without
 *     tripping a signature is invisible here — coverage is a lower bound, and an
 *     empty tactic cell means "my IPS did not *alert* on it", not "it did not
 *     happen".
 *   - **Window-bounded & store-capped.** A long look-back can hit the alert
 *     store's history cap and undercount.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network. Output is
 * both a structured model and a ready-to-paste Markdown document, mirroring
 * killchain.ts, scan.ts, classify.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/**
 * The fourteen MITRE ATT&CK Enterprise tactics, in canonical ATT&CK order. The
 * report only renders tactics that were actually observed, but the order here is
 * authoritative for display so the matrix always reads left-to-right along the
 * kill-chain-of-tactics the way an analyst expects.
 */
export const ATTACK_TACTICS = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
] as const;

export type Tactic = (typeof ATTACK_TACTICS)[number];

/** Canonical ATT&CK tactic IDs (TA-codes), for export / Navigator round-trips. */
export const TACTIC_IDS: Record<Tactic, string> = {
  Reconnaissance: "TA0043",
  "Resource Development": "TA0042",
  "Initial Access": "TA0001",
  Execution: "TA0002",
  Persistence: "TA0003",
  "Privilege Escalation": "TA0004",
  "Defense Evasion": "TA0005",
  "Credential Access": "TA0006",
  Discovery: "TA0007",
  "Lateral Movement": "TA0008",
  Collection: "TA0009",
  "Command and Control": "TA0011",
  Exfiltration: "TA0010",
  Impact: "TA0040",
};

/** A single ATT&CK technique the report can attribute an alert to. */
export interface TechniqueDef {
  /** ATT&CK technique ID, e.g. "T1190". */
  id: string;
  /** Human technique name, e.g. "Exploit Public-Facing Application". */
  name: string;
  /** Parent tactic. */
  tactic: Tactic;
}

/**
 * The curated catalog of techniques this report attributes alerts to. Kept
 * deliberately small and IPS-relevant (an IDS/IPS only ever evidences a slice of
 * ATT&CK), and indexed by ID so a rule can reference a technique once.
 */
export const TECHNIQUES: Record<string, TechniqueDef> = {
  T1595: { id: "T1595", name: "Active Scanning", tactic: "Reconnaissance" },
  T1592: { id: "T1592", name: "Gather Victim Host Information", tactic: "Reconnaissance" },
  T1190: { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  T1566: { id: "T1566", name: "Phishing", tactic: "Initial Access" },
  T1133: { id: "T1133", name: "External Remote Services", tactic: "Initial Access" },
  T1203: { id: "T1203", name: "Exploitation for Client Execution", tactic: "Execution" },
  T1059: { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
  T1068: { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation" },
  T1211: { id: "T1211", name: "Exploitation for Defense Evasion", tactic: "Defense Evasion" },
  T1110: { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
  T1212: { id: "T1212", name: "Exploitation for Credential Access", tactic: "Credential Access" },
  T1046: { id: "T1046", name: "Network Service Discovery", tactic: "Discovery" },
  T1021: { id: "T1021", name: "Remote Services", tactic: "Lateral Movement" },
  T1210: { id: "T1210", name: "Exploitation of Remote Services", tactic: "Lateral Movement" },
  T1071: { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control" },
  T1090: { id: "T1090", name: "Proxy", tactic: "Command and Control" },
  T1105: { id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control" },
  T1041: { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
  T1048: { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration" },
  T1499: { id: "T1499", name: "Endpoint Denial of Service", tactic: "Impact" },
  T1498: { id: "T1498", name: "Network Denial of Service", tactic: "Impact" },
  T1486: { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
  T1496: { id: "T1496", name: "Resource Hijacking", tactic: "Impact" },
};

/**
 * Ordered mapping rules: the first whose pattern matches the alert's combined
 * `classification + signature + category` text wins. Order is most-specific →
 * least-specific so a precise classtype (e.g. "denial of service") beats a broad
 * keyword (e.g. "scan"). Patterns are matched case-insensitively.
 */
const RULES: Array<{ technique: string; re: RegExp }> = [
  // Impact — unambiguous, dangerous outcomes first so they never fall through.
  { technique: "T1486", re: /ransomware|data encrypted|crypto.?lock/i },
  { technique: "T1496", re: /coin.?miner|crypto.?(currency|mining|miner)|xmrig|monero|stratum/i },
  { technique: "T1498", re: /\bddos\b|distributed denial|amplification|reflection attack/i },
  { technique: "T1499", re: /denial of service|\bdos\b|syn flood|\bflood\b/i },
  // Credential access.
  { technique: "T1110", re: /brute.?force|password (guess|spray)|credential stuffing|login attempt|hydra|excessive login|auth.* fail/i },
  { technique: "T1212", re: /credential (access|theft|dump)|kerberoast|asreproast|mimikatz/i },
  // Exfiltration.
  { technique: "T1048", re: /dns tunnel|exfiltration over (dns|icmp|alternative)|data over (dns|icmp)/i },
  { technique: "T1041", re: /exfil|data (theft|leak|exfiltration)|information leak/i },
  // Command & control — trojans, CnC, beacons, proxies, tool transfer.
  { technique: "T1090", re: /\btor\b|\bproxy\b|anonymi[sz]er|socks|onion/i },
  { technique: "T1105", re: /tool transfer|payload download|drop(per| file)|stager|download.* (exe|payload|malware)/i },
  { technique: "T1071", re: /\bc2\b|\bcnc\b|command and control|command-and-control|\bbeacon|trojan|\bbot\b|botnet|malware|backdoor|implant|\brat\b/i },
  // Lateral movement.
  { technique: "T1210", re: /eternalblue|smb.* (exploit|rce)|exploitation of remote|wannacry|ms17-010/i },
  { technique: "T1021", re: /lateral movement|\bpsexec\b|\bwmic?\b|remote desktop|\bsmb\b|\brdp\b|remote services/i },
  // Privilege escalation / execution / client-side exploitation.
  { technique: "T1068", re: /privilege (gain|escalation)|priv.?esc|local exploit/i },
  { technique: "T1203", re: /exploit kit|client (execution|exploit)|drive.?by|shellcode|buffer overflow|metasploit|meterpreter|heap spray/i },
  { technique: "T1059", re: /powershell|\bmshta\b|wscript|cscript|command (injection|execution)|os command|scripting interpreter/i },
  // Initial access — web app attacks, phishing, exposed remote services.
  { technique: "T1190", re: /sql.?injection|\bsqli\b|\bxss\b|cross.?site|directory traversal|path traversal|\blfi\b|\brfi\b|file inclusion|web (application )?attack|web.?server|web_specific|deserializ|\brce\b|remote code execution|\bcve-/i },
  { technique: "T1566", re: /phish|spear.?phish|malicious (attachment|link|document)/i },
  { technique: "T1133", re: /external remote service|exposed (rdp|ssh|vpn)|vpn (brute|exploit)/i },
  // Discovery vs reconnaissance — service enumeration vs broad scanning.
  { technique: "T1046", re: /service (scan|discovery|enumeration)|version (scan|probe)|banner grab|attempted (information|info) leak/i },
  { technique: "T1592", re: /host (discovery|enumeration)|os fingerprint|ping sweep/i },
  { technique: "T1595", re: /\bscan\b|portscan|port scan|\bnmap\b|masscan|\bzmap\b|network scan|probe|recon/i },
];

/** Blocked / passed / unknown disposition split for an ATT&CK cell. */
export interface DispositionSplit {
  /** Alerts the gateway actively blocked / dropped. */
  blocked: number;
  /** Alerts the gateway logged but let through (detected / allowed). */
  passed: number;
  /** Alerts with no recorded action (excluded from {@link passRate}). */
  unknown: number;
  /**
   * Fraction of *actioned* (blocked + passed) alerts that were let through,
   * 0..1 (4dp), or null when nothing was actioned. A high pass rate on a severe
   * technique is the control gap worth verifying first.
   */
  passRate: number | null;
}

/** Per-technique roll-up over the window. */
export interface MitreTechnique {
  /** ATT&CK technique ID. */
  id: string;
  /** Human technique name. */
  name: string;
  /** Parent tactic. */
  tactic: Tactic;
  /** Total alerts attributed to this technique. */
  count: number;
  /** Share of all *mapped* alerts, 0..1 (4dp). */
  share: number;
  /** Distinct attacker source IPs evidencing this technique. */
  distinctSources: number;
  /** Distinct destination hosts touched. */
  distinctTargets: number;
  /** Distinct *internal* source IPs (an internal source is a compromise tell). */
  internalSources: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Worst severity seen for this technique. */
  severityMax: Severity;
  /** Severity-weighted score (Σ SEVERITY_WEIGHT) — the ranking key. */
  score: number;
  /** Blocked / passed / unknown disposition split. */
  disposition: DispositionSplit;
  /** The dominant signature for this technique, for context. */
  topSignature?: string;
  /** First/last time (ms epoch) this technique fired in the window. */
  firstSeenMs: number;
  lastSeenMs: number;
  /**
   * A control gap: medium-or-worse and mostly *passed* (let through). The
   * highest-value rows to verify enforcement on.
   */
  controlGap: boolean;
}

/** Per-tactic coverage roll-up. */
export interface MitreTactic {
  /** Tactic name. */
  tactic: Tactic;
  /** Canonical ATT&CK tactic ID (TA-code). */
  tacticId: string;
  /** Distinct techniques observed under this tactic. */
  techniqueCount: number;
  /** Total alerts under this tactic. */
  count: number;
  /** Share of all *mapped* alerts, 0..1 (4dp). */
  share: number;
  /** Distinct attacker source IPs across the tactic. */
  distinctSources: number;
  /** Distinct destination hosts across the tactic. */
  distinctTargets: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Worst severity seen across the tactic. */
  severityMax: Severity;
  /** Blocked / passed / unknown disposition split. */
  disposition: DispositionSplit;
  /** The busiest technique under this tactic (by alert volume). */
  topTechniqueId?: string;
  /** Name of {@link topTechniqueId}. */
  topTechniqueName?: string;
}

export interface MitreReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts mapped to an ATT&CK technique. */
  mappedAlerts: number;
  /** Of those, alerts that matched no rule (honest unmapped bucket). */
  unmappedAlerts: number;
  /** Distinct tactics observed. */
  tacticsObserved: number;
  /** Distinct techniques observed. */
  techniquesObserved: number;
  /** Per-tactic coverage, in canonical ATT&CK order (observed tactics only). */
  tactics: MitreTactic[];
  /** Per-technique detail, ranked by severity-weighted score (capped to limit). */
  techniques: MitreTechnique[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface MitreOptions {
  /** Max rows in the per-technique table (clamped to [1, 200]). */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 30;
const MS_PER_HOUR = 3_600_000;

// ----- classifiers / helpers (mirror scan.ts / killchain.ts) ----------------

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

function topOf(counts: Map<string, number>): string | undefined {
  let key: string | undefined;
  let count = 0;
  for (const [k, c] of counts) {
    if (c > count || (c === count && key !== undefined && k < key)) {
      key = k;
      count = c;
    }
  }
  return key;
}

/** A compact ASCII bar (8th-block glyphs) for the tactic coverage column. */
function bar(frac: number, width = 16): string {
  const filled = Math.max(0, Math.min(width, Math.round(frac * width)));
  return "█".repeat(filled) + "·".repeat(width - filled);
}

/**
 * Map a single alert to one ATT&CK technique by first-match-wins over its
 * combined classification + signature + category text. Returns undefined when no
 * rule matches (the alert lands in the honest unmapped bucket).
 */
export function mapTechnique(a: {
  classification?: string;
  signature?: string;
  category?: string;
}): TechniqueDef | undefined {
  const text = `${a.classification ?? ""} ${a.signature ?? ""} ${a.category ?? ""}`;
  if (!text.trim()) return undefined;
  for (const rule of RULES) {
    if (rule.re.test(text)) return TECHNIQUES[rule.technique];
  }
  return undefined;
}

// ----- aggregation ----------------------------------------------------------

interface TechAcc {
  count: number;
  score: number;
  severe: number;
  sources: Set<string>;
  internalSources: Set<string>;
  targets: Set<string>;
  blocked: number;
  passed: number;
  unknown: number;
  sigCounts: Map<string, number>;
  severityMax: Severity;
  firstSeenMs: number;
  lastSeenMs: number;
}

function newTechAcc(): TechAcc {
  return {
    count: 0,
    score: 0,
    severe: 0,
    sources: new Set(),
    internalSources: new Set(),
    targets: new Set(),
    blocked: 0,
    passed: 0,
    unknown: 0,
    sigCounts: new Map(),
    severityMax: "info",
    firstSeenMs: Number.POSITIVE_INFINITY,
    lastSeenMs: Number.NEGATIVE_INFINITY,
  };
}

interface TacticAcc {
  techniques: Set<string>;
  count: number;
  severe: number;
  sources: Set<string>;
  targets: Set<string>;
  blocked: number;
  passed: number;
  unknown: number;
  techCounts: Map<string, number>;
  severityMax: Severity;
}

function newTacticAcc(): TacticAcc {
  return {
    techniques: new Set(),
    count: 0,
    severe: 0,
    sources: new Set(),
    targets: new Set(),
    blocked: 0,
    passed: 0,
    unknown: 0,
    techCounts: new Map(),
    severityMax: "info",
  };
}

function dispOf(blocked: number, passed: number, unknown: number): DispositionSplit {
  const actioned = blocked + passed;
  return { blocked, passed, unknown, passRate: actioned ? round4(passed / actioned) : null };
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  m: { mappedAlerts: number; unmappedAlerts: number; totalWindowAlerts: number },
  tactics: MitreTactic[],
  techniques: MitreTechnique[],
): string[] {
  const out: string[] = [];
  if (!techniques.length) return out;

  out.push(
    `⚔️ Over the last ${hours}h, **${m.mappedAlerts} alert(s)** mapped to **${techniques.length} ATT&CK ` +
      `technique(s)** across **${tactics.length} tactic(s)**` +
      (m.unmappedAlerts ? ` (${m.unmappedAlerts} alert(s) matched no rule — see *unmapped*).` : `.`),
  );

  // The busiest tactic — where the bulk of observed adversary activity sits.
  const topTactic = [...tactics].sort((a, b) => b.count - a.count)[0]!;
  out.push(
    `📊 Busiest tactic is **${topTactic.tactic}** (${topTactic.tacticId}) — ${topTactic.count} alert(s), ` +
      `${pct(topTactic.share)} of mapped activity across ${topTactic.techniqueCount} technique(s), ` +
      `worst severity **${topTactic.severityMax}**.`,
  );

  // The single highest-scoring technique.
  const lead = techniques[0]!;
  out.push(
    `🎯 Top technique by severity-weighted score is **${lead.id} ${lead.name}** (${lead.tactic}) — ` +
      `${lead.count} alert(s), ${lead.distinctSources} source(s), worst **${lead.severityMax}**` +
      (lead.topSignature ? `; dominant signature \`${lead.topSignature}\`.` : `.`),
  );

  // Control gaps — severe techniques mostly let through.
  const gaps = techniques.filter((t) => t.controlGap);
  if (gaps.length) {
    const g = gaps[0]!;
    out.push(
      `🚩 **${gaps.length} control gap(s)** — medium-or-worse technique(s) mostly *detected, not blocked*. ` +
        `Worst: **${g.id} ${g.name}** is ${g.disposition.passRate === null ? "—" : pct(g.disposition.passRate)} ` +
        `let through (${g.disposition.passed} actioned alerts passed). Verify enforcement on this ATT&CK cell first.`,
    );
  }

  // Internal sources — an internal host *sourcing* a technique is a compromise tell.
  const insider = techniques.filter((t) => t.internalSources > 0).sort((a, b) => b.score - a.score)[0];
  if (insider) {
    out.push(
      `🚨 **${insider.internalSources} *internal* host(s)** are the **source** of **${insider.id} ${insider.name}** ` +
        `(${insider.tactic}) — an inside box evidencing this technique is a lateral-movement / compromise tell, not ` +
        `inbound noise. Investigate it ahead of external attackers.`,
    );
  }

  // Coverage honesty — how much of the stream mapped at all.
  if (m.totalWindowAlerts > 0) {
    const frac = m.mappedAlerts / m.totalWindowAlerts;
    if (frac < 0.5) {
      out.push(
        `ℹ️ Only **${pct(frac)} of windowed alerts mapped** to an ATT&CK technique — the rest carried no ` +
          `classtype/signature text a rule recognised. Coverage is a lower bound; an empty tactic means "not ` +
          `*alerted* on", not "did not happen".`,
      );
    }
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function tacticTable(rows: MitreTactic[]): string {
  return mdTable(
    ["Tactic", "ID", "Coverage", "Techniques", "Alerts", "Share", "Sources", "Hosts", "Severe", "Worst", "Blocked%", "Top technique"],
    rows.map((t) => {
      const actioned = t.disposition.blocked + t.disposition.passed;
      const blockRate = actioned ? `${Math.round((t.disposition.blocked / actioned) * 100)}%` : "—";
      return [
        cell(t.tactic),
        cell(t.tacticId),
        bar(t.share),
        String(t.techniqueCount),
        String(t.count),
        pct(t.share),
        String(t.distinctSources),
        String(t.distinctTargets),
        String(t.severe),
        cell(t.severityMax),
        blockRate,
        t.topTechniqueId ? cell(`${t.topTechniqueId} ${t.topTechniqueName ?? ""}`.trim()) : "—",
      ];
    }),
  );
}

function techniqueTable(rows: MitreTechnique[]): string {
  return mdTable(
    ["#", "Technique", "ID", "Tactic", "Alerts", "Sources", "Hosts", "Severe", "Worst", "Blocked", "Pass rate", "Top signature", "Flags"],
    rows.map((t, i) => {
      const flags = (t.internalSources ? "🏠" : "") + (t.controlGap ? "🚩" : "");
      return [
        String(i + 1),
        cell(t.name),
        cell(t.id),
        cell(t.tactic),
        String(t.count),
        String(t.distinctSources),
        String(t.distinctTargets),
        String(t.severe),
        cell(t.severityMax),
        String(t.disposition.blocked),
        t.disposition.passRate === null ? "—" : pct(t.disposition.passRate),
        cell(t.topSignature ?? "—"),
        flags || "—",
      ];
    }),
  );
}

function renderMarkdown(m: MitreReport): string {
  const lines: string[] = [];
  lines.push(`# ⚔️ SecTool MITRE ATT&CK Coverage Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** each alert mapped to one ATT&CK technique by a first-match heuristic over its ` +
      `\`classification\` / \`signature\` / \`category\` text, rolled up by tactic and technique · ` +
      `**Mapped:** ${m.mappedAlerts} of ${m.totalWindowAlerts} alert(s) (${m.unmappedAlerts} unmapped) → ` +
      `${m.techniquesObserved} technique(s) across ${m.tacticsObserved} tactic(s)`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.techniques.length) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to map.`);
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but none carried ` +
          `classtype / signature text that mapped to an ATT&CK technique.`,
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

  lines.push(`## Tactic coverage`);
  lines.push("");
  lines.push(`ATT&CK tactics in canonical order, observed cells only. The coverage bar is each tactic's share of mapped alerts.`);
  lines.push("");
  lines.push(tacticTable(m.tactics));
  lines.push("");

  lines.push(`## Techniques by severity-weighted attention`);
  lines.push("");
  lines.push(techniqueTable(m.techniques));
  lines.push("");
  lines.push(
    `**Legend:** ranked by severity-weighted score so a small but dangerous technique outranks a flood of low-severity ` +
      `noise. _Pass rate_ = share of *actioned* (blocked + passed) alerts let through. **Flags:** 🏠 an *internal* host ` +
      `is the source of the technique (compromise / lateral-movement tell) · 🚩 control gap (medium-or-worse but mostly ` +
      `detected, not blocked).`,
  );
  lines.push("");

  if (m.unmappedAlerts) {
    lines.push(
      `> **Unmapped:** ${m.unmappedAlerts} alert(s) (${pct(m.unmappedAlerts / Math.max(1, m.totalWindowAlerts))} of the ` +
        `window) matched no rule and are excluded from the tables above — counted here so coverage is never overstated.`,
    );
    lines.push("");
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. ATT&CK mapping is a **heuristic** over free-text Suricata fields, not a curated ` +
      `rule→technique table — a strong triage hint, not an authored mapping. To keep the coverage math clean each alert ` +
      `is attributed to a **single** best-match technique (a real ATT&CK mapping is often many-to-one); everything that ` +
      `matched no rule is counted in the **unmapped** bucket, never silently dropped. These are IPS **detections**, not ` +
      `full telemetry — a technique used without tripping a signature is invisible, so coverage is a lower bound and an ` +
      `empty tactic means "not *alerted* on", not "did not happen". A long look-back can hit the store's history cap and ` +
      `undercount. No SSH, no Claude, no live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the MITRE ATT&CK coverage report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link MitreOptions}: `limit` and a `nowMs` pin for tests.
 */
export function buildMitre(hours: number, opts: MitreOptions = {}): MitreReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const techAccs = new Map<string, TechAcc>();
  const tacticAccs = new Map<Tactic, TacticAcc>();
  let mapped = 0;
  let unmapped = 0;

  for (const a of windowed) {
    const def = mapTechnique(a);
    if (!def) {
      unmapped++;
      continue;
    }
    mapped++;

    const src = validIp(a.srcIp);
    const dst = validIp(a.dstIp);
    const disp = classifyDisposition(a.action);

    // --- technique accumulator ---
    const tacc = techAccs.get(def.id) ?? newTechAcc();
    if (!techAccs.has(def.id)) techAccs.set(def.id, tacc);
    tacc.count++;
    tacc.score += weightOf(a.severity);
    tacc.severityMax = maxSeverity(tacc.severityMax, a.severity);
    if (isSevere(a.severity)) tacc.severe++;
    if (src) {
      tacc.sources.add(src);
      if (isPrivate(src)) tacc.internalSources.add(src);
    }
    if (dst) tacc.targets.add(dst);
    if (a.signature) tacc.sigCounts.set(a.signature, (tacc.sigCounts.get(a.signature) ?? 0) + 1);
    if (disp === "blocked") tacc.blocked++;
    else if (disp === "passed") tacc.passed++;
    else tacc.unknown++;
    if (a.time < tacc.firstSeenMs) tacc.firstSeenMs = a.time;
    if (a.time > tacc.lastSeenMs) tacc.lastSeenMs = a.time;

    // --- tactic accumulator ---
    const cacc = tacticAccs.get(def.tactic) ?? newTacticAcc();
    if (!tacticAccs.has(def.tactic)) tacticAccs.set(def.tactic, cacc);
    cacc.techniques.add(def.id);
    cacc.count++;
    cacc.severityMax = maxSeverity(cacc.severityMax, a.severity);
    if (isSevere(a.severity)) cacc.severe++;
    if (src) cacc.sources.add(src);
    if (dst) cacc.targets.add(dst);
    cacc.techCounts.set(def.id, (cacc.techCounts.get(def.id) ?? 0) + 1);
    if (disp === "blocked") cacc.blocked++;
    else if (disp === "passed") cacc.passed++;
    else cacc.unknown++;
  }

  const mappedSafe = Math.max(1, mapped);

  // Per-technique rows, ranked by severity-weighted score then volume.
  const techniques: MitreTechnique[] = [...techAccs.entries()]
    .map(([id, acc]) => {
      const def = TECHNIQUES[id]!;
      const passRate = acc.blocked + acc.passed ? round4(acc.passed / (acc.blocked + acc.passed)) : null;
      const controlGap = isSevere(acc.severityMax) && passRate !== null && passRate >= 0.5 && acc.passed >= 2;
      return {
        id,
        name: def.name,
        tactic: def.tactic,
        count: acc.count,
        share: round4(acc.count / mappedSafe),
        distinctSources: acc.sources.size,
        distinctTargets: acc.targets.size,
        internalSources: acc.internalSources.size,
        severe: acc.severe,
        severityMax: acc.severityMax,
        score: acc.score,
        disposition: dispOf(acc.blocked, acc.passed, acc.unknown),
        topSignature: topOf(acc.sigCounts),
        firstSeenMs: Number.isFinite(acc.firstSeenMs) ? acc.firstSeenMs : windowStartMs,
        lastSeenMs: Number.isFinite(acc.lastSeenMs) ? acc.lastSeenMs : windowEndMs,
        controlGap,
      } satisfies MitreTechnique;
    })
    .sort(
      (x, y) =>
        y.score - x.score ||
        y.count - x.count ||
        (x.id < y.id ? -1 : x.id > y.id ? 1 : 0),
    );

  // Per-tactic rows, emitted in canonical ATT&CK order (observed only).
  const tactics: MitreTactic[] = ATTACK_TACTICS.filter((t) => tacticAccs.has(t)).map((t) => {
    const acc = tacticAccs.get(t)!;
    const topTechniqueId = topOf(acc.techCounts);
    return {
      tactic: t,
      tacticId: TACTIC_IDS[t],
      techniqueCount: acc.techniques.size,
      count: acc.count,
      share: round4(acc.count / mappedSafe),
      distinctSources: acc.sources.size,
      distinctTargets: acc.targets.size,
      severe: acc.severe,
      severityMax: acc.severityMax,
      disposition: dispOf(acc.blocked, acc.passed, acc.unknown),
      topTechniqueId,
      topTechniqueName: topTechniqueId ? TECHNIQUES[topTechniqueId]?.name : undefined,
    } satisfies MitreTactic;
  });

  const cappedTechniques = techniques.slice(0, limit);

  const highlights = writeHighlights(
    safeHours,
    { mappedAlerts: mapped, unmappedAlerts: unmapped, totalWindowAlerts: windowed.length },
    tactics,
    cappedTechniques,
  );

  const model: MitreReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    mappedAlerts: mapped,
    unmappedAlerts: unmapped,
    tacticsObserved: tactics.length,
    techniquesObserved: techniques.length,
    tactics,
    techniques: cappedTechniques,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded MITRE ATT&CK report. */
export function mitreFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-mitre-${stamp}.md`;
}
