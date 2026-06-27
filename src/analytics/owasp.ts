/**
 * OWASP Top 10 (2021) coverage report — "which of the **ten industry-standard web
 * risk categories** is my perimeter actually being probed for, how serious is each,
 * and which categories are getting through unblocked?"
 *
 * SecTool already maps the alert stream onto two security taxonomies: `mitre`
 * (adversary *behaviour* — ATT&CK tactics/techniques) and `cwe` (software
 * *weakness classes* — SQLi, traversal, overflow…). Both are practitioner
 * frameworks. Neither speaks the **third** language every AppSec program, pen-test
 * report, compliance questionnaire and secure-SDLC review is written in: the
 * **OWASP Top 10**. A board slide, a SOC 2 / PCI narrative or a developer ticket
 * does not ask "how much CWE-89 did we see" — it asks "are we exposed to **A03
 * Injection**?" This report answers exactly that, in OWASP's own vocabulary, so
 * the IPS history drops straight into an OWASP-aligned risk register without a
 * human re-mapping it by hand.
 *
 * It mirrors the proven shape of `cwe` / `mitre`: every windowed alert is mapped,
 * by an ordered first-match-wins heuristic over its `classification` / `signature`
 * / `category` text, onto **one** OWASP 2021 category. The mapping honours the
 * official 2021 CWE→category groupings, which moved several familiar classes:
 *
 *   - **A01 Broken Access Control** — path traversal, IDOR, missing authorization,
 *     forced browsing, open redirect, **and sensitive-information exposure**
 *     (CWE-200 sits under A01 in 2021).
 *   - **A02 Cryptographic Failures** — cleartext transmission, weak/deprecated
 *     TLS/SSL, plaintext credentials.
 *   - **A03 Injection** — SQLi, **XSS** (folded into Injection in 2021), OS-command
 *     and code injection, file inclusion (LFI/RFI), template/expression injection,
 *     generic remote code execution.
 *   - **A04 Insecure Design** — unrestricted file upload / web-shell drop, improper
 *     privilege management.
 *   - **A05 Security Misconfiguration** — **XXE** (moved here in 2021), default
 *     config, directory listing, exposed admin/config surface.
 *   - **A06 Vulnerable and Outdated Components** — named-CVE exploits against known
 *     products (Struts, Log4j-adjacent, Confluence, Citrix, Exchange…), the
 *     "patch-your-stack" bucket.
 *   - **A07 Identification and Authentication Failures** — brute force, credential
 *     stuffing, auth bypass, default/weak credentials.
 *   - **A08 Software and Data Integrity Failures** — insecure deserialization,
 *     untrusted-update / supply-chain integrity.
 *   - **A10 Server-Side Request Forgery (SSRF)**.
 *
 * (**A09 Security Logging & Monitoring Failures** is a defensive-process gap with no
 * network-observable exploit signature, so it legitimately never maps from IPS
 * telemetry — its absence is expected, not a miss.)
 *
 * For each observed category it rolls up, purely from stored history: alert volume
 * and its share of mapped activity, distinct attacker sources and internal sources
 * (an internal host *probing* a category is a pivot tell), distinct targets,
 * severity-weighted attention score, worst severity, the blocked/passed/unknown
 * **enforcement split** (a severe category mostly *let through* is the control gap
 * the report exists to float), the dominant signatures, and a durable,
 * category-level remediation hint — the fix for the *class*, not one bug.
 *
 * Honest caveats baked into the output:
 *
 *   - **Heuristic, not an authored map.** It greps free-text Suricata fields; a
 *     signature that detects a category without naming it is invisible, and a
 *     mis-named rule can mis-bucket. A strong triage hint, not a certified mapping.
 *   - **Single best-match.** Each alert maps to exactly one category (most-specific
 *     rule wins); everything matching no rule lands in the honest **unmapped**
 *     bucket — recon, scanning, C2 and policy chatter exercise no OWASP web risk
 *     and are never silently dropped.
 *   - **Targeted ≠ vulnerable.** A category here means the *exploit pattern was seen
 *     on the wire*, not that an asset is vulnerable or was breached. It is exposure
 *     pressure for prioritisation, not a vulnerability-scan result — pair it with
 *     the `cve` patch worklist and `cwe` weakness view.
 *   - **Window-bounded & store-capped.** A long look-back can hit the store's
 *     history cap and undercount.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network. Output is
 * both a structured model and a ready-to-paste Markdown document, mirroring
 * cwe.ts, mitre.ts, classify.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/**
 * The ten OWASP Top 10 (2021) category IDs, in canonical order. The report only
 * renders categories actually observed, but this order is authoritative for
 * display so the matrix always reads A01 → A10 the way an AppSec reviewer expects.
 */
export const OWASP_CATEGORIES = [
  "A01:2021",
  "A02:2021",
  "A03:2021",
  "A04:2021",
  "A05:2021",
  "A06:2021",
  "A07:2021",
  "A08:2021",
  "A09:2021",
  "A10:2021",
] as const;

export type OwaspId = (typeof OWASP_CATEGORIES)[number];

/** Static metadata for one OWASP Top 10 (2021) category. */
export interface OwaspDef {
  /** Category id, e.g. "A03:2021". */
  id: OwaspId;
  /** Official category name. */
  name: string;
  /** Short display label for narrow table cells. */
  short: string;
  /** One-line description of what the category covers. */
  blurb: string;
  /** Durable remediation hint — what fixes the *class*, not one bug. */
  fix: string;
}

/** The OWASP Top 10 (2021) catalog this report attributes alerts to. */
export const OWASP_CATALOG: Record<OwaspId, OwaspDef> = {
  "A01:2021": {
    id: "A01:2021",
    name: "Broken Access Control",
    short: "Access Control",
    blurb: "Path traversal, IDOR, missing authorization, forced browsing, open redirect and sensitive-info exposure.",
    fix: "deny-by-default authorization, server-side access checks, canonicalise & allow-list paths",
  },
  "A02:2021": {
    id: "A02:2021",
    name: "Cryptographic Failures",
    short: "Crypto Failures",
    blurb: "Cleartext transmission, weak / deprecated TLS-SSL, plaintext credentials.",
    fix: "force modern TLS, retire cleartext protocols and weak ciphers, encrypt data in transit",
  },
  "A03:2021": {
    id: "A03:2021",
    name: "Injection",
    short: "Injection",
    blurb: "SQLi, XSS, OS-command / code injection, file inclusion (LFI/RFI), template injection, RCE.",
    fix: "parameterise queries, encode output, validate input, deploy a WAF injection ruleset",
  },
  "A04:2021": {
    id: "A04:2021",
    name: "Insecure Design",
    short: "Insecure Design",
    blurb: "Unrestricted file upload / web-shell drop, improper privilege management.",
    fix: "validate & sandbox uploads, threat-model the flow, enforce least privilege by design",
  },
  "A05:2021": {
    id: "A05:2021",
    name: "Security Misconfiguration",
    short: "Misconfiguration",
    blurb: "XXE, default configuration, directory listing, exposed admin / config surface.",
    fix: "harden defaults, disable XML external entities, remove debug/admin endpoints",
  },
  "A06:2021": {
    id: "A06:2021",
    name: "Vulnerable and Outdated Components",
    short: "Vuln Components",
    blurb: "Named-CVE exploits against known products (Struts, Confluence, Citrix, Exchange…).",
    fix: "patch / upgrade the affected component, retire end-of-life software, virtual-patch at the WAF",
  },
  "A07:2021": {
    id: "A07:2021",
    name: "Identification and Authentication Failures",
    short: "Auth Failures",
    blurb: "Brute force, credential stuffing, auth bypass, default / weak credentials.",
    fix: "rate-limit & lock out auth, enforce MFA, ban default/weak credentials",
  },
  "A08:2021": {
    id: "A08:2021",
    name: "Software and Data Integrity Failures",
    short: "Integrity Failures",
    blurb: "Insecure deserialization, untrusted-update / supply-chain integrity.",
    fix: "avoid native deserialization, verify update signatures, pin & verify dependencies",
  },
  "A09:2021": {
    id: "A09:2021",
    name: "Security Logging and Monitoring Failures",
    short: "Logging Failures",
    blurb: "A defensive-process gap with no network-observable exploit signature.",
    fix: "centralise logging, alert on auth/integrity events, test detection coverage",
  },
  "A10:2021": {
    id: "A10:2021",
    name: "Server-Side Request Forgery (SSRF)",
    short: "SSRF",
    blurb: "Coercing the server into making attacker-controlled outbound requests.",
    fix: "allow-list egress destinations, block internal-metadata IPs, validate & pin URLs",
  },
};

/**
 * Ordered mapping rules: the first whose pattern matches the alert's combined
 * `classification + signature + category` text wins. Order is most-specific →
 * least-specific so a precise category (e.g. "sql injection" → A03) beats the
 * broad "vulnerable component" catch-all (A06). The CWE→category groupings follow
 * the official OWASP Top 10 (2021) lists. Patterns match case-insensitively.
 */
const RULES: Array<{ cat: OwaspId; re: RegExp }> = [
  // --- A10 SSRF (very specific) ---
  { cat: "A10:2021", re: /\bssrf\b|server.?side request forgery/i },
  // --- A08 Integrity — deserialization / untrusted update / supply chain ---
  { cat: "A08:2021", re: /deserializ|object injection|\bognl\b|java.*serial|insecure deserialization|unsigned (update|code|firmware)|supply.?chain/i },
  // --- A05 XXE (moved into Security Misconfiguration in 2021) ---
  { cat: "A05:2021", re: /\bxxe\b|xml external entit|external entity/i },
  // --- A03 Injection — the specific web-injection classes (XSS folded in here) ---
  { cat: "A03:2021", re: /sql.?injection|\bsqli\b|union\s+select|sql\b.*\b(inject|attack)/i },
  { cat: "A03:2021", re: /\bxss\b|cross.?site scripting|script injection/i },
  { cat: "A03:2021", re: /os command|command injection|shell (injection|command)|\bcmd\b injection/i },
  { cat: "A03:2021", re: /file inclusion|\blfi\b|\brfi\b|remote file include|local file include/i },
  { cat: "A03:2021", re: /\bssti\b|template injection|server.?side template|expression language|\beval\b|code injection|code execution|\brce\b|remote code execution/i },
  // --- A01 Broken Access Control — traversal, authz, exposure (CWE-200 → A01) ---
  { cat: "A01:2021", re: /directory traversal|path traversal|\.\.[\\/]|dot.?dot.?slash|\btraversal\b/i },
  { cat: "A01:2021", re: /authorization bypass|missing authorization|broken access control|\bidor\b|insecure direct object|forced browsing|access control/i },
  { cat: "A01:2021", re: /open redirect|directory listing|backup file|\.git\b|\.env\b|information (leak|disclosure|exposure)|info leak|sensitive (data|information)/i },
  // --- A07 Identification & Authentication Failures ---
  { cat: "A07:2021", re: /brute.?force|password (guess|spray)|credential stuffing|excessive login|login attempt|auth.*\bfail|authentication (bypass|fail)|auth bypass|\bhydra\b|default (password|credential)|weak (password|credential)|hardcoded (password|credential)/i },
  // --- A02 Cryptographic Failures ---
  { cat: "A02:2021", re: /cleartext|plaintext (password|credential)|unencrypted|weak (cipher|tls|ssl|crypto)|deprecated tls|sslv[23]|\bpoodle\b|\bbeast\b|self.?signed (cert|certificate)/i },
  // --- A04 Insecure Design — upload / web-shell, privilege management ---
  { cat: "A04:2021", re: /file upload|unrestricted upload|web.?shell|upload.*\b(shell|asp|php|jsp)\b|privilege (gain|escalation)|priv.?esc|elevation of privilege/i },
  // --- A05 Security Misconfiguration (broad config issues, after XXE above) ---
  { cat: "A05:2021", re: /misconfigurat|default (config|configuration|install|page|account)|exposed (admin|console|dashboard|panel)|debug mode|test page/i },
  // --- A06 Vulnerable & Outdated Components — broad known-CVE / product exploit catch-all (last) ---
  { cat: "A06:2021", re: /\bCVE-\d{4}-\d{3,}|outdated|end.?of.?life|\beol\b|vulnerable component|known vulnerabilit|exploit kit|\bet exploit\b|struts|drupalgeddon|shellshock|eternalblue|bluekeep|spring4shell|log4j|log4shell|proxyshell|proxylogon|\bjboss\b|weblogic|\bconfluence\b|\bcitrix\b|forti(net|os|gate)|\bvmware\b|heartbleed|ghostcat/i },
];

/** Blocked / passed / unknown disposition split for a category. */
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
   * category is the control gap worth verifying (or virtual-patching) first.
   */
  passRate: number | null;
}

/** Per-OWASP-category roll-up over the window. */
export interface OwaspCategory {
  /** Category id, e.g. "A03:2021". */
  id: OwaspId;
  /** Official category name. */
  name: string;
  /** One-line description. */
  blurb: string;
  /** Durable remediation hint. */
  fix: string;
  /** Total alerts attributed to this category. */
  count: number;
  /** Share of all *mapped* alerts, 0..1 (4dp). */
  share: number;
  /** Distinct attacker source IPs probing this category. */
  distinctSources: number;
  /** Distinct destination hosts touched. */
  distinctTargets: number;
  /** Distinct *internal* source IPs (an internal source is a compromise tell). */
  internalSources: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Worst severity seen for this category. */
  severityMax: Severity;
  /** Severity-weighted score (Σ SEVERITY_WEIGHT) — the ranking key. */
  score: number;
  /** Blocked / passed / unknown disposition split. */
  disposition: DispositionSplit;
  /** Up to three dominant signatures for this category, busiest first. */
  topSignatures: string[];
  /** First/last time (ms epoch) this category fired in the window. */
  firstSeenMs: number;
  lastSeenMs: number;
  /**
   * A control gap: medium-or-worse and mostly *passed* (let through). The
   * highest-value categories to verify enforcement / virtual-patch on.
   */
  controlGap: boolean;
}

export interface OwaspReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts mapped to an OWASP category. */
  mappedAlerts: number;
  /** Of those, alerts that matched no rule (honest unmapped bucket). */
  unmappedAlerts: number;
  /** Distinct OWASP categories observed (of the ten). */
  categoriesObserved: number;
  /** Per-category roll-up, in canonical A01 → A10 order (observed only). */
  categories: OwaspCategory[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface OwaspOptions {
  /** Max dominant signatures listed per category (clamped to [1, 10]). */
  topSignatures?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_TOP_SIGNATURES = 3;
const MS_PER_HOUR = 3_600_000;

// ----- classifiers / helpers (mirror cwe.ts / mitre.ts) ----------------------

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

function clip(s: string, max = 48): string {
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

/** The N busiest keys of a count map, ties broken lexicographically. */
function topKeys(counts: Map<string, number>, n: number): string[] {
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .slice(0, n)
    .map(([k]) => k);
}

/** A compact ASCII bar (8th-block glyphs) for the coverage column. */
function bar(frac: number, width = 16): string {
  const filled = Math.max(0, Math.min(width, Math.round(frac * width)));
  return "█".repeat(filled) + "·".repeat(width - filled);
}

/**
 * Map a single alert to one OWASP Top 10 (2021) category by first-match-wins over
 * its combined classification + signature + category text. Returns undefined when
 * no rule matches (the alert lands in the honest unmapped bucket — recon, C2 and
 * scanning legitimately exercise no OWASP web risk).
 */
export function mapOwasp(a: {
  classification?: string;
  signature?: string;
  category?: string;
}): OwaspDef | undefined {
  const text = `${a.classification ?? ""} ${a.signature ?? ""} ${a.category ?? ""}`;
  if (!text.trim()) return undefined;
  for (const rule of RULES) {
    if (rule.re.test(text)) return OWASP_CATALOG[rule.cat];
  }
  return undefined;
}

// ----- aggregation -----------------------------------------------------------

interface CatAcc {
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

function newCatAcc(): CatAcc {
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

function dispOf(blocked: number, passed: number, unknown: number): DispositionSplit {
  const actioned = blocked + passed;
  return { blocked, passed, unknown, passRate: actioned ? round4(passed / actioned) : null };
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(
  hours: number,
  m: { mappedAlerts: number; unmappedAlerts: number; totalWindowAlerts: number },
  categories: OwaspCategory[],
): string[] {
  const out: string[] = [];
  if (!categories.length) return out;

  out.push(
    `🔟 Over the last ${hours}h, **${m.mappedAlerts} alert(s)** mapped to **${categories.length} of the ten ` +
      `OWASP Top 10 (2021) categories**` +
      (m.unmappedAlerts ? ` (${m.unmappedAlerts} alert(s) exercised no OWASP web risk — see *unmapped*).` : `.`),
  );

  // The most-probed category by volume — where the web-attack pressure sits.
  const byVolume = [...categories].sort((a, b) => b.count - a.count)[0]!;
  out.push(
    `📊 Most-probed category is **${byVolume.id} ${byVolume.name}** — ${byVolume.count} alert(s), ` +
      `${pct(byVolume.share)} of mapped activity, ${byVolume.distinctSources} source(s), worst severity ` +
      `**${byVolume.severityMax}**. Durable fix: _${byVolume.fix}_.`,
  );

  // The highest-scoring category by severity-weighted attention (may differ).
  const byScore = [...categories].sort((a, b) => b.score - a.score)[0]!;
  if (byScore.id !== byVolume.id) {
    out.push(
      `🎯 By severity-weighted attention the leader is **${byScore.id} ${byScore.name}** — fewer alerts ` +
        `(${byScore.count}) but nastier (worst **${byScore.severityMax}**). Triage this ahead of raw volume.`,
    );
  }

  // Control gaps — severe categories mostly let through unblocked.
  const gaps = categories.filter((c) => c.controlGap).sort((a, b) => b.score - a.score);
  if (gaps.length) {
    const g = gaps[0]!;
    out.push(
      `🚩 **${gaps.length} control gap(s)** — medium-or-worse OWASP categor(y/ies) mostly *detected, not blocked*. ` +
        `Worst: **${g.id} ${g.name}** is ${g.disposition.passRate === null ? "—" : pct(g.disposition.passRate)} ` +
        `let through (${g.disposition.passed} actioned alerts passed). Verify the IPS policy or virtual-patch this ` +
        `category first.`,
    );
  }

  // Internal sources — an internal host *probing* a category is a pivot tell.
  const insider = categories.filter((c) => c.internalSources > 0).sort((a, b) => b.score - a.score)[0];
  if (insider) {
    out.push(
      `🚨 **${insider.internalSources} *internal* host(s)** are the **source** of **${insider.id} ${insider.name}** ` +
        `attempts — an inside box exercising an OWASP attack is a lateral-movement / compromise tell, not inbound ` +
        `noise. Investigate it ahead of external attackers.`,
    );
  }

  // Coverage honesty — how much of the stream exercised an OWASP risk at all.
  if (m.totalWindowAlerts > 0) {
    const frac = m.mappedAlerts / m.totalWindowAlerts;
    out.push(
      `ℹ️ **${pct(frac)} of windowed alerts** mapped to an OWASP web risk; the rest is behaviour (recon, scanning, ` +
        `C2, policy) that exercises no Top 10 category — that is expected, not a parsing miss. Coverage here is ` +
        `*exposure pressure*, not a confirmed vulnerability; pair it with the \`cve\` and \`cwe\` reports.`,
    );
  }

  return out;
}

// ----- markdown --------------------------------------------------------------

function matrixTable(rows: OwaspCategory[]): string {
  return mdTable(
    ["OWASP", "Category", "Coverage", "Alerts", "Share", "Sources", "Hosts", "Severe", "Worst", "Blocked%", "Flags"],
    rows.map((c) => {
      const actioned = c.disposition.blocked + c.disposition.passed;
      const blockRate = actioned ? `${Math.round((c.disposition.blocked / actioned) * 100)}%` : "—";
      const flags = (c.internalSources ? "🏠" : "") + (c.controlGap ? "🚩" : "");
      return [
        cell(c.id),
        cell(c.name),
        bar(c.share),
        String(c.count),
        pct(c.share),
        String(c.distinctSources),
        String(c.distinctTargets),
        String(c.severe),
        cell(c.severityMax),
        blockRate,
        flags || "—",
      ];
    }),
  );
}

function renderMarkdown(m: OwaspReport): string {
  const lines: string[] = [];
  lines.push(`# 🔟 SecTool OWASP Top 10 (2021) Coverage Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** each alert mapped to one OWASP Top 10 (2021) category by a first-match heuristic over its ` +
      `\`classification\` / \`signature\` / \`category\` text, using the official 2021 CWE→category groupings · ` +
      `**Mapped:** ${m.mappedAlerts} of ${m.totalWindowAlerts} alert(s) (${m.unmappedAlerts} unmapped) → ` +
      `${m.categoriesObserved} of 10 categor(y/ies)`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.categories.length) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to map.`);
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but none carried classtype / signature ` +
          `text that maps to an OWASP Top 10 category. On most edges the stream is dominated by recon, scanning ` +
          `and C2 behaviour, which exercise no web-application risk — see the \`mitre\` report for that axis.`,
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

  lines.push(`## Top 10 coverage matrix`);
  lines.push("");
  lines.push(
    `OWASP categories in canonical order, observed rows only. The coverage bar is each category's share of mapped ` +
      `alerts; **Blocked%** is the share of *actioned* alerts the gateway dropped.`,
  );
  lines.push("");
  lines.push(matrixTable(m.categories));
  lines.push("");
  lines.push(
    `**Flags:** 🏠 an *internal* host is the source of the attempt (compromise / pivot tell) · 🚩 control gap ` +
      `(medium-or-worse but mostly detected, not blocked — a virtual-patch candidate).`,
  );
  lines.push("");

  // Per-category detail, ranked by severity-weighted attention.
  lines.push(`## Category detail (by severity-weighted attention)`);
  lines.push("");
  const ranked = [...m.categories].sort(
    (a, b) => b.score - a.score || b.count - a.count || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
  );
  for (const c of ranked) {
    const pr = c.disposition.passRate;
    lines.push(`### ${c.id} ${c.name}${c.controlGap ? " 🚩" : ""}${c.internalSources ? " 🏠" : ""}`);
    lines.push("");
    lines.push(`_${c.blurb}_`);
    lines.push("");
    lines.push(
      `- **Volume:** ${c.count} alert(s) (${pct(c.share)} of mapped) · worst severity **${c.severityMax}** · ` +
        `${c.severe} medium-or-worse`,
    );
    lines.push(
      `- **Breadth:** ${c.distinctSources} source(s)` +
        (c.internalSources ? ` (incl. **${c.internalSources} internal**)` : ``) +
        ` → ${c.distinctTargets} target host(s)`,
    );
    lines.push(
      `- **Enforcement:** ${c.disposition.blocked} blocked · ${c.disposition.passed} passed · ` +
        `${c.disposition.unknown} unknown` +
        (pr === null ? `` : ` · **${pct(pr)} of actioned let through**`) +
        (c.controlGap ? ` — ⚠️ control gap` : ``),
    );
    lines.push(`- **First → last seen:** ${fmtTime(c.firstSeenMs)} → ${fmtTime(c.lastSeenMs)}`);
    if (c.topSignatures.length) {
      lines.push(`- **Top signatures:** ${c.topSignatures.map((s) => `\`${clip(s)}\``).join(" · ")}`);
    }
    lines.push(`- **Durable fix:** _${c.fix}_`);
    lines.push("");
  }

  if (m.unmappedAlerts) {
    lines.push(
      `> **Unmapped:** ${m.unmappedAlerts} alert(s) (${pct(m.unmappedAlerts / Math.max(1, m.totalWindowAlerts))} of the ` +
        `window) exercised no OWASP web risk — recon, scanning, C2 and policy chatter — and are excluded from the ` +
        `tables above. Counted here so coverage is never overstated; for the *behaviour* of that traffic see the ` +
        `\`mitre\` and \`classify\` reports. **A09 Logging & Monitoring Failures** has no network-observable ` +
        `signature and so never maps from IPS telemetry — its absence is expected.`,
    );
    lines.push("");
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. OWASP mapping is a **heuristic** over free-text Suricata fields, not a curated ` +
      `rule→OWASP table — a strong triage hint, not an authored mapping. Each alert is attributed to a **single** ` +
      `best-match category (most-specific rule wins); everything matching no rule is counted in the **unmapped** ` +
      `bucket, never silently dropped. A category here means the web risk was **targeted**, not that the asset is ` +
      `**vulnerable** — this is exposure pressure, not a vulnerability scan; pair it with the \`cve\` patch worklist, ` +
      `the \`cwe\` weakness view and the \`mitre\` behaviour view. These are IPS **detections**, not full telemetry, ` +
      `so coverage is a lower bound. A long look-back can hit the store's history cap and undercount. No SSH, no ` +
      `Claude, no live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the OWASP Top 10 (2021) coverage report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link OwaspOptions}: `topSignatures` and a `nowMs` pin for tests.
 */
export function buildOwasp(hours: number, opts: OwaspOptions = {}): OwaspReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const topSigN = Math.max(1, Math.min(10, Math.floor(opts.topSignatures ?? DEFAULT_TOP_SIGNATURES)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const accs = new Map<OwaspId, CatAcc>();
  let mapped = 0;
  let unmapped = 0;

  for (const a of windowed) {
    const def = mapOwasp(a);
    if (!def) {
      unmapped++;
      continue;
    }
    mapped++;

    const src = validIp(a.srcIp);
    const dst = validIp(a.dstIp);
    const disp = classifyDisposition(a.action);

    const acc = accs.get(def.id) ?? newCatAcc();
    if (!accs.has(def.id)) accs.set(def.id, acc);
    acc.count++;
    acc.score += weightOf(a.severity);
    acc.severityMax = maxSeverity(acc.severityMax, a.severity);
    if (isSevere(a.severity)) acc.severe++;
    if (src) {
      acc.sources.add(src);
      if (isPrivate(src)) acc.internalSources.add(src);
    }
    if (dst) acc.targets.add(dst);
    if (a.signature) acc.sigCounts.set(a.signature, (acc.sigCounts.get(a.signature) ?? 0) + 1);
    if (disp === "blocked") acc.blocked++;
    else if (disp === "passed") acc.passed++;
    else acc.unknown++;
    if (a.time < acc.firstSeenMs) acc.firstSeenMs = a.time;
    if (a.time > acc.lastSeenMs) acc.lastSeenMs = a.time;
  }

  const mappedSafe = Math.max(1, mapped);

  // Per-category rows, emitted in canonical A01 → A10 order (observed only).
  const categories: OwaspCategory[] = OWASP_CATEGORIES.filter((id) => accs.has(id)).map((id) => {
    const acc = accs.get(id)!;
    const def = OWASP_CATALOG[id];
    const passRate = acc.blocked + acc.passed ? round4(acc.passed / (acc.blocked + acc.passed)) : null;
    const controlGap = isSevere(acc.severityMax) && passRate !== null && passRate >= 0.5 && acc.passed >= 2;
    return {
      id,
      name: def.name,
      blurb: def.blurb,
      fix: def.fix,
      count: acc.count,
      share: round4(acc.count / mappedSafe),
      distinctSources: acc.sources.size,
      distinctTargets: acc.targets.size,
      internalSources: acc.internalSources.size,
      severe: acc.severe,
      severityMax: acc.severityMax,
      score: acc.score,
      disposition: dispOf(acc.blocked, acc.passed, acc.unknown),
      topSignatures: topKeys(acc.sigCounts, topSigN),
      firstSeenMs: Number.isFinite(acc.firstSeenMs) ? acc.firstSeenMs : windowStartMs,
      lastSeenMs: Number.isFinite(acc.lastSeenMs) ? acc.lastSeenMs : windowEndMs,
      controlGap,
    } satisfies OwaspCategory;
  });

  const highlights = writeHighlights(
    safeHours,
    { mappedAlerts: mapped, unmappedAlerts: unmapped, totalWindowAlerts: windowed.length },
    categories,
  );

  const model: OwaspReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    mappedAlerts: mapped,
    unmappedAlerts: unmapped,
    categoriesObserved: categories.length,
    categories,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded OWASP Top 10 report. */
export function owaspFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-owasp-${stamp}.md`;
}
