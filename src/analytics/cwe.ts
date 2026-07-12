/**
 * CWE weakness-class coverage report — "expressed in the *vulnerability*
 * taxonomy my AppSec team, my scanner and my secure-coding standard already
 * speak: which classes of software **weakness** is my attack surface being
 * probed and exploited for?"
 *
 * This is the third leg of SecTool's standards-mapping trio, and it is
 * deliberately orthogonal to the other two — confusing them defeats the point:
 *
 *   - **cve.ts** maps signatures to **specific CVE identifiers** — individual,
 *     already-patched vulnerabilities. Its payload is a *patch worklist*: "this
 *     exact bug, in this exact product, has a fix — apply it."
 *   - **mitre.ts** maps alerts to **ATT&CK techniques** — adversary *behaviour*
 *     (how the attacker operates: scan, brute-force, exfiltrate). Its payload is
 *     a *detection-coverage matrix*.
 *   - **This report** maps alerts to **CWE weakness classes** (MITRE's Common
 *     Weakness Enumeration) — the *category of software flaw* the traffic is
 *     trying to exercise: SQL injection (CWE-89), path traversal (CWE-22), a
 *     memory-safety overflow (CWE-787), broken authentication (CWE-287)…
 *
 * The distinction is the value. A CVE tells you to patch *one* bug; a CWE tells
 * you a *whole class* of bug is being hunted on your edge, which drives durable
 * hardening that no single patch delivers — a WAF ruleset for injection, input
 * validation for traversal, an auth-rate limit for credential abuse, compiler
 * mitigations for memory safety. It is the language an OWASP-aligned AppSec
 * program, a SAST/DAST report and a secure-development lifecycle all share, so
 * this view drops straight into a vulnerability-management or hardening review.
 *
 * For the chosen window every stored alert is mapped to **one** CWE by a
 * first-match-wins heuristic ({@link mapWeakness}) over its Suricata
 * **classification** (classtype), **signature** and **category** text — the same
 * fields the live detector and mitre.ts already key off. The result is rolled up
 * two ways:
 *
 *   1. **Weakness-family coverage** — per family (Injection, Memory Safety,
 *      Access Control, …, in a fixed canonical order): how many distinct CWEs
 *      fired under it, alert volume and share, distinct attacker sources and
 *      internal hosts touched, the severity ceiling, the blocked-vs-detected
 *      disposition split and the busiest CWE. An ASCII coverage bar reads the
 *      distribution at a glance.
 *   2. **Per-CWE detail** — every observed weakness ranked by a severity-weighted
 *      score: its CWE-ID + name + family, alert volume, distinct sources and
 *      targets, severity ceiling, disposition split, the dominant signature, and
 *      a flag when an **internal** host is the *source* of the weakness probe (a
 *      strong compromise / pivot tell rather than inbound noise).
 *
 * The sharpest rows are the **control gaps** (🚩): medium-or-worse weakness
 * classes that were mostly *detected, not blocked* — exactly the weakness
 * categories where enforcement (or a virtual patch) should be verified first.
 *
 * Honest about its limits, all stated in the output:
 *
 *   - **Mapping is a heuristic, not a curated CWE mapping.** It keys off
 *     free-text Suricata fields, so it is a strong triage hint, not an authored
 *     rule→CWE table. To keep the coverage math clean each alert is attributed to
 *     a *single* best-match CWE; everything that matches no rule lands in an
 *     honest **unmapped** bucket (counted, never silently dropped). Recon, C2,
 *     scanning and policy chatter legitimately do *not* exercise a software
 *     weakness, so a large unmapped fraction is expected and not a defect — it is
 *     the share of the stream that is behaviour, not exploitation.
 *   - **CWE describes the weakness *being targeted*, not a *confirmed* one.** An
 *     SQL-injection signature firing means someone *tried*; it does not prove the
 *     app is vulnerable. This is exposure pressure, not a vulnerability scan.
 *   - **Detections, not full telemetry.** A weakness probed without tripping a
 *     signature is invisible here — coverage is a lower bound.
 *   - **Window-bounded & store-capped.** A long look-back can hit the alert
 *     store's history cap and undercount.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network. Output is
 * both a structured model and a ready-to-paste Markdown document, mirroring
 * mitre.ts, cve.ts, classify.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/**
 * The weakness families this report rolls CWEs up into, in a fixed canonical
 * order (roughly: things you fix in code first → things you fix in config /
 * transport / capacity). The report only renders families that were actually
 * observed, but the order here is authoritative for display so the matrix always
 * reads top-to-bottom the way an AppSec reviewer expects.
 */
export const WEAKNESS_FAMILIES = [
  "Injection",
  "Path Traversal",
  "Request Forgery & Unsafe Parsing",
  "Memory Safety",
  "Authentication & Access Control",
  "Information Disclosure",
  "Cryptographic / Transport",
  "Resource Management",
] as const;

export type WeaknessFamily = (typeof WEAKNESS_FAMILIES)[number];

/** A single CWE weakness class the report can attribute an alert to. */
export interface WeaknessDef {
  /** CWE identifier, e.g. "CWE-89". */
  id: string;
  /** Human weakness name, e.g. "SQL Injection". */
  name: string;
  /** Parent weakness family. */
  family: WeaknessFamily;
}

/**
 * The curated catalog of CWE weakness classes this report attributes alerts to.
 * Kept deliberately small and IPS-relevant — an IDS/IPS only ever evidences the
 * slice of CWE that produces network-observable exploitation traffic — and
 * indexed by ID so a rule can reference a weakness once.
 */
export const WEAKNESSES: Record<string, WeaknessDef> = {
  // --- Injection ---
  "CWE-89": { id: "CWE-89", name: "SQL Injection", family: "Injection" },
  "CWE-79": { id: "CWE-79", name: "Cross-site Scripting (XSS)", family: "Injection" },
  "CWE-78": { id: "CWE-78", name: "OS Command Injection", family: "Injection" },
  "CWE-94": { id: "CWE-94", name: "Code Injection", family: "Injection" },
  "CWE-98": { id: "CWE-98", name: "PHP / Remote File Inclusion", family: "Injection" },
  "CWE-434": { id: "CWE-434", name: "Unrestricted File Upload", family: "Injection" },
  // --- Path traversal ---
  "CWE-22": { id: "CWE-22", name: "Path Traversal", family: "Path Traversal" },
  // --- Request forgery & unsafe parsing ---
  "CWE-918": { id: "CWE-918", name: "Server-Side Request Forgery (SSRF)", family: "Request Forgery & Unsafe Parsing" },
  "CWE-611": { id: "CWE-611", name: "XML External Entity (XXE)", family: "Request Forgery & Unsafe Parsing" },
  "CWE-502": { id: "CWE-502", name: "Deserialization of Untrusted Data", family: "Request Forgery & Unsafe Parsing" },
  // --- Memory safety ---
  "CWE-787": { id: "CWE-787", name: "Out-of-bounds Write / Buffer Overflow", family: "Memory Safety" },
  "CWE-416": { id: "CWE-416", name: "Use After Free", family: "Memory Safety" },
  "CWE-190": { id: "CWE-190", name: "Integer Overflow or Wraparound", family: "Memory Safety" },
  // --- Authentication & access control ---
  "CWE-307": { id: "CWE-307", name: "Improper Restriction of Excessive Auth Attempts", family: "Authentication & Access Control" },
  "CWE-287": { id: "CWE-287", name: "Improper Authentication", family: "Authentication & Access Control" },
  "CWE-862": { id: "CWE-862", name: "Missing Authorization", family: "Authentication & Access Control" },
  "CWE-269": { id: "CWE-269", name: "Improper Privilege Management", family: "Authentication & Access Control" },
  // --- Information disclosure ---
  "CWE-200": { id: "CWE-200", name: "Exposure of Sensitive Information", family: "Information Disclosure" },
  // --- Cryptographic / transport ---
  "CWE-319": { id: "CWE-319", name: "Cleartext Transmission of Sensitive Info", family: "Cryptographic / Transport" },
  // --- Resource management ---
  "CWE-400": { id: "CWE-400", name: "Uncontrolled Resource Consumption (DoS)", family: "Resource Management" },
};

/**
 * Ordered mapping rules: the first whose pattern matches the alert's combined
 * `classification + signature + category` text wins. Order is most-specific →
 * least-specific so a precise weakness (e.g. "sql injection") beats a broad
 * keyword (e.g. a generic "remote code execution" that maps to code injection).
 * Patterns are matched case-insensitively.
 */
const RULES: Array<{ weakness: string; re: RegExp }> = [
  // Injection — the specific, unambiguous web-app classes first.
  { weakness: "CWE-89", re: /sql.?injection|\bsqli\b|union\s+select|sql\b.*\b(inject|attack)/i },
  { weakness: "CWE-79", re: /\bxss\b|cross.?site scripting|script injection/i },
  { weakness: "CWE-98", re: /file inclusion|\blfi\b|\brfi\b|remote file include|local file include/i },
  { weakness: "CWE-434", re: /file upload|unrestricted upload|web.?shell|upload.*\b(shell|asp|php|jsp)\b/i },
  { weakness: "CWE-78", re: /os command|command injection|shell (injection|command)|\bcmd\b injection/i },
  { weakness: "CWE-502", re: /deserializ|object injection|\bognl\b|java.*serial|insecure deserialization/i },
  { weakness: "CWE-611", re: /\bxxe\b|xml external entit|external entity/i },
  { weakness: "CWE-918", re: /\bssrf\b|server.?side request forgery/i },
  // Path traversal.
  { weakness: "CWE-22", re: /directory traversal|path traversal|\.\.[\\/]|dot.?dot.?slash|\btraversal\b/i },
  // Code execution — the generic catch after the specific injection types above.
  { weakness: "CWE-94", re: /code injection|\bssti\b|server.?side template|template injection|\beval\b|code execution|\brce\b|remote code execution/i },
  // Memory safety.
  { weakness: "CWE-416", re: /use.?after.?free|double free|\buaf\b/i },
  { weakness: "CWE-190", re: /integer (overflow|underflow|wraparound)/i },
  { weakness: "CWE-787", re: /buffer overflow|stack overflow|heap (overflow|spray)|out.?of.?bounds|\bbof\b|overflow attempt|shellcode/i },
  // Authentication & access control.
  { weakness: "CWE-307", re: /brute.?force|password (guess|spray)|credential stuffing|excessive login|login attempt|auth.*\bfail|\bhydra\b/i },
  { weakness: "CWE-287", re: /authentication (bypass|fail)|auth bypass|improper authentication|default (password|credential)|weak (password|credential)/i },
  { weakness: "CWE-269", re: /privilege (gain|escalation)|priv.?esc|elevation of privilege/i },
  { weakness: "CWE-862", re: /authorization bypass|missing authorization|broken access control|\bidor\b|insecure direct object|forced browsing/i },
  // Information disclosure.
  { weakness: "CWE-200", re: /information (leak|disclosure|exposure)|info leak|sensitive (data|information)|directory listing|backup file|\.git\b|attempted (information|info) leak/i },
  // Cryptographic / transport.
  { weakness: "CWE-319", re: /cleartext|plaintext (password|credential)|unencrypted|cleartext transmission/i },
  // Resource management — denial-of-service that exhausts the target.
  { weakness: "CWE-400", re: /denial of service|\bdos\b|\bddos\b|syn flood|\bflood\b|resource (exhaustion|consumption)|amplification/i },
];

/** Blocked / passed / unknown disposition split for a weakness cell. */
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
   * weakness is the control gap worth verifying (or virtual-patching) first.
   */
  passRate: number | null;
}

/** Per-CWE roll-up over the window. */
export interface CweWeakness {
  /** CWE identifier. */
  id: string;
  /** Human weakness name. */
  name: string;
  /** Parent weakness family. */
  family: WeaknessFamily;
  /** Total alerts attributed to this weakness. */
  count: number;
  /** Share of all *mapped* alerts, 0..1 (4dp). */
  share: number;
  /** Distinct attacker source IPs probing this weakness. */
  distinctSources: number;
  /** Distinct destination hosts touched. */
  distinctTargets: number;
  /** Distinct *internal* source IPs (an internal source is a compromise tell). */
  internalSources: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Worst severity seen for this weakness. */
  severityMax: Severity;
  /** Severity-weighted score (Σ SEVERITY_WEIGHT) — the ranking key. */
  score: number;
  /** Blocked / passed / unknown disposition split. */
  disposition: DispositionSplit;
  /** The dominant signature for this weakness, for context. */
  topSignature?: string;
  /** First/last time (ms epoch) this weakness fired in the window. */
  firstSeenMs: number;
  lastSeenMs: number;
  /**
   * A control gap: medium-or-worse and mostly *passed* (let through). The
   * highest-value rows to verify enforcement / virtual-patch on.
   */
  controlGap: boolean;
  /**
   * Durable class-level hardening action for this weakness — the fix that no
   * single CVE patch delivers. Derived from the weakness's parent family via
   * {@link familyHardening}. Surface this alongside a control gap or top-score
   * weakness so the reader knows *what to do*, not just *what is firing*.
   */
  hardeningAction: string;
}

/** Per-family coverage roll-up. */
export interface CweFamily {
  /** Family name. */
  family: WeaknessFamily;
  /** Distinct CWEs observed under this family. */
  weaknessCount: number;
  /** Total alerts under this family. */
  count: number;
  /** Share of all *mapped* alerts, 0..1 (4dp). */
  share: number;
  /** Distinct attacker source IPs across the family. */
  distinctSources: number;
  /** Distinct destination hosts across the family. */
  distinctTargets: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Worst severity seen across the family. */
  severityMax: Severity;
  /** Blocked / passed / unknown disposition split. */
  disposition: DispositionSplit;
  /** The busiest CWE under this family (by alert volume). */
  topWeaknessId?: string;
  /** Name of {@link topWeaknessId}. */
  topWeaknessName?: string;
  /**
   * The durable class-level hardening action for this family — the fix that no
   * single CVE patch delivers. Use this to drive WAF rules, auth-rate limits,
   * input-validation or compiler-mitigation work at the *class* level, not just
   * the specific exploit instance. Derived from {@link familyHardening}.
   */
  hardeningAction: string;
}

export interface CweReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts mapped to a CWE weakness class. */
  mappedAlerts: number;
  /** Of those, alerts that matched no rule (honest unmapped bucket). */
  unmappedAlerts: number;
  /** Distinct families observed. */
  familiesObserved: number;
  /** Distinct CWEs observed. */
  weaknessesObserved: number;
  /** Per-family coverage, in canonical order (observed families only). */
  families: CweFamily[];
  /** Per-CWE detail, ranked by severity-weighted score (capped to limit). */
  weaknesses: CweWeakness[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface CweOptions {
  /** Max rows in the per-CWE table (clamped to [1, 200]). */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 30;
const MS_PER_HOUR = 3_600_000;

// ----- classifiers / helpers (mirror mitre.ts / classify.ts) ----------------

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

/** A compact ASCII bar (8th-block glyphs) for the family coverage column. */
function bar(frac: number, width = 16): string {
  const filled = Math.max(0, Math.min(width, Math.round(frac * width)));
  return "█".repeat(filled) + "·".repeat(width - filled);
}

/**
 * Durable hardening hint per weakness family — what fixes the *class*, not one bug.
 * Exported so callers (dashboard, report templates, summarise) can surface the action
 * alongside the structured {@link CweFamily} data without re-deriving it from text.
 */
export function familyHardening(family: WeaknessFamily): string {
  switch (family) {
    case "Injection":
      return "parameterise queries, encode output, deploy a WAF injection ruleset";
    case "Path Traversal":
      return "canonicalise & allow-list paths, sandbox file access";
    case "Request Forgery & Unsafe Parsing":
      return "allow-list egress, disable external entities, avoid native deserialization";
    case "Memory Safety":
      return "patch the affected service, enable ASLR/DEP/stack canaries";
    case "Authentication & Access Control":
      return "rate-limit auth, enforce MFA, re-check server-side authorization";
    case "Information Disclosure":
      return "remove debug/backup endpoints, suppress verbose errors";
    case "Cryptographic / Transport":
      return "force TLS, retire cleartext protocols";
    case "Resource Management":
      return "rate-limit, add upstream DDoS scrubbing & connection caps";
    default:
      return "—";
  }
}

/**
 * Map a single alert to one CWE weakness class by first-match-wins over its
 * combined classification + signature + category text. Returns undefined when no
 * rule matches (the alert lands in the honest unmapped bucket — recon, C2 and
 * scanning legitimately do not exercise a software weakness).
 */
export function mapWeakness(a: {
  classification?: string;
  signature?: string;
  category?: string;
}): WeaknessDef | undefined {
  const text = `${a.classification ?? ""} ${a.signature ?? ""} ${a.category ?? ""}`;
  if (!text.trim()) return undefined;
  for (const rule of RULES) {
    if (rule.re.test(text)) return WEAKNESSES[rule.weakness];
  }
  return undefined;
}

// ----- aggregation ----------------------------------------------------------

interface WeakAcc {
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

function newWeakAcc(): WeakAcc {
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

interface FamilyAcc {
  weaknesses: Set<string>;
  count: number;
  severe: number;
  sources: Set<string>;
  targets: Set<string>;
  blocked: number;
  passed: number;
  unknown: number;
  weakCounts: Map<string, number>;
  severityMax: Severity;
}

function newFamilyAcc(): FamilyAcc {
  return {
    weaknesses: new Set(),
    count: 0,
    severe: 0,
    sources: new Set(),
    targets: new Set(),
    blocked: 0,
    passed: 0,
    unknown: 0,
    weakCounts: new Map(),
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
  families: CweFamily[],
  weaknesses: CweWeakness[],
): string[] {
  const out: string[] = [];
  if (!weaknesses.length) return out;

  out.push(
    `🧬 Over the last ${hours}h, **${m.mappedAlerts} alert(s)** mapped to **${weaknesses.length} CWE ` +
      `weakness class(es)** across **${families.length} family(ies)**` +
      (m.unmappedAlerts ? ` (${m.unmappedAlerts} alert(s) exercised no software weakness — see *unmapped*).` : `.`),
  );

  // The busiest family — where the bulk of weakness-hunting pressure sits.
  const topFamily = [...families].sort((a, b) => b.count - a.count)[0]!;
  out.push(
    `📊 Most-probed family is **${topFamily.family}** — ${topFamily.count} alert(s), ${pct(topFamily.share)} of ` +
      `mapped activity across ${topFamily.weaknessCount} weakness class(es), worst severity **${topFamily.severityMax}**. ` +
      `Durable fix: _${familyHardening(topFamily.family)}_.`,
  );

  // The single highest-scoring CWE.
  const lead = weaknesses[0]!;
  out.push(
    `🎯 Top weakness by severity-weighted score is **${lead.id} ${lead.name}** (${lead.family}) — ` +
      `${lead.count} alert(s), ${lead.distinctSources} source(s), worst **${lead.severityMax}**` +
      (lead.topSignature ? `; dominant signature \`${lead.topSignature}\`` : ``) +
      `. Class-level hardening: _${lead.hardeningAction}_.`,
  );

  // Control gaps — severe weakness classes mostly let through.
  const gaps = weaknesses.filter((w) => w.controlGap);
  if (gaps.length) {
    const g = gaps[0]!;
    out.push(
      `🚩 **${gaps.length} control gap(s)** — medium-or-worse weakness class(es) mostly *detected, not blocked*. ` +
        `Worst: **${g.id} ${g.name}** is ${g.disposition.passRate === null ? "—" : pct(g.disposition.passRate)} ` +
        `let through (${g.disposition.passed} actioned alerts passed). Class-level fix: _${g.hardeningAction}_. ` +
        `Verify the IPS policy or virtual-patch this class first.`,
    );
  }

  // Internal sources — an internal host *probing* a weakness is a pivot tell.
  const insider = weaknesses.filter((w) => w.internalSources > 0).sort((a, b) => b.score - a.score)[0];
  if (insider) {
    out.push(
      `🚨 **${insider.internalSources} *internal* host(s)** are the **source** of **${insider.id} ${insider.name}** ` +
        `probes — an inside box hunting a software weakness is a lateral-movement / compromise tell, not inbound ` +
        `noise. Investigate it ahead of external attackers.`,
    );
  }

  // Coverage honesty — how much of the stream exercised a weakness at all.
  if (m.totalWindowAlerts > 0) {
    const frac = m.mappedAlerts / m.totalWindowAlerts;
    out.push(
      `ℹ️ **${pct(frac)} of windowed alerts** mapped to a software weakness; the rest is behaviour (recon, ` +
        `scanning, C2, policy) that exercises no code flaw — that is expected, not a parsing miss. CWE coverage ` +
        `here is *exposure pressure*, not a confirmed vulnerability.`,
    );
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function familyTable(rows: CweFamily[]): string {
  return mdTable(
    ["Family", "Coverage", "CWEs", "Alerts", "Share", "Sources", "Hosts", "Severe", "Worst", "Blocked%", "Top CWE", "Hardening action"],
    rows.map((f) => {
      const actioned = f.disposition.blocked + f.disposition.passed;
      const blockRate = actioned ? `${Math.round((f.disposition.blocked / actioned) * 100)}%` : "—";
      return [
        cell(f.family),
        bar(f.share),
        String(f.weaknessCount),
        String(f.count),
        pct(f.share),
        String(f.distinctSources),
        String(f.distinctTargets),
        String(f.severe),
        cell(f.severityMax),
        blockRate,
        f.topWeaknessId ? cell(`${f.topWeaknessId} ${f.topWeaknessName ?? ""}`.trim()) : "—",
        cell(f.hardeningAction),
      ];
    }),
  );
}

function weaknessTable(rows: CweWeakness[]): string {
  return mdTable(
    ["#", "Weakness", "CWE", "Family", "Alerts", "Sources", "Hosts", "Severe", "Worst", "Blocked", "Pass rate", "Top signature", "Hardening action", "Flags"],
    rows.map((w, i) => {
      const flags = (w.internalSources ? "🏠" : "") + (w.controlGap ? "🚩" : "");
      return [
        String(i + 1),
        cell(w.name),
        cell(w.id),
        cell(w.family),
        String(w.count),
        String(w.distinctSources),
        String(w.distinctTargets),
        String(w.severe),
        cell(w.severityMax),
        String(w.disposition.blocked),
        w.disposition.passRate === null ? "—" : pct(w.disposition.passRate),
        cell(w.topSignature ?? "—"),
        cell(w.hardeningAction),
        flags || "—",
      ];
    }),
  );
}

function renderMarkdown(m: CweReport): string {
  const lines: string[] = [];
  lines.push(`# 🧬 SecTool CWE Weakness-Class Coverage Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** each alert mapped to one CWE weakness class by a first-match heuristic over its ` +
      `\`classification\` / \`signature\` / \`category\` text, rolled up by family and CWE · ` +
      `**Mapped:** ${m.mappedAlerts} of ${m.totalWindowAlerts} alert(s) (${m.unmappedAlerts} unmapped) → ` +
      `${m.weaknessesObserved} weakness(es) across ${m.familiesObserved} family(ies)`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.weaknesses.length) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to map.`);
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but none carried classtype / signature ` +
          `text that maps to a known software-weakness class. On most edges the stream is dominated by recon, ` +
          `scanning and C2 behaviour, which exercise no code weakness — see the \`mitre\` report for that axis.`,
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

  lines.push(`## Weakness-family coverage`);
  lines.push("");
  lines.push(`Weakness families in a fixed canonical order, observed cells only. The coverage bar is each family's share of mapped alerts. The **Hardening action** column is the durable class-level fix — what no single CVE patch delivers.`);
  lines.push("");
  lines.push(familyTable(m.families));
  lines.push("");

  lines.push(`## Weaknesses by severity-weighted attention`);
  lines.push("");
  lines.push(weaknessTable(m.weaknesses));
  lines.push("");
  lines.push(
    `**Legend:** ranked by severity-weighted score so a small but dangerous weakness class outranks a flood of ` +
      `low-severity noise. _Pass rate_ = share of *actioned* (blocked + passed) alerts let through. ` +
      `_Hardening action_ = the durable class-level fix a CVE patch alone cannot deliver — a WAF rule, ` +
      `input-validation mandate, auth rate-limit, or compiler mitigation applied across the whole weakness class. ` +
      `**Flags:** 🏠 an *internal* host is the source of the probe (compromise / pivot tell) · 🚩 control gap ` +
      `(medium-or-worse but mostly detected, not blocked — a virtual-patch candidate).`,
  );
  lines.push("");

  if (m.unmappedAlerts) {
    lines.push(
      `> **Unmapped:** ${m.unmappedAlerts} alert(s) (${pct(m.unmappedAlerts / Math.max(1, m.totalWindowAlerts))} of the ` +
        `window) exercised no software weakness — recon, scanning, C2 and policy chatter — and are excluded from the ` +
        `tables above. Counted here so coverage is never overstated; for the *behaviour* of that traffic see the ` +
        `\`mitre\` and \`classify\` reports.`,
    );
    lines.push("");
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. CWE mapping is a **heuristic** over free-text Suricata fields, not a curated ` +
      `rule→CWE table — a strong triage hint, not an authored mapping. Each alert is attributed to a **single** ` +
      `best-match weakness; everything matching no rule is counted in the **unmapped** bucket, never silently ` +
      `dropped. A CWE here means the weakness was **targeted**, not that the asset is **vulnerable** — this is ` +
      `exposure pressure, not a vulnerability scan; pair it with the \`cve\` patch worklist and \`mitre\` behaviour ` +
      `view. These are IPS **detections**, not full telemetry, so coverage is a lower bound. A long look-back can ` +
      `hit the store's history cap and undercount. No SSH, no Claude, no live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the CWE weakness-class coverage report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link CweOptions}: `limit` and a `nowMs` pin for tests.
 */
export function buildCwe(hours: number, opts: CweOptions = {}): CweReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const weakAccs = new Map<string, WeakAcc>();
  const familyAccs = new Map<WeaknessFamily, FamilyAcc>();
  let mapped = 0;
  let unmapped = 0;

  for (const a of windowed) {
    const def = mapWeakness(a);
    if (!def) {
      unmapped++;
      continue;
    }
    mapped++;

    const src = validIp(a.srcIp);
    const dst = validIp(a.dstIp);
    const disp = classifyDisposition(a.action);

    // --- weakness accumulator ---
    const wacc = weakAccs.get(def.id) ?? newWeakAcc();
    if (!weakAccs.has(def.id)) weakAccs.set(def.id, wacc);
    wacc.count++;
    wacc.score += weightOf(a.severity);
    wacc.severityMax = maxSeverity(wacc.severityMax, a.severity);
    if (isSevere(a.severity)) wacc.severe++;
    if (src) {
      wacc.sources.add(src);
      if (isPrivate(src)) wacc.internalSources.add(src);
    }
    if (dst) wacc.targets.add(dst);
    if (a.signature) wacc.sigCounts.set(a.signature, (wacc.sigCounts.get(a.signature) ?? 0) + 1);
    if (disp === "blocked") wacc.blocked++;
    else if (disp === "passed") wacc.passed++;
    else wacc.unknown++;
    if (a.time < wacc.firstSeenMs) wacc.firstSeenMs = a.time;
    if (a.time > wacc.lastSeenMs) wacc.lastSeenMs = a.time;

    // --- family accumulator ---
    const facc = familyAccs.get(def.family) ?? newFamilyAcc();
    if (!familyAccs.has(def.family)) familyAccs.set(def.family, facc);
    facc.weaknesses.add(def.id);
    facc.count++;
    facc.severityMax = maxSeverity(facc.severityMax, a.severity);
    if (isSevere(a.severity)) facc.severe++;
    if (src) facc.sources.add(src);
    if (dst) facc.targets.add(dst);
    facc.weakCounts.set(def.id, (facc.weakCounts.get(def.id) ?? 0) + 1);
    if (disp === "blocked") facc.blocked++;
    else if (disp === "passed") facc.passed++;
    else facc.unknown++;
  }

  const mappedSafe = Math.max(1, mapped);

  // Per-CWE rows, ranked by severity-weighted score then volume.
  const weaknesses: CweWeakness[] = [...weakAccs.entries()]
    .map(([id, acc]) => {
      const def = WEAKNESSES[id]!;
      const passRate = acc.blocked + acc.passed ? round4(acc.passed / (acc.blocked + acc.passed)) : null;
      const controlGap = isSevere(acc.severityMax) && passRate !== null && passRate >= 0.5 && acc.passed >= 2;
      return {
        id,
        name: def.name,
        family: def.family,
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
        hardeningAction: familyHardening(def.family),
      } satisfies CweWeakness;
    })
    .sort(
      (x, y) =>
        y.score - x.score ||
        y.count - x.count ||
        (x.id < y.id ? -1 : x.id > y.id ? 1 : 0),
    );

  // Per-family rows, emitted in canonical order (observed only).
  const families: CweFamily[] = WEAKNESS_FAMILIES.filter((f) => familyAccs.has(f)).map((f) => {
    const acc = familyAccs.get(f)!;
    const topWeaknessId = topOf(acc.weakCounts);
    return {
      family: f,
      weaknessCount: acc.weaknesses.size,
      count: acc.count,
      share: round4(acc.count / mappedSafe),
      distinctSources: acc.sources.size,
      distinctTargets: acc.targets.size,
      severe: acc.severe,
      severityMax: acc.severityMax,
      disposition: dispOf(acc.blocked, acc.passed, acc.unknown),
      topWeaknessId,
      topWeaknessName: topWeaknessId ? WEAKNESSES[topWeaknessId]?.name : undefined,
      hardeningAction: familyHardening(f),
    } satisfies CweFamily;
  });

  const cappedWeaknesses = weaknesses.slice(0, limit);

  const highlights = writeHighlights(
    safeHours,
    { mappedAlerts: mapped, unmappedAlerts: unmapped, totalWindowAlerts: windowed.length },
    families,
    cappedWeaknesses,
  );

  const model: CweReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    mappedAlerts: mapped,
    unmappedAlerts: unmapped,
    familiesObserved: families.length,
    weaknessesObserved: weaknesses.length,
    families,
    weaknesses: cappedWeaknesses,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded CWE weakness-class report. */
export function cweFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-cwe-${stamp}.md`;
}
