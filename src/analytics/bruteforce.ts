/**
 * Credential-attack / brute-force report — "is anyone trying to *log in* to my
 * services — and is the guessing concentrated on one host (brute-force /
 * stuffing), sprayed thin across many (password spraying), or coming from a
 * crowd of sources at once (a distributed assault)?"
 *
 * Every other offline report in this project treats the alert stream
 * *generically* — it ranks a source by breadth (scan, spread, repertoire), a
 * signature by noise (tuning, lifecycle), a window by shape (concentration,
 * surge), or the gateway by enforcement (efficacy). classify.ts rolls the whole
 * Suricata taxonomy up into a *mix*, but a mix percentage ("12% credential
 * access") does not tell you *which login surface is under fire, how hard, from
 * how many sources, and whether the guesses are reaching the service*. None of
 * them drill into the single attack class that matters most to almost every
 * org's threat model: **someone trying to authenticate as someone they are not.**
 *
 * Credential access is the highest-leverage thing an IPS stream can warn you
 * about, because the response is so cheap and so specific. A web-app probe might
 * mean a dozen things; a sustained run of failed SSH/RDP/SMB logins against one
 * box means exactly one — turn on MFA, enable lockout / rate-limiting, and
 * restrict the source — and the shape of the attack tells you *which* of those
 * to reach for:
 *
 *   - **Brute-force / stuffing** — *many attempts concentrated on one (or few)
 *     targets*. A classic dictionary / credential-stuffing run against a single
 *     login. The fix is host-centric: lock that account / service down and
 *     rate-limit it.
 *   - **Password spray** — *a few attempts each, fanned across many targets*.
 *     The attacker trades depth for breadth to stay under per-account lockout
 *     thresholds, trying one or two common passwords everywhere. Per-host
 *     lockout never trips; the tell is the *fan-out*, and the fix is org-wide
 *     (disable legacy auth, enforce MFA everywhere, alert on the pattern).
 *   - **Distributed** — *one target, many sources*. A botnet sharing the guess
 *     work across IPs to dodge source-based blocking. The tell is the source
 *     *count* on a single victim, and source-blocking alone will not hold.
 *   - **Probe** — *low volume*. A handful of login attempts: opportunistic
 *     noise, surfaced for completeness, never ranked above a real run.
 *
 * The report identifies credential-bearing alerts two complementary ways and
 * records which fired (for honesty about the heuristic):
 *
 *   1. **By signature semantics** — the signature / classification / category /
 *      raw line matches a curated set of credential-access keywords
 *      (brute-force, login, auth, password, kerberos, hydra, "privilege gain",
 *      …). This catches attacks on non-standard ports and app-layer logins
 *      (e.g. a WordPress / web login flood) that a port test would miss.
 *   2. **By target service** — the destination port (re-parsed from the raw line
 *      via the same {@link recoverFlow} that powers ports.ts) is a well-known
 *      authentication service (SSH/22, RDP/3389, SMB/445, FTP/21, the database
 *      and mail-auth ports, …).
 *
 * It then folds the qualifying alerts two ways: per **target login surface**
 * (`dstIp` × service — where is the guessing landing, how hard, from how many
 * sources, and how much is being *let through*) and per **attacking source**
 * (who is guessing, classified into the four shapes above). A passed-through
 * credential attempt is the headline: the gateway *detected* the login attempt
 * and let the packet reach the service, so the only thing standing between the
 * attacker and the account is the password itself.
 *
 * Honest caveats baked into the output:
 *
 *   - **Detections, not auth outcomes.** SecTool stores IPS *detections*. An
 *     alert means a login attempt tripped a rule — never that a password was
 *     *correct*. This report measures pressure and exposure, not breach; a
 *     "passed" attempt reached the service but may still have been rejected by
 *     the application. Equally, a brute-force that never trips a rule is
 *     invisible, so every count is a lower bound.
 *   - **Heuristic identification.** Membership is a keyword/port heuristic. The
 *     keyword-confirmed vs. port-only split is always shown so a thin or
 *     port-inflated set is visible rather than mistaken for signal; an attack on
 *     a bespoke login over an odd port with a generic signature can be missed.
 *   - **Ports are re-parsed, not stored.** Service attribution leans on the same
 *     best-effort raw-line re-parse as ports.ts; alerts with no recoverable port
 *     fall back to a service inferred from the signature text, or "unknown".
 *   - **Window-bounded & store-capped.** A long look-back can hit the store's
 *     history cap and undercount.
 *
 * Pure in-memory math over alertStore (plus blocklist / watchlist / safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring report.ts, scan.ts,
 * ports.ts, efficacy.ts and the other offline reports.
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

/** The four shapes a credential attack from a single source can take. */
export type AttackShape = "brute-force" | "spray" | "distributed" | "probe";

/** How a qualifying alert was identified as credential-bearing. */
export type MatchBasis = "signature" | "port";

/**
 * Authentication / credential-bearing destination services. A destination port
 * in this set marks an alert as a credential-access candidate even when the
 * signature text is generic. Labels prefer {@link SERVICE_NAMES}; a few
 * login-relevant ports absent from that map are added here.
 */
export const AUTH_SERVICE_PORTS: ReadonlyMap<number, string> = new Map<number, string>([
  [21, "FTP"],
  [22, "SSH"],
  [23, "Telnet"],
  [25, "SMTP"],
  [88, "Kerberos"],
  [110, "POP3"],
  [135, "MSRPC"],
  [139, "NetBIOS-ssn"],
  [143, "IMAP"],
  [389, "LDAP"],
  [445, "SMB"],
  [465, "SMTPS"],
  [587, "SMTP-sub"],
  [623, "IPMI"],
  [636, "LDAPS"],
  [993, "IMAPS"],
  [995, "POP3S"],
  [1099, "Java-RMI"],
  [1433, "MSSQL"],
  [1521, "Oracle"],
  [2222, "SSH-alt"],
  [3306, "MySQL"],
  [3389, "RDP"],
  [5432, "PostgreSQL"],
  [5900, "VNC"],
  [5985, "WinRM"],
  [5986, "WinRM-TLS"],
  [6379, "Redis"],
  [10000, "Webmin"],
  [11211, "Memcached"],
  [27017, "MongoDB"],
  [27018, "MongoDB"],
]);

/**
 * Curated credential-access vocabulary. A match anywhere in a signature's
 * text / classification / category / raw line marks the alert as a credential
 * attack regardless of port. `\bauth(entication)?\b` deliberately does not match
 * "author"; the multi-word phrases are matched without word boundaries because
 * Suricata renders them with spaces / underscores / hyphens interchangeably.
 */
const AUTH_KEYWORDS =
  /\b(?:brute[\s_-]?force|bruteforce|login|logon|log[\s_-]?in|sign[\s_-]?in|auth(?:entication)?|password|passwd|credential|kerberos|kerberoast|as[\s_-]?rep|hydra|medusa|ncrack|patator|crowbar)\b|privilege[\s_-]?gain|user[\s_-]?enumeration|default[\s_-]?credential|failed[\s_-]?(?:login|password|auth)|excessive[\s_-]?(?:login|auth)|invalid[\s_-]?user/i;

/** Service inference from free text when no destination port was recovered. */
const TEXT_SERVICE_HINTS: ReadonlyArray<[RegExp, string]> = [
  [/\bssh\b/i, "SSH"],
  [/\brdp\b|remote desktop/i, "RDP"],
  [/\bsmb\b|netbios|cifs/i, "SMB"],
  [/\bftps?\b/i, "FTP"],
  [/\btelnet\b/i, "Telnet"],
  [/\bvnc\b/i, "VNC"],
  [/kerberos|as[\s_-]?rep|kerberoast/i, "Kerberos"],
  [/\bldap\b/i, "LDAP"],
  [/\bmysql\b/i, "MySQL"],
  [/mssql|sql server/i, "MSSQL"],
  [/postgres/i, "PostgreSQL"],
  [/wordpress|wp-login|joomla|drupal|\bhttp\b|web(?:mail|app)?/i, "HTTP"],
  [/\bimap\b|\bpop3?\b|\bsmtp\b|webmail|mail/i, "Mail"],
];

/** Blocked / passed / unknown disposition split for a credential-attack actor. */
export interface DispositionSplit {
  /** Login attempts the gateway actively blocked / dropped. */
  blocked: number;
  /** Login attempts the gateway logged but let reach the service. */
  passed: number;
  /** Attempts with no recorded action (excluded from {@link passRate}). */
  unknown: number;
  /**
   * Fraction of *actioned* (blocked + passed) attempts that reached the service,
   * 0..1 (4dp), or null when nothing was actioned. A high pass rate on a busy
   * login surface means the guessing is reaching the password prompt.
   */
  passRate: number | null;
}

/** Per-attacking-source credential-attack metrics over the window. */
export interface AttackSource {
  /** The source IP doing the guessing. */
  ip: string;
  /** True when the source is one of our own hosts (RFC1918 / loopback / …). */
  internal: boolean;
  /** The classified attack shape (see {@link AttackShape}). */
  shape: AttackShape;
  /** Total credential-attack attempts attributed to this source. */
  attempts: number;
  /** Distinct destination hosts this source tried to log in to. */
  distinctTargets: number;
  /** Distinct authentication services this source touched. */
  distinctServices: number;
  /** Mean attempts per distinct target (a depth-vs-breadth tell). */
  attemptsPerTarget: number;
  /** Attempts at medium severity or worse. */
  severe: number;
  /** Severity-weighted score (Σ SEVERITY_WEIGHT) — a secondary signal. */
  score: number;
  /** Blocked / passed / unknown disposition split. */
  disposition: DispositionSplit;
  /** The most-attacked destination host for this source, if any. */
  topTarget?: string;
  /** The most-attacked authentication service for this source, if any. */
  topService?: string;
  /** Worst severity seen from this source. */
  severityMax: Severity;
  /** First attempt timestamp (ms) in the window. */
  firstMs: number;
  /** Last attempt timestamp (ms) in the window. */
  lastMs: number;
  /** The source is on the blocklist. */
  blocked: boolean;
  /** The source is on the watchlist. */
  watched: boolean;
  /** The source is marked safe. */
  safe: boolean;
}

/** Per-target login-surface (`dstIp` × service) metrics over the window. */
export interface TargetSurface {
  /** The destination host under credential attack. */
  ip: string;
  /** True when the target is one of our own hosts. */
  internal: boolean;
  /** The authentication service being attacked (e.g. "SSH", "RDP"). */
  service: string;
  /** Destination port, when one was recovered for this surface. */
  port?: number;
  /** A remote-admin / data-store / management port (see ports.ts). */
  highRisk: boolean;
  /** Total credential-attack attempts against this surface. */
  attempts: number;
  /** Distinct source IPs guessing at this surface. */
  distinctSources: number;
  /** True when attacked by enough distinct sources to look coordinated. */
  distributed: boolean;
  /** Attempts at medium severity or worse. */
  severe: number;
  /** Blocked / passed / unknown disposition split. */
  disposition: DispositionSplit;
  /** The single most-active source against this surface, if any. */
  topSource?: string;
  /** Worst severity seen against this surface. */
  severityMax: Severity;
  /** First attempt timestamp (ms) in the window. */
  firstMs: number;
  /** Last attempt timestamp (ms) in the window. */
  lastMs: number;
}

/** Count of sources falling into each attack shape (the headline split). */
export interface ShapeCounts {
  "brute-force": number;
  spray: number;
  distributed: number;
  probe: number;
}

export interface BruteforceReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts identified as credential-bearing (the analysable set). */
  credentialAlerts: number;
  /** Of those, identified by signature/text semantics. */
  keywordConfirmed: number;
  /** Of those, identified only by a known authentication destination port. */
  portOnly: number;
  /** Of those, the gateway let reach the service (passed disposition). */
  passedCredential: number;
  /** Of those, the gateway blocked. */
  blockedCredential: number;
  /** Distinct attacking source IPs analysed. */
  distinctAttackers: number;
  /** Distinct destination hosts attacked. */
  distinctTargets: number;
  /** Distinct authentication services attacked. */
  distinctServices: number;
  /** Distinct-target count at/above which a source is a "spray". */
  sprayThreshold: number;
  /** Attempt count at/above which a concentrated source is "brute-force". */
  bruteThreshold: number;
  /** Distinct-source count at/above which a target surface is "distributed". */
  distributedThreshold: number;
  /** How many sources fell into each shape. */
  shapeCounts: ShapeCounts;
  /** Per-target login surfaces, most-attacked first. */
  targets: TargetSurface[];
  /** Per-attacking-source rows, most-active first. */
  sources: AttackSource[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface BruteforceOptions {
  /** Max rows in the per-target and per-source tables (clamped to [1, 200]). */
  limit?: number;
  /** Minimum attempts a source needs before it is analysed (drops one-offs). */
  minAttempts?: number;
  /** Distinct targets at/above which a source is classed a spray (≥2). */
  sprayThreshold?: number;
  /** Attempts at/above which a concentrated source is brute-force (≥2). */
  bruteThreshold?: number;
  /** Distinct sources at/above which a target is "distributed" (≥2). */
  distributedThreshold?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const DEFAULT_MIN_ATTEMPTS = 3;
const DEFAULT_SPRAY_THRESHOLD = 5;
const DEFAULT_BRUTE_THRESHOLD = 15;
const DEFAULT_DISTRIBUTED_THRESHOLD = 3;
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

function round2(n: number): number {
  return Math.round(n * 100) / 100;
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

/** Compact duration label for a [first,last] span. */
function fmtSpan(firstMs: number, lastMs: number): string {
  const mins = Math.max(0, Math.round((lastMs - firstMs) / 60000));
  if (mins < 1) return "<1m";
  if (mins < 60) return `${mins}m`;
  const hrs = mins / 60;
  if (hrs < 24) return `${round2(hrs)}h`;
  return `${round2(hrs / 24)}d`;
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

/** Human label for an attack shape, with a glanceable emoji. */
function shapeLabel(s: AttackShape): string {
  switch (s) {
    case "brute-force":
      return "🔨 brute-force";
    case "spray":
      return "💦 spray";
    case "distributed":
      return "🕸 distributed";
    case "probe":
      return "• probe";
  }
}

/** Display label for a service surface: "SSH (22)" or just "SSH". */
function serviceWithPort(service: string, port: number | undefined): string {
  return port !== undefined ? `${service} (${port})` : service;
}

/**
 * Decide whether an alert is credential-bearing, and the service it targets.
 * Returns the matched service label + port + basis, or undefined when the alert
 * is not a credential attack. Keyword semantics take precedence over the port
 * test for the {@link MatchBasis} flag, since a named credential signature is
 * stronger evidence than "the destination happened to be 22".
 */
function classifyAuth(
  a: StoredAlert,
): { service: string; port?: number; basis: MatchBasis; highRisk: boolean } | undefined {
  const port = recoverFlow(a.raw)?.dstPort;
  const portService = port !== undefined ? AUTH_SERVICE_PORTS.get(port) : undefined;

  const text = `${a.signature ?? ""} ${a.classification ?? ""} ${a.category ?? ""} ${a.raw ?? ""}`;
  const keywordHit = AUTH_KEYWORDS.test(text);

  if (!keywordHit && portService === undefined) return undefined;

  // Resolve the service label: a known auth port wins; else infer from text;
  // else any mapped service name for the port; else "unknown".
  let service = portService;
  if (service === undefined) {
    for (const [re, label] of TEXT_SERVICE_HINTS) {
      if (re.test(text)) {
        service = label;
        break;
      }
    }
  }
  if (service === undefined && port !== undefined) service = SERVICE_NAMES[port];
  if (service === undefined) service = "unknown";

  const basis: MatchBasis = keywordHit ? "signature" : "port";
  const highRisk = port !== undefined && HIGH_RISK_PORTS.has(port);
  return { service, port, basis, highRisk };
}

/**
 * Classify a source's attack shape from its breadth/depth. A wide fan-out is a
 * spray; otherwise heavy concentrated volume is brute-force; the rest are probes.
 * (The "distributed" shape is a property of the *target*, surfaced separately;
 * here a source is labelled by what it alone is doing.)
 */
function classifyShape(
  attempts: number,
  distinctTargets: number,
  sprayThreshold: number,
  bruteThreshold: number,
): AttackShape {
  if (distinctTargets >= sprayThreshold) return "spray";
  if (attempts >= bruteThreshold) return "brute-force";
  return "probe";
}

// ----- aggregation ----------------------------------------------------------

interface SourceAcc {
  attempts: number;
  score: number;
  severe: number;
  targets: Set<string>;
  services: Set<string>;
  blocked: number;
  passed: number;
  unknown: number;
  targetCounts: Map<string, number>;
  serviceCounts: Map<string, number>;
  severityMax: Severity;
  firstMs: number;
  lastMs: number;
}

function newSourceAcc(t: number): SourceAcc {
  return {
    attempts: 0,
    score: 0,
    severe: 0,
    targets: new Set(),
    services: new Set(),
    blocked: 0,
    passed: 0,
    unknown: 0,
    targetCounts: new Map(),
    serviceCounts: new Map(),
    severityMax: "info",
    firstMs: t,
    lastMs: t,
  };
}

interface SurfaceAcc {
  service: string;
  port?: number;
  highRisk: boolean;
  attempts: number;
  severe: number;
  sources: Set<string>;
  sourceCounts: Map<string, number>;
  blocked: number;
  passed: number;
  unknown: number;
  severityMax: Severity;
  firstMs: number;
  lastMs: number;
}

function newSurfaceAcc(service: string, port: number | undefined, highRisk: boolean, t: number): SurfaceAcc {
  return {
    service,
    port,
    highRisk,
    attempts: 0,
    severe: 0,
    sources: new Set(),
    sourceCounts: new Map(),
    blocked: 0,
    passed: 0,
    unknown: 0,
    severityMax: "info",
    firstMs: t,
    lastMs: t,
  };
}

function splitOf(blocked: number, passed: number, unknown: number): DispositionSplit {
  const actioned = blocked + passed;
  return { blocked, passed, unknown, passRate: actioned ? round4(passed / actioned) : null };
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  m: BruteforceReport,
): string[] {
  const out: string[] = [];
  if (!m.sources.length && !m.targets.length) return out;

  // Overall scale of the credential pressure.
  const sharePct =
    m.totalWindowAlerts > 0 ? pct(m.credentialAlerts / m.totalWindowAlerts) : "0%";
  out.push(
    `🔑 Over the last ${hours}h, **${m.credentialAlerts} credential-attack attempt(s)** (${sharePct} of all ` +
      `alerts) hit **${m.distinctServices} service(s)** on **${m.distinctTargets} host(s)** from ` +
      `**${m.distinctAttackers} source(s)** — ${m.shapeCounts["brute-force"]} brute-force · ${m.shapeCounts.spray} ` +
      `spray · ${m.shapeCounts.probe} probe.`,
  );

  // The worst-hit login surface.
  const lead = m.targets[0];
  if (lead) {
    const leak =
      lead.disposition.passRate !== null && lead.disposition.passed > 0
        ? ` — **${pct(lead.disposition.passRate)} reached the service** (${lead.disposition.passed} attempt(s) let ` +
          `through): turn on MFA / lockout and rate-limit this login.`
        : ` — the gateway blocked all actioned attempts so far.`;
    out.push(
      `🎯 Hardest-hit surface is **${serviceWithPort(lead.service, lead.port)}** on \`${lead.ip}\`` +
        `${lead.internal ? " *(your host)*" : ""}: ${lead.attempts} attempt(s) from ${lead.distinctSources} ` +
        `source(s) over ${fmtSpan(lead.firstMs, lead.lastMs)}${leak}`,
    );
  }

  // Concentrated brute-force — the worst single guesser.
  const brute = m.sources.filter((s) => s.shape === "brute-force")[0];
  if (brute) {
    out.push(
      `🔨 Worst brute-force is \`${brute.ip}\`${brute.internal ? " *(internal!)*" : ""} — ${brute.attempts} ` +
        `attempt(s)${brute.topService ? ` against ${brute.topService}` : ""}` +
        `${brute.topTarget ? ` on \`${brute.topTarget}\`` : ""} ` +
        `(${round2(brute.attemptsPerTarget)} per target). Block it and confirm the account survived.`,
    );
  }

  // Password spraying — the per-host lockout blind spot.
  const sprays = m.sources.filter((s) => s.shape === "spray");
  if (sprays.length) {
    const s = sprays[0]!;
    out.push(
      `💦 **${sprays.length} password-spray source(s)** are fanning thin across many hosts to dodge per-account ` +
        `lockout. Worst: \`${s.ip}\` touched ${s.distinctTargets} host(s) at ${round2(s.attemptsPerTarget)} ` +
        `attempt(s) each — per-host lockout will never trip; enforce MFA org-wide and alert on the fan-out.`,
    );
  }

  // Distributed assault on one surface — source-blocking alone won't hold.
  const dist = m.targets.filter((t) => t.distributed)[0];
  if (dist) {
    out.push(
      `🕸 **${serviceWithPort(dist.service, dist.port)}** on \`${dist.ip}\` is under a *distributed* attack — ` +
        `${dist.distinctSources} distinct sources sharing the guess work to dodge IP blocks. Rate-limit the ` +
        `service itself, not just the addresses.`,
    );
  }

  // Internal source guessing credentials — lateral movement / compromise tell.
  const insider = m.sources.filter((s) => s.internal && s.shape !== "probe")[0];
  if (insider) {
    out.push(
      `🚨 *Internal* host \`${insider.ip}\` is itself running credential attacks (${shapeLabel(insider.shape)}, ` +
        `${insider.attempts} attempt(s)) — an inside box guessing logins is a lateral-movement / compromise tell. ` +
        `Investigate it first.`,
    );
  }

  // Overall pass-through concern across every surface.
  if (m.passedCredential > 0 && m.credentialAlerts > 0) {
    const frac = m.passedCredential / (m.passedCredential + m.blockedCredential || m.passedCredential);
    out.push(
      `⚠️ **${m.passedCredential} credential attempt(s) reached a service** (vs ${m.blockedCredential} blocked` +
        `${Number.isFinite(frac) ? `, ${pct(frac)} of actioned` : ""}). Every one is a login the gateway *saw and ` +
        `let through* — only the password stopped it. MFA closes that gap.`,
    );
  }

  // Identification honesty — keyword vs port basis.
  if (m.credentialAlerts > 0) {
    const portFrac = m.portOnly / m.credentialAlerts;
    if (portFrac >= 0.5) {
      out.push(
        `ℹ️ **${pct(portFrac)} of the set was matched only by destination port**, not a credential signature — ` +
          `some may be ordinary traffic to an auth service rather than a login attempt. The signature-confirmed ` +
          `${m.keywordConfirmed} are the higher-confidence core.`,
      );
    }
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function targetTable(rows: TargetSurface[]): string {
  return mdTable(
    ["#", "Target", "Service", "Attempts", "Sources", "Severe", "Passed", "Pass rate", "Span", "Flags"],
    rows.map((t, i) => {
      const flags =
        (t.internal ? "🏠" : "") + (t.distributed ? "🕸" : "") + (t.highRisk ? "⚠️" : "");
      return [
        String(i + 1),
        cell(t.ip),
        cell(serviceWithPort(t.service, t.port)),
        String(t.attempts),
        String(t.distinctSources),
        String(t.severe),
        String(t.disposition.passed),
        t.disposition.passRate === null ? "—" : pct(t.disposition.passRate),
        fmtSpan(t.firstMs, t.lastMs),
        flags || "—",
      ];
    }),
  );
}

function sourceTable(rows: AttackSource[]): string {
  return mdTable(
    ["#", "Source", "Shape", "Attempts", "Targets", "Services", "Per-target", "Top service", "Passed", "Flags"],
    rows.map((s, i) => {
      const flags =
        (s.internal ? "🏠" : "") +
        (s.blocked ? "⛔" : "") +
        (s.watched ? "👁" : "") +
        (s.safe ? "✅" : "");
      return [
        String(i + 1),
        cell(s.ip),
        cell(shapeLabel(s.shape)),
        String(s.attempts),
        String(s.distinctTargets),
        String(s.distinctServices),
        String(round2(s.attemptsPerTarget)),
        cell(s.topService ?? "—"),
        String(s.disposition.passed),
        flags || "—",
      ];
    }),
  );
}

function renderMarkdown(m: BruteforceReport): string {
  const lines: string[] = [];
  lines.push(`# 🔑 SecTool Credential-Attack / Brute-Force Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** alerts identified as credential-bearing by signature semantics (brute-force / login / auth / ` +
      `password / kerberos / …) **or** a known authentication destination port (SSH/22, RDP/3389, SMB/445, …), ` +
      `folded per target login surface and per attacking source · ` +
      `**Credential alerts:** ${m.credentialAlerts} of ${m.totalWindowAlerts} ` +
      `(${m.keywordConfirmed} signature-confirmed, ${m.portOnly} port-only)`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.sources.length && !m.targets.length) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but none looked like a credential / ` +
          `login attack (no auth signature and no known authentication destination port). That is the good ` +
          `outcome — nobody is visibly guessing your logins this window.`,
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

  lines.push(`## Login surfaces under attack`);
  lines.push("");
  lines.push(
    `Destination \`host × service\` ranked by attempt volume — *where* the guessing is landing, how hard, from how ` +
      `many sources, and how much the gateway let reach the service.`,
  );
  lines.push("");
  lines.push(targetTable(m.targets));
  lines.push("");
  lines.push(
    `**Legend:** _Pass rate_ = share of *actioned* attempts the gateway let through to the service (only the ` +
      `password stopped those). _Span_ = first→last attempt. **Flags:** 🏠 your host · 🕸 distributed ` +
      `(≥${m.distributedThreshold} distinct sources — source-blocking alone won't hold) · ⚠️ high-risk admin / ` +
      `data-store port.`,
  );
  lines.push("");

  lines.push(`## Attacking sources by guessing volume`);
  lines.push("");
  lines.push(sourceTable(m.sources));
  lines.push("");
  lines.push(
    `**Legend:** _Shape_ — **🔨 brute-force** (≥${m.bruteThreshold} attempts concentrated on few hosts: dictionary ` +
      `/ stuffing — lock the host down) · **💦 spray** (≥${m.sprayThreshold} hosts, thin per host: dodging ` +
      `per-account lockout — enforce MFA org-wide) · **• probe** (low volume). _Per-target_ = mean attempts per ` +
      `distinct host (depth vs breadth). **Flags:** 🏠 internal source · ⛔ blocked · 👁 watched · ✅ safe.`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. These are IPS **detections**, not authentication outcomes — an attempt means a ` +
      `login tripped a rule, never that a password was **correct**; a "passed" attempt reached the service but may ` +
      `still have been rejected by the application, and a brute-force that never trips a rule is invisible, so every ` +
      `count is a lower bound. Credential identification is a **keyword / port heuristic** (the signature-confirmed ` +
      `vs. port-only split is shown above so a port-inflated set is visible); **destination ports are re-parsed from ` +
      `each alert's raw line**, not stored columns, and unparsed alerts fall back to a service inferred from the ` +
      `signature text or "unknown". A long look-back can hit the store's history cap and undercount. No live gateway ` +
      `query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the credential-attack / brute-force report from the stored alert
 * history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link BruteforceOptions}: `limit`, `minAttempts`,
 *              `sprayThreshold`, `bruteThreshold`, `distributedThreshold`, and a
 *              `nowMs` pin for deterministic tests.
 */
export function buildBruteforce(hours: number, opts: BruteforceOptions = {}): BruteforceReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minAttempts = Math.max(1, Math.floor(opts.minAttempts ?? DEFAULT_MIN_ATTEMPTS));
  const sprayThreshold = Math.max(2, Math.floor(opts.sprayThreshold ?? DEFAULT_SPRAY_THRESHOLD));
  const bruteThreshold = Math.max(2, Math.floor(opts.bruteThreshold ?? DEFAULT_BRUTE_THRESHOLD));
  const distributedThreshold = Math.max(2, Math.floor(opts.distributedThreshold ?? DEFAULT_DISTRIBUTED_THRESHOLD));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const sources = new Map<string, SourceAcc>();
  const surfaces = new Map<string, SurfaceAcc>();
  let credentialAlerts = 0;
  let keywordConfirmed = 0;
  let portOnly = 0;
  let passedCredential = 0;
  let blockedCredential = 0;

  for (const a of windowed) {
    const auth = classifyAuth(a);
    if (!auth) continue;
    credentialAlerts++;
    if (auth.basis === "signature") keywordConfirmed++;
    else portOnly++;

    const disp = classifyDisposition(a.action);
    if (disp === "passed") passedCredential++;
    else if (disp === "blocked") blockedCredential++;

    const src = validIp(a.srcIp);
    const dst = validIp(a.dstIp);

    // --- per-source aggregation (needs a valid source IP) ---
    if (src) {
      const acc = sources.get(src) ?? newSourceAcc(a.time);
      if (!sources.has(src)) sources.set(src, acc);
      acc.attempts++;
      acc.score += weightOf(a.severity);
      acc.severityMax = maxSeverity(acc.severityMax, a.severity);
      if (isSevere(a.severity)) acc.severe++;
      if (a.time < acc.firstMs) acc.firstMs = a.time;
      if (a.time > acc.lastMs) acc.lastMs = a.time;
      if (dst) {
        acc.targets.add(dst);
        acc.targetCounts.set(dst, (acc.targetCounts.get(dst) ?? 0) + 1);
      }
      acc.services.add(auth.service);
      acc.serviceCounts.set(auth.service, (acc.serviceCounts.get(auth.service) ?? 0) + 1);
      if (disp === "blocked") acc.blocked++;
      else if (disp === "passed") acc.passed++;
      else acc.unknown++;
    }

    // --- per-target-surface aggregation (needs a valid destination IP) ---
    if (dst) {
      const key = `${dst}|${auth.service}`;
      const acc = surfaces.get(key) ?? newSurfaceAcc(auth.service, auth.port, auth.highRisk, a.time);
      if (!surfaces.has(key)) surfaces.set(key, acc);
      acc.attempts++;
      acc.severityMax = maxSeverity(acc.severityMax, a.severity);
      if (isSevere(a.severity)) acc.severe++;
      if (a.time < acc.firstMs) acc.firstMs = a.time;
      if (a.time > acc.lastMs) acc.lastMs = a.time;
      // Backfill a port if a later alert on the same surface recovered one.
      if (acc.port === undefined && auth.port !== undefined) {
        acc.port = auth.port;
        acc.highRisk = auth.highRisk;
      }
      if (src) {
        acc.sources.add(src);
        acc.sourceCounts.set(src, (acc.sourceCounts.get(src) ?? 0) + 1);
      }
      if (disp === "blocked") acc.blocked++;
      else if (disp === "passed") acc.passed++;
      else acc.unknown++;
    }
  }

  const shapeCounts: ShapeCounts = { "brute-force": 0, spray: 0, distributed: 0, probe: 0 };
  const allServices = new Set<string>();
  const allTargets = new Set<string>();

  const sourceList: AttackSource[] = [...sources.entries()]
    .filter(([, acc]) => acc.attempts >= minAttempts)
    .map(([ip, acc]) => {
      const distinctTargets = acc.targets.size;
      const distinctServices = acc.services.size;
      for (const s of acc.services) allServices.add(s);
      for (const t of acc.targets) allTargets.add(t);
      const shape = classifyShape(acc.attempts, distinctTargets, sprayThreshold, bruteThreshold);
      shapeCounts[shape]++;
      const topTarget = topOf(acc.targetCounts);
      const topService = topOf(acc.serviceCounts);
      return {
        ip,
        internal: isPrivate(ip),
        shape,
        attempts: acc.attempts,
        distinctTargets,
        distinctServices,
        attemptsPerTarget: round2(acc.attempts / Math.max(1, distinctTargets)),
        severe: acc.severe,
        score: acc.score,
        disposition: splitOf(acc.blocked, acc.passed, acc.unknown),
        topTarget: topTarget.key,
        topService: topService.key,
        severityMax: acc.severityMax,
        firstMs: acc.firstMs,
        lastMs: acc.lastMs,
        blocked: blockStore.has(ip),
        watched: watchStore.has(ip),
        safe: safeStore.has(ip),
      } satisfies AttackSource;
    })
    // Most-active first: attempts, then reach, then severity score.
    .sort(
      (x, y) =>
        y.attempts - x.attempts ||
        y.distinctTargets - x.distinctTargets ||
        y.score - x.score ||
        (x.ip < y.ip ? -1 : x.ip > y.ip ? 1 : 0),
    );

  // The per-surface map is keyed by `${dstIp}|${service}`; rebuild rows directly
  // from the entries so the dstIp is recoverable from the key.
  const targets: TargetSurface[] = [...surfaces.entries()]
    .map(([key, acc]) => {
      const dstIp = key.slice(0, key.lastIndexOf("|"));
      const distinctSources = acc.sources.size;
      allServices.add(acc.service);
      allTargets.add(dstIp);
      const top = topOf(acc.sourceCounts);
      return {
        ip: dstIp,
        internal: isPrivate(dstIp),
        service: acc.service,
        port: acc.port,
        highRisk: acc.highRisk,
        attempts: acc.attempts,
        distinctSources,
        distributed: distinctSources >= distributedThreshold,
        severe: acc.severe,
        disposition: splitOf(acc.blocked, acc.passed, acc.unknown),
        topSource: top.key,
        severityMax: acc.severityMax,
        firstMs: acc.firstMs,
        lastMs: acc.lastMs,
      } satisfies TargetSurface;
    })
    // Most-attacked first: attempts, then distinct sources, then severe volume.
    .sort(
      (x, y) =>
        y.attempts - x.attempts ||
        y.distinctSources - x.distinctSources ||
        y.severe - x.severe ||
        (x.ip < y.ip ? -1 : x.ip > y.ip ? 1 : 0),
    );

  const cappedSources = sourceList.slice(0, limit);
  const cappedTargets = targets.slice(0, limit);

  const model: BruteforceReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    credentialAlerts,
    keywordConfirmed,
    portOnly,
    passedCredential,
    blockedCredential,
    distinctAttackers: sourceList.length,
    distinctTargets: allTargets.size,
    distinctServices: allServices.size,
    sprayThreshold,
    bruteThreshold,
    distributedThreshold,
    shapeCounts,
    targets: cappedTargets,
    sources: cappedSources,
    highlights: [],
    markdown: "",
  };
  model.highlights = writeHighlights(safeHours, model);
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded credential-attack report. */
export function bruteforceFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-bruteforce-${stamp}.md`;
}
