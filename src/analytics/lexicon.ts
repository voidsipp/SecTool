/**
 * Threat-lexicon / signature-vocabulary report — "**what words keep showing up
 * in the threats hitting me, and what do they say my landscape is about?**"
 *
 * Every other signature-axis report in SecTool treats a signature as an opaque,
 * indivisible string:
 *
 *   - **lifecycle / audience / rarity** rank *whole* signatures (chronic vs
 *     acute, spray vs snipe, common vs bespoke). Two near-identical rules — `ET
 *     SCAN Suspicious inbound to MSSQL 1433` and `ET SCAN Suspicious inbound to
 *     PostgreSQL 5432` — count as two unrelated rows, so the *theme* they share
 *     ("inbound database-port scanning") never surfaces as a single number.
 *   - **ruleset** keys by the stable `gid:sid` and its feed provenance — the rule
 *     *identity*, not its *content*.
 *   - **cve / cwe / owasp / mitre** map signatures onto external *taxonomies*
 *     (specific bugs, weakness classes, web-risk buckets, adversary behaviour) —
 *     authoritative, but only as good as the mapping table and blind to anything
 *     not yet mapped (a fresh malware family name, a tool string, a campaign tag).
 *
 * This report takes the opposite, bottom-up view: it **tokenises the signature
 * text itself** and counts the *vocabulary* of your threat landscape. It answers
 * the question a word-frequency view answers that a row-per-signature view never
 * can — *"`log4j` appears across 4 distinct signatures and 212 alerts from 30
 * sources"* — by collapsing rule variants down to the words they share. Two
 * complementary lenses:
 *
 *   1. **Rule-class taxonomy** — the vendor's own coarse class, parsed from the
 *      Emerging-Threats / Snort prefix convention (`ET SCAN …`, `ET EXPLOIT …`,
 *      `GPL WEB_SERVER …`, `ETPRO MALWARE …`). This is the ruleset author's
 *      one-word verdict on intent, and it is *free* — already sitting in the
 *      first token of most signatures — yet no other report extracts it. It is
 *      distinct from the gateway's own `category` field (a different, often
 *      coarser, vendor axis) and from `--ruleset` (which keys by SID, not class).
 *
 *   2. **Threat lexicon** — the ranked frequency of every meaningful *term* mined
 *      from the signature corpus (generic IDS filler like "inbound", "possible",
 *      "suspicious" stop-worded out), each term bucketed into a human **theme**
 *      (recon, exploitation, malware/C2, web, auth/brute-force, protocol-abuse,
 *      reputation, policy/info) so the table doubles as a one-glance map of *what
 *      kind* of trouble dominates — the "word cloud as a sortable table".
 *
 * Why it is operationally useful, not just cute: a term that spans **many
 * distinct signatures** is a *theme* your rule-by-rule reports fragment, and a
 * term whose alerts are **mostly serious and mostly un-blocked** is a vocabulary
 * word worth a hunt. The report ranks on alert volume but prints distinct-
 * signature spread, distinct-source reach, worst severity and block-rate beside
 * every term so the eye lands on "broad theme + nasty + getting through" without
 * arithmetic.
 *
 * Honest caveats baked into the output:
 *
 *   - **It is lexical, not semantic.** `scan` the verb and `scan` inside a
 *     product name tokenise the same; a term floor (`--min`, default 2) keeps
 *     one-off noise out, and the theme buckets are a heuristic best-effort, not a
 *     taxonomy with authority — for that, use `--mitre` / `--cwe` / `--cve`.
 *   - **A term's alerts overlap.** A single alert contributes a count to *every*
 *     distinct term in its signature, so term alert-counts deliberately sum past
 *     the alert total — this is a vocabulary frequency, not a partition. The
 *     header states the alert total separately so the distinction is explicit.
 *   - **Empty signatures contribute nothing.** Alerts that arrived without a
 *     signature string (some flow/anomaly events) are counted in the header's
 *     "no signature" tally and excluded from both lenses, so the corpus size is
 *     never silently overstated.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network. Output is
 * both a structured model and a ready-to-paste Markdown document, mirroring
 * potency.ts, lifecycle.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** The human theme buckets a lexicon term is sorted into. */
export type LexiconTheme =
  | "recon"
  | "exploit"
  | "malware"
  | "web"
  | "auth"
  | "protocol"
  | "reputation"
  | "policy"
  | "other";

/** One ranked term in the threat lexicon. */
export interface LexiconTerm {
  /** The normalised (lower-case) term as mined from signature text. */
  term: string;
  /** Which theme bucket the term was sorted into. */
  theme: LexiconTheme;
  /** Total alerts whose signature contains this term (counts overlap across terms). */
  alerts: number;
  /** Distinct signatures the term appears in — its theme-spread. */
  signatures: number;
  /** Distinct source IPs that fired a signature carrying this term. */
  sources: number;
  /** Distinct destination IPs touched by those alerts. */
  targets: number;
  /** Worst severity observed across the term's alerts. */
  severityMax: Severity;
  /** High + critical alert count for the term. */
  serious: number;
  /** Share of the term's alerts the gateway blocked, 0..1. */
  blockedShare: number;
  /** A representative signature the term was mined from (busiest). */
  exampleSignature: string;
}

/** One row of the vendor rule-class taxonomy (parsed from the signature prefix). */
export interface LexiconRuleClass {
  /** The class token, upper-cased (e.g. "SCAN", "EXPLOIT", "MALWARE"). */
  klass: string;
  /** The ruleset family the class came from (e.g. "ET", "GPL", "ETPRO"). */
  family: string;
  /** Total alerts whose signature carried this class prefix. */
  alerts: number;
  /** Distinct signatures under this class. */
  signatures: number;
  /** Distinct source IPs. */
  sources: number;
  /** Worst severity observed. */
  severityMax: Severity;
  /** High + critical alert count. */
  serious: number;
  /** Share of the class's alerts the gateway blocked, 0..1. */
  blockedShare: number;
  /** Share of all classified alerts this class carries, 0..1. */
  share: number;
}

/** A theme roll-up across all its terms. */
export interface LexiconThemeRollup {
  theme: LexiconTheme;
  /** Distinct terms filed under this theme. */
  terms: number;
  /** Summed alert mentions across those terms (overlapping). */
  alerts: number;
  /** Share of all term mentions this theme carries, 0..1. */
  share: number;
}

export interface LexiconReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts in the window that carried a non-empty signature string. */
  totalAlerts: number;
  /** Alerts in the window with NO signature (excluded from both lenses). */
  noSignature: number;
  /** Distinct signature strings seen in the window. */
  distinctSignatures: number;
  /** Distinct meaningful terms mined (before the {@link minCount} floor). */
  distinctTerms: number;
  /** The term-frequency floor applied to qualify for the lexicon table. */
  minCount: number;
  /** The theme carrying the most term mentions, if any. */
  topTheme?: LexiconTheme;
  /** Vendor rule-class taxonomy, ranked by alerts desc. */
  ruleClasses: LexiconRuleClass[];
  /** Alerts whose signature carried a recognised vendor class prefix. */
  classifiedAlerts: number;
  /** Per-theme roll-up, ordered by the canonical theme order. */
  themes: LexiconThemeRollup[];
  /** Ranked qualifying terms (alerts desc), capped at the row limit. */
  terms: LexiconTerm[];
  /** True when more qualifying terms exist than were shown. */
  truncated: boolean;
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface LexiconOptions {
  /** Max term rows shown (highest alert-count kept); clamped to [1, 200]. Default 30. */
  limit?: number;
  /** Term-frequency floor to qualify for the table; clamped to [1, 1000]. Default 2. */
  minCount?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 30;
const DEFAULT_MIN_COUNT = 2;
const MS_PER_HOUR = 3_600_000;

/** Canonical display order for the theme buckets. */
const THEME_ORDER: readonly LexiconTheme[] = [
  "exploit",
  "malware",
  "recon",
  "web",
  "auth",
  "protocol",
  "reputation",
  "policy",
  "other",
];

const THEME_LABEL: Record<LexiconTheme, string> = {
  recon: "🔍 Recon / scan",
  exploit: "💥 Exploitation",
  malware: "🦠 Malware / C2",
  web: "🌐 Web attack",
  auth: "🔑 Auth / brute-force",
  protocol: "📡 Protocol abuse",
  reputation: "🚫 Reputation / blocklist",
  policy: "📜 Policy / info",
  other: "· Other",
};

/**
 * Curated term → theme map. Deliberately small and high-signal: only words whose
 * presence in a Suricata/ET signature is a reliable tell of intent. Anything not
 * matched here (exactly, then by the substring fallback below) lands in "other".
 */
const THEME_KEYWORDS: Record<Exclude<LexiconTheme, "other">, readonly string[]> = {
  recon: [
    "scan", "scanner", "sweep", "probe", "probing", "recon", "reconnaissance",
    "enumeration", "discovery", "masscan", "zmap", "nmap", "shodan", "censys",
    "crawler", "fingerprint",
  ],
  exploit: [
    "exploit", "rce", "overflow", "injection", "sqli", "sql", "traversal", "lfi",
    "rfi", "deserialization", "deserialize", "log4j", "log4shell", "struts",
    "shellshock", "heartbleed", "eternalblue", "spring4shell", "shellcode",
    "rom-0", "ghostcat", "proxylogon", "proxyshell", "command", "execution",
  ],
  malware: [
    "malware", "trojan", "botnet", "mirai", "mozi", "gafgyt", "tsunami", "cnc",
    "c2", "cobalt", "beacon", "ransomware", "miner", "coinminer", "cryptominer",
    "backdoor", "rat", "worm", "loader", "dropper", "stealer", "keylogger",
    "rootkit", "emotet", "qakbot", "trickbot",
  ],
  web: [
    "web", "xss", "webshell", "php", "wordpress", "joomla", "drupal", "apache",
    "nginx", "cgi", "phpmyadmin", "thinkphp", "wso", "jndi", "cms", "plugin",
  ],
  auth: [
    "brute", "bruteforce", "login", "password", "credential", "credentials",
    "auth", "ssh", "rdp", "telnet", "vnc", "smb", "ftp", "spray", "default-login",
  ],
  protocol: [
    "amplification", "amp", "dos", "ddos", "flood", "icmp", "snmp", "ntp", "ldap",
    "memcached", "dns", "tftp", "ssdp", "reflection", "fragmentation",
  ],
  reputation: [
    "dshield", "cins", "spamhaus", "blocklist", "blacklist", "reputation", "tor",
    "compromised", "drop", "abuse", "feodo", "bruteforceblocker", "poor",
  ],
  policy: [
    "policy", "info", "informational", "hunting", "user_agent", "user-agent",
    "tls", "ssl", "certificate", "external",
  ],
};

/** Reverse index built once at module load: exact term → theme. */
const TERM_THEME = new Map<string, LexiconTheme>();
for (const theme of Object.keys(THEME_KEYWORDS) as Array<Exclude<LexiconTheme, "other">>) {
  for (const kw of THEME_KEYWORDS[theme]) if (!TERM_THEME.has(kw)) TERM_THEME.set(kw, theme);
}

/** Substring fallbacks for terms not matched exactly (e.g. "sqlinjection", "cve-…"). */
const THEME_SUBSTRINGS: ReadonlyArray<readonly [string, LexiconTheme]> = [
  ["cve-", "exploit"],
  ["exploit", "exploit"],
  ["inject", "exploit"],
  ["overflow", "exploit"],
  ["traversal", "exploit"],
  ["scan", "recon"],
  ["sweep", "recon"],
  ["brute", "auth"],
  ["login", "auth"],
  ["trojan", "malware"],
  ["malware", "malware"],
  ["botnet", "malware"],
  ["miner", "malware"],
  ["ransom", "malware"],
  ["webshell", "web"],
  ["flood", "protocol"],
  ["ddos", "protocol"],
  ["blocklist", "reputation"],
  ["blacklist", "reputation"],
];

/**
 * Generic IDS-grammar filler with no threat-intel value. Stop-worded out so the
 * lexicon surfaces vocabulary, not connective tissue.
 */
const STOPWORDS = new Set<string>([
  "to", "the", "a", "an", "and", "or", "of", "for", "from", "via", "with", "in",
  "on", "at", "by", "is", "are", "be", "as", "no", "not", "non", "may", "might",
  "likely", "possible", "potential", "potentially", "suspicious", "suspect",
  "attempt", "attempted", "attempts", "inbound", "outbound", "external",
  "internal", "known", "observed", "detected", "seen", "response", "responses",
  "request", "requests", "server", "client", "traffic", "activity", "rule",
  "alert", "this", "that", "these", "those", "using", "used", "use", "over",
  "into", "out", "off", "your", "you", "etc", "generic", "common", "other",
  "unknown", "default", "test", "port", "ports", "tcp", "udp", "ip", "net",
  "data", "bytes", "byte", "len", "length", "based", "type", "attack", "attacker",
  "remote", "local", "host", "service", "connection", "session", "packet",
  "string", "version", "system", "access", "successful", "failed", "multiple",
  "single", "new", "old", "via", "abnormal", "anomalous", "behavior", "behaviour",
]);

/** Short tokens (< 3 chars) worth keeping despite the length floor. */
const SHORT_ALLOW = new Set<string>(["c2", "ai"]);

const TOKEN_RE = /[a-z0-9]+(?:[._-][a-z0-9]+)*/g;

/** Ruleset families whose second token is the coarse class (ET SCAN, GPL WEB_SERVER…). */
const RULE_FAMILIES = new Set<string>(["ET", "ETPRO", "GPL", "SURICATA", "EMERGING"]);

// ----- helpers (mirror potency.ts) -------------------------------------------

function validIp(ip: string | undefined): string | undefined {
  return ip && isIP(ip) !== 0 ? ip : undefined;
}

function asSeverity(s: string | undefined): Severity {
  return (SEVERITY_ORDER as readonly string[]).includes(s ?? "") ? (s as Severity) : "info";
}

function sevRank(s: Severity): number {
  return (SEVERITY_ORDER as readonly string[]).indexOf(s);
}

function maxSeverity(a: Severity, b: Severity): Severity {
  return sevRank(b) > sevRank(a) ? b : a;
}

function isSerious(s: Severity): boolean {
  return sevRank(s) >= sevRank("high");
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

function pct(share: number): string {
  return `${Math.round(share * 100)}%`;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function clip(s: string, max = 46): string {
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

/** Classify a single mined term into its theme bucket (exact, then substring). */
function themeOf(term: string): LexiconTheme {
  const exact = TERM_THEME.get(term);
  if (exact) return exact;
  for (const [needle, theme] of THEME_SUBSTRINGS) if (term.includes(needle)) return theme;
  return "other";
}

/** Extract the distinct, meaningful terms from one signature string. */
function termsOf(signature: string): string[] {
  const seen = new Set<string>();
  const matches = signature.toLowerCase().match(TOKEN_RE);
  if (!matches) return [];
  for (const raw of matches) {
    const t = raw.replace(/^[._-]+|[._-]+$/g, "");
    if (!t || STOPWORDS.has(t)) continue;
    if (t.length < 3 && !SHORT_ALLOW.has(t)) continue;
    // Drop pure-numeric / dotted-numeric tokens (ports, byte counts, IP fragments).
    if (/^[0-9._-]+$/.test(t)) continue;
    seen.add(t);
  }
  return [...seen];
}

/**
 * Parse the vendor rule-class from a signature prefix, e.g.
 *   "ET SCAN Suspicious inbound to MSSQL 1433"   -> { family: "ET", klass: "SCAN" }
 *   "GPL WEB_SERVER 403 Forbidden"               -> { family: "GPL", klass: "WEB_SERVER" }
 * Returns undefined when the leading token is not a recognised ruleset family.
 */
function ruleClassOf(signature: string): { family: string; klass: string } | undefined {
  const parts = signature.trim().split(/\s+/);
  if (parts.length < 2) return undefined;
  const family = parts[0]!.toUpperCase();
  if (!RULE_FAMILIES.has(family)) return undefined;
  const klass = parts[1]!.toUpperCase();
  // The class token is an uppercase identifier (letters, digits, underscores).
  if (!/^[A-Z][A-Z0-9_]*$/.test(klass)) return undefined;
  return { family, klass };
}

// ----- aggregation -----------------------------------------------------------

interface TermAcc {
  term: string;
  alerts: number;
  blocked: number;
  serious: number;
  severityMax: Severity;
  signatures: Map<string, number>;
  sources: Set<string>;
  targets: Set<string>;
}

function newTermAcc(term: string): TermAcc {
  return {
    term,
    alerts: 0,
    blocked: 0,
    serious: 0,
    severityMax: "info",
    signatures: new Map(),
    sources: new Set(),
    targets: new Set(),
  };
}

interface ClassAcc {
  family: string;
  klass: string;
  alerts: number;
  blocked: number;
  serious: number;
  severityMax: Severity;
  signatures: Set<string>;
  sources: Set<string>;
}

function newClassAcc(family: string, klass: string): ClassAcc {
  return { family, klass, alerts: 0, blocked: 0, serious: 0, severityMax: "info", signatures: new Set(), sources: new Set() };
}

/** Pick the busiest signature from a count map (deterministic tie-break by string). */
function topSignature(counts: Map<string, number>): string {
  let best = "";
  let bestN = -1;
  for (const [sig, n] of counts) {
    if (n > bestN || (n === bestN && sig < best)) {
      best = sig;
      bestN = n;
    }
  }
  return best;
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(
  report: Omit<LexiconReport, "highlights" | "markdown">,
  ranked: LexiconTerm[],
): string[] {
  const out: string[] = [];
  if (report.totalAlerts === 0) return out;

  // The headline term — most mentioned vocabulary word.
  const top = ranked[0];
  if (top) {
    out.push(
      `🔤 Loudest word in your threat landscape: **\`${top.term}\`** (${THEME_LABEL[top.theme]}) — ` +
        `**${top.alerts}** alert(s) across **${top.signatures}** distinct signature(s) and ${top.sources} source(s), ` +
        `worst \`${top.severityMax}\`, ${pct(top.blockedShare)} blocked. e.g. \`${clip(top.exampleSignature)}\`.`,
    );
  }

  // The broadest theme word — a term spanning many distinct signatures is a
  // theme your per-signature reports fragment into unrelated rows.
  const broad = [...ranked].sort((a, b) => b.signatures - a.signatures || b.alerts - a.alerts)[0];
  if (broad && broad.signatures >= 3 && broad.term !== top?.term) {
    out.push(
      `🧩 Cross-cutting theme: **\`${broad.term}\`** spans **${broad.signatures}** distinct signatures ` +
        `(${broad.alerts} alerts) — rule-by-rule reports like \`--lifecycle\` / \`--rarity\` scatter this across ` +
        `${broad.signatures} unrelated rows; here it is one number.`,
    );
  }

  // A serious + leaking term — nasty vocabulary that mostly got through.
  const leak = [...ranked]
    .filter((t) => isSerious(t.severityMax) && t.blockedShare < 0.5 && t.alerts >= report.minCount)
    .sort((a, b) => b.serious - a.serious || b.alerts - a.alerts)[0];
  if (leak) {
    out.push(
      `⚠️ Worth a hunt: **\`${leak.term}\`** carries **${leak.serious}** serious alert(s) (worst \`${leak.severityMax}\`) ` +
        `yet only **${pct(leak.blockedShare)}** were blocked — pivot with \`--detection\` / \`--cve\` on the signatures it tags.`,
    );
  }

  // The dominant theme split.
  if (report.topTheme && report.topTheme !== "other") {
    const t = report.themes.find((x) => x.theme === report.topTheme);
    if (t) {
      out.push(
        `📊 Your landscape's accent is **${THEME_LABEL[t.theme]}** — ${t.terms} term(s), ` +
          `**${pct(t.share)}** of all term mentions. The vocabulary tells you what kind of trouble dominates before you read a single rule.`,
      );
    }
  }

  // The biggest vendor rule-class.
  const cls = report.ruleClasses[0];
  if (cls) {
    out.push(
      `🏷️ Vendor verdict: the busiest rule-class is **\`${cls.family} ${cls.klass}\`** — ` +
        `**${pct(cls.share)}** of classified alerts (${cls.alerts} across ${cls.signatures} signatures, worst \`${cls.severityMax}\`). ` +
        `That is the ruleset author's one-word read on intent.`,
    );
  }

  return out;
}

// ----- markdown --------------------------------------------------------------

function classTable(rows: LexiconRuleClass[]): string {
  return mdTable(
    ["Rule class", "Alerts", "% class'd", "Sigs", "Sources", "Serious", "Worst", "Blocked"],
    rows.map((c) => [
      cell(`\`${c.family} ${c.klass}\``),
      String(c.alerts),
      pct(c.share),
      String(c.signatures),
      String(c.sources),
      c.serious > 0 ? `**${c.serious}**` : "0",
      cell(c.severityMax),
      pct(c.blockedShare),
    ]),
  );
}

function themeTable(rows: LexiconThemeRollup[]): string {
  return mdTable(
    ["Theme", "Terms", "Mentions", "% mentions"],
    rows.map((t) => [THEME_LABEL[t.theme], String(t.terms), String(t.alerts), pct(t.share)]),
  );
}

function termTable(rows: LexiconTerm[]): string {
  return mdTable(
    ["Term", "Theme", "Alerts", "Sigs", "Sources", "Dsts", "Serious", "Worst", "Blocked", "Example signature"],
    rows.map((t) => [
      cell(`\`${t.term}\``),
      THEME_LABEL[t.theme],
      `**${t.alerts}**`,
      String(t.signatures),
      String(t.sources),
      String(t.targets),
      t.serious > 0 ? `**${t.serious}**` : "0",
      cell(t.severityMax),
      pct(t.blockedShare),
      cell(clip(t.exampleSignature)),
    ]),
  );
}

function renderMarkdown(m: LexiconReport): string {
  const lines: string[] = [];
  lines.push(`# 🔤 SecTool Threat-Lexicon / Signature Vocabulary`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** signature text tokenised into terms (generic IDS filler stop-worded out), each bucketed into a ` +
      `threat theme; vendor rule-class parsed from the \`ET\`/\`GPL\`/\`ETPRO\` prefix. Offline, deterministic · ` +
      `**Alerts w/ signature:** ${m.totalAlerts} · **No signature:** ${m.noSignature} · ` +
      `**Distinct signatures:** ${m.distinctSignatures} · **Distinct terms:** ${m.distinctTerms} · ` +
      `**Floor:** ≥ ${m.minCount} alert(s) to list a term.`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (m.totalAlerts === 0) {
    lines.push(
      `No alerts with a signature string landed in the last ${m.hours}h — there is no vocabulary to mine. ` +
        `Widen the window (\`--lexicon <more hours>\`) or confirm forwarding with \`--coverage\`.`,
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Vendor rule-class taxonomy`);
  lines.push("");
  lines.push(
    `_The ruleset author's own coarse verdict, free in the signature prefix. Distinct from the gateway's \`category\` ` +
      `field and from \`--ruleset\` (which keys by SID, not class)._`,
  );
  lines.push("");
  lines.push(classTable(m.ruleClasses));
  lines.push("");

  lines.push(`## Threat themes`);
  lines.push("");
  lines.push(`_Where your vocabulary clusters. Mentions overlap (one alert tags every term in its signature)._`);
  lines.push("");
  lines.push(themeTable(m.themes));
  lines.push("");

  lines.push(`## Threat lexicon — ranked terms`);
  lines.push("");
  if (m.truncated) {
    lines.push(`_Showing the **${m.terms.length}** most-mentioned qualifying term(s). Raise \`--limit\` to see more._`);
    lines.push("");
  }
  lines.push(termTable(m.terms));
  lines.push("");
  lines.push(
    `**Legend:** _Alerts_ = alerts whose signature contains the term (the ranking key; counts overlap across terms). ` +
      `_Sigs_ = distinct signatures the term spans (its theme-spread). _Serious_ = high + critical. ` +
      `_Blocked_ = share the gateway dropped. Themes: ${THEME_ORDER.map((t) => THEME_LABEL[t]).join(" · ")}.`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. This is a **lexical** view — it counts words, not meaning: a term floor ` +
      `(\`--min ${m.minCount}\`) keeps one-off noise out, and the theme buckets are a heuristic. For authoritative ` +
      `mappings use \`--cve\` (specific bugs), \`--cwe\` / \`--owasp\` (weakness classes) or \`--mitre\` (adversary ` +
      `behaviour); for whole-signature lifecycle use \`--lifecycle\` / \`--rarity\` / \`--audience\`. Term alert-counts ` +
      `deliberately sum past the alert total because one alert contributes to every term in its signature. No live ` +
      `gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the threat-lexicon / signature-vocabulary report from the stored alert
 * history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link LexiconOptions}: `limit`, `minCount`, and a `nowMs` pin for
 *              deterministic tests.
 */
export function buildLexicon(hours: number, opts: LexiconOptions = {}): LexiconReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minCount = Math.max(1, Math.min(1000, Math.floor(opts.minCount ?? DEFAULT_MIN_COUNT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const terms = new Map<string, TermAcc>();
  const classes = new Map<string, ClassAcc>();
  const distinctSignatures = new Set<string>();
  let totalAlerts = 0;
  let noSignature = 0;
  let classifiedAlerts = 0;

  for (const a of windowed) {
    const sig = a.signature?.trim();
    if (!sig) {
      noSignature++;
      continue;
    }
    totalAlerts++;
    distinctSignatures.add(sig);

    const severity = asSeverity(a.severity);
    const serious = isSerious(severity);
    const blocked = classifyDisposition(a.action) === "blocked";
    const src = validIp(a.srcIp);
    const dst = validIp(a.dstIp);

    // --- lens 1: vendor rule-class -------------------------------------------
    const rc = ruleClassOf(sig);
    if (rc) {
      classifiedAlerts++;
      const key = `${rc.family} ${rc.klass}`;
      let cacc = classes.get(key);
      if (!cacc) {
        cacc = newClassAcc(rc.family, rc.klass);
        classes.set(key, cacc);
      }
      cacc.alerts++;
      if (blocked) cacc.blocked++;
      if (serious) cacc.serious++;
      cacc.severityMax = maxSeverity(cacc.severityMax, severity);
      cacc.signatures.add(sig);
      if (src) cacc.sources.add(src);
    }

    // --- lens 2: lexicon terms -----------------------------------------------
    for (const term of termsOf(sig)) {
      let tacc = terms.get(term);
      if (!tacc) {
        tacc = newTermAcc(term);
        terms.set(term, tacc);
      }
      tacc.alerts++;
      if (blocked) tacc.blocked++;
      if (serious) tacc.serious++;
      tacc.severityMax = maxSeverity(tacc.severityMax, severity);
      tacc.signatures.set(sig, (tacc.signatures.get(sig) ?? 0) + 1);
      if (src) tacc.sources.add(src);
      if (dst) tacc.targets.add(dst);
    }
  }

  const distinctTerms = terms.size;

  // Rank vendor rule-classes by alert volume (tie-break sigs, then name).
  const ruleClasses: LexiconRuleClass[] = [...classes.values()]
    .map((c) => ({
      klass: c.klass,
      family: c.family,
      alerts: c.alerts,
      signatures: c.signatures.size,
      sources: c.sources.size,
      severityMax: c.severityMax,
      serious: c.serious,
      blockedShare: c.alerts > 0 ? round4(c.blocked / c.alerts) : 0,
      share: classifiedAlerts > 0 ? round4(c.alerts / classifiedAlerts) : 0,
    } satisfies LexiconRuleClass))
    .sort(
      (a, b) =>
        b.alerts - a.alerts ||
        b.signatures - a.signatures ||
        (a.family + a.klass < b.family + b.klass ? -1 : 1),
    );

  // Build the ranked term list (alerts desc; tie-break sigs, sources, then term).
  const rankedAll: LexiconTerm[] = [...terms.values()]
    .filter((t) => t.alerts >= minCount)
    .map((t) => ({
      term: t.term,
      theme: themeOf(t.term),
      alerts: t.alerts,
      signatures: t.signatures.size,
      sources: t.sources.size,
      targets: t.targets.size,
      severityMax: t.severityMax,
      serious: t.serious,
      blockedShare: t.alerts > 0 ? round4(t.blocked / t.alerts) : 0,
      exampleSignature: topSignature(t.signatures),
    } satisfies LexiconTerm))
    .sort(
      (a, b) =>
        b.alerts - a.alerts ||
        b.signatures - a.signatures ||
        b.sources - a.sources ||
        (a.term < b.term ? -1 : a.term > b.term ? 1 : 0),
    );

  // Per-theme roll-up over ALL qualifying terms (not just the shown rows).
  const totalMentions = rankedAll.reduce((n, t) => n + t.alerts, 0);
  const themeMap = new Map<LexiconTheme, { terms: number; alerts: number }>();
  for (const t of rankedAll) {
    const e = themeMap.get(t.theme) ?? { terms: 0, alerts: 0 };
    e.terms++;
    e.alerts += t.alerts;
    themeMap.set(t.theme, e);
  }
  const themes: LexiconThemeRollup[] = THEME_ORDER.map((theme) => {
    const e = themeMap.get(theme) ?? { terms: 0, alerts: 0 };
    return {
      theme,
      terms: e.terms,
      alerts: e.alerts,
      share: totalMentions > 0 ? round4(e.alerts / totalMentions) : 0,
    } satisfies LexiconThemeRollup;
  }).filter((t) => t.terms > 0);

  // The dominant theme (most mentions), ignoring the "other" catch-all.
  const topTheme = [...themes]
    .filter((t) => t.theme !== "other")
    .sort((a, b) => b.alerts - a.alerts)[0]?.theme;

  const truncated = rankedAll.length > limit;
  const shown = truncated ? rankedAll.slice(0, limit) : rankedAll;

  const base: Omit<LexiconReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalAlerts,
    noSignature,
    distinctSignatures: distinctSignatures.size,
    distinctTerms,
    minCount,
    topTheme,
    ruleClasses,
    classifiedAlerts,
    themes,
    terms: shown,
    truncated,
  };

  const highlights = writeHighlights(base, rankedAll);
  const model: LexiconReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded lexicon report. */
export function lexiconFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-lexicon-${stamp}.md`;
}
