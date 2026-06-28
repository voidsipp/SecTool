/**
 * Payload-artifact / embedded-IOC extraction report — "**beyond the IP, what
 * concrete indicators are actually riding inside my alert payloads — domains,
 * URLs, file hashes, CVEs, tool user-agents — that I can pivot, block or hunt
 * on?**"
 *
 * Every other indicator-oriented report in this project stops at the *network*
 * layer:
 *
 *   - **iocs.ts** exports the *IP-level* indicators (the attacking addresses)
 *     in firewall-ready formats — it never looks *inside* the payload.
 *   - **ports.ts** re-parses only the destination *port / protocol* from the raw
 *     line; **cve.ts** maps CVEs from the *signature name*, not the payload body.
 *   - **clusters.ts / netblocks.ts / srcport.ts** correlate *infrastructure*
 *     (ranges, source ports), not the content an alert carried.
 *
 * Yet a single Suricata EVE record routinely carries far richer, more durable
 * indicators than its endpoints: the **HTTP host / URL** that was requested, the
 * **TLS SNI** or **DNS query** name, a downloaded file's **MD5 / SHA-256**, an
 * embedded **CVE** reference, and the attacker's **User-Agent** string. These
 * *content-level* artifacts are exactly what a threat hunter pivots on — an IP
 * rotates in minutes, but a malware hash, a C2 domain, or a `sqlmap` user-agent
 * is a fingerprint you can block estate-wide and search historical logs for.
 *
 * This report mines every stored alert's raw line for those artifacts, using the
 * same two-shape strategy ports.ts uses for ports — a structured pass over an
 * embedded Suricata **EVE JSON** object, then a conservative **regex** fallback
 * over the raw text — and rolls each distinct artifact up over the window:
 *
 *   - **kind** — one of `hash`, `cve`, `domain`, `url`, `useragent`, ordered by
 *     hunting value (a file hash or CVE is a sharper IOC than a common UA);
 *   - **prevalence** — alerts carrying it, distinct source IPs, distinct internal
 *     targets, first/last seen, and the loudest signature it rode in on;
 *   - **a suspicious flag** — set for *every* hash and CVE (always notable), and
 *     for user-agents matching known offensive-tooling fingerprints (sqlmap,
 *     nikto, nmap, masscan, curl, python-requests …).
 *
 * Honest caveats baked into the output:
 *
 *   - **Artifacts are re-parsed, not stored.** Only alerts whose raw line still
 *     carried an EVE JSON body or a recognisable artifact contribute; the
 *     *unparsed* count is shown so thin coverage is visible rather than mistaken
 *     for "no indicators". A bare UniFi notification or a fast.log line with only
 *     a flow tuple yields nothing here — and that is the common case, so treat
 *     every count as a lower bound.
 *   - **Extraction is deliberately conservative.** Domains are taken from
 *     structured fields and parsed out of URLs, *not* from a blanket domain regex
 *     (which would match file extensions and noise); hashes are only mined from
 *     `fileinfo` or when a hash-context keyword is present, to avoid matching
 *     arbitrary hex IDs. Precision over recall — a missed artifact is safer than
 *     a fabricated one.
 *   - **Presence ≠ malice.** A domain or URL in a payload is *observed*, not
 *     *judged*. `example.com` can appear in a benign request that merely tripped
 *     a rule. The report surfaces indicators to pivot on; enrichment / reputation
 *     is the analyst's next step (and out of scope for this offline view).
 *   - **Window-bounded & store-capped.** A long look-back can hit the store's
 *     history cap and undercount artifacts.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network. Output is
 * both a structured model and a ready-to-paste Markdown document, mirroring
 * report.ts, ports.ts, scan.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** The content-level indicator kinds this report extracts, hunting-value order. */
export type ArtifactKind = "hash" | "cve" | "domain" | "url" | "useragent";

/** Canonical display order + human label for each artifact kind. */
export const ARTIFACT_KINDS: readonly { kind: ArtifactKind; label: string; emoji: string }[] = [
  { kind: "hash", label: "File hashes", emoji: "🧬" },
  { kind: "cve", label: "CVE references", emoji: "🩹" },
  { kind: "domain", label: "Domains / hostnames", emoji: "🌐" },
  { kind: "url", label: "URLs", emoji: "🔗" },
  { kind: "useragent", label: "User-agents", emoji: "🪪" },
] as const;

/** One distinct extracted artifact and its prevalence over the window. */
export interface Artifact {
  /** Which indicator family this value belongs to. */
  kind: ArtifactKind;
  /** The artifact value (normalised: lower-cased hashes/domains, trimmed UA). */
  value: string;
  /** Alerts in the window whose payload carried this artifact. */
  count: number;
  /** Distinct source IPs that carried it. */
  distinctSources: number;
  /** Distinct internal (RFC1918) destination hosts it was aimed at. */
  distinctTargets: number;
  /** Worst severity across the alerts carrying it. */
  severityMax: Severity;
  /** First sighting (ms epoch). */
  firstSeenMs: number;
  /** Most-recent sighting (ms epoch). */
  lastSeenMs: number;
  /** The loudest signature this artifact rode in on, if any. */
  topSignature?: string;
  /** True for every hash/CVE and for known offensive-tool user-agents. */
  suspicious: boolean;
}

/** A kind and the artifacts filed under it, most-prevalent first. */
export interface ArtifactGroup {
  kind: ArtifactKind;
  label: string;
  /** Distinct artifacts of this kind in the (unfiltered) window. */
  count: number;
  /** Capped, ranked rows for display. */
  entries: Artifact[];
}

export interface ArtifactsReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts from which ≥1 artifact was recovered. */
  artifactBearingAlerts: number;
  /** Of those, alerts whose raw line yielded no recoverable artifact. */
  unparsedAlerts: number;
  /** Distinct artifacts recovered across all kinds. */
  distinctArtifacts: number;
  /** Distinct artifacts per kind (full, before per-kind row capping). */
  countsByKind: Record<ArtifactKind, number>;
  /** Per-kind groups, in {@link ARTIFACT_KINDS} order, empty kinds omitted. */
  groups: ArtifactGroup[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface ArtifactsOptions {
  /** Max rows per kind table (clamped to [1, 500]). */
  limit?: number;
  /** Minimum alerts an artifact must appear in to be listed (≥1). */
  minCount?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 25;
const DEFAULT_MIN_COUNT = 1;
const MS_PER_HOUR = 3_600_000;

// ----- classifiers / helpers (mirror ports.ts) ------------------------------

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

function pct(frac: number): string {
  return `${Math.round(frac * 100)}%`;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function clip(s: string, max = 60): string {
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

// ----- artifact extraction --------------------------------------------------

/** One artifact recovered from a single raw line, before aggregation. */
interface RawArtifact {
  kind: ArtifactKind;
  value: string;
}

// Conservative, low-false-positive patterns over the raw text.
const URL_RE = /\bhttps?:\/\/[^\s"'<>\\)\]}]+/gi;
const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const SHA256_RE = /\b[a-f0-9]{64}\b/gi;
const SHA1_RE = /\b[a-f0-9]{40}\b/gi;
const MD5_RE = /\b[a-f0-9]{32}\b/gi;
// Only mine bare-hex hashes from raw when a hash-context keyword is present, so
// arbitrary 32/40/64-char hex IDs (flow ids, request ids) aren't mistaken for IOCs.
const HASH_CONTEXT_RE = /\b(md5|sha1|sha256|filehash|fileinfo|hash)\b/i;
// A `User-Agent: ...` header echoed into a syslog line (rare but cheap to catch).
const UA_HEADER_RE = /user-agent:\s*([^\r\n"]+?)(?:["\r\n]|$)/i;

/**
 * Offensive-tooling / scanner user-agent fingerprints. A UA matching one of
 * these is flagged suspicious — it is software that legitimate browsers are not.
 */
const TOOL_UA_RE =
  /sqlmap|nikto|nmap|masscan|zgrab|zmap|nessus|acunetix|netsparker|havij|hydra|medusa|dirb|dirbuster|gobuster|feroxbuster|wpscan|wfuzz|ffuf|burp|nuclei|metasploit|python-requests|go-http-client|libwww|curl\/|wget\/|httpx|fasthttp|okhttp|scrapy|censys|shodan/i;

/** Lower-case, strip a trailing dot / port, and reject obvious non-domains. */
function normalizeDomain(raw: string): string | undefined {
  let d = raw.trim().toLowerCase().replace(/\.$/, "");
  // Strip a :port suffix (but keep IPv6 in brackets out — those are addresses).
  const port = d.match(/^([a-z0-9._-]+):\d+$/)?.[1];
  if (port) d = port;
  // Must look like host.tld with a non-numeric TLD; this also rejects bare IPs.
  if (!/^([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(d)) return undefined;
  return d;
}

/** Pull the hostname out of a URL string, if it carries a domain (not an IP). */
function hostFromUrl(u: string): string | undefined {
  const host = u.match(/^https?:\/\/([^/?#:]+)/i)?.[1];
  return host ? normalizeDomain(host) : undefined;
}

/** Read a string field from a possibly-nested record, tolerating shape drift. */
function str(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

/**
 * Mine the structured Suricata EVE fields out of an already-parsed JSON object.
 * Pushes any artifacts found onto `out` (deduplication happens in the caller).
 */
function extractFromEve(obj: Record<string, unknown>, out: RawArtifact[]): void {
  const http = obj["http"] as Record<string, unknown> | undefined;
  if (http && typeof http === "object") {
    const host = str(http["hostname"]) ?? str(http["http_hostname"]) ?? str(http["host"]);
    const dom = host ? normalizeDomain(host) : undefined;
    if (dom) out.push({ kind: "domain", value: dom });
    const ua = str(http["http_user_agent"]) ?? str(http["user_agent"]);
    if (ua) out.push({ kind: "useragent", value: ua });
    // Build a full URL from host + uri when both are present; else take url/uri.
    const uri = str(http["url"]) ?? str(http["uri"]);
    if (uri) {
      if (/^https?:\/\//i.test(uri)) out.push({ kind: "url", value: uri });
      else if (host) out.push({ kind: "url", value: `http://${host}${uri.startsWith("/") ? "" : "/"}${uri}` });
    }
  }

  const tls = obj["tls"] as Record<string, unknown> | undefined;
  if (tls && typeof tls === "object") {
    const sni = str(tls["sni"]);
    const dom = sni ? normalizeDomain(sni) : undefined;
    if (dom) out.push({ kind: "domain", value: dom });
  }

  const dns = obj["dns"] as Record<string, unknown> | undefined;
  if (dns && typeof dns === "object") {
    const rrname = str(dns["rrname"]);
    const dom = rrname ? normalizeDomain(rrname) : undefined;
    if (dom) out.push({ kind: "domain", value: dom });
    const query = dns["query"];
    if (Array.isArray(query)) {
      for (const q of query) {
        const name = q && typeof q === "object" ? str((q as Record<string, unknown>)["rrname"]) : undefined;
        const qd = name ? normalizeDomain(name) : undefined;
        if (qd) out.push({ kind: "domain", value: qd });
      }
    }
  }

  const fileinfo = obj["fileinfo"] as Record<string, unknown> | undefined;
  if (fileinfo && typeof fileinfo === "object") {
    for (const f of ["sha256", "sha1", "md5"] as const) {
      const h = str(fileinfo[f]);
      if (h && /^[a-fA-F0-9]+$/.test(h)) out.push({ kind: "hash", value: h.toLowerCase() });
    }
  }
}

/**
 * Recover every distinct content-level artifact from one stored alert's raw
 * line: a structured pass over an embedded EVE JSON object, then a conservative
 * regex pass over the raw text. Returns a *deduplicated* list (one entry per
 * distinct kind+value), so a value repeated within a single alert counts once.
 */
export function extractArtifacts(raw: string | undefined): RawArtifact[] {
  if (!raw) return [];
  const found: RawArtifact[] = [];

  // 1) Structured EVE JSON, if the raw line embeds one (same envelope ports.ts
  //    parses for dest_port).
  const start = raw.indexOf("{");
  const end = raw.lastIndexOf("}");
  if (start !== -1 && end > start) {
    try {
      const obj = JSON.parse(raw.slice(start, end + 1)) as Record<string, unknown>;
      if (obj && typeof obj === "object") extractFromEve(obj, found);
    } catch {
      // not JSON — regex fallback below still applies
    }
  }

  // 2) Regex fallback over the whole raw line.
  for (const m of raw.matchAll(URL_RE)) {
    const hit = m[0];
    if (!hit) continue;
    // Trim trailing punctuation a sentence/log line tends to glue on.
    const u = hit.replace(/[.,;'")\]}]+$/, "");
    found.push({ kind: "url", value: u });
    const host = hostFromUrl(u);
    if (host) found.push({ kind: "domain", value: host });
  }
  for (const m of raw.matchAll(CVE_RE)) {
    const hit = m[0];
    if (hit) found.push({ kind: "cve", value: hit.toUpperCase() });
  }

  if (HASH_CONTEXT_RE.test(raw)) {
    // Longest-first so a sha256 isn't double-counted as the md5 inside it.
    const claimed = new Set<string>();
    for (const re of [SHA256_RE, SHA1_RE, MD5_RE]) {
      for (const m of raw.matchAll(re)) {
        const hit = m[0];
        if (!hit) continue;
        const h = hit.toLowerCase();
        // Skip a substring already claimed by a longer hash.
        if ([...claimed].some((c) => c.includes(h))) continue;
        claimed.add(h);
        found.push({ kind: "hash", value: h });
      }
    }
  }

  const uaVal = raw.match(UA_HEADER_RE)?.[1]?.trim();
  if (uaVal) found.push({ kind: "useragent", value: uaVal });

  // Deduplicate within this single alert.
  const seen = new Set<string>();
  const out: RawArtifact[] = [];
  for (const a of found) {
    const key = `${a.kind}|${a.value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(a);
  }
  return out;
}

// ----- aggregation ----------------------------------------------------------

interface ArtifactAcc {
  count: number;
  sources: Set<string>;
  targets: Set<string>;
  sevMax: Severity;
  first: number;
  last: number;
  sigCounts: Map<string, number>;
}

function newAcc(t: number): ArtifactAcc {
  return {
    count: 0,
    sources: new Set(),
    targets: new Set(),
    sevMax: "info",
    first: t,
    last: t,
    sigCounts: new Map(),
  };
}

/** A hash/CVE is always notable; a UA only when it matches offensive tooling. */
function isSuspicious(kind: ArtifactKind, value: string): boolean {
  if (kind === "hash" || kind === "cve") return true;
  if (kind === "useragent") return TOOL_UA_RE.test(value);
  return false;
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  m: { artifactBearingAlerts: number; unparsedAlerts: number; distinctArtifacts: number },
  groups: ArtifactGroup[],
): string[] {
  const out: string[] = [];
  if (!m.distinctArtifacts) return out;

  const byKind = new Map(groups.map((g) => [g.kind, g]));

  out.push(
    `🔬 Over the last ${hours}h, **${m.distinctArtifacts} distinct payload artifact(s)** were extracted from ` +
      `${m.artifactBearingAlerts} alert(s) that carried recoverable content — concrete indicators you can pivot, ` +
      `block or hunt on beyond the attacking IP.`,
  );

  // Headline: hashes — the sharpest, most portable IOC.
  const hashes = byKind.get("hash");
  if (hashes?.entries.length) {
    const lead = hashes.entries[0]!;
    out.push(
      `🧬 **${hashes.count} file hash(es)** observed in payloads — the highest-value indicators here. e.g. ` +
        `\`${clip(lead.value, 24)}…\` (${lead.count} alert(s)). Look each up in VirusTotal / your EDR and block the ` +
        `binary estate-wide; a hash outlives any IP the file was delivered from.`,
    );
  }

  // CVEs in the payload body — exploit attempts naming a specific bug.
  const cves = byKind.get("cve");
  if (cves?.entries.length) {
    const top = cves.entries.slice(0, 3).map((e) => e.value).join(", ");
    out.push(
      `🩹 **${cves.count} CVE reference(s)** appear in payloads (${top}${cves.count > 3 ? ", …" : ""}). These are ` +
        `exploit attempts naming a specific vulnerability — confirm each affected service is patched. (The \`--cve\` ` +
        `report maps CVEs from *signature names*; this surfaces them from the payload body.)`,
    );
  }

  // Domains / URLs — block-list and hunt fuel.
  const domains = byKind.get("domain");
  if (domains?.entries.length) {
    const lead = domains.entries[0]!;
    out.push(
      `🌐 **${domains.count} domain(s)** were seen in requests/queries (busiest \`${clip(lead.value, 40)}\`, ` +
        `${lead.count} alert(s)). Cross-reference against threat-intel and consider DNS/proxy blocks for the ` +
        `confirmed-bad ones — a C2 or phishing domain is a durable indicator an IP rotation can't shed.`,
    );
  }

  // Offensive-tool user-agents — direct attribution of the tooling in use.
  const uas = byKind.get("useragent");
  const toolUas = uas?.entries.filter((e) => e.suspicious) ?? [];
  if (toolUas.length) {
    const lead = toolUas[0]!;
    out.push(
      `🪪 **${toolUas.length} offensive-tool user-agent(s)** fingerprinted (e.g. \`${clip(lead.value, 40)}\` from ` +
        `${lead.distinctSources} source(s)) — automated scanning / exploitation tooling, not a browser. These sources ` +
        `are unambiguously hostile; prioritise them for blocking.`,
    );
  }

  // Coverage honesty — how much of the stream carried any artifact at all.
  const total = m.artifactBearingAlerts + m.unparsedAlerts;
  if (total > 0) {
    const frac = m.artifactBearingAlerts / total;
    out.push(
      `ℹ️ Only **${pct(frac)} of windowed alerts carried a recoverable artifact** (${m.unparsedAlerts} had none — ` +
        `bare flow-tuple or UniFi-notification lines that never printed payload detail). Content IOCs depend on the ` +
        `richer EVE JSON the live syslog feed provides; treat every count as a lower bound.`,
    );
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function artifactTable(rows: Artifact[]): string {
  return mdTable(
    ["#", "Artifact", "Alerts", "Sources", "Targets", "First seen", "Last seen", "Top signature", "Flag"],
    rows.map((a, i) => [
      String(i + 1),
      `\`${cell(clip(a.value, 70))}\``,
      String(a.count),
      String(a.distinctSources),
      String(a.distinctTargets),
      fmtTime(a.firstSeenMs),
      fmtTime(a.lastSeenMs),
      a.topSignature ? cell(clip(a.topSignature, 36)) : "—",
      a.suspicious ? "⚠️" : "",
    ]),
  );
}

function renderMarkdown(m: ArtifactsReport): string {
  const lines: string[] = [];
  lines.push(`# 🔬 SecTool Payload-Artifact / Embedded-IOC Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** content-level indicators (domains, URLs, file hashes, CVEs, user-agents) re-parsed from each stored ` +
      `alert's raw line (Suricata EVE JSON + conservative regex) · **Artifact-bearing alerts:** ` +
      `${m.artifactBearingAlerts} of ${m.totalWindowAlerts} (${m.unparsedAlerts} carried none)`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.distinctArtifacts) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but **none carried a recoverable payload ` +
          `artifact** (no EVE JSON body, no domain/URL/hash/CVE/user-agent in the raw line). Content IOCs need the ` +
          `richer detail the live syslog feed provides; bare flow-tuple or UniFi-notification lines yield none. The ` +
          `\`--iocs\` report still exports the IP-level indicators.`,
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

  // A tiny header so a long report stays navigable.
  lines.push(`## Artifacts by kind`);
  lines.push("");
  for (const g of m.groups) {
    const meta = ARTIFACT_KINDS.find((k) => k.kind === g.kind)!;
    lines.push(`- ${meta.emoji} **${g.label}** — ${g.count} distinct`);
  }
  lines.push("");

  for (const g of m.groups) {
    const meta = ARTIFACT_KINDS.find((k) => k.kind === g.kind)!;
    lines.push(`## ${meta.emoji} ${g.label}`);
    lines.push("");
    if (g.count > g.entries.length) {
      lines.push(`_Showing the top ${g.entries.length} of ${g.count} distinct ${g.label.toLowerCase()}._`);
      lines.push("");
    }
    lines.push(artifactTable(g.entries));
    lines.push("");
  }

  lines.push(
    `**Legend:** _Sources_ = distinct IPs that carried the artifact · _Targets_ = distinct internal hosts it was ` +
      `aimed at · **⚠️ Flag** marks an always-notable indicator (every file hash and CVE) or a user-agent matching ` +
      `known offensive tooling. Values are clipped for display; the JSON model carries them in full.`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Artifacts are **re-parsed from each alert's raw line**, not stored columns — only ` +
      `alerts whose raw text still carried an EVE JSON body or a recognisable indicator contribute (${m.unparsedAlerts} ` +
      `carried none and were excluded), so every count is a lower bound. Extraction is **deliberately conservative**: ` +
      `domains come from structured fields and URL hostnames (not a blanket regex), and hashes are mined only from ` +
      `\`fileinfo\` or when a hash-context keyword is present, to avoid mistaking arbitrary hex for an IOC. **Presence ` +
      `is not malice** — an artifact in a payload is *observed*, not *judged*; reputation / enrichment is the next step. ` +
      `For IP-level indicators see the \`--iocs\` export; for signature-mapped CVEs see \`--cve\`. A long look-back can ` +
      `hit the store's history cap and undercount artifacts. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the payload-artifact / embedded-IOC report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link ArtifactsOptions}: `limit` (per-kind rows), `minCount`, and
 *              a `nowMs` pin for deterministic tests.
 */
export function buildArtifacts(hours: number, opts: ArtifactsOptions = {}): ArtifactsReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(500, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minCount = Math.max(1, Math.floor(opts.minCount ?? DEFAULT_MIN_COUNT));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  // kind+value -> accumulator.
  const accs = new Map<string, { kind: ArtifactKind; value: string; acc: ArtifactAcc }>();
  let artifactBearing = 0;
  let unparsed = 0;

  for (const a of windowed) {
    const arts = extractArtifacts(a.raw);
    if (!arts.length) {
      unparsed++;
      continue;
    }
    artifactBearing++;

    const src = validIp(a.srcIp);
    const dst = validIp(a.dstIp);
    const dstInternal = dst ? isPrivate(dst) : false;
    const sig = a.signature?.trim();

    for (const art of arts) {
      const key = `${art.kind}|${art.value}`;
      let rec = accs.get(key);
      if (!rec) {
        rec = { kind: art.kind, value: art.value, acc: newAcc(a.time) };
        accs.set(key, rec);
      }
      const acc = rec.acc;
      acc.count++;
      if (src) acc.sources.add(src);
      if (dst && dstInternal) acc.targets.add(dst);
      acc.sevMax = maxSeverity(acc.sevMax, a.severity);
      if (a.time < acc.first) acc.first = a.time;
      if (a.time > acc.last) acc.last = a.time;
      if (sig) acc.sigCounts.set(sig, (acc.sigCounts.get(sig) ?? 0) + 1);
    }
  }

  // Materialise artifacts, gated by minCount.
  const all: Artifact[] = [...accs.values()]
    .filter((r) => r.acc.count >= minCount)
    .map((r) => ({
      kind: r.kind,
      value: r.value,
      count: r.acc.count,
      distinctSources: r.acc.sources.size,
      distinctTargets: r.acc.targets.size,
      severityMax: r.acc.sevMax,
      firstSeenMs: r.acc.first,
      lastSeenMs: r.acc.last,
      topSignature: topOf(r.acc.sigCounts),
      suspicious: isSuspicious(r.kind, r.value),
    }));

  // Per-kind grouping in canonical order; rank within each kind by prevalence.
  const countsByKind = { hash: 0, cve: 0, domain: 0, url: 0, useragent: 0 } as Record<ArtifactKind, number>;
  for (const a of all) countsByKind[a.kind]++;

  const rank = (x: Artifact, y: Artifact): number =>
    y.count - x.count ||
    y.distinctSources - x.distinctSources ||
    sevRank(y.severityMax) - sevRank(x.severityMax) ||
    y.lastSeenMs - x.lastSeenMs ||
    (x.value < y.value ? -1 : x.value > y.value ? 1 : 0);

  const groups: ArtifactGroup[] = ARTIFACT_KINDS.map(({ kind, label }) => {
    const entries = all.filter((a) => a.kind === kind).sort(rank);
    return { kind, label, count: entries.length, entries: entries.slice(0, limit) };
  }).filter((g) => g.count > 0);

  const distinctArtifacts = all.length;

  const highlights = writeHighlights(
    safeHours,
    { artifactBearingAlerts: artifactBearing, unparsedAlerts: unparsed, distinctArtifacts },
    groups,
  );

  const model: ArtifactsReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    artifactBearingAlerts: artifactBearing,
    unparsedAlerts: unparsed,
    distinctArtifacts,
    countsByKind,
    groups,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded payload-artifact report. */
export function artifactsFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-artifacts-${stamp}.md`;
}
