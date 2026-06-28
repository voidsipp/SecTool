/**
 * DNS sinkhole / blocklist export — "**every other enforcement export stops at
 * the IP. Turn the malicious *domains* my alert payloads actually carried into a
 * ready-to-load DNS-layer blocklist.**"
 *
 * SecTool ships a rich enforcement-export family, and yet every member of it
 * operates at the **network / IP layer**:
 *
 *   - **iocExport.ts / fwrules.ts** export the attacking *IP addresses* into
 *     firewall-ready config (ipset/iptables/nftables/pf/…).
 *   - **snort.ts** feeds those IPs back to the IDS sensor; **pcap.ts** turns them
 *     into capture filters; **stix / sigma / cef / ecs** carry the IP indicators
 *     into a SIEM.
 *
 * None of them enforce at the **DNS layer** — and DNS blocking is the single most
 * effective, lowest-collateral control against the *durable* half of an attack's
 * fingerprint. An attacker's IP rotates in minutes; the **C2 / payload / phishing
 * domain** riding inside the request (the HTTP `Host`, the TLS SNI, the DNS query,
 * a URL in the body) is a far stickier IOC, and a single `0.0.0.0` answer at the
 * resolver black-holes it for the *whole estate* — every host, every port, every
 * protocol — without touching a firewall rule. That is exactly the surface
 * artifacts.ts already *mines* (it lists the domains) but nothing *enforces*.
 *
 * This module closes that loop. It reuses the very same conservative,
 * low-false-positive domain extractor artifacts.ts uses ({@link extractArtifacts}
 * — a structured pass over an embedded Suricata EVE JSON object, then a careful
 * regex fallback), rolls every distinct domain up over the look-back window, and
 * renders the worklist into the formats every DNS-layer control understands:
 *
 *   - **hosts** (default) — `0.0.0.0 domain` lines for `/etc/hosts`, a Pi-hole /
 *     AdGuard custom list, or any OS hosts file. The lowest common denominator.
 *   - **dnsmasq** — `address=/domain/0.0.0.0`, which also black-holes *every*
 *     subdomain in one line (wildcard semantics a flat hosts file can't express).
 *   - **unbound** — `local-zone: "domain." always_nxdomain`, the Unbound /
 *     recursive-resolver idiom (returns NXDOMAIN for the name and all subdomains).
 *   - **rpz** — a complete BIND **Response Policy Zone** (SOA + NS + per-domain
 *     `CNAME .` NXDOMAIN actions, apex and wildcard), the enterprise resolver
 *     standard that also drops cleanly into Unbound's `rpz:` and Knot Resolver.
 *   - **pihole** — a bare newline-delimited domain list, the universal adlist
 *     format Pi-hole / AdGuard Home / Blocky / many resolvers ingest as a URL.
 *   - **json** — the structured model; **md** — a human review table.
 *
 * Safety first — a DNS blocklist that black-holes a *legitimate* domain is an
 * outage, so this export is deliberately conservative and advisory:
 *
 *   - **A built-in benign-infrastructure skip-list.** A curated set of high-traffic
 *     CDN / OS-update / cloud / telemetry suffixes (Microsoft, Apple, Google,
 *     Cloudflare, Akamai, AWS, GitHub, Let's Encrypt/OCSP, NTP, reverse-DNS …) is
 *     excluded by default — these routinely appear *inside* alert payloads (a rule
 *     tripped on otherwise-benign traffic) and sinkholing them would break the
 *     estate. `--include-benign` overrides the skip (with a loud caveat).
 *   - **Observed, not judged.** A domain in a payload is *seen*, not *adjudicated
 *     malicious* — the same honesty artifacts.ts carries. The output is a review
 *     worklist; the Markdown twin exists to be eyeballed before you load it, and a
 *     `--min N` alert-count floor plus a `--min-severity` floor keep one-off noise
 *     out. Confidence (0–100) is surfaced per domain so the obvious blocks sort up.
 *   - **Window- & extraction-bounded.** Only alerts whose raw line still carried an
 *     EVE body or a recognisable domain contribute; a bare flow-tuple alert yields
 *     nothing. Counts are a lower bound (the *unparsed* tally is shown).
 *
 * Pure in-memory math over alertStore (+ the shared artifact extractor) — no SSH,
 * no Claude, no network. Output is a structured model plus the deliverable text
 * and a Markdown review twin, mirroring iocExport.ts / snort.ts / pcap.ts so it
 * plugs straight into the same CLI flag, npm script and `/api/dns[.txt]` routes.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";
import { extractArtifacts } from "./artifacts.ts";

/** Output flavours the DNS blocklist can render into. */
export type DnsFormat = "hosts" | "dnsmasq" | "unbound" | "rpz" | "pihole" | "json" | "md";

/** Default severity floor — domains often ride low-severity policy/recon hits,
 * so unlike the IP IOC export this defaults to *no* floor; the benign skip-list
 * and `--min` count carry the safety. Callers can still pass one. */
const DEFAULT_MIN_COUNT = 1;
/** Hard ceiling on emitted entries so a zone file never grows unwieldy. */
const MAX_LIMIT = 5000;
/** The address a sinkholed name resolves to by default (the null route). */
const DEFAULT_SINKHOLE = "0.0.0.0";

const MS_PER_HOUR = 3_600_000;

/**
 * Benign-infrastructure suffixes excluded by default. These are high-traffic
 * CDN / OS-update / cloud / certificate / telemetry domains that frequently
 * appear *inside* alert payloads on otherwise-legitimate traffic — sinkholing
 * them would cause an estate-wide outage, so precision wins over recall here. A
 * host matches when it equals an entry or is a subdomain of it. `--include-benign`
 * disables this skip-list.
 */
const BENIGN_SUFFIXES: readonly string[] = [
  // Microsoft / Windows
  "microsoft.com", "windows.com", "windowsupdate.com", "update.microsoft.com",
  "msftncsi.com", "msftconnecttest.com", "office.com", "office365.com",
  "live.com", "outlook.com", "azure.com", "azureedge.net", "windows.net",
  "msedge.net", "microsoftonline.com", "skype.com", "xboxlive.com",
  // Apple
  "apple.com", "icloud.com", "mzstatic.com", "cdn-apple.com", "push.apple.com",
  // Google
  "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
  "gvt1.com", "gvt2.com", "ggpht.com", "youtube.com", "ytimg.com",
  "android.com", "googlevideo.com", "1e100.net", "gmail.com", "doubleclick.net",
  // Cloudflare
  "cloudflare.com", "cloudflare.net", "cloudflaressl.com", "cloudflare-dns.com",
  // Akamai
  "akamai.net", "akamaiedge.net", "akamaihd.net", "akadns.net", "akamaized.net",
  // Amazon / AWS
  "amazonaws.com", "amazon.com", "cloudfront.net", "aws.dev",
  // Other major CDNs / platforms
  "fastly.net", "fbcdn.net", "facebook.com", "instagram.com", "whatsapp.net",
  "fastlylb.net", "edgekey.net", "edgesuite.net",
  // Mozilla / browsers
  "mozilla.org", "mozilla.net", "mozilla.com", "firefox.com",
  // Linux distros / package mirrors
  "ubuntu.com", "canonical.com", "debian.org", "archlinux.org",
  "fedoraproject.org", "centos.org", "redhat.com",
  // Dev infra
  "github.com", "githubusercontent.com", "githubassets.com", "ghcr.io",
  "jsdelivr.net", "unpkg.com", "npmjs.org", "npmjs.com", "pypi.org",
  // Certificate / OCSP / CRL / time
  "digicert.com", "letsencrypt.org", "sectigo.com", "globalsign.com",
  "entrust.net", "ocsp.apple.com", "pool.ntp.org", "ntp.org", "time.windows.com",
  // Root / reverse DNS infrastructure
  "root-servers.net", "in-addr.arpa", "ip6.arpa",
];

/** One domain row in the blocklist worklist. */
export interface DnsIndicator {
  /** The observed, normalised hostname (lower-case, no trailing dot). */
  domain: string;
  /** 0–100 confidence this domain belongs on a blocklist. */
  confidence: number;
  /** Worst severity of any alert this domain rode in on. */
  severityMax: Severity;
  /** Total in-window alerts carrying this domain. */
  alertCount: number;
  /** Distinct external source IPs that carried it. */
  sourceCount: number;
  /** Distinct internal hosts that requested / received it. */
  targetCount: number;
  /** Distinct signatures it appeared under. */
  signatureCount: number;
  /** Its loudest signature, if any (review context). */
  topSignature?: string;
  /** Earliest / latest alert times (ms epoch). */
  firstSeen: number;
  lastSeen: number;
}

export interface DnsExport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Severity floor applied (or "info" when none). */
  minSeverity: Severity;
  /** Minimum alert count a domain needed to qualify. */
  minCount: number;
  /** Output flavour requested. */
  format: DnsFormat;
  /** The address sinkholed names resolve to (hosts / dnsmasq / rpz). */
  sinkhole: string;
  /** Whether the benign-infrastructure skip-list was applied. */
  excludeBenign: boolean;
  /** Distinct domains emitted in the blocklist. */
  domainCount: number;
  /** Domains dropped because they matched the benign skip-list. */
  excludedBenign: number;
  /** Domains dropped because their worst severity was below the floor. */
  excludedBelowSeverity: number;
  /** Domains dropped because their alert count was below `minCount`. */
  excludedBelowCount: number;
  /** Domains truncated by `limit` (kept the top {@link domainCount}). */
  truncated: number;
  /** Alerts scanned in the window. */
  scannedAlerts: number;
  /** Alerts that yielded no extractable artifact at all (coverage tell). */
  unparsedAlerts: number;
  /** The ranked blocklist (highest confidence first). */
  indicators: DnsIndicator[];
  /** The deliverable for the chosen format (the loadable blocklist). */
  text: string;
  /** Human Markdown review twin. */
  markdown: string;
}

export interface DnsExportOptions {
  /** Drop domains whose worst severity is below this (default none). */
  minSeverity?: Severity;
  /** Minimum alerts a domain needs to qualify (default {@link DEFAULT_MIN_COUNT}). */
  minCount?: number;
  /** Cap on emitted domains, highest confidence first (default no cap). */
  limit?: number;
  /** Output flavour (default `hosts`). */
  format?: DnsFormat;
  /** Sinkhole address for hosts / dnsmasq / rpz (default `0.0.0.0`). */
  sinkhole?: string;
  /** Keep benign-infrastructure domains instead of skipping them (default false). */
  includeBenign?: boolean;
  /** Pins the window end / timestamps for deterministic tests; defaults to now. */
  nowMs?: number;
}

// ----- helpers ---------------------------------------------------------------

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? (b as Severity) : a;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function mdCell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function mdTable(headers: string[], rows: string[][]): string {
  if (!rows.length) return "_None._";
  const head = `| ${headers.join(" | ")} |`;
  const sep = `| ${headers.map(() => "---").join(" | ")} |`;
  const body = rows.map((r) => `| ${r.join(" | ")} |`).join("\n");
  return `${head}\n${sep}\n${body}`;
}

/** A valid, non-empty external IP, or undefined. Excludes RFC1918 / loopback. */
function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
}

function externalIp(ip: string | undefined): string | undefined {
  return ip && isIP(ip) !== 0 && !isPrivate(ip) ? ip : undefined;
}

function internalIp(ip: string | undefined): string | undefined {
  return ip && isIP(ip) !== 0 && isPrivate(ip) ? ip : undefined;
}

/** True when `host` equals, or is a subdomain of, any benign suffix. */
function isBenign(host: string): boolean {
  return BENIGN_SUFFIXES.some((s) => host === s || host.endsWith(`.${s}`));
}

/**
 * Validate / normalise a sinkhole address. Falls back to `0.0.0.0` for anything
 * that is not a literal IPv4/IPv6 address (the value is spliced into emitted
 * config the operator loads, so it must never be attacker-controlled garbage).
 */
function sanitizeSinkhole(raw: string | undefined): string {
  const v = (raw ?? "").trim();
  return v && isIP(v) !== 0 ? v : DEFAULT_SINKHOLE;
}

/**
 * Composite 0–100 confidence a domain belongs on a blocklist. Mirrors the spirit
 * of the IP IOC engine: severity dominates, then volume, signature diversity and
 * fan-out across internal hosts (a name many of your hosts resolved is a wider
 * exposure). Deliberately has no "already blocked" boost — DNS names aren't on the
 * IP blocklist.
 */
function scoreConfidence(c: {
  severityMax: Severity;
  alertCount: number;
  signatureCount: number;
  sourceCount: number;
  targetCount: number;
}): number {
  let score = sevRank(c.severityMax) * 16; // medium=32, high=48, critical=64
  score += Math.min(16, Math.log2(c.alertCount + 1) * 5); // volume, diminishing
  score += Math.min(10, (c.signatureCount - 1) * 4); // signature diversity
  score += Math.min(6, (c.sourceCount - 1) * 2); // distinct carriers
  score += Math.min(6, (c.targetCount - 1) * 3); // internal fan-out
  return Math.max(0, Math.min(100, Math.round(score)));
}

// ----- aggregation -----------------------------------------------------------

interface DomainAcc {
  alertCount: number;
  severityMax: Severity;
  sources: Set<string>;
  targets: Set<string>;
  sigCounts: Map<string, number>;
  firstSeen: number;
  lastSeen: number;
}

function topSig(counts: Map<string, number>): string | undefined {
  let best: string | undefined;
  let bestN = -1;
  for (const [sig, n] of counts) {
    if (n > bestN || (n === bestN && best !== undefined && sig < best)) {
      best = sig;
      bestN = n;
    }
  }
  return best;
}

// ----- text deliverables -----------------------------------------------------

function bannerLines(m: Omit<DnsExport, "text" | "markdown">, comment: string): string[] {
  return [
    `${comment} SecTool DNS sinkhole / blocklist export — ${m.domainCount} domain(s)`,
    `${comment} Generated: ${fmtTime(m.windowEndMs)} · window: last ${m.hours}h`,
    `${comment} Source: domains mined from IDS/IPS alert payloads (observed, not adjudicated).`,
    `${comment} REVIEW before loading — a sinkholed legitimate domain is an outage.`,
  ];
}

function renderHosts(m: Omit<DnsExport, "text" | "markdown">): string {
  const lines = bannerLines(m, "#");
  if (!m.indicators.length) {
    lines.push("# (no qualifying domains in this window)");
    return lines.join("\n") + "\n";
  }
  lines.push(`# Format: hosts file (load into /etc/hosts, Pi-hole or AdGuard custom list).`);
  for (const d of m.indicators) lines.push(`${m.sinkhole} ${d.domain}`);
  return lines.join("\n") + "\n";
}

function renderDnsmasq(m: Omit<DnsExport, "text" | "markdown">): string {
  const lines = bannerLines(m, "#");
  if (!m.indicators.length) {
    lines.push("# (no qualifying domains in this window)");
    return lines.join("\n") + "\n";
  }
  lines.push(`# Format: dnsmasq — address=/<domain>/<ip> also black-holes every subdomain.`);
  for (const d of m.indicators) lines.push(`address=/${d.domain}/${m.sinkhole}`);
  return lines.join("\n") + "\n";
}

function renderUnbound(m: Omit<DnsExport, "text" | "markdown">): string {
  const lines = bannerLines(m, "#");
  if (!m.indicators.length) {
    lines.push("# (no qualifying domains in this window)");
    return lines.join("\n") + "\n";
  }
  lines.push(`# Format: Unbound — drop inside server: clause. NXDOMAIN for the name + subdomains.`);
  lines.push("server:");
  for (const d of m.indicators) lines.push(`    local-zone: "${d.domain}." always_nxdomain`);
  return lines.join("\n") + "\n";
}

/**
 * A complete BIND Response Policy Zone. Each name maps to the NXDOMAIN action
 * (`CNAME .`) for both the apex and a wildcard so subdomains are covered too. The
 * SOA serial is derived from the window end (deterministic for a given `nowMs`).
 */
function renderRpz(m: Omit<DnsExport, "text" | "markdown">): string {
  const serial = Math.floor(m.windowEndMs / 1000);
  const lines = bannerLines(m, ";");
  lines.push(`; Format: BIND Response Policy Zone (RPZ). Reference as a zone, then`);
  lines.push(`; response-policy { zone "rpz.sectool"; }; in named.conf.`);
  lines.push("$TTL 300");
  lines.push(`@ IN SOA localhost. root.localhost. ( ${serial} 3600 600 86400 300 )`);
  lines.push(`@ IN NS  localhost.`);
  if (!m.indicators.length) {
    lines.push("; (no qualifying domains in this window)");
    return lines.join("\n") + "\n";
  }
  for (const d of m.indicators) {
    lines.push(`${d.domain} CNAME .`);
    lines.push(`*.${d.domain} CNAME .`);
  }
  return lines.join("\n") + "\n";
}

function renderPihole(m: Omit<DnsExport, "text" | "markdown">): string {
  // Bare domain list — the universal adlist format (Pi-hole / AdGuard / Blocky).
  // A short comment header is tolerated by every consumer that reads adlists.
  const lines = bannerLines(m, "#");
  if (!m.indicators.length) {
    lines.push("# (no qualifying domains in this window)");
    return lines.join("\n") + "\n";
  }
  for (const d of m.indicators) lines.push(d.domain);
  return lines.join("\n") + "\n";
}

function renderText(m: Omit<DnsExport, "text" | "markdown">): string {
  switch (m.format) {
    case "dnsmasq": return renderDnsmasq(m);
    case "unbound": return renderUnbound(m);
    case "rpz": return renderRpz(m);
    case "pihole": return renderPihole(m);
    case "hosts":
    default: return renderHosts(m);
  }
}

// ----- markdown --------------------------------------------------------------

function renderMarkdown(m: DnsExport): string {
  const lines: string[] = [];
  lines.push(`# 🕳️ SecTool DNS Sinkhole / Blocklist Export`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** domains re-mined from each alert's raw payload (Suricata EVE \`http.hostname\` / \`tls.sni\` / ` +
      `\`dns.rrname\` / URL host), rolled up over the window and ranked by a 0–100 blocklist confidence. ` +
      `Offline, deterministic · **Scanned alerts:** ${m.scannedAlerts} · **Yielded no artifact:** ${m.unparsedAlerts}`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  lines.push(`- **Domains in blocklist:** ${m.domainCount}`);
  lines.push(
    `- **Excluded:** ${m.excludedBenign} benign-infra${m.excludeBenign ? "" : " (skip-list off)"}, ` +
      `${m.excludedBelowCount} below min-count (${m.minCount}), ${m.excludedBelowSeverity} below severity floor` +
      (m.truncated > 0 ? `, ${m.truncated} truncated by limit` : ``),
  );
  lines.push(`- **Severity floor:** ${m.minSeverity === "info" ? "none" : m.minSeverity} · **Sinkhole:** \`${m.sinkhole}\``);
  lines.push("");

  if (!m.indicators.length) {
    lines.push(
      `_No qualifying domains were mined from the last ${m.hours}h. Either no payloads carried an extractable ` +
        `domain (a bare flow-tuple alert yields nothing — see the "yielded no artifact" count), or every candidate ` +
        `was filtered. Widen the window (\`--dns <more hours>\`), lower \`--min\`, or pass \`--include-benign\`._`,
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  lines.push(`## Domains (review before loading)`);
  lines.push("");
  lines.push(
    mdTable(
      ["#", "Domain", "Conf", "Worst", "Alerts", "Srcs", "Targets", "Sigs", "Last seen", "Top signature"],
      m.indicators.map((d, i) => [
        String(i + 1),
        mdCell(d.domain),
        String(d.confidence),
        mdCell(d.severityMax),
        String(d.alertCount),
        String(d.sourceCount),
        String(d.targetCount),
        String(d.signatureCount),
        mdCell(fmtTime(d.lastSeen)),
        mdCell(d.topSignature ? (d.topSignature.length > 48 ? d.topSignature.slice(0, 47) + "…" : d.topSignature) : "—"),
      ]),
    ),
  );
  lines.push("");
  lines.push(
    `**Legend:** _Conf_ = 0–100 blocklist confidence (severity, volume, signature diversity, internal fan-out). ` +
      `_Srcs_ = distinct external IPs that carried the domain. _Targets_ = distinct internal hosts that resolved / ` +
      `received it.`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. **A domain in a payload is observed, not adjudicated malicious** — sinkholing a ` +
      `legitimate name is an estate-wide outage, so review this worklist before loading it. A built-in benign-` +
      `infrastructure skip-list (CDN / OS-update / cloud / certificate / NTP / reverse-DNS) is ` +
      `${m.excludeBenign ? "**on**" : "**off** (\`--include-benign\`)"}. Counts are a lower bound: only alerts whose ` +
      `raw line still carried an EVE body or a recognisable domain contribute. This is the DNS-layer sibling of ` +
      `\`--fwrules\` (IP firewall codegen) and \`--artifacts\` (which mines but does not enforce). No live gateway ` +
      `query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

// ----- build -----------------------------------------------------------------

/**
 * Build the DNS blocklist export from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link DnsExportOptions}.
 */
export function buildDnsExport(hours: number, opts: DnsExportOptions = {}): DnsExport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const nowMs = opts.nowMs ?? Date.now();
  const windowStartMs = nowMs - safeHours * MS_PER_HOUR;
  const format: DnsFormat = opts.format ?? "hosts";
  const minSeverity: Severity = opts.minSeverity ?? "info";
  const minCount = Math.max(1, Math.floor(opts.minCount ?? DEFAULT_MIN_COUNT));
  const sinkhole = sanitizeSinkhole(opts.sinkhole);
  const excludeBenign = !opts.includeBenign;
  const limit =
    opts.limit !== undefined && opts.limit > 0
      ? Math.min(MAX_LIMIT, Math.floor(opts.limit))
      : MAX_LIMIT;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= nowMs);

  const domains = new Map<string, DomainAcc>();
  let scannedAlerts = 0;
  let unparsedAlerts = 0;

  for (const a of windowed) {
    scannedAlerts++;
    const arts = extractArtifacts(a.raw);
    const hosts = arts.filter((x) => x.kind === "domain").map((x) => x.value);
    if (!arts.length) unparsedAlerts++;
    if (!hosts.length) continue;

    const src = externalIp(a.srcIp);
    const dst = internalIp(a.dstIp);
    const sig = (a.signature ?? "").trim();

    // De-dup hosts within this single alert so one alert counts once per domain.
    for (const host of new Set(hosts)) {
      let acc = domains.get(host);
      if (!acc) {
        acc = {
          alertCount: 0,
          severityMax: "info",
          sources: new Set(),
          targets: new Set(),
          sigCounts: new Map(),
          firstSeen: a.time,
          lastSeen: a.time,
        };
        domains.set(host, acc);
      }
      acc.alertCount++;
      acc.severityMax = maxSeverity(acc.severityMax, a.severity);
      if (src) acc.sources.add(src);
      if (dst) acc.targets.add(dst);
      if (sig) acc.sigCounts.set(sig, (acc.sigCounts.get(sig) ?? 0) + 1);
      if (a.time < acc.firstSeen) acc.firstSeen = a.time;
      if (a.time > acc.lastSeen) acc.lastSeen = a.time;
    }
  }

  const sevFloor = sevRank(minSeverity);
  let excludedBenign = 0;
  let excludedBelowSeverity = 0;
  let excludedBelowCount = 0;

  const qualified: DnsIndicator[] = [];
  for (const [domain, acc] of domains) {
    if (excludeBenign && isBenign(domain)) {
      excludedBenign++;
      continue;
    }
    if (sevRank(acc.severityMax) < sevFloor) {
      excludedBelowSeverity++;
      continue;
    }
    if (acc.alertCount < minCount) {
      excludedBelowCount++;
      continue;
    }
    const ind: DnsIndicator = {
      domain,
      severityMax: acc.severityMax,
      alertCount: acc.alertCount,
      sourceCount: acc.sources.size,
      targetCount: acc.targets.size,
      signatureCount: acc.sigCounts.size,
      topSignature: topSig(acc.sigCounts),
      firstSeen: acc.firstSeen,
      lastSeen: acc.lastSeen,
      confidence: 0,
    };
    ind.confidence = scoreConfidence({
      severityMax: ind.severityMax,
      alertCount: ind.alertCount,
      signatureCount: ind.signatureCount,
      sourceCount: ind.sourceCount,
      targetCount: ind.targetCount,
    });
    qualified.push(ind);
  }

  // Rank: highest confidence, then loudest, then most-recent, then name (stable).
  qualified.sort(
    (a, b) =>
      b.confidence - a.confidence ||
      b.alertCount - a.alertCount ||
      b.lastSeen - a.lastSeen ||
      (a.domain < b.domain ? -1 : a.domain > b.domain ? 1 : 0),
  );

  const truncated = Math.max(0, qualified.length - limit);
  const indicators = qualified.slice(0, limit);

  const base: Omit<DnsExport, "text" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs: nowMs,
    minSeverity,
    minCount,
    format,
    sinkhole,
    excludeBenign,
    domainCount: indicators.length,
    excludedBenign,
    excludedBelowSeverity,
    excludedBelowCount,
    truncated,
    scannedAlerts,
    unparsedAlerts,
    indicators,
  };

  const text = renderText(base);
  const model: DnsExport = { ...base, text, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded DNS blocklist in the given flavour. */
export function dnsFilename(nowMs: number, format: DnsFormat = "hosts"): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  const ext =
    format === "json" ? "json" :
    format === "md" ? "md" :
    format === "rpz" ? "rpz" :
    format === "unbound" || format === "dnsmasq" ? "conf" :
    "txt";
  return `sectool-dns-blocklist-${stamp}.${ext}`;
}

/** Coerce an arbitrary string into a valid {@link DnsFormat}, defaulting to hosts. */
export function parseDnsFormat(raw: string | undefined | null): DnsFormat {
  const f = (raw ?? "").trim().toLowerCase();
  if (f === "dnsmasq") return "dnsmasq";
  if (f === "unbound") return "unbound";
  if (f === "rpz" || f === "bind") return "rpz";
  if (f === "pihole" || f === "adguard" || f === "adlist" || f === "list" || f === "plain") return "pihole";
  if (f === "json") return "json";
  if (f === "md" || f === "markdown") return "md";
  return "hosts"; // also the home of "hostfile"
}
