/**
 * OSINT investigation pivot sheet — "**I have a suspicious IP on my dashboard;
 * now what do I actually click?**"
 *
 * Every other source-oriented report in SecTool answers a question *from our own
 * data* — who is loudest (`focus`), nastiest (`risk`/`potency`), where they're
 * allocated (`origins`/`cloud`/`netblocks`), or what they did to us (`profile`).
 * None of them get the analyst the next click of a real triage: the external,
 * third-party reputation and reconnaissance lookups that turn *"this IP keeps
 * hitting me"* into *"this IP is a known Mirai node on a DigitalOcean droplet,
 * already abuse-reported 400 times"*. Pasting an address into AbuseIPDB, then
 * VirusTotal, then Shodan, then GreyNoise, one tab at a time, is the single most
 * repetitive motion in manual SOC triage.
 *
 * This report is the pivot sheet that removes that friction. It ranks the worst
 * **public** attacking sources in the window (severity-weighted, so the genuinely
 * dangerous float up — not just the chattiest scanner), and for each one emits a
 * ready-to-use investigation block:
 *
 *   - **External OSINT links** across the major free / freemium threat-intel and
 *     reconnaissance services (AbuseIPDB, VirusTotal, GreyNoise, Shodan, Censys,
 *     Talos, AlienVault OTX, Pulsedive, Spamhaus, IPinfo, Hurricane Electric BGP),
 *     each a fully-formed clickable URL with the address pre-filled — no API key
 *     needed just to open the page.
 *   - **Copy-paste CLI commands** for the terminal-first analyst (`whois`,
 *     reverse-DNS `dig -x`) plus the internal cross-link back into SecTool's own
 *     deep dossier (`--profile <ip>`), so the external and internal views are one
 *     hop apart.
 *   - **The context SecTool already holds** — alert count, worst severity, top
 *     signature, internal hosts touched, first/last-seen, hosting provider (reused
 *     from `cloud`'s offline attribution) and the block / watch / safelist flags —
 *     so the analyst walks into the lookup already knowing what they're chasing.
 *
 * A `--format links` mode collapses the whole sheet into a flat, de-duplicated
 * list of URLs (one per line) — pipe it into `xargs open` / a browser-batch tool
 * to fan every lookup open at once.
 *
 * Honest scoping baked in:
 *
 *   - **Internal / RFC1918 sources are excluded.** Public reputation services
 *     have nothing to say about your own 10.x host; the count of excluded lateral
 *     sources is surfaced so the omission is explicit, not silent.
 *   - **Safelisted sources are excluded by default** (vetted-benign — you don't
 *     re-investigate them) but the count is shown; nothing is hidden quietly.
 *   - **The links are deep-link templates, not verdicts.** SecTool performs no
 *     network call and makes no reputation claim — it builds the URL; the service
 *     on the other end is the source of truth. Some services cover IPv4 better
 *     than IPv6; a dead-end lookup is information too.
 *
 * Pure in-memory string templating over alertStore — no SSH, no Claude, no
 * network. Output is a structured model, a ready-to-paste Markdown worklist, and
 * a flat URL list, mirroring potency.ts / abuse.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { classifyProvider, providerInfo } from "./cloud.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Which investigative axis a lookup serves. */
export type PivotCategory = "reputation" | "recon" | "network";

/** A static description of one external OSINT service we deep-link into. */
export interface PivotService {
  /** Stable id / display key, e.g. "abuseipdb". */
  key: string;
  /** Human label, e.g. "AbuseIPDB". */
  label: string;
  /** The investigative axis it serves. */
  category: PivotCategory;
  /** One-line note on what the analyst gets from it. */
  note: string;
  /** Builds the deep link for a given address (already URL-safe). */
  url: (ip: string) => string;
}

/** One ready-to-click link for a specific target IP. */
export interface PivotLink {
  service: string;
  label: string;
  category: PivotCategory;
  url: string;
}

/** One attacking source with its full investigation kit. */
export interface PivotTarget {
  ip: string;
  /** Windowed alert count from this source. */
  alerts: number;
  /** Severity-weighted score (Σ SEVERITY_WEIGHT) — the ranking key. */
  weight: number;
  /** High + critical alert count. */
  serious: number;
  /** Worst severity observed. */
  severityMax: Severity;
  /** Busiest signature from this source, if any. */
  topSignature?: string;
  /** Distinct internal hosts this source reached. */
  targets: number;
  firstSeenMs: number;
  lastSeenMs: number;
  /** Hosting provider label (offline attribution), or undefined if unclassified. */
  provider?: string;
  blocked: boolean;
  watched: boolean;
  safe: boolean;
  /** External OSINT deep links, in service order. */
  links: PivotLink[];
  /** Copy-paste CLI / internal cross-link commands. */
  commands: string[];
}

export interface PivotReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts in the window carrying a usable source IP. */
  totalAlerts: number;
  /** Distinct public sources seen (before the row limit). */
  totalSources: number;
  /** Internal / RFC1918 sources skipped (no OSINT value). */
  internalExcluded: number;
  /** Safelisted public sources skipped (vetted benign), unless `includeSafe`. */
  safeExcluded: number;
  /** The alert floor a source had to clear to be listed. */
  minAlerts: number;
  /** Max source rows produced. */
  limit: number;
  /** True when more qualifying sources exist than were shown. */
  truncated: boolean;
  /** The catalog of services every target was linked into. */
  services: { key: string; label: string; category: PivotCategory; note: string }[];
  /** Ranked targets (most-investigate-worthy first), capped at {@link limit}. */
  targets: PivotTarget[];
  /** Flat, de-duplicated list of every external URL across all targets. */
  links: string[];
  /** Plain-language call-outs. */
  highlights: string[];
  /** The finished Markdown worklist. */
  markdown: string;
}

export interface PivotOptions {
  /** Max target rows produced; clamped to [1, 200]. Default 15. */
  limit?: number;
  /** Alert floor to qualify; clamped to [1, 1000]. Default 1. */
  minAlerts?: number;
  /** Include safelisted sources too (default excludes them). */
  includeSafe?: boolean;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 15;
const DEFAULT_MIN_ALERTS = 1;
const MS_PER_HOUR = 3_600_000;

/**
 * The external services we build deep links into. All are free or freemium and
 * expose a stable per-IP URL that needs no API key just to open the page. Order
 * here is the order links render in — reputation first (the triage verdict), then
 * recon (what's actually listening), then network (who owns the space).
 */
export const PIVOT_SERVICES: readonly PivotService[] = [
  {
    key: "abuseipdb",
    label: "AbuseIPDB",
    category: "reputation",
    note: "crowd-sourced abuse confidence score + recent report categories",
    url: (ip) => `https://www.abuseipdb.com/check/${enc(ip)}`,
  },
  {
    key: "virustotal",
    label: "VirusTotal",
    category: "reputation",
    note: "multi-engine reputation, passive DNS, communicating files",
    url: (ip) => `https://www.virustotal.com/gui/ip-address/${enc(ip)}`,
  },
  {
    key: "greynoise",
    label: "GreyNoise",
    category: "reputation",
    note: "internet-background-noise classifier — benign scanner vs targeted",
    url: (ip) => `https://viz.greynoise.io/ip/${enc(ip)}`,
  },
  {
    key: "talos",
    label: "Cisco Talos",
    category: "reputation",
    note: "email/web reputation, owner & block-list status",
    url: (ip) => `https://talosintelligence.com/reputation_center/lookup?search=${enc(ip)}`,
  },
  {
    key: "otx",
    label: "AlienVault OTX",
    category: "reputation",
    note: "community pulses — which campaigns name this address",
    url: (ip) => `https://otx.alienvault.com/indicator/ip/${enc(ip)}`,
  },
  {
    key: "pulsedive",
    label: "Pulsedive",
    category: "reputation",
    note: "aggregated risk score + linked indicators / feeds",
    url: (ip) => `https://pulsedive.com/indicator/?ioc=${enc(ip)}`,
  },
  {
    key: "spamhaus",
    label: "Spamhaus",
    category: "reputation",
    note: "DROP / SBL / XBL block-list membership",
    url: (ip) => `https://check.spamhaus.org/results/?query=${enc(ip)}`,
  },
  {
    key: "shodan",
    label: "Shodan",
    category: "recon",
    note: "open ports, banners, exposed services & CVEs on the host",
    url: (ip) => `https://www.shodan.io/host/${enc(ip)}`,
  },
  {
    key: "censys",
    label: "Censys",
    category: "recon",
    note: "TLS certs, service fingerprints & autonomous-system context",
    url: (ip) => `https://search.censys.io/hosts/${enc(ip)}`,
  },
  {
    key: "ipinfo",
    label: "IPinfo",
    category: "network",
    note: "geo, ASN, hosting/VPN flags & rDNS",
    url: (ip) => `https://ipinfo.io/${enc(ip)}`,
  },
  {
    key: "hebgp",
    label: "HE BGP",
    category: "network",
    note: "announcing ASN, prefix & upstream peering",
    url: (ip) => `https://bgp.he.net/ip/${enc(ip)}`,
  },
] as const;

const CATEGORY_ORDER: readonly PivotCategory[] = ["reputation", "recon", "network"];

const CATEGORY_LABEL: Record<PivotCategory, string> = {
  reputation: "Reputation",
  recon: "Recon / exposure",
  network: "Network / ownership",
};

// ----- helpers (mirror potency.ts / abuse.ts) --------------------------------

/** URL-encode the address so IPv6 colons survive in a path / query segment. */
function enc(ip: string): string {
  return encodeURIComponent(ip);
}

function validIp(ip: string | undefined): string | undefined {
  return ip && isIP(ip) !== 0 ? ip : undefined;
}

/** RFC1918 / loopback / link-local / ULA — a lateral source, not a public attacker. */
function isInternal(ip: string): boolean {
  if (ip.includes(":")) {
    const lc = ip.toLowerCase();
    return lc === "::1" || lc.startsWith("fe80") || lc.startsWith("fc") || lc.startsWith("fd");
  }
  const o = ip.split(".").map(Number);
  if (o.length !== 4 || o.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  if (o[0] === 10) return true;
  if (o[0] === 172 && o[1]! >= 16 && o[1]! <= 31) return true;
  if (o[0] === 192 && o[1] === 168) return true;
  if (o[0] === 127) return true;
  if (o[0] === 169 && o[1] === 254) return true;
  return false;
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

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function clip(s: string, max = 44): string {
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

function flagStr(t: PivotTarget): string {
  const f: string[] = [];
  if (t.safe) f.push("🟢safe");
  if (t.blocked) f.push("🚫blocked");
  if (t.watched) f.push("👁watch");
  return f.length ? f.join(" ") : "—";
}

/** The most frequent value of a count map (deterministic tie-break on key). */
function topKey(counts: Map<string, number>): string | undefined {
  let best: string | undefined;
  let bestN = -1;
  for (const [k, n] of counts) {
    if (n > bestN || (n === bestN && best !== undefined && k < best)) {
      best = k;
      bestN = n;
    }
  }
  return best;
}

/** Offline hosting-provider label for an address, or undefined if unclassified. */
function providerLabel(ip: string): string | undefined {
  const key = classifyProvider(ip);
  if (!key) return undefined;
  const info = providerInfo(key);
  // The "unclassified" bucket is not a real attribution — treat as unknown.
  return info && info.kind !== "unclassified" ? info.label : undefined;
}

// ----- aggregation -----------------------------------------------------------

interface SourceAcc {
  ip: string;
  alerts: number;
  weight: number;
  serious: number;
  severityMax: Severity;
  firstSeenMs: number;
  lastSeenMs: number;
  targets: Set<string>;
  signatureCounts: Map<string, number>;
}

function newSourceAcc(ip: string): SourceAcc {
  return {
    ip,
    alerts: 0,
    weight: 0,
    serious: 0,
    severityMax: "info",
    firstSeenMs: Number.POSITIVE_INFINITY,
    lastSeenMs: Number.NEGATIVE_INFINITY,
    targets: new Set(),
    signatureCounts: new Map(),
  };
}

/** Build the per-IP investigation links + CLI commands. */
function buildLinks(ip: string): PivotLink[] {
  return PIVOT_SERVICES.map((s) => ({
    service: s.key,
    label: s.label,
    category: s.category,
    url: s.url(ip),
  }));
}

function buildCommands(ip: string): string[] {
  return [
    `whois ${ip}`,
    `dig -x ${ip} +short`,
    `node src/index.ts --profile ${ip}`,
  ];
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(report: Omit<PivotReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (report.targets.length === 0) return out;

  const worst = report.targets[0]!;
  out.push(
    `🔎 Start here: **\`${worst.ip}\`** — ${worst.alerts} alert(s), ${worst.serious} serious (worst ` +
      `\`${worst.severityMax}\`)${worst.topSignature ? `, led by \`${clip(worst.topSignature, 46)}\`` : ""}` +
      `${worst.provider ? ` on ${worst.provider}` : ""}. ${PIVOT_SERVICES.length} lookups queued` +
      `${worst.blocked ? " (already blocked — confirm via \`--recidivism\`)" : worst.safe ? " (safelisted — re-vet)" : ""}.`,
  );

  const unblocked = report.targets.filter((t) => !t.blocked && !t.safe);
  if (unblocked.length) {
    out.push(
      `🚨 **${unblocked.length}** of the ${report.targets.length} listed source(s) are neither blocked nor safelisted — ` +
        `run the reputation column first, then feed confirmed-bad ones to \`--blockplan\` / \`--abuse\`.`,
    );
  }

  const attributed = report.targets.filter((t) => t.provider).length;
  if (attributed) {
    out.push(
      `🏢 **${attributed}** source(s) resolve to a known hosting provider (offline attribution) — those carry an abuse ` +
        `desk you can escalate to; see \`--cloud\` / \`--abuse\` for the contacts.`,
    );
  }

  if (report.internalExcluded > 0 || report.safeExcluded > 0) {
    const bits: string[] = [];
    if (report.internalExcluded > 0) bits.push(`${report.internalExcluded} internal/lateral`);
    if (report.safeExcluded > 0) bits.push(`${report.safeExcluded} safelisted`);
    out.push(
      `ℹ️ Excluded from the sheet: ${bits.join(" and ")} source(s) — public reputation services have nothing to say ` +
        `about those. ${report.safeExcluded > 0 ? "Pass `--include-safe` to fold safelisted ones back in. " : ""}` +
        `Use \`--profile <ip>\` for the internal view of any address.`,
    );
  }

  out.push(
    `🌐 ${report.targets.length * PIVOT_SERVICES.length} external lookups built across ${PIVOT_SERVICES.length} services — ` +
      `the \`links\` format emits them as a flat list to fan open in one shot. No network call was made; SecTool only ` +
      `built the URLs.`,
  );

  return out;
}

// ----- markdown --------------------------------------------------------------

function summaryTable(targets: PivotTarget[]): string {
  return mdTable(
    ["#", "Source", "Alerts", "Weight", "Serious", "Worst", "Dsts", "Provider", "Top signature", "Flags"],
    targets.map((t, i) => [
      String(i + 1),
      cell(`\`${t.ip}\``),
      String(t.alerts),
      String(t.weight),
      t.serious > 0 ? `**${t.serious}**` : "0",
      cell(t.severityMax),
      String(t.targets),
      cell(t.provider ?? "—"),
      cell(t.topSignature ? clip(t.topSignature) : "—"),
      flagStr(t),
    ]),
  );
}

function linkTable(links: PivotLink[]): string {
  return mdTable(
    ["Axis", "Service", "Lookup"],
    CATEGORY_ORDER.flatMap((cat) =>
      links
        .filter((l) => l.category === cat)
        .map((l) => [CATEGORY_LABEL[cat], cell(l.label), `[open](${l.url})`]),
    ),
  );
}

function renderTargetBlock(t: PivotTarget, idx: number): string[] {
  const lines: string[] = [];
  lines.push(`### ${idx + 1}. \`${t.ip}\`${t.blocked ? " 🚫" : ""}${t.safe ? " 🟢" : ""}${t.watched ? " 👁" : ""}`);
  lines.push("");
  const ctx: string[] = [
    `**${t.alerts}** alert(s)`,
    `weight **${t.weight}**`,
    `**${t.serious}** serious`,
    `worst \`${t.severityMax}\``,
    `**${t.targets}** internal host(s) touched`,
  ];
  if (t.provider) ctx.push(`provider **${t.provider}**`);
  lines.push(ctx.join(" · "));
  lines.push("");
  lines.push(`_Seen ${fmtTime(t.firstSeenMs)} → ${fmtTime(t.lastSeenMs)}${t.topSignature ? ` · top \`${clip(t.topSignature, 60)}\`` : ""}._`);
  lines.push("");
  lines.push(linkTable(t.links));
  lines.push("");
  lines.push("```sh");
  for (const c of t.commands) lines.push(c);
  lines.push("```");
  lines.push("");
  return lines;
}

function renderMarkdown(m: PivotReport): string {
  const lines: string[] = [];
  lines.push(`# 🔎 SecTool OSINT Investigation Pivot Sheet`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** worst **public** attacking sources ranked by severity-weighted score ` +
      `(\`Σ severity weight\`, the \`--risk\` ladder: info 1·low 3·medium 9·high 27·critical 81), each deep-linked into ` +
      `${PIVOT_SERVICES.length} OSINT services. Offline, deterministic · ` +
      `**Alerts:** ${m.totalAlerts} · **Public sources:** ${m.totalSources} · **Floor:** ≥ ${m.minAlerts} alert(s).`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (m.targets.length === 0) {
    lines.push(
      `No public attacking source with ≥ ${m.minAlerts} alert(s) landed in the last ${m.hours}h — there is nothing to ` +
        `investigate. Widen the window (\`--pivot <more hours>\`), lower \`--min\`, or confirm forwarding with ` +
        `\`--coverage\`.` +
        (m.internalExcluded > 0 || m.safeExcluded > 0
          ? ` (${m.internalExcluded} internal and ${m.safeExcluded} safelisted source(s) were excluded.)`
          : ""),
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query and no third-party lookup was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Targets`);
  lines.push("");
  if (m.truncated) {
    lines.push(`_Showing the **${m.targets.length}** highest-priority public source(s). Raise \`--limit\` to see more._`);
    lines.push("");
  }
  lines.push(summaryTable(m.targets));
  lines.push("");
  lines.push(
    `**Legend:** _Weight_ = severity-weighted score (the ranking key). _Serious_ = high + critical. _Dsts_ = distinct ` +
      `internal hosts reached. _Provider_ = offline hosting attribution (see \`--cloud\`). Flags: 🚫blocked · 👁watch · 🟢safe.`,
  );
  lines.push("");

  lines.push(`## Investigation kits`);
  lines.push("");
  lines.push(
    `_Each block: external reputation/recon/network lookups, then copy-paste CLI commands and the internal ` +
      `\`--profile\` cross-link. Click the reputation row first — it's the fastest verdict._`,
  );
  lines.push("");
  m.targets.forEach((t, i) => lines.push(...renderTargetBlock(t, i)));

  lines.push(`## Services linked`);
  lines.push("");
  lines.push(
    mdTable(
      ["Axis", "Service", "What it gives you"],
      CATEGORY_ORDER.flatMap((cat) =>
        m.services.filter((s) => s.category === cat).map((s) => [CATEGORY_LABEL[cat], cell(s.label), cell(s.note)]),
      ),
    ),
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. The links are deep-link **templates** — SecTool made no network call and asserts no ` +
      `reputation verdict of its own; the service on the other end is the source of truth, and some cover IPv4 better ` +
      `than IPv6 (a dead-end lookup is information too). Internal/lateral and safelisted sources are excluded by design. ` +
      `This is the external-triage companion to \`--profile\` (internal dossier), \`--abuse\` (takedown drafts) and ` +
      `\`--blockplan\` (what to block next). No third-party service was contacted._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the OSINT investigation pivot sheet from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link PivotOptions}: `limit`, `minAlerts`, `includeSafe`, and a
 *              `nowMs` pin for deterministic tests.
 */
export function buildPivot(hours: number, opts: PivotOptions = {}): PivotReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minAlerts = Math.max(1, Math.min(1000, Math.floor(opts.minAlerts ?? DEFAULT_MIN_ALERTS)));
  const includeSafe = opts.includeSafe ?? false;
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const sources = new Map<string, SourceAcc>();
  let totalAlerts = 0;
  let internalExcluded = 0;
  const internalSeen = new Set<string>();

  for (const a of windowed) {
    const ip = validIp(a.srcIp);
    if (!ip) continue;
    totalAlerts++;
    if (isInternal(ip)) {
      if (!internalSeen.has(ip)) {
        internalSeen.add(ip);
        internalExcluded++;
      }
      continue;
    }

    const severity = asSeverity(a.severity);
    let acc = sources.get(ip);
    if (!acc) {
      acc = newSourceAcc(ip);
      sources.set(ip, acc);
    }
    acc.alerts++;
    acc.weight += SEVERITY_WEIGHT[severity];
    if (isSerious(severity)) acc.serious++;
    acc.severityMax = maxSeverity(acc.severityMax, severity);
    acc.firstSeenMs = Math.min(acc.firstSeenMs, a.time);
    acc.lastSeenMs = Math.max(acc.lastSeenMs, a.time);

    const dst = validIp(a.dstIp);
    if (dst) acc.targets.add(dst);
    const sig = a.signature?.trim();
    if (sig) acc.signatureCounts.set(sig, (acc.signatureCounts.get(sig) ?? 0) + 1);
  }

  // Apply the alert floor and the safelist exclusion, counting what we drop.
  let safeExcluded = 0;
  const qualifying: SourceAcc[] = [];
  for (const acc of sources.values()) {
    if (acc.alerts < minAlerts) continue;
    if (!includeSafe && safeStore.has(acc.ip)) {
      safeExcluded++;
      continue;
    }
    qualifying.push(acc);
  }

  const totalSources = qualifying.length;

  const ranked: PivotTarget[] = qualifying
    .map((acc) => ({
      ip: acc.ip,
      alerts: acc.alerts,
      weight: acc.weight,
      serious: acc.serious,
      severityMax: acc.severityMax,
      topSignature: topKey(acc.signatureCounts),
      targets: acc.targets.size,
      firstSeenMs: Number.isFinite(acc.firstSeenMs) ? acc.firstSeenMs : windowStartMs,
      lastSeenMs: Number.isFinite(acc.lastSeenMs) ? acc.lastSeenMs : windowEndMs,
      provider: providerLabel(acc.ip),
      blocked: blockStore.has(acc.ip),
      watched: watchStore.has(acc.ip),
      safe: safeStore.has(acc.ip),
      links: buildLinks(acc.ip),
      commands: buildCommands(acc.ip),
    } satisfies PivotTarget))
    // Most investigation-worthy first: weight, then serious, then volume, then
    // recency, with IP as a final stable tie-break for deterministic output.
    .sort(
      (a, b) =>
        b.weight - a.weight ||
        b.serious - a.serious ||
        b.alerts - a.alerts ||
        b.lastSeenMs - a.lastSeenMs ||
        (a.ip < b.ip ? -1 : a.ip > b.ip ? 1 : 0),
    );

  const truncated = ranked.length > limit;
  const targets = truncated ? ranked.slice(0, limit) : ranked;

  // Flat, de-duplicated URL list across the SHOWN targets (the worklist you'd
  // actually fan open), preserving target-then-service order.
  const seen = new Set<string>();
  const links: string[] = [];
  for (const t of targets) {
    for (const l of t.links) {
      if (!seen.has(l.url)) {
        seen.add(l.url);
        links.push(l.url);
      }
    }
  }

  const services = PIVOT_SERVICES.map((s) => ({ key: s.key, label: s.label, category: s.category, note: s.note }));

  const base: Omit<PivotReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalAlerts,
    totalSources,
    internalExcluded,
    safeExcluded,
    minAlerts,
    limit,
    truncated,
    services,
    targets,
    links,
  };

  const highlights = writeHighlights(base);
  const model: PivotReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded pivot sheet. */
export function pivotFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-pivot-${stamp}.md`;
}
