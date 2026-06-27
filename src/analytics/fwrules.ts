/**
 * Firewall-rule export / code-generator — "**turn SecTool's blocklist into config
 * I can paste straight into my perimeter device.**"
 *
 * SecTool already *decides* what to block and *enforces* it on the UDM itself:
 *
 *   - respond/blocker.ts drops blocked sources at the gateway via a dedicated
 *     `SECTOOL_BLOCK` ipset referenced by INPUT/FORWARD DROP rules;
 *   - store/blocklist.ts is the durable record of every IP that decision produced;
 *   - blockplan.ts / autoblock.ts decide *which* sources to block next;
 *   - iocExport.ts (`--iocs`) emits a confidence-ranked list of bad IPs mined from
 *     the *alert window* — a feed of addresses, in plain / csv / json — for another
 *     tool to ingest.
 *
 * None of them answers the operational question an admin asks when SecTool is *not*
 * the only thing on the network: *"I run a pfSense box / a Cisco ASA / a MikroTik /
 * a cloud security group as well — give me SecTool's current block decisions as a
 * ready-to-apply ruleset in **that device's own syntax**, not a bare IP list I have
 * to hand-translate."* iocExport stops at the IP list; this module is the codegen
 * step after it — it takes the **live, enforced blocklist** (the ground truth of
 * what SecTool has actually decided is hostile) and renders deployable firewall
 * configuration in ten dialects:
 *
 *   - **ipset**    — `ipset` + `iptables`/`ip6tables`, mirroring blocker.ts's own
 *                    `SECTOOL_BLOCK` set so the output matches SecTool's enforcement
 *                    exactly (and scales to tens of thousands of entries);
 *   - **iptables** — plain per-IP `iptables -A INPUT -s … -j DROP` (no ipset needed);
 *   - **nftables** — a named `set` + a single `drop` rule (modern Linux);
 *   - **ufw**      — `ufw deny from …` (Debian/Ubuntu uncomplicated firewall);
 *   - **pf**       — a `<sectool_block>` table + `block in quick` (pfSense/OPNsense/BSD);
 *   - **cisco**    — extended-ACL `deny ip host … any` (IOS/ASA);
 *   - **mikrotik** — RouterOS `/ip firewall address-list` + a drop filter rule;
 *   - **vyatta**   — EdgeRouter / VyOS / UniFi `set firewall group address-group`;
 *   - **windows**  — `netsh advfirewall` inbound block rule;
 *   - **plain**    — a bare CIDR list (one per line) for a generic import.
 *
 * Every dialect is emitted as a complete, copy-pasteable script with a commented
 * header (in that dialect's own comment syntax) and is *idempotent where the device
 * allows it* (`-exist`, `add … || true`, `-C` guards) so re-running it is safe.
 *
 * Safety rails that make the output trustworthy as live firewall config:
 *   - **Safelisted IPs are excluded by default.** Generating a DROP rule for an
 *     address the operator has explicitly trusted would be an outage waiting to
 *     happen; the count of excluded-safe IPs is reported so the omission is never
 *     silent. Pass `includeSafe` only when you really mean it.
 *   - **Invalid / non-routable entries are skipped**, never emitted into a rule.
 *   - **Aggregation is advisory, not applied.** When many hosts in the same /24
 *     are blocked the report *suggests* a CIDR rollup (smaller rulesets, lower CPU
 *     on the device) but never silently widens a /32 into a /24 on its own —
 *     collateral blocking is the operator's call, so the suggestion is surfaced as
 *     a highlight, not baked into the rules.
 *
 * This is the *current enforced state*, not a time window: it reads the blocklist,
 * not the alert history, so — unlike almost every other report here — it takes no
 * `hours` parameter. For staleness ("which of these blocks should I prune?") see
 * the `hygiene` report; for "which sources should I add next?" see `blockplan`.
 *
 * Pure in-memory math over the block/safe stores — no SSH, no Claude, no network —
 * so it is safe to call from the dashboard or CLI at any time. Output is both a
 * structured model and a ready-to-paste Markdown document, mirroring iocExport.ts
 * and the other offline reports.
 */
import { isIP } from "node:net";
import { blockStore, type BlockEntry } from "../store/blocklist.ts";
import { safeStore } from "../store/safelist.ts";

/** The firewall syntaxes this exporter can render into. */
export type FirewallDialect =
  | "ipset"
  | "iptables"
  | "nftables"
  | "ufw"
  | "pf"
  | "cisco"
  | "mikrotik"
  | "vyatta"
  | "windows"
  | "plain";

/** Display metadata for each supported dialect (drives docs and the CLI help). */
export interface DialectInfo {
  id: FirewallDialect;
  /** Human label for tables / headers. */
  label: string;
  /** Target platform(s) this dialect applies to. */
  platform: string;
  /** Fenced-code-block language hint for the Markdown render. */
  lang: string;
  /** Whether this dialect's render emits IPv6 rules too (vs IPv4-only). */
  ipv6: boolean;
}

/** Curated registry of every dialect, in a sensible "reach for this first" order. */
export const FIREWALL_DIALECTS: readonly DialectInfo[] = [
  { id: "ipset", label: "ipset + iptables", platform: "Linux (UDM / netfilter)", lang: "bash", ipv6: true },
  { id: "iptables", label: "iptables (plain)", platform: "Linux (netfilter)", lang: "bash", ipv6: true },
  { id: "nftables", label: "nftables", platform: "Linux (modern)", lang: "bash", ipv6: true },
  { id: "ufw", label: "UFW", platform: "Debian / Ubuntu", lang: "bash", ipv6: true },
  { id: "pf", label: "pf table", platform: "pfSense / OPNsense / BSD", lang: "pf", ipv6: true },
  { id: "cisco", label: "Cisco extended ACL", platform: "IOS / ASA", lang: "text", ipv6: false },
  { id: "mikrotik", label: "MikroTik RouterOS", platform: "RouterOS", lang: "routeros", ipv6: true },
  { id: "vyatta", label: "EdgeRouter / VyOS / UniFi", platform: "Vyatta CLI", lang: "bash", ipv6: true },
  { id: "windows", label: "Windows netsh", platform: "Windows Defender Firewall", lang: "powershell", ipv6: true },
  { id: "plain", label: "Plain CIDR list", platform: "generic import", lang: "text", ipv6: true },
] as const;

const DIALECT_IDS = new Set<string>(FIREWALL_DIALECTS.map((d) => d.id));

/** Default name for the generated set / table / address-group / ACL. */
const DEFAULT_SET_NAME = "SECTOOL_BLOCK";
/** Minimum same-/24 host count before the report suggests a CIDR rollup. */
const AGGREGATE_THRESHOLD = 4;
/** Hard ceiling on emitted entries (matches blocker.ts's ipset maxelem headroom). */
const MAX_ENTRIES = 131072;
const MS_PER_HOUR = 3_600_000;

/** One blocked address rendered into the export. */
export interface FwRuleEntry {
  /** The blocked IP (verbatim from the blocklist). */
  ip: string;
  /** 4 or 6. */
  version: 4 | 6;
  /** ms epoch the block was recorded. */
  at: number;
  /** Whole hours since the block was recorded (for the review table). */
  ageHours: number;
  /** Free-text reason recorded with the block, if any. */
  reason?: string;
  /** Who/what created the block, if recorded. */
  by?: string;
}

/** An advisory CIDR rollup: many blocked hosts share one /24 (or /48). */
export interface FwAggregate {
  /** The covering prefix, e.g. "203.0.113.0/24". */
  cidr: string;
  version: 4 | 6;
  /** How many individually-blocked hosts fall inside it. */
  hostCount: number;
}

export interface FwRulesReport {
  /** ms epoch the export was rendered (header stamp + age math). */
  generatedMs: number;
  /** Name used for the generated set / table / address-group. */
  setName: string;
  /** Total entries currently in the blocklist. */
  totalBlocked: number;
  /** Entries actually emitted into the rules (after exclusions / cap). */
  emitted: number;
  /** Blocklist entries skipped because they are safelisted. */
  excludedSafe: number;
  /** Blocklist entries skipped because the IP was invalid / unparseable. */
  excludedInvalid: number;
  /** Whether safelisted IPs were force-included (`includeSafe`). */
  includeSafe: boolean;
  /** Emitted IPv4 / IPv6 split. */
  ipv4: number;
  ipv6: number;
  /** The emitted entries, newest block first. */
  entries: FwRuleEntry[];
  /** Advisory same-/24 (or /48) rollups worth considering. */
  aggregates: FwAggregate[];
  /** Rendered script per dialect, keyed by {@link FirewallDialect}. */
  scripts: Record<FirewallDialect, string>;
  /** Plain-language call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface FwRulesOptions {
  /** Override the generated set / table / group name (sanitised). */
  setName?: string;
  /** Emit safelisted IPs too (default false — they are excluded for safety). */
  includeSafe?: boolean;
  /** Pins the generated stamp for deterministic tests; defaults to now. */
  nowMs?: number;
}

// ----- helpers --------------------------------------------------------------

/** Parse a dialect string, defaulting to `ipset` (mirrors SecTool's own enforcement). */
export function parseFwDialect(raw: string | null | undefined): FirewallDialect {
  const v = (raw ?? "").trim().toLowerCase();
  return (DIALECT_IDS.has(v) ? v : "ipset") as FirewallDialect;
}

/**
 * Sanitise a user-supplied set name to the safe intersection every dialect
 * accepts: letters, digits, underscore and hyphen, never empty, length-capped.
 */
function sanitizeSetName(raw: string | undefined): string {
  const cleaned = (raw ?? "").replace(/[^A-Za-z0-9_-]/g, "").slice(0, 40);
  return cleaned || DEFAULT_SET_NAME;
}

function ipVersion(ip: string): 4 | 6 | 0 {
  const v = isIP(ip);
  return v === 4 ? 4 : v === 6 ? 6 : 0;
}

/** The /24 (IPv4) or /48 (IPv6) prefix label an address rolls up into. */
function prefixOf(ip: string, version: 4 | 6): string | null {
  if (version === 4) {
    const parts = ip.split(".");
    if (parts.length !== 4) return null;
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  }
  // IPv6: take the first three hextets as a /48 (best-effort; full forms only).
  const hextets = ip.split(":");
  if (hextets.length < 3 || ip.includes("::")) return null; // skip compressed forms — not worth mis-rolling
  return `${hextets[0]}:${hextets[1]}:${hextets[2]}::/48`;
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function fmtAge(hours: number): string {
  if (hours < 1) return "<1h";
  if (hours < 48) return `${Math.round(hours)}h`;
  return `${round1(hours / 24)}d`;
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

// ----- per-dialect renderers ------------------------------------------------

/** A small banner explaining provenance, in the supplied comment style. */
function banner(prefix: string, m: FwRulesReport): string[] {
  return [
    `${prefix} SecTool firewall blocklist — generated ${fmtTime(m.generatedMs)}`,
    `${prefix} ${m.emitted} address(es) (${m.ipv4} IPv4, ${m.ipv6} IPv6). Set: ${m.setName}`,
    `${prefix} Source: SecTool's enforced blocklist. Safelisted IPs ${m.includeSafe ? "INCLUDED" : "excluded"}.`,
    `${prefix} Re-running is safe (idempotent where the platform allows it).`,
  ];
}

function v4Entries(m: FwRulesReport): FwRuleEntry[] {
  return m.entries.filter((e) => e.version === 4);
}
function v6Entries(m: FwRulesReport): FwRuleEntry[] {
  return m.entries.filter((e) => e.version === 6);
}

function renderIpset(m: FwRulesReport): string {
  const out = [...banner("#", m), ""];
  const v4 = v4Entries(m);
  const v6 = v6Entries(m);
  if (v4.length) {
    const set = m.setName;
    out.push(`# --- IPv4 (${v4.length}) ---`);
    out.push(`ipset create ${set} hash:ip family inet maxelem ${MAX_ENTRIES} -exist`);
    out.push(`iptables -C INPUT -m set --match-set ${set} src -j DROP 2>/dev/null || iptables -I INPUT 1 -m set --match-set ${set} src -j DROP`);
    out.push(`iptables -C FORWARD -m set --match-set ${set} src -j DROP 2>/dev/null || iptables -I FORWARD 1 -m set --match-set ${set} src -j DROP`);
    for (const e of v4) out.push(`ipset add ${set} ${e.ip} -exist`);
    out.push("");
  }
  if (v6.length) {
    const set6 = `${m.setName}6`;
    out.push(`# --- IPv6 (${v6.length}) ---`);
    out.push(`ipset create ${set6} hash:ip family inet6 maxelem ${MAX_ENTRIES} -exist`);
    out.push(`ip6tables -C INPUT -m set --match-set ${set6} src -j DROP 2>/dev/null || ip6tables -I INPUT 1 -m set --match-set ${set6} src -j DROP`);
    out.push(`ip6tables -C FORWARD -m set --match-set ${set6} src -j DROP 2>/dev/null || ip6tables -I FORWARD 1 -m set --match-set ${set6} src -j DROP`);
    for (const e of v6) out.push(`ipset add ${set6} ${e.ip} -exist`);
    out.push("");
  }
  return out.join("\n").trimEnd() + "\n";
}

function renderIptables(m: FwRulesReport): string {
  const out = [...banner("#", m), ""];
  for (const e of v4Entries(m)) out.push(`iptables -A INPUT -s ${e.ip} -j DROP`);
  for (const e of v6Entries(m)) out.push(`ip6tables -A INPUT -s ${e.ip} -j DROP`);
  return out.join("\n").trimEnd() + "\n";
}

function renderNftables(m: FwRulesReport): string {
  const set = m.setName.toLowerCase();
  const out = [...banner("#", m), ""];
  out.push(`# Adds drop sets to the existing 'inet filter' table's input chain.`);
  out.push(`nft add table inet filter 2>/dev/null || true`);
  out.push(`nft add chain inet filter input '{ type filter hook input priority 0 ; }' 2>/dev/null || true`);
  const v4 = v4Entries(m);
  const v6 = v6Entries(m);
  if (v4.length) {
    out.push(`nft add set inet filter ${set} '{ type ipv4_addr ; flags interval ; }' 2>/dev/null || true`);
    out.push(`nft add element inet filter ${set} { ${v4.map((e) => e.ip).join(", ")} }`);
    out.push(`nft add rule inet filter input ip saddr @${set} drop`);
  }
  if (v6.length) {
    const set6 = `${set}6`;
    out.push(`nft add set inet filter ${set6} '{ type ipv6_addr ; flags interval ; }' 2>/dev/null || true`);
    out.push(`nft add element inet filter ${set6} { ${v6.map((e) => e.ip).join(", ")} }`);
    out.push(`nft add rule inet filter input ip6 saddr @${set6} drop`);
  }
  return out.join("\n").trimEnd() + "\n";
}

function renderUfw(m: FwRulesReport): string {
  const out = [...banner("#", m), ""];
  for (const e of m.entries) out.push(`ufw deny from ${e.ip} to any`);
  return out.join("\n").trimEnd() + "\n";
}

function renderPf(m: FwRulesReport): string {
  const table = m.setName.toLowerCase();
  const out = [...banner("#", m), ""];
  out.push(`# Add to /etc/pf.conf (pfSense/OPNsense manage tables in the GUI):`);
  out.push(`table <${table}> persist { \\`);
  const ips = m.entries.map((e) => e.ip);
  out.push(ips.length ? `  ${ips.join(" \\\n  ")} \\` : "  # (empty)");
  out.push(`}`);
  out.push(`block in quick from <${table}> to any`);
  out.push(`block out quick from any to <${table}>`);
  return out.join("\n").trimEnd() + "\n";
}

function renderCisco(m: FwRulesReport): string {
  const acl = m.setName.replace(/[^A-Za-z0-9_-]/g, "_");
  const out = [...banner("!", m), ""];
  out.push(`! IPv6 is not represented in this IPv4 extended ACL.`);
  out.push(`ip access-list extended ${acl}`);
  for (const e of v4Entries(m)) out.push(` deny ip host ${e.ip} any`);
  out.push(` permit ip any any`);
  const v6 = v6Entries(m);
  if (v6.length) out.push(`! ${v6.length} IPv6 address(es) omitted — add to an ipv6 access-list separately.`);
  return out.join("\n").trimEnd() + "\n";
}

function renderMikrotik(m: FwRulesReport): string {
  const list = m.setName;
  const out = [...banner("#", m), ""];
  out.push(`/ip firewall address-list`);
  for (const e of v4Entries(m)) {
    const c = e.reason ? ` comment="${e.reason.replace(/"/g, "'")}"` : "";
    out.push(`add list=${list} address=${e.ip}${c}`);
  }
  out.push(`/ip firewall filter`);
  out.push(`add chain=input src-address-list=${list} action=drop comment="SecTool block"`);
  out.push(`add chain=forward src-address-list=${list} action=drop comment="SecTool block"`);
  const v6 = v6Entries(m);
  if (v6.length) {
    out.push(`/ipv6 firewall address-list`);
    for (const e of v6) out.push(`add list=${list} address=${e.ip}`);
    out.push(`/ipv6 firewall filter`);
    out.push(`add chain=input src-address-list=${list} action=drop comment="SecTool block"`);
    out.push(`add chain=forward src-address-list=${list} action=drop comment="SecTool block"`);
  }
  return out.join("\n").trimEnd() + "\n";
}

function renderVyatta(m: FwRulesReport): string {
  const group = m.setName;
  const out = [...banner("#", m), ""];
  out.push(`# EdgeRouter / VyOS / UniFi (Vyatta) — paste in configuration mode.`);
  out.push(`# Then reference the group from a firewall ruleset, e.g.:`);
  out.push(`#   set firewall name WAN_IN rule 10 action drop`);
  out.push(`#   set firewall name WAN_IN rule 10 source group address-group ${group}`);
  const v4 = v4Entries(m);
  if (v4.length) {
    out.push(`set firewall group address-group ${group} description "SecTool blocklist"`);
    for (const e of v4) out.push(`set firewall group address-group ${group} address ${e.ip}`);
  }
  const v6 = v6Entries(m);
  if (v6.length) {
    const g6 = `${group}6`;
    out.push(`set firewall group ipv6-address-group ${g6} description "SecTool blocklist (IPv6)"`);
    for (const e of v6) out.push(`set firewall group ipv6-address-group ${g6} address ${e.ip}`);
  }
  return out.join("\n").trimEnd() + "\n";
}

function renderWindows(m: FwRulesReport): string {
  const rule = m.setName;
  const out = [...banner("REM", m), ""];
  out.push(`REM Run in an elevated Command Prompt. netsh accepts a comma-separated remoteip list.`);
  const ips = m.entries.map((e) => e.ip);
  if (ips.length) {
    // netsh caps practical command length; chunk the remoteip list to stay safe.
    const CHUNK = 200;
    for (let i = 0; i < ips.length; i += CHUNK) {
      const part = ips.slice(i, i + CHUNK).join(",");
      const name = ips.length > CHUNK ? `${rule}_${Math.floor(i / CHUNK) + 1}` : rule;
      out.push(
        `netsh advfirewall firewall add rule name="${name}" dir=in action=block remoteip=${part}`,
      );
    }
  } else {
    out.push(`REM (no addresses to block)`);
  }
  return out.join("\n").trimEnd() + "\n";
}

function renderPlain(m: FwRulesReport): string {
  const out = [...banner("#", m), ""];
  for (const e of m.entries) out.push(e.ip);
  return out.join("\n").trimEnd() + "\n";
}

const RENDERERS: Record<FirewallDialect, (m: FwRulesReport) => string> = {
  ipset: renderIpset,
  iptables: renderIptables,
  nftables: renderNftables,
  ufw: renderUfw,
  pf: renderPf,
  cisco: renderCisco,
  mikrotik: renderMikrotik,
  vyatta: renderVyatta,
  windows: renderWindows,
  plain: renderPlain,
};

/** Render a single dialect's script from a finished model. */
export function renderFwScript(m: FwRulesReport, dialect: FirewallDialect): string {
  return (RENDERERS[dialect] ?? renderPlain)(m);
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(m: {
  totalBlocked: number;
  emitted: number;
  excludedSafe: number;
  excludedInvalid: number;
  ipv4: number;
  ipv6: number;
  aggregates: FwAggregate[];
  oldestAgeHours: number;
}): string[] {
  const out: string[] = [];
  if (!m.emitted) {
    out.push(
      m.totalBlocked
        ? `✅ The blocklist holds **${m.totalBlocked} entr(ies)** but **none are emittable** — every one is ` +
            `safelisted or invalid. Nothing to deploy.`
        : `✅ **The blocklist is empty** — SecTool has not blocked anything yet, so there is no firewall ruleset to ` +
            `generate. See the \`blockplan\` report for sources worth blocking.`,
    );
    return out;
  }

  out.push(
    `🧱 **${m.emitted} address(es)** ready to deploy (${m.ipv4} IPv4, ${m.ipv6} IPv6), rendered into ` +
      `**${FIREWALL_DIALECTS.length} firewall dialects**. Pick the section that matches your edge device and paste it in.`,
  );

  if (m.excludedSafe > 0) {
    out.push(
      `🛟 **${m.excludedSafe} safelisted IP(s) were excluded** from the rules — generating a DROP for a trusted ` +
        `address is an outage waiting to happen. Pass \`includeSafe\` only if you really intend to block them.`,
    );
  }
  if (m.excludedInvalid > 0) {
    out.push(`⚠️ **${m.excludedInvalid} blocklist entr(ies) had an unparseable IP** and were skipped.`);
  }

  if (m.aggregates.length) {
    const top = m.aggregates[0]!;
    const total = m.aggregates.reduce((s, a) => s + a.hostCount, 0);
    out.push(
      `📦 **${m.aggregates.length} subnet(s) have ${AGGREGATE_THRESHOLD}+ blocked hosts** (${total} hosts in all; ` +
        `worst is **${top.cidr}** with ${top.hostCount}). Consider replacing the individual /32 rules with a single ` +
        `CIDR block per subnet — smaller ruleset, lower device CPU — *if* you accept the collateral. ` +
        `(Advisory only; the generated rules still list individual hosts.)`,
    );
  }

  if (m.ipv6 > 0) {
    out.push(
      `🌐 **${m.ipv6} IPv6 address(es)** are included. The \`cisco\` dialect omits them (IPv4 ACL only) and says so ` +
        `inline; every other dialect emits matching IPv6 rules.`,
    );
  }

  if (m.oldestAgeHours >= 24 * 30) {
    out.push(
      `🧹 The oldest block is **${fmtAge(m.oldestAgeHours)}** old. Before deploying, consider pruning stale entries — ` +
        `see the \`hygiene\` report for which blocks are worth keeping.`,
    );
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function renderMarkdown(m: FwRulesReport): string {
  const lines: string[] = [];
  lines.push(`# 🧱 SecTool Firewall-Rule Export`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.generatedMs)}`);
  lines.push(
    `**Source:** SecTool's **enforced blocklist** (current state, not a time window) · ` +
      `**Set name:** \`${m.setName}\``,
  );
  lines.push(
    `**Emitted:** ${m.emitted} of ${m.totalBlocked} blocklist entr(ies) ` +
      `(${m.ipv4} IPv4, ${m.ipv6} IPv6)` +
      (m.excludedSafe ? ` · ${m.excludedSafe} safelisted excluded` : "") +
      (m.excludedInvalid ? ` · ${m.excludedInvalid} invalid skipped` : ""),
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  if (!m.emitted) {
    lines.push("---");
    lines.push(`_Generated offline by SecTool from the blocklist store. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  // Per-dialect scripts.
  lines.push(`## Ready-to-apply rules`);
  lines.push("");
  lines.push(
    `Each block below is a complete, copy-pasteable script for one platform, with an idempotent header where the ` +
      `device allows it. Choose the one that matches your edge device.`,
  );
  lines.push("");
  for (const d of FIREWALL_DIALECTS) {
    lines.push(`### ${d.label} — _${d.platform}_${d.ipv6 ? "" : " (IPv4 only)"}`);
    lines.push("");
    lines.push("```" + d.lang);
    lines.push(m.scripts[d.id].trimEnd());
    lines.push("```");
    lines.push("");
  }

  // Advisory aggregation table.
  if (m.aggregates.length) {
    lines.push(`## Suggested CIDR rollups (advisory)`);
    lines.push("");
    lines.push(
      `These subnets each contain ${AGGREGATE_THRESHOLD}+ individually-blocked hosts. Collapsing them into a single ` +
        `CIDR rule shrinks the ruleset, but blocks the *whole* subnet — only do this if the collateral is acceptable. ` +
        `**The generated rules above still list individual hosts**; this is a suggestion, not applied.`,
    );
    lines.push("");
    lines.push(
      mdTable(
        ["#", "Subnet", "Version", "Blocked hosts"],
        m.aggregates.map((a, i) => [String(i + 1), cell(a.cidr), `IPv${a.version}`, String(a.hostCount)]),
      ),
    );
    lines.push("");
  }

  // Review table of what is being blocked.
  lines.push(`## Blocked addresses (${m.emitted})`);
  lines.push("");
  lines.push(
    mdTable(
      ["#", "IP", "Ver", "Blocked", "Age", "Reason", "By"],
      m.entries.map((e, i) => [
        String(i + 1),
        cell(e.ip),
        `v${e.version}`,
        fmtTime(e.at),
        fmtAge(e.ageHours),
        e.reason ? cell(clip(e.reason)) : "—",
        e.by ? cell(clip(e.by, 20)) : "—",
      ]),
    ),
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from the **blocklist store** (the current enforced state, not a time window). ` +
      `Safelisted IPs are excluded by default so a trusted address is never dropped; CIDR rollups are advisory and ` +
      `never applied automatically. For block staleness see the \`hygiene\` report; for which sources to block next ` +
      `see \`blockplan\`. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

// ----- builder --------------------------------------------------------------

/**
 * Build the firewall-rule export from SecTool's current blocklist.
 *
 * @param opts {@link FwRulesOptions}: `setName` override, `includeSafe` to emit
 *             safelisted IPs too, and a `nowMs` pin for deterministic tests.
 */
export function buildFwRules(opts: FwRulesOptions = {}): FwRulesReport {
  const generatedMs = opts.nowMs ?? Date.now();
  const setName = sanitizeSetName(opts.setName);
  const includeSafe = opts.includeSafe === true;

  const all: BlockEntry[] = blockStore.all(); // newest first
  const totalBlocked = all.length;

  const entries: FwRuleEntry[] = [];
  let excludedSafe = 0;
  let excludedInvalid = 0;
  const prefixCounts = new Map<string, { version: 4 | 6; count: number }>();

  for (const e of all) {
    const ip = (e.ip ?? "").trim();
    const version = ipVersion(ip);
    if (version === 0) {
      excludedInvalid++;
      continue;
    }
    if (!includeSafe && safeStore.has(ip)) {
      excludedSafe++;
      continue;
    }
    if (entries.length >= MAX_ENTRIES) break;

    const at = Number.isFinite(e.at) ? e.at : generatedMs;
    entries.push({
      ip,
      version,
      at,
      ageHours: Math.max(0, round1((generatedMs - at) / MS_PER_HOUR)),
      reason: e.reason?.trim() || undefined,
      by: e.by?.trim() || undefined,
    });

    const pfx = prefixOf(ip, version);
    if (pfx) {
      const cur = prefixCounts.get(pfx) ?? { version, count: 0 };
      cur.count++;
      prefixCounts.set(pfx, cur);
    }
  }

  const ipv4 = entries.filter((e) => e.version === 4).length;
  const ipv6 = entries.length - ipv4;

  const aggregates: FwAggregate[] = [...prefixCounts.entries()]
    .filter(([, v]) => v.count >= AGGREGATE_THRESHOLD)
    .map(([cidr, v]) => ({ cidr, version: v.version, hostCount: v.count }))
    .sort((a, b) => b.hostCount - a.hostCount || (a.cidr < b.cidr ? -1 : 1));

  const oldestAgeHours = entries.reduce((mx, e) => Math.max(mx, e.ageHours), 0);

  const model: FwRulesReport = {
    generatedMs,
    setName,
    totalBlocked,
    emitted: entries.length,
    excludedSafe,
    excludedInvalid,
    includeSafe,
    ipv4,
    ipv6,
    entries,
    aggregates,
    scripts: {} as Record<FirewallDialect, string>,
    highlights: [],
    markdown: "",
  };

  // Render every dialect once against the finished entry list.
  for (const d of FIREWALL_DIALECTS) model.scripts[d.id] = renderFwScript(model, d.id);

  model.highlights = writeHighlights({
    totalBlocked,
    emitted: entries.length,
    excludedSafe,
    excludedInvalid,
    ipv4,
    ipv6,
    aggregates,
    oldestAgeHours,
  });
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded firewall-rule export. */
export function fwRulesFilename(nowMs: number, dialect?: FirewallDialect): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  const ext = dialect && dialect !== "plain" ? `-${dialect}` : "";
  return `sectool-fwrules${ext}-${stamp}.${dialect ? "txt" : "md"}`;
}
