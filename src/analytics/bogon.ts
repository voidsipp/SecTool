/**
 * Bogon / special-use source-address audit — "are any of my attackers using a
 * source IP that **cannot legitimately exist** on the public Internet, and what
 * does that tell me about spoofing or where my sensor is sitting?"
 *
 * Every source-attribution report in this project takes the alert's `srcIp` at
 * face value and ranks it: persist.ts (longevity), netblock.ts (rolls sources
 * up into /24 infrastructure ranges), clusters.ts (botnet correlation),
 * spread.ts (fan-out). None of them ever asks the prior, integrity-level
 * question a network engineer asks the moment a source address looks wrong:
 * **is this address even a valid, globally-routable unicast source at all?**
 *
 * The IANA IPv4/IPv6 Special-Purpose Address Registries (RFC 6890 and friends)
 * carve out large blocks that must never appear as the *source* of inbound
 * Internet traffic:
 *
 *   - **Martians / bogons** — `0.0.0.0/8` (this-network), `127.0.0.0/8`
 *     (loopback), `169.254.0.0/16` (link-local), the three TEST-NET
 *     documentation blocks, `198.18.0.0/15` (benchmarking), `192.0.0.0/24`
 *     (IETF protocol), `192.88.99.0/24` (deprecated 6to4 relay), `224.0.0.0/4`
 *     (multicast — invalid as a *source*), `240.0.0.0/4` (reserved) and the
 *     `255.255.255.255` limited broadcast. A packet *claiming* one of these as
 *     its source is, by definition, **spoofed** — the real sender forged it, or
 *     a misconfiguration is leaking it. On an Internet-facing gateway these
 *     should be dropped by uRPF/bogon filtering before Suricata ever sees them,
 *     so their mere presence is both a spoofing tell *and* an edge-ACL gap.
 *
 *   - **Internal / non-global** — RFC1918 (`10/8`, `172.16/12`, `192.168/16`),
 *     CGN `100.64.0.0/10`, IPv6 ULA `fc00::/7`. These are perfectly normal
 *     *inside* the network, so seeing them as a source is not an alarm by
 *     itself — but it tells you the alert is **lateral / internally-sourced**,
 *     not an external attack, which reframes how you triage it (and how every
 *     volume-ranked "top attacker" leaderboard should be read).
 *
 *   - **Public** — everything else: a globally-routable unicast address, the
 *     normal case. Reported only as the denominator so the special-use share is
 *     auditable.
 *
 * For every class this module rolls up, from the stored history:
 *
 *   - alert volume and its share of the (source-bearing) stream,
 *   - the severity profile (worst, medium-or-worse, critical) and a
 *     severity-weighted score — the ranking key, so a dangerous-but-quiet class
 *     is not buried under recon noise (mirrors classify.ts / protocols.ts),
 *   - enforcement posture — blocked vs detected and the resulting block rate, so
 *     a *spoofed-source* class that is mostly only-detected surfaces as a gap,
 *   - breadth — distinct source addresses and distinct internal targets reached,
 *   - the dominant signature and a recent-vs-older split so an *emerging*
 *     spoofing wave (most hits in the recent half) is flagged.
 *
 * It then lists the individual offending source addresses behind the martian and
 * internal classes (the public class is summarised, not enumerated — that is
 * what netblock.ts / persist.ts are for), each with its own volume, worst
 * severity, target reach and block status, so the finding is immediately
 * actionable: an address you can hand to a uRPF/bogon ACL.
 *
 * Honest caveats baked into the output:
 *
 *   - **Spoofed ≠ attributable.** A forged source address is *not* the real
 *     attacker — you cannot block your way to safety on a spoofed IP (the next
 *     packet will forge a different one). The value is detecting that spoofing
 *     is happening and that your edge is not filtering bogons, not building a
 *     blocklist. The report says so.
 *   - **Classification is prefix-based, offline.** Membership is decided purely
 *     from the address against the static IANA special-use ranges — no WHOIS, no
 *     network. IPv6 special-use detection is textual-prefix based and covers the
 *     common blocks; an exotically-formatted v6 literal may fall through to
 *     "public".
 *   - **Volume ≠ risk.** A single spoofed-source flood can dominate by count;
 *     rows are ranked by severity-weighted score, and the martian classes are
 *     called out separately so they are never lost under benign internal chatter.
 *   - **Window-bounded & store-capped.** A long look-back can hit the alert
 *     store's history cap and clip the earliest alerts.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network. Output is
 * both a structured model and a ready-to-paste Markdown document, mirroring
 * protocols.ts, classify.ts, dwell.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** The integrity verdict for an address class. */
export type BogonKind = "martian" | "internal" | "public";

/** Blocked / passed / unknown disposition split for an address class. */
export interface DispositionSplit {
  /** Alerts the gateway actively blocked / dropped. */
  blocked: number;
  /** Alerts the gateway logged but let through (detected / allowed). */
  passed: number;
  /** Alerts with no recorded action (excluded from {@link blockRate}). */
  unknown: number;
  /**
   * Fraction of *actioned* (blocked + passed) alerts that were blocked, 0..1
   * (4dp), or null when nothing was actioned.
   */
  blockRate: number | null;
}

/** One offending source address inside a non-public class. */
export interface OffendingSource {
  /** The source IP, verbatim. */
  ip: string;
  /** Address-class key this IP fell into (e.g. "loopback", "rfc1918"). */
  classKey: string;
  /** Windowed alerts from this address. */
  alerts: number;
  /** Distinct internal hosts this address reached. */
  distinctTargets: number;
  /** Worst severity seen from this address. */
  severityMax: Severity;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Whether this address is currently on the blocklist. */
  blocked: boolean;
  /** The most-frequent signature from this address, if any. */
  topSignature?: string;
}

/** One special-use (or public) address class rolled up over the window. */
export interface BogonClassEntry {
  /** Stable key, e.g. "loopback", "test-net", "rfc1918", "public". */
  key: string;
  /** Human label, e.g. "Loopback (127.0.0.0/8)". */
  label: string;
  /** Integrity verdict for the class. */
  kind: BogonKind;
  /** One-line "why this matters" hint shown inline. */
  hint: string;
  /** Total windowed alerts whose source fell in this class. */
  alerts: number;
  /** Share of all source-resolved alerts, 0..1 (4dp). */
  share: number;
  /** Distinct source addresses in this class. */
  distinctSources: number;
  /** Distinct internal destination hosts this class reached. */
  distinctTargets: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Alerts at critical severity. */
  critical: number;
  /** Severity-weighted score (Σ SEVERITY_WEIGHT) — the ranking key. */
  score: number;
  /** Worst severity seen for this class. */
  severityMax: Severity;
  /** Blocked / passed / unknown disposition split. */
  disposition: DispositionSplit;
  /** ms epoch of the first alert in the window for this class. */
  firstSeenMs: number;
  /** ms epoch of the last alert in the window for this class. */
  lastSeenMs: number;
  /** Alerts whose timestamp fell in the recent half of the window. */
  recentHalf: number;
  /** Share of this class's alerts in the recent half, 0..1 (4dp). */
  recentShare: number;
  /** The most-frequent signature for this class, if any. */
  topSignature?: string;
  /** Distinct signatures seen on this class. */
  distinctSignatures: number;
  /** How many of this class's source addresses are currently blocked. */
  blockedSources: number;
}

export interface BogonReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts that carried a parseable source IP. */
  resolvedSources: number;
  /** Alerts with no usable source IP (excluded). */
  unresolved: number;
  /** Total windowed alerts whose source is a martian / spoofed address. */
  martianAlerts: number;
  /** Distinct martian source addresses seen. */
  distinctMartianSources: number;
  /** Total windowed alerts whose source is internal / non-global. */
  internalAlerts: number;
  /** Per-class rows, most dangerous (weighted) first. */
  classes: BogonClassEntry[];
  /** The individual offending non-public source addresses (martian first). */
  offenders: OffendingSource[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface BogonOptions {
  /** Max rows in the offending-source table (clamped to [1, 200]). */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 25;
const MS_PER_HOUR = 3_600_000;

// ----- IANA special-purpose address classification -------------------------

/** Static description of one special-use address class. */
interface ClassDef {
  key: string;
  label: string;
  kind: BogonKind;
  hint: string;
}

const CLASS_DEFS: Record<string, ClassDef> = {
  "this-network": {
    key: "this-network",
    label: "This-network (0.0.0.0/8)",
    kind: "martian",
    hint: "RFC1122 'this host' — invalid as a routed source; spoofed",
  },
  loopback: {
    key: "loopback",
    label: "Loopback (127.0.0.0/8)",
    kind: "martian",
    hint: "host-local only — can never traverse a wire; spoofed",
  },
  "link-local": {
    key: "link-local",
    label: "Link-local (169.254.0.0/16)",
    kind: "martian",
    hint: "single-segment only — must not be routed; spoofed/misconfig",
  },
  "ietf-protocol": {
    key: "ietf-protocol",
    label: "IETF protocol assignments (192.0.0.0/24)",
    kind: "martian",
    hint: "reserved IETF block — not a valid Internet source",
  },
  "test-net": {
    key: "test-net",
    label: "Documentation / TEST-NET (192.0.2/24, 198.51.100/24, 203.0.113/24)",
    kind: "martian",
    hint: "RFC5737 documentation blocks — never real traffic; spoofed",
  },
  "6to4-relay": {
    key: "6to4-relay",
    label: "6to4 relay anycast (192.88.99.0/24)",
    kind: "martian",
    hint: "deprecated 6to4 relay (RFC7526) — should not appear inbound",
  },
  benchmark: {
    key: "benchmark",
    label: "Benchmarking (198.18.0.0/15)",
    kind: "martian",
    hint: "RFC2544 device-test block — never legitimate Internet traffic",
  },
  multicast: {
    key: "multicast",
    label: "Multicast as source (224.0.0.0/4)",
    kind: "martian",
    hint: "multicast is a destination scope — invalid as a source; spoofed",
  },
  reserved: {
    key: "reserved",
    label: "Reserved / future use (240.0.0.0/4)",
    kind: "martian",
    hint: "RFC1112 reserved — unallocated, cannot be a real source",
  },
  broadcast: {
    key: "broadcast",
    label: "Limited broadcast (255.255.255.255)",
    kind: "martian",
    hint: "broadcast address — invalid as a unicast source; spoofed",
  },
  rfc1918: {
    key: "rfc1918",
    label: "Private / RFC1918 (10/8, 172.16/12, 192.168/16)",
    kind: "internal",
    hint: "internally-sourced / lateral — not an external attacker",
  },
  cgn: {
    key: "cgn",
    label: "Carrier-grade NAT (100.64.0.0/10)",
    kind: "internal",
    hint: "RFC6598 CGN space — ISP/internal NAT, not globally routable",
  },
  "v6-unspecified": {
    key: "v6-unspecified",
    label: "IPv6 unspecified (::/128)",
    kind: "martian",
    hint: "the unspecified address — invalid as a source; spoofed",
  },
  "v6-loopback": {
    key: "v6-loopback",
    label: "IPv6 loopback (::1)",
    kind: "martian",
    hint: "host-local only — can never traverse a wire; spoofed",
  },
  "v6-link-local": {
    key: "v6-link-local",
    label: "IPv6 link-local (fe80::/10)",
    kind: "martian",
    hint: "single-segment only — must not be routed; spoofed/misconfig",
  },
  "v6-doc": {
    key: "v6-doc",
    label: "IPv6 documentation (2001:db8::/32)",
    kind: "martian",
    hint: "RFC3849 documentation block — never real traffic; spoofed",
  },
  "v6-multicast": {
    key: "v6-multicast",
    label: "IPv6 multicast as source (ff00::/8)",
    kind: "martian",
    hint: "multicast is a destination scope — invalid as a source; spoofed",
  },
  "v6-ula": {
    key: "v6-ula",
    label: "IPv6 ULA (fc00::/7)",
    kind: "internal",
    hint: "RFC4193 unique-local — internally-sourced / lateral",
  },
  public: {
    key: "public",
    label: "Public (globally-routable unicast)",
    kind: "public",
    hint: "normal external source — the denominator",
  },
};

/** Parse a dotted-quad into octets, or null if it is not a valid IPv4 literal. */
function ipv4Octets(ip: string): [number, number, number, number] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const o: [number, number, number, number] = [
    Number(m[1]),
    Number(m[2]),
    Number(m[3]),
    Number(m[4]),
  ];
  if (o.some((x) => x > 255)) return null;
  return o;
}

/** Classify an IPv4 address against the IANA special-purpose registry. */
function classifyV4(ip: string): string {
  const o = ipv4Octets(ip);
  if (!o) return "public";
  const [a, b] = o;
  if (a === 0) return "this-network";
  if (a === 127) return "loopback";
  if (a === 169 && b === 254) return "link-local";
  if (a === 10) return "rfc1918";
  if (a === 172 && b >= 16 && b <= 31) return "rfc1918";
  if (a === 192 && b === 168) return "rfc1918";
  if (a === 100 && b >= 64 && b <= 127) return "cgn";
  if (a === 192 && b === 0 && o[2] === 0) return "ietf-protocol";
  if (a === 192 && b === 0 && o[2] === 2) return "test-net";
  if (a === 198 && b === 51 && o[2] === 100) return "test-net";
  if (a === 203 && b === 0 && o[2] === 113) return "test-net";
  if (a === 192 && b === 88 && o[2] === 99) return "6to4-relay";
  if (a === 198 && (b === 18 || b === 19)) return "benchmark";
  if (a === 255 && b === 255 && o[2] === 255 && o[3] === 255) return "broadcast";
  if (a >= 224 && a <= 239) return "multicast";
  if (a >= 240) return "reserved";
  return "public";
}

/**
 * Classify an IPv6 address against the common special-purpose blocks. Detection
 * is textual-prefix based on the lower-cased literal: it covers the blocks that
 * realistically appear in IDS telemetry and falls through to "public" for an
 * exotically-formatted literal.
 */
function classifyV6(ip: string): string {
  const s = ip.toLowerCase();
  if (s === "::" || s === "::0" || s === "0:0:0:0:0:0:0:0") return "v6-unspecified";
  if (s === "::1") return "v6-loopback";
  if (/^fe[89ab]/.test(s)) return "v6-link-local";
  if (/^f[cd]/.test(s)) return "v6-ula";
  if (s.startsWith("ff")) return "v6-multicast";
  if (s.startsWith("2001:db8")) return "v6-doc";
  return "public";
}

/** Classify any source IP into a special-use class key. */
export function classifyAddress(ip: string): string {
  const v = isIP(ip);
  if (v === 4) return classifyV4(ip);
  if (v === 6) return classifyV6(ip);
  return "public";
}

// ----- shared helpers (mirror protocols.ts) ---------------------------------

/** RFC1918 / loopback / link-local / ULA — an address treated as one of ours. */
function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
}

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

function isCritical(s: string | undefined): boolean {
  return sevRank(s) >= 4;
}

function weightOf(s: string | undefined): number {
  return SEVERITY_WEIGHT[(s as Severity) ?? "info"] ?? SEVERITY_WEIGHT.info;
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

function pct(frac: number | null): string {
  return frac === null ? "—" : `${Math.round(frac * 100)}%`;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function clip(s: string, max = 40): string {
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
  let count = -1;
  for (const [k, c] of counts) {
    if (c > count || (c === count && key !== undefined && k < key)) {
      key = k;
      count = c;
    }
  }
  return key;
}

// ----- aggregation ----------------------------------------------------------

interface ClassAcc {
  alerts: number;
  sources: Set<string>;
  targets: Set<string>;
  severe: number;
  critical: number;
  score: number;
  severityMax: Severity;
  blocked: number;
  passed: number;
  unknown: number;
  firstSeenMs: number;
  lastSeenMs: number;
  recentHalf: number;
  sigCounts: Map<string, number>;
  blockedSources: Set<string>;
}

function newClassAcc(): ClassAcc {
  return {
    alerts: 0,
    sources: new Set(),
    targets: new Set(),
    severe: 0,
    critical: 0,
    score: 0,
    severityMax: "info",
    blocked: 0,
    passed: 0,
    unknown: 0,
    firstSeenMs: Number.POSITIVE_INFINITY,
    lastSeenMs: Number.NEGATIVE_INFINITY,
    recentHalf: 0,
    sigCounts: new Map(),
    blockedSources: new Set(),
  };
}

interface SrcAcc {
  ip: string;
  classKey: string;
  alerts: number;
  targets: Set<string>;
  severityMax: Severity;
  severe: number;
  sigCounts: Map<string, number>;
}

function tallyClass(acc: ClassAcc, a: StoredAlert, src: string, midMs: number): void {
  acc.alerts++;
  acc.score += weightOf(a.severity);
  acc.severityMax = maxSeverity(acc.severityMax, a.severity);
  if (isSevere(a.severity)) acc.severe++;
  if (isCritical(a.severity)) acc.critical++;

  acc.sources.add(src);
  if (blockStore.has(src)) acc.blockedSources.add(src);

  const dst = validIp(a.dstIp);
  if (dst && isPrivate(dst)) acc.targets.add(dst);

  const disp = classifyDisposition(a.action);
  if (disp === "blocked") acc.blocked++;
  else if (disp === "passed") acc.passed++;
  else acc.unknown++;

  if (a.time < acc.firstSeenMs) acc.firstSeenMs = a.time;
  if (a.time > acc.lastSeenMs) acc.lastSeenMs = a.time;
  if (a.time >= midMs) acc.recentHalf++;

  const sig = (a.signature ?? "").trim();
  if (sig) acc.sigCounts.set(sig, (acc.sigCounts.get(sig) ?? 0) + 1);
}

function tallySource(acc: SrcAcc, a: StoredAlert): void {
  acc.alerts++;
  acc.severityMax = maxSeverity(acc.severityMax, a.severity);
  if (isSevere(a.severity)) acc.severe++;
  const dst = validIp(a.dstIp);
  if (dst && isPrivate(dst)) acc.targets.add(dst);
  const sig = (a.signature ?? "").trim();
  if (sig) acc.sigCounts.set(sig, (acc.sigCounts.get(sig) ?? 0) + 1);
}

function finalizeClass(def: ClassDef, acc: ClassAcc, resolvedTotal: number): BogonClassEntry {
  const actioned = acc.blocked + acc.passed;
  return {
    key: def.key,
    label: def.label,
    kind: def.kind,
    hint: def.hint,
    alerts: acc.alerts,
    share: resolvedTotal ? round4(acc.alerts / resolvedTotal) : 0,
    distinctSources: acc.sources.size,
    distinctTargets: acc.targets.size,
    severe: acc.severe,
    critical: acc.critical,
    score: round4(acc.score),
    severityMax: acc.severityMax,
    disposition: {
      blocked: acc.blocked,
      passed: acc.passed,
      unknown: acc.unknown,
      blockRate: actioned ? round4(acc.blocked / actioned) : null,
    },
    firstSeenMs: Number.isFinite(acc.firstSeenMs) ? acc.firstSeenMs : 0,
    lastSeenMs: Number.isFinite(acc.lastSeenMs) ? acc.lastSeenMs : 0,
    recentHalf: acc.recentHalf,
    recentShare: acc.alerts ? round4(acc.recentHalf / acc.alerts) : 0,
    topSignature: topOf(acc.sigCounts),
    distinctSignatures: acc.sigCounts.size,
    blockedSources: acc.blockedSources.size,
  } satisfies BogonClassEntry;
}

/** Rank classes: martian before internal before public, then weighted, then volume. */
function kindRank(k: BogonKind): number {
  return k === "martian" ? 0 : k === "internal" ? 1 : 2;
}

function rankClass(a: BogonClassEntry, b: BogonClassEntry): number {
  return (
    kindRank(a.kind) - kindRank(b.kind) ||
    b.score - a.score ||
    b.alerts - a.alerts ||
    (a.label < b.label ? -1 : a.label > b.label ? 1 : 0)
  );
}

/** Rank offending sources: martian before internal, then volume, then severity. */
function rankSource(a: OffendingSource, b: OffendingSource): number {
  const ka = CLASS_DEFS[a.classKey]?.kind === "martian" ? 0 : 1;
  const kb = CLASS_DEFS[b.classKey]?.kind === "martian" ? 0 : 1;
  return (
    ka - kb ||
    b.alerts - a.alerts ||
    sevRank(b.severityMax) - sevRank(a.severityMax) ||
    (a.ip < b.ip ? -1 : a.ip > b.ip ? 1 : 0)
  );
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  m: { resolvedSources: number; unresolved: number; martianAlerts: number; internalAlerts: number },
  classes: BogonClassEntry[],
  offenders: OffendingSource[],
): string[] {
  const out: string[] = [];
  if (!classes.length) return out;

  const martians = classes.filter((c) => c.kind === "martian");
  const internal = classes.filter((c) => c.kind === "internal");
  const publicCls = classes.find((c) => c.kind === "public");

  if (martians.length) {
    const distinctMartian = new Set(
      offenders.filter((o) => CLASS_DEFS[o.classKey]?.kind === "martian").map((o) => o.ip),
    ).size;
    const names = martians
      .slice(0, 4)
      .map((c) => `${c.key} (${c.alerts})`)
      .join(", ");
    out.push(
      `🛑 **${m.martianAlerts} alert(s) from ${distinctMartian} spoofed / bogon source address(es)** — ` +
        `${names}. A packet claiming one of these as its source is forged by definition: these blocks ` +
        `cannot legitimately originate Internet traffic. Their presence is both a **spoofing tell** and an ` +
        `**edge-filter gap** — your gateway should drop bogons (uRPF / bogon ACL) before Suricata ever logs them.`,
    );
    const worst = martians[0]!;
    if (worst.severe > 0) {
      out.push(
        `⚠️ The worst spoofed-source class is **${worst.label}** — ${worst.severe} medium-or-worse alert(s) ` +
          `(worst severity ${worst.severityMax}), only **${pct(worst.disposition.blockRate)}** of its actioned ` +
          `traffic blocked. You cannot blocklist your way out of spoofing (the next packet forges a different ` +
          `source); fix it at the edge with anti-spoofing / bogon filtering instead.`,
      );
    }
    const rising = martians
      .filter((c) => c.alerts >= 5 && c.recentShare >= 0.6)
      .sort((a, b) => b.recentShare - a.recentShare)[0];
    if (rising) {
      out.push(
        `📈 **Spoofing wave forming:** ${pct(rising.recentShare)} of the ${rising.alerts} **${rising.key}** ` +
          `alert(s) landed in the recent half of the window — an emerging forged-source push, not a stale artefact.`,
      );
    }
  } else {
    out.push(
      `✅ **No bogon / martian source addresses in this window** — every source IP is either a globally-routable ` +
        `public address or a recognised internal range. No evidence of source-spoofing reaching the sensor, and ` +
        `(at least for this window) no obvious gap in edge bogon filtering.`,
    );
  }

  if (internal.length) {
    const internalSources = new Set(
      offenders.filter((o) => CLASS_DEFS[o.classKey]?.kind === "internal").map((o) => o.ip),
    ).size;
    out.push(
      `🏠 **${m.internalAlerts} alert(s) are internally-sourced** (${internal.map((c) => c.key).join(", ")}) from ` +
        `${internalSources} private/CGN address(es) — these are **lateral / inside-out**, not external attacks. ` +
        `Read every "top attacker" leaderboard with that in mind, and treat internal sources as a possible ` +
        `compromised-host or misrouted-traffic signal rather than perimeter noise.`,
    );
  }

  if (publicCls) {
    out.push(
      `🌐 For scale: **${pct(publicCls.share)}** of source-resolved alerts (${publicCls.alerts}) come from normal ` +
        `**public** addresses — the expected case, analysed by the source/netblock reports. This audit is about ` +
        `the ${pct(round4((m.martianAlerts + m.internalAlerts) / Math.max(1, m.resolvedSources)))} that are *not*.`,
    );
  }

  if (m.unresolved > 0) {
    out.push(
      `🔍 **${m.unresolved} alert(s) carried no parseable source IP** and were excluded — the source-completeness ` +
        `caveat the \`coverage\` report tracks in full.`,
    );
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function classTable(rows: BogonClassEntry[]): string {
  const headers = [
    "#",
    "Address class",
    "Verdict",
    "Alerts",
    "Share",
    "Sources",
    "Targets",
    "Worst",
    "Severe",
    "Block rate",
    "Recent½",
    "Why it matters",
  ];
  return mdTable(
    headers,
    rows.map((c, i) => [
      String(i + 1),
      cell(c.label),
      c.kind === "martian" ? "🛑 spoofed" : c.kind === "internal" ? "🏠 internal" : "🌐 public",
      String(c.alerts),
      pct(c.share),
      String(c.distinctSources),
      String(c.distinctTargets),
      cell(c.severityMax),
      String(c.severe),
      pct(c.disposition.blockRate),
      pct(c.recentShare),
      cell(c.hint),
    ]),
  );
}

function offenderTable(rows: OffendingSource[]): string {
  const headers = [
    "#",
    "Source address",
    "Class",
    "Verdict",
    "Alerts",
    "Targets",
    "Worst",
    "Severe",
    "Blocked?",
    "Top signature",
  ];
  return mdTable(
    headers,
    rows.map((o, i) => {
      const kind = CLASS_DEFS[o.classKey]?.kind;
      return [
        String(i + 1),
        cell(o.ip),
        cell(o.classKey),
        kind === "martian" ? "🛑 spoofed" : "🏠 internal",
        String(o.alerts),
        String(o.distinctTargets),
        cell(o.severityMax),
        String(o.severe),
        o.blocked ? "yes" : "no",
        o.topSignature ? cell(clip(o.topSignature)) : "—",
      ];
    }),
  );
}

function renderMarkdown(m: BogonReport): string {
  const lines: string[] = [];
  lines.push(`# 🛰️ SecTool Bogon / Special-Use Source-Address Audit`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`,
  );
  lines.push(
    `**Method:** each alert's **source IP** is classified offline against the IANA IPv4/IPv6 special-purpose ` +
      `registries (RFC 6890 & friends) into **spoofed / bogon**, **internal / non-global** or **public**, then ` +
      `ranked by **severity-weighted score** · **Resolved:** ${m.resolvedSources} of ${m.totalWindowAlerts} ` +
      `alert(s) carried a source IP (${m.unresolved} unresolved)`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.classes.length) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but **none carried a parseable source ` +
          `IP** — without a source address there is nothing to classify here. See the \`coverage\` report for the ` +
          `field-completeness picture.`,
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

  lines.push(`## Address classes`);
  lines.push("");
  lines.push(classTable(m.classes));
  lines.push("");
  lines.push(
    `**Legend:** _Share_ is of the ${m.resolvedSources} source-resolved alerts. **🛑 spoofed** = a martian/bogon ` +
      `block that cannot legitimately source Internet traffic (forged); **🏠 internal** = a private/CGN/ULA range ` +
      `(lateral / inside-out, not an external attacker); **🌐 public** = a normal globally-routable address. ` +
      `_Severe_ = medium-or-worse. _Block rate_ = blocked ÷ actioned. _Recent½_ = share of the class's alerts in ` +
      `the recent half of the window (> 60% = emerging). Rows are ranked spoofed → internal → public, then by ` +
      `severity-weighted score.`,
  );
  lines.push("");

  lines.push(`## Offending source addresses (non-public)`);
  lines.push("");
  if (m.offenders.length) {
    lines.push(offenderTable(m.offenders));
    lines.push("");
    lines.push(
      `_The individual martian (🛑) and internal (🏠) source addresses behind the classes above. ` +
        `**Do not treat a spoofed source as an attacker to blocklist** — it is forged and the next packet will ` +
        `carry a different one; the action is anti-spoofing / bogon filtering at the edge. Internal sources are ` +
        `candidates for compromised-host or misrouting investigation. Public sources are intentionally omitted — ` +
        `see the \`netblocks\` / \`persist\` reports for those._`,
    );
  } else {
    lines.push(
      `_Every source address in this window is a normal public address — there are no bogon or internal sources ` +
        `to enumerate. That is the healthy outcome: no spoofing reaching the sensor and no internal traffic ` +
        `leaking into the alert stream._`,
    );
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Source addresses are classified purely from the static IANA special-use ` +
      `ranges — no WHOIS, no network lookup; IPv6 special-use detection is textual-prefix based and covers the ` +
      `common blocks. A **spoofed source is not the real attacker** — the value is detecting that spoofing is ` +
      `occurring and that edge bogon filtering is absent, not building a blocklist. Volume ≠ risk: a single ` +
      `forged-source flood can dominate by count, so classes are ranked by severity-weighted score and the ` +
      `martian classes are surfaced first. Figures are drawn from the ${m.resolvedSources} of ${m.totalWindowAlerts} ` +
      `alert(s) that carried a source IP; ${m.unresolved} were unresolved and excluded. A long look-back can hit ` +
      `the store's history cap and clip the earliest alerts. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the bogon / special-use source-address audit from the stored alert
 * history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link BogonOptions}: `limit` for the offender table and a `nowMs`
 *              pin for deterministic tests.
 */
export function buildBogon(hours: number, opts: BogonOptions = {}): BogonReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;
  const midMs = windowStartMs + (windowEndMs - windowStartMs) / 2;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const classAcc = new Map<string, ClassAcc>();
  const srcAcc = new Map<string, SrcAcc>();
  let resolvedSources = 0;
  let unresolved = 0;
  let martianAlerts = 0;
  let internalAlerts = 0;

  for (const a of windowed) {
    const src = validIp(a.srcIp);
    if (!src) {
      unresolved++;
      continue;
    }
    resolvedSources++;

    const key = classifyAddress(src);
    const def = CLASS_DEFS[key] ?? CLASS_DEFS.public!;

    const acc = classAcc.get(key) ?? newClassAcc();
    if (!classAcc.has(key)) classAcc.set(key, acc);
    tallyClass(acc, a, src, midMs);

    if (def.kind === "martian") martianAlerts++;
    else if (def.kind === "internal") internalAlerts++;

    // Enumerate the individual offending (non-public) addresses.
    if (def.kind !== "public") {
      const sa = srcAcc.get(src) ?? {
        ip: src,
        classKey: key,
        alerts: 0,
        targets: new Set<string>(),
        severityMax: "info" as Severity,
        severe: 0,
        sigCounts: new Map<string, number>(),
      };
      if (!srcAcc.has(src)) srcAcc.set(src, sa);
      tallySource(sa, a);
    }
  }

  const classes = [...classAcc.entries()]
    .map(([key, acc]) => finalizeClass(CLASS_DEFS[key] ?? CLASS_DEFS.public!, acc, resolvedSources))
    .sort(rankClass);

  const offenders: OffendingSource[] = [...srcAcc.values()]
    .map((sa) => ({
      ip: sa.ip,
      classKey: sa.classKey,
      alerts: sa.alerts,
      distinctTargets: sa.targets.size,
      severityMax: sa.severityMax,
      severe: sa.severe,
      blocked: blockStore.has(sa.ip),
      topSignature: topOf(sa.sigCounts),
    }))
    .sort(rankSource)
    .slice(0, limit);

  const distinctMartianSources = [...srcAcc.values()].filter(
    (sa) => CLASS_DEFS[sa.classKey]?.kind === "martian",
  ).length;

  const highlights = writeHighlights(
    safeHours,
    { resolvedSources, unresolved, martianAlerts, internalAlerts },
    classes,
    offenders,
  );

  const model: BogonReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    resolvedSources,
    unresolved,
    martianAlerts,
    distinctMartianSources,
    internalAlerts,
    classes,
    offenders,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded bogon audit report. */
export function bogonFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-bogon-${stamp}.md`;
}
