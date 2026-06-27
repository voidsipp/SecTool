/**
 * Cloud / hosting-origin attribution — "how much of my attack traffic is coming
 * from rented cloud and VPS infrastructure, *which* provider, and who do I email
 * to get it shut down?"
 *
 * Every source-attribution report in this project ranks the attacker's `srcIp`
 * but stops at the address: persist.ts (longevity), netblock.ts (rolls sources
 * up into the /24 the address sits in), clusters.ts (botnet correlation),
 * bogon.ts (is the address even a *valid* public unicast source). None of them
 * answers the question a responder asks the instant a public scanner shows up:
 * **whose infrastructure is this — a hyperscaler, a budget VPS host, a CDN, or an
 * unattributable residential/corporate netblock — and is there an abuse desk I
 * can report it to?**
 *
 * That distinction changes the response, not just the label:
 *
 *   - **Hyperscaler** (AWS, GCP, Azure, Oracle, Alibaba, Tencent) and **budget
 *     VPS** (DigitalOcean, Linode/Akamai, Vultr, OVH, Hetzner, Scaleway) hosts
 *     are *rented* — the attacker spun up a throwaway instance. The IP is
 *     ephemeral (blocklisting it ages out fast and risks a future legitimate
 *     tenant), but the provider has a real **abuse contact** and a track record
 *     of terminating offending instances. The action is *report to the abuse
 *     desk*, not just block. Budget VPS providers in particular are the workhorse
 *     of internet-wide scanning, so a heavy VPS share is a "commodity scan noise"
 *     tell.
 *   - **CDN / proxy** (Cloudflare) in the *source* position is a caveat, not an
 *     attacker: the real origin is hidden behind the proxy, so the visible IP is
 *     the CDN edge. Blocklisting it can break legitimate proxied traffic. The
 *     report flags it rather than ranking it as a culprit.
 *   - **Unclassified** — everything not in the table: residential ISP space, a
 *     corporate netblock, an un-curated host, or simply a provider this offline
 *     table does not know. A high unclassified share is *not* "no cloud" — it is
 *     "attribution unknown", and a residential-looking source is a possible
 *     **compromised home host / proxy / botnet node**, which is a different and
 *     often more interesting signal than a rented scanner.
 *
 * For every provider this module rolls up, from the stored history:
 *
 *   - alert volume and its share of the (public-source) stream,
 *   - the severity profile (worst, medium-or-worse, critical) and a
 *     severity-weighted score — the ranking key, so a dangerous-but-quiet
 *     provider is not buried under recon noise (mirrors classify.ts / bogon.ts),
 *   - enforcement posture — blocked vs detected and the resulting block rate,
 *   - breadth — distinct source addresses and distinct internal targets reached,
 *   - the dominant signature and a recent-vs-older split so an *emerging* push
 *     from one provider (most hits in the recent half) is flagged,
 *   - the provider's **abuse contact**, so the finding is immediately actionable.
 *
 * It then lists the individual top offending cloud/VPS source addresses, each
 * with its volume, worst severity, target reach, block status and the abuse
 * contact for its provider — a ready-to-action worklist.
 *
 * Honest caveats baked into the output:
 *
 *   - **The CIDR table is a curated, best-effort subset, not authoritative.**
 *     Membership is decided offline by longest-prefix match against a static set
 *     of well-known published provider ranges — no WHOIS, no BGP, no network. A
 *     provider's newer or smaller allocations may be missing (→ counted as
 *     *unclassified*), and large aggregates can occasionally over-claim. Treat a
 *     match as a strong hint, not courtroom proof. Unclassified ≠ "not cloud".
 *   - **IPv4 only.** Cloud IPv6 ranges are not in the table; an IPv6 source falls
 *     to *unclassified* with this caveat. Most IDS scan telemetry is v4.
 *   - **A cloud IP is ephemeral.** The action is usually *report to abuse*, not
 *     *permanent block* — the next instance gets a different address and the
 *     current one may later belong to an innocent tenant.
 *   - **Volume ≠ risk.** A single cloud-hosted flood can dominate by count; rows
 *     are ranked by severity-weighted score, with provider class as the primary
 *     sort so attributable infra surfaces above the unclassified bucket.
 *   - **Window-bounded & store-capped.** A long look-back can hit the alert
 *     store's history cap and clip the earliest alerts.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network. Output is
 * both a structured model and a ready-to-paste Markdown document, mirroring
 * bogon.ts, protocols.ts, classify.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Coarse class a provider falls into — drives sort order and response advice. */
export type ProviderKind = "hyperscaler" | "vps" | "cdn" | "unclassified";

/** Blocked / passed / unknown disposition split for a provider. */
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

/** Static description of one hosting provider. */
export interface ProviderDef {
  /** Stable key, e.g. "aws", "digitalocean". */
  key: string;
  /** Human label, e.g. "Amazon AWS". */
  label: string;
  /** Coarse class — hyperscaler / vps / cdn. */
  kind: Exclude<ProviderKind, "unclassified">;
  /** Where to report abuse (email or URL). */
  abuse: string;
  /** One-line "why this matters" hint shown inline. */
  hint: string;
}

/** One top offending cloud/VPS source address. */
export interface OffendingSource {
  /** The source IP, verbatim. */
  ip: string;
  /** Provider key this IP matched. */
  providerKey: string;
  /** Provider label, for display. */
  providerLabel: string;
  /** Provider abuse contact, for the worklist. */
  abuse: string;
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

/** One provider (or the unclassified bucket) rolled up over the window. */
export interface CloudProviderEntry {
  /** Stable key, e.g. "aws", "ovh", "unclassified". */
  key: string;
  /** Human label, e.g. "Amazon AWS". */
  label: string;
  /** Coarse class. */
  kind: ProviderKind;
  /** Abuse contact (empty for the unclassified bucket). */
  abuse: string;
  /** One-line "why this matters" hint shown inline. */
  hint: string;
  /** Total windowed alerts whose source fell to this provider. */
  alerts: number;
  /** Share of all public-source alerts, 0..1 (4dp). */
  share: number;
  /** Distinct source addresses attributed to this provider. */
  distinctSources: number;
  /** Distinct internal destination hosts this provider's sources reached. */
  distinctTargets: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Alerts at critical severity. */
  critical: number;
  /** Severity-weighted score (Σ SEVERITY_WEIGHT) — the ranking key. */
  score: number;
  /** Worst severity seen for this provider. */
  severityMax: Severity;
  /** Blocked / passed / unknown disposition split. */
  disposition: DispositionSplit;
  /** ms epoch of the first alert in the window for this provider. */
  firstSeenMs: number;
  /** ms epoch of the last alert in the window for this provider. */
  lastSeenMs: number;
  /** Alerts whose timestamp fell in the recent half of the window. */
  recentHalf: number;
  /** Share of this provider's alerts in the recent half, 0..1 (4dp). */
  recentShare: number;
  /** The most-frequent signature for this provider, if any. */
  topSignature?: string;
  /** Distinct signatures seen on this provider. */
  distinctSignatures: number;
  /** How many of this provider's source addresses are currently blocked. */
  blockedSources: number;
}

export interface CloudReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts with a parseable *public* source IP (the denominator). */
  publicSources: number;
  /** Alerts excluded for having no parseable source IP. */
  unresolved: number;
  /** Alerts excluded for an internal / bogon / non-public source. */
  nonPublic: number;
  /** Total windowed alerts attributed to a known cloud/VPS/CDN provider. */
  attributedAlerts: number;
  /** Distinct source addresses attributed to a known provider. */
  distinctAttributedSources: number;
  /** Per-provider rows, most actionable (class then weighted) first. */
  providers: CloudProviderEntry[];
  /** The individual top offending cloud/VPS source addresses. */
  offenders: OffendingSource[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface CloudOptions {
  /** Max rows in the offending-source table (clamped to [1, 200]). */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 25;
const MS_PER_HOUR = 3_600_000;

// ----- provider registry ----------------------------------------------------

const PROVIDERS: Record<string, ProviderDef> = {
  aws: {
    key: "aws",
    label: "Amazon AWS",
    kind: "hyperscaler",
    abuse: "abuse@amazonaws.com",
    hint: "rented hyperscaler instance — ephemeral; report to AWS abuse",
  },
  gcp: {
    key: "gcp",
    label: "Google Cloud",
    kind: "hyperscaler",
    abuse: "https://cloud.google.com/abuse",
    hint: "rented hyperscaler instance — ephemeral; report via GCP abuse",
  },
  azure: {
    key: "azure",
    label: "Microsoft Azure",
    kind: "hyperscaler",
    abuse: "abuse@microsoft.com",
    hint: "rented hyperscaler instance — ephemeral; report to MSRC/abuse",
  },
  oracle: {
    key: "oracle",
    label: "Oracle Cloud (OCI)",
    kind: "hyperscaler",
    abuse: "abuse_request@oracle.com",
    hint: "rented hyperscaler instance — ephemeral; report to Oracle abuse",
  },
  alibaba: {
    key: "alibaba",
    label: "Alibaba Cloud",
    kind: "hyperscaler",
    abuse: "abuse@alibabacloud.com",
    hint: "rented hyperscaler instance — common scan origin; report to abuse",
  },
  tencent: {
    key: "tencent",
    label: "Tencent Cloud",
    kind: "hyperscaler",
    abuse: "tencent_cloud_abuse@tencent.com",
    hint: "rented hyperscaler instance — common scan origin; report to abuse",
  },
  digitalocean: {
    key: "digitalocean",
    label: "DigitalOcean",
    kind: "vps",
    abuse: "abuse@digitalocean.com",
    hint: "budget VPS — workhorse of internet-wide scanning; report to abuse",
  },
  linode: {
    key: "linode",
    label: "Linode / Akamai",
    kind: "vps",
    abuse: "abuse@linode.com",
    hint: "budget VPS — common scan/bot origin; report to abuse",
  },
  vultr: {
    key: "vultr",
    label: "Vultr (Constant)",
    kind: "vps",
    abuse: "abuse@vultr.com",
    hint: "budget VPS — common scan/bot origin; report to abuse",
  },
  ovh: {
    key: "ovh",
    label: "OVH / OVHcloud",
    kind: "vps",
    abuse: "abuse@ovh.net",
    hint: "budget VPS / dedicated — frequent abuse origin; report to abuse",
  },
  hetzner: {
    key: "hetzner",
    label: "Hetzner",
    kind: "vps",
    abuse: "abuse@hetzner.com",
    hint: "budget VPS / dedicated — frequent abuse origin; report to abuse",
  },
  scaleway: {
    key: "scaleway",
    label: "Scaleway / Online SAS",
    kind: "vps",
    abuse: "abuse@scaleway.com",
    hint: "budget VPS — common scan origin; report to abuse",
  },
  cloudflare: {
    key: "cloudflare",
    label: "Cloudflare (CDN/proxy)",
    kind: "cdn",
    abuse: "https://abuse.cloudflare.com",
    hint: "CDN/proxy edge — the real origin is hidden; do NOT blocklist blindly",
  },
};

/** The unclassified bucket — not a real provider, synthesised for the rollup. */
const UNCLASSIFIED: { key: string; label: string; kind: ProviderKind; abuse: string; hint: string } = {
  key: "unclassified",
  label: "Unclassified (residential / ISP / unknown)",
  kind: "unclassified",
  abuse: "",
  hint: "not in the cloud table — residential/ISP/corp or unknown; possible compromised host",
};

/**
 * Curated, best-effort table of well-known published provider IPv4 ranges. This
 * is intentionally a representative subset, not an authoritative BGP dump: a
 * match is a strong hint, a miss means *unclassified*, not "not cloud". Ranges
 * are resolved by longest-prefix match so a more-specific entry wins over a
 * broader aggregate.
 */
const CIDRS: ReadonlyArray<readonly [string, string]> = [
  // Amazon AWS
  ["aws", "3.0.0.0/8"],
  ["aws", "15.177.0.0/18"],
  ["aws", "18.32.0.0/11"],
  ["aws", "18.128.0.0/9"],
  ["aws", "52.0.0.0/10"],
  ["aws", "54.64.0.0/11"],
  ["aws", "54.144.0.0/12"],
  ["aws", "54.160.0.0/11"],
  ["aws", "54.224.0.0/11"],
  ["aws", "99.77.0.0/16"],
  // Google Cloud
  ["gcp", "34.0.0.0/9"],
  ["gcp", "34.64.0.0/10"],
  ["gcp", "34.128.0.0/10"],
  ["gcp", "35.184.0.0/13"],
  ["gcp", "35.192.0.0/13"],
  ["gcp", "35.208.0.0/12"],
  ["gcp", "35.224.0.0/12"],
  ["gcp", "104.154.0.0/15"],
  ["gcp", "104.196.0.0/14"],
  ["gcp", "130.211.0.0/16"],
  // Microsoft Azure
  ["azure", "13.64.0.0/11"],
  ["azure", "20.0.0.0/8"],
  ["azure", "40.64.0.0/10"],
  ["azure", "52.224.0.0/11"],
  ["azure", "104.40.0.0/13"],
  ["azure", "137.116.0.0/15"],
  ["azure", "168.61.0.0/16"],
  // Oracle Cloud (OCI)
  ["oracle", "129.146.0.0/16"],
  ["oracle", "130.61.0.0/16"],
  ["oracle", "132.145.0.0/16"],
  ["oracle", "150.136.0.0/16"],
  ["oracle", "158.101.0.0/16"],
  // Alibaba Cloud
  ["alibaba", "8.208.0.0/12"],
  ["alibaba", "47.74.0.0/15"],
  ["alibaba", "47.76.0.0/14"],
  ["alibaba", "47.80.0.0/13"],
  ["alibaba", "47.96.0.0/11"],
  ["alibaba", "47.235.0.0/16"],
  ["alibaba", "47.236.0.0/14"],
  ["alibaba", "47.240.0.0/13"],
  ["alibaba", "39.96.0.0/11"],
  ["alibaba", "47.250.0.0/15"],
  ["alibaba", "8.128.0.0/10"],
  // Tencent Cloud
  ["tencent", "43.128.0.0/14"],
  ["tencent", "43.132.0.0/14"],
  ["tencent", "49.51.0.0/16"],
  ["tencent", "101.32.0.0/15"],
  ["tencent", "101.34.0.0/15"],
  ["tencent", "119.28.0.0/15"],
  ["tencent", "129.211.0.0/16"],
  ["tencent", "129.226.0.0/16"],
  ["tencent", "139.155.0.0/16"],
  ["tencent", "150.109.0.0/16"],
  ["tencent", "170.106.0.0/16"],
  // DigitalOcean
  ["digitalocean", "45.55.0.0/16"],
  ["digitalocean", "64.227.0.0/16"],
  ["digitalocean", "68.183.0.0/16"],
  ["digitalocean", "104.131.0.0/16"],
  ["digitalocean", "104.236.0.0/16"],
  ["digitalocean", "134.122.0.0/16"],
  ["digitalocean", "134.209.0.0/16"],
  ["digitalocean", "138.68.0.0/16"],
  ["digitalocean", "138.197.0.0/16"],
  ["digitalocean", "142.93.0.0/16"],
  ["digitalocean", "143.110.0.0/16"],
  ["digitalocean", "143.198.0.0/16"],
  ["digitalocean", "146.190.0.0/16"],
  ["digitalocean", "157.230.0.0/16"],
  ["digitalocean", "159.65.0.0/16"],
  ["digitalocean", "159.89.0.0/16"],
  ["digitalocean", "161.35.0.0/16"],
  ["digitalocean", "164.90.0.0/16"],
  ["digitalocean", "164.92.0.0/16"],
  ["digitalocean", "165.22.0.0/16"],
  ["digitalocean", "165.227.0.0/16"],
  ["digitalocean", "167.71.0.0/16"],
  ["digitalocean", "167.99.0.0/16"],
  ["digitalocean", "167.172.0.0/16"],
  ["digitalocean", "174.138.0.0/16"],
  ["digitalocean", "178.62.0.0/16"],
  ["digitalocean", "188.166.0.0/16"],
  ["digitalocean", "206.189.0.0/16"],
  ["digitalocean", "209.97.0.0/16"],
  // Linode / Akamai
  ["linode", "45.33.0.0/16"],
  ["linode", "45.56.0.0/16"],
  ["linode", "45.79.0.0/16"],
  ["linode", "50.116.0.0/18"],
  ["linode", "96.126.96.0/19"],
  ["linode", "139.144.0.0/16"],
  ["linode", "139.162.0.0/16"],
  ["linode", "172.104.0.0/15"],
  ["linode", "172.232.0.0/16"],
  ["linode", "173.255.192.0/18"],
  ["linode", "178.79.128.0/18"],
  ["linode", "192.46.208.0/20"],
  ["linode", "192.155.80.0/20"],
  ["linode", "198.58.96.0/19"],
  // Vultr (Constant Company)
  ["vultr", "45.32.0.0/16"],
  ["vultr", "45.63.0.0/16"],
  ["vultr", "45.76.0.0/16"],
  ["vultr", "45.77.0.0/16"],
  ["vultr", "64.176.0.0/16"],
  ["vultr", "95.179.128.0/18"],
  ["vultr", "104.156.224.0/19"],
  ["vultr", "108.61.0.0/16"],
  ["vultr", "136.244.64.0/18"],
  ["vultr", "144.202.0.0/16"],
  ["vultr", "149.28.0.0/16"],
  ["vultr", "155.138.128.0/17"],
  ["vultr", "207.148.0.0/17"],
  // OVH / OVHcloud
  ["ovh", "5.39.0.0/17"],
  ["ovh", "5.135.0.0/16"],
  ["ovh", "37.59.0.0/16"],
  ["ovh", "37.187.0.0/16"],
  ["ovh", "46.105.0.0/16"],
  ["ovh", "51.68.0.0/14"],
  ["ovh", "51.75.0.0/16"],
  ["ovh", "51.81.0.0/16"],
  ["ovh", "51.83.0.0/16"],
  ["ovh", "51.89.0.0/16"],
  ["ovh", "51.91.0.0/16"],
  ["ovh", "51.178.0.0/15"],
  ["ovh", "51.195.0.0/16"],
  ["ovh", "51.210.0.0/16"],
  ["ovh", "54.36.0.0/14"],
  ["ovh", "91.121.0.0/16"],
  ["ovh", "92.222.0.0/16"],
  ["ovh", "94.23.0.0/16"],
  ["ovh", "137.74.0.0/16"],
  ["ovh", "144.217.0.0/16"],
  ["ovh", "147.135.0.0/16"],
  ["ovh", "149.202.0.0/16"],
  ["ovh", "167.114.0.0/16"],
  ["ovh", "178.32.0.0/15"],
  ["ovh", "188.165.0.0/16"],
  // Hetzner
  ["hetzner", "5.9.0.0/16"],
  ["hetzner", "23.88.0.0/17"],
  ["hetzner", "49.12.0.0/16"],
  ["hetzner", "49.13.0.0/16"],
  ["hetzner", "65.108.0.0/16"],
  ["hetzner", "65.109.0.0/16"],
  ["hetzner", "78.46.0.0/15"],
  ["hetzner", "88.99.0.0/16"],
  ["hetzner", "88.198.0.0/16"],
  ["hetzner", "95.216.0.0/15"],
  ["hetzner", "116.202.0.0/15"],
  ["hetzner", "128.140.0.0/17"],
  ["hetzner", "135.181.0.0/16"],
  ["hetzner", "138.201.0.0/16"],
  ["hetzner", "142.132.128.0/17"],
  ["hetzner", "144.76.0.0/16"],
  ["hetzner", "148.251.0.0/16"],
  ["hetzner", "157.90.0.0/16"],
  ["hetzner", "159.69.0.0/16"],
  ["hetzner", "162.55.0.0/16"],
  ["hetzner", "167.235.0.0/16"],
  ["hetzner", "168.119.0.0/16"],
  ["hetzner", "176.9.0.0/16"],
  ["hetzner", "178.63.0.0/16"],
  ["hetzner", "188.40.0.0/16"],
  ["hetzner", "195.201.0.0/16"],
  // Scaleway / Online SAS
  ["scaleway", "51.15.0.0/16"],
  ["scaleway", "51.158.0.0/15"],
  ["scaleway", "62.210.0.0/16"],
  ["scaleway", "151.115.0.0/16"],
  ["scaleway", "163.172.0.0/16"],
  ["scaleway", "195.154.0.0/16"],
  ["scaleway", "212.47.224.0/19"],
  ["scaleway", "212.83.128.0/19"],
  // Cloudflare (CDN / proxy)
  ["cloudflare", "103.21.244.0/22"],
  ["cloudflare", "103.22.200.0/22"],
  ["cloudflare", "103.31.4.0/22"],
  ["cloudflare", "104.16.0.0/13"],
  ["cloudflare", "104.24.0.0/14"],
  ["cloudflare", "108.162.192.0/18"],
  ["cloudflare", "131.0.72.0/22"],
  ["cloudflare", "141.101.64.0/18"],
  ["cloudflare", "162.158.0.0/15"],
  ["cloudflare", "172.64.0.0/13"],
  ["cloudflare", "173.245.48.0/20"],
  ["cloudflare", "188.114.96.0/20"],
  ["cloudflare", "190.93.240.0/20"],
  ["cloudflare", "197.234.240.0/22"],
  ["cloudflare", "198.41.128.0/17"],
  ["cloudflare", "162.159.0.0/16"],
];

/** One compiled prefix: provider key, network base (uint32) and mask bits. */
interface CompiledPrefix {
  providerKey: string;
  base: number;
  bits: number;
  mask: number;
}

/** Parse a dotted-quad into a uint32, or null if it is not a valid IPv4 literal. */
function ipv4ToInt(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  let v = 0;
  for (let i = 1; i <= 4; i++) {
    const o = Number(m[i]);
    if (o > 255) return null;
    v = (v << 8) | o;
  }
  // Coerce to unsigned (>>> 0) so the high bit does not make it negative.
  return v >>> 0;
}

/** Compile the CIDR table once at module load, longest-prefix first. */
const COMPILED: CompiledPrefix[] = (() => {
  const out: CompiledPrefix[] = [];
  for (const [providerKey, cidr] of CIDRS) {
    const slash = cidr.indexOf("/");
    const bits = Number(cidr.slice(slash + 1));
    const base = ipv4ToInt(cidr.slice(0, slash));
    if (base === null || !Number.isFinite(bits) || bits < 0 || bits > 32) continue;
    // 32-bit mask for the given prefix length (bits === 0 → mask 0).
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    out.push({ providerKey, base: (base & mask) >>> 0, bits, mask });
  }
  // Longest prefix first so the most-specific match wins on overlap.
  out.sort((a, b) => b.bits - a.bits);
  return out;
})();

/** Classify a public IPv4 source to a provider key, or null if unattributable. */
export function classifyProvider(ip: string): string | null {
  const v = ipv4ToInt(ip);
  if (v === null) return null; // IPv6 / malformed → unclassified by caller
  for (const p of COMPILED) {
    if ((v & p.mask) >>> 0 === p.base) return p.providerKey;
  }
  return null;
}

// ----- shared helpers (mirror bogon.ts) -------------------------------------

/** RFC1918 / loopback / link-local / ULA / CGN — treated as non-public. */
function isPrivate(ip: string): boolean {
  return /^(0\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|22[4-9]\.|23\d\.|24\d\.|25[0-5]\.|::1|::$|fe80|fc|fd|ff)/i.test(
    ip,
  );
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

interface ProviderAcc {
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

function newProviderAcc(): ProviderAcc {
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
  providerKey: string;
  alerts: number;
  targets: Set<string>;
  severityMax: Severity;
  severe: number;
  sigCounts: Map<string, number>;
}

function tallyProvider(acc: ProviderAcc, a: StoredAlert, src: string, midMs: number): void {
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

function metaFor(key: string): { label: string; kind: ProviderKind; abuse: string; hint: string } {
  if (key === UNCLASSIFIED.key) return UNCLASSIFIED;
  const p = PROVIDERS[key];
  return p
    ? { label: p.label, kind: p.kind, abuse: p.abuse, hint: p.hint }
    : { label: key, kind: "unclassified", abuse: "", hint: "" };
}

function finalizeProvider(key: string, acc: ProviderAcc, publicTotal: number): CloudProviderEntry {
  const meta = metaFor(key);
  const actioned = acc.blocked + acc.passed;
  return {
    key,
    label: meta.label,
    kind: meta.kind,
    abuse: meta.abuse,
    hint: meta.hint,
    alerts: acc.alerts,
    share: publicTotal ? round4(acc.alerts / publicTotal) : 0,
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
  } satisfies CloudProviderEntry;
}

/** Rank: attributable (hyperscaler/vps/cdn) before unclassified, then weighted. */
function kindRank(k: ProviderKind): number {
  return k === "hyperscaler" ? 0 : k === "vps" ? 1 : k === "cdn" ? 2 : 3;
}

function rankProvider(a: CloudProviderEntry, b: CloudProviderEntry): number {
  return (
    kindRank(a.kind) - kindRank(b.kind) ||
    b.score - a.score ||
    b.alerts - a.alerts ||
    (a.label < b.label ? -1 : a.label > b.label ? 1 : 0)
  );
}

/** Rank offending sources by volume, then severity, then address. */
function rankSource(a: OffendingSource, b: OffendingSource): number {
  return (
    b.alerts - a.alerts ||
    sevRank(b.severityMax) - sevRank(a.severityMax) ||
    (a.ip < b.ip ? -1 : a.ip > b.ip ? 1 : 0)
  );
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  m: {
    publicSources: number;
    unresolved: number;
    nonPublic: number;
    attributedAlerts: number;
    distinctAttributedSources: number;
  },
  providers: CloudProviderEntry[],
  offenders: OffendingSource[],
): string[] {
  const out: string[] = [];
  if (!providers.length) return out;

  const attributable = providers.filter((p) => p.kind !== "unclassified");
  const unclassified = providers.find((p) => p.kind === "unclassified");
  const vps = attributable.filter((p) => p.kind === "vps");
  const cdn = attributable.find((p) => p.kind === "cdn");

  const attributedShare = m.publicSources ? round4(m.attributedAlerts / m.publicSources) : 0;

  if (attributable.length) {
    const top = attributable.slice(0, 4).map((p) => `${p.label} (${p.alerts})`).join(", ");
    out.push(
      `☁️ **${m.attributedAlerts} of ${m.publicSources} public-source alert(s) (${pct(attributedShare)}) trace to ` +
        `rented infrastructure** across ${attributable.length} provider(s) — ${top}. These are throwaway cloud/VPS ` +
        `instances: the address is ephemeral (blocklisting ages out), but each provider has an **abuse desk** that ` +
        `will terminate offending instances. The action is *report*, not just block.`,
    );
    const worst = attributable[0]!;
    if (worst.severe > 0) {
      out.push(
        `⚠️ The most dangerous attributed provider is **${worst.label}** — ${worst.severe} medium-or-worse alert(s) ` +
          `(worst ${worst.severityMax}) from ${worst.distinctSources} source(s), **${pct(worst.disposition.blockRate)}** ` +
          `of actioned traffic blocked. Report to \`${worst.abuse || "the provider abuse desk"}\` with the source ` +
          `IP(s), timestamps and signatures from the worklist below.`,
      );
    }
  }

  if (vps.length) {
    const vpsAlerts = vps.reduce((s, p) => s + p.alerts, 0);
    const vpsShare = m.publicSources ? round4(vpsAlerts / m.publicSources) : 0;
    out.push(
      `🧰 **Budget-VPS share: ${pct(vpsShare)}** (${vpsAlerts} alert(s) from ${vps.map((p) => p.key).join(", ")}). ` +
        `Cheap VPS providers are the workhorse of internet-wide scanning — a heavy share here is a strong "commodity ` +
        `automated-scan noise" tell rather than a targeted operator.`,
    );
  }

  const rising = attributable
    .filter((p) => p.alerts >= 5 && p.recentShare >= 0.6)
    .sort((a, b) => b.recentShare - a.recentShare)[0];
  if (rising) {
    out.push(
      `📈 **Emerging push from ${rising.label}:** ${pct(rising.recentShare)} of its ${rising.alerts} alert(s) landed ` +
        `in the recent half of the window — a building campaign from that provider, not a stale artefact.`,
    );
  }

  if (cdn) {
    out.push(
      `🛡️ **${cdn.alerts} alert(s) appear to source from ${cdn.label}** — a CDN/proxy edge, so the *visible* IP is ` +
        `the proxy, not the real origin. Do **not** blocklist it blindly (you may break legitimate proxied traffic); ` +
        `pivot on the payload / Host header / X-Forwarded-For instead, and use the provider's abuse channel.`,
    );
  }

  if (unclassified) {
    out.push(
      `🏠 **${pct(unclassified.share)}** of public-source alerts (${unclassified.alerts}) are **unclassified** — not ` +
        `in the cloud table. That is *attribution unknown*, not "no cloud": much of it is residential / ISP / ` +
        `corporate space (a possible **compromised host, open proxy or botnet node**) or a provider this offline ` +
        `table simply does not list. Pivot these through the \`netblocks\` / \`clusters\` reports.`,
    );
  }

  if (m.nonPublic > 0 || m.unresolved > 0) {
    out.push(
      `🔍 Excluded from the denominator: **${m.nonPublic}** internal/bogon-source alert(s) (see the \`bogon\` report) ` +
        `and **${m.unresolved}** with no parseable source IP (see \`coverage\`). This audit covers only the ` +
        `${m.publicSources} alert(s) with a public source address.`,
    );
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function providerTable(rows: CloudProviderEntry[]): string {
  const headers = [
    "#",
    "Provider",
    "Class",
    "Alerts",
    "Share",
    "Sources",
    "Targets",
    "Worst",
    "Severe",
    "Block rate",
    "Recent½",
    "Abuse contact",
  ];
  return mdTable(
    headers,
    rows.map((p, i) => [
      String(i + 1),
      cell(p.label),
      p.kind === "hyperscaler"
        ? "☁️ cloud"
        : p.kind === "vps"
          ? "🧰 vps"
          : p.kind === "cdn"
            ? "🛡️ cdn"
            : "🏠 other",
      String(p.alerts),
      pct(p.share),
      String(p.distinctSources),
      String(p.distinctTargets),
      cell(p.severityMax),
      String(p.severe),
      pct(p.disposition.blockRate),
      pct(p.recentShare),
      p.abuse ? cell(p.abuse) : "—",
    ]),
  );
}

function offenderTable(rows: OffendingSource[]): string {
  const headers = [
    "#",
    "Source address",
    "Provider",
    "Alerts",
    "Targets",
    "Worst",
    "Severe",
    "Blocked?",
    "Abuse contact",
    "Top signature",
  ];
  return mdTable(
    headers,
    rows.map((o, i) => [
      String(i + 1),
      cell(o.ip),
      cell(o.providerLabel),
      String(o.alerts),
      String(o.distinctTargets),
      cell(o.severityMax),
      String(o.severe),
      o.blocked ? "yes" : "no",
      o.abuse ? cell(o.abuse) : "—",
      o.topSignature ? cell(clip(o.topSignature)) : "—",
    ]),
  );
}

function renderMarkdown(m: CloudReport): string {
  const lines: string[] = [];
  lines.push(`# ☁️ SecTool Cloud / Hosting-Origin Attribution`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`,
  );
  lines.push(
    `**Method:** each alert's **public source IP** is matched offline (longest-prefix) against a curated table of ` +
      `well-known cloud / VPS / CDN provider ranges, rolled up per provider and ranked by **severity-weighted ` +
      `score** · **Public sources:** ${m.publicSources} of ${m.totalWindowAlerts} alert(s) ` +
      `(${m.nonPublic} internal/bogon, ${m.unresolved} no source — excluded)`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.providers.length) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but **none carried a parseable public ` +
          `source IP** — without a public source address there is nothing to attribute here. See the \`bogon\` ` +
          `report for internal/spoofed sources and \`coverage\` for field completeness.`,
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

  lines.push(`## Providers`);
  lines.push("");
  lines.push(providerTable(m.providers));
  lines.push("");
  lines.push(
    `**Legend:** _Share_ is of the ${m.publicSources} public-source alerts. **☁️ cloud** = hyperscaler ` +
      `(AWS/GCP/Azure/Oracle/Alibaba/Tencent); **🧰 vps** = budget VPS host (DigitalOcean/Linode/Vultr/OVH/Hetzner/` +
      `Scaleway) — the scanning workhorse; **🛡️ cdn** = CDN/proxy edge (the visible IP is *not* the real origin); ` +
      `**🏠 other** = unclassified (residential/ISP/unknown — attribution unknown, *not* "no cloud"). _Severe_ = ` +
      `medium-or-worse. _Block rate_ = blocked ÷ actioned. _Recent½_ = share of the provider's alerts in the recent ` +
      `half of the window (> 60% = emerging). Rows are ranked cloud → vps → cdn → other, then by severity-weighted ` +
      `score.`,
  );
  lines.push("");

  lines.push(`## Top offending cloud/VPS source addresses`);
  lines.push("");
  if (m.offenders.length) {
    lines.push(offenderTable(m.offenders));
    lines.push("");
    lines.push(
      `_The individual attributed (cloud/VPS/CDN) source addresses, ready to action. For a rented instance the ` +
        `effective response is to **report to the provider's abuse desk** — paste the source IP, the timestamps and ` +
        `the signatures here — rather than rely on a permanent blocklist entry that will age out and may later hit ` +
        `an innocent tenant. CDN edges are listed for completeness but should not be blocklisted blindly. ` +
        `Unclassified sources are intentionally omitted — pivot those through the \`netblocks\` / \`clusters\` reports._`,
    );
  } else {
    lines.push(
      `_No public source address in this window matched the cloud/VPS table — every attacker is either unclassified ` +
        `(residential/ISP/unknown) or internal. That does not mean "no cloud"; it means none of the curated provider ` +
        `ranges matched. Pivot the unclassified sources through the \`netblocks\` / \`clusters\` reports._`,
    );
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Source IPs are attributed purely by longest-prefix match against a **curated, ` +
      `best-effort subset** of well-known published provider IPv4 ranges — no WHOIS, no BGP, no network lookup. A ` +
      `match is a strong hint, not authoritative: a provider's newer/smaller allocations may be missing (counted as ` +
      `**unclassified**, *not* "not cloud") and broad aggregates can occasionally over-claim. **IPv4 only** — IPv6 ` +
      `sources fall to unclassified. A cloud IP is **ephemeral**: the action is usually *report to abuse*, not a ` +
      `permanent block. Volume ≠ risk: providers are ranked by severity-weighted score, attributable infra first. ` +
      `Figures are drawn from the ${m.publicSources} of ${m.totalWindowAlerts} alert(s) with a public source IP ` +
      `(${m.nonPublic} internal/bogon and ${m.unresolved} source-less were excluded). A long look-back can hit the ` +
      `store's history cap and clip the earliest alerts. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the cloud / hosting-origin attribution report from the stored alert
 * history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link CloudOptions}: `limit` for the offender table and a `nowMs`
 *              pin for deterministic tests.
 */
export function buildCloud(hours: number, opts: CloudOptions = {}): CloudReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;
  const midMs = windowStartMs + (windowEndMs - windowStartMs) / 2;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const providerAcc = new Map<string, ProviderAcc>();
  const srcAcc = new Map<string, SrcAcc>();
  const providerCache = new Map<string, string>(); // ip -> provider key (memoised)
  let publicSources = 0;
  let unresolved = 0;
  let nonPublic = 0;
  let attributedAlerts = 0;

  for (const a of windowed) {
    const src = validIp(a.srcIp);
    if (!src) {
      unresolved++;
      continue;
    }
    if (isPrivate(src)) {
      nonPublic++;
      continue;
    }
    publicSources++;

    let key = providerCache.get(src);
    if (key === undefined) {
      key = classifyProvider(src) ?? UNCLASSIFIED.key;
      providerCache.set(src, key);
    }
    const meta = metaFor(key);

    const acc = providerAcc.get(key) ?? newProviderAcc();
    if (!providerAcc.has(key)) providerAcc.set(key, acc);
    tallyProvider(acc, a, src, midMs);

    if (meta.kind !== "unclassified") {
      attributedAlerts++;
      // Enumerate the individual attributed (cloud/VPS/CDN) source addresses.
      const sa = srcAcc.get(src) ?? {
        ip: src,
        providerKey: key,
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

  const providers = [...providerAcc.entries()]
    .map(([key, acc]) => finalizeProvider(key, acc, publicSources))
    .sort(rankProvider);

  const offenders: OffendingSource[] = [...srcAcc.values()]
    .map((sa) => {
      const meta = metaFor(sa.providerKey);
      return {
        ip: sa.ip,
        providerKey: sa.providerKey,
        providerLabel: meta.label,
        abuse: meta.abuse,
        alerts: sa.alerts,
        distinctTargets: sa.targets.size,
        severityMax: sa.severityMax,
        severe: sa.severe,
        blocked: blockStore.has(sa.ip),
        topSignature: topOf(sa.sigCounts),
      } satisfies OffendingSource;
    })
    .sort(rankSource)
    .slice(0, limit);

  const distinctAttributedSources = srcAcc.size;

  const highlights = writeHighlights(
    safeHours,
    { publicSources, unresolved, nonPublic, attributedAlerts, distinctAttributedSources },
    providers,
    offenders,
  );

  const model: CloudReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    publicSources,
    unresolved,
    nonPublic,
    attributedAlerts,
    distinctAttributedSources,
    providers,
    offenders,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded cloud-attribution report. */
export function cloudFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-cloud-${stamp}.md`;
}
