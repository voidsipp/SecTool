/**
 * Coordinated-infrastructure / toolkit-cluster report — "are these dozens of
 * separate attacker IPs actually ONE operation running the same toolkit?"
 *
 * Every attacker-centric report in this project groups by a *fixed* key:
 *
 *   - campaigns.ts / persistence.ts / focus.ts roll up a **single** source IP —
 *     50 botnet members brute-forcing one box are 50 separate rows, never one.
 *   - netblock.ts groups by **CIDR adjacency** (numeric IP proximity) — it catches
 *     a noisy /24 but is *blind* to a botnet whose 50 members are scattered across
 *     40 different netblocks and three continents, which is the common shape.
 *   - cooccurrence.ts looks at which signatures co-fire **within one source**;
 *     edges.ts ranks src→dst **pairs**. Neither relates *distinct sources to each
 *     other*.
 *
 * None of them answer the correlation question that turns noise into an incident:
 *
 *   **"Which distinct external IPs are behaving *identically* — firing the same
 *    set of signatures — and therefore are probably the same actor / botnet /
 *    rented toolkit, even though they share no netblock?"**
 *
 * A behavioral fingerprint carries coordination signal that no address-based
 * grouping can:
 *
 *   1. **Shared toolkit = shared operator.** Two unrelated scanners rarely trip
 *      the *exact same* uncommon signature set. When ten IPs all fire the same
 *      handful of distinctive rules, that is one campaign wearing ten masks — the
 *      defining texture of a botnet sprayer or a rented attack service.
 *   2. **Address-independent.** Because clustering is on *behavior*, not address,
 *      it survives the evasion that defeats netblock rollups: source rotation,
 *      fast-flux, and cloud/VPS spread across many ASNs.
 *   3. **One decision per cluster.** A confirmed cluster is a single thing to
 *      block, watch, or tune against — collapsing dozens of alert rows into one
 *      operator action and one IOC set (cross-reference the IOC export).
 *
 * How clustering works (deterministic, no ML, fully auditable):
 *
 *   1. Window the stored alerts; keep external (routable, non-RFC1918) **source**
 *      IPs that fired at least `minAlerts` and produced a non-trivial fingerprint.
 *      A fingerprint is the *set* of signatures the IP tripped (falling back to
 *      categories when an IP has no named signatures).
 *   2. Down-weight ubiquitous signatures: a signature fired by almost every source
 *      (e.g. a generic policy ping) carries no attribution value, so signatures
 *      seen across more than {@link COMMON_FRACTION} of candidates are dropped from
 *      every fingerprint before comparison. This stops the whole internet from
 *      collapsing into one meaningless "cluster".
 *   3. Link two IPs when their fingerprints are **similar enough** — Jaccard
 *      overlap ≥ `minJaccard` **and** they share at least {@link MIN_SHARED}
 *      distinctive signatures (so a single coincidental shared rule never links
 *      two IPs). Single-linkage union-find then grows the transitive clusters.
 *   4. Keep clusters with ≥2 members (a lone IP is just a campaign — already
 *      covered elsewhere) and rank them by member breadth, then severity-weighted
 *      pressure, then unblocked pressure.
 *
 * Per cluster the report surfaces: member IPs and how many distinct netblocks /16
 * they span (breadth across the internet is itself a coordination tell), the
 * shared "core" signatures that bind them, total + unblocked severity-weighted
 * pressure (same info 1 · low 3 · medium 9 · high 27 · critical 81 ladder risk.ts
 * uses), distinct internal targets the cluster touched, time span, and how many
 * members are already blocked / watched / safelisted so the UI can offer the right
 * one-click action.
 *
 * Honest caveats baked into the output:
 *
 *   - **Correlation, not attribution.** A shared fingerprint means shared
 *     *behavior* — the same scanner binary or rented service — not provably the
 *     same human. Two operators running the same off-the-shelf tool will cluster.
 *   - **Heuristic thresholds.** `minJaccard`, {@link MIN_SHARED} and
 *     {@link COMMON_FRACTION} are deliberate, tunable choices; read clusters as
 *     leads, and trust a cluster more when its core signatures are *distinctive*
 *     (specific exploit/scan rules) than when they are generic.
 *   - **Single-linkage chaining.** Transitive linking can chain A–B–C even if A and
 *     C are not directly similar; the shared-core column lets you sanity-check.
 *   - **Candidate cap.** To bound the O(n²) pairing, only the top
 *     {@link MAX_CANDIDATES} sources by alert volume are clustered; any overflow is
 *     reported, never silently dropped.
 *   - **Window-bounded & store-capped.** A long look-back can hit the store's
 *     history cap and truncate the oldest alerts.
 *
 * Pure in-memory math over alertStore (plus blocklist/watchlist/safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring targets.ts, netblock.ts,
 * spread.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** One external attacker IP that is a member of a behavioral cluster. */
export interface ClusterMember {
  /** The external source IP. */
  ip: string;
  /** Alerts this IP fired in the window. */
  count: number;
  /** Distinct signatures in this IP's fingerprint (after common-signature pruning). */
  fingerprintSize: number;
  /** Worst severity this IP reached. */
  severityMax: Severity;
  /** Severity-weighted pressure attributable to this IP. */
  pressure: number;
  /** This member is on the blocklist. */
  blocklisted: boolean;
  /** This member is on the watchlist. */
  watched: boolean;
  /** This member is marked safe. */
  safe: boolean;
}

/** A group of distinct external IPs that share a behavioral fingerprint. */
export interface InfraCluster {
  /** Stable 1-based rank id within the report. */
  id: number;
  /** Member IPs, ranked by their own pressure (heaviest first). */
  members: ClusterMember[];
  /** Distinct member IPs — the "coordination breadth". */
  size: number;
  /** Distinct /16 netblocks the members span (high = spread across the internet). */
  netblocks: number;
  /** Distinct /24 netblocks the members span. */
  subnets: number;
  /** Signatures shared by EVERY member — the binding "core" of the cluster. */
  coreSignatures: string[];
  /** Distinct signatures fired by ANY member (union — the cluster's full toolkit). */
  unionSignatures: number;
  /** Total alerts across all members. */
  totalAlerts: number;
  /** Distinct internal (RFC1918) hosts this cluster touched. */
  internalTargets: number;
  /** Worst severity any member reached. */
  severityMax: Severity;
  /** Alerts at medium severity or worse, across the cluster. */
  severe: number;
  /** Severity-weighted pressure summed across the cluster. */
  pressure: number;
  /** Of {@link pressure}, the part the gateway let through (passed + unknown). */
  unblockedPressure: number;
  /** unblockedPressure / pressure, 0..1 (4dp). */
  exposure: number;
  /** Epoch ms of the cluster's first alert. */
  firstMs: number;
  /** Epoch ms of the cluster's most recent alert. */
  lastMs: number;
  /** Members already on the blocklist. */
  blockedMembers: number;
  /** Members on the watchlist. */
  watchedMembers: number;
  /** Members marked safe. */
  safeMembers: number;
}

export interface ClusterReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Distinct external source IPs seen this window. */
  distinctSources: number;
  /** Of those, IPs that met the {@link ClusterOptions.minAlerts} / fingerprint bar. */
  candidateSources: number;
  /** Candidates dropped by the {@link MAX_CANDIDATES} cap (reported, not hidden). */
  droppedToCap: number;
  /** Distinct signatures pruned as too-common to carry attribution value. */
  commonSignaturesPruned: number;
  /** Clusters found (groups of ≥2 behaviorally-similar IPs). */
  clusterCount: number;
  /** Candidate IPs that landed in a multi-member cluster. */
  clusteredSources: number;
  /** The clustering knobs used, echoed for reproducibility. */
  params: { minJaccard: number; minShared: number; minAlerts: number; commonFraction: number };
  /** Clusters ranked worst-first, truncated to the limit. */
  clusters: InfraCluster[];
  /** True when {@link clusters} was truncated by the limit. */
  truncated: boolean;
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface ClusterOptions {
  /** Max clusters to list (clamped to [1, 100]). */
  limit?: number;
  /** Min alerts an IP must fire to be a clustering candidate (clamped to [1, 1000]). */
  minAlerts?: number;
  /** Min Jaccard overlap to link two IPs (clamped to [0.1, 1]). */
  minJaccard?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 15;
const DEFAULT_MIN_ALERTS = 2;
const DEFAULT_MIN_JACCARD = 0.5;
const MS_PER_HOUR = 3_600_000;
/** Min distinctive signatures two IPs must share to be linked. */
const MIN_SHARED = 2;
/** Signatures fired by more than this fraction of candidates are non-distinctive. */
const COMMON_FRACTION = 0.6;
/** Below this many candidates, common-signature pruning is not run (too small to be meaningful). */
const COMMON_PRUNE_FLOOR = 10;
/** Hard cap on clustered candidates to bound the O(n²) pairing. */
const MAX_CANDIDATES = 600;
/** Max member IPs rendered per cluster in the Markdown table. */
const MAX_MEMBERS_SHOWN = 12;
/** Max core signatures rendered per cluster. */
const MAX_CORE_SHOWN = 6;

// ----- formatting helpers (mirror targets.ts / netblock.ts / spread.ts) ------

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** A compact relative-age label like "3h" / "2d" — mirrors spread.ts. */
function fmtAge(ms: number, nowMs: number): string {
  const sec = Math.max(0, Math.round((nowMs - ms) / 1000));
  if (sec < 90) return `${sec}s`;
  const min = Math.round(sec / 60);
  if (min < 90) return `${min}m`;
  const hr = Math.round(min / 60);
  if (hr < 48) return `${hr}h`;
  return `${Math.round(hr / 24)}d`;
}

/** A 0..1 fraction as a whole-number percent string, e.g. 0.823 -> "82%". */
function pct(frac: number): string {
  return `${Math.round(frac * 100)}%`;
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
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

/** Truncate a long free-form string for a table cell. */
function clip(s: string, max = 44): string {
  const t = s.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

// ----- classifiers -----------------------------------------------------------

/** RFC1918 / loopback / link-local / ULA — mirrors targets.ts / spread.ts. */
function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
}

/** A routable, external IPv4/IPv6 source (the attacker side we cluster). */
function isExternal(ip: string | undefined): ip is string {
  return !!ip && isIP(ip) > 0 && !isPrivate(ip);
}

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

function asSeverity(s: string | undefined): Severity {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? "info" : (s as Severity);
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? asSeverity(b) : a;
}

function isSevere(s: string | undefined): boolean {
  return sevRank(s) >= 2; // medium or worse
}

/** The /16 (first two octets) of an IPv4, or the IP itself for IPv6. */
function net16(ip: string): string {
  const m = ip.match(/^(\d+)\.(\d+)\./);
  return m ? `${m[1]}.${m[2]}` : ip;
}

/** The /24 (first three octets) of an IPv4, or the IP itself for IPv6. */
function net24(ip: string): string {
  const m = ip.match(/^(\d+)\.(\d+)\.(\d+)\./);
  return m ? `${m[1]}.${m[2]}.${m[3]}` : ip;
}

// ----- per-source aggregation ------------------------------------------------

interface SourceAcc {
  ip: string;
  count: number;
  /** Signatures (or category fallback) this IP fired — the raw fingerprint. */
  fingerprint: Set<string>;
  severityMax: Severity;
  severe: number;
  pressure: number;
  unblockedPressure: number;
  internalTargets: Set<string>;
  firstMs: number;
  lastMs: number;
}

function newSourceAcc(ip: string, time: number): SourceAcc {
  return {
    ip,
    count: 0,
    fingerprint: new Set(),
    severityMax: "info",
    severe: 0,
    pressure: 0,
    unblockedPressure: 0,
    internalTargets: new Set(),
    firstMs: time,
    lastMs: time,
  };
}

// ----- union-find (single-linkage clustering) --------------------------------

class UnionFind {
  #parent: number[];
  constructor(n: number) {
    this.#parent = Array.from({ length: n }, (_, i) => i);
  }
  find(x: number): number {
    let r = x;
    while (this.#parent[r] !== r) r = this.#parent[r]!;
    // Path compression for near-linear amortized cost.
    while (this.#parent[x] !== r) {
      const next = this.#parent[x]!;
      this.#parent[x] = r;
      x = next;
    }
    return r;
  }
  union(a: number, b: number): void {
    const ra = this.find(a);
    const rb = this.find(b);
    if (ra !== rb) this.#parent[Math.max(ra, rb)] = Math.min(ra, rb);
  }
}

/** Jaccard overlap of two sets: |A∩B| / |A∪B|, plus the raw intersection size. */
function jaccard(a: Set<string>, b: Set<string>): { sim: number; shared: number } {
  // Iterate the smaller set for the intersection.
  const [small, large] = a.size <= b.size ? [a, b] : [b, a];
  let inter = 0;
  for (const v of small) if (large.has(v)) inter++;
  const union = a.size + b.size - inter;
  return { sim: union ? inter / union : 0, shared: inter };
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(
  m: Omit<ClusterReport, "highlights" | "markdown">,
  nowMs: number,
): string[] {
  const out: string[] = [];
  if (!m.totalWindowAlerts) return out;

  if (!m.clusterCount) {
    out.push(
      `🧩 No coordinated clusters found among **${m.candidateSources} candidate source(s)** over the last ${m.hours}h ` +
        `(IPs firing ≥${m.params.minAlerts} alert(s) with a usable fingerprint). Every attacker behaved distinctly — ` +
        `the alert volume reads as independent/background activity, not one toolkit sprayed across many IPs. ` +
        `(Thresholds: Jaccard ≥ ${m.params.minJaccard}, ≥${m.params.minShared} shared signatures.)`,
    );
    return out;
  }

  out.push(
    `🧩 Found **${m.clusterCount} coordinated cluster(s)** binding **${m.clusteredSources} distinct attacker IP(s)** ` +
      `that fire the *same* signature set — likely one toolkit / botnet / rented service each, even where the members ` +
      `share no netblock. This is correlation address-based reports (campaigns, netblocks) cannot see.`,
  );

  const worst = m.clusters[0];
  if (worst) {
    out.push(
      `🚨 Largest cluster **#${worst.id}** ties **${worst.size} IP(s)** across **${worst.netblocks} distinct /16 ` +
        `netblock(s)**, peak ${worst.severityMax}, ${pct(worst.exposure)} of its pressure unblocked, last seen ` +
        `${fmtAge(worst.lastMs, nowMs)} ago. Core signature(s): ${worst.coreSignatures.slice(0, 3).map((s) => `"${clip(s, 36)}"`).join(", ") || "—"}. ` +
        (worst.netblocks >= 3
          ? `Spread across many netblocks = source rotation / botnet — block the whole cluster as one IOC set, not IP-by-IP.`
          : `Block/watch the cluster as a unit.`),
    );
  }

  // Distributed clusters: many members across many netblocks = the botnet shape.
  const distributed = m.clusters.filter((c) => c.size >= 3 && c.netblocks >= 3);
  if (distributed.length) {
    out.push(
      `🌐 **${distributed.length} cluster(s) are spread across ≥3 netblocks** (source rotation / fast-flux texture): ` +
        distributed
          .slice(0, 4)
          .map((c) => `#${c.id} (${c.size} IPs / ${c.netblocks} nets)`)
          .join(", ") +
        `. Address-based blocking plays whack-a-mole here; cluster-level blocking does not.`,
    );
  }

  // Clusters with unblocked exposure are the ones to action first.
  const exposed = m.clusters.filter((c) => c.unblockedPressure > 0);
  if (exposed.length) {
    out.push(
      `⚠️ **${exposed.length} cluster(s) have unblocked pressure** — coordinated activity the gateway did not fully ` +
        `stop. Each is a single block/watch decision covering all its members; start with #${exposed[0]!.id}.`,
    );
  } else {
    out.push(
      `✅ Every cluster's pressure was fully blocked this window — the coordinated activity was mitigated. The clusters ` +
        `are still worth a watchlist entry so a return from fresh IPs is caught early.`,
    );
  }

  // Partially-actioned clusters: some members blocked, some not — a coverage gap.
  const partial = m.clusters.filter((c) => c.blockedMembers > 0 && c.blockedMembers < c.size);
  if (partial.length) {
    out.push(
      `🧱 **${partial.length} cluster(s) are only partially blocked** — some members are on the blocklist but their ` +
        `behavioral twins are not. These are exactly the IPs to add: same toolkit, not yet stopped ` +
        `(e.g. #${partial[0]!.id}: ${partial[0]!.blockedMembers}/${partial[0]!.size} blocked).`,
    );
  }

  return out;
}

// ----- markdown --------------------------------------------------------------

function clusterTable(c: InfraCluster): string {
  return mdTable(
    ["#", "Member IP", "Alerts", "Sigs", "Pressure", "Peak sev", "Flags"],
    c.members.slice(0, MAX_MEMBERS_SHOWN).map((mem, i) => {
      const flags =
        (mem.blocklisted ? "⛔" : "") + (mem.watched ? "👁" : "") + (mem.safe ? "✅" : "");
      return [
        String(i + 1),
        cell(mem.ip),
        String(mem.count),
        String(mem.fingerprintSize),
        String(mem.pressure),
        cell(mem.severityMax),
        flags || "—",
      ];
    }),
  );
}

function renderClusterDetail(c: InfraCluster, nowMs: number): string {
  const lines: string[] = [];
  lines.push(
    `### Cluster #${c.id} — ${c.size} IP(s) · ${c.netblocks} /16 · peak ${c.severityMax}`,
  );
  lines.push("");
  lines.push(
    `- **Pressure:** ${c.pressure} (severity-weighted) · **unblocked:** ${c.unblockedPressure} (${pct(c.exposure)})`,
  );
  lines.push(
    `- **Spread:** ${c.size} IP(s) across ${c.netblocks} /16 and ${c.subnets} /24 netblock(s) · ` +
      `**alerts:** ${c.totalAlerts} · **severe (≥medium):** ${c.severe}`,
  );
  lines.push(
    `- **Targets:** ${c.internalTargets} internal host(s) touched · ` +
      `**active:** ${fmtAge(c.firstMs, nowMs)} → ${fmtAge(c.lastMs, nowMs)} ago`,
  );
  lines.push(
    `- **Disposition:** ${c.blockedMembers}/${c.size} member(s) already blocked` +
      (c.watchedMembers ? ` · ${c.watchedMembers} watched` : "") +
      (c.safeMembers ? ` · ${c.safeMembers} safelisted` : ""),
  );
  lines.push(
    `- **Core signatures (shared by all ${c.size}):** ` +
      (c.coreSignatures.length
        ? c.coreSignatures.slice(0, MAX_CORE_SHOWN).map((s) => `\`${clip(s, 60)}\``).join(" · ") +
          (c.coreSignatures.length > MAX_CORE_SHOWN ? ` _(+${c.coreSignatures.length - MAX_CORE_SHOWN} more)_` : "")
        : "_(linked transitively — no single signature common to every member; see members below)_"),
  );
  lines.push(`  (full toolkit union: ${c.unionSignatures} distinct signature(s))`);
  lines.push("");
  lines.push(clusterTable(c));
  if (c.size > MAX_MEMBERS_SHOWN) {
    lines.push("");
    lines.push(`_…${c.size - MAX_MEMBERS_SHOWN} more member(s) not shown._`);
  }
  lines.push("");
  return lines.join("\n");
}

function renderMarkdown(m: ClusterReport, nowMs: number): string {
  const lines: string[] = [];
  lines.push(`# 🧩 SecTool Coordinated-Infrastructure / Toolkit-Cluster Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`,
  );
  lines.push(
    `**Method:** external attacker IPs clustered by **shared signature fingerprint** ` +
      `(single-linkage union-find: Jaccard ≥ ${m.params.minJaccard} **and** ≥${m.params.minShared} shared distinctive ` +
      `signatures). Pressure = Σ severity weight (info 1 · low 3 · medium 9 · high 27 · critical 81). ` +
      `**Window alerts:** ${m.totalWindowAlerts}`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.totalWindowAlerts) {
    lines.push(
      `No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to cluster.`,
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  lines.push(`| Metric | Value |`);
  lines.push(`| --- | --- |`);
  lines.push(`| Distinct external sources | ${m.distinctSources.toLocaleString("en-US")} |`);
  lines.push(`| Clustering candidates (≥${m.params.minAlerts} alerts + fingerprint) | ${m.candidateSources.toLocaleString("en-US")} |`);
  lines.push(`| Common signatures pruned | ${m.commonSignaturesPruned.toLocaleString("en-US")} |`);
  lines.push(`| Coordinated clusters found | ${m.clusterCount.toLocaleString("en-US")} |`);
  lines.push(`| IPs in a cluster | ${m.clusteredSources.toLocaleString("en-US")} |`);
  if (m.droppedToCap) {
    lines.push(`| Candidates over cap (not clustered) | ${m.droppedToCap.toLocaleString("en-US")} |`);
  }
  lines.push("");

  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Clusters`);
  lines.push("");
  if (!m.clusters.length) {
    lines.push(
      `_No group of ≥2 behaviorally-similar attacker IPs was found at the current thresholds ` +
        `(Jaccard ≥ ${m.params.minJaccard}, ≥${m.params.minShared} shared signatures). ` +
        `Lower \`minJaccard\` to cast a wider net, or read this as genuinely uncoordinated background activity._`,
    );
  } else {
    lines.push(
      `Each cluster is a set of distinct external IPs that fire the **same** signatures — probably one toolkit / ` +
        `botnet / rented service. _Spread_ across many netblocks is itself a coordination tell. Flags: ` +
        `⛔ blocklisted · 👁 watchlisted · ✅ safelisted. Block / watch a cluster as **one unit**.`,
    );
    lines.push("");
    for (const c of m.clusters) lines.push(renderClusterDetail(c, nowMs));
    if (m.truncated) {
      lines.push(`_…more clusters not shown (raise \`limit\`)._`);
      lines.push("");
    }
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from stored **IPS-alert** signatures. Clustering is **correlation, not ` +
      `attribution**: a shared fingerprint means shared *behavior* (the same scanner binary or rented service), not ` +
      `provably the same human — two operators running the same off-the-shelf tool will cluster. Thresholds ` +
      `(Jaccard ≥ ${m.params.minJaccard}, ≥${m.params.minShared} shared, common-signature cut ${pct(m.params.commonFraction)}) are ` +
      `deliberate, tunable heuristics; trust a cluster more when its core signatures are *distinctive*. Single-linkage ` +
      `can chain A–B–C without A–C being directly similar (the shared-core column lets you check). To bound the O(n²) ` +
      `pairing only the top ${MAX_CANDIDATES} sources by volume are clustered. A long look-back can hit the store's ` +
      `history cap. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

// ----- assembly --------------------------------------------------------------

/** Build a finished {@link InfraCluster} from its member accumulators. */
function finishCluster(id: number, members: SourceAcc[]): InfraCluster {
  // Members ranked by their own pressure (heaviest attacker first), IP tie-break.
  const ranked = [...members].sort(
    (a, b) =>
      b.pressure - a.pressure ||
      b.count - a.count ||
      (a.ip < b.ip ? -1 : a.ip > b.ip ? 1 : 0),
  );

  // Core = signatures present in EVERY member's fingerprint (the binding set).
  const union = new Set<string>();
  let core: Set<string> | null = null;
  const net16s = new Set<string>();
  const net24s = new Set<string>();
  const internalTargets = new Set<string>();
  let totalAlerts = 0;
  let pressure = 0;
  let unblockedPressure = 0;
  let severe = 0;
  let severityMax: Severity = "info";
  let firstMs = Infinity;
  let lastMs = -Infinity;
  let blockedMembers = 0;
  let watchedMembers = 0;
  let safeMembers = 0;

  for (const mem of ranked) {
    for (const s of mem.fingerprint) union.add(s);
    core = core === null ? new Set(mem.fingerprint) : intersect(core, mem.fingerprint);
    net16s.add(net16(mem.ip));
    net24s.add(net24(mem.ip));
    for (const t of mem.internalTargets) internalTargets.add(t);
    totalAlerts += mem.count;
    pressure += mem.pressure;
    unblockedPressure += mem.unblockedPressure;
    severe += mem.severe;
    severityMax = sevRank(mem.severityMax) > sevRank(severityMax) ? mem.severityMax : severityMax;
    if (mem.firstMs < firstMs) firstMs = mem.firstMs;
    if (mem.lastMs > lastMs) lastMs = mem.lastMs;
    if (blockStore.has(mem.ip)) blockedMembers++;
    if (watchStore.has(mem.ip)) watchedMembers++;
    if (safeStore.has(mem.ip)) safeMembers++;
  }

  const coreSorted = [...(core ?? new Set<string>())].sort();

  return {
    id,
    members: ranked.map((mem) => ({
      ip: mem.ip,
      count: mem.count,
      fingerprintSize: mem.fingerprint.size,
      severityMax: mem.severityMax,
      pressure: round1(mem.pressure),
      blocklisted: blockStore.has(mem.ip),
      watched: watchStore.has(mem.ip),
      safe: safeStore.has(mem.ip),
    })),
    size: ranked.length,
    netblocks: net16s.size,
    subnets: net24s.size,
    coreSignatures: coreSorted,
    unionSignatures: union.size,
    totalAlerts,
    internalTargets: internalTargets.size,
    severityMax,
    severe,
    pressure: round1(pressure),
    unblockedPressure: round1(unblockedPressure),
    exposure: pressure ? round4(unblockedPressure / pressure) : 0,
    firstMs: Number.isFinite(firstMs) ? firstMs : 0,
    lastMs: Number.isFinite(lastMs) ? lastMs : 0,
    blockedMembers,
    watchedMembers,
    safeMembers,
  } satisfies InfraCluster;
}

/** Set intersection A∩B (returns a new set). */
function intersect(a: Set<string>, b: Set<string>): Set<string> {
  const out = new Set<string>();
  const [small, large] = a.size <= b.size ? [a, b] : [b, a];
  for (const v of small) if (large.has(v)) out.add(v);
  return out;
}

/**
 * Build the coordinated-infrastructure / toolkit-cluster report from the stored
 * alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link ClusterOptions}: `limit`, `minAlerts`, `minJaccard`, `nowMs`.
 */
export function buildClusters(hours: number, opts: ClusterOptions = {}): ClusterReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(100, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minAlerts = Math.max(1, Math.min(1000, Math.floor(opts.minAlerts ?? DEFAULT_MIN_ALERTS)));
  const minJaccard = Math.max(0.1, Math.min(1, opts.minJaccard ?? DEFAULT_MIN_JACCARD));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  // 1. Aggregate per external source IP.
  const sources = new Map<string, SourceAcc>();
  for (const a of windowed) {
    if (!isExternal(a.srcIp)) continue;
    let acc = sources.get(a.srcIp);
    if (!acc) {
      acc = newSourceAcc(a.srcIp, a.time);
      sources.set(a.srcIp, acc);
    }
    acc.count++;
    const severity = asSeverity(a.severity);
    const weight = SEVERITY_WEIGHT[severity];
    acc.pressure += weight;
    if (classifyDisposition(a.action) !== "blocked") acc.unblockedPressure += weight;
    acc.severityMax = maxSeverity(acc.severityMax, severity);
    if (isSevere(severity)) acc.severe++;
    if (a.time < acc.firstMs) acc.firstMs = a.time;
    if (a.time > acc.lastMs) acc.lastMs = a.time;
    // Fingerprint token: prefer the named signature, fall back to category so an
    // IP with only category-level alerts still gets a (coarser) fingerprint.
    const sig = a.signature?.trim() || a.category?.trim();
    if (sig) acc.fingerprint.add(sig);
    if (a.dstIp && isIP(a.dstIp) > 0 && isPrivate(a.dstIp)) acc.internalTargets.add(a.dstIp);
  }

  const distinctSources = sources.size;

  // 2. Keep IPs that cleared the alert bar and produced a usable fingerprint,
  //    capped (heaviest-first) to bound the O(n²) pairing.
  const allCandidates = [...sources.values()]
    .filter((s) => s.count >= minAlerts && s.fingerprint.size > 0)
    .sort((a, b) => b.count - a.count || (a.ip < b.ip ? -1 : a.ip > b.ip ? 1 : 0));
  const droppedToCap = Math.max(0, allCandidates.length - MAX_CANDIDATES);
  const candidates = allCandidates.slice(0, MAX_CANDIDATES);

  // 3. Prune ubiquitous signatures (no attribution value) from every fingerprint.
  //    Only meaningful on a sizable population — on a handful of candidates a
  //    "common" signature is just as likely to be the genuine binding core of one
  //    real cluster, so skip pruning entirely below the floor.
  const sigDocFreq = new Map<string, number>();
  for (const c of candidates) for (const s of c.fingerprint) sigDocFreq.set(s, (sigDocFreq.get(s) ?? 0) + 1);
  const commonCut = Math.max(2, Math.ceil(candidates.length * COMMON_FRACTION));
  let commonSignaturesPruned = 0;
  if (candidates.length >= COMMON_PRUNE_FLOOR) {
    for (const [s, df] of sigDocFreq) {
      if (df > commonCut) {
        commonSignaturesPruned++;
        for (const c of candidates) c.fingerprint.delete(s);
      }
    }
  }
  // After pruning, an IP can lose its whole fingerprint — it can no longer be
  // distinctively matched, so it cannot anchor a cluster.
  const clusterable = candidates.filter((c) => c.fingerprint.size > 0);

  // 4. Single-linkage union-find: link IPs whose fingerprints are similar enough.
  const uf = new UnionFind(clusterable.length);
  for (let i = 0; i < clusterable.length; i++) {
    const fi = clusterable[i]!.fingerprint;
    for (let j = i + 1; j < clusterable.length; j++) {
      const { sim, shared } = jaccard(fi, clusterable[j]!.fingerprint);
      if (shared >= MIN_SHARED && sim >= minJaccard) uf.union(i, j);
    }
  }

  // 5. Collect components of size ≥2.
  const groups = new Map<number, SourceAcc[]>();
  for (let i = 0; i < clusterable.length; i++) {
    const root = uf.find(i);
    let g = groups.get(root);
    if (!g) {
      g = [];
      groups.set(root, g);
    }
    g.push(clusterable[i]!);
  }
  const rawClusters = [...groups.values()].filter((g) => g.length >= 2);

  // Rank clusters worst-first: more members, then more pressure / unblocked.
  const built = rawClusters
    .map((g, i) => finishCluster(i + 1, g))
    .sort(
      (a, b) =>
        b.size - a.size ||
        b.pressure - a.pressure ||
        b.unblockedPressure - a.unblockedPressure ||
        b.netblocks - a.netblocks ||
        (a.members[0]!.ip < b.members[0]!.ip ? -1 : 1),
    )
    // Re-stamp ids to match the final ranked order (1-based, stable).
    .map((c, i) => ({ ...c, id: i + 1 }));

  const clusteredSources = built.reduce((sum, c) => sum + c.size, 0);

  const base: Omit<ClusterReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    distinctSources,
    candidateSources: candidates.length,
    droppedToCap,
    commonSignaturesPruned,
    clusterCount: built.length,
    clusteredSources,
    params: { minJaccard, minShared: MIN_SHARED, minAlerts, commonFraction: COMMON_FRACTION },
    clusters: built.slice(0, limit),
    truncated: built.length > limit,
  };

  const highlights = writeHighlights(base, windowEndMs);
  const model: ClusterReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model, windowEndMs);
  return model;
}

/** A filesystem-safe filename for a downloaded cluster report. */
export function clustersFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-clusters-${stamp}.md`;
}
