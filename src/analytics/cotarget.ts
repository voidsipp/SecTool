/**
 * Co-targeting / shared-attacker affinity report — "**which of my own hosts are
 * being hunted by the *same* adversaries — and so, if one falls, which is the
 * attacker most likely to reach next?**"
 *
 * Every target-side report in this project looks at one asset at a time, never at
 * the *relationship* between two assets through the attackers they share:
 *
 *   - **assets.ts / targets.ts** rank each internal host by how *hard* it is hit
 *     (volume, worst severity). They answer "what's on fire", never "what burns
 *     *together*".
 *   - **edges.ts** draws the source→target topology and lateral-movement graph —
 *     it relates a *source* to a *target*, not two *targets* to each other.
 *   - **clusters.ts / netblock.ts** group *sources* by shared infrastructure; this
 *     report is their mirror image — it groups *targets* by shared attackers.
 *   - **spread.ts / scan.ts** measure a single source's fan-out across hosts; they
 *     never invert the question to ask which host-pairs that fan-out *binds*.
 *
 * The overlap in two assets' attacker sets is a sharp, under-used defensive
 * signal. When the same selective adversaries keep appearing against host A *and*
 * host B, the two share a fate: they are in the same exposure class (same service
 * surface, same trust zone, same campaign target list). That is precisely the
 * blast-radius an analyst needs before an incident — if A is compromised, the
 * actors already probing B are the ones to watch, and a segmentation boundary
 * between high-overlap hosts buys the most containment per rule.
 *
 * For every pair of internal assets over the window this report computes:
 *
 *   - **Shared attackers** — distinct *selective* sources that hit *both* assets.
 *   - **Jaccard affinity** — `sharedAttackers / unionAttackers`, 0..1, the
 *     overlap normalised by how broadly each asset is attacked so a single shared
 *     scanner can't make a heavily-probed pair look intimate.
 *   - the **top shared source** (the attacker most active against the two
 *     combined), the **worst severity** carried by the shared activity, and each
 *     asset's individual attacker count.
 *
 * A companion **per-asset** roll-up answers the hub question the pair table can't:
 * which single asset shares attackers with the *most* other hosts — the host
 * whose compromise (or whose attacker, if pivoted) puts the widest blast-radius
 * of peers within reach.
 *
 * **Background-scanner dampening.** A ubiquitous internet scanner that sprays the
 * *whole* estate would tie every asset to every other and drown the signal (and
 * blow up the pair math combinatorially). A source is therefore treated as a
 * *broad scanner* and excluded from affinity once it has touched more than a
 * threshold share of all assets (default: half, capped at an absolute fan-out
 * bound); only *selective* adversaries — the ones picking specific hosts — drive
 * the overlap. The count of excluded scanners is always reported so the dampening
 * is visible, never silent.
 *
 * Honest caveats baked into the output:
 *
 *   - **Affinity ≠ causation.** Two assets sharing attackers means they are in the
 *     same exposure class, not that one leads to the other; the ranking directs
 *     attention, it does not prove a path.
 *   - **Scanner cut-off is a heuristic.** The broad-scanner threshold is tunable;
 *     a borderline source can sit either side of it. The excluded-scanner count
 *     and the raw per-asset attacker totals are shown so the call can be
 *     second-guessed.
 *   - **Alerts, not full flows.** SecTool stores IPS *detections*; a source that
 *     touched a host without tripping a rule is invisible, so every overlap is a
 *     lower bound.
 *   - **Internal assets only.** Affinity is computed over RFC1918 destination
 *     hosts (your estate). Outbound / external destinations are out of scope here
 *     — direction.ts and edges.ts cover those.
 *   - **Window-bounded & store-capped.** A long look-back can hit the store's
 *     history cap and undercount overlap.
 *
 * Pure in-memory math over alertStore (plus watchlist / safelist membership flags
 * on the assets) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring report.ts, scan.ts,
 * spread.ts, clusters.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Affinity metrics for one ordered pair of internal assets (A < B). */
export interface CoTargetPair {
  /** First asset IP (lexically smaller, for a stable key). */
  assetA: string;
  /** Second asset IP. */
  assetB: string;
  /** Distinct *selective* sources that hit both assets (broad scanners excluded). */
  sharedAttackers: number;
  /** Distinct selective sources that hit *either* asset (the Jaccard denominator). */
  unionAttackers: number;
  /** sharedAttackers / unionAttackers, 0..1 (4dp) — the affinity score. */
  jaccard: number;
  /** The shared source most active against the two assets combined, if any. */
  topSharedSource?: string;
  /** Combined alerts the {@link topSharedSource} aimed at the two assets. */
  topSharedAlerts: number;
  /** Worst severity carried by the shared activity across either asset. */
  severityMax: Severity;
}

/** Per-asset affinity roll-up — how connected one host is to the rest. */
export interface CoTargetAsset {
  /** The internal asset IP. */
  ip: string;
  /** Distinct sources that hit this asset (raw, incl. broad scanners). */
  distinctAttackers: number;
  /** Distinct *selective* sources that hit this asset (broad scanners excluded). */
  selectiveAttackers: number;
  /** Total alerts aimed at this asset in the window. */
  alerts: number;
  /** Distinct other assets it shares ≥ minShared selective attackers with. */
  peers: number;
  /** The peer it shares the most attackers with, if any. */
  topPeer?: string;
  /** Shared-attacker count with {@link topPeer}. */
  topPeerShared: number;
  /** Worst severity seen against this asset. */
  severityMax: Severity;
  /** The asset is on the watchlist. */
  watched: boolean;
  /** The asset is marked safe. */
  safe: boolean;
}

export interface CoTargetReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts with an internal destination and a valid source (analysable). */
  inboundAlerts: number;
  /** Distinct internal assets attacked. */
  distinctAssets: number;
  /** Distinct sources seen attacking those assets. */
  distinctAttackers: number;
  /** Asset fan-out above which a source is treated as a broad scanner and excluded. */
  scannerThreshold: number;
  /** Sources excluded from affinity as broad scanners. */
  broadScanners: number;
  /** Minimum shared attackers a pair needs to be listed / counted as a peer link. */
  minShared: number;
  /** Asset pairs by shared-attacker affinity, strongest first. */
  pairs: CoTargetPair[];
  /** Per-asset roll-up, most-connected first. */
  assets: CoTargetAsset[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface CoTargetOptions {
  /** Max rows in the pair table (clamped to [1, 200]). */
  limit?: number;
  /** Max rows in the per-asset table (clamped to [1, 200]). */
  assetLimit?: number;
  /** Minimum shared attackers for a pair to be listed / counted (≥1). */
  minShared?: number;
  /** Minimum alerts an asset needs before it is analysed (drops one-off noise). */
  minAlerts?: number;
  /** Share of all assets above which a source is a broad scanner (0..1). */
  scannerFraction?: number;
  /** Absolute fan-out cap on the broad-scanner threshold (combinatorial safety). */
  maxFanout?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const DEFAULT_ASSET_LIMIT = 20;
const DEFAULT_MIN_SHARED = 2;
const DEFAULT_MIN_ALERTS = 1;
const DEFAULT_SCANNER_FRACTION = 0.5;
const DEFAULT_MAX_FANOUT = 60;
const MS_PER_HOUR = 3_600_000;

// ----- classifiers / helpers (mirror scan.ts) -------------------------------

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

/** A stable, order-independent key for an unordered asset pair. */
function pairKey(a: string, b: string): string {
  return a < b ? `${a} ${b}` : `${b} ${a}`;
}

// ----- aggregation ----------------------------------------------------------

/** What one source did against one asset. */
interface Touch {
  count: number;
  sevMax: Severity;
}

/** Mutable per-pair accumulator. */
interface PairAcc {
  assetA: string;
  assetB: string;
  shared: number;
  sevMax: Severity;
  topSource?: string;
  topAlerts: number;
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  m: {
    distinctAssets: number;
    distinctAttackers: number;
    broadScanners: number;
    inboundAlerts: number;
  },
  pairs: CoTargetPair[],
  assets: CoTargetAsset[],
): string[] {
  const out: string[] = [];
  if (!m.distinctAssets) return out;

  // Scope line — how much of the estate is in play and how it was dampened.
  out.push(
    `🕸️ Over the last ${hours}h, **${m.distinctAssets} internal asset(s)** were attacked by ` +
      `**${m.distinctAttackers} source(s)**` +
      (m.broadScanners
        ? ` (**${m.broadScanners}** broad scanner(s) excluded from affinity so the overlap reflects *selective* adversaries).`
        : `.`),
  );

  if (!pairs.length) {
    out.push(
      `🔍 No two assets share **≥${DEFAULT_MIN_SHARED}** selective attacker(s) — your attacked hosts are being hunted ` +
        `independently this window (or the shared traffic is all broad-scanner background). Each target's adversary is ` +
        `dedicated to it; there is no obvious shared-fate cluster to segment.`,
    );
    return out;
  }

  // The tightest-bound pair — the strongest shared-fate signal.
  const lead = pairs[0]!;
  out.push(
    `🔗 Strongest co-targeting: \`${lead.assetA}\` ↔ \`${lead.assetB}\` share **${lead.sharedAttackers} selective ` +
      `attacker(s)** (Jaccard ${pct(lead.jaccard)}, worst sev *${lead.severityMax}*). They sit in the same exposure ` +
      `class — a segmentation boundary between them, or watching one when the other is hit, buys the most containment.`,
  );

  // High-affinity pairs — normalised overlap, not just raw count.
  const tight = pairs.filter((p) => p.jaccard >= 0.5 && p.sharedAttackers >= DEFAULT_MIN_SHARED);
  if (tight.length > 1) {
    out.push(
      `🎯 **${tight.length} pair(s)** overlap ≥50% of their attackers — near-identical adversary sets. Treat each ` +
        `such pair as one unit for monitoring and response: what reaches one is almost certainly coming for the other.`,
    );
  }

  // The hub asset — widest blast-radius of shared-fate peers.
  const hub = assets[0];
  if (hub && hub.peers >= 2) {
    out.push(
      `📡 \`${hub.ip}\` is the most *connected* asset — it shares selective attackers with **${hub.peers} other ` +
        `host(s)**` +
        (hub.topPeer ? ` (tightest with \`${hub.topPeer}\`, ${hub.topPeerShared} shared)` : "") +
        `. If it is compromised, those peers are the attacker's most likely next reach — prioritise it for hardening ` +
        `and monitoring.`,
    );
  }

  // A shared attacker hammering a pair — a concrete actor to action now.
  const actor = pairs.find((p) => p.topSharedSource && p.topSharedAlerts >= 3);
  if (actor) {
    out.push(
      `⚠️ \`${actor.topSharedSource}\` is hitting **both** \`${actor.assetA}\` and \`${actor.assetB}\` ` +
        `(${actor.topSharedAlerts} combined alert(s)) — a single source working a host cluster. Blocking it defends ` +
        `the whole cluster at once; investigate whether it has footholds on either.`,
    );
  }

  // Isolated assets — a dedicated adversary, a different kind of concern.
  const lonely = assets.filter((a) => a.selectiveAttackers > 0 && a.peers === 0);
  if (lonely.length) {
    out.push(
      `🧭 **${lonely.length} asset(s)** share *no* selective attacker with any peer (e.g. \`${lonely[0]!.ip}\`) — ` +
        `whoever is after them picked them specifically, not as part of a sweep. Targeted interest in a single host ` +
        `can be the more deliberate threat.`,
    );
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function pairTable(rows: CoTargetPair[]): string {
  return mdTable(
    ["#", "Asset A", "Asset B", "Shared", "Union", "Affinity", "Top shared source", "Worst sev"],
    rows.map((p, i) => [
      String(i + 1),
      cell(p.assetA),
      cell(p.assetB),
      String(p.sharedAttackers),
      String(p.unionAttackers),
      pct(p.jaccard),
      p.topSharedSource ? `${cell(p.topSharedSource)} (${p.topSharedAlerts})` : "—",
      cell(p.severityMax),
    ]),
  );
}

function assetTable(rows: CoTargetAsset[]): string {
  return mdTable(
    ["#", "Asset", "Attackers", "Selective", "Peers", "Tightest peer", "Alerts", "Worst sev", "Flags"],
    rows.map((a, i) => {
      const flags = (a.watched ? "👁" : "") + (a.safe ? "✅" : "");
      return [
        String(i + 1),
        cell(a.ip),
        String(a.distinctAttackers),
        String(a.selectiveAttackers),
        String(a.peers),
        a.topPeer ? `${cell(a.topPeer)} (${a.topPeerShared})` : "—",
        String(a.alerts),
        cell(a.severityMax),
        flags || "—",
      ];
    }),
  );
}

function renderMarkdown(m: CoTargetReport): string {
  const lines: string[] = [];
  lines.push(`# 🕸️ SecTool Co-Targeting / Shared-Attacker Affinity Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** for each pair of internal assets, distinct *selective* sources hitting **both**, scored by Jaccard ` +
      `overlap of their attacker sets · broad scanners touching >${m.scannerThreshold} asset(s) are excluded ` +
      `(${m.broadScanners} excluded) · **Inbound alerts:** ${m.inboundAlerts} of ${m.totalWindowAlerts} ` +
      `(${m.distinctAssets} asset(s), ${m.distinctAttackers} source(s))`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.distinctAssets) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but none targeted an internal asset with a ` +
          `valid source IP (min ${DEFAULT_MIN_ALERTS} alert(s)/asset) — no co-targeting to compute.`,
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

  lines.push(`## Asset pairs by shared-attacker affinity`);
  lines.push("");
  if (!m.pairs.length) {
    lines.push(
      `_No asset pair shares ≥${m.minShared} selective attacker(s) this window_ — attacked hosts are being hunted ` +
        `independently (or only by broad scanners, which are excluded). The per-asset roll-up below still stands.`,
    );
  } else {
    lines.push(pairTable(m.pairs));
    lines.push("");
    lines.push(
      `**Legend:** _Shared_ = distinct selective sources hitting **both** assets · _Union_ = sources hitting either · ` +
        `_Affinity_ = Jaccard (shared ÷ union), normalising for how broadly each host is attacked so one common ` +
        `scanner can't inflate a heavily-probed pair. Pairs need ≥${m.minShared} shared attacker(s) to be listed. A ` +
        `high-affinity pair is a shared-fate unit — segment between them and monitor them together.`,
    );
  }
  lines.push("");

  lines.push(`## Assets by connectivity`);
  lines.push("");
  lines.push(assetTable(m.assets));
  lines.push("");
  lines.push(
    `**Legend:** _Attackers_ = all distinct sources (incl. broad scanners) · _Selective_ = sources after broad-scanner ` +
      `dampening · _Peers_ = other assets sharing ≥${m.minShared} selective attacker(s) · _Tightest peer_ = the host it ` +
      `overlaps most. The top row is the most-connected asset — the widest blast-radius if it (or its attacker) ` +
      `pivots. **Flags:** 👁 watched · ✅ safe.`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. **Affinity is association, not causation** — two assets sharing attackers means ` +
      `they are in the same exposure class, not that one leads to the other; the ranking directs attention, it does ` +
      `not prove a path. The **broad-scanner cut-off** (>${m.scannerThreshold} assets) is a tunable heuristic, so a ` +
      `borderline source can sit either side of it; the excluded count and raw per-asset attacker totals are shown so ` +
      `the call can be second-guessed. These are IPS **detections**, not full flows — a source that touched a host ` +
      `without tripping a rule is invisible, so every overlap is a lower bound. Affinity is computed over **internal ` +
      `(RFC1918) destination assets only**; outbound / external destinations are out of scope (see the direction and ` +
      `edges reports). A long look-back can hit the store's history cap and undercount overlap. No live gateway query ` +
      `was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the co-targeting / shared-attacker affinity report from the stored alert
 * history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link CoTargetOptions}: `limit`, `assetLimit`, `minShared`,
 *              `minAlerts`, `scannerFraction`, `maxFanout`, and a `nowMs` pin for
 *              deterministic tests.
 */
export function buildCoTarget(hours: number, opts: CoTargetOptions = {}): CoTargetReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const assetLimit = Math.max(1, Math.min(200, Math.floor(opts.assetLimit ?? DEFAULT_ASSET_LIMIT)));
  const minShared = Math.max(1, Math.floor(opts.minShared ?? DEFAULT_MIN_SHARED));
  const minAlerts = Math.max(1, Math.floor(opts.minAlerts ?? DEFAULT_MIN_ALERTS));
  const scannerFraction = Math.min(1, Math.max(0.01, opts.scannerFraction ?? DEFAULT_SCANNER_FRACTION));
  const maxFanout = Math.max(2, Math.floor(opts.maxFanout ?? DEFAULT_MAX_FANOUT));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  // Pass 1: fold inbound alerts (internal dst + valid src) into per-asset and
  // per-source incidence maps.
  const assetAttackers = new Map<string, Set<string>>(); // asset -> all sources (raw)
  const assetAlerts = new Map<string, number>();
  const assetSev = new Map<string, Severity>();
  const attackerTouches = new Map<string, Map<string, Touch>>(); // source -> asset -> touch
  let inbound = 0;

  for (const a of windowed) {
    const src = validIp(a.srcIp);
    const dst = validIp(a.dstIp);
    if (!src || !dst || !isPrivate(dst)) continue;
    inbound++;

    let set = assetAttackers.get(dst);
    if (!set) {
      set = new Set();
      assetAttackers.set(dst, set);
    }
    set.add(src);
    assetAlerts.set(dst, (assetAlerts.get(dst) ?? 0) + 1);
    assetSev.set(dst, maxSeverity(assetSev.get(dst) ?? "info", a.severity));

    let touches = attackerTouches.get(src);
    if (!touches) {
      touches = new Map();
      attackerTouches.set(src, touches);
    }
    const t = touches.get(dst) ?? { count: 0, sevMax: "info" as Severity };
    t.count++;
    t.sevMax = maxSeverity(t.sevMax, a.severity);
    touches.set(dst, t);
  }

  // Drop assets below the alert floor before any pairing or counting.
  for (const [asset, n] of assetAlerts) {
    if (n < minAlerts) {
      assetAttackers.delete(asset);
      assetAlerts.delete(asset);
      assetSev.delete(asset);
    }
  }

  const distinctAssets = assetAttackers.size;
  const distinctAttackers = attackerTouches.size;

  // Broad-scanner threshold: a source touching more than this many *qualifying*
  // assets is background noise tying everything together — exclude it from
  // affinity. min 2 (a source on 1 asset can form no pair anyway).
  const scannerThreshold = Math.max(
    2,
    Math.min(maxFanout, Math.ceil(scannerFraction * Math.max(distinctAssets, 1))),
  );

  // Per-asset selective-attacker counts (the Jaccard denominators) and the
  // broad-scanner tally.
  const selectiveCount = new Map<string, number>();
  let broadScanners = 0;
  const pairs = new Map<string, PairAcc>();

  for (const [src, touches] of attackerTouches) {
    // Restrict to qualifying assets (those that survived the alert floor).
    const hit = [...touches.entries()].filter(([asset]) => assetAttackers.has(asset));
    if (hit.length === 0) continue;
    if (hit.length > scannerThreshold) {
      broadScanners++;
      continue; // broad scanner: excluded from both selective counts and pairing
    }
    for (const [asset] of hit) selectiveCount.set(asset, (selectiveCount.get(asset) ?? 0) + 1);
    if (hit.length < 2) continue;

    // Generate every unordered asset pair this selective source binds together.
    const assets = hit.map(([asset]) => asset).sort();
    for (let i = 0; i < assets.length; i++) {
      for (let j = i + 1; j < assets.length; j++) {
        const a = assets[i]!;
        const b = assets[j]!;
        const key = pairKey(a, b);
        let acc = pairs.get(key);
        if (!acc) {
          acc = { assetA: a, assetB: b, shared: 0, sevMax: "info", topSource: undefined, topAlerts: 0 };
          pairs.set(key, acc);
        }
        acc.shared++;
        const combined = (touches.get(a)?.count ?? 0) + (touches.get(b)?.count ?? 0);
        const sev = maxSeverity(touches.get(a)?.sevMax ?? "info", touches.get(b)?.sevMax);
        acc.sevMax = maxSeverity(acc.sevMax, sev);
        if (combined > acc.topAlerts) {
          acc.topAlerts = combined;
          acc.topSource = src;
        }
      }
    }
  }

  // Materialise the qualifying pairs with Jaccard, gated by minShared.
  const pairList: CoTargetPair[] = [...pairs.values()]
    .filter((p) => p.shared >= minShared)
    .map((p) => {
      const selA = selectiveCount.get(p.assetA) ?? 0;
      const selB = selectiveCount.get(p.assetB) ?? 0;
      const union = selA + selB - p.shared;
      return {
        assetA: p.assetA,
        assetB: p.assetB,
        sharedAttackers: p.shared,
        unionAttackers: union,
        jaccard: union > 0 ? round4(p.shared / union) : 0,
        topSharedSource: p.topSource,
        topSharedAlerts: p.topAlerts,
        severityMax: p.sevMax,
      } satisfies CoTargetPair;
    })
    // Strongest shared-fate first: raw shared count, then affinity, then severity,
    // then a stable lexical tie-break.
    .sort(
      (x, y) =>
        y.sharedAttackers - x.sharedAttackers ||
        y.jaccard - x.jaccard ||
        sevRank(y.severityMax) - sevRank(x.severityMax) ||
        (x.assetA < y.assetA ? -1 : x.assetA > y.assetA ? 1 : x.assetB < y.assetB ? -1 : 1),
    );

  // Per-asset peer roll-up, derived from the *gated* pair list so "peers" matches
  // what the pair table shows.
  const peerCount = new Map<string, number>();
  const topPeer = new Map<string, { ip: string; shared: number }>();
  const bump = (asset: string, peer: string, shared: number): void => {
    peerCount.set(asset, (peerCount.get(asset) ?? 0) + 1);
    const cur = topPeer.get(asset);
    if (!cur || shared > cur.shared || (shared === cur.shared && peer < cur.ip)) {
      topPeer.set(asset, { ip: peer, shared });
    }
  };
  for (const p of pairList) {
    bump(p.assetA, p.assetB, p.sharedAttackers);
    bump(p.assetB, p.assetA, p.sharedAttackers);
  }

  const assetList: CoTargetAsset[] = [...assetAttackers.entries()]
    .map(([ip, sources]) => {
      const tp = topPeer.get(ip);
      return {
        ip,
        distinctAttackers: sources.size,
        selectiveAttackers: selectiveCount.get(ip) ?? 0,
        alerts: assetAlerts.get(ip) ?? 0,
        peers: peerCount.get(ip) ?? 0,
        topPeer: tp?.ip,
        topPeerShared: tp?.shared ?? 0,
        severityMax: assetSev.get(ip) ?? "info",
        watched: watchStore.has(ip),
        safe: safeStore.has(ip),
      } satisfies CoTargetAsset;
    })
    // Most connected first: peer count, then attacker volume, then alert volume,
    // then a stable IP tie-break.
    .sort(
      (x, y) =>
        y.peers - x.peers ||
        y.selectiveAttackers - x.selectiveAttackers ||
        y.alerts - x.alerts ||
        (x.ip < y.ip ? -1 : x.ip > y.ip ? 1 : 0),
    );

  const cappedPairs = pairList.slice(0, limit);
  const cappedAssets = assetList.slice(0, assetLimit);

  const highlights = writeHighlights(
    safeHours,
    { distinctAssets, distinctAttackers, broadScanners, inboundAlerts: inbound },
    cappedPairs,
    cappedAssets,
  );

  const model: CoTargetReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    inboundAlerts: inbound,
    distinctAssets,
    distinctAttackers,
    scannerThreshold,
    broadScanners,
    minShared,
    pairs: cappedPairs,
    assets: cappedAssets,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded co-targeting report. */
export function cotargetFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-cotarget-${stamp}.md`;
}
