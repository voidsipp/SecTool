/**
 * Traffic-direction / exposure report — "which way is the alert traffic
 * *flowing*, and is anything pointing the wrong way?"
 *
 * Every other offline report in this project treats the two endpoints of an
 * alert symmetrically: it ranks the worst source (persistence, netblock),
 * the worst destination/asset (assets, spread), the worst source→dest *pair*
 * (edges), or rolls a taxonomy / time axis (classify, focus, surge, beacon).
 * None of them ask the one question that re-frames a host from *victim* to
 * *suspect*:
 *
 *   **"Is the internal host the TARGET of this alert, or the SOURCE of it?"**
 *
 * That distinction is the sharpest compromise signal SecTool's data holds. An
 * external IP tripping a rule against your server is the expected, all-day-long
 * perimeter background (`inbound`). But one of *your* hosts tripping a rule
 * while reaching *out* to the internet (`outbound`) — or pivoting *sideways*
 * into another internal host (`lateral`) — is the texture of a live compromise:
 * C2 beaconing, data exfiltration, or east-west movement. A symmetric ranking
 * buries those few outbound/lateral alerts inside thousands of inbound ones; a
 * directional split surfaces them as their own bucket, with the responsible
 * *internal* host named.
 *
 * The report classifies every windowed alert by the RFC1918 / loopback /
 * link-local status of its two endpoints into one of five directions, in
 * descending operational concern:
 *
 *   - **outbound** — internal source → external destination. The highest-concern
 *     bucket: an internal host is the one tripping the rule, reaching outward.
 *     Treat as candidate C2 / exfil / compromised-host beaconing.
 *   - **lateral**  — internal → internal. East-west movement; a foothold probing
 *     or pivoting to neighbours. Rare in a healthy network, loud when real.
 *   - **inbound**  — external → internal. Classic perimeter attacks: the normal,
 *     high-volume background of an internet-facing gateway. Expected, not benign.
 *   - **external** — external → external. Neither endpoint is yours: spoofed
 *     sources, transit, or mis-parsed lines. Usually noise; called out as such.
 *   - **unknown**  — one or both endpoints missing / unparseable. Excluded from
 *     the directional verdict so it never inflates a concern bucket.
 *
 * For each bucket it computes, from the windowed alerts: volume and share,
 * distinct sources and destinations, the blocked-vs-passed disposition split
 * (reusing efficacy.ts's `classifyDisposition`) and the resulting pass rate,
 * the severe (≥ medium) count, and the single loudest signature. A high pass
 * rate on the *outbound* bucket is the alarm worth the most: the gateway is
 * watching an internal host reach out and *letting it through*.
 *
 * It then drills into the buckets that matter — outbound + lateral — and ranks
 * the **internal hosts that are SOURCING** those alerts. Each such host is a
 * candidate compromise, scored by unblocked-outbound volume (the unmitigated
 * C2 / exfil) and shown with its external-destination breadth, lateral-target
 * count, peak severity, top signature, and blocklist / watchlist / safelist
 * membership (mirroring edges.ts / persistence.ts / focus.ts).
 *
 * Honest caveats baked into the output:
 *
 *   - **Direction is inferred, not observed.** It rests on RFC1918 / loopback /
 *     link-local classification of the two IPs. NAT, VPN tunnels, asymmetric
 *     routing, carrier-grade NAT, or a gateway that rewrites addresses can
 *     mislabel a flow. A surprising outbound/lateral hit is a *lead to verify*
 *     (pull the host's egress in the live investigator), not a conviction.
 *   - **Alerts, not flows.** SecTool stores IPS *detections*. A host beaconing
 *     over a channel that never trips a rule is invisible here; "no outbound"
 *     means none *alerted*, not none happened.
 *   - **Window-bounded & store-capped.** The store keeps a bounded history; a
 *     long look-back can hit that cap and skew the directional mix.
 *
 * Pure in-memory math over alertStore (plus blocklist/watchlist/safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring report.ts, focus.ts,
 * edges.ts, efficacy.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Stable machine key for each traffic direction, in descending concern order. */
export type DirectionKey = "outbound" | "lateral" | "inbound" | "external" | "unknown";

/** Canonical bucket order, highest operational concern first. */
const DIRECTION_ORDER: DirectionKey[] = ["outbound", "lateral", "inbound", "external", "unknown"];

const DIRECTION_LABEL: Record<DirectionKey, string> = {
  outbound: "Outbound (internal → external)",
  lateral: "Lateral (internal → internal)",
  inbound: "Inbound (external → internal)",
  external: "External (external → external)",
  unknown: "Unknown (missing endpoint)",
};

/** Disposition / blocking split for a bucket or host, via classifyDisposition. */
export interface DispositionSplit {
  /** Alerts the gateway actively blocked / dropped. */
  blocked: number;
  /** Alerts the gateway logged but let through (detected / allowed). */
  passed: number;
  /** Alerts with no recorded action (excluded from {@link passRate}). */
  unknown: number;
  /**
   * Fraction of *actioned* (blocked + passed) alerts that were let through,
   * 0..1 (4dp), or null when nothing was actioned. High on `outbound` is the
   * alarm: an internal host reached out and the gateway allowed it.
   */
  passRate: number | null;
}

/** Directional metrics for a single bucket over the window. */
export interface DirectionBucket {
  key: DirectionKey;
  /** Human label of the direction. */
  label: string;
  /** Alerts classified into this direction. */
  count: number;
  /** count / totalWindowAlerts, 0..1 (4dp). */
  share: number;
  /** Distinct source IPs seen in this direction. */
  distinctSources: number;
  /** Distinct destination IPs seen in this direction. */
  distinctDestinations: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Blocked / passed / unknown disposition split. */
  disposition: DispositionSplit;
  /** The loudest signature in this direction, or undefined if none carried one. */
  topSignature?: string;
  /** That signature's alert count. */
  topSignatureCount: number;
}

/** One internal host that is *sourcing* outbound / lateral alerts. */
export interface InternalSource {
  /** The internal host's IP. */
  ip: string;
  /** Outbound + lateral alerts sourced by this host (the row's volume). */
  total: number;
  /** Of {@link total}, alerts reaching an external destination. */
  outbound: number;
  /** Of {@link total}, alerts reaching another internal host. */
  lateral: number;
  /** Distinct external destinations this host reached (C2 / exfil breadth). */
  externalPeers: number;
  /** Distinct internal hosts this host touched (lateral target breadth). */
  internalPeers: number;
  /** Outbound alerts that were *not* blocked — the unmitigated egress. */
  outboundPassed: number;
  /** Worst severity seen across this host's sourced alerts. */
  severityMax: Severity;
  /** Sourced alerts at medium severity or worse. */
  severe: number;
  /** The host's loudest signature, or undefined. */
  topSignature?: string;
  /** The host is on the blocklist. */
  blocked: boolean;
  /** The host is on the watchlist. */
  watched: boolean;
  /** The host is marked safe. */
  safe: boolean;
}

export interface DirectionReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Per-direction buckets, in canonical concern order. */
  buckets: DirectionBucket[];
  /** Internal hosts sourcing outbound/lateral alerts, worst (most unmitigated) first. */
  internalSources: InternalSource[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface DirectionOptions {
  /** Max rows in the internal-source table (clamped to [1, 100]). */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 15;
const MS_PER_HOUR = 3_600_000;

// ----- formatting helpers (mirror focus.ts / edges.ts / efficacy.ts) --------

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** A 0..1 fraction as a whole-number percent string, e.g. 0.823 -> "82%". */
function pct(frac: number): string {
  return `${Math.round(frac * 100)}%`;
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
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
function clip(s: string, max = 40): string {
  const t = s.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

// ----- classifiers ----------------------------------------------------------

/**
 * RFC1918 / loopback / link-local / ULA — mirrors profile.ts / spread.ts /
 * netblock.ts. An address that matches is treated as one of *ours* (internal).
 */
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

/**
 * Classify one alert's direction from its endpoints. Returns `unknown` when
 * either endpoint is missing or unparseable, so a half-formed alert can never
 * be mislabelled into a concern bucket.
 */
export function classifyDirection(srcIp: string | undefined, dstIp: string | undefined): DirectionKey {
  const src = validIp(srcIp);
  const dst = validIp(dstIp);
  if (!src || !dst) return "unknown";
  const srcInt = isPrivate(src);
  const dstInt = isPrivate(dst);
  if (srcInt && dstInt) return "lateral";
  if (srcInt && !dstInt) return "outbound";
  if (!srcInt && dstInt) return "inbound";
  return "external";
}

// ----- bucket aggregation ---------------------------------------------------

interface BucketAcc {
  count: number;
  sources: Set<string>;
  destinations: Set<string>;
  severe: number;
  blocked: number;
  passed: number;
  unknown: number;
  sigCounts: Map<string, number>;
}

function newBucketAcc(): BucketAcc {
  return {
    count: 0,
    sources: new Set(),
    destinations: new Set(),
    severe: 0,
    blocked: 0,
    passed: 0,
    unknown: 0,
    sigCounts: new Map(),
  };
}

function topSig(sigCounts: Map<string, number>): { sig?: string; count: number } {
  let sig: string | undefined;
  let count = 0;
  for (const [s, c] of sigCounts) {
    if (c > count || (c === count && sig !== undefined && s < sig)) {
      sig = s;
      count = c;
    }
  }
  return { sig, count };
}

function finishBucket(key: DirectionKey, acc: BucketAcc, total: number): DirectionBucket {
  const actioned = acc.blocked + acc.passed;
  const top = topSig(acc.sigCounts);
  return {
    key,
    label: DIRECTION_LABEL[key],
    count: acc.count,
    share: total ? round4(acc.count / total) : 0,
    distinctSources: acc.sources.size,
    distinctDestinations: acc.destinations.size,
    severe: acc.severe,
    disposition: {
      blocked: acc.blocked,
      passed: acc.passed,
      unknown: acc.unknown,
      passRate: actioned ? round4(acc.passed / actioned) : null,
    },
    topSignature: top.sig,
    topSignatureCount: top.count,
  };
}

// ----- internal-source aggregation ------------------------------------------

interface SourceAcc {
  total: number;
  outbound: number;
  lateral: number;
  externalPeers: Set<string>;
  internalPeers: Set<string>;
  outboundPassed: number;
  severityMax: Severity;
  severe: number;
  sigCounts: Map<string, number>;
}

function newSourceAcc(): SourceAcc {
  return {
    total: 0,
    outbound: 0,
    lateral: 0,
    externalPeers: new Set(),
    internalPeers: new Set(),
    outboundPassed: 0,
    severityMax: "info",
    severe: 0,
    sigCounts: new Map(),
  };
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  total: number,
  buckets: DirectionBucket[],
  internalSources: InternalSource[],
): string[] {
  const out: string[] = [];
  if (!total) return out;

  const byKey = new Map(buckets.map((b) => [b.key, b]));
  const outbound = byKey.get("outbound");
  const lateral = byKey.get("lateral");
  const inbound = byKey.get("inbound");

  // Overall directional read — what the bulk of the alert traffic is doing.
  const dominant = [...buckets].filter((b) => b.key !== "unknown").sort((a, b) => b.count - a.count)[0];
  if (dominant && dominant.count > 0) {
    if (dominant.key === "inbound") {
      out.push(
        `🧭 Over the last ${hours}h the alert traffic is mostly **inbound** (${pct(dominant.share)}) — external ` +
          `actors probing your perimeter. That is the normal background of an internet-facing gateway; the signal to ` +
          `hunt for is anything pointing *outward* (below), not the inbound volume itself.`,
      );
    } else {
      out.push(
        `🧭 Over the last ${hours}h the largest direction is **${dominant.key}** (${pct(dominant.share)} of alerts) — ` +
          `unusual for a perimeter sensor, where inbound normally dominates. Read the outbound / lateral sections ` +
          `below carefully before assuming this is noise.`,
      );
    }
  }

  // Outbound — the headline compromise signal.
  if (outbound && outbound.count > 0) {
    const passed = outbound.disposition.passed;
    const hostCount = outbound.distinctSources;
    const lead = internalSources.find((s) => s.outbound > 0);
    const leadNote = lead
      ? ` Loudest is \`${lead.ip}\` (${lead.outbound} outbound alert(s) to ${lead.externalPeers} external dest(s)` +
        `${lead.outboundPassed ? `, ${lead.outboundPassed} unblocked` : ""}).`
      : "";
    out.push(
      `🚨 **${outbound.count} outbound alert(s)** from **${hostCount} internal host(s)** reaching external ` +
        `destinations — candidate C2 / exfil / compromise.${leadNote} Verify each host's egress before dismissing; ` +
        `direction is inferred from RFC1918 status and NAT/VPN can mislabel, but outbound IPS hits rarely lie.`,
    );
    if (passed > 0 && outbound.disposition.passRate !== null) {
      out.push(
        `⚠️ Of the actioned outbound alerts, **${pct(outbound.disposition.passRate)} were let through** ` +
          `(${passed} not blocked). The gateway watched an internal host reach out and allowed it — the most ` +
          `urgent gap here: confirm the destination and block at the firewall if it is hostile.`,
      );
    }
  } else {
    out.push(
      `✅ No outbound alerts this window — no internal host tripped a rule while reaching the internet. (Absence of ` +
        `*alerts* is not proof of no beaconing; a channel that never trips a signature is invisible here.)`,
    );
  }

  // Lateral — east-west movement.
  if (lateral && lateral.count > 0) {
    out.push(
      `↔️ **${lateral.count} lateral alert(s)** between internal hosts (${lateral.distinctSources} source(s) → ` +
        `${lateral.distinctDestinations} dest(s)) — east-west movement. Rare in a healthy network; treat each as a ` +
        `possible foothold pivoting to a neighbour and check the source host first.`,
    );
  }

  // Internal-source roll-up — how many of your own hosts are implicated, and
  // whether any are already known-bad.
  if (internalSources.length) {
    const flagged = internalSources.filter((s) => s.blocked || s.watched).length;
    const safe = internalSources.filter((s) => s.safe).length;
    const note =
      (flagged ? ` ${flagged} already blocked/watched.` : "") +
      (safe ? ` ${safe} are safelisted (expected egress — likely benign).` : "");
    out.push(
      `🖥️ **${internalSources.length} internal host(s)** are *sourcing* alerts (outbound or lateral) — the candidate ` +
        `compromise list. Work it top-down; rows are ranked by unmitigated outbound volume.${note}`,
    );
  }

  // Inbound context, kept brief — it is the expected bucket.
  if (inbound && inbound.count > 0 && inbound.disposition.passRate !== null && inbound.severe > 0) {
    const severePass = inbound.disposition.passRate;
    if (severePass >= 0.5) {
      out.push(
        `🛡️ Inbound is the expected perimeter background (${inbound.count} alerts, ${inbound.severe} severe), but ` +
          `${pct(severePass)} of actioned inbound alerts passed — see the efficacy report for the enforcement gaps.`,
      );
    }
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function bucketTable(buckets: DirectionBucket[]): string {
  return mdTable(
    ["Direction", "Alerts", "Share", "Sources", "Dests", "Severe", "Blocked", "Passed", "Pass rate"],
    buckets.map((b) => [
      cell(b.label),
      String(b.count),
      pct(b.share),
      String(b.distinctSources),
      String(b.distinctDestinations),
      String(b.severe),
      String(b.disposition.blocked),
      String(b.disposition.passed),
      b.disposition.passRate === null ? "—" : pct(b.disposition.passRate),
    ]),
  );
}

function internalSourceTable(rows: InternalSource[]): string {
  return mdTable(
    ["#", "Internal host", "Total", "Outbound", "Lateral", "Ext dests", "Int peers", "Unblocked out", "Peak sev", "Top signature", "Flags"],
    rows.map((s, i) => {
      const flags = (s.blocked ? "⛔" : "") + (s.watched ? "👁" : "") + (s.safe ? "✅" : "");
      return [
        String(i + 1),
        cell(s.ip),
        String(s.total),
        String(s.outbound),
        String(s.lateral),
        String(s.externalPeers),
        String(s.internalPeers),
        String(s.outboundPassed),
        cell(s.severityMax),
        cell(s.topSignature ? clip(s.topSignature) : "—"),
        flags || "—",
      ];
    }),
  );
}

function renderMarkdown(m: DirectionReport): string {
  const lines: string[] = [];
  lines.push(`# 🧭 SecTool Traffic-Direction / Exposure Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** each stored IPS alert bucketed by RFC1918 status of its two endpoints ` +
      `(outbound · lateral · inbound · external · unknown) · **Window alerts:** ${m.totalWindowAlerts}`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.totalWindowAlerts) {
    lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Direction at a glance`);
  lines.push("");
  lines.push(bucketTable(m.buckets));
  lines.push("");
  lines.push(
    `**Legend:** _Outbound_ (internal→external) and _Lateral_ (internal→internal) are the compromise-bearing ` +
      `directions — an internal host is the one tripping the rule. _Inbound_ (external→internal) is the expected ` +
      `perimeter background. _External_ (external→external) is usually spoofed / transit noise. _Pass rate_ = share ` +
      `of *actioned* alerts the gateway let through; a high pass rate on **outbound** is the alarm worth chasing.`,
  );
  lines.push("");

  lines.push(`## Internal hosts sourcing alerts (candidate compromise)`);
  lines.push("");
  if (!m.internalSources.length) {
    lines.push(
      `_No internal host sourced an outbound or lateral alert this window._ Every alert with a usable internal ` +
        `endpoint had that host as the *target*, not the origin — the expected posture for a perimeter sensor.`,
    );
  } else {
    lines.push(
      `Internal hosts that *originated* outbound or lateral alerts, ranked by unmitigated outbound volume — the ` +
        `nearest thing this dataset has to a "which of my machines is compromised?" list. Verify each host's live ` +
        `egress before acting; direction is inferred and NAT / VPN can mislabel.`,
    );
    lines.push("");
    lines.push(internalSourceTable(m.internalSources));
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from stored **IPS-alert** endpoints. Direction is **inferred** from the ` +
      `RFC1918 / loopback / link-local status of each alert's source and destination — NAT, VPN tunnels, asymmetric ` +
      `routing or carrier-grade NAT can mislabel a flow, so a surprising outbound / lateral hit is a lead to verify ` +
      `(pull the host's egress in the live investigator), not a conviction. These are detections, not full flows: a ` +
      `host beaconing over a channel that never trips a rule is invisible here. A long look-back can hit the store's ` +
      `history cap and skew the directional mix. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the traffic-direction / exposure report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link DirectionOptions}: `limit` (internal-source rows) and a `nowMs` pin.
 */
export function buildDirection(hours: number, opts: DirectionOptions = {}): DirectionReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(100, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const buckets = new Map<DirectionKey, BucketAcc>(
    DIRECTION_ORDER.map((k) => [k, newBucketAcc()] as const),
  );
  const sources = new Map<string, SourceAcc>();

  for (const a of windowed) {
    const dir = classifyDirection(a.srcIp, a.dstIp);
    const acc = buckets.get(dir)!;
    acc.count++;
    const src = validIp(a.srcIp);
    const dst = validIp(a.dstIp);
    if (src) acc.sources.add(src);
    if (dst) acc.destinations.add(dst);
    if (isSevere(a.severity)) acc.severe++;
    const disp = classifyDisposition(a.action);
    if (disp === "blocked") acc.blocked++;
    else if (disp === "passed") acc.passed++;
    else acc.unknown++;
    const sig = a.signature?.trim();
    if (sig) acc.sigCounts.set(sig, (acc.sigCounts.get(sig) ?? 0) + 1);

    // Internal-source roll-up: only outbound / lateral, keyed on the internal
    // origin host (which we know is private because of the direction).
    if ((dir === "outbound" || dir === "lateral") && src) {
      let s = sources.get(src);
      if (!s) {
        s = newSourceAcc();
        sources.set(src, s);
      }
      s.total++;
      s.severityMax = maxSeverity(s.severityMax, a.severity);
      if (isSevere(a.severity)) s.severe++;
      if (sig) s.sigCounts.set(sig, (s.sigCounts.get(sig) ?? 0) + 1);
      if (dir === "outbound") {
        s.outbound++;
        if (dst) s.externalPeers.add(dst);
        if (disp === "passed") s.outboundPassed++;
      } else {
        s.lateral++;
        if (dst) s.internalPeers.add(dst);
      }
    }
  }

  const bucketList: DirectionBucket[] = DIRECTION_ORDER.map((k) =>
    finishBucket(k, buckets.get(k)!, windowed.length),
  );

  const internalSources: InternalSource[] = [...sources.entries()]
    .map(([ip, s]) => {
      const top = topSig(s.sigCounts);
      return {
        ip,
        total: s.total,
        outbound: s.outbound,
        lateral: s.lateral,
        externalPeers: s.externalPeers.size,
        internalPeers: s.internalPeers.size,
        outboundPassed: s.outboundPassed,
        severityMax: s.severityMax,
        severe: s.severe,
        topSignature: top.sig,
        blocked: blockStore.has(ip),
        watched: watchStore.has(ip),
        safe: safeStore.has(ip),
      } satisfies InternalSource;
    })
    // Worst first: unmitigated outbound volume, then total outbound, then total,
    // then IP for a stable deterministic order.
    .sort(
      (x, y) =>
        y.outboundPassed - x.outboundPassed ||
        y.outbound - x.outbound ||
        y.total - x.total ||
        (x.ip < y.ip ? -1 : x.ip > y.ip ? 1 : 0),
    )
    .slice(0, limit);

  const highlights = writeHighlights(safeHours, windowed.length, bucketList, internalSources);
  const model: DirectionReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    buckets: bucketList,
    internalSources,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded traffic-direction report. */
export function directionFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-direction-${stamp}.md`;
}
