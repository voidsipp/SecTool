/**
 * Internal-asset exposure scoreboard.
 *
 * Campaigns answers "who is attacking me?" by clustering alerts around the
 * external (attacker) IP. This module answers the mirror-image question every
 * operator eventually asks — "which of MY devices should I worry about?" — by
 * clustering the same stored alert history around the *internal* host instead.
 *
 * For each internal host it rolls up, from the local alert history:
 *
 *   - total alerts and the worst severity it reached,
 *   - the security-critical split between OUTBOUND alerts (the host was the
 *     SOURCE — a strong "this box may be compromised / beaconing out" signal)
 *     and INBOUND alerts (the host was the DESTINATION — it was scanned or
 *     targeted),
 *   - every distinct counterpart it exchanged alerts with, split internal
 *     (lateral movement) vs external (attackers/peers),
 *   - the signatures and categories it tripped,
 *   - blocked vs detected-only dispositions and open triage items,
 *   - its active time span,
 *   - a composite 0-100 exposure risk score that weights outbound/compromise
 *     signals more heavily than inbound/targeting ones, and
 *   - a one-word posture label (compromise-suspected / targeted / noisy / calm).
 *
 * It is pure in-memory math over alertStore — no SSH, no Claude, no network — so
 * it is safe to call from the dashboard or CLI at any time. Output is both a
 * structured model and a ready-to-paste Markdown document, mirroring report.ts,
 * compare.ts and profile.ts.
 *
 * This complements:
 *   - campaigns.ts (clusters by EXTERNAL attacker — the inverse axis),
 *   - profile.ts   (a single-entity deep dive — not a ranked board), and
 *   - trends.ts    (window-wide aggregates — not per-host).
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { dismissStore } from "../store/dismissed.ts";
import { triageStore } from "../store/triage.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Lowest severity weight that reads as a real detection (not info noise). */
const SEV_WEIGHT: Record<string, number> = { info: 0, low: 1, medium: 2, high: 4, critical: 8 };

export interface AssetSignature {
  signature: string;
  count: number;
  severityMax: Severity;
}

export interface AssetPeer {
  /** The counterpart endpoint this host exchanged alerts with. */
  ip: string;
  /** Number of alerts shared with this peer. */
  count: number;
  /** Whether the peer is an internal (RFC1918 / loopback / link-local) host. */
  internal: boolean;
  /** Highest severity seen across alerts with this peer. */
  severityMax: Severity;
  /** Most recent alert time with this peer, ms epoch. */
  lastSeen: number;
  /** Whether this peer is currently blocked at the gateway. */
  blocked: boolean;
}

/** A one-word risk posture derived from the in/outbound split + severity. */
export type AssetPosture = "compromise-suspected" | "targeted" | "noisy" | "calm";

export interface AssetEntry {
  /** The internal host this row is about. */
  ip: string;
  /** Total alerts involving this host in the window. */
  alertCount: number;
  /** Highest severity seen across the host's alerts. */
  severityMax: Severity;
  /** Per-severity counts, ordered info → critical (zeros omitted). */
  bySeverity: Array<{ severity: Severity; count: number }>;
  /** Alerts where this host was the SOURCE (outbound — possible compromise). */
  asSrc: number;
  /** Alerts where this host was the DESTINATION (inbound — targeted/scanned). */
  asDst: number;
  /** Severe (medium+) alerts where this host was the source — the compromise signal. */
  outboundSevere: number;
  /** Distinct counterpart endpoints, most-contacted first. */
  peers: AssetPeer[];
  /** Of {@link peers}, how many are external. */
  externalPeerCount: number;
  /** Distinct signatures this host tripped, most-seen first. */
  signatures: AssetSignature[];
  /** Distinct Suricata categories tripped. */
  categories: string[];
  /** Earliest / latest alert times (ms epoch) and the span between them. */
  firstSeen: number;
  lastSeen: number;
  spanMs: number;
  /** How many of the host's alerts the gateway actually blocked. */
  blockedCount: number;
  /** Detected-only (seen but not stopped) alerts. */
  detectedCount: number;
  /** Alerts still open in triage. */
  openCount: number;
  /** Composite 0-100 exposure risk score (see scoreAsset). */
  riskScore: number;
  /** One-word posture label. */
  posture: AssetPosture;
  /** Current operator state for this host. */
  blocked: boolean;
  watched: boolean;
  safe: boolean;
  watchNote?: string;
  /** Most-recent alert ids involving this host (for drill-in), newest first. */
  sampleAlertIds: string[];
}

export interface AssetsReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Number of distinct internal hosts that appeared in any alert. */
  assetCount: number;
  /** Alerts that involved at least one internal host (contributed to the board). */
  consideredAlerts: number;
  /** In-window alerts with no internal endpoint (external↔external) — skipped. */
  externalOnlyAlerts: number;
  /** Plain-language call-outs about the board as a whole. */
  highlights: string[];
  /** The ranked internal hosts (highest exposure first). */
  assets: AssetEntry[];
  /** The finished Markdown document. */
  markdown: string;
}

const SAMPLE_IDS = 8;
const DEFAULT_TOP_PEERS = 12;
const DEFAULT_TOP_SIGS = 8;
const NOTABLE_MIN_WEIGHT = SEV_WEIGHT.medium!;

function isPrivate(ip: string): boolean {
  return (
    /^10\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^127\./.test(ip) ||
    /^169\.254\./.test(ip) ||
    /^(::1|fe80|fc|fd)/i.test(ip)
  );
}

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? (b as Severity) : a;
}

function normalizeAction(a: string | undefined): string {
  const v = (a ?? "").toLowerCase().trim();
  if (v === "blocked" || v === "detected" || v === "allowed") return v;
  return "unknown";
}

/** The internal endpoint(s) of an alert. Usually one; two for lateral (int↔int). */
function internalEndpoints(a: StoredAlert): string[] {
  const out: string[] = [];
  for (const ip of [a.srcIp, a.dstIp]) {
    if (ip && isIP(ip) > 0 && isPrivate(ip) && !out.includes(ip)) out.push(ip);
  }
  return out;
}

/**
 * Composite 0-100 exposure risk score for an internal host. Unlike a campaign
 * (where the attacker drives the score), an internal host is most alarming when
 * it is the *source* of severe alerts — that reads as a compromised box phoning
 * home. So outbound-severe activity is weighted hardest, on top of the usual
 * severity / volume / breadth signals.
 */
function scoreAsset(p: {
  severityMax: Severity;
  alertCount: number;
  externalPeerCount: number;
  signatureCount: number;
  outboundSevere: number;
  blockedCount: number;
  safe: boolean;
  watched: boolean;
}): number {
  if (p.alertCount === 0) return 0;
  let score = sevRank(p.severityMax) * 12; // up to 48 from severity
  score += Math.min(16, Math.log2(p.alertCount + 1) * 5); // volume, diminishing
  score += Math.min(12, Math.max(0, p.signatureCount - 1) * 3); // signature diversity
  score += Math.min(10, Math.max(0, p.externalPeerCount - 1) * 3); // distinct attackers/peers
  // The compromise signal: this host *initiating* severe traffic.
  score += Math.min(24, p.outboundSevere * 8);
  if (p.watched) score += 4; // operator already flagged it
  if (p.blockedCount === p.alertCount && p.alertCount > 0) score -= 6; // gateway stopped it all
  if (p.safe) score -= 30; // explicitly trusted
  return Math.max(0, Math.min(100, Math.round(score)));
}

/** Classify the host's posture from its in/outbound split and severity. */
function classifyPosture(p: {
  alertCount: number;
  severityMax: Severity;
  asSrc: number;
  outboundSevere: number;
}): AssetPosture {
  if (p.alertCount === 0) return "calm";
  // Outbound severe traffic dominates → the host itself looks like the problem.
  if (p.outboundSevere > 0 && p.asSrc >= p.alertCount / 2) return "compromise-suspected";
  // Real (medium+) detections that aren't outbound-driven → the host is being hit.
  if (sevRank(p.severityMax) >= 2) return "targeted";
  // Lots of low/info chatter but nothing severe.
  if (p.alertCount >= 10) return "noisy";
  return "calm";
}

// ----- formatting helpers (mirror report.ts / profile.ts conventions) -----

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function fmtAgo(ms: number, now: number): string {
  const s = Math.max(0, Math.round((now - ms) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

function fmtSpan(ms: number): string {
  if (ms <= 0) return "single hit";
  const m = Math.round(ms / 60_000);
  if (m < 60) return `${m}m`;
  const h = m / 60;
  if (h < 48) return `${h.toFixed(1)}h`;
  return `${(h / 24).toFixed(1)}d`;
}

function pct(n: number, total: number): number {
  return total > 0 ? Math.round((n / total) * 100) : 0;
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

const POSTURE_LABEL: Record<AssetPosture, string> = {
  "compromise-suspected": "⚠️ Compromise suspected",
  targeted: "🎯 Targeted",
  noisy: "📢 Noisy",
  calm: "· Calm",
};

/** Compose the board-level highlight bullets from the ranked hosts. */
function writeHighlights(assets: AssetEntry[], consideredAlerts: number): string[] {
  const highlights: string[] = [];
  if (!assets.length) return highlights;

  const compromise = assets.filter((a) => a.posture === "compromise-suspected");
  if (compromise.length) {
    highlights.push(
      `${compromise.length} host(s) show OUTBOUND severe activity (possible compromise): ` +
        compromise
          .slice(0, 5)
          .map((a) => `${a.ip} (risk ${a.riskScore})`)
          .join(", ") +
        ".",
    );
  }

  const top = assets[0]!;
  highlights.push(
    `Highest exposure: ${top.ip} — risk ${top.riskScore}/100, ${top.alertCount} alert(s), ` +
      `peak ${top.severityMax}, ${top.externalPeerCount} external peer(s).`,
  );

  const targeted = assets.filter((a) => a.posture === "targeted").length;
  if (targeted) highlights.push(`${targeted} host(s) were targeted/scanned from outside.`);

  const open = assets.reduce((n, a) => n + a.openCount, 0);
  if (open) highlights.push(`${open} alert(s) across these hosts are still open in triage.`);

  highlights.push(`${assets.length} internal host(s) appeared across ${consideredAlerts} alert(s) this window.`);
  return highlights;
}

function renderMarkdown(model: AssetsReport): string {
  const lines: string[] = [];
  lines.push(`# 🖥️ SecTool Asset Exposure Scoreboard`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(model.windowEndMs)}`);
  lines.push(`**Window:** last ${model.hours} hour(s) — ${fmtTime(model.windowStartMs)} → ${fmtTime(model.windowEndMs)}`);
  lines.push(
    `**Internal hosts:** ${model.assetCount} · **Alerts considered:** ${model.consideredAlerts}` +
      (model.externalOnlyAlerts ? ` · ${model.externalOnlyAlerts} external-only alert(s) skipped` : ""),
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!model.assets.length) {
    lines.push(`No internal hosts appeared in any alert in the last ${model.hours} hour(s).`);
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of model.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Ranked hosts`);
  lines.push("");
  lines.push(
    mdTable(
      ["#", "Host", "Risk", "Posture", "Alerts", "Out→/In←", "Peak", "Ext peers", "Blocked", "Open", "Last seen"],
      model.assets.map((a, i) => [
        String(i + 1),
        cell(a.ip),
        String(a.riskScore),
        cell(POSTURE_LABEL[a.posture]),
        String(a.alertCount),
        `${a.asSrc}→ / ${a.asDst}←`,
        cell(a.severityMax),
        String(a.externalPeerCount),
        String(a.blockedCount),
        String(a.openCount),
        fmtAgo(a.lastSeen, model.windowEndMs),
      ]),
    ),
  );
  lines.push("");

  // Per-host detail for the worst offenders so the doc is actionable.
  const detailLimit = Math.min(model.assets.length, 10);
  lines.push(`## Host detail (top ${detailLimit})`);
  lines.push("");
  for (let i = 0; i < detailLimit; i++) {
    const a = model.assets[i]!;
    const state: string[] = [];
    if (a.blocked) state.push("🚫 blocked");
    if (a.watched) state.push(`⚑ watched${a.watchNote ? ` — ${a.watchNote}` : ""}`);
    if (a.safe) state.push("✓ safe");
    lines.push(`### ${i + 1}. \`${a.ip}\` — ${POSTURE_LABEL[a.posture]} (risk ${a.riskScore}/100)`);
    lines.push("");
    lines.push(
      `- **${a.alertCount}** alert(s) — ${a.asSrc} outbound (source) / ${a.asDst} inbound (dest), ` +
        `${a.outboundSevere} severe outbound. Peak severity **${a.severityMax}**.`,
    );
    lines.push(
      `- ${a.blockedCount} blocked, ${a.detectedCount} detected-only, ${a.openCount} open in triage. ` +
        `Active span ${fmtSpan(a.spanMs)}; last seen ${fmtAgo(a.lastSeen, model.windowEndMs)}.`,
    );
    if (state.length) lines.push(`- Operator state: ${state.join(" · ")}.`);
    if (a.signatures.length) {
      lines.push(
        `- Top signatures: ${a.signatures
          .slice(0, 5)
          .map((s) => `${s.signature} ×${s.count}`)
          .join("; ")}.`,
      );
    }
    if (a.peers.length) {
      lines.push("");
      lines.push(
        mdTable(
          ["Peer", "Scope", "Alerts", "Peak", "Blocked", "Last"],
          a.peers.map((p) => [
            cell(p.ip),
            p.internal ? "internal" : "external",
            String(p.count),
            cell(p.severityMax),
            p.blocked ? "yes" : "—",
            fmtAgo(p.lastSeen, model.windowEndMs),
          ]),
        ),
      );
    }
    lines.push("");
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from ${model.consideredAlerts} stored alert(s) involving ${model.assetCount} ` +
      `internal host(s). No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the asset-exposure scoreboard from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param limit Cap on how many hosts are returned (the highest-risk ones).
 * @param nowMs Pins the window end for deterministic tests; defaults to now.
 */
export function buildAssets(hours: number, limit = 50, nowMs = Date.now()): AssetsReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const windowEndMs = nowMs;
  const windowStartMs = windowEndMs - safeHours * 3_600_000;
  const safeLimit = Math.max(1, Math.min(500, Math.floor(limit)));

  const all: StoredAlert[] = alertStore.all();
  const inWindow = all.filter(
    (a) => typeof a.time === "number" && a.time >= windowStartMs && a.time <= windowEndMs && !dismissStore.has(a.id),
  );

  interface PeerAccum {
    count: number;
    internal: boolean;
    severityMax: Severity;
    lastSeen: number;
  }
  interface Agg {
    ip: string;
    alertCount: number;
    severityMax: Severity;
    bySev: Map<Severity, number>;
    sigCounts: Map<string, number>;
    sigMaxSev: Map<string, Severity>;
    categories: Set<string>;
    peers: Map<string, PeerAccum>;
    asSrc: number;
    asDst: number;
    outboundSevere: number;
    firstSeen: number;
    lastSeen: number;
    blockedCount: number;
    detectedCount: number;
    openCount: number;
    samples: Array<{ id: string; time: number }>;
  }

  const byHost = new Map<string, Agg>();
  let consideredAlerts = 0;
  let externalOnlyAlerts = 0;

  for (const a of inWindow) {
    const hosts = internalEndpoints(a);
    if (!hosts.length) {
      externalOnlyAlerts++;
      continue;
    }
    consideredAlerts++;
    const sev = (a.severity as Severity) ?? "info";
    const weight = SEV_WEIGHT[sev] ?? 0;
    const action = normalizeAction(a.action);

    for (const host of hosts) {
      let agg = byHost.get(host);
      if (!agg) {
        agg = {
          ip: host,
          alertCount: 0,
          severityMax: "info",
          bySev: new Map(),
          sigCounts: new Map(),
          sigMaxSev: new Map(),
          categories: new Set(),
          peers: new Map(),
          asSrc: 0,
          asDst: 0,
          outboundSevere: 0,
          firstSeen: a.time,
          lastSeen: a.time,
          blockedCount: 0,
          detectedCount: 0,
          openCount: 0,
          samples: [],
        };
        byHost.set(host, agg);
      }
      agg.alertCount++;
      agg.severityMax = maxSeverity(agg.severityMax, sev);
      agg.bySev.set(sev, (agg.bySev.get(sev) ?? 0) + 1);
      if (a.signature) {
        agg.sigCounts.set(a.signature, (agg.sigCounts.get(a.signature) ?? 0) + 1);
        agg.sigMaxSev.set(a.signature, maxSeverity(agg.sigMaxSev.get(a.signature) ?? "info", sev));
      }
      if (a.category) agg.categories.add(a.category);

      const isSrc = a.srcIp === host;
      const isDst = a.dstIp === host;
      if (isSrc) {
        agg.asSrc++;
        if (weight >= NOTABLE_MIN_WEIGHT) agg.outboundSevere++;
      }
      if (isDst) agg.asDst++;

      // The counterpart endpoint (the "other side" of the alert).
      const peer = isSrc ? a.dstIp : a.srcIp;
      if (peer && peer !== host && isIP(peer) > 0) {
        const acc = agg.peers.get(peer) ?? {
          count: 0,
          internal: isPrivate(peer),
          severityMax: "info" as Severity,
          lastSeen: a.time,
        };
        acc.count++;
        acc.severityMax = maxSeverity(acc.severityMax, sev);
        if (a.time > acc.lastSeen) acc.lastSeen = a.time;
        agg.peers.set(peer, acc);
      }

      if (a.time < agg.firstSeen) agg.firstSeen = a.time;
      if (a.time > agg.lastSeen) agg.lastSeen = a.time;
      if (action === "blocked") agg.blockedCount++;
      else if (action === "detected") agg.detectedCount++;
      if ((triageStore.get(a.id)?.status ?? "open") === "open") agg.openCount++;
      agg.samples.push({ id: a.id, time: a.time });
    }
  }

  const assets: AssetEntry[] = [...byHost.values()].map((agg) => {
    const signatures: AssetSignature[] = [...agg.sigCounts.entries()]
      .map(([signature, count]) => ({ signature, count, severityMax: agg.sigMaxSev.get(signature) ?? "info" }))
      .sort((x, y) => y.count - x.count || x.signature.localeCompare(y.signature))
      .slice(0, DEFAULT_TOP_SIGS);
    const peers: AssetPeer[] = [...agg.peers.entries()]
      .map(([ip, acc]) => ({
        ip,
        count: acc.count,
        internal: acc.internal,
        severityMax: acc.severityMax,
        lastSeen: acc.lastSeen,
        blocked: blockStore.has(ip),
      }))
      .sort((x, y) => y.count - x.count || y.lastSeen - x.lastSeen)
      .slice(0, DEFAULT_TOP_PEERS);
    const externalPeerCount = [...agg.peers.values()].filter((p) => !p.internal).length;
    const bySeverity = SEVERITY_ORDER.map((severity) => ({ severity, count: agg.bySev.get(severity) ?? 0 })).filter(
      (x) => x.count > 0,
    );
    const spanMs = agg.lastSeen - agg.firstSeen;
    const watchEntry = watchStore.match(agg.ip);
    const safe = safeStore.has(agg.ip);
    const watched = watchStore.has(agg.ip);
    const riskScore = scoreAsset({
      severityMax: agg.severityMax,
      alertCount: agg.alertCount,
      externalPeerCount,
      signatureCount: agg.sigCounts.size,
      outboundSevere: agg.outboundSevere,
      blockedCount: agg.blockedCount,
      safe,
      watched,
    });
    const posture = classifyPosture({
      alertCount: agg.alertCount,
      severityMax: agg.severityMax,
      asSrc: agg.asSrc,
      outboundSevere: agg.outboundSevere,
    });
    const sampleAlertIds = agg.samples
      .sort((x, y) => y.time - x.time)
      .slice(0, SAMPLE_IDS)
      .map((s) => s.id);
    return {
      ip: agg.ip,
      alertCount: agg.alertCount,
      severityMax: agg.severityMax,
      bySeverity,
      asSrc: agg.asSrc,
      asDst: agg.asDst,
      outboundSevere: agg.outboundSevere,
      peers,
      externalPeerCount,
      signatures,
      categories: [...agg.categories].sort(),
      firstSeen: agg.firstSeen,
      lastSeen: agg.lastSeen,
      spanMs,
      blockedCount: agg.blockedCount,
      detectedCount: agg.detectedCount,
      openCount: agg.openCount,
      riskScore,
      posture,
      blocked: blockStore.has(agg.ip),
      watched,
      safe,
      watchNote: watchEntry?.note,
      sampleAlertIds,
    };
  });

  // Compromise-suspected hosts always float to the top, then by risk, volume, recency.
  const postureRank: Record<AssetPosture, number> = {
    "compromise-suspected": 3,
    targeted: 2,
    noisy: 1,
    calm: 0,
  };
  assets.sort(
    (a, b) =>
      postureRank[b.posture] - postureRank[a.posture] ||
      b.riskScore - a.riskScore ||
      b.alertCount - a.alertCount ||
      b.lastSeen - a.lastSeen,
  );

  const ranked = assets.slice(0, safeLimit);
  const highlights = writeHighlights(ranked, consideredAlerts);

  const model: AssetsReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    assetCount: assets.length,
    consideredAlerts,
    externalOnlyAlerts,
    highlights,
    assets: ranked,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded asset scoreboard. */
export function assetsFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-assets-${stamp}.md`;
}
