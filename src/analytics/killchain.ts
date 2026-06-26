/**
 * Kill-chain / attack-stage coverage report — "how far along the attack
 * lifecycle is what I'm seeing, and has any one host walked the whole chain?"
 *
 * Every other offline report slices the alert history by an *entity* (IP, host,
 * attacker, signature, watched target) or by the *clock* (rhythm). None of them
 * answer the question an analyst asks when deciding whether scattered alerts are
 * background noise or one unfolding intrusion: *which phases of the attack
 * lifecycle are firing — and is any single internal host progressing through
 * them in sequence?* A lone port-scan is routine internet weather; that same
 * scanner's target later showing **exploitation** then **command-and-control**
 * traffic is a breach in motion. Reading that story requires mapping each
 * detection to a kill-chain stage and then watching it per host — exactly what no
 * existing report does.
 *
 * This module classifies every stored alert into one ordered kill-chain stage
 * using a heuristic over its Suricata **classification**, **category**, and
 * **signature** text (the same fields the detector already extracts), then
 * produces two complementary views:
 *
 *   1. **Stage coverage** — per stage: alert volume, distinct attackers and
 *      distinct internal hosts touched, the worst severity reached,
 *      blocked-vs-detected disposition, and the signatures that defined it. This
 *      is the "what are attackers *trying to do* to me?" lens.
 *
 *   2. **Per-host progression** — for every internal host, the *set* of stages it
 *      appears in and the **furthest** stage it reached. A host that shows up in
 *      several successive stages — and especially one seen as the **source** of
 *      command-and-control or exfiltration traffic — is flagged
 *      *compromise-suspected*. Stage depth + furthest stage is a far sharper
 *      compromise signal than raw alert volume, which buries one host walking the
 *      chain under thousands of identical scan hits.
 *
 * Stage taxonomy (a pragmatic, Suricata-friendly collapse of the
 * Lockheed-Martin Cyber Kill Chain / MITRE ATT&CK tactics into five on-chain
 * stages plus an off-chain bucket):
 *
 *   recon     → Reconnaissance        (scans, probes, enumeration)
 *   access    → Delivery / Access     (web attacks, brute force, phishing, logins)
 *   exploit   → Exploitation          (exploits, shellcode, RCE, privilege gain)
 *   c2        → Command & Control      (trojan / CNC / beacon callbacks)
 *   objective → Actions on Objectives (exfiltration, data theft, DoS, ransom)
 *   other     → off-chain             (info / policy / misc — counted, never on the chain)
 *
 * Honest caveats baked into the output:
 *
 *   - **Heuristic mapping.** Stage assignment is keyword-based over free-form
 *     signature text; it is a triage aid, not ground truth. Unclassifiable alerts
 *     land in `other` and are reported as a coverage gap, never silently dropped.
 *   - **Correlation, not causation.** A host appearing in recon *and* c2 is a
 *     lead to investigate, not proof of a completed intrusion — the stages may be
 *     unrelated events that merely share an endpoint.
 *
 * It is pure in-memory math over alertStore — no SSH, no Claude, no network — so
 * it is safe to call from the dashboard or CLI at any time. Output is both a
 * structured model and a ready-to-paste Markdown document, mirroring report.ts,
 * compare.ts, profile.ts, assets.ts, tuning.ts, watchlist.ts, rhythm.ts and
 * novelty.ts.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** The canonical kill-chain stage keys, ordered along the attack lifecycle. */
export type StageKey = "recon" | "access" | "exploit" | "c2" | "objective" | "other";

/** Stage metadata: display title, a one-line meaning, and chain position. */
interface StageMeta {
  key: StageKey;
  title: string;
  blurb: string;
  /** Position on the kill chain (0 = earliest). `other` is off-chain (-1). */
  chainIndex: number;
  /** A glyph used in the per-host progression strip. */
  glyph: string;
}

/**
 * Ordered stage definitions. The array order is the kill-chain order and drives
 * every "furthest stage" comparison; `other` is appended last and is off-chain.
 */
export const STAGES: readonly StageMeta[] = [
  { key: "recon", title: "Reconnaissance", blurb: "Scans, probes, enumeration", chainIndex: 0, glyph: "①" },
  { key: "access", title: "Delivery / Access", blurb: "Web attacks, brute force, phishing, logins", chainIndex: 1, glyph: "②" },
  { key: "exploit", title: "Exploitation", blurb: "Exploits, shellcode, RCE, privilege gain", chainIndex: 2, glyph: "③" },
  { key: "c2", title: "Command & Control", blurb: "Trojan / CNC / beacon callbacks", chainIndex: 3, glyph: "④" },
  { key: "objective", title: "Actions on Objectives", blurb: "Exfiltration, data theft, DoS, ransom", chainIndex: 4, glyph: "⑤" },
  { key: "other", title: "Off-chain", blurb: "Info / policy / misc — not mapped to a stage", chainIndex: -1, glyph: "·" },
];

const STAGE_BY_KEY = new Map<StageKey, StageMeta>(STAGES.map((s) => [s.key, s]));

/**
 * Ordered classifier rules. Each alert is assigned to the **first** matching
 * rule, so rules are ordered most-decisive-first: a "trojan" signature is C2
 * regardless of whether it also mentions a port, an exfil/DoS signature is an
 * objective, and so on down to reconnaissance. The haystack is the lower-cased
 * concatenation of classification + category + signature.
 *
 * Patterns lean on the well-known Suricata classtypes (classification.config)
 * and Emerging Threats category/signature naming so they generalise beyond any
 * single ruleset.
 */
const RULES: ReadonlyArray<{ stage: StageKey; re: RegExp }> = [
  // C2 — strongest compromise signal, matched before objective so a malware
  // callback isn't mis-bucketed by an incidental "download"/"transfer" word.
  { stage: "c2", re: /trojan|command.?and.?control|\bc2\b|\bcnc\b|beacon|botnet|backdoor|malware|implant|cobalt|adware|spyware|coinminer|cryptomin/i },
  // Actions on objectives — exfiltration, theft, destruction, denial of service.
  { stage: "objective", re: /exfil|data.?theft|data.?leak|sensitive.?data|\bransom|\bwiper\b|\bddos\b|denial.?of.?service|attempted-dos|successful-dos|flood\b/i },
  // Exploitation — code execution, memory corruption, privilege gain.
  { stage: "exploit", re: /exploit|shellcode|shell.?code|buffer.?overflow|overflow|\brce\b|remote.?code|code.?execution|deserial|attempted-admin|successful-admin|successful-user|privilege|system-call-detect|sql.?injection|\bsqli\b|command.?injection/i },
  // Delivery / initial access — web app attacks, credential abuse, phishing.
  { stage: "access", re: /web.?application.?attack|web.?application.?activity|web_specific_apps|web_server|attempted-user|brute.?force|\bbrute\b|credential|default-login|login|phish|\bxss\b|cross.?site|directory.?travers|\blfi\b|\brfi\b|file.?upload|user-agent.*attack/i },
  // Reconnaissance — scans, probes, sweeps, enumeration.
  { stage: "recon", re: /\bscan\b|recon|portmap|probe|sweep|enumerat|fingerprint|nmap|masscan|port.?scan|network.?scan|host.?sweep|discovery/i },
  // Explicit "definitely not a stage" classtypes fall through to `other` below.
];

/** Aggregate stats for one stage across the window. */
export interface StageBucket {
  key: StageKey;
  title: string;
  blurb: string;
  chainIndex: number;
  /** Total alerts mapped to this stage. */
  count: number;
  /** Distinct external (routable) source IPs seen at this stage. */
  attackerCount: number;
  /** Distinct internal (RFC1918) hosts touched at this stage. */
  internalHostCount: number;
  /** Worst severity observed at this stage. */
  severityMax: Severity;
  /** Alerts at medium severity or worse. */
  severeCount: number;
  /** Alerts the gateway actively blocked. */
  blockedCount: number;
  /** Most frequent signatures defining this stage (top few). */
  topSignatures: Array<{ signature: string; count: number }>;
}

/** One internal host's walk through the kill chain. */
export interface HostProgression {
  ip: string;
  /** Total alerts (any stage) involving this host. */
  alertCount: number;
  /** On-chain stage keys this host appears in, in kill-chain order. */
  stages: StageKey[];
  /** How many distinct on-chain stages it reached (its progression depth). */
  depth: number;
  /** The furthest stage reached (highest chainIndex), or null if only off-chain. */
  furthestStage: StageKey | null;
  /** Worst severity across this host's alerts. */
  severityMax: Severity;
  /**
   * True when this host was the **source** of a C2 or objective-stage alert —
   * the sharpest "this box is compromised and acting" signal.
   */
  outboundLateStage: boolean;
  /** One-word posture derived from depth + furthest stage + outbound late stage. */
  posture: "compromise-suspected" | "progressing" | "targeted" | "noise";
}

export interface KillChainReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalAlerts: number;
  /** Alerts that mapped to a real on-chain stage (excludes `other`). */
  onChainAlerts: number;
  /** Distinct on-chain stages that fired (0–5) — the breadth of the campaign. */
  stagesCovered: number;
  /** The furthest stage reached by *any* activity in the window, or null. */
  deepestStage: StageKey | null;
  /** Per-stage rollups, in kill-chain order (always all six buckets). */
  buckets: StageBucket[];
  /** Internal hosts ranked worst-first by progression, truncated to the limit. */
  hosts: HostProgression[];
  /** True when {@link hosts} was truncated by the limit. */
  hostsTruncated: boolean;
  /** Plain-language call-outs about the report as a whole. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface KillChainOptions {
  /** Max internal hosts to list in the progression table (clamped to [1, 500]). */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 25;
const TOP_SIGNATURES = 5;

// ----- shared helpers (mirror assets.ts / novelty.ts) -----

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

function isSevere(s: string | undefined): boolean {
  return sevRank(s) >= 2;
}

function isBlocked(action: string | undefined): boolean {
  return (action ?? "").toLowerCase() === "blocked";
}

/** Classify a single alert into its kill-chain stage. */
export function classifyStage(a: Pick<StoredAlert, "classification" | "category" | "signature">): StageKey {
  const hay = `${a.classification ?? ""} ${a.category ?? ""} ${a.signature ?? ""}`.toLowerCase();
  for (const r of RULES) if (r.re.test(hay)) return r.stage;
  return "other";
}

function isRoutable(ip: string | undefined): ip is string {
  return !!ip && isIP(ip) > 0 && !isPrivate(ip);
}

// ----- formatting helpers -----

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

function clip(s: string, max = 48): string {
  const t = s.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

/** Most frequent keys in a tally, ranked, ties broken lexically for stability. */
function topN(map: Map<string, number>, n: number): Array<{ signature: string; count: number }> {
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))
    .slice(0, n)
    .map(([signature, count]) => ({ signature, count }));
}

// ----- internal accumulators -----

interface BucketAcc {
  count: number;
  attackers: Set<string>;
  internalHosts: Set<string>;
  severityMax: Severity;
  severeCount: number;
  blockedCount: number;
  signatures: Map<string, number>;
}

function newBucketAcc(): BucketAcc {
  return {
    count: 0,
    attackers: new Set(),
    internalHosts: new Set(),
    severityMax: "info",
    severeCount: 0,
    blockedCount: 0,
    signatures: new Map(),
  };
}

interface HostAcc {
  ip: string;
  alertCount: number;
  stages: Set<StageKey>;
  severityMax: Severity;
  outboundLateStage: boolean;
}

function newHostAcc(ip: string): HostAcc {
  return { ip, alertCount: 0, stages: new Set(), severityMax: "info", outboundLateStage: false };
}

/** Late-stage = on-chain stages where an internal *source* signals compromise. */
function isLateStage(stage: StageKey): boolean {
  return stage === "c2" || stage === "objective";
}

function derivePosture(h: { depth: number; furthestStage: StageKey | null; outboundLateStage: boolean }): HostProgression["posture"] {
  const furthestIdx = h.furthestStage ? STAGE_BY_KEY.get(h.furthestStage)!.chainIndex : -1;
  if (h.outboundLateStage || (h.depth >= 2 && furthestIdx >= 3)) return "compromise-suspected";
  if (h.depth >= 2) return "progressing";
  if (furthestIdx >= 0) return "targeted";
  return "noise";
}

const POSTURE_RANK: Record<HostProgression["posture"], number> = {
  "compromise-suspected": 3,
  progressing: 2,
  targeted: 1,
  noise: 0,
};

function writeHighlights(m: Omit<KillChainReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (!m.totalAlerts) return out;

  out.push(
    `Activity spans **${m.stagesCovered} of 5** kill-chain stages (${m.onChainAlerts} of ${m.totalAlerts} alerts mapped to a stage).`,
  );

  if (m.deepestStage) {
    const meta = STAGE_BY_KEY.get(m.deepestStage)!;
    const verb = meta.chainIndex >= 3 ? "🚨 Deepest stage reached" : "Deepest stage reached";
    out.push(`${verb}: **${meta.title}** — ${meta.blurb.toLowerCase()}.`);
  }

  const compromised = m.hosts.filter((h) => h.posture === "compromise-suspected");
  if (compromised.length) {
    const worst = compromised[0]!;
    const fs = worst.furthestStage ? STAGE_BY_KEY.get(worst.furthestStage)!.title : "—";
    out.push(
      `🚨 **${compromised.length}** internal host(s) flagged *compromise-suspected* — e.g. \`${worst.ip}\` ` +
        `reached **${fs}** across ${worst.depth} stage(s)${worst.outboundLateStage ? " as the **source** of late-stage traffic" : ""}. Investigate first.`,
    );
  }

  const progressing = m.hosts.filter((h) => h.posture === "progressing").length;
  if (progressing) {
    out.push(`${progressing} host(s) seen in 2+ stages (*progressing*) — worth a look before they advance further.`);
  }

  const other = m.buckets.find((b) => b.key === "other");
  if (other && m.totalAlerts && other.count / m.totalAlerts > 0.5) {
    out.push(
      `⚠️ ${Math.round((other.count / m.totalAlerts) * 100)}% of alerts are **off-chain** (info/policy/unclassified) — ` +
        `the stage view covers only the mapped remainder.`,
    );
  }
  return out;
}

/** Render the compact stage-coverage funnel (one row per on-chain stage). */
function renderFunnel(m: KillChainReport): string {
  const onChain = m.buckets.filter((b) => b.chainIndex >= 0);
  const maxCount = Math.max(1, ...onChain.map((b) => b.count));
  const lines: string[] = [];
  lines.push("```");
  for (const b of onChain) {
    const meta = STAGE_BY_KEY.get(b.key)!;
    const barLen = b.count ? Math.max(1, Math.round((b.count / maxCount) * 24)) : 0;
    const bar = "█".repeat(barLen).padEnd(24, "·");
    lines.push(`${meta.glyph} ${meta.title.padEnd(22)} ${bar} ${String(b.count).padStart(5)}`);
  }
  lines.push("```");
  return lines.join("\n");
}

function renderStageDetail(b: StageBucket): string {
  const lines: string[] = [];
  const meta = STAGE_BY_KEY.get(b.key)!;
  lines.push(`### ${meta.glyph} ${b.title} — ${b.count} alert(s)`);
  lines.push("");
  if (!b.count) {
    lines.push(`_No alerts mapped to this stage._`);
    lines.push("");
    return lines.join("\n");
  }
  lines.push(
    `- **Severity ceiling:** ${b.severityMax} · **severe (≥medium):** ${b.severeCount} · **blocked:** ${b.blockedCount}/${b.count}`,
  );
  lines.push(`- **Distinct external attackers:** ${b.attackerCount} · **internal hosts touched:** ${b.internalHostCount}`);
  if (b.topSignatures.length) {
    lines.push(
      `- **Top signatures:** ${b.topSignatures.map((s) => `${clip(s.signature)} (${s.count})`).join(" · ")}`,
    );
  }
  lines.push("");
  return lines.join("\n");
}

/** A glyph strip showing which stages a host hit, e.g. `①·③④·`. */
function progressionStrip(stages: StageKey[]): string {
  const hit = new Set(stages);
  return STAGES.filter((s) => s.chainIndex >= 0)
    .map((s) => (hit.has(s.key) ? s.glyph : "·"))
    .join("");
}

function postureBadge(p: HostProgression["posture"]): string {
  switch (p) {
    case "compromise-suspected":
      return "🔴 compromise-suspected";
    case "progressing":
      return "🟠 progressing";
    case "targeted":
      return "🟡 targeted";
    default:
      return "⚪ noise";
  }
}

function renderMarkdown(m: KillChainReport): string {
  const lines: string[] = [];
  lines.push(`# ⛓️ SecTool Kill-Chain / Attack-Stage Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Alerts:** ${m.totalAlerts} (${m.onChainAlerts} mapped to a stage)`);
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.totalAlerts) {
    lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to map.`);
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Stage coverage`);
  lines.push("");
  lines.push(renderFunnel(m));
  lines.push("");
  for (const b of m.buckets) {
    if (b.key === "other") continue; // off-chain summarised separately below
    lines.push(renderStageDetail(b));
  }
  const other = m.buckets.find((b) => b.key === "other");
  if (other && other.count) {
    lines.push(
      `> **Off-chain:** ${other.count} alert(s) (info / policy / unmapped signatures) were not placed on the kill chain.`,
    );
    lines.push("");
  }

  lines.push(`## Internal host progression`);
  lines.push("");
  lines.push(
    `_Stages each internal host appears in (${STAGES.filter((s) => s.chainIndex >= 0).map((s) => `${s.glyph}=${s.title}`).join(", ")}), ` +
      `ranked worst-first. Depth = distinct on-chain stages reached._`,
  );
  lines.push("");
  if (!m.hosts.length) {
    lines.push(`_No internal hosts appeared in any mapped stage._`);
    lines.push("");
  } else {
    lines.push(
      mdTable(
        ["Host", "Chain", "Depth", "Furthest stage", "Alerts", "Peak", "Posture"],
        m.hosts.map((h) => [
          cell(h.ip),
          progressionStrip(h.stages),
          String(h.depth),
          cell(h.furthestStage ? STAGE_BY_KEY.get(h.furthestStage)!.title : "—"),
          String(h.alertCount),
          cell(h.severityMax),
          postureBadge(h.posture),
        ]),
      ),
    );
    if (m.hostsTruncated) {
      lines.push("");
      lines.push(`_…more hosts not shown (raise \`limit\`)._`);
    }
    lines.push("");
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Stage assignment is a **heuristic** over signature/classification text — a triage ` +
      `aid, not ground truth — and a shared endpoint across stages is a lead to investigate, not proof of a completed ` +
      `intrusion. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the kill-chain / attack-stage report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link KillChainOptions}: host-table `limit` and a `nowMs` pin.
 */
export function buildKillChain(hours: number, opts: KillChainOptions = {}): KillChainReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(500, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * 3_600_000;

  const window = alertStore
    .all()
    .filter(
      (a): a is StoredAlert =>
        typeof a.time === "number" && Number.isFinite(a.time) && a.time >= windowStartMs && a.time <= windowEndMs,
    );

  const buckets = new Map<StageKey, BucketAcc>(STAGES.map((s) => [s.key, newBucketAcc()]));
  const hosts = new Map<string, HostAcc>();
  let onChainAlerts = 0;

  for (const a of window) {
    const stage = classifyStage(a);
    const acc = buckets.get(stage)!;
    acc.count++;
    acc.severityMax = maxSeverity(acc.severityMax, a.severity);
    if (isSevere(a.severity)) acc.severeCount++;
    if (isBlocked(a.action)) acc.blockedCount++;
    if (a.signature) acc.signatures.set(a.signature, (acc.signatures.get(a.signature) ?? 0) + 1);
    if (isRoutable(a.srcIp)) acc.attackers.add(a.srcIp);

    const onChain = STAGE_BY_KEY.get(stage)!.chainIndex >= 0;
    if (onChain) onChainAlerts++;

    // Internal endpoints (one host, or two for an internal↔internal lateral move).
    for (const ip of [a.srcIp, a.dstIp]) {
      if (!ip || isIP(ip) <= 0 || !isPrivate(ip)) continue;
      acc.internalHosts.add(ip);
      let h = hosts.get(ip);
      if (!h) {
        h = newHostAcc(ip);
        hosts.set(ip, h);
      }
      h.alertCount++;
      h.severityMax = maxSeverity(h.severityMax, a.severity);
      if (onChain) h.stages.add(stage);
      // The compromise tell: an internal host that is the *source* of a
      // late-stage (C2 / exfil) detection is acting, not merely being targeted.
      if (ip === a.srcIp && isLateStage(stage)) h.outboundLateStage = true;
    }
  }

  const orderedBuckets: StageBucket[] = STAGES.map((meta) => {
    const acc = buckets.get(meta.key)!;
    return {
      key: meta.key,
      title: meta.title,
      blurb: meta.blurb,
      chainIndex: meta.chainIndex,
      count: acc.count,
      attackerCount: acc.attackers.size,
      internalHostCount: acc.internalHosts.size,
      severityMax: acc.severityMax,
      severeCount: acc.severeCount,
      blockedCount: acc.blockedCount,
      topSignatures: topN(acc.signatures, TOP_SIGNATURES),
    };
  });

  const onChainKeysHit = orderedBuckets.filter((b) => b.chainIndex >= 0 && b.count > 0);
  const stagesCovered = onChainKeysHit.length;
  const deepestStage =
    onChainKeysHit.length > 0
      ? onChainKeysHit.reduce((a, b) => (b.chainIndex > a.chainIndex ? b : a)).key
      : null;

  // Finalize per-host progression and rank worst-first.
  const hostList: HostProgression[] = [...hosts.values()]
    .map((h) => {
      const onChainStages = STAGES.filter((s) => s.chainIndex >= 0 && h.stages.has(s.key));
      const stageKeys = onChainStages.map((s) => s.key);
      const furthest = onChainStages.length
        ? onChainStages.reduce((a, b) => (b.chainIndex > a.chainIndex ? b : a))
        : null;
      const depth = stageKeys.length;
      const posture = derivePosture({
        depth,
        furthestStage: furthest?.key ?? null,
        outboundLateStage: h.outboundLateStage,
      });
      return {
        ip: h.ip,
        alertCount: h.alertCount,
        stages: stageKeys,
        depth,
        furthestStage: furthest?.key ?? null,
        severityMax: h.severityMax,
        outboundLateStage: h.outboundLateStage,
        posture,
      };
    })
    // Only surface hosts that touched the chain at all (noise = off-chain only).
    .filter((h) => h.depth > 0)
    .sort((x, y) => {
      const p = POSTURE_RANK[y.posture] - POSTURE_RANK[x.posture];
      if (p) return p;
      if (y.depth !== x.depth) return y.depth - x.depth;
      const fx = x.furthestStage ? STAGE_BY_KEY.get(x.furthestStage)!.chainIndex : -1;
      const fy = y.furthestStage ? STAGE_BY_KEY.get(y.furthestStage)!.chainIndex : -1;
      if (fy !== fx) return fy - fx;
      if (sevRank(y.severityMax) !== sevRank(x.severityMax)) return sevRank(y.severityMax) - sevRank(x.severityMax);
      return y.alertCount - x.alertCount;
    });

  const base: Omit<KillChainReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalAlerts: window.length,
    onChainAlerts,
    stagesCovered,
    deepestStage,
    buckets: orderedBuckets,
    hosts: hostList.slice(0, limit),
    hostsTruncated: hostList.length > limit,
  };
  const highlights = writeHighlights(base);
  const model: KillChainReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded kill-chain report. */
export function killChainFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-killchain-${stamp}.md`;
}
