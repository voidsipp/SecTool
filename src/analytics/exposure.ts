/**
 * Target exposure-breadth / hardening-priority report — "which of my hosts is
 * attacked across the *widest variety* of vectors — and therefore needs broad
 * hardening — versus which is hammered through a single door that one fix shuts?"
 *
 * This is the defender-side mirror of repertoire.ts. Where repertoire ranks each
 * *attacker* by the breadth of its offensive toolkit, this report ranks each
 * *target* by the breadth of the attack surface aimed at it. Every other
 * target-centric report in this project ranks a host by *how much* fire it draws,
 * never by *how many different kinds* of fire:
 *
 *   - assets.ts / targets.ts rank a victim by **volume** and worst **severity** —
 *     a host hammered by a single brute-force signature five thousand times tops
 *     them, even though closing one door (rate-limit SSH) neutralises all of it.
 *   - ports.ts / services.ts roll up by the **service / port** *globally* ("which
 *     service is attacked across the whole estate"), then list the hosts exposing
 *     each — they answer "what is hit", not "which host faces the most *varied*
 *     mix".
 *   - direction.ts / edges.ts keep the source→dest *relationship* and flag the
 *     dangerous orientation (outbound / lateral); cotarget.ts groups hosts by
 *     shared adversaries. None of them rank a single host by the *diversity* of
 *     the threats converging on it.
 *
 * That diversity is the sharpest *hardening-priority* signal the IPS stream holds.
 * A host probed by **one** signature ten thousand times needs **one** control. A
 * host probed by **forty** distinct signatures across recon → web → database →
 * remote-access, by dozens of independent sources, is a *systemically exposed*
 * box: no single block fixes it, and volume rankings — which a quiet, broadly
 * surveyed host never tops — bury it. When that broadly-attacked host is also
 * having its traffic **let through** (high pass rate), it is the single most
 * urgent thing on the estate to firewall.
 *
 * For every destination host over the window this report folds the windowed
 * alerts and measures five orthogonal breadth axes:
 *
 *   - **Service breadth** — distinct *service classes* hit (remote-access, web,
 *     database, file-share, directory, ICS/IoT, …), re-parsing each alert's
 *     destination port from its raw line (shared {@link recoverFlow}) and mapping
 *     it through services.ts's {@link PORT_CLASS}. This is the attack-surface
 *     footprint and the heaviest-weighted axis — it is what you actually harden.
 *   - **Technique breadth** — distinct *signatures* aimed at the host (the
 *     concrete exploits / probes).
 *   - **Class breadth** — distinct Suricata *classifications* (threat classes),
 *     resolved exactly as classify.ts / repertoire.ts resolve them.
 *   - **Stage breadth** — distinct *kill-chain stages* reached against the host
 *     (recon → access → exploit → c2 → objective), via the same
 *     {@link classifyStage} heuristic killchain.ts uses, plus the **furthest**
 *     stage — a host already being driven to exploitation/C2 is past recon.
 *   - **Adversary breadth** — distinct *source* IPs attacking it (is the variety
 *     one busy actor, or a crowd?).
 *
 * From those it computes a 0–100 **exposure-breadth score** (service breadth
 * weighted heaviest, then technique, class and stage breadth, a small adversary
 * and worst-severity nudge) and assigns a one-word **tier**:
 *
 *   - **broad** — exposed across **≥3 service classes** or **≥3 threat classes**:
 *     a systemic attack surface that needs a hardening *program*, not a one-off
 *     block. The highest-priority bucket.
 *   - **multi** — **2 service classes**, **≥4 signatures**, or **≥2 kill-chain
 *     stages**: more than one door under attack, worth a closer look.
 *   - **focused** — a single service but **multiple signatures / classes**:
 *     varied probing of one surface (one service to harden well).
 *   - **pinpoint** — minimal breadth: one signature through one door — the long
 *     tail a single control resolves.
 *
 * Hosts are ranked by exposure-breadth score (not volume) so the quietly,
 * broadly-surveyed crown jewel floats above the loud single-signature flood. Each
 * row also carries a compact **stage strip** (①②③④⑤ lit for the stages reached),
 * the blocked-vs-passed split (a broadly-attacked host whose traffic is *let
 * through* is the worst case), worst severity, the top service class / signature,
 * a 🔥 flag when any hit service is a should-never-be-exposed class, and
 * blocklist / watchlist / safelist membership of the host itself.
 *
 * Honest caveats baked into the output:
 *
 *   - **Service breadth needs ports.** The destination port is re-parsed from the
 *     raw line, not stored; alerts whose raw text carries no recoverable port
 *     contribute to every *other* axis but not to service breadth (the unparsed
 *     count is reported so thin port coverage is visible, not silent).
 *   - **Stage & class are heuristics.** The kill-chain stage is a regex over
 *     classification + category + signature (shared with killchain.ts); the threat
 *     class is Suricata's own `classification` (or the coarser `category`). Both
 *     can mis-bucket an oddly-named rule, so the raw distinct counts are always
 *     shown beside the derived tier.
 *   - **Targets, not just your hosts.** Direction is inferred from RFC1918 /
 *     loopback classification; an internal flag marks the hosts you most likely
 *     own, but NAT / shared egress can blur it. The highlights lead with internal
 *     hosts because those are what you harden.
 *   - **Alerts, not full flows.** SecTool stores IPS *detections*; a vector that
 *     never tripped a rule is invisible, so exposure breadth is a lower bound.
 *   - **Window-bounded & store-capped.** A long look-back can hit the store's
 *     history cap and undercount breadth.
 *
 * Pure in-memory math over alertStore (plus blocklist / watchlist / safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring repertoire.ts,
 * ports.ts, services.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { classifyStage, STAGES, type StageKey } from "./killchain.ts";
import { recoverFlow } from "./ports.ts";
import { PORT_CLASS, SERVICE_CLASS_META, type ServiceClassId } from "./services.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** The four exposure-breadth tiers a target host can fall into. */
export type ExposureTier = "broad" | "multi" | "focused" | "pinpoint";

/** Blocked / passed / unknown disposition split for a target. */
export interface ExposureDisposition {
  /** Alerts the gateway actively blocked / dropped before they reached the host. */
  blocked: number;
  /** Alerts the gateway logged but let through to the host (detected / allowed). */
  passed: number;
  /** Alerts with no recorded action (excluded from {@link passRate}). */
  unknown: number;
  /**
   * Fraction of *actioned* (blocked + passed) alerts let through, 0..1 (4dp), or
   * null when nothing was actioned. High on a broadly-attacked host means its
   * varied incoming fire is reaching it unblocked — the worst case.
   */
  passRate: number | null;
}

/** Per-target exposure-breadth metrics over the window. */
export interface ExposureTarget {
  /** The destination (target) IP. */
  ip: string;
  /** True when the target is one of our own hosts (RFC1918 / loopback / …). */
  internal: boolean;
  /** The assigned exposure tier (see {@link ExposureTier}). */
  tier: ExposureTier;
  /** 0–100 exposure-breadth score — the ranking key. */
  exposure: number;
  /** Distinct service classes attacked on this host (the attack-surface footprint). */
  distinctServices: number;
  /** The hit service-class ids, most-attacked first. */
  serviceClasses: ServiceClassId[];
  /** True when any hit service class is a should-never-be-exposed (high-value) class. */
  highValueExposed: boolean;
  /** Distinct signatures (techniques) aimed at this host. */
  distinctSignatures: number;
  /** Distinct threat classifications (classes) aimed at this host. */
  distinctClasses: number;
  /** Distinct on-chain kill-chain stages reached against this host (0–5). */
  distinctStages: number;
  /** The on-chain stage keys reached, in kill-chain order. */
  stages: StageKey[];
  /** The furthest stage reached (highest chain position), or null if only off-chain. */
  furthestStage: StageKey | null;
  /** Distinct source IPs (adversaries) that attacked this host. */
  distinctSources: number;
  /** Total alerts targeting this host in the window. */
  count: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Severity-weighted score (Σ SEVERITY_WEIGHT) — a secondary signal. */
  score: number;
  /** Worst severity seen against this host. */
  severityMax: Severity;
  /** Display label of the most-attacked service class, if any. */
  topService?: string;
  /** The most-frequent signature aimed at this host, if any. */
  topSignature?: string;
  /** Blocked / passed / unknown disposition split. */
  disposition: ExposureDisposition;
  /** The target IP is on the blocklist. */
  blocked: boolean;
  /** The target IP is on the watchlist. */
  watched: boolean;
  /** The target IP is marked safe. */
  safe: boolean;
}

/** Count of targets falling into each tier (the headline distribution). */
export interface ExposureTierCounts {
  broad: number;
  multi: number;
  focused: number;
  pinpoint: number;
}

export interface ExposureReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts carrying a valid destination IP (the analysable set). */
  targetedAlerts: number;
  /** Of those, alerts whose raw line yielded a recoverable destination port. */
  portMappedAlerts: number;
  /** Of those, alerts that mapped to a real on-chain kill-chain stage. */
  onChainAlerts: number;
  /** Distinct destination IPs analysed (passed the min-alerts floor). */
  distinctTargets: number;
  /** How many targets fell into each tier. */
  tierCounts: ExposureTierCounts;
  /** Per-target exposure rows, most broadly-exposed first. */
  targets: ExposureTarget[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface ExposureOptions {
  /** Max rows in the per-target table (clamped to [1, 200]). */
  limit?: number;
  /** Minimum alerts a host needs before it is analysed (drops one-off noise). */
  minAlerts?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const DEFAULT_MIN_ALERTS = 2;
const MS_PER_HOUR = 3_600_000;

/** On-chain stages in kill-chain order (excludes the off-chain `other` bucket). */
const ON_CHAIN = STAGES.filter((s) => s.chainIndex >= 0).sort((a, b) => a.chainIndex - b.chainIndex);
const STAGE_INDEX = new Map<StageKey, number>(ON_CHAIN.map((s, i) => [s.key, i]));

// ----- classifiers / helpers (mirror repertoire.ts / ports.ts) ---------------

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

function isSevere(s: string | undefined): boolean {
  return sevRank(s) >= 2; // medium or worse
}

function weightOf(s: string | undefined): number {
  return SEVERITY_WEIGHT[(s as Severity) ?? "info"] ?? SEVERITY_WEIGHT.info;
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

function clip(s: string, max = 36): string {
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

/**
 * Resolve the threat-class label for an alert. Prefers the Suricata
 * `classification`; falls back to the coarser event `category`; failing both an
 * explicit "(unclassified)" bucket so nothing is silently dropped. Mirrors the
 * resolution in classify.ts / repertoire.ts so the reports agree on a "class".
 */
function classOf(a: StoredAlert): string {
  const cls = (a.classification ?? "").trim();
  if (cls) return cls;
  const cat = (a.category ?? "").trim();
  if (cat) return cat;
  return "(unclassified)";
}

/** Title of an on-chain stage key, for prose. */
function stageTitle(k: StageKey | null): string {
  if (!k) return "—";
  return STAGES.find((s) => s.key === k)?.title ?? k;
}

/**
 * Render the stage strip: the five on-chain glyphs (①..⑤) with the stages reached
 * against the host lit and the rest dimmed to a middle dot — a kill-chain reach
 * bar that reads at a glance, mirroring killchain.ts / repertoire.ts.
 */
function stageStrip(reached: Set<StageKey>): string {
  return ON_CHAIN.map((s) => (reached.has(s.key) ? s.glyph : "·")).join("");
}

/** Human label + emoji for a tier, ordered by exposure breadth. */
function tierLabel(t: ExposureTier): string {
  switch (t) {
    case "broad":
      return "🎯 broad";
    case "multi":
      return "🧰 multi";
    case "focused":
      return "🔧 focused";
    case "pinpoint":
      return "• pinpoint";
  }
}

/**
 * Assign an exposure tier from the breadth axes. Service-class breadth is the
 * decisive axis (the count of distinct doors under attack *is* the hardening
 * scope here); threat-class, technique and stage breadth refine the rest.
 */
function classifyTier(
  services: number,
  classes: number,
  signatures: number,
  stages: number,
): ExposureTier {
  if (services >= 3 || classes >= 3) return "broad";
  if (services === 2 || signatures >= 4 || stages >= 2) return "multi";
  if (signatures >= 2 || classes >= 2) return "focused";
  return "pinpoint";
}

/**
 * Compute the 0–100 exposure-breadth score from the breadth axes + worst severity.
 * Weights (max contribution): service breadth 30, technique breadth 25, class
 * breadth 18, stage breadth 15, adversary breadth 7, severity 5 — summing to 100
 * at full saturation. Service breadth dominates because the count of distinct
 * services under attack is the size of the hardening job; volume is deliberately
 * absent so a quiet, broadly-surveyed host outranks a loud single-signature flood.
 */
function exposureScore(
  distinctServices: number,
  distinctSignatures: number,
  distinctClasses: number,
  distinctStages: number,
  distinctSources: number,
  severityMax: Severity,
): number {
  const svcPts = (Math.min(distinctServices, 6) / 6) * 30;
  const techPts = (Math.min(distinctSignatures, 10) / 10) * 25;
  const classPts = (Math.min(distinctClasses, 6) / 6) * 18;
  const stagePts = (Math.min(distinctStages, ON_CHAIN.length) / ON_CHAIN.length) * 15;
  // Adversary breadth is log-scaled so a crowd does not dwarf the variety axes.
  const srcPts = Math.min(7, Math.log2(distinctSources + 1) * 2);
  const sevPts = (sevRank(severityMax) / (SEVERITY_ORDER.length - 1)) * 5;
  return Math.max(0, Math.min(100, Math.round(svcPts + techPts + classPts + stagePts + srcPts + sevPts)));
}

// ----- aggregation ----------------------------------------------------------

interface TargetAcc {
  count: number;
  score: number;
  severe: number;
  sources: Set<string>;
  stages: Set<StageKey>;
  classes: Set<string>;
  signatures: Set<string>;
  serviceCounts: Map<ServiceClassId, number>;
  sigCounts: Map<string, number>;
  blocked: number;
  passed: number;
  unknown: number;
  severityMax: Severity;
}

function newTargetAcc(): TargetAcc {
  return {
    count: 0,
    score: 0,
    severe: 0,
    sources: new Set(),
    stages: new Set(),
    classes: new Set(),
    signatures: new Set(),
    serviceCounts: new Map(),
    sigCounts: new Map(),
    blocked: 0,
    passed: 0,
    unknown: 0,
    severityMax: "info",
  };
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  m: { distinctTargets: number; portMappedAlerts: number; targetedAlerts: number },
  tierCounts: ExposureTierCounts,
  targets: ExposureTarget[],
): string[] {
  const out: string[] = [];
  if (!targets.length) return out;

  // Overall tier distribution — how much of the estate is broadly exposed.
  const wide = tierCounts.broad + tierCounts.multi;
  out.push(
    `🛡️ Over the last ${hours}h, **${m.distinctTargets} host(s)** drew fire; **${wide}** face a *varied* attack ` +
      `surface (${tierCounts.broad} broad · ${tierCounts.multi} multi-vector), ${tierCounts.focused} focused and ` +
      `${tierCounts.pinpoint} pinpoint (single-door) target(s).`,
  );

  // The most broadly-exposed host overall — the lead to harden first.
  const lead = targets[0]!;
  out.push(
    `🥇 Widest attack surface is \`${lead.ip}\`${lead.internal ? " *(internal)*" : " *(external/unowned)*"} — ` +
      `**${tierLabel(lead.tier)}**, score **${lead.exposure}/100**: ${lead.distinctServices} service class(es), ` +
      `${lead.distinctSignatures} signature(s), ${lead.distinctClasses} threat class(es) and ${lead.distinctStages} ` +
      `kill-chain stage(s) from ${lead.distinctSources} source(s) across ${lead.count} alert(s).`,
  );

  // Broad-surface internal hosts — the systemic hardening priority.
  const broadInternal = targets.filter((t) => t.internal && t.tier === "broad");
  if (broadInternal.length) {
    const b = broadInternal[0]!;
    out.push(
      `🎯 **${broadInternal.length} internal host(s)** are under *broad* attack (≥3 service classes or threat ` +
        `classes) — no single block fixes a systemic surface. \`${b.ip}\` spans ${b.distinctServices} service ` +
        `class(es)${b.topService ? ` (top: ${b.topService})` : ""}; treat it as a hardening *program*, not a one-off.`,
    );
  }

  // A broadly-attacked host whose varied fire is being let through — worst case.
  const leaky = targets
    .filter((t) => t.tier !== "pinpoint" && t.disposition.passRate !== null && t.disposition.passed >= 3)
    .sort((a, b) => (b.disposition.passRate ?? 0) - (a.disposition.passRate ?? 0))[0];
  if (leaky && (leaky.disposition.passRate ?? 0) >= 0.5) {
    out.push(
      `⚠️ \`${leaky.ip}\`'s varied incoming fire is **${pct(leaky.disposition.passRate!)} let through** ` +
        `(${leaky.disposition.passed} actioned alerts passed across ${leaky.distinctSignatures} signature(s)). A ` +
        `broadly-probed host reached unblocked is the worst case — firewall the exposed services and confirm.`,
    );
  }

  // A host being driven deep into the kill chain — past recon into exploit/C2.
  const deep = targets
    .filter((t) => t.furthestStage && (STAGE_INDEX.get(t.furthestStage) ?? 0) >= 2)
    .sort((a, b) => (STAGE_INDEX.get(b.furthestStage!) ?? 0) - (STAGE_INDEX.get(a.furthestStage!) ?? 0))[0];
  if (deep) {
    out.push(
      `🚨 \`${deep.ip}\`${deep.internal ? " *(internal)*" : ""} has been driven to **${stageTitle(deep.furthestStage)}** ` +
        `(${deep.distinctStages} stage(s) reached) — past reconnaissance into hands-on attack stages. Investigate ` +
        `whether the host held.`,
    );
  }

  // High-value (should-never-be-exposed) services under varied attack.
  const crown = targets.find((t) => t.highValueExposed && t.tier !== "pinpoint");
  if (crown) {
    out.push(
      `🔥 \`${crown.ip}\` exposes a should-never-face-the-internet service${crown.topService ? ` (${crown.topService})` : ""} ` +
        `under varied attack (${crown.distinctSignatures} signature(s)) — a crown-jewel surface; confirm it is meant to ` +
        `be reachable at all before tuning detections.`,
    );
  }

  // Port-coverage honesty — service breadth is only as good as recoverable ports.
  if (m.targetedAlerts > 0) {
    const frac = m.portMappedAlerts / m.targetedAlerts;
    if (frac < 0.5) {
      out.push(
        `ℹ️ Only **${pct(frac)} of targeted alerts carried a recoverable destination port** — *service* breadth is a ` +
          `lower bound (the other breadth axes are unaffected); a host hit through an unprinted port can under-read.`,
      );
    }
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function targetTable(rows: ExposureTarget[]): string {
  return mdTable(
    ["#", "Target", "Tier", "Score", "Svcs", "Reach", "Sigs", "Classes", "Srcs", "Alerts", "Top service", "Passed", "Flags"],
    rows.map((t, i) => {
      const reached = new Set(t.stages);
      const flags =
        (t.internal ? "🏠" : "") +
        (t.highValueExposed ? "🔥" : "") +
        (t.blocked ? "⛔" : "") +
        (t.watched ? "👁" : "") +
        (t.safe ? "✅" : "");
      return [
        String(i + 1),
        cell(t.ip),
        cell(tierLabel(t.tier)),
        String(t.exposure),
        String(t.distinctServices),
        stageStrip(reached),
        String(t.distinctSignatures),
        String(t.distinctClasses),
        String(t.distinctSources),
        String(t.count),
        cell(clip(t.topService ?? "—")),
        String(t.disposition.passed),
        flags || "—",
      ];
    }),
  );
}

function renderMarkdown(m: ExposureReport): string {
  const lines: string[] = [];
  lines.push(`# 🛡️ SecTool Target Exposure-Breadth / Hardening-Priority Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** per target host, distinct **service classes** × distinct **signatures** × distinct threat ` +
      `**classes** × distinct kill-chain **stages** (${ON_CHAIN.map((s) => s.glyph).join("")} = ` +
      `${ON_CHAIN.map((s) => s.title.toLowerCase()).join(" → ")}) × distinct **sources**, scored 0–100 (service ` +
      `breadth weighted heaviest) and ranked by exposure breadth, **not volume** · **Targeted alerts:** ` +
      `${m.targetedAlerts} of ${m.totalWindowAlerts} (${m.portMappedAlerts} carried a recoverable port, ` +
      `${m.onChainAlerts} mapped to a stage)`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.targets.length) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but none had a usable destination IP and ` +
          `enough volume to profile an exposure surface (min ${DEFAULT_MIN_ALERTS} alerts/host by default).`,
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

  lines.push(`## Hosts by attack-surface breadth`);
  lines.push("");
  lines.push(targetTable(m.targets));
  lines.push("");
  lines.push(
    `**Legend:** _Tier_ — **🎯 broad** (≥3 service or threat classes: a systemic surface needing a hardening ` +
      `program) · **🧰 multi** (2 service classes, ≥4 signatures or ≥2 kill-chain stages: more than one door) · ` +
      `**🔧 focused** (one service, many signatures/classes: one surface to harden well) · **• pinpoint** (one ` +
      `signature through one door: a single point fix). _Score_ 0–100 weights service breadth heaviest, then ` +
      `technique, class and stage breadth, with small adversary-count and worst-severity nudges — **volume is ` +
      `deliberately excluded** so a quiet, broadly-surveyed host outranks a loud single-signature flood. _Svcs_ = ` +
      `distinct service classes attacked. _Reach_ lights the kill-chain stages reached against the host ` +
      `(${ON_CHAIN.map((s) => `${s.glyph} ${s.title.toLowerCase()}`).join(" · ")}). **Flags:** 🏠 internal host · ` +
      `🔥 a should-never-be-exposed service was hit · ⛔ blocked · 👁 watched · ✅ safe.`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. **Volume is not breadth**: this report deliberately ranks how *many different ` +
      `kinds* of attack converge on a host, not how loud they are — a host hammered by one signature needs one ` +
      `control, a host probed across many services needs a hardening program. **Service breadth needs ports**: the ` +
      `destination port is re-parsed from each raw line, so an alert with no recoverable port still counts toward ` +
      `every other axis but not the service count (port coverage is reported above). **Tier, stage and class are ` +
      `heuristics** — the kill-chain stage is a regex over classification + category + signature (shared with the ` +
      `kill-chain report) and the threat class is Suricata's own \`classification\` (or the coarser \`category\`), so ` +
      `the raw distinct counts are shown for second-guessing. The internal flag (RFC1918 / loopback) marks the hosts ` +
      `you most likely own, but NAT can blur it. These are IPS **detections**, not full flows — a vector that never ` +
      `tripped a rule is invisible, so breadth is a lower bound, and a long look-back can hit the store's history ` +
      `cap. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the target exposure-breadth / hardening-priority report from the stored
 * alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link ExposureOptions}: `limit`, `minAlerts`, and a `nowMs` pin
 *              for deterministic tests.
 */
export function buildExposure(hours: number, opts: ExposureOptions = {}): ExposureReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minAlerts = Math.max(1, Math.floor(opts.minAlerts ?? DEFAULT_MIN_ALERTS));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const targets = new Map<string, TargetAcc>();
  let targeted = 0;
  let portMapped = 0;
  let onChain = 0;

  for (const a of windowed) {
    const dst = validIp(a.dstIp);
    if (!dst) continue;
    targeted++;

    const acc = targets.get(dst) ?? newTargetAcc();
    if (!targets.has(dst)) targets.set(dst, acc);
    acc.count++;
    acc.score += weightOf(a.severity);
    acc.severityMax = maxSeverity(acc.severityMax, a.severity);
    if (isSevere(a.severity)) acc.severe++;

    const src = validIp(a.srcIp);
    if (src) acc.sources.add(src);

    const stage = classifyStage(a);
    if (STAGE_INDEX.has(stage)) {
      onChain++;
      acc.stages.add(stage);
    }

    acc.classes.add(classOf(a));

    const sig = (a.signature ?? "").trim();
    if (sig) {
      acc.signatures.add(sig);
      acc.sigCounts.set(sig, (acc.sigCounts.get(sig) ?? 0) + 1);
    }

    // Service breadth: re-parse the destination port and map it to a class.
    const flow = recoverFlow(a.raw);
    if (flow) {
      portMapped++;
      const svc: ServiceClassId = PORT_CLASS[flow.dstPort] ?? "other";
      acc.serviceCounts.set(svc, (acc.serviceCounts.get(svc) ?? 0) + 1);
    }

    const disp = classifyDisposition(a.action);
    if (disp === "blocked") acc.blocked++;
    else if (disp === "passed") acc.passed++;
    else acc.unknown++;
  }

  const tierCounts: ExposureTierCounts = { broad: 0, multi: 0, focused: 0, pinpoint: 0 };

  const targetList: ExposureTarget[] = [...targets.entries()]
    .filter(([, acc]) => acc.count >= minAlerts)
    .map(([ip, acc]) => {
      const orderedStages = [...acc.stages].sort(
        (x, y) => (STAGE_INDEX.get(x) ?? 0) - (STAGE_INDEX.get(y) ?? 0),
      );
      const furthestStage = orderedStages.length ? orderedStages[orderedStages.length - 1]! : null;
      // Service classes most-attacked first (count desc, then id for stability).
      const serviceClasses = [...acc.serviceCounts.entries()]
        .sort((x, y) => y[1] - x[1] || (x[0] < y[0] ? -1 : 1))
        .map(([id]) => id);
      const distinctServices = serviceClasses.length;
      const distinctSignatures = acc.signatures.size;
      const distinctClasses = acc.classes.size;
      const distinctStages = orderedStages.length;
      const distinctSources = acc.sources.size;
      const tier = classifyTier(distinctServices, distinctClasses, distinctSignatures, distinctStages);
      tierCounts[tier]++;
      const topServiceId = serviceClasses[0];
      const actioned = acc.blocked + acc.passed;
      return {
        ip,
        internal: isPrivate(ip),
        tier,
        exposure: exposureScore(
          distinctServices,
          distinctSignatures,
          distinctClasses,
          distinctStages,
          distinctSources,
          acc.severityMax,
        ),
        distinctServices,
        serviceClasses,
        highValueExposed: serviceClasses.some((id) => SERVICE_CLASS_META[id].highValue),
        distinctSignatures,
        distinctClasses,
        distinctStages,
        stages: orderedStages,
        furthestStage,
        distinctSources,
        count: acc.count,
        severe: acc.severe,
        score: acc.score,
        severityMax: acc.severityMax,
        topService: topServiceId ? SERVICE_CLASS_META[topServiceId].label : undefined,
        topSignature: topOf(acc.sigCounts),
        disposition: {
          blocked: acc.blocked,
          passed: acc.passed,
          unknown: acc.unknown,
          passRate: actioned ? round4(acc.passed / actioned) : null,
        },
        blocked: blockStore.has(ip),
        watched: watchStore.has(ip),
        safe: safeStore.has(ip),
      } satisfies ExposureTarget;
    })
    // Most broadly-exposed first: score, then service breadth, then severity-weighted
    // magnitude, then volume, then IP for a stable order.
    .sort(
      (x, y) =>
        y.exposure - x.exposure ||
        y.distinctServices - x.distinctServices ||
        y.score - x.score ||
        y.count - x.count ||
        (x.ip < y.ip ? -1 : x.ip > y.ip ? 1 : 0),
    );

  // tierCounts is accumulated across *all* qualifying targets above; the table is
  // then capped to `limit` rows for display without disturbing the totals.
  const cappedTargets = targetList.slice(0, limit);

  const highlights = writeHighlights(
    safeHours,
    { distinctTargets: targetList.length, portMappedAlerts: portMapped, targetedAlerts: targeted },
    tierCounts,
    cappedTargets,
  );

  const model: ExposureReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    targetedAlerts: targeted,
    portMappedAlerts: portMapped,
    onChainAlerts: onChain,
    distinctTargets: targetList.length,
    tierCounts,
    targets: cappedTargets,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded exposure-breadth report. */
export function exposureFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-exposure-${stamp}.md`;
}
