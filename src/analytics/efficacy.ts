/**
 * IPS enforcement-gap / efficacy report — "of everything my gateway *detected*,
 * how much did it actually *block* — and which serious threats are slipping
 * through as detect-only?"
 *
 * Every other offline report answers "what is happening to me?" (which entity,
 * which stage, which cadence, what's new). None of them answers the operational
 * follow-up an analyst asks the moment they trust the detections: *is my IPS
 * actually stopping any of this?* A UDM Pro can run a signature in **IPS** mode
 * (drop the packet → `action: "blocked"`) or **IDS** mode (log only →
 * `action: "detected"`/`"allowed"`/none). A high-severity signature that only
 * ever *detects* is a wide-open hole: the gateway sees the attack land and waves
 * it through. Finding those holes — and quantifying how much of the serious
 * traffic the IPS is really enforcing — is exactly what no existing report does.
 *
 * This module rolls the stored alert history up by **disposition** (blocked vs.
 * passed-through) and produces three complementary views:
 *
 *   1. **Overall posture** — total alerts, the share actually blocked, and the
 *      sharper number: the **severe** (≥ medium) block rate. A 90% overall block
 *      rate means little if every one of the unblocked 10% is critical.
 *
 *   2. **Per-signature enforcement gaps** — for each signature: volume, blocked
 *      vs. passed counts, block rate, peak severity, distinct attackers/targets,
 *      and a one-word **gap** posture. Severe signatures that are *never* blocked
 *      ("open-gap") rank first — these are the detect→block conversions with the
 *      highest payoff. The ranking weights unblocked **severe** volume, not raw
 *      count, so one critical exploit waved through outranks a thousand blocked
 *      scans.
 *
 *   3. **Per-category rollup** — block rate by category, so an operator can see
 *      at a glance whether, say, "Emerging Threats" is enforced while
 *      "Web Application Attack" is mostly watch-only.
 *
 * Honest caveats baked into the output:
 *
 *   - **Disposition fidelity.** Classification leans entirely on the gateway's
 *     `action` field. Alerts with no recorded action are reported as *unknown*
 *     disposition and excluded from block-rate denominators (never silently
 *     counted as either blocked or passed), so the rate reflects only alerts the
 *     gateway actually labelled.
 *   - **Detection ≠ exposure.** A detect-only severe signature is an enforcement
 *     *gap*, not proof of compromise — the traffic may have been benign or
 *     stopped elsewhere. It flags where to tighten policy, not what breached.
 *
 * It is pure in-memory math over alertStore — no SSH, no Claude, no network — so
 * it is safe to call from the dashboard or CLI at any time. Output is both a
 * structured model and a ready-to-paste Markdown document, mirroring report.ts,
 * compare.ts, profile.ts, assets.ts, tuning.ts, watchlist.ts, rhythm.ts,
 * novelty.ts, killchain.ts and beacon.ts.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Coarse disposition of an alert as labelled by the gateway. */
export type Disposition = "blocked" | "passed" | "unknown";

/** One-word enforcement posture for a signature (or category). */
export type GapPosture = "open-gap" | "partial-gap" | "enforced" | "low-priority";

/** Per-signature enforcement rollup. */
export interface SignatureEfficacy {
  signature: string;
  category: string;
  /** Total alerts for this signature in the window (any disposition). */
  count: number;
  /** Alerts the gateway actively blocked/dropped. */
  blocked: number;
  /** Alerts the gateway logged but let through (detected/allowed). */
  passed: number;
  /** Alerts with no recorded action (excluded from {@link blockRate}). */
  unknown: number;
  /**
   * Fraction of *actioned* alerts (blocked + passed) that were blocked, in
   * [0, 1]. `null` when every alert had an unknown disposition.
   */
  blockRate: number | null;
  /** Worst severity seen for this signature. */
  severityMax: Severity;
  /** Alerts at medium severity or worse. */
  severeCount: number;
  /** Severe alerts that were *not* blocked — the raw size of the gap. */
  severeUnblocked: number;
  /** Distinct external (routable) source IPs. */
  attackerCount: number;
  /** Distinct internal (RFC1918) hosts touched. */
  targetCount: number;
  /** Enforcement posture derived from severity + block rate. */
  posture: GapPosture;
  /** Sort weight: unblocked-severe volume scaled by peak severity. */
  gapScore: number;
}

/** Per-category enforcement rollup. */
export interface CategoryEfficacy {
  category: string;
  count: number;
  blocked: number;
  passed: number;
  unknown: number;
  blockRate: number | null;
  severeCount: number;
  severeUnblocked: number;
  posture: GapPosture;
}

export interface EfficacyReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalAlerts: number;
  /** Disposition tallies across the whole window. */
  blocked: number;
  passed: number;
  unknown: number;
  /** Overall block rate over actioned alerts, or null if none were actioned. */
  blockRate: number | null;
  /** Severe (≥ medium) alert count and how many of those were blocked. */
  severeTotal: number;
  severeBlocked: number;
  /** Severe block rate over actioned severe alerts, or null. */
  severeBlockRate: number | null;
  /** Distinct signatures flagged open-gap (severe, zero enforcement). */
  openGapCount: number;
  /** Per-signature rollups, worst gap first, truncated to the limit. */
  signatures: SignatureEfficacy[];
  /** True when {@link signatures} was truncated by the limit. */
  signaturesTruncated: boolean;
  /** Per-category rollups, worst gap first (always complete, not truncated). */
  categories: CategoryEfficacy[];
  /** Plain-language call-outs about the report as a whole. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface EfficacyOptions {
  /** Max signatures to list in the gap table (clamped to [1, 500]). */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 25;
/** Block rate at or above which a signature counts as meaningfully enforced. */
const ENFORCED_THRESHOLD = 0.8;

// ----- shared helpers (mirror killchain.ts / novelty.ts) -----

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

function isRoutable(ip: string | undefined): ip is string {
  return !!ip && isIP(ip) > 0 && !isPrivate(ip);
}

/**
 * Map a gateway `action` to a coarse disposition. "blocked"/"dropped"/"reject"
 * are enforcement; "detected"/"allowed"/"pass" are pass-through; anything
 * missing or unrecognised is `unknown` and never inflates a block rate.
 */
export function classifyDisposition(action: string | undefined): Disposition {
  const a = (action ?? "").trim().toLowerCase();
  if (!a) return "unknown";
  if (/block|drop|deny|reject|denied|dropped|blocked/.test(a)) return "blocked";
  if (/detect|allow|pass|accept|logged|alert/.test(a)) return "passed";
  return "unknown";
}

/** Derive the enforcement posture from severity presence and block rate. */
function derivePosture(severeCount: number, blockRate: number | null): GapPosture {
  if (severeCount === 0) return "low-priority";
  if (blockRate === null) return "open-gap"; // severe but nothing actioned at all
  if (blockRate <= 0) return "open-gap";
  if (blockRate >= ENFORCED_THRESHOLD) return "enforced";
  return "partial-gap";
}

const POSTURE_RANK: Record<GapPosture, number> = {
  "open-gap": 3,
  "partial-gap": 2,
  enforced: 1,
  "low-priority": 0,
};

// ----- formatting helpers (mirror killchain.ts) -----

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

function pct(rate: number | null): string {
  return rate === null ? "—" : `${Math.round(rate * 100)}%`;
}

function postureBadge(p: GapPosture): string {
  switch (p) {
    case "open-gap":
      return "🔴 open-gap";
    case "partial-gap":
      return "🟠 partial-gap";
    case "enforced":
      return "🟢 enforced";
    default:
      return "⚪ low-priority";
  }
}

// ----- internal accumulators -----

interface EffAcc {
  count: number;
  blocked: number;
  passed: number;
  unknown: number;
  severeCount: number;
  severeUnblocked: number;
  severityMax: Severity;
  attackers: Set<string>;
  targets: Set<string>;
  category: string;
}

function newEffAcc(category = ""): EffAcc {
  return {
    count: 0,
    blocked: 0,
    passed: 0,
    unknown: 0,
    severeCount: 0,
    severeUnblocked: 0,
    severityMax: "info",
    attackers: new Set(),
    targets: new Set(),
    category,
  };
}

/** Apply one alert to an accumulator. Returns its disposition for reuse. */
function tally(acc: EffAcc, a: StoredAlert): Disposition {
  const disp = classifyDisposition(a.action);
  acc.count++;
  acc.severityMax = maxSeverity(acc.severityMax, a.severity);
  if (disp === "blocked") acc.blocked++;
  else if (disp === "passed") acc.passed++;
  else acc.unknown++;
  if (isSevere(a.severity)) {
    acc.severeCount++;
    if (disp !== "blocked") acc.severeUnblocked++;
  }
  if (isRoutable(a.srcIp)) acc.attackers.add(a.srcIp);
  for (const ip of [a.srcIp, a.dstIp]) {
    if (ip && isIP(ip) > 0 && isPrivate(ip)) acc.targets.add(ip);
  }
  return disp;
}

/** Block rate over *actioned* alerts (blocked + passed); null if none actioned. */
function blockRateOf(blocked: number, passed: number): number | null {
  const actioned = blocked + passed;
  return actioned === 0 ? null : blocked / actioned;
}

function writeHighlights(m: Omit<EfficacyReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (!m.totalAlerts) return out;

  const actioned = m.blocked + m.passed;
  out.push(
    `Overall enforcement: **${m.blocked}** of ${actioned} actioned alert(s) blocked (**${pct(m.blockRate)}**)` +
      (m.unknown ? ` — ${m.unknown} alert(s) had no recorded disposition and are excluded from the rate.` : "."),
  );

  if (m.severeTotal > 0) {
    const verb = (m.severeBlockRate ?? 1) < 0.5 ? "🚨 Severe enforcement" : "Severe enforcement";
    out.push(
      `${verb}: **${m.severeBlocked}** of ${m.severeTotal} severe (≥ medium) alert(s) blocked (**${pct(m.severeBlockRate)}**).`,
    );
  }

  if (m.openGapCount > 0) {
    const worst = m.signatures.find((s) => s.posture === "open-gap");
    out.push(
      `🚨 **${m.openGapCount}** severe signature(s) are **never blocked** (open enforcement gap)` +
        (worst
          ? ` — e.g. \`${clip(worst.signature, 56)}\` (${worst.severeUnblocked} severe hit(s) waved through). Convert detect→block first.`
          : "."),
    );
  }

  const partial = m.signatures.filter((s) => s.posture === "partial-gap").length;
  if (partial) {
    out.push(`${partial} severe signature(s) are only **partially** enforced (some hits still pass) — tighten next.`);
  }

  const worstCat = m.categories.find((c) => c.posture === "open-gap" || c.posture === "partial-gap");
  if (worstCat) {
    out.push(
      `Weakest category: **${worstCat.category}** at ${pct(worstCat.blockRate)} block rate ` +
        `(${worstCat.severeUnblocked} severe hit(s) unblocked).`,
    );
  }
  return out;
}

function renderPostureBar(m: EfficacyReport): string {
  const lines: string[] = [];
  lines.push("```");
  const row = (label: string, value: number, rate: number | null) => {
    const frac = rate ?? 0;
    const barLen = rate === null ? 0 : Math.max(value > 0 ? 1 : 0, Math.round(frac * 24));
    const bar = "█".repeat(barLen).padEnd(24, "·");
    lines.push(`${label.padEnd(20)} ${bar} ${String(value).padStart(5)} blocked (${pct(rate)})`);
  };
  row("All actioned", m.blocked, m.blockRate);
  row("Severe (≥medium)", m.severeBlocked, m.severeBlockRate);
  lines.push("```");
  return lines.join("\n");
}

function renderMarkdown(m: EfficacyReport): string {
  const lines: string[] = [];
  lines.push(`# 🛡️ SecTool IPS Enforcement-Gap / Efficacy Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Alerts:** ${m.totalAlerts} (${m.blocked} blocked · ${m.passed} passed · ${m.unknown} unknown)`);
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.totalAlerts) {
    lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to measure.`);
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Enforcement posture`);
  lines.push("");
  lines.push(renderPostureBar(m));
  lines.push("");

  lines.push(`## Signature enforcement gaps`);
  lines.push("");
  lines.push(
    `_Worst gap first. **Block rate** is over *actioned* alerts (blocked + passed); ` +
      `unknown-disposition alerts are excluded. Posture: ` +
      `${postureBadge("open-gap")} (severe, never blocked) · ${postureBadge("partial-gap")} (severe, some pass) · ` +
      `${postureBadge("enforced")} (≥${Math.round(ENFORCED_THRESHOLD * 100)}% blocked) · ${postureBadge("low-priority")} (not severe)._`,
  );
  lines.push("");
  if (!m.signatures.length) {
    lines.push(`_No signatures in the window._`);
    lines.push("");
  } else {
    lines.push(
      mdTable(
        ["Signature", "Category", "Total", "Blocked", "Passed", "Block rate", "Severe unblk", "Peak", "Posture"],
        m.signatures.map((s) => [
          cell(clip(s.signature, 52)),
          cell(clip(s.category, 24)),
          String(s.count),
          String(s.blocked),
          String(s.passed),
          pct(s.blockRate),
          String(s.severeUnblocked),
          cell(s.severityMax),
          postureBadge(s.posture),
        ]),
      ),
    );
    if (m.signaturesTruncated) {
      lines.push("");
      lines.push(`_…more signatures not shown (raise \`limit\`)._`);
    }
    lines.push("");
  }

  lines.push(`## Category rollup`);
  lines.push("");
  if (!m.categories.length) {
    lines.push(`_No categories in the window._`);
    lines.push("");
  } else {
    lines.push(
      mdTable(
        ["Category", "Total", "Blocked", "Passed", "Block rate", "Severe unblk", "Posture"],
        m.categories.map((c) => [
          cell(clip(c.category, 32)),
          String(c.count),
          String(c.blocked),
          String(c.passed),
          pct(c.blockRate),
          String(c.severeUnblocked),
          postureBadge(c.posture),
        ]),
      ),
    );
    lines.push("");
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Disposition is read from the gateway's recorded **action** — alerts with no ` +
      `action are reported as *unknown* and excluded from block-rate denominators. A detect-only severe signature is ` +
      `an enforcement **gap** (where to tighten policy), not proof of compromise. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the IPS enforcement-gap / efficacy report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link EfficacyOptions}: signature-table `limit` and a `nowMs` pin.
 */
export function buildEfficacy(hours: number, opts: EfficacyOptions = {}): EfficacyReport {
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

  const bySig = new Map<string, EffAcc>();
  const byCat = new Map<string, EffAcc>();
  let blocked = 0;
  let passed = 0;
  let unknown = 0;
  let severeTotal = 0;
  let severeBlocked = 0;
  let severeActioned = 0;

  for (const a of window) {
    const category = a.category || "uncategorized";
    const sigKey = a.signature?.trim() || `(${category})`;

    let sa = bySig.get(sigKey);
    if (!sa) {
      sa = newEffAcc(category);
      bySig.set(sigKey, sa);
    }
    const disp = tally(sa, a);

    let ca = byCat.get(category);
    if (!ca) {
      ca = newEffAcc(category);
      byCat.set(category, ca);
    }
    tally(ca, a);

    if (disp === "blocked") blocked++;
    else if (disp === "passed") passed++;
    else unknown++;

    if (isSevere(a.severity)) {
      severeTotal++;
      if (disp === "blocked") {
        severeBlocked++;
        severeActioned++;
      } else if (disp === "passed") {
        severeActioned++;
      }
    }
  }

  const signatures: SignatureEfficacy[] = [...bySig.entries()].map(([signature, acc]) => {
    const blockRate = blockRateOf(acc.blocked, acc.passed);
    const posture = derivePosture(acc.severeCount, blockRate);
    // Weight the gap by unblocked-severe volume scaled by peak severity so one
    // critical exploit waved through outranks a flood of blocked scans.
    const gapScore = acc.severeUnblocked * (sevRank(acc.severityMax) + 1);
    return {
      signature,
      category: acc.category,
      count: acc.count,
      blocked: acc.blocked,
      passed: acc.passed,
      unknown: acc.unknown,
      blockRate,
      severityMax: acc.severityMax,
      severeCount: acc.severeCount,
      severeUnblocked: acc.severeUnblocked,
      attackerCount: acc.attackers.size,
      targetCount: acc.targets.size,
      posture,
      gapScore,
    };
  });

  signatures.sort((x, y) => {
    const p = POSTURE_RANK[y.posture] - POSTURE_RANK[x.posture];
    if (p) return p;
    if (y.gapScore !== x.gapScore) return y.gapScore - x.gapScore;
    if (y.severeUnblocked !== x.severeUnblocked) return y.severeUnblocked - x.severeUnblocked;
    if (sevRank(y.severityMax) !== sevRank(x.severityMax)) return sevRank(y.severityMax) - sevRank(x.severityMax);
    if (y.count !== x.count) return y.count - x.count;
    return x.signature < y.signature ? -1 : 1;
  });

  const categories: CategoryEfficacy[] = [...byCat.values()]
    .map((acc) => {
      const blockRate = blockRateOf(acc.blocked, acc.passed);
      return {
        category: acc.category,
        count: acc.count,
        blocked: acc.blocked,
        passed: acc.passed,
        unknown: acc.unknown,
        blockRate,
        severeCount: acc.severeCount,
        severeUnblocked: acc.severeUnblocked,
        posture: derivePosture(acc.severeCount, blockRate),
      };
    })
    .sort((x, y) => {
      const p = POSTURE_RANK[y.posture] - POSTURE_RANK[x.posture];
      if (p) return p;
      if (y.severeUnblocked !== x.severeUnblocked) return y.severeUnblocked - x.severeUnblocked;
      if (y.count !== x.count) return y.count - x.count;
      return x.category < y.category ? -1 : 1;
    });

  const openGapCount = signatures.filter((s) => s.posture === "open-gap").length;

  const base: Omit<EfficacyReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalAlerts: window.length,
    blocked,
    passed,
    unknown,
    blockRate: blockRateOf(blocked, passed),
    severeTotal,
    severeBlocked,
    severeBlockRate: severeActioned === 0 ? null : severeBlocked / severeActioned,
    openGapCount,
    signatures: signatures.slice(0, limit),
    signaturesTruncated: signatures.length > limit,
    categories,
  };
  const highlights = writeHighlights(base);
  const model: EfficacyReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded efficacy report. */
export function efficacyFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-efficacy-${stamp}.md`;
}
