/**
 * Signature severity-stability / label-consistency audit — "**can I trust the
 * `severity` field that every other report sorts, ranks and triages on?**"
 *
 * Almost every report in this project leans on one field: `severity`. risk.ts
 * weights by it, escalation.ts trends it, drift.ts tracks its mix, briefing.ts
 * headlines the high/critical count, and the dashboard colours rows by it. Yet
 * SecTool's severity is not a stored ground-truth label — it is *derived* per
 * alert by `deriveSeverity()` from a blend of Suricata priority, classification,
 * the syslog severity and **whether the packet was blocked**:
 *
 *     /(trojan|malware|exploit|botnet|command|c2|attack)/ → blocked ? "high" : "critical"
 *
 * That last clause is the catch. The *same signature* can land at **high** when
 * the IPS dropped it and **critical** when it was only detected — a clean,
 * explainable flip, but a flip nonetheless. Different priority, a different
 * classification string, or a different syslog level on otherwise-identical
 * traffic produce the same wobble. No existing report measures it. drift.ts asks
 * whether the *global* mean severity is rising over *time*; noise.ts asks which
 * event tuples are *redundant*; classify.ts rolls the threat-*class* mix up. None
 * ask the data-quality question underneath all of them: **is a given signature's
 * severity self-consistent, and if not, why?**
 *
 * This report answers exactly that. For every signature in the window it measures
 * the spread of severities assigned to it and classifies each as:
 *
 *   - **stable** — one severity, always. The field can be trusted at face value.
 *   - **minor** — wobbles between two *adjacent* levels with one clearly dominant
 *     (e.g. mostly high, occasionally medium): real but low-stakes variance.
 *   - **unstable** — spans non-adjacent levels (a `medium`↔`critical` jump) or no
 *     single level holds a majority. Sorting these by severity is misleading.
 *
 * For each non-stable signature it then names the **likely driver** from the
 * fields SecTool actually stores: if splitting the alerts by **enforcement**
 * (blocked vs not) makes each subgroup single-severity, the wobble is the
 * block→`high` / detect→`critical` interaction above — *expected*, not a bug. If
 * splitting by **classification** string does, the upstream rule is emitting
 * different classes. Otherwise the cause is **mixed** (priority / syslog variance
 * buried in the raw line) and warrants a closer look.
 *
 * The headline is a single **severity-trust** number: the share of alert *volume*
 * that sits under stable signatures. "92% of your alert volume has a trustworthy
 * severity; the shaky 8% is almost all the block/detect flip" is a one-sentence
 * confidence statement for every other report in the suite.
 *
 * Honest caveats baked into the output:
 *
 *   - **Variance is not error.** A derived severity *should* differ when the
 *     traffic differs (blocked vs detected is a real distinction). This report
 *     flags inconsistency so you can decide whether it is meaningful or noise —
 *     it does not assert the label is wrong.
 *   - **Driver detection is best-effort.** It only sees the stored `action` and
 *     `classification`; a "mixed" verdict means *those two* fields don't explain
 *     the spread, not that nothing does (priority/syslog live in the raw line).
 *   - **Window- & store-bounded.** A short look-back may show a signature at only
 *     one severity simply because its other face hasn't fired yet; a long one can
 *     hit the alert store's history cap.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network. Output is
 * both a structured model and a ready-to-paste Markdown document, mirroring
 * concentration.ts, drift.ts and the other offline reports.
 */
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** A one-word verdict on how self-consistent a signature's severity is. */
export type StabilityVerdict = "stable" | "minor" | "unstable";

/** The stored field that best explains a signature's severity spread. */
export type InstabilityDriver = "action" | "classification" | "mixed" | "none";

/** Per-signature severity-stability analysis. */
export interface SignatureStability {
  /** The signature string (trimmed). */
  signature: string;
  /** Alerts attributed to this signature in the window. */
  count: number;
  /** Count per severity level, only levels that actually occurred. */
  severityCounts: Partial<Record<Severity, number>>;
  /** Distinct severity levels observed (1 = perfectly stable). */
  distinctSeverities: number;
  /** The most frequent severity. */
  dominantSeverity: Severity;
  /** The dominant severity's share of this signature's alerts, 0..1 (4dp). */
  dominantShare: number;
  /** Lowest severity observed. */
  minSeverity: Severity;
  /** Highest severity observed. */
  maxSeverity: Severity;
  /** Ladder distance between min and max severity (0 = single level, ≤4). */
  spread: number;
  /** Shannon entropy of the severity mix, normalised to 0..1 over the 5-level ladder (4dp). */
  severityEntropy: number;
  /** The one-word stability verdict. */
  verdict: StabilityVerdict;
  /** The field that best explains the spread (only meaningful when not stable). */
  driver: InstabilityDriver;
  /** Human detail for the driver, e.g. "blocked→high · detected→critical". */
  driverDetail?: string;
}

/** Window-level rollup of the per-signature verdicts. */
export interface StabilitySummary {
  /** Distinct signatures analysed (had a usable signature string). */
  signatures: number;
  stableCount: number;
  minorCount: number;
  unstableCount: number;
  /** Alert volume under stable / minor / unstable signatures. */
  stableVolume: number;
  minorVolume: number;
  unstableVolume: number;
  /** Alerts that carried a usable signature key. */
  attributedAlerts: number;
  /** Share of attributed volume under stable signatures, 0..1 (4dp) — the trust score. */
  trustShare: number;
  /** Share of attributed volume under unstable signatures, 0..1 (4dp). */
  shakyShare: number;
  /** Of the non-stable signatures, how many each driver explains. */
  driverBreakdown: Record<InstabilityDriver, number>;
}

export interface StabilityReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  summary: StabilitySummary;
  /** Non-stable signatures, least-stable first (capped to the row limit). */
  unstable: SignatureStability[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface StabilityOptions {
  /** Max rows in the least-stable leaderboard (clamped to [1, 200]). */
  limit?: number;
  /** Ignore signatures with fewer than this many alerts (clamped to [1, 1000]). */
  minCount?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const DEFAULT_MIN_COUNT = 2;
const MS_PER_HOUR = 3_600_000;

/** Dominant-share at/below which a multi-level signature is called unstable. */
const UNSTABLE_DOMINANT = 0.6;

// ----- helpers (mirror concentration.ts / drift.ts) --------------------------

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

function pct(frac: number, dp = 0): string {
  return `${(frac * 100).toFixed(dp)}%`;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
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

/** Human label + emoji for a verdict. */
function verdictLabel(v: StabilityVerdict): string {
  switch (v) {
    case "stable":
      return "✅ stable";
    case "minor":
      return "🟡 minor";
    case "unstable":
      return "🔴 unstable";
  }
}

/** Human label for an instability driver. */
function driverLabel(d: InstabilityDriver): string {
  switch (d) {
    case "action":
      return "enforcement (block/detect)";
    case "classification":
      return "classification";
    case "mixed":
      return "mixed / priority";
    case "none":
      return "—";
  }
}

// ----- severity-distribution maths -------------------------------------------

/**
 * Normalised Shannon entropy of a severity distribution. 0 when a single level
 * holds everything; → 1 as the mix approaches uniform across the full 5-level
 * ladder. Normalised by log2(ladder size) so values are comparable between
 * signatures regardless of how many levels each touches.
 */
function severityEntropy(counts: number[]): number {
  const total = counts.reduce((s, c) => s + c, 0);
  if (total <= 0) return 0;
  let h = 0;
  for (const c of counts) {
    if (c <= 0) continue;
    const p = c / total;
    h -= p * Math.log2(p);
  }
  const max = Math.log2(SEVERITY_ORDER.length);
  return max > 0 ? round4(Math.min(1, h / max)) : 0;
}

/**
 * Classify a signature's stability from its severity spread and dominant share.
 * Single level → stable. Adjacent levels with a clear majority → minor. A
 * non-adjacent jump or no majority → unstable.
 */
function classifyVerdict(distinct: number, spread: number, dominantShare: number): StabilityVerdict {
  if (distinct <= 1) return "stable";
  if (spread >= 2 || dominantShare < UNSTABLE_DOMINANT) return "unstable";
  return "minor";
}

// ----- aggregation -----------------------------------------------------------

interface SigAcc {
  count: number;
  /** severity → count. */
  sev: Map<Severity, number>;
  /** enforcement group ("blocked" | "unenforced") → set of severities seen. */
  byAction: Map<string, Set<Severity>>;
  /** classification string → set of severities seen. */
  byClass: Map<string, Set<Severity>>;
}

function newSigAcc(): SigAcc {
  return { count: 0, sev: new Map(), byAction: new Map(), byClass: new Map() };
}

/** Enforcement bucket: "blocked" for dropped traffic, "unenforced" otherwise. */
function actionGroup(action: string | undefined): string {
  return (action ?? "").toLowerCase() === "blocked" ? "blocked" : "unenforced";
}

function bumpSet(map: Map<string, Set<Severity>>, key: string, sev: Severity): void {
  let s = map.get(key);
  if (!s) {
    s = new Set();
    map.set(key, s);
  }
  s.add(sev);
}

/**
 * Determine which stored field best explains a signature's severity spread. If
 * grouping by enforcement (or classification) leaves every subgroup at a single
 * severity *and* there is more than one subgroup, that field fully accounts for
 * the variance. Enforcement is checked first because the block/detect flip is the
 * known systematic cause in `deriveSeverity()`.
 */
function detectDriver(acc: SigAcc): { driver: InstabilityDriver; detail?: string } {
  const explains = (map: Map<string, Set<Severity>>): boolean =>
    map.size >= 2 && [...map.values()].every((set) => set.size === 1);

  const detailFor = (map: Map<string, Set<Severity>>): string =>
    [...map.entries()]
      .map(([k, set]) => `${k}→${[...set][0]}`)
      .sort()
      .join(" · ");

  if (explains(acc.byAction)) return { driver: "action", detail: detailFor(acc.byAction) };
  if (explains(acc.byClass)) {
    return { driver: "classification", detail: detailFor(acc.byClass) };
  }
  return { driver: "mixed" };
}

/** Build the full {@link SignatureStability} from a raw accumulator. */
function summariseSignature(signature: string, acc: SigAcc): SignatureStability {
  const entries = [...acc.sev.entries()].sort((a, b) => sevRank(a[0]) - sevRank(b[0]));
  const counts = entries.map(([, c]) => c);
  const total = acc.count;

  const severityCounts: Partial<Record<Severity, number>> = {};
  for (const [s, c] of entries) severityCounts[s] = c;

  let dominantSeverity: Severity = entries[0]![0];
  let dominantCount = 0;
  for (const [s, c] of entries) {
    if (c > dominantCount) {
      dominantCount = c;
      dominantSeverity = s;
    }
  }

  const minSeverity = entries[0]![0];
  const maxSeverity = entries[entries.length - 1]![0];
  const spread = sevRank(maxSeverity) - sevRank(minSeverity);
  const distinctSeverities = entries.length;
  const dominantShare = total > 0 ? round4(dominantCount / total) : 0;
  const verdict = classifyVerdict(distinctSeverities, spread, dominantShare);

  let driver: InstabilityDriver = "none";
  let driverDetail: string | undefined;
  if (verdict !== "stable") {
    const d = detectDriver(acc);
    driver = d.driver;
    driverDetail = d.detail;
  }

  return {
    signature,
    count: total,
    severityCounts,
    distinctSeverities,
    dominantSeverity,
    dominantShare,
    minSeverity,
    maxSeverity,
    spread,
    severityEntropy: severityEntropy(counts),
    verdict,
    driver,
    driverDetail,
  };
}

/**
 * Concern score for ranking the least-stable signatures: instability magnitude
 * (spread + entropy) amplified by log-scaled volume, so a wide flip on a busy
 * signature outranks a wide flip seen twice.
 */
function concernScore(s: SignatureStability): number {
  const magnitude = s.spread + s.severityEntropy;
  return magnitude * Math.log10(s.count + 1);
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(
  hours: number,
  summary: StabilitySummary,
  unstable: SignatureStability[],
): string[] {
  const out: string[] = [];
  if (summary.signatures === 0) return out;

  // Headline: the single severity-trust number.
  out.push(
    `🎯 **Severity-trust: ${pct(summary.trustShare)}** of attributed alert volume sits under ` +
      `**${summary.stableCount} stable** signature(s) (always one severity) over the last ${hours}h. ` +
      `${summary.unstableCount} signature(s) are **unstable** and ${summary.minorCount} wobble minorly — ` +
      `together **${pct(summary.shakyShare)}** of the volume has a severity worth a second look.`,
  );

  // Whether the shakiness is the known, expected block/detect flip vs real noise.
  const drivers = summary.driverBreakdown;
  const nonStable = summary.minorCount + summary.unstableCount;
  if (nonStable > 0) {
    if (drivers.action >= drivers.classification && drivers.action >= drivers.mixed && drivers.action > 0) {
      out.push(
        `🔁 The dominant cause is **enforcement**: ${drivers.action} of ${nonStable} non-stable signature(s) flip ` +
          `severity purely on blocked-vs-detected — the expected \`deriveSeverity()\` rule, not a labeling bug. ` +
          `Read their severity *together with* the action field.`,
      );
    } else if (drivers.mixed >= drivers.action && drivers.mixed >= drivers.classification && drivers.mixed > 0) {
      out.push(
        `❓ The dominant cause is **mixed**: ${drivers.mixed} of ${nonStable} non-stable signature(s) are not ` +
          `explained by the stored action or classification — the variance hides in priority / syslog level in the ` +
          `raw line. These are the ones to inspect for genuine inconsistency.`,
      );
    } else if (drivers.classification > 0) {
      out.push(
        `🏷 The dominant cause is **classification**: ${drivers.classification} of ${nonStable} non-stable ` +
          `signature(s) carry different classification strings on different alerts, dragging severity with them.`,
      );
    }
  }

  // The single worst high-volume offender, with its actual range.
  const worst = unstable.find((s) => s.verdict === "unstable");
  if (worst) {
    out.push(
      `🔴 Least-trustworthy busy signature: \`${clip(worst.signature, 60)}\` fires **${worst.count}×** spanning ` +
        `**${worst.minSeverity} → ${worst.maxSeverity}** (${worst.distinctSeverities} levels, dominant ` +
        `${worst.dominantSeverity} only ${pct(worst.dominantShare)}). ` +
        (worst.driver === "mixed"
          ? `No stored field explains it — inspect the raw priority.`
          : `Driver: ${driverLabel(worst.driver)}.`),
    );
  }

  // A signature that reaches critical/high but only sometimes is a triage trap.
  const triageTrap = unstable.find(
    (s) => s.verdict === "unstable" && sevRank(s.maxSeverity) >= sevRank("high") && s.spread >= 2,
  );
  if (triageTrap && triageTrap !== worst) {
    out.push(
      `⚠️ \`${clip(triageTrap.signature, 60)}\` can land as high as **${triageTrap.maxSeverity}** but as low as ` +
        `**${triageTrap.minSeverity}** — ranking it by a single severity will either over- or under-triage it.`,
    );
  }

  if (summary.unstableCount === 0 && summary.minorCount === 0) {
    out.push(
      `✅ Every signature in the window maps to exactly one severity — the severity axis is fully self-consistent ` +
        `here, so every severity-ranked report can be read at face value.`,
    );
  }

  return out;
}

// ----- markdown --------------------------------------------------------------

/** Compact "high×3 · critical×1" rendering of a severity distribution. */
function sevMix(s: SignatureStability): string {
  return (SEVERITY_ORDER as readonly Severity[])
    .filter((lvl) => (s.severityCounts[lvl] ?? 0) > 0)
    .map((lvl) => `${lvl}×${s.severityCounts[lvl]}`)
    .join(" · ");
}

function unstableTable(rows: SignatureStability[]): string {
  return mdTable(
    ["#", "Signature", "Alerts", "Verdict", "Levels", "Range", "Dominant", "Entropy", "Likely driver"],
    rows.map((s, i) => [
      String(i + 1),
      cell(clip(s.signature)),
      String(s.count),
      cell(verdictLabel(s.verdict)),
      String(s.distinctSeverities),
      `${s.minSeverity}→${s.maxSeverity}`,
      `${s.dominantSeverity} (${pct(s.dominantShare, 0)})`,
      s.severityEntropy.toFixed(2),
      cell(s.driverDetail ? `${driverLabel(s.driver)} — ${s.driverDetail}` : driverLabel(s.driver)),
    ]),
  );
}

function renderMarkdown(m: StabilityReport): string {
  const lines: string[] = [];
  lines.push(`# 🧭 SecTool Signature Severity-Stability Audit`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** for each signature, the spread of *derived* severities assigned to it is measured (distinct ` +
      `levels, min→max range, dominant share, normalised entropy) and classified **stable / minor / unstable**; ` +
      `the stored \`action\` and \`classification\` fields are tested as the likely driver. Offline, deterministic · ` +
      `**Window alerts:** ${m.totalWindowAlerts}`,
  );
  lines.push("");

  const s = m.summary;
  lines.push(`## Summary`);
  lines.push("");
  if (s.signatures === 0) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    } else {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but none carried a usable signature ` +
          `string to measure severity stability over.`,
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

  // At-a-glance trust matrix.
  lines.push(`## Severity-trust at a glance`);
  lines.push("");
  lines.push(
    mdTable(
      ["Verdict", "Signatures", "Alert volume", "Volume share"],
      [
        [
          verdictLabel("stable"),
          String(s.stableCount),
          String(s.stableVolume),
          s.attributedAlerts > 0 ? pct(round4(s.stableVolume / s.attributedAlerts), 1) : "—",
        ],
        [
          verdictLabel("minor"),
          String(s.minorCount),
          String(s.minorVolume),
          s.attributedAlerts > 0 ? pct(round4(s.minorVolume / s.attributedAlerts), 1) : "—",
        ],
        [
          verdictLabel("unstable"),
          String(s.unstableCount),
          String(s.unstableVolume),
          s.attributedAlerts > 0 ? pct(round4(s.unstableVolume / s.attributedAlerts), 1) : "—",
        ],
      ],
    ),
  );
  lines.push("");
  lines.push(
    `**Severity-trust score: ${pct(s.trustShare, 1)}** — the share of attributed alert volume whose signature ` +
      `always maps to one severity. The remaining **${pct(s.shakyShare, 1)}** sits under signatures that span ` +
      `more than one level.`,
  );
  lines.push("");

  // Driver breakdown for the non-stable set.
  const nonStable = s.minorCount + s.unstableCount;
  if (nonStable > 0) {
    lines.push(`## What drives the wobble`);
    lines.push("");
    lines.push(
      mdTable(
        ["Driver", "Signatures", "What it means"],
        [
          [
            driverLabel("action"),
            String(s.driverBreakdown.action),
            "Severity is fully determined by blocked-vs-detected — the expected `deriveSeverity()` rule, not a bug.",
          ],
          [
            driverLabel("classification"),
            String(s.driverBreakdown.classification),
            "The rule emits different classification strings, dragging severity with them.",
          ],
          [
            driverLabel("mixed"),
            String(s.driverBreakdown.mixed),
            "Neither stored field explains it — variance lives in priority / syslog level. Inspect these first.",
          ],
        ],
      ),
    );
    lines.push("");
  }

  // The least-stable leaderboard.
  lines.push(`## Least-stable signatures`);
  lines.push("");
  if (!m.unstable.length) {
    lines.push(
      `_Every signature with ≥ the minimum alert count maps to a single severity — nothing to flag._`,
    );
  } else {
    lines.push(
      `Non-stable signatures, least-trustworthy first (instability magnitude × log-volume). _Range_ is the lowest ` +
        `and highest severity seen; _Entropy_ is 0 for a single level, → 1 as the mix flattens; _Likely driver_ ` +
        `names the stored field that accounts for the spread.`,
    );
    lines.push("");
    lines.push(unstableTable(m.unstable));
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Severity here is **derived** per alert (Suricata priority + classification + ` +
      `syslog level + whether it was blocked), so variance is not necessarily an *error* — blocked-vs-detected is a ` +
      `real distinction. This audit flags inconsistency so you can judge it; a "mixed" driver means the stored ` +
      `action/classification don't explain the spread, not that nothing does. A short window may show a signature ` +
      `at only one of its faces; a long one can hit the store's history cap. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the signature severity-stability audit from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link StabilityOptions}: `limit`, `minCount`, and a `nowMs` pin
 *              for deterministic tests.
 */
export function buildStability(hours: number, opts: StabilityOptions = {}): StabilityReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minCount = Math.max(1, Math.min(1000, Math.floor(opts.minCount ?? DEFAULT_MIN_COUNT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const accs = new Map<string, SigAcc>();
  for (const a of windowed) {
    const sig = (a.signature ?? "").trim();
    if (!sig) continue;
    const sev = (SEVERITY_ORDER as readonly string[]).includes(a.severity)
      ? (a.severity as Severity)
      : "info";
    let acc = accs.get(sig);
    if (!acc) {
      acc = newSigAcc();
      accs.set(sig, acc);
    }
    acc.count++;
    acc.sev.set(sev, (acc.sev.get(sev) ?? 0) + 1);
    bumpSet(acc.byAction, actionGroup(a.action), sev);
    bumpSet(acc.byClass, (a.classification ?? "").trim() || "(none)", sev);
  }

  // Only signatures meeting the minimum-count floor are eligible for a verdict —
  // a single sighting can't be "inconsistent" and would only add noise.
  const analysed: SignatureStability[] = [];
  for (const [sig, acc] of accs) {
    if (acc.count < minCount) continue;
    analysed.push(summariseSignature(sig, acc));
  }

  const driverBreakdown: Record<InstabilityDriver, number> = {
    action: 0,
    classification: 0,
    mixed: 0,
    none: 0,
  };
  let stableCount = 0;
  let minorCount = 0;
  let unstableCount = 0;
  let stableVolume = 0;
  let minorVolume = 0;
  let unstableVolume = 0;
  let attributedAlerts = 0;

  for (const sig of analysed) {
    attributedAlerts += sig.count;
    if (sig.verdict === "stable") {
      stableCount++;
      stableVolume += sig.count;
    } else if (sig.verdict === "minor") {
      minorCount++;
      minorVolume += sig.count;
      driverBreakdown[sig.driver]++;
    } else {
      unstableCount++;
      unstableVolume += sig.count;
      driverBreakdown[sig.driver]++;
    }
  }

  const summary: StabilitySummary = {
    signatures: analysed.length,
    stableCount,
    minorCount,
    unstableCount,
    stableVolume,
    minorVolume,
    unstableVolume,
    attributedAlerts,
    trustShare: attributedAlerts > 0 ? round4(stableVolume / attributedAlerts) : 0,
    shakyShare: attributedAlerts > 0 ? round4((minorVolume + unstableVolume) / attributedAlerts) : 0,
    driverBreakdown,
  };

  const unstable = analysed
    .filter((sig) => sig.verdict !== "stable")
    .sort(
      (a, b) =>
        concernScore(b) - concernScore(a) ||
        b.count - a.count ||
        (a.signature < b.signature ? -1 : a.signature > b.signature ? 1 : 0),
    )
    .slice(0, limit);

  const highlights = writeHighlights(safeHours, summary, unstable);

  const model: StabilityReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    summary,
    unstable,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded stability report. */
export function stabilityFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-stability-${stamp}.md`;
}
