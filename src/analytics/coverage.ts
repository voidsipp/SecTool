/**
 * Data-coverage / quality (dataset-integrity) report — "**can I trust the reports
 * I'm reading?**"
 *
 * Every other offline report in this project *analyses* the stored alert
 * history — it ranks sources, shapes time, rolls up a taxonomy, measures
 * concentration. Every one of them ends with the same honest disclaimer: the
 * answer is only as good as the stored data, which is *window-bounded*,
 * *store-capped*, and only as complete as the collector that fed it. No report
 * actually *measures* that foundation. This one does.
 *
 * It is a meta-report: it audits the dataset itself rather than the threats in
 * it, and answers the question a responder should ask *before* acting on any
 * other report —
 *
 *   **"Is this history complete enough that the conclusions hold?"**
 *
 * Three failure modes silently corrupt every downstream report, and none of them
 * is visible from the reports themselves:
 *
 *   - **Truncation.** The store keeps a bounded number of alerts
 *     ({@link ALERT_STORE_CAP}); once full, the oldest are evicted. A long
 *     look-back then reads a *clipped* history — "first-seen", "novelty",
 *     "persistence" and every windowed count quietly understate the past. This
 *     report flags when the store is at (or near) capacity and when the
 *     requested window reaches back further than the oldest retained alert.
 *
 *   - **Missing fields.** A report can only rank what was recorded. If a third
 *     of alerts arrived with no `srcIp`, the source rankings are built on the
 *     two-thirds that did — and nobody told you. This report measures
 *     *completeness* of every field other reports depend on (source/destination
 *     IP, signature, severity, classification, action) so a hole is named, not
 *     inferred from a suspiciously short table.
 *
 *   - **Blind spots.** A collector outage, a syslog drop, a gateway reboot — the
 *     history simply goes quiet for a stretch, and a "no alerts" period reads as
 *     "no activity" when it may be "no *visibility*". This report finds the
 *     largest **time gaps** between consecutive alerts in the window and flags
 *     any far longer than the typical inter-arrival as a candidate outage.
 *
 * From the stored history it computes:
 *
 *   - **Store saturation** — retained alerts vs the hard cap, with an
 *     at-capacity / near-capacity warning and whether the look-back exceeds the
 *     retained span (history truncated).
 *   - **Time coverage** — earliest / latest retained alert, the span, and the
 *     count of alerts with an unusable timestamp (invisible to every windowed
 *     report).
 *   - **Field completeness** — per field, how many windowed alerts carry a
 *     usable value, the missing count, IP fields' *invalid* (present-but-malformed)
 *     count, and a 0..1 completeness fraction; core fields (the ones that drive
 *     rankings) are marked.
 *   - **Blind-spot gaps** — median inter-arrival, the largest gaps, and each
 *     gap's size relative to the median (the outage signal).
 *   - **Value vocabularies** — the distinct `severity` and `action` labels seen,
 *     so an empty or unexpected label (a parser regression) is obvious.
 *   - **Enrichment** — how many alerts carry a Claude summary and how many were
 *     notified, the coverage of the AI / delivery layers.
 *   - A **0-100 health score** and a categorical **grade**
 *     (`excellent` / `good` / `fair` / `poor`) from the above, with the raw
 *     numbers always shown so the operator can overrule the heuristic.
 *
 * Honest caveats baked into the output:
 *
 *   - **Completeness ≠ correctness.** A field being *present* says nothing about
 *     whether its value is *right*; this measures whether data exists, not whether
 *     the parser interpreted it correctly.
 *   - **Gaps ≠ outages.** A genuinely quiet network also produces long gaps. A
 *     flagged gap is a prompt to check the collector, not proof it failed.
 *   - **Self-referential bound.** This report reads the same capped store; it can
 *     see *that* the store is full, but not what was evicted before it looked.
 *
 * Pure in-memory math over alertStore (plus the exported store cap) — no SSH, no
 * Claude, no network. Output is both a structured model and a ready-to-paste
 * Markdown document, mirroring report.ts, focus.ts, netblock.ts and the other
 * offline reports.
 */
import { isIP } from "node:net";
import { alertStore, ALERT_STORE_CAP, type StoredAlert } from "../store/alertStore.ts";

/** Categorical read of overall dataset health, in descending trust order. */
export type HealthGrade = "excellent" | "good" | "fair" | "poor";

/** Completeness audit of a single recorded field over the window. */
export interface FieldCompleteness {
  /** Stable machine key (matches the {@link StoredAlert} field name). */
  key: string;
  /** Human label for display ("Source IP", "Signature", …). */
  label: string;
  /** Windowed alerts carrying a usable value for this field. */
  present: number;
  /** Windowed alerts missing (or blank-valued) for this field. */
  missing: number;
  /** IP fields only: present but not a parseable IPv4/IPv6 address. */
  invalid?: number;
  /** present / totalWindowAlerts, 0..1 (4dp). */
  completeness: number;
  /** True when this field materially drives downstream rankings. */
  core: boolean;
}

/** A silent stretch between two consecutive windowed alerts. */
export interface CoverageGap {
  /** Timestamp of the alert before the gap. */
  startMs: number;
  /** Timestamp of the alert after the gap. */
  endMs: number;
  /** (endMs − startMs) in hours, 2dp. */
  gapHours: number;
  /** gap / median inter-arrival, 1dp — how anomalous the silence is. */
  factor: number;
}

/** A distinct categorical label and how often it appeared in the window. */
export interface ValueCount {
  value: string;
  count: number;
}

export interface CoverageReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;

  // ----- store-wide saturation / retention -----
  /** Alerts currently retained in the store (all time). */
  storeTotal: number;
  /** Hard capacity before the oldest alerts are evicted. */
  storeCap: number;
  /** storeTotal / storeCap, 0..1 (4dp). */
  saturation: number;
  /** True once the store has reached its cap (eviction is active). */
  atCapacity: boolean;
  /** True when within 10% of the cap (truncation is imminent). */
  nearCapacity: boolean;
  /** Oldest retained alert timestamp, or null if none. */
  earliestStoredMs: number | null;
  /** Newest retained alert timestamp, or null if none. */
  latestStoredMs: number | null;
  /** Hours between the earliest and latest retained alert (2dp). */
  storeSpanHours: number;
  /** True when the look-back reaches before the oldest retained alert. */
  historyTruncated: boolean;
  /** Store-wide alerts with an unusable (non-finite) timestamp. */
  missingTimestamp: number;

  // ----- window -----
  /** Alerts with a usable timestamp inside the window. */
  totalWindowAlerts: number;
  /** Per-field completeness, in canonical display order. */
  fields: FieldCompleteness[];

  // ----- blind-spot gaps -----
  /** Median inter-arrival between consecutive windowed alerts, minutes (2dp). */
  medianGapMinutes: number;
  /** Largest single gap in the window, hours (2dp). */
  maxGapHours: number;
  /** The largest gaps, longest first. */
  topGaps: CoverageGap[];

  // ----- vocabularies / enrichment -----
  /** Distinct severity labels seen in the window, most frequent first. */
  severities: ValueCount[];
  /** Distinct action labels seen in the window, most frequent first. */
  actions: ValueCount[];
  /** Windowed alerts carrying a Claude summary. */
  summarized: number;
  /** Windowed alerts that were delivered to a notifier. */
  notified: number;

  // ----- verdict -----
  /** 0-100 composite data-health score. */
  healthScore: number;
  /** Categorical grade derived from {@link healthScore} and hard flags. */
  grade: HealthGrade;
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface CoverageOptions {
  /** Max blind-spot gap rows (clamped to [1, 50]). */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 6;
const MS_PER_HOUR = 3_600_000;
const MS_PER_MIN = 60_000;
/** A gap this many times the median inter-arrival is flagged as a blind spot. */
const GAP_OUTAGE_FACTOR = 6;
/** Within this fraction of the cap counts as "near capacity". */
const NEAR_CAP_FRACTION = 0.9;

// ----- formatting helpers (mirror focus.ts / netblock.ts) ------------------

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** A 0..1 fraction as a whole-number percent string, e.g. 0.823 -> "82%". */
function pct(frac: number): string {
  return `${Math.round(frac * 100)}%`;
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
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

/** Compact human duration from a millisecond span. */
function fmtDuration(ms: number): string {
  if (ms < MS_PER_MIN) return `${Math.round(ms / 1000)}s`;
  if (ms < MS_PER_HOUR) return `${round2(ms / MS_PER_MIN)} min`;
  if (ms < 24 * MS_PER_HOUR) return `${round2(ms / MS_PER_HOUR)} h`;
  return `${round2(ms / (24 * MS_PER_HOUR))} d`;
}

// ----- stats helpers -------------------------------------------------------

/** Median of a numeric list (0 for empty). Does not mutate the input. */
function median(values: number[]): number {
  if (!values.length) return 0;
  const s = [...values].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid]! : (s[mid - 1]! + s[mid]!) / 2;
}

/** Tally a categorical field across the window, most-frequent first. */
function vocab(alerts: StoredAlert[], pick: (a: StoredAlert) => string | undefined): ValueCount[] {
  const counts = new Map<string, number>();
  for (const a of alerts) {
    const v = pick(a)?.trim();
    const key = v && v.length ? v : "(blank)";
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([value, count]) => ({ value, count }))
    .sort((x, y) => (y.count - x.count) || (x.value < y.value ? -1 : 1));
}

// ----- field completeness --------------------------------------------------

/** Definition of one auditable field: how to read it and whether it's core. */
interface FieldSpec {
  key: string;
  label: string;
  core: boolean;
  /** True when the field holds an IP (enables the present-but-invalid count). */
  ip?: boolean;
  /** Extract the raw value (undefined/blank ⇒ missing). */
  get: (a: StoredAlert) => string | undefined;
}

const FIELD_SPECS: FieldSpec[] = [
  { key: "srcIp", label: "Source IP", core: true, ip: true, get: (a) => a.srcIp },
  { key: "dstIp", label: "Destination IP", core: true, ip: true, get: (a) => a.dstIp },
  { key: "signature", label: "Signature", core: true, get: (a) => a.signature },
  { key: "severity", label: "Severity", core: true, get: (a) => a.severity },
  { key: "category", label: "Category", core: false, get: (a) => a.category },
  { key: "classification", label: "Classification", core: false, get: (a) => a.classification },
  { key: "action", label: "Action", core: false, get: (a) => a.action },
];

function auditField(spec: FieldSpec, alerts: StoredAlert[]): FieldCompleteness {
  let present = 0;
  let invalid = 0;
  for (const a of alerts) {
    const raw = spec.get(a)?.trim();
    if (!raw) continue;
    if (spec.ip && isIP(raw) === 0) {
      invalid++; // recorded a value, but it isn't a parseable address
      continue;
    }
    present++;
  }
  const total = alerts.length;
  const result: FieldCompleteness = {
    key: spec.key,
    label: spec.label,
    present,
    missing: total - present - (spec.ip ? invalid : 0),
    completeness: total ? round4(present / total) : 0,
    core: spec.core,
  };
  if (spec.ip) result.invalid = invalid;
  return result;
}

// ----- health score --------------------------------------------------------

/**
 * Compose a 0-100 health score from the audited signals. Conservative and
 * transparent — the raw numbers are always shown so the operator can overrule.
 *
 *   - up to 50 pts: average completeness of the *core* fields,
 *   - up to 20 pts: timestamp integrity (share of alerts with a usable time),
 *   - up to 15 pts: retention headroom (penalised when truncated / at cap),
 *   - up to 15 pts: absence of blind-spot gaps.
 */
function scoreHealth(
  coreFields: FieldCompleteness[],
  tsIntegrity: number,
  historyTruncated: boolean,
  atCapacity: boolean,
  nearCapacity: boolean,
  worstGapFactor: number,
): number {
  // Core completeness — the dominant term.
  const avgCore = coreFields.length
    ? coreFields.reduce((s, f) => s + f.completeness, 0) / coreFields.length
    : 1;
  let score = avgCore * 50;

  // Timestamp integrity.
  score += tsIntegrity * 20;

  // Retention headroom.
  if (historyTruncated) score += 0;
  else if (atCapacity) score += 6;
  else if (nearCapacity) score += 11;
  else score += 15;

  // Blind-spot gaps — full marks until a gap clearly dwarfs the median.
  if (worstGapFactor < GAP_OUTAGE_FACTOR) score += 15;
  else {
    // Linearly fade from 15 → 0 between 6× and 30× the median.
    const over = Math.min(1, (worstGapFactor - GAP_OUTAGE_FACTOR) / (30 - GAP_OUTAGE_FACTOR));
    score += 15 * (1 - over);
  }

  return Math.max(0, Math.min(100, Math.round(score)));
}

function gradeFor(score: number): HealthGrade {
  if (score >= 85) return "excellent";
  if (score >= 70) return "good";
  if (score >= 50) return "fair";
  return "poor";
}

function gradeLabel(g: HealthGrade): string {
  switch (g) {
    case "excellent":
      return "🟢 excellent";
    case "good":
      return "🟡 good";
    case "fair":
      return "🟠 fair";
    default:
      return "🔴 poor";
  }
}

// ----- highlights ----------------------------------------------------------

function writeHighlights(m: Omit<CoverageReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];

  out.push(
    `🩺 Dataset health is **${m.grade}** (${m.healthScore}/100) over the last ${m.hours}h — ` +
      `${m.totalWindowAlerts} alert(s) audited across ${m.fields.length} recorded field(s). ` +
      `Treat this as the trust floor for every other report below.`,
  );

  if (!m.totalWindowAlerts) {
    out.push(
      `📭 No alerts with a usable timestamp in the window — either the network was genuinely quiet, the ` +
        `collector is not feeding the store, or the look-back predates the retained history. ` +
        `Confirm ingestion before reading "all-clear" into any other report.`,
    );
    if (m.missingTimestamp > 0) {
      out.push(
        `⏱️ ${m.missingTimestamp} stored alert(s) carry an unusable timestamp and are invisible to every ` +
          `time-windowed report — a parser or clock issue worth fixing at the source.`,
      );
    }
    return out;
  }

  // Worst core field — the sharpest "your rankings are built on a subset" warning.
  const worstCore = [...m.fields.filter((f) => f.core)].sort((a, b) => a.completeness - b.completeness)[0];
  if (worstCore && worstCore.completeness < 0.98) {
    const inv = worstCore.invalid ? ` (+${worstCore.invalid} present but unparseable)` : "";
    out.push(
      `🧩 **${worstCore.label}** is only ${pct(worstCore.completeness)} complete — ${worstCore.missing} of ` +
        `${m.totalWindowAlerts} windowed alert(s) have none${inv}. Every report that ranks by ` +
        `${worstCore.label.toLowerCase()} silently drops those alerts; the tables understate reality.`,
    );
  } else {
    out.push(
      `✅ Core fields (source/destination IP, signature, severity) are essentially complete — entity and ` +
        `taxonomy rankings are built on the full windowed set, not a fragment.`,
    );
  }

  // Truncation / saturation — the most damaging silent failure.
  if (m.historyTruncated) {
    out.push(
      `🗃️ **History is truncated.** The store is at its ${m.storeCap}-alert cap and its oldest retained alert ` +
        `(${m.earliestStoredMs !== null ? fmtTime(m.earliestStoredMs) : "—"}) is *newer* than the start of your ` +
        `${m.hours}h window. Older activity has been evicted — "first-seen" / "novelty" / long-range counts are ` +
        `clipped. Shorten the look-back or raise the store cap for a faithful long view.`,
    );
  } else if (m.atCapacity) {
    out.push(
      `🗃️ The store is **at capacity** (${m.storeTotal}/${m.storeCap}); the next alerts will evict the oldest. ` +
        `This window still fits inside the retained span, but a longer look-back will start to clip.`,
    );
  } else if (m.nearCapacity) {
    out.push(
      `🗃️ The store is **near capacity** (${m.storeTotal}/${m.storeCap}, ${pct(m.saturation)}); eviction of the ` +
        `oldest alerts is imminent. Plan a larger cap or shorter look-backs before history starts to clip.`,
    );
  }

  // Blind-spot gap — possible collector outage.
  const g = m.topGaps[0];
  if (g && g.factor >= GAP_OUTAGE_FACTOR) {
    out.push(
      `🕳️ **Possible blind spot:** a ${g.gapHours}h silence between ${fmtTime(g.startMs)} and ` +
        `${fmtTime(g.endMs)} — ${g.factor}× the median inter-arrival (${m.medianGapMinutes} min). A quiet network ` +
        `looks identical to a dropped collector here; verify the gateway / syslog feed was up across that stretch.`,
    );
  }

  // Timestamp integrity (store-wide).
  if (m.missingTimestamp > 0) {
    out.push(
      `⏱️ ${m.missingTimestamp} stored alert(s) have an unusable timestamp and are excluded from every windowed ` +
        `report — investigate the event clock / parser so they stop disappearing.`,
    );
  }

  // Value-vocabulary regressions — a blank label is usually a parser break.
  const blankSev = m.severities.find((s) => s.value === "(blank)");
  if (blankSev) {
    out.push(
      `🏷️ ${blankSev.count} alert(s) carry a blank severity label — likely a parser regression; severity-ranked ` +
        `reports treat them as the empty bucket.`,
    );
  }

  // Enrichment coverage — informational, not a defect.
  if (m.summarized < m.totalWindowAlerts) {
    out.push(
      `🤖 ${m.summarized} of ${m.totalWindowAlerts} windowed alert(s) have a Claude summary ` +
        `(${pct(m.totalWindowAlerts ? m.summarized / m.totalWindowAlerts : 0)}); the rest were stored without AI ` +
        `enrichment (filtered, throttled, or offline). The dashboard's AI panels reflect only the enriched subset.`,
    );
  }

  return out;
}

// ----- markdown ------------------------------------------------------------

function retentionTable(m: CoverageReport): string {
  const rows: string[][] = [
    ["Retained alerts", `${m.storeTotal} / ${m.storeCap} (${pct(m.saturation)})`],
    [
      "Capacity state",
      m.historyTruncated
        ? "🔴 truncated (look-back exceeds history)"
        : m.atCapacity
          ? "🟠 at capacity (eviction active)"
          : m.nearCapacity
            ? "🟡 near capacity"
            : "🟢 headroom",
    ],
    ["Earliest retained", m.earliestStoredMs !== null ? fmtTime(m.earliestStoredMs) : "—"],
    ["Latest retained", m.latestStoredMs !== null ? fmtTime(m.latestStoredMs) : "—"],
    ["Retained span", `${m.storeSpanHours} h`],
    ["Unusable timestamps", String(m.missingTimestamp)],
  ];
  return mdTable(["Retention", "Value"], rows.map((r) => [cell(r[0]), cell(r[1])]));
}

function fieldTable(m: CoverageReport): string {
  return mdTable(
    ["Field", "Role", "Present", "Missing", "Invalid", "Complete"],
    m.fields.map((f) => [
      cell(f.label),
      f.core ? "core" : "aux",
      String(f.present),
      String(f.missing),
      f.invalid !== undefined ? String(f.invalid) : "—",
      pct(f.completeness),
    ]),
  );
}

function gapTable(m: CoverageReport): string {
  return mdTable(
    ["#", "From", "To", "Silence", "× median"],
    m.topGaps.map((g, i) => [
      String(i + 1),
      fmtTime(g.startMs),
      fmtTime(g.endMs),
      fmtDuration(g.endMs - g.startMs),
      `${g.factor}×`,
    ]),
  );
}

function vocabTable(title: string, values: ValueCount[], total: number): string {
  return mdTable(
    [title, "Alerts", "Share"],
    values.map((v) => [cell(clip(v.value)), String(v.count), pct(total ? v.count / total : 0)]),
  );
}

function renderMarkdown(m: CoverageReport): string {
  const lines: string[] = [];
  lines.push(`# 🩺 SecTool Data-Coverage / Quality Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** offline integrity audit of the stored alert history (retention · field completeness · ` +
      `blind-spot gaps) · **Health:** ${gradeLabel(m.grade)} ${m.healthScore}/100 · ` +
      `**Window alerts:** ${m.totalWindowAlerts}`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Retention & time coverage`);
  lines.push("");
  lines.push(retentionTable(m));
  lines.push("");
  lines.push(
    `_The store keeps at most ${m.storeCap} alerts; once full the oldest are evicted, so a look-back longer than ` +
      `the retained span reads a clipped history. "Unusable timestamps" are stored but excluded from every ` +
      `time-windowed report._`,
  );
  lines.push("");

  if (!m.totalWindowAlerts) {
    lines.push(`## Field completeness`);
    lines.push("");
    lines.push(`_No alerts with a usable timestamp in the window — nothing to audit for completeness._`);
    lines.push("");
    lines.push("---");
    lines.push(
      `_Generated offline by SecTool from the stored alert history. Completeness ≠ correctness (a present value ` +
        `can still be mis-parsed) and a long gap can be a genuinely quiet network rather than an outage. This ` +
        `report reads the same capped store it audits, so it can see *that* the store is full but not what was ` +
        `evicted before it looked. No live gateway query was performed._`,
    );
    lines.push("");
    return lines.join("\n");
  }

  lines.push(`## Field completeness`);
  lines.push("");
  lines.push(fieldTable(m));
  lines.push("");
  lines.push(
    `**Legend:** _core_ fields drive entity / taxonomy rankings; a hole here silently shrinks those tables. ` +
      `_Invalid_ counts values that were recorded but are not parseable addresses. _Complete_ = present / ` +
      `${m.totalWindowAlerts} windowed alert(s).`,
  );
  lines.push("");

  lines.push(`## Blind-spot gaps`);
  lines.push("");
  lines.push(
    `Median inter-arrival between windowed alerts: **${m.medianGapMinutes} min**. Largest single silence: ` +
      `**${m.maxGapHours} h**. Gaps far larger than the median can mark a collector outage rather than a quiet ` +
      `network.`,
  );
  lines.push("");
  lines.push(gapTable(m));
  lines.push("");

  lines.push(`## Value vocabularies & enrichment`);
  lines.push("");
  lines.push(
    `Distinct **severity** labels (${m.severities.length}) and **action** labels (${m.actions.length}) seen this ` +
      `window — an unexpected or \`(blank)\` label usually means a parser regression.`,
  );
  lines.push("");
  lines.push(vocabTable("Severity", m.severities, m.totalWindowAlerts));
  lines.push("");
  lines.push(vocabTable("Action", m.actions, m.totalWindowAlerts));
  lines.push("");
  lines.push(
    `**Enrichment:** ${m.summarized}/${m.totalWindowAlerts} alert(s) carry a Claude summary ` +
      `(${pct(m.totalWindowAlerts ? m.summarized / m.totalWindowAlerts : 0)}); ` +
      `${m.notified}/${m.totalWindowAlerts} were delivered to a notifier ` +
      `(${pct(m.totalWindowAlerts ? m.notified / m.totalWindowAlerts : 0)}).`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from the stored alert history. **Completeness ≠ correctness** — a present ` +
      `value can still be mis-parsed; this measures whether data exists, not whether it is right. **Gaps ≠ ` +
      `outages** — a genuinely quiet network also goes silent, so a flagged gap is a prompt to check the ` +
      `collector, not proof it failed. This report reads the same capped store it audits, so it can see *that* ` +
      `the store is full but not what was evicted before it looked. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the data-coverage / quality report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link CoverageOptions}: `limit` (blind-spot gap rows) and `nowMs`.
 */
export function buildCoverage(hours: number, opts: CoverageOptions = {}): CoverageReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(50, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const all = alertStore.all(); // newest-first, whole store
  const storeTotal = all.length;
  const storeCap = ALERT_STORE_CAP;
  const saturation = storeCap > 0 ? round4(storeTotal / storeCap) : 0;
  const atCapacity = storeTotal >= storeCap;
  const nearCapacity = !atCapacity && storeTotal >= Math.floor(storeCap * NEAR_CAP_FRACTION);

  const timed = all.filter(
    (a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time),
  );
  const missingTimestamp = storeTotal - timed.length;

  // Store-wide time coverage (from the timestamped alerts).
  const times = timed.map((a) => a.time);
  const earliestStoredMs = times.length ? Math.min(...times) : null;
  const latestStoredMs = times.length ? Math.max(...times) : null;
  const storeSpanHours =
    earliestStoredMs !== null && latestStoredMs !== null
      ? round2((latestStoredMs - earliestStoredMs) / MS_PER_HOUR)
      : 0;
  // Truncated when the store is full AND its oldest alert is newer than the
  // window's start — older activity must have been evicted.
  const historyTruncated =
    atCapacity && earliestStoredMs !== null && earliestStoredMs > windowStartMs;

  // Windowed slice (ascending for gap analysis).
  const windowed = timed
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs)
    .sort((a, b) => a.time - b.time);
  const totalWindowAlerts = windowed.length;

  const fields = FIELD_SPECS.map((spec) => auditField(spec, windowed));

  // Blind-spot gaps between consecutive windowed alerts.
  const interArrivals: number[] = [];
  for (let i = 1; i < windowed.length; i++) {
    interArrivals.push(windowed[i]!.time - windowed[i - 1]!.time);
  }
  const medGapMs = median(interArrivals);
  const medianGapMinutes = round2(medGapMs / MS_PER_MIN);
  const gaps: CoverageGap[] = [];
  for (let i = 1; i < windowed.length; i++) {
    const startMs = windowed[i - 1]!.time;
    const endMs = windowed[i]!.time;
    const span = endMs - startMs;
    gaps.push({
      startMs,
      endMs,
      gapHours: round2(span / MS_PER_HOUR),
      factor: medGapMs > 0 ? Math.round((span / medGapMs) * 10) / 10 : 0,
    });
  }
  gaps.sort((a, b) => (b.endMs - b.startMs) - (a.endMs - a.startMs));
  const topGaps = gaps.slice(0, limit);
  const maxGapHours = topGaps.length ? topGaps[0]!.gapHours : 0;
  const worstGapFactor = topGaps.length ? topGaps[0]!.factor : 0;

  const severities = vocab(windowed, (a) => a.severity);
  const actions = vocab(windowed, (a) => a.action);
  const summarized = windowed.filter((a) => a.summary !== undefined).length;
  const notified = windowed.filter((a) => typeof a.notifiedAt === "number").length;

  const tsIntegrity = storeTotal ? timed.length / storeTotal : 1;
  const coreFields = fields.filter((f) => f.core);
  const healthScore = scoreHealth(
    coreFields,
    tsIntegrity,
    historyTruncated,
    atCapacity,
    nearCapacity,
    worstGapFactor,
  );
  const grade = gradeFor(healthScore);

  const partial: Omit<CoverageReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    storeTotal,
    storeCap,
    saturation,
    atCapacity,
    nearCapacity,
    earliestStoredMs,
    latestStoredMs,
    storeSpanHours,
    historyTruncated,
    missingTimestamp,
    totalWindowAlerts,
    fields,
    medianGapMinutes,
    maxGapHours,
    topGaps,
    severities,
    actions,
    summarized,
    notified,
    healthScore,
    grade,
  };

  const highlights = writeHighlights(partial);
  const model: CoverageReport = { ...partial, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded data-coverage report. */
export function coverageFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-coverage-${stamp}.md`;
}
