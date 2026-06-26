/**
 * Notification audit / alert-fatigue report — "of everything SecTool saw, what
 * actually reached a human, and was it the *right* stuff?"
 *
 * Every other offline report analyses the alert *stream* — who attacked, which
 * signatures fired, when the bursts were, which pairs moved laterally. None of
 * them looks at the **delivery layer**: SecTool stores every alert it processes,
 * but only a subset are pushed to Discord (`notifiedAt`) and only some carry a
 * Claude AI write-up (`summary`). Those two fields are unique to the alert store
 * and untouched by any other analytic — yet they decide what an on-call human
 * ever sees. A perfectly tuned detector is useless if the dangerous alerts never
 * left the box, or if the channel is so noisy the real ones are scrolled past.
 *
 * This report audits the notification pipeline against the stored history and
 * surfaces the two failure modes that quietly erode an alerting setup:
 *
 *   1. **Signal gaps** — medium-or-worse alerts that were *never notified*. These
 *      are the misses: a real detection that sat silently in the store while no
 *      one was paged. The single most important number in the report.
 *   2. **Alert fatigue** — info/low alerts that *were* notified. Noise in the
 *      channel trains responders to ignore it, so the genuine high-severity push
 *      gets dismissed with the rest. High notified-noise share is a tuning smell.
 *
 * Alongside those it reports per-severity delivery coverage, AI-summary coverage
 * of the notified alerts (real Claude analysis vs. a non-AI fallback vs. none),
 * and notification latency (how long after the event the push went out).
 *
 * Honest caveats baked into the output:
 *
 *   - **`notifiedAt` is processing time, not a live SLA.** It is stamped when
 *     SecTool *processed and pushed* the alert, which for a `--backfill` /
 *     `--pull` run is the import time, not the moment the event happened. So
 *     latency is meaningful for live ingestion and inflated for backfilled
 *     history — the report flags this rather than pretending otherwise.
 *   - **Not-notified ≠ dropped.** An alert can be unnotified because it was
 *     deduped, suppressed, below the notify threshold, or simply predates the
 *     time notifications were wired up. The report measures *coverage*, it does
 *     not assert intent.
 *   - **Store cap.** The alert store is rotated (newest N), so a long window can
 *     silently start mid-history; counts are of what is *retained*, not of all
 *     time.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network. Output is
 * both a structured model and a ready-to-paste Markdown document, mirroring
 * report.ts, compare.ts, edges.ts, persistence.ts and the other offline reports.
 */
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Delivery coverage for a single severity tier. */
export interface SeverityCoverage {
  severity: Severity;
  /** Alerts at this severity inside the window. */
  total: number;
  /** Of those, how many were notified (pushed to Discord). */
  notified: number;
  /** notified / total, 0..1 (0 when total is 0). */
  rate: number;
}

/** One signature filling the notification channel (or being missed). */
export interface SignatureRow {
  signature: string;
  /** Alerts on this signature relevant to the row's purpose. */
  count: number;
  /** Worst severity observed for this signature in the window. */
  severityMax: Severity;
  /** ms epoch of the most recent relevant alert. */
  lastSeenMs: number;
}

export interface NotifyReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, how many were notified at all. */
  notifiedCount: number;
  /** notifiedCount / totalWindowAlerts, 0..1. */
  notifyRate: number;

  /** Per-severity delivery coverage, low → high (mirrors SEVERITY_ORDER). */
  severityCoverage: SeverityCoverage[];

  /** Medium-or-worse alerts in the window. */
  severeTotal: number;
  /** Of the severe alerts, how many were notified. */
  severeNotified: number;
  /** severeNotified / severeTotal, 0..1 — the headline coverage number. */
  severeCoverageRate: number;
  /** Severe alerts that were NOT notified (the signal gaps). */
  severeMissed: number;

  /** Of the notified alerts, how many were info/low (the fatigue share, count). */
  notifiedNoise: number;
  /** notifiedNoise / notifiedCount, 0..1. */
  notifiedNoiseRate: number;

  /** Of the notified alerts, how many carried a real (non-fallback) Claude summary. */
  notifiedWithAi: number;
  /** Of the notified alerts, how many carried a non-AI fallback summary. */
  notifiedWithFallback: number;
  /** Of the notified alerts, how many had no summary at all. */
  notifiedNoSummary: number;

  /** Notification latency (notifiedAt − time, clamped ≥0) — sample size. */
  latencySamples: number;
  /** Median notification latency in ms (0 when no samples). */
  latencyMedianMs: number;
  /** 95th-percentile notification latency in ms (0 when no samples). */
  latencyP95Ms: number;
  /** True when ≥1 latency sample looked backfilled (latency > window), so the latency figures are inflated. */
  latencyLikelyBackfilled: boolean;

  /** Signatures filling the channel — most-notified first, truncated to limit. */
  topNotified: SignatureRow[];
  /** Severe signatures that went unnotified — worst-severity first, truncated. */
  missedSevere: SignatureRow[];

  /** Plain-language call-outs about the report as a whole. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface NotifyOptions {
  /** Max rows in each signature table (clamped to [1, 1000]). */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 15;
const MS_PER_HOUR = 3_600_000;

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? (b as Severity) : a;
}

/** Medium or above is "severe" — the tier an on-call human must not miss. */
function isSevere(s: string | undefined): boolean {
  return sevRank(s) >= 2;
}

function isNotified(a: StoredAlert): boolean {
  return typeof a.notifiedAt === "number" && Number.isFinite(a.notifiedAt);
}

// ----- formatting helpers (mirror edges.ts / persistence.ts) -----

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function fmtAge(ms: number, nowMs: number): string {
  const sec = Math.max(0, Math.round((nowMs - ms) / 1000));
  if (sec < 90) return `${sec}s`;
  const min = Math.round(sec / 60);
  if (min < 90) return `${min}m`;
  const hr = Math.round(min / 60);
  if (hr < 48) return `${hr}h`;
  return `${Math.round(hr / 24)}d`;
}

/** A human duration like "45m" / "2h 10m" / "3d 4h" for a latency. */
function fmtDuration(ms: number): string {
  const sec = Math.max(0, Math.round(ms / 1000));
  if (sec < 90) return `${sec}s`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m`;
  const hr = Math.floor(min / 60);
  if (hr < 24) {
    const rem = min % 60;
    return rem ? `${hr}h ${rem}m` : `${hr}h`;
  }
  const days = Math.floor(hr / 24);
  const remHr = hr % 24;
  return remHr ? `${days}d ${remHr}h` : `${days}d`;
}

function pct(x: number): string {
  return `${Math.round(x * 100)}%`;
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
function clip(s: string, max = 48): string {
  const t = s.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

/** Percentile of an ascending-sorted numeric array (nearest-rank). */
function percentile(sorted: number[], p: number): number {
  if (!sorted.length) return 0;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil(p * sorted.length) - 1));
  return sorted[idx]!;
}

/**
 * Internal accumulator for one signature while we fold its alerts, used for both
 * the most-notified and missed-severe tables.
 */
interface SigAccum {
  signature: string;
  count: number;
  severityMax: Severity;
  lastSeenMs: number;
}

function bumpSig(map: Map<string, SigAccum>, sig: string, sev: string | undefined, t: number): void {
  let acc = map.get(sig);
  if (!acc) {
    acc = { signature: sig, count: 0, severityMax: "info", lastSeenMs: t };
    map.set(sig, acc);
  }
  acc.count++;
  acc.severityMax = maxSeverity(acc.severityMax, sev);
  if (t > acc.lastSeenMs) acc.lastSeenMs = t;
}

/** Rank signature rows by volume, then severity, then recency (stable). */
function rankByVolume(rows: SignatureRow[]): SignatureRow[] {
  return rows.sort((a, b) => {
    if (b.count !== a.count) return b.count - a.count;
    if (sevRank(b.severityMax) !== sevRank(a.severityMax)) return sevRank(b.severityMax) - sevRank(a.severityMax);
    return b.lastSeenMs - a.lastSeenMs;
  });
}

/** Rank missed-severe rows by severity first (the worst miss leads), then volume. */
function rankBySeverity(rows: SignatureRow[]): SignatureRow[] {
  return rows.sort((a, b) => {
    if (sevRank(b.severityMax) !== sevRank(a.severityMax)) return sevRank(b.severityMax) - sevRank(a.severityMax);
    if (b.count !== a.count) return b.count - a.count;
    return b.lastSeenMs - a.lastSeenMs;
  });
}

function toRow(a: SigAccum): SignatureRow {
  return { signature: a.signature, count: a.count, severityMax: a.severityMax, lastSeenMs: a.lastSeenMs };
}

function writeHighlights(m: Omit<NotifyReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (!m.totalWindowAlerts) return out;

  out.push(
    `🔔 Over the last ${m.hours}h, **${m.notifiedCount} of ${m.totalWindowAlerts}** stored alert(s) were notified ` +
      `(${pct(m.notifyRate)} delivery).`,
  );

  // Signal gaps are the headline — surface them first and loudest.
  if (m.severeTotal === 0) {
    out.push(`✅ No medium-or-worse alerts in the window — nothing severe to deliver.`);
  } else if (m.severeMissed > 0) {
    const worst = m.missedSevere[0];
    out.push(
      `🚨 **${m.severeMissed} severe (medium+) alert(s) were NOT notified** — only ${pct(m.severeCoverageRate)} of ` +
        `the ${m.severeTotal} severe alert(s) reached a human. These are silent detections.` +
        (worst ? ` Worst miss: \`${clip(worst.signature)}\` (${worst.count}×, peak ${worst.severityMax}).` : ""),
    );
  } else {
    out.push(
      `🛡️ Full severe coverage — all ${m.severeTotal} medium-or-worse alert(s) were notified (${pct(m.severeCoverageRate)}).`,
    );
  }

  // Alert fatigue — noise in the channel.
  if (m.notifiedCount > 0 && m.notifiedNoiseRate >= 0.5) {
    out.push(
      `📣 **Alert fatigue risk** — ${m.notifiedNoise} of ${m.notifiedCount} notified alert(s) (${pct(m.notifiedNoiseRate)}) ` +
        `were only info/low severity. A noisy channel trains responders to ignore the real ones; tighten the notify ` +
        `threshold or add suppressions.`,
    );
  } else if (m.notifiedCount > 0 && m.notifiedNoise > 0) {
    out.push(
      `📣 ${m.notifiedNoise} of ${m.notifiedCount} notified alert(s) (${pct(m.notifiedNoiseRate)}) were info/low — ` +
        `modest channel noise.`,
    );
  }

  // AI-summary coverage of what was delivered.
  if (m.notifiedCount > 0) {
    const aiRate = m.notifiedWithAi / m.notifiedCount;
    out.push(
      `🤖 AI coverage of notified alerts: ${m.notifiedWithAi} with Claude analysis (${pct(aiRate)}), ` +
        `${m.notifiedWithFallback} fallback, ${m.notifiedNoSummary} none.`,
    );
  }

  // Latency, with the backfill honesty caveat.
  if (m.latencySamples > 0) {
    out.push(
      `⏱️ Notification latency: median ${fmtDuration(m.latencyMedianMs)}, p95 ${fmtDuration(m.latencyP95Ms)} ` +
        `(over ${m.latencySamples} sample(s))` +
        (m.latencyLikelyBackfilled
          ? ` — ⚠️ some samples exceed the window, so these are inflated by **backfilled** history, not live delay.`
          : `.`),
    );
  }
  return out;
}

function coverageTable(rows: SeverityCoverage[]): string {
  return mdTable(
    ["Severity", "Alerts", "Notified", "Coverage"],
    // High → low reads more naturally for an operator scanning for gaps.
    [...rows]
      .sort((a, b) => sevRank(b.severity) - sevRank(a.severity))
      .map((r) => [
        cell(r.severity),
        String(r.total),
        String(r.notified),
        r.total ? `${pct(r.rate)} (${r.notified}/${r.total})` : "—",
      ]),
  );
}

function signatureTable(rows: SignatureRow[], nowMs: number, countHeader: string): string {
  return mdTable(
    ["Signature", countHeader, "Peak sev", "Last"],
    rows.map((r) => [cell(clip(r.signature || "—")), String(r.count), cell(r.severityMax), fmtAge(r.lastSeenMs, nowMs)]),
  );
}

function renderMarkdown(m: NotifyReport): string {
  const lines: string[] = [];
  lines.push(`# 🔔 SecTool Notification Audit / Alert-Fatigue Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** audits the delivery layer (\`notifiedAt\` / \`summary\`) of the stored alert history · ` +
      `**${m.notifiedCount} notified** of ${m.totalWindowAlerts} window alert(s) (${pct(m.notifyRate)})`,
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

  lines.push(`## Delivery coverage by severity`);
  lines.push("");
  lines.push(coverageTable(m.severityCoverage));
  lines.push("");
  lines.push(
    `_Coverage = notified / total at each tier. The medium+ rows are the ones that matter: an uncovered severe row ` +
      `is a **silent detection** no one was paged for._`,
  );
  lines.push("");

  lines.push(`## Signal gaps — severe signatures that went unnotified`);
  lines.push("");
  if (!m.severeMissed) {
    lines.push(`_None — every medium-or-worse alert in the window was notified. 🛡️_`);
    lines.push("");
  } else {
    lines.push(signatureTable(m.missedSevere, m.windowEndMs, "Unnotified"));
    lines.push("");
    lines.push(`_These are real detections that never reached a human. Verify the notify threshold and suppressions._`);
    lines.push("");
  }

  lines.push(`## Channel noise — most-notified signatures`);
  lines.push("");
  if (!m.topNotified.length) {
    lines.push(`_Nothing was notified in this window._`);
    lines.push("");
  } else {
    lines.push(signatureTable(m.topNotified, m.windowEndMs, "Notified"));
    lines.push("");
    lines.push(
      `_What is filling the channel. Low-severity rows near the top are fatigue candidates — suppress or raise the ` +
        `threshold so the high-severity pushes stand out._`,
    );
    lines.push("");
  }

  lines.push(
    `**Legend:** _Coverage_ = share of a tier's alerts that were pushed to Discord. _Signal gaps_ = medium-or-worse ` +
      `alerts with no notification (silent detections). _Channel noise_ = what was actually delivered, most first; ` +
      `info/low rows are alert-fatigue candidates. AI coverage splits notified alerts into Claude-analysed, non-AI ` +
      `fallback, and no-summary.`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from the **stored alert history**. \`notifiedAt\` records when SecTool processed ` +
      `and pushed an alert, so latency is a live-delivery delay for streamed alerts but is **inflated by backfilled / ` +
      `pulled history** (import time, not event time). "Not notified" can mean deduped, suppressed, below threshold, ` +
      `or predating notification setup — this measures coverage, not intent. The store is rotated (newest entries), ` +
      `so a long window may begin mid-history. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the notification audit / alert-fatigue report from the stored history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link NotifyOptions}: `limit` (per table) and a `nowMs` pin.
 */
export function buildNotify(hours: number, opts: NotifyOptions = {}): NotifyReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(1000, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;
  const windowMs = Math.max(1, windowEndMs - windowStartMs);

  const all = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time));

  // Per-severity coverage accumulators, seeded for every tier so a tier with
  // zero alerts still renders an explicit "—" row.
  const cov = new Map<Severity, { total: number; notified: number }>();
  for (const s of SEVERITY_ORDER) cov.set(s, { total: 0, notified: 0 });

  const topNotifiedSigs = new Map<string, SigAccum>();
  const missedSevereSigs = new Map<string, SigAccum>();
  const latencies: number[] = [];

  let totalWindowAlerts = 0;
  let notifiedCount = 0;
  let severeTotal = 0;
  let severeNotified = 0;
  let notifiedNoise = 0;
  let notifiedWithAi = 0;
  let notifiedWithFallback = 0;
  let notifiedNoSummary = 0;
  let latencyLikelyBackfilled = false;

  for (const a of all) {
    if (a.time < windowStartMs || a.time > windowEndMs) continue;
    totalWindowAlerts++;

    const sev = (SEVERITY_ORDER as readonly string[]).includes(a.severity)
      ? (a.severity as Severity)
      : "info";
    const bucket = cov.get(sev)!;
    bucket.total++;

    const notified = isNotified(a);
    const severe = isSevere(a.severity);
    if (severe) severeTotal++;

    const sig = a.signature && a.signature.trim() ? a.signature.trim() : "(unlabelled)";

    if (notified) {
      notifiedCount++;
      bucket.notified++;
      if (severe) severeNotified++;
      if (!severe) notifiedNoise++; // info/low that was pushed = fatigue candidate

      // AI-summary coverage of what was actually delivered.
      const sum = a.summary;
      if (sum && !sum.fallback) notifiedWithAi++;
      else if (sum && sum.fallback) notifiedWithFallback++;
      else notifiedNoSummary++;

      bumpSig(topNotifiedSigs, sig, a.severity, a.time);

      // Notification latency: clamp negatives (clock skew) to 0; a sample that
      // exceeds the whole window is almost certainly backfilled history.
      const raw = a.notifiedAt! - a.time;
      const lat = Math.max(0, raw);
      latencies.push(lat);
      if (lat > windowMs) latencyLikelyBackfilled = true;
    } else if (severe) {
      // The signal gaps: severe detections that never reached a human.
      bumpSig(missedSevereSigs, sig, a.severity, a.time);
    }
  }

  const severityCoverage: SeverityCoverage[] = SEVERITY_ORDER.map((s) => {
    const b = cov.get(s)!;
    return { severity: s, total: b.total, notified: b.notified, rate: b.total ? b.notified / b.total : 0 };
  });

  latencies.sort((a, b) => a - b);
  const latencyMedianMs = percentile(latencies, 0.5);
  const latencyP95Ms = percentile(latencies, 0.95);

  const topNotified = rankByVolume([...topNotifiedSigs.values()].map(toRow)).slice(0, limit);
  const missedSevere = rankBySeverity([...missedSevereSigs.values()].map(toRow)).slice(0, limit);

  const base: Omit<NotifyReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts,
    notifiedCount,
    notifyRate: totalWindowAlerts ? notifiedCount / totalWindowAlerts : 0,
    severityCoverage,
    severeTotal,
    severeNotified,
    severeCoverageRate: severeTotal ? severeNotified / severeTotal : 0,
    severeMissed: severeTotal - severeNotified,
    notifiedNoise,
    notifiedNoiseRate: notifiedCount ? notifiedNoise / notifiedCount : 0,
    notifiedWithAi,
    notifiedWithFallback,
    notifiedNoSummary,
    latencySamples: latencies.length,
    latencyMedianMs,
    latencyP95Ms,
    latencyLikelyBackfilled,
    topNotified,
    missedSevere,
  };
  const highlights = writeHighlights(base);
  const model: NotifyReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded notification-audit report. */
export function notifyFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-notify-${stamp}.md`;
}
