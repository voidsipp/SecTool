/**
 * Signature lifecycle / chronic-vs-acute report — "of all the signatures firing,
 * which ones are *constant background noise* I should tune out, and which are
 * *discrete bursts* that mark a real event worth investigating?"
 *
 * Every other report in this project measures a signature by *how much* it fires
 * (tuning, trends, focus), *who* fires it (persistence, netblock, edges), or *when
 * it was first seen* (novelty). None of them measures the **temporal shape** of a
 * signature — the way its alerts are *distributed across the window* — even though
 * that shape is the single best discriminator between two operationally opposite
 * things that look identical in a volume ranking:
 *
 *   - A **chronic** signature fires a little, all the time — evenly smeared across
 *     the whole window. High volume here is *background*: a policy hit, a benign
 *     scanner, a protocol-anomaly rule. It will fire again tomorrow no matter what
 *     you do. This is the noise to **suppress / tune** so the signal stands out.
 *   - An **acute** signature fires a lot, briefly — its alerts pile into one short
 *     stretch of the window and then stop. That concentration is the texture of a
 *     discrete *event*: an exploitation attempt, a scan campaign, a misconfig that
 *     came and went. This is the thing to **investigate**, even at low total volume.
 *
 * A signature firing 500 times spread evenly over a week and one firing 500 times
 * inside ten minutes have identical volume and identical top-signature rank — but
 * the first is noise and the second is an incident. This report tells them apart.
 *
 * It buckets each signature's windowed alerts into equal time slices and, from the
 * per-bucket counts, computes two orthogonal shape measures:
 *
 *   - **coverage** (`activeRatio`) — the fraction of buckets in which the signature
 *     fired at all. High coverage = present throughout = chronic-leaning.
 *   - **burstiness** — a 0..1 normalized dispersion of the per-bucket counts
 *     (coefficient of variation scaled by its single-bucket maximum). 0 = perfectly
 *     even, 1 = every alert in one bucket. High burstiness = spiky = acute-leaning.
 *
 * From those it assigns each signature one of four shapes, in descending
 * investigate-priority:
 *
 *   - **acute**       — concentrated burst; a discrete event. Investigate.
 *   - **one-shot**    — fired in a single bucket only; an isolated blip. Triage.
 *   - **intermittent**— on-and-off, neither steady nor a single spike. Watch.
 *   - **chronic**     — steady, broad coverage, low dispersion. Tune / suppress.
 *
 * Each row also carries the supporting context an operator needs to act: total
 * volume and per-day rate, peak-bucket share and when that peak landed, distinct
 * sources / destinations (a broad acute burst is a spray; a single-source chronic
 * trickle is one chatty host), severity ceiling, first/last seen, lifespan, and a
 * `dormant` flag for signatures whose last alert is old relative to the window
 * (a chronic rule that *stopped* — fixed, rotated away, or sensor gap).
 *
 * The summary quantifies the **noise floor**: how many signatures and how much of
 * the total alert volume are chronic background, so the operator can see at a
 * glance how much of the firehose is suppressible — and pulls out the loudest
 * acute bursts (with their peak time) as the morning's investigate-first list.
 *
 * Honest caveats baked into the output:
 *
 *   - **Shape is window-relative.** A rule that looks acute in a 24h window can
 *     look chronic in a 7-day one (and vice-versa). The classification describes
 *     the chosen window, not the signature's eternal nature.
 *   - **Bucket granularity matters.** Coarser buckets smear bursts toward chronic;
 *     finer ones fracture chronic noise toward intermittent. The bucket size used
 *     is printed so the read is reproducible.
 *   - **Alerts, not flows / not verdicts.** A "chronic" shape says a rule fires
 *     steadily, not that it is benign — verify before suppressing. An "acute" shape
 *     is a lead to investigate, not a confirmed incident.
 *   - **Window-bounded & store-capped.** A long look-back can hit the store's
 *     history cap and truncate older buckets, flattening early shape.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network. Output is
 * both a structured model and a ready-to-paste Markdown document, mirroring
 * report.ts, direction.ts, netblock.ts, focus.ts and the other offline reports.
 */
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Stable machine key for each temporal shape, in descending investigate-priority. */
export type ShapeKey = "acute" | "one-shot" | "intermittent" | "chronic";

/** Canonical shape order, highest investigate-priority first. */
const SHAPE_ORDER: ShapeKey[] = ["acute", "one-shot", "intermittent", "chronic"];

const SHAPE_LABEL: Record<ShapeKey, string> = {
  acute: "Acute (concentrated burst — investigate)",
  "one-shot": "One-shot (single slice — triage)",
  intermittent: "Intermittent (on & off — watch)",
  chronic: "Chronic (steady background — tune)",
};

/** Per-signature lifecycle metrics over the window. */
export interface SignatureLifecycle {
  /** The signature text (already trimmed); never empty. */
  signature: string;
  /** Total alerts for this signature inside the window. */
  total: number;
  /** Normalized alerts-per-day rate over the window. */
  perDay: number;
  /** total / all classified alerts, 0..1 (4dp). */
  share: number;
  /** Time buckets in which this signature fired at least once. */
  activeBuckets: number;
  /** activeBuckets / bucketCount, 0..1 (4dp) — temporal coverage of the window. */
  activeRatio: number;
  /** Alerts in this signature's busiest bucket. */
  peakBucket: number;
  /** peakBucket / total, 0..1 (4dp) — how concentrated the busiest slice is. */
  peakShare: number;
  /** Start time (ms) of the busiest bucket — when the signature peaked. */
  peakBucketStartMs: number;
  /**
   * Normalized dispersion of the per-bucket counts, 0..1 (4dp). 0 = perfectly
   * even across the window (chronic), 1 = every alert in a single bucket (a spike).
   */
  burstiness: number;
  /** Assigned temporal shape. */
  shape: ShapeKey;
  /** Distinct source IPs that fired this signature. */
  distinctSources: number;
  /** Distinct destination IPs this signature targeted. */
  distinctDestinations: number;
  /** Worst severity this signature ever reached. */
  severityMax: Severity;
  /** First alert time for this signature (ms). */
  firstSeenMs: number;
  /** Last alert time for this signature (ms). */
  lastSeenMs: number;
  /** lastSeenMs - firstSeenMs (ms) — how long the signature was active. */
  lifespanMs: number;
  /**
   * True when the last alert is old relative to the window (no activity in the
   * final {@link DORMANT_FRACTION} of it) — a rule that fired and then went quiet.
   */
  dormant: boolean;
}

/** Roll-up of one shape across all signatures assigned to it. */
export interface ShapeBucket {
  key: ShapeKey;
  label: string;
  /** Distinct signatures assigned this shape. */
  signatures: number;
  /** Total alert volume across those signatures. */
  alerts: number;
  /** alerts / all classified alerts, 0..1 (4dp). */
  volumeShare: number;
}

export interface LifecycleReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Number of equal time buckets the window was sliced into. */
  bucketCount: number;
  /** Size of each bucket in milliseconds. */
  bucketMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts that carried a non-empty signature (the analysis base). */
  classifiedAlerts: number;
  /** Alerts inside the window with no signature (excluded from per-signature shape). */
  unsignedAlerts: number;
  /** Distinct signatures seen in the window. */
  distinctSignatures: number;
  /** Per-shape roll-up, in canonical investigate-priority order. */
  shapes: ShapeBucket[];
  /** Per-signature lifecycle rows, ranked (acute/loud first), truncated to the limit. */
  signatures: SignatureLifecycle[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface LifecycleOptions {
  /** Max rows in the per-signature table (clamped to [1, 200]). */
  limit?: number;
  /** Override the number of time buckets (clamped to [6, 336]); default is window-derived. */
  buckets?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 25;
const MS_PER_HOUR = 3_600_000;
const MS_PER_DAY = 86_400_000;

/** A signature firing in ≥ this share of buckets with low burstiness reads as chronic. */
const CHRONIC_ACTIVE = 0.5;
/** Burstiness at/below this, with broad coverage, reads as chronic (even smear). */
const CHRONIC_BURST = 0.4;
/** Burstiness at/above this reads as acute (a spike), regardless of coverage. */
const ACUTE_BURST = 0.7;
/** No alert in the final fraction of the window ⇒ the signature is dormant. */
const DORMANT_FRACTION = 0.25;

// ----- formatting helpers (mirror direction.ts / netblock.ts / focus.ts) -----

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
function clip(s: string, max = 44): string {
  const t = s.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

/** A short relative-age phrase for a "last seen" timestamp. */
function ago(ms: number, nowMs: number): string {
  const d = Math.max(0, nowMs - ms);
  const h = d / MS_PER_HOUR;
  if (h < 1) return `${Math.round(d / 60000)}m ago`;
  if (h < 48) return `${Math.round(h)}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

/** A compact human duration for a lifespan, e.g. "3d", "5h", "12m", "0m". */
function dur(ms: number): string {
  if (ms <= 0) return "0m";
  const h = ms / MS_PER_HOUR;
  if (h < 1) return `${Math.max(1, Math.round(ms / 60000))}m`;
  if (h < 48) return `${Math.round(h)}h`;
  return `${Math.round(h / 24)}d`;
}

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf((s ?? "").toLowerCase());
  return i < 0 ? 0 : i;
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? (b as Severity) : a;
}

// ----- shape classification -------------------------------------------------

/**
 * Normalized burstiness of a per-bucket count vector, 0..1.
 *
 * Computes the coefficient of variation (stddev/mean) of the counts across *all*
 * buckets — including the empty ones, so a signature that touches only one bucket
 * out of many reads as maximally bursty — then scales it by its theoretical
 * maximum (all mass in a single bucket ⇒ CV = sqrt(bucketCount - 1)). The result
 * is 0 for a perfectly even smear and 1 for a single concentrated spike.
 */
function burstiness(counts: number[]): number {
  const n = counts.length;
  if (n <= 1) return 0;
  const total = counts.reduce((s, c) => s + c, 0);
  if (total <= 0) return 0;
  const mean = total / n;
  let variance = 0;
  for (const c of counts) variance += (c - mean) ** 2;
  variance /= n;
  const cv = Math.sqrt(variance) / mean;
  const cvMax = Math.sqrt(n - 1); // all mass in one bucket
  return cvMax > 0 ? Math.min(1, cv / cvMax) : 0;
}

/**
 * Classify a signature's temporal shape from its coverage and burstiness. The
 * order of tests encodes priority: a single active bucket is always one-shot; a
 * genuine spike is acute; a broad even smear is chronic; everything else is the
 * intermittent middle ground.
 */
function classifyShape(activeBuckets: number, activeRatio: number, burst: number): ShapeKey {
  if (activeBuckets <= 1) return "one-shot";
  if (burst >= ACUTE_BURST) return "acute";
  if (activeRatio >= CHRONIC_ACTIVE && burst <= CHRONIC_BURST) return "chronic";
  return "intermittent";
}

// ----- aggregation ----------------------------------------------------------

interface SigAcc {
  total: number;
  counts: number[]; // per-bucket alert counts
  sources: Set<string>;
  destinations: Set<string>;
  severityMax: Severity;
  firstSeenMs: number;
  lastSeenMs: number;
  peakBucketIdx: number;
  peakBucket: number;
}

function newSigAcc(bucketCount: number): SigAcc {
  return {
    total: 0,
    counts: new Array<number>(bucketCount).fill(0),
    sources: new Set(),
    destinations: new Set(),
    severityMax: "info",
    firstSeenMs: Number.POSITIVE_INFINITY,
    lastSeenMs: 0,
    peakBucketIdx: 0,
    peakBucket: 0,
  };
}

/**
 * Derive a sensible bucket count for the window: roughly one bucket per hour, so
 * the granularity tracks the look-back, clamped to a band that keeps the math
 * cheap and the shape meaningful. An explicit override wins (also clamped).
 */
function deriveBucketCount(hours: number, override: number | undefined): number {
  if (override !== undefined && Number.isFinite(override)) {
    return Math.max(6, Math.min(336, Math.floor(override)));
  }
  return Math.max(6, Math.min(336, Math.round(hours)));
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  m: Pick<
    LifecycleReport,
    "classifiedAlerts" | "distinctSignatures" | "shapes" | "signatures" | "unsignedAlerts"
  >,
  bucketMs: number,
  nowMs: number,
): string[] {
  const out: string[] = [];
  if (!m.classifiedAlerts) return out;

  const byKey = new Map(m.shapes.map((s) => [s.key, s]));
  const chronic = byKey.get("chronic");
  const acute = byKey.get("acute");

  // Headline: how much of the firehose is suppressible background.
  if (chronic && chronic.alerts > 0) {
    out.push(
      `🌫️ **Chronic background = ${pct(chronic.volumeShare)} of all alert volume** (${chronic.alerts} alerts across ` +
        `${chronic.signatures} signature(s)) — these fire steadily across the whole ${hours}h window and will fire ` +
        `again tomorrow. This is the noise to tune/suppress so real signal stands out; see the tuning report for the ` +
        `operator-value evidence before silencing each.`,
    );
  } else {
    out.push(
      `🌫️ No signature fired steadily enough across the last ${hours}h to read as chronic background — the alert ` +
        `stream is event-driven rather than a constant noise floor. Good: little here to tune out.`,
    );
  }

  // The loudest chronic rule — the single highest-leverage suppression candidate.
  const topChronic = m.signatures
    .filter((s) => s.shape === "chronic")
    .sort((a, b) => b.total - a.total)[0];
  if (topChronic) {
    out.push(
      `🔇 Loudest chronic rule is \`${clip(topChronic.signature, 60)}\` — ${topChronic.total} alerts ` +
        `(${topChronic.perDay.toFixed(1)}/day) smeared across ${pct(topChronic.activeRatio)} of the window from ` +
        `${topChronic.distinctSources} source(s), peak severity ${topChronic.severityMax}. Highest-leverage single ` +
        `suppression: confirm it has never produced a real incident, then tune it down.`,
    );
  }

  // Acute bursts — the investigate-first list.
  const acuteSigs = m.signatures
    .filter((s) => s.shape === "acute")
    .sort((a, b) => b.total - a.total);
  if (acute && acuteSigs.length) {
    const lead = acuteSigs[0]!;
    out.push(
      `🚨 **${acuteSigs.length} acute burst signature(s)** (${acute.alerts} alerts) — concentrated spikes that mark ` +
        `discrete events. Loudest: \`${clip(lead.signature, 56)}\` — ${lead.total} alerts, ${pct(lead.peakShare)} of ` +
        `them inside one ${dur(bucketMs)} slice peaking ${ago(lead.peakBucketStartMs, nowMs)} (${lead.distinctSources} ` +
        `source(s) → ${lead.distinctDestinations} dest(s), sev ${lead.severityMax}). Investigate these first.`,
    );
  } else {
    out.push(
      `✅ No acute burst signatures this window — no rule concentrated its alerts into a short spike. The stream is ` +
        `either steady background or scattered intermittent activity.`,
    );
  }

  // High-severity one-shots — isolated but potentially important blips.
  const sharpOneShot = m.signatures
    .filter((s) => s.shape === "one-shot" && sevRank(s.severityMax) >= 3)
    .sort((a, b) => sevRank(b.severityMax) - sevRank(a.severityMax) || b.total - a.total)[0];
  if (sharpOneShot) {
    out.push(
      `⚡ A high-severity **one-shot** fired in a single time slice: \`${clip(sharpOneShot.signature, 56)}\` ` +
        `(${sharpOneShot.total} alert(s), sev ${sharpOneShot.severityMax}, ${ago(sharpOneShot.lastSeenMs, nowMs)}). ` +
        `Isolated in time but severe — triage it even though the volume is low.`,
    );
  }

  // Dormant chronic — a background rule that *stopped* (fixed? rotated? sensor gap?).
  const dormantChronic = m.signatures
    .filter((s) => s.dormant && (s.shape === "chronic" || s.shape === "intermittent") && s.total >= 5)
    .sort((a, b) => b.total - a.total)[0];
  if (dormantChronic) {
    out.push(
      `💤 \`${clip(dormantChronic.signature, 56)}\` was a recurring rule (${dormantChronic.total} alerts) but has been ` +
        `silent since ${ago(dormantChronic.lastSeenMs, nowMs)} — it stopped mid-window. Worth a glance: a fixed ` +
        `misconfig, an attacker who moved on, or a sensor/ingest gap worth ruling out.`,
    );
  }

  // Data-hygiene note on unsigned alerts (excluded from shape).
  if (m.unsignedAlerts > 0) {
    out.push(
      `ℹ️ ${m.unsignedAlerts} windowed alert(s) carried no signature and are excluded from per-signature shape — ` +
        `see the coverage report if that share looks high.`,
    );
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function shapeTable(shapes: ShapeBucket[]): string {
  return mdTable(
    ["Shape", "Signatures", "Alerts", "Volume share"],
    shapes.map((s) => [cell(s.label), String(s.signatures), String(s.alerts), pct(s.volumeShare)]),
  );
}

const SHAPE_BADGE: Record<ShapeKey, string> = {
  acute: "🚨 acute",
  "one-shot": "⚡ one-shot",
  intermittent: "🔁 intermittent",
  chronic: "🌫️ chronic",
};

function signatureTable(rows: SignatureLifecycle[], nowMs: number): string {
  return mdTable(
    ["#", "Signature", "Shape", "Alerts", "/day", "Coverage", "Burst", "Peak", "Peaked", "Src", "Dst", "Sev", "Lifespan", "Last"],
    rows.map((s, i) => [
      String(i + 1),
      cell(clip(s.signature)),
      SHAPE_BADGE[s.shape] + (s.dormant ? " 💤" : ""),
      String(s.total),
      s.perDay.toFixed(1),
      pct(s.activeRatio),
      pct(s.burstiness),
      pct(s.peakShare),
      ago(s.peakBucketStartMs, nowMs),
      String(s.distinctSources),
      String(s.distinctDestinations),
      cell(s.severityMax),
      dur(s.lifespanMs),
      ago(s.lastSeenMs, nowMs),
    ]),
  );
}

function renderMarkdown(m: LifecycleReport): string {
  const lines: string[] = [];
  lines.push(`# 🫀 SecTool Signature Lifecycle / Chronic-vs-Acute Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** each signature's alerts bucketed into ${m.bucketCount} equal ${dur(m.bucketMs)} slices; ` +
      `shape = coverage (active slices) × burstiness (dispersion) · **Classified alerts:** ${m.classifiedAlerts} ` +
      `across ${m.distinctSignatures} signature(s)`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.classifiedAlerts) {
    lines.push(
      `No alerts with both a usable timestamp and a signature in the last ${m.hours} hour(s) — nothing to shape.` +
        (m.unsignedAlerts ? ` (${m.unsignedAlerts} windowed alert(s) carried no signature.)` : ""),
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Shape at a glance`);
  lines.push("");
  lines.push(shapeTable(m.shapes));
  lines.push("");
  lines.push(
    `**Legend:** _Acute_ = alerts concentrated into a short burst (a discrete event → investigate). _One-shot_ = ` +
      `fired in a single time slice (an isolated blip → triage). _Intermittent_ = on-and-off, neither steady nor a ` +
      `single spike (→ watch). _Chronic_ = steady across the window with low dispersion (background noise → tune / ` +
      `suppress). High chronic volume share means much of your firehose is suppressible.`,
  );
  lines.push("");

  lines.push(`## Signatures by lifecycle`);
  lines.push("");
  lines.push(
    `Ranked acute/loud first. _Coverage_ = share of time slices the signature fired in (high = ever-present). ` +
      `_Burst_ = dispersion, 0% even … 100% all-in-one-slice (high = spiky). _Peak_ = share of the signature's ` +
      `alerts in its busiest slice. _💤_ marks a signature that went silent in the final ${pct(DORMANT_FRACTION)} of ` +
      `the window.`,
  );
  lines.push("");
  lines.push(signatureTable(m.signatures, m.windowEndMs));
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from stored **IPS-alert** timestamps. Shape is **window-relative** — a rule that ` +
      `looks acute in a short window can look chronic in a long one — and depends on the ${dur(m.bucketMs)} bucket ` +
      `granularity printed above. A "chronic" shape means a rule fires steadily, **not** that it is benign: verify ` +
      `(and check the tuning report's operator-value evidence) before suppressing. An "acute" shape is a lead to ` +
      `investigate, not a confirmed incident. These are detections, not flows; a long look-back can hit the store's ` +
      `history cap and truncate early buckets. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the signature-lifecycle / chronic-vs-acute report from the stored alert
 * history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link LifecycleOptions}: `limit` (table rows), `buckets`
 *              (granularity override) and a `nowMs` pin for deterministic tests.
 */
export function buildLifecycle(hours: number, opts: LifecycleOptions = {}): LifecycleReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;
  const bucketCount = deriveBucketCount(safeHours, opts.buckets);
  const bucketMs = (safeHours * MS_PER_HOUR) / bucketCount;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const dormantCutoffMs = windowEndMs - DORMANT_FRACTION * safeHours * MS_PER_HOUR;

  const accs = new Map<string, SigAcc>();
  let unsignedAlerts = 0;

  for (const a of windowed) {
    const sig = a.signature?.trim();
    if (!sig) {
      unsignedAlerts++;
      continue;
    }
    let acc = accs.get(sig);
    if (!acc) {
      acc = newSigAcc(bucketCount);
      accs.set(sig, acc);
    }
    acc.total++;
    // Bucket index: clamp the rare end-of-window alert (time === windowEndMs) into
    // the last bucket so it is never lost to an off-by-one.
    let idx = Math.floor((a.time - windowStartMs) / bucketMs);
    if (idx < 0) idx = 0;
    if (idx >= bucketCount) idx = bucketCount - 1;
    const next = (acc.counts[idx] ?? 0) + 1;
    acc.counts[idx] = next;
    if (next > acc.peakBucket) {
      acc.peakBucket = next;
      acc.peakBucketIdx = idx;
    }
    const src = a.srcIp?.trim();
    const dst = a.dstIp?.trim();
    if (src) acc.sources.add(src);
    if (dst) acc.destinations.add(dst);
    acc.severityMax = maxSeverity(acc.severityMax, a.severity);
    if (a.time < acc.firstSeenMs) acc.firstSeenMs = a.time;
    if (a.time > acc.lastSeenMs) acc.lastSeenMs = a.time;
  }

  const classifiedAlerts = windowed.length - unsignedAlerts;
  const windowDays = (safeHours * MS_PER_HOUR) / MS_PER_DAY;

  const signatures: SignatureLifecycle[] = [...accs.entries()].map(([signature, acc]) => {
    const activeBuckets = acc.counts.reduce((n, c) => n + (c > 0 ? 1 : 0), 0);
    const activeRatio = bucketCount ? round4(activeBuckets / bucketCount) : 0;
    const burst = round4(burstiness(acc.counts));
    const shape = classifyShape(activeBuckets, activeRatio, burst);
    const firstSeenMs = Number.isFinite(acc.firstSeenMs) ? acc.firstSeenMs : acc.lastSeenMs;
    return {
      signature,
      total: acc.total,
      perDay: windowDays > 0 ? round4(acc.total / windowDays) : acc.total,
      share: classifiedAlerts ? round4(acc.total / classifiedAlerts) : 0,
      activeBuckets,
      activeRatio,
      peakBucket: acc.peakBucket,
      peakShare: acc.total ? round4(acc.peakBucket / acc.total) : 0,
      peakBucketStartMs: Math.round(windowStartMs + acc.peakBucketIdx * bucketMs),
      burstiness: burst,
      shape,
      distinctSources: acc.sources.size,
      distinctDestinations: acc.destinations.size,
      severityMax: acc.severityMax,
      firstSeenMs,
      lastSeenMs: acc.lastSeenMs,
      lifespanMs: Math.max(0, acc.lastSeenMs - firstSeenMs),
      dormant: acc.lastSeenMs < dormantCutoffMs,
    } satisfies SignatureLifecycle;
  });

  // Per-shape roll-up over the full signature set (before table truncation).
  const shapes: ShapeBucket[] = SHAPE_ORDER.map((key) => {
    const members = signatures.filter((s) => s.shape === key);
    const alerts = members.reduce((n, s) => n + s.total, 0);
    return {
      key,
      label: SHAPE_LABEL[key],
      signatures: members.length,
      alerts,
      volumeShare: classifiedAlerts ? round4(alerts / classifiedAlerts) : 0,
    } satisfies ShapeBucket;
  });

  // Table rank: investigate-priority shape first (acute > one-shot > intermittent
  // > chronic), then volume, then burstiness, then signature for a stable order.
  const shapeRank = (k: ShapeKey): number => SHAPE_ORDER.indexOf(k);
  signatures.sort(
    (x, y) =>
      shapeRank(x.shape) - shapeRank(y.shape) ||
      y.total - x.total ||
      y.burstiness - x.burstiness ||
      (x.signature < y.signature ? -1 : x.signature > y.signature ? 1 : 0),
  );

  // Highlights are computed over the FULL sorted signature set (chronic rows sort
  // last, so a small table `limit` must not hide the loudest chronic/dormant rule).
  const highlights = writeHighlights(
    safeHours,
    { classifiedAlerts, distinctSignatures: accs.size, shapes, signatures, unsignedAlerts },
    bucketMs,
    windowEndMs,
  );

  const model: LifecycleReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    bucketCount,
    bucketMs: Math.round(bucketMs),
    totalWindowAlerts: windowed.length,
    classifiedAlerts,
    unsignedAlerts,
    distinctSignatures: accs.size,
    shapes,
    signatures: signatures.slice(0, limit),
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded signature-lifecycle report. */
export function lifecycleFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-lifecycle-${stamp}.md`;
}
