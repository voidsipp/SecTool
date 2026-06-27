/**
 * Rarity / signal-surprise report — "**which source is doing something nobody
 * else is doing?**"
 *
 * Almost every leaderboard SecTool ships ranks a source by *volume* or *reach*:
 * who fired the most alerts (report.ts), who touched the most hosts (spread.ts,
 * scan.ts), who fired the most distinct signatures (repertoire.ts). On a live
 * IPS those boards are perpetually topped by the same commodity background
 * radiation — mass internet scanners and worm traffic that trip ubiquitous,
 * everybody-sees-them rules thousands of times. The genuinely interesting
 * actor — the one running a *bespoke* tool, or hunting a niche service almost
 * nobody else probes — is buried under that noise precisely because it is
 * *quiet*. Ranking by volume actively hides it.
 *
 * This report inverts the axis. Borrowing the **TF-IDF / inverse-document-
 * frequency** idea from information retrieval, it weights every signature by how
 * *rare* it is across the source population, then scores each source by the
 * rarity of what it fires rather than the quantity:
 *
 *   - For each labelled signature `S`, its **source frequency** `df(S)` is the
 *     number of *distinct sources* that fired it in the window, and its
 *     **rarity** is `idf(S) = ln(N / df(S))` where `N` is the distinct-source
 *     count. A signature everyone fires (`df ≈ N`) has rarity ≈ 0; one fired by
 *     a single source has the maximum rarity `ln(N)`.
 *   - A signature with `df == 1` is **exclusive** — only one source in the whole
 *     window tripped it. Exclusive signatures are the strongest "this is bespoke
 *     / targeted, not commodity" tell the stream holds.
 *   - Each source's **distinctiveness score** is the sum of `idf(S)` over the
 *     *distinct* signatures it fired — it rewards firing many rare things, and is
 *     deliberately blind to raw volume so a loud-but-boring scanner cannot buy
 *     its way up the board. Its **mean rarity** (idf averaged over the source's
 *     alerts) says how unusual a *typical* alert from it is.
 *
 * From those two numbers each source is placed in a self-scaling **band** (the
 * thresholds are fractions of the window's maximum possible rarity `ln(N)`, so
 * the call travels across deployments of any size):
 *
 *   - **bespoke** — fires at least one *exclusive* signature; nobody else trips
 *     it. Look here first.
 *   - **distinctive** — no exclusive sig, but its mean rarity is high: it lives
 *     in the long tail of uncommon signatures.
 *   - **mixed** — a blend of common and uncommon.
 *   - **commodity** — almost everything it fires is ubiquitous background noise;
 *     high volume here is the *expected* shape and can usually be deprioritised.
 *
 * A companion **"rarest signatures"** roll-up answers the dual question the
 * per-source table can't: across the whole window, which individual signatures
 * are the most unusual — the niche rules only one or two actors ever trip — and
 * who tripped them.
 *
 * Honest caveats baked into the output:
 *
 *   - **Rarity is relative to *this* window's population, not the internet.** A
 *     signature rare here may be globally common and vice-versa; idf measures
 *     "unusual *for my sensor, right now*", which is exactly the triage question.
 *   - **Unlabelled alerts are excluded.** An alert with no signature text cannot
 *     be scored for rarity; the dropped count is surfaced so a thin labelled set
 *     is visible rather than mistaken for "quiet".
 *   - **Degenerate at N = 1.** With a single source every signature is trivially
 *     exclusive and idf collapses to 0; the report says so instead of pretending
 *     to rank.
 *   - **Alerts, not flows; window-bounded & store-capped.** SecTool stores IPS
 *     *detections*, and a long look-back can hit the store's history cap, so both
 *     df and the source population are lower bounds.
 *
 * Pure in-memory math over alertStore (plus blocklist / watchlist / safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring report.ts, scan.ts,
 * audience.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Where a source sits on the commodity↔bespoke spectrum. */
export type RarityBand = "bespoke" | "distinctive" | "mixed" | "commodity";

/** Blocked / passed / unknown disposition split for a source. */
export interface DispositionSplit {
  /** Alerts the gateway actively blocked / dropped. */
  blocked: number;
  /** Alerts the gateway logged but let through (detected / allowed). */
  passed: number;
  /** Alerts with no recorded action (excluded from {@link passRate}). */
  unknown: number;
  /**
   * Fraction of *actioned* (blocked + passed) alerts let through, 0..1 (4dp), or
   * null when nothing was actioned.
   */
  passRate: number | null;
}

/** Per-source rarity metrics over the window. */
export interface RaritySource {
  /** The source IP. */
  ip: string;
  /** True when the source is one of our own hosts (RFC1918 / loopback / …). */
  internal: boolean;
  /** The commodity↔bespoke band this source falls in. */
  band: RarityBand;
  /** Labelled alerts attributed to this source in the window. */
  alerts: number;
  /** Distinct (labelled) signatures this source fired. */
  distinctSignatures: number;
  /** Of those, signatures *no other source* fired (df == 1). */
  exclusiveSignatures: number;
  /** Σ idf over the source's distinct signatures — the ranking key. */
  distinctivenessScore: number;
  /** idf averaged over the source's alerts: how unusual a typical alert is. */
  meanRarity: number;
  /** The single rarest signature's idf (the source's peak surprise). */
  peakRarity: number;
  /** The rarest signature this source fired (highest idf). */
  topSignature?: string;
  /** Distinct sources that *also* fired {@link topSignature} (df, incl. this). */
  topSignatureSources: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Severity-weighted score (Σ SEVERITY_WEIGHT) — a secondary signal. */
  score: number;
  /** Worst severity seen from this source. */
  severityMax: Severity;
  /** Blocked / passed / unknown disposition split. */
  disposition: DispositionSplit;
  /** The source is on the blocklist. */
  blocked: boolean;
  /** The source is on the watchlist. */
  watched: boolean;
  /** The source is marked safe. */
  safe: boolean;
}

/** One signature and how rare it is across the source population. */
export interface RareSignature {
  /** The signature text. */
  signature: string;
  /** idf = ln(N / df) — higher means rarer. */
  rarity: number;
  /** Distinct sources that fired it (df). */
  distinctSources: number;
  /** Total alerts naming this signature. */
  count: number;
  /** When exclusive (df == 1), the sole source that fired it. */
  soleSource?: string;
  /** Worst severity seen for this signature. */
  severityMax: Severity;
}

/** Count of sources falling into each band (the headline distribution). */
export interface BandCounts {
  bespoke: number;
  distinctive: number;
  mixed: number;
  commodity: number;
}

export interface RarityReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts carrying a valid source IP. */
  sourcedAlerts: number;
  /** Of those, alerts that also carried a usable signature label (the scored set). */
  labelledAlerts: number;
  /** Sourced alerts dropped for having no signature label (excluded from rarity). */
  unlabelledAlerts: number;
  /** Distinct source IPs in the scored population (N). */
  distinctSources: number;
  /** Distinct labelled signatures observed. */
  distinctSignatures: number;
  /** Signatures fired by exactly one source (df == 1). */
  exclusiveSignatures: number;
  /** The maximum possible rarity this window, ln(N) — the band-scaling anchor. */
  maxRarity: number;
  /** True when N < 2 and rarity is degenerate (everything trivially exclusive). */
  degenerate: boolean;
  /** How many sources fell into each band. */
  bandCounts: BandCounts;
  /** Per-source rarity rows, most distinctive first. */
  sources: RaritySource[];
  /** The rarest individual signatures across the window, rarest first. */
  rareSignatures: RareSignature[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface RarityOptions {
  /** Max rows in the per-source and rare-signature tables (clamped to [1, 200]). */
  limit?: number;
  /** Minimum labelled alerts a source needs before it is scored (drops one-offs). */
  minAlerts?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const DEFAULT_MIN_ALERTS = 2;
const MS_PER_HOUR = 3_600_000;
/** Band thresholds, as fractions of the window's maximum rarity ln(N). */
const DISTINCTIVE_FRACTION = 0.5;
const MIXED_FRACTION = 0.15;

// ----- classifiers / helpers (mirror scan.ts / audience.ts) -----------------

/** RFC1918 / loopback / link-local / ULA — an address treated as one of ours. */
function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
}

/** A valid, non-empty IP, or undefined if the field is missing/garbage. */
function validIp(ip: string | undefined): string | undefined {
  return ip && isIP(ip) !== 0 ? ip : undefined;
}

/** The signature label, trimmed, or undefined when the alert carried none. */
function sigOf(a: StoredAlert): string | undefined {
  const s = (a.signature ?? "").trim();
  return s.length ? s : undefined;
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

function round2(n: number): number {
  return Math.round(n * 100) / 100;
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

/** Truncate a long signature so the Markdown table stays readable. */
function truncSig(s: string, max = 56): string {
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}

function mdTable(headers: string[], rows: string[][]): string {
  if (!rows.length) return "_None._";
  const head = `| ${headers.join(" | ")} |`;
  const sep = `| ${headers.map(() => "---").join(" | ")} |`;
  const body = rows.map((r) => `| ${r.join(" | ")} |`).join("\n");
  return `${head}\n${sep}\n${body}`;
}

/** Human label for a band, with an emoji that reads at a glance. */
function bandLabel(b: RarityBand): string {
  switch (b) {
    case "bespoke":
      return "🎯 bespoke";
    case "distinctive":
      return "✨ distinctive";
    case "mixed":
      return "◐ mixed";
    case "commodity":
      return "📦 commodity";
  }
}

/**
 * Place a source in a band from its exclusive-signature count and mean rarity.
 * The mean-rarity thresholds are fractions of `maxRarity` (= ln(N)) so the call
 * self-scales with the size of the source population.
 */
function classifyBand(
  exclusiveSignatures: number,
  meanRarity: number,
  maxRarity: number,
): RarityBand {
  if (exclusiveSignatures >= 1) return "bespoke";
  if (maxRarity <= 0) return "commodity";
  if (meanRarity >= DISTINCTIVE_FRACTION * maxRarity) return "distinctive";
  if (meanRarity >= MIXED_FRACTION * maxRarity) return "mixed";
  return "commodity";
}

// ----- aggregation ----------------------------------------------------------

interface SourceAcc {
  alerts: number;
  score: number;
  severe: number;
  /** signature -> alert count from this source. */
  sigCounts: Map<string, number>;
  blocked: number;
  passed: number;
  unknown: number;
  severityMax: Severity;
}

function newSourceAcc(): SourceAcc {
  return {
    alerts: 0,
    score: 0,
    severe: 0,
    sigCounts: new Map(),
    blocked: 0,
    passed: 0,
    unknown: 0,
    severityMax: "info",
  };
}

interface SigAcc {
  /** Distinct sources that fired this signature (df). */
  sources: Set<string>;
  count: number;
  severityMax: Severity;
}

function newSigAcc(): SigAcc {
  return { sources: new Set(), count: 0, severityMax: "info" };
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  m: {
    distinctSources: number;
    distinctSignatures: number;
    exclusiveSignatures: number;
    labelledAlerts: number;
    sourcedAlerts: number;
    unlabelledAlerts: number;
    maxRarity: number;
    degenerate: boolean;
  },
  bandCounts: BandCounts,
  sources: RaritySource[],
  rareSignatures: RareSignature[],
): string[] {
  const out: string[] = [];
  if (m.degenerate) {
    out.push(
      `ℹ️ Only **${m.distinctSources} source** fired a labelled signature this window, so rarity is degenerate ` +
        `(every signature is trivially "exclusive" and idf collapses to 0). Rarity scoring needs at least two ` +
        `distinct sources to compare — widen the window.`,
    );
    return out;
  }
  if (!sources.length) return out;

  // The standout — the source the rarity lens is built to surface.
  const lead = sources[0]!;
  out.push(
    `🔎 Cutting through the volume, the most *distinctive* source is \`${lead.ip}\`${lead.internal ? " *(internal!)*" : ""} ` +
      `— **${bandLabel(lead.band)}**, distinctiveness **${round2(lead.distinctivenessScore)}** across ` +
      `${lead.distinctSignatures} signature(s) (${lead.exclusiveSignatures} exclusive) on just ${lead.alerts} alert(s). ` +
      `Rarest: _${lead.topSignature ? truncSig(lead.topSignature) : "—"}_.`,
  );

  // Exclusive signatures — the strongest bespoke / targeted tell. The owner of an
  // exclusive signature can sit below the volume gate or beyond the row cap, so
  // the displayed `sources` may hold none even when the window-wide count is > 0.
  if (m.exclusiveSignatures > 0) {
    const bespoke = sources.filter((s) => s.exclusiveSignatures > 0);
    const worst = [...bespoke].sort(
      (a, b) => sevRank(b.severityMax) - sevRank(a.severityMax) || b.distinctivenessScore - a.distinctivenessScore,
    )[0];
    if (worst) {
      out.push(
        `🎯 **${m.exclusiveSignatures} signature(s)** were fired by exactly *one* source each — bespoke behaviour no ` +
          `other actor is showing. **${bespoke.length} of the shown source(s)** own at least one. Most severe: ` +
          `\`${worst.ip}\` (${worst.severityMax}) with ${worst.exclusiveSignatures} exclusive signature(s) — ` +
          `start triage here.`,
      );
    } else {
      out.push(
        `🎯 **${m.exclusiveSignatures} signature(s)** were fired by exactly *one* source each — bespoke behaviour no ` +
          `other actor is showing. See the **Rarest signatures** table below for the owners (they sit below the ` +
          `per-source volume gate).`,
      );
    }
  }

  // The commodity contrast — loud but boring, safe to deprioritise.
  const loudest = [...sources].sort((a, b) => b.alerts - a.alerts)[0]!;
  if (loudest.band === "commodity" && loudest.alerts >= 5) {
    out.push(
      `📦 By contrast \`${loudest.ip}\` is the loudest source (${loudest.alerts} alert(s)) yet scores **commodity** — ` +
        `mean rarity ${round2(loudest.meanRarity)} of a possible ${round2(m.maxRarity)}. It is background radiation ` +
        `everyone sees; a volume-ranked board would wrongly put it on top.`,
    );
  }

  // Internal source firing rare things — bespoke tooling / compromise tell.
  const insider = sources.find((s) => s.internal && (s.exclusiveSignatures > 0 || s.band === "distinctive"));
  if (insider) {
    out.push(
      `🚨 *Internal* host \`${insider.ip}\` is firing **unusual** signatures (${bandLabel(insider.band)}, ` +
        `${insider.exclusiveSignatures} exclusive) — rare detections from one of your own boxes point at bespoke ` +
        `tooling or compromise, not inbound noise. Investigate before the externals.`,
    );
  }

  // The single rarest signature across the window.
  const rare = rareSignatures[0];
  if (rare && rare.distinctSources <= 2) {
    out.push(
      `🧬 Rarest detection overall: _${truncSig(rare.signature)}_ (${rare.severityMax}) — fired by only ` +
        `${rare.distinctSources} source(s)${rare.soleSource ? `, solely \`${rare.soleSource}\`` : ""} across ` +
        `${rare.count} alert(s). The niche end of the stream is where targeted activity hides.`,
    );
  }

  // Band distribution — the shape of the population.
  out.push(
    `📊 Of ${m.distinctSources} scored source(s): **${bandCounts.bespoke} bespoke** · ${bandCounts.distinctive} ` +
      `distinctive · ${bandCounts.mixed} mixed · ${bandCounts.commodity} commodity. The bespoke + distinctive ` +
      `slice is the short list worth a human's time.`,
  );

  // Coverage honesty — how much of the sourced stream carried a label.
  if (m.sourcedAlerts > 0) {
    const frac = m.unlabelledAlerts / m.sourcedAlerts;
    if (frac >= 0.25) {
      out.push(
        `ℹ️ **${pct(frac)} of sourced alerts carried no signature label** and were excluded from rarity scoring — ` +
          `the scored set is ${m.labelledAlerts} of ${m.sourcedAlerts} alert(s), so a quiet source may simply be ` +
          `under-labelled rather than rare.`,
      );
    }
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function sourceTable(rows: RaritySource[]): string {
  return mdTable(
    ["#", "Source", "Band", "Distinct.", "Sigs", "Excl.", "Mean rarity", "Peak", "Alerts", "Sev", "Rarest signature", "Flags"],
    rows.map((s, i) => {
      const flags =
        (s.internal ? "🏠" : "") +
        (s.blocked ? "⛔" : "") +
        (s.watched ? "👁" : "") +
        (s.safe ? "✅" : "");
      return [
        String(i + 1),
        cell(s.ip),
        cell(bandLabel(s.band)),
        String(round2(s.distinctivenessScore)),
        String(s.distinctSignatures),
        String(s.exclusiveSignatures),
        String(round2(s.meanRarity)),
        String(round2(s.peakRarity)),
        String(s.alerts),
        cell(s.severityMax),
        cell(s.topSignature ? truncSig(s.topSignature) : "—"),
        flags || "—",
      ];
    }),
  );
}

function signatureTable(rows: RareSignature[]): string {
  return mdTable(
    ["#", "Signature", "Rarity (idf)", "Sources", "Alerts", "Sole source", "Sev"],
    rows.map((s, i) => [
      String(i + 1),
      cell(truncSig(s.signature, 64)),
      String(round2(s.rarity)),
      String(s.distinctSources),
      String(s.count),
      cell(s.soleSource ?? "—"),
      cell(s.severityMax),
    ]),
  );
}

function renderMarkdown(m: RarityReport): string {
  const lines: string[] = [];
  lines.push(`# 🔎 SecTool Rarity / Signal-Surprise Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** every labelled signature weighted by rarity \`idf = ln(N / df)\` (N = ${m.distinctSources} distinct ` +
      `sources, df = distinct sources firing it); each source scored by Σ idf over its distinct signatures, ranked ` +
      `most distinctive first · **Scored alerts:** ${m.labelledAlerts} of ${m.sourcedAlerts} sourced ` +
      `(${m.unlabelledAlerts} unlabelled, excluded) · **Signatures:** ${m.distinctSignatures} ` +
      `(${m.exclusiveSignatures} exclusive)`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (m.degenerate || !m.sources.length) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    } else if (!m.labelledAlerts) {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but none carried both a source IP and a ` +
          `signature label, so rarity cannot be scored.`,
      );
    } else if (m.degenerate) {
      for (const h of m.highlights) lines.push(`- ${h}`);
    } else {
      lines.push(
        `${m.labelledAlerts} labelled alert(s) in the last ${m.hours} hour(s), but no source cleared the minimum ` +
          `volume gate (default ${DEFAULT_MIN_ALERTS} labelled alerts/source) to be scored.`,
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

  lines.push(`## Sources by distinctiveness`);
  lines.push("");
  lines.push(sourceTable(m.sources));
  lines.push("");
  lines.push(
    `**Legend:** _Band_ — **🎯 bespoke** (fires ≥1 signature *no other source* tripped) · ` +
      `**✨ distinctive** (mean rarity ≥ ${DISTINCTIVE_FRACTION}·ln(N)) · **◐ mixed** ` +
      `(≥ ${MIXED_FRACTION}·ln(N)) · **📦 commodity** (mostly ubiquitous background noise). _Distinct._ = Σ idf over ` +
      `the source's distinct signatures (the ranking key — blind to volume on purpose). _Mean rarity_ = idf averaged ` +
      `over its alerts (max possible ${round2(m.maxRarity)} this window). _Peak_ = its rarest single signature. ` +
      `**Flags:** 🏠 internal source · ⛔ blocked · 👁 watched · ✅ safe.`,
  );
  lines.push("");

  lines.push(`## Rarest signatures`);
  lines.push("");
  if (!m.rareSignatures.length) {
    lines.push(`_No labelled signatures to rank this window._`);
  } else {
    lines.push(
      `Individual signatures ranked by rarity — the niche rules only one or two actors ever trip, and who tripped ` +
        `them. An *exclusive* (single-source) signature at medium severity or worse is the highest-value thing here.`,
    );
    lines.push("");
    lines.push(signatureTable(m.rareSignatures));
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. **Rarity is relative to this window's source population**, not the internet — ` +
      `idf measures "unusual for my sensor, right now", which is the triage question, not global prevalence. ` +
      `**Unlabelled alerts are excluded** from scoring (${m.unlabelledAlerts} this window), so a thinly-labelled ` +
      `source can read as quiet. With a single source rarity is degenerate (everything trivially exclusive, idf = 0). ` +
      `These are IPS **detections**, not full flows, and a long look-back can hit the store's history cap — so both ` +
      `df and the source count are lower bounds. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the rarity / signal-surprise report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link RarityOptions}: `limit`, `minAlerts`, and a `nowMs` pin for
 *              deterministic tests.
 */
export function buildRarity(hours: number, opts: RarityOptions = {}): RarityReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minAlerts = Math.max(1, Math.floor(opts.minAlerts ?? DEFAULT_MIN_ALERTS));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const sources = new Map<string, SourceAcc>();
  const sigs = new Map<string, SigAcc>();
  let sourced = 0;
  let labelled = 0;
  let unlabelled = 0;

  // Pass 1 — fold alerts into per-source and per-signature accumulators.
  for (const a of windowed) {
    const src = validIp(a.srcIp);
    if (!src) continue;
    sourced++;

    const sig = sigOf(a);
    if (!sig) {
      unlabelled++;
      continue;
    }
    labelled++;

    const acc = sources.get(src) ?? newSourceAcc();
    if (!sources.has(src)) sources.set(src, acc);
    acc.alerts++;
    acc.score += weightOf(a.severity);
    acc.severityMax = maxSeverity(acc.severityMax, a.severity);
    if (isSevere(a.severity)) acc.severe++;
    acc.sigCounts.set(sig, (acc.sigCounts.get(sig) ?? 0) + 1);

    const disp = classifyDisposition(a.action);
    if (disp === "blocked") acc.blocked++;
    else if (disp === "passed") acc.passed++;
    else acc.unknown++;

    const sAcc = sigs.get(sig) ?? newSigAcc();
    if (!sigs.has(sig)) sigs.set(sig, sAcc);
    sAcc.sources.add(src);
    sAcc.count++;
    sAcc.severityMax = maxSeverity(sAcc.severityMax, a.severity);
  }

  const distinctSources = sources.size;
  const distinctSignatures = sigs.size;
  // N is the scored source population; idf = ln(N / df). With N < 2 every idf is
  // 0 (degenerate), so we flag it and skip ranking rather than emit a flat board.
  const maxRarity = distinctSources >= 2 ? Math.log(distinctSources) : 0;
  const degenerate = distinctSources < 2;

  // Per-signature rarity (idf) and exclusivity, computed once and reused.
  const idf = new Map<string, number>();
  let exclusiveCount = 0;
  for (const [sig, sAcc] of sigs) {
    const df = sAcc.sources.size;
    idf.set(sig, degenerate ? 0 : round4(Math.log(distinctSources / df)));
    if (df === 1) exclusiveCount++;
  }

  const bandCounts: BandCounts = { bespoke: 0, distinctive: 0, mixed: 0, commodity: 0 };

  const sourceList: RaritySource[] = degenerate
    ? []
    : [...sources.entries()]
        .filter(([, acc]) => acc.alerts >= minAlerts)
        .map(([ip, acc]) => {
          let distinctivenessScore = 0;
          let weightedRarity = 0;
          let exclusive = 0;
          // Start below zero so the first signature always wins, even when every
          // signature this source fires is ubiquitous (idf 0) — a commodity source
          // should still report *its* rarest signature rather than a blank.
          let peakRarity = -1;
          let topSignature: string | undefined;
          let topSignatureSources = 0;
          for (const [sig, c] of acc.sigCounts) {
            const r = idf.get(sig) ?? 0;
            const df = sigs.get(sig)?.sources.size ?? 0;
            distinctivenessScore += r;
            weightedRarity += r * c;
            if (df === 1) exclusive++;
            // Peak = rarest single signature; tie → the one this source fired most.
            if (r > peakRarity || (r === peakRarity && topSignature !== undefined && c > (acc.sigCounts.get(topSignature) ?? 0))) {
              peakRarity = r;
              topSignature = sig;
              topSignatureSources = df;
            }
          }
          const meanRarity = acc.alerts ? round4(weightedRarity / acc.alerts) : 0;
          const band = classifyBand(exclusive, meanRarity, maxRarity);
          bandCounts[band]++;
          const actioned = acc.blocked + acc.passed;
          return {
            ip,
            internal: isPrivate(ip),
            band,
            alerts: acc.alerts,
            distinctSignatures: acc.sigCounts.size,
            exclusiveSignatures: exclusive,
            distinctivenessScore: round4(distinctivenessScore),
            meanRarity,
            peakRarity: round4(Math.max(0, peakRarity)),
            topSignature,
            topSignatureSources,
            severe: acc.severe,
            score: round4(acc.score),
            severityMax: acc.severityMax,
            disposition: {
              blocked: acc.blocked,
              passed: acc.passed,
              unknown: acc.unknown,
              passRate: actioned ? round4(acc.passed / actioned) : null,
            },
            blocked: blockStore.has(ip),
            watched: watchStore.has(ip),
            safe: safeStore.has(ip),
          } satisfies RaritySource;
        })
        // Most distinctive first: Σ idf, then mean rarity, then exclusivity, then volume.
        .sort(
          (x, y) =>
            y.distinctivenessScore - x.distinctivenessScore ||
            y.meanRarity - x.meanRarity ||
            y.exclusiveSignatures - x.exclusiveSignatures ||
            y.alerts - x.alerts ||
            (x.ip < y.ip ? -1 : x.ip > y.ip ? 1 : 0),
        );

  // bandCounts is accumulated across *all* qualifying sources above; the table
  // is then capped to `limit` rows for display without disturbing the totals.
  const cappedSources = sourceList.slice(0, limit);

  const rareSignatures: RareSignature[] = degenerate
    ? []
    : [...sigs.entries()]
        .map(([signature, sAcc]) => {
          const df = sAcc.sources.size;
          return {
            signature,
            rarity: idf.get(signature) ?? 0,
            distinctSources: df,
            count: sAcc.count,
            soleSource: df === 1 ? [...sAcc.sources][0] : undefined,
            severityMax: sAcc.severityMax,
          } satisfies RareSignature;
        })
        // Rarest first: idf, then volume (a rare sig fired a lot is more notable), then name.
        .sort(
          (x, y) =>
            y.rarity - x.rarity ||
            y.count - x.count ||
            (x.signature < y.signature ? -1 : x.signature > y.signature ? 1 : 0),
        )
        .slice(0, limit);

  const highlights = writeHighlights(
    safeHours,
    {
      distinctSources,
      distinctSignatures,
      exclusiveSignatures: exclusiveCount,
      labelledAlerts: labelled,
      sourcedAlerts: sourced,
      unlabelledAlerts: unlabelled,
      maxRarity: round4(maxRarity),
      degenerate,
    },
    bandCounts,
    cappedSources,
    rareSignatures,
  );

  const model: RarityReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    sourcedAlerts: sourced,
    labelledAlerts: labelled,
    unlabelledAlerts: unlabelled,
    distinctSources,
    distinctSignatures,
    exclusiveSignatures: exclusiveCount,
    maxRarity: round4(maxRarity),
    degenerate,
    bandCounts,
    sources: cappedSources,
    rareSignatures,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded rarity report. */
export function rarityFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-rarity-${stamp}.md`;
}
