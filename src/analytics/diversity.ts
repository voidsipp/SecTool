/**
 * Threat-landscape diversity / biodiversity report — "**is my attack surface a
 * monoculture I can fight with a handful of blocks, or a sprawling, even
 * ecosystem that needs broad policy — and is it diversifying or consolidating
 * over time?**"
 *
 * SecTool already measures the *shape* of a single distribution from one angle and
 * the *richness* of one dimension from another, but it never lays a single,
 * volume-normalised, cross-dimensional diversity score side by side across the
 * whole landscape:
 *
 *   - **concentration.ts** computes the **Gini coefficient** and Pareto top-shares
 *     per dimension — an *inequality* measure ("how lopsided is this, and how few
 *     blocks buy back the quiet"). Gini and a diversity index are cousins, but a
 *     Gini of 0.8 on sources and 0.8 on signatures are not directly comparable as
 *     *counts of things* — and Gini says nothing about **richness** (how many
 *     distinct entities exist at all), which is half of what "diversity" means.
 *   - **focus.ts** is a Pareto/vital-few view; **classify.ts** rolls up the
 *     threat-class *mix* but does not score its evenness.
 *   - **audience.ts** uses an inverse-Simpson *effective source count* — but only
 *     *per signature*, to tell a sprayed signature from a sniped one. **srcport.ts**,
 *     **sequence.ts** and **stability.ts** each compute a Shannon entropy, but each
 *     bounded to one narrow sub-question (a source's port set, a next-signature
 *     fork, a severity field's self-consistency).
 *
 * None of them answer the ecologist's question about the landscape as a whole:
 * given the alerts in the window, **how many *effectively equally-common* attackers,
 * signatures, threat-classes and targets are really driving this?** Ten thousand
 * alerts can be one species or ten thousand; the raw count renders both
 * identically, and the answer flips the entire defensive strategy — block-and-win
 * versus tune-rate-limit-and-geo-policy.
 *
 * This report borrows the standard ecological diversity toolkit and applies it
 * uniformly across **four orthogonal dimensions** — **sources** (attacker IPs),
 * **signatures** (which rules fire), **categories** (Suricata threat-class) and
 * **targets** (destination hosts). For each it computes, from the per-entity alert
 * counts:
 *
 *   - **Richness (N₀)** — the raw count of distinct entities (Hill number q=0).
 *   - **Shannon index (H)** in nats, and its exponential **effective count
 *     (N₁ = eᴴ, Hill q=1)** — the number of *equally-common* entities that would
 *     produce the same Shannon diversity. This is the headline "effectively N
 *     things" figure, and unlike Gini it is in plain entity units, so the
 *     diversity of sources and of signatures sit on the same scale.
 *   - **Inverse-Simpson (N₂ = 1 / Σpᵢ², Hill q=2)** — the effective count that
 *     weights the common entities most heavily (the probability two random alerts
 *     share an entity is Σpᵢ²; N₂ is its reciprocal). N₀ ≥ N₁ ≥ N₂ always; the gap
 *     between them *is* the unevenness.
 *   - **Hill evenness (E = N₁ / N₀, 0–1)** — effective count as a fraction of the
 *     richness. 1.0 = every entity equally common (a perfectly even ecosystem);
 *     →0 = one entity dominates a long tail (a monoculture). The single comparable
 *     "how even" number, and the basis for the one-word **shape** (monoculture /
 *     concentrated / mixed / diffuse).
 *   - The **dominant** entity and its share, so the monoculture has a name.
 *
 * Then — because a snapshot of diversity is only half the story — each dimension
 * carries a **diversity drift**: the effective count (N₁) of the window's *second*
 * half versus its *first*. A rising effective count means the landscape is
 * **diversifying** (a broadening campaign, a new botnet fanning in, more rules
 * lighting up — defend wider); a falling one means it is **consolidating** (a few
 * actors / signatures taking over — a block-list is starting to pay off, or one
 * campaign is drowning out the rest).
 *
 * Honest caveats baked into the output:
 *
 *   - **Volume ≠ severity.** Diversity is measured on alert *counts*; a rich, even
 *     spread of low-severity scans can sit alongside one concentrated critical
 *     actor. Diversity guides *strategy* (broad vs narrow), not triage order — pair
 *     it with the severity-ranked reports (`--risk`, `--potency`, `--efficacy`).
 *   - **Detections, not ground truth.** One noisy rule on one host can inflate or
 *     deflate a dimension's evenness; read it next to `--tuning` and `--noise`.
 *   - **Richness is history-bounded.** The alert store is capped/rotated, so a very
 *     long window's richness undercounts entities evicted before it opened (see
 *     `--coverage`). Effective counts (N₁/N₂) are far less sensitive than raw
 *     richness, which is precisely why they are the headline.
 *   - This is the *effective-count / evenness* lens; for the *inequality / quick-win*
 *     lens of the same distributions use `--concentration` (Gini + "block N, cut
 *     X%"), and for the vital-few share use `--focus`.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network. Output is
 * both a structured model and a ready-to-paste Markdown document, mirroring
 * concentration.ts, timeline.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";

/** The dimensions the diversity toolkit is applied to, in display order. */
export type DiversityDimensionKey = "sources" | "signatures" | "categories" | "targets";

/** One-word reading of a dimension's evenness. */
export type DiversityShape = "monoculture" | "concentrated" | "mixed" | "diffuse";

/** Coarse direction of a dimension's first-half → second-half effective-count change. */
export type DiversityDrift = "diversifying" | "consolidating" | "stable" | "n/a";

/** The diversity indices for one dimension of the landscape. */
export interface DiversityDimension {
  key: DiversityDimensionKey;
  /** Human label ("Sources", "Signatures", …). */
  label: string;
  /** Plural noun for prose ("attacker IPs", "signatures", …). */
  noun: string;
  /** Alerts in the window that carried a usable value for this dimension. */
  total: number;
  /** Richness — distinct entities (Hill N₀, q=0). */
  richness: number;
  /** Shannon index H in nats. */
  shannon: number;
  /** Effective count N₁ = eᴴ (Hill q=1) — equally-common entities of equal diversity. */
  effective1: number;
  /** Inverse-Simpson N₂ = 1 / Σpᵢ² (Hill q=2). */
  effective2: number;
  /** Σpᵢ² — Simpson's dominance (probability two random alerts share an entity). */
  simpson: number;
  /** Gini-Simpson diversity 1 − Σpᵢ². */
  giniSimpson: number;
  /** Pielou evenness J = H / ln(R); 1 when R ≤ 1. */
  pielou: number;
  /** Hill evenness E = N₁ / N₀ (0–1) — the headline "how even" number. */
  evenness: number;
  /** Share (0–1) of the single most-common entity. */
  dominantShare: number;
  /** The most-common entity's label, or undefined when the dimension is empty. */
  dominant?: string;
  /** One-word reading of {@link evenness}. */
  shape: DiversityShape;
  /** Percent change in effective count (N₁) second half vs first half; null if undefined. */
  driftPct: number | null;
  /** Coarse direction of {@link driftPct}. */
  drift: DiversityDrift;
}

export interface DiversityReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Total alerts (with a usable timestamp) inside the window. */
  totalAlerts: number;
  /** The four dimensions, in display order. */
  dimensions: DiversityDimension[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface DiversityOptions {
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const MS_PER_HOUR = 3_600_000;

/** Evenness thresholds (Hill E = N₁/N₀) for the one-word shape. */
const EVEN_DIFFUSE = 0.7;
const EVEN_MIXED = 0.4;
const EVEN_CONCENTRATED = 0.15;
/** A diversity drift beyond this magnitude (%) counts as a real move, not noise. */
const DRIFT_THRESHOLD_PCT = 15;

// ----- helpers (mirror concentration.ts / timeline.ts) -----------------------

function validIp(ip: string | undefined): string | undefined {
  return ip && isIP(ip) !== 0 ? ip : undefined;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function clip(s: string, max = 38): string {
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

/** Round to `dp` decimal places, returned as a number (avoids 0.30000000001 noise). */
function round(n: number, dp = 2): number {
  const f = 10 ** dp;
  return Math.round(n * f) / f;
}

function pct(n: number): string {
  return `${Math.round(n * 100)}%`;
}

/** A short proportional meter (0–1) for an inline evenness gauge. */
function meter(frac: number, width = 8): string {
  const f = Math.max(0, Math.min(1, frac));
  const filled = Math.round(f * width);
  return "█".repeat(filled) + "░".repeat(width - filled);
}

/** ▲+X% / ▼-X% / – delta label for a percent change (null → not computable). */
function driftLabel(pct: number | null): string {
  if (pct === null) return "—";
  if (pct === 0) return "± 0%";
  const arrow = pct > 0 ? "▲" : "▼";
  const mag = Math.abs(pct);
  return `${arrow} ${mag >= 1000 ? "≥1000" : Math.round(mag)}%`;
}

function shapeOf(evenness: number): DiversityShape {
  if (evenness >= EVEN_DIFFUSE) return "diffuse";
  if (evenness >= EVEN_MIXED) return "mixed";
  if (evenness >= EVEN_CONCENTRATED) return "concentrated";
  return "monoculture";
}

const SHAPE_GLYPH: Record<DiversityShape, string> = {
  diffuse: "🌐",
  mixed: "🔀",
  concentrated: "🎯",
  monoculture: "🧬",
};

const DRIFT_GLYPH: Record<DiversityDrift, string> = {
  diversifying: "📈",
  consolidating: "📉",
  stable: "➖",
  "n/a": "·",
};

// ----- core diversity math ---------------------------------------------------

interface DistMath {
  total: number;
  richness: number;
  shannon: number;
  effective1: number;
  effective2: number;
  simpson: number;
  giniSimpson: number;
  pielou: number;
  evenness: number;
  dominantShare: number;
  dominant?: string;
}

/**
 * Compute the full diversity toolkit for one count map. Returns a zeroed result
 * for an empty map so callers never branch on emptiness.
 */
function diversityOf(counts: Map<string, number>): DistMath {
  let total = 0;
  for (const n of counts.values()) total += n;
  const richness = counts.size;
  if (total === 0 || richness === 0) {
    return {
      total: 0,
      richness: 0,
      shannon: 0,
      effective1: 0,
      effective2: 0,
      simpson: 0,
      giniSimpson: 0,
      pielou: 0,
      evenness: 0,
      dominantShare: 0,
    };
  }
  let shannon = 0;
  let sumSq = 0;
  let topN = -1;
  let dominant: string | undefined;
  for (const [k, n] of counts) {
    const p = n / total;
    shannon += -p * Math.log(p);
    sumSq += p * p;
    // Deterministic tie-break on the key so output is stable run-to-run.
    if (n > topN || (n === topN && dominant !== undefined && k < dominant)) {
      topN = n;
      dominant = k;
    }
  }
  const effective1 = Math.exp(shannon); // Hill N₁
  const effective2 = sumSq > 0 ? 1 / sumSq : 0; // Hill N₂ (inverse-Simpson)
  const pielou = richness > 1 ? shannon / Math.log(richness) : 1; // even by definition when R≤1
  const evenness = richness > 0 ? effective1 / richness : 0; // Hill evenness E = N₁/N₀
  return {
    total,
    richness,
    shannon,
    effective1,
    effective2,
    simpson: sumSq,
    giniSimpson: 1 - sumSq,
    pielou,
    evenness,
    dominantShare: topN / total,
    dominant,
  };
}

/** Effective count N₁ for a count map alone (used for the half-window drift). */
function effective1Of(counts: Map<string, number>): number {
  return diversityOf(counts).effective1;
}

function bump(m: Map<string, number>, k: string): void {
  m.set(k, (m.get(k) ?? 0) + 1);
}

/** Pull the dimension value from an alert, or undefined when it carries none. */
function valueFor(key: DiversityDimensionKey, a: StoredAlert): string | undefined {
  switch (key) {
    case "sources":
      return validIp(a.srcIp);
    case "targets":
      return validIp(a.dstIp);
    case "signatures": {
      const s = (a.signature ?? "").trim();
      return s || undefined;
    }
    case "categories": {
      const c = (a.category ?? "").trim();
      return c || undefined;
    }
  }
}

const DIMENSIONS: ReadonlyArray<{ key: DiversityDimensionKey; label: string; noun: string }> = [
  { key: "sources", label: "Sources", noun: "attacker IPs" },
  { key: "signatures", label: "Signatures", noun: "signatures" },
  { key: "categories", label: "Categories", noun: "threat-classes" },
  { key: "targets", label: "Targets", noun: "destination hosts" },
];

// ----- highlights ------------------------------------------------------------

function writeHighlights(dims: DiversityDimension[]): string[] {
  const out: string[] = [];
  const populated = dims.filter((d) => d.total > 0 && d.richness > 0);
  if (!populated.length) return out;

  // Most concentrated dimension (lowest evenness, but only where there's room to
  // be uneven — richness > 1) — where blocking a few entities buys the most quiet.
  const concentrated = [...populated]
    .filter((d) => d.richness > 1)
    .sort((a, b) => a.evenness - b.evenness)[0];
  if (concentrated && concentrated.evenness < EVEN_DIFFUSE) {
    out.push(
      `${SHAPE_GLYPH[concentrated.shape]} Most concentrated: **${concentrated.label.toLowerCase()}** ` +
        `(evenness ${round(concentrated.evenness)}, effectively **${round(concentrated.effective1, 1)}** of ` +
        `${concentrated.richness} ${concentrated.noun})${concentrated.dominant ? ` — led by \`${clip(concentrated.dominant, 46)}\` ` +
        `at ${pct(concentrated.dominantShare)} of volume` : ""}. A few targeted blocks/tunes go a long way here — see \`--concentration\`.`,
    );
  }

  // Most diverse dimension — where no single block helps and broad policy is the play.
  const diffuse = [...populated].sort((a, b) => b.effective1 - a.effective1)[0];
  if (diffuse && diffuse.richness > 1) {
    out.push(
      `${SHAPE_GLYPH[diffuse.shape]} Broadest front: **${diffuse.label.toLowerCase()}** spread across an effective ` +
        `**${round(diffuse.effective1, 1)}** ${diffuse.noun} (of ${diffuse.richness}; evenness ${round(diffuse.evenness)}). ` +
        `No single block moves the needle — think rate-limiting, geo/ASN policy or rule tuning, not a short blocklist.`,
    );
  }

  // Diversity drift — the campaign-onset / consolidation tell.
  const diversifying = populated
    .filter((d) => d.drift === "diversifying" && d.driftPct !== null)
    .sort((a, b) => (b.driftPct ?? 0) - (a.driftPct ?? 0))[0];
  if (diversifying) {
    out.push(
      `📈 Diversifying: **${diversifying.label.toLowerCase()}** widened **${driftLabel(diversifying.driftPct).replace(/^▲ /, "")}** ` +
        `(effective count, second half vs first) — a broadening campaign or new infrastructure fanning in. Cross-check \`--novelty\`.`,
    );
  }
  const consolidating = populated
    .filter((d) => d.drift === "consolidating" && d.driftPct !== null)
    .sort((a, b) => (a.driftPct ?? 0) - (b.driftPct ?? 0))[0];
  if (consolidating) {
    out.push(
      `📉 Consolidating: **${consolidating.label.toLowerCase()}** narrowed **${driftLabel(consolidating.driftPct).replace(/^▼ /, "")}** ` +
        `(effective count, second half vs first) — a few ${consolidating.noun} are taking over (one campaign dominating, or a ` +
        `block-list paying off). Confirm with \`--heat\` / \`--recidivism\`.`,
    );
  }

  // A monoculture call-out names the single thing running the show.
  const mono = populated.find((d) => d.shape === "monoculture" && d.richness > 1 && d.dominant);
  if (mono) {
    out.push(
      `🧬 Monoculture warning: one ${mono.noun.replace(/s$/, "")} — \`${clip(mono.dominant!, 46)}\` — owns ` +
        `${pct(mono.dominantShare)} of all ${mono.label.toLowerCase()} volume. The landscape *looks* busy but is effectively ` +
        `one actor; a single well-placed control could quiet most of it.`,
    );
  }

  return out;
}

// ----- markdown --------------------------------------------------------------

function indicesTable(dims: DiversityDimension[]): string {
  return mdTable(
    ["Dimension", "Alerts", "Richness N₀", "Effective N₁", "Inv-Simpson N₂", "Evenness", "Shape", "Dominant", "Drift"],
    dims.map((d) => {
      if (d.total === 0) {
        return [`**${d.label}**`, "0", "0", "—", "—", "—", "_n/a_", "—", "—"];
      }
      return [
        `**${d.label}**`,
        String(d.total),
        String(d.richness),
        round(d.effective1, 1).toFixed(1),
        round(d.effective2, 1).toFixed(1),
        `\`${meter(d.evenness)}\` ${round(d.evenness)}`,
        `${SHAPE_GLYPH[d.shape]} ${d.shape}`,
        d.dominant ? `${cell(clip(d.dominant, 30))} (${pct(d.dominantShare)})` : "—",
        `${DRIFT_GLYPH[d.drift]} ${d.drift === "n/a" ? "—" : driftLabel(d.driftPct)}`,
      ];
    }),
  );
}

function renderMarkdown(m: DiversityReport): string {
  const lines: string[] = [];
  lines.push(`# 🧬 SecTool Threat-Landscape Diversity`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** ecological diversity indices (Hill numbers N₀/N₁/N₂, Shannon H, Simpson, Pielou & Hill evenness) ` +
      `over per-entity alert counts, computed identically across four dimensions. ` +
      `Offline, deterministic · **Total alerts:** ${m.totalAlerts}.`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (m.totalAlerts === 0) {
    lines.push(
      `No alerts with a usable timestamp landed in the last ${m.hours}h — there is no landscape to measure. ` +
        `Widen the window (\`--diversity <more hours>\`) or confirm forwarding with \`--coverage\`.`,
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  if (m.highlights.length) {
    for (const h of m.highlights) lines.push(`- ${h}`);
  } else {
    lines.push(`_Too little spread to read — every dimension is effectively a single entity in this window._`);
  }
  lines.push("");

  lines.push(`## Diversity by dimension`);
  lines.push("");
  lines.push(indicesTable(m.dimensions));
  lines.push("");
  lines.push(
    `**How to read it:** _N₀_ is the raw count of distinct entities (richness). _N₁ = eᴴ_ and _N₂ = 1/Σpᵢ²_ are ` +
      `**effective counts** — how many *equally-common* entities would yield the same diversity (N₀ ≥ N₁ ≥ N₂; the gap ` +
      `is the unevenness). _Evenness_ = N₁/N₀ on a 0–1 scale (1 = perfectly even, →0 = one entity dominates). _Shape_: ` +
      `${SHAPE_GLYPH.diffuse} diffuse (≥${EVEN_DIFFUSE}) · ${SHAPE_GLYPH.mixed} mixed (≥${EVEN_MIXED}) · ` +
      `${SHAPE_GLYPH.concentrated} concentrated (≥${EVEN_CONCENTRATED}) · ${SHAPE_GLYPH.monoculture} monoculture. ` +
      `_Drift_ = change in effective count (N₁) second half vs first (📈 diversifying / 📉 consolidating).`,
  );
  lines.push("");

  // A small per-dimension detail block for the numbers the table can't fit.
  lines.push(`## Detail`);
  lines.push("");
  for (const d of m.dimensions) {
    if (d.total === 0) {
      lines.push(`- **${d.label}** — no ${d.noun} carried a usable value in the window.`);
      continue;
    }
    const driftPhrase =
      d.drift === "n/a"
        ? "drift not computable (one half was empty)"
        : d.drift === "stable"
          ? "effective count held steady across the window"
          : `effective count ${d.drift === "diversifying" ? "rose" : "fell"} ${driftLabel(d.driftPct).replace(/^[▲▼] /, "")} second half vs first (${d.drift})`;
    lines.push(
      `- **${d.label}** (${d.total} alert(s), ${d.richness} distinct ${d.noun}): ` +
        `effectively **${round(d.effective1, 1)}** equally-common ${d.noun} (N₁), ` +
        `${round(d.effective2, 1)} by inverse-Simpson (N₂); Shannon H ${round(d.shannon, 2)}, ` +
        `Pielou J ${round(d.pielou)}, Gini-Simpson ${round(d.giniSimpson)}; ` +
        `**${d.shape}** (evenness ${round(d.evenness)})${d.dominant ? `, dominated by \`${clip(d.dominant, 50)}\` at ${pct(d.dominantShare)}` : ""}; ${driftPhrase}.`,
    );
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Diversity is measured on alert **counts**, not severity — it guides *strategy* ` +
      `(fight narrow vs broad), not triage order (pair with \`--risk\` / \`--potency\`). Richness is bounded by the ` +
      `retained store (see \`--coverage\`); effective counts (N₁/N₂) are far less sensitive to that cap than raw richness. ` +
      `This is the effective-count / evenness lens — for the inequality / quick-win lens of the same distributions use ` +
      `\`--concentration\` (Gini + "block N, cut X%") and \`--focus\` (vital-few share). No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the threat-landscape diversity report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 365 days]).
 * @param opts  {@link DiversityOptions}: a `nowMs` pin for deterministic tests.
 */
export function buildDiversity(hours: number, opts: DiversityOptions = {}): DiversityReport {
  const safeHours = Math.max(1, Math.min(24 * 365, Math.floor(hours)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;
  const midMs = windowStartMs + (windowEndMs - windowStartMs) / 2;

  const windowed = alertStore
    .all()
    .filter(
      (a): a is StoredAlert =>
        typeof a.time === "number" &&
        Number.isFinite(a.time) &&
        a.time >= windowStartMs &&
        a.time <= windowEndMs,
    );

  const totalAlerts = windowed.length;

  const dimensions: DiversityDimension[] = DIMENSIONS.map(({ key, label, noun }) => {
    const counts = new Map<string, number>();
    const firstHalf = new Map<string, number>();
    const secondHalf = new Map<string, number>();
    for (const a of windowed) {
      const v = valueFor(key, a);
      if (!v) continue;
      bump(counts, v);
      if (a.time < midMs) bump(firstHalf, v);
      else bump(secondHalf, v);
    }

    const d = diversityOf(counts);

    // Diversity drift: effective count (N₁) of the second half vs the first.
    let driftPct: number | null = null;
    let drift: DiversityDrift = "n/a";
    if (firstHalf.size > 0 && secondHalf.size > 0) {
      const e1a = effective1Of(firstHalf);
      const e1b = effective1Of(secondHalf);
      if (e1a > 0) {
        driftPct = Math.round(((e1b - e1a) / e1a) * 100);
        drift =
          driftPct > DRIFT_THRESHOLD_PCT
            ? "diversifying"
            : driftPct < -DRIFT_THRESHOLD_PCT
              ? "consolidating"
              : "stable";
      }
    }

    return {
      key,
      label,
      noun,
      total: d.total,
      richness: d.richness,
      shannon: d.shannon,
      effective1: d.effective1,
      effective2: d.effective2,
      simpson: d.simpson,
      giniSimpson: d.giniSimpson,
      pielou: d.pielou,
      evenness: d.evenness,
      dominantShare: d.dominantShare,
      dominant: d.dominant,
      shape: shapeOf(d.evenness),
      driftPct,
      drift,
    };
  });

  const highlights = writeHighlights(dimensions);

  const model: DiversityReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalAlerts,
    dimensions,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded diversity report. */
export function diversityFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-diversity-${stamp}.md`;
}
