/**
 * Single-signature dossier report — "**tell me everything about THIS one
 * detection.**"
 *
 * `profile.ts` answers the investigator's question on the *entity* axis ("tell me
 * everything about this one IP"). This module is its exact twin on the *signature*
 * axis: the analyst stares at one Suricata rule name in a Discord ping or another
 * report and asks *"what is this detection, how often does it fire, who trips it,
 * what does it hit, is the gateway actually stopping it, and is it a real threat
 * or rule noise?"* — and wants the whole answer on one page.
 *
 * Every existing signature-oriented report deliberately ranks *many* signatures,
 * one summarised row each, and is the wrong tool for drilling into a single one:
 *
 *   - **tuning.ts** scores *all* signatures for noise-reduction triage (which to
 *     suppress) — a leaderboard, not a dossier.
 *   - **audience.ts** asks, per signature, *who* trips it (source breadth) — one
 *     axis only, across the whole catalogue.
 *   - **lifecycle.ts** tracks each signature's *appear → peak → fade* shape over
 *     time — again the whole set, one curve each.
 *   - **efficacy.ts / priority.ts** roll signatures up by *disposition* (blocked
 *     vs passed) to find enforcement gaps — fleet-wide, not a single-rule view.
 *
 * None of them let you type one signature and get *its* volume, severity profile,
 * enforcement posture, attacker set, target set, threat taxonomy, CVE/CWE
 * references, a volume sparkline, representative raw detections and any stored AI
 * summary — together. That is this report.
 *
 * **Matching is forgiving.** A real Suricata signature string is long and full of
 * punctuation ("ET SCAN Suspicious inbound to MSSQL port 1433"), so the query is
 * a *case-insensitive substring*: `--detection mssql` resolves to that rule. When
 * the substring hits more than one distinct signature the dossier profiles the
 * **busiest** match and lists the alternatives so the operator can narrow the
 * query. When nothing matches it degrades to a clearly-flagged stub that suggests
 * the loudest signatures actually present in the window.
 *
 * Honest caveats baked into the output:
 *
 *   - **Block rate excludes unknown disposition.** It is computed only over
 *     alerts the gateway labelled (blocked / detected / allowed); action-less
 *     alerts are reported but never silently counted as either — mirroring
 *     efficacy.ts so the rate isn't flattered.
 *   - **CVE/CWE references are scraped, not authoritative.** They are pulled from
 *     the signature text and raw detections by pattern; see `--cve` / `--cwe` for
 *     the curated cross-window rollups.
 *   - **Severity is the derived field.** If one signature shows several severities
 *     the dossier flags it and points at `--stability` for the trust audit.
 *
 * Pure in-memory math over alertStore (with triage state) — no SSH, no Claude, no
 * network. Output is both a structured model and a ready-to-paste Markdown
 * document, mirroring profile.ts, report.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { dismissStore } from "../store/dismissed.ts";
import { triageStore, type TriageStatus } from "../store/triage.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** A distinct signature the query matched, with its alert volume (for disambiguation). */
export interface DetectionMatch {
  signature: string;
  count: number;
}

/** One attacking source that tripped the profiled signature. */
export interface DetectionSourceEntry {
  ip: string;
  count: number;
  internal: boolean;
  lastSeen: number;
  severityMax: Severity;
}

/** One target the profiled signature fired against. */
export interface DetectionTargetEntry {
  ip: string;
  count: number;
  internal: boolean;
}

export interface DetectionTimelineBucket {
  startMs: number;
  count: number;
}

/** A representative raw detection line, lightly clipped for display. */
export interface DetectionSample {
  id: string;
  time: number;
  severity: string;
  srcIp?: string;
  dstIp?: string;
  action: string;
  raw: string;
}

export interface DetectionModel {
  /** The query the operator typed, echoed back trimmed. */
  query: string;
  /** False when the query matched no signature — the model is then a guidance stub. */
  matched: boolean;
  /** The resolved (busiest-matching) signature, or "" when none matched. */
  signature: string;
  /** How many distinct signatures the substring query matched. */
  matchCount: number;
  /** Other signatures the query matched (busiest profiled one excluded), busiest first. */
  alternatives: DetectionMatch[];
  /** When `matched` is false: the loudest signatures in the window to try instead. */
  suggestions: DetectionMatch[];
  /** Look-back window in hours; 0 = entire stored history. */
  hours: number;
  /** When the dossier was generated, ms epoch. */
  generatedAt: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts carrying the resolved signature in the window. */
  total: number;
  firstSeen?: number;
  lastSeen?: number;
  spanMs: number;
  severityMax: Severity;
  /** Per-severity counts, ordered info → critical (zeros included). */
  bySeverity: Array<{ severity: Severity; count: number }>;
  /** How many distinct severities this one signature was assigned. */
  distinctSeverities: number;
  /** True when the signature always derived to a single severity (trustworthy to sort on). */
  severityConsistent: boolean;
  /** Disposition breakdown (blocked / detected / allowed / unknown), zeros omitted. */
  byAction: Array<{ action: string; count: number }>;
  /** Blocked share of *labelled* alerts (excludes unknown disposition); null if none labelled. */
  blockRate: number | null;
  /** Distinct attacking sources / distinct targets. */
  distinctSources: number;
  distinctTargets: number;
  /** Top attacking sources, busiest first. */
  topSources: DetectionSourceEntry[];
  /** Top targets, busiest first. */
  topTargets: DetectionTargetEntry[];
  topCategories: DetectionMatch[];
  topClassifications: DetectionMatch[];
  /** Triage workflow breakdown across the matching alerts. */
  byTriage: Array<{ status: TriageStatus | "open"; count: number }>;
  /** CVE / CWE identifiers scraped from the signature text and raw detections. */
  refs: { cves: string[]; cwes: string[] };
  /** Volume buckets across the window (always 24 evenly-sized bins). */
  timeline: DetectionTimelineBucket[];
  timelineBucketMs: number;
  timelineMax: number;
  /** A few representative raw detections, most-recent first. */
  samples: DetectionSample[];
  /** A stored Claude summary excerpt for this signature, if one exists. */
  aiSummary?: { title: string; whatHappened: string; model?: string };
  /** Composite 0-100 threat score (see scoreDetection). */
  riskScore: number;
  /** Plain-language one-line headline. */
  narrative: string;
  /** Bulleted call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

const DEFAULT_TOP_N = 12;
const TIMELINE_BUCKETS = 24;
const SAMPLE_LIMIT = 5;
const ALT_LIMIT = 12;
const MS_PER_HOUR = 3_600_000;

// ----- helpers (mirror profile.ts conventions) -------------------------------

function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
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

function bump<T>(m: Map<T, number>, k: T | undefined | null): void {
  if (k === undefined || k === null || k === "") return;
  m.set(k, (m.get(k) ?? 0) + 1);
}

function pct(n: number, total: number): number {
  return total > 0 ? Math.round((n / total) * 100) : 0;
}

function topMatches(m: Map<string, number>, n: number): DetectionMatch[] {
  return [...m.entries()]
    .map(([signature, count]) => ({ signature, count }))
    .sort((a, b) => b.count - a.count || a.signature.localeCompare(b.signature))
    .slice(0, n);
}

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
  if (ms <= 0) return "—";
  const m = Math.round(ms / 60_000);
  if (m < 60) return `${m}m`;
  const h = m / 60;
  if (h < 48) return `${h.toFixed(1)}h`;
  return `${(h / 24).toFixed(1)}d`;
}

function sparkline(timeline: DetectionTimelineBucket[], max: number): string {
  const blocks = "▁▂▃▄▅▆▇█";
  const peak = max || 1;
  return timeline
    .map((b) => {
      if (b.count === 0) return "·";
      const idx = Math.min(blocks.length - 1, Math.max(0, Math.round((b.count / peak) * (blocks.length - 1))));
      return blocks[idx];
    })
    .join("");
}

function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function clip(s: string, max = 120): string {
  const t = s.trim().replace(/\s+/g, " ");
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

function mdTable(headers: string[], rows: string[][]): string {
  if (!rows.length) return "_None._";
  const head = `| ${headers.join(" | ")} |`;
  const sep = `| ${headers.map(() => "---").join(" | ")} |`;
  const body = rows.map((r) => `| ${r.join(" | ")} |`).join("\n");
  return `${head}\n${sep}\n${body}`;
}

/** Scrape CVE-YYYY-NNNN and CWE-NNN identifiers from arbitrary text. */
function scrapeRefs(text: string, cves: Set<string>, cwes: Set<string>): void {
  const cveRe = /CVE-\d{4}-\d{4,7}/gi;
  const cweRe = /CWE-\d{1,5}/gi;
  for (const m of text.matchAll(cveRe)) cves.add(m[0].toUpperCase());
  for (const m of text.matchAll(cweRe)) cwes.add(m[0].toUpperCase());
}

/**
 * Composite 0-100 threat score for a single signature. Rewards peak severity,
 * raw volume and attacker breadth (a rule tripped by many sources is a broad
 * campaign, not a one-off), and adds an exposure penalty when a *serious*
 * signature is not being fully blocked.
 */
function scoreDetection(p: {
  severityMax: Severity;
  total: number;
  distinctSources: number;
  blocked: number;
  labelled: number;
}): number {
  if (p.total === 0) return 0;
  let score = sevRank(p.severityMax) * 14; // up to 56 from severity
  score += Math.min(20, Math.log2(p.total + 1) * 5); // volume, diminishing
  score += Math.min(14, (p.distinctSources - 1) * 3); // breadth of attackers
  // Exposure: a high/critical signature the gateway is not stopping.
  if (sevRank(p.severityMax) >= sevRank("high") && p.labelled > 0) {
    const unblockedShare = (p.labelled - p.blocked) / p.labelled;
    score += Math.round(unblockedShare * 12);
  }
  return Math.max(0, Math.min(100, Math.round(score)));
}

// ----- narrative -------------------------------------------------------------

function writeNarrative(
  model: Omit<DetectionModel, "narrative" | "highlights" | "markdown">,
): { narrative: string; highlights: string[] } {
  const highlights: string[] = [];

  if (!model.matched) {
    return {
      narrative:
        `No signature matching "${model.query}" fired${model.hours ? ` in the last ${model.hours}h` : " in the stored history"}.`,
      highlights,
    };
  }

  const windowLabel = model.hours ? `the last ${model.hours}h` : "stored history";
  const narrative =
    `\`${model.signature}\` fired in **${model.total}** alert(s) across ${windowLabel} ` +
    `from **${model.distinctSources}** distinct source(s) against **${model.distinctTargets}** target(s), ` +
    `peaking at ${model.severityMax} severity (threat score ${model.riskScore}/100).`;

  const sevMap = new Map(model.bySeverity.map((s) => [s.severity, s.count]));
  const crit = sevMap.get("critical") ?? 0;
  const high = sevMap.get("high") ?? 0;
  if (crit + high > 0) highlights.push(`${crit} critical + ${high} high-severity hit(s).`);

  if (model.blockRate !== null) {
    const blocked = model.byAction.find((a) => a.action === "blocked")?.count ?? 0;
    const labelled = model.byAction
      .filter((a) => a.action !== "unknown")
      .reduce((s, a) => s + a.count, 0);
    const posture =
      model.blockRate >= 99
        ? "fully enforced by the gateway"
        : model.blockRate === 0
          ? "**detect-only — nothing is being blocked**"
          : `only ${model.blockRate}% blocked`;
    highlights.push(`${blocked}/${labelled} labelled alert(s) blocked → ${posture}.`);
  }

  if (!model.severityConsistent) {
    highlights.push(
      `Severity is **inconsistent** (${model.distinctSeverities} distinct levels) — confirm with \`--stability\`.`,
    );
  }

  if (model.refs.cves.length || model.refs.cwes.length) {
    const parts: string[] = [];
    if (model.refs.cves.length) parts.push(model.refs.cves.slice(0, 5).join(", "));
    if (model.refs.cwes.length) parts.push(model.refs.cwes.slice(0, 5).join(", "));
    highlights.push(`References: ${parts.join(" · ")}.`);
  }

  if (model.firstSeen && model.lastSeen) {
    highlights.push(
      `Active ${fmtAgo(model.firstSeen, model.generatedAt)} → ${fmtAgo(model.lastSeen, model.generatedAt)} ` +
        `(span ${fmtSpan(model.spanMs)}).`,
    );
  }

  const open = model.byTriage.find((t) => t.status === "open")?.count ?? 0;
  if (open > 0) highlights.push(`${open} alert(s) still open in triage.`);

  if (model.matchCount > 1) {
    highlights.push(
      `Query matched ${model.matchCount} signatures — profiling the busiest; ${model.alternatives.length} alternative(s) listed below.`,
    );
  }

  return { narrative, highlights };
}

// ----- markdown --------------------------------------------------------------

function renderMarkdown(model: DetectionModel): string {
  const lines: string[] = [];
  lines.push(`# 🔬 SecTool Detection Dossier`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(model.generatedAt)}`);
  lines.push(`**Query:** \`${model.query}\``);
  lines.push(`**Scope:** ${model.hours ? `last ${model.hours}h` : "entire stored history"}`);
  lines.push("");

  // No-match guidance stub.
  if (!model.matched) {
    lines.push(`## No match`);
    lines.push("");
    lines.push(model.narrative);
    lines.push("");
    if (model.suggestions.length) {
      lines.push(`Try one of the loudest signatures currently in the window:`);
      lines.push("");
      lines.push(
        mdTable(
          ["#", "Signature", "Alerts"],
          model.suggestions.map((s, i) => [String(i + 1), cell(clip(s.signature, 80)), String(s.count)]),
        ),
      );
      lines.push("");
    } else {
      lines.push(`_No signatures are present in the window at all — widen the scope or check \`--coverage\`._`);
      lines.push("");
    }
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  lines.push(`**Signature:** \`${model.signature}\``);
  lines.push(`**Threat score:** ${model.riskScore}/100 (peak severity ${model.severityMax})`);
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  lines.push(model.narrative);
  if (model.highlights.length) {
    lines.push("");
    for (const h of model.highlights) lines.push(`- ${h}`);
  }
  lines.push("");

  lines.push(`## Key metrics`);
  lines.push("");
  lines.push(
    mdTable(
      ["Metric", "Value"],
      [
        ["Total alerts", String(model.total)],
        ["Distinct sources", String(model.distinctSources)],
        ["Distinct targets", String(model.distinctTargets)],
        ["Peak severity", model.severityMax],
        [
          "Block rate",
          model.blockRate === null ? "— (no labelled disposition)" : `${model.blockRate}% (of labelled)`,
        ],
        ["First seen", model.firstSeen ? `${fmtTime(model.firstSeen)} (${fmtAgo(model.firstSeen, model.generatedAt)})` : "—"],
        ["Last seen", model.lastSeen ? `${fmtTime(model.lastSeen)} (${fmtAgo(model.lastSeen, model.generatedAt)})` : "—"],
        ["Active span", fmtSpan(model.spanMs)],
      ],
    ),
  );
  lines.push("");

  lines.push(`## Severity breakdown`);
  lines.push("");
  lines.push(
    mdTable(
      ["Severity", "Count", "Share"],
      model.bySeverity.map((s) => [cell(s.severity), String(s.count), `${pct(s.count, model.total)}%`]),
    ),
  );
  if (!model.severityConsistent) {
    lines.push("");
    lines.push(
      `> ⚠ This signature derived to **${model.distinctSeverities}** distinct severities — the value other reports ` +
        `sort on is not stable for it. See \`--stability\` for the per-signature severity-trust audit.`,
    );
  }
  lines.push("");

  if (model.byAction.length) {
    lines.push(`## Disposition (enforcement)`);
    lines.push("");
    lines.push(
      mdTable(
        ["Action", "Count", "Share"],
        model.byAction.map((a) => [cell(a.action), String(a.count), `${pct(a.count, model.total)}%`]),
      ),
    );
    lines.push("");
    lines.push(
      `_Block rate is computed over **labelled** alerts only (blocked / detected / allowed); ` +
        `\`unknown\` disposition is excluded from the denominator — see \`--efficacy\` for the fleet-wide gap view._`,
    );
    lines.push("");
  }

  lines.push(`## Volume over time`);
  lines.push("");
  lines.push("```");
  lines.push(sparkline(model.timeline, model.timelineMax));
  lines.push(`${fmtTime(model.windowStartMs)}  …  ${fmtTime(model.windowEndMs)}   (peak ${model.timelineMax}/bucket)`);
  lines.push("```");
  lines.push("");

  lines.push(`## Top attacking sources`);
  lines.push("");
  lines.push(
    mdTable(
      ["#", "Source IP", "Scope", "Hits", "Max sev", "Last seen"],
      model.topSources.map((s, i) => [
        String(i + 1),
        cell(s.ip),
        s.internal ? "internal" : "external",
        String(s.count),
        cell(s.severityMax),
        fmtAgo(s.lastSeen, model.generatedAt),
      ]),
    ),
  );
  lines.push("");

  lines.push(`## Top targets`);
  lines.push("");
  lines.push(
    mdTable(
      ["#", "Target IP", "Scope", "Hits"],
      model.topTargets.map((t, i) => [String(i + 1), cell(t.ip), t.internal ? "internal" : "external", String(t.count)]),
    ),
  );
  lines.push("");

  if (model.topCategories.length || model.topClassifications.length) {
    lines.push(`## Threat taxonomy`);
    lines.push("");
    if (model.topCategories.length) {
      lines.push(`**Categories**`);
      lines.push("");
      lines.push(
        mdTable(
          ["Category", "Count"],
          model.topCategories.map((c) => [cell(c.signature), String(c.count)]),
        ),
      );
      lines.push("");
    }
    if (model.topClassifications.length) {
      lines.push(`**Classifications**`);
      lines.push("");
      lines.push(
        mdTable(
          ["Classification", "Count"],
          model.topClassifications.map((c) => [cell(c.signature), String(c.count)]),
        ),
      );
      lines.push("");
    }
  }

  if (model.refs.cves.length || model.refs.cwes.length) {
    lines.push(`## References (scraped)`);
    lines.push("");
    if (model.refs.cves.length) lines.push(`- **CVEs:** ${model.refs.cves.join(", ")}`);
    if (model.refs.cwes.length) lines.push(`- **CWEs:** ${model.refs.cwes.join(", ")}`);
    lines.push("");
    lines.push(`_Scraped by pattern from the signature text and raw detections — see \`--cve\` / \`--cwe\` for curated rollups._`);
    lines.push("");
  }

  if (model.aiSummary) {
    lines.push(`## AI analyst summary`);
    lines.push("");
    lines.push(`**${cell(model.aiSummary.title)}**`);
    lines.push("");
    lines.push(clip(model.aiSummary.whatHappened, 600));
    if (model.aiSummary.model) {
      lines.push("");
      lines.push(`_— ${cell(model.aiSummary.model)}_`);
    }
    lines.push("");
  }

  if (model.samples.length) {
    lines.push(`## Representative raw detections`);
    lines.push("");
    for (const s of model.samples) {
      const meta = `${fmtTime(s.time)} · ${s.severity} · ${s.action}` +
        `${s.srcIp ? ` · src ${s.srcIp}` : ""}${s.dstIp ? ` → dst ${s.dstIp}` : ""}`;
      lines.push(`- ${meta}`);
      lines.push("  ```");
      lines.push(`  ${clip(s.raw, 240)}`);
      lines.push("  ```");
    }
    lines.push("");
  }

  if (model.alternatives.length) {
    lines.push(`## Other signatures matching \`${model.query}\``);
    lines.push("");
    lines.push(
      mdTable(
        ["#", "Signature", "Alerts"],
        model.alternatives.map((a, i) => [String(i + 1), cell(clip(a.signature, 80)), String(a.count)]),
      ),
    );
    lines.push("");
    lines.push(`_Narrow the query to profile one of these instead._`);
    lines.push("");
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from ${model.total} stored alert(s) for this signature. ` +
      `The signature-axis twin of \`--profile\` (single-IP dossier). No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build a single-signature dossier from the stored alert history.
 *
 * @param query Case-insensitive substring of a Suricata signature to profile.
 * @param hours Look-back window in hours; 0 / undefined profiles the whole history.
 * @param nowMs Pins the window end for deterministic tests; defaults to now.
 */
export function buildDetection(query: string, hours = 0, nowMs = Date.now()): DetectionModel {
  const q = (query ?? "").trim();
  const safeHours = Number.isFinite(hours) && hours > 0 ? Math.min(24 * 90, Math.floor(hours)) : 0;
  const windowEndMs = nowMs;
  const windowStartMs = safeHours > 0 ? windowEndMs - safeHours * MS_PER_HOUR : 0;
  const since = safeHours > 0 ? windowEndMs - safeHours * MS_PER_HOUR : -Infinity;

  const stubBase: Omit<DetectionModel, "narrative" | "highlights" | "markdown"> = {
    query: q,
    matched: false,
    signature: "",
    matchCount: 0,
    alternatives: [],
    suggestions: [],
    hours: safeHours,
    generatedAt: nowMs,
    windowStartMs,
    windowEndMs,
    total: 0,
    spanMs: 0,
    severityMax: "info",
    bySeverity: SEVERITY_ORDER.map((severity) => ({ severity, count: 0 })),
    distinctSeverities: 0,
    severityConsistent: true,
    byAction: [],
    blockRate: null,
    distinctSources: 0,
    distinctTargets: 0,
    topSources: [],
    topTargets: [],
    topCategories: [],
    topClassifications: [],
    byTriage: [],
    refs: { cves: [], cwes: [] },
    timeline: [],
    timelineBucketMs: 0,
    timelineMax: 0,
    samples: [],
    riskScore: 0,
  };

  const finish = (
    base: Omit<DetectionModel, "narrative" | "highlights" | "markdown">,
  ): DetectionModel => {
    const { narrative, highlights } = writeNarrative(base);
    const model: DetectionModel = { ...base, narrative, highlights, markdown: "" };
    model.markdown = renderMarkdown(model);
    return model;
  };

  // Window-scoped alerts, dismissed ones excluded (consistent with profile.ts).
  const windowed: StoredAlert[] = alertStore
    .all()
    .filter(
      (a) =>
        typeof a.time === "number" &&
        a.time <= windowEndMs &&
        a.time >= since &&
        !dismissStore.has(a.id),
    );

  if (!q) {
    // Empty query → guidance stub with the loudest signatures to try.
    const sigCounts = new Map<string, number>();
    for (const a of windowed) bump(sigCounts, a.signature?.trim());
    return finish({ ...stubBase, suggestions: topMatches(sigCounts, DEFAULT_TOP_N) });
  }

  // Resolve the query: every distinct signature whose text contains it (case-insensitive).
  const needle = q.toLowerCase();
  const matchCounts = new Map<string, number>();
  for (const a of windowed) {
    const sig = a.signature?.trim();
    if (sig && sig.toLowerCase().includes(needle)) bump(matchCounts, sig);
  }

  if (matchCounts.size === 0) {
    const sigCounts = new Map<string, number>();
    for (const a of windowed) bump(sigCounts, a.signature?.trim());
    return finish({ ...stubBase, suggestions: topMatches(sigCounts, DEFAULT_TOP_N) });
  }

  const ranked = topMatches(matchCounts, matchCounts.size);
  const resolved = ranked[0]!.signature;
  const alternatives = ranked.slice(1, 1 + ALT_LIMIT);

  // Roll up the resolved signature.
  const matching = windowed.filter((a) => a.signature?.trim() === resolved);

  const bySev = new Map<Severity, number>();
  const byAct = new Map<string, number>();
  const byTri = new Map<TriageStatus | "open", number>();
  const catCounts = new Map<string, number>();
  const classCounts = new Map<string, number>();
  const cves = new Set<string>();
  const cwes = new Set<string>();

  interface SrcAccum {
    count: number;
    internal: boolean;
    lastSeen: number;
    severityMax: Severity;
  }
  const srcMap = new Map<string, SrcAccum>();
  interface DstAccum {
    count: number;
    internal: boolean;
  }
  const dstMap = new Map<string, DstAccum>();

  let blocked = 0;
  let labelled = 0;
  let severityMax: Severity = "info";
  let firstSeen: number | undefined;
  let lastSeen: number | undefined;

  scrapeRefs(resolved, cves, cwes);

  for (const a of matching) {
    const sev = (a.severity as Severity) ?? "info";
    severityMax = maxSeverity(severityMax, sev);
    bump(bySev, sev);

    const act = normalizeAction(a.action);
    bump(byAct, act);
    if (act !== "unknown") labelled++;
    if (act === "blocked") blocked++;

    bump(byTri, triageStore.get(a.id)?.status ?? "open");
    bump(catCounts, a.category?.trim());
    bump(classCounts, a.classification?.trim());
    if (a.raw) scrapeRefs(a.raw, cves, cwes);

    const src = a.srcIp;
    if (src && isIP(src) > 0) {
      const acc = srcMap.get(src) ?? { count: 0, internal: isPrivate(src), lastSeen: a.time, severityMax: "info" as Severity };
      acc.count++;
      if (a.time > acc.lastSeen) acc.lastSeen = a.time;
      acc.severityMax = maxSeverity(acc.severityMax, sev);
      srcMap.set(src, acc);
    }
    const dst = a.dstIp;
    if (dst && isIP(dst) > 0) {
      const acc = dstMap.get(dst) ?? { count: 0, internal: isPrivate(dst) };
      acc.count++;
      dstMap.set(dst, acc);
    }

    if (firstSeen === undefined || a.time < firstSeen) firstSeen = a.time;
    if (lastSeen === undefined || a.time > lastSeen) lastSeen = a.time;
  }

  const total = matching.length;

  // Volume timeline: bin across the window, or first→last for full history.
  const tlStart = safeHours > 0 ? windowStartMs : (firstSeen ?? windowEndMs);
  const tlEnd = safeHours > 0 ? windowEndMs : (lastSeen ?? windowEndMs);
  const tlBucketMs = Math.max(60_000, Math.floor(Math.max(1, tlEnd - tlStart) / TIMELINE_BUCKETS));
  const timeline: DetectionTimelineBucket[] = Array.from({ length: TIMELINE_BUCKETS }, (_, i) => ({
    startMs: tlStart + i * tlBucketMs,
    count: 0,
  }));
  for (const a of matching) {
    const idx = Math.min(TIMELINE_BUCKETS - 1, Math.max(0, Math.floor((a.time - tlStart) / tlBucketMs)));
    timeline[idx]!.count++;
  }
  let timelineMax = 0;
  for (const b of timeline) if (b.count > timelineMax) timelineMax = b.count;

  const topSources: DetectionSourceEntry[] = [...srcMap.entries()]
    .map(([ip, acc]) => ({ ip, count: acc.count, internal: acc.internal, lastSeen: acc.lastSeen, severityMax: acc.severityMax }))
    .sort((a, b) => b.count - a.count || b.lastSeen - a.lastSeen)
    .slice(0, DEFAULT_TOP_N);

  const topTargets: DetectionTargetEntry[] = [...dstMap.entries()]
    .map(([ip, acc]) => ({ ip, count: acc.count, internal: acc.internal }))
    .sort((a, b) => b.count - a.count || a.ip.localeCompare(b.ip))
    .slice(0, DEFAULT_TOP_N);

  // A few representative raw detections, most-recent first.
  const samples: DetectionSample[] = [...matching]
    .sort((a, b) => b.time - a.time)
    .slice(0, SAMPLE_LIMIT)
    .map((a) => ({
      id: a.id,
      time: a.time,
      severity: a.severity,
      srcIp: a.srcIp,
      dstIp: a.dstIp,
      action: normalizeAction(a.action),
      raw: a.raw ?? "",
    }));

  // The first available stored AI summary for this signature (most-recent first).
  let aiSummary: DetectionModel["aiSummary"];
  for (const a of [...matching].sort((x, y) => y.time - x.time)) {
    const s = a.summary;
    if (s && !s.fallback && (s.whatHappened || s.title)) {
      aiSummary = { title: s.title, whatHappened: s.whatHappened, model: s.model };
      break;
    }
  }

  const bySeverity = SEVERITY_ORDER.map((severity) => ({ severity, count: bySev.get(severity) ?? 0 }));
  const distinctSeverities = bySeverity.filter((s) => s.count > 0).length;
  const blockRate = labelled > 0 ? pct(blocked, labelled) : null;

  const triageOrder: Array<TriageStatus | "open"> = ["open", "investigating", "resolved", "false-positive"];
  const byTriage = triageOrder
    .map((status) => ({ status, count: byTri.get(status) ?? 0 }))
    .filter((t) => t.count > 0);

  const riskScore = scoreDetection({
    severityMax,
    total,
    distinctSources: srcMap.size,
    blocked,
    labelled,
  });

  const base: Omit<DetectionModel, "narrative" | "highlights" | "markdown"> = {
    query: q,
    matched: true,
    signature: resolved,
    matchCount: matchCounts.size,
    alternatives,
    suggestions: [],
    hours: safeHours,
    generatedAt: nowMs,
    windowStartMs,
    windowEndMs,
    total,
    firstSeen,
    lastSeen,
    spanMs: firstSeen !== undefined && lastSeen !== undefined ? lastSeen - firstSeen : 0,
    severityMax,
    bySeverity,
    distinctSeverities,
    severityConsistent: distinctSeverities <= 1,
    byAction: [...byAct.entries()]
      .map(([action, count]) => ({ action, count }))
      .sort((a, b) => b.count - a.count),
    blockRate,
    distinctSources: srcMap.size,
    distinctTargets: dstMap.size,
    topSources,
    topTargets,
    topCategories: topMatches(catCounts, 8),
    topClassifications: topMatches(classCounts, 8),
    byTriage,
    refs: { cves: [...cves].sort(), cwes: [...cwes].sort() },
    timeline,
    timelineBucketMs: tlBucketMs,
    timelineMax,
    samples,
    aiSummary,
    riskScore,
  };

  return finish(base);
}

/** A filesystem-safe filename for a downloaded detection dossier. */
export function detectionFilename(query: string, nowMs: number): string {
  const safe = (query || "signature").replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 48) || "signature";
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-detection-${safe}-${stamp}.md`;
}
