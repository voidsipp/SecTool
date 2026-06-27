/**
 * Detection-rule (Suricata SID) inventory & ruleset-provenance report — "which
 * actual *rules* are firing, where did each rule come from (Snort/Talos vs my own
 * local rules vs Emerging Threats), and did my ruleset change underneath me this
 * window?"
 *
 * Every signature-centric report in this project keys off the **signature text**
 * — the human-readable `msg` ("ET SCAN Suspicious inbound to mySQL port 3306"):
 *
 *   - tuning.ts / lifecycle.ts / audience.ts / noise.ts all group, rank and
 *     de-dup by that signature string. But the string is **mutable**: Emerging
 *     Threats rewrites a rule's `msg` across revisions, and two different rules
 *     can share confusingly similar text. Group-by-text silently splits one rule
 *     across its wording changes and conflates near-duplicates.
 *   - efficacy.ts / priority.ts audit enforcement, classify.ts / mitre.ts roll up
 *     the *taxonomy*. None of them look at the one field that is a **stable,
 *     globally-unique identity** for the rule that fired: the Suricata
 *     `gid:sid:rev` stamp (`[1:2024897:4]`) that leads every fast.log line.
 *
 * That numeric identity carries information the text cannot:
 *
 *   - **Provenance.** Suricata/Snort allocate SID ranges by *source*: < 1,000,000
 *     is Snort/Talos (the GPL + registered VRT ruleset), 1,000,000–1,999,999 is
 *     the range reserved for an operator's **own local rules**, and 2,000,000+ is
 *     **Emerging Threats** (ET OPEN / ETPRO). So the SID alone tells you whether a
 *     detection came from a commodity community feed, a paid feed, or a rule *you*
 *     wrote — and confirms at a glance that your local rules are actually loaded
 *     and firing (or that they have gone silent).
 *   - **Revision drift.** The `rev` is the rule's version. The *same* SID firing
 *     under **two different revisions inside one window** is a fingerprint that
 *     your ruleset was **updated mid-window** — the detection logic changed under
 *     your historical comparison, which silently undermines any week-over-week
 *     trend. Nothing else in SecTool surfaces that.
 *   - **Family / category.** The ET `msg` carries the ruleset's own family +
 *     category prefix (`ET MALWARE`, `ET SCAN`, `GPL ICMP`, `ETPRO …`) — a
 *     coarser, source-native grouping distinct from Suricata's `Classification`.
 *
 * This report re-parses the rule identity straight from each stored alert's raw
 * line — using the very same `[gid:sid:rev]` bracket the ingest detector keys on,
 * plus the JSON `signature_id`/`gid`/`rev` fields for eve-format alerts — and
 * produces four complementary views:
 *
 *   1. **Provenance rollup** — distinct rules and total hits per source bucket
 *      (Snort/Talos · local · Emerging Threats · other), so an operator sees the
 *      ruleset's centre of gravity and can confirm their local rules fire.
 *   2. **Rule-family rollup** — hits per ET/GPL family+category prefix.
 *   3. **Top rules by activity** — per SID: rev(s), gid, provenance, family,
 *      signature text, hits, peak severity, block-rate, distinct sources/targets.
 *   4. **Revision-drift watch** — every SID that fired under ≥2 revisions in the
 *      window, newest rev highlighted: the ruleset-updated-mid-window tells.
 *
 * Honest caveats baked into the output:
 *
 *   - **Parse coverage.** Only alerts whose raw line still carries a `gid:sid:rev`
 *     bracket (fast.log) or a JSON `signature_id` can be attributed to a rule.
 *     Firewall / threat-management events and alerts whose raw was lost carry no
 *     SID; they are counted as *un-attributable* and excluded from the rule
 *     tables (never silently folded into a rule), and the coverage fraction is
 *     reported so a thin parse rate is visible, not hidden.
 *   - **Provenance is range-heuristic.** The SID→source mapping is the documented
 *     Suricata/Snort convention, not ground truth — a feed that allocates outside
 *     its conventional range will mis-bucket. The raw SID is always shown so the
 *     call can be checked.
 *   - **Window-bounded & store-capped.** A long look-back can hit the store's
 *     history cap and undercount a rule's true volume / revision span.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network. Output is
 * both a structured model and a ready-to-paste Markdown document, mirroring
 * tuning.ts, efficacy.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** The provenance bucket a rule's SID falls into. */
export type RuleProvenance = "snort" | "local" | "et" | "other";

/** Blocked / passed / unknown split for a rule's alerts. */
export interface RuleDisposition {
  blocked: number;
  passed: number;
  unknown: number;
  /** Fraction of *actioned* (blocked + passed) alerts blocked, 0..1 (4dp), or null. */
  blockRate: number | null;
}

/** Per-rule (per-SID) inventory row over the window. */
export interface RuleRow {
  /** The Suricata generator id (almost always 1 for text rules). */
  gid: number;
  /** The Suricata signature id — the stable, globally-unique rule identity. */
  sid: number;
  /** Composite key `gid:sid` used for display. */
  key: string;
  /** Distinct revisions seen in the window, ascending. */
  revs: number[];
  /** Highest (newest) revision seen. */
  latestRev: number;
  /** True when the rule fired under ≥2 revisions in the window (ruleset drift). */
  revDrift: boolean;
  /** Source-feed provenance derived from the SID range. */
  provenance: RuleProvenance;
  /** Ruleset family + category prefix from the msg ("ET MALWARE"), if any. */
  family?: string;
  /** Representative signature text for the rule. */
  signature: string;
  /** Total alerts this rule produced in the window. */
  hits: number;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Severity-weighted magnitude (Σ SEVERITY_WEIGHT) — the ranking key. */
  weight: number;
  /** Worst severity the rule reached. */
  severityMax: Severity;
  /** Distinct source IPs that tripped the rule. */
  distinctSources: number;
  /** Distinct destination IPs the rule fired against. */
  distinctTargets: number;
  /** Blocked / passed / unknown split. */
  disposition: RuleDisposition;
}

/** A provenance bucket rollup row. */
export interface ProvenanceRollup {
  provenance: RuleProvenance;
  /** Distinct rules in the bucket. */
  rules: number;
  /** Total alerts attributed to the bucket. */
  hits: number;
  /** Alerts at medium severity or worse. */
  severe: number;
}

/** A ruleset-family rollup row (ET/GPL family+category prefix). */
export interface FamilyRollup {
  family: string;
  rules: number;
  hits: number;
  severe: number;
}

export interface RulesetReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts a `gid:sid` rule identity could be recovered from. */
  attributedAlerts: number;
  /** Of those, alerts with no recoverable rule identity (firewall events, lost raw…). */
  unattributableAlerts: number;
  /** Distinct rules (SIDs) seen in the window. */
  distinctRules: number;
  /** Distinct rules that exhibited revision drift. */
  driftRules: number;
  /** Provenance rollup, busiest bucket first. */
  provenance: ProvenanceRollup[];
  /** Ruleset-family rollup, busiest first (capped). */
  families: FamilyRollup[];
  /** Per-rule inventory rows, busiest first (capped to `limit`). */
  rules: RuleRow[];
  /** Revision-drift rows (subset of `rules` with revDrift), most revisions first. */
  drift: RuleRow[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface RulesetOptions {
  /** Max rows in the per-rule table (clamped to [1, 500]). */
  limit?: number;
  /** Minimum hits a rule needs before it appears in the inventory table. */
  minHits?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 25;
const DEFAULT_MIN_HITS = 1;
const MAX_FAMILIES = 12;
const MS_PER_HOUR = 3_600_000;

// ----- rule-identity recovery (mirrors ingest/alertDetector.ts) --------------

/** The fast.log `[gid:sid:rev]` bracket the ingest detector keys on (rev optional). */
const RULE_BRACKET = /\[(\d+):(\d+)(?::(\d+))?\]/;

/** Leading ruleset family + category from an ET/GPL msg: "ET MALWARE", "GPL ICMP". */
const FAMILY_PREFIX = /^(ETPRO|ET|GPL)\s+([A-Z0-9_]+)/;

interface RuleId {
  gid: number;
  sid: number;
  rev: number | null;
}

function toInt(v: unknown): number | undefined {
  const n = typeof v === "number" ? v : Number(v);
  return Number.isInteger(n) && n >= 0 ? n : undefined;
}

/**
 * Recover the `gid:sid:rev` rule identity from a stored alert's raw line, using
 * the same two shapes the ingest detector understands: the fast.log
 * `[gid:sid:rev]` bracket, or a JSON payload carrying `signature_id`/`sid` (with
 * optional `gid`/`rev`). Returns undefined when no rule identity survives.
 */
export function recoverRuleId(raw: string | undefined): RuleId | undefined {
  if (!raw) return undefined;

  // 1) fast.log bracket: [1:2024897:4] ET MALWARE ... — the canonical form.
  const m = RULE_BRACKET.exec(raw);
  if (m) {
    const gid = toInt(m[1]);
    const sid = toInt(m[2]);
    if (gid !== undefined && sid !== undefined && sid > 0) {
      const rev = m[3] !== undefined ? (toInt(m[3]) ?? null) : null;
      return { gid, sid, rev };
    }
  }

  // 2) JSON payload (eve): {"signature_id":2024897,"gid":1,"rev":4, ...}
  const start = raw.indexOf("{");
  const end = raw.lastIndexOf("}");
  if (start !== -1 && end > start) {
    try {
      const obj = JSON.parse(raw.slice(start, end + 1)) as Record<string, unknown>;
      if (obj && typeof obj === "object") {
        const sid = toInt(obj["signature_id"]) ?? toInt(obj["sid"]);
        if (sid !== undefined && sid > 0) {
          const gid = toInt(obj["gid"]) ?? 1;
          const rev = obj["rev"] !== undefined ? (toInt(obj["rev"]) ?? null) : null;
          return { gid, sid, rev };
        }
      }
    } catch {
      // not JSON — fall through
    }
  }
  return undefined;
}

/**
 * Map a SID to its source-feed provenance using the documented Suricata/Snort
 * range convention. Heuristic, not ground truth — a feed allocating outside its
 * conventional range will mis-bucket, which is why the raw SID is always shown.
 */
export function provenanceOf(sid: number): RuleProvenance {
  if (sid < 1_000_000) return "snort"; // Snort/Talos GPL + registered VRT
  if (sid < 2_000_000) return "local"; // operator-authored local rules
  if (sid < 4_000_000) return "et"; // Emerging Threats (ET OPEN / ETPRO)
  return "other";
}

const PROVENANCE_LABEL: Record<RuleProvenance, string> = {
  snort: "🦟 Snort / Talos",
  local: "🏠 Local / custom",
  et: "🌩 Emerging Threats",
  other: "❓ Other / unknown",
};

const PROVENANCE_HINT: Record<RuleProvenance, string> = {
  snort: "SID < 1,000,000 — Snort/Talos (GPL + registered VRT) community ruleset",
  local: "SID 1,000,000–1,999,999 — the range reserved for your own local rules",
  et: "SID 2,000,000–3,999,999 — Emerging Threats (ET OPEN / ETPRO)",
  other: "SID ≥ 4,000,000 — outside the conventional ranges",
};

/** The ET/GPL ruleset family + category prefix from a signature, if present. */
function familyOf(signature: string | undefined): string | undefined {
  if (!signature) return undefined;
  const m = FAMILY_PREFIX.exec(signature.trim());
  if (!m) return undefined;
  return `${m[1]} ${m[2]}`;
}

// ----- generic helpers (mirror repertoire.ts / efficacy.ts) ------------------

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

function clip(s: string, max = 52): string {
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

/** Format a revision list as "4" or "3→4" (drift) or "—" (unknown). */
function fmtRevs(revs: number[]): string {
  if (!revs.length) return "—";
  if (revs.length === 1) return `r${revs[0]}`;
  return revs.map((r) => `r${r}`).join("→");
}

// ----- aggregation -----------------------------------------------------------

interface RuleAcc {
  gid: number;
  sid: number;
  revs: Set<number>;
  hits: number;
  severe: number;
  weight: number;
  severityMax: Severity;
  sources: Set<string>;
  targets: Set<string>;
  sigCounts: Map<string, number>;
  blocked: number;
  passed: number;
  unknown: number;
}

function newRuleAcc(gid: number, sid: number): RuleAcc {
  return {
    gid,
    sid,
    revs: new Set(),
    hits: 0,
    severe: 0,
    weight: 0,
    severityMax: "info",
    sources: new Set(),
    targets: new Set(),
    sigCounts: new Map(),
    blocked: 0,
    passed: 0,
    unknown: 0,
  };
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(
  hours: number,
  m: {
    distinctRules: number;
    attributedAlerts: number;
    totalWindowAlerts: number;
    driftRules: number;
  },
  provenance: ProvenanceRollup[],
  rules: RuleRow[],
  drift: RuleRow[],
): string[] {
  const out: string[] = [];
  if (!rules.length) return out;

  // Overall inventory + provenance centre of gravity.
  const lead = provenance[0];
  out.push(
    `📜 Over the last ${hours}h, **${m.distinctRules} distinct rule(s)** fired across ` +
      `${m.attributedAlerts} attributable alert(s)` +
      (lead
        ? ` — busiest feed is **${PROVENANCE_LABEL[lead.provenance]}** (${lead.rules} rule(s), ${lead.hits} hit(s))`
        : "") +
      `.`,
  );

  // The single noisiest rule — the first tuning candidate, by stable SID.
  const top = rules[0]!;
  out.push(
    `🔝 Loudest rule is **\`${top.key}\`** (${PROVENANCE_LABEL[top.provenance]}) — “${clip(top.signature, 60)}”: ` +
      `**${top.hits} hit(s)** from ${top.distinctSources} source(s), peak ${top.severityMax}, ` +
      `${top.disposition.blockRate !== null ? pct(top.disposition.blockRate) + " blocked" : "no actioned alerts"}. ` +
      `Tune by **SID** (\`${top.key}\`), not by msg — the SID survives wording changes.`,
  );

  // Confirm the operator's own local rules are loaded and firing (or not).
  const local = provenance.find((p) => p.provenance === "local");
  if (local && local.hits > 0) {
    out.push(
      `🏠 **${local.rules} local rule(s)** (SID 1,000,000–1,999,999) fired ${local.hits} time(s) — your own ` +
        `custom detections are loaded and active.`,
    );
  } else {
    out.push(
      `🏠 **No local rules fired** (SID 1,000,000–1,999,999). If you maintain custom rules, confirm they are ` +
        `loaded — silent local rules are a coverage blind spot.`,
    );
  }

  // Revision drift — ruleset updated mid-window, undermining trend comparisons.
  if (drift.length) {
    const d = drift[0]!;
    out.push(
      `🔄 **${m.driftRules} rule(s) changed revision mid-window** — e.g. \`${d.key}\` fired under ` +
        `${d.revs.length} revisions (${fmtRevs(d.revs)}). Your ruleset was updated inside this window, so ` +
        `week-over-week comparisons that straddle the update are comparing different detection logic.`,
    );
  }

  // A high-volume rule that is detect-only — pairs with the efficacy report.
  const openGap = rules
    .filter((r) => r.disposition.blockRate !== null && r.disposition.blockRate < 0.5 && r.severe > 0)
    .sort((a, b) => b.severe - a.severe)[0];
  if (openGap) {
    out.push(
      `⚠️ Rule \`${openGap.key}\` produced **${openGap.severe} severe alert(s)** but only ` +
        `${pct(openGap.disposition.blockRate ?? 0)} were blocked — a serious rule running mostly detect-only ` +
        `(cross-check the IPS enforcement-gap report).`,
    );
  }

  // Parse-coverage honesty.
  if (m.totalWindowAlerts > 0) {
    const frac = m.attributedAlerts / m.totalWindowAlerts;
    if (frac < 0.8) {
      out.push(
        `ℹ️ Only **${pct(frac)} of windowed alerts carried a recoverable rule id** — the rest (firewall / ` +
          `threat-management events, or alerts whose raw line was lost) are un-attributable and excluded from ` +
          `the rule tables. Inventory counts are a lower bound.`,
      );
    }
  }

  return out;
}

// ----- markdown --------------------------------------------------------------

function provenanceTable(rows: ProvenanceRollup[], totalHits: number): string {
  return mdTable(
    ["Feed", "Rules", "Hits", "Share", "Severe", "What it means"],
    rows.map((r) => [
      cell(PROVENANCE_LABEL[r.provenance]),
      String(r.rules),
      String(r.hits),
      totalHits ? pct(r.hits / totalHits) : "—",
      String(r.severe),
      cell(PROVENANCE_HINT[r.provenance]),
    ]),
  );
}

function familyTable(rows: FamilyRollup[]): string {
  return mdTable(
    ["Family", "Rules", "Hits", "Severe"],
    rows.map((r) => [cell(r.family), String(r.rules), String(r.hits), String(r.severe)]),
  );
}

function ruleTable(rows: RuleRow[]): string {
  return mdTable(
    ["#", "Rule (gid:sid)", "Rev", "Feed", "Signature", "Hits", "Sev", "Block%", "Src", "Tgt"],
    rows.map((r, i) => [
      String(i + 1),
      `\`${cell(r.key)}\`${r.revDrift ? " 🔄" : ""}`,
      fmtRevs(r.revs),
      cell(PROVENANCE_LABEL[r.provenance]),
      cell(clip(r.signature)),
      String(r.hits),
      cell(r.severityMax),
      r.disposition.blockRate !== null ? pct(r.disposition.blockRate) : "—",
      String(r.distinctSources),
      String(r.distinctTargets),
    ]),
  );
}

function driftTable(rows: RuleRow[]): string {
  return mdTable(
    ["Rule (gid:sid)", "Revisions seen", "Newest", "Feed", "Signature", "Hits"],
    rows.map((r) => [
      `\`${cell(r.key)}\``,
      fmtRevs(r.revs),
      `r${r.latestRev}`,
      cell(PROVENANCE_LABEL[r.provenance]),
      cell(clip(r.signature)),
      String(r.hits),
    ]),
  );
}

function renderMarkdown(m: RulesetReport): string {
  const lines: string[] = [];
  lines.push(`# 📜 SecTool Detection-Rule (SID) Inventory & Ruleset-Provenance Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** each alert's Suricata \`gid:sid:rev\` rule identity re-parsed from its raw line (fast.log ` +
      `\`[gid:sid:rev]\` bracket or eve JSON \`signature_id\`), grouped by the **stable SID** (not the mutable ` +
      `signature text) and bucketed to a source feed by SID range · ` +
      `**Attributable:** ${m.attributedAlerts} of ${m.totalWindowAlerts} alert(s) ` +
      `(${m.unattributableAlerts} carried no recoverable rule id)`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.rules.length) {
    if (!m.totalWindowAlerts) {
      lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to analyse.`);
    } else if (!m.attributedAlerts) {
      lines.push(
        `${m.totalWindowAlerts} alert(s) in the last ${m.hours} hour(s), but **none carried a recoverable ` +
          `\`gid:sid\` rule identity** (no fast.log bracket or JSON \`signature_id\` survived in the raw line). ` +
          `This report needs Suricata IDS/IPS alerts; firewall / threat-management events have no SID.`,
      );
    } else {
      lines.push(
        `${m.attributedAlerts} attributable alert(s) in the last ${m.hours} hour(s), but none met the minimum-hits ` +
          `floor for the inventory table.`,
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

  const totalHits = m.provenance.reduce((s, p) => s + p.hits, 0);

  lines.push(`## Provenance — where your detections come from`);
  lines.push("");
  lines.push(provenanceTable(m.provenance, totalHits));
  lines.push("");

  if (m.families.length) {
    lines.push(`## Ruleset families (ET / GPL category prefix)`);
    lines.push("");
    lines.push(familyTable(m.families));
    lines.push(
      `\n_The ruleset's own family + category from the rule message — distinct from Suricata's \`Classification\` ` +
        `taxonomy (see the threat-class report). Rules without an \`ET …\`/\`GPL …\` prefix are omitted here._`,
    );
    lines.push("");
  }

  lines.push(`## Top rules by activity`);
  lines.push("");
  lines.push(ruleTable(m.rules));
  lines.push("");
  lines.push(
    `**Legend:** _Rule_ is the stable \`gid:sid\` identity — **tune and suppress by this, not by the signature ` +
      `text**, which Emerging Threats rewrites across revisions. _Rev_ shows the revision(s) seen (an arrow like ` +
      `\`r3→r4\` 🔄 means the rule changed version mid-window). _Feed_: ${PROVENANCE_LABEL.snort} · ` +
      `${PROVENANCE_LABEL.local} · ${PROVENANCE_LABEL.et} · ${PROVENANCE_LABEL.other}. _Block%_ is the share of ` +
      `*actioned* alerts the gateway dropped (— = none actioned). _Src/Tgt_ = distinct sources / targets.`,
  );
  lines.push("");

  if (m.drift.length) {
    lines.push(`## 🔄 Revision drift — ruleset updated mid-window`);
    lines.push("");
    lines.push(driftTable(m.drift));
    lines.push(
      `\n_Each of these SIDs fired under more than one revision inside the window — your ruleset was updated ` +
        `while this data accrued. Any trend or period comparison that straddles the update is comparing different ` +
        `detection logic, so treat a sudden change in one of these rules' volume with care._`,
    );
    lines.push("");
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. **Provenance is a range heuristic**: SIDs are bucketed by the documented ` +
      `Suricata/Snort allocation (< 1M Snort/Talos · 1M–2M local · 2M–4M Emerging Threats · ≥ 4M other), which a ` +
      `feed allocating outside its conventional range will mis-bucket — the raw SID is always shown so the call ` +
      `can be checked. Only alerts whose raw line still carried a \`gid:sid:rev\` bracket or a JSON ` +
      `\`signature_id\` can be attributed to a rule; firewall / threat-management events and alerts with a lost ` +
      `raw line are un-attributable and excluded from the rule tables (their count is reported above), so ` +
      `inventory figures are a lower bound. A long look-back can hit the store's history cap and undercount a ` +
      `rule's volume or revision span. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the detection-rule (SID) inventory & ruleset-provenance report from the
 * stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link RulesetOptions}: `limit`, `minHits`, and a `nowMs` pin for
 *              deterministic tests.
 */
export function buildRuleset(hours: number, opts: RulesetOptions = {}): RulesetReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(500, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minHits = Math.max(1, Math.floor(opts.minHits ?? DEFAULT_MIN_HITS));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const rules = new Map<number, RuleAcc>(); // keyed by SID (the stable identity)
  let attributed = 0;
  let unattributable = 0;

  for (const a of windowed) {
    const id = recoverRuleId(a.raw);
    if (!id) {
      unattributable++;
      continue;
    }
    attributed++;

    const acc = rules.get(id.sid) ?? newRuleAcc(id.gid, id.sid);
    if (!rules.has(id.sid)) rules.set(id.sid, acc);
    acc.hits++;
    acc.weight += weightOf(a.severity);
    acc.severityMax = maxSeverity(acc.severityMax, a.severity);
    if (isSevere(a.severity)) acc.severe++;
    if (id.rev !== null) acc.revs.add(id.rev);

    const src = validIp(a.srcIp);
    if (src) acc.sources.add(src);
    const dst = validIp(a.dstIp);
    if (dst) acc.targets.add(dst);

    const sig = (a.signature ?? "").trim();
    if (sig) acc.sigCounts.set(sig, (acc.sigCounts.get(sig) ?? 0) + 1);

    const disp = classifyDisposition(a.action);
    if (disp === "blocked") acc.blocked++;
    else if (disp === "passed") acc.passed++;
    else acc.unknown++;
  }

  // ----- per-rule rows --------------------------------------------------------
  const allRows: RuleRow[] = [...rules.values()].map((acc) => {
    const revs = [...acc.revs].sort((x, y) => x - y);
    const latestRev = revs.length ? revs[revs.length - 1]! : 0;
    const signature = topOf(acc.sigCounts) ?? `SID ${acc.sid}`;
    const actioned = acc.blocked + acc.passed;
    return {
      gid: acc.gid,
      sid: acc.sid,
      key: `${acc.gid}:${acc.sid}`,
      revs,
      latestRev,
      revDrift: revs.length >= 2,
      provenance: provenanceOf(acc.sid),
      family: familyOf(signature),
      signature,
      hits: acc.hits,
      severe: acc.severe,
      weight: round4(acc.weight),
      severityMax: acc.severityMax,
      distinctSources: acc.sources.size,
      distinctTargets: acc.targets.size,
      disposition: {
        blocked: acc.blocked,
        passed: acc.passed,
        unknown: acc.unknown,
        blockRate: actioned ? round4(acc.blocked / actioned) : null,
      },
    } satisfies RuleRow;
  });

  // ----- provenance rollup (over ALL rules, before the table cap) -------------
  const provMap = new Map<RuleProvenance, ProvenanceRollup>();
  for (const r of allRows) {
    const p = provMap.get(r.provenance) ?? {
      provenance: r.provenance,
      rules: 0,
      hits: 0,
      severe: 0,
    };
    p.rules++;
    p.hits += r.hits;
    p.severe += r.severe;
    provMap.set(r.provenance, p);
  }
  const provenance = [...provMap.values()].sort(
    (a, b) => b.hits - a.hits || b.rules - a.rules || a.provenance.localeCompare(b.provenance),
  );

  // ----- ruleset-family rollup ------------------------------------------------
  const famMap = new Map<string, FamilyRollup>();
  for (const r of allRows) {
    if (!r.family) continue;
    const f = famMap.get(r.family) ?? { family: r.family, rules: 0, hits: 0, severe: 0 };
    f.rules++;
    f.hits += r.hits;
    f.severe += r.severe;
    famMap.set(r.family, f);
  }
  const families = [...famMap.values()]
    .sort((a, b) => b.hits - a.hits || b.rules - a.rules || a.family.localeCompare(b.family))
    .slice(0, MAX_FAMILIES);

  // ----- revision drift (over all rules) --------------------------------------
  const drift = allRows
    .filter((r) => r.revDrift)
    .sort(
      (a, b) =>
        b.revs.length - a.revs.length || b.hits - a.hits || a.sid - b.sid,
    )
    .slice(0, limit);
  const driftRules = allRows.filter((r) => r.revDrift).length;

  // ----- inventory table: busiest first, by severity-weighted magnitude -------
  const inventory = allRows
    .filter((r) => r.hits >= minHits)
    .sort(
      (a, b) =>
        b.weight - a.weight || b.hits - a.hits || b.severe - a.severe || a.sid - b.sid,
    )
    .slice(0, limit);

  const highlights = writeHighlights(
    safeHours,
    {
      distinctRules: allRows.length,
      attributedAlerts: attributed,
      totalWindowAlerts: windowed.length,
      driftRules,
    },
    provenance,
    inventory,
    drift,
  );

  const model: RulesetReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    attributedAlerts: attributed,
    unattributableAlerts: unattributable,
    distinctRules: allRows.length,
    driftRules,
    provenance,
    families,
    rules: inventory,
    drift,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded ruleset report. */
export function rulesetFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-ruleset-${stamp}.md`;
}
