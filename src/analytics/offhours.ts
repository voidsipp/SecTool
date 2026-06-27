/**
 * Defender off-hours / coverage-gap report — "how much of the attack pressure
 * lands while nobody is watching, and which of it slips through *un-blocked* in
 * that window?"
 *
 * Every other temporal report in this project looks at the clock from the
 * *attacker's* side. This one flips the question to the **defender's roster**.
 * A small team can only staff so many hours; the rest — nights and weekends — is
 * the *unattended window*. An adversary who fires at 03:00 local on a Sunday is
 * not just another row in a heat-map: they have chosen the hours when a human
 * response is slowest, and any *detect-only* (un-blocked) serious alert in that
 * window is a real, quantifiable exposure gap that justifies on-call rotation or
 * automated containment.
 *
 * The report builds an explicit **business-hours model** — a configurable local
 * timezone offset and a weekday start/end (default Mon–Fri 09:00–17:00 local) —
 * partitions every windowed alert into **staffed** vs **off-hours** (further split
 * into **weeknight** and **weekend**), and then measures:
 *
 *   - **Coverage skew.** If attacks were spread uniformly across the week, the
 *     off-hours share would simply equal the off-hours *fraction of the week*
 *     (e.g. a 40-hour staffed week leaves 76% of the clock unattended). The
 *     **skew index** = actual off-hours share ÷ that expectation. >1 means
 *     adversaries are *concentrating* on your blind window — they wait until
 *     you've gone home; ≈1 means time-agnostic automation; <1 means, oddly, they
 *     hit during your day.
 *   - **Unattended exposure.** Off-hours alerts that are both **serious**
 *     (≥ medium) *and* **detect-only** (the gateway saw them but never blocked) —
 *     the single most actionable number here: serious traffic that arrived with
 *     nobody watching *and* nothing stopping it. A high count is the business
 *     case for an automated block path.
 *   - **Off-hours-skewed signatures, sources and target assets.** Which rules,
 *     which external sources and which of *your own* hosts take a
 *     disproportionate share of their hits in the unattended window — so the
 *     follow-up (auto-block rule, geo-policy, on-call page) is specific.
 *
 * How this differs from the existing reports — there is no overlap:
 *
 *   - rhythm.ts folds the whole stream onto an hour×day heat-map ("when is my
 *     network busiest?"). It has no concept of a *staffed window*, no skew vs a
 *     coverage baseline, and no enforcement/severity lens — it is descriptive,
 *     this is a defender-readiness decision aid.
 *   - patterns.ts attributes each *attacker's* working hours to a timezone (bot
 *     vs human shift). This report does not care where the attacker sleeps; it
 *     cares whether *you* were awake when they struck.
 *   - surge.ts / burstiness.ts describe volume shape over time; efficacy.ts /
 *     priority.ts grade enforcement irrespective of the clock. None cross the
 *     enforcement gap with a *staffing* window.
 *
 * Honest caveats baked into the output:
 *
 *   - **A staffing model, not your real roster.** The 09:00–17:00 default and the
 *     single UTC offset are assumptions; pass `--tz`, `--start`, `--end` to match
 *     reality. Follow-the-sun teams and 24/7 SOCs have no off-hours window at all.
 *   - **Detections, not response.** SecTool stores IPS *alerts*; it does not know
 *     whether an analyst actually triaged one. "Unattended" means *outside staffed
 *     hours*, a structural exposure, not proof nobody looked.
 *   - **Off-hours ≠ worse.** A detect-only serious alert is exactly as dangerous
 *     at noon; the off-hours lens ranks where a *slow human response* compounds
 *     the risk, it does not re-grade the threat itself.
 *   - **Window- & store-bounded.** A short window can't separate "only hits at
 *     night" from "only happened to fire at night"; a long look-back can hit the
 *     alert store's history cap and clip the tail.
 *
 * Pure in-memory math over alertStore (plus blocklist / watchlist membership
 * flags) — no SSH, no Claude, no network. Output is both a structured model and a
 * ready-to-paste Markdown document, mirroring patterns.ts, rhythm.ts and the
 * other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Which staffing bucket an alert fell into. */
export type Coverage = "staffed" | "weeknight" | "weekend";

/** Per-signature off-hours skew row. */
export interface SignatureOffHours {
  signature: string;
  total: number;
  offHours: number;
  /** Off-hours alerts ÷ this signature's alerts, 0..1 (4dp). */
  offHoursFrac: number;
  /** Off-hours serious (≥ medium) alerts. */
  serious: number;
  /** Off-hours serious alerts the gateway only *detected* (never blocked). */
  unattended: number;
  severityMax: Severity;
}

/** Per-source off-hours skew row (external attackers only). */
export interface SourceOffHours {
  ip: string;
  total: number;
  offHours: number;
  offHoursFrac: number;
  serious: number;
  unattended: number;
  severityMax: Severity;
  blocked: boolean;
  watched: boolean;
  signatureTop?: string;
}

/** Per-internal-asset off-hours exposure row. */
export interface AssetOffHours {
  ip: string;
  total: number;
  offHours: number;
  offHoursFrac: number;
  serious: number;
  /** Off-hours serious + detect-only hits this host absorbed — the exposure number. */
  unattended: number;
  severityMax: Severity;
}

export interface OffHoursReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** The staffing model used. */
  tzOffset: number;
  bizStart: number;
  bizEnd: number;
  /** Staffed clock-hours per 7-day week (weekdays × the daily band). */
  staffedHoursPerWeek: number;
  /** 168 − staffedHoursPerWeek. */
  offHoursPerWeek: number;
  /** Off-hours fraction of the week, 0..1 — the uniform-attack expectation. */
  expectedOffHoursFrac: number;

  /** Alerts with a usable timestamp inside the window. */
  totalWindowAlerts: number;
  staffedCount: number;
  weeknightCount: number;
  weekendCount: number;
  /** weeknightCount + weekendCount. */
  offHoursCount: number;
  /** Actual off-hours share, 0..1 — compare to expectedOffHoursFrac. */
  actualOffHoursFrac: number;
  /** actualOffHoursFrac ÷ expectedOffHoursFrac (>1 = attacks skew off-hours). */
  skewIndex: number;

  /** Serious (≥ medium) alerts that landed off-hours. */
  offHoursSerious: number;
  /** Of those, the ones the gateway only *detected* (never blocked) — the exposure. */
  unattendedExposure: number;

  /** 24-bucket local-hour histogram of off-hours alerts (staffed hours read 0). */
  offHoursByLocalHour: number[];
  /** 24-bucket local-hour histogram of ALL alerts (context for the band). */
  allByLocalHour: number[];

  signatures: SignatureOffHours[];
  sources: SourceOffHours[];
  assets: AssetOffHours[];

  highlights: string[];
  markdown: string;
}

export interface OffHoursOptions {
  /** SOC local timezone as a whole-hour UTC offset (clamped to [-12, 14]). */
  tzOffset?: number;
  /** Local hour the staffed day starts (clamped to [0, 23]). */
  bizStart?: number;
  /** Local hour the staffed day ends, exclusive (clamped to [bizStart+1, 24]). */
  bizEnd?: number;
  /** Count Saturday/Sunday as off-hours even during business hours (default true). */
  weekendsOff?: boolean;
  /** Max rows in each leaderboard (clamped to [1, 200]). */
  limit?: number;
  /** Min alerts before a signature/source/asset is ranked (clamped to [1, 1000]). */
  minAlerts?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_TZ_OFFSET = 0;
const DEFAULT_BIZ_START = 9;
const DEFAULT_BIZ_END = 17;
const DEFAULT_LIMIT = 15;
const DEFAULT_MIN_ALERTS = 4;
const MS_PER_HOUR = 3_600_000;

/** Severity at or above which an alert is "serious" for the unattended lens. */
const SERIOUS_MIN_RANK = 2; // SEVERITY_ORDER index of "medium"

// ----- classifiers / helpers (mirror patterns.ts) ---------------------------

function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
}

/** A valid, external (non-private) IP, or undefined — for the attacker leaderboard. */
function externalIp(ip: string | undefined): string | undefined {
  if (!ip || isIP(ip) === 0) return undefined;
  return isPrivate(ip) ? undefined : ip;
}

/** A valid, private (internal) IP, or undefined — for the target-asset leaderboard. */
function internalIp(ip: string | undefined): string | undefined {
  if (!ip || isIP(ip) === 0) return undefined;
  return isPrivate(ip) ? ip : undefined;
}

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

function isSerious(s: string | undefined): boolean {
  return sevRank(s) >= SERIOUS_MIN_RANK;
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? (b as Severity) : a;
}

/** The gateway actually stopped it (vs merely "detected"/"allowed"/unknown). */
function isBlocked(action: string | undefined): boolean {
  return (action ?? "").toLowerCase().includes("block");
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

/** Two-digit hour label, e.g. 5 → "05". */
function hh(h: number): string {
  return String(((h % 24) + 24) % 24).padStart(2, "0");
}

/** A signed UTC-offset label, e.g. 0 → "UTC", 3 → "UTC+3", -5 → "UTC−5". */
function offsetLabel(off: number): string {
  if (off === 0) return "UTC";
  return `UTC${off > 0 ? "+" : "−"}${Math.abs(off)}`;
}

function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function clip(s: string, max = 40): string {
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

// ----- time classification ---------------------------------------------------

interface LocalParts {
  hour: number;
  /** 0 = Sun … 6 = Sat (local). */
  dow: number;
}

/** Decompose a UTC ms instant into local hour/day-of-week at a whole-hour offset. */
function localParts(ms: number, tzOffset: number): LocalParts {
  const d = new Date(ms + tzOffset * MS_PER_HOUR);
  return { hour: d.getUTCHours(), dow: d.getUTCDay() };
}

/** Which staffing bucket does a local time fall into? */
function coverageOf(
  parts: LocalParts,
  bizStart: number,
  bizEnd: number,
  weekendsOff: boolean,
): Coverage {
  const isWeekend = parts.dow === 0 || parts.dow === 6;
  if (isWeekend && weekendsOff) return "weekend";
  const inBand = parts.hour >= bizStart && parts.hour < bizEnd;
  if (inBand) return "staffed";
  return isWeekend ? "weekend" : "weeknight";
}

// ----- aggregation -----------------------------------------------------------

interface EntityAcc {
  total: number;
  offHours: number;
  serious: number;
  unattended: number;
  severityMax: Severity;
  signatures: Map<string, number>;
}

function newEntityAcc(): EntityAcc {
  return { total: 0, offHours: 0, serious: 0, unattended: 0, severityMax: "info", signatures: new Map() };
}

function bumpEntity(acc: EntityAcc, a: StoredAlert, offHours: boolean): void {
  acc.total++;
  acc.severityMax = maxSeverity(acc.severityMax, a.severity);
  const serious = isSerious(a.severity);
  const sig = (a.signature ?? "").trim();
  if (sig) acc.signatures.set(sig, (acc.signatures.get(sig) ?? 0) + 1);
  if (!offHours) return;
  acc.offHours++;
  if (serious) {
    acc.serious++;
    if (!isBlocked(a.action)) acc.unattended++;
  }
}

function topSignature(sigs: Map<string, number>): string | undefined {
  let best: string | undefined;
  let bestN = 0;
  for (const [s, n] of sigs) {
    if (n > bestN || (n === bestN && best !== undefined && s < best)) {
      best = s;
      bestN = n;
    }
  }
  return best;
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(m: OffHoursReport): string[] {
  const out: string[] = [];
  if (!m.totalWindowAlerts) return out;

  const skewWord =
    m.skewIndex >= 1.25 ? "**concentrate on** your blind window" :
    m.skewIndex <= 0.8 ? "actually favour your *staffed* hours" :
    "are roughly time-agnostic";
  out.push(
    `🌙 Over the last ${m.hours}h, **${pct(m.actualOffHoursFrac)}** of ${m.totalWindowAlerts} alert(s) landed ` +
      `**off-hours** (vs a **${pct(m.expectedOffHoursFrac)}** uniform-attack expectation from a ` +
      `${m.staffedHoursPerWeek}h staffed week) — a **${m.skewIndex.toFixed(2)}×** skew, so attacks ${skewWord}.`,
  );

  if (m.unattendedExposure > 0) {
    out.push(
      `🚨 **${m.unattendedExposure}** serious (≥ medium) off-hours alert(s) were **detect-only** — seen by the ` +
        `gateway but never blocked, while nobody was on shift. This is the case for an automated block path or ` +
        `on-call rotation: serious traffic arriving unattended *and* unstopped.`,
    );
  } else if (m.offHoursSerious > 0) {
    out.push(
      `✅ All **${m.offHoursSerious}** serious off-hours alert(s) were actively **blocked** — enforcement held the ` +
        `line through the unattended window. The risk is response latency on anything detect-only, not these.`,
    );
  }

  const wn = m.weeknightCount;
  const we = m.weekendCount;
  if (m.offHoursCount > 0) {
    const heavier = we >= wn ? "weekends" : "weeknights";
    out.push(
      `📅 Off-hours pressure splits **${wn}** weeknight vs **${we}** weekend alert(s) — heavier on **${heavier}**. ` +
        `Local staffed window assumed **${hh(m.bizStart)}:00–${hh(m.bizEnd)}:00 ${offsetLabel(m.tzOffset)}**, Mon–Fri.`,
    );
  }

  const sig = m.signatures[0];
  if (sig && sig.offHoursFrac > m.expectedOffHoursFrac) {
    out.push(
      `🎯 Most off-hours-skewed rule: \`${clip(sig.signature, 56)}\` — **${pct(sig.offHoursFrac)}** of its ` +
        `${sig.total} hit(s) land off-hours (baseline ${pct(m.expectedOffHoursFrac)}). A candidate for an ` +
        `auto-block rule that does not need a human in the loop.`,
    );
  }

  const src = m.sources[0];
  if (src && src.unattended > 0) {
    out.push(
      `🛰️ Source \`${src.ip}\`${src.watched ? " 👁" : ""}${src.blocked ? " ⛔" : ""} drove **${src.unattended}** ` +
        `serious detect-only off-hours hit(s) (${pct(src.offHoursFrac)} of its traffic off-hours) — a prime ` +
        `block / geo-policy candidate.`,
    );
  }

  const asset = m.assets[0];
  if (asset && asset.unattended > 0) {
    out.push(
      `🏠 Your host \`${asset.ip}\` absorbed **${asset.unattended}** serious unattended hit(s) off-hours — the ` +
        `asset most exposed when no one is watching; prioritise its hardening / auto-containment.`,
    );
  }

  return out;
}

// ----- markdown --------------------------------------------------------------

/** A 24-cell sparkline; idle staffed hours render as `▒` so the staffed band shows. */
function hourSparkline(hist: number[], bizStart: number, bizEnd: number): string {
  const blocks = "▁▂▃▄▅▆▇█";
  const max = Math.max(1, ...hist);
  return hist
    .map((v, h) => {
      const staffed = h >= bizStart && h < bizEnd;
      if (v <= 0) return staffed ? "▒" : "·";
      return blocks[Math.min(blocks.length - 1, Math.floor((v / max) * (blocks.length - 1)))] ?? "█";
    })
    .join("");
}

function signatureTable(rows: SignatureOffHours[]): string {
  return mdTable(
    ["#", "Signature", "Total", "Off-hrs", "Off-hrs %", "Serious", "Unatt.", "Worst"],
    rows.map((s, i) => [
      String(i + 1),
      cell(clip(s.signature, 52)),
      String(s.total),
      String(s.offHours),
      pct(s.offHoursFrac, 0),
      String(s.serious),
      String(s.unattended),
      cell(s.severityMax),
    ]),
  );
}

function sourceTable(rows: SourceOffHours[]): string {
  return mdTable(
    ["#", "Source", "Total", "Off-hrs", "Off-hrs %", "Serious", "Unatt.", "Worst", "Top signature", "Flags"],
    rows.map((s, i) => [
      String(i + 1),
      cell(s.ip),
      String(s.total),
      String(s.offHours),
      pct(s.offHoursFrac, 0),
      String(s.serious),
      String(s.unattended),
      cell(s.severityMax),
      cell(clip(s.signatureTop ?? "—", 36)),
      (s.blocked ? "⛔" : "") + (s.watched ? "👁" : "") || "—",
    ]),
  );
}

function assetTable(rows: AssetOffHours[]): string {
  return mdTable(
    ["#", "Asset (yours)", "Total", "Off-hrs", "Off-hrs %", "Serious", "Unatt.", "Worst"],
    rows.map((s, i) => [
      String(i + 1),
      cell(s.ip),
      String(s.total),
      String(s.offHours),
      pct(s.offHoursFrac, 0),
      String(s.serious),
      String(s.unattended),
      cell(s.severityMax),
    ]),
  );
}

function renderMarkdown(m: OffHoursReport): string {
  const lines: string[] = [];
  lines.push(`# 🌙 SecTool Off-Hours / Defender Coverage-Gap Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Staffing model:** Mon–Fri **${hh(m.bizStart)}:00–${hh(m.bizEnd)}:00 ${offsetLabel(m.tzOffset)}** ` +
      `(${m.staffedHoursPerWeek}h staffed / ${m.offHoursPerWeek}h off-hours per week → ` +
      `**${pct(m.expectedOffHoursFrac)}** of the clock unattended). ` +
      `Offline, deterministic · **Window alerts:** ${m.totalWindowAlerts}`,
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

  // Coverage scoreboard.
  lines.push(`## Coverage at a glance`);
  lines.push("");
  lines.push(
    mdTable(
      ["Bucket", "Alerts", "Share", "Note"],
      [
        ["🟢 Staffed (Mon–Fri, in-hours)", String(m.staffedCount), pct(m.totalWindowAlerts ? m.staffedCount / m.totalWindowAlerts : 0), "A human could respond promptly."],
        ["🌆 Weeknight (out-of-hours)", String(m.weeknightCount), pct(m.totalWindowAlerts ? m.weeknightCount / m.totalWindowAlerts : 0), "Slow response — overnight."],
        ["🛌 Weekend", String(m.weekendCount), pct(m.totalWindowAlerts ? m.weekendCount / m.totalWindowAlerts : 0), "Slowest response window."],
        ["**🌙 Off-hours total**", `**${m.offHoursCount}**`, `**${pct(m.actualOffHoursFrac)}**`, `vs **${pct(m.expectedOffHoursFrac)}** expected → **${m.skewIndex.toFixed(2)}×** skew.`],
        ["🚨 Serious off-hours", String(m.offHoursSerious), pct(m.offHoursCount ? m.offHoursSerious / m.offHoursCount : 0), "≥ medium, arrived unattended."],
        ["🔥 Unattended exposure", String(m.unattendedExposure), pct(m.offHoursSerious ? m.unattendedExposure / m.offHoursSerious : 0), "Serious **and** detect-only — the gap to close."],
      ],
    ),
  );
  lines.push("");
  lines.push(
    `_Skew index = actual off-hours share ÷ the off-hours fraction of the week. **>1** = attacks concentrate when ` +
      `you're away; **≈1** = time-agnostic automation; **<1** = they favour your staffed hours._`,
  );
  lines.push("");

  // Time-of-day exposure.
  lines.push(`## Time-of-day exposure (local ${offsetLabel(m.tzOffset)})`);
  lines.push("");
  lines.push(
    "All alerts, by **local** hour-of-day. `▒` marks an idle *staffed* hour, `·` an idle off-hour; taller bars are " +
      "busier. The staffed band is **" + hh(m.bizStart) + ":00–" + hh(m.bizEnd) + ":00**.",
  );
  lines.push("");
  lines.push("```");
  lines.push("hour  00                      12                      23");
  lines.push("all   " + hourSparkline(m.allByLocalHour, m.bizStart, m.bizEnd));
  lines.push("off   " + hourSparkline(m.offHoursByLocalHour, m.bizStart, m.bizEnd));
  lines.push("```");
  lines.push("");

  // Off-hours-skewed signatures.
  lines.push(`## 🎯 Off-hours-skewed signatures`);
  lines.push("");
  if (m.signatures.length) {
    lines.push(
      `Rules whose hits land disproportionately off-hours (sorted by off-hours volume). _Off-hrs %_ above the ` +
        `**${pct(m.expectedOffHoursFrac)}** baseline means the rule fires more at night/weekends than chance — a ` +
        `candidate for an auto-block that needs no human in the loop. _Unatt._ = serious + detect-only off-hours hits.`,
    );
    lines.push("");
    lines.push(signatureTable(m.signatures));
  } else {
    lines.push(`_No signature cleared the minimum-evidence bar in this window._`);
  }
  lines.push("");

  // Off-hours-skewed sources.
  lines.push(`## 🛰️ Off-hours attackers`);
  lines.push("");
  if (m.sources.length) {
    lines.push(
      `External sources ranked by serious detect-only off-hours impact, then off-hours volume. These struck when a ` +
        `human response was slowest — prime **block / geo-policy** candidates. ⛔ already blocked · 👁 watched.`,
    );
    lines.push("");
    lines.push(sourceTable(m.sources));
  } else {
    lines.push(`_No external source cleared the minimum-evidence bar in this window._`);
  }
  lines.push("");

  // Most-exposed internal assets.
  lines.push(`## 🏠 Most-exposed assets off-hours`);
  lines.push("");
  if (m.assets.length) {
    lines.push(
      `Your own hosts ranked by serious unattended hits — where a slow off-hours response compounds the risk. ` +
        `Prioritise hardening or automated containment for the top rows.`,
    );
    lines.push("");
    lines.push(assetTable(m.assets));
  } else {
    lines.push(`_No internal target asset cleared the minimum-evidence bar in this window._`);
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. The staffing window is a **model** (default Mon–Fri 09:00–17:00, single UTC ` +
      `offset) — pass \`--tz\`, \`--start\`, \`--end\` to match your real roster; a 24/7 or follow-the-sun team has ` +
      `no off-hours window. "Unattended" means *outside staffed hours*, a structural exposure — not proof nobody ` +
      `triaged the alert. These are IPS **detections**, not response actions; off-hours does not re-grade a threat, ` +
      `it ranks where slow human response compounds it. A long look-back can hit the alert store's history cap and ` +
      `clip the tail. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the off-hours / defender coverage-gap report from the stored alert
 * history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]). A multi-day
 *              window is needed for a weekday/weekend split to be meaningful.
 * @param opts  {@link OffHoursOptions}: the staffing model (`tzOffset`,
 *              `bizStart`, `bizEnd`, `weekendsOff`), row `limit`, the `minAlerts`
 *              evidence bar, and a `nowMs` pin for deterministic tests.
 */
export function buildOffHours(hours: number, opts: OffHoursOptions = {}): OffHoursReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const tzOffset = Math.max(-12, Math.min(14, Math.floor(opts.tzOffset ?? DEFAULT_TZ_OFFSET)));
  const bizStart = Math.max(0, Math.min(23, Math.floor(opts.bizStart ?? DEFAULT_BIZ_START)));
  const bizEnd = Math.max(bizStart + 1, Math.min(24, Math.floor(opts.bizEnd ?? DEFAULT_BIZ_END)));
  const weekendsOff = opts.weekendsOff !== false;
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minAlerts = Math.max(1, Math.min(1000, Math.floor(opts.minAlerts ?? DEFAULT_MIN_ALERTS)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  // Coverage model: staffed clock-hours per 7-day week.
  const dailyBand = bizEnd - bizStart;
  const staffedHoursPerWeek = dailyBand * 5; // weekdays only
  const offHoursPerWeek = Math.max(0, 168 - staffedHoursPerWeek);
  const expectedOffHoursFrac = round4(offHoursPerWeek / 168);

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  let staffedCount = 0;
  let weeknightCount = 0;
  let weekendCount = 0;
  let offHoursSerious = 0;
  let unattendedExposure = 0;
  const offHoursByLocalHour = new Array(24).fill(0);
  const allByLocalHour = new Array(24).fill(0);

  const bySig = new Map<string, EntityAcc>();
  const bySrc = new Map<string, EntityAcc>();
  const byAsset = new Map<string, EntityAcc>();

  for (const a of windowed) {
    const parts = localParts(a.time, tzOffset);
    allByLocalHour[parts.hour]++;
    const cov = coverageOf(parts, bizStart, bizEnd, weekendsOff);
    const off = cov !== "staffed";
    if (cov === "staffed") staffedCount++;
    else if (cov === "weeknight") weeknightCount++;
    else weekendCount++;

    if (off) {
      offHoursByLocalHour[parts.hour]++;
      if (isSerious(a.severity)) {
        offHoursSerious++;
        if (!isBlocked(a.action)) unattendedExposure++;
      }
    }

    const sig = (a.signature ?? "").trim();
    if (sig) {
      let acc = bySig.get(sig);
      if (!acc) { acc = newEntityAcc(); bySig.set(sig, acc); }
      bumpEntity(acc, a, off);
    }
    const src = externalIp(a.srcIp);
    if (src) {
      let acc = bySrc.get(src);
      if (!acc) { acc = newEntityAcc(); bySrc.set(src, acc); }
      bumpEntity(acc, a, off);
    }
    const asset = internalIp(a.dstIp);
    if (asset) {
      let acc = byAsset.get(asset);
      if (!acc) { acc = newEntityAcc(); byAsset.set(asset, acc); }
      bumpEntity(acc, a, off);
    }
  }

  const offHoursCount = weeknightCount + weekendCount;
  const totalWindowAlerts = windowed.length;
  const actualOffHoursFrac = totalWindowAlerts ? round4(offHoursCount / totalWindowAlerts) : 0;
  const skewIndex =
    expectedOffHoursFrac > 0 ? Math.round((actualOffHoursFrac / expectedOffHoursFrac) * 100) / 100 : 0;

  // Signatures: only those with any off-hours presence and enough evidence.
  const signatures: SignatureOffHours[] = [...bySig.entries()]
    .filter(([, acc]) => acc.total >= minAlerts && acc.offHours > 0)
    .map(([signature, acc]) => ({
      signature,
      total: acc.total,
      offHours: acc.offHours,
      offHoursFrac: round4(acc.offHours / acc.total),
      serious: acc.serious,
      unattended: acc.unattended,
      severityMax: acc.severityMax,
    }))
    .sort((a, b) => b.offHours - a.offHours || b.unattended - a.unattended || (a.signature < b.signature ? -1 : 1))
    .slice(0, limit);

  // Sources: rank by serious detect-only off-hours impact, then off-hours volume.
  const sources: SourceOffHours[] = [...bySrc.entries()]
    .filter(([, acc]) => acc.total >= minAlerts && acc.offHours > 0)
    .map(([ip, acc]) => ({
      ip,
      total: acc.total,
      offHours: acc.offHours,
      offHoursFrac: round4(acc.offHours / acc.total),
      serious: acc.serious,
      unattended: acc.unattended,
      severityMax: acc.severityMax,
      blocked: blockStore.has(ip),
      watched: watchStore.has(ip),
      signatureTop: topSignature(acc.signatures),
    }))
    .sort((a, b) => b.unattended - a.unattended || b.offHours - a.offHours || (a.ip < b.ip ? -1 : 1))
    .slice(0, limit);

  // Assets: your own hosts, ranked by serious unattended exposure.
  const assets: AssetOffHours[] = [...byAsset.entries()]
    .filter(([, acc]) => acc.total >= minAlerts && acc.offHours > 0)
    .map(([ip, acc]) => ({
      ip,
      total: acc.total,
      offHours: acc.offHours,
      offHoursFrac: round4(acc.offHours / acc.total),
      serious: acc.serious,
      unattended: acc.unattended,
      severityMax: acc.severityMax,
    }))
    .sort((a, b) => b.unattended - a.unattended || b.serious - a.serious || b.offHours - a.offHours || (a.ip < b.ip ? -1 : 1))
    .slice(0, limit);

  const model: OffHoursReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    tzOffset,
    bizStart,
    bizEnd,
    staffedHoursPerWeek,
    offHoursPerWeek,
    expectedOffHoursFrac,
    totalWindowAlerts,
    staffedCount,
    weeknightCount,
    weekendCount,
    offHoursCount,
    actualOffHoursFrac,
    skewIndex,
    offHoursSerious,
    unattendedExposure,
    offHoursByLocalHour,
    allByLocalHour,
    signatures,
    sources,
    assets,
    highlights: [],
    markdown: "",
  };
  model.highlights = writeHighlights(model);
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded off-hours report. */
export function offhoursFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-offhours-${stamp}.md`;
}
