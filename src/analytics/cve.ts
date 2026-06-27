/**
 * CVE-exposure / exploited-vulnerability report — "which *named, known*
 * vulnerabilities are being fired at my network, who is firing them, which of my
 * hosts are the targets, and — the part that decides my morning — how much of it
 * is getting through unblocked?"
 *
 * Every other offline report in this project pivots on an *entity* (attacker IP,
 * netblock, internal target), a *time shape* (surge, beacon, rhythm), or the
 * IDS engine's own taxonomy (classify on classtype, killchain on stage, tuning /
 * lifecycle on the raw signature string). None of them extract the single most
 * patch-actionable token an IPS rule can carry: the **CVE identifier**.
 *
 * Emerging-Threats / Suricata rule names routinely embed the CVE(s) a signature
 * detects, e.g.
 *
 *   "ET EXPLOIT Apache Log4j RCE Attempt ... (CVE-2021-44228)"
 *   "ET WEB_SPECIFIC_APPS ... SQL Injection ... CVE-2019-9978"
 *
 * That `CVE-YYYY-NNNN` token is a globally-stable join key into the entire
 * vulnerability-management world: NVD severity/CVSS, the CISA KEV catalogue, a
 * vendor patch, a virtual-patch WAF rule. Surfacing it turns the alert history
 * from "signatures fired" into a **patch / virtual-patch worklist**:
 *
 *   **"CVE-2021-44228 was thrown at `10.0.0.20` 14 times from 6 distinct
 *    sources, peak severity high, and 9 of those got through unblocked — patch
 *    or virtual-patch that box now."**
 *
 * That question — known-exploit exposure ranked by what the gateway *failed* to
 * stop — is exactly what a defender wants first and is absent from every existing
 * report. classify.ts rolls up *intent* ("Web Application Attack"); this rolls
 * up *the specific flaw being exploited*, which is a finer and far more
 * actionable axis (one classtype spans hundreds of unrelated CVEs).
 *
 * For each distinct CVE this module rolls up, purely from the stored history:
 *
 *   - alert volume and its share of all CVE-tagged volume,
 *   - severity-weighted **pressure** (Σ `SEVERITY_WEIGHT` — the shared geometric
 *     info 1 · low 3 · medium 9 · high 27 · critical 81 ladder risk.ts uses),
 *     split blocked vs. unblocked, with the CVE ranked by *unblocked* pressure,
 *   - **enforcement posture** — block rate and an open-gap flag, because a
 *     known-exploit CVE that is *not* being blocked is the headline this report
 *     exists to float,
 *   - breadth — distinct attacker sources and distinct internal targets, so a
 *     CVE worked by a botnet against many boxes reads differently from a single
 *     probe,
 *   - the CVE's *age* (derived from its year) — a years-old CVE still landing
 *     means an unpatched box, fresh ammunition aimed at legacy software,
 *   - first/last seen, the dominant signature, and the heaviest target/attacker.
 *
 * Honest caveats baked into the output:
 *
 *   - **Only as good as the rule name.** This greps `CVE-YYYY-NNNN` out of the
 *     signature and raw line. A signature that detects a CVE without naming it is
 *     invisible here; absence of a CVE row is *not* absence of exploit attempts.
 *   - **Detection ≠ vulnerability.** A CVE alert means the *exploit pattern* was
 *     seen on the wire, not that the target is actually vulnerable or was
 *     compromised. It is a prioritisation signal for patch/verify, not proof.
 *   - **Blocked ≠ safe forever.** A blocked exploit means *this* attempt was
 *     stopped; the underlying CVE is still worth patching.
 *   - **src/dst are the gateway's labels.** NAT / hairpin / asymmetric routing
 *     can mislabel which side is the target; internal = RFC1918.
 *   - **Window-bounded & store-capped.** A long look-back can hit the store's
 *     history cap and truncate the oldest alerts, deflating a CVE's counts.
 *
 * Pure in-memory math over alertStore (plus blocklist/watchlist membership flags
 * on the heaviest attacker) — no SSH, no Claude, no network. Output is both a
 * structured model and a ready-to-paste Markdown document, mirroring targets.ts,
 * risk.ts, classify.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/**
 * Matches a CVE identifier anywhere in free text. CVEs are `CVE-YYYY-NNNN+`
 * (4-digit year, then a 4-or-more-digit sequence number). Case-insensitive and
 * global so a single signature naming two CVEs contributes to both. The token is
 * upper-cased on capture so `cve-2021-44228` and `CVE-2021-44228` collapse.
 */
const CVE_RE = /CVE-(\d{4})-(\d{4,7})/gi;

/** One distinct CVE, with every alert that named it collapsed into one row. */
export interface CveExposure {
  /** The canonical, upper-cased identifier, e.g. "CVE-2021-44228". */
  cve: string;
  /** The 4-digit disclosure year parsed from the identifier. */
  year: number;
  /** Whole years between the CVE's year and the report window end. */
  ageYears: number;
  /** Alerts that named this CVE inside the window. */
  count: number;
  /** This CVE's unblocked pressure as a share of all CVE unblocked pressure, 0..1 (4dp). */
  share: number;
  /** Distinct source IPs that fired an alert naming this CVE. */
  attackers: number;
  /** Of {@link attackers}, those that are external (public, non-RFC1918). */
  externalAttackers: number;
  /** Distinct destination IPs hit by an alert naming this CVE. */
  targets: number;
  /** Of {@link targets}, those that are internal (RFC1918 — your assets). */
  internalTargets: number;
  /** Distinct signatures that referenced this CVE. */
  signatures: number;
  /** Worst severity any alert naming this CVE reached. */
  severityMax: Severity;
  /** Alerts naming this CVE at medium severity or worse. */
  severe: number;
  /** Of {@link count}, alerts the gateway blocked. */
  blocked: number;
  /** Of {@link count}, alerts the gateway let through (detected/allowed). */
  passed: number;
  /** Of {@link count}, alerts with no recorded action. */
  unknown: number;
  /** blocked / count, 0..1 (4dp) — this CVE's enforcement coverage. */
  blockRate: number;
  /** Severity-weighted total pressure for this CVE (Σ severity weight). */
  pressure: number;
  /** Of {@link pressure}, the part on *unblocked* (passed+unknown) alerts. */
  unblockedPressure: number;
  /** A severe-or-worse CVE the gateway left mostly unblocked — patch worklist top. */
  openGap: boolean;
  /** Epoch ms of the first alert naming this CVE in the window. */
  firstMs: number;
  /** Epoch ms of the most recent alert naming this CVE in the window. */
  lastMs: number;
  /** The single most frequent signature that named this CVE. */
  topSignature?: string;
  /** The internal target hit most by this CVE (the box to patch first). */
  topTarget?: string;
  /** The source that fired this CVE most (the heaviest attacker). */
  topAttacker?: string;
  /** {@link topAttacker} is on the blocklist. */
  topAttackerBlocked: boolean;
  /** {@link topAttacker} is on the watchlist. */
  topAttackerWatched: boolean;
}

export interface CveReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts with a usable timestamp inside the window. */
  totalWindowAlerts: number;
  /** Of {@link totalWindowAlerts}, those that named at least one CVE. */
  cveAlerts: number;
  /** cveAlerts / totalWindowAlerts, 0..1 (4dp) — how CVE-rich the traffic is. */
  cveAlertShare: number;
  /** Distinct CVEs seen this window. */
  distinctCves: number;
  /** Of {@link distinctCves}, those that are an {@link CveExposure.openGap}. */
  openGapCves: number;
  /** Severity-weighted pressure summed across every CVE-tagged alert. */
  totalPressure: number;
  /** Of {@link totalPressure}, the part on unblocked alerts. */
  totalUnblockedPressure: number;
  /** The CVEs, ranked by unblocked pressure (the patch worklist). */
  top: CveExposure[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface CveOptions {
  /** Max rows in the CVE table (clamped to [1, 200]). */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const MS_PER_HOUR = 3_600_000;
const MS_PER_YEAR = 365 * 24 * MS_PER_HOUR;

// ----- formatting helpers (mirror targets.ts / risk.ts) ---------------------

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** A compact relative-age label like "3h" / "2d" — mirrors targets.ts. */
function fmtAge(ms: number, nowMs: number): string {
  const sec = Math.max(0, Math.round((nowMs - ms) / 1000));
  if (sec < 90) return `${sec}s`;
  const min = Math.round(sec / 60);
  if (min < 90) return `${min}m`;
  const hr = Math.round(min / 60);
  if (hr < 48) return `${hr}h`;
  return `${Math.round(hr / 24)}d`;
}

/** A 0..1 fraction as a whole-number percent string, e.g. 0.823 -> "82%". */
function pct(frac: number): string {
  return `${Math.round(frac * 100)}%`;
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
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

// ----- classifiers (mirror targets.ts) --------------------------------------

/** RFC1918 / loopback / link-local / ULA — mirrors targets.ts / spread.ts. */
function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
}

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

/** Coerce a stored severity string to a known band, defaulting to "info". */
function asSeverity(s: string | undefined): Severity {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? "info" : (s as Severity);
}

function maxSeverity(a: Severity, b: Severity): Severity {
  return sevRank(b) > sevRank(a) ? b : a;
}

function isSevere(s: Severity): boolean {
  return sevRank(s) >= 2; // medium or worse
}

/** A valid, non-empty IP, or undefined if the field is missing/garbage. */
function validIp(ip: string | undefined): string | undefined {
  return ip && isIP(ip) !== 0 ? ip : undefined;
}

/** Increment a counter in a frequency map. */
function bump(map: Map<string, number>, key: string): void {
  map.set(key, (map.get(key) ?? 0) + 1);
}

/** The (key, count) with the highest count; key tie-break for determinism. */
function topOf(map: Map<string, number>): { key?: string; count: number } {
  let bestKey: string | undefined;
  let best = 0;
  for (const [k, c] of map) {
    if (c > best || (c === best && bestKey !== undefined && k < bestKey)) {
      best = c;
      bestKey = k;
    }
  }
  return { key: bestKey, count: best };
}

/**
 * Extract every distinct CVE id named in an alert's signature + raw line.
 * Returns canonical upper-cased ids; a single line naming a CVE twice yields it
 * once. Both fields are scanned because ET rule metadata sometimes carries the
 * CVE in the raw `metadata` block rather than the rule name proper.
 */
export function extractCves(alert: Pick<StoredAlert, "signature" | "raw">): string[] {
  const hay = `${alert.signature ?? ""} ${alert.raw ?? ""}`;
  if (!hay.includes("CVE") && !hay.includes("cve")) return [];
  const found = new Set<string>();
  // `matchAll` over a fresh-state global regex; lastIndex is per-iterator here.
  for (const m of hay.matchAll(CVE_RE)) {
    found.add(`CVE-${m[1]}-${m[2]}`.toUpperCase());
  }
  return [...found];
}

// ----- per-CVE aggregation --------------------------------------------------

interface CveAcc {
  year: number;
  count: number;
  sources: Map<string, number>;
  externalSources: Set<string>;
  targets: Map<string, number>; // internal targets only (the patch worklist)
  allTargets: Set<string>;
  signatures: Map<string, number>;
  severityMax: Severity;
  severe: number;
  blocked: number;
  passed: number;
  unknown: number;
  pressure: number;
  unblockedPressure: number;
  firstMs: number;
  lastMs: number;
}

function newCveAcc(year: number, time: number): CveAcc {
  return {
    year,
    count: 0,
    sources: new Map(),
    externalSources: new Set(),
    targets: new Map(),
    allTargets: new Set(),
    signatures: new Map(),
    severityMax: "info",
    severe: 0,
    blocked: 0,
    passed: 0,
    unknown: 0,
    pressure: 0,
    unblockedPressure: 0,
    firstMs: time,
    lastMs: time,
  };
}

/**
 * An open gap = a CVE that reached medium severity or worse yet the gateway
 * blocked less than half of its attempts. These are the rows a defender must act
 * on: a known exploit landing with little or no enforcement.
 */
const OPEN_GAP_BLOCK_RATE = 0.5;

function finishCve(cve: string, a: CveAcc, totalCvePressure: number, windowEndMs: number): CveExposure {
  const blockRate = a.count ? round4(a.blocked / a.count) : 0;
  const topSignature = topOf(a.signatures);
  const topTarget = topOf(a.targets);
  const topAttacker = topOf(a.sources);
  const ageYears = Math.max(0, new Date(windowEndMs).getUTCFullYear() - a.year);
  return {
    cve,
    year: a.year,
    ageYears,
    count: a.count,
    share: totalCvePressure ? round4(a.unblockedPressure / totalCvePressure) : 0,
    attackers: a.sources.size,
    externalAttackers: a.externalSources.size,
    targets: a.allTargets.size,
    internalTargets: a.targets.size,
    signatures: a.signatures.size,
    severityMax: a.severityMax,
    severe: a.severe,
    blocked: a.blocked,
    passed: a.passed,
    unknown: a.unknown,
    blockRate,
    pressure: round1(a.pressure),
    unblockedPressure: round1(a.unblockedPressure),
    openGap: isSevere(a.severityMax) && blockRate < OPEN_GAP_BLOCK_RATE,
    firstMs: a.firstMs,
    lastMs: a.lastMs,
    topSignature: topSignature.key,
    topTarget: topTarget.key,
    topAttacker: topAttacker.key,
    topAttackerBlocked: topAttacker.key ? blockStore.has(topAttacker.key) : false,
    topAttackerWatched: topAttacker.key ? watchStore.has(topAttacker.key) : false,
  } satisfies CveExposure;
}

/**
 * Rank CVEs by *unblocked* pressure (known exploit that got through), tie-broken
 * by open-gap status, raw pressure, target breadth, volume, then id — so the
 * order is fully deterministic.
 */
function rankCves(rows: CveExposure[], limit: number): CveExposure[] {
  return [...rows]
    .sort(
      (x, y) =>
        y.unblockedPressure - x.unblockedPressure ||
        Number(y.openGap) - Number(x.openGap) ||
        y.pressure - x.pressure ||
        y.internalTargets - x.internalTargets ||
        y.count - x.count ||
        (x.cve < y.cve ? -1 : x.cve > y.cve ? 1 : 0),
    )
    .slice(0, limit);
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  m: Omit<CveReport, "highlights" | "markdown">,
  nowMs: number,
): string[] {
  const out: string[] = [];
  if (!m.cveAlerts) return out;

  out.push(
    `🧬 **${m.distinctCves.toLocaleString("en-US")} distinct CVE(s)** were named across ` +
      `${m.cveAlerts.toLocaleString("en-US")} alert(s) over the last ${m.hours}h ` +
      `(${pct(m.cveAlertShare)} of all alerts carried a CVE id), with ` +
      `**${m.totalUnblockedPressure.toLocaleString("en-US")} of ${m.totalPressure.toLocaleString("en-US")} ` +
      `severity-weighted pressure unblocked**. This report turns the alert history into a ` +
      `*patch / virtual-patch worklist*, ranked by known-exploit pressure the gateway let through.`,
  );

  // Open-gap CVEs — the headline a defender wants first.
  const gaps = m.top.filter((c) => c.openGap);
  if (gaps.length) {
    out.push(
      `🚨 **${gaps.length} CVE(s) are an open gap** (severe yet <50% blocked): ` +
        gaps
          .slice(0, 6)
          .map(
            (c) =>
              `\`${c.cve}\` (${c.count}× from ${c.attackers} src, ${pct(c.blockRate)} blocked` +
              (c.topTarget ? `, hitting \`${c.topTarget}\`` : "") +
              `)`,
          )
          .join(", ") +
        `. A *named, known* exploit landing with little enforcement is the top patch / virtual-patch priority — ` +
        `patch the target, or add a blocking rule.`,
    );
  } else {
    out.push(
      `✅ No CVE reached medium+ severity with under half its attempts blocked — every known-exploit ` +
        `attempt of consequence this window was mostly or fully enforced. Still patch the underlying flaws; ` +
        `a blocked attempt stops *this* try, not the vulnerability.`,
    );
  }

  // The single worst CVE by unblocked pressure.
  const worst = m.top[0];
  if (worst) {
    out.push(
      `🎯 Heaviest known-exploit exposure: \`${worst.cve}\` — **${worst.count} alert(s) from ` +
        `${worst.attackers} distinct source(s)** against ${worst.targets} target(s), peak ${worst.severityMax}, ` +
        `${pct(worst.blockRate)} blocked` +
        (worst.topTarget ? `, heaviest on internal \`${worst.topTarget}\`` : "") +
        `. Most recent ${fmtAge(worst.lastMs, nowMs)} ago. Top rule: ${clip(worst.topSignature ?? "—", 50)}.`,
    );
  }

  // Aged-CVE call-out: years-old exploits still landing = unpatched legacy software.
  const aged = m.top
    .filter((c) => c.ageYears >= 3)
    .sort((a, b) => b.ageYears - a.ageYears || b.unblockedPressure - a.unblockedPressure);
  if (aged.length) {
    out.push(
      `🕰️ **${aged.length} CVE(s) are ${aged[0]!.ageYears}+ years old yet still being fired** — e.g. ` +
        aged
          .slice(0, 5)
          .map((c) => `\`${c.cve}\` (${c.ageYears}y, ${c.count}×)`)
          .join(", ") +
        `. Attackers spray old CVEs because *someone* never patched; if any of your assets run the affected ` +
        `software, these are trivially exploitable.`,
    );
  }

  // Breadth call-out: a CVE worked against many of your boxes.
  const wide = m.top
    .filter((c) => c.internalTargets >= 3)
    .sort((a, b) => b.internalTargets - a.internalTargets)[0];
  if (wide) {
    out.push(
      `🌐 \`${wide.cve}\` was thrown at **${wide.internalTargets} distinct internal target(s)** — a single ` +
        `flaw being swept across your estate. Confirm which of those boxes actually run the affected software and ` +
        `prioritise them together rather than one ticket at a time.`,
    );
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function cveTable(rows: CveExposure[], nowMs: number): string {
  return mdTable(
    [
      "#",
      "CVE",
      "Age",
      "Pressure",
      "Unblocked",
      "Share",
      "Alerts",
      "Block%",
      "Src",
      "Targets",
      "Int",
      "Peak sev",
      "Top target",
      "Last",
      "Gap",
    ],
    rows.map((r, i) => [
      String(i + 1),
      cell(r.cve),
      `${r.ageYears}y`,
      String(r.pressure),
      String(r.unblockedPressure),
      pct(r.share),
      String(r.count),
      pct(r.blockRate),
      String(r.attackers),
      String(r.targets),
      String(r.internalTargets),
      cell(r.severityMax),
      r.topTarget ? cell(r.topTarget) : "—",
      fmtAge(r.lastMs, nowMs),
      r.openGap ? "🚨" : "—",
    ]),
  );
}

function renderMarkdown(m: CveReport, nowMs: number): string {
  const lines: string[] = [];
  lines.push(`# 🧬 SecTool CVE-Exposure / Exploited-Vulnerability Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`,
  );
  lines.push(
    `**Method:** stored IPS alerts whose signature/raw line names a \`CVE-YYYY-NNNN\` id, grouped by CVE; ` +
      `pressure = Σ severity weight (info 1 · low 3 · medium 9 · high 27 · critical 81), split blocked vs. ` +
      `unblocked. CVEs ranked by *unblocked* pressure, then open-gap status · ` +
      `**Window alerts:** ${m.totalWindowAlerts} _(+${m.cveAlerts} named a CVE)_`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.cveAlerts) {
    lines.push(
      `No alert named a \`CVE-YYYY-NNNN\` identifier in the last ${m.hours} hour(s). This is **not** proof ` +
        `you are un-probed — many signatures detect a flaw without printing its CVE in the rule name, so a CVE ` +
        `cannot be rolled up for them. Cross-check the classification and signature-tuning reports for the wider picture.`,
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  lines.push(`| Metric | Value |`);
  lines.push(`| --- | --- |`);
  lines.push(`| Distinct CVEs | ${m.distinctCves.toLocaleString("en-US")} |`);
  lines.push(`| — open gaps (severe & <50% blocked) | ${m.openGapCves.toLocaleString("en-US")} |`);
  lines.push(
    `| CVE-tagged alerts | ${m.cveAlerts.toLocaleString("en-US")} (${pct(m.cveAlertShare)} of all) |`,
  );
  lines.push(`| Total CVE pressure | ${m.totalPressure.toLocaleString("en-US")} |`);
  lines.push(
    `| Unblocked CVE pressure | ${m.totalUnblockedPressure.toLocaleString("en-US")} (${m.totalPressure ? pct(round4(m.totalUnblockedPressure / m.totalPressure)) : "0%"}) |`,
  );
  lines.push("");

  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## CVEs (patch / virtual-patch worklist)`);
  lines.push("");
  lines.push(
    `Each row is one distinct CVE, every alert that named it collapsed in, ranked by *unblocked* pressure — ` +
      `the known-exploit volume the gateway let through. _Block%_ is the share actively blocked; _Targets_ / _Int_ ` +
      `are distinct destinations / internal (RFC1918) destinations hit; _Top target_ is the internal box hit most ` +
      `(patch it first). 🚨 _Gap_ marks a severe CVE under 50% blocked — the rows that earn a morning.`,
  );
  lines.push("");
  lines.push(cveTable(m.top, nowMs));
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from stored **IPS-alert** signatures + raw lines by extracting ` +
      `\`CVE-YYYY-NNNN\` identifiers. **Pressure** is a **heuristic** severity-weighted volume ` +
      `(info 1 · low 3 · medium 9 · high 27 · critical 81); read the ranking as relative. A CVE alert means the ` +
      `*exploit pattern* was seen on the wire — **not** that the target is vulnerable or was compromised; treat it ` +
      `as a prioritisation signal for patch/verify, not proof. A **blocked** attempt stops *this* try, not the ` +
      `underlying flaw — still patch it. Coverage is only as good as the rule name: a signature that detects a CVE ` +
      `without naming it is invisible here, so an empty or short list is not proof of safety. src/dst are the ` +
      `gateway's own labels (NAT / hairpin / asymmetric routing can mislabel which side is the target); internal = ` +
      `RFC1918. A long look-back can hit the store's history cap and deflate a CVE's counts. No live gateway query ` +
      `was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the CVE-exposure report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link CveOptions}: `limit` (rows in the table) and a `nowMs` pin.
 */
export function buildCve(hours: number, opts: CveOptions = {}): CveReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const cves = new Map<string, CveAcc>();
  let totalWindowAlerts = 0;
  let cveAlerts = 0;
  let totalPressure = 0;
  let totalUnblockedPressure = 0;

  for (const a of windowed) {
    totalWindowAlerts++;
    const ids = extractCves(a);
    if (!ids.length) continue;
    cveAlerts++;

    const severity = asSeverity(a.severity);
    const disp = classifyDisposition(a.action);
    const weight = SEVERITY_WEIGHT[severity];
    const unblocked = disp !== "blocked";

    totalPressure += weight;
    if (unblocked) totalUnblockedPressure += weight;

    const src = validIp(a.srcIp);
    const dst = validIp(a.dstIp);
    const sig = a.signature?.trim();

    for (const id of ids) {
      const year = Number(id.slice(4, 8));
      let acc = cves.get(id);
      if (!acc) {
        acc = newCveAcc(year, a.time);
        cves.set(id, acc);
      }
      acc.count++;
      acc.pressure += weight;
      if (disp === "blocked") acc.blocked++;
      else {
        acc.unblockedPressure += weight;
        if (disp === "passed") acc.passed++;
        else acc.unknown++;
      }
      acc.severityMax = maxSeverity(acc.severityMax, severity);
      if (isSevere(severity)) acc.severe++;
      if (a.time < acc.firstMs) acc.firstMs = a.time;
      if (a.time > acc.lastMs) acc.lastMs = a.time;
      if (src) {
        bump(acc.sources, src);
        if (!isPrivate(src)) acc.externalSources.add(src);
      }
      if (dst) {
        acc.allTargets.add(dst);
        if (isPrivate(dst)) bump(acc.targets, dst);
      }
      if (sig) bump(acc.signatures, sig);
    }
  }

  const rows = [...cves.entries()].map(([cve, acc]) =>
    finishCve(cve, acc, totalUnblockedPressure || totalPressure, windowEndMs),
  );
  const top = rankCves(rows, limit);

  const base: Omit<CveReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts,
    cveAlerts,
    cveAlertShare: totalWindowAlerts ? round4(cveAlerts / totalWindowAlerts) : 0,
    distinctCves: rows.length,
    openGapCves: rows.filter((r) => r.openGap).length,
    totalPressure: round1(totalPressure),
    totalUnblockedPressure: round1(totalUnblockedPressure),
    top,
  };

  const highlights = writeHighlights(base, windowEndMs);
  const model: CveReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model, windowEndMs);
  return model;
}

/** A filesystem-safe filename for a downloaded CVE-exposure report. */
export function cveFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-cve-${stamp}.md`;
}
