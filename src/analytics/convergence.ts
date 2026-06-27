/**
 * Temporal-convergence / coordinated-strike report — "did a *crowd* of distinct
 * sources all hit the same target (or fire the same signature) inside a narrow
 * window of seconds — the flash-crowd signature of a botnet, a DDoS, or a
 * coordinated credential spray?"
 *
 * The single most reliable tell of *coordination* is **simultaneity**: many
 * unrelated source IPs converging on one target in the same handful of seconds.
 * No human types from forty addresses at once; a tasked botnet, a stresser
 * service, or a distributed password-spray does exactly that. The members of
 * such a crowd are deliberately diverse — scattered across different netblocks,
 * sometimes even firing *different* signatures — so the only thing that binds
 * them is the **clock**. That is precisely the axis the existing reports throw
 * away:
 *
 *   - cluster.ts groups sources that share the *same signature set* (Jaccard) —
 *     it catches a botnet running one toolkit, but is blind to a crowd whose
 *     members trip different rules, and it ignores *when* they fired.
 *   - netblock.ts groups by /24 CIDR — it catches rotation inside one allocation,
 *     but a real botnet is spread across dozens of unrelated networks, and again
 *     timing never enters the math.
 *   - surge.ts flags spikes in the *aggregate* stream and attributes them, but a
 *     single hammering source produces an identical spike — it never asks how
 *     many *distinct* sources made the storm.
 *   - burstiness.ts / beacon.ts / dwell.ts all score a *single* source's own
 *     timeline; convergence is the orthogonal question — many sources, one
 *     instant.
 *   - targets.ts ranks victims by total pressure and distinct-attacker count over
 *     the *whole window*; it never localises that crowd to a few seconds, so a
 *     target hit by 50 sources spread evenly over a week scores the same as one
 *     hit by 50 sources in 30 seconds — yet only the second is an attack.
 *
 * This report localises the crowd in time. For every target (destination IP) it
 * slides a `windowSec` window across that target's alert timeline and records the
 * **peak number of distinct sources** seen inside any single window — the moment
 * of tightest convergence — together with the members present at that peak. A
 * target whose peak clears `minSources` is a **convergence event**: a coordinated
 * strike, not background drizzle. The same statistic is then computed per
 * **signature** (many distinct sources firing one rule in one window — a
 * coordinated campaign / mass-exploitation of a single CVE across the estate).
 *
 * For each convergence it reports the concrete picture an operator can act on:
 * the peak distinct-source count and the seconds it spanned, a sample of the
 * member IPs, the **convergence ratio** (peak-window distinct sources ÷ the
 * target's total distinct sources — how *temporally* concentrated the crowd was,
 * vs. merely many attackers over a long span), the external-source share,
 * direction (external→internal inbound pressure vs. internal noise), peak
 * severity, block share, and the dominant signature.
 *
 * Honest caveats baked into the output:
 *
 *   - **Alerts, not packets, and second-resolution clocks.** SecTool stores IPS
 *     *alerts* with syslog second-granularity timestamps, so the crowd is a crowd
 *     of *detections* and sub-second ordering is lost. A true volumetric flood is
 *     under-counted (the gateway logs a sample, not every packet); read counts as
 *     a floor, not a census.
 *   - **Spoofing.** Volumetric DDoS can forge source addresses, inflating the
 *     distinct-source count. IPS alerts usually ride established-ish flows, which
 *     resists naive spoofing, but the report flags the crowd to *look at*, it does
 *     not attribute.
 *   - **Coincidence at scale.** On a very busy target, unrelated sources will
 *     occasionally co-occur by chance; the `minSources` floor and the convergence
 *     ratio exist to separate a genuine synchronized strike from background
 *     coincidence. Cross-check flagged crowds against the toolkit-cluster
 *     (`--clusters`) and netblock (`--netblocks`) reports for the *who*.
 *
 * It is pure in-memory math over alertStore — no SSH, no Claude, no network — so
 * it is safe to call from the dashboard or CLI at any time. Output is both a
 * structured model and a ready-to-paste Markdown document, mirroring report.ts,
 * compare.ts, profile.ts, assets.ts, tuning.ts, watchlist.ts, rhythm.ts,
 * novelty.ts, killchain.ts, beacon.ts, surge.ts, dwell.ts and burstiness.ts.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Orientation of a convergence (who the crowd is and who it struck). */
export type ConvergenceDirection = "inbound" | "internal" | "outbound" | "external";

/** One destination IP scored for the tightest crowd of distinct sources that struck it. */
export interface ConvergenceTarget {
  dstIp: string;
  /** True when the target is a public (non-RFC1918) address. */
  external: boolean;
  /** Total alerts to this target inside the window. */
  count: number;
  /** Distinct source IPs that struck this target across the whole window. */
  distinctSources: number;
  /** Peak number of distinct sources inside any `windowSec` sliding window. */
  peakSources: number;
  /** Alerts inside that same peak window (≥ {@link peakSources}). */
  peakAlerts: number;
  /** ms epoch where the peak window starts (first alert of the densest window). */
  peakStartMs: number;
  /** Actual span of the peak crowd in seconds (last − first member alert in the window). */
  peakSpanSeconds: number;
  /** A sample of the member source IPs present at the peak (capped for display). */
  peakMembers: string[];
  /** How many of {@link peakSources} were external (public) addresses. */
  peakExternalSources: number;
  /**
   * Convergence ratio = {@link peakSources} ÷ {@link distinctSources}, in (0, 1].
   * → 1 means the *entire* attacker set landed inside one window (a true
   * synchronized strike); a low value means many attackers spread over the span,
   * with only a few coinciding (closer to background coincidence).
   */
  convergenceRatio: number;
  /** Dominant orientation of the peak crowd. */
  direction: ConvergenceDirection;
  /** Distinct signatures the crowd tripped against this target. */
  distinctSignatures: number;
  /** The dominant signature for context (may be empty). */
  topSignature: string;
  /** Worst severity observed across this target's alerts. */
  severityMax: Severity;
  /** Alerts at medium severity or above. */
  severeCount: number;
  /** Alerts whose action was an active block. */
  blockedCount: number;
  /** ms epoch of the most recent alert to this target inside the window. */
  lastSeenMs: number;
}

/** One signature scored for the tightest crowd of distinct sources that fired it. */
export interface ConvergenceSignature {
  signature: string;
  /** Total alerts carrying this signature inside the window. */
  count: number;
  /** Distinct source IPs that fired it across the whole window. */
  distinctSources: number;
  /** Peak number of distinct sources inside any `windowSec` sliding window. */
  peakSources: number;
  /** Alerts inside that same peak window. */
  peakAlerts: number;
  /** ms epoch where the peak window starts. */
  peakStartMs: number;
  /** A sample of the member source IPs present at the peak (capped for display). */
  peakMembers: string[];
  /** How many of {@link peakSources} were external (public) addresses. */
  peakExternalSources: number;
  /** Distinct destination IPs the crowd struck with this signature. */
  distinctTargets: number;
  /** Worst severity observed for this signature. */
  severityMax: Severity;
  /** Alerts whose action was an active block. */
  blockedCount: number;
  /** ms epoch of the most recent alert carrying this signature inside the window. */
  lastSeenMs: number;
}

export interface ConvergenceReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp + source) inside the window. */
  totalWindowAlerts: number;
  /** Distinct destination IPs seen in the window. */
  distinctTargets: number;
  /** Sliding-window width (seconds) used for the convergence measurement. */
  windowSec: number;
  /** Minimum distinct sources in one window for a target/signature to be flagged. */
  minSources: number;
  /** How many targets were struck by a converging crowd (≥ {@link minSources}). */
  targetEvents: number;
  /** How many signatures were fired by a converging crowd (≥ {@link minSources}). */
  signatureEvents: number;
  /** The single largest peak-distinct-source count seen on any target. */
  maxPeakSources: number;
  /** Flagged target convergences, most-coordinated first, truncated to the limit. */
  targets: ConvergenceTarget[];
  /** Flagged signature convergences, most-coordinated first, truncated to the limit. */
  signatures: ConvergenceSignature[];
  /** True when the target table was truncated by the limit. */
  truncatedTargets: boolean;
  /** True when the signature table was truncated by the limit. */
  truncatedSignatures: boolean;
  /** Plain-language call-outs about the report as a whole. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface ConvergenceOptions {
  /** Max rows in each table (clamped to [1, 500]). */
  limit?: number;
  /** Min distinct sources in one window to flag a convergence (clamped to [2, 100000]). */
  minSources?: number;
  /** Sliding-window width in seconds (clamped to [10, 86400]). */
  windowSec?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 20;
const DEFAULT_MIN_SOURCES = 5;
const DEFAULT_WINDOW_SEC = 120;
/** Members shown inline before collapsing the rest into "(+N more)". */
const MEMBER_SAMPLE = 4;
/** A convergence ratio at/above this reads as a *tightly* synchronized strike. */
const TIGHT_RATIO = 0.8;

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? (b as Severity) : a;
}

/** Medium or above is worth promoting / hunting. */
function isSevere(s: string | undefined): boolean {
  return sevRank(s) >= 2;
}

function isBlocked(action: string | undefined): boolean {
  return (action ?? "").toLowerCase() === "blocked";
}

/** RFC1918 / loopback / link-local / ULA — mirrors burstiness.ts / spread.ts / surge.ts. */
function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
}

// ----- formatting helpers (mirror burstiness.ts / surge.ts) -----

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** A compact relative-age label like "3h" / "2d" for the recency column. */
function fmtAge(ms: number, nowMs: number): string {
  const sec = Math.max(0, Math.round((nowMs - ms) / 1000));
  if (sec < 90) return `${sec}s`;
  const min = Math.round(sec / 60);
  if (min < 90) return `${min}m`;
  const hr = Math.round(min / 60);
  if (hr < 48) return `${hr}h`;
  return `${Math.round(hr / 24)}d`;
}

/** A human duration like "8s" / "45m" / "2h 10m" / "3d" for a span. */
function fmtDuration(sec: number): string {
  const s = Math.max(0, Math.round(sec));
  if (s < 90) return `${s}s`;
  const min = Math.round(s / 60);
  if (min < 90) return `${min}m`;
  const hr = Math.floor(min / 60);
  if (hr < 48) {
    const rem = min % 60;
    return rem ? `${hr}h ${rem}m` : `${hr}h`;
  }
  return `${Math.round(hr / 24)}d`;
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

function bump(map: Map<string, number>, key: string | undefined): void {
  if (!key) return;
  map.set(key, (map.get(key) ?? 0) + 1);
}

/** Most frequent key in a tally, ties broken by lexical order for stability. */
function topKey(map: Map<string, number>): { key: string; count: number } {
  let best = "";
  let bestN = -1;
  for (const [k, n] of map) {
    if (n > bestN || (n === bestN && k < best)) {
      best = k;
      bestN = n;
    }
  }
  return { key: best, count: Math.max(0, bestN) };
}

/** Render the member-IP sample with an overflow tail. */
function fmtMembers(members: string[], peakSources: number): string {
  if (!members.length) return "—";
  const shown = members.slice(0, MEMBER_SAMPLE).map((m) => `\`${m}\``).join(" ");
  const extra = peakSources - Math.min(members.length, MEMBER_SAMPLE);
  return extra > 0 ? `${shown} (+${extra} more)` : shown;
}

/** One alert reduced to the two fields the convergence sweep needs. */
interface Event {
  t: number;
  src: string;
  external: boolean;
}

/** Per-target accumulator while folding the window. */
interface TargetAccum {
  events: Event[];
  sources: Set<string>;
  signatures: Map<string, number>;
  severityMax: Severity;
  severeCount: number;
  blockedCount: number;
  lastSeenMs: number;
  external: boolean;
}

/** Per-signature accumulator while folding the window. */
interface SigAccum {
  events: Event[];
  sources: Set<string>;
  targets: Set<string>;
  severityMax: Severity;
  blockedCount: number;
  lastSeenMs: number;
}

/**
 * Peak distinct-source count inside any sliding window of `windowMs`, found with
 * a two-pointer sweep that maintains a per-source multiset over the current
 * window. Returns the peak count, the window start time, the alert count and
 * actual span at the peak, and the member sources present at that moment.
 *
 * `events` MUST be sorted ascending by `t`.
 */
function peakConvergence(events: Event[], windowMs: number): {
  peakSources: number;
  peakAlerts: number;
  peakStartMs: number;
  peakSpanSeconds: number;
  members: string[];
  externalCount: number;
} {
  const counts = new Map<string, number>();
  let lo = 0;
  let best = 0;
  let bestStart = events[0]?.t ?? 0;
  let bestAlerts = 0;
  let bestSpanSec = 0;
  let bestMembers: string[] = [];
  for (let hi = 0; hi < events.length; hi++) {
    counts.set(events[hi]!.src, (counts.get(events[hi]!.src) ?? 0) + 1);
    while (events[hi]!.t - events[lo]!.t > windowMs) {
      const ls = events[lo]!.src;
      const c = (counts.get(ls) ?? 0) - 1;
      if (c <= 0) counts.delete(ls);
      else counts.set(ls, c);
      lo++;
    }
    if (counts.size > best) {
      best = counts.size;
      bestStart = events[lo]!.t;
      bestAlerts = hi - lo + 1;
      bestSpanSec = Math.round((events[hi]!.t - events[lo]!.t) / 1000);
      bestMembers = [...counts.keys()];
    }
  }
  let externalCount = 0;
  const memberSet = new Set(bestMembers);
  for (const e of events) {
    if (memberSet.has(e.src) && e.external) {
      memberSet.delete(e.src); // count each member once
      externalCount++;
    }
  }
  return {
    peakSources: best,
    peakAlerts: bestAlerts,
    peakStartMs: bestStart,
    peakSpanSeconds: bestSpanSec,
    members: bestMembers,
    externalCount,
  };
}

/** Orientation of a crowd from the target side and its members' external share. */
function classifyDirection(targetExternal: boolean, peakExternal: number, peakSources: number): ConvergenceDirection {
  const mostlyExternalSources = peakSources > 0 && peakExternal / peakSources >= 0.5;
  if (!targetExternal) return mostlyExternalSources ? "inbound" : "internal";
  return mostlyExternalSources ? "external" : "outbound";
}

const DIRECTION_LABEL: Record<ConvergenceDirection, string> = {
  inbound: "ext→int",
  internal: "int→int",
  outbound: "int→ext",
  external: "ext→ext",
};

/** Rank most-coordinated first: peak sources, then ratio, then severity, then volume, then recency. */
function rankTargets(items: ConvergenceTarget[]): ConvergenceTarget[] {
  return [...items].sort((x, y) => {
    if (y.peakSources !== x.peakSources) return y.peakSources - x.peakSources;
    if (y.convergenceRatio !== x.convergenceRatio) return y.convergenceRatio - x.convergenceRatio;
    if (sevRank(y.severityMax) !== sevRank(x.severityMax)) return sevRank(y.severityMax) - sevRank(x.severityMax);
    if (y.count !== x.count) return y.count - x.count;
    return y.lastSeenMs - x.lastSeenMs;
  });
}

function rankSignatures(items: ConvergenceSignature[]): ConvergenceSignature[] {
  return [...items].sort((x, y) => {
    if (y.peakSources !== x.peakSources) return y.peakSources - x.peakSources;
    if (sevRank(y.severityMax) !== sevRank(x.severityMax)) return sevRank(y.severityMax) - sevRank(x.severityMax);
    if (y.count !== x.count) return y.count - x.count;
    return y.lastSeenMs - x.lastSeenMs;
  });
}

function writeHighlights(m: Omit<ConvergenceReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (!m.totalWindowAlerts) return out;

  if (!m.targetEvents && !m.signatureEvents) {
    out.push(
      `🤝 No coordinated convergence found over the last ${m.hours}h — no target or signature drew **${m.minSources}+** ` +
        `distinct sources inside any ${fmtDuration(m.windowSec)} window. Activity looks like independent background ` +
        `traffic, not a synchronized crowd. Lower \`minSources\` or widen \`window\` to loosen the bar.`,
    );
    return out;
  }

  out.push(
    `🤝 Found **${m.targetEvents} target(s)** and **${m.signatureEvents} signature(s)** struck by a converging crowd ` +
      `of **${m.minSources}+** distinct sources within a single ${fmtDuration(m.windowSec)} window over the last ` +
      `${m.hours}h — the flash-crowd signature of a botnet / DDoS / coordinated spray, not background drizzle.`,
  );

  const top = m.targets[0];
  if (top) {
    out.push(
      `🎯 Tightest target convergence on \`${top.dstIp}\`${top.external ? "" : " (internal)"} — **${top.peakSources} ` +
        `distinct sources in ${fmtDuration(Math.max(1, top.peakSpanSeconds))}** (${DIRECTION_LABEL[top.direction]}, ` +
        `${top.peakExternalSources}/${top.peakSources} external` +
        (top.convergenceRatio >= TIGHT_RATIO
          ? `, and **${Math.round(top.convergenceRatio * 100)}% of all its attackers** landed in that one window — a ` +
            `tightly synchronized strike`
          : ``) +
        `)` +
        (top.topSignature ? `, driven by \`${clip(top.topSignature)}\`` : "") +
        `. ${top.peakSources} unrelated IPs in seconds is no human — it is tasked infrastructure.`,
    );
  }

  const inbound = m.targets.filter((t) => t.direction === "inbound");
  const severeInbound = inbound.filter((t) => isSevere(t.severityMax));
  if (severeInbound.length) {
    out.push(
      `⚠️ ${severeInbound.length} **internal** target(s) under a coordinated *external* crowd carrying a ` +
        `medium-or-worse signature — distributed pressure (spray / volumetric / mass-exploit) aimed inside your ` +
        `perimeter; the peak window is the moment to investigate, not the daily average.`,
    );
  }

  const sig = m.signatures[0];
  if (sig) {
    out.push(
      `🧬 Top signature convergence — \`${clip(sig.signature)}\` fired by **${sig.peakSources} distinct sources** ` +
        `inside ${fmtDuration(m.windowSec)} across ${sig.distinctTargets} target(s). Many independent IPs exploiting ` +
        `the *same* rule at once is mass-exploitation of a single CVE / a coordinated campaign — cross-check it ` +
        `against the CVE (\`--cve\`) and kill-chain (\`--killchain\`) reports.`,
    );
  }

  out.push(
    `🔎 The members of a convergence are bound only by *timing* — they may span unrelated netblocks and even fire ` +
      `different signatures, so they slip past the toolkit-cluster (\`--clusters\`, shared-signature) and netblock ` +
      `(\`--netblocks\`, CIDR-rotation) views. Cross-check those reports to attribute the *who* behind the *when*.`,
  );
  return out;
}

function targetTable(rows: ConvergenceTarget[], nowMs: number, windowSec: number): string {
  return mdTable(
    ["Target", `Peak src/${fmtDuration(windowSec)}`, "Span", "Ratio", "Dir", "Ext", "Total src", "Alerts", "Peak sig", "Peak sev", "Blocked", "Last", "Members"],
    rows.map((t) => [
      cell(t.dstIp) + (t.external ? "" : " 🏠"),
      String(t.peakSources),
      fmtDuration(Math.max(1, t.peakSpanSeconds)),
      `${Math.round(t.convergenceRatio * 100)}%`,
      DIRECTION_LABEL[t.direction],
      `${t.peakExternalSources}/${t.peakSources}`,
      String(t.distinctSources),
      String(t.count),
      t.topSignature ? cell(clip(t.topSignature, 28)) : "—",
      cell(t.severityMax),
      t.blockedCount ? `${t.blockedCount}/${t.count}` : "0",
      fmtAge(t.lastSeenMs, nowMs),
      fmtMembers(t.peakMembers, t.peakSources),
    ]),
  );
}

function signatureTable(rows: ConvergenceSignature[], nowMs: number, windowSec: number): string {
  return mdTable(
    ["Signature", `Peak src/${fmtDuration(windowSec)}`, "Ext", "Total src", "Tgts", "Alerts", "Peak sev", "Blocked", "Last", "Members"],
    rows.map((s) => [
      cell(clip(s.signature, 42)),
      String(s.peakSources),
      `${s.peakExternalSources}/${s.peakSources}`,
      String(s.distinctSources),
      String(s.distinctTargets),
      String(s.count),
      cell(s.severityMax),
      s.blockedCount ? `${s.blockedCount}/${s.count}` : "0",
      fmtAge(s.lastSeenMs, nowMs),
      fmtMembers(s.peakMembers, s.peakSources),
    ]),
  );
}

function renderMarkdown(m: ConvergenceReport): string {
  const lines: string[] = [];
  lines.push(`# 🤝 SecTool Convergence / Coordinated-Strike Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Scope:** ${m.distinctTargets} distinct target(s) · convergence window **${fmtDuration(m.windowSec)}** · ` +
      `flag threshold **${m.minSources}+ distinct sources** · **${m.targetEvents} target** + **${m.signatureEvents} ` +
      `signature** convergence(s) · **Window alerts:** ${m.totalWindowAlerts}`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.totalWindowAlerts) {
    lines.push(`No alerts with a usable timestamp and source in the last ${m.hours} hour(s) — nothing to analyse.`);
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Coordinated strikes on a target — crowd of distinct sources, one window`);
  lines.push("");
  if (!m.targets.length) {
    lines.push(`_No target drew ${m.minSources}+ distinct sources inside a single ${fmtDuration(m.windowSec)} window._`);
    lines.push("");
  } else {
    lines.push(targetTable(m.targets, m.windowEndMs, m.windowSec));
    lines.push("");
    if (m.truncatedTargets) {
      lines.push(`_Truncated to the row limit — raise \`limit\` to see more._`);
      lines.push("");
    }
  }

  if (m.signatures.length) {
    lines.push(`## Coordinated strikes by signature — one rule, many sources at once`);
    lines.push("");
    lines.push(signatureTable(m.signatures, m.windowEndMs, m.windowSec));
    lines.push("");
    if (m.truncatedSignatures) {
      lines.push(`_Truncated to the row limit — raise \`limit\` to see more._`);
      lines.push("");
    }
    lines.push(
      `_Many distinct sources firing the **same** signature inside one window is mass-exploitation of a single CVE / a ` +
        `coordinated campaign — cross-check the CVE (\`--cve\`) and kill-chain (\`--killchain\`) reports._`,
    );
    lines.push("");
  }

  lines.push(
    `**Legend:** _Peak src/${fmtDuration(m.windowSec)}_ = most distinct source IPs inside any ${fmtDuration(m.windowSec)} ` +
      `sliding window (the moment of tightest convergence). _Span_ = the actual seconds that peak crowd spanned. ` +
      `_Ratio_ = peak-window distinct sources ÷ the target's total distinct sources (**100%** ⇒ every attacker landed ` +
      `in one window, a tightly synchronized strike; low ⇒ many attackers spread out, only a few coinciding). ` +
      `_Dir_ = orientation (ext→int inbound · int→int internal · int→ext outbound · ext→ext passthrough). ` +
      `_Ext_ = external members ÷ peak sources. 🏠 = internal (RFC1918) target. _Members_ = a sample of the peak crowd.`,
  );
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from stored **IPS-alert** timestamps, not full flow data — the crowd is a crowd of ` +
      `*detections* at syslog second-resolution, so a true volumetric flood is under-counted (read counts as a floor) ` +
      `and sub-second ordering is lost. Source addresses can be spoofed in volumetric attacks; the report flags the ` +
      `crowd to investigate, it does not attribute. On a very busy target unrelated sources can coincide by chance — ` +
      `the \`minSources\` floor and the convergence ratio separate a synchronized strike from background coincidence. ` +
      `No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the temporal-convergence / coordinated-strike report from the stored
 * alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link ConvergenceOptions}: `limit`, `minSources`, `windowSec`, and a `nowMs` pin.
 */
export function buildConvergence(hours: number, opts: ConvergenceOptions = {}): ConvergenceReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(500, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minSources = Math.max(2, Math.min(100000, Math.floor(opts.minSources ?? DEFAULT_MIN_SOURCES)));
  const windowSec = Math.max(10, Math.min(86400, Math.floor(opts.windowSec ?? DEFAULT_WINDOW_SEC)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * 3_600_000;
  const windowMs = windowSec * 1000;

  const all = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time));

  const byTarget = new Map<string, TargetAccum>();
  const bySignature = new Map<string, SigAccum>();
  let totalWindowAlerts = 0;

  for (const a of all) {
    if (a.time < windowStartMs || a.time > windowEndMs) continue;
    const src = a.srcIp;
    if (!src || isIP(src) === 0) continue;
    const srcExternal = !isPrivate(src);

    const dst = a.dstIp;
    if (dst && isIP(dst) > 0) {
      totalWindowAlerts++;
      let t = byTarget.get(dst);
      if (!t) {
        t = {
          events: [],
          sources: new Set(),
          signatures: new Map(),
          severityMax: "info",
          severeCount: 0,
          blockedCount: 0,
          lastSeenMs: 0,
          external: !isPrivate(dst),
        };
        byTarget.set(dst, t);
      }
      t.events.push({ t: a.time, src, external: srcExternal });
      t.sources.add(src);
      bump(t.signatures, a.signature);
      t.severityMax = maxSeverity(t.severityMax, a.severity);
      if (isSevere(a.severity)) t.severeCount++;
      if (isBlocked(a.action)) t.blockedCount++;
      if (a.time > t.lastSeenMs) t.lastSeenMs = a.time;
    }

    if (a.signature) {
      let s = bySignature.get(a.signature);
      if (!s) {
        s = {
          events: [],
          sources: new Set(),
          targets: new Set(),
          severityMax: "info",
          blockedCount: 0,
          lastSeenMs: 0,
        };
        bySignature.set(a.signature, s);
      }
      s.events.push({ t: a.time, src, external: srcExternal });
      s.sources.add(src);
      if (dst && isIP(dst) > 0) s.targets.add(dst);
      s.severityMax = maxSeverity(s.severityMax, a.severity);
      if (isBlocked(a.action)) s.blockedCount++;
      if (a.time > s.lastSeenMs) s.lastSeenMs = a.time;
    }
  }

  // ----- score targets -----
  const scoredTargets: ConvergenceTarget[] = [];
  for (const [dstIp, acc] of byTarget) {
    // A convergence needs at least minSources distinct sources to even be possible.
    if (acc.sources.size < minSources) continue;
    acc.events.sort((x, y) => x.t - y.t);
    const peak = peakConvergence(acc.events, windowMs);
    if (peak.peakSources < minSources) continue;
    const sig = topKey(acc.signatures);
    scoredTargets.push({
      dstIp,
      external: acc.external,
      count: acc.events.length,
      distinctSources: acc.sources.size,
      peakSources: peak.peakSources,
      peakAlerts: peak.peakAlerts,
      peakStartMs: peak.peakStartMs,
      peakSpanSeconds: peak.peakSpanSeconds,
      peakMembers: peak.members,
      peakExternalSources: peak.externalCount,
      convergenceRatio: acc.sources.size > 0 ? Math.round((peak.peakSources / acc.sources.size) * 1000) / 1000 : 0,
      direction: classifyDirection(acc.external, peak.externalCount, peak.peakSources),
      distinctSignatures: acc.signatures.size,
      topSignature: sig.key,
      severityMax: acc.severityMax,
      severeCount: acc.severeCount,
      blockedCount: acc.blockedCount,
      lastSeenMs: acc.lastSeenMs,
    });
  }

  // ----- score signatures -----
  const scoredSignatures: ConvergenceSignature[] = [];
  for (const [signature, acc] of bySignature) {
    if (acc.sources.size < minSources) continue;
    acc.events.sort((x, y) => x.t - y.t);
    const peak = peakConvergence(acc.events, windowMs);
    if (peak.peakSources < minSources) continue;
    scoredSignatures.push({
      signature,
      count: acc.events.length,
      distinctSources: acc.sources.size,
      peakSources: peak.peakSources,
      peakAlerts: peak.peakAlerts,
      peakStartMs: peak.peakStartMs,
      peakMembers: peak.members,
      peakExternalSources: peak.externalCount,
      distinctTargets: acc.targets.size,
      severityMax: acc.severityMax,
      blockedCount: acc.blockedCount,
      lastSeenMs: acc.lastSeenMs,
    });
  }

  const targetsAll = rankTargets(scoredTargets);
  const signaturesAll = rankSignatures(scoredSignatures);
  const targets = targetsAll.slice(0, limit);
  const signatures = signaturesAll.slice(0, limit);
  const maxPeakSources = Math.max(0, ...scoredTargets.map((t) => t.peakSources), ...scoredSignatures.map((s) => s.peakSources));

  const base: Omit<ConvergenceReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts,
    distinctTargets: byTarget.size,
    windowSec,
    minSources,
    targetEvents: scoredTargets.length,
    signatureEvents: scoredSignatures.length,
    maxPeakSources,
    targets,
    signatures,
    truncatedTargets: targetsAll.length > targets.length,
    truncatedSignatures: signaturesAll.length > signatures.length,
  };
  const highlights = writeHighlights(base);
  const model: ConvergenceReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded convergence report. */
export function convergenceFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-convergence-${stamp}.md`;
}
