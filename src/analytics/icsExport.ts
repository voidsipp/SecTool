/**
 * iCalendar (.ics) security-calendar export — "**put my security history on a
 * calendar I can actually subscribe to.**"
 *
 * SecTool already exports to almost every downstream a security team owns: a
 * firewall (`--fwrules`, `--iocs`), a SIEM (`--cef`, `--ecs`, `--sigma`), an IDS
 * sensor (`--snort`), a TAXII/intel server (`--stix`), a feed reader (`--feed`),
 * a spreadsheet (`--csv`) and a Prometheus scrape (`--metrics`). One universal
 * surface is conspicuously missing: the **calendar**. Every analyst, manager and
 * on-call lead already lives in Outlook / Google Calendar / Apple Calendar /
 * Thunderbird all day, yet nothing in SecTool puts the security picture *there*.
 *
 * This export fills that gap. It renders the recent alert history as a valid
 * **RFC 5545 iCalendar** document — one **all-day event per UTC day** carrying
 * that day's headline numbers (volume, serious count, unique sources, the busiest
 * source / top signature / dominant category, and how many brand-new attackers
 * arrived), plus a day-over-day delta and notable-day flags (busiest day, biggest
 * spike, critical-severity day, new-attacker influx). Drop the `.ics` into any
 * calendar app — or, far better, point a *subscription* at `webcal://…/api/ics.ics`
 * so the security calendar refreshes itself hourly — and the threat history shows
 * up alongside the team's meetings, with a reminder (`VALARM`) automatically
 * raised on the days that carried high/critical activity.
 *
 * Why this is genuinely distinct from the neighbours:
 *
 *   - **`--feed`** (RSS/Atom/JSON Feed) is a *per-alert item stream* for a feed
 *     reader — newest-first, item-shaped, no time anchoring. A calendar is the
 *     opposite shape: *time-anchored day blocks* you scroll by date, with alarms
 *     and free/busy semantics a feed cannot express. Different consumer, different
 *     mental model.
 *   - **`--timeline`** answers the same chronological "walk the calendar" question
 *     but as a *Markdown ledger you read*; this turns that ledger into an artefact
 *     your calendar app *renders and reminds you about*, sharable as a single file
 *     or a live subscription URL.
 *   - **`--briefing` / `--digest`** summarise *one* window for a human to read
 *     once; the calendar is a standing, self-updating record across many days.
 *
 * Honest caveats baked into the output:
 *
 *   - **Days are UTC.** Each event is a UTC calendar day (`VALUE=DATE`), so
 *     activity near local midnight can fall either side of a boundary. The
 *     calendar declares `X-WR-TIMEZONE:UTC` so apps render it consistently.
 *   - **"New" attackers are history-bounded.** "New" means a source not seen in
 *     the retained store *before* the window opened (same baseline `--novelty` and
 *     `--timeline` use); the store is capped/rotated, so a long-quiet returning
 *     source can read as new.
 *   - **Quiet days are skipped by default** to keep the calendar uncluttered
 *     (calendars full of "0 alerts" blocks are noise); pass `includeQuiet` to
 *     emit every day, including silent ones.
 *
 * Pure in-memory math over `alertStore` — no SSH, no Claude, no network. Output
 * is the finished `.ics` text, a structured model, and a Markdown review twin,
 * mirroring `snort.ts`, `pcap.ts` and the other offline export reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Serialisation flavour requested from the iCalendar export. */
export type IcsFormat = "ics" | "json" | "md";

/** One emitted UTC day in the security calendar (one `VEVENT`). */
export interface IcsDay {
  /** `YYYY-MM-DD` UTC date stamp (the event's all-day date). */
  date: string;
  /** Day start (ms epoch, UTC midnight). */
  startMs: number;
  /** Day end (ms epoch, exclusive — next UTC midnight). */
  endMs: number;
  /** Total alerts (with a usable timestamp) that day. */
  total: number;
  /** High + critical alerts that day. */
  serious: number;
  /** Distinct source IPs seen that day. */
  uniqueSources: number;
  /** Distinct destination IPs seen that day. */
  uniqueTargets: number;
  /** Distinct signatures seen that day. */
  uniqueSignatures: number;
  /** Sources appearing for the first time vs the pre-window baseline. */
  newSources: number;
  /** Worst severity observed that day. */
  severityMax: Severity;
  /** Busiest source IP that day (by alert count), or undefined. */
  topSource?: string;
  /** Busiest signature that day (by alert count), or undefined. */
  topSignature?: string;
  /** Dominant Suricata category that day, or undefined. */
  topCategory?: string;
  /** Percent change in {@link total} vs the previous day; null for the first. */
  deltaPct: number | null;
  /** Notable-day flags (busiest / spike / critical / influx). */
  notable: string[];
  /** Deterministic `VEVENT` UID for this day. */
  uid: string;
  /** RFC 5545 PRIORITY (1 = highest … 9 = lowest), derived from severity. */
  priority: number;
  /** True when this day raises a `VALARM` reminder (serious activity). */
  alarm: boolean;
}

export interface IcsReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Timestamp stamped onto every event (`DTSTAMP`); pinned for tests. */
  nowMs: number;
  /** Distinct source IPs seen strictly before the window (the new-source baseline). */
  baselineSources: number;
  /** Start (ms epoch) of the retained history used to seed the baseline. */
  baselineStartMs: number | null;
  /** Total alerts (with a usable timestamp) inside the window. */
  totalAlerts: number;
  /** Calendar days spanned by the window (including quiet ones). */
  dayCount: number;
  /** Days actually emitted as events (active days, or all if includeQuiet). */
  emittedCount: number;
  /** True when quiet (zero-alert) days are emitted too. */
  includeQuiet: boolean;
  /** True when serious days raise a reminder alarm. */
  alarms: boolean;
  /** Severity floor at/above which a day raises an alarm. */
  alarmFloor: Severity;
  /** True when more days qualified than were emitted (most recent kept). */
  truncated: boolean;
  /** The calendar display name (`X-WR-CALNAME`). */
  calendarName: string;
  /** Emitted days, chronological (oldest first). */
  days: IcsDay[];
  /** The finished `.ics` document (CRLF line endings, RFC 5545). */
  text: string;
  /** A human Markdown review twin (eyeball / preview before subscribing). */
  markdown: string;
}

export interface IcsOptions {
  /** Max events emitted (most recent kept); clamped to [1, 366]. Default 120. */
  limit?: number;
  /** Emit quiet (zero-alert) days too. Default false (skip them). */
  includeQuiet?: boolean;
  /** Raise a `VALARM` reminder on serious days. Default true. */
  alarms?: boolean;
  /** Severity floor for the alarm (default `high`). */
  alarmFloor?: Severity;
  /** Override the calendar display name. */
  calendarName?: string;
  /** Pins the window end / `DTSTAMP` for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 120;
const DEFAULT_CALENDAR_NAME = "SecTool Security Alerts";
const MS_PER_HOUR = 3_600_000;
const MS_PER_DAY = 86_400_000;
/** A day-over-day rise beyond this magnitude (%) is flagged as a spike. */
const SPIKE_THRESHOLD_PCT = 50;
/** iCalendar product identifier (RFC 5545 PRODID). */
const PRODID = "-//SecTool//Security Alert Calendar//EN";

// ----- helpers (mirror timeline.ts / snort.ts) -------------------------------

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

/** High or critical — the "serious" band every report counts. */
function isSerious(s: string | undefined): boolean {
  return sevRank(s) >= sevRank("high");
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** `YYYY-MM-DD` UTC date stamp. */
function fmtDate(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

/** RFC 5545 `VALUE=DATE` stamp — `YYYYMMDD` (UTC). */
function icsDate(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10).replace(/-/g, "");
}

/** RFC 5545 UTC `DATE-TIME` — `YYYYMMDDTHHMMSSZ`. */
function icsDateTime(ms: number): string {
  return new Date(ms).toISOString().replace(/[-:]/g, "").replace(/\.\d+/, "");
}

/**
 * Escape free text for an iCalendar `TEXT` value (RFC 5545 §3.3.11): a literal
 * backslash, semicolon, comma and newline must be escaped, else they would be
 * read as value/parameter separators and silently corrupt the calendar.
 */
function icsText(s: string): string {
  return String(s ?? "")
    .replace(/\\/g, "\\\\")
    .replace(/;/g, "\\;")
    .replace(/,/g, "\\,")
    .replace(/\r?\n/g, "\\n");
}

/**
 * Fold a single content line to the RFC 5545 75-octet limit: a long line is
 * continued with CRLF followed by a single leading space. Folding is computed in
 * UTF-8 bytes (not code units) so multi-byte characters never split mid-octet.
 */
function foldLine(line: string): string {
  const bytes = Buffer.from(line, "utf8");
  if (bytes.length <= 75) return line;
  const out: string[] = [];
  let start = 0;
  let limit = 75; // first line: 75 octets; continuations: 74 (the leading space counts).
  while (start < bytes.length) {
    let end = Math.min(start + limit, bytes.length);
    // Do not split a multi-byte UTF-8 sequence: back off to a code-point boundary.
    while (end < bytes.length && (bytes[end]! & 0xc0) === 0x80) end--;
    const chunk = bytes.subarray(start, end).toString("utf8");
    out.push(out.length === 0 ? chunk : ` ${chunk}`);
    start = end;
    limit = 74;
  }
  return out.join("\r\n");
}

function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function clip(s: string, max = 48): string {
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

/** The most frequent value in a count map, with a deterministic key tie-break. */
function topKey(counts: Map<string, number>): string | undefined {
  let best: string | undefined;
  let bestN = -1;
  for (const [k, n] of counts) {
    if (n > bestN || (n === bestN && best !== undefined && k < best)) {
      best = k;
      bestN = n;
    }
  }
  return best;
}

function bumpCount(m: Map<string, number>, k: string): void {
  m.set(k, (m.get(k) ?? 0) + 1);
}

/** A coarse emoji for a severity band, used to make the SUMMARY scannable. */
function severityEmoji(s: Severity): string {
  switch (s) {
    case "critical":
      return "🔴";
    case "high":
      return "🟠";
    case "medium":
      return "🟡";
    case "low":
      return "🔵";
    default:
      return "⚪";
  }
}

/** RFC 5545 PRIORITY (1 highest … 9 lowest) from the day's worst severity. */
function severityPriority(s: Severity): number {
  switch (s) {
    case "critical":
      return 1;
    case "high":
      return 3;
    case "medium":
      return 5;
    case "low":
      return 7;
    default:
      return 9;
  }
}

// ----- aggregation -----------------------------------------------------------

interface DayAcc {
  startMs: number;
  endMs: number;
  total: number;
  serious: number;
  sources: Set<string>;
  targets: Set<string>;
  signatures: Set<string>;
  newSources: Set<string>;
  severityMax: Severity;
  sourceCounts: Map<string, number>;
  signatureCounts: Map<string, number>;
  categoryCounts: Map<string, number>;
}

function newDayAcc(startMs: number, endMs: number): DayAcc {
  return {
    startMs,
    endMs,
    total: 0,
    serious: 0,
    sources: new Set(),
    targets: new Set(),
    signatures: new Set(),
    newSources: new Set(),
    severityMax: "info",
    sourceCounts: new Map(),
    signatureCounts: new Map(),
    categoryCounts: new Map(),
  };
}

// ----- event rendering -------------------------------------------------------

/** Compose the one-line `SUMMARY` for a day's event. */
function daySummary(d: IcsDay): string {
  if (d.total === 0) return `${severityEmoji(d.severityMax)} 🛡 Quiet — 0 alerts`;
  const plural = d.total === 1 ? "alert" : "alerts";
  const parts = [`${d.total} ${plural}`];
  if (d.serious > 0) parts.push(`${d.serious} serious`);
  parts.push(`${d.uniqueSources} src`);
  if (d.newSources > 0) parts.push(`${d.newSources} new`);
  const flag = d.notable.includes("critical")
    ? "🔴"
    : d.notable.includes("busiest")
      ? "📈"
      : d.notable.includes("spike")
        ? "⚡"
        : "🛡";
  return `${severityEmoji(d.severityMax)} ${flag} ${parts.join(" · ")}`;
}

/** Compose the multi-line `DESCRIPTION` body (pre-escape; `\n`-joined later). */
function dayDescriptionLines(d: IcsDay): string[] {
  const lines: string[] = [];
  if (d.total === 0) {
    lines.push("No alerts with a usable timestamp landed on this UTC day.");
    return lines;
  }
  lines.push(`Total alerts: ${d.total}`);
  lines.push(`Serious (high+critical): ${d.serious}`);
  lines.push(`Worst severity: ${d.severityMax}`);
  lines.push(`Unique sources: ${d.uniqueSources}  |  targets: ${d.uniqueTargets}  |  signatures: ${d.uniqueSignatures}`);
  if (d.newSources > 0) lines.push(`New attackers (first-seen): ${d.newSources}`);
  if (d.deltaPct !== null) {
    const arrow = d.deltaPct > 0 ? "up" : d.deltaPct < 0 ? "down" : "flat";
    lines.push(`Day-over-day: ${arrow} ${Math.abs(d.deltaPct)}% vs the previous day`);
  }
  if (d.topSource) lines.push(`Busiest source: ${d.topSource}`);
  if (d.topSignature) lines.push(`Top signature: ${d.topSignature}`);
  if (d.topCategory) lines.push(`Dominant category: ${d.topCategory}`);
  if (d.notable.length) {
    const labels = d.notable.map((n) =>
      n === "busiest"
        ? "busiest day in window"
        : n === "spike"
          ? "day-over-day spike"
          : n === "critical"
            ? "critical-severity activity"
            : n === "influx"
              ? "largest new-attacker influx"
              : n,
    );
    lines.push(`Notable: ${labels.join("; ")}`);
  }
  lines.push("");
  lines.push("Generated offline by SecTool — see --timeline for the full ledger.");
  return lines;
}

/** Render one `VEVENT` block (array of raw, unfolded content lines). */
function renderEvent(d: IcsDay, report: { nowMs: number; alarms: boolean }): string[] {
  const lines: string[] = [];
  lines.push("BEGIN:VEVENT");
  lines.push(`UID:${d.uid}`);
  lines.push(`DTSTAMP:${icsDateTime(report.nowMs)}`);
  // All-day event: DTSTART/DTEND are dates, DTEND is the *next* day (exclusive).
  lines.push(`DTSTART;VALUE=DATE:${icsDate(d.startMs)}`);
  lines.push(`DTEND;VALUE=DATE:${icsDate(d.endMs)}`);
  lines.push(`SUMMARY:${icsText(daySummary(d))}`);
  lines.push(`DESCRIPTION:${icsText(dayDescriptionLines(d).join("\n"))}`);
  lines.push(`CATEGORIES:${icsText(`SecTool,${d.severityMax}`)}`);
  lines.push(`PRIORITY:${d.priority}`);
  // The calendar should not mark the analyst "busy" — these are informational.
  lines.push("TRANSP:TRANSPARENT");
  if (report.alarms && d.alarm) {
    lines.push("BEGIN:VALARM");
    lines.push("ACTION:DISPLAY");
    lines.push(`DESCRIPTION:${icsText(`SecTool: ${d.serious} serious alert(s) on ${d.date}`)}`);
    // Fire at the start of the day (UTC midnight) — relative to DTSTART.
    lines.push("TRIGGER;RELATED=START:PT0S");
    lines.push("END:VALARM");
  }
  lines.push("END:VEVENT");
  return lines;
}

/** Assemble the full `VCALENDAR`, with CRLF endings and 75-octet line folding. */
function renderCalendar(report: IcsReport): string {
  const lines: string[] = [];
  lines.push("BEGIN:VCALENDAR");
  lines.push("VERSION:2.0");
  lines.push(`PRODID:${PRODID}`);
  lines.push("CALSCALE:GREGORIAN");
  lines.push("METHOD:PUBLISH");
  lines.push(`X-WR-CALNAME:${icsText(report.calendarName)}`);
  lines.push(
    `X-WR-CALDESC:${icsText(
      `SecTool security-alert summary — ${report.totalAlerts} alert(s) across ${report.emittedCount} day(s), ` +
        `window ending ${fmtTime(report.windowEndMs)} (UTC).`,
    )}`,
  );
  lines.push("X-WR-TIMEZONE:UTC");
  // Hint subscribed clients to re-fetch hourly (Apple/Outlook honour these).
  lines.push("X-PUBLISHED-TTL:PT1H");
  lines.push("REFRESH-INTERVAL;VALUE=DURATION:PT1H");
  for (const d of report.days) lines.push(...renderEvent(d, report));
  lines.push("END:VCALENDAR");
  return lines.map(foldLine).join("\r\n") + "\r\n";
}

// ----- markdown twin ---------------------------------------------------------

function renderMarkdown(m: IcsReport): string {
  const lines: string[] = [];
  lines.push(`# 🗓️ SecTool Security Calendar (iCalendar export)`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.nowMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** one all-day **VEVENT per UTC day** over the window` +
      `${m.includeQuiet ? " (quiet days included)" : " (quiet days skipped)"}. ` +
      `Offline, deterministic, RFC 5545 · **Total alerts:** ${m.totalAlerts} · ` +
      `**Events:** ${m.emittedCount}${m.truncated ? ` (showing most recent ${m.days.length})` : ""}.`,
  );
  lines.push("");

  lines.push(`## How to use`);
  lines.push("");
  lines.push(
    `- **Subscribe (recommended):** point your calendar app at ` +
      `\`webcal://<host>/api/ics.ics\` (Apple Calendar / Outlook / Google "From URL"). ` +
      `The calendar declares a 1-hour refresh, so it keeps itself current.`,
  );
  lines.push(
    `- **One-off import:** download \`/api/ics.ics\` (or \`npm run ics > sectool.ics\`) and open it in any ` +
      `calendar app to import the events once.`,
  );
  lines.push(
    `- Days with high/critical activity raise a reminder (\`VALARM\`)${m.alarms ? "" : " — currently disabled"}; ` +
      `each event is marked free/\`TRANSPARENT\` so it never blocks your availability.`,
  );
  lines.push("");

  lines.push(`## Days on the calendar`);
  lines.push("");
  if (!m.days.length) {
    lines.push(
      `No ${m.includeQuiet ? "" : "active "}days to place on the calendar in the last ${m.hours}h. ` +
        `Widen the window (\`--ics <more hours>\`)${m.includeQuiet ? "" : " or pass `--include-quiet`"}, ` +
        `or confirm forwarding with \`--coverage\`.`,
    );
  } else {
    if (m.truncated) {
      lines.push(`_${m.emittedCount} day(s) qualified; showing the most recent **${m.days.length}**. Raise \`--limit\` for more._`);
      lines.push("");
    }
    lines.push(
      mdTable(
        ["Day (UTC)", "Alerts", "Serious", "Worst", "Srcs", "New", "Top source", "Top signature", "Flags"],
        m.days.map((d) => [
          cell(d.date) + (d.alarm ? " 🔔" : ""),
          String(d.total),
          d.serious > 0 ? `**${d.serious}**` : "0",
          cell(d.severityMax),
          String(d.uniqueSources),
          d.newSources > 0 ? `🆕 ${d.newSources}` : "0",
          cell(d.topSource ? `\`${d.topSource}\`` : "—"),
          cell(d.topSignature ? clip(d.topSignature) : "—"),
          cell(
            d.notable
              .map((n) => (n === "busiest" ? "📈" : n === "spike" ? "⚡" : n === "critical" ? "🔴" : n === "influx" ? "🆕" : n))
              .join(" ") || "—",
          ),
        ]),
      ),
    );
  }
  lines.push("");
  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Days are **UTC** (\`X-WR-TIMEZONE:UTC\`) — activity near local midnight can fall ` +
      `either side of a boundary. "New" attackers are bounded by the retained store (${m.baselineSources} source(s) of ` +
      `pre-window baseline back to ${m.baselineStartMs !== null ? fmtTime(m.baselineStartMs) : "the start of history"}), ` +
      `so a long-quiet returning source can read as new (see \`--novelty\`). This is the calendar-app companion to ` +
      `\`--timeline\` (Markdown ledger) and \`--feed\` (RSS/Atom item stream). No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

// ----- build -----------------------------------------------------------------

/**
 * Build the iCalendar security-calendar export from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [2, 366 days]).
 * @param opts  {@link IcsOptions}: `limit`, `includeQuiet`, `alarms`,
 *              `alarmFloor`, `calendarName`, and a `nowMs` pin for tests.
 */
export function buildIcs(hours: number, opts: IcsOptions = {}): IcsReport {
  const safeHours = Math.max(2, Math.min(24 * 366, Math.floor(hours)));
  const limit = Math.max(1, Math.min(366, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const includeQuiet = opts.includeQuiet ?? false;
  const alarms = opts.alarms ?? true;
  const alarmFloor = (SEVERITY_ORDER as readonly string[]).includes(opts.alarmFloor ?? "")
    ? (opts.alarmFloor as Severity)
    : "high";
  const calendarName = (opts.calendarName ?? "").trim() || DEFAULT_CALENDAR_NAME;
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const all = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time));

  // New-source baseline: every source seen strictly before the window opened
  // (mirrors timeline.ts / novelty.ts so "new" means first-seen in retained
  // history, not merely first-seen in-window).
  const baselineSources = new Set<string>();
  let baselineStartMs: number | null = null;
  for (const a of all) {
    if (a.time >= windowStartMs) continue;
    if (baselineStartMs === null || a.time < baselineStartMs) baselineStartMs = a.time;
    const src = validIp(a.srcIp);
    if (src) baselineSources.add(src);
  }

  const windowed = all
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs)
    .sort((a, b) => a.time - b.time);

  // Pre-generate every UTC calendar day in the window (including empty ones),
  // aligned to UTC midnight; partial edge days still align to their day grid.
  const firstStart = Math.floor(windowStartMs / MS_PER_DAY) * MS_PER_DAY;
  const accs: DayAcc[] = [];
  const indexOfStart = new Map<number, number>();
  for (let s = firstStart; s < windowEndMs; s += MS_PER_DAY) {
    indexOfStart.set(s, accs.length);
    accs.push(newDayAcc(s, s + MS_PER_DAY));
  }

  const seenSources = new Set(baselineSources);
  let totalAlerts = 0;

  for (const a of windowed) {
    const gridStart = Math.floor(a.time / MS_PER_DAY) * MS_PER_DAY;
    const idx = indexOfStart.get(gridStart);
    if (idx === undefined) continue;
    const acc = accs[idx]!;
    totalAlerts++;
    acc.total++;
    if (isSerious(a.severity)) acc.serious++;
    acc.severityMax = maxSeverity(acc.severityMax, a.severity);

    const src = validIp(a.srcIp);
    if (src) {
      acc.sources.add(src);
      bumpCount(acc.sourceCounts, src);
      if (!seenSources.has(src)) {
        seenSources.add(src);
        acc.newSources.add(src);
      }
    }
    const dst = validIp(a.dstIp);
    if (dst) acc.targets.add(dst);

    const sig = (a.signature ?? "").trim();
    if (sig) {
      acc.signatures.add(sig);
      bumpCount(acc.signatureCounts, sig);
    }
    const cat = (a.category ?? "").trim();
    if (cat) bumpCount(acc.categoryCounts, cat);
  }

  // Window-level superlatives, so we can flag the notable days.
  let maxTotal = 0;
  let maxNew = 0;
  for (const acc of accs) {
    if (acc.total > maxTotal) maxTotal = acc.total;
    if (acc.newSources.size > maxNew) maxNew = acc.newSources.size;
  }

  // Materialise every day, computing day-over-day deltas + notable flags.
  const allDays: IcsDay[] = accs.map((acc, i) => {
    const prevTotal = i > 0 ? accs[i - 1]!.total : null;
    let deltaPct: number | null = null;
    if (i > 0) {
      if (prevTotal === 0) deltaPct = acc.total > 0 ? 1000 : 0;
      else deltaPct = Math.round(((acc.total - prevTotal!) / prevTotal!) * 100);
    }
    const date = fmtDate(acc.startMs);
    const severityMax = acc.severityMax;

    const notable: string[] = [];
    if (acc.total > 0 && acc.total === maxTotal) notable.push("busiest");
    if (deltaPct !== null && deltaPct >= SPIKE_THRESHOLD_PCT && acc.total > 0) notable.push("spike");
    if (severityMax === "critical") notable.push("critical");
    if (acc.newSources.size > 0 && acc.newSources.size === maxNew && maxNew > 0) notable.push("influx");

    const alarm = acc.total > 0 && sevRank(severityMax) >= sevRank(alarmFloor);

    return {
      date,
      startMs: acc.startMs,
      endMs: acc.endMs,
      total: acc.total,
      serious: acc.serious,
      uniqueSources: acc.sources.size,
      uniqueTargets: acc.targets.size,
      uniqueSignatures: acc.signatures.size,
      newSources: acc.newSources.size,
      severityMax,
      topSource: topKey(acc.sourceCounts),
      topSignature: topKey(acc.signatureCounts),
      topCategory: topKey(acc.categoryCounts),
      deltaPct,
      notable,
      uid: `sectool-${date.replace(/-/g, "")}@sectool.local`,
      priority: severityPriority(severityMax),
      alarm,
    };
  });

  // Keep only the days we will actually emit: active days by default, or all when
  // includeQuiet is set. Then cap to the most recent `limit`.
  const qualifying = includeQuiet ? allDays : allDays.filter((d) => d.total > 0);
  const truncated = qualifying.length > limit;
  const days = truncated ? qualifying.slice(qualifying.length - limit) : qualifying;

  const report: IcsReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    nowMs: windowEndMs,
    baselineSources: baselineSources.size,
    baselineStartMs,
    totalAlerts,
    dayCount: allDays.length,
    emittedCount: qualifying.length,
    includeQuiet,
    alarms,
    alarmFloor,
    truncated,
    calendarName,
    days,
    text: "",
    markdown: "",
  };

  report.text = renderCalendar(report);
  report.markdown = renderMarkdown(report);
  return report;
}

/** Coerce a free-form `--format` value into a supported {@link IcsFormat}. */
export function parseIcsFormat(raw: string | undefined | null): IcsFormat {
  const v = (raw ?? "").trim().toLowerCase();
  if (v === "json") return "json";
  if (v === "md" || v === "markdown") return "md";
  return "ics";
}

/** A filesystem-safe filename for a downloaded calendar / review twin. */
export function icsFilename(nowMs: number, format: IcsFormat = "ics"): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  const ext = format === "md" ? "md" : format === "json" ? "json" : "ics";
  return `sectool-calendar-${stamp}.${ext}`;
}
