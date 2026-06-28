/**
 * Tabular CSV / TSV alert export — the "**give me the spreadsheet**" export that
 * SecTool's export family was missing.
 *
 * SecTool already speaks every machine-to-machine forwarding dialect a SIEM or
 * sensor wants — `cef` (CEF/LEEF lines for ArcSight/Splunk/Sentinel/QRadar),
 * `ecs` (Elastic JSON documents), `stix`/`iocs` (intel), `sigma`/`snort`
 * (detection rules), `pcap` (capture filters). What none of them produces is the
 * single most universally analysable artefact: a **flat, one-row-per-alert table
 * an analyst can drop straight into Excel, Google Sheets, `pandas`, R, SQLite or
 * `awk`** for ad-hoc slicing without standing up a SIEM at all. This module is
 * that export.
 *
 * It is deliberately distinct from the dashboard's `GET /api/search.csv`
 * (`hitsToCsv` in `search.ts`): that one serialises a *query result* — the
 * dashboard's triage view (triage status, dismissed, notified) — is HTTP-only and
 * carries no re-parsed flow detail. This is a first-class **export-family member**
 * with a CLI flag (`--csv`), an `npm run csv` script and the full `/api/csv[.csv|
 * .tsv|.json|.md]` route set, and it enriches every row with the same re-parsed
 * network fields the `cef`/`ecs` exports recover — destination/source ports,
 * transport + application protocol, the stable `gid:sid` rule identity, traffic
 * direction and the coarse gateway disposition — plus the live enforcement-posture
 * flags (`blocked`/`watched`/`safelisted`). One window, one wide table.
 *
 * Output is RFC 4180-compliant:
 *   - fields containing a comma, quote, CR or LF are double-quoted and embedded
 *     quotes are doubled;
 *   - records are CRLF-terminated (the spec, and what Excel expects);
 *   - a cell beginning with `=`, `+`, `-`, `@` or a control char is prefixed with
 *     a single quote to defuse CSV/formula injection when opened in a spreadsheet
 *     (same hardening `hitsToCsv` applies);
 *   - an optional leading UTF-8 BOM (`--bom` / `?bom=1`) makes Excel read the file
 *     as UTF-8 so non-ASCII signature text is not mojibake'd.
 *
 * Four serializations: `csv` (default), `tsv` (tab-separated, no quoting needed
 * for the standard analytic pipelines that split on tab), `json` (the structured
 * model + the row objects, mirroring the other reports' `json`) and `markdown`
 * (the human review twin — a compact table plus the column dictionary and a
 * load-it one-liner).
 *
 * Honest about its limits, surfaced in the output:
 *   - **Ports & protocol are re-parsed, not stored.** Recovered from each alert's
 *     raw line (exactly as `cef`/`ecs`/`ports`/`protocols`); alerts whose raw text
 *     no longer carries a flow tuple leave those columns blank.
 *   - **Window-bounded & store-capped.** A long look-back can hit the alert
 *     store's retention cap and miss older events.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network — so it is
 * safe to call from the dashboard or CLI at any time. Mirrors the model + render
 * shape of cefExport.ts / ecsExport.ts so it plugs into the same CLI and HTTP
 * plumbing.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { recoverFlow } from "./ports.ts";
import { recoverSrcPort } from "./srcport.ts";
import { recoverProtocol } from "./protocols.ts";
import { recoverRuleId } from "./ruleset.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Serializations the export can render into. */
export type CsvFormat = "csv" | "tsv" | "json" | "markdown";

/** Hard ceiling on emitted rows (matches the alert store retention cap). */
const MAX_ROWS = 2000;
const MS_PER_HOUR = 3_600_000;

/** Coarse traffic direction relative to the internal estate. */
export type TrafficDirection = "inbound" | "outbound" | "lateral" | "external";

/**
 * The ordered column dictionary — the single source of truth for both the header
 * row and the per-row field extraction, so the two can never drift. Each entry
 * pairs a stable, machine-friendly column key with a one-line human description
 * (surfaced in the Markdown twin's data dictionary).
 */
export const CSV_COLUMNS: readonly { key: string; desc: string }[] = [
  { key: "time_iso", desc: "Event time, ISO-8601 UTC." },
  { key: "time_epoch_ms", desc: "Event time, milliseconds since the Unix epoch (sortable integer)." },
  { key: "id", desc: "SecTool's stable alert id (dedupe key across exports)." },
  { key: "severity", desc: "Severity rung: info / low / medium / high / critical." },
  { key: "category", desc: "Suricata category." },
  { key: "classification", desc: "Suricata classification / classtype text." },
  { key: "signature", desc: "Human signature / rule name." },
  { key: "rule_gid", desc: "Generator id of the gid:sid rule identity (re-parsed)." },
  { key: "rule_sid", desc: "Signature id of the gid:sid rule identity (re-parsed)." },
  { key: "src_ip", desc: "Source / attacker IP." },
  { key: "src_port", desc: "Source port (re-parsed from the raw line)." },
  { key: "dst_ip", desc: "Destination / victim IP." },
  { key: "dst_port", desc: "Destination port (re-parsed from the raw line)." },
  { key: "transport", desc: "Transport protocol — tcp/udp/icmp/… (re-parsed)." },
  { key: "app_proto", desc: "Application protocol — http/dns/tls/… (re-parsed)." },
  { key: "direction", desc: "Flow direction vs the estate: inbound/outbound/lateral/external." },
  { key: "action", desc: "Raw gateway action string as logged." },
  { key: "disposition", desc: "Coarse enforcement disposition: blocked / passed / unknown." },
  { key: "safelisted", desc: "yes if the source IP is on the vetted-benign safelist." },
  { key: "blocked", desc: "yes if the source IP is currently on the enforced blocklist." },
  { key: "watched", desc: "yes if the source IP is on the watchlist." },
  { key: "notified", desc: "yes if a Discord notification was sent for this alert." },
  { key: "has_summary", desc: "yes if a stored Claude analyst summary exists." },
  { key: "raw", desc: "The original raw syslog line." },
] as const;

/** One fully-enriched alert row, pre-serialization. */
export interface CsvRow {
  time_iso: string;
  time_epoch_ms: number;
  id: string;
  severity: Severity;
  category: string;
  classification: string;
  signature: string;
  rule_gid: number | "";
  rule_sid: number | "";
  src_ip: string;
  src_port: number | "";
  dst_ip: string;
  dst_port: number | "";
  transport: string;
  app_proto: string;
  direction: TrafficDirection;
  action: string;
  disposition: "blocked" | "passed" | "unknown";
  safelisted: boolean;
  blocked: boolean;
  watched: boolean;
  notified: boolean;
  has_summary: boolean;
  raw: string;
}

export interface CsvExport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Rows emitted (after the limit). */
  totalRows: number;
  /** Rows dropped by the `limit` (totalRows ignores these). */
  truncated: number;
  /** The enriched rows, newest first. */
  rows: CsvRow[];
}

export interface CsvExportOptions {
  /** Cap on emitted rows (newest first). Default = the store cap. */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

export interface CsvRenderOptions {
  /** Prepend a UTF-8 BOM so Excel reads the file as UTF-8 (csv/tsv only). */
  bom?: boolean;
}

// ----- classifiers / helpers (mirror cefExport.ts / ecsExport.ts) ------------

/** RFC1918 / loopback / link-local / ULA — an address treated as one of ours. */
function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
}

/** A valid, non-empty IP, or "" if the field is missing/garbage. */
function validIp(ip: string | undefined): string {
  return ip && isIP(ip) !== 0 ? ip : "";
}

function sevWord(s: string | undefined): Severity {
  return (SEVERITY_ORDER as readonly string[]).includes(s ?? "") ? (s as Severity) : "info";
}

/** Direction of a flow relative to the internal estate. */
function directionOf(src: string, dst: string): TrafficDirection {
  const sPriv = src ? isPrivate(src) : undefined;
  const dPriv = dst ? isPrivate(dst) : undefined;
  if (sPriv === false && dPriv === true) return "inbound";
  if (sPriv === true && dPriv === false) return "outbound";
  if (sPriv === true && dPriv === true) return "lateral";
  return "external";
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function yn(b: boolean): string {
  return b ? "yes" : "no";
}

// ----- serialization ---------------------------------------------------------

/** UTF-8 byte-order mark — Excel needs this to read a UTF-8 CSV correctly. */
const BOM = "﻿";

/**
 * Stringify one row's cells in column order. Booleans become yes/no, an empty
 * numeric/string field becomes "". The raw values are returned untouched here;
 * delimiter-specific quoting is applied by {@link csvCell} / {@link tsvCell}.
 */
function rowValues(r: CsvRow): string[] {
  const v: Record<string, unknown> = {
    ...r,
    safelisted: yn(r.safelisted),
    blocked: yn(r.blocked),
    watched: yn(r.watched),
    notified: yn(r.notified),
    has_summary: yn(r.has_summary),
  };
  return CSV_COLUMNS.map((c) => {
    const cell = v[c.key];
    return cell === undefined || cell === null ? "" : String(cell);
  });
}

/**
 * RFC 4180 field quoting with spreadsheet formula-injection hardening: a cell
 * starting with a risky character (`= + - @` or a control char) is prefixed with
 * a single quote, then the whole field is double-quoted iff it contains a comma,
 * quote, CR or LF (embedded quotes doubled).
 */
function csvCell(s: string): string {
  const safe = /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
  return /[",\r\n]/.test(safe) ? '"' + safe.replace(/"/g, '""') + '"' : safe;
}

/**
 * TSV field cleaning: TSV has no quoting convention, so any tab/CR/LF inside a
 * value would corrupt the column grid — replace them with a single space. The
 * same formula-injection prefix is applied for spreadsheet safety.
 */
function tsvCell(s: string): string {
  const safe = /^[=+\-@]/.test(s) ? "'" + s : s;
  return safe.replace(/[\t\r\n]+/g, " ");
}

function renderDelimited(m: CsvExport, delimiter: "," | "\t", opts: CsvRenderOptions): string {
  const cellFn = delimiter === "," ? csvCell : tsvCell;
  const header = CSV_COLUMNS.map((c) => cellFn(c.key)).join(delimiter);
  const lines = [header, ...m.rows.map((r) => rowValues(r).map(cellFn).join(delimiter))];
  // RFC 4180 mandates CRLF record separators; spreadsheets and \n-splitters both
  // accept them, so use CRLF for both csv and tsv for a single consistent rule.
  const body = lines.join("\r\n");
  return (opts.bom ? BOM : "") + body;
}

// ----- markdown twin ---------------------------------------------------------

function mdCell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function clip(s: string, max = 48): string {
  const t = s.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

function renderMarkdown(m: CsvExport): string {
  const lines: string[] = [];
  lines.push(`# 📑 SecTool Tabular Alert Export (CSV / TSV)`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Rows:** ${m.totalRows} · **Columns:** ${CSV_COLUMNS.length}` +
      (m.truncated ? ` · **Truncated:** ${m.truncated} older row(s)` : ""),
  );
  lines.push("");

  if (!m.totalRows) {
    lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to export.`);
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  lines.push(
    `One IPS alert per row, ready for Excel / Google Sheets / \`pandas\` / SQLite / \`awk\`. Ports and protocol are ` +
      `re-parsed from each alert's raw line; enforcement-posture flags reflect the live block/watch/safe lists.`,
  );
  lines.push("");

  // The one-liner that fetches the spreadsheet — the deliverable's "how to use".
  lines.push(`## Get it`);
  lines.push("");
  lines.push("```bash");
  lines.push(`# Download the CSV (add ?bom=1 for Excel, or use /api/csv.tsv for tab-separated):`);
  lines.push(`curl -s 'http://<sectool-host>/api/csv.csv?hours=${m.hours}' -o sectool-alerts.csv`);
  lines.push(`# …or straight into pandas / DuckDB / SQLite for analysis.`);
  lines.push("```");
  lines.push("");

  // A compact preview over a representative slice of the columns (the full set is
  // wide; the file/JSON carries every column).
  const head = ["time_iso", "severity", "src_ip", "dst_ip", "dst_port", "proto", "dir", "disp", "signature"];
  lines.push(`## Preview`);
  lines.push("");
  lines.push(`| ${head.join(" | ")} |`);
  lines.push(`| ${head.map(() => "---").join(" | ")} |`);
  for (const r of m.rows.slice(0, 100)) {
    const proto = [r.transport, r.app_proto].filter(Boolean).join("/") || "·";
    lines.push(
      `| ${[
        r.time_iso,
        r.severity,
        mdCell(r.src_ip || "·"),
        mdCell(r.dst_ip || "·"),
        r.dst_port === "" ? "·" : String(r.dst_port),
        proto,
        r.direction,
        r.disposition,
        mdCell(clip(r.signature || "·")),
      ].join(" | ")} |`,
    );
  }
  if (m.rows.length > 100) {
    lines.push("");
    lines.push(`_…and ${m.rows.length - 100} more row(s) — request the \`csv\` / \`tsv\` format for the full table._`);
  }
  lines.push("");

  // The data dictionary — every column, so the spreadsheet is self-documenting.
  lines.push(`## Columns`);
  lines.push("");
  lines.push(`| # | Column | Description |`);
  lines.push(`| --- | --- | --- |`);
  CSV_COLUMNS.forEach((c, i) => lines.push(`| ${i + 1} | \`${c.key}\` | ${mdCell(c.desc)} |`));
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. This is the **flat tabular** alert export — the analyst's spreadsheet sibling of ` +
      `the \`cef\` and \`ecs\` SIEM event exports, distinct from the dashboard's query-driven \`/api/search.csv\`. ` +
      `Output is RFC 4180 (CRLF records, quoted fields, doubled quotes) with formula-injection hardening; add ` +
      `\`?bom=1\` for an Excel-friendly UTF-8 BOM. Ports and protocol are **re-parsed from each alert's raw line**, not ` +
      `a stored column, so they are blank when the raw text no longer carries them. A long look-back can hit the alert ` +
      `store's retention cap and miss older rows. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

// ----- build -----------------------------------------------------------------

/**
 * Build the tabular CSV/TSV export model from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link CsvExportOptions}: `limit` and a `nowMs` pin for
 *              deterministic tests.
 */
export function buildCsvExport(hours: number, opts: CsvExportOptions = {}): CsvExport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;
  const limit =
    opts.limit !== undefined ? Math.max(1, Math.min(MAX_ROWS, Math.floor(opts.limit))) : MAX_ROWS;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);
  // alertStore.all() already returns newest-first; keep that order for the table.

  const allRows: CsvRow[] = windowed.map((a) => {
    const flow = recoverFlow(a.raw);
    const proto = recoverProtocol(a.raw);
    const srcPort = recoverSrcPort(a.raw);
    const ruleId = recoverRuleId(a.raw);
    const severity = sevWord(a.severity);
    const src = validIp(a.srcIp);
    const dst = validIp(a.dstIp);

    return {
      time_iso: new Date(a.time).toISOString(),
      time_epoch_ms: a.time,
      id: a.id,
      severity,
      category: a.category ?? "",
      classification: a.classification ?? "",
      signature: a.signature ?? "",
      rule_gid: ruleId?.gid ?? "",
      rule_sid: ruleId?.sid ?? "",
      src_ip: src,
      src_port: srcPort ?? "",
      dst_ip: dst,
      dst_port: flow?.dstPort ?? "",
      transport: (proto.transport ?? flow?.protocol ?? "").toLowerCase(),
      app_proto: proto.appProto ?? "",
      direction: directionOf(src, dst),
      action: a.action ?? "",
      disposition: classifyDisposition(a.action),
      safelisted: src ? safeStore.has(src) : false,
      blocked: src ? blockStore.has(src) : false,
      watched: src ? watchStore.has(src) : false,
      notified: Boolean(a.notifiedAt),
      has_summary: Boolean(a.summary),
      raw: a.raw ?? "",
    } satisfies CsvRow;
  });

  const truncated = Math.max(0, allRows.length - limit);
  const rows = allRows.slice(0, limit);

  return {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalWindowAlerts: windowed.length,
    totalRows: rows.length,
    truncated,
    rows,
  };
}

/**
 * Render a built export model into the requested serialization. `csv` (default)
 * and `tsv` produce the delimited table; `markdown` the human review twin; `json`
 * the structured model with its rows materialized.
 */
export function renderCsv(model: CsvExport, format: CsvFormat, opts: CsvRenderOptions = {}): string {
  switch (format) {
    case "tsv":
      return renderDelimited(model, "\t", opts);
    case "markdown":
      return renderMarkdown(model);
    case "json":
      return JSON.stringify({ ...model, columns: CSV_COLUMNS }, null, 2);
    case "csv":
    default:
      return renderDelimited(model, ",", opts);
  }
}

/** A filesystem-safe filename for a downloaded export in the given format. */
export function csvFilename(nowMs: number, format: CsvFormat): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  const ext = format === "markdown" ? "md" : format;
  return `sectool-alerts-${stamp}.${ext}`;
}

/** Coerce an arbitrary string into a valid {@link CsvFormat}, defaulting to csv. */
export function parseCsvFormat(raw: string | undefined | null): CsvFormat {
  const f = (raw ?? "").trim().toLowerCase();
  if (f === "tsv") return "tsv";
  if (f === "json") return "json";
  if (f === "markdown" || f === "md") return "markdown";
  return "csv";
}
