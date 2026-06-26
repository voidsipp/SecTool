/**
 * Full-history alert search over the local `alertStore`.
 *
 * The live alert list (`/api/alerts`) requires SSH and only covers a recent
 * window pulled from the UDM. This module instead queries the persisted alert
 * history (up to MAX_ENTRIES, complete with Claude summaries and triage state)
 * entirely in-memory, so an operator can hunt for a specific past alert by free
 * text plus structured filters — no SSH, safe to call at any time.
 *
 * Pure functions against the store; the web layer adds the HTTP/CSV plumbing.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { dismissStore } from "../store/dismissed.ts";
import { triageStore, type TriageStatus } from "../store/triage.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

export type SortMode = "time-desc" | "time-asc" | "severity";

export interface SearchQuery {
  /** Free text — space-separated terms, ANDed, case-insensitive substring. */
  q?: string;
  /** Minimum severity (inclusive) along the info→critical ladder. */
  minSeverity?: Severity;
  /** Category substring (case-insensitive). */
  category?: string;
  /** Action label: blocked | detected | allowed | unknown. */
  action?: string;
  /** Match src OR dst — accepts a plain IP or an IPv4 CIDR (e.g. 10.0.0.0/8). */
  ip?: string;
  /** Triage workflow status. */
  status?: TriageStatus | "open";
  /** Look-back window in hours; 0 / undefined searches the whole history. */
  hours?: number;
  /** Only alerts that have / don't have a stored AI summary. */
  hasSummary?: boolean;
  /** Only alerts that were / weren't notified to Discord. */
  notified?: boolean;
  /** Include dismissed alerts (default: excluded). */
  includeDismissed?: boolean;
  sort?: SortMode;
  limit?: number;
  offset?: number;
}

export interface SearchHit {
  id: string;
  time: number;
  severity: string;
  category: string;
  signature?: string;
  classification?: string;
  srcIp?: string;
  dstIp?: string;
  action?: string;
  raw: string;
  hasSummary: boolean;
  notifiedAt?: number;
  dismissed: boolean;
  triageStatus: TriageStatus | "open";
  noteCount: number;
}

export interface SearchResult {
  /** Total matches before pagination. */
  total: number;
  /** Number of hits returned in this page. */
  count: number;
  offset: number;
  limit: number;
  /** Window searched, in hours (0 = entire history). */
  hours: number;
  /** Total alerts in the store (denominator for "X of Y"). */
  scanned: number;
  /** Severity breakdown of the full match set (pre-pagination), info→critical. */
  bySeverity: Array<{ severity: Severity; count: number }>;
  /** Echo of the effective, normalized query (useful for the UI / debugging). */
  query: Required<Pick<SearchQuery, "sort" | "limit" | "offset" | "hours" | "includeDismissed">> &
    Pick<SearchQuery, "q" | "minSeverity" | "category" | "action" | "ip" | "status" | "hasSummary" | "notified">;
  items: SearchHit[];
}

const DEFAULT_LIMIT = 50;
/** Interactive pages are bounded here; CSV export may request up to MAX_EXPORT. */
const MAX_LIMIT = 200;
/** Hard ceiling for a CSV export — matches the alertStore retention cap. */
export const MAX_EXPORT = 2000;

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

function normalizeAction(a: string | undefined): string {
  const v = (a ?? "").toLowerCase().trim();
  if (v === "blocked" || v === "detected" || v === "allowed") return v;
  return "unknown";
}

function ipv4ToInt(ip: string): number | null {
  if (isIP(ip) !== 4) return null;
  const parts = ip.split(".").map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return null;
  return ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
}

/** Build a predicate for the `ip` filter: exact IP match or IPv4 CIDR containment. */
function makeIpMatcher(raw: string): ((ip: string | undefined) => boolean) | null {
  const target = raw.trim();
  if (!target) return null;
  const slash = target.indexOf("/");
  if (slash >= 0) {
    const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(target);
    if (!m) return null;
    const bits = Number.parseInt(m[2]!, 10);
    if (!Number.isFinite(bits) || bits < 0 || bits > 32) return null;
    const base = ipv4ToInt(m[1]!);
    if (base === null) return null;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    const net = (base & mask) >>> 0;
    return (ip) => {
      if (!ip) return false;
      const n = ipv4ToInt(ip);
      return n !== null && ((n & mask) >>> 0) === net;
    };
  }
  if (isIP(target) === 0) return null;
  const needle = target.toLowerCase();
  return (ip) => !!ip && ip.toLowerCase() === needle;
}

function clampLimit(n: number | undefined, max = MAX_LIMIT): number {
  if (!Number.isFinite(n) || (n as number) <= 0) return DEFAULT_LIMIT;
  return Math.min(max, Math.floor(n as number));
}

/**
 * Run a structured search against the stored alert history.
 * `nowMs` lets callers pin the window end (useful for tests).
 */
export function searchAlerts(
  query: SearchQuery,
  nowMs = Date.now(),
  opts: { maxLimit?: number } = {},
): SearchResult {
  const all: StoredAlert[] = alertStore.all(); // newest-first
  const scanned = all.length;

  const hours = Number.isFinite(query.hours) && (query.hours as number) > 0 ? Math.floor(query.hours as number) : 0;
  const since = hours > 0 ? nowMs - hours * 3_600_000 : -Infinity;

  const terms = (query.q ?? "")
    .toLowerCase()
    .split(/\s+/)
    .map((t) => t.trim())
    .filter(Boolean);

  const minRank = query.minSeverity ? sevRank(query.minSeverity) : -1;
  const wantCategory = (query.category ?? "").toLowerCase().trim();
  const wantAction = query.action ? normalizeAction(query.action) : null;
  const ipMatch = query.ip ? makeIpMatcher(query.ip) : null;
  const wantStatus = query.status ?? null;
  const includeDismissed = query.includeDismissed === true;
  const sort: SortMode = query.sort ?? "time-desc";
  const limit = clampLimit(query.limit, opts.maxLimit ?? MAX_LIMIT);
  const offset = Number.isFinite(query.offset) && (query.offset as number) > 0 ? Math.floor(query.offset as number) : 0;

  const bySev = new Map<Severity, number>();
  const matched: SearchHit[] = [];

  for (const a of all) {
    if (typeof a.time === "number" && a.time < since) continue;
    if (minRank >= 0 && sevRank(a.severity) < minRank) continue;
    if (wantCategory && !(a.category ?? "").toLowerCase().includes(wantCategory)) continue;
    if (wantAction && normalizeAction(a.action) !== wantAction) continue;
    if (ipMatch && !ipMatch(a.srcIp) && !ipMatch(a.dstIp)) continue;

    const dismissed = dismissStore.has(a.id);
    if (dismissed && !includeDismissed) continue;
    if (query.hasSummary !== undefined && !!a.summary !== query.hasSummary) continue;
    if (query.notified !== undefined && !!a.notifiedAt !== query.notified) continue;

    const triage = triageStore.get(a.id);
    const triageStatus: TriageStatus | "open" = triage?.status ?? "open";
    if (wantStatus && triageStatus !== wantStatus) continue;

    if (terms.length) {
      const hay = [a.raw, a.signature, a.classification, a.category, a.srcIp, a.dstIp, a.id]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      if (!terms.every((t) => hay.includes(t))) continue;
    }

    bump(bySev, (a.severity as Severity) ?? "info");
    matched.push({
      id: a.id,
      time: a.time,
      severity: a.severity,
      category: a.category,
      signature: a.signature,
      classification: a.classification,
      srcIp: a.srcIp,
      dstIp: a.dstIp,
      action: a.action,
      raw: a.raw,
      hasSummary: !!a.summary,
      notifiedAt: a.notifiedAt,
      dismissed,
      triageStatus,
      noteCount: triage?.notes.length ?? 0,
    });
  }

  if (sort === "time-asc") matched.sort((x, y) => x.time - y.time);
  else if (sort === "severity") matched.sort((x, y) => sevRank(y.severity) - sevRank(x.severity) || y.time - x.time);
  else matched.sort((x, y) => y.time - x.time);

  const page = matched.slice(offset, offset + limit);

  return {
    total: matched.length,
    count: page.length,
    offset,
    limit,
    hours,
    scanned,
    bySeverity: SEVERITY_ORDER.map((severity) => ({ severity, count: bySev.get(severity) ?? 0 })),
    query: {
      q: query.q?.trim() || undefined,
      minSeverity: query.minSeverity,
      category: query.category?.trim() || undefined,
      action: wantAction ?? undefined,
      ip: query.ip?.trim() || undefined,
      status: wantStatus ?? undefined,
      hasSummary: query.hasSummary,
      notified: query.notified,
      includeDismissed,
      sort,
      limit,
      offset,
      hours,
    },
    items: page,
  };
}

function bump(m: Map<Severity, number>, k: Severity): void {
  m.set(k, (m.get(k) ?? 0) + 1);
}

/** Render a set of search hits as a spreadsheet-friendly CSV string. */
export function hitsToCsv(items: SearchHit[]): string {
  const headers = [
    "time_iso",
    "id",
    "severity",
    "category",
    "signature",
    "classification",
    "src_ip",
    "dst_ip",
    "action",
    "triage_status",
    "notified",
    "dismissed",
    "has_summary",
    "raw",
  ];
  const cell = (v: unknown): string => {
    const s = v === undefined || v === null ? "" : String(v);
    // RFC-4180 quoting; prefix risky leading chars to defuse CSV-injection in Excel.
    const safe = /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
    return /[",\r\n]/.test(safe) ? '"' + safe.replace(/"/g, '""') + '"' : safe;
  };
  const lines = [headers.join(",")];
  for (const h of items) {
    lines.push(
      [
        new Date(h.time).toISOString(),
        h.id,
        h.severity,
        h.category,
        h.signature ?? "",
        h.classification ?? "",
        h.srcIp ?? "",
        h.dstIp ?? "",
        h.action ?? "",
        h.triageStatus,
        h.notifiedAt ? "yes" : "no",
        h.dismissed ? "yes" : "no",
        h.hasSummary ? "yes" : "no",
        h.raw,
      ]
        .map(cell)
        .join(","),
    );
  }
  return lines.join("\r\n");
}
