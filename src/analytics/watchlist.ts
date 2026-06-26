/**
 * Watchlist activity report.
 *
 * The watchlist (see store/watchlist.ts) is the operator's curated set of IPs /
 * CIDR ranges they want to keep an eye on — a known C2 block, a vendor doing a
 * sanctioned pen-test, a noisy-neighbour ASN. Unlike the blocklist it takes no
 * action and unlike the safelist it changes no scoring; it is purely
 * observational. The dashboard highlights live hits, but until now there was no
 * *portable, point-in-time* answer to the question the watchlist exists to
 * answer: **"of everything I'm watching, what has actually been active — and
 * what has gone quiet?"**
 *
 * This module clusters the stored alert history around each watchlist entry and,
 * for every entry, rolls up:
 *
 *   - total hits, the worst severity reached, and the per-severity split,
 *   - the direction split — alerts where the watched address was the SOURCE
 *     (it reached toward us) vs the DESTINATION (one of our hosts reached it),
 *   - which concrete addresses inside a CIDR entry actually lit up,
 *   - the counterpart endpoints it exchanged alerts with (almost always *your*
 *     internal hosts — "what did this watched address touch?"),
 *   - the signatures and categories it tripped,
 *   - blocked vs detected-only dispositions and how many alerts are still open
 *     in triage, and
 *   - its active time span / per-day rate.
 *
 * Crucially it ALSO lists entries with **zero** hits in the window. A watched
 * address going silent is itself a finding ("that C2 we flagged last week has
 * been dormant for 6 days") and is invisible to every other report, which only
 * ranks things that appeared.
 *
 * Each entry is labelled `active` (real, recent, or voluminous activity),
 * `quiet` (a few low-severity touches) or `dormant` (nothing this window). The
 * watchlist is observational, so — unlike assets.ts — dismissed alerts are kept:
 * acknowledging an alert as noise does not mean the watched target was inactive.
 *
 * It is pure in-memory math over alertStore + the watch / block / safe / triage
 * stores — no SSH, no Claude, no network — so it is safe to call from the
 * dashboard or CLI at any time. Output is both a structured model and a
 * ready-to-paste Markdown document, mirroring report.ts, compare.ts, profile.ts,
 * assets.ts and tuning.ts.
 *
 * This complements:
 *   - assets.ts    (ranks YOUR internal hosts by exposure — different axis),
 *   - campaigns.ts (clusters by external attacker IP, watched or not), and
 *   - profile.ts   (a single-entity deep dive — not a watchlist-wide board).
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { triageStore } from "../store/triage.ts";
import { blockStore } from "../store/blocklist.ts";
import { safeStore } from "../store/safelist.ts";
import { watchStore, type WatchEntry } from "../store/watchlist.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** A signature one watched entry tripped, with its severity ceiling. */
export interface WatchSignature {
  signature: string;
  count: number;
  severityMax: Severity;
}

/** A counterpart endpoint a watched address exchanged alerts with. */
export interface WatchCounterpart {
  /** The "other side" of the alert (usually one of your internal hosts). */
  ip: string;
  /** Number of alerts shared with this counterpart. */
  count: number;
  /** Whether the counterpart is an internal (RFC1918 / loopback / link-local) host. */
  internal: boolean;
  /** Highest severity seen across alerts with this counterpart. */
  severityMax: Severity;
  /** Most recent alert time with this counterpart, ms epoch. */
  lastSeen: number;
}

/** Coarse activity label for a watchlist entry over the window. */
export type WatchActivity = "active" | "quiet" | "dormant";

export interface WatchlistEntryActivity {
  /** The watchlist entry as stored — IP or CIDR. */
  target: string;
  /** Family hint copied from the entry: 4, 6, or 0 for CIDR. */
  family: 4 | 6 | 0;
  /** Operator note explaining why it's watched, if any. */
  note?: string;
  /** When the entry was added to the watchlist (ms epoch). */
  addedAt: number;
  /** Total alerts that touched this entry in the window. */
  hitCount: number;
  /** Highest severity seen across those alerts. */
  severityMax: Severity;
  /** Per-severity counts, ordered info → critical (zeros omitted). */
  bySeverity: Array<{ severity: Severity; count: number }>;
  /** Alerts where the watched address was the SOURCE (it reached toward us). */
  asSrc: number;
  /** Alerts where the watched address was the DESTINATION (we reached it). */
  asDst: number;
  /** Distinct concrete addresses inside this entry that appeared (≥1 for a hit; relevant for CIDR). */
  distinctMatchedIps: number;
  /** The concrete addresses that lit up, most-active first (capped). */
  matchedIps: string[];
  /** Counterpart endpoints, most-contacted first (capped). */
  counterparts: WatchCounterpart[];
  /** Of {@link counterparts}, how many are internal hosts. */
  internalCounterpartCount: number;
  /** Distinct signatures tripped, most-seen first (capped). */
  signatures: WatchSignature[];
  /** Distinct Suricata categories tripped. */
  categories: string[];
  /** How many of the entry's alerts the gateway actually blocked. */
  blockedCount: number;
  /** Detected-only (seen but not stopped) alerts. */
  detectedCount: number;
  /** Alerts still open in triage. */
  openCount: number;
  /** Earliest / latest alert times (ms epoch); 0 when dormant. */
  firstSeen: number;
  lastSeen: number;
  /** Span between first and last hit, ms (0 when ≤1 hit). */
  spanMs: number;
  /** Normalized alerts-per-day rate over the window. */
  perDay: number;
  /** Whether this target is also currently on the blocklist. */
  blocked: boolean;
  /** Whether this target is also on the safelist (an unusual, worth-flagging combo). */
  safe: boolean;
  /** Coarse activity label. */
  activity: WatchActivity;
  /** Most-recent alert ids touching this entry (for drill-in), newest first. */
  sampleAlertIds: string[];
}

export interface WatchlistReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Total watchlist entries considered. */
  entryCount: number;
  /** Entries labelled `active`. */
  activeCount: number;
  /** Entries labelled `quiet`. */
  quietCount: number;
  /** Entries with no hits this window. */
  dormantCount: number;
  /** Sum of hits across all watched entries. */
  totalHits: number;
  /** Distinct alerts that touched at least one watched entry. */
  matchedAlerts: number;
  /** Plain-language call-outs about the report as a whole. */
  highlights: string[];
  /** Entries ranked active-first. */
  entries: WatchlistEntryActivity[];
  /** The finished Markdown document. */
  markdown: string;
}

const SAMPLE_IDS = 8;
const DEFAULT_TOP = 100;
const TOP_COUNTERPARTS = 10;
const TOP_SIGS = 6;
const TOP_MATCHED_IPS = 6;
/** A hit volume at/above which an entry counts as `active` regardless of severity. */
const ACTIVE_MIN_HITS = 5;

function isPrivate(ip: string): boolean {
  return (
    /^10\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^127\./.test(ip) ||
    /^169\.254\./.test(ip) ||
    /^(::1|fe80|fc|fd)/i.test(ip)
  );
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

/** Label an entry from its hit volume + worst severity. */
function classifyActivity(hitCount: number, severityMax: Severity): WatchActivity {
  if (hitCount === 0) return "dormant";
  // Any medium+ detection, or sustained volume, is "active".
  if (sevRank(severityMax) >= 2 || hitCount >= ACTIVE_MIN_HITS) return "active";
  return "quiet";
}

// ----- formatting helpers (mirror assets.ts / tuning.ts conventions) -----

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

const ACTIVITY_LABEL: Record<WatchActivity, string> = {
  active: "🔴 Active",
  quiet: "🟡 Quiet",
  dormant: "· Dormant",
};

/** Compose the report-level highlight bullets. */
function writeHighlights(model: Omit<WatchlistReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  if (!model.entryCount) return out;

  const active = model.entries.filter((e) => e.activity === "active");
  if (active.length) {
    out.push(
      `${active.length} watched target(s) are ACTIVE: ` +
        active
          .slice(0, 5)
          .map((e) => `${e.target} (${e.hitCount} hit(s), peak ${e.severityMax})`)
          .join(", ") +
        ".",
    );
    const top = active[0]!;
    out.push(
      `Most active: ${top.target} — ${top.hitCount} alert(s) (${top.perDay.toFixed(1)}/day), ` +
        `peak ${top.severityMax}, ${top.internalCounterpartCount} internal host(s) touched.`,
    );
  } else {
    out.push(`No watched target generated a medium+ or high-volume alert this window — the watchlist is quiet.`);
  }

  const activeUnblocked = model.entries.filter((e) => e.activity !== "dormant" && !e.blocked);
  if (activeUnblocked.length) {
    out.push(
      `${activeUnblocked.length} watched target(s) with activity are NOT on the blocklist — review whether any warrant a block.`,
    );
  }
  const safeAndActive = model.entries.filter((e) => e.activity !== "dormant" && e.safe);
  if (safeAndActive.length) {
    out.push(
      `⚠️ ${safeAndActive.length} watched target(s) are also SAFELISTED yet still alerting — a conflicting curation worth resolving.`,
    );
  }
  if (model.dormantCount) {
    out.push(`${model.dormantCount} watched target(s) were dormant (no activity in the last ${model.hours} hour(s)).`);
  }
  const open = model.entries.reduce((n, e) => n + e.openCount, 0);
  if (open) out.push(`${open} alert(s) across watched targets are still open in triage.`);
  return out;
}

function renderMarkdown(model: WatchlistReport): string {
  const lines: string[] = [];
  lines.push(`# 👁️ SecTool Watchlist Activity Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(model.windowEndMs)}`);
  lines.push(`**Window:** last ${model.hours} hour(s) — ${fmtTime(model.windowStartMs)} → ${fmtTime(model.windowEndMs)}`);
  lines.push(
    `**Watched targets:** ${model.entryCount} · ` +
      `🔴 ${model.activeCount} active · 🟡 ${model.quietCount} quiet · ⚪ ${model.dormantCount} dormant`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!model.entryCount) {
    lines.push(`Your watchlist is empty — add targets with the dashboard or \`watchStore.add()\` to populate this report.`);
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of model.highlights) lines.push(`- ${h}`);
  lines.push("");

  // Ranked board: active and quiet entries first (anything that moved).
  const moved = model.entries.filter((e) => e.activity !== "dormant");
  if (moved.length) {
    lines.push(`## Activity (loudest first)`);
    lines.push("");
    lines.push(
      mdTable(
        ["#", "Target", "Status", "Hits", "/day", "It→us / us→it", "Peak", "Hosts", "Blocked", "Open", "Last", "Note"],
        moved.map((e, i) => [
          String(i + 1),
          cell(e.target),
          cell(ACTIVITY_LABEL[e.activity]),
          String(e.hitCount),
          e.perDay.toFixed(1),
          `${e.asSrc} / ${e.asDst}`,
          cell(e.severityMax),
          String(e.internalCounterpartCount),
          String(e.blockedCount),
          String(e.openCount),
          fmtAgo(e.lastSeen, model.windowEndMs),
          cell(e.note ?? ""),
        ]),
      ),
    );
    lines.push("");

    // Per-entry detail for the loudest, so the doc is actionable on its own.
    const detailLimit = Math.min(moved.length, 10);
    lines.push(`## Target detail (top ${detailLimit})`);
    lines.push("");
    for (let i = 0; i < detailLimit; i++) {
      const e = moved[i]!;
      const state: string[] = [];
      if (e.blocked) state.push("🚫 blocked");
      if (e.safe) state.push("✅ safelisted");
      lines.push(
        `### ${i + 1}. ${e.target} — ${ACTIVITY_LABEL[e.activity]}` + (state.length ? ` (${state.join(", ")})` : ""),
      );
      lines.push("");
      if (e.note) lines.push(`> ${cell(e.note)}`);
      lines.push(
        `- **Hits:** ${e.hitCount} (${e.perDay.toFixed(1)}/day) · peak **${e.severityMax}** · ` +
          `${e.asSrc} inbound (it→us) / ${e.asDst} outbound (us→it)`,
      );
      lines.push(
        `- **First/last:** ${fmtTime(e.firstSeen)} → ${fmtTime(e.lastSeen)} (${fmtAgo(e.lastSeen, model.windowEndMs)})`,
      );
      if (e.family === 0) {
        lines.push(
          `- **Live addresses in range:** ${e.distinctMatchedIps}` +
            (e.matchedIps.length ? ` — ${e.matchedIps.join(", ")}` : ""),
        );
      }
      if (e.counterparts.length) {
        const cp = e.counterparts
          .slice(0, TOP_COUNTERPARTS)
          .map((c) => `${c.ip}${c.internal ? "" : " (ext)"} ×${c.count}`)
          .join(", ");
        lines.push(`- **Touched hosts:** ${cp}`);
      }
      if (e.signatures.length) {
        const sigs = e.signatures.map((s) => `${s.signature} ×${s.count}`).join("; ");
        lines.push(`- **Signatures:** ${sigs}`);
      }
      if (e.categories.length) lines.push(`- **Categories:** ${e.categories.join(", ")}`);
      lines.push(
        `- **Disposition:** ${e.blockedCount} blocked / ${e.detectedCount} detected-only · ${e.openCount} open in triage`,
      );
      lines.push("");
    }
  } else {
    lines.push(`_Every watched target was dormant this window — no alert touched any of them._`);
    lines.push("");
  }

  // Dormant roll-up: silence is itself a finding, so always surface it.
  const dormant = model.entries.filter((e) => e.activity === "dormant");
  if (dormant.length) {
    lines.push(`## Dormant targets (no activity this window)`);
    lines.push("");
    lines.push(
      mdTable(
        ["Target", "Added", "Blocked", "Safelisted", "Note"],
        dormant.map((e) => [
          cell(e.target),
          fmtAgo(e.addedAt, model.windowEndMs),
          e.blocked ? "yes" : "—",
          e.safe ? "yes" : "—",
          cell(e.note ?? ""),
        ]),
      ),
    );
    lines.push("");
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool from ${model.matchedAlerts} matching alert(s) across ${model.entryCount} ` +
      `watched target(s). The watchlist is observational — these rows take no action. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

interface Agg {
  entry: WatchEntry;
  hitCount: number;
  severityMax: Severity;
  bySev: Map<Severity, number>;
  matchedIps: Map<string, number>;
  counterparts: Map<string, { count: number; internal: boolean; severityMax: Severity; lastSeen: number }>;
  sigCounts: Map<string, number>;
  sigMaxSev: Map<string, Severity>;
  categories: Set<string>;
  asSrc: number;
  asDst: number;
  blockedCount: number;
  detectedCount: number;
  openCount: number;
  firstSeen: number;
  lastSeen: number;
  samples: Array<{ id: string; time: number }>;
}

function newAgg(entry: WatchEntry): Agg {
  return {
    entry,
    hitCount: 0,
    severityMax: "info",
    bySev: new Map(),
    matchedIps: new Map(),
    counterparts: new Map(),
    sigCounts: new Map(),
    sigMaxSev: new Map(),
    categories: new Set(),
    asSrc: 0,
    asDst: 0,
    blockedCount: 0,
    detectedCount: 0,
    openCount: 0,
    firstSeen: 0,
    lastSeen: 0,
    samples: [],
  };
}

/**
 * Fold one (matched address, counterpart, role) observation of an alert into the
 * entry's aggregate. `role` is "src" when the watched address was the alert
 * source (it reached toward us) and "dst" when it was the destination.
 */
function applyHit(
  agg: Agg,
  a: StoredAlert,
  matchedIp: string,
  counterpart: string | undefined,
  role: "src" | "dst",
  sev: Severity,
  action: string,
): void {
  agg.hitCount++;
  agg.severityMax = maxSeverity(agg.severityMax, sev);
  agg.bySev.set(sev, (agg.bySev.get(sev) ?? 0) + 1);
  agg.matchedIps.set(matchedIp, (agg.matchedIps.get(matchedIp) ?? 0) + 1);
  if (role === "src") agg.asSrc++;
  else agg.asDst++;

  if (a.signature) {
    agg.sigCounts.set(a.signature, (agg.sigCounts.get(a.signature) ?? 0) + 1);
    agg.sigMaxSev.set(a.signature, maxSeverity(agg.sigMaxSev.get(a.signature) ?? "info", sev));
  }
  if (a.category) agg.categories.add(a.category);

  if (counterpart && counterpart !== matchedIp && isIP(counterpart) > 0) {
    const acc = agg.counterparts.get(counterpart) ?? {
      count: 0,
      internal: isPrivate(counterpart),
      severityMax: "info" as Severity,
      lastSeen: a.time,
    };
    acc.count++;
    acc.severityMax = maxSeverity(acc.severityMax, sev);
    if (a.time > acc.lastSeen) acc.lastSeen = a.time;
    agg.counterparts.set(counterpart, acc);
  }

  if (action === "blocked") agg.blockedCount++;
  else if (action === "detected") agg.detectedCount++;
  if ((triageStore.get(a.id)?.status ?? "open") === "open") agg.openCount++;

  if (agg.firstSeen === 0 || a.time < agg.firstSeen) agg.firstSeen = a.time;
  if (a.time > agg.lastSeen) agg.lastSeen = a.time;
  agg.samples.push({ id: a.id, time: a.time });
}

/**
 * Build the watchlist activity report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param limit Cap on how many entries are returned (active ones first).
 * @param nowMs Pins the window end for deterministic tests; defaults to now.
 */
export function buildWatchlist(hours: number, limit = DEFAULT_TOP, nowMs = Date.now()): WatchlistReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const windowEndMs = nowMs;
  const windowStartMs = windowEndMs - safeHours * 3_600_000;
  const safeLimit = Math.max(1, Math.min(2000, Math.floor(limit)));
  const windowDays = safeHours / 24;

  // Seed an aggregate for every watchlist entry so dormant ones still appear.
  const entries = watchStore.all();
  const byTarget = new Map<string, Agg>();
  for (const e of entries) byTarget.set(e.target, newAgg(e));

  const matchedAlertIds = new Set<string>();

  if (byTarget.size) {
    const inWindow = alertStore
      .all()
      .filter((a) => typeof a.time === "number" && a.time >= windowStartMs && a.time <= windowEndMs);

    for (const a of inWindow) {
      const sev = (a.severity as Severity) ?? "info";
      const action = normalizeAction(a.action);

      // The watched address can be on either side of the alert. watchStore.match
      // resolves both plain IPs and CIDR membership back to the stored entry.
      // Collect at most ONE observation per distinct entry so an alert whose
      // src and dst both fall in the same watched range still counts as a single
      // hit (src takes precedence for the direction/counterpart attribution).
      const obs = new Map<string, { matchedIp: string; counterpart: string | undefined; role: "src" | "dst" }>();
      if (a.srcIp) {
        const hit = watchStore.match(a.srcIp);
        if (hit && byTarget.has(hit.target)) {
          obs.set(hit.target, { matchedIp: a.srcIp, counterpart: a.dstIp, role: "src" });
        }
      }
      if (a.dstIp) {
        const hit = watchStore.match(a.dstIp);
        if (hit && byTarget.has(hit.target) && !obs.has(hit.target)) {
          obs.set(hit.target, { matchedIp: a.dstIp, counterpart: a.srcIp, role: "dst" });
        }
      }
      for (const [target, o] of obs) {
        applyHit(byTarget.get(target)!, a, o.matchedIp, o.counterpart, o.role, sev, action);
      }
      if (obs.size) matchedAlertIds.add(a.id);
    }
  }

  const built: WatchlistEntryActivity[] = [...byTarget.values()].map((agg) => {
    const bySeverity = SEVERITY_ORDER.map((severity) => ({ severity, count: agg.bySev.get(severity) ?? 0 })).filter(
      (x) => x.count > 0,
    );
    const counterparts: WatchCounterpart[] = [...agg.counterparts.entries()]
      .map(([ip, acc]) => ({ ip, count: acc.count, internal: acc.internal, severityMax: acc.severityMax, lastSeen: acc.lastSeen }))
      .sort((x, y) => y.count - x.count || y.lastSeen - x.lastSeen)
      .slice(0, TOP_COUNTERPARTS);
    const internalCounterpartCount = [...agg.counterparts.values()].filter((c) => c.internal).length;
    const signatures: WatchSignature[] = [...agg.sigCounts.entries()]
      .map(([signature, count]) => ({ signature, count, severityMax: agg.sigMaxSev.get(signature) ?? "info" }))
      .sort((x, y) => y.count - x.count || x.signature.localeCompare(y.signature))
      .slice(0, TOP_SIGS);
    const matchedIps = [...agg.matchedIps.entries()]
      .sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0]))
      .slice(0, TOP_MATCHED_IPS)
      .map(([ip]) => ip);
    const spanMs = agg.hitCount ? agg.lastSeen - agg.firstSeen : 0;
    const perDay = agg.hitCount / Math.max(windowDays, 1 / 24);
    const activity = classifyActivity(agg.hitCount, agg.severityMax);
    const sampleAlertIds = agg.samples
      .sort((x, y) => y.time - x.time)
      .slice(0, SAMPLE_IDS)
      .map((s) => s.id);

    return {
      target: agg.entry.target,
      family: agg.entry.family,
      note: agg.entry.note,
      addedAt: agg.entry.at,
      hitCount: agg.hitCount,
      severityMax: agg.severityMax,
      bySeverity,
      asSrc: agg.asSrc,
      asDst: agg.asDst,
      distinctMatchedIps: agg.matchedIps.size,
      matchedIps,
      counterparts,
      internalCounterpartCount,
      signatures,
      categories: [...agg.categories].sort(),
      blockedCount: agg.blockedCount,
      detectedCount: agg.detectedCount,
      openCount: agg.openCount,
      firstSeen: agg.firstSeen,
      lastSeen: agg.lastSeen,
      spanMs,
      perDay,
      blocked: blockStore.has(agg.entry.target),
      safe: safeStore.has(agg.entry.target),
      activity,
      sampleAlertIds,
    };
  });

  // Active first, then quiet, then dormant; within a tier by hits, severity, recency.
  const actRank: Record<WatchActivity, number> = { active: 2, quiet: 1, dormant: 0 };
  built.sort(
    (a, b) =>
      actRank[b.activity] - actRank[a.activity] ||
      b.hitCount - a.hitCount ||
      sevRank(b.severityMax) - sevRank(a.severityMax) ||
      b.lastSeen - a.lastSeen ||
      b.addedAt - a.addedAt,
  );

  const ranked = built.slice(0, safeLimit);
  const activeCount = built.filter((e) => e.activity === "active").length;
  const quietCount = built.filter((e) => e.activity === "quiet").length;
  const dormantCount = built.filter((e) => e.activity === "dormant").length;
  const totalHits = built.reduce((n, e) => n + e.hitCount, 0);

  const base: Omit<WatchlistReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    entryCount: built.length,
    activeCount,
    quietCount,
    dormantCount,
    totalHits,
    matchedAlerts: matchedAlertIds.size,
    entries: ranked,
  };
  const highlights = writeHighlights(base);
  const model: WatchlistReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded watchlist activity report. */
export function watchlistFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-watchlist-${stamp}.md`;
}
