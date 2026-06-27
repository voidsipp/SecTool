/**
 * Block-effectiveness / post-block recidivism audit — "after I blocked an IP,
 * did the traffic actually stop?"
 *
 * Every blocked source carries a *block timestamp* (`BlockEntry.at`, set when the
 * IP was added to the blocklist via the responder or the dashboard). No other
 * offline report in this project reads that timestamp, yet it answers the single
 * most important question about an enforcement action: **was it effective?**
 *
 * The related reports each see a different slice and none of them cross the block
 * timestamp with the alert stream:
 *
 *   - **efficacy.ts** scores the *gateway's* per-alert disposition (blocked vs
 *     passed) across the whole stream. It never asks whether a *source we
 *     explicitly blocked at the firewall* is still getting through — it has no
 *     notion of when we blocked it.
 *   - **persistence.ts / recurrence.ts** rank sources/signatures that keep coming
 *     back over time, but they treat all sources alike — they don't know which
 *     ones we already took action against, so a stubborn attacker we've *already
 *     contained* looks identical to a fresh enforcement gap.
 *   - **suppressions.ts** audits the *alert-suppression* rules, a different
 *     control entirely (what we choose not to be told about), not the firewall
 *     blocks (what we choose to drop).
 *
 * For every IP currently on the blocklist this report folds the windowed alerts
 * whose source is that IP and splits them on the block timestamp:
 *
 *   - **pre-block** alerts (`time < at`) — the activity that *led to* the block,
 *     kept for context when the block landed inside the window;
 *   - **post-block** alerts (`time >= at`) — the recidivism signal. An IP that
 *     keeps tripping rules *after* we blocked it is either a stubborn attacker the
 *     gateway is successfully dropping, or — the alarm — traffic still reaching
 *     our services despite the block on paper.
 *
 * The post-block alerts are further split by the gateway's own disposition
 * (reusing efficacy.ts's {@link classifyDisposition}) to make that distinction,
 * which drives a three-way status:
 *
 *   - **🟢 clean** — no alerts since the block. The block held (or the attacker
 *     moved on). The desired outcome.
 *   - **🟡 stubborn** — post-block alerts exist but the gateway *blocked* them all
 *     (none passed). Enforcement is working; the attacker just won't quit. Noise,
 *     not exposure — but worth a wider edge block if the volume is high.
 *   - **🔴 leaking** — at least one post-block alert was *let through* (passed).
 *     The block exists in the list but traffic is still reaching you. This is the
 *     headline finding: the ipset/iptables DROP may not have applied, the rule may
 *     be detection-only, or the block was never pushed to the gateway. Re-apply it
 *     and confirm enforcement.
 *
 * A separate **cleanup roll-up** flags *stale* blocks — IPs that have been silent
 * for the entire window despite being blocked before it began. Blocklists grow
 * monotonically (the responder only ever adds); a long-silent entry is a safe
 * candidate to retire so the active list stays meaningful and the ipset stays
 * lean.
 *
 * Honest caveats baked into the output:
 *
 *   - **Source-side match.** Alerts are attributed to a blocked IP by `srcIp`
 *     (blocks target attacker sources). An attack *toward* a blocked IP, or one
 *     that only names it in the raw line, is not counted.
 *   - **Alerts, not flows.** SecTool stores IPS *detections*. A blocked IP whose
 *     traffic is silently dropped by the firewall before any rule fires generates
 *     *no* alert — which correctly reads as **clean** here. "Clean" means "no
 *     detections since the block", which is exactly what an effective block looks
 *     like, but a detection-free *bypass* (rare) would also look clean.
 *   - **Window-bounded & store-capped.** Post-block activity older than the
 *     look-back (or evicted past the store's history cap) is invisible; a long
 *     look-back can hit the cap and undercount. The block timestamp itself is not
 *     windowed — every current block is audited regardless of its age.
 *
 * Pure in-memory math over alertStore + blockStore (plus watchlist / safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring report.ts, efficacy.ts,
 * persistence.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore, type BlockEntry } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** The three-way post-block effectiveness verdict for a blocked IP. */
export type BlockStatus = "clean" | "stubborn" | "leaking";

/** Blocked / passed / unknown disposition split for a source's post-block hits. */
export interface DispositionSplit {
  /** Post-block alerts the gateway actively blocked / dropped. */
  blocked: number;
  /** Post-block alerts the gateway logged but let through (the leak signal). */
  passed: number;
  /** Post-block alerts with no recorded action (excluded from {@link passRate}). */
  unknown: number;
  /**
   * Fraction of *actioned* (blocked + passed) post-block alerts that were let
   * through, 0..1 (4dp), or null when nothing was actioned. Any non-zero value on
   * a blocked IP is an enforcement gap.
   */
  passRate: number | null;
}

/** Per-blocked-IP recidivism metrics over the window. */
export interface BlockedSource {
  /** The blocked source IP. */
  ip: string;
  /** When the IP was blocked (epoch ms, from the blocklist). */
  blockedAt: number;
  /** Why it was blocked, if a reason was recorded. */
  reason?: string;
  /** Who/what placed the block (responder, user, …), if recorded. */
  by?: string;
  /** The three-way effectiveness verdict. */
  status: BlockStatus;
  /**
   * True when the block predates the window *and* the IP was silent for the whole
   * window — a safe candidate to retire from the blocklist.
   */
  staleCandidate: boolean;
  /** Alerts in the window from this source *before* the block (context). */
  preBlock: number;
  /** Alerts in the window from this source *after* the block (recidivism). */
  postBlock: number;
  /** Disposition split of the {@link postBlock} alerts. */
  disposition: DispositionSplit;
  /** Post-block alerts at medium severity or worse. */
  postSevere: number;
  /** Severity-weighted score (Σ SEVERITY_WEIGHT) of the post-block alerts. */
  postScore: number;
  /** Worst severity seen in the post-block alerts. */
  postSeverityMax: Severity;
  /** Most-recent alert time from this source in the window, or undefined. */
  lastSeenMs?: number;
  /** Most-recent *post-block* alert time, or undefined if none. */
  lastPostBlockMs?: number;
  /** The loudest signature in the post-block alerts, if any. */
  topSignature?: string;
  /** The IP is also on the watchlist. */
  watched: boolean;
  /** The IP is marked safe (a contradiction worth surfacing). */
  safe: boolean;
}

/** Headline counts across all audited blocks. */
export interface StatusCounts {
  clean: number;
  stubborn: number;
  leaking: number;
}

export interface RecidivismReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Total IPs currently on the blocklist (the audited universe). */
  totalBlocked: number;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Of those, alerts whose source is a currently-blocked IP. */
  blockedSourceAlerts: number;
  /** Post-block alerts let through (passed) summed across every blocked IP. */
  totalLeaked: number;
  /** How many blocked IPs fell into each status. */
  statusCounts: StatusCounts;
  /** Per-blocked-IP rows, leaks first then stubborn then clean. */
  sources: BlockedSource[];
  /** Stale blocks (silent the whole window) — cleanup candidates, oldest first. */
  staleCandidates: BlockedSource[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface RecidivismOptions {
  /** Max rows in the per-source table (clamped to [1, 500]). */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 30;
const MS_PER_HOUR = 3_600_000;

// ----- classifiers / helpers (mirror efficacy.ts / persistence.ts) ----------

/** A valid, non-empty IP, or undefined if the field is missing/garbage. */
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

/** Humanise a duration in ms as a compact "3d 4h" / "5h" / "12m" / "just now". */
function fmtDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  const mins = Math.floor(ms / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) {
    const m = mins % 60;
    return m ? `${hours}h ${m}m` : `${hours}h`;
  }
  const days = Math.floor(hours / 24);
  const h = hours % 24;
  return h ? `${days}d ${h}h` : `${days}d`;
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

function topOf(counts: Map<string, number>): { key?: string; count: number } {
  let key: string | undefined;
  let count = 0;
  for (const [k, c] of counts) {
    if (c > count || (c === count && key !== undefined && k < key)) {
      key = k;
      count = c;
    }
  }
  return { key, count };
}

/** Human label + emoji for a status, reading at a glance. */
function statusLabel(s: BlockStatus): string {
  switch (s) {
    case "clean":
      return "🟢 clean";
    case "stubborn":
      return "🟡 stubborn";
    case "leaking":
      return "🔴 leaking";
  }
}

/** Sort weight so leaks float to the top, then stubborn, then clean. */
function statusRank(s: BlockStatus): number {
  switch (s) {
    case "leaking":
      return 3;
    case "stubborn":
      return 2;
    case "clean":
      return 1;
  }
}

// ----- aggregation ----------------------------------------------------------

interface SourceAcc {
  pre: number;
  post: number;
  blocked: number;
  passed: number;
  unknown: number;
  postSevere: number;
  postScore: number;
  postSeverityMax: Severity;
  lastSeen: number;
  lastPost: number;
  sigCounts: Map<string, number>;
}

function newSourceAcc(): SourceAcc {
  return {
    pre: 0,
    post: 0,
    blocked: 0,
    passed: 0,
    unknown: 0,
    postSevere: 0,
    postScore: 0,
    postSeverityMax: "info",
    lastSeen: 0,
    lastPost: 0,
    sigCounts: new Map(),
  };
}

function classifyStatus(acc: SourceAcc): BlockStatus {
  if (acc.post === 0) return "clean";
  if (acc.passed > 0) return "leaking";
  return "stubborn";
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  hours: number,
  nowMs: number,
  m: { totalBlocked: number; blockedSourceAlerts: number; totalLeaked: number },
  statusCounts: StatusCounts,
  sources: BlockedSource[],
  staleCandidates: BlockedSource[],
): string[] {
  const out: string[] = [];
  if (!m.totalBlocked) return out;

  // Overview — the effectiveness distribution across the whole blocklist.
  out.push(
    `🚫 Over the last ${hours}h, audited **${m.totalBlocked} blocked IP(s)** against the alert stream: ` +
      `**${statusCounts.leaking} leaking** (still getting through), **${statusCounts.stubborn} stubborn** ` +
      `(re-tripping but dropped), **${statusCounts.clean} clean** (silent since block).`,
  );

  // Leaks are the headline — blocks that aren't actually stopping traffic.
  const leaks = sources.filter((s) => s.status === "leaking");
  if (leaks.length) {
    const lead = leaks[0]!;
    out.push(
      `🔴 **${leaks.length} block(s) are leaking** — traffic still passed the gateway *after* the block was placed. ` +
        `Worst is \`${lead.ip}\`: **${lead.disposition.passed} post-block alert(s) let through** ` +
        `(${lead.disposition.passRate === null ? "—" : pct(lead.disposition.passRate)} of actioned), last seen ` +
        `${lead.lastPostBlockMs ? fmtDuration(nowMs - lead.lastPostBlockMs) + " ago" : "—"}. ` +
        `Re-apply the firewall block and confirm the ipset/iptables DROP actually took.`,
    );
  } else if (m.totalBlocked) {
    out.push(
      `✅ **No leaking blocks** — every blocked IP that re-tripped a rule was dropped by the gateway. The blocklist ` +
        `is being enforced where it matters.`,
    );
  }

  // Stubborn but contained — enforcement works, attacker won't quit.
  const stubborn = sources.filter((s) => s.status === "stubborn");
  if (stubborn.length) {
    const lead = stubborn[0]!;
    out.push(
      `🟡 **${stubborn.length} stubborn block(s)** keep re-tripping rules but are being dropped. Loudest is ` +
        `\`${lead.ip}\` with ${lead.postBlock} post-block detection(s), all blocked — contained, but a noisy ` +
        `source worth a wider edge/ASN block if the volume bites.`,
    );
  }

  // The aggregate leak — total traffic that got through despite a block.
  if (m.totalLeaked > 0) {
    out.push(
      `⚠️ Across all blocks, **${m.totalLeaked} post-block alert(s) were let through** in total — each one is a ` +
        `source we *decided* to drop yet the gateway allowed. Treat the leaking rows as enforcement bugs, not noise.`,
    );
  }

  // Cleanup opportunity — long-silent blocks that can be retired.
  if (staleCandidates.length) {
    const oldest = staleCandidates[0]!;
    out.push(
      `🧹 **${staleCandidates.length} block(s) have been silent the entire window** (blocked before it began, no ` +
        `activity since) — safe candidates to retire so the active blocklist stays meaningful. Oldest: \`${oldest.ip}\`, ` +
        `blocked ${fmtDuration(nowMs - oldest.blockedAt)} ago.`,
    );
  }

  // A safelisted IP that is also blocked is a contradictory control — surface it.
  const contradictory = sources.filter((s) => s.safe);
  if (contradictory.length) {
    out.push(
      `❗ **${contradictory.length} blocked IP(s) are *also* marked safe** (e.g. \`${contradictory[0]!.ip}\`) — ` +
        `contradictory controls. Decide which wins and remove the other to avoid confusing future triage.`,
    );
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function sourceTable(rows: BlockedSource[], nowMs: number): string {
  return mdTable(
    ["#", "Source", "Status", "Blocked", "By", "Post-block", "Passed", "Dropped", "Peak sev", "Last post-block", "Flags"],
    rows.map((s, i) => {
      const flags =
        (s.staleCandidate ? "🧹" : "") + (s.watched ? "👁" : "") + (s.safe ? "✅" : "");
      const lastPost = s.lastPostBlockMs ? `${fmtDuration(nowMs - s.lastPostBlockMs)} ago` : "—";
      return [
        String(i + 1),
        cell(s.ip),
        cell(statusLabel(s.status)),
        cell(`${fmtDuration(nowMs - s.blockedAt)} ago`),
        cell(s.by ? clip(s.by, 18) : "—"),
        String(s.postBlock),
        String(s.disposition.passed),
        String(s.disposition.blocked),
        cell(s.postBlock ? s.postSeverityMax : "—"),
        cell(lastPost),
        flags || "—",
      ];
    }),
  );
}

function staleTable(rows: BlockedSource[], nowMs: number): string {
  return mdTable(
    ["#", "Source", "Blocked", "By", "Reason"],
    rows.map((s, i) => [
      String(i + 1),
      cell(s.ip),
      cell(`${fmtDuration(nowMs - s.blockedAt)} ago`),
      cell(s.by ? clip(s.by, 18) : "—"),
      cell(s.reason ? clip(s.reason, 48) : "—"),
    ]),
  );
}

function renderMarkdown(m: RecidivismReport): string {
  const lines: string[] = [];
  lines.push(`# 🚫 SecTool Block-Effectiveness / Post-Block Recidivism Audit`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** every IP on the blocklist, with its windowed alerts split on the block timestamp ` +
      `(\`time < at\` = pre-block context, \`time >= at\` = post-block recidivism) and the post-block alerts ` +
      `classified by gateway disposition · **Blocked IPs audited:** ${m.totalBlocked} · ` +
      `**Blocked-source alerts in window:** ${m.blockedSourceAlerts} of ${m.totalWindowAlerts}`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.totalBlocked) {
    lines.push(
      `The blocklist is **empty** — there are no firewall blocks to audit. Once SecTool (or you) blocks a source, ` +
        `this report tracks whether the traffic actually stopped afterwards.`,
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Blocked sources by post-block recidivism`);
  lines.push("");
  if (!m.sources.length) {
    lines.push(`_No blocked IP could be matched to a windowed alert._`);
  } else {
    lines.push(sourceTable(m.sources, m.windowEndMs));
    lines.push("");
    lines.push(
      `**Legend:** _Status_ — **🟢 clean** (no alerts since the block: it held) · **🟡 stubborn** (re-tripping but ` +
        `every post-block hit was dropped: enforcement works, attacker persists) · **🔴 leaking** (≥1 post-block ` +
        `alert *let through*: the block isn't stopping the traffic — re-apply and confirm). _Post-block_ = alerts ` +
        `from this source at/after its block time; _Passed_ of those is the leak. **Flags:** 🧹 silent all window ` +
        `(retire candidate) · 👁 watched · ✅ marked safe (contradicts the block).`,
    );
  }
  lines.push("");

  lines.push(`## Cleanup candidates — stale blocks`);
  lines.push("");
  if (!m.staleCandidates.length) {
    lines.push(
      `_No stale blocks._ Every block either predates the window with no activity removed, or has been active within ` +
        `it. (A block is "stale" when it predates the window **and** the source was silent for the whole window.)`,
    );
  } else {
    lines.push(
      `These IPs were blocked *before* this window began and produced **no alerts at all** during it — they are safe ` +
        `to retire from the blocklist so the active set (and the ipset behind it) stays lean and meaningful.`,
    );
    lines.push("");
    lines.push(staleTable(m.staleCandidates, m.windowEndMs));
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Alerts are matched to a blocked IP by **source address** (\`srcIp\`); blocks ` +
      `target attacker sources, so traffic *toward* a blocked IP is not counted. These are IPS **detections**, not ` +
      `full flows — an effective firewall block produces *no* detections, which correctly reads as **clean** here, so ` +
      `"clean" means "no detections since the block". The block timestamp is taken from the blocklist and is **not** ` +
      `windowed (every current block is audited regardless of age), but post-block *activity* older than the ` +
      `look-back, or evicted past the store's history cap, is invisible. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the block-effectiveness / post-block recidivism audit from the stored
 * blocklist and alert history.
 *
 * @param hours Look-back window in hours for *alert activity* (clamped to
 *              [1, 90 days]). The blocklist itself is audited in full regardless
 *              of window — only the alerts attributed to each block are windowed.
 * @param opts  {@link RecidivismOptions}: `limit` and a `nowMs` pin for tests.
 */
export function buildRecidivism(hours: number, opts: RecidivismOptions = {}): RecidivismReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(500, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const blocks: BlockEntry[] = blockStore.all();
  const blockedIps = new Map<string, BlockEntry>();
  for (const b of blocks) if (b?.ip) blockedIps.set(b.ip, b);

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  // Index windowed alerts by source IP, but only for IPs we actually blocked —
  // a blocklist is small, so this keeps the pass over the alert stream cheap.
  const accs = new Map<string, SourceAcc>();
  let blockedSourceAlerts = 0;

  for (const a of windowed) {
    const src = validIp(a.srcIp);
    if (!src) continue;
    const entry = blockedIps.get(src);
    if (!entry) continue;
    blockedSourceAlerts++;

    const acc = accs.get(src) ?? newSourceAcc();
    if (!accs.has(src)) accs.set(src, acc);

    acc.lastSeen = Math.max(acc.lastSeen, a.time);
    if (a.time < entry.at) {
      acc.pre++;
      continue;
    }

    // Post-block activity — the recidivism signal.
    acc.post++;
    acc.postScore += weightOf(a.severity);
    acc.postSeverityMax = maxSeverity(acc.postSeverityMax, a.severity);
    if (isSevere(a.severity)) acc.postSevere++;
    acc.lastPost = Math.max(acc.lastPost, a.time);
    const disp = classifyDisposition(a.action);
    if (disp === "blocked") acc.blocked++;
    else if (disp === "passed") acc.passed++;
    else acc.unknown++;
    const sig = a.signature?.trim();
    if (sig) acc.sigCounts.set(sig, (acc.sigCounts.get(sig) ?? 0) + 1);
  }

  const statusCounts: StatusCounts = { clean: 0, stubborn: 0, leaking: 0 };
  let totalLeaked = 0;

  const sources: BlockedSource[] = [...blockedIps.values()].map((entry) => {
    const acc = accs.get(entry.ip) ?? newSourceAcc();
    const status = classifyStatus(acc);
    statusCounts[status]++;
    totalLeaked += acc.passed;
    const actioned = acc.blocked + acc.passed;
    // Stale = blocked before the window started AND no activity at all in-window.
    const staleCandidate =
      entry.at < windowStartMs && acc.pre === 0 && acc.post === 0 && acc.lastSeen === 0;
    const sig = topOf(acc.sigCounts);
    return {
      ip: entry.ip,
      blockedAt: entry.at,
      reason: entry.reason,
      by: entry.by,
      status,
      staleCandidate,
      preBlock: acc.pre,
      postBlock: acc.post,
      disposition: {
        blocked: acc.blocked,
        passed: acc.passed,
        unknown: acc.unknown,
        passRate: actioned ? round4(acc.passed / actioned) : null,
      },
      postSevere: acc.postSevere,
      postScore: acc.postScore,
      postSeverityMax: acc.postSeverityMax,
      lastSeenMs: acc.lastSeen || undefined,
      lastPostBlockMs: acc.lastPost || undefined,
      topSignature: sig.key,
      watched: watchStore.has(entry.ip),
      safe: safeStore.has(entry.ip),
    } satisfies BlockedSource;
  });

  // Worst first: leaks (by passed volume), then stubborn (by post-block volume),
  // then clean — within a tier, more let-through / louder / higher score first.
  sources.sort(
    (x, y) =>
      statusRank(y.status) - statusRank(x.status) ||
      y.disposition.passed - x.disposition.passed ||
      y.postBlock - x.postBlock ||
      y.postScore - x.postScore ||
      (x.ip < y.ip ? -1 : x.ip > y.ip ? 1 : 0),
  );

  // Stale candidates, oldest block first — the longest-silent are safest to drop.
  const staleCandidates = sources
    .filter((s) => s.staleCandidate)
    .sort((x, y) => x.blockedAt - y.blockedAt)
    .slice(0, limit);

  const highlights = writeHighlights(
    safeHours,
    windowEndMs,
    { totalBlocked: blockedIps.size, blockedSourceAlerts, totalLeaked },
    statusCounts,
    sources,
    staleCandidates,
  );

  const model: RecidivismReport = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalBlocked: blockedIps.size,
    totalWindowAlerts: windowed.length,
    blockedSourceAlerts,
    totalLeaked,
    statusCounts,
    sources: sources.slice(0, limit),
    staleCandidates,
    highlights,
    markdown: "",
  };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded block-effectiveness report. */
export function recidivismFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-recidivism-${stamp}.md`;
}
