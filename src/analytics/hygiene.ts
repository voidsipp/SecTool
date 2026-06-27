/**
 * Blocklist hygiene / stale-IOC report — "my blocklist keeps growing; which
 * entries still earn their keep, and which are dead weight I can safely prune?"
 *
 * Every other offline report in this project reads the alert history to rank
 * *threats* — the worst source (persistence, netblock, focus), the besieged
 * target (targets.ts), the coordinated botnet (cluster.ts), what the gateway
 * blocked vs. let through (efficacy.ts). None of them turn the lens around and
 * audit **the blocklist itself** as an aging operational asset.
 *
 * That is a real, recurring defender problem. SecTool's blocker enforces with an
 * ipset + iptables DROP (see respond/blocker.ts), and the blocklist only ever
 * *grows* — reactive blocks, manual blocks and intel blocks all accrete. An
 * unbounded blocklist is not free: it bloats the ruleset, slows provisioning,
 * and — worst of all — buries the handful of entries that genuinely matter under
 * a pile of stale ones nobody dares touch. SOCs prune periodically, but pruning
 * *blind* is dangerous: remove an IP that is still hammering you and it walks
 * straight back in. The question this report exists to answer is therefore:
 *
 *   **"For every IP on my blocklist, is it still trying to reach me (proven
 *    hostile — keep), has it gone silent since I blocked it (the threat moved on
 *    — candidate to prune), or did it never fire an alert here at all (a
 *    preemptive intel/manual block I can't judge from detections alone)?"**
 *
 * How each entry is classified (deterministic, no ML, fully auditable):
 *
 *   1. Scan the **entire** stored alert history (not just the window) for alerts
 *      whose source was this IP — we need the last-seen timestamp regardless of
 *      age to tell "dormant" from "never fired".
 *   2. Split that activity around the block timestamp (`at`): alerts **before**
 *      the block are the justification trail; alerts **at-or-after** the block
 *      are post-block detections (the IP is still being seen by the IPS engine).
 *   3. Assign a **status**:
 *        - **active** — fired at least one alert inside the freshness window
 *          (last `hours`): still hostile, the block is earning its keep → *keep*.
 *        - **dormant** — fired historically but nothing in the freshness window:
 *          the threat appears to have moved on → *prune-candidate*. The longer it
 *          has been silent, the safer the prune.
 *        - **unverified** — never fired any alert in the stored history: almost
 *          certainly a preemptive (intel feed / manual) block, OR its alerts have
 *          rotated out of the capped store. Cannot be judged from detections →
 *          *review* (don't auto-prune; you blocked it for a reason off-platform).
 *
 * Each entry also carries a **hostility** number = Σ `SEVERITY_WEIGHT[severity]`
 * over its alerts (the same geometric info 1 · low 3 · medium 9 · high 27 ·
 * critical 81 ladder risk.ts/targets.ts use, imported so the weighting is shared
 * and auditable). A high-hostility dormant entry was a *real* threat that has
 * since gone quiet — worth keeping longer than a low-hostility one — so prune
 * candidates are ranked by dormancy age but the hostility column lets an operator
 * hold the heavy hitters back.
 *
 * Two cross-checks that catch genuine misconfiguration are surfaced loudly:
 *
 *   - **Safelisted AND blocklisted** — an IP on both lists is a contradiction
 *     (one says "always allow", the other "always drop"); the report flags every
 *     such entry so the operator can resolve the conflict.
 *   - **Still passing post-block** — an entry that keeps firing *passed* (not
 *     blocked-action) alerts after its block timestamp may not actually be
 *     enforced on the live gateway (a leaky / drifted block); flagged for a
 *     re-provision check. (Detections that log *before* the DROP are normal, so
 *     this is a soft signal, read alongside recency.)
 *
 * Honest caveats baked into the output:
 *
 *   - **Absence of alerts ≠ absence of threat.** A dormant entry might be quiet
 *     *because the block works* (packets dropped before they can trip a rule).
 *     Pruning it could invite the source back. Dormancy age is the mitigant: the
 *     longer the silence, the lower that risk — but it is never zero.
 *   - **Store-capped history.** The alert store keeps only the most recent
 *     {@link ALERT_STORE_CAP} alerts; an "unverified" entry may simply have had
 *     its evidence rotated out. The report warns when the store is at its cap.
 *   - **Detections, not flows.** Activity reflects what *tripped an IPS rule*,
 *     not raw packets — a calm entry is not proof the source is gone.
 *   - **Hostility is a heuristic** severity-weighted volume; read it as relative.
 *
 * Pure in-memory math over blockStore + alertStore (plus watchlist/safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring targets.ts, cluster.ts,
 * efficacy.ts and the other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, ALERT_STORE_CAP } from "../store/alertStore.ts";
import { blockStore, type BlockEntry } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_WEIGHT } from "./risk.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Lifecycle status of a single blocklist entry, judged from alert recency. */
export type BlockStatus = "active" | "dormant" | "unverified";

/** What to do with the entry, derived from {@link BlockStatus}. */
export type BlockRecommendation = "keep" | "prune-candidate" | "review";

/** One blocklist entry audited against the stored alert history. */
export interface BlockHealth {
  /** The blocked IP. */
  ip: string;
  /** Epoch ms the block was added. */
  blockedAtMs: number;
  /** How the block was justified, if recorded. */
  reason?: string;
  /** Who/what added the block (e.g. "auto", an operator), if recorded. */
  by?: string;
  /** Lifecycle status from alert recency. */
  status: BlockStatus;
  /** The pruning recommendation derived from {@link status}. */
  recommendation: BlockRecommendation;
  /** Total alerts from this IP across the *entire* stored history. */
  totalAlerts: number;
  /** Of {@link totalAlerts}, those before the block timestamp (the justification). */
  alertsBeforeBlock: number;
  /** Of {@link totalAlerts}, those at-or-after the block timestamp (post-block). */
  alertsAfterBlock: number;
  /** Of {@link alertsAfterBlock}, those the gateway did NOT block (possible leak). */
  passedAfterBlock: number;
  /** Alerts from this IP inside the freshness window (last `hours`). */
  windowAlerts: number;
  /** Worst severity this IP ever reached. */
  severityMax: Severity;
  /** Alerts at medium severity or worse. */
  severe: number;
  /** Severity-weighted hostility (Σ severity weight) over all this IP's alerts. */
  hostility: number;
  /** Epoch ms of this IP's most recent alert (any time), or 0 if never seen. */
  lastSeenMs: number;
  /** Epoch ms of this IP's first alert, or 0 if never seen. */
  firstSeenMs: number;
  /** How long the entry has been silent (now − lastSeen), ms; 0 if active/never-seen handled in render. */
  dormantMs: number;
  /** The single most frequent signature fired by this IP. */
  topSignature?: string;
  /** The IP is also on the watchlist. */
  watched: boolean;
  /** The IP is ALSO on the safelist — a contradiction worth resolving. */
  safeConflict: boolean;
}

export interface HygieneReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Total entries on the blocklist right now. */
  totalBlocks: number;
  /** Blocks whose source still fired inside the freshness window (keep). */
  activeBlocks: number;
  /** Blocks that fired historically but not in the window (prune candidates). */
  dormantBlocks: number;
  /** Blocks that never fired any alert in the stored history (review). */
  unverifiedBlocks: number;
  /** Entries flagged as also safelisted (a config contradiction). */
  safeConflicts: number;
  /** Entries still firing *passed* alerts after their block (possible leak). */
  leakyBlocks: number;
  /** Blocks added by automation (`by` looks automated). */
  autoBlocks: number;
  /** Blocks added manually / by an operator. */
  manualBlocks: number;
  /** dormantBlocks / totalBlocks, 0..1 (4dp) — share of the list that is dead weight. */
  staleRatio: number;
  /** Total alerts the whole blocklist accounts for (justification volume). */
  alertsAttributed: number;
  /** True when the alert store is at/near its cap (history may be truncated). */
  storeNearCap: boolean;
  /** Active entries, ranked by recent activity (the ones working hardest). */
  topActive: BlockHealth[];
  /** Dormant entries, ranked by dormancy age (longest-silent first = safest prune). */
  topDormant: BlockHealth[];
  /** Unverified entries, ranked by age (oldest preemptive blocks first). */
  topUnverified: BlockHealth[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface HygieneOptions {
  /** Max rows in each (active / dormant / unverified) table (clamped to [1, 100]). */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 15;
const MS_PER_HOUR = 3_600_000;

// ----- formatting helpers (mirror targets.ts / cluster.ts) ------------------

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
function clip(s: string, max = 40): string {
  const t = s.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

// ----- classifiers ----------------------------------------------------------

function sevRank(s: string | undefined): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? 0 : i;
}

function asSeverity(s: string | undefined): Severity {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s ?? "");
  return i < 0 ? "info" : (s as Severity);
}

function maxSeverity(a: Severity, b: string | undefined): Severity {
  if (!b) return a;
  return sevRank(b) > sevRank(a) ? asSeverity(b) : a;
}

function isSevere(s: string | undefined): boolean {
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
function topOf(map: Map<string, number>): string | undefined {
  let bestKey: string | undefined;
  let best = 0;
  for (const [k, c] of map) {
    if (c > best || (c === best && bestKey !== undefined && k < bestKey)) {
      best = c;
      bestKey = k;
    }
  }
  return bestKey;
}

/**
 * Whether a block's `by` field looks like it came from automation rather than a
 * human operator. Reactive/auto blocks record machine-ish actors ("auto",
 * "reactive", "honeypot"); anything else (or absent) is treated as manual so we
 * never over-claim automation.
 */
function looksAutomated(by: string | undefined): boolean {
  const b = (by ?? "").trim().toLowerCase();
  if (!b) return false;
  return /auto|reactive|honeypot|baseline|system|agent|rule/.test(b);
}

// ----- per-IP alert aggregation ---------------------------------------------

interface IpActivity {
  total: number;
  before: number;
  after: number;
  passedAfter: number;
  window: number;
  severityMax: Severity;
  severe: number;
  hostility: number;
  firstMs: number;
  lastMs: number;
  signatures: Map<string, number>;
}

function newActivity(): IpActivity {
  return {
    total: 0,
    before: 0,
    after: 0,
    passedAfter: 0,
    window: 0,
    severityMax: "info",
    severe: 0,
    hostility: 0,
    firstMs: 0,
    lastMs: 0,
    signatures: new Map(),
  };
}

/**
 * Index the *entire* stored alert history by source IP, but only for the set of
 * IPs that are actually on the blocklist (so a huge store doesn't build a map of
 * every attacker that ever existed). `blockedAt` lets us split each IP's
 * activity around its own block timestamp in a single pass.
 */
function indexActivity(
  blockedAt: Map<string, number>,
  windowStartMs: number,
  windowEndMs: number,
): Map<string, IpActivity> {
  const out = new Map<string, IpActivity>();
  for (const a of alertStore.all()) {
    const src = validIp(a.srcIp);
    if (!src || !blockedAt.has(src)) continue;
    if (typeof a.time !== "number" || !Number.isFinite(a.time)) continue;

    let act = out.get(src);
    if (!act) {
      act = newActivity();
      out.set(src, act);
    }
    act.total++;
    const severity = asSeverity(a.severity);
    act.hostility += SEVERITY_WEIGHT[severity];
    act.severityMax = maxSeverity(act.severityMax, severity);
    if (isSevere(severity)) act.severe++;

    const at = blockedAt.get(src)!;
    if (a.time >= at) {
      act.after++;
      if (classifyDisposition(a.action) === "passed") act.passedAfter++;
    } else {
      act.before++;
    }
    if (a.time >= windowStartMs && a.time <= windowEndMs) act.window++;

    if (act.firstMs === 0 || a.time < act.firstMs) act.firstMs = a.time;
    if (a.time > act.lastMs) act.lastMs = a.time;

    const sig = a.signature?.trim();
    if (sig) bump(act.signatures, sig);
  }
  return out;
}

// ----- per-entry assembly ----------------------------------------------------

function assess(entry: BlockEntry, act: IpActivity | undefined, nowMs: number): BlockHealth {
  const windowAlerts = act?.window ?? 0;
  const totalAlerts = act?.total ?? 0;
  const lastSeenMs = act?.lastMs ?? 0;

  let status: BlockStatus;
  if (windowAlerts > 0) status = "active";
  else if (totalAlerts > 0) status = "dormant";
  else status = "unverified";

  const recommendation: BlockRecommendation =
    status === "active" ? "keep" : status === "dormant" ? "prune-candidate" : "review";

  // Dormancy is measured from the last alert (dormant) or, when the IP never
  // fired, from when it was blocked (how long it has sat unproven).
  const dormantMs =
    status === "dormant"
      ? Math.max(0, nowMs - lastSeenMs)
      : status === "unverified"
        ? Math.max(0, nowMs - entry.at)
        : 0;

  return {
    ip: entry.ip,
    blockedAtMs: entry.at,
    reason: entry.reason,
    by: entry.by,
    status,
    recommendation,
    totalAlerts,
    alertsBeforeBlock: act?.before ?? 0,
    alertsAfterBlock: act?.after ?? 0,
    passedAfterBlock: act?.passedAfter ?? 0,
    windowAlerts,
    severityMax: act?.severityMax ?? "info",
    severe: act?.severe ?? 0,
    hostility: round1(act?.hostility ?? 0),
    lastSeenMs,
    firstSeenMs: act?.firstMs ?? 0,
    dormantMs,
    topSignature: act ? topOf(act.signatures) : undefined,
    watched: watchStore.has(entry.ip),
    safeConflict: safeStore.has(entry.ip),
  } satisfies BlockHealth;
}

// ----- highlights -----------------------------------------------------------

function writeHighlights(
  m: Omit<HygieneReport, "highlights" | "markdown">,
  nowMs: number,
): string[] {
  const out: string[] = [];
  if (!m.totalBlocks) {
    out.push(
      `🧹 The blocklist is **empty** — nothing to audit. As reactive/manual/intel blocks accumulate, this report ` +
        `will tell you which ones are still earning their keep and which have gone stale and can be pruned.`,
    );
    return out;
  }

  out.push(
    `🧹 Auditing **${m.totalBlocks.toLocaleString("en-US")} blocklist entr(y/ies)** against the stored alert history: ` +
      `**${m.activeBlocks} active** (still firing in the last ${m.hours}h — keep), ` +
      `**${m.dormantBlocks} dormant** (gone quiet — prune candidates, ${pct(m.staleRatio)} of the list), ` +
      `**${m.unverifiedBlocks} unverified** (never fired here — preemptive/intel blocks to review). ` +
      `${m.manualBlocks} manual / ${m.autoBlocks} automated.`,
  );

  // The pruning headline — the whole reason to run this.
  if (m.dormantBlocks > 0) {
    const oldest = m.topDormant[0];
    out.push(
      `✂️ **${m.dormantBlocks} entr(y/ies) are prune candidates** — they fired historically but nothing in the last ` +
        `${m.hours}h, so the threat appears to have moved on. Pruning them keeps the ipset lean without losing live ` +
        `coverage. Safest to remove first are the longest-silent` +
        (oldest ? `, led by \`${oldest.ip}\` (silent ${fmtAge(oldest.lastSeenMs, nowMs)}, hostility ${oldest.hostility})` : "") +
        `. Hold back any with high *hostility* — those were real threats that merely went quiet.`,
    );
  } else {
    out.push(
      `✅ **No dormant entries** — every blocklisted IP that ever fired here is still active within the window, so the ` +
        `list carries no obvious dead weight from proven-hostile sources.`,
    );
  }

  // Config-contradiction call-out: an IP on both block and safe lists.
  if (m.safeConflicts > 0) {
    out.push(
      `⚠️ **${m.safeConflicts} entr(y/ies) are on BOTH the blocklist and the safelist** — a direct contradiction ` +
        `(one says always-drop, the other always-allow). Resolve each: drop it from whichever list no longer reflects ` +
        `your intent. This is a misconfiguration, not a tuning choice.`,
    );
  }

  // Possible-leak call-out: still passing traffic after the block.
  if (m.leakyBlocks > 0) {
    out.push(
      `🚧 **${m.leakyBlocks} entr(y/ies) kept firing *passed* (un-dropped) alerts AFTER being blocked** — the DROP may ` +
        `not be live on the gateway (a drifted/leaky block). Re-provision the blocker and confirm the ipset is applied. ` +
        `(Detections logged *before* the drop are normal, so cross-check recency before acting.)`,
    );
  }

  // Unverified guidance — don't blindly prune intel blocks.
  if (m.unverifiedBlocks > 0) {
    out.push(
      `🔎 **${m.unverifiedBlocks} entr(y/ies) never fired an alert here** — almost certainly preemptive blocks from an ` +
        `intel feed or a manual decision. They cannot be judged from detections; **do not auto-prune** them. Treat as ` +
        `*review*: keep if you still trust the source intel, drop if you no longer remember why it is there.` +
        (m.storeNearCap
          ? ` (Note: the alert store is near its ${ALERT_STORE_CAP.toLocaleString("en-US")}-entry cap, so some of these may simply have aged out of history.)`
          : ""),
    );
  }

  // The hardest-working entry — reassurance the list is doing something.
  const busiest = m.topActive[0];
  if (busiest) {
    out.push(
      `🛡️ Hardest-working block: \`${busiest.ip}\` — **${busiest.windowAlerts} alert(s) in the last ${m.hours}h** ` +
        `(${busiest.totalAlerts} all-time, peak ${busiest.severityMax}, hostility ${busiest.hostility}). This entry is ` +
        `actively stopping a source that is still trying — definitively keep.`,
    );
  }

  return out;
}

// ----- markdown -------------------------------------------------------------

function activeTable(rows: BlockHealth[], nowMs: number): string {
  return mdTable(
    ["#", "IP", "Window", "All-time", "Hostility", "Peak sev", "Post-block", "Blocked", "By", "Flags"],
    rows.map((r, i) => {
      const flags = (r.watched ? "👁" : "") + (r.safeConflict ? "⚠️" : "");
      return [
        String(i + 1),
        cell(r.ip),
        String(r.windowAlerts),
        String(r.totalAlerts),
        String(r.hostility),
        cell(r.severityMax),
        String(r.alertsAfterBlock),
        fmtAge(r.blockedAtMs, nowMs),
        cell(clip(r.by || "—", 14)),
        flags || "—",
      ];
    }),
  );
}

function dormantTable(rows: BlockHealth[], nowMs: number): string {
  return mdTable(
    ["#", "IP", "Silent for", "All-time", "Hostility", "Peak sev", "Last seen", "Blocked", "By", "Flags"],
    rows.map((r, i) => {
      const flags = (r.watched ? "👁" : "") + (r.safeConflict ? "⚠️" : "");
      return [
        String(i + 1),
        cell(r.ip),
        fmtAge(r.lastSeenMs, nowMs),
        String(r.totalAlerts),
        String(r.hostility),
        cell(r.severityMax),
        fmtTime(r.lastSeenMs),
        fmtAge(r.blockedAtMs, nowMs),
        cell(clip(r.by || "—", 14)),
        flags || "—",
      ];
    }),
  );
}

function unverifiedTable(rows: BlockHealth[], nowMs: number): string {
  return mdTable(
    ["#", "IP", "Blocked", "By", "Reason", "Flags"],
    rows.map((r, i) => {
      const flags = (r.watched ? "👁" : "") + (r.safeConflict ? "⚠️" : "");
      return [
        String(i + 1),
        cell(r.ip),
        fmtAge(r.blockedAtMs, nowMs),
        cell(clip(r.by || "—", 14)),
        cell(clip(r.reason || "—", 44)),
        flags || "—",
      ];
    }),
  );
}

function renderMarkdown(m: HygieneReport, nowMs: number): string {
  const lines: string[] = [];
  lines.push(`# 🧹 SecTool Blocklist Hygiene / Stale-IOC Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Freshness window:** last ${m.hours} hour(s) — an entry with no alert since ${fmtTime(m.windowStartMs)} ` +
      `is treated as dormant.`,
  );
  lines.push(
    `**Method:** every blocklist entry audited against the **entire** stored alert history. ` +
      `_active_ = fired in the window (keep) · _dormant_ = fired before, silent now (prune candidate) · ` +
      `_unverified_ = never fired here (intel/manual — review). Hostility = Σ severity weight ` +
      `(info 1 · low 3 · medium 9 · high 27 · critical 81).`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (!m.totalBlocks) {
    for (const h of m.highlights) lines.push(`- ${h}`);
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  lines.push(`| Metric | Value |`);
  lines.push(`| --- | --- |`);
  lines.push(`| Blocklist entries | ${m.totalBlocks.toLocaleString("en-US")} |`);
  lines.push(`| — active (keep) | ${m.activeBlocks.toLocaleString("en-US")} |`);
  lines.push(
    `| — dormant (prune candidates) | ${m.dormantBlocks.toLocaleString("en-US")} (${pct(m.staleRatio)}) |`,
  );
  lines.push(`| — unverified (review) | ${m.unverifiedBlocks.toLocaleString("en-US")} |`);
  lines.push(`| Manual / automated | ${m.manualBlocks.toLocaleString("en-US")} / ${m.autoBlocks.toLocaleString("en-US")} |`);
  if (m.safeConflicts) lines.push(`| ⚠️ Safelist conflicts | ${m.safeConflicts.toLocaleString("en-US")} |`);
  if (m.leakyBlocks) lines.push(`| 🚧 Possible leaks (passed post-block) | ${m.leakyBlocks.toLocaleString("en-US")} |`);
  lines.push(`| Alerts attributed to the list | ${m.alertsAttributed.toLocaleString("en-US")} |`);
  lines.push("");

  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  lines.push(`## Active blocks (still firing — keep)`);
  lines.push("");
  if (!m.topActive.length) {
    lines.push(`_No blocklisted IP fired an alert inside the freshness window — nothing here is provably "still hot"._`);
  } else {
    lines.push(
      `Entries whose source is **still trying** inside the last ${m.hours}h — the list is actively stopping these, so ` +
        `keep them. _Post-block_ is alerts seen at/after the block (a busy IPS still sees the source even as the gateway ` +
        `drops it). Flags: 👁 watchlisted · ⚠️ also safelisted (conflict).`,
    );
    lines.push("");
    lines.push(activeTable(m.topActive, nowMs));
  }
  lines.push("");

  lines.push(`## Dormant blocks (gone quiet — prune candidates)`);
  lines.push("");
  if (!m.topDormant.length) {
    lines.push(`_No dormant entries — every IP that ever fired here is still active. No dead weight from proven sources._`);
  } else {
    lines.push(
      `Entries that fired historically but have been **silent through the whole window** — the threat appears to have ` +
        `moved on, so these are the safest to prune (longest-silent first). Hold back high-_Hostility_ rows: those were ` +
        `real threats that merely went quiet, and removing the block could invite them back. Flags: 👁 watchlisted · ⚠️ safelist conflict.`,
    );
    lines.push("");
    lines.push(dormantTable(m.topDormant, nowMs));
  }
  lines.push("");

  lines.push(`## Unverified blocks (never fired here — review)`);
  lines.push("");
  if (!m.topUnverified.length) {
    lines.push(`_Every blocklist entry has fired at least one alert in the stored history — none are unverified._`);
  } else {
    lines.push(
      `Entries with **no alert in the stored history** — almost certainly preemptive blocks (intel feed / manual). They ` +
        `can't be judged from detections, so **don't auto-prune**: keep if you still trust the reason, drop if it's ` +
        `forgotten.` +
        (m.storeNearCap
          ? ` _The alert store is near its ${ALERT_STORE_CAP.toLocaleString("en-US")}-entry cap, so some evidence may have rotated out._`
          : ""),
    );
    lines.push("");
    lines.push(unverifiedTable(m.topUnverified, nowMs));
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool by auditing the **blocklist** against stored **IPS-alert** history. **Absence of ` +
      `alerts is not absence of threat**: a dormant entry may be quiet precisely *because the block works* (packets ` +
      `dropped before they can trip a rule), so pruning carries a residual risk that dormancy age mitigates but never ` +
      `eliminates. These are detections, not flows. The alert store keeps only the most recent ` +
      `${ALERT_STORE_CAP.toLocaleString("en-US")} alerts, so an "unverified" entry may simply have aged out. **Hostility** ` +
      `is a heuristic severity-weighted volume (info 1 · low 3 · medium 9 · high 27 · critical 81); read it as relative. ` +
      `No live gateway query was performed — this never modifies the blocklist, it only recommends._`,
  );
  lines.push("");
  return lines.join("\n");
}

// ----- ranking --------------------------------------------------------------

/** Active entries: busiest in the window first (working hardest), then all-time. */
function rankActive(rows: BlockHealth[], limit: number): BlockHealth[] {
  return [...rows]
    .sort(
      (x, y) =>
        y.windowAlerts - x.windowAlerts ||
        y.hostility - x.hostility ||
        y.totalAlerts - x.totalAlerts ||
        (x.ip < y.ip ? -1 : x.ip > y.ip ? 1 : 0),
    )
    .slice(0, limit);
}

/** Dormant entries: longest-silent first (safest to prune), then lowest hostility. */
function rankDormant(rows: BlockHealth[], limit: number): BlockHealth[] {
  return [...rows]
    .sort(
      (x, y) =>
        x.lastSeenMs - y.lastSeenMs || // older lastSeen (smaller ms) first
        x.hostility - y.hostility || // lower hostility = safer to drop
        (x.ip < y.ip ? -1 : x.ip > y.ip ? 1 : 0),
    )
    .slice(0, limit);
}

/** Unverified entries: oldest block first (longest sat unproven). */
function rankUnverified(rows: BlockHealth[], limit: number): BlockHealth[] {
  return [...rows]
    .sort(
      (x, y) =>
        x.blockedAtMs - y.blockedAtMs ||
        (x.ip < y.ip ? -1 : x.ip > y.ip ? 1 : 0),
    )
    .slice(0, limit);
}

/**
 * Build the blocklist hygiene / stale-IOC report from the persisted blocklist
 * and the stored alert history.
 *
 * @param hours Freshness window in hours — an entry with no alert in this window
 *              is "dormant" (clamped to [1, 90 days]). Defaults via the caller.
 * @param opts  {@link HygieneOptions}: `limit` (rows per table) and a `nowMs` pin.
 */
export function buildHygiene(hours: number, opts: HygieneOptions = {}): HygieneReport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(100, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  const entries = blockStore.all();
  const blockedAt = new Map<string, number>();
  for (const e of entries) blockedAt.set(e.ip, e.at);

  const activity = indexActivity(blockedAt, windowStartMs, windowEndMs);

  const health = entries.map((e) => assess(e, activity.get(e.ip), windowEndMs));

  const active = health.filter((h) => h.status === "active");
  const dormant = health.filter((h) => h.status === "dormant");
  const unverified = health.filter((h) => h.status === "unverified");

  const safeConflicts = health.filter((h) => h.safeConflict).length;
  const leakyBlocks = health.filter((h) => h.passedAfterBlock > 0).length;
  const autoBlocks = health.filter((h) => looksAutomated(h.by)).length;
  const manualBlocks = health.length - autoBlocks;
  const alertsAttributed = health.reduce((sum, h) => sum + h.totalAlerts, 0);

  const base: Omit<HygieneReport, "highlights" | "markdown"> = {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    totalBlocks: entries.length,
    activeBlocks: active.length,
    dormantBlocks: dormant.length,
    unverifiedBlocks: unverified.length,
    safeConflicts,
    leakyBlocks,
    autoBlocks,
    manualBlocks,
    staleRatio: entries.length ? round4(dormant.length / entries.length) : 0,
    alertsAttributed,
    storeNearCap: alertStore.all().length >= ALERT_STORE_CAP * 0.95,
    topActive: rankActive(active, limit),
    topDormant: rankDormant(dormant, limit),
    topUnverified: rankUnverified(unverified, limit),
  };

  const highlights = writeHighlights(base, windowEndMs);
  const model: HygieneReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model, windowEndMs);
  return model;
}

/** A filesystem-safe filename for a downloaded blocklist-hygiene report. */
export function hygieneFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-hygiene-${stamp}.md`;
}
