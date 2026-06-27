/**
 * Silence / dormancy ("gone-quiet") report — "**what was a reliable fixture in my
 * history but has produced *nothing* recently — and is that a win or a blind
 * spot?**"
 *
 * Every other report in SecTool surfaces what is *present and loud*: the biggest
 * counts, the hottest risers, the freshest arrivals. None of them surfaces the
 * opposite — an entity that was an established, recurring part of the alert stream
 * and has now **fallen completely silent**. That absence carries two very
 * different, equally actionable meanings, and a defender needs to know which:
 *
 *   1. **Good news.** A source you blocked has actually stopped (the block is
 *      working — see also recidivism.ts, which checks the inverse). A noisy
 *      campaign burned out. A targeted asset was decommissioned or hardened and is
 *      no longer drawing fire.
 *   2. **A blind spot.** A signature that fired like clockwork for days has gone
 *      silent — which can mean the rule was disabled, an Emerging-Threats / Talos
 *      feed lapsed, or the sensor simply stopped forwarding. A chronically-firing
 *      rule going to zero is one of the few *silent* failure modes in a detection
 *      stack: nothing errors, no alert fires, and **every other report quietly
 *      under-counts** because the data stopped arriving. The same logic flags a
 *      *heavy, unblocked* source that vanished — it either self-stopped or you lost
 *      visibility into it; both are worth a human confirming.
 *
 * The adjacent reports each answer a *different* question and none answers this one:
 *
 *   - **novelty.ts** surfaces *arrivals* (first-seen sources / signatures /
 *     targets) — this report is its mirror image: *departures*.
 *   - **heat.ts** ranks by recency-weighted intensity and can label a top entity
 *     `❄ cooling`, but only among the *hottest* entities and only relative to the
 *     rest — it never says "this fixture has produced literally nothing recently".
 *   - **lifecycle.ts** separates *chronic* background signatures from *acute*
 *     spikes over the whole window — it is about texture, not disappearance.
 *   - **recurrence.ts** predicts *when a repeat attacker is due back* from its
 *     inter-arrival cadence — this report is about established entities that simply
 *     **stopped**, with no claim about return.
 *   - **recidivism.ts** asks whether a *blocked* source kept firing *after* the
 *     block — the opposite outcome to the "block confirmed working" case here.
 *   - **coverage.ts** flags store truncation / parse health at the *dataset* level
 *     — this flags a suspected detection gap at the *per-entity* level.
 *
 * Method. The look-back window is split into an **established** period and a
 * trailing **recent** ("quiet-check") period of `quietHours` (default a quarter of
 * the window). An entity is **dormant** when it had at least `minCount` alerts in
 * the established period and **zero** in the recent period. Dormant entities are
 * ranked by how big a fixture they were (established count), across the same three
 * orthogonal dimensions as heat.ts — **sources**, **signatures** and **targets** —
 * and each carries:
 *
 *   - **established count** — how loud it was before going quiet (the ranking key);
 *   - **last seen** — and **hours since**, so you can tell a just-stopped fixture
 *     from one quiet for days;
 *   - **active days** — how many distinct calendar days it fired on in the
 *     established period; a high number is what makes a silence *alarming* rather
 *     than routine (a one-day blip going quiet is expected; a 6-day regular going
 *     quiet is not);
 *   - for sources / targets: blocklist / watchlist / safelist / internal flags, so
 *     the "block worked" case is separated from the "lost visibility" case;
 *   - for signatures: a **chronic** flag (active on ≥ `CHRONIC_DAYS` distinct days)
 *     — a chronic signature going silent is the headline detection-blind-spot tell.
 *
 * Honest caveats baked into the output:
 *
 *   - **Silence is not proof.** Zero recent alerts can mean the threat genuinely
 *     stopped *or* that you stopped seeing it — this report flags candidates for a
 *     human to confirm, it does not adjudicate which.
 *   - **Window- & store-bounded.** "Established" only reaches as far back as the
 *     look-back window and the alert store's history cap; an entity that has been
 *     quiet since before the window opened never appears (it is not "newly" silent).
 *   - **Detections, not ground truth.** NAT / shared egress and rotating botnet
 *     IPs blur the source identity, so a "silent source" may just be the same actor
 *     arriving from a fresh address (see novelty.ts for the arrivals side).
 *
 * Pure in-memory math over alertStore (plus blocklist / watchlist / safelist
 * membership flags) — no SSH, no Claude, no network. Output is both a structured
 * model and a ready-to-paste Markdown document, mirroring heat.ts, drift.ts and the
 * other offline reports.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { blockStore } from "../store/blocklist.ts";
import { watchStore } from "../store/watchlist.ts";
import { safeStore } from "../store/safelist.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** The three distributions whose dormancy we measure. */
export type SilenceDimensionKey = "source" | "signature" | "target";

/** A single dormant entity row inside a dimension's silence leaderboard. */
export interface SilenceEntity {
  /** The entity key (an IP for source/target, a signature string otherwise). */
  key: string;
  /** Alerts attributed to this entity in the established (pre-quiet) period. */
  establishedCount: number;
  /** Distinct calendar days (UTC) it fired on in the established period. */
  activeDays: number;
  /** Last time (ms epoch) this entity was seen anywhere in the window. */
  lastSeenMs: number;
  /** Hours between {@link lastSeenMs} and the window end (how long it's been quiet). */
  hoursSinceLastSeen: number;
  /** Worst severity observed for this entity in the window. */
  severityMax: Severity;
  /** Signature only: active on ≥ CHRONIC_DAYS distinct days — a long-standing regular. */
  chronic?: boolean;
  /** Source/target only: the entity is a private/internal address. */
  internal?: boolean;
  /** Source/target only: the entity is on the blocklist. */
  blocked?: boolean;
  /** Source/target only: the entity is on the watchlist. */
  watched?: boolean;
  /** Source/target only: the entity is marked safe. */
  safe?: boolean;
}

/** Silence metrics for one dimension (sources, signatures or targets). */
export interface SilenceDimension {
  key: SilenceDimensionKey;
  /** Human label ("sources", "signatures", "targets"). */
  label: string;
  /** Distinct entities that were active in the established period at all. */
  establishedEntities: number;
  /** Distinct entities that qualified as dormant (≥ minCount established, 0 recent). */
  dormantEntities: number;
  /** Dormant entities, biggest established fixture first (capped to the row limit). */
  top: SilenceEntity[];
}

export interface SilenceReport {
  hours: number;
  /** Trailing "quiet-check" period in hours actually used (after clamping). */
  quietHours: number;
  /** Minimum established alerts required to count an entity as a fixture. */
  minCount: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Boundary dividing the established period from the recent quiet-check period. */
  quietCutoffMs: number;
  /** Alerts (with a usable timestamp) inside the established period. */
  establishedAlerts: number;
  /** Alerts (with a usable timestamp) inside the recent quiet-check period. */
  recentAlerts: number;
  /** The three dimension analyses, in source → signature → target order. */
  dimensions: SilenceDimension[];
  /** Plain-language, action-oriented call-outs. */
  highlights: string[];
  /** The finished Markdown document. */
  markdown: string;
}

export interface SilenceOptions {
  /** Max rows in each per-dimension leaderboard (clamped to [1, 200]). */
  limit?: number;
  /**
   * Minimum established-period alert count for an entity to count as a "fixture"
   * worth flagging when it goes quiet (clamped to [1, 1000]). Default 3.
   */
  minCount?: number;
  /**
   * Trailing window (hours) that must be alert-free for an entity to read as
   * dormant (clamped to [1, window − 1]). Defaults to a quarter of the window.
   */
  quietHours?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
}

const DEFAULT_LIMIT = 15;
const DEFAULT_MIN_COUNT = 3;
const MS_PER_HOUR = 3_600_000;
const MS_PER_DAY = 86_400_000;

/** Distinct active days before a silent *signature* is treated as a chronic regular. */
const CHRONIC_DAYS = 3;
/** A "heavy" fixture: enough established volume that its silence warrants a look. */
const HEAVY_COUNT = 10;

// ----- classifiers / helpers (mirror heat.ts / concentration.ts) -------------

/** RFC1918 / loopback / link-local / ULA — an address treated as one of ours. */
function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
}

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

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** Compact "3d 4h" / "5h" / "12m" elapsed-time label for a span in hours. */
function fmtSince(hours: number): string {
  if (hours < 1) return `${Math.max(1, Math.round(hours * 60))}m`;
  if (hours < 48) return `${Math.round(hours)}h`;
  const days = Math.floor(hours / 24);
  const rem = Math.round(hours - days * 24);
  return rem > 0 ? `${days}d ${rem}h` : `${days}d`;
}

function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function clip(s: string, max = 44): string {
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

// ----- aggregation -----------------------------------------------------------

interface EntityAcc {
  establishedCount: number;
  recentCount: number;
  lastSeenMs: number;
  severityMax: Severity;
  /** Distinct established-period calendar days (UTC), for the chronic test. */
  estDays: Set<number>;
}

interface DimAcc {
  /** key → running established/recent counts + last-seen + severity + active days. */
  entities: Map<string, EntityAcc>;
}

function newDimAcc(): DimAcc {
  return { entities: new Map() };
}

/**
 * Fold one alert into a dimension accumulator: bump the established or recent
 * count depending on which side of the quiet cutoff it falls, track the latest
 * sighting, the worst severity, and (for the established side) the active day.
 */
function bump(
  acc: DimAcc,
  key: string,
  timeMs: number,
  established: boolean,
  severity: string | undefined,
): void {
  let e = acc.entities.get(key);
  if (!e) {
    e = {
      establishedCount: 0,
      recentCount: 0,
      lastSeenMs: timeMs,
      severityMax: "info",
      estDays: new Set(),
    };
    acc.entities.set(key, e);
  }
  if (established) {
    e.establishedCount++;
    e.estDays.add(Math.floor(timeMs / MS_PER_DAY));
  } else {
    e.recentCount++;
  }
  if (timeMs > e.lastSeenMs) e.lastSeenMs = timeMs;
  e.severityMax = maxSeverity(e.severityMax, severity);
}

/**
 * Build the full {@link SilenceDimension} from a raw accumulator: keep entities
 * that were a fixture (≥ minCount established) and have gone fully silent (zero
 * recent), then rank by how big a fixture they were.
 */
function summariseDimension(
  key: SilenceDimensionKey,
  label: string,
  acc: DimAcc,
  windowEndMs: number,
  minCount: number,
  limit: number,
  decorate: boolean,
): SilenceDimension {
  const entries = [...acc.entities.entries()];
  const establishedEntities = entries.filter(([, e]) => e.establishedCount > 0).length;

  const dormant = entries.filter(
    ([, e]) => e.establishedCount >= minCount && e.recentCount === 0,
  );

  // Rank: biggest fixture first, then the one quiet longest, then key for determinism.
  dormant.sort(
    (a, b) =>
      b[1].establishedCount - a[1].establishedCount ||
      a[1].lastSeenMs - b[1].lastSeenMs ||
      (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0),
  );

  const top: SilenceEntity[] = dormant.slice(0, limit).map(([k, e]) => {
    const activeDays = e.estDays.size;
    const row: SilenceEntity = {
      key: k,
      establishedCount: e.establishedCount,
      activeDays,
      lastSeenMs: e.lastSeenMs,
      hoursSinceLastSeen: Math.max(0, Math.round(((windowEndMs - e.lastSeenMs) / MS_PER_HOUR) * 10) / 10),
      severityMax: e.severityMax,
    };
    if (key === "signature") {
      row.chronic = activeDays >= CHRONIC_DAYS;
    }
    if (decorate) {
      row.internal = isPrivate(k);
      row.blocked = blockStore.has(k);
      row.watched = watchStore.has(k);
      row.safe = safeStore.has(k);
    }
    return row;
  });

  return {
    key,
    label,
    establishedEntities,
    dormantEntities: dormant.length,
    top,
  };
}

// ----- highlights ------------------------------------------------------------

function writeHighlights(report: Omit<SilenceReport, "highlights" | "markdown">): string[] {
  const out: string[] = [];
  const { hours, quietHours, dimensions } = report;
  const analysable = dimensions.some((d) => d.dormantEntities > 0);

  if (report.establishedAlerts === 0) {
    return out; // handled in the Markdown "nothing to analyse" branch
  }
  if (!analysable) {
    out.push(
      `✅ Nothing went quiet: every fixture (≥ ${report.minCount} alert(s)) that was active earlier in the last ${hours}h ` +
        `also fired in the recent ${quietHours}h. No source, signature or target has fallen silent — no blind spot, ` +
        `but also no campaign confirmed over.`,
    );
    return out;
  }

  const src = dimensions.find((d) => d.key === "source");
  const sig = dimensions.find((d) => d.key === "signature");
  const dst = dimensions.find((d) => d.key === "target");

  // Headline: the single biggest fixture (any dimension) that has gone silent.
  const biggest = dimensions
    .flatMap((d) => d.top.map((e) => ({ d, e })))
    .sort((a, b) => b.e.establishedCount - a.e.establishedCount)[0];
  if (biggest) {
    const { d, e } = biggest;
    const noun = d.key === "signature" ? "signature" : d.key;
    out.push(
      `🔇 Quietest big fixture: ${noun} **${d.key === "signature" ? clip(e.key, 60) : `\`${e.key}\``}** fired ` +
        `**${e.establishedCount}** time(s) across **${e.activeDays}** day(s) earlier in the window but **nothing** in ` +
        `the last **${quietHours}h** (last seen ${fmtSince(e.hoursSinceLastSeen)} ago). Confirm whether it stopped — ` +
        `or whether you stopped seeing it.`,
    );
  }

  // The headline detection-blind-spot: a chronic signature gone completely silent.
  const chronicSilent = sig?.top.find((e) => e.chronic);
  if (chronicSilent) {
    out.push(
      `🚨 **Possible detection blind spot:** signature **${clip(chronicSilent.key, 60)}** fired on ` +
        `**${chronicSilent.activeDays}** distinct day(s) (${chronicSilent.establishedCount} alert(s)) then produced ` +
        `**zero** in the last ${quietHours}h. A long-standing rule going silent can mean it was disabled, a feed ` +
        `lapsed, or the sensor stopped forwarding — verify the rule/feed/sensor is still live before trusting the ` +
        `other reports' counts.`,
    );
  }

  // The good-news case: a blocked source that has actually stopped firing.
  const blockedSilent = src?.top.find((e) => e.blocked);
  if (blockedSilent) {
    out.push(
      `✅ **Block confirmed working:** blocked source \`${blockedSilent.key}\` was a ${blockedSilent.establishedCount}-alert ` +
        `fixture and has been silent for ${fmtSince(blockedSilent.hoursSinceLastSeen)} — the block appears to be holding ` +
        `(contrast \`--recidivism\`, which flags blocks that *didn't* stop the traffic).`,
    );
  }

  // The ambiguous case: a heavy *unblocked, external* source that simply vanished.
  const heavyUnblocked = src?.top.find(
    (e) => !e.blocked && !e.internal && !e.safe && e.establishedCount >= HEAVY_COUNT,
  );
  if (heavyUnblocked) {
    out.push(
      `🔎 **Verify:** unblocked external source \`${heavyUnblocked.key}\`${heavyUnblocked.watched ? " 👁" : ""} was a ` +
        `${heavyUnblocked.establishedCount}-alert fixture and then went silent on its own (quiet for ` +
        `${fmtSince(heavyUnblocked.hoursSinceLastSeen)}). It either self-stopped or you lost visibility into it — neither ` +
        `is a block you can take credit for.`,
    );
  }

  // A targeted asset that stopped drawing fire — decommissioned, hardened, or moved-on attacker.
  const silentTarget = dst?.top[0];
  if (silentTarget) {
    out.push(
      `🎯 Target \`${silentTarget.key}\`${silentTarget.internal ? " 🏠" : ""} drew ${silentTarget.establishedCount} alert(s) ` +
        `then went quiet (${fmtSince(silentTarget.hoursSinceLastSeen)}). If it's one of yours, confirm it was hardened or ` +
        `decommissioned rather than simply dropped from the log feed.`,
    );
  }

  // Scale call-out across all three dimensions.
  const totals = dimensions.map((d) => `${d.dormantEntities} ${d.label}`).join(", ");
  out.push(`📋 Gone-quiet fixtures this window: ${totals} (≥ ${report.minCount} prior alert(s), zero in the last ${quietHours}h).`);

  return out;
}

// ----- markdown --------------------------------------------------------------

function flagsCell(e: SilenceEntity): string {
  const f =
    (e.internal ? "🏠" : "") +
    (e.blocked ? "⛔" : "") +
    (e.watched ? "👁" : "") +
    (e.safe ? "✅" : "");
  return f || "—";
}

function dimensionTable(d: SilenceDimension): string {
  const isIpDim = d.key === "source" || d.key === "target";
  const entityHeader = d.key === "source" ? "Source" : d.key === "target" ? "Target" : "Signature";
  const headers = isIpDim
    ? ["#", entityHeader, "Prior alerts", "Active days", "Quiet for", "Last seen", "Worst", "Flags"]
    : ["#", entityHeader, "Prior alerts", "Active days", "Quiet for", "Last seen", "Worst", "Chronic"];
  return mdTable(
    headers,
    d.top.map((e, i) => {
      const base = [
        String(i + 1),
        cell(isIpDim ? e.key : clip(e.key)),
        String(e.establishedCount),
        String(e.activeDays),
        fmtSince(e.hoursSinceLastSeen),
        cell(fmtTime(e.lastSeenMs)),
        cell(e.severityMax),
      ];
      return isIpDim ? [...base, flagsCell(e)] : [...base, e.chronic ? "🚨 yes" : "no"];
    }),
  );
}

function renderMarkdown(m: SilenceReport): string {
  const lines: string[] = [];
  lines.push(`# 🔇 SecTool Silence / Dormancy (Gone-Quiet) Report`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Method:** a fixture is **dormant** when it had **≥ ${m.minCount}** alert(s) in the *established* period ` +
      `(${fmtTime(m.windowStartMs)} → ${fmtTime(m.quietCutoffMs)}) and **zero** in the trailing *quiet-check* period ` +
      `(last **${m.quietHours}h**). Measured across **sources**, **signatures** and **targets**. ` +
      `Offline, deterministic · **Established alerts:** ${m.establishedAlerts} · **Recent alerts:** ${m.recentAlerts}`,
  );
  lines.push("");

  lines.push(`## Summary`);
  lines.push("");
  if (m.establishedAlerts === 0) {
    lines.push(
      `No alerts with a usable timestamp landed in the established period (last ${m.hours}h minus the recent ` +
        `${m.quietHours}h) — there is no prior baseline against which anything could have gone quiet. Widen the window ` +
        `(\`--silence <more hours>\`) or shorten the quiet-check window (\`--quiet <fewer hours>\`).`,
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }
  for (const h of m.highlights) lines.push(`- ${h}`);
  lines.push("");

  // At-a-glance: how many fixtures went quiet in each dimension.
  lines.push(`## Dormancy at a glance`);
  lines.push("");
  lines.push(
    mdTable(
      ["Dimension", "Active fixtures", "Gone quiet", "Quietest (prior alerts)"],
      m.dimensions.map((d) => {
        const top = d.top[0];
        return [
          cell(d.label),
          String(d.establishedEntities),
          String(d.dormantEntities),
          top ? cell(`${d.key === "signature" ? clip(top.key, 40) : top.key} (${top.establishedCount})`) : "—",
        ];
      }),
    ),
  );
  lines.push("");
  lines.push(
    `**Legend:** _Prior alerts_ = volume in the established period before it went quiet (the ranking key). ` +
      `_Active days_ = distinct calendar days it fired on — a high count makes the silence *alarming* rather than ` +
      `routine. _Quiet for_ = time since its last sighting. For IP rows: 🏠 internal · ⛔ blocked · 👁 watched · ` +
      `✅ safelisted. For signatures: **🚨 Chronic** = active on ≥ ${CHRONIC_DAYS} days — a likely detection blind ` +
      `spot if it has gone fully silent.`,
  );
  lines.push("");

  // Per-dimension detail.
  for (const d of m.dimensions) {
    lines.push(`## ${d.label[0]!.toUpperCase()}${d.label.slice(1)} gone quiet`);
    lines.push("");
    if (d.dormantEntities === 0) {
      lines.push(
        `_No ${d.label.replace(/s$/, "")} that was a fixture (≥ ${m.minCount} prior alert(s)) has fallen silent in ` +
          `the last ${m.quietHours}h._`,
      );
      lines.push("");
      continue;
    }
    const shown = Math.min(d.top.length, d.dormantEntities);
    lines.push(
      `**${d.dormantEntities}** ${d.label} that were active earlier have produced nothing in the last ${m.quietHours}h` +
        (d.dormantEntities > shown ? ` (showing the top ${shown})` : ``) +
        `.`,
    );
    lines.push("");
    lines.push(dimensionTable(d));
    lines.push("");
  }

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. **Silence is a lead, not a verdict** — zero recent alerts can mean a threat ` +
      `genuinely stopped (a block that held, a campaign that ended, an asset hardened) *or* that you stopped seeing it ` +
      `(a disabled rule, a lapsed feed, a sensor that quit forwarding). A **chronic signature** going silent is the ` +
      `blind-spot tell worth checking first. "Established" only reaches as far back as the window and the alert ` +
      `store's history cap, so an entity quiet since before the window opened never appears here. These are IPS ` +
      `**detections**: a "silent source" may just be the same actor on a fresh IP (see \`--novelty\` for the arrivals ` +
      `side). No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * Build the silence / dormancy (gone-quiet) report from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [2, 90 days]).
 * @param opts  {@link SilenceOptions}: `limit`, `minCount`, `quietHours`, and a
 *              `nowMs` pin for deterministic tests.
 */
export function buildSilence(hours: number, opts: SilenceOptions = {}): SilenceReport {
  const safeHours = Math.max(2, Math.min(24 * 90, Math.floor(hours)));
  const limit = Math.max(1, Math.min(200, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const minCount = Math.max(1, Math.min(1000, Math.floor(opts.minCount ?? DEFAULT_MIN_COUNT)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;

  // Quiet-check window: default a quarter of the look-back, clamped so at least one
  // hour is checked and at least one hour of established baseline remains.
  const requestedQuiet = opts.quietHours ?? safeHours / 4;
  const quietHours = Math.max(1, Math.min(safeHours - 1, Math.round(requestedQuiet)));
  const quietCutoffMs = windowEndMs - quietHours * MS_PER_HOUR;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);

  const srcAcc = newDimAcc();
  const sigAcc = newDimAcc();
  const dstAcc = newDimAcc();

  let establishedAlerts = 0;
  let recentAlerts = 0;

  for (const a of windowed) {
    const established = a.time < quietCutoffMs;
    if (established) establishedAlerts++;
    else recentAlerts++;

    const src = validIp(a.srcIp);
    if (src) bump(srcAcc, src, a.time, established, a.severity);

    const sig = (a.signature ?? "").trim();
    if (sig) bump(sigAcc, sig, a.time, established, a.severity);

    const dst = validIp(a.dstIp);
    if (dst) bump(dstAcc, dst, a.time, established, a.severity);
  }

  const dimensions: SilenceDimension[] = [
    summariseDimension("source", "sources", srcAcc, windowEndMs, minCount, limit, true),
    summariseDimension("signature", "signatures", sigAcc, windowEndMs, minCount, limit, false),
    summariseDimension("target", "targets", dstAcc, windowEndMs, minCount, limit, true),
  ];

  const base: Omit<SilenceReport, "highlights" | "markdown"> = {
    hours: safeHours,
    quietHours,
    minCount,
    windowStartMs,
    windowEndMs,
    quietCutoffMs,
    establishedAlerts,
    recentAlerts,
    dimensions,
  };

  const highlights = writeHighlights(base);

  const model: SilenceReport = { ...base, highlights, markdown: "" };
  model.markdown = renderMarkdown(model);
  return model;
}

/** A filesystem-safe filename for a downloaded silence report. */
export function silenceFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-silence-${stamp}.md`;
}
