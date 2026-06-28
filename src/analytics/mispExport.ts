/**
 * MISP event export — turn the stored alert history into a **native MISP
 * (Malware Information Sharing Platform) Event** that the single most widely
 * deployed open threat-intel platform among CSIRTs, CERTs and ISACs ingests
 * directly: PyMISP `add_event`, the REST `POST /events/add`, or — with zero
 * code on the consumer side — a static **MISP feed** (a `manifest.json` plus one
 * event JSON per uuid).
 *
 * It is the deliberately distinct, ecosystem-native sibling of `--stix`:
 *
 *   - `--stix` emits an OASIS **STIX 2.1** bundle. MISP *can* import STIX, but the
 *     round-trip is lossy and many MISP-centric communities (national CERTs,
 *     sector ISACs, the CIRCL feeds) share and consume the **native MISP JSON**
 *     instead — it is the format MISP's own feed system, galaxies, taxonomy tags
 *     and `to_ids` correlation engine are built around. STIX is the lingua-franca
 *     for crossing *between* platforms; native MISP JSON is what you publish when
 *     your sharing community *is* MISP.
 *   - `--iocs` / `--fwrules` emit SecTool-shaped lists for a firewall or
 *     spreadsheet — no platform auto-recognises them as structured intel.
 *
 * Rather than re-deriving the indicator set, this module **reuses
 * {@link buildIocExport}** as its scoring engine — the exact same confidence
 * model, severity floor, safelist exclusion and dismissed-alert handling that
 * make the IOC export trustworthy as a blocklist source apply here verbatim, so
 * no scoring logic is duplicated or allowed to drift. Each scored attacker IP
 * becomes one MISP `ip-src` **Attribute** ("Network activity") on a single MISP
 * **Event**, carrying:
 *
 *   - a deterministic **UUIDv5** (so re-publishing the same intel updates the
 *     attribute in place instead of duplicating it — exactly the property a MISP
 *     feed needs to stay idempotent across pulls),
 *   - the **`to_ids`** flag set from the same confidence the IOC engine computes
 *     (high-confidence hosts are marked usable for automated IDS/blocklist
 *     export; the rest are intel-only context), so a MISP admin's "publish to
 *     IDS" workflow inherits SecTool's triage,
 *   - a human `comment` (worst severity, alert volume, dominant signature,
 *     gateway-blocked corroboration, watchlist note), and
 *   - per-attribute **taxonomy tags** in a `sectool:` namespace (severity,
 *     confidence band, category) plus the event-level **TLP** tag.
 *
 * Event-level metadata is mapped to MISP's own vocabulary: `threat_level_id`
 * from the worst observed severity (1 High · 2 Medium · 3 Low · 4 Undefined),
 * `analysis` = 0 (Initial — this is machine-generated, unvetted intel),
 * `distribution` = 0 (your-organisation-only by default; the TLP tag conveys the
 * intended sharing scope and the consumer re-distributes deliberately),
 * `published` = false (never auto-publish someone else's feed), and a
 * deterministic Event `uuid` derived from the window so the same window re-exports
 * as the same event.
 *
 * Honest caveats baked into the output:
 *   - **Confidence is heuristic, not vetted intel.** It is SecTool's blocklist
 *     confidence (severity, volume, gateway corroboration, watchlist), surfaced
 *     in the `to_ids` decision and a `sectool:confidence` tag — not a
 *     human-curated assertion. Review before publishing to a sharing community.
 *   - **Safelisted IPs are excluded by default**, exactly as in the IOC export —
 *     publishing a trusted address as a malicious attribute would be an outage
 *     waiting to happen at every consumer. The exclusion count is reported.
 *   - **Window-bounded & store-capped.** A long look-back can hit the alert
 *     store's retention cap and clip the earliest attributes.
 *
 * Pure in-memory math over alertStore (via iocExport) — no SSH, no Claude, no
 * network. Output is the native MISP Event JSON plus a human Markdown review
 * twin, mirroring the model + Markdown shape of stix.ts and the other offline
 * exports.
 */
import { createHash } from "node:crypto";
import { buildIocExport, type IocIndicator } from "./iocExport.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/**
 * A fixed UUID namespace for SecTool's deterministic identifiers — the same
 * constant the STIX export pins. Changing it would re-key every uuid and defeat
 * the idempotency it exists to guarantee. (Any constant UUID works; this is ours.)
 */
const SECTOOL_NAMESPACE = "6f9b1d2c-3a4e-5b6c-8d7e-0f1a2b3c4d5e";

/** A loosely-typed MISP tag ({ name, ... } in the MISP schema). */
export interface MispTag {
  name: string;
  colour?: string;
}

/** A single MISP Attribute (the IOC carrier). */
export interface MispAttribute {
  uuid: string;
  type: string;
  category: string;
  to_ids: boolean;
  distribution: string;
  value: string;
  timestamp: string;
  comment: string;
  Tag: MispTag[];
}

/** A MISP Event — the publishable container of attributes. */
export interface MispEvent {
  uuid: string;
  info: string;
  date: string;
  threat_level_id: string;
  analysis: string;
  distribution: string;
  published: boolean;
  timestamp: string;
  Orgc: { name: string; uuid: string };
  Tag: MispTag[];
  Attribute: MispAttribute[];
}

/** The MISP wire object: a single top-level `Event` key (what `/events/add` wants). */
export interface MispEnvelope {
  Event: MispEvent;
}

export interface MispReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Severity floor applied to qualify as an attribute (from the IOC engine). */
  minSeverity: Severity;
  /** TLP marking applied to the event (lower-case, e.g. `amber`). */
  tlp: string;
  /** Confidence at/above which an attribute is marked `to_ids: true`. */
  toIdsThreshold: number;
  /** Number of `ip-src` Attributes emitted. */
  attributeCount: number;
  /** Of those, how many carry `to_ids: true` (the actionable subset). */
  toIdsCount: number;
  /** Worst severity observed across the attributes (drives `threat_level_id`). */
  worstSeverity: Severity;
  /** Attributes dropped because the IP is safelisted (explicitly trusted). */
  excludedSafe: number;
  /** Attributes dropped because their worst severity was below the floor. */
  excludedBelowSeverity: number;
  /** Attributes truncated by the `limit`. */
  truncated: number;
  /** The finished native MISP Event (wrapped in its `Event` envelope). */
  event: MispEnvelope;
  /** Pretty-printed JSON of {@link event}, ready to POST or drop in a feed. */
  json: string;
  /** A human Markdown review twin (eyeball before publishing). */
  markdown: string;
}

export interface MispOptions {
  /** Severity floor (default `medium`, inherited from the IOC engine). */
  minSeverity?: Severity;
  /** Cap on emitted attributes, highest confidence first (default: no cap). */
  limit?: number;
  /** Include safelisted IPs instead of excluding them (default false). */
  includeSafe?: boolean;
  /** TLP marking — white/clear/green/amber/red (default `amber`). */
  tlp?: string;
  /** Confidence at/above which an attribute gets `to_ids: true` (default 60). */
  toIdsThreshold?: number;
  /** Pins the window end / timestamps for deterministic tests; defaults to now. */
  nowMs?: number;
}

// ----- deterministic UUIDv5 (RFC 4122, name-based SHA-1) ---------------------
// Mirrors the helper in stix.ts so the two exports key identical concepts to
// identical uuids; kept self-contained rather than cross-importing a private fn.

function uuidToBytes(uuid: string): Buffer {
  const hex = uuid.replace(/-/g, "");
  const bytes = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function bytesToUuid(bytes: Buffer): string {
  const hex = bytes.toString("hex");
  return (
    `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-` +
    `${hex.slice(16, 20)}-${hex.slice(20, 32)}`
  );
}

/**
 * Deterministic RFC 4122 v5 (SHA-1, name-based) UUID. The same `name` always
 * yields the same UUID — the property that makes a re-published MISP feed
 * idempotent (the consumer updates the existing event/attribute in place).
 */
function uuidv5(name: string, namespace = SECTOOL_NAMESPACE): string {
  const ns = uuidToBytes(namespace);
  const hash = createHash("sha1").update(ns).update(Buffer.from(name, "utf8")).digest();
  const bytes = Buffer.from(hash.subarray(0, 16));
  bytes[6] = (bytes[6]! & 0x0f) | 0x50; // version 5
  bytes[8] = (bytes[8]! & 0x3f) | 0x80; // RFC 4122 variant
  return bytesToUuid(bytes);
}

// ----- MISP vocabulary helpers ----------------------------------------------

/** Stable producing-organisation uuid (one identity for every SecTool feed). */
const ORGC = { name: "SecTool", uuid: uuidv5("orgc:sectool") };

/** Valid TLP markings MISP recognises as taxonomy tags. */
const TLP_VALUES = new Set(["white", "clear", "green", "amber", "amber+strict", "red"]);

/** Coerce a free-text TLP into a recognised marking, defaulting to `amber`. */
export function parseTlp(raw: string | undefined | null): string {
  const t = (raw ?? "").trim().toLowerCase().replace(/^tlp:/, "");
  return TLP_VALUES.has(t) ? t : "amber";
}

/** MISP epoch-second timestamp strings. */
function epochSec(ms: number): string {
  return String(Math.floor(ms / 1000));
}

/** MISP event `date` is a bare YYYY-MM-DD (UTC). */
function ymd(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

function sevRank(s: Severity): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s);
  return i < 0 ? 0 : i;
}

function maxSeverity(a: Severity, b: Severity): Severity {
  return sevRank(b) > sevRank(a) ? b : a;
}

/** MISP `threat_level_id`: 1 High · 2 Medium · 3 Low · 4 Undefined. */
function threatLevelId(worst: Severity): string {
  switch (worst) {
    case "critical":
    case "high":
      return "1";
    case "medium":
      return "2";
    case "low":
      return "3";
    default:
      return "4";
  }
}

/** A coarse confidence band for the `sectool:confidence` taxonomy tag. */
function confidenceBand(c: number): string {
  if (c >= 80) return "high";
  if (c >= 60) return "medium";
  if (c >= 40) return "low";
  return "very-low";
}

/** Lower-kebab a free-text token so it is safe inside a taxonomy tag predicate. */
function tagToken(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

// ----- attribute builder -----------------------------------------------------

/** Map one scored IOC indicator to a MISP `ip-src` Attribute. */
function buildAttribute(ind: IocIndicator, toIdsThreshold: number, tlp: string): MispAttribute {
  const toIds = ind.confidence >= toIdsThreshold;

  const commentParts = [
    `${ind.alertCount} SecTool alert(s), worst severity ${ind.severityMax}, ` +
      `across ${ind.signatureCount} signature(s) and ${ind.targetCount} internal host(s).`,
  ];
  if (ind.signatures.length) {
    commentParts.push(`Top signature(s): ${ind.signatures.slice(0, 3).join("; ")}.`);
  }
  if (ind.blockedCount > 0) {
    commentParts.push(`Gateway already blocked ${ind.blockedCount} of these alert(s).`);
  }
  if (ind.watched) {
    commentParts.push(`Operator watchlist match${ind.watchNote ? `: ${ind.watchNote}` : ""}.`);
  }
  commentParts.push(`SecTool confidence ${ind.confidence}/100.`);

  const tags: MispTag[] = [
    { name: `tlp:${tlp}` },
    { name: `sectool:severity="${ind.severityMax}"` },
    { name: `sectool:confidence="${confidenceBand(ind.confidence)}"` },
  ];
  // The dominant Suricata category gives the analyst a one-glance threat class.
  const cat = ind.categories.map(tagToken).filter(Boolean)[0];
  if (cat) tags.push({ name: `sectool:category="${cat}"` });

  return {
    // Deterministic per-IP uuid — re-publishing updates the attribute in place.
    uuid: uuidv5(`attribute:ip-src:${ind.ip}`),
    type: "ip-src",
    category: "Network activity",
    to_ids: toIds,
    // 5 = "Inherit event" — the attribute follows the event's distribution policy.
    distribution: "5",
    value: ind.ip,
    timestamp: epochSec(ind.lastSeen),
    comment: commentParts.join(" "),
    Tag: tags,
  };
}

// ----- markdown twin ---------------------------------------------------------

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function mdCell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function renderMarkdown(m: MispReport, indicators: IocIndicator[]): string {
  const lines: string[] = [];
  lines.push(`# 🛡️ SecTool MISP Event Export`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Event:** \`${m.event.Event.uuid}\` · **Attributes:** ${m.attributeCount} ` +
      `(${m.toIdsCount} \`to_ids\`) · **TLP:** ${m.tlp} · **Threat level:** ${threatLevelLabel(m.worstSeverity)} · ` +
      `**Min severity:** ${m.minSeverity}` +
      (m.excludedSafe ? ` · **Excluded (safelisted):** ${m.excludedSafe}` : "") +
      (m.truncated ? ` · **Truncated:** ${m.truncated} more` : ""),
  );
  lines.push("");

  if (!m.attributeCount) {
    lines.push(
      `No external attacker IPs at **${m.minSeverity}** severity or above in the last ${m.hours} hour(s).` +
        (m.excludedBelowSeverity
          ? ` (${m.excludedBelowSeverity} lower-severity IP(s) were below the floor.)`
          : ""),
    );
    lines.push("");
    lines.push("The event still validates — it is published as an empty MISP event you can populate by hand.");
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  lines.push(
    `A native **MISP Event** for ingestion via PyMISP \`add_event\`, the REST \`POST /events/add\`, or a static ` +
      `**MISP feed** (drop this JSON beside a \`manifest.json\`). Attribute uuids are **deterministic (UUIDv5)** so ` +
      `re-publishing the same intel updates attributes in place instead of duplicating them. The \`to_ids\` flag is ` +
      `set from SecTool's confidence (≥ ${m.toIdsThreshold}), so MISP's "publish to IDS" workflow inherits the triage.`,
  );
  lines.push("");

  const head = ["IP", "Conf.", "Sev", "Alerts", "to_ids", "Attribute uuid"];
  lines.push(`| ${head.join(" | ")} |`);
  lines.push(`| ${head.map(() => "---").join(" | ")} |`);
  for (const ind of indicators) {
    lines.push(
      `| ${mdCell(ind.ip)} | ${ind.confidence} | ${mdCell(ind.severityMax)} | ${ind.alertCount} | ` +
        `${ind.confidence >= m.toIdsThreshold ? "✅" : "—"} | \`${uuidv5(`attribute:ip-src:${ind.ip}`)}\` |`,
    );
  }
  lines.push("");

  lines.push(`## Event (MISP JSON)`);
  lines.push("");
  lines.push("Save as `.json` and import — e.g. `misp-event-add.py`, or place it in a feed directory:");
  lines.push("");
  lines.push("```json");
  lines.push(m.json);
  lines.push("```");
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Attributes are scored by the same heuristic confidence model as the IOC export ` +
      `(severity, volume, gateway corroboration, watchlist); that confidence drives the \`to_ids\` flag and a ` +
      `\`sectool:confidence\` tag — review before publishing to a sharing community. Safelisted IPs are excluded by ` +
      `default. The event is \`published: false\` and \`distribution: 0\` (your-org-only) — set the sharing scope ` +
      `deliberately in MISP after review. A long look-back can hit the alert store's retention cap and clip the ` +
      `earliest attributes. The native-MISP companion to the \`stix\` (STIX 2.1) export. No live gateway query was ` +
      `performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

/** Human label for a MISP threat level, for the Markdown header. */
function threatLevelLabel(worst: Severity): string {
  const id = threatLevelId(worst);
  return id === "1" ? "High" : id === "2" ? "Medium" : id === "3" ? "Low" : "Undefined";
}

// ----- entry point -----------------------------------------------------------

/**
 * Build the native MISP Event export from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days] by the IOC engine).
 * @param opts  {@link MispOptions}: severity floor, attribute limit, safelist
 *              handling, TLP marking, `to_ids` threshold and a `nowMs` pin for
 *              deterministic / reproducible output.
 */
export function buildMisp(hours: number, opts: MispOptions = {}): MispReport {
  const nowMs = opts.nowMs ?? Date.now();
  const tlp = parseTlp(opts.tlp);
  const toIdsThreshold = Math.max(0, Math.min(100, Math.floor(opts.toIdsThreshold ?? 60)));

  // Reuse the IOC engine as the scoring source of truth — same filters, same
  // confidence model, same safelist/dismissed handling. No logic duplicated.
  const ioc = buildIocExport(hours, {
    minSeverity: opts.minSeverity,
    limit: opts.limit,
    includeSafe: opts.includeSafe,
    nowMs,
  });

  const attributes = ioc.indicators.map((ind) => buildAttribute(ind, toIdsThreshold, tlp));
  const toIdsCount = attributes.filter((a) => a.to_ids).length;
  const worstSeverity = ioc.indicators.reduce<Severity>(
    (w, ind) => maxSeverity(w, ind.severityMax),
    "info",
  );

  // Deterministic event uuid from the window so the same window re-exports as the
  // same event (a feed consumer updates it in place rather than duplicating).
  const eventUuid = uuidv5(`event:${ioc.windowStartMs}:${ioc.windowEndMs}`);

  const event: MispEvent = {
    uuid: eventUuid,
    info: `SecTool IDS/IPS attacker indicators — last ${ioc.hours}h (${ymd(ioc.windowStartMs)} → ${ymd(ioc.windowEndMs)})`,
    date: ymd(ioc.windowEndMs),
    threat_level_id: threatLevelId(worstSeverity),
    analysis: "0", // Initial — machine-generated, unvetted intel.
    distribution: "0", // Your-organisation-only; raise deliberately after review.
    published: false, // Never auto-publish someone else's feed.
    timestamp: epochSec(nowMs),
    Orgc: ORGC,
    Tag: [{ name: `tlp:${tlp}` }, { name: "type:OSINT" }, { name: 'sectool:source="ids-ips"' }],
    Attribute: attributes,
  };

  const envelope: MispEnvelope = { Event: event };
  const json = JSON.stringify(envelope, null, 2);

  const model: MispReport = {
    hours: ioc.hours,
    windowStartMs: ioc.windowStartMs,
    windowEndMs: ioc.windowEndMs,
    minSeverity: ioc.minSeverity,
    tlp,
    toIdsThreshold,
    attributeCount: attributes.length,
    toIdsCount,
    worstSeverity,
    excludedSafe: ioc.excludedSafe,
    excludedBelowSeverity: ioc.excludedBelowSeverity,
    truncated: ioc.truncated,
    event: envelope,
    json,
    markdown: "",
  };
  model.markdown = renderMarkdown(model, ioc.indicators);
  return model;
}

/** A filesystem-safe filename for a downloaded MISP event. */
export function mispFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-misp-${stamp}.json`;
}
