/**
 * STIX 2.1 threat-intelligence export — turn the stored alert history into an
 * **OASIS STIX 2.1 bundle** that interoperable threat-intel platforms ingest
 * directly: MISP, OpenCTI, Anomali, ThreatConnect, a TAXII 2.1 collection, or
 * any SIEM that speaks STIX. It is the *standards-based* sibling of the existing
 * exports and deliberately does not overlap them:
 *
 *   - iocExport.ts (`--iocs`) emits firewall/SIEM-friendly **plain / csv / json /
 *     markdown** — great for `ipset restore` or a spreadsheet, but each is a
 *     SecTool-specific shape no other tool auto-recognises.
 *   - fwrules.ts (`--fwrules`) renders the *enforced blocklist* into vendor
 *     firewall config — the enforcement codegen step, not an intel-sharing feed.
 *   - This module emits the one format the threat-intel ecosystem agreed on. A
 *     STIX bundle drops straight into a sharing community (an ISAC, a partner's
 *     OpenCTI, an internal TAXII server) and arrives as first-class Indicator
 *     objects with patterns, confidence, validity windows and provenance — no
 *     bespoke parser required.
 *
 * Rather than re-deriving the indicator set, this report **reuses
 * {@link buildIocExport}** as its scoring engine: the same confidence model,
 * severity floor, safelist exclusion and dismissed-alert handling that make the
 * IOC export trustworthy as a blocklist source apply here verbatim. Each scored
 * indicator is then mapped to STIX 2.1 Standard Domain Objects:
 *
 *   - one **Identity** SDO for SecTool itself (the producer / `created_by_ref`),
 *   - one **Indicator** SDO per attacker IP, carrying a STIX pattern
 *     (`[ipv4-addr:value = '…']`), `indicator_types`, the 0–100 `confidence`,
 *     a `valid_from` (first-seen) window, category `labels`, and an
 *     `external_references` note with the dominant signature for analyst context,
 *
 * all wrapped in a STIX 2.1 `bundle`.
 *
 * **Deterministic, idempotent identifiers.** STIX object IDs are normally random
 * UUIDv4, which means re-publishing the same intel creates duplicate objects in
 * the consumer. That is poison for a recurring feed. Instead every ID here is a
 * **deterministic UUIDv5** (RFC 4122, name-based SHA-1) derived from a fixed
 * SecTool namespace and the indicator value, so the *same attacker IP always maps
 * to the same Indicator ID across runs* — a consumer that already holds the
 * object updates it in place instead of accumulating duplicates. Timestamps are
 * driven by the pinned `nowMs`, so the whole bundle is reproducible (and
 * testable) byte-for-byte for identical input.
 *
 * Honest caveats baked into the output:
 *   - **Confidence is heuristic, not vetted intel.** It is SecTool's blocklist
 *     confidence (severity, volume, gateway corroboration, watchlist), surfaced
 *     in the STIX `confidence` field so a consumer can threshold on it — it is
 *     not a human-curated assertion. Review before auto-actioning downstream.
 *   - **Safelisted IPs are excluded by default**, exactly as in the IOC export —
 *     publishing a trusted address as a malicious Indicator would be an outage
 *     waiting to happen at every consumer. The exclusion count is reported.
 *   - **Window-bounded & store-capped.** A long look-back can hit the alert
 *     store's retention cap and clip the earliest indicators.
 *
 * Pure in-memory math over alertStore (via iocExport) — no SSH, no Claude, no
 * network. Output is a structured STIX bundle plus a human Markdown review twin,
 * mirroring the model + Markdown shape of the other offline reports.
 */
import { createHash } from "node:crypto";
import { buildIocExport, type IocIndicator } from "./iocExport.ts";
import type { Severity } from "../types.ts";

/** STIX spec version this bundle conforms to. */
const STIX_VERSION = "2.1";

/**
 * A fixed UUID namespace for SecTool's deterministic STIX identifiers. Generated
 * once and pinned forever: changing it would re-key every object and defeat the
 * idempotency it exists to guarantee. (Any constant UUID works; this is ours.)
 */
const SECTOOL_NAMESPACE = "6f9b1d2c-3a4e-5b6c-8d7e-0f1a2b3c4d5e";

/** A single STIX 2.1 Standard Domain Object (loosely typed — JSON for export). */
export type StixObject = Record<string, unknown>;

/** A STIX 2.1 bundle: a typed, id'd container of SDOs. */
export interface StixBundle {
  type: "bundle";
  id: string;
  objects: StixObject[];
}

export interface StixReport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Severity floor applied to qualify as an indicator (from the IOC engine). */
  minSeverity: Severity;
  /** Number of Indicator SDOs emitted (excludes the Identity SDO). */
  indicatorCount: number;
  /** Total SDOs in the bundle (indicators + the producer Identity). */
  objectCount: number;
  /** Indicators dropped because the IP is safelisted (explicitly trusted). */
  excludedSafe: number;
  /** Indicators dropped because their worst severity was below the floor. */
  excludedBelowSeverity: number;
  /** Indicators truncated by the `limit`. */
  truncated: number;
  /** The finished, standards-compliant STIX 2.1 bundle — the deliverable. */
  bundle: StixBundle;
  /** Pretty-printed JSON of {@link bundle}, ready to write to a `.json` file. */
  json: string;
  /** A human Markdown review twin (eyeball before publishing). */
  markdown: string;
}

export interface StixOptions {
  /** Severity floor (default `medium`, inherited from the IOC engine). */
  minSeverity?: Severity;
  /** Cap on emitted indicators, highest confidence first (default: no cap). */
  limit?: number;
  /** Include safelisted IPs instead of excluding them (default false). */
  includeSafe?: boolean;
  /** Pins the window end / timestamps for deterministic tests; defaults to now. */
  nowMs?: number;
}

// ----- deterministic UUIDv5 (RFC 4122, name-based SHA-1) ---------------------

/** Parse a canonical 36-char UUID string into its 16 raw bytes. */
function uuidToBytes(uuid: string): Buffer {
  const hex = uuid.replace(/-/g, "");
  const bytes = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

/** Render 16 raw bytes as a canonical lower-case UUID string. */
function bytesToUuid(bytes: Buffer): string {
  const hex = bytes.toString("hex");
  return (
    `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-` +
    `${hex.slice(16, 20)}-${hex.slice(20, 32)}`
  );
}

/**
 * Deterministic RFC 4122 v5 (SHA-1, name-based) UUID. The same (namespace, name)
 * always yields the same UUID — the property that makes the exported bundle
 * idempotent across re-publishes.
 */
function uuidv5(name: string, namespace = SECTOOL_NAMESPACE): string {
  const ns = uuidToBytes(namespace);
  const hash = createHash("sha1").update(ns).update(Buffer.from(name, "utf8")).digest();
  const bytes = Buffer.from(hash.subarray(0, 16));
  bytes[6] = (bytes[6]! & 0x0f) | 0x50; // version 5
  bytes[8] = (bytes[8]! & 0x3f) | 0x80; // RFC 4122 variant
  return bytesToUuid(bytes);
}

/** A STIX object id of the form `<type>--<uuid>`, deterministic from `seed`. */
function stixId(type: string, seed: string): string {
  return `${type}--${uuidv5(`${type}:${seed}`)}`;
}

// ----- STIX value helpers ----------------------------------------------------

/** STIX timestamps are RFC 3339 / ISO-8601 UTC with millisecond precision. */
function stixTime(ms: number): string {
  return new Date(ms).toISOString();
}

/**
 * Escape a string value for embedding inside a STIX pattern single-quoted
 * literal. STIX patterning escapes `\` and `'`; an IP can't contain either, but
 * we harden anyway so the pattern is always syntactically valid.
 */
function patternEscape(v: string): string {
  return v.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

/** The STIX Cyber-observable pattern for an attacker IP (v4 or v6 aware). */
function ipPattern(ip: string, family: 4 | 6): string {
  const objType = family === 6 ? "ipv6-addr" : "ipv4-addr";
  return `[${objType}:value = '${patternEscape(ip)}']`;
}

/** Lower-kebab a free-text category into a STIX-friendly label token. */
function toLabel(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

// ----- SDO builders ----------------------------------------------------------

/** The producer Identity SDO — SecTool itself, referenced by every Indicator. */
function buildIdentity(nowMs: number): StixObject {
  const ts = stixTime(nowMs);
  return {
    type: "identity",
    spec_version: STIX_VERSION,
    id: stixId("identity", "sectool"),
    created: ts,
    modified: ts,
    name: "SecTool",
    identity_class: "system",
    description:
      "SecTool — UDM Pro IDS/IPS alert ingestion, correlation and analysis. " +
      "Indicators are derived from observed Suricata alert traffic.",
  };
}

/** Map one scored IOC indicator to a STIX 2.1 Indicator SDO. */
function buildIndicator(ind: IocIndicator, identityId: string, nowMs: number): StixObject {
  const ts = stixTime(nowMs);
  const pattern = ipPattern(ind.ip, ind.family);

  // Categories become open-vocab labels; always assert malicious-activity, and
  // anomalous-activity when the gateway itself corroborated by blocking.
  const labels = [...new Set(ind.categories.map(toLabel).filter(Boolean))];
  const indicatorTypes = ["malicious-activity"];
  if (ind.blockedCount > 0) indicatorTypes.push("anomalous-activity");

  const externalReferences: StixObject[] = [];
  if (ind.signatures.length) {
    externalReferences.push({
      source_name: "sectool-signature",
      description: `Top Suricata signature(s): ${ind.signatures.slice(0, 3).join("; ")}`,
    });
  }

  const descParts = [
    `Source IP observed in ${ind.alertCount} SecTool alert(s) ` +
      `(worst severity ${ind.severityMax}) across ${ind.signatureCount} signature(s) ` +
      `and ${ind.targetCount} internal host(s).`,
  ];
  if (ind.blockedCount > 0) {
    descParts.push(`The gateway already blocked ${ind.blockedCount} of these alert(s).`);
  }
  if (ind.watched) {
    descParts.push(`Operator watchlist match${ind.watchNote ? `: ${ind.watchNote}` : ""}.`);
  }

  const obj: StixObject = {
    type: "indicator",
    spec_version: STIX_VERSION,
    id: stixId("indicator", ind.ip),
    created_by_ref: identityId,
    created: ts,
    modified: ts,
    name: `Malicious host ${ind.ip}`,
    description: descParts.join(" "),
    indicator_types: indicatorTypes,
    pattern,
    pattern_type: "stix",
    pattern_version: STIX_VERSION,
    valid_from: stixTime(ind.firstSeen),
    // STIX confidence is an integer 0–100 — SecTool's blocklist confidence maps directly.
    confidence: ind.confidence,
  };
  if (labels.length) obj.labels = labels;
  if (externalReferences.length) obj.external_references = externalReferences;
  return obj;
}

// ----- markdown twin ---------------------------------------------------------

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function mdCell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function renderMarkdown(m: StixReport, indicators: IocIndicator[]): string {
  const lines: string[] = [];
  lines.push(`# 🛰️ SecTool STIX 2.1 Threat-Intel Export`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`,
  );
  lines.push(
    `**Bundle:** \`${m.bundle.id}\` · **Objects:** ${m.objectCount} ` +
      `(${m.indicatorCount} Indicator + 1 Identity) · **Min severity:** ${m.minSeverity}` +
      (m.excludedSafe ? ` · **Excluded (safelisted):** ${m.excludedSafe}` : "") +
      (m.truncated ? ` · **Truncated:** ${m.truncated} more` : ""),
  );
  lines.push("");

  if (!m.indicatorCount) {
    lines.push(
      `No external attacker IPs at **${m.minSeverity}** severity or above in the last ${m.hours} hour(s).` +
        (m.excludedBelowSeverity
          ? ` (${m.excludedBelowSeverity} lower-severity IP(s) were below the floor.)`
          : ""),
    );
    lines.push("");
    lines.push("The bundle still validates — it contains only the producer Identity object.");
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  lines.push(
    `A standards-compliant **OASIS STIX 2.1** bundle for ingestion into MISP, OpenCTI, a TAXII 2.1 ` +
      `collection, or any STIX-aware SIEM. Object IDs are **deterministic (UUIDv5)** so re-publishing the ` +
      `same intel updates objects in place instead of creating duplicates.`,
  );
  lines.push("");

  const head = ["IP", "Conf.", "Sev", "Alerts", "Indicator ID"];
  lines.push(`| ${head.join(" | ")} |`);
  lines.push(`| ${head.map(() => "---").join(" | ")} |`);
  for (const ind of indicators) {
    lines.push(
      `| ${mdCell(ind.ip)} | ${ind.confidence} | ${mdCell(ind.severityMax)} | ${ind.alertCount} | ` +
        `\`${stixId("indicator", ind.ip)}\` |`,
    );
  }
  lines.push("");

  lines.push(`## Bundle (STIX 2.1 JSON)`);
  lines.push("");
  lines.push("Save as `.json` and import into your TI platform / TAXII server:");
  lines.push("");
  lines.push("```json");
  lines.push(m.json);
  lines.push("```");
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. Indicators are scored by the same heuristic confidence model as the ` +
      `IOC export (severity, volume, gateway corroboration, watchlist) and surfaced in the STIX ` +
      `\`confidence\` field — review before auto-actioning downstream. Safelisted IPs are excluded by ` +
      `default. A long look-back can hit the alert store's retention cap and clip the earliest ` +
      `indicators. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

// ----- entry point -----------------------------------------------------------

/**
 * Build the STIX 2.1 export bundle from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days] by the IOC engine).
 * @param opts  {@link StixOptions}: severity floor, indicator limit, safelist
 *              handling, and a `nowMs` pin for deterministic / reproducible output.
 */
export function buildStix(hours: number, opts: StixOptions = {}): StixReport {
  const nowMs = opts.nowMs ?? Date.now();

  // Reuse the IOC engine as the scoring source of truth — same filters, same
  // confidence model, same safelist/dismissed handling. No logic duplicated.
  const ioc = buildIocExport(hours, {
    minSeverity: opts.minSeverity,
    limit: opts.limit,
    includeSafe: opts.includeSafe,
    nowMs,
  });

  const identity = buildIdentity(nowMs);
  const identityId = identity.id as string;
  const indicatorObjs = ioc.indicators.map((ind) => buildIndicator(ind, identityId, nowMs));

  // Deterministic bundle id from the window + the (already deterministic) member
  // ids, so identical content yields an identical bundle id across runs.
  const seed =
    `${ioc.windowStartMs}:${ioc.windowEndMs}:` +
    indicatorObjs.map((o) => o.id as string).join(",");
  const bundle: StixBundle = {
    type: "bundle",
    id: stixId("bundle", seed),
    objects: [identity, ...indicatorObjs],
  };

  const json = JSON.stringify(bundle, null, 2);

  const model: StixReport = {
    hours: ioc.hours,
    windowStartMs: ioc.windowStartMs,
    windowEndMs: ioc.windowEndMs,
    minSeverity: ioc.minSeverity,
    indicatorCount: indicatorObjs.length,
    objectCount: bundle.objects.length,
    excludedSafe: ioc.excludedSafe,
    excludedBelowSeverity: ioc.excludedBelowSeverity,
    truncated: ioc.truncated,
    bundle,
    json,
    markdown: "",
  };
  model.markdown = renderMarkdown(model, ioc.indicators);
  return model;
}

/** A filesystem-safe filename for a downloaded STIX bundle. */
export function stixFilename(nowMs: number): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  return `sectool-stix-${stamp}.json`;
}
