/**
 * Elastic Common Schema (ECS) event export — re-shape the stored alert history
 * into **ECS-normalized JSON documents** ready to load straight into the
 * Elastic Stack / OpenSearch ecosystem, the one major SIEM target SecTool's
 * other event export does not speak.
 *
 * SecTool already forwards events to the *legacy, line-oriented* collectors via
 * `cefExport.ts` (CEF for ArcSight / Splunk / Sentinel, LEEF for QRadar). But
 * the single most-deployed open-source SIEM stack — Elasticsearch + Kibana +
 * Elastic Security, and its OpenSearch fork — does not ingest CEF natively; it
 * ingests **JSON documents mapped onto the Elastic Common Schema** (`source.ip`,
 * `destination.port`, `event.category`, `rule.name`, …). That is a completely
 * different shape and a different ingestion path (`Filebeat` / `Logstash` / the
 * `_bulk` API), so it needs its own exporter. This module is that exporter.
 *
 * It is deliberately orthogonal to SecTool's other six exports — confusing them
 * defeats the purpose:
 *
 *   - **iocExport.ts** emits a deduplicated, confidence-ranked list of *bad IPs*
 *     (an indicator/blocklist source). One row per attacker.
 *   - **stix.ts** emits *threat-intel objects* (STIX SDOs) for MISP / OpenCTI.
 *   - **sigma.ts** emits *detection rules* (logic a SIEM evaluates) and
 *     **snort.ts** the same for the IDS sensor.
 *   - **cefExport.ts** emits the *events themselves* as CEF / LEEF **lines** for
 *     the legacy collectors.
 *   - **This module** emits the *events themselves* as ECS **JSON documents** for
 *     the Elastic / OpenSearch collectors — the same "forward my IPS log into the
 *     SIEM" primitive as CEF, but in the schema and serialization the modern
 *     ELK / OpenSearch pipeline actually expects. One document per alert.
 *
 * For every stored alert in the window this module recovers a normalized record
 * — exactly the same field recovery `cefExport.ts` uses (the stable Suricata
 * `gid:sid` rule identity, the source/destination IPs, and the ports / transport
 * / application protocol re-parsed from the raw line, since SecTool's store keeps
 * no flow column) — and maps it onto canonical ECS fields:
 *
 *   - `@timestamp`, `event.{kind,category,type,action,severity,id,module,dataset}`
 *   - `log.level`, `message`, `tags`
 *   - `source.{ip,port}`, `destination.{ip,port}`
 *   - `network.{transport,protocol,direction,type}`
 *   - `rule.{id,name,ruleset,category,reference}`
 *   - `observer.{vendor,product,type}`
 *   - `ecs.version`
 *
 * Four serializations cover the whole Elastic ingestion surface:
 *
 *   - **bulk** (default) — newline-delimited JSON ready to `POST .../_bulk`: each
 *     document is preceded by its `{"index":{...}}` action line carrying a
 *     **deterministic `_id`** (SecTool's alert id) so re-publishing the same
 *     window is idempotent — no duplicate documents on re-index.
 *   - **ndjson** — the bare documents, one JSON object per line, for a Filebeat /
 *     Logstash / Fluent Bit file input that supplies its own index routing.
 *   - **json** — the full structured model (metadata + the documents array),
 *     pretty-printed, mirroring the other reports' `json` format.
 *   - **markdown** — the human review twin: a sample document, a compact event
 *     table and the curl one-liner to load it.
 *
 * Honest about its limits, all surfaced in the output:
 *   - **Ports & protocol are re-parsed, not stored.** Recovered from each alert's
 *     raw line (same as `cef` / `ports` / `protocols`); alerts whose raw text no
 *     longer carries a flow tuple omit those fields — the document is still valid.
 *   - **Severity is mapped, not measured.** SecTool's five-rung ladder is folded
 *     onto the 0–99 risk-score scale Elastic Security uses (low 21 / medium 47 /
 *     high 73 / critical 99) so alerts bucket naturally there.
 *   - **Window-bounded & store-capped.** A long look-back can hit the alert
 *     store's retention cap and miss older events.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network — so it is
 * safe to call from the dashboard or CLI at any time. Mirrors the model + render
 * shape of cefExport.ts so it plugs into the same CLI and HTTP plumbing.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { safeStore } from "../store/safelist.ts";
import { recoverFlow } from "./ports.ts";
import { recoverSrcPort } from "./srcport.ts";
import { recoverProtocol } from "./protocols.ts";
import { recoverRuleId } from "./ruleset.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Serializations the export can render into. */
export type EcsFormat = "bulk" | "ndjson" | "json" | "markdown";

/** ECS revision the documents conform to (stamped into `ecs.version`). */
export const ECS_VERSION = "8.11.0";

/** Default `_index` / data-stream name written into each bulk action line. */
const DEFAULT_INDEX = "sectool-alerts";

/** Identity stamped into every document's `observer.*` fields. */
const OBSERVER_VENDOR = "Ubiquiti";
const OBSERVER_PRODUCT = "UDM Pro";
const OBSERVER_TYPE = "ids";

/** Hard ceiling on emitted documents (matches the alert store retention cap). */
const MAX_EVENTS = 2000;
const MS_PER_HOUR = 3_600_000;

/**
 * SecTool's five-rung severity ladder folded onto the 0–99 risk-score scale
 * Elastic Security uses for detection signals (low 21 / medium 47 / high 73 /
 * critical 99), so exported alerts bucket into the same severity bands an Elastic
 * analyst already reasons about. `info` maps to 0 (informational, not a signal).
 */
const ECS_SEVERITY: Record<Severity, number> = {
  info: 0,
  low: 21,
  medium: 47,
  high: 73,
  critical: 99,
};

/**
 * Severity word → ECS `log.level` token. ECS `log.level` is free text but the
 * Elastic convention leans on a small vocabulary; this keeps the mapping stable
 * and greppable in Kibana.
 */
const LOG_LEVEL: Record<Severity, string> = {
  info: "informational",
  low: "low",
  medium: "medium",
  high: "high",
  critical: "critical",
};

/** Coarse traffic direction relative to the internal estate. */
export type TrafficDirection = "inbound" | "outbound" | "lateral" | "external";

/**
 * Map SecTool's traffic direction onto an ECS `network.direction` allowed value.
 * ECS permits `inbound` / `outbound` / `internal` / `external` / `unknown`; our
 * `lateral` (private→private) is ECS `internal`, and an indeterminate flow is
 * `unknown` rather than the non-standard `external`.
 */
const ECS_DIRECTION: Record<TrafficDirection, string> = {
  inbound: "inbound",
  outbound: "outbound",
  lateral: "internal",
  external: "unknown",
};

/**
 * Gateway disposition → ECS `event.type` allowed values. A blocked alert is a
 * `denied` connection, a passed one `allowed`; an unknown disposition carries no
 * action verb, only `info`.
 */
const EVENT_TYPE: Record<"blocked" | "passed" | "unknown", string[]> = {
  blocked: ["denied", "connection"],
  passed: ["allowed", "connection"],
  unknown: ["info", "connection"],
};

/** One normalized event, pre-ECS — the intermediate the document is built from. */
export interface EcsEvent {
  /** SecTool's stable alert id (becomes the bulk `_id` and `event.id`). */
  id: string;
  /** Event time, ms epoch (`@timestamp`). */
  time: number;
  /** SecTool severity word. */
  severity: Severity;
  /** Severity mapped onto the 0–99 Elastic risk-score scale (`event.severity`). */
  ecsSeverity: number;
  /** The stable `gid:sid` rule identity, used for `rule.id` / `rule.ruleset`. */
  ruleSid?: number;
  ruleGid?: number;
  /** The human signature text (`rule.name`, `message`). */
  name: string;
  /** Suricata classification / classtype (`rule.category`). */
  classification?: string;
  /** Suricata category. */
  category?: string;
  /** Attacker / source IP, if present. */
  srcIp?: string;
  /** Destination / victim IP, if present. */
  dstIp?: string;
  /** Source port, re-parsed from the raw line. */
  srcPort?: number;
  /** Destination port, re-parsed from the raw line. */
  dstPort?: number;
  /** Transport protocol (tcp/udp/icmp…), re-parsed from the raw line. */
  transport?: string;
  /** Application protocol (http/dns/tls…), re-parsed from the raw line. */
  appProto?: string;
  /** Coarse gateway disposition. */
  disposition: "blocked" | "passed" | "unknown";
  /** Inbound / outbound / lateral / external relative to the estate. */
  direction: TrafficDirection;
  /** True when the source IP is on the vetted-benign safelist. */
  safelisted: boolean;
}

/** A finished ECS document — a nested JSON object conforming to ECS. */
export type EcsDocument = Record<string, unknown>;

export interface EcsExport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** ECS revision stamped into every document. */
  ecsVersion: string;
  /** The `_index` / data-stream the bulk action lines target. */
  index: string;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Documents emitted (after the limit). */
  totalEvents: number;
  /** Documents dropped by the `limit` (totalEvents ignores these). */
  truncated: number;
  /** The normalized events, newest first. */
  events: EcsEvent[];
}

export interface EcsExportOptions {
  /** Cap on emitted documents (newest first). Default = the store cap. */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
  /** Override the target `_index` / data-stream name. */
  index?: string;
}

// ----- classifiers / helpers (mirror cefExport.ts) ---------------------------

/** RFC1918 / loopback / link-local / ULA — an address treated as one of ours. */
function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|fc|fd)/i.test(ip);
}

/** A valid, non-empty IP, or undefined if the field is missing/garbage. */
function validIp(ip: string | undefined): string | undefined {
  return ip && isIP(ip) !== 0 ? ip : undefined;
}

function sevWord(s: string | undefined): Severity {
  return (SEVERITY_ORDER as readonly string[]).includes(s ?? "") ? (s as Severity) : "info";
}

/** Direction of a flow relative to the internal estate. */
function directionOf(src: string | undefined, dst: string | undefined): TrafficDirection {
  const sPriv = src ? isPrivate(src) : undefined;
  const dPriv = dst ? isPrivate(dst) : undefined;
  if (sPriv === false && dPriv === true) return "inbound";
  if (sPriv === true && dPriv === false) return "outbound";
  if (sPriv === true && dPriv === true) return "lateral";
  return "external";
}

/** ECS `network.type` for an IP: ipv4 / ipv6, or undefined if unparseable. */
function ipVersion(ip: string | undefined): string | undefined {
  if (!ip) return undefined;
  const v = isIP(ip);
  return v === 4 ? "ipv4" : v === 6 ? "ipv6" : undefined;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

// ----- ECS document construction ---------------------------------------------

/**
 * Assign `obj[key] = value` only when `value` is meaningful — undefined, null,
 * empty-string and empty-array fields are dropped so documents stay sparse and
 * ECS-clean (Elastic indexes absence as absence, not as empty values).
 */
function set(obj: Record<string, unknown>, key: string, value: unknown): void {
  if (value === undefined || value === null || value === "") return;
  if (Array.isArray(value) && value.length === 0) return;
  obj[key] = value;
}

/** Build the nested ECS document for one normalized event. */
export function toEcsDocument(e: EcsEvent, ecsVersion: string): EcsDocument {
  const event: Record<string, unknown> = {};
  set(event, "kind", "alert");
  set(event, "category", ["intrusion_detection", "network"]);
  set(event, "type", EVENT_TYPE[e.disposition]);
  set(event, "action", e.disposition === "unknown" ? "detected" : e.disposition);
  set(event, "severity", e.ecsSeverity);
  set(event, "id", e.id);
  set(event, "module", "suricata");
  set(event, "dataset", "suricata.alert");
  set(event, "provider", "SecTool");

  const source: Record<string, unknown> = {};
  set(source, "ip", e.srcIp);
  set(source, "port", e.srcPort);

  const destination: Record<string, unknown> = {};
  set(destination, "ip", e.dstIp);
  set(destination, "port", e.dstPort);

  const network: Record<string, unknown> = {};
  set(network, "transport", e.transport ? e.transport.toLowerCase() : undefined);
  set(network, "protocol", e.appProto);
  set(network, "direction", ECS_DIRECTION[e.direction]);
  // network.type prefers the source's IP family, falling back to the destination.
  set(network, "type", ipVersion(e.srcIp) ?? ipVersion(e.dstIp));

  const rule: Record<string, unknown> = {};
  set(rule, "id", e.ruleSid !== undefined ? String(e.ruleSid) : undefined);
  set(rule, "name", e.name);
  set(rule, "ruleset", e.ruleGid !== undefined ? `gid:${e.ruleGid}` : undefined);
  set(rule, "category", e.classification);

  const observer: Record<string, unknown> = {};
  set(observer, "vendor", OBSERVER_VENDOR);
  set(observer, "product", OBSERVER_PRODUCT);
  set(observer, "type", OBSERVER_TYPE);

  const tags = ["sectool", e.severity, e.disposition, ECS_DIRECTION[e.direction]];
  if (e.safelisted) tags.push("safelisted");
  if (e.category) tags.push(e.category);

  const doc: EcsDocument = {};
  set(doc, "@timestamp", new Date(e.time).toISOString());
  set(doc, "message", e.name);
  set(doc, "tags", tags);
  set(doc, "ecs", { version: ecsVersion });
  set(doc, "log", { level: LOG_LEVEL[e.severity] });
  set(doc, "event", event);
  set(doc, "source", source);
  set(doc, "destination", destination);
  set(doc, "network", network);
  set(doc, "rule", rule);
  set(doc, "observer", observer);
  return doc;
}

// ----- line / stream rendering -----------------------------------------------

/**
 * Render the bulk-API stream: one `{"index":{...}}` action line per document,
 * each carrying SecTool's alert id as the deterministic `_id` so a re-published
 * window updates documents in place instead of duplicating them. Terminated with
 * a trailing newline, exactly as the `_bulk` endpoint requires.
 */
function renderBulk(m: EcsExport): string {
  const lines: string[] = [];
  for (const e of m.events) {
    lines.push(JSON.stringify({ index: { _index: m.index, _id: e.id } }));
    lines.push(JSON.stringify(toEcsDocument(e, m.ecsVersion)));
  }
  // The _bulk API mandates a trailing newline after the final document.
  return lines.length ? lines.join("\n") + "\n" : "";
}

/** Render the bare documents, one JSON object per line (no action lines). */
function renderNdjson(m: EcsExport): string {
  return m.events.map((e) => JSON.stringify(toEcsDocument(e, m.ecsVersion))).join("\n");
}

// ----- markdown twin ---------------------------------------------------------

function mdCell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function renderMarkdown(m: EcsExport): string {
  const lines: string[] = [];
  lines.push(`# 🔎 SecTool ECS (Elastic Common Schema) Event Export`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(`**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**ECS:** \`${m.ecsVersion}\` · **Index:** \`${m.index}\` · ` +
      `**Documents:** ${m.totalEvents}` +
      (m.truncated ? ` · **Truncated:** ${m.truncated} older event(s)` : ""),
  );
  lines.push("");

  if (!m.totalEvents) {
    lines.push(`No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to forward.`);
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  lines.push(
    `One IPS alert per ECS document, ready for Elasticsearch / OpenSearch (Kibana, Elastic Security). ` +
      `Severity is mapped onto the 0–99 Elastic risk-score scale; ports and protocol are re-parsed from each ` +
      `alert's raw line.`,
  );
  lines.push("");

  // The curl one-liner that loads the bulk stream — the deliverable's "how to use".
  lines.push(`## Load it`);
  lines.push("");
  lines.push("```bash");
  lines.push(`# Request the bulk stream and POST it to your cluster's _bulk endpoint:`);
  lines.push(
    `curl -s -H 'Content-Type: application/x-ndjson' \\\n` +
      `  'http://<sectool-host>/api/ecs.ndjson?hours=${m.hours}' \\\n` +
      `  | curl -s -H 'Content-Type: application/x-ndjson' \\\n` +
      `      -XPOST 'https://<elastic-host>:9200/_bulk' --data-binary @-`,
  );
  lines.push("```");
  lines.push("");

  // A sample document — the shape an operator verifies before wiring a pipeline.
  const sample = m.events[0]!;
  lines.push(`## Sample document`);
  lines.push("");
  lines.push("```json");
  lines.push(JSON.stringify(toEcsDocument(sample, m.ecsVersion), null, 2));
  lines.push("```");
  lines.push("");

  // A compact human table over the same events.
  const head = ["@timestamp", "Sev (score)", "rule.id", "rule.name", "source.ip", "destination.ip", "net", "dir", "type"];
  lines.push(`## Events`);
  lines.push("");
  lines.push(`| ${head.join(" | ")} |`);
  lines.push(`| ${head.map(() => "---").join(" | ")} |`);
  for (const e of m.events.slice(0, 100)) {
    const src = e.srcIp ? `${e.srcIp}${e.srcPort ? `:${e.srcPort}` : ""}` : "·";
    const dst = e.dstIp ? `${e.dstIp}${e.dstPort ? `:${e.dstPort}` : ""}` : "·";
    lines.push(
      `| ${[
        fmtTime(e.time),
        `${e.severity} (${e.ecsSeverity})`,
        e.ruleSid !== undefined ? String(e.ruleSid) : "·",
        mdCell(e.name),
        mdCell(src),
        mdCell(dst),
        e.transport ? e.transport.toLowerCase() : "·",
        ECS_DIRECTION[e.direction],
        EVENT_TYPE[e.disposition][0]!,
      ].join(" | ")} |`,
    );
  }
  if (m.events.length > 100) {
    lines.push("");
    lines.push(
      `_…and ${m.events.length - 100} more event(s) — request the \`bulk\` or \`ndjson\` format for the full stream._`,
    );
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. This is the **Elastic / OpenSearch** event-forwarding export (one ECS JSON ` +
      `document per alert), the modern-SIEM sibling of the \`cef\` CEF/LEEF line export — distinct from the \`iocs\` ` +
      `indicator list, the \`stix\` intel bundle and the \`sigma\` detection rules. The \`bulk\` format carries a ` +
      `deterministic \`_id\` (the alert id) so re-publishing is idempotent. Severity is mapped onto the 0–99 Elastic ` +
      `risk-score scale; ports and protocol are **re-parsed from each alert's raw line**, not a stored column, so they ` +
      `are omitted when the raw text no longer carries them. A long look-back can hit the alert store's retention cap ` +
      `and miss older events. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

// ----- build -----------------------------------------------------------------

/**
 * Build the ECS event-export model from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link EcsExportOptions}: `limit`, `index`, and a `nowMs` pin for
 *              deterministic tests.
 */
export function buildEcsExport(hours: number, opts: EcsExportOptions = {}): EcsExport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;
  const limit =
    opts.limit !== undefined ? Math.max(1, Math.min(MAX_EVENTS, Math.floor(opts.limit))) : MAX_EVENTS;
  const index = (opts.index ?? DEFAULT_INDEX).trim() || DEFAULT_INDEX;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);
  // alertStore.all() already returns newest-first; keep that order for the stream.

  const allEvents: EcsEvent[] = windowed.map((a) => {
    const flow = recoverFlow(a.raw);
    const proto = recoverProtocol(a.raw);
    const srcPort = recoverSrcPort(a.raw);
    const ruleId = recoverRuleId(a.raw);
    const severity = sevWord(a.severity);
    const src = validIp(a.srcIp);
    const dst = validIp(a.dstIp);

    return {
      id: a.id,
      time: a.time,
      severity,
      ecsSeverity: ECS_SEVERITY[severity],
      ruleSid: ruleId?.sid,
      ruleGid: ruleId?.gid,
      name: a.signature ?? a.category ?? "IPS alert",
      classification: a.classification,
      category: a.category,
      srcIp: src,
      dstIp: dst,
      srcPort,
      dstPort: flow?.dstPort,
      transport: proto.transport ?? flow?.protocol,
      appProto: proto.appProto,
      disposition: classifyDisposition(a.action),
      direction: directionOf(src, dst),
      safelisted: src ? safeStore.has(src) : false,
    } satisfies EcsEvent;
  });

  const truncated = Math.max(0, allEvents.length - limit);
  const events = allEvents.slice(0, limit);

  return {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    ecsVersion: ECS_VERSION,
    index,
    totalWindowAlerts: windowed.length,
    totalEvents: events.length,
    truncated,
    events,
  };
}

/**
 * Render a built ECS export model into the requested serialization. `bulk`
 * produces the `_bulk`-ready action+document stream (the default deliverable);
 * `ndjson` the bare documents; `markdown` the human review twin; `json` the
 * structured model with its `documents` array materialized.
 */
export function renderEcs(model: EcsExport, format: EcsFormat): string {
  switch (format) {
    case "ndjson":
      return renderNdjson(model);
    case "markdown":
      return renderMarkdown(model);
    case "json":
      // Materialize the documents alongside the metadata so the JSON model is
      // self-contained (the events array is the pre-ECS intermediate).
      return JSON.stringify(
        { ...model, documents: model.events.map((e) => toEcsDocument(e, model.ecsVersion)) },
        null,
        2,
      );
    case "bulk":
    default:
      return renderBulk(model);
  }
}

/** A filesystem-safe filename for a downloaded ECS export in the given format. */
export function ecsFilename(nowMs: number, format: EcsFormat): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  const ext = format === "markdown" ? "md" : format === "json" ? "json" : "ndjson";
  return `sectool-ecs-${stamp}.${ext}`;
}

/** Coerce an arbitrary string into a valid {@link EcsFormat}, defaulting to bulk. */
export function parseEcsFormat(raw: string | undefined | null): EcsFormat {
  const f = (raw ?? "").trim().toLowerCase();
  if (f === "ndjson") return "ndjson";
  if (f === "json") return "json";
  if (f === "markdown" || f === "md") return "markdown";
  return "bulk";
}
