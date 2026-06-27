/**
 * CEF / LEEF SIEM event-export — turn the stored alert history into a stream of
 * **normalized log-forwarding events** that a legacy SIEM can ingest directly,
 * one line per alert, in the two interchange syntaxes those products speak:
 *
 *   - **CEF** (ArcSight Common Event Format) — `CEF:0|Vendor|Product|Version|
 *     SignatureID|Name|Severity|extension…`. The lingua franca of Micro Focus
 *     ArcSight, and a first-class ingest format for Splunk (the CEF add-on),
 *     Microsoft Sentinel (the CEF-via-AMA connector) and almost every other
 *     log pipeline.
 *   - **LEEF** (IBM Log Event Extended Format) — `LEEF:2.0|Vendor|Product|
 *     Version|EventID|<delim>key=value…`. QRadar's native event syntax.
 *
 * This is deliberately orthogonal to SecTool's other three exports, and the
 * distinction is the whole point — mixing them up defeats it:
 *
 *   - **iocExport.ts** emits a deduplicated, confidence-ranked list of *bad IPs*
 *     (an indicator/blocklist source). One row per attacker.
 *   - **stix.ts** emits *threat-intel objects* (STIX Indicator/Identity SDOs) for
 *     MISP / OpenCTI / a TAXII collection. One object per attacker.
 *   - **sigma.ts** emits *detection rules* (Sigma YAML) — logic a SIEM evaluates
 *     against its own data.
 *   - **This module** emits the *events themselves* — the raw, per-alert
 *     telemetry — re-shaped into the line format an event collector expects. One
 *     line per alert. It is the "forward my IPS log into the SIEM" primitive that
 *     closes the loop the other three assume already happened: they all describe
 *     *what to look for*; CEF/LEEF carries *what was seen*.
 *
 * For every stored alert in the window this module recovers a normalized event
 * record — severity (mapped onto CEF's 0–10 scale), the stable Suricata
 * `gid:sid` as the event/signature id, the signature text as the name, the
 * source/destination IPs and (re-parsed from the raw line, since SecTool's store
 * keeps no port/protocol column — exactly like ports.ts, srcport.ts and
 * protocols.ts) the source/destination ports, transport and application
 * protocol, the gateway disposition, and the inbound/outbound/lateral traffic
 * direction — then renders it into the requested syntax with full, spec-correct
 * escaping (CEF header `\` / `|`, CEF extension `\` / `=` / newline; LEEF tab /
 * newline). A Markdown review twin and the structured JSON model round out the
 * four output formats, mirroring iocExport.ts.
 *
 * Honest about its limits, all surfaced in the output:
 *   - **Ports & protocol are re-parsed, not stored.** Recovered from each alert's
 *     raw line; alerts whose raw text no longer carries a flow tuple or JSON
 *     payload simply omit those extension keys (the event is still emitted).
 *   - **Severity is mapped, not measured.** SecTool's five-rung ladder is folded
 *     onto CEF's 0–10 integer scale by a fixed table.
 *   - **Window-bounded & store-capped.** A long look-back can hit the alert
 *     store's retention cap and miss older events.
 *
 * Pure in-memory math over alertStore — no SSH, no Claude, no network — so it is
 * safe to call from the dashboard or CLI at any time.
 */
import { isIP } from "node:net";
import { alertStore, type StoredAlert } from "../store/alertStore.ts";
import { recoverFlow } from "./ports.ts";
import { recoverSrcPort } from "./srcport.ts";
import { recoverProtocol } from "./protocols.ts";
import { recoverRuleId } from "./ruleset.ts";
import { classifyDisposition } from "./efficacy.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";

/** Interchange syntaxes / serializations the export can render into. */
export type CefFormat = "cef" | "leef" | "json" | "markdown";

/** Default device identity stamped into every event header. */
const DEFAULT_VENDOR = "SecTool";
const DEFAULT_PRODUCT = "UDM-Pro-IPS";
const DEFAULT_VERSION = "1.0";

/** Hard ceiling on emitted events (matches the alert store retention cap). */
const MAX_EVENTS = 2000;
const MS_PER_HOUR = 3_600_000;

/**
 * SecTool's five-rung severity ladder folded onto CEF's 0–10 integer scale
 * (LEEF uses the same 0–10 `sev` convention, so the table is shared).
 */
const CEF_SEVERITY: Record<Severity, number> = {
  info: 0,
  low: 3,
  medium: 6,
  high: 8,
  critical: 10,
};

/** Coarse traffic direction relative to the internal estate. */
export type TrafficDirection = "inbound" | "outbound" | "lateral" | "external";

/** One normalized event ready to serialize as a CEF / LEEF line. */
export interface CefEvent {
  /** SecTool's stable alert id (CEF `externalId`, LEEF `externalId`). */
  id: string;
  /** Event time, ms epoch (CEF `rt`, LEEF `devTime`). */
  time: number;
  /** SecTool severity word. */
  severity: Severity;
  /** Severity mapped onto the CEF/LEEF 0–10 scale. */
  cefSeverity: number;
  /** The stable `gid:sid` rule identity, used as the signature/event id. */
  signatureId: string;
  /** The human signature text (CEF `Name`). */
  name: string;
  /** Suricata classification (classtype), if any. */
  classification?: string;
  /** Suricata category, if any. */
  category?: string;
  /** Attacker / source IP, if present. */
  srcIp?: string;
  /** Destination / victim IP, if present. */
  dstIp?: string;
  /** Source port, re-parsed from the raw line. */
  srcPort?: number;
  /** Destination port, re-parsed from the raw line. */
  dstPort?: number;
  /** Transport protocol (TCP/UDP/ICMP…), re-parsed from the raw line. */
  protocol?: string;
  /** Application protocol (http/dns/tls…), re-parsed from the raw line. */
  appProto?: string;
  /** Coarse gateway disposition. */
  disposition: "blocked" | "passed" | "unknown";
  /** Inbound / outbound / lateral / external relative to the estate. */
  direction: TrafficDirection;
}

export interface CefExport {
  hours: number;
  windowStartMs: number;
  windowEndMs: number;
  /** Device vendor stamped in the header. */
  deviceVendor: string;
  /** Device product stamped in the header. */
  deviceProduct: string;
  /** Device version stamped in the header. */
  deviceVersion: string;
  /** Alerts (with a usable timestamp) inside the window. */
  totalWindowAlerts: number;
  /** Events emitted (after the limit). */
  totalEvents: number;
  /** Events dropped by the `limit` (totalEvents ignores these). */
  truncated: number;
  /** The normalized events, newest first. */
  events: CefEvent[];
}

export interface CefExportOptions {
  /** Cap on emitted events (newest first). Default = the store cap. */
  limit?: number;
  /** Pins the window end for deterministic tests; defaults to now. */
  nowMs?: number;
  /** Override the CEF/LEEF device vendor header field. */
  deviceVendor?: string;
  /** Override the CEF/LEEF device product header field. */
  deviceProduct?: string;
  /** Override the CEF/LEEF device version header field. */
  deviceVersion?: string;
}

// ----- classifiers / helpers (mirror iocExport.ts / protocols.ts) ------------

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

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

// ----- CEF / LEEF escaping ---------------------------------------------------

/**
 * Escape a CEF *header* field: backslash and pipe are the field delimiters, so
 * both must be backslash-escaped; newlines/CRs are flattened to a space (a header
 * field can never span lines).
 */
function cefHeader(v: string): string {
  return v.replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/[\r\n]+/g, " ");
}

/**
 * Escape a CEF *extension* value: in the `key=value` extension, `\` and `=` are
 * special and newlines are encoded as the literal escape `\n` (per the CEF
 * spec). The key itself is always a fixed dictionary token, so only values are
 * escaped.
 */
function cefValue(v: string): string {
  return v
    .replace(/\\/g, "\\\\")
    .replace(/=/g, "\\=")
    .replace(/\r\n|\r|\n/g, "\\n");
}

/**
 * Escape a LEEF header field (`|` delimited) — backslash and pipe escaped,
 * newlines flattened. LEEF 2.0 uses the same header-delimiter rules as CEF.
 */
function leefHeader(v: string): string {
  return v.replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/[\r\n]+/g, " ");
}

/**
 * Sanitize a LEEF attribute value. LEEF attributes are delimited by a single
 * character (we use the spec-default TAB), so a literal tab or newline inside a
 * value would corrupt the record — both are flattened to a space. (LEEF has no
 * in-value escape mechanism, unlike CEF, so flattening is the correct, lossless-
 * enough choice for free-text fields.)
 */
function leefValue(v: string): string {
  return v.replace(/[\t\r\n]+/g, " ");
}

// ----- line rendering --------------------------------------------------------

/** Append a CEF extension `key=value` pair when the value is present. */
function ext(parts: string[], key: string, value: unknown): void {
  if (value === undefined || value === null || value === "") return;
  parts.push(`${key}=${cefValue(String(value))}`);
}

/** Render one normalized event as a single CEF:0 line. */
export function renderCefLine(e: CefEvent, m: CefExport): string {
  const header =
    `CEF:0|${cefHeader(m.deviceVendor)}|${cefHeader(m.deviceProduct)}|` +
    `${cefHeader(m.deviceVersion)}|${cefHeader(e.signatureId)}|` +
    `${cefHeader(e.name || "IPS alert")}|${e.cefSeverity}`;

  const parts: string[] = [];
  ext(parts, "rt", e.time);
  ext(parts, "externalId", e.id);
  ext(parts, "src", e.srcIp);
  ext(parts, "spt", e.srcPort);
  ext(parts, "dst", e.dstIp);
  ext(parts, "dpt", e.dstPort);
  ext(parts, "proto", e.protocol);
  ext(parts, "app", e.appProto);
  ext(parts, "act", e.disposition === "unknown" ? undefined : e.disposition);
  ext(parts, "cat", e.category);
  // Custom-string slots carry SecTool context that has no standard CEF key.
  if (e.classification) {
    parts.push(`cs1Label=Classification`);
    ext(parts, "cs1", e.classification);
  }
  parts.push(`cs2Label=Direction`);
  ext(parts, "cs2", e.direction);
  parts.push(`cs3Label=Severity`);
  ext(parts, "cs3", e.severity);

  return `${header}|${parts.join(" ")}`;
}

/** Append a LEEF attribute when present. */
function attr(parts: string[], key: string, value: unknown): void {
  if (value === undefined || value === null || value === "") return;
  parts.push(`${key}=${leefValue(String(value))}`);
}

/** Render one normalized event as a single LEEF:2.0 line (TAB-delimited). */
export function renderLeefLine(e: CefEvent, m: CefExport): string {
  // LEEF 2.0 declares its attribute delimiter in the header; we use TAB (\x09),
  // which we announce as the hex literal `x09` so collectors parse it reliably.
  const header =
    `LEEF:2.0|${leefHeader(m.deviceVendor)}|${leefHeader(m.deviceProduct)}|` +
    `${leefHeader(m.deviceVersion)}|${leefHeader(e.signatureId)}|x09|`;

  const parts: string[] = [];
  attr(parts, "devTime", new Date(e.time).toISOString());
  attr(parts, "devTimeFormat", "yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
  attr(parts, "externalId", e.id);
  attr(parts, "sev", e.cefSeverity);
  attr(parts, "src", e.srcIp);
  attr(parts, "srcPort", e.srcPort);
  attr(parts, "dst", e.dstIp);
  attr(parts, "dstPort", e.dstPort);
  attr(parts, "proto", e.protocol);
  attr(parts, "appProto", e.appProto);
  attr(parts, "name", e.name);
  attr(parts, "cat", e.category);
  attr(parts, "classification", e.classification);
  attr(parts, "action", e.disposition === "unknown" ? undefined : e.disposition);
  attr(parts, "direction", e.direction);

  return header + parts.join("\t");
}

// ----- markdown twin ---------------------------------------------------------

function mdCell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function renderMarkdown(m: CefExport): string {
  const lines: string[] = [];
  lines.push(`# 🧾 SecTool CEF / LEEF Event Export`);
  lines.push("");
  lines.push(`**Generated:** ${fmtTime(m.windowEndMs)}`);
  lines.push(
    `**Window:** last ${m.hours} hour(s) — ${fmtTime(m.windowStartMs)} → ${fmtTime(m.windowEndMs)}`,
  );
  lines.push(
    `**Device:** \`${m.deviceVendor}\` / \`${m.deviceProduct}\` / \`${m.deviceVersion}\` · ` +
      `**Events:** ${m.totalEvents}` +
      (m.truncated ? ` · **Truncated:** ${m.truncated} older event(s)` : ""),
  );
  lines.push("");

  if (!m.totalEvents) {
    lines.push(
      `No alerts with a usable timestamp in the last ${m.hours} hour(s) — nothing to forward.`,
    );
    lines.push("");
    lines.push("---");
    lines.push(`_Generated offline by SecTool. No live gateway query was performed._`);
    lines.push("");
    return lines.join("\n");
  }

  lines.push(
    `One IPS alert per event, normalized for a CEF-aware (ArcSight / Splunk / Sentinel) or ` +
      `LEEF-aware (QRadar) collector. Severity is mapped onto the 0–10 scale; ports and ` +
      `protocol are re-parsed from each alert's raw line.`,
  );
  lines.push("");

  // A preview of the actual CEF lines — the deliverable an operator pastes.
  const preview = m.events.slice(0, 10);
  lines.push(`## CEF preview (first ${preview.length} of ${m.totalEvents})`);
  lines.push("");
  lines.push("```");
  for (const e of preview) lines.push(renderCefLine(e, m));
  lines.push("```");
  lines.push("");

  lines.push(`## LEEF preview (first ${preview.length} of ${m.totalEvents})`);
  lines.push("");
  lines.push("```");
  for (const e of preview) lines.push(renderLeefLine(e, m).replace(/\t/g, " "));
  lines.push("```");
  lines.push("");
  lines.push(`> LEEF lines are TAB-delimited on the wire; tabs are shown as spaces above for readability.`);
  lines.push("");

  // A compact human table over the same events.
  const head = ["Time", "Sev", "SigID", "Name", "Src", "Dst", "Proto", "Dir", "Action"];
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
        `${e.severity} (${e.cefSeverity})`,
        e.signatureId,
        mdCell(e.name),
        mdCell(src),
        mdCell(dst),
        e.protocol ?? "·",
        e.direction,
        e.disposition,
      ].join(" | ")} |`,
    );
  }
  if (m.events.length > 100) {
    lines.push("");
    lines.push(`_…and ${m.events.length - 100} more event(s) — request the \`cef\` or \`leef\` format for the full stream._`);
  }
  lines.push("");

  lines.push("---");
  lines.push(
    `_Generated offline by SecTool. This is an **event-forwarding** export (one line per alert), distinct from the ` +
      `\`iocs\` indicator list, the \`stix\` intel bundle and the \`sigma\` detection rules. Severity is mapped onto ` +
      `the CEF/LEEF 0–10 scale; ports and protocol are **re-parsed from each alert's raw line**, not a stored column, ` +
      `so they are omitted when the raw text no longer carries them. A long look-back can hit the alert store's ` +
      `retention cap and miss older events. No live gateway query was performed._`,
  );
  lines.push("");
  return lines.join("\n");
}

// ----- build -----------------------------------------------------------------

/**
 * Build the CEF/LEEF event-export model from the stored alert history.
 *
 * @param hours Look-back window in hours (clamped to [1, 90 days]).
 * @param opts  {@link CefExportOptions}: `limit`, device-header overrides, and a
 *              `nowMs` pin for deterministic tests.
 */
export function buildCefExport(hours: number, opts: CefExportOptions = {}): CefExport {
  const safeHours = Math.max(1, Math.min(24 * 90, Math.floor(hours)));
  const windowEndMs = opts.nowMs ?? Date.now();
  const windowStartMs = windowEndMs - safeHours * MS_PER_HOUR;
  const limit =
    opts.limit !== undefined
      ? Math.max(1, Math.min(MAX_EVENTS, Math.floor(opts.limit)))
      : MAX_EVENTS;

  const deviceVendor = (opts.deviceVendor ?? DEFAULT_VENDOR).trim() || DEFAULT_VENDOR;
  const deviceProduct = (opts.deviceProduct ?? DEFAULT_PRODUCT).trim() || DEFAULT_PRODUCT;
  const deviceVersion = (opts.deviceVersion ?? DEFAULT_VERSION).trim() || DEFAULT_VERSION;

  const windowed = alertStore
    .all()
    .filter((a): a is StoredAlert => typeof a.time === "number" && Number.isFinite(a.time))
    .filter((a) => a.time >= windowStartMs && a.time <= windowEndMs);
  // alertStore.all() already returns newest-first; keep that order for the stream.

  const allEvents: CefEvent[] = windowed.map((a) => {
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
      cefSeverity: CEF_SEVERITY[severity],
      // Prefer the stable gid:sid identity; fall back to a generic "0" so the
      // header field is never empty (CEF requires a Signature ID token).
      signatureId: ruleId ? `${ruleId.gid}:${ruleId.sid}` : "0",
      name: a.signature ?? a.category ?? "IPS alert",
      classification: a.classification,
      category: a.category,
      srcIp: src,
      dstIp: dst,
      srcPort,
      dstPort: flow?.dstPort,
      protocol: proto.transport ?? flow?.protocol,
      appProto: proto.appProto,
      disposition: classifyDisposition(a.action),
      direction: directionOf(src, dst),
    } satisfies CefEvent;
  });

  const truncated = Math.max(0, allEvents.length - limit);
  const events = allEvents.slice(0, limit);

  return {
    hours: safeHours,
    windowStartMs,
    windowEndMs,
    deviceVendor,
    deviceProduct,
    deviceVersion,
    totalWindowAlerts: windowed.length,
    totalEvents: events.length,
    truncated,
    events,
  };
}

/**
 * Render a built CEF/LEEF export model into the requested serialization. `cef`
 * and `leef` produce the newline-joined event stream (the deliverable a
 * collector ingests); `markdown` is the human review twin; `json` is the model.
 */
export function renderCef(model: CefExport, format: CefFormat): string {
  switch (format) {
    case "leef":
      return model.events.map((e) => renderLeefLine(e, model)).join("\n");
    case "markdown":
      return renderMarkdown(model);
    case "json":
      return JSON.stringify(model, null, 2);
    case "cef":
    default:
      return model.events.map((e) => renderCefLine(e, model)).join("\n");
  }
}

/** A filesystem-safe filename for a downloaded CEF/LEEF export in the given format. */
export function cefFilename(nowMs: number, format: CefFormat): string {
  const stamp = new Date(nowMs).toISOString().replace(/[:T]/g, "-").replace(/\..+$/, "");
  const ext =
    format === "markdown" ? "md" : format === "json" ? "json" : format === "leef" ? "leef" : "cef";
  return `sectool-events-${stamp}.${ext}`;
}

/** Coerce an arbitrary string into a valid {@link CefFormat}, defaulting to cef. */
export function parseCefFormat(raw: string | undefined | null): CefFormat {
  const f = (raw ?? "").trim().toLowerCase();
  if (f === "leef") return "leef";
  if (f === "json") return "json";
  if (f === "markdown" || f === "md") return "markdown";
  return "cef";
}
