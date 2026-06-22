/**
 * Classifies a LogEvent as a security alert and extracts structured fields.
 *
 * Handles the common UDM Pro / Suricata IDS/IPS shapes, e.g.:
 *   [1:2027865:3] ET INFO Observed DNS Query [Classification: Misc] \
 *     [Priority: 3] {UDP} 10.0.0.5:54321 -> 8.8.8.8:53
 * as well as UniFi "Threat Management" / firewall notifications and JSON
 * payloads. Falls back to keyword heuristics for everything else.
 */
import { createHash } from "node:crypto";
import type { LogEvent, SecurityAlert, Severity } from "../types.ts";

const SIG_ID = /\[(\d+:\d+:\d+)\]/;
const CLASSIFICATION = /\[Classification:\s*([^\]]+)\]/i;
const PRIORITY = /\[Priority:\s*(\d+)\]/i;
// {PROTO} src:port -> dst:port  (also matches "<->" and missing ports)
const FLOW =
  /\{(\w+)\}\s*([0-9a-fA-F.:]+?)(?::(\d+))?\s*(?:->|<->|<-)\s*([0-9a-fA-F.:]+?)(?::(\d+))?(?:\s|$)/;

// Words that strongly imply a security-relevant event from UniFi/Suricata.
const KEYWORDS =
  /\b(IDS|IPS|suricata|threat|malware|exploit|botnet|trojan|intrusion|honeypot|portscan|port scan|brute[\s-]?force|blocked|drop(?:ped)?|deny|denied|attack|scan|signature|c2|command and control| et\s+(?:malware|exploit|trojan|scan|policy|info))\b/i;

const ACTION_BLOCKED = /\b(block(?:ed)?|drop(?:ped)?|deny|denied|reject(?:ed)?|prevent(?:ed)?)\b/i;
const ACTION_DETECTED = /\b(detect(?:ed)?|alert|would[\s-]?block|notice)\b/i;

function isPrivate(ip: string): boolean {
  return (
    /^10\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^127\./.test(ip) ||
    /^169\.254\./.test(ip) ||
    /^(fe80|fc|fd)/i.test(ip)
  );
}

/** Map Suricata priority + syslog severity + classification to our ladder. */
function deriveSeverity(
  priority: number | undefined,
  classification: string | undefined,
  syslogSeverity: number | undefined,
  blocked: boolean,
): Severity {
  if (priority !== undefined) {
    if (priority <= 1) return "critical";
    if (priority === 2) return "high";
    if (priority === 3) return "medium";
    return "low";
  }
  const cls = (classification ?? "").toLowerCase();
  if (/(trojan|malware|exploit|botnet|command|c2|attack)/.test(cls)) return blocked ? "high" : "critical";
  if (/(attempted|scan|policy|misc)/.test(cls)) return "medium";
  // No Suricata metadata: lean on syslog severity (0=emerg .. 7=debug).
  if (syslogSeverity !== undefined) {
    if (syslogSeverity <= 2) return "critical";
    if (syslogSeverity === 3) return "high";
    if (syslogSeverity === 4) return "medium";
    if (syslogSeverity === 5) return "low";
  }
  return "low";
}

function tryJson(message: string): Record<string, unknown> | undefined {
  const start = message.indexOf("{");
  const end = message.lastIndexOf("}");
  if (start === -1 || end <= start) return undefined;
  try {
    const obj = JSON.parse(message.slice(start, end + 1));
    return obj && typeof obj === "object" ? (obj as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

function pick(obj: Record<string, unknown>, ...keys: string[]): string | undefined {
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === "string" && v) return v;
    if (typeof v === "number") return String(v);
  }
  return undefined;
}

export interface DetectorOptions {
  /** If set, a line must match this to be considered an alert at all. */
  customPattern?: RegExp;
}

/**
 * Returns a SecurityAlert when the event is security-relevant, else null.
 */
export function detectAlert(event: LogEvent, opts: DetectorOptions = {}): SecurityAlert | null {
  const text = event.message || event.raw;

  if (opts.customPattern) {
    if (!opts.customPattern.test(text)) return null;
  }

  const sigIdMatch = SIG_ID.exec(text);
  const json = tryJson(text);
  const hasKeyword = KEYWORDS.test(text);

  // Decide whether this is an alert. Strong signals: a Suricata signature id,
  // a structured threat JSON, or keyword + a flow/classification context.
  const looksLikeThreatJson =
    !!json && (("signature" in json) || ("threat" in json) || ("event_type" in json && json["event_type"] === "alert"));

  if (!opts.customPattern && !sigIdMatch && !looksLikeThreatJson && !hasKeyword) {
    return null;
  }

  let signatureId: string | undefined = sigIdMatch?.[1];
  let classification = CLASSIFICATION.exec(text)?.[1]?.trim();
  let priority = PRIORITY.exec(text)?.[1] ? Number(PRIORITY.exec(text)?.[1]) : undefined;
  let protocol: string | undefined;
  let srcIp: string | undefined;
  let srcPort: number | undefined;
  let dstIp: string | undefined;
  let dstPort: number | undefined;
  let signature: string | undefined;

  const flow = FLOW.exec(text);
  if (flow) {
    protocol = flow[1];
    srcIp = flow[2];
    srcPort = flow[3] ? Number(flow[3]) : undefined;
    dstIp = flow[4];
    dstPort = flow[5] ? Number(flow[5]) : undefined;
  }

  // Signature text = between the signature id and the first bracketed metadata.
  if (sigIdMatch) {
    const after = text.slice(sigIdMatch.index + sigIdMatch[0].length);
    const cut = after.search(/\[(Classification|Priority):/i);
    signature = (cut === -1 ? after : after.slice(0, cut)).trim() || undefined;
  }

  // Merge in JSON-provided fields (they win when present).
  if (json) {
    signature = pick(json, "signature", "msg", "alert", "name") ?? signature;
    classification = pick(json, "category", "classification", "class") ?? classification;
    signatureId = pick(json, "signature_id", "sid", "gid") ?? signatureId;
    protocol = pick(json, "proto", "protocol") ?? protocol;
    srcIp = pick(json, "src_ip", "srcip", "source_ip", "src") ?? srcIp;
    dstIp = pick(json, "dest_ip", "dst_ip", "destip", "destination_ip", "dst") ?? dstIp;
    const sp = pick(json, "src_port", "srcport", "source_port");
    const dp = pick(json, "dest_port", "dst_port", "destport", "destination_port");
    if (sp) srcPort = Number(sp);
    if (dp) dstPort = Number(dp);
    const jprio = pick(json, "priority", "severity");
    if (jprio && priority === undefined) priority = Number(jprio);
  }

  // If the flow wasn't parsed, fall back to the first two distinct IPs found.
  if (!srcIp || !dstIp) {
    const ips = event.ips;
    if (!srcIp && ips[0]) srcIp = ips[0];
    if (!dstIp && ips.find((ip) => ip !== srcIp)) dstIp = ips.find((ip) => ip !== srcIp);
  }

  const blocked = ACTION_BLOCKED.test(text);
  const action = blocked ? "blocked" : ACTION_DETECTED.test(text) ? "detected" : undefined;

  const severity = deriveSeverity(priority, classification, event.syslogSeverity, blocked);

  const category = signatureId
    ? "IDS/IPS"
    : /threat/i.test(text)
      ? "Threat Management"
      : /(block|drop|deny|firewall)/i.test(text)
        ? "Firewall"
        : "Security";

  if (!signature) {
    // Use the message itself (trimmed) as a human-readable signature.
    signature = text.replace(/\s+/g, " ").trim().slice(0, 200);
  }

  // Stable id for de-duplication: signature identity + endpoints.
  const id = createHash("sha1")
    .update([signatureId ?? signature, srcIp ?? "", dstIp ?? "", dstPort ?? ""].join("|"))
    .digest("hex")
    .slice(0, 16);

  return {
    id,
    event,
    category,
    signature,
    signatureId,
    classification,
    priority,
    protocol,
    srcIp,
    srcPort,
    dstIp,
    dstPort,
    action,
    severity,
  };
}

export const __testing = { isPrivate, deriveSeverity };
