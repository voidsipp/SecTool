/**
 * Minimal UniFi OS (UDM Pro) controller API client used for historical backfill.
 *
 * Authenticates with a local UniFi account, then pulls stored IDS/IPS events for
 * a time window from the Network application's `stat/ips/event` endpoint and maps
 * them into SecTool's SecurityAlert / LogEvent shapes.
 *
 * Notes:
 *  - UDM Pro proxies the Network API under `/proxy/network/...`.
 *  - The gateway uses a self-signed certificate; TLS verification is disabled by
 *    default (override with UNIFI_VERIFY_TLS=true if you've installed a CA).
 *  - Session is a `TOKEN` cookie + an `X-CSRF-Token` header returned at login.
 */
import { createHash } from "node:crypto";
import { isIP } from "node:net";
import type { Config } from "../config.ts";
import type { LogEvent, SecurityAlert, Severity } from "../types.ts";
import { log } from "../logger.ts";

export class UnifiError extends Error {}

interface RawIpsEvent {
  [k: string]: unknown;
}

export interface MappedEvent {
  alert: SecurityAlert;
  logEvent: LogEvent;
}

/**
 * Unwrap MongoDB extended-JSON wrappers so events exported via mongo/mongoexport
 * (e.g. {"$numberLong":"..."}, {"$date":...}, {"$oid":"..."}) read like plain
 * values. Returns the value unchanged when it isn't a wrapper.
 */
function unwrap(v: unknown): unknown {
  if (v && typeof v === "object" && !Array.isArray(v)) {
    const o = v as Record<string, unknown>;
    if ("$numberLong" in o) return Number(o["$numberLong"]);
    if ("$numberInt" in o) return Number(o["$numberInt"]);
    if ("$numberDouble" in o) return Number(o["$numberDouble"]);
    if ("$oid" in o) return o["$oid"];
    if ("$date" in o) {
      const d = o["$date"];
      if (typeof d === "number") return d;
      if (typeof d === "string") return Date.parse(d);
      if (d && typeof d === "object" && "$numberLong" in (d as Record<string, unknown>)) {
        return Number((d as Record<string, unknown>)["$numberLong"]);
      }
    }
  }
  return v;
}

function num(value: unknown): number | undefined {
  const v = unwrap(value);
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v.trim() !== "" && Number.isFinite(Number(v))) return Number(v);
  return undefined;
}

function s(value: unknown): string | undefined {
  const v = unwrap(value);
  if (typeof v === "string" && v) return v;
  if (typeof v === "number") return String(v);
  return undefined;
}

function firstStr(ev: RawIpsEvent, keys: string[]): string | undefined {
  for (const k of keys) {
    const v = s(ev[k]);
    if (v) return v;
  }
  return undefined;
}

function firstNum(ev: RawIpsEvent, keys: string[]): number | undefined {
  for (const k of keys) {
    const v = num(ev[k]);
    if (v !== undefined) return v;
  }
  return undefined;
}

/** UniFi/Suricata severity (1 = most severe) → our ladder. */
function severityFrom(priority: number | undefined, action: string | undefined): Severity {
  if (priority !== undefined) {
    if (priority <= 1) return "critical";
    if (priority === 2) return "high";
    if (priority === 3) return "medium";
    return "low";
  }
  return action === "blocked" ? "high" : "medium";
}

/** UniFi alert `severity` string → our ladder. */
function severityFromLabel(label: string | undefined): Severity {
  switch ((label ?? "").toUpperCase()) {
    case "CRITICAL":
    case "VERY_HIGH":
      return "critical";
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      return "info";
  }
}

/** "THREAT_DETECTED_KNOWN_SOURCE_CLIENT" → "Threat Detected Known Source Client". */
function humanizeKey(key: string): string {
  return key
    .replace(/_V\d+$/i, "")
    .split("_")
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
    .join(" ");
}

/** Read a UniFi alert `parameters.<NAME>` sub-object. */
function param(ev: RawIpsEvent, name: string): Record<string, unknown> | undefined {
  const params = ev["parameters"];
  if (params && typeof params === "object") {
    const p = (params as Record<string, unknown>)[name];
    if (p && typeof p === "object") return p as Record<string, unknown>;
  }
  return undefined;
}

/**
 * Map a UniFi Network `alert` document (key + parameters + severity) — what the
 * UDM actually stores for IDS/IPS detections — into our alert/log shapes.
 */
function mapUnifiAlert(ev: RawIpsEvent): MappedEvent {
  const ts = firstNum(ev, ["time", "timestamp", "datetime"]) ?? Date.now();
  const key = s(ev["key"]) ?? "THREAT_DETECTED";
  const human = humanizeKey(key);
  const severity = severityFromLabel(s(ev["severity"]));

  const srcP = param(ev, "SRC_IP") ?? param(ev, "SRC_CLIENT");
  const dstP = param(ev, "DST_IP") ?? param(ev, "DST_CLIENT");
  const srcId = s(srcP?.["target_id"]);
  const dstId = s(dstP?.["target_id"]);
  const srcIp = srcId && isIP(srcId) > 0 ? srcId : undefined;
  const dstIp = dstId && isIP(dstId) > 0 ? dstId : undefined;
  const srcLabel = s(srcP?.["hostname"]) ?? s(srcP?.["name"]) ?? srcId;
  const dstLabel = s(dstP?.["hostname"]) ?? s(dstP?.["name"]) ?? dstId;

  const deviceP = param(ev, "DEVICE");
  const device = s(deviceP?.["name"]) ?? s(deviceP?.["ip"]);

  const action = /BLOCK/i.test(key) ? "blocked" : "detected";

  const raw =
    `${human} [${(s(ev["severity"]) ?? severity).toString()}]` +
    `${srcLabel ? ` from ${srcLabel}` : ""}${dstLabel ? ` to ${dstLabel}` : ""}` +
    `${device ? ` (via ${device})` : ""} (${action})`;

  const ips = [srcIp, dstIp].filter((ip): ip is string => !!ip);

  const logEvent: LogEvent = {
    raw,
    receivedAt: ts,
    timestamp: ts,
    host: device,
    appName: "unifi-ips",
    message: raw,
    transport: "unifi-mongo",
    ips,
  };

  // Include time so distinct detections from the same hosts each post.
  const id = createHash("sha1")
    .update([key, srcId ?? "", dstId ?? "", ts].join("|"))
    .digest("hex")
    .slice(0, 16);

  const alert: SecurityAlert = {
    id,
    event: logEvent,
    category: "Threat Management",
    signature: human + (srcLabel || dstLabel ? ` (${srcLabel ?? "?"} → ${dstLabel ?? "?"})` : ""),
    classification: key,
    srcIp: srcIp ?? srcLabel,
    dstIp: dstIp ?? dstLabel,
    action,
    severity,
  };

  return { alert, logEvent };
}

export class UnifiClient {
  readonly #cfg: Config;
  #cookie?: string;
  #csrf?: string;

  constructor(cfg: Config) {
    this.#cfg = cfg;
  }

  /**
   * Fetch against the gateway. The UDM uses a self-signed cert, so when TLS
   * verification is disabled we toggle NODE_TLS_REJECT_UNAUTHORIZED only for the
   * duration of this (sequential) request — leaving the Claude/Discord HTTPS
   * calls fully verified.
   */
  async #fetch(path: string, init: RequestInit = {}): Promise<Response> {
    const url = path.startsWith("http") ? path : `${this.#cfg.unifi.host}${path}`;
    const headers: Record<string, string> = {
      "content-type": "application/json",
      ...(init.headers as Record<string, string> | undefined),
    };
    if (this.#cfg.unifi.apiKey) headers["x-api-key"] = this.#cfg.unifi.apiKey;
    if (this.#cookie) headers["cookie"] = this.#cookie;
    if (this.#csrf) headers["x-csrf-token"] = this.#csrf;

    const skipTls = !this.#cfg.unifi.verifyTls;
    const prev = process.env["NODE_TLS_REJECT_UNAUTHORIZED"];
    if (skipTls) process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";
    try {
      return await fetch(url, { ...init, headers });
    } finally {
      if (skipTls) {
        if (prev === undefined) delete process.env["NODE_TLS_REJECT_UNAUTHORIZED"];
        else process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = prev;
      }
    }
  }

  async login(): Promise<void> {
    // With an API key we authenticate per-request via the X-API-KEY header;
    // there is no session login step.
    if (this.#cfg.unifi.apiKey) {
      log.info("Using UDM API key authentication (X-API-KEY).");
      return;
    }
    const { username, password } = this.#cfg.unifi;
    if (!username || !password) {
      throw new UnifiError(
        "Backfill needs UDM credentials. Set UNIFI_API_KEY, or UNIFI_USERNAME + UNIFI_PASSWORD " +
          "in .env (a local UniFi admin account — not your Ubiquiti SSO email).",
      );
    }
    let res: Response;
    try {
      res = await this.#fetch("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password, rememberMe: false }),
      });
    } catch (err) {
      throw new UnifiError(
        `Could not reach the UDM at ${this.#cfg.unifi.host}: ${(err as Error).message}`,
      );
    }
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new UnifiError(
        `UDM login failed (${res.status}). Check UNIFI_USERNAME/UNIFI_PASSWORD and that the ` +
          `account is a local admin. ${body.slice(0, 200)}`,
      );
    }
    // Capture session cookie + CSRF token for subsequent requests.
    const setCookies = res.headers.getSetCookie?.() ?? [];
    const token = setCookies.find((c) => /^TOKEN=/.test(c));
    if (token) this.#cookie = token.split(";")[0];
    this.#csrf =
      res.headers.get("x-csrf-token") ??
      res.headers.get("x-updated-csrf-token") ??
      this.#csrf;
    if (!this.#cookie) {
      throw new UnifiError("UDM login succeeded but no session cookie was returned.");
    }
    log.info(`Authenticated to UDM at ${this.#cfg.unifi.host} ✓`);
  }

  /** Fetch raw IDS/IPS events in [startMs, endMs]. Tries POST then GET fallback. */
  async fetchIpsEvents(startMs: number, endMs: number, limit: number): Promise<RawIpsEvent[]> {
    const site = this.#cfg.unifi.site;
    const base = `/proxy/network/api/s/${site}/stat/ips/event`;

    const parse = async (res: Response): Promise<RawIpsEvent[] | null> => {
      if (!res.ok) return null;
      const j = (await res.json().catch(() => null)) as { data?: RawIpsEvent[] } | null;
      return Array.isArray(j?.data) ? j!.data! : null;
    };

    // Preferred: POST with explicit window.
    let data = await parse(
      await this.#fetch(base, {
        method: "POST",
        body: JSON.stringify({ start: startMs, end: endMs, _limit: limit, _sort: "-timestamp" }),
      }),
    ).catch(() => null);

    // Fallback: GET with `within` hours.
    if (!data) {
      const withinHours = Math.max(1, Math.ceil((endMs - startMs) / 3_600_000));
      data = await parse(
        await this.#fetch(`${base}?within=${withinHours}&_limit=${limit}`, { method: "GET" }),
      ).catch(() => null);
    }

    if (!data) {
      // Diagnose: if an API key is in use, check whether the key itself is valid
      // by probing the Integration API, so we can tell "key rejected" apart from
      // "key valid but this endpoint isn't exposed to it".
      if (this.#cfg.unifi.apiKey) {
        const probe = await this.#fetch("/proxy/network/integration/v1/sites", {
          method: "GET",
        }).catch(() => null);
        if (probe && (probe.status === 401 || probe.status === 403)) {
          throw new UnifiError(
            "The UDM API key was rejected (401/403). Recreate it under Settings → Control Plane → " +
              "Integrations and copy it exactly into UNIFI_API_KEY.",
          );
        }
        throw new UnifiError(
          "Authenticated with the API key, but the IDS/IPS event endpoint isn't accessible to it. " +
            "UniFi's Integration API does not expose threat events yet, so backfill needs a local " +
            "admin instead: set UNIFI_USERNAME + UNIFI_PASSWORD (Settings → Admins → local-only admin).",
        );
      }
      throw new UnifiError(
        "Could not fetch IDS/IPS events. Ensure IPS/IDS (Threat Management) is enabled and your " +
          "firmware exposes stat/ips/event.",
      );
    }
    // Filter to the requested window (GET fallback is coarse) and sort ascending.
    return data
      .filter((e) => {
        const t = firstNum(e, ["timestamp", "time", "datetime"]);
        return t === undefined || (t >= startMs && t <= endMs);
      })
      .sort((a, b) => (firstNum(a, ["timestamp", "time"]) ?? 0) - (firstNum(b, ["timestamp", "time"]) ?? 0));
  }

  async logout(): Promise<void> {
    try {
      await this.#fetch("/api/auth/logout", { method: "POST" });
    } catch {
      /* best effort */
    }
  }

  /** Map a raw UniFi IPS event into SecTool's alert + log-event shapes. */
  static mapEvent(ev: RawIpsEvent): MappedEvent {
    // UniFi `alert` documents (key + parameters) use a different schema than raw
    // Suricata events; route them to the dedicated mapper.
    if (ev["key"] && ev["parameters"]) return mapUnifiAlert(ev);

    const ts = firstNum(ev, ["timestamp", "time", "datetime"]) ?? Date.now();
    const signature = firstStr(ev, ["inner_alert_signature", "signature", "msg", "catname", "name"]);
    const sid = firstStr(ev, ["inner_alert_signature_id", "signature_id", "sid"]);
    const gid = firstStr(ev, ["inner_alert_gid", "gid"]);
    const rev = firstStr(ev, ["inner_alert_rev", "rev"]);
    const classification = firstStr(ev, ["inner_alert_category", "catname", "category", "classification"]);
    const priority = firstNum(ev, ["inner_alert_severity", "priority", "severity"]);
    const protocol = firstStr(ev, ["proto", "protocol", "app_proto"]);
    const srcIp = firstStr(ev, ["src_ip", "srcip", "source_ip", "src"]);
    const dstIp = firstStr(ev, ["dest_ip", "dst_ip", "destip", "destination_ip", "dst"]);
    const srcPort = firstNum(ev, ["src_port", "srcport", "source_port"]);
    const dstPort = firstNum(ev, ["dest_port", "dst_port", "destport", "destination_port"]);
    const rawAction = firstStr(ev, ["action", "event_type", "inner_alert_action"]);
    const action =
      rawAction && /block|drop|deny|reject/i.test(rawAction)
        ? "blocked"
        : rawAction
          ? "detected"
          : undefined;
    const host = firstStr(ev, ["host", "hostname", "device_name"]);

    const signatureId = sid ? `${gid ?? "1"}:${sid}${rev ? ":" + rev : ""}` : undefined;
    const severity = severityFrom(priority, action);

    // Reconstruct a human-readable raw line for display + IP indexing.
    const flow =
      srcIp && dstIp
        ? `{${protocol ?? "?"}} ${srcIp}${srcPort ? ":" + srcPort : ""} -> ${dstIp}${dstPort ? ":" + dstPort : ""}`
        : "";
    const raw =
      `${signatureId ? "[" + signatureId + "] " : ""}${signature ?? "IDS/IPS detection"}` +
      `${classification ? " [Classification: " + classification + "]" : ""}` +
      `${priority !== undefined ? " [Priority: " + priority + "]" : ""}` +
      `${flow ? " " + flow : ""}${action ? " (" + action + ")" : ""}`;

    const ips = [srcIp, dstIp].filter((ip): ip is string => !!ip && isIP(ip) > 0);

    const logEvent: LogEvent = {
      raw,
      receivedAt: ts,
      timestamp: ts,
      host,
      appName: "suricata",
      message: raw,
      transport: "unifi-api",
      ips,
    };

    const id = createHash("sha1")
      .update([signatureId ?? signature ?? raw, srcIp ?? "", dstIp ?? "", dstPort ?? ""].join("|"))
      .digest("hex")
      .slice(0, 16);

    const alert: SecurityAlert = {
      id,
      event: logEvent,
      category: "IDS/IPS",
      signature: signature ?? "IDS/IPS detection",
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

    return { alert, logEvent };
  }
}
