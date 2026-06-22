/**
 * IP enrichment against public threat-intel / geolocation APIs:
 *   - ip-api.com   (keyless): geo, ASN, ISP/org, hosting/proxy/mobile flags
 *   - VirusTotal   (VT_API_KEY): last-analysis verdicts, reputation
 *   - AbuseIPDB    (ABUSEIPDB_API_KEY): abuse confidence score
 *
 * On-demand only (a button), and private/internal IPs are skipped — we don't
 * send RFC1918 addresses to third parties. Results are cached to respect the
 * free-tier rate limits.
 */
import { isIP } from "node:net";
import type { Config } from "../config.ts";
import type { Severity } from "../types.ts";
import { feedMatch } from "../intel/feedAccess.ts";

const cache = new Map<string, { data: Enrichment; expires: number }>();
const TTL_MS = 6 * 3_600_000;

export interface Enrichment {
  ip: string;
  isPrivate: boolean;
  geo?: {
    country?: string;
    region?: string;
    city?: string;
    lat?: number;
    lon?: number;
    isp?: string;
    org?: string;
    asn?: string;
    asname?: string;
    reverse?: string;
    hosting?: boolean;
    proxy?: boolean;
    mobile?: boolean;
  };
  virustotal?: {
    malicious: number;
    suspicious: number;
    harmless: number;
    undetected: number;
    reputation?: number;
    asOwner?: string;
    country?: string;
    link: string;
  };
  abuseipdb?: {
    score: number;
    totalReports: number;
    usageType?: string;
    domain?: string;
    isp?: string;
  };
  feeds: string[];
  errors: string[];
  cachedAt: number;
}

function isPrivateIp(ip: string): boolean {
  return (
    /^10\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^127\./.test(ip) ||
    /^169\.254\./.test(ip) ||
    /^0\./.test(ip) ||
    /^(::1|fe80|fc|fd)/i.test(ip)
  );
}

async function fetchJson(
  url: string,
  opts: RequestInit,
  timeoutMs = 9000,
): Promise<{ ok: boolean; status: number; json: any }> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const r = await fetch(url, { ...opts, signal: ac.signal });
    const json = await r.json().catch(() => null);
    return { ok: r.ok, status: r.status, json };
  } finally {
    clearTimeout(t);
  }
}

export async function enrichIp(cfg: Config, ip: string): Promise<Enrichment> {
  if (isIP(ip) === 0) throw new Error(`Invalid IP: ${ip}`);
  const hit = cache.get(ip);
  if (hit && hit.expires > Date.now()) return hit.data;

  const result: Enrichment = { ip, isPrivate: isPrivateIp(ip), feeds: feedMatch(ip), errors: [], cachedAt: Date.now() };
  if (result.isPrivate) {
    result.errors.push("Private/internal IP — external reputation lookups skipped.");
    cache.set(ip, { data: result, expires: Date.now() + TTL_MS });
    return result;
  }

  // Run the lookups concurrently.
  const tasks: Promise<void>[] = [];

  tasks.push(
    (async () => {
      try {
        const fields = "status,message,country,regionName,city,lat,lon,isp,org,as,asname,reverse,mobile,proxy,hosting,query";
        const r = await fetchJson(`http://ip-api.com/json/${ip}?fields=${fields}`, { method: "GET" });
        if (r.json && r.json.status === "success") {
          result.geo = {
            country: r.json.country,
            region: r.json.regionName,
            city: r.json.city,
            lat: r.json.lat,
            lon: r.json.lon,
            isp: r.json.isp,
            org: r.json.org,
            asn: r.json.as,
            asname: r.json.asname,
            reverse: r.json.reverse,
            hosting: r.json.hosting,
            proxy: r.json.proxy,
            mobile: r.json.mobile,
          };
        } else {
          result.errors.push(`ip-api: ${r.json?.message ?? r.status}`);
        }
      } catch {
        result.errors.push("ip-api: request failed.");
      }
    })(),
  );

  if (cfg.enrich.vtApiKey) {
    tasks.push(
      (async () => {
        try {
          const r = await fetchJson(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
            method: "GET",
            headers: { "x-apikey": cfg.enrich.vtApiKey! },
          });
          if (r.ok && r.json?.data?.attributes) {
            const a = r.json.data.attributes;
            const st = a.last_analysis_stats ?? {};
            result.virustotal = {
              malicious: st.malicious ?? 0,
              suspicious: st.suspicious ?? 0,
              harmless: st.harmless ?? 0,
              undetected: st.undetected ?? 0,
              reputation: a.reputation,
              asOwner: a.as_owner,
              country: a.country,
              link: `https://www.virustotal.com/gui/ip-address/${ip}`,
            };
          } else {
            result.errors.push(`VirusTotal: ${r.json?.error?.message ?? "HTTP " + r.status}`);
          }
        } catch {
          result.errors.push("VirusTotal: request failed.");
        }
      })(),
    );
  } else {
    result.errors.push("VirusTotal: set VT_API_KEY to enable.");
  }

  if (cfg.enrich.abuseKey) {
    tasks.push(
      (async () => {
        try {
          const r = await fetchJson(
            `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`,
            { method: "GET", headers: { Key: cfg.enrich.abuseKey!, Accept: "application/json" } },
          );
          if (r.ok && r.json?.data) {
            const d = r.json.data;
            result.abuseipdb = {
              score: d.abuseConfidenceScore,
              totalReports: d.totalReports,
              usageType: d.usageType,
              domain: d.domain,
              isp: d.isp,
            };
          } else {
            result.errors.push(`AbuseIPDB: HTTP ${r.status}`);
          }
        } catch {
          result.errors.push("AbuseIPDB: request failed.");
        }
      })(),
    );
  }

  await Promise.all(tasks);
  cache.set(ip, { data: result, expires: Date.now() + TTL_MS });
  return result;
}

/** Choose the externally-routable IP from an alert's endpoints (prefer src). */
export function pickExternalIp(srcIp?: string, dstIp?: string): string | undefined {
  for (const ip of [srcIp, dstIp]) if (ip && isIP(ip) > 0 && !isPrivateIp(ip)) return ip;
  return [srcIp, dstIp].find((ip) => ip && isIP(ip) > 0);
}

/** Escalate severity based on threat-intel verdicts. */
export function escalate(
  severity: Severity,
  e: Enrichment | undefined,
  cfg: Config,
): { severity: Severity; escalated: boolean; reason?: string } {
  if (!e) return { severity, escalated: false };
  const vtBad = (e.virustotal?.malicious ?? 0) + (e.virustotal?.suspicious ?? 0);
  const abuse = e.abuseipdb?.score ?? 0;
  const reasons: string[] = [];
  if (e.virustotal && vtBad >= cfg.enrich.escalateVtMalicious) reasons.push(`VT ${e.virustotal.malicious} malicious`);
  if (abuse >= cfg.enrich.escalateAbuseScore) reasons.push(`AbuseIPDB ${abuse}%`);
  if (e.feeds.length) reasons.push(`on ${e.feeds.length} threat feed(s)`);
  if (reasons.length && severity !== "critical") {
    return { severity: "critical", escalated: true, reason: reasons.join(", ") };
  }
  return { severity, escalated: false, reason: reasons.join(", ") || undefined };
}
