/**
 * Builds the "war map" dataset: aggregates traffic and threats by country.
 * External flow endpoints (and threat-alert sources) are geolocated and summed
 * per country, with inbound/outbound byte split and a threat count overlay.
 */
import { isIP } from "node:net";
import type { Config } from "../config.ts";
import { getActiveFlowStore } from "../netflow/flowAccess.ts";
import { geolocate, geolocateSelf, type GeoLoc } from "./geo.ts";
import { mongoQuery } from "../ingest/sshPull.ts";
import type { Flow } from "../netflow/ipfix.ts";

function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/.test(ip);
}

export interface CountryAgg {
  country: string;
  code: string;
  lat: number;
  lon: number;
  flows: number;
  bytes: number;
  inboundBytes: number;
  outboundBytes: number;
  ips: number;
  threats: number;
}
export interface GeoMap {
  home: GeoLoc | null;
  hours: number;
  totalBytes: number;
  countries: CountryAgg[];
}

interface IpAgg {
  bytes: number;
  flows: number;
  inB: number;
  outB: number;
}

export async function buildGeoMap(cfg: Config, hours: number, nowMs: number): Promise<GeoMap> {
  const ipAgg = new Map<string, IpAgg>();

  const store = getActiveFlowStore();
  if (store) {
    const flows = store.query([], nowMs - hours * 3_600_000, nowMs, 200000) as Flow[];
    for (const f of flows) {
      const s = f.srcIp;
      const d = f.dstIp;
      if (!s || !d || isIP(s) === 0 || isIP(d) === 0) continue;
      const sp = isPrivate(s);
      const dp = isPrivate(d);
      if (sp === dp) continue; // need one internal + one external
      const ext = sp ? d : s;
      const bytes = f.bytes ?? 0;
      let a = ipAgg.get(ext);
      if (!a) {
        a = { bytes: 0, flows: 0, inB: 0, outB: 0 };
        ipAgg.set(ext, a);
      }
      a.bytes += bytes;
      a.flows++;
      if (sp) a.outB += bytes; // internal -> external = outbound
      else a.inB += bytes;
    }
  }

  // Threat counts per external source IP (from the IDS alert store).
  const threatByIp = new Map<string, number>();
  try {
    const lo = nowMs - hours * 3_600_000;
    const js =
      `var m={}; db.alert.find({time:{$gte:${lo}},key:/THREAT_DETECTED/}).forEach(function(d){` +
      `var p=d.parameters||{};var ip=p.SRC_IP&&p.SRC_IP.target_id;if(ip){m[ip]=(m[ip]||0)+1;}}); print(JSON.stringify(m))`;
    const out = await mongoQuery(js, { timeoutMs: 20000 });
    const a = out.indexOf("{");
    const b = out.lastIndexOf("}");
    if (a !== -1 && b > a) {
      const obj = JSON.parse(out.slice(a, b + 1)) as Record<string, number>;
      for (const [ip, n] of Object.entries(obj)) {
        if (isIP(ip) !== 4 || isPrivate(ip)) continue;
        threatByIp.set(ip, n);
        if (!ipAgg.has(ip)) ipAgg.set(ip, { bytes: 0, flows: 0, inB: 0, outB: 0 });
      }
    }
  } catch {
    /* threats overlay is best-effort */
  }

  // Rank to bound geolocation lookups (threats weighted heavily so attackers map).
  const ranked = [...ipAgg.entries()]
    .filter(([ip]) => isIP(ip) === 4 && !isPrivate(ip))
    .sort((x, y) => y[1].bytes + (threatByIp.get(y[0]) ?? 0) * 1e7 - (x[1].bytes + (threatByIp.get(x[0]) ?? 0) * 1e7))
    .slice(0, 500)
    .map(([ip]) => ip);

  const geo = await geolocate(ranked);
  const byCountry = new Map<string, CountryAgg>();
  for (const ip of ranked) {
    const g = geo.get(ip);
    if (!g) continue;
    const a = ipAgg.get(ip)!;
    let c = byCountry.get(g.code);
    if (!c) {
      c = { country: g.country, code: g.code, lat: g.lat, lon: g.lon, flows: 0, bytes: 0, inboundBytes: 0, outboundBytes: 0, ips: 0, threats: 0 };
      byCountry.set(g.code, c);
    }
    c.flows += a.flows;
    c.bytes += a.bytes;
    c.inboundBytes += a.inB;
    c.outboundBytes += a.outB;
    c.ips++;
    c.threats += threatByIp.get(ip) ?? 0;
  }

  const countries = [...byCountry.values()].sort((a, b) => b.bytes - a.bytes || b.threats - a.threats);
  const totalBytes = countries.reduce((s, c) => s + c.bytes, 0);
  const home = await geolocateSelf();
  return { home, hours, totalBytes, countries };
}
