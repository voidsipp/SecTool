/**
 * Lightweight IP→country/lat-lon geolocation using ip-api's free batch endpoint
 * (no key; up to 100 IPs per request, ~15 req/min). Results are cached for the
 * process lifetime so the war map can geolocate many flow endpoints cheaply.
 */
const cache = new Map<string, GeoLoc | null>();
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export interface GeoLoc {
  country: string;
  code: string;
  lat: number;
  lon: number;
}

interface BatchEntry {
  status?: string;
  country?: string;
  countryCode?: string;
  lat?: number;
  lon?: number;
  query?: string;
}

/** Geolocate the caller's own public IP (used as the map's "home" node). */
export async function geolocateSelf(): Promise<GeoLoc | null> {
  try {
    const r = await fetch("http://ip-api.com/json/?fields=status,country,countryCode,lat,lon,query", {
      signal: AbortSignal.timeout(10000),
    });
    const e = (await r.json()) as BatchEntry;
    if (e.status === "success") return { country: e.country!, code: e.countryCode!, lat: e.lat!, lon: e.lon! };
  } catch {
    /* ignore */
  }
  return null;
}

/** Geolocate a set of IPs, returning a map of ip -> GeoLoc (misses omitted). */
export async function geolocate(ips: string[], maxLookups = 600): Promise<Map<string, GeoLoc>> {
  const out = new Map<string, GeoLoc>();
  const need: string[] = [];
  for (const ip of ips) {
    if (cache.has(ip)) {
      const v = cache.get(ip);
      if (v) out.set(ip, v);
    } else {
      need.push(ip);
    }
  }
  const todo = need.slice(0, maxLookups);
  for (let i = 0; i < todo.length; i += 100) {
    const chunk = todo.slice(i, i + 100);
    try {
      const r = await fetch("http://ip-api.com/batch?fields=status,country,countryCode,lat,lon,query", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(chunk),
        signal: AbortSignal.timeout(15000),
      });
      const arr = (await r.json()) as BatchEntry[];
      for (const e of arr) {
        if (e.status === "success" && e.query) {
          const v: GeoLoc = { country: e.country ?? "?", code: e.countryCode ?? "??", lat: e.lat ?? 0, lon: e.lon ?? 0 };
          cache.set(e.query, v);
          out.set(e.query, v);
        } else if (e.query) {
          cache.set(e.query, null);
        }
      }
    } catch {
      /* skip this batch */
    }
    if (i + 100 < todo.length) await sleep(1500); // respect the rate limit
  }
  return out;
}
