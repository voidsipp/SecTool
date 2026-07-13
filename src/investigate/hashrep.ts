/**
 * Executable-hash reputation (feature #1). Looks a SHA-256 up on VirusTotal's
 * file endpoint and caches the verdict. "Unknown to VT" is itself a strong hunting
 * signal for a binary running on your network, so it's a first-class result.
 */
import type { Config } from "../config.ts";

export interface HashVerdict {
  sha256: string;
  known: boolean; // does VT have a record at all?
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  reputation?: number;
  typeDescription?: string;
  names?: string[];
  signed?: boolean;
  link: string;
  error?: string;
}

const cache = new Map<string, { v: HashVerdict; at: number }>();
const TTL_MS = 6 * 3600_000;

export async function lookupHash(cfg: Config, sha256raw: string): Promise<HashVerdict> {
  const sha256 = String(sha256raw || "").toLowerCase();
  const link = `https://www.virustotal.com/gui/file/${sha256}`;
  if (!/^[a-f0-9]{64}$/.test(sha256)) return { sha256, known: false, link, error: "not a sha256" };
  const c = cache.get(sha256);
  if (c && Date.now() - c.at < TTL_MS) return c.v;
  if (!cfg.enrich.vtApiKey) return { sha256, known: false, link, error: "VT_API_KEY not set" };
  try {
    const r = await fetch(`https://www.virustotal.com/api/v3/files/${sha256}`, {
      headers: { "x-apikey": cfg.enrich.vtApiKey },
      signal: AbortSignal.timeout(10000),
    });
    if (r.status === 404) {
      const v: HashVerdict = { sha256, known: false, link };
      cache.set(sha256, { v, at: Date.now() });
      return v;
    }
    const j = (await r.json().catch(() => null)) as
      | { data?: { attributes?: Record<string, unknown> }; error?: { message?: string } }
      | null;
    const a = j?.data?.attributes as Record<string, unknown> | undefined;
    if (!r.ok || !a) return { sha256, known: false, link, error: j?.error?.message ?? `HTTP ${r.status}` };
    const st = (a["last_analysis_stats"] as Record<string, number>) ?? {};
    const sig = a["signature_info"] as { verified?: string } | undefined;
    const v: HashVerdict = {
      sha256,
      known: true,
      malicious: st["malicious"] ?? 0,
      suspicious: st["suspicious"] ?? 0,
      harmless: st["harmless"] ?? 0,
      undetected: st["undetected"] ?? 0,
      reputation: a["reputation"] as number,
      typeDescription: a["type_description"] as string,
      names: ((a["names"] as string[]) ?? []).slice(0, 3),
      signed: sig?.verified ? true : undefined,
      link,
    };
    cache.set(sha256, { v, at: Date.now() });
    return v;
  } catch (err) {
    return { sha256, known: false, link, error: (err as Error).message };
  }
}
