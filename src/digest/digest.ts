/**
 * Threat digest: aggregates detections over a period into stats (top attackers,
 * top targeted hosts, threat types, totals), enriches the top attacker IPs, asks
 * Claude for a short analyst narrative, and posts a summary embed to Discord.
 */
import { isIP } from "node:net";
import type { Config } from "../config.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";
import { pullMapped, loadSshTarget } from "../ingest/sshPull.ts";
import { enrichIp, pickExternalIp, type Enrichment } from "../investigate/enrich.ts";
import { Summarizer } from "../summarize/claude.ts";
import { DiscordNotifier } from "../notify/discord.ts";
import { log } from "../logger.ts";

const DIGEST_SYSTEM = `You are a SOC analyst writing a brief security digest for a home/small-office network protected by a UniFi UDM Pro.
Given aggregated IDS/IPS detection stats for a time period, write a concise, non-alarmist narrative (3-6 sentences).
Call out the most notable items: persistent/high-reputation attackers, any internal host doing something unusual, spikes, and whether anything needs attention. If it was a quiet period, say so plainly. Do not invent data. Plain text, no markdown headers.`;

function bump<T>(m: Map<T, number>, k: T | undefined): void {
  if (k === undefined || k === null) return;
  m.set(k, (m.get(k) ?? 0) + 1);
}
function topN<T>(m: Map<T, number>, n: number): Array<{ key: T; count: number }> {
  return [...m.entries()].map(([key, count]) => ({ key, count })).sort((a, b) => b.count - a.count).slice(0, n);
}
function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|fe80|fc|fd)/i.test(ip);
}

export interface Digest {
  hours: number;
  total: number;
  blocked: number;
  bySeverity: Record<string, number>;
  topAttackers: Array<{ ip: string; count: number; enrichment?: Enrichment }>;
  topTargets: Array<{ ip: string; count: number }>;
  topTypes: Array<{ type: string; count: number }>;
  narrative: string;
}

export async function generateDigest(cfg: Config, hours: number, nowMs: number): Promise<Digest> {
  if (!loadSshTarget()) throw new Error("Digest needs SSH configured (run --setup-ssh).");
  const mapped = await pullMapped(cfg, hours, nowMs);

  const bySev = new Map<Severity, number>();
  const attackers = new Map<string, number>();
  const targets = new Map<string, number>();
  const types = new Map<string, number>();
  let blocked = 0;

  for (const { alert: a } of mapped) {
    bump(bySev, a.severity);
    if (a.action === "blocked") blocked++;
    bump(types, a.classification ?? a.category);
    const ext = pickExternalIp(a.srcIp, a.dstIp);
    if (ext && isIP(ext) > 0 && !isPrivate(ext)) bump(attackers, ext);
    for (const ip of [a.srcIp, a.dstIp]) if (ip && isIP(ip) > 0 && isPrivate(ip)) bump(targets, ip);
  }

  const topAttackers = topN(attackers, 5).map((x) => ({ ip: x.key, count: x.count }));
  // Enrich the top attackers sequentially (cache + VT rate-limit friendly).
  const enrichedAttackers: Digest["topAttackers"] = [];
  for (const att of topAttackers) {
    const enrichment = await enrichIp(cfg, att.ip).catch(() => undefined);
    enrichedAttackers.push({ ...att, enrichment });
  }

  const bySeverity: Record<string, number> = {};
  for (const s of SEVERITY_ORDER) if (bySev.get(s)) bySeverity[s] = bySev.get(s)!;

  const digest: Digest = {
    hours,
    total: mapped.length,
    blocked,
    bySeverity,
    topAttackers: enrichedAttackers,
    topTargets: topN(targets, 5).map((x) => ({ ip: x.key, count: x.count })),
    topTypes: topN(types, 6).map((x) => ({ type: String(x.key), count: x.count })),
    narrative: "",
  };

  // Build the narrative.
  const summarizer = new Summarizer(cfg);
  await summarizer.preflight();
  const statBlock = JSON.stringify(
    {
      periodHours: hours,
      totalDetections: digest.total,
      blocked: digest.blocked,
      bySeverity: digest.bySeverity,
      topAttackers: digest.topAttackers.map((a) => ({
        ip: a.ip,
        hits: a.count,
        country: a.enrichment?.geo?.country,
        asn: a.enrichment?.geo?.asn,
        hosting: a.enrichment?.geo?.hosting,
        vtMalicious: a.enrichment?.virustotal?.malicious,
      })),
      topTargetedHosts: digest.topTargets,
      topThreatTypes: digest.topTypes,
    },
    null,
    1,
  );
  try {
    digest.narrative = await summarizer.complete(
      DIGEST_SYSTEM,
      `Detection stats for the last ${hours} hours:\n${statBlock}\n\nWrite the digest narrative.`,
      800,
    );
  } catch (err) {
    digest.narrative = `Automated narrative unavailable (${(err as Error).message}). ${digest.total} detections in the last ${hours}h.`;
  }
  return digest;
}

export function digestEmbed(d: Digest) {
  const sev = Object.entries(d.bySeverity).map(([k, v]) => `${k} ${v}`).join(" · ") || "none";
  const attackers =
    d.topAttackers
      .map((a) => {
        const vt = a.enrichment?.virustotal ? ` · VT ${a.enrichment.virustotal.malicious}` : "";
        const geo = a.enrichment?.geo?.country ? ` (${a.enrichment.geo.country})` : "";
        return `\`${a.ip}\`${geo} — ${a.count} hits${vt}`;
      })
      .join("\n") || "none";
  const targets = d.topTargets.map((t) => `\`${t.ip}\` — ${t.count}`).join("\n") || "none";
  const typesTxt = d.topTypes.map((t) => `${t.type} (${t.count})`).join("\n") || "none";

  return {
    title: `🛡️ Threat Digest — last ${d.hours}h`,
    description: (d.narrative || "No narrative.").slice(0, 4096),
    color: d.total > 0 ? 0xe67e22 : 0x2ecc71,
    fields: [
      { name: "Totals", value: `${d.total} detections · ${d.blocked} blocked\nseverity: ${sev}`, inline: false },
      { name: "Top attackers", value: attackers.slice(0, 1024), inline: false },
      { name: "Most-targeted hosts", value: targets.slice(0, 1024), inline: true },
      { name: "Threat types", value: typesTxt.slice(0, 1024), inline: true },
    ],
    timestamp: new Date().toISOString(),
  };
}

export async function runDigest(cfg: Config, hours: number, nowMs: number): Promise<void> {
  log.info(`Generating threat digest for the last ${hours}h…`);
  const digest = await generateDigest(cfg, hours, nowMs);
  const ok = await new DiscordNotifier(cfg).postEmbed(digestEmbed(digest));
  log.info(`Digest: ${digest.total} detections, ${digest.topAttackers.length} top attackers — posted=${ok}.`);
}
