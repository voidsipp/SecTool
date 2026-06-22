/**
 * Formats an alert + Claude summary into a Discord embed and posts it to the
 * configured webhook, respecting Discord's size limits and rate limiting.
 */
import type { Config } from "../config.ts";
import type { AlertSummary, CorrelatedContext, Severity } from "../types.ts";
import type { Enrichment } from "../investigate/enrich.ts";
import { log } from "../logger.ts";

const COLORS: Record<Severity, number> = {
  critical: 0x992d22,
  high: 0xe67e22,
  medium: 0xf1c40f,
  low: 0x3498db,
  info: 0x95a5a6,
};

const EMOJI: Record<Severity, string> = {
  critical: "🚨",
  high: "🔴",
  medium: "🟠",
  low: "🔵",
  info: "⚪",
};

// Discord limits.
const FIELD_VALUE_MAX = 1024;
const DESC_MAX = 4096;

function clip(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + "…";
}

function codeBlock(s: string, lang = ""): string {
  const fenced = "```" + lang + "\n" + s + "\n```";
  // Reserve room for fences within the field-value cap.
  if (fenced.length <= FIELD_VALUE_MAX) return fenced;
  const room = FIELD_VALUE_MAX - lang.length - 9;
  return "```" + lang + "\n" + s.slice(0, room) + "…\n```";
}

interface EmbedField {
  name: string;
  value: string;
  inline?: boolean;
}

function intelField(e: Enrichment): EmbedField | null {
  const parts: string[] = [];
  if (e.virustotal) {
    const bad = e.virustotal.malicious + e.virustotal.suspicious;
    parts.push(`**VirusTotal:** ${e.virustotal.malicious} malicious / ${e.virustotal.suspicious} suspicious${bad === 0 ? " (clean)" : ""}`);
  }
  if (e.abuseipdb) parts.push(`**AbuseIPDB:** ${e.abuseipdb.score}% (${e.abuseipdb.totalReports} reports)`);
  if (e.geo) {
    const loc = [e.geo.city, e.geo.country].filter(Boolean).join(", ");
    const flags = [e.geo.hosting ? "hosting" : "", e.geo.proxy ? "proxy/VPN" : ""].filter(Boolean).join(", ");
    parts.push(`**Origin:** ${loc || "?"}${e.geo.asn ? ` · ${e.geo.asn}` : ""}${flags ? ` · ${flags}` : ""}`);
  }
  if (!parts.length) return null;
  return { name: `🌍 IP intel — ${e.ip}`, value: parts.join("\n").slice(0, FIELD_VALUE_MAX), inline: false };
}

export function buildEmbed(ctx: CorrelatedContext, summary: AlertSummary, enrichment?: Enrichment) {
  const a = ctx.alert;
  const sev = summary.severity;
  const fields: EmbedField[] = [];

  if (a.srcIp) {
    fields.push({ name: "Source", value: `\`${a.srcIp}${a.srcPort ? ":" + a.srcPort : ""}\``, inline: true });
  }
  if (a.dstIp) {
    fields.push({ name: "Destination", value: `\`${a.dstIp}${a.dstPort ? ":" + a.dstPort : ""}\``, inline: true });
  }
  if (a.protocol) fields.push({ name: "Protocol", value: a.protocol, inline: true });
  if (a.action) fields.push({ name: "Action", value: a.action, inline: true });
  if (a.classification) fields.push({ name: "Classification", value: clip(a.classification, 256), inline: true });
  if (a.signatureId) fields.push({ name: "Signature ID", value: `\`${a.signatureId}\``, inline: true });

  if (enrichment) {
    const f = intelField(enrichment);
    if (f) fields.push(f);
  }

  fields.push({ name: "Risk assessment", value: clip(summary.riskAssessment, FIELD_VALUE_MAX), inline: false });

  if (summary.recommendedActions.length) {
    const actions = summary.recommendedActions.map((x) => `• ${x}`).join("\n");
    fields.push({ name: "Recommended actions", value: clip(actions, FIELD_VALUE_MAX), inline: false });
  }

  fields.push({ name: "Raw alert", value: codeBlock(a.event.raw, ""), inline: false });

  if (ctx.relatedEvents.length) {
    const ctxText = ctx.relatedEvents
      .slice(0, 8)
      .map((e) => (e.message || e.raw).replace(/\s+/g, " ").trim())
      .join("\n");
    fields.push({
      name: `Related log context (${ctx.relatedEvents.length})`,
      value: codeBlock(clip(ctxText, FIELD_VALUE_MAX - 12)),
      inline: false,
    });
  }

  return {
    title: clip(`${EMOJI[sev]} ${summary.title}`, 256),
    description: clip(summary.whatHappened, DESC_MAX),
    color: COLORS[sev],
    fields,
    footer: {
      text: clip(
        `${a.category} • severity ${sev}` +
          (summary.fallback ? " • offline summary" : summary.model ? ` • ${summary.model}` : "") +
          (a.event.host ? ` • ${a.event.host}` : ""),
        2048,
      ),
    },
    timestamp: new Date(a.event.timestamp ?? a.event.receivedAt).toISOString(),
  };
}

export class DiscordNotifier {
  readonly #cfg: Config;
  constructor(cfg: Config) {
    this.#cfg = cfg;
  }

  async send(ctx: CorrelatedContext, summary: AlertSummary, enrichment?: Enrichment): Promise<boolean> {
    const embed = buildEmbed(ctx, summary, enrichment);
    const mentionable = summary.severity === "critical" || summary.severity === "high";
    const payload: Record<string, unknown> = {
      username: this.#cfg.discord.username,
      embeds: [embed],
    };
    if (this.#cfg.discord.avatarUrl) payload["avatar_url"] = this.#cfg.discord.avatarUrl;
    if (this.#cfg.discord.mention && mentionable) {
      payload["content"] = this.#cfg.discord.mention;
      payload["allowed_mentions"] = { parse: ["roles", "users", "everyone"] };
    }

    if (this.#cfg.runtime.dryRun) {
      log.info(`[dry-run] would post to Discord: ${embed.title}`);
      log.debug(JSON.stringify(payload, null, 2));
      return true;
    }

    for (let attempt = 0; attempt < 3; attempt++) {
      const res = await fetch(this.#cfg.discord.webhookUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      }).catch((err: Error) => {
        log.warn(`Discord POST network error: ${err.message}`);
        return undefined;
      });
      if (!res) {
        await new Promise((r) => setTimeout(r, 500 * 2 ** attempt));
        continue;
      }
      if (res.status === 429) {
        const body = (await res.json().catch(() => ({}))) as { retry_after?: number };
        const wait = (body.retry_after ?? 1) * 1000;
        log.warn(`Discord rate limited, retrying in ${wait}ms`);
        await new Promise((r) => setTimeout(r, wait));
        continue;
      }
      if (res.ok || res.status === 204) return true;
      const text = await res.text().catch(() => "");
      log.error(`Discord webhook error ${res.status}: ${text.slice(0, 300)}`);
      return false;
    }
    log.error("Discord webhook failed after retries.");
    return false;
  }

  /** Post an arbitrary embed (used by the digest). */
  async postEmbed(embed: Record<string, unknown>, content?: string): Promise<boolean> {
    const payload: Record<string, unknown> = { username: this.#cfg.discord.username, embeds: [embed] };
    if (this.#cfg.discord.avatarUrl) payload["avatar_url"] = this.#cfg.discord.avatarUrl;
    if (content) payload["content"] = content;
    if (this.#cfg.runtime.dryRun) {
      log.info(`[dry-run] would post digest embed: ${String((embed as { title?: string }).title ?? "")}`);
      return true;
    }
    const res = await fetch(this.#cfg.discord.webhookUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    }).catch(() => undefined);
    if (res && (res.ok || res.status === 204)) return true;
    log.error(`Digest post failed: ${res ? res.status : "network error"}`);
    return false;
  }
}
