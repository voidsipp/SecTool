/**
 * Formats an alert + Claude summary into a Discord embed and posts it to the
 * configured webhook, respecting Discord's size limits and rate limiting.
 */
import type { Config } from "../config.ts";
import type { AlertSummary, CorrelatedContext, Severity } from "../types.ts";
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

export function buildEmbed(ctx: CorrelatedContext, summary: AlertSummary) {
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

  async send(ctx: CorrelatedContext, summary: AlertSummary): Promise<boolean> {
    const embed = buildEmbed(ctx, summary);
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
}
