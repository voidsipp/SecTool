/**
 * Deception layer: opens decoy services on ports nothing legitimate should ever
 * touch. Any connection is a near-zero-false-positive signal — an external
 * attacker who reached in, or (high value) a COMPROMISED INTERNAL host doing
 * reconnaissance / lateral movement. Hits flow into the same Discord/enrich
 * pipeline; internal hits are flagged as likely compromise.
 */
import net from "node:net";
import type { Config } from "../config.ts";
import { DiscordNotifier } from "../notify/discord.ts";
import { enrichIp } from "../investigate/enrich.ts";
import { blockIp, blockGuard } from "../respond/blocker.ts";
import { log } from "../logger.ts";

// Plausible banners so a scanner thinks it found a real service.
const BANNERS: Record<number, string> = {
  21: "220 ProFTPD 1.3.5 Server ready\r\n",
  23: "\xff\xfd\x18\xff\xfd\x20login: ",
  2222: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
  3389: "",
  5900: "RFB 003.008\n",
  1433: "",
  8081: "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Router\"\r\n\r\n",
};

const recent = new Map<string, number>(); // source IP -> last alert ms (dedupe)

function normalizeIp(ip: string | undefined): string {
  return (ip ?? "?").replace(/^::ffff:/, "");
}
function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/.test(ip);
}

export interface Honeypot {
  close: () => Promise<void>;
}

export async function startHoneypot(cfg: Config): Promise<Honeypot> {
  const notifier = new DiscordNotifier(cfg);
  const servers: net.Server[] = [];
  let bound = 0;

  for (const port of cfg.honeypot.ports) {
    const srv = net.createServer((socket) => void onHit(cfg, notifier, port, socket));
    srv.on("error", (err) => log.warn(`Honeypot: could not bind decoy port ${port}: ${err.message}`));
    srv.listen(port, cfg.honeypot.host, () => {
      bound++;
    });
    servers.push(srv);
  }
  // Give listen callbacks a tick to run, then report.
  await new Promise((r) => setTimeout(r, 300));
  log.info(`Honeypot active — ${bound}/${cfg.honeypot.ports.length} decoy ports on ${cfg.honeypot.host}.`);

  return {
    close: async () => {
      await Promise.all(servers.map((s) => new Promise<void>((r) => s.close(() => r()))));
    },
  };
}

async function onHit(cfg: Config, notifier: DiscordNotifier, port: number, socket: net.Socket): Promise<void> {
  const src = normalizeIp(socket.remoteAddress);
  try {
    const banner = BANNERS[port];
    if (banner) socket.write(banner);
  } catch {
    /* ignore */
  }
  setTimeout(() => socket.destroy(), 1500);

  // Dedupe per source for 5 minutes.
  const now = Date.now();
  const last = recent.get(src);
  if (last && now - last < 300_000) return;
  recent.set(src, now);

  const internal = isPrivate(src);
  log.warn(`🍯 HONEYPOT HIT: ${src} → decoy port ${port}${internal ? " (INTERNAL host — likely compromised!)" : ""}`);

  const enrichment = internal ? undefined : await enrichIp(cfg, src).catch(() => undefined);

  await notifier.postEmbed(
    {
      title: `🍯 Honeypot triggered — ${src}`,
      description: internal
        ? `**An internal host (${src}) connected to a decoy service.** Nothing legitimate should ever touch this — this host is very likely **compromised and scanning your network**. Investigate it immediately.`
        : `External IP ${src} connected to a decoy service (unsolicited inbound to a fake port).`,
      color: 0x992d22,
      fields: [
        { name: "Source", value: `\`${src}\`${internal ? " (internal)" : ""}`, inline: true },
        { name: "Decoy port", value: String(port), inline: true },
        ...(enrichment?.geo ? [{ name: "Origin", value: `${enrichment.geo.country ?? "?"} · ${enrichment.geo.asn ?? ""}`, inline: true }] : []),
        ...(enrichment?.virustotal ? [{ name: "VirusTotal", value: `${enrichment.virustotal.malicious} malicious`, inline: true }] : []),
        ...(enrichment?.feeds?.length ? [{ name: "Threat feeds", value: enrichment.feeds.join(", "), inline: false }] : []),
      ],
      footer: { text: "SecTool deception · zero-false-positive detection" },
      timestamp: new Date().toISOString(),
    },
    cfg.discord.mention || undefined,
  );

  // External honeypot hits are high-confidence; auto-block if enabled. Never
  // auto-block an internal host (that would cut off your own device).
  if (!internal && cfg.honeypot.autoBlock && !blockGuard(cfg, src)) {
    try {
      await blockIp(cfg, src, `honeypot hit (decoy port ${port})`, "honeypot");
    } catch (err) {
      log.warn(`Honeypot auto-block failed for ${src}: ${(err as Error).message}`);
    }
  }
}
