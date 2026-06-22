/**
 * UDP and/or TCP syslog listener. Each received line is parsed into a LogEvent
 * and handed to the provided callback. One datagram may contain several
 * newline-separated messages; TCP streams are split on newlines as well.
 */
import dgram from "node:dgram";
import net from "node:net";
import type { Config } from "../config.ts";
import type { LogEvent } from "../types.ts";
import { parseSyslog } from "./parser.ts";
import { log } from "../logger.ts";

export type EventHandler = (event: LogEvent) => void;

export interface SyslogServer {
  close: () => Promise<void>;
}

export async function startSyslogServer(cfg: Config, onEvent: EventHandler): Promise<SyslogServer> {
  const { protocol, host, udpPort, tcpPort } = cfg.syslog;
  const closers: Array<() => Promise<void>> = [];

  const handlePayload = (payload: string, transport: string) => {
    const now = Date.now();
    for (const line of payload.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        onEvent(parseSyslog(trimmed, transport, now));
      } catch (err) {
        log.warn(`Failed to handle syslog line: ${(err as Error).message}`);
      }
    }
  };

  if (protocol === "udp" || protocol === "both") {
    const udp = dgram.createSocket({ type: "udp4", reuseAddr: true });
    udp.on("message", (msg, rinfo) => handlePayload(msg.toString("utf8"), rinfo.address));
    udp.on("error", (err) => log.error(`UDP syslog error: ${err.message}`));
    await new Promise<void>((resolve, reject) => {
      udp.once("error", reject);
      udp.bind(udpPort, host, () => {
        udp.removeListener("error", reject);
        log.info(`UDP syslog listening on ${host}:${udpPort}`);
        resolve();
      });
    });
    closers.push(() => new Promise((r) => udp.close(() => r())));
  }

  if (protocol === "tcp" || protocol === "both") {
    const server = net.createServer((socket) => {
      const peer = socket.remoteAddress ?? "unknown";
      let buffer = "";
      socket.setEncoding("utf8");
      socket.on("data", (chunk: string) => {
        buffer += chunk;
        const idx = buffer.lastIndexOf("\n");
        if (idx >= 0) {
          handlePayload(buffer.slice(0, idx), peer);
          buffer = buffer.slice(idx + 1);
        }
        // Guard against an unbounded line from a misbehaving sender.
        if (buffer.length > 1_000_000) buffer = "";
      });
      socket.on("end", () => {
        if (buffer.trim()) handlePayload(buffer, peer);
      });
      socket.on("error", (err) => log.debug(`TCP client ${peer} error: ${err.message}`));
    });
    server.on("error", (err) => log.error(`TCP syslog error: ${err.message}`));
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(tcpPort, host, () => {
        server.removeListener("error", reject);
        log.info(`TCP syslog listening on ${host}:${tcpPort}`);
        resolve();
      });
    });
    closers.push(() => new Promise((r) => server.close(() => r())));
  }

  return {
    close: async () => {
      await Promise.all(closers.map((c) => c()));
    },
  };
}
