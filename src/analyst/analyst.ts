/**
 * Conversational security analyst: answers natural-language questions by giving
 * Claude read-only tools that query the network's actual telemetry — collected
 * flows, IDS/IPS alerts (Mongo), DNS history, IP reputation/feeds, host risk,
 * and the blocklist. The model decides which tools to call.
 */
import { isIP } from "node:net";
import type { Config } from "../config.ts";
import { Summarizer, type AnalystTool } from "../summarize/claude.ts";
import { getActiveFlowStore } from "../netflow/flowAccess.ts";
import { mongoQuery, sshExec } from "../ingest/sshPull.ts";
import { enrichIp } from "../investigate/enrich.ts";
import { feedMatch } from "../intel/feedAccess.ts";
import { computeHostRisks } from "../investigate/hosts.ts";
import { listBlocks } from "../respond/blocker.ts";

const SYSTEM = `You are a security analyst assistant for a home/small-office network behind a UniFi UDM Pro.
Answer the user's question by calling the provided tools to query their REAL network telemetry — never invent data.
Internal network is 192.168.0.0/24; the main host is 192.168.0.60; the UDM gateway is 192.168.0.1.
Be concise and specific: cite concrete IPs, counts, times, and verdicts. If the data doesn't answer the question, say so plainly. Prefer 2-3 tool calls over many. Summarize findings for a non-expert.`;

const TOOLS: AnalystTool[] = [
  {
    name: "query_flows",
    description: "Query collected NetFlow connection records. Optionally filter by an IP (matches src or dst) and a lookback window in hours. Returns recent flows (proto, endpoints, bytes).",
    input_schema: {
      type: "object",
      properties: { ip: { type: "string" }, hours: { type: "number" }, limit: { type: "number" } },
    },
  },
  {
    name: "query_alerts",
    description: "Query stored IDS/IPS threat detections from the UDM. Optional ip filter and lookback hours. Returns alert key, severity, src->dst, time.",
    input_schema: {
      type: "object",
      properties: { ip: { type: "string" }, hours: { type: "number" } },
    },
  },
  {
    name: "query_dns",
    description: "Search the network's DNS resolution log for domains containing a substring within the last N hours. Returns matching domains with counts.",
    input_schema: {
      type: "object",
      properties: { contains: { type: "string" }, hours: { type: "number" } },
      required: ["contains"],
    },
  },
  {
    name: "enrich_ip",
    description: "Look up reputation/geo for an IP: country, ASN, hosting/proxy flags, VirusTotal verdict, AbuseIPDB, and threat-feed membership.",
    input_schema: { type: "object", properties: { ip: { type: "string" } }, required: ["ip"] },
  },
  {
    name: "host_risks",
    description: "Return internal hosts showing compromise signals (outbound to known-bad, beaconing, fan-out) with risk scores and evidence.",
    input_schema: { type: "object", properties: {} },
  },
  {
    name: "list_blocks",
    description: "List IPs currently blocked at the firewall, with how long they've been blocked and why.",
    input_schema: { type: "object", properties: {} },
  },
];

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").slice(0, 19);
}

async function execTool(cfg: Config, name: string, input: Record<string, unknown>): Promise<string> {
  const ip = typeof input["ip"] === "string" ? (input["ip"] as string) : undefined;
  const hours = typeof input["hours"] === "number" ? (input["hours"] as number) : 24;

  switch (name) {
    case "query_flows": {
      const store = getActiveFlowStore();
      if (!store) return "Flow collector not running — no flow data.";
      const now = Date.now();
      const flows = ip
        ? store.query([ip], now - hours * 3_600_000, now, 60)
        : store.query([], now - hours * 3_600_000, now, 60);
      if (!flows.length) return `No flows in the last ${hours}h${ip ? ` for ${ip}` : ""}.`;
      const proto: Record<number, string> = { 1: "ICMP", 6: "TCP", 17: "UDP" };
      return `${flows.length} flows:\n` + flows
        .slice(0, 50)
        .map((f) => `${fmtTime(f.start ?? f.receivedAt)} ${proto[f.proto ?? 0] ?? f.proto} ${f.srcIp}:${f.srcPort}->${f.dstIp}:${f.dstPort} ${f.bytes ?? 0}B`)
        .join("\n");
    }
    case "query_alerts": {
      const now = Date.now();
      const lo = now - hours * 3_600_000;
      const ipClause = ip && isIP(ip) > 0
        ? `,$or:[{'parameters.SRC_IP.target_id':${JSON.stringify(ip)}},{'parameters.DST_IP.target_id':${JSON.stringify(ip)}}]`
        : "";
      const js =
        `print(JSON.stringify(db.alert.find({time:{$gte:${lo}}${ipClause}}).sort({time:-1}).limit(60).toArray()` +
        `.map(function(d){var p=d.parameters||{};function i(o){return o&&(o.target_id||o.name);}` +
        `return {t:(d.time&&d.time.valueOf?d.time.valueOf():d.time),key:d.key,sev:d.severity,src:i(p.SRC_IP)||i(p.SRC_CLIENT),dst:i(p.DST_IP)||i(p.DST_CLIENT)};})))`;
      const out = await mongoQuery(js, { timeoutMs: 20000 });
      try {
        const a = out.indexOf("[");
        const b = out.lastIndexOf("]");
        const arr = a !== -1 && b > a ? (JSON.parse(out.slice(a, b + 1)) as Array<Record<string, unknown>>) : [];
        if (!arr.length) return `No IDS/IPS alerts in the last ${hours}h${ip ? ` for ${ip}` : ""}.`;
        return `${arr.length} alerts:\n` + arr.map((d) => `${fmtTime(Number(d["t"]))} [${d["sev"]}] ${d["key"]} ${d["src"]}->${d["dst"]}`).join("\n");
      } catch {
        return "Could not parse alert data.";
      }
    }
    case "query_dns": {
      const contains = String(input["contains"] ?? "").replace(/[^\w.-]/g, "");
      if (!contains) return "Provide a domain substring.";
      const lo = Math.round((Date.now() - hours * 3_600_000) / 1000);
      const remote =
        `LO=$(date -d @${lo} '+%Y-%m-%d %H:%M:%S'); ` +
        `awk -v lo="$LO" 'substr($0,2,19)>=lo' /var/log/query-dnscrypt-proxy.log 2>/dev/null | grep -iF '${contains}' | awk '{print $3}' | sort | uniq -c | sort -rn | head -40`;
      const out = await sshExec(remote, { timeoutMs: 20000 });
      return out.trim() ? `DNS lookups matching "${contains}" (count domain):\n${out.trim()}` : `No DNS lookups matching "${contains}" in the last ${hours}h.`;
    }
    case "enrich_ip": {
      if (!ip || isIP(ip) === 0) return "Provide a valid IP.";
      const e = await enrichIp(cfg, ip);
      return JSON.stringify({
        ip: e.ip,
        private: e.isPrivate,
        geo: e.geo ? { country: e.geo.country, asn: e.geo.asn, org: e.geo.org, hosting: e.geo.hosting, proxy: e.geo.proxy } : null,
        virustotal: e.virustotal ? { malicious: e.virustotal.malicious, suspicious: e.virustotal.suspicious, reputation: e.virustotal.reputation } : null,
        abuseipdb: e.abuseipdb ? { score: e.abuseipdb.score } : null,
        threatFeeds: feedMatch(ip),
      });
    }
    case "host_risks": {
      const risks = computeHostRisks();
      if (!risks.length) return "No internal hosts show risk signals.";
      return risks.slice(0, 10).map((h) => `${h.ip} risk=${h.score}: ${h.reasons.join("; ")}`).join("\n");
    }
    case "list_blocks": {
      const blocks = listBlocks();
      if (!blocks.length) return "No IPs are currently blocked.";
      return blocks.map((b) => `${b.ip} — ${Math.round(b.durationMs / 3_600_000)}h — ${b.reason ?? ""}`).join("\n");
    }
    default:
      return `Unknown tool: ${name}`;
  }
}

export async function askAnalyst(cfg: Config, question: string): Promise<{ answer: string; toolsUsed: string[] }> {
  const summarizer = new Summarizer(cfg);
  await summarizer.preflight();
  return summarizer.toolLoop(SYSTEM, question, TOOLS, (name, input) => execTool(cfg, name, input), {
    maxTokens: 1500,
    maxRounds: 6,
  });
}
