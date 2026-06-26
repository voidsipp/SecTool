/**
 * Action-capable automation agent.
 *
 * Where the read-only analyst (analyst.ts) answers questions, this agent *operates*
 * SecTool on the operator's behalf: it can create/remove suppression rules, manage
 * the safelist/watchlist, block/unblock IPs at the firewall, and drive per-alert
 * triage (status, notes, dismiss/restore). Every project feature that has a
 * mutating endpoint in the dashboard is exposed here as a tool so a natural-language
 * instruction ("mute the noisy SSH-scan signature from 10.0.0.5 for 24h") becomes a
 * concrete, audited change.
 *
 * Safety model:
 *   - Every mutating tool call is recorded in an audit list returned to the caller.
 *   - A dry-run mode lets the operator preview exactly what *would* change without
 *     touching any store or the firewall.
 *   - Destructive firewall blocks still pass through blockGuard() (the same
 *     allowlist/private-range protections the manual block button uses).
 *
 * It reuses the same Claude tool-use loop (Summarizer.toolLoop) and a subset of the
 * analyst's read tools so the model can look before it leaps (e.g. enrich an IP, or
 * list current rules before adding a duplicate).
 */
import { isIP } from "node:net";
import type { Config } from "../config.ts";
import { Summarizer, type AnalystTool } from "../summarize/claude.ts";
import { enrichIp } from "../investigate/enrich.ts";
import { feedMatch } from "../intel/feedAccess.ts";
import { mongoQuery } from "../ingest/sshPull.ts";
import { suppressionStore, describeMatch, type SuppressionInput } from "../store/suppressions.ts";
import { safeStore } from "../store/safelist.ts";
import { watchStore, canonicalizeTarget } from "../store/watchlist.ts";
import { triageStore, isTriageStatus, TRIAGE_STATUSES, type TriageStatus } from "../store/triage.ts";
import { dismissStore } from "../store/dismissed.ts";
import { blockIp, unblockIp, blockGuard, listBlocks } from "../respond/blocker.ts";
import { SEVERITY_ORDER, type Severity } from "../types.ts";
import { loadHistory, recordExchange, type MemoryOpts } from "./memory.ts";

const SYSTEM = `You are the automation agent embedded in "SecTool", a network-security monitoring app for a home/small-office network behind a UniFi UDM Pro.
Unlike the read-only "Ask" analyst, you can TAKE ACTIONS on the operator's behalf by calling the mutating tools below. Use them to fulfil the operator's instruction precisely.

You can operate every operator-facing SecTool feature:
- Suppressions — silence Discord notifications for FUTURE alerts matching a pattern (signature/category/srcIp/dstIp/maxSeverity), optionally with a TTL. Tools: list_suppressions, create_suppression, remove_suppression. Alerts are still detected/visible; only notification is muted.
- Safelist — operator-vetted "safe" external IPs, exempt from risk scoring and protected from auto-blocking. Tools: list_safelist, add_safelist, remove_safelist.
- Watchlist — IPs/CIDRs to monitor closely (purely observational). Tools: list_watchlist, add_watchlist, remove_watchlist.
- Firewall blocklist — DROP an external IP at the UDM. Tools: list_blocks, block_ip, unblock_ip. Private/internal/gateway/safelisted IPs are refused by a guard.
- Triage — per-alert workflow status (open / investigating / resolved / false-positive) + an append-only note trail. Tools: set_triage_status, add_triage_note. (Alert ids come from the alert list / query_alerts.)
- Dismiss — hide / restore a single alert by id. Tools: dismiss_alert, restore_alert.
For context you may also enrich_ip, query_alerts, and app_overview before acting.

Rules of engagement:
- Do exactly what the operator asks — no more. Prefer the narrowest change that satisfies the request (e.g. one specific signature, not a broad severity sweep) unless told otherwise.
- A suppression needs at least one match field. NEVER create a suppression with only a high maxSeverity that would mute critical alerts unless the operator explicitly asks.
- Before blocking, you may enrich_ip to confirm the target; never block private/internal IPs (the guard will refuse anyway).
- If the instruction is ambiguous or could be destructive in a way the operator may not intend, make the safest reasonable choice and clearly state in your final answer what you did and what you deliberately did NOT do.
- After acting, summarize concretely: which rules/entries were created or removed (with their ids), and the net effect. Cite IPs, signatures, counts.
Internal network is 192.168.0.0/24; the main host is 192.168.0.60; the UDM gateway is 192.168.0.1.`;

const READ_TOOLS: AnalystTool[] = [
  {
    name: "app_overview",
    description:
      "High-level snapshot of how SecTool is configured: counts of suppression rules, safelisted IPs, watchlisted targets, firewall blocks, dismissed alerts, triage status breakdown. Use this to orient before making changes.",
    input_schema: { type: "object", properties: {} },
  },
  {
    name: "list_suppressions",
    description:
      "List existing alert-suppression rules with their id, match pattern, reason, hit count and expiry. Use before creating a rule to avoid duplicates, or to find the id to remove.",
    input_schema: { type: "object", properties: {} },
  },
  {
    name: "list_safelist",
    description: "List operator-vetted 'safe' external IPs. Returns each IP, when it was marked safe, and any note.",
    input_schema: { type: "object", properties: {} },
  },
  {
    name: "list_watchlist",
    description: "List the IPs/CIDRs on the watchlist. Returns each target, when it was added, and any note.",
    input_schema: { type: "object", properties: {} },
  },
  {
    name: "list_blocks",
    description: "List IPs currently blocked at the firewall, with how long they've been blocked and why.",
    input_schema: { type: "object", properties: {} },
  },
  {
    name: "enrich_ip",
    description: "Look up reputation/geo for an IP: country, ASN, hosting/proxy flags, VirusTotal verdict, AbuseIPDB, and threat-feed membership. Use to confirm a target before blocking/safelisting.",
    input_schema: { type: "object", properties: { ip: { type: "string" } }, required: ["ip"] },
  },
  {
    name: "query_alerts",
    description: "Query stored IDS/IPS threat detections from the UDM. Optional ip filter and lookback hours. Returns alert key, severity, src->dst, time — useful to find a signature/category/IP to suppress.",
    input_schema: { type: "object", properties: { ip: { type: "string" }, hours: { type: "number" } } },
  },
];

const ACTION_TOOLS: AnalystTool[] = [
  {
    name: "create_suppression",
    description:
      "Create a suppression rule that silences Discord notifications for FUTURE alerts matching the given pattern. Provide at least one of signature (case-insensitive substring), category (exact), srcIp, dstIp, maxSeverity (low|medium|high|critical — matches alerts at or below this level). Optional reason and ttlHours (auto-expire). Matched alerts remain detected/visible.",
    input_schema: {
      type: "object",
      properties: {
        signature: { type: "string", description: "Case-insensitive substring of the alert signature." },
        category: { type: "string", description: "Exact alert category." },
        srcIp: { type: "string", description: "Exact source IP." },
        dstIp: { type: "string", description: "Exact destination IP." },
        maxSeverity: { type: "string", enum: [...SEVERITY_ORDER], description: "Mute only alerts at or below this severity." },
        reason: { type: "string", description: "Why this rule exists (shown in the UI)." },
        ttlHours: { type: "number", description: "Auto-expire the rule after this many hours." },
      },
    },
  },
  {
    name: "remove_suppression",
    description: "Delete a suppression rule by its id (get ids from list_suppressions).",
    input_schema: { type: "object", properties: { id: { type: "string" } }, required: ["id"] },
  },
  {
    name: "add_safelist",
    description: "Mark an external IP 'safe': exempt it from host-risk scoring and protect it from auto-blocking. Optional note.",
    input_schema: { type: "object", properties: { ip: { type: "string" }, note: { type: "string" } }, required: ["ip"] },
  },
  {
    name: "remove_safelist",
    description: "Remove an IP from the safelist.",
    input_schema: { type: "object", properties: { ip: { type: "string" } }, required: ["ip"] },
  },
  {
    name: "add_watchlist",
    description: "Add an IP or IPv4 CIDR (e.g. 185.220.101.0/24) to the watchlist for close monitoring. Optional note.",
    input_schema: { type: "object", properties: { target: { type: "string" }, note: { type: "string" } }, required: ["target"] },
  },
  {
    name: "remove_watchlist",
    description: "Remove an IP or CIDR from the watchlist.",
    input_schema: { type: "object", properties: { target: { type: "string" } }, required: ["target"] },
  },
  {
    name: "block_ip",
    description: "Block an external IPv4 at the UDM firewall (DROP). Refuses private/internal/gateway/safelisted IPs. Optional reason.",
    input_schema: { type: "object", properties: { ip: { type: "string" }, reason: { type: "string" } }, required: ["ip"] },
  },
  {
    name: "unblock_ip",
    description: "Remove an IP from the firewall blocklist.",
    input_schema: { type: "object", properties: { ip: { type: "string" } }, required: ["ip"] },
  },
  {
    name: "set_triage_status",
    description: `Set an alert's triage workflow status. status must be one of: ${TRIAGE_STATUSES.join(", ")}. The id is the alert id from the alert list.`,
    input_schema: {
      type: "object",
      properties: { id: { type: "string" }, status: { type: "string", enum: [...TRIAGE_STATUSES] } },
      required: ["id", "status"],
    },
  },
  {
    name: "add_triage_note",
    description: "Append a timestamped note to an alert's triage audit trail. The id is the alert id from the alert list.",
    input_schema: { type: "object", properties: { id: { type: "string" }, text: { type: "string" } }, required: ["id", "text"] },
  },
  {
    name: "dismiss_alert",
    description: "Hide a single alert from the dashboard list by its id (restorable). Optional reason.",
    input_schema: { type: "object", properties: { id: { type: "string" }, reason: { type: "string" } }, required: ["id"] },
  },
  {
    name: "restore_alert",
    description: "Un-dismiss a previously dismissed alert by its id.",
    input_schema: { type: "object", properties: { id: { type: "string" } }, required: ["id"] },
  },
];

const TOOLS: AnalystTool[] = [...READ_TOOLS, ...ACTION_TOOLS];
const ACTION_TOOL_NAMES = new Set(ACTION_TOOLS.map((t) => t.name));

export interface AgentAction {
  tool: string;
  ok: boolean;
  /** Human-readable description of what was (or, in dry-run, would be) done. */
  detail: string;
  /** True when the change was only simulated (dry-run). */
  planned?: boolean;
}

function fmtTime(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").slice(0, 19);
}

function str(input: Record<string, unknown>, k: string): string | undefined {
  return typeof input[k] === "string" && (input[k] as string).trim() ? (input[k] as string).trim() : undefined;
}

function severityFrom(v: unknown): Severity | undefined {
  return typeof v === "string" && (SEVERITY_ORDER as readonly string[]).includes(v) ? (v as Severity) : undefined;
}

/**
 * Build the tool executor for one agent run. Mutating tools push an entry to
 * `actions`; when `dryRun` is set they describe the change without performing it.
 */
function makeExecutor(cfg: Config, dryRun: boolean, actions: AgentAction[]) {
  const record = (tool: string, ok: boolean, detail: string): string => {
    actions.push({ tool, ok, detail, planned: dryRun });
    return (dryRun ? "[dry-run] " : "") + detail;
  };

  return async function execTool(name: string, input: Record<string, unknown>): Promise<string> {
    switch (name) {
      // ---- read / context ----
      case "app_overview": {
        const tri = triageStore.counts();
        return [
          "SecTool configuration snapshot:",
          `- Suppression rules: ${suppressionStore.count()}`,
          `- Safelisted IPs: ${safeStore.count()}`,
          `- Watchlisted targets: ${watchStore.count()}`,
          `- Firewall blocks active: ${listBlocks().length}`,
          `- Dismissed alerts: ${dismissStore.count()}`,
          `- Triaged alerts: ${tri.total} (open=${tri.open}, investigating=${tri.investigating}, resolved=${tri.resolved}, false-positive=${tri["false-positive"]})`,
        ].join("\n");
      }
      case "list_suppressions": {
        const rules = suppressionStore.all();
        if (!rules.length) return "No suppression rules are configured.";
        const now = Date.now();
        return `${rules.length} suppression rule(s):\n` + rules
          .map((r) => {
            const expiry = r.expiresAt
              ? r.expiresAt <= now
                ? " (expired)"
                : ` (expires in ${Math.max(1, Math.round((r.expiresAt - now) / 3_600_000))}h)`
              : "";
            return `[${r.id}] ${describeMatch(r.match)}${expiry} — ${r.hitCount} hit(s)${r.reason ? ` — reason: ${r.reason}` : ""}`;
          })
          .join("\n");
      }
      case "list_safelist": {
        const entries = safeStore.all();
        if (!entries.length) return "The safelist is empty.";
        return `${entries.length} safelisted IP(s):\n` + entries.map((e) => `${e.ip} — added ${fmtTime(e.at)}${e.note ? ` — ${e.note}` : ""}`).join("\n");
      }
      case "list_watchlist": {
        const entries = watchStore.all();
        if (!entries.length) return "The watchlist is empty.";
        return `${entries.length} watchlisted target(s):\n` + entries.map((e) => `${e.target}${e.family === 0 ? " (CIDR)" : ""} — added ${fmtTime(e.at)}${e.note ? ` — ${e.note}` : ""}`).join("\n");
      }
      case "list_blocks": {
        const blocks = listBlocks();
        if (!blocks.length) return "No IPs are currently blocked.";
        return blocks.map((b) => `${b.ip} — ${Math.round(b.durationMs / 3_600_000)}h — ${b.reason ?? ""}`).join("\n");
      }
      case "enrich_ip": {
        const ip = str(input, "ip");
        if (!ip || isIP(ip) === 0) return "Provide a valid IP.";
        const e = await enrichIp(cfg, ip);
        return JSON.stringify({
          ip: e.ip,
          private: e.isPrivate,
          geo: e.geo ? { country: e.geo.country, asn: e.geo.asn, org: e.geo.org, hosting: e.geo.hosting, proxy: e.geo.proxy } : null,
          virustotal: e.virustotal ? { malicious: e.virustotal.malicious, suspicious: e.virustotal.suspicious } : null,
          abuseipdb: e.abuseipdb ? { score: e.abuseipdb.score } : null,
          threatFeeds: feedMatch(ip),
        });
      }
      case "query_alerts": {
        const ip = str(input, "ip");
        const hours = typeof input["hours"] === "number" ? (input["hours"] as number) : 24;
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

      // ---- actions ----
      case "create_suppression": {
        const ttlHours = typeof input["ttlHours"] === "number" && (input["ttlHours"] as number) > 0 ? (input["ttlHours"] as number) : undefined;
        const spec: SuppressionInput = {
          signature: str(input, "signature"),
          category: str(input, "category"),
          srcIp: str(input, "srcIp"),
          dstIp: str(input, "dstIp"),
          maxSeverity: severityFrom(input["maxSeverity"]),
          reason: str(input, "reason"),
          ttlMs: ttlHours ? Math.round(ttlHours * 3_600_000) : undefined,
        };
        if (dryRun) {
          const preview = buildMatchPreview(spec);
          if (!preview) return record("create_suppression", false, "would NOT create: needs at least one match field (signature/category/srcIp/dstIp/maxSeverity).");
          return record("create_suppression", true, `would create suppression ${preview}${ttlHours ? ` (expires in ${ttlHours}h)` : ""}${spec.reason ? ` — reason: ${spec.reason}` : ""}`);
        }
        const rule = suppressionStore.add(spec);
        if (!rule) return record("create_suppression", false, "failed: needs at least one match field (signature/category/srcIp/dstIp/maxSeverity).");
        return record("create_suppression", true, `created suppression [${rule.id}] ${describeMatch(rule.match)}${rule.expiresAt ? ` (expires ${fmtTime(rule.expiresAt)})` : ""}${rule.reason ? ` — reason: ${rule.reason}` : ""}`);
      }
      case "remove_suppression": {
        const id = str(input, "id");
        if (!id) return record("remove_suppression", false, "no rule id provided.");
        if (dryRun) {
          const exists = suppressionStore.all().some((r) => r.id === id);
          return record("remove_suppression", exists, exists ? `would remove suppression [${id}]` : `no suppression with id [${id}]`);
        }
        const removed = suppressionStore.remove(id);
        return record("remove_suppression", removed, removed ? `removed suppression [${id}]` : `no suppression with id [${id}]`);
      }
      case "add_safelist": {
        const ip = str(input, "ip");
        const note = str(input, "note");
        if (!ip || isIP(ip) === 0) return record("add_safelist", false, "invalid or missing IP.");
        if (dryRun) return record("add_safelist", true, `would mark ${ip} safe${note ? ` — ${note}` : ""}`);
        safeStore.add(ip, note);
        return record("add_safelist", true, `marked ${ip} safe${note ? ` — ${note}` : ""}`);
      }
      case "remove_safelist": {
        const ip = str(input, "ip");
        if (!ip || isIP(ip) === 0) return record("remove_safelist", false, "invalid or missing IP.");
        if (dryRun) return record("remove_safelist", safeStore.has(ip), safeStore.has(ip) ? `would remove ${ip} from the safelist` : `${ip} is not on the safelist`);
        const removed = safeStore.remove(ip);
        return record("remove_safelist", removed, removed ? `removed ${ip} from the safelist` : `${ip} was not on the safelist`);
      }
      case "add_watchlist": {
        const target = str(input, "target") ?? str(input, "ip");
        const note = str(input, "note");
        if (!target || !canonicalizeTarget(target)) return record("add_watchlist", false, "invalid IP or CIDR.");
        if (dryRun) return record("add_watchlist", true, `would add ${canonicalizeTarget(target)!.canonical} to the watchlist${note ? ` — ${note}` : ""}`);
        const entry = watchStore.add(target, note);
        return entry
          ? record("add_watchlist", true, `added ${entry.target} to the watchlist${entry.note ? ` — ${entry.note}` : ""}`)
          : record("add_watchlist", false, "invalid IP or CIDR.");
      }
      case "remove_watchlist": {
        const target = str(input, "target") ?? str(input, "ip");
        if (!target) return record("remove_watchlist", false, "no target provided.");
        if (dryRun) return record("remove_watchlist", watchStore.has(target), watchStore.has(target) ? `would remove ${target} from the watchlist` : `${target} is not on the watchlist`);
        const removed = watchStore.remove(target);
        return record("remove_watchlist", removed, removed ? `removed ${target} from the watchlist` : `${target} was not on the watchlist`);
      }
      case "block_ip": {
        const ip = str(input, "ip");
        const reason = str(input, "reason");
        if (!ip) return record("block_ip", false, "no IP provided.");
        const guard = blockGuard(cfg, ip);
        if (guard) return record("block_ip", false, `refused to block ${ip}: ${guard}`);
        if (dryRun) return record("block_ip", true, `would block ${ip} at the firewall${reason ? ` — ${reason}` : ""}`);
        try {
          await blockIp(cfg, ip, reason ?? "automation agent", "automation-agent");
          return record("block_ip", true, `blocked ${ip} at the firewall${reason ? ` — ${reason}` : ""}`);
        } catch (err) {
          return record("block_ip", false, `block failed for ${ip}: ${(err as Error).message}`);
        }
      }
      case "unblock_ip": {
        const ip = str(input, "ip");
        if (!ip) return record("unblock_ip", false, "no IP provided.");
        if (dryRun) return record("unblock_ip", true, `would unblock ${ip}`);
        const had = await unblockIp(ip);
        return record("unblock_ip", had, had ? `unblocked ${ip}` : `${ip} was not blocked`);
      }
      case "set_triage_status": {
        const id = str(input, "id");
        const status = input["status"];
        if (!id) return record("set_triage_status", false, "no alert id provided.");
        if (!isTriageStatus(status)) return record("set_triage_status", false, `status must be one of: ${TRIAGE_STATUSES.join(", ")}`);
        if (dryRun) return record("set_triage_status", true, `would set alert ${id} to "${status}"`);
        triageStore.setStatus(id, status as TriageStatus);
        return record("set_triage_status", true, `set alert ${id} to "${status}"`);
      }
      case "add_triage_note": {
        const id = str(input, "id");
        const text = str(input, "text");
        if (!id) return record("add_triage_note", false, "no alert id provided.");
        if (!text) return record("add_triage_note", false, "note text is empty.");
        if (dryRun) return record("add_triage_note", true, `would add note to alert ${id}: "${text}"`);
        const note = triageStore.addNote(id, text);
        return note ? record("add_triage_note", true, `added note to alert ${id}`) : record("add_triage_note", false, "note text is empty.");
      }
      case "dismiss_alert": {
        const id = str(input, "id");
        const reason = str(input, "reason");
        if (!id) return record("dismiss_alert", false, "no alert id provided.");
        if (dryRun) return record("dismiss_alert", true, `would dismiss alert ${id}${reason ? ` — ${reason}` : ""}`);
        dismissStore.dismiss(id, reason);
        return record("dismiss_alert", true, `dismissed alert ${id}${reason ? ` — ${reason}` : ""}`);
      }
      case "restore_alert": {
        const id = str(input, "id");
        if (!id) return record("restore_alert", false, "no alert id provided.");
        if (dryRun) return record("restore_alert", dismissStore.has(id), dismissStore.has(id) ? `would restore alert ${id}` : `alert ${id} was not dismissed`);
        const had = dismissStore.restore(id);
        return record("restore_alert", had, had ? `restored alert ${id}` : `alert ${id} was not dismissed`);
      }
      default:
        return `Unknown tool: ${name}`;
    }
  };
}

/** Describe the rule a SuppressionInput would produce, or null if it has no match field. */
function buildMatchPreview(spec: SuppressionInput): string | null {
  const parts: string[] = [];
  if (spec.signature) parts.push(`sig~"${spec.signature}"`);
  if (spec.category) parts.push(`cat=${spec.category}`);
  if (spec.srcIp) parts.push(`src=${spec.srcIp}`);
  if (spec.dstIp) parts.push(`dst=${spec.dstIp}`);
  if (spec.maxSeverity) parts.push(`sev<=${spec.maxSeverity}`);
  return parts.length ? parts.join(" & ") : null;
}

export interface AgentResult {
  answer: string;
  toolsUsed: string[];
  actions: AgentAction[];
  dryRun: boolean;
  /**
   * True when the model's first draft answer described/promised an action but
   * called no action tool, so it was nudged to actually act (or retract the
   * claim) before this result was finalized. Surfaced for transparency/debugging.
   */
  nudged: boolean;
}

/**
 * Phrases that indicate the model *thinks* it performed or is about to perform a
 * mutating operation: a forward-looking promise ("I'll block…", "let me create…")
 * or a claimed completion ("done", "I've muted…", "the IP is now blocked").
 */
const ACTION_INTENT_RE =
  /\b(i'?ll|i will|i'?m going to|i am going to|let me|i'?m about to|i'?ll go ahead|i'?ve|i have|i just|i shall|going to|now|has been|have been|done)\b/i;

/** A mutating verb tied to one of SecTool's action tools. */
const ACTION_VERB_RE =
  /\b(creat(?:e|es|ed|ing)?|add(?:s|ed|ing)?|block(?:s|ed|ing)?|unblock(?:s|ed|ing)?|remov(?:e|es|ed|ing)|delet(?:e|es|ed|ing)|suppress(?:es|ed|ing|ion)?|mut(?:e|es|ed|ing)|safelist(?:ed|ing)?|watchlist(?:ed|ing)?|dismiss(?:es|ed|ing)?|restor(?:e|es|ed|ing)|set(?:s|ting)?|mark(?:s|ed|ing)?|triag(?:e|ed|ing))\b/i;

/**
 * Honest refusals / no-ops ("I will NOT block…", "no changes were made", "I did
 * not act"). When the model openly says it is *not* acting it is telling the
 * truth, so we must not nudge it into taking an action it deliberately declined.
 */
const NO_ACTION_RE =
  /\b(will not|won'?t|cannot|can'?t|did not|didn'?t|do not|don'?t|not going to|decided not to|chose not|refrain|no action|no change|nothing (?:to|was|has)|did nothing|deliberately|already (?:exists|present|blocked|safelisted|suppressed|on the))\b/i;

/**
 * Detect the "promised-but-never-did-it" failure mode: the model produced a final
 * answer that claims/promises a mutating action, yet no action tool actually ran
 * (so `actions` is empty). Honest refusals and read-only answers are excluded.
 */
function claimsUnexecutedAction(answer: string, actions: AgentAction[]): boolean {
  if (actions.length > 0) return false;
  const a = answer.trim();
  if (!a) return false;
  if (NO_ACTION_RE.test(a)) return false;
  return ACTION_INTENT_RE.test(a) && ACTION_VERB_RE.test(a);
}

/**
 * Run the automation agent against a natural-language instruction. When `dryRun`
 * is true, no store or firewall is modified — the returned `actions` describe what
 * would have happened.
 */
export async function runAgent(
  cfg: Config,
  instruction: string,
  opts: { dryRun?: boolean } & MemoryOpts = {},
): Promise<AgentResult> {
  const dryRun = !!opts.dryRun;
  const actions: AgentAction[] = [];
  const summarizer = new Summarizer(cfg);
  await summarizer.preflight();
  const history = loadHistory(cfg, opts.sessionId);
  const system = dryRun
    ? SYSTEM + "\n\nDRY-RUN MODE: the operator is previewing. Decide and call the action tools exactly as you would for real; the system will simulate them and report what WOULD change. Do not refuse just because it's a dry-run."
    : SYSTEM;

  let nudged = false;
  // Guard against the "said it would do it but never called a tool" failure mode:
  // if the model's final answer claims/promises a mutating action yet no action
  // tool actually ran, push it to either perform the action now or honestly
  // retract the claim. Bounded to a single nudge so the loop always terminates.
  const onFinal = (answer: string): string | null => {
    if (!claimsUnexecutedAction(answer, actions)) return null;
    nudged = true;
    const what = dryRun ? "simulated — nothing was previewed" : "performed — nothing was changed";
    return (
      `Your answer describes an action, but you did not call any action tool, so it was NOT ${what}. ` +
      `If you intend to carry out what you described, call the appropriate action tool(s) now (e.g. ` +
      `create_suppression, block_ip, add_safelist, add_watchlist, set_triage_status, dismiss_alert, …). ` +
      `If you did not actually mean to make a change — because the request was informational, the desired ` +
      `state already holds, or you deliberately declined — then reply with your final answer and do NOT ` +
      `state or imply that any change was made.`
    );
  };

  const { answer, toolsUsed } = await summarizer.toolLoop(
    system,
    instruction,
    TOOLS,
    makeExecutor(cfg, dryRun, actions),
    { maxTokens: 1800, maxRounds: 8, onFinal, maxNudges: 1, history },
  );
  // Persist this turn so follow-ups keep context. Tag dry-run answers so the
  // model doesn't later believe a previewed change was actually applied.
  recordExchange(cfg, opts.sessionId, instruction, dryRun ? `[dry-run preview] ${answer}` : answer);
  return { answer, toolsUsed, actions, dryRun, nudged };
}

export { ACTION_TOOL_NAMES };
