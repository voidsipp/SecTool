/**
 * Builds the analyst prompt sent to Claude from a correlated alert context.
 */
import type { CorrelatedContext, LogEvent } from "../types.ts";

// Identity block required when calling the API with Claude Code OAuth creds.
export const CLAUDE_CODE_IDENTITY = "You are Claude Code, Anthropic's official CLI for Claude.";

export const ANALYST_SYSTEM = `You are a senior network security analyst triaging IDS/IPS and firewall alerts from a Ubiquiti UDM Pro gateway.
Given one alert and the surrounding log context, produce a concise, accurate, non-alarmist triage.
Be specific about what the signature means, whether the traffic was blocked or merely detected, and the realistic risk given that the gateway often logs benign or low-severity events.
Do not invent facts that are not supported by the provided data. If information is missing, say so.
Respond with ONLY a single minified JSON object, no markdown fences, matching exactly:
{"title":string,"severity":"critical"|"high"|"medium"|"low"|"info","whatHappened":string,"riskAssessment":string,"recommendedActions":string[]}
- title: <= 90 chars, human readable.
- whatHappened: 1-3 sentences in plain English.
- riskAssessment: 1-3 sentences; state if action was already taken (blocked) and likelihood of real threat.
- recommendedActions: 1-4 short imperative steps; use [] if none are warranted.`;

function fmtTime(ms: number | undefined): string {
  return ms ? new Date(ms).toISOString() : "unknown";
}

function summarizeEvent(ev: LogEvent): string {
  const t = fmtTime(ev.timestamp ?? ev.receivedAt);
  return `[${t}] ${ev.appName ? ev.appName + ": " : ""}${ev.message || ev.raw}`.slice(0, 400);
}

export function buildUserPrompt(ctx: CorrelatedContext): string {
  const a = ctx.alert;
  const lines: string[] = [];
  lines.push("## ALERT");
  lines.push(`category: ${a.category}`);
  if (a.signature) lines.push(`signature: ${a.signature}`);
  if (a.signatureId) lines.push(`signature_id: ${a.signatureId}`);
  if (a.classification) lines.push(`classification: ${a.classification}`);
  if (a.priority !== undefined) lines.push(`suricata_priority: ${a.priority}`);
  if (a.action) lines.push(`action_taken: ${a.action}`);
  if (a.protocol) lines.push(`protocol: ${a.protocol}`);
  if (a.srcIp) lines.push(`source: ${a.srcIp}${a.srcPort ? ":" + a.srcPort : ""}`);
  if (a.dstIp) lines.push(`destination: ${a.dstIp}${a.dstPort ? ":" + a.dstPort : ""}`);
  lines.push(`gateway_severity_guess: ${a.severity}`);
  lines.push(`time: ${fmtTime(a.event.timestamp ?? a.event.receivedAt)}`);
  lines.push("");
  lines.push("## RAW ALERT LINE");
  lines.push(a.event.raw.slice(0, 1000));
  lines.push("");
  lines.push(`## RELATED LOG CONTEXT (${ctx.relatedEvents.length} lines involving ${ctx.involvedIps.join(", ") || "n/a"})`);
  if (ctx.relatedEvents.length === 0) {
    lines.push("(no correlated events in the buffer)");
  } else {
    for (const ev of ctx.relatedEvents.slice(0, 25)) lines.push(summarizeEvent(ev));
  }
  return lines.join("\n");
}
