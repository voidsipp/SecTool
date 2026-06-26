/**
 * Claude Messages API client supporting two auth modes:
 *  - oauth : Authorization: Bearer <token> + anthropic-beta: oauth-... header,
 *            with the Claude Code identity as the first system block. Token is
 *            refreshed automatically on expiry / 401.
 *  - apikey: standard x-api-key header.
 *
 * Produces a structured AlertSummary from a correlated alert context, with a
 * deterministic fallback if Claude is disabled or unreachable.
 */
import type { Config } from "../config.ts";
import type { AlertSummary, CorrelatedContext, Severity } from "../types.ts";
import { SEVERITY_ORDER } from "../types.ts";
import { ClaudeOAuth } from "./oauth.ts";
import { ANALYST_SYSTEM, CLAUDE_CODE_IDENTITY, buildUserPrompt } from "./prompt.ts";
import { log } from "../logger.ts";

const API_URL = "https://api.anthropic.com/v1/messages";
const API_VERSION = "2023-06-01";
const OAUTH_BETA = "oauth-2025-04-20";
const MAX_RETRIES = 3;

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

interface ContentBlock {
  type: string;
  text?: string;
  id?: string;
  name?: string;
  input?: Record<string, unknown>;
}
interface MessagesResponse {
  content?: ContentBlock[];
  stop_reason?: string;
  error?: { message?: string };
}

export interface AnalystTool {
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
}
export type ToolExecutor = (name: string, input: Record<string, unknown>) => Promise<string>;

export class Summarizer {
  readonly #cfg: Config;
  readonly #oauth?: ClaudeOAuth;
  readonly #useOauth: boolean;

  constructor(cfg: Config) {
    this.#cfg = cfg;
    const mode = cfg.claude.authMode;
    this.#useOauth = mode === "oauth" || (mode === "auto" && !cfg.claude.apiKey);
    if (this.#useOauth) this.#oauth = new ClaudeOAuth(cfg.claude.credentialsPath);
  }

  /** Validate that the chosen auth path can produce credentials. */
  async preflight(): Promise<void> {
    if (this.#useOauth) {
      await this.#oauth!.getAccessToken();
      log.info("Claude auth: OAuth (Claude Code credentials) ✓");
    } else if (this.#cfg.claude.apiKey) {
      log.info("Claude auth: API key ✓");
    } else {
      throw new Error("No Claude credentials available (set ANTHROPIC_API_KEY or sign in with claude).");
    }
  }

  async #headers(forceRefresh = false): Promise<Record<string, string>> {
    const base: Record<string, string> = {
      "content-type": "application/json",
      "anthropic-version": API_VERSION,
    };
    if (this.#useOauth) {
      const token = await this.#oauth!.getAccessToken(forceRefresh);
      base["authorization"] = `Bearer ${token}`;
      base["anthropic-beta"] = OAUTH_BETA;
    } else {
      base["x-api-key"] = this.#cfg.claude.apiKey!;
    }
    return base;
  }

  #body(ctx: CorrelatedContext): string {
    // OAuth path requires the Claude Code identity as the first system block.
    const system = this.#useOauth
      ? [
          { type: "text", text: CLAUDE_CODE_IDENTITY },
          { type: "text", text: ANALYST_SYSTEM },
        ]
      : [{ type: "text", text: ANALYST_SYSTEM }];

    return JSON.stringify({
      model: this.#cfg.claude.model,
      max_tokens: this.#cfg.claude.maxTokens,
      temperature: 0,
      system,
      messages: [{ role: "user", content: buildUserPrompt(ctx) }],
    });
  }

  async #call(ctx: CorrelatedContext): Promise<string> {
    return this.#post(this.#body(ctx));
  }

  /** Generic completion (used for digests etc.). Returns the model's text. */
  async complete(systemText: string, userText: string, maxTokens = 1500): Promise<string> {
    const system = this.#useOauth
      ? [
          { type: "text", text: CLAUDE_CODE_IDENTITY },
          { type: "text", text: systemText },
        ]
      : [{ type: "text", text: systemText }];
    return this.#post(
      JSON.stringify({
        model: this.#cfg.claude.model,
        max_tokens: maxTokens,
        temperature: 0.3,
        system,
        messages: [{ role: "user", content: userText }],
      }),
    );
  }

  async #post(body: string): Promise<string> {
    const data = await this.#request(body);
    const text = (data.content ?? [])
      .filter((b) => b.type === "text" && b.text)
      .map((b) => b.text)
      .join("")
      .trim();
    if (!text) throw new Error("Claude returned an empty response.");
    return text;
  }

  /** POST a Messages request with auth + retry, returning the parsed response. */
  async #request(body: string): Promise<MessagesResponse> {
    let lastErr: Error | undefined;
    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      const forceRefresh = attempt > 0 && this.#useOauth;
      const res = await fetch(API_URL, {
        method: "POST",
        headers: await this.#headers(forceRefresh),
        body,
      }).catch((err: Error) => {
        lastErr = err;
        return undefined;
      });
      if (!res) {
        await sleep(500 * 2 ** attempt);
        continue;
      }
      if (res.ok) return (await res.json()) as MessagesResponse;

      const bodyText = await res.text().catch(() => "");
      if (res.status === 401 && this.#useOauth && attempt === 0) {
        lastErr = new Error(`401 unauthorized: ${bodyText.slice(0, 200)}`);
        continue;
      }
      if (res.status === 429 || res.status >= 500) {
        lastErr = new Error(`HTTP ${res.status}: ${bodyText.slice(0, 200)}`);
        const retryAfter = Number(res.headers.get("retry-after"));
        await sleep(Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : 500 * 2 ** attempt);
        continue;
      }
      throw new Error(`Claude API error ${res.status}: ${bodyText.slice(0, 300)}`);
    }
    throw lastErr ?? new Error("Claude request failed after retries.");
  }

  /**
   * Agentic tool-use loop: Claude answers `userText` by calling the provided
   * tools (executed by `exec`) until it produces a final text answer.
   *
   * `opts.history` seeds the conversation with prior turns (oldest→newest) so the
   * model can resolve follow-up references. It must start with a `user` message
   * and strictly alternate user/assistant (the conversation store guarantees
   * this); it is prepended ahead of the new `userText` turn.
   *
   * `opts.onFinal` lets the caller validate a would-be final answer before it is
   * returned. It is invoked with the drafted answer and the tools used so far;
   * returning a non-empty string injects that string as a follow-up user message
   * and continues the loop (e.g. to force an action the model *said* it would take
   * but never actually called a tool for). It fires at most `opts.maxNudges` times
   * (default 0 — disabled, preserving the original single-shot behavior) so a model
   * that keeps producing prose can never loop forever.
   */
  async toolLoop(
    systemText: string,
    userText: string,
    tools: AnalystTool[],
    exec: ToolExecutor,
    opts: {
      maxTokens?: number;
      maxRounds?: number;
      onFinal?: (answer: string, toolsUsed: string[]) => string | null | undefined;
      maxNudges?: number;
      history?: Array<{ role: "user" | "assistant"; content: string }>;
    } = {},
  ): Promise<{ answer: string; toolsUsed: string[] }> {
    const system = this.#useOauth
      ? [{ type: "text", text: CLAUDE_CODE_IDENTITY }, { type: "text", text: systemText }]
      : [{ type: "text", text: systemText }];
    const messages: Array<{ role: string; content: unknown }> = [
      ...(opts.history ?? []).map((m) => ({ role: m.role, content: m.content })),
      { role: "user", content: userText },
    ];
    const toolsUsed: string[] = [];
    const maxNudges = opts.maxNudges ?? 0;
    let nudges = 0;

    for (let round = 0; round < (opts.maxRounds ?? 6); round++) {
      const data = await this.#request(
        JSON.stringify({ model: this.#cfg.claude.model, max_tokens: opts.maxTokens ?? 1500, system, tools, messages }),
      );
      const content = data.content ?? [];
      messages.push({ role: "assistant", content });
      const toolUses = content.filter((b) => b.type === "tool_use");
      if (data.stop_reason !== "tool_use" || toolUses.length === 0) {
        const answer = content.filter((b) => b.type === "text").map((b) => b.text).join("").trim();
        if (opts.onFinal && nudges < maxNudges) {
          const nudge = opts.onFinal(answer, toolsUsed);
          if (nudge) {
            nudges++;
            messages.push({ role: "user", content: nudge });
            continue;
          }
        }
        return { answer: answer || "(no answer produced)", toolsUsed };
      }
      const results = [];
      for (const tu of toolUses) {
        toolsUsed.push(tu.name ?? "?");
        let out: string;
        try {
          out = await exec(tu.name ?? "", tu.input ?? {});
        } catch (err) {
          out = `Error: ${(err as Error).message}`;
        }
        results.push({ type: "tool_result", tool_use_id: tu.id, content: out.slice(0, 12000) });
      }
      messages.push({ role: "user", content: results });
    }
    return { answer: "(reached the tool-use limit without a final answer)", toolsUsed };
  }

  /** Run the model and return a structured summary, or a fallback on failure. */
  async summarize(ctx: CorrelatedContext): Promise<AlertSummary> {
    if (!this.#cfg.claude.summarizeEnabled) return fallbackSummary(ctx, "summarization disabled");
    try {
      const text = await this.#call(ctx);
      return parseSummary(text, ctx, this.#cfg.claude.model);
    } catch (err) {
      log.warn(`Claude summarization failed, using fallback: ${(err as Error).message}`);
      return fallbackSummary(ctx, (err as Error).message);
    }
  }
}

function coerceSeverity(value: unknown, fallback: Severity): Severity {
  const s = String(value ?? "").toLowerCase();
  return (SEVERITY_ORDER as readonly string[]).includes(s) ? (s as Severity) : fallback;
}

function parseSummary(text: string, ctx: CorrelatedContext, model: string): AlertSummary {
  // Strip markdown fences and isolate the JSON object if the model added prose.
  let body = text.replace(/^```(?:json)?/i, "").replace(/```$/i, "").trim();
  const start = body.indexOf("{");
  const end = body.lastIndexOf("}");
  if (start !== -1 && end > start) body = body.slice(start, end + 1);

  try {
    const obj = JSON.parse(body) as Record<string, unknown>;
    const actions = Array.isArray(obj["recommendedActions"])
      ? (obj["recommendedActions"] as unknown[]).map((a) => String(a)).filter(Boolean).slice(0, 6)
      : [];
    return {
      title: String(obj["title"] ?? ctx.alert.signature ?? "Security alert").slice(0, 200),
      severity: coerceSeverity(obj["severity"], ctx.alert.severity),
      whatHappened: String(obj["whatHappened"] ?? "").trim() || "No description provided.",
      riskAssessment: String(obj["riskAssessment"] ?? "").trim() || "Risk not assessed.",
      recommendedActions: actions,
      model,
    };
  } catch (err) {
    log.warn(`Could not parse Claude JSON (${(err as Error).message}); using fallback.`);
    return fallbackSummary(ctx, "unparseable model output");
  }
}

/** Deterministic summary used when Claude is disabled or fails. */
export function fallbackSummary(ctx: CorrelatedContext, reason: string): AlertSummary {
  const a = ctx.alert;
  const flow =
    a.srcIp && a.dstIp ? ` from ${a.srcIp}${a.srcPort ? ":" + a.srcPort : ""} to ${a.dstIp}${a.dstPort ? ":" + a.dstPort : ""}` : "";
  return {
    title: (a.signature ?? `${a.category} alert`).slice(0, 90),
    severity: a.severity,
    whatHappened: `${a.category} event${flow}${a.action ? ` (${a.action})` : ""}. ${a.classification ?? ""}`.trim(),
    riskAssessment: `Automated summary unavailable (${reason}). Review the raw alert and related logs below.`,
    recommendedActions:
      a.action === "blocked"
        ? ["Confirm the source/destination are expected.", "No immediate action if the block is appropriate."]
        : ["Investigate the involved hosts.", "Consider blocking the remote IP if malicious."],
    fallback: true,
  };
}
