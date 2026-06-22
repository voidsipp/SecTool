/**
 * Reads and refreshes the Claude Code OAuth credentials that the `claude` CLI
 * stores at ~/.claude/.credentials.json, so SecTool can call the Messages API
 * using the user's existing subscription instead of a billed API key.
 *
 * The access token is short-lived; when it is expired (or about to be) we use
 * the refresh token against Anthropic's OAuth endpoint and write the rotated
 * credentials back atomically — mirroring what the CLI does itself.
 */
import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { log } from "../logger.ts";

// Public OAuth client id used by Claude Code.
const CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const TOKEN_URL = "https://console.anthropic.com/v1/oauth/token";
// Refresh a bit early to avoid races against the token's true expiry.
const EXPIRY_SKEW_MS = 60_000;

interface OauthBlock {
  accessToken: string;
  refreshToken: string;
  expiresAt: number; // ms epoch
  [k: string]: unknown;
}

interface CredentialsFile {
  claudeAiOauth?: OauthBlock;
  [k: string]: unknown;
}

export class OAuthError extends Error {}

export class ClaudeOAuth {
  readonly #path: string;
  #cached?: OauthBlock;

  constructor(credentialsPath: string) {
    this.#path = credentialsPath;
  }

  #read(): OauthBlock {
    let parsed: CredentialsFile;
    try {
      parsed = JSON.parse(readFileSync(this.#path, "utf8")) as CredentialsFile;
    } catch (err) {
      throw new OAuthError(
        `Could not read Claude credentials at ${this.#path}: ${(err as Error).message}. ` +
          `Run "claude" once to sign in, or switch CLAUDE_AUTH_MODE to apikey.`,
      );
    }
    const block = parsed.claudeAiOauth;
    if (!block?.accessToken || !block?.refreshToken) {
      throw new OAuthError(
        `Claude credentials at ${this.#path} are missing OAuth tokens. Sign in with "claude".`,
      );
    }
    return block;
  }

  #write(block: OauthBlock): void {
    let current: CredentialsFile = {};
    try {
      current = JSON.parse(readFileSync(this.#path, "utf8")) as CredentialsFile;
    } catch {
      /* file will be (re)created */
    }
    current.claudeAiOauth = { ...current.claudeAiOauth, ...block };
    const tmp = `${this.#path}.tmp-${process.pid}`;
    writeFileSync(tmp, JSON.stringify(current, null, 2), { mode: 0o600 });
    renameSync(tmp, this.#path);
  }

  async #refresh(block: OauthBlock): Promise<OauthBlock> {
    log.info("Refreshing Claude OAuth access token…");
    const res = await fetch(TOKEN_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        grant_type: "refresh_token",
        refresh_token: block.refreshToken,
        client_id: CLIENT_ID,
      }),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new OAuthError(
        `OAuth token refresh failed (${res.status}). Re-authenticate with "claude". ${body.slice(0, 300)}`,
      );
    }
    const data = (await res.json()) as {
      access_token: string;
      refresh_token?: string;
      expires_in?: number;
    };
    const updated: OauthBlock = {
      ...block,
      accessToken: data.access_token,
      refreshToken: data.refresh_token ?? block.refreshToken,
      expiresAt: Date.now() + (data.expires_in ?? 3600) * 1000,
    };
    this.#write(updated);
    return updated;
  }

  /** Returns a valid access token, refreshing transparently when needed. */
  async getAccessToken(forceRefresh = false): Promise<string> {
    let block = this.#cached ?? this.#read();
    if (forceRefresh || Date.now() >= block.expiresAt - EXPIRY_SKEW_MS) {
      block = await this.#refresh(block);
    }
    this.#cached = block;
    return block.accessToken;
  }
}
