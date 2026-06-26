/**
 * In-memory conversational memory for the "Ask" analyst (analyst.ts) and the
 * action-capable automation agent (agent.ts).
 *
 * Both features previously treated every request as a cold start: the Claude
 * tool-loop was seeded with only the latest question, so follow-ups that refer
 * back ("block that IP", "what about the second one", "now suppress it") lost
 * all context. This store gives each browser chat session a rolling window of
 * the most recent turns so the model can resolve those references.
 *
 * Design notes:
 *   - A "message" is one role-tagged turn (a user question or an assistant
 *     answer). Messages are recorded in user→assistant pairs, so the window
 *     always alternates correctly and the Claude Messages API contract (start
 *     with a user message, strict alternation) is preserved.
 *   - History is deliberately EPHEMERAL — never persisted to disk. Chat content
 *     can contain sensitive operator questions; it is working context, not
 *     durable state. It is evicted after an idle TTL and bounded by a
 *     max-session cap so memory cannot grow without bound.
 *   - The window size and idle TTL are operator-configurable (see the
 *     `conversation` config block); a hard MAX_SESSIONS cap protects the
 *     process regardless of configuration.
 */

/** A single role-tagged conversational turn (plain text — no tool blocks). */
export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

/** Per-call window parameters, derived from `cfg.conversation`. */
export interface MemoryWindow {
  /** Maximum number of messages (user + assistant turns) to retain. */
  maxMessages: number;
  /** Idle expiry: a session untouched for longer than this is treated as empty. */
  ttlMs: number;
}

interface Session {
  messages: ChatMessage[];
  updatedAt: number;
}

/** Hard upper bound on concurrent sessions, independent of config. */
const MAX_SESSIONS = 500;
/** Trim individual stored messages so one giant answer can't bloat memory. */
const MAX_MESSAGE_CHARS = 8000;

class ConversationStore {
  #sessions = new Map<string, Session>();

  /**
   * Return the retained window for a session, oldest→newest, as a fresh array
   * safe for the caller to mutate. Honours the configured size and idle TTL: an
   * expired session yields an empty window. The returned window is guaranteed to
   * start with a `user` message (a leading orphan `assistant` is dropped) so it
   * can be prepended directly to a new user turn without violating the API's
   * alternation contract.
   */
  history(sessionId: string | undefined | null, win: MemoryWindow): ChatMessage[] {
    if (!sessionId) return [];
    const s = this.#sessions.get(sessionId);
    if (!s) return [];
    if (this.#expired(s, win.ttlMs)) {
      this.#sessions.delete(sessionId);
      return [];
    }
    let window = s.messages.slice(-Math.max(0, win.maxMessages));
    if (window.length && window[0]!.role !== "user") window = window.slice(1);
    return window.map((m) => ({ role: m.role, content: m.content }));
  }

  /**
   * Append a completed exchange (the user's question and the assistant's final
   * answer) to a session, then trim to the configured window. Empty inputs are
   * ignored. Recording touches the session's last-used time and triggers
   * lightweight eviction of stale/excess sessions.
   */
  record(sessionId: string | undefined | null, userText: string, assistantText: string, win: MemoryWindow): void {
    if (!sessionId) return;
    const user = userText.trim();
    const assistant = assistantText.trim();
    if (!user || !assistant) return;

    const now = Date.now();
    let s = this.#sessions.get(sessionId);
    if (!s || this.#expired(s, win.ttlMs)) s = { messages: [], updatedAt: now };

    s.messages.push({ role: "user", content: user.slice(0, MAX_MESSAGE_CHARS) });
    s.messages.push({ role: "assistant", content: assistant.slice(0, MAX_MESSAGE_CHARS) });
    // Keep an even, user-leading window. maxMessages may be odd, in which case
    // we round down to the nearest pair so the window never starts mid-exchange.
    const keep = Math.max(0, Math.floor(win.maxMessages / 2) * 2);
    if (keep === 0) s.messages = [];
    else if (s.messages.length > keep) s.messages = s.messages.slice(-keep);
    s.updatedAt = now;

    this.#sessions.set(sessionId, s);
    this.#evict(win.ttlMs);
  }

  /** Forget a session (e.g. the user starts a new chat). Returns whether one existed. */
  clear(sessionId: string | undefined | null): boolean {
    if (!sessionId) return false;
    return this.#sessions.delete(sessionId);
  }

  /** Number of live (non-expired) sessions — used by diagnostics/tests. */
  count(): number {
    return this.#sessions.size;
  }

  #expired(s: Session, ttlMs: number): boolean {
    return ttlMs > 0 && Date.now() - s.updatedAt > ttlMs;
  }

  /** Drop idle sessions, then evict the oldest until under the hard cap. */
  #evict(ttlMs: number): void {
    if (ttlMs > 0) {
      const now = Date.now();
      for (const [id, s] of this.#sessions) {
        if (now - s.updatedAt > ttlMs) this.#sessions.delete(id);
      }
    }
    if (this.#sessions.size <= MAX_SESSIONS) return;
    const ordered = [...this.#sessions.entries()].sort((a, b) => a[1].updatedAt - b[1].updatedAt);
    for (const [id] of ordered) {
      if (this.#sessions.size <= MAX_SESSIONS) break;
      this.#sessions.delete(id);
    }
  }
}

export const conversationStore = new ConversationStore();
