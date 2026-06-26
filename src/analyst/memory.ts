/**
 * Shared conversational-memory plumbing for the read-only analyst (analyst.ts)
 * and the action agent (agent.ts). Both load prior turns before a request and
 * record the completed exchange after, using the same configured window.
 */
import type { Config } from "../config.ts";
import { conversationStore, type ChatMessage, type MemoryWindow } from "../store/conversation.ts";

/** Per-request memory options threaded through the HTTP layer. */
export interface MemoryOpts {
  /** Opaque chat-session id (one per browser chat). Absent → memory disabled for this call. */
  sessionId?: string;
}

/** Derive the active memory window from config, or null when memory is off. */
export function memoryWindow(cfg: Config): MemoryWindow | null {
  const c = cfg.conversation;
  if (!c.memoryEnabled || c.memoryMaxMessages <= 0) return null;
  return { maxMessages: c.memoryMaxMessages, ttlMs: c.memoryTtlMin * 60_000 };
}

/** Fetch the prior-turn history for a session, or [] when memory is disabled. */
export function loadHistory(cfg: Config, sessionId: string | undefined): ChatMessage[] {
  const win = memoryWindow(cfg);
  if (!win || !sessionId) return [];
  return conversationStore.history(sessionId, win);
}

/** Persist a completed exchange to the session window (no-op when disabled). */
export function recordExchange(cfg: Config, sessionId: string | undefined, question: string, answer: string): void {
  const win = memoryWindow(cfg);
  if (!win || !sessionId) return;
  conversationStore.record(sessionId, question, answer, win);
}
