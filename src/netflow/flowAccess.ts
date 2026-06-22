/**
 * Process-wide handle to the active FlowStore, so investigation code can query
 * collected flows without threading the collector through every call site.
 */
import type { FlowStore } from "./flowStore.ts";

let active: FlowStore | null = null;

export function setActiveFlowStore(store: FlowStore | null): void {
  active = store;
}

export function getActiveFlowStore(): FlowStore | null {
  return active;
}
