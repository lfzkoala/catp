export type RuntimePhase = "pre" | "post";

/**
 * Runtime-neutral action shape consumed by CATP policy evaluation, audit
 * logging, and optional authorization extraction.
 *
 * Runtime adapters should preserve the original payload in `raw`, but CATP core
 * logic must only depend on the normalized fields below.
 */
export interface ToolAction {
  /** Stable runtime id, for example "claude-code" or a future agent runtime. */
  runtime: string;
  /** Whether the event is before tool execution or after tool execution. */
  phase: RuntimePhase;
  /** Runtime session/conversation id when the upstream runtime provides one. */
  sessionId?: string;
  /** Runtime tool name normalized to CATP's policy rule surface. */
  toolName: string;
  /** Structured tool input used by policy rules and authorization extraction. */
  toolInput: Record<string, unknown>;
  /** Original runtime payload, kept for debugging and adapter evolution. */
  raw?: unknown;
}

/**
 * Minimal adapter contract for adding a new agent runtime.
 *
 * Adapters own runtime-specific parsing and validation. Returning null means the
 * payload is not a valid event for that runtime and should be ignored by the
 * hook boundary rather than passed into the core policy engine.
 */
export interface RuntimeAdapter {
  runtime: string;
  fromPreToolUse(input: unknown): ToolAction | null;
  fromPostToolUse(input: unknown): ToolAction | null;
}
