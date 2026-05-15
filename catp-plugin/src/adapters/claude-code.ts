import type { RuntimeAdapter, RuntimePhase, ToolAction } from "../runtime/types.js";

interface ClaudeCodeHookInput {
  session_id?: string;
  tool_name: string;
  tool_input: Record<string, unknown>;
}

export const claudeCodeAdapter: RuntimeAdapter = {
  runtime: "claude-code",
  fromPreToolUse(input: unknown): ToolAction | null {
    return toToolAction(input, "pre");
  },
  fromPostToolUse(input: unknown): ToolAction | null {
    return toToolAction(input, "post");
  },
};

function toToolAction(input: unknown, phase: RuntimePhase): ToolAction | null {
  if (!isClaudeCodeHookInput(input)) {
    return null;
  }

  return {
    runtime: claudeCodeAdapter.runtime,
    phase,
    sessionId: input.session_id,
    toolName: input.tool_name,
    toolInput: input.tool_input,
    raw: input,
  };
}

function isClaudeCodeHookInput(input: unknown): input is ClaudeCodeHookInput {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return false;
  }
  const value = input as Record<string, unknown>;
  return (
    typeof value.tool_name === "string" &&
    !!value.tool_name &&
    isRecord(value.tool_input) &&
    (value.session_id === undefined || typeof value.session_id === "string")
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
