import type { RuntimeAdapter, RuntimePhase, ToolAction } from "../runtime/types.js";

interface CodexHookInput {
  hook_event_name?: string;
  session_id?: string;
  tool_name: string;
  tool_input: Record<string, unknown>;
}

const EVENT_BY_PHASE: Record<RuntimePhase, string> = {
  pre: "PreToolUse",
  post: "PostToolUse",
};

export const codexAdapter: RuntimeAdapter = {
  runtime: "codex",
  fromPreToolUse(input: unknown): ToolAction | null {
    return toToolAction(input, "pre");
  },
  fromPostToolUse(input: unknown): ToolAction | null {
    return toToolAction(input, "post");
  },
};

function toToolAction(input: unknown, phase: RuntimePhase): ToolAction | null {
  if (!isCodexHookInput(input, phase)) {
    return null;
  }

  return {
    runtime: codexAdapter.runtime,
    phase,
    sessionId: input.session_id,
    toolName: input.tool_name,
    toolInput: normalizeToolInput(input.tool_input),
    raw: input,
  };
}

// Validation mirrors the claude-code adapter: only the fields CATP core logic
// depends on are required, so payloads from older Codex builds that predate
// newer schema fields (model, turn_id, ...) still parse.
function isCodexHookInput(input: unknown, phase: RuntimePhase): input is CodexHookInput {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return false;
  }
  const value = input as Record<string, unknown>;
  if (value.hook_event_name !== undefined && value.hook_event_name !== EVENT_BY_PHASE[phase]) {
    return false;
  }
  return (
    typeof value.tool_name === "string" &&
    !!value.tool_name &&
    isRecord(value.tool_input) &&
    (value.session_id === undefined || typeof value.session_id === "string")
  );
}

// Codex shell-family tools may pass `command` as an argv array. Join it into a
// single string so policy pattern matching sees the same command shape as on
// other runtimes. Non-string argv elements are left untouched.
function normalizeToolInput(toolInput: Record<string, unknown>): Record<string, unknown> {
  const command = toolInput.command;
  if (!Array.isArray(command) || command.some((part) => typeof part !== "string")) {
    return toolInput;
  }
  return { ...toolInput, command: command.join(" ") };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
