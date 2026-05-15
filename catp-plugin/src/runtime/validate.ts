import type { RuntimePhase, ToolAction } from "./types.js";

export interface ToolActionValidation {
  ok: boolean;
  errors: string[];
  action?: ToolAction;
}

export function validateToolAction(value: unknown): ToolActionValidation {
  const errors: string[] = [];
  if (!isRecord(value)) {
    return { ok: false, errors: ["event must be an object"] };
  }

  if (!isNonEmptyString(value.runtime)) {
    errors.push("runtime must be a non-empty string");
  }
  if (value.phase !== "pre" && value.phase !== "post") {
    errors.push('phase must be "pre" or "post"');
  }
  if (!isNonEmptyString(value.toolName)) {
    errors.push("toolName must be a non-empty string");
  }
  if (!isRecord(value.toolInput)) {
    errors.push("toolInput must be an object");
  }
  if (value.sessionId !== undefined && typeof value.sessionId !== "string") {
    errors.push("sessionId must be a string when present");
  }

  if (errors.length > 0) {
    return { ok: false, errors };
  }

  return {
    ok: true,
    errors: [],
    action: {
      runtime: value.runtime as string,
      phase: value.phase as RuntimePhase,
      sessionId: value.sessionId as string | undefined,
      toolName: value.toolName as string,
      toolInput: value.toolInput as Record<string, unknown>,
      raw: value.raw,
    },
  };
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
