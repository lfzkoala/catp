export type RuntimePhase = "pre" | "post";

export interface ToolAction {
  runtime: string;
  phase: RuntimePhase;
  sessionId?: string;
  toolName: string;
  toolInput: Record<string, unknown>;
  raw?: unknown;
}

export interface RuntimeAdapter {
  runtime: string;
  fromPreToolUse(input: unknown): ToolAction | null;
  fromPostToolUse(input: unknown): ToolAction | null;
}
