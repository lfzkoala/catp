import { claudeCodeAdapter } from "./claude-code.js";
import type { RuntimeAdapter, RuntimePhase, ToolAction } from "../runtime/types.js";

const adapters: RuntimeAdapter[] = [claudeCodeAdapter];

export function listRuntimeAdapters(): string[] {
  return adapters.map((adapter) => adapter.runtime);
}

export function getRuntimeAdapter(name: string): RuntimeAdapter | null {
  return adapters.find((adapter) => adapter.runtime === name) ?? null;
}

export function adaptRuntimePayload(
  adapterName: string,
  phase: RuntimePhase,
  payload: unknown
): ToolAction | null {
  const adapter = getRuntimeAdapter(adapterName);
  if (!adapter) {
    return null;
  }
  return phase === "post"
    ? adapter.fromPostToolUse(payload)
    : adapter.fromPreToolUse(payload);
}
