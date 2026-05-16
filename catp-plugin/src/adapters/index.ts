import { claudeCodeAdapter } from "./claude-code.js";
import type { RuntimeAdapter } from "../runtime/types.js";

const ADAPTERS = [claudeCodeAdapter] as const;

export function getRuntimeAdapter(runtime: string): RuntimeAdapter | null {
  return ADAPTERS.find((adapter) => adapter.runtime === runtime) ?? null;
}

export function supportedRuntimeAdapters(): string[] {
  return ADAPTERS.map((adapter) => adapter.runtime);
}

export function formatSupportedRuntimeAdapters(): string {
  return [
    "Supported runtime adapters:",
    ...supportedRuntimeAdapters().map((runtime) => `- ${runtime}`),
  ].join("\n") + "\n";
}
