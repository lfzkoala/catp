import type { RuntimeAdapter, RuntimePhase, ToolAction } from "../runtime/types.js";

export function parseHookAction(
  raw: string,
  adapter: RuntimeAdapter,
  phase: RuntimePhase,
): ToolAction | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }

  return phase === "pre"
    ? adapter.fromPreToolUse(parsed)
    : adapter.fromPostToolUse(parsed);
}

export async function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => { data += chunk; });
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", () => resolve(""));
  });
}
