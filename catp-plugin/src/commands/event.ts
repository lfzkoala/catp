import { readFileSync } from "node:fs";
import { adaptRuntimePayload, listRuntimeAdapters } from "../adapters/registry.js";
import type { RuntimePhase, ToolAction } from "../runtime/types.js";
import { validateToolAction } from "../runtime/validate.js";

interface ValidateEventOptions {
  file?: string;
  adapter?: string;
  phase?: string;
}

interface EventValidationResult {
  ok: boolean;
  errors: string[];
  action?: ToolAction;
}

export async function cmdValidateEvent(opts: ValidateEventOptions): Promise<void> {
  let parsed: unknown;
  try {
    const raw = opts.file ? readFileSync(opts.file, "utf8") : await readStdin();
    parsed = JSON.parse(raw);
  } catch (err) {
    process.stderr.write(`catp: invalid event JSON: ${(err as Error).message}\n`);
    process.exit(1);
  }

  const result = validateEventPayload(parsed, opts);
  if (!result.ok) {
    process.stderr.write(formatEventValidationSummary(result));
    process.exit(1);
  }

  process.stdout.write(formatEventValidationSummary(result));
}

export function cmdListAdapters(): void {
  process.stdout.write(`${listRuntimeAdapters().join("\n")}\n`);
}

export function validateEventPayload(
  payload: unknown,
  opts: Pick<ValidateEventOptions, "adapter" | "phase"> = {}
): EventValidationResult {
  const action = adaptPayload(payload, opts);
  if (!action) {
    return {
      ok: false,
      errors: [`unsupported or invalid adapter payload: ${opts.adapter ?? "none"}`],
    };
  }
  return validateToolAction(action);
}

export function formatEventValidationSummary(result: EventValidationResult): string {
  if (!result.ok) {
    return `✗ event invalid\n${result.errors.map((e) => `  ${e}`).join("\n")}\n`;
  }
  const action = result.action;
  return [
    "✓ event valid",
    `  runtime: ${action?.runtime}`,
    `  phase: ${action?.phase}`,
    `  tool: ${action?.toolName}`,
    `  inputKeys: ${Object.keys(action?.toolInput ?? {}).length}`,
  ].join("\n") + "\n";
}

function adaptPayload(
  payload: unknown,
  opts: Pick<ValidateEventOptions, "adapter" | "phase">
): ToolAction | null {
  if (!opts.adapter) {
    return validateToolAction(payload).action ?? null;
  }

  if (opts.adapter !== "claude-code") {
    return null;
  }

  const phase = parsePhase(opts.phase);
  return adaptRuntimePayload(opts.adapter, phase, payload);
}

function parsePhase(value: string | undefined): RuntimePhase {
  return value === "post" ? "post" : "pre";
}

async function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => { data += chunk; });
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", () => resolve(""));
  });
}
