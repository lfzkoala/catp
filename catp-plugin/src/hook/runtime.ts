import type { RuntimeAdapter, RuntimePhase, ToolAction } from "../runtime/types.js";

// Hook payloads are small tool-event JSON documents. Cap and deadline keep a
// hostile or stuck runtime pipe from exhausting enforcement-process memory or
// hanging the hook; violations reject, and the CLI fail-closed path blocks.
export const HOOK_STDIN_MAX_BYTES = 1024 * 1024;
export const HOOK_STDIN_DEADLINE_MS = 10_000;

export interface ReadStreamOptions {
  maxBytes?: number;
  deadlineMs?: number;
}

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

export async function readStdin(opts: ReadStreamOptions = {}): Promise<string> {
  return readStream(process.stdin, opts);
}

export function readStream(
  stream: NodeJS.ReadableStream,
  opts: ReadStreamOptions = {},
): Promise<string> {
  const maxBytes = opts.maxBytes ?? HOOK_STDIN_MAX_BYTES;
  const deadlineMs = opts.deadlineMs ?? HOOK_STDIN_DEADLINE_MS;

  return new Promise((resolve, reject) => {
    let data = "";
    let bytes = 0;
    let settled = false;

    const timer = setTimeout(() => {
      finish(() => reject(new Error(`hook stdin deadline exceeded (${deadlineMs}ms)`)));
    }, deadlineMs);

    function finish(settle: () => void): void {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      stream.removeListener("data", onData);
      stream.removeListener("end", onEnd);
      stream.removeListener("error", onError);
      if (typeof (stream as NodeJS.ReadStream).destroy === "function") {
        (stream as NodeJS.ReadStream).destroy();
      }
      settle();
    }

    function onData(chunk: string | Buffer): void {
      const text = typeof chunk === "string" ? chunk : chunk.toString("utf8");
      bytes += Buffer.byteLength(text, "utf8");
      if (bytes > maxBytes) {
        finish(() => reject(new Error(`hook stdin exceeded ${maxBytes} byte limit`)));
        return;
      }
      data += text;
    }

    function onEnd(): void {
      finish(() => resolve(data));
    }

    function onError(): void {
      finish(() => resolve(""));
    }

    stream.on("data", onData);
    stream.on("end", onEnd);
    stream.on("error", onError);
  });
}
