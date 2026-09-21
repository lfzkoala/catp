import { describe, expect, it } from "@jest/globals";
import { PassThrough } from "node:stream";
import { claudeCodeAdapter } from "../../src/adapters/claude-code.js";
import { parseHookAction, readStream } from "../../src/hook/runtime.js";

describe("parseHookAction", () => {
  it("parses pre hook JSON through the selected runtime adapter", () => {
    const action = parseHookAction(
      JSON.stringify({
        session_id: "session-1",
        tool_name: "Bash",
        tool_input: { command: "ls" },
      }),
      claudeCodeAdapter,
      "pre",
    );

    expect(action).toMatchObject({
      runtime: "claude-code",
      phase: "pre",
      sessionId: "session-1",
      toolName: "Bash",
      toolInput: { command: "ls" },
    });
  });

  it("parses post hook JSON through the selected runtime adapter", () => {
    const action = parseHookAction(
      JSON.stringify({
        tool_name: "Write",
        tool_input: { file_path: "README.md" },
      }),
      claudeCodeAdapter,
      "post",
    );

    expect(action).toMatchObject({
      runtime: "claude-code",
      phase: "post",
      toolName: "Write",
      toolInput: { file_path: "README.md" },
    });
  });

  it("returns null for malformed JSON or invalid adapter payloads", () => {
    expect(parseHookAction("{", claudeCodeAdapter, "pre")).toBeNull();
    expect(parseHookAction(JSON.stringify({ tool_name: "Bash" }), claudeCodeAdapter, "pre")).toBeNull();
  });
});

describe("readStream", () => {
  it("resolves the full payload when the stream ends within limits", async () => {
    const stream = new PassThrough();
    const pending = readStream(stream, { maxBytes: 64, deadlineMs: 1000 });
    stream.write('{"a":');
    stream.write("1}");
    stream.end();

    await expect(pending).resolves.toBe('{"a":1}');
  });

  it("rejects when the payload exceeds the byte cap", async () => {
    const stream = new PassThrough();
    const pending = readStream(stream, { maxBytes: 8, deadlineMs: 1000 });
    stream.write("x".repeat(64));
    stream.end();

    await expect(pending).rejects.toThrow("hook stdin exceeded 8 byte limit");
  });

  it("rejects when the stream never ends before the deadline", async () => {
    const stream = new PassThrough();
    const pending = readStream(stream, { maxBytes: 64, deadlineMs: 20 });
    stream.write("partial");

    await expect(pending).rejects.toThrow("hook stdin deadline exceeded");
  });
});
