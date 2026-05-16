import { describe, expect, it } from "@jest/globals";
import { claudeCodeAdapter } from "../../src/adapters/claude-code.js";
import { parseHookAction } from "../../src/hook/runtime.js";

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
