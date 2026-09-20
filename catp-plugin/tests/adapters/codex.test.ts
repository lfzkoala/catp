import { afterEach, describe, expect, it } from "@jest/globals";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { codexAdapter } from "../../src/adapters/codex.js";
import { auditDir } from "../../src/audit/logger.js";
import { verifyChain } from "../../src/audit/verifier.js";
import { evaluatePreHookInput } from "../../src/hook/pre.js";

describe("codexAdapter", () => {
  it("maps PreToolUse payloads into runtime-neutral tool actions", () => {
    const action = codexAdapter.fromPreToolUse({
      hook_event_name: "PreToolUse",
      session_id: "session-1",
      tool_name: "shell",
      tool_input: { command: "git status" },
      cwd: "/repo",
      model: "gpt-5.5",
      permission_mode: "default",
      tool_use_id: "call-1",
      transcript_path: null,
      turn_id: "turn-1",
    });

    expect(action).toMatchObject({
      runtime: "codex",
      phase: "pre",
      sessionId: "session-1",
      toolName: "shell",
      toolInput: { command: "git status" },
    });
    expect(action?.raw).toMatchObject({ tool_use_id: "call-1", turn_id: "turn-1" });
  });

  it("normalizes argv-array commands into a single string", () => {
    const action = codexAdapter.fromPreToolUse({
      tool_name: "exec_command",
      tool_input: { command: ["git", "push", "origin main"] },
    });

    expect(action?.toolInput).toEqual({ command: "git push origin main" });
  });

  it("keeps non-string argv commands untouched", () => {
    const action = codexAdapter.fromPreToolUse({
      tool_name: "exec_command",
      tool_input: { command: ["git", 42] },
    });

    expect(action?.toolInput).toEqual({ command: ["git", 42] });
  });

  it("maps PostToolUse payloads with post phase", () => {
    const action = codexAdapter.fromPostToolUse({
      hook_event_name: "PostToolUse",
      tool_name: "apply_patch",
      tool_input: { input: "*** Begin Patch" },
    });

    expect(action?.runtime).toBe("codex");
    expect(action?.phase).toBe("post");
    expect(action?.toolName).toBe("apply_patch");
  });

  it("accepts payloads without hook_event_name for older builds", () => {
    const action = codexAdapter.fromPreToolUse({
      tool_name: "shell",
      tool_input: { command: "ls" },
    });

    expect(action?.phase).toBe("pre");
  });

  it("rejects malformed hook payloads", () => {
    expect(codexAdapter.fromPreToolUse(null)).toBeNull();
    expect(codexAdapter.fromPreToolUse("not-json")).toBeNull();
    expect(codexAdapter.fromPreToolUse({ tool_name: "shell" })).toBeNull();
    expect(codexAdapter.fromPreToolUse({ tool_name: "", tool_input: {} })).toBeNull();
    expect(codexAdapter.fromPreToolUse({ tool_name: "shell", tool_input: [] })).toBeNull();
    expect(codexAdapter.fromPreToolUse({ tool_name: "shell", tool_input: {}, session_id: 7 })).toBeNull();
  });

  it("rejects payloads whose hook_event_name does not match the phase", () => {
    expect(
      codexAdapter.fromPreToolUse({ hook_event_name: "PostToolUse", tool_name: "shell", tool_input: {} })
    ).toBeNull();
    expect(
      codexAdapter.fromPostToolUse({ hook_event_name: "PreToolUse", tool_name: "shell", tool_input: {} })
    ).toBeNull();
  });
});

const ROOT = join(tmpdir(), `catp-codex-hook-test-${Date.now()}`);
const ORIGINAL_CATP_HOME = process.env.CATP_HOME;

const CODEX_POLICY = `
[agent]
id = "codex-agent"
version = "1"

[[rules]]
tool = "shell"
allow = false
pattern = ["rm -rf"]
reason = "destructive commands are blocked"

[[rules]]
tool = "shell"
allow = true
`;

function codexHookInput(command: string[]): string {
  return JSON.stringify({
    hook_event_name: "PreToolUse",
    session_id: "session",
    tool_name: "shell",
    tool_input: { command },
    cwd: ROOT,
    model: "gpt-5.5",
    permission_mode: "default",
    tool_use_id: "call-1",
    transcript_path: null,
    turn_id: "turn-1",
  });
}

describe("codex pre-hook enforcement", () => {
  afterEach(() => {
    if (existsSync(ROOT)) rmSync(ROOT, { recursive: true, force: true });
    if (ORIGINAL_CATP_HOME === undefined) delete process.env.CATP_HOME;
    else process.env.CATP_HOME = ORIGINAL_CATP_HOME;
  });

  function setup(): void {
    mkdirSync(ROOT, { recursive: true });
    writeFileSync(join(ROOT, "catp-policy.toml"), CODEX_POLICY, "utf8");
    process.env.CATP_HOME = join(ROOT, ".catp");
  }

  it("blocks a denied argv command after normalizing it to a string", () => {
    setup();
    const result = evaluatePreHookInput(codexHookInput(["rm", "-rf", "/tmp/x"]), {
      adapter: codexAdapter,
      startDir: ROOT,
    });

    expect(result).toMatchObject({
      exitCode: 2,
      policyFound: true,
      auditRecorded: true,
      reason: "destructive commands are blocked",
    });
  });

  it("allows a permitted argv command and keeps the audit chain verifiable", async () => {
    setup();
    const result = evaluatePreHookInput(codexHookInput(["git", "status"]), {
      adapter: codexAdapter,
      startDir: ROOT,
    });

    expect(result).toMatchObject({ exitCode: 0, auditRecorded: true });

    const logFile = join(auditDir("codex-agent"), "actions.jsonl");
    expect(existsSync(logFile)).toBe(true);
    const verification = await verifyChain(logFile);
    expect(verification).toMatchObject({ ok: true, checked: 1, broken_at: null });
  });
});
