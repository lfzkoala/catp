import { afterEach, describe, expect, it } from "@jest/globals";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { evaluatePreHookInput } from "../../src/hook/pre.js";

const ROOT = join(tmpdir(), `catp-pre-hook-test-${Date.now()}`);
const ORIGINAL_CATP_HOME = process.env.CATP_HOME;

function writePolicy(dir: string, contents = `
[agent]
id = "pre-hook-agent"
version = "1"

[[rules]]
tool = "Bash"
allow = true
`): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "catp-policy.toml"), contents, "utf8");
}

function hookInput(): string {
  return JSON.stringify({
    session_id: "session",
    tool_name: "Bash",
    tool_input: { command: "echo ok" },
  });
}

describe("evaluatePreHookInput", () => {
  afterEach(() => {
    if (existsSync(ROOT)) rmSync(ROOT, { recursive: true, force: true });
    if (ORIGINAL_CATP_HOME === undefined) delete process.env.CATP_HOME;
    else process.env.CATP_HOME = ORIGINAL_CATP_HOME;
  });

  it("allows when CATP is not enabled in the project", () => {
    mkdirSync(ROOT, { recursive: true });
    expect(evaluatePreHookInput("not-json", { startDir: ROOT })).toMatchObject({
      exitCode: 0,
      policyFound: false,
    });
  });

  it("blocks malformed hook input when a policy exists", () => {
    writePolicy(ROOT);
    expect(evaluatePreHookInput("not-json", { startDir: ROOT })).toMatchObject({
      exitCode: 2,
      policyFound: true,
      reason: "invalid pre-hook input",
    });
  });

  it("blocks when the discovered policy is invalid", () => {
    writePolicy(ROOT, "[agent]\nid = \"broken\"\n");
    const result = evaluatePreHookInput(hookInput(), { startDir: ROOT });
    expect(result.exitCode).toBe(2);
    expect(result.reason).toContain("policy error");
  });

  it("blocks when the audit entry cannot be written", () => {
    writePolicy(ROOT);
    const invalidHome = join(ROOT, "not-a-directory");
    writeFileSync(invalidHome, "file", "utf8");
    process.env.CATP_HOME = invalidHome;

    const result = evaluatePreHookInput(hookInput(), { startDir: ROOT });

    expect(result.exitCode).toBe(2);
    expect(result.reason).toContain("audit error");
  });

  it("allows and records a valid policy decision", () => {
    writePolicy(ROOT);
    process.env.CATP_HOME = join(ROOT, ".catp-home");

    const result = evaluatePreHookInput(hookInput(), { startDir: ROOT });

    expect(result).toMatchObject({ exitCode: 0, policyFound: true, auditRecorded: true });
  });
});
