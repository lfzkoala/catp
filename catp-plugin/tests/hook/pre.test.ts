import { afterEach, describe, expect, it } from "@jest/globals";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { evaluatePreHookInput, preHookBlockOutput } from "../../src/hook/pre.js";
import { actionSidecarPath, auditRoot } from "../../src/audit/paths.js";
import { computeActionCommitment } from "../../src/evidence/commitments.js";
import { nodeAuditStorage, type AuditStorage } from "../../src/audit/durable.js";
import { verifyChain } from "../../src/audit/verifier.js";
import type { AuditEntryV4 } from "../../src/policy/types.js";

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

// nodeAuditStorage with exactly one method forced to throw, so a test can
// simulate a sidecar-fsync or log-fsync failure while the rest of the durable
// path (including the empty-file creation the lock needs) still works.
function failingStorage(method: keyof AuditStorage, message: string): AuditStorage {
  return {
    ...nodeAuditStorage,
    [method]: () => {
      throw new Error(message);
    },
  } as AuditStorage;
}

// Locate the daily audit directory from the filesystem rather than re-deriving
// it from the current time, so these helpers cannot flake across a UTC midnight
// boundary between the logger's date and a test's own clock read.
function latestAuditDate(agentId: string): string {
  const dates = readdirSync(auditRoot(agentId)).sort();
  return dates[dates.length - 1];
}

function readLastEntry(agentId: string): AuditEntryV4 {
  const dir = join(auditRoot(agentId), latestAuditDate(agentId));
  const lines = readFileSync(join(dir, "actions.jsonl"), "utf8").trim().split("\n");
  return JSON.parse(lines[lines.length - 1]) as AuditEntryV4;
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

  // CLI-level fail-closed case: exercise the REAL durable storage backend
  // (nodeAuditStorage, no injected mock) against a structurally invalid
  // CATP_HOME, and assert the exact contract `runPreHook` enforces for the CLI:
  // exit code 2, a block (never allow) response on both streams, and no action
  // durably recorded. An otherwise-allowable action must NOT slip through when
  // its evidence cannot be persisted.
  it("fails closed at the CLI when CATP_HOME is structurally invalid", () => {
    writePolicy(ROOT);
    const invalidHome = join(ROOT, "cli-invalid-home");
    writeFileSync(invalidHome, "a regular file, not a CATP_HOME directory\n", "utf8");
    process.env.CATP_HOME = invalidHome;

    const outcome = evaluatePreHookInput(hookInput(), { startDir: ROOT });

    // runPreHook maps exitCode 2 to process.exit(2) plus a block on both streams.
    expect(outcome.exitCode).toBe(2);
    expect(outcome.auditRecorded).toBe(false);
    expect(outcome.reason).toContain("audit error");

    const block = preHookBlockOutput(outcome.reason);
    const parsed = JSON.parse(block.stdout) as { decision: string };
    expect(parsed.decision).toBe("block");
    expect(parsed.decision).not.toBe("allow");
    expect(block.stderr.trim().length).toBeGreaterThan(0);

    // The fail-closed guarantee must not be a silent fallback: the structurally
    // invalid CATP_HOME stays an unchanged regular file, so the hook never
    // recreated it as a directory in order to record evidence.
    expect(statSync(invalidHome).isFile()).toBe(true);
    expect(readFileSync(invalidHome, "utf8")).toBe(
      "a regular file, not a CATP_HOME directory\n",
    );
  });

  it("allows and records a valid policy decision", () => {
    writePolicy(ROOT);
    process.env.CATP_HOME = join(ROOT, ".catp-home");

    const result = evaluatePreHookInput(hookInput(), { startDir: ROOT });

    expect(result).toMatchObject({ exitCode: 0, policyFound: true, auditRecorded: true });
  });

  it("durably binds the recorded v4 entry to its action sidecar", () => {
    writePolicy(ROOT);
    process.env.CATP_HOME = join(ROOT, ".catp-home");

    const result = evaluatePreHookInput(hookInput(), { startDir: ROOT });
    expect(result).toMatchObject({ exitCode: 0, auditRecorded: true });

    const entry = readLastEntry("pre-hook-agent");
    expect(entry.commitment_version).toBe(4);
    const sidecar = actionSidecarPath(
      "pre-hook-agent",
      latestAuditDate("pre-hook-agent"),
      entry.action_commitment,
    );
    expect(existsSync(sidecar)).toBe(true);
    // Recomputing the digest over the persisted sidecar reproduces the binding
    // recorded in the entry: the complete action, not the display summary.
    const stored = JSON.parse(readFileSync(sidecar, "utf8"));
    expect(computeActionCommitment(stored)).toBe(entry.action_commitment);
    expect(stored.tool_name).toBe("Bash");
    expect(stored.tool_input).toEqual({ command: "echo ok" });
  });

  it("produces an audit log whose hash chain verifies", async () => {
    writePolicy(ROOT);
    process.env.CATP_HOME = join(ROOT, ".catp-home");
    evaluatePreHookInput(hookInput(), { startDir: ROOT });

    const dir = join(auditRoot("pre-hook-agent"), latestAuditDate("pre-hook-agent"));
    const verification = await verifyChain(join(dir, "actions.jsonl"));
    expect(verification.ok).toBe(true);
  });

  it("fails closed when the action sidecar cannot be persisted", () => {
    writePolicy(ROOT);
    process.env.CATP_HOME = join(ROOT, ".catp-home");

    // The action is allowed by policy, so a durable-write failure must downgrade
    // the outcome to a blocking internal error rather than a successful allow.
    const result = evaluatePreHookInput(hookInput(), {
      startDir: ROOT,
      storage: failingStorage("writeContentAddressed", "sidecar fsync failed"),
    });

    expect(result.exitCode).toBe(2);
    expect(result.auditRecorded).toBe(false);
    expect(result.reason).toContain("audit error");
  });

  it("fails closed when the audit log append cannot be persisted", () => {
    writePolicy(ROOT);
    process.env.CATP_HOME = join(ROOT, ".catp-home");

    const result = evaluatePreHookInput(hookInput(), {
      startDir: ROOT,
      storage: failingStorage("appendLine", "log fsync failed"),
    });

    expect(result.exitCode).toBe(2);
    expect(result.auditRecorded).toBe(false);
    expect(result.reason).toContain("audit error");
  });
});

describe("preHookBlockOutput", () => {
  it("writes the JSON decision to stdout and the reason to stderr", () => {
    const block = preHookBlockOutput("destructive commands are blocked");

    expect(JSON.parse(block.stdout)).toEqual({
      decision: "block",
      reason: "destructive commands are blocked",
    });
    // Codex CLI only honors the blocking reason on stderr (exit code 2).
    expect(block.stderr).toBe("destructive commands are blocked\n");
  });
});
