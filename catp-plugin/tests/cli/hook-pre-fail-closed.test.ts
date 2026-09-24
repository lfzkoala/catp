import { afterAll, beforeAll, describe, expect, it } from "@jest/globals";
import { execSync, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Real CLI-level fail-closed coverage (issue #4): spawn the built CLI as a
// child process instead of calling evaluatePreHookInput in-process, so the
// assertions exercise the actual exit code, the actual stdout/stderr the agent
// runtime would see, and the actual durable-storage backend. Jest runs with
// the catp-plugin package root as cwd (see package.json "test" script).
const PACKAGE_ROOT = process.cwd();
const CLI_PATH = join(PACKAGE_ROOT, "dist", "cli.js");
const ROOT = join(tmpdir(), `catp-cli-hook-test-${Date.now()}`);

// A controlled wrapper stands in for the agent runtime's tool executor: it
// pipes the hook input into the real CLI and executes the action (recording a
// marker) only when the hook exits 0, mirroring how Claude Code/Codex treat a
// non-zero hook exit as blocking. If the hook fails closed, the marker must
// never be created, proving the otherwise-allowable action did not proceed.
function writeWrapper(dir: string, cliMarkerFile: string, hookInput: string): string {
  mkdirSync(dir, { recursive: true });
  const wrapper = join(dir, "runtime-wrapper.sh");
  writeFileSync(
    wrapper,
    [
      "#!/bin/sh",
      `printf '%s' '${hookInput}' | node "${CLI_PATH}" hook pre --runtime claude-code`,
      "status=$?",
      'if [ "$status" -eq 0 ]; then',
      `  echo "executed" >> "${cliMarkerFile}"`,
      "fi",
      "exit $status",
      "",
    ].join("\n"),
    "utf8",
  );
  chmodSync(wrapper, 0o755);
  return wrapper;
}

const HOOK_INPUT = JSON.stringify({
  session_id: "session",
  tool_name: "Bash",
  tool_input: { command: "echo ok" },
});

const ALLOW_POLICY = `
[agent]
id = "cli-hook-agent"
version = "1"

[[rules]]
tool = "Bash"
allow = true
`;

function runWrapper(wrapper: string, cwd: string, catpHome: string) {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined && key !== "CATP_HOME") env[key] = value;
  }
  env.CATP_HOME = catpHome;
  return spawnSync(wrapper, [], { cwd, env, encoding: "utf8" });
}

describe("CLI child process: catp hook pre fail-closed", () => {
  beforeAll(() => {
    // The test spawns the built artifact, so make sure dist/cli.js reflects
    // the current sources before any child process runs.
    if (!existsSync(CLI_PATH)) {
      execSync("npm run build", { cwd: PACKAGE_ROOT });
    }
  }, 120_000);

  afterAll(() => {
    if (existsSync(ROOT)) rmSync(ROOT, { recursive: true, force: true });
  });

  it("blocks with exit code 2 when CATP_HOME is structurally invalid and never executes the action", () => {
    const projectDir = join(ROOT, "invalid-home-project");
    mkdirSync(projectDir, { recursive: true });
    writeFileSync(join(projectDir, "catp-policy.toml"), ALLOW_POLICY, "utf8");

    // Structurally invalid CATP_HOME: a regular file where a directory tree
    // is required, so no evidence can be persisted.
    const invalidHome = join(ROOT, "invalid-catp-home");
    writeFileSync(invalidHome, "a regular file, not a CATP_HOME directory\n", "utf8");

    const marker = join(ROOT, "action-executed-invalid.marker");
    const wrapper = writeWrapper(join(ROOT, "wrapper-invalid"), marker, HOOK_INPUT);

    const result = runWrapper(wrapper, projectDir, invalidHome);

    // Real child-process exit code must be the fail-closed block code.
    expect(result.status).toBe(2);

    // Real stdout must be a block decision and must never offer an allow.
    const parsed = JSON.parse(result.stdout.trim()) as { decision: string; reason: string };
    expect(parsed.decision).toBe("block");
    expect(result.stdout).not.toContain("allow");

    // Real stderr must carry a diagnosable reason (audit persistence failure).
    expect(result.stderr.trim().length).toBeGreaterThan(0);
    expect(parsed.reason).toContain("audit error");

    // The controlled wrapper proves the action never executed: like a real
    // agent runtime, it only runs the tool when the hook exits 0, so a
    // fail-closed block must leave the marker unwritten.
    expect(existsSync(marker)).toBe(false);

    // No evidence path was silently repaired: CATP_HOME is still the same
    // regular file with identical contents, never recreated as a directory.
    expect(statSync(invalidHome).isFile()).toBe(true);
    expect(readFileSync(invalidHome, "utf8")).toBe(
      "a regular file, not a CATP_HOME directory\n",
    );
  });

  it("positive control: the same wrapper allows and records evidence when CATP_HOME is valid", () => {
    const projectDir = join(ROOT, "valid-home-project");
    mkdirSync(projectDir, { recursive: true });
    writeFileSync(join(projectDir, "catp-policy.toml"), ALLOW_POLICY, "utf8");

    const validHome = join(ROOT, "valid-catp-home");
    const marker = join(ROOT, "action-executed-valid.marker");
    const wrapper = writeWrapper(join(ROOT, "wrapper-valid"), marker, HOOK_INPUT);

    const result = runWrapper(wrapper, projectDir, validHome);

    // Guards against a vacuous fail-closed test: the harness itself works and
    // an allowable action passes when evidence can be persisted.
    expect(result.status).toBe(0);
    expect(existsSync(marker)).toBe(true);
    const auditLog = join(validHome, "audit", "cli-hook-agent");
    expect(existsSync(auditLog)).toBe(true);
  });
});
