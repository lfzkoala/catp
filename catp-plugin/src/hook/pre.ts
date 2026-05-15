import { findPolicyFile, loadPolicy } from "../policy/loader.js";
import { appendAuditEntry, getLastCommitment } from "../audit/logger.js";
import { claudeCodeAdapter } from "../adapters/claude-code.js";
import { evaluatePreAction } from "../enforcement/core.js";

export async function runPreHook(): Promise<void> {
  const raw = await readStdin();
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    process.exit(0);
  }
  const action = claudeCodeAdapter.fromPreToolUse(parsed);
  if (!action) {
    process.exit(0);
  }

  const policyPath = findPolicyFile();
  if (!policyPath) {
    process.exit(0);
  }

  let policy;
  try {
    policy = loadPolicy(policyPath);
  } catch (err) {
    process.stderr.write(`catp: policy error: ${(err as Error).message}\n`);
    process.exit(0);
  }

  const prev = getLastCommitment(policy.agent.id);
  const result = evaluatePreAction(policy, action, prev);
  try {
    appendAuditEntry(policy.agent.id, result.auditEntry);
  } catch {
    // Audit log failure must not block the agent
  }

  if (!result.allow) {
    process.stdout.write(
      JSON.stringify({ decision: "block", reason: result.reason }) + "\n"
    );
    process.exit(2);
  }

  process.exit(0);
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
