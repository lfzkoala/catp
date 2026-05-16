import { findPolicyFile, loadPolicy } from "../policy/loader.js";
import { appendAuditEntry, getLastCommitment } from "../audit/logger.js";
import { claudeCodeAdapter } from "../adapters/claude-code.js";
import { evaluatePreAction } from "../enforcement/core.js";
import { parseHookAction, readStdin } from "./runtime.js";

export async function runPreHook(): Promise<void> {
  const raw = await readStdin();
  const action = parseHookAction(raw, claudeCodeAdapter, "pre");
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
