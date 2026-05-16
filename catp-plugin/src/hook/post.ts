import { findPolicyFile, loadPolicy } from "../policy/loader.js";
import { appendAuditEntry, getLastCommitment } from "../audit/logger.js";
import { claudeCodeAdapter } from "../adapters/claude-code.js";
import { recordPostAction } from "../enforcement/core.js";
import { parseHookAction, readStdin } from "./runtime.js";

export async function runPostHook(): Promise<void> {
  const raw = await readStdin();
  const action = parseHookAction(raw, claudeCodeAdapter, "post");
  if (!action) {
    process.exit(0);
  }

  const policyPath = findPolicyFile();
  if (!policyPath) process.exit(0);

  let policy;
  try {
    policy = loadPolicy(policyPath);
  } catch {
    process.exit(0);
  }

  // PostToolUse always records allow — the action already executed
  const prev = getLastCommitment(policy.agent.id);
  const result = recordPostAction(action, prev);
  try {
    appendAuditEntry(policy.agent.id, result.auditEntry);
  } catch {
    // Audit log failure must not block the agent
  }

  process.exit(0);
}
