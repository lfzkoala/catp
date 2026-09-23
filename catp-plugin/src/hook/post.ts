import { findPolicyFile, loadPolicy } from "../policy/loader.js";
import { appendChainedAuditEntry } from "../audit/logger.js";
import { claudeCodeAdapter } from "../adapters/claude-code.js";
import { recordPostAction } from "../enforcement/core.js";
import type { AuditStorage } from "../audit/durable.js";
import type { RuntimeAdapter } from "../runtime/types.js";
import { parseHookAction, readStdin } from "./runtime.js";

export interface HookOptions {
  adapter?: RuntimeAdapter;
  /**
   * Test seam for injecting audit-storage failures. CLI execution leaves this
   * undefined so the logger always uses the fsync-backed nodeAuditStorage.
   */
  storage?: AuditStorage;
}

export async function runPostHook(opts: HookOptions = {}): Promise<void> {
  const adapter = opts.adapter ?? claudeCodeAdapter;
  const raw = await readStdin();
  const action = parseHookAction(raw, adapter, "post");
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
  try {
    appendChainedAuditEntry(
      policy.agent.id,
      (prev) => recordPostAction(policy, action, prev),
      opts.storage,
    );
  } catch {
    // Audit log failure must not block the agent
  }

  process.exit(0);
}
