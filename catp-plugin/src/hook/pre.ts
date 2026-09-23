import { findPolicyFile, loadPolicy } from "../policy/loader.js";
import { appendChainedAuditEntry } from "../audit/logger.js";
import { claudeCodeAdapter } from "../adapters/claude-code.js";
import { evaluatePreAction } from "../enforcement/core.js";
import type { AuditStorage } from "../audit/durable.js";
import type { RuntimeAdapter } from "../runtime/types.js";
import { parseHookAction, readStdin } from "./runtime.js";

export interface HookOptions {
  adapter?: RuntimeAdapter;
  startDir?: string;
  /**
   * Test seam for injecting audit-storage failures. CLI execution leaves this
   * undefined so the logger always uses the fsync-backed nodeAuditStorage.
   */
  storage?: AuditStorage;
}

export interface PreHookOutcome {
  exitCode: 0 | 2;
  policyFound: boolean;
  auditRecorded: boolean;
  reason: string;
}

export function evaluatePreHookInput(raw: string, opts: HookOptions = {}): PreHookOutcome {
  const adapter = opts.adapter ?? claudeCodeAdapter;
  const policyPath = findPolicyFile(opts.startDir);
  if (!policyPath) {
    return {
      exitCode: 0,
      policyFound: false,
      auditRecorded: false,
      reason: "CATP policy not found",
    };
  }

  const action = parseHookAction(raw, adapter, "pre");
  if (!action) {
    return {
      exitCode: 2,
      policyFound: true,
      auditRecorded: false,
      reason: "invalid pre-hook input",
    };
  }

  let policy;
  try {
    policy = loadPolicy(policyPath);
  } catch (err) {
    return {
      exitCode: 2,
      policyFound: true,
      auditRecorded: false,
      reason: `policy error: ${(err as Error).message}`,
    };
  }

  try {
    const result = appendChainedAuditEntry(
      policy.agent.id,
      (prev) => evaluatePreAction(policy, action, prev),
      opts.storage,
    );

    return {
      exitCode: result.allow ? 0 : 2,
      policyFound: true,
      auditRecorded: true,
      reason: result.reason,
    };
  } catch (err) {
    // Fail closed: if the action sidecar, audit append, or any fsync failed, the
    // decision was not durably recorded, so it must not be returned as a
    // successful allow/deny. Surface a concise internal error and exit 2.
    return {
      exitCode: 2,
      policyFound: true,
      auditRecorded: false,
      reason: `audit error: ${(err as Error).message}`,
    };
  }
}

export function preHookBlockOutput(reason: string): { stdout: string; stderr: string } {
  return {
    stdout: JSON.stringify({ decision: "block", reason }) + "\n",
    // Codex CLI ignores stdout JSON when the hook exits non-zero and treats a
    // missing stderr reason as a hook failure (fail-open); Claude Code also
    // surfaces stderr on exit code 2. Write the reason to both streams.
    stderr: reason + "\n",
  };
}

export async function runPreHook(opts: HookOptions = {}): Promise<void> {
  const raw = await readStdin();
  const outcome = evaluatePreHookInput(raw, opts);

  if (outcome.exitCode === 2) {
    const block = preHookBlockOutput(outcome.reason);
    process.stdout.write(block.stdout);
    process.stderr.write(block.stderr);
    process.exit(2);
  }

  process.exit(0);
}
