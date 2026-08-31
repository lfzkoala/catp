import { findPolicyFile, loadPolicy } from "../policy/loader.js";
import { appendChainedAuditEntry } from "../audit/logger.js";
import { claudeCodeAdapter } from "../adapters/claude-code.js";
import { evaluatePreAction } from "../enforcement/core.js";
import type { RuntimeAdapter } from "../runtime/types.js";
import { parseHookAction, readStdin } from "./runtime.js";

export interface HookOptions {
  adapter?: RuntimeAdapter;
  startDir?: string;
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
    const result = appendChainedAuditEntry(policy.agent.id, (prev) =>
      evaluatePreAction(policy, action, prev)
    );

    return {
      exitCode: result.allow ? 0 : 2,
      policyFound: true,
      auditRecorded: true,
      reason: result.reason,
    };
  } catch (err) {
    return {
      exitCode: 2,
      policyFound: true,
      auditRecorded: false,
      reason: `audit error: ${(err as Error).message}`,
    };
  }
}

export async function runPreHook(opts: HookOptions = {}): Promise<void> {
  const raw = await readStdin();
  const outcome = evaluatePreHookInput(raw, opts);

  if (outcome.exitCode === 2) {
    process.stdout.write(
      JSON.stringify({ decision: "block", reason: outcome.reason }) + "\n"
    );
    process.exit(2);
  }

  process.exit(0);
}
