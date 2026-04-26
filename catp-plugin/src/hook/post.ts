import { findPolicyFile, loadPolicy } from "../policy/loader.js";
import { buildEntry, appendAuditEntry, getLastCommitment } from "../audit/logger.js";
import type { HookInput } from "../policy/types.js";

export async function runPostHook(): Promise<void> {
  const raw = await readStdin();
  let input: HookInput;
  try {
    input = JSON.parse(raw) as HookInput;
  } catch {
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
  const entry = buildEntry(input, "allow", null, prev);
  try {
    appendAuditEntry(policy.agent.id, entry);
  } catch {
    // Audit log failure must not block the agent
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
