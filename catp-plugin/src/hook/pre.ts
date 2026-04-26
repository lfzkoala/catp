import { findPolicyFile, loadPolicy } from "../policy/loader.js";
import { evaluate } from "../policy/engine.js";
import { buildEntry, appendAuditEntry, getLastCommitment } from "../audit/logger.js";
import type { HookInput } from "../policy/types.js";

export async function runPreHook(): Promise<void> {
  const raw = await readStdin();
  let input: HookInput;
  try {
    input = JSON.parse(raw) as HookInput;
  } catch {
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

  const decision = evaluate(policy, input);
  const ruleName = decision.rule
    ? `${decision.rule.tool}:${decision.rule.allow ? "allow" : "deny"}`
    : null;

  const prev = getLastCommitment(policy.agent.id);
  const entry = buildEntry(input, decision.allow ? "allow" : "deny", ruleName, prev);
  try {
    appendAuditEntry(policy.agent.id, entry);
  } catch {
    // Audit log failure must not block the agent
  }

  if (!decision.allow) {
    process.stdout.write(
      JSON.stringify({ decision: "block", reason: decision.reason }) + "\n"
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
