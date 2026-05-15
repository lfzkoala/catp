import { findPolicyFile, loadPolicy } from "../policy/loader.js";
import type { CatpPolicy } from "../policy/types.js";

export function cmdValidate(opts: { file?: string }): void {
  const policyPath = opts.file ?? findPolicyFile();
  if (!policyPath) {
    process.stderr.write("catp: no catp-policy.toml found in current directory or any parent\n");
    process.exit(1);
  }

  try {
    const policy = loadPolicy(policyPath);
    process.stdout.write(formatValidationSummary(policyPath, policy));
  } catch (err) {
    process.stderr.write(`✗ ${policyPath}\n  ${(err as Error).message}\n`);
    process.exit(1);
  }
}

export function formatValidationSummary(policyPath: string, policy: CatpPolicy): string {
  const lines = [
    `✓ ${policyPath}`,
    `  agent: ${policy.agent.id} v${policy.agent.version}`,
    `  rules: ${policy.rules.length}`,
  ];
  if (policy.authorization) {
    lines.push(
      "  authorization: authorization_groth16_v1-ready",
      `    allowedAction: ${policy.authorization.allowed_action}`,
      `    maxValuePerTx: ${policy.authorization.max_value_per_tx}`,
      `    maxValueTotal: ${policy.authorization.max_value_total}`,
      `    validFrom: ${policy.authorization.valid_from}`,
      `    validUntil: ${policy.authorization.valid_until}`,
      "    next: catp witness --action <action.json> --out <witness.json>",
    );
  }
  return `${lines.join("\n")}\n`;
}
