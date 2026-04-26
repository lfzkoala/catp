import { findPolicyFile, loadPolicy } from "../policy/loader.js";

export function cmdValidate(opts: { file?: string }): void {
  const policyPath = opts.file ?? findPolicyFile();
  if (!policyPath) {
    process.stderr.write("catp: no catp-policy.toml found in current directory or any parent\n");
    process.exit(1);
  }

  try {
    const policy = loadPolicy(policyPath);
    process.stdout.write(
      `✓ ${policyPath}\n  agent: ${policy.agent.id} v${policy.agent.version}\n  rules: ${policy.rules.length}\n`
    );
  } catch (err) {
    process.stderr.write(`✗ ${policyPath}\n  ${(err as Error).message}\n`);
    process.exit(1);
  }
}
