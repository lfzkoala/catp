import { writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const TEMPLATE = `[agent]
id = "my-agent"
version = "1"

# Rules are evaluated top-to-bottom; first match wins.
# Omit pattern/path fields to match any invocation of that tool.
# Command patterns are matched against the raw command string; CATP does not
# parse shell syntax. Keep the control-operator deny rule below ahead of any
# Bash allow rule so allowlisted commands cannot be chained into others.

[[rules]]
tool = "Bash"
allow = false
pattern = ["&&", ";", "|", "\`", "$("]
reason = "Compound shell commands are blocked; remove this rule only if you understand the bypass risk"

[[rules]]
tool = "Bash"
allow = false
pattern = ["rm -rf*", "*--force*", "*git push*prod*"]
reason = "Destructive or production-affecting shell commands are blocked"

[[rules]]
tool = "Bash"
allow = true

[[rules]]
tool = "Write"
allow = false
path_allowlist = ["./src/**", "./tests/**", "./docs/**"]
reason = "Writes outside the project allowlist are blocked"

[[rules]]
tool = "WebFetch"
allow = false
reason = "External network calls require explicit approval"

# On OpenAI Codex CLI (catp hook pre/post --runtime codex), tool rules match
# the names Codex reports: v0.155.1 uses "Bash" for shell commands and
# "apply_patch" for file edits (patch text arrives in tool_input.command;
# argv-array commands are normalized to a single string). Run "catp log show"
# after a tool call to confirm the names your runtime reports.
`;

const AUTHORIZATION_TEMPLATE = `
[authorization]
allowed_action = "Swap"
allowed_protocol = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
allowed_token = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
max_value_per_tx = "1000"
max_value_total = "10000"
valid_from = "1778042786"
valid_until = "1778129246"
`;

export function policyTemplate(opts: { authorization?: boolean } = {}): string {
  return opts.authorization ? `${TEMPLATE}${AUTHORIZATION_TEMPLATE}` : TEMPLATE;
}

export function cmdInit(opts: { authorization?: boolean } = {}): void {
  const dest = join(process.cwd(), "catp-policy.toml");
  if (existsSync(dest)) {
    process.stdout.write("catp-policy.toml already exists — skipping.\n");
    return;
  }
  writeFileSync(dest, policyTemplate(opts), "utf8");
  const authorizationStep = opts.authorization
    ? "  3. Run: catp witness --action <action.json> --out <witness.json>\n" +
      "  4. Add CATP hooks to ~/.claude/settings.json, or ~/.codex/hooks.json for Codex CLI (see README)\n"
    : "  3. Add CATP hooks to ~/.claude/settings.json, or ~/.codex/hooks.json for Codex CLI (see README)\n";
  process.stdout.write(
    "Created catp-policy.toml\n\nNext steps:\n" +
    "  1. Edit catp-policy.toml to match your agent's requirements\n" +
    "  2. Run: catp validate\n" +
    authorizationStep
  );
}
