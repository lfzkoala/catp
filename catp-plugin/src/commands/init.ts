import { writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const TEMPLATE = `[agent]
id = "my-agent"
version = "1"

# Rules are evaluated top-to-bottom; first match wins.
# Omit pattern/path fields to match any invocation of that tool.

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
`;

export function cmdInit(): void {
  const dest = join(process.cwd(), "catp-policy.toml");
  if (existsSync(dest)) {
    process.stdout.write("catp-policy.toml already exists — skipping.\n");
    return;
  }
  writeFileSync(dest, TEMPLATE, "utf8");
  process.stdout.write(
    "Created catp-policy.toml\n\nNext steps:\n" +
    "  1. Edit catp-policy.toml to match your agent's requirements\n" +
    "  2. Run: catp validate\n" +
    "  3. Add CATP hooks to ~/.claude/settings.json (see README)\n"
  );
}
