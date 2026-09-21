import micromatch from "micromatch";
import { posix as posixPath } from "node:path";
import type { CatpPolicy, Rule } from "./types.js";
import type { ToolAction } from "../runtime/types.js";

export interface Decision {
  allow: boolean;
  rule: Rule | null;
  reason: string;
}

export function evaluate(policy: CatpPolicy, input: ToolAction): Decision {
  const toolRules = policy.rules.filter(
    (r) => r.tool === "*" || r.tool === input.toolName
  );

  for (const rule of toolRules) {
    if (matchesRule(rule, input)) {
      return {
        allow: rule.allow,
        rule,
        reason: rule.reason ?? (rule.allow ? "allowed by policy" : "denied by policy"),
      };
    }
  }

  // Default allow if no rule matches
  return { allow: true, rule: null, reason: "no matching rule — default allow" };
}

function matchesRule(rule: Rule, input: ToolAction): boolean {
  if (rule.pattern && rule.pattern.length > 0) {
    const command = extractCommand(input);
    if (command === null) return false;
    return rule.pattern.some((p) => micromatch.isMatch(command, p) || command.includes(p));
  }

  if (rule.path_allowlist || rule.path_denylist) {
    const rawPath = extractPath(input);
    if (rawPath === null) return false;
    // Lexical normalization collapses dot segments and redundant separators on
    // both sides so "src/../secrets/x" cannot slip past an allowlist label.
    // Symlink and runtime-CWD resolution remain host-side residual risk.
    const filePath = normalizePathLabel(rawPath);

    if (rule.path_denylist && rule.path_denylist.length > 0) {
      if (micromatch.isMatch(filePath, rule.path_denylist.map(normalizePathLabel))) return true;
    }
    if (rule.path_allowlist && rule.path_allowlist.length > 0) {
      return !micromatch.isMatch(filePath, rule.path_allowlist.map(normalizePathLabel));
    }
    // path condition present but file didn't match denylist and no allowlist — no match
    return false;
  }

  // No pattern/path conditions — matches any invocation of this tool
  return true;
}

function extractCommand(input: ToolAction): string | null {
  const cmd = input.toolInput["command"];
  return typeof cmd === "string" ? cmd : null;
}

function extractPath(input: ToolAction): string | null {
  for (const key of ["file_path", "path", "filePath"]) {
    const v = input.toolInput[key];
    if (typeof v === "string") return v;
  }
  return null;
}

function normalizePathLabel(value: string): string {
  return posixPath.normalize(value);
}
