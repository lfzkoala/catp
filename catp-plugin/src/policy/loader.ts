import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { parse } from "smol-toml";
import type { AuthorizationConfig, CatpPolicy } from "./types.js";

const POLICY_FILENAME = "catp-policy.toml";

export function findPolicyFile(startDir: string = process.cwd()): string | null {
  let dir = startDir;
  while (true) {
    const candidate = join(dir, POLICY_FILENAME);
    if (existsSync(candidate)) return candidate;
    const parent = join(dir, "..");
    if (parent === dir) return null;
    dir = parent;
  }
}

export function loadPolicy(policyPath: string): CatpPolicy {
  const raw = readFileSync(policyPath, "utf8");
  const parsed = parse(raw) as unknown;
  return validate(parsed, policyPath);
}

function validate(raw: unknown, path: string): CatpPolicy {
  if (typeof raw !== "object" || raw === null) {
    throw new Error(`${path}: policy must be a TOML object`);
  }
  const obj = raw as Record<string, unknown>;

  if (!obj.agent || typeof obj.agent !== "object") {
    throw new Error(`${path}: missing [agent] section`);
  }
  const agent = obj.agent as Record<string, unknown>;
  if (typeof agent.id !== "string" || !agent.id) {
    throw new Error(`${path}: agent.id must be a non-empty string`);
  }
  if (typeof agent.version !== "string" || !agent.version) {
    throw new Error(`${path}: agent.version must be a non-empty string`);
  }

  if (!Array.isArray(obj.rules)) {
    throw new Error(`${path}: [[rules]] must be an array`);
  }

  const rules = obj.rules.map((r: unknown, i: number) => {
    if (typeof r !== "object" || r === null) {
      throw new Error(`${path}: rules[${i}] must be an object`);
    }
    const rule = r as Record<string, unknown>;
    if (typeof rule.tool !== "string" || !rule.tool) {
      throw new Error(`${path}: rules[${i}].tool must be a non-empty string`);
    }
    if (typeof rule.allow !== "boolean") {
      throw new Error(`${path}: rules[${i}].allow must be a boolean`);
    }
    return {
      tool: rule.tool as string,
      allow: rule.allow as boolean,
      pattern: toStringArray(rule.pattern),
      path_allowlist: toStringArray(rule.path_allowlist),
      path_denylist: toStringArray(rule.path_denylist),
      reason: typeof rule.reason === "string" ? rule.reason : undefined,
    };
  });

  return {
    agent: { id: agent.id as string, version: agent.version as string },
    rules,
    authorization: validateAuthorization(obj.authorization, path),
  };
}

function toStringArray(v: unknown): string[] | undefined {
  if (v === undefined || v === null) return undefined;
  if (!Array.isArray(v)) return undefined;
  return v.filter((x): x is string => typeof x === "string");
}

function validateAuthorization(raw: unknown, path: string): AuthorizationConfig | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (typeof raw !== "object") {
    throw new Error(`${path}: [authorization] must be an object`);
  }
  const auth = raw as Record<string, unknown>;
  const required = [
    "allowed_action",
    "allowed_protocol",
    "allowed_token",
    "max_value_per_tx",
    "max_value_total",
    "valid_from",
    "valid_until",
  ] as const;
  for (const field of required) {
    if (typeof auth[field] !== "string" || auth[field] === "") {
      throw new Error(`${path}: authorization.${field} must be a non-empty string`);
    }
  }
  return {
    allowed_action: auth.allowed_action as string,
    allowed_protocol: auth.allowed_protocol as string,
    allowed_token: auth.allowed_token as string,
    max_value_per_tx: auth.max_value_per_tx as string,
    max_value_total: auth.max_value_total as string,
    valid_from: auth.valid_from as string,
    valid_until: auth.valid_until as string,
  };
}
