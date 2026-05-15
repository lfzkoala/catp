import { buildEntry } from "../audit/logger.js";
import { evaluate } from "../policy/engine.js";
import type { CatpPolicy } from "../policy/types.js";
import type { AuditEntry } from "../policy/types.js";
import type { ToolAction } from "../runtime/types.js";

export interface EnforcementResult {
  allow: boolean;
  reason: string;
  auditEntry: AuditEntry;
}

export function evaluatePreAction(
  policy: CatpPolicy,
  action: ToolAction,
  prevCommitment: string = "0"
): EnforcementResult {
  const decision = evaluate(policy, action);
  const ruleName = decision.rule
    ? `${decision.rule.tool}:${decision.rule.allow ? "allow" : "deny"}`
    : null;

  return {
    allow: decision.allow,
    reason: decision.reason,
    auditEntry: buildEntry(
      action,
      decision.allow ? "allow" : "deny",
      ruleName,
      prevCommitment
    ),
  };
}

export function recordPostAction(
  action: ToolAction,
  prevCommitment: string = "0"
): EnforcementResult {
  return {
    allow: true,
    reason: "post-action audit record",
    auditEntry: buildEntry(action, "allow", null, prevCommitment),
  };
}
