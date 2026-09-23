import { buildEntry } from "../audit/logger.js";
import { evaluate } from "../policy/engine.js";
import {
  canonicalizeToolAction,
  computeActionCommitment,
  computePolicyCommitment,
  type CanonicalToolActionV1,
} from "../evidence/commitments.js";
import type { AuditEntryV4, CatpPolicy } from "../policy/types.js";
import type { ToolAction } from "../runtime/types.js";

export interface EnforcementResult {
  allow: boolean;
  reason: string;
  auditEntry: AuditEntryV4;
  /**
   * The complete canonical action evidence the decision is bound to. Persisted
   * as a content-addressed sidecar (see audit storage) and referenced by the
   * v4 entry's `action_commitment`.
   */
  action: CanonicalToolActionV1;
}

/**
 * Fail closed if the canonical action evidence does not hash to the commitment
 * recorded in the audit entry. This prevents pairing an entry with a different
 * sidecar and is re-checked at the storage boundary before persistence.
 */
function assertActionBinding(action: CanonicalToolActionV1, auditEntry: AuditEntryV4): void {
  if (computeActionCommitment(action) !== auditEntry.action_commitment) {
    throw new Error("internal error: action evidence does not match audit entry binding");
  }
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

  // Bind the decision to the exact policy and complete action used at
  // enforcement time. Both commitments are computed here, from the normalized
  // policy passed to the engine and the canonicalized action, never recomputed
  // later from mutable files.
  const preAction: ToolAction = { ...action, phase: "pre" };
  const canonical = canonicalizeToolAction(preAction);
  const bindings = {
    reason: decision.reason,
    policyCommitment: computePolicyCommitment(policy),
    actionCommitment: computeActionCommitment(canonical),
  };
  const auditEntry = buildEntry(
    preAction,
    decision.allow ? "allow" : "deny",
    ruleName,
    prevCommitment,
    bindings,
  );
  assertActionBinding(canonical, auditEntry);

  return {
    allow: decision.allow,
    reason: decision.reason,
    auditEntry,
    action: canonical,
  };
}

export function recordPostAction(
  policy: CatpPolicy,
  action: ToolAction,
  prevCommitment: string = "0"
): EnforcementResult {
  const reason = "post-action audit record";
  const postAction: ToolAction = { ...action, phase: "post" };
  const canonical = canonicalizeToolAction(postAction);
  const bindings = {
    reason,
    policyCommitment: computePolicyCommitment(policy),
    actionCommitment: computeActionCommitment(canonical),
  };
  const auditEntry = buildEntry(postAction, "allow", null, prevCommitment, bindings);
  assertActionBinding(canonical, auditEntry);

  return {
    allow: true,
    reason,
    auditEntry,
    action: canonical,
  };
}
