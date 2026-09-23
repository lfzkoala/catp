export interface AgentMeta {
  id: string;
  version: string;
}

export interface Rule {
  tool: string;
  allow: boolean;
  pattern?: string[];
  path_allowlist?: string[];
  path_denylist?: string[];
  reason?: string;
}

export interface CatpPolicy {
  agent: AgentMeta;
  rules: Rule[];
  authorization?: AuthorizationConfig;
}

import type { RuntimePhase } from "../runtime/types.js";

/**
 * Fields common to every audit entry version. These are the only fields that
 * may be accessed without first narrowing the entry to a specific version.
 */
export interface AuditEntryBase {
  phase?: RuntimePhase;
  ts: string;
  tool: string;
  decision: "allow" | "deny";
  rule_matched: string | null;
  commitment: string;
  input_summary: string;
  authorization?: AuthorizationAction;
}

/**
 * Legacy audit entries (commitment versions 1--3). They remain verifiable for
 * compatibility with existing logs, but they carry NO enforcement-time
 * policy/action binding and can never be upgraded into one.
 */
export interface AuditEntryLegacy extends AuditEntryBase {
  commitment_version?: 1 | 2 | 3;
}

/**
 * Version-4 audit entry: binds the decision to the exact policy and complete
 * normalized action used at enforcement time. Every binding field is required;
 * `input_summary` remains for display only and is never the action binding.
 */
export interface AuditEntryV4 extends AuditEntryBase {
  commitment_version: 4;
  reason: string;
  policy_commitment: string;
  action_commitment: string;
}

export type AuditEntry = AuditEntryLegacy | AuditEntryV4;

export interface AuthorizationConfig {
  allowed_action: string;
  allowed_protocol: string;
  allowed_token: string;
  max_value_per_tx: string;
  max_value_total: string;
  valid_from: string;
  valid_until: string;
}

export interface AuthorizationAction {
  actionType: string | number;
  protocol: string;
  token: string;
  value: string | number;
  currentTimestamp?: string | number;
  cumulativeSpend?: string | number;
}
