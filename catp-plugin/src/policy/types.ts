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

export interface AuditEntry {
  ts: string;
  tool: string;
  decision: "allow" | "deny";
  rule_matched: string | null;
  commitment: string;
  input_summary: string;
  authorization?: AuthorizationAction;
}

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
