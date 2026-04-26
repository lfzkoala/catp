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
}

export interface HookInput {
  session_id?: string;
  tool_name: string;
  tool_input: Record<string, unknown>;
}

export interface AuditEntry {
  ts: string;
  tool: string;
  decision: "allow" | "deny";
  rule_matched: string | null;
  commitment: string;
  input_summary: string;
}
