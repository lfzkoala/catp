import { createHash } from "node:crypto";
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { auditDirForDate } from "./paths.js";
import type { AuditEntry, AuthorizationAction, HookInput } from "../policy/types.js";

// Phase 0: SHA-256 audit commitment.
// Chains on fields stored in the log (tool, decision, ts, prev) so the chain
// is verifiable from the JSONL file alone without replaying tool_input.
// A future proof bridge can add Poseidon commitments over the full action witness.
export function computeCommitment(
  tool: string,
  decision: "allow" | "deny",
  ts: string,
  prev: string = "0",
  ruleMatched: string | null = null,
  inputSummary: string = ""
): string {
  return createHash("sha256")
    .update(JSON.stringify({ tool, decision, ts, ruleMatched, inputSummary, prev }))
    .digest("hex");
}

export function summarizeInput(input: HookInput): string {
  const raw = JSON.stringify(input.tool_input);
  return raw.length > 200 ? raw.slice(0, 200) + "…" : raw;
}

export function auditDir(agentId: string): string {
  const date = new Date().toISOString().slice(0, 10);
  return auditDirForDate(agentId, date);
}

export function getLastCommitment(agentId: string): string {
  const dir = auditDir(agentId);
  const file = join(dir, "actions.jsonl");
  try {
    const content = readFileSync(file, "utf8").trimEnd();
    if (!content) return "0";
    const lastLine = content.split("\n").pop() ?? "";
    const entry = JSON.parse(lastLine) as AuditEntry;
    return entry.commitment;
  } catch {
    return "0";
  }
}

export function appendAuditEntry(agentId: string, entry: AuditEntry): void {
  const dir = auditDir(agentId);
  mkdirSync(dir, { recursive: true });
  appendFileSync(join(dir, "actions.jsonl"), JSON.stringify(entry) + "\n", "utf8");
}

export function buildEntry(
  input: HookInput,
  decision: "allow" | "deny",
  ruleMatched: string | null,
  prevCommitment: string = "0"
): AuditEntry {
  const ts = new Date().toISOString();
  const inputSummary = summarizeInput(input);
  const entry: AuditEntry = {
    ts,
    tool: input.tool_name,
    decision,
    rule_matched: ruleMatched,
    commitment: computeCommitment(input.tool_name, decision, ts, prevCommitment, ruleMatched, inputSummary),
    input_summary: inputSummary,
  };
  const authorization = extractAuthorizationAction(input);
  if (authorization) {
    entry.authorization = authorization;
  }
  return entry;
}

export function extractAuthorizationAction(input: HookInput): AuthorizationAction | undefined {
  const candidate = input.tool_input.catp_authorization ?? input.tool_input.authorization;
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
    return undefined;
  }
  const value = candidate as Record<string, unknown>;
  if (
    !isStringOrNumber(value.actionType) ||
    typeof value.protocol !== "string" ||
    typeof value.token !== "string" ||
    !isStringOrNumber(value.value)
  ) {
    return undefined;
  }
  return {
    actionType: value.actionType,
    protocol: value.protocol,
    token: value.token,
    value: value.value,
    ...(isStringOrNumber(value.currentTimestamp) ? { currentTimestamp: value.currentTimestamp } : {}),
    ...(isStringOrNumber(value.cumulativeSpend) ? { cumulativeSpend: value.cumulativeSpend } : {}),
  };
}

function isStringOrNumber(value: unknown): value is string | number {
  return typeof value === "string" || typeof value === "number";
}
