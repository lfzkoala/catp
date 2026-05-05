import { createHash } from "node:crypto";
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type { AuditEntry, HookInput } from "../policy/types.js";

// Phase 0: SHA-256 commitment placeholder.
// Chains on fields stored in the log (tool, decision, ts, prev) so the chain
// is verifiable from the JSONL file alone without replaying tool_input.
// Phase 1 replaces this with a Poseidon hash over the full action witness via WASM.
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
  return join(homedir(), ".catp", "audit", agentId, date);
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
  return {
    ts,
    tool: input.tool_name,
    decision,
    rule_matched: ruleMatched,
    commitment: computeCommitment(input.tool_name, decision, ts, prevCommitment, ruleMatched, inputSummary),
    input_summary: inputSummary,
  };
}
