import { createHash } from "node:crypto";
import { appendFileSync, closeSync, existsSync, mkdirSync, openSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { lockSync } from "proper-lockfile";
import { auditDirForDate } from "./paths.js";
import type { AuditEntry, AuthorizationAction } from "../policy/types.js";
import type { ToolAction } from "../runtime/types.js";
import type { RuntimePhase } from "../runtime/types.js";

const AUDIT_LOCK_STALE_MS = 5_000;
const AUDIT_LOCK_WAIT_MS = 2_000;
const AUDIT_LOCK_RETRY_MS = 10;
const lockWaitBuffer = new Int32Array(new SharedArrayBuffer(4));

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
  inputSummary: string = "",
  authorization?: AuthorizationAction,
  commitmentVersion: 1 | 2 | 3 = 1,
  phase?: RuntimePhase,
): string {
  const payload = commitmentVersion === 3
    ? { commitmentVersion, phase, tool, decision, ts, ruleMatched, inputSummary, authorization: authorization ?? null, prev }
    : commitmentVersion === 2
    ? { commitmentVersion, tool, decision, ts, ruleMatched, inputSummary, authorization: authorization ?? null, prev }
    : { tool, decision, ts, ruleMatched, inputSummary, prev };
  return createHash("sha256")
    .update(JSON.stringify(payload))
    .digest("hex");
}

export function summarizeInput(input: ToolAction): string {
  const raw = JSON.stringify(input.toolInput);
  return raw.length > 200 ? raw.slice(0, 200) + "…" : raw;
}

export function auditDir(agentId: string): string {
  const date = new Date().toISOString().slice(0, 10);
  return auditDirForDate(agentId, date);
}

export function getLastCommitment(agentId: string): string {
  const dir = auditDir(agentId);
  const file = join(dir, "actions.jsonl");
  return getLastCommitmentFromFile(file);
}

function getLastCommitmentFromFile(file: string): string {
  if (!existsSync(file)) return "0";

  const content = readFileSync(file, "utf8").trimEnd();
  if (!content) return "0";
  const lastLine = content.split("\n").pop() ?? "";
  const entry = JSON.parse(lastLine) as AuditEntry;
  if (typeof entry.commitment !== "string" || !/^[0-9a-f]{64}$/i.test(entry.commitment)) {
    throw new Error(`invalid audit log tail in ${file}`);
  }
  return entry.commitment;
}

export function appendAuditEntry(agentId: string, entry: AuditEntry): void {
  const dir = auditDir(agentId);
  mkdirSync(dir, { recursive: true });
  const file = join(dir, "actions.jsonl");
  withAuditLock(file, () => appendEntryToFile(file, entry));
}

export function appendChainedAuditEntry<T extends { auditEntry: AuditEntry }>(
  agentId: string,
  build: (prevCommitment: string) => T,
): T {
  const dir = auditDir(agentId);
  mkdirSync(dir, { recursive: true });
  const file = join(dir, "actions.jsonl");

  return withAuditLock(file, () => {
    const result = build(getLastCommitmentFromFile(file));
    appendEntryToFile(file, result.auditEntry);
    return result;
  });
}

function appendEntryToFile(file: string, entry: AuditEntry): void {
  appendFileSync(file, JSON.stringify(entry) + "\n", "utf8");
}

function withAuditLock<T>(file: string, operation: () => T): T {
  closeSync(openSync(file, "a"));
  const release = acquireAuditLock(file);
  try {
    return operation();
  } finally {
    release();
  }
}

function acquireAuditLock(file: string): () => void {
  const deadline = Date.now() + AUDIT_LOCK_WAIT_MS;
  while (true) {
    try {
      return lockSync(file, {
        lockfilePath: join(dirname(file), ".actions.lock"),
        stale: AUDIT_LOCK_STALE_MS,
        realpath: true,
      });
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ELOCKED" || Date.now() >= deadline) {
        throw err;
      }
      Atomics.wait(lockWaitBuffer, 0, 0, AUDIT_LOCK_RETRY_MS);
    }
  }
}

export function buildEntry(
  input: ToolAction,
  decision: "allow" | "deny",
  ruleMatched: string | null,
  prevCommitment: string = "0"
): AuditEntry {
  const ts = new Date().toISOString();
  const inputSummary = summarizeInput(input);
  const authorization = extractAuthorizationAction(input);
  const entry: AuditEntry = {
    commitment_version: 3,
    phase: input.phase,
    ts,
    tool: input.toolName,
    decision,
    rule_matched: ruleMatched,
    commitment: computeCommitment(
      input.toolName,
      decision,
      ts,
      prevCommitment,
      ruleMatched,
      inputSummary,
      authorization,
      3,
      input.phase,
    ),
    input_summary: inputSummary,
  };
  if (authorization) {
    entry.authorization = authorization;
  }
  return entry;
}

export function extractAuthorizationAction(input: ToolAction): AuthorizationAction | undefined {
  const candidate = input.toolInput.catp_authorization ?? input.toolInput.authorization;
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
