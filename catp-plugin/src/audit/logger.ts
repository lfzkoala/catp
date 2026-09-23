import { createHash } from "node:crypto";
import { closeSync, existsSync, openSync, readSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { lockSync } from "proper-lockfile";
import { actionSidecarPath, auditDirForDate } from "./paths.js";
import { sha256Hex, stableStringify } from "../evidence/canonical.js";
import { computeActionCommitment, type CanonicalToolActionV1 } from "../evidence/commitments.js";
import { nodeAuditStorage, type AuditStorage } from "./durable.js";
import type { AuditEntry, AuditEntryV4, AuthorizationAction } from "../policy/types.js";
import type { ToolAction } from "../runtime/types.js";
import type { RuntimePhase } from "../runtime/types.js";

const AUDIT_LOCK_STALE_MS = 5_000;
const AUDIT_LOCK_WAIT_MS = 2_000;
const AUDIT_LOCK_RETRY_MS = 10;
// Tail recovery reads only this suffix of the daily file: audit entries are
// bounded (input summaries are capped), so the last line always fits, and
// append cost stays constant as the daily log grows.
const AUDIT_TAIL_READ_BYTES = 64 * 1024;
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

// Domain separator for version-4 audit-entry commitments. v4 is a NEW format
// with no backward-compatibility constraint, so it uses the shared canonical
// serializer and an explicit domain string. Legacy v1--v3 commitments above are
// left byte-for-byte unchanged.
const AUDIT_ENTRY_V4_DOMAIN = "catp:audit-entry:v4\n";

export interface AuditEntryV4Fields {
  phase: RuntimePhase;
  tool: string;
  decision: "allow" | "deny";
  ts: string;
  ruleMatched: string | null;
  reason: string;
  inputSummary: string;
  policyCommitment: string;
  actionCommitment: string;
  authorization?: AuthorizationAction;
  prev: string;
}

/**
 * Version-4 entry commitment. Covers every security-relevant field with a
 * domain separator: prev_commitment, phase, tool, decision, ts, rule, reason,
 * the enforcement-time policy commitment, and the complete-action commitment.
 * `inputSummary` is chained for display tamper-evidence only; the authoritative
 * action binding is `actionCommitment`.
 */
export function computeCommitmentV4(fields: AuditEntryV4Fields): string {
  const payload = {
    phase: fields.phase,
    tool: fields.tool,
    decision: fields.decision,
    ts: fields.ts,
    ruleMatched: fields.ruleMatched,
    reason: fields.reason,
    inputSummary: fields.inputSummary,
    policyCommitment: fields.policyCommitment,
    actionCommitment: fields.actionCommitment,
    authorization: fields.authorization ?? null,
    prev: fields.prev,
  };
  return sha256Hex(AUDIT_ENTRY_V4_DOMAIN + stableStringify(payload));
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

  const lastLine = readLastAuditLine(file);
  if (lastLine === null) return "0";
  const entry = JSON.parse(lastLine) as AuditEntry;
  if (typeof entry.commitment !== "string" || !/^[0-9a-f]{64}$/i.test(entry.commitment)) {
    throw new Error(`invalid audit log tail in ${file}`);
  }
  return entry.commitment;
}

function readLastAuditLine(file: string): string | null {
  const size = statSync(file).size;
  if (size === 0) return null;

  const fd = openSync(file, "r");
  try {
    const chunkSize = Math.min(size, AUDIT_TAIL_READ_BYTES);
    const buffer = Buffer.alloc(chunkSize);
    readSync(fd, buffer, 0, chunkSize, size - chunkSize);
    let text = buffer.toString("utf8");
    // A valid file ends every entry with a newline, so the suffix must
    // contain one unless the whole file is a single oversized line.
    if (size > chunkSize && !text.includes("\n")) {
      throw new Error(`invalid audit log tail in ${file}`);
    }
    text = text.trimEnd();
    if (!text) return null;
    const cut = text.lastIndexOf("\n");
    return cut === -1 ? text : text.slice(cut + 1);
  } finally {
    closeSync(fd);
  }
}

export function appendAuditEntry(
  agentId: string,
  entry: AuditEntry,
  storage: AuditStorage = nodeAuditStorage,
): void {
  const file = join(auditDir(agentId), "actions.jsonl");
  withAuditLock(file, storage, () => appendEntryToFile(file, entry, storage));
}

/**
 * Append a v4 entry produced by `build`, persisting the complete canonical
 * action as a content-addressed sidecar BEFORE the entry that references it.
 *
 * The sidecar write and the entry append both happen while holding the same
 * per-log lock used to choose `prev_commitment`, so the ordering is atomic with
 * respect to concurrent appends. A crash may leave an unreferenced sidecar, but
 * never a committed entry whose action evidence was not flushed first. Any
 * storage/fsync error propagates so the caller (pre-hook) can fail closed.
 */
export function appendChainedAuditEntry<
  T extends { auditEntry: AuditEntryV4; action: CanonicalToolActionV1 },
>(
  agentId: string,
  build: (prevCommitment: string) => T,
  storage: AuditStorage = nodeAuditStorage,
): T {
  // Compute the date once so the log file and its action sidecars always land
  // in the same daily directory even across a midnight boundary.
  const date = new Date().toISOString().slice(0, 10);
  const dir = auditDirForDate(agentId, date);
  const file = join(dir, "actions.jsonl");

  return withAuditLock(file, storage, () => {
    const result = build(getLastCommitmentFromFile(file));
    const entry = result.auditEntry;
    // Re-check the binding at the persistence boundary so a mismatched
    // entry/action pair can never be durably recorded.
    if (computeActionCommitment(result.action) !== entry.action_commitment) {
      throw new Error("internal error: action evidence does not match audit entry binding");
    }
    const sidecar = actionSidecarPath(agentId, date, entry.action_commitment);
    storage.writeContentAddressed(sidecar, Buffer.from(stableStringify(result.action), "utf8"));
    appendEntryToFile(file, entry, storage);
    return result;
  });
}

// `input_summary` is capped for operator readability and is NON-AUTHORITATIVE:
// the security binding is the content-addressed action sidecar plus the entry's
// action_commitment, never this display string.
function appendEntryToFile(file: string, entry: AuditEntry, storage: AuditStorage): void {
  storage.appendLine(file, JSON.stringify(entry));
}

function withAuditLock<T>(file: string, storage: AuditStorage, operation: () => T): T {
  // Durably materialize the log file (fsync new file + parent) before
  // proper-lockfile resolves its realpath, so lock setup cannot bypass the
  // new-file durability path.
  storage.createEmptyFile(file);
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

export interface AuditEntryBindings {
  reason: string;
  policyCommitment: string;
  actionCommitment: string;
}

/**
 * Build a version-4 audit entry that binds the decision to the exact
 * enforcement-time policy commitment and complete-action commitment. The caller
 * (enforcement core) computes both commitments from the normalized policy and
 * canonical action used for the decision; this function never recomputes them
 * from mutable files.
 */
export function buildEntry(
  input: ToolAction,
  decision: "allow" | "deny",
  ruleMatched: string | null,
  prevCommitment: string,
  bindings: AuditEntryBindings,
): AuditEntryV4 {
  const ts = new Date().toISOString();
  const inputSummary = summarizeInput(input);
  const authorization = extractAuthorizationAction(input);
  const phase = input.phase;
  const commitment = computeCommitmentV4({
    phase,
    tool: input.toolName,
    decision,
    ts,
    ruleMatched,
    reason: bindings.reason,
    inputSummary,
    policyCommitment: bindings.policyCommitment,
    actionCommitment: bindings.actionCommitment,
    authorization,
    prev: prevCommitment,
  });
  const entry: AuditEntryV4 = {
    commitment_version: 4,
    phase,
    ts,
    tool: input.toolName,
    decision,
    rule_matched: ruleMatched,
    reason: bindings.reason,
    policy_commitment: bindings.policyCommitment,
    action_commitment: bindings.actionCommitment,
    commitment,
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
