import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";
import { computeCommitment, computeCommitmentV4 } from "./logger.js";
import type { AuditEntry } from "../policy/types.js";

export interface VerifyResult {
  ok: boolean;
  checked: number;
  broken_at: number | null;
  message: string;
}

const HEX64 = /^[0-9a-f]{64}$/;

export async function verifyChain(logFile: string): Promise<VerifyResult> {
  const lines = await readLines(logFile);
  if (lines.length === 0) {
    return { ok: true, checked: 0, broken_at: null, message: "empty log" };
  }

  const entries: AuditEntry[] = [];
  for (let i = 0; i < lines.length; i++) {
    try {
      entries.push(JSON.parse(lines[i]) as AuditEntry);
    } catch {
      return { ok: false, checked: i, broken_at: i, message: `line ${i + 1}: invalid JSON` };
    }
  }
  return verifyEntryChain(entries);
}

/**
 * Pure chain validation over already-parsed entries. Both the on-disk
 * `verifyChain` wrapper and offline audit-export verification delegate here, so
 * the exact same commitment rules apply to a live daily log and to a portable
 * export bundle. `broken_at`/`checked` are entry indices (0-based); messages use
 * the human-facing 1-based `line N` wording shared with the file wrapper.
 */
export function verifyEntryChain(entries: AuditEntry[]): VerifyResult {
  if (entries.length === 0) {
    return { ok: true, checked: 0, broken_at: null, message: "empty log" };
  }

  let prev = "0";
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];

    const decision = entry.decision as "allow" | "deny";
    const version = entry.commitment_version;
    if (
      version !== undefined &&
      version !== 1 &&
      version !== 2 &&
      version !== 3 &&
      version !== 4
    ) {
      return {
        ok: false,
        checked: i,
        broken_at: i,
        message: `line ${i + 1}: unsupported commitment version`,
      };
    }

    let expected: string;
    if (entry.commitment_version === 4) {
      // Version 4 binds the decision to the enforcement-time policy and the
      // complete normalized action. Require both bindings present and
      // lowercase-hex, plus a valid phase, before recomputing.
      if (typeof entry.reason !== "string") {
        return { ok: false, checked: i, broken_at: i, message: `line ${i + 1}: commitment version 4 requires a reason` };
      }
      if (typeof entry.policy_commitment !== "string" || !HEX64.test(entry.policy_commitment)) {
        return { ok: false, checked: i, broken_at: i, message: `line ${i + 1}: commitment version 4 requires a lowercase-hex policy_commitment` };
      }
      if (typeof entry.action_commitment !== "string" || !HEX64.test(entry.action_commitment)) {
        return { ok: false, checked: i, broken_at: i, message: `line ${i + 1}: commitment version 4 requires a lowercase-hex action_commitment` };
      }
      if (entry.phase !== "pre" && entry.phase !== "post") {
        return { ok: false, checked: i, broken_at: i, message: `line ${i + 1}: commitment version 4 requires a valid phase` };
      }
      expected = computeCommitmentV4({
        phase: entry.phase,
        tool: entry.tool,
        decision,
        ts: entry.ts,
        ruleMatched: entry.rule_matched,
        reason: entry.reason,
        inputSummary: entry.input_summary,
        policyCommitment: entry.policy_commitment,
        actionCommitment: entry.action_commitment,
        authorization: entry.authorization,
        prev,
      });
    } else {
      const commitmentVersion = entry.commitment_version ?? 1;
      if (commitmentVersion === 3 && entry.phase !== "pre" && entry.phase !== "post") {
        return {
          ok: false,
          checked: i,
          broken_at: i,
          message: `line ${i + 1}: commitment version 3 requires a valid phase`,
        };
      }
      expected = computeCommitment(
        entry.tool,
        decision,
        entry.ts,
        prev,
        entry.rule_matched,
        entry.input_summary,
        entry.authorization,
        commitmentVersion,
        entry.phase,
      );
    }
    if (entry.commitment !== expected) {
      return {
        ok: false,
        checked: i,
        broken_at: i,
        message: `line ${i + 1}: commitment mismatch (chain broken or tampered)`,
      };
    }
    prev = entry.commitment;
  }

  return { ok: true, checked: entries.length, broken_at: null, message: "chain intact" };
}

async function readLines(file: string): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const lines: string[] = [];
    const rl = createInterface({ input: createReadStream(file), crlfDelay: Infinity });
    rl.on("line", (l) => { if (l.trim()) lines.push(l); });
    rl.on("close", () => resolve(lines));
    rl.on("error", reject);
  });
}
