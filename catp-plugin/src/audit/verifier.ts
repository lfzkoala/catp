import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";
import { computeCommitment } from "./logger.js";
import type { AuditEntry } from "../policy/types.js";

export interface VerifyResult {
  ok: boolean;
  checked: number;
  broken_at: number | null;
  message: string;
}

export async function verifyChain(logFile: string): Promise<VerifyResult> {
  const lines = await readLines(logFile);
  if (lines.length === 0) {
    return { ok: true, checked: 0, broken_at: null, message: "empty log" };
  }

  let prev = "0";
  for (let i = 0; i < lines.length; i++) {
    let entry: AuditEntry;
    try {
      entry = JSON.parse(lines[i]) as AuditEntry;
    } catch {
      return { ok: false, checked: i, broken_at: i, message: `line ${i + 1}: invalid JSON` };
    }

    const decision = entry.decision as "allow" | "deny";
    if (entry.commitment_version !== undefined && entry.commitment_version !== 1 && entry.commitment_version !== 2) {
      return {
        ok: false,
        checked: i,
        broken_at: i,
        message: `line ${i + 1}: unsupported commitment version`,
      };
    }
    const commitmentVersion = entry.commitment_version ?? 1;
    const expected = computeCommitment(
      entry.tool,
      decision,
      entry.ts,
      prev,
      entry.rule_matched,
      entry.input_summary,
      entry.authorization,
      commitmentVersion,
    );
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

  return { ok: true, checked: lines.length, broken_at: null, message: "chain intact" };
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
