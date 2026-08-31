import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { auditRoot } from "../audit/paths.js";
import { verifyChain } from "../audit/verifier.js";
import { auditLogFiles } from "./log.js";
import { findPolicyFile, loadPolicy } from "../policy/loader.js";
import type { AuditEntry } from "../policy/types.js";

export interface AuditAnchorBundle {
  anchorVersion: "catp_audit_anchor_v1";
  agentId: string;
  commitmentCount: number;
  merkleRoot: `0x${string}`;
}

function resolveAgentId(opts: { agent?: string }): string {
  if (opts.agent) return opts.agent;
  const policyPath = findPolicyFile();
  if (policyPath) {
    try {
      return loadPolicy(policyPath).agent.id;
    } catch {
      // fall through
    }
  }
  throw new Error(
    "Could not determine agent ID. Specify --agent <id> or run from a directory with catp-policy.toml.",
  );
}

export function readCommitments(agentId: string): string[] {
  const baseDir = auditRoot(agentId);
  if (!existsSync(baseDir)) return [];

  const commitments: string[] = [];
  const dates = readdirSync(baseDir).sort();
  for (const date of dates) {
    const file = join(baseDir, date, "actions.jsonl");
    if (!existsSync(file)) continue;
    const lines = readFileSync(file, "utf8").trimEnd().split("\n").filter(Boolean);
    for (let index = 0; index < lines.length; index++) {
      let entry: AuditEntry;
      try {
        entry = JSON.parse(lines[index]) as AuditEntry;
      } catch {
        throw new Error(`invalid JSON in ${file} at line ${index + 1}`);
      }
      if (typeof entry.commitment !== "string" || !/^[0-9a-f]{64}$/i.test(entry.commitment)) {
        throw new Error(`invalid commitment in ${file} at line ${index + 1}`);
      }
      commitments.push(entry.commitment);
    }
  }
  return commitments;
}

export function merkleRoot(commitments: string[]): `0x${string}` {
  if (commitments.length === 0) {
    return `0x${"00".repeat(32)}`;
  }

  let level: Buffer[] = commitments.map((c) => {
    const b = Buffer.from(c, "hex");
    return b.length === 32 ? b : createHash("sha256").update(c).digest();
  });

  while (level.length > 1) {
    if (level.length % 2 !== 0) {
      level.push(level[level.length - 1]);
    }
    const next: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(
        createHash("sha256").update(level[i]).update(level[i + 1]).digest(),
      );
    }
    level = next;
  }

  return `0x${level[0].toString("hex")}`;
}

export async function cmdAnchor(opts: {
  agent?: string;
  out?: string;
}): Promise<void> {
  const agentId = resolveAgentId(opts);
  const logFiles = auditLogFiles(agentId);
  for (const { file } of logFiles) {
    const result = await verifyChain(file);
    if (!result.ok) {
      throw new Error(`audit chain broken in ${file}: ${result.message}`);
    }
  }

  const commitments = readCommitments(agentId);
  const root = merkleRoot(commitments);

  process.stdout.write(`Agent:       ${agentId}\n`);
  process.stdout.write(`Commitments: ${commitments.length}\n`);
  process.stdout.write(`Merkle root: ${root}\n`);

  if (commitments.length === 0) {
    process.stdout.write("No audit entries found — nothing to anchor.\n");
    return;
  }

  if (opts.out) {
    const bundle: AuditAnchorBundle = {
      anchorVersion: "catp_audit_anchor_v1",
      agentId,
      commitmentCount: commitments.length,
      merkleRoot: root,
    };
    mkdirSync(dirname(opts.out), { recursive: true });
    writeFileSync(opts.out, JSON.stringify(bundle, null, 2) + "\n", "utf8");
    process.stdout.write(`Anchor bundle written to ${opts.out}\n`);
  }
}
