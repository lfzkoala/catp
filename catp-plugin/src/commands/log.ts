import { createHash } from "node:crypto";
import { readFileSync, readdirSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { auditRoot } from "../audit/paths.js";
import { findPolicyFile, loadPolicy } from "../policy/loader.js";
import { verifyChain } from "../audit/verifier.js";
import type { AuditEntry } from "../policy/types.js";

export interface AuditExport {
  exportVersion: "catp_audit_export_v1";
  agentId: string;
  logDate: string;
  entryIndex: number;
  commitment: string;
  entrySha256: string;
  entry: AuditEntry;
}

function resolveAgentId(opts: { agent?: string }): string {
  if (opts.agent) return opts.agent;
  const policyPath = findPolicyFile();
  if (!policyPath) {
    process.stderr.write("catp: no --agent id and no catp-policy.toml found\n");
    process.exit(1);
  }
  return loadPolicy(policyPath).agent.id;
}

export interface AuditLogFile {
  date: string;
  file: string;
}

function latestLogFile(agentId: string): string | null {
  const base = auditRoot(agentId);
  if (!existsSync(base)) return null;
  const dates = readdirSync(base).sort().reverse();
  if (dates.length === 0) return null;
  return join(base, dates[0], "actions.jsonl");
}

export function auditLogFiles(agentId: string): AuditLogFile[] {
  const base = auditRoot(agentId);
  if (!existsSync(base)) return [];
  return readdirSync(base)
    .sort()
    .map((date) => ({ date, file: join(base, date, "actions.jsonl") }))
    .filter(({ file }) => existsSync(file));
}

export function cmdLogShow(opts: { lines: string; agent?: string; commitments?: boolean }): void {
  const agentId = resolveAgentId(opts);
  const logFile = latestLogFile(agentId);
  if (!logFile || !existsSync(logFile)) {
    process.stdout.write(`No audit log found for agent "${agentId}"\n`);
    return;
  }

  const lines = readFileSync(logFile, "utf8").trim().split("\n").filter(Boolean);
  const n = Math.min(parseInt(opts.lines, 10) || 50, lines.length);
  const recent = lines.slice(-n);

  for (const line of recent) {
    try {
      const e = JSON.parse(line) as AuditEntry;
      const icon = e.decision === "allow" ? "✓" : "✗";
      const rule = e.rule_matched ? ` [${e.rule_matched}]` : "";
      process.stdout.write(`${icon} ${e.ts}  ${e.tool}${rule}\n    ${e.input_summary}\n`);
      if (opts.commitments) {
        process.stdout.write(`    commitment=${e.commitment}\n`);
      }
    } catch {
      process.stdout.write(`? ${line}\n`);
    }
  }
  process.stdout.write(`\n${recent.length} entries from ${logFile}\n`);
}

export async function cmdLogVerify(opts: { agent?: string }): Promise<void> {
  const agentId = resolveAgentId(opts);
  const logFiles = auditLogFiles(agentId);
  if (logFiles.length === 0) {
    process.stdout.write(`No audit log found for agent "${agentId}"\n`);
    return;
  }

  let checked = 0;
  for (const { file } of logFiles) {
    const result = await verifyChain(file);
    checked += result.checked;
    if (!result.ok) {
      process.stderr.write(`✗ Chain broken in ${file} at entry ${result.broken_at}: ${result.message}\n`);
      process.exit(1);
    }
  }
  process.stdout.write(`✓ Chain intact — ${checked} entries verified across ${logFiles.length} log file(s)\n`);
}

export function cmdLogExport(opts: { commitment?: string; agent?: string; out?: string }): void {
  if (!opts.commitment) {
    throw new Error("missing --commitment <hex>");
  }
  assertCommitment(opts.commitment);

  const agentId = resolveAgentId(opts);
  const auditExport = buildAuditExport(agentId, opts.commitment);
  const json = stableStringify(auditExport, 2) + "\n";

  if (opts.out) {
    writeFileSync(opts.out, json, "utf8");
    process.stdout.write(`Wrote audit export to ${opts.out}\n`);
    process.stdout.write(`commitment=${auditExport.commitment}\n`);
    process.stdout.write(`entrySha256=${auditExport.entrySha256}\n`);
    return;
  }

  process.stdout.write(json);
}

export function buildAuditExport(agentId: string, commitment: string): AuditExport {
  assertCommitment(commitment);
  const found = findAuditEntry(agentId, commitment);
  if (!found) {
    throw new Error(`No audit entry found for commitment ${commitment}`);
  }

  return {
    exportVersion: "catp_audit_export_v1",
    agentId,
    logDate: found.date,
    entryIndex: found.index,
    commitment: found.entry.commitment,
    entrySha256: sha256Hex(stableStringify(found.entry)),
    entry: found.entry,
  };
}

function findAuditEntry(agentId: string, commitment: string): { date: string; index: number; entry: AuditEntry } | null {
  for (const { date, file } of auditLogFiles(agentId)) {
    const lines = readFileSync(file, "utf8").split("\n").filter(Boolean);
    for (const [index, line] of lines.entries()) {
      try {
        const entry = JSON.parse(line) as AuditEntry;
        if (entry.commitment.toLowerCase() === commitment.toLowerCase()) {
          return { date, index, entry };
        }
      } catch {
        // skip malformed audit lines; chain verification reports them separately
      }
    }
  }
  return null;
}

function assertCommitment(commitment: string): void {
  if (!/^[0-9a-fA-F]{64}$/.test(commitment)) {
    throw new Error("--commitment must be a 64-character hex commitment");
  }
}

function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

export function stableStringify(value: unknown, spaces = 0): string {
  return JSON.stringify(sortForJson(value), null, spaces);
}

function sortForJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortForJson);
  }
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(Object.keys(record).sort().map((key) => [key, sortForJson(record[key])]));
  }
  return value;
}
