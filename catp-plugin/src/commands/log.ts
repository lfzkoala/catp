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

interface AuditLineRecord {
  line: string;
}

export function auditLogFiles(agentId: string): AuditLogFile[] {
  const base = auditRoot(agentId);
  if (!existsSync(base)) return [];
  return readdirSync(base)
    .sort()
    .map((date) => ({ date, file: join(base, date, "actions.jsonl") }))
    .filter(({ file }) => existsSync(file));
}

export function cmdLogShow(opts: {
  lines: string;
  agent?: string;
  commitments?: boolean;
  json?: boolean;
  tool?: string;
  decision?: "allow" | "deny";
}): void {
  if (opts.decision !== undefined && opts.decision !== "allow" && opts.decision !== "deny") {
    throw new Error("--decision must be allow or deny");
  }
  const agentId = resolveAgentId(opts);
  const logFiles = auditLogFiles(agentId);
  const records = auditLineRecords(logFiles);
  if (records.length === 0) {
    if (opts.json) {
      process.stdout.write("[]\n");
      return;
    }
    process.stdout.write(`No audit log found for agent "${agentId}"\n`);
    return;
  }

  const n = Math.min(parseInt(opts.lines, 10) || 50, records.length);
  const filteredEntries = opts.tool || opts.decision ? filterAuditRecords(records, opts).slice(-n) : null;

  if (opts.json) {
    const recent = filteredEntries ?? parseAuditRecords(records.slice(-n));
    const entries = recent.map((record) => record.entry);
    process.stdout.write(stableStringify(entries, 2) + "\n");
    return;
  }

  if (filteredEntries) {
    for (const { entry } of filteredEntries) {
      writeAuditEntrySummary(entry, opts);
    }
    process.stdout.write(`\n${filteredEntries.length} matching entries from ${logFiles.length} log file(s)\n`);
    return;
  }

  const recent = records.slice(-n);
  for (const record of recent) {
    try {
      const e = JSON.parse(record.line) as AuditEntry;
      writeAuditEntrySummary(e, opts);
    } catch {
      process.stdout.write(`? ${record.line}\n`);
    }
  }
  process.stdout.write(`\n${recent.length} entries from ${logFiles.length} log file(s)\n`);
}

function auditLineRecords(logFiles: AuditLogFile[]): AuditLineRecord[] {
  return logFiles.flatMap(({ file }) =>
    readFileSync(file, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => ({ line }))
  );
}

function parseAuditRecords(records: AuditLineRecord[]): Array<{ record: AuditLineRecord; entry: AuditEntry }> {
  const entries: Array<{ record: AuditLineRecord; entry: AuditEntry }> = [];
  for (const record of records) {
    try {
      entries.push({ record, entry: JSON.parse(record.line) as AuditEntry });
    } catch {
      // Keep machine-readable output parseable; chain verification reports malformed lines.
    }
  }
  return entries;
}

function filterAuditRecords(records: AuditLineRecord[], opts: { tool?: string; decision?: "allow" | "deny" }): Array<{ record: AuditLineRecord; entry: AuditEntry }> {
  return parseAuditRecords(records).filter(({ entry }) => {
    if (opts.tool && entry.tool !== opts.tool) {
      return false;
    }
    if (opts.decision && entry.decision !== opts.decision) {
      return false;
    }
    return true;
  });
}

function writeAuditEntrySummary(e: AuditEntry, opts: { commitments?: boolean }): void {
  const icon = e.decision === "allow" ? "✓" : "✗";
  const rule = e.rule_matched ? ` [${e.rule_matched}]` : "";
  process.stdout.write(`${icon} ${e.ts}  ${e.tool}${rule}\n    ${e.input_summary}\n`);
  if (opts.commitments) {
    process.stdout.write(`    commitment=${e.commitment}\n`);
  }
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

export function cmdLogExport(opts: {
  commitment?: string;
  agent?: string;
  out?: string;
  latest?: boolean;
  tool?: string;
  decision?: "allow" | "deny";
}): void {
  const selectorCount = [opts.commitment, opts.latest ? "latest" : undefined, opts.tool].filter(Boolean).length;
  if (selectorCount > 1) {
    throw new Error("use only one of --commitment <hex>, --latest, or --tool <name>");
  }
  if (selectorCount === 0) {
    throw new Error("missing --commitment <hex>, --latest, or --tool <name>");
  }
  if (opts.decision !== undefined && opts.decision !== "allow" && opts.decision !== "deny") {
    throw new Error("--decision must be allow or deny");
  }
  if (opts.commitment && opts.decision) {
    throw new Error("--decision can only be used with --latest or --tool");
  }

  const agentId = resolveAgentId(opts);
  const commitment = resolveLogExportCommitment(agentId, opts);
  const auditExport = buildAuditExport(agentId, commitment);
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

function resolveLogExportCommitment(agentId: string, opts: { commitment?: string; latest?: boolean; tool?: string; decision?: "allow" | "deny" }): string {
  if (opts.commitment) {
    assertCommitment(opts.commitment);
    return opts.commitment;
  }
  return latestAuditCommitment(agentId, {
    ...(opts.tool ? { tool: opts.tool } : {}),
    ...(opts.decision ? { decision: opts.decision } : {}),
  });
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

export function latestAuditEntry(
  agentId: string,
  opts: { tool?: string; decision?: "allow" | "deny" } = {}
): { date: string; index: number; entry: AuditEntry } | null {
  const files = auditLogFiles(agentId).slice().reverse();
  for (const { date, file } of files) {
    const lines = readFileSync(file, "utf8").split("\n").filter(Boolean);
    for (let index = lines.length - 1; index >= 0; index -= 1) {
      try {
        const entry = JSON.parse(lines[index]) as AuditEntry;
        if (opts.tool && entry.tool !== opts.tool) {
          continue;
        }
        if (opts.decision && entry.decision !== opts.decision) {
          continue;
        }
        return { date, index, entry };
      } catch {
        // skip malformed audit lines; chain verification reports them separately
      }
    }
  }
  return null;
}

export function latestAuditCommitment(agentId: string, opts: { tool?: string; decision?: "allow" | "deny" } = {}): string {
  const latest = latestAuditEntry(agentId, opts);
  if (!latest) {
    if (opts.tool && opts.decision) {
      throw new Error(`No audit log entry found for agent "${agentId}", tool "${opts.tool}", and decision "${opts.decision}"`);
    }
    if (opts.tool) {
      throw new Error(`No audit log entry found for agent "${agentId}" and tool "${opts.tool}"`);
    }
    if (opts.decision) {
      throw new Error(`No audit log entry found for agent "${agentId}" and decision "${opts.decision}"`);
    }
    throw new Error(`No audit log entry found for agent "${agentId}"`);
  }
  return latest.entry.commitment;
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
