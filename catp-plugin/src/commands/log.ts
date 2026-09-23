import { readFileSync, readdirSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { actionSidecarPath, auditRoot } from "../audit/paths.js";
import { findPolicyFile, loadPolicy } from "../policy/loader.js";
import { verifyChain, verifyEntryChain } from "../audit/verifier.js";
import { sha256Hex, stableStringify } from "../evidence/canonical.js";
import { computeActionCommitment, type CanonicalToolActionV1 } from "../evidence/commitments.js";
import type { AuditEntry } from "../policy/types.js";

// The canonical serializer now lives in evidence/canonical.ts and is shared with
// the commitment code. It is re-exported here so existing importers (receipt.ts
// and tests) keep resolving `stableStringify` from the audit-export module.
export { stableStringify };

export interface AuditExport {
  exportVersion: "catp_audit_export_v1";
  agentId: string;
  logDate: string;
  entryIndex: number;
  commitment: string;
  entrySha256: string;
  entry: AuditEntry;
}

// Domain separator for the self-contained version-2 audit export hash.
const AUDIT_EXPORT_V2_DOMAIN = "catp:audit-export:v2\n";

/**
 * Self-contained portable evidence bundle. Unlike v1 (which carried only the
 * selected entry and its display `input_summary`), v2 embeds the daily chain
 * prefix up to the selected entry AND the complete canonical action whose digest
 * the entry commits to. `entries` runs from index 0 through `selected_index`, so
 * the selected entry is always `entries[entries.length - 1]`.
 *
 * This proves the selected entry's position within the supplied daily prefix and
 * binds it to the exact action; it does NOT prove absence of later entries or of
 * other undisclosed logs.
 */
export interface AuditExportV2Body {
  export_version: "catp_audit_export_v2";
  agent_id: string;
  log_date: string;
  selected_index: number;
  entries: AuditEntry[];
  action: CanonicalToolActionV1;
}

export interface AuditExportV2 extends AuditExportV2Body {
  export_sha256: string;
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
  const auditExport = buildAuditExportV2(agentId, commitment);
  const json = stableStringify(auditExport, 2) + "\n";

  if (opts.out) {
    writeFileSync(opts.out, json, "utf8");
    process.stdout.write(`Wrote audit export to ${opts.out}\n`);
    process.stdout.write(`commitment=${commitment}\n`);
    process.stdout.write(`exportSha256=${auditExport.export_sha256}\n`);
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

/**
 * Build the self-contained version-2 export for a commitment. Before bundling:
 * verify the daily chain prefix offline, require the selected entry to be
 * commitment version 4, load its content-addressed action sidecar, and require
 * `computeActionCommitment(action) === entry.action_commitment`. Missing or
 * mismatched evidence is rejected so a v2 bundle always carries the exact action.
 */
export function buildAuditExportV2(agentId: string, commitment: string): AuditExportV2 {
  assertCommitment(commitment);
  const found = findAuditEntry(agentId, commitment);
  if (!found) {
    throw new Error(`No audit entry found for commitment ${commitment}`);
  }
  const selected = found.entry;
  if (selected.commitment_version !== 4) {
    throw new Error("audit export v2 requires a commitment version 4 selected entry");
  }

  const file = join(auditRoot(agentId), found.date, "actions.jsonl");
  const rawLines = readFileSync(file, "utf8").split("\n").filter(Boolean);
  const parsed: AuditEntry[] = [];
  for (let i = 0; i < rawLines.length; i++) {
    try {
      parsed.push(JSON.parse(rawLines[i]) as AuditEntry);
    } catch {
      // Fail closed with the same line-oriented diagnostic verifyChain uses,
      // rather than leaking a raw SyntaxError.
      throw new Error(`audit log ${file} line ${i + 1}: invalid JSON`);
    }
  }
  const entries = parsed.slice(0, found.index + 1);
  const verification = verifyEntryChain(entries);
  if (!verification.ok) {
    throw new Error(`audit chain verification failed at entry ${verification.broken_at}: ${verification.message}`);
  }
  if (entries.length !== found.index + 1) {
    throw new Error("internal error: audit export prefix length does not match selected_index + 1");
  }

  const sidecar = actionSidecarPath(agentId, found.date, selected.action_commitment);
  if (!existsSync(sidecar)) {
    throw new Error(`missing action evidence sidecar for commitment ${commitment}`);
  }
  const action = JSON.parse(readFileSync(sidecar, "utf8")) as CanonicalToolActionV1;
  if (computeActionCommitment(action) !== selected.action_commitment) {
    throw new Error("action evidence does not match the audit entry action_commitment");
  }

  const body: AuditExportV2Body = {
    export_version: "catp_audit_export_v2",
    agent_id: agentId,
    log_date: found.date,
    selected_index: found.index,
    entries,
    action,
  };
  const export_sha256 = sha256Hex(AUDIT_EXPORT_V2_DOMAIN + stableStringify(body));
  return { ...body, export_sha256 };
}

export function latestAuditEntry(
  agentId: string,
  opts: { tool?: string; decision?: "allow" | "deny"; phase?: "pre" | "post" } = {}
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
        if (opts.phase && entry.phase !== undefined && entry.phase !== opts.phase) {
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

export function latestAuditCommitment(
  agentId: string,
  opts: { tool?: string; decision?: "allow" | "deny"; phase?: "pre" | "post" } = {},
): string {
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


