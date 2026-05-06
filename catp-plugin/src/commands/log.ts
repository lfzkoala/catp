import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { auditRoot } from "../audit/paths.js";
import { findPolicyFile, loadPolicy } from "../policy/loader.js";
import { verifyChain } from "../audit/verifier.js";
import type { AuditEntry } from "../policy/types.js";

function resolveAgentId(opts: { agent?: string }): string {
  if (opts.agent) return opts.agent;
  const policyPath = findPolicyFile();
  if (!policyPath) {
    process.stderr.write("catp: no --agent id and no catp-policy.toml found\n");
    process.exit(1);
  }
  return loadPolicy(policyPath).agent.id;
}

function latestLogFile(agentId: string): string | null {
  const base = auditRoot(agentId);
  if (!existsSync(base)) return null;
  const dates = readdirSync(base).sort().reverse();
  if (dates.length === 0) return null;
  return join(base, dates[0], "actions.jsonl");
}

function allLogFiles(agentId: string): string[] {
  const base = auditRoot(agentId);
  if (!existsSync(base)) return [];
  return readdirSync(base)
    .sort()
    .map((date) => join(base, date, "actions.jsonl"))
    .filter((file) => existsSync(file));
}

export function cmdLogShow(opts: { lines: string; agent?: string }): void {
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
    } catch {
      process.stdout.write(`? ${line}\n`);
    }
  }
  process.stdout.write(`\n${recent.length} entries from ${logFile}\n`);
}

export async function cmdLogVerify(opts: { agent?: string }): Promise<void> {
  const agentId = resolveAgentId(opts);
  const logFiles = allLogFiles(agentId);
  if (logFiles.length === 0) {
    process.stdout.write(`No audit log found for agent "${agentId}"\n`);
    return;
  }

  let checked = 0;
  for (const logFile of logFiles) {
    const result = await verifyChain(logFile);
    checked += result.checked;
    if (!result.ok) {
      process.stderr.write(`✗ Chain broken in ${logFile} at entry ${result.broken_at}: ${result.message}\n`);
      process.exit(1);
    }
  }
  process.stdout.write(`✓ Chain intact — ${checked} entries verified across ${logFiles.length} log file(s)\n`);
}
