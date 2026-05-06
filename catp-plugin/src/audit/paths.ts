import { homedir } from "node:os";
import { join } from "node:path";

export function catpHome(): string {
  return process.env.CATP_HOME ?? join(homedir(), ".catp");
}

export function auditRoot(agentId: string): string {
  return join(catpHome(), "audit", agentId);
}

export function auditDirForDate(agentId: string, date: string): string {
  return join(auditRoot(agentId), date);
}
