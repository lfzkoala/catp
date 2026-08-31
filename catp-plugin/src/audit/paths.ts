import { homedir } from "node:os";
import { join } from "node:path";

export function catpHome(): string {
  return process.env.CATP_HOME ?? join(homedir(), ".catp");
}

export function validateAgentId(agentId: string): string {
  if (!/^[A-Za-z0-9._-]+$/.test(agentId) || agentId === "." || agentId === "..") {
    throw new Error("agent id may contain only letters, numbers, dots, underscores, and hyphens");
  }
  return agentId;
}

export function auditRoot(agentId: string): string {
  return join(catpHome(), "audit", validateAgentId(agentId));
}

export function auditDirForDate(agentId: string, date: string): string {
  return join(auditRoot(agentId), date);
}
