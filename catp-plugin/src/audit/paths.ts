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

/**
 * Directory holding the content-addressed canonical action sidecars for a given
 * agent/day: `$CATP_HOME/audit/<agent>/<YYYY-MM-DD>/actions`.
 */
export function actionsDirForDate(agentId: string, date: string): string {
  return join(auditDirForDate(agentId, date), "actions");
}

const ACTION_COMMITMENT_HEX64 = /^[0-9a-f]{64}$/;

/**
 * Absolute path of the durable sidecar storing the complete canonical action
 * whose digest is `actionCommitment`. The commitment must be a 64-character
 * lowercase hex digest so it can never escape the actions directory.
 */
export function actionSidecarPath(
  agentId: string,
  date: string,
  actionCommitment: string,
): string {
  if (!ACTION_COMMITMENT_HEX64.test(actionCommitment)) {
    throw new Error("action commitment must be a 64-character lowercase hex digest");
  }
  return join(actionsDirForDate(agentId, date), `${actionCommitment}.json`);
}
