import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { auditRoot } from "../audit/paths.js";
import { findPolicyFile, loadPolicy } from "../policy/loader.js";
import type { AuditEntry, AuthorizationAction, AuthorizationConfig, CatpPolicy } from "../policy/types.js";

const MAX_U64 = (1n << 64n) - 1n;

const ACTION_TYPE: Record<string, string> = {
  swap: "0",
  transfer: "1",
  deposit: "2",
  withdraw: "3",
};

export type WitnessActionInput = AuthorizationAction;

export interface Groth16Witness {
  actionType: string;
  protocol: string;
  token: string;
  value: string;
  currentTimestamp: string;
  cumulativeSpend: string;
  allowedAction: string;
  allowedProtocol: string;
  allowedToken: string;
  maxValuePerTx: string;
  maxValueTotal: string;
  validFrom: string;
  validUntil: string;
}

export function buildGroth16Witness(
  policy: CatpPolicy,
  action: WitnessActionInput,
  opts: { currentTimestamp?: string | number; cumulativeSpend?: string | number } = {},
): Groth16Witness {
  if (!policy.authorization) {
    throw new Error("catp-policy.toml is missing [authorization]");
  }

  const auth = normalizeAuthorization(policy.authorization);
  const actionType = normalizeActionType(action.actionType, "actionType");
  const value = normalizeU64(action.value, "value");
  const currentTimestamp = normalizeU64(
    opts.currentTimestamp ?? action.currentTimestamp ?? Math.floor(Date.now() / 1000),
    "currentTimestamp",
  );
  const cumulativeSpend = normalizeU64(opts.cumulativeSpend ?? action.cumulativeSpend ?? "0", "cumulativeSpend");
  const protocol = normalizeBytes32(action.protocol, "protocol");
  const token = normalizeBytes32(action.token, "token");

  if (actionType !== auth.allowedAction) {
    throw new Error("actionType must match authorization.allowed_action");
  }
  if (protocol.toLowerCase() !== auth.allowedProtocol.toLowerCase()) {
    throw new Error("protocol must match authorization.allowed_protocol");
  }
  if (token.toLowerCase() !== auth.allowedToken.toLowerCase()) {
    throw new Error("token must match authorization.allowed_token");
  }

  return {
    actionType,
    protocol,
    token,
    value,
    currentTimestamp,
    cumulativeSpend,
    allowedAction: auth.allowedAction,
    allowedProtocol: auth.allowedProtocol,
    allowedToken: auth.allowedToken,
    maxValuePerTx: auth.maxValuePerTx,
    maxValueTotal: auth.maxValueTotal,
    validFrom: auth.validFrom,
    validUntil: auth.validUntil,
  };
}

export function cmdWitness(opts: {
  action?: string;
  auditCommitment?: string;
  agent?: string;
  file?: string;
  out?: string;
  currentTimestamp?: string;
  cumulativeSpend?: string;
}): void {
  const witness = buildGroth16WitnessFromSources(opts);
  const encoded = `${JSON.stringify(witness, null, 2)}\n`;

  if (opts.out) {
    writeFileSync(opts.out, encoded, "utf8");
    process.stdout.write(`Wrote Groth16 witness to ${opts.out}\n`);
    process.stdout.write(formatGroth16WitnessSummary(witness));
  } else {
    process.stdout.write(encoded);
  }
}

export function formatGroth16WitnessSummary(witness: Groth16Witness): string {
  const lines = [
    "proofVersion=authorization_groth16_v1",
    `actionType=${witness.actionType}`,
    `value=${witness.value}`,
    `currentTimestamp=${witness.currentTimestamp}`,
    `cumulativeSpend=${witness.cumulativeSpend}`,
    `maxValuePerTx=${witness.maxValuePerTx}`,
    `maxValueTotal=${witness.maxValueTotal}`,
    `validFrom=${witness.validFrom}`,
    `validUntil=${witness.validUntil}`,
    "next=Run catp prove authorization with the same policy/action inputs to generate a proof manifest.",
  ];
  return `${lines.join("\n")}\n`;
}

export function buildGroth16WitnessFromSources(opts: {
  action?: string;
  auditCommitment?: string;
  agent?: string;
  file?: string;
  currentTimestamp?: string;
  cumulativeSpend?: string;
}): Groth16Witness {
  if (!opts.action && !opts.auditCommitment) {
    throw new Error("missing --action <path> or --audit-commitment <hex>");
  }
  if (opts.action && opts.auditCommitment) {
    throw new Error("use only one of --action or --audit-commitment");
  }

  const policyPath = opts.file ?? findPolicyFile();
  if (!policyPath) {
    throw new Error("Could not find catp-policy.toml. Specify --file <path>.");
  }

  const policy = loadPolicy(policyPath);
  const action = opts.action
    ? (JSON.parse(readFileSync(opts.action, "utf8")) as WitnessActionInput)
    : readAuthorizationActionFromAudit(resolveAgentId(policy, opts.agent), opts.auditCommitment as string);

  return buildGroth16Witness(policy, action, {
    currentTimestamp: opts.currentTimestamp,
    cumulativeSpend: opts.cumulativeSpend,
  });
}

function resolveAgentId(policy: CatpPolicy, agent?: string): string {
  return agent ?? policy.agent.id;
}

function readAuthorizationActionFromAudit(agentId: string, commitment: string): WitnessActionInput {
  if (!/^[0-9a-fA-F]{64}$/.test(commitment)) {
    throw new Error("--audit-commitment must be a 64-character hex commitment");
  }
  const entry = findAuditEntry(agentId, commitment);
  if (!entry) {
    throw new Error(`No audit entry found for commitment ${commitment}`);
  }
  if (!entry.authorization) {
    throw new Error(`Audit entry ${commitment} does not contain authorization action data`);
  }
  return entry.authorization;
}

function findAuditEntry(agentId: string, commitment: string): AuditEntry | null {
  const root = auditRoot(agentId);
  if (!existsSync(root)) return null;
  for (const date of readdirSync(root).sort()) {
    const file = join(root, date, "actions.jsonl");
    if (!existsSync(file)) continue;
    const lines = readFileSync(file, "utf8").trimEnd().split("\n").filter(Boolean);
    for (const line of lines) {
      try {
        const entry = JSON.parse(line) as AuditEntry;
        if (entry.commitment.toLowerCase() === commitment.toLowerCase()) {
          return entry;
        }
      } catch {
        // skip malformed audit lines
      }
    }
  }
  return null;
}

function normalizeAuthorization(auth: AuthorizationConfig) {
  return {
    allowedAction: normalizeActionType(auth.allowed_action, "authorization.allowed_action"),
    allowedProtocol: normalizeBytes32(auth.allowed_protocol, "authorization.allowed_protocol"),
    allowedToken: normalizeBytes32(auth.allowed_token, "authorization.allowed_token"),
    maxValuePerTx: normalizeU64(auth.max_value_per_tx, "authorization.max_value_per_tx"),
    maxValueTotal: normalizeU64(auth.max_value_total, "authorization.max_value_total"),
    validFrom: normalizeU64(auth.valid_from, "authorization.valid_from"),
    validUntil: normalizeU64(auth.valid_until, "authorization.valid_until"),
  };
}

function normalizeActionType(value: string | number, field: string): string {
  if (typeof value === "string" && ACTION_TYPE[value.toLowerCase()] !== undefined) {
    return ACTION_TYPE[value.toLowerCase()];
  }
  const parsed = normalizeU64(value, field);
  if (!["0", "1", "2", "3"].includes(parsed)) {
    throw new Error(`${field} must be Swap, Transfer, Deposit, Withdraw, or 0..3`);
  }
  return parsed;
}

function normalizeBytes32(value: string, field: string): string {
  if (!/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${field} must be a 0x-prefixed 32-byte hex string`);
  }
  return value;
}

function normalizeU64(value: string | number, field: string): string {
  let parsed: bigint;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new Error(`${field} must be a safe integer`);
    }
    parsed = BigInt(value);
  } else if (/^0x[0-9a-fA-F]+$/.test(value) || /^[0-9]+$/.test(value)) {
    parsed = BigInt(value);
  } else {
    throw new Error(`${field} must be an integer string`);
  }
  if (parsed < 0n || parsed > MAX_U64) {
    throw new Error(`${field} must fit in u64`);
  }
  return parsed.toString();
}
