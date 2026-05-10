import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildGroth16WitnessFromSources } from "./witness.js";
import { auditRoot } from "../audit/paths.js";
import { findPolicyFile, loadPolicy } from "../policy/loader.js";
import type { AuditEntry } from "../policy/types.js";

const PROOF_VERSION = "authorization_groth16_v1";

export interface AuthorizationProofArtifact {
  proofVersion: string;
  policyCommitment: string;
  publicInputs: string[];
  actionData: string;
  currentTimestamp: string | number;
  cumulativeSpend: string | number;
  value: string | number;
  proof: string;
  constraintCount?: number;
}

export interface AuthorizationProofManifest {
  manifestVersion: "catp_authorization_proof_manifest_v1";
  proofVersion: "authorization_groth16_v1";
  auditCommitment: string | null;
  auditAgent: string | null;
  policyCommitment: string;
  publicInputs: string[];
  actionData: string;
  currentTimestamp: string;
  cumulativeSpend: string;
  value: string;
  proof: string;
  verifier: string | null;
  agentAuthorizer: string | null;
  chainId: string | null;
  proofUrl: string | null;
  sourceArtifact: string | null;
}

export function buildAuthorizationProofManifest(
  artifact: AuthorizationProofArtifact,
  opts: {
    auditCommitment?: string;
    auditAgent?: string;
    verifier?: string;
    agentAuthorizer?: string;
    chainId?: string;
    proofUrl?: string;
    sourceArtifact?: string;
  } = {},
): AuthorizationProofManifest {
  validateGroth16Artifact(artifact);

  if (opts.auditCommitment !== undefined) {
    assertCommitment(opts.auditCommitment, "auditCommitment");
  }
  if (opts.auditAgent !== undefined) {
    assertNonEmptyString(opts.auditAgent, "auditAgent");
  }
  if (opts.verifier !== undefined) {
    assertAddress(opts.verifier, "verifier");
  }
  if (opts.agentAuthorizer !== undefined) {
    assertAddress(opts.agentAuthorizer, "agentAuthorizer");
  }
  if (opts.chainId !== undefined && !/^[0-9]+$/.test(opts.chainId)) {
    throw new Error("chainId must be a decimal integer string");
  }

  return {
    manifestVersion: "catp_authorization_proof_manifest_v1",
    proofVersion: PROOF_VERSION,
    auditCommitment: opts.auditCommitment ?? null,
    auditAgent: opts.auditAgent ?? null,
    policyCommitment: artifact.policyCommitment,
    publicInputs: artifact.publicInputs,
    actionData: artifact.actionData,
    currentTimestamp: normalizeIntegerString(artifact.currentTimestamp, "currentTimestamp"),
    cumulativeSpend: normalizeIntegerString(artifact.cumulativeSpend, "cumulativeSpend"),
    value: normalizeIntegerString(artifact.value, "value"),
    proof: artifact.proof,
    verifier: opts.verifier ?? null,
    agentAuthorizer: opts.agentAuthorizer ?? null,
    chainId: opts.chainId ?? null,
    proofUrl: opts.proofUrl ?? null,
    sourceArtifact: opts.sourceArtifact ?? null,
  };
}

export function validateAuthorizationProofManifest(manifest: AuthorizationProofManifest): void {
  if (manifest.manifestVersion !== "catp_authorization_proof_manifest_v1") {
    throw new Error("manifestVersion must be catp_authorization_proof_manifest_v1");
  }
  validateGroth16Artifact({
    proofVersion: manifest.proofVersion,
    policyCommitment: manifest.policyCommitment,
    publicInputs: manifest.publicInputs,
    actionData: manifest.actionData,
    currentTimestamp: manifest.currentTimestamp,
    cumulativeSpend: manifest.cumulativeSpend,
    value: manifest.value,
    proof: manifest.proof,
  });
  if (manifest.auditCommitment !== null) {
    assertCommitment(manifest.auditCommitment, "auditCommitment");
  }
  if (manifest.auditAgent !== null) {
    assertNonEmptyString(manifest.auditAgent, "auditAgent");
  }
  if (manifest.verifier !== null) {
    assertAddress(manifest.verifier, "verifier");
  }
  if (manifest.agentAuthorizer !== null) {
    assertAddress(manifest.agentAuthorizer, "agentAuthorizer");
  }
  if (manifest.chainId !== null && !/^[0-9]+$/.test(manifest.chainId)) {
    throw new Error("chainId must be a decimal integer string");
  }
}

export function cmdProveAuthorization(opts: {
  artifact?: string;
  action?: string;
  auditCommitment?: string;
  agent?: string;
  file?: string;
  currentTimestamp?: string;
  cumulativeSpend?: string;
  artifactOut?: string;
  witnessOut?: string;
  proverScript?: string;
  verifier?: string;
  agentAuthorizer?: string;
  chainId?: string;
  proofUrl?: string;
  out?: string;
}): void {
  if (opts.artifact && opts.action) {
    throw new Error("use --artifact or --action, not both");
  }

  let artifactPath = opts.artifact;
  let cleanupDir: string | null = null;
  if (!artifactPath) {
    const generated = generateGroth16Artifact(opts);
    artifactPath = generated.artifactPath;
    cleanupDir = generated.cleanupDir;
  }

  if (!existsSync(artifactPath)) {
    if (cleanupDir) rmSync(cleanupDir, { recursive: true, force: true });
    throw new Error(`artifact not found: ${artifactPath}`);
  }

  try {
    const artifact = JSON.parse(readFileSync(artifactPath, "utf8")) as AuthorizationProofArtifact;
    const manifest = buildAuthorizationProofManifest(artifact, {
      auditCommitment: opts.auditCommitment,
      auditAgent: resolveAuditAgent(opts),
      verifier: opts.verifier,
      agentAuthorizer: opts.agentAuthorizer,
      chainId: opts.chainId,
      proofUrl: opts.proofUrl,
      sourceArtifact: opts.artifact ?? opts.artifactOut ?? undefined,
    });
    const encoded = `${JSON.stringify(manifest, null, 2)}\n`;

    if (opts.out) {
      writeFileSync(opts.out, encoded, "utf8");
      process.stdout.write(`Wrote authorization proof manifest to ${opts.out}\n`);
    } else {
      process.stdout.write(encoded);
    }
  } finally {
    if (cleanupDir) {
      rmSync(cleanupDir, { recursive: true, force: true });
    }
  }
}

export function cmdVerifyAuthorization(opts: { manifest?: string; checkAudit?: boolean; auditAgent?: string }): void {
  if (!opts.manifest) {
    throw new Error("missing --manifest <path>");
  }
  if (!existsSync(opts.manifest)) {
    throw new Error(`manifest not found: ${opts.manifest}`);
  }

  const manifest = JSON.parse(readFileSync(opts.manifest, "utf8")) as AuthorizationProofManifest;
  validateAuthorizationProofManifest(manifest);
  const lines = [
    "Authorization proof manifest is structurally valid.",
    `proofVersion=${manifest.proofVersion}`,
    `policyCommitment=${manifest.policyCommitment}`,
    `auditCommitment=${manifest.auditCommitment ?? "none"}`,
  ];
  if (opts.checkAudit) {
    const auditAgent = opts.auditAgent ?? manifest.auditAgent;
    if (!manifest.auditCommitment) {
      throw new Error("manifest has no auditCommitment to check");
    }
    if (!auditAgent) {
      throw new Error("missing --audit-agent <id>; manifest does not include auditAgent");
    }
    if (!findAuditEntry(auditAgent, manifest.auditCommitment)) {
      throw new Error(`No audit entry found for commitment ${manifest.auditCommitment}`);
    }
    lines.push(`auditEntry=found:${auditAgent}`);
  }
  process.stdout.write(`${lines.join("\n")}\n`);
}

function validateGroth16Artifact(artifact: AuthorizationProofArtifact): void {
  if (artifact.proofVersion !== PROOF_VERSION) {
    throw new Error(`proofVersion must be ${PROOF_VERSION}`);
  }
  assertBytes32(artifact.policyCommitment, "policyCommitment");
  assertHex(artifact.actionData, "actionData");
  assertHex(artifact.proof, "proof");
  if (hexByteLength(artifact.proof) !== 256) {
    throw new Error("proof must be 256 bytes");
  }
  if (!Array.isArray(artifact.publicInputs) || artifact.publicInputs.length !== 13) {
    throw new Error("publicInputs must contain 13 values");
  }
  for (const [index, input] of artifact.publicInputs.entries()) {
    assertBytes32(input, `publicInputs[${index}]`);
  }
  if (artifact.publicInputs[0].toLowerCase() !== artifact.policyCommitment.toLowerCase()) {
    throw new Error("publicInputs[0] must equal policyCommitment");
  }

  const value = normalizePositiveU64(artifact.value, "value");
  const currentTimestamp = normalizeU64(artifact.currentTimestamp, "currentTimestamp");
  const cumulativeSpend = normalizeU64(artifact.cumulativeSpend, "cumulativeSpend");
  if (normalizeU64(artifact.publicInputs[10], "publicInputs[10]") !== value) {
    throw new Error("publicInputs[10] must equal value");
  }
  if (normalizeU64(artifact.publicInputs[11], "publicInputs[11]") !== currentTimestamp) {
    throw new Error("publicInputs[11] must equal currentTimestamp");
  }
  if (normalizeU64(artifact.publicInputs[12], "publicInputs[12]") !== cumulativeSpend) {
    throw new Error("publicInputs[12] must equal cumulativeSpend");
  }
}

function generateGroth16Artifact(opts: {
  action?: string;
  auditCommitment?: string;
  agent?: string;
  file?: string;
  currentTimestamp?: string;
  cumulativeSpend?: string;
  artifactOut?: string;
  witnessOut?: string;
  proverScript?: string;
}): { artifactPath: string; cleanupDir: string | null } {
  if (!opts.action && !opts.auditCommitment) {
    throw new Error("missing --artifact <path>, --action <path>, or --audit-commitment <hex>");
  }
  if (opts.action && opts.auditCommitment) {
    throw new Error("use only one of --action or --audit-commitment");
  }

  const cleanupDir = opts.artifactOut && opts.witnessOut ? null : mkdtempSync(join(tmpdir(), "catp-prove-"));
  const witnessPath = opts.witnessOut ?? join(cleanupDir as string, "authorization_groth16_v1.witness.json");
  const artifactPath = opts.artifactOut ?? join(cleanupDir as string, "authorization_groth16_v1.json");
  const proverScript = opts.proverScript ?? join(process.cwd(), "scripts", "generate-groth16-verifier.sh");
  if (!existsSync(proverScript)) {
    if (cleanupDir) rmSync(cleanupDir, { recursive: true, force: true });
    throw new Error(`prover script not found: ${proverScript}`);
  }

  const witness = buildGroth16WitnessFromSources({
    action: opts.action,
    auditCommitment: opts.auditCommitment,
    agent: opts.agent,
    file: opts.file,
    currentTimestamp: opts.currentTimestamp,
    cumulativeSpend: opts.cumulativeSpend,
  });
  writeFileSync(witnessPath, `${JSON.stringify(witness, null, 2)}\n`, "utf8");

  execFileSync("bash", [
    proverScript,
    "--witness",
    witnessPath,
    "--out",
    artifactPath,
  ], { stdio: "inherit" });

  return { artifactPath, cleanupDir };
}

function resolveAuditAgent(opts: { auditCommitment?: string; agent?: string; file?: string }): string | undefined {
  if (!opts.auditCommitment) return undefined;
  if (opts.agent) return opts.agent;
  const policyPath = opts.file ?? findPolicyFile();
  if (!policyPath) return undefined;
  return loadPolicy(policyPath).agent.id;
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

function normalizeIntegerString(value: string | number, field: string): string {
  return normalizeU64(value, field);
}

function normalizePositiveU64(value: string | number, field: string): string {
  const parsed = BigInt(normalizeU64(value, field));
  if (parsed === 0n) {
    throw new Error(`${field} must be between 1 and u64::MAX`);
  }
  return parsed.toString();
}

function normalizeU64(value: string | number, field: string): string {
  const parsed = parseInteger(value, field);
  const max = (1n << 64n) - 1n;
  if (parsed < 0n || parsed > max) {
    throw new Error(`${field} must fit in u64`);
  }
  return parsed.toString();
}

function parseInteger(value: string | number, field: string): bigint {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new Error(`${field} must be a safe integer`);
    }
    return BigInt(value);
  }
  if (/^0x[0-9a-fA-F]+$/.test(value)) return BigInt(value);
  if (/^[0-9]+$/.test(value)) return BigInt(value);
  throw new Error(`${field} must be an integer string`);
}

function assertHex(value: string, field: string): void {
  if (!/^0x([0-9a-fA-F]{2})*$/.test(value)) {
    throw new Error(`${field} must be an even-length 0x-prefixed hex string`);
  }
}

function assertBytes32(value: string, field: string): void {
  if (!/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${field} must be a 32-byte 0x-prefixed hex string`);
  }
}

function assertCommitment(value: string, field: string): void {
  if (!/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${field} must be a 64-character hex commitment`);
  }
}

function assertNonEmptyString(value: string, field: string): void {
  if (value.length === 0) {
    throw new Error(`${field} must be a non-empty string`);
  }
}

function assertAddress(value: string, field: string): void {
  if (!/^0x[0-9a-fA-F]{40}$/.test(value)) {
    throw new Error(`${field} must be an EVM address`);
  }
}

function hexByteLength(value: string): number {
  return (value.length - 2) / 2;
}
