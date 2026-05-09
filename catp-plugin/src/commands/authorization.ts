import { existsSync, readFileSync, writeFileSync } from "node:fs";

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
  auditCommitment?: string;
  verifier?: string;
  agentAuthorizer?: string;
  chainId?: string;
  proofUrl?: string;
  out?: string;
}): void {
  if (!opts.artifact) {
    throw new Error("missing --artifact <path>");
  }
  if (!existsSync(opts.artifact)) {
    throw new Error(`artifact not found: ${opts.artifact}`);
  }

  const artifact = JSON.parse(readFileSync(opts.artifact, "utf8")) as AuthorizationProofArtifact;
  const manifest = buildAuthorizationProofManifest(artifact, {
    auditCommitment: opts.auditCommitment,
    verifier: opts.verifier,
    agentAuthorizer: opts.agentAuthorizer,
    chainId: opts.chainId,
    proofUrl: opts.proofUrl,
    sourceArtifact: opts.artifact,
  });
  const encoded = `${JSON.stringify(manifest, null, 2)}\n`;

  if (opts.out) {
    writeFileSync(opts.out, encoded, "utf8");
    process.stdout.write(`Wrote authorization proof manifest to ${opts.out}\n`);
  } else {
    process.stdout.write(encoded);
  }
}

export function cmdVerifyAuthorization(opts: { manifest?: string }): void {
  if (!opts.manifest) {
    throw new Error("missing --manifest <path>");
  }
  if (!existsSync(opts.manifest)) {
    throw new Error(`manifest not found: ${opts.manifest}`);
  }

  const manifest = JSON.parse(readFileSync(opts.manifest, "utf8")) as AuthorizationProofManifest;
  validateAuthorizationProofManifest(manifest);
  process.stdout.write([
    "Authorization proof manifest is structurally valid.",
    `proofVersion=${manifest.proofVersion}`,
    `policyCommitment=${manifest.policyCommitment}`,
    `auditCommitment=${manifest.auditCommitment ?? "none"}`,
  ].join("\n") + "\n");
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

function assertAddress(value: string, field: string): void {
  if (!/^0x[0-9a-fA-F]{40}$/.test(value)) {
    throw new Error(`${field} must be an EVM address`);
  }
}

function hexByteLength(value: string): number {
  return (value.length - 2) / 2;
}
