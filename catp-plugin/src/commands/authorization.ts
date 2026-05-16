import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildGroth16WitnessFromSources } from "./witness.js";
import { auditRoot } from "../audit/paths.js";
import { findPolicyFile, loadPolicy } from "../policy/loader.js";
import type { AuditEntry, AuthorizationAction } from "../policy/types.js";

const PROOF_VERSION = "authorization_groth16_v1";
const ACTION_TYPE: Record<string, string> = {
  swap: "0",
  transfer: "1",
  deposit: "2",
  withdraw: "3",
};

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
  if (opts.proofUrl !== undefined) {
    assertProofUrl(opts.proofUrl, "proofUrl");
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
  if (manifest.proofUrl !== null) {
    assertProofUrl(manifest.proofUrl, "proofUrl");
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
  deployment?: string;
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
    const deployment = opts.deployment ? readDeploymentMetadata(opts.deployment) : {};
    const manifest = buildAuthorizationProofManifest(artifact, {
      auditCommitment: opts.auditCommitment,
      auditAgent: resolveAuditAgent(opts),
      verifier: opts.verifier ?? deployment.verifier,
      agentAuthorizer: opts.agentAuthorizer ?? deployment.agentAuthorizer,
      chainId: opts.chainId ?? deployment.chainId,
      proofUrl: opts.proofUrl,
      sourceArtifact: opts.artifact ?? opts.artifactOut ?? undefined,
    });
    const encoded = `${JSON.stringify(manifest, null, 2)}\n`;

    if (opts.out) {
      writeFileSync(opts.out, encoded, "utf8");
      process.stdout.write(`Wrote authorization proof manifest to ${opts.out}\n`);
      process.stdout.write(formatAuthorizationManifestSummary(manifest, { includeStatus: false, manifestPath: opts.out }));
    } else {
      process.stdout.write(encoded);
    }
  } finally {
    if (cleanupDir) {
      rmSync(cleanupDir, { recursive: true, force: true });
    }
  }
}

export function readDeploymentMetadata(path: string): {
  verifier?: string;
  agentAuthorizer?: string;
  chainId?: string;
} {
  if (!existsSync(path)) {
    throw new Error(`deployment not found: ${path}`);
  }
  const parsed = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  const verifier = optionalString(parsed.groth16AuthorizationVerifier, "deployment.groth16AuthorizationVerifier");
  const agentAuthorizer = optionalString(parsed.agentAuthorizer, "deployment.agentAuthorizer");
  const chainId = optionalIntegerString(parsed.chainId, "deployment.chainId");
  if (verifier !== undefined) assertAddress(verifier, "deployment.groth16AuthorizationVerifier");
  if (agentAuthorizer !== undefined) assertAddress(agentAuthorizer, "deployment.agentAuthorizer");
  return { verifier, agentAuthorizer, chainId };
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
  const extraLines: string[] = [];
  if (opts.checkAudit) {
    const auditAgent = opts.auditAgent ?? manifest.auditAgent;
    if (!manifest.auditCommitment) {
      throw new Error("manifest has no auditCommitment to check");
    }
    if (!auditAgent) {
      throw new Error("missing --audit-agent <id>; manifest does not include auditAgent");
    }
    const entry = findAuditEntry(auditAgent, manifest.auditCommitment);
    if (!entry) {
      throw new Error(`No audit entry found for commitment ${manifest.auditCommitment}`);
    }
    validateAuditEntryMatchesManifest(entry, manifest);
    extraLines.push(`auditEntry=found:${auditAgent}`);
    extraLines.push("auditAction=matched");
  }
  process.stdout.write(formatAuthorizationManifestSummary(manifest, {
    extraLines,
    includeStatus: true,
  }));
}

export function formatAuthorizationManifestSummary(
  manifest: AuthorizationProofManifest,
  opts: { extraLines?: string[]; includeStatus?: boolean; manifestPath?: string } = {},
): string {
  const lines = [
    ...(opts.includeStatus === false ? [] : ["Authorization proof manifest is structurally valid."]),
    `proofVersion=${manifest.proofVersion}`,
    `policyCommitment=${manifest.policyCommitment}`,
    `value=${manifest.value}`,
    `currentTimestamp=${manifest.currentTimestamp}`,
    `cumulativeSpend=${manifest.cumulativeSpend}`,
    `chainId=${manifest.chainId ?? "none"}`,
    `verifier=${manifest.verifier ?? "none"}`,
    `agentAuthorizer=${manifest.agentAuthorizer ?? "none"}`,
    `auditCommitment=${manifest.auditCommitment ?? "none"}`,
    `auditAgent=${manifest.auditAgent ?? "none"}`,
    `sourceArtifact=${manifest.sourceArtifact ?? "none"}`,
    `proofUrl=${manifest.proofUrl ?? "none"}`,
    ...(opts.extraLines ?? []),
    "cryptographicVerification=external:EVM-or-offchain-verifier",
  ];
  if (manifest.agentAuthorizer) {
    lines.push("next=Use the proof artifact with AgentAuthorizer.executeAuthorized or npm run groth16:execute.");
  } else {
    lines.push("next=Attach deployment metadata to execute this proof on-chain.");
  }
  if (opts.manifestPath) {
    lines.push(`verifyCommand=catp verify authorization --manifest ${opts.manifestPath}${manifest.auditCommitment ? " --check-audit" : ""}`);
  }
  return `${lines.join("\n")}\n`;
}

function validateGroth16Artifact(artifact: AuthorizationProofArtifact): void {
  if (artifact.proofVersion !== PROOF_VERSION) {
    throw new Error(`proofVersion must be ${PROOF_VERSION}`);
  }
  assertBytes32(artifact.policyCommitment, "policyCommitment");
  assertHex(artifact.actionData, "actionData");
  if (hexByteLength(artifact.actionData) !== 128) {
    throw new Error("actionData must be 128 bytes");
  }
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

  validateActionDataMatchesPublicInputs(artifact.actionData, artifact.publicInputs);
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
    throw new Error(
      `prover script not found: ${proverScript}. ` +
      "Full Groth16 proof generation requires a CATP repository checkout; " +
      "the npm CLI package only includes local enforcement, audit logs, witness generation, and manifest tooling. " +
      "Run this command from the repository root or pass --prover-script <path>.",
    );
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
    "--proof-only",
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

function validateAuditEntryMatchesManifest(entry: AuditEntry, manifest: AuthorizationProofManifest): void {
  if (!entry.authorization) {
    throw new Error(`Audit entry ${entry.commitment} does not contain authorization action data`);
  }

  const expectedActionData = encodeAuthorizationAction(entry.authorization);
  if (expectedActionData.toLowerCase() !== manifest.actionData.toLowerCase()) {
    throw new Error("manifest actionData does not match audit authorization action");
  }

  const auditValue = normalizeU64(entry.authorization.value, "audit.authorization.value");
  if (auditValue !== manifest.value) {
    throw new Error("manifest value does not match audit authorization action");
  }

  if (entry.authorization.currentTimestamp !== undefined) {
    const auditTimestamp = normalizeU64(entry.authorization.currentTimestamp, "audit.authorization.currentTimestamp");
    if (auditTimestamp !== manifest.currentTimestamp) {
      throw new Error("manifest currentTimestamp does not match audit authorization action");
    }
  }

  if (entry.authorization.cumulativeSpend !== undefined) {
    const auditSpend = normalizeU64(entry.authorization.cumulativeSpend, "audit.authorization.cumulativeSpend");
    if (auditSpend !== manifest.cumulativeSpend) {
      throw new Error("manifest cumulativeSpend does not match audit authorization action");
    }
  }
}

function validateActionDataMatchesPublicInputs(actionData: string, publicInputs: string[]): void {
  const decoded = decodeActionData(actionData);
  if (decoded.actionType !== normalizeU64(publicInputs[1], "publicInputs[1]")) {
    throw new Error("actionData actionType must equal publicInputs[1]");
  }
  for (const [index, limb] of decoded.protocol.entries()) {
    if (limb !== normalizeU64(publicInputs[2 + index], `publicInputs[${2 + index}]`)) {
      throw new Error(`actionData protocol limb ${index} must equal publicInputs[${2 + index}]`);
    }
  }
  for (const [index, limb] of decoded.token.entries()) {
    if (limb !== normalizeU64(publicInputs[6 + index], `publicInputs[${6 + index}]`)) {
      throw new Error(`actionData token limb ${index} must equal publicInputs[${6 + index}]`);
    }
  }
  if (decoded.value !== normalizeU64(publicInputs[10], "publicInputs[10]")) {
    throw new Error("actionData value must equal publicInputs[10]");
  }
}

function decodeActionData(actionData: string): {
  actionType: string;
  protocol: string[];
  token: string[];
  value: string;
} {
  const clean = actionData.slice(2);
  const actionType = BigInt(`0x${clean.slice(0, 64)}`).toString();
  const protocol = decodeLeU64Limbs(clean.slice(64, 128));
  const token = decodeLeU64Limbs(clean.slice(128, 192));
  const value = BigInt(`0x${clean.slice(192, 256)}`).toString();
  return { actionType, protocol, token, value };
}

function decodeLeU64Limbs(wordHex: string): string[] {
  const limbs: string[] = [];
  for (let limbIndex = 0; limbIndex < 4; limbIndex += 1) {
    const offset = limbIndex * 16;
    let value = 0n;
    for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
      const byteHex = wordHex.slice(offset + byteIndex * 2, offset + byteIndex * 2 + 2);
      value |= BigInt(`0x${byteHex}`) << BigInt(8 * byteIndex);
    }
    limbs.push(value.toString());
  }
  return limbs;
}

function encodeAuthorizationAction(action: AuthorizationAction): string {
  const actionType = normalizeAuthorizationActionType(action.actionType, "audit.authorization.actionType");
  const value = normalizeU64(action.value, "audit.authorization.value");
  assertBytes32(action.protocol, "audit.authorization.protocol");
  assertBytes32(action.token, "audit.authorization.token");
  return `0x${u256Hex(actionType)}${action.protocol.slice(2)}${action.token.slice(2)}${u256Hex(value)}`;
}

function normalizeAuthorizationActionType(value: string | number, field: string): string {
  if (typeof value === "string" && ACTION_TYPE[value.toLowerCase()] !== undefined) {
    return ACTION_TYPE[value.toLowerCase()];
  }
  const parsed = normalizeU64(value, field);
  if (!["0", "1", "2", "3"].includes(parsed)) {
    throw new Error(`${field} must be Swap, Transfer, Deposit, Withdraw, or 0..3`);
  }
  return parsed;
}

function u256Hex(value: string): string {
  return BigInt(value).toString(16).padStart(64, "0");
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

function optionalString(value: unknown, field: string): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string") {
    throw new Error(`${field} must be a string`);
  }
  return value;
}

function optionalIntegerString(value: unknown, field: string): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`${field} must be a non-negative safe integer`);
    }
    return value.toString();
  }
  if (typeof value === "string" && /^[0-9]+$/.test(value)) {
    return value;
  }
  throw new Error(`${field} must be a decimal integer`);
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

function assertProofUrl(value: string, field: string): void {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${field} must be a valid URL`);
  }
  if (parsed.protocol === "https:" || parsed.protocol === "ipfs:" || parsed.protocol === "ar:") {
    return;
  }
  if (
    parsed.protocol === "http:" &&
    (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "::1" || parsed.hostname === "[::1]")
  ) {
    return;
  }
  throw new Error(`${field} must use https, ipfs, ar, or localhost http`);
}

function hexByteLength(value: string): number {
  return (value.length - 2) / 2;
}
