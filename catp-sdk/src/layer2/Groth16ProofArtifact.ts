import type {
  AuthorizationPublicInputs,
  Groth16AuthorizationCall,
  Groth16AuthorizationProofArtifact,
} from "./types.js";

const MAX_U64 = (1n << 64n) - 1n;

export function groth16ArtifactToAuthorizationCall(
  artifact: Groth16AuthorizationProofArtifact,
): Groth16AuthorizationCall {
  if (artifact.proofVersion !== "authorization_groth16_v1") {
    throw new Error("Groth16 artifact proofVersion must be authorization_groth16_v1");
  }
  assertBytes32Hex(artifact.policyCommitment, "policyCommitment");
  assertHex(artifact.actionData, "actionData");
  assertHex(artifact.proof, "proof");
  if (hexByteLength(artifact.proof) !== 256) {
    throw new Error("proof must be 256 bytes");
  }
  if (artifact.publicInputs.length !== 13) {
    throw new Error("publicInputs must contain 13 values");
  }
  for (const [index, input] of artifact.publicInputs.entries()) {
    assertBytes32Hex(input, `publicInputs[${index}]`);
  }
  if (artifact.publicInputs[0].toLowerCase() !== artifact.policyCommitment.toLowerCase()) {
    throw new Error("publicInputs[0] must equal policyCommitment");
  }

  const currentTimestamp = parseU64(artifact.currentTimestamp, "currentTimestamp");
  const cumulativeSpend = parseU64(artifact.cumulativeSpend, "cumulativeSpend");
  const value = parsePositiveU64(artifact.value, "value");
  if (parseU64(artifact.publicInputs[10], "publicInputs[10]") !== value) {
    throw new Error("publicInputs[10] must equal value");
  }
  if (parseU64(artifact.publicInputs[11], "publicInputs[11]") !== currentTimestamp) {
    throw new Error("publicInputs[11] must equal currentTimestamp");
  }
  if (parseU64(artifact.publicInputs[12], "publicInputs[12]") !== cumulativeSpend) {
    throw new Error("publicInputs[12] must equal cumulativeSpend");
  }

  return {
    proofVersion: "authorization_groth16_v1",
    policyCommitment: artifact.policyCommitment,
    actionData: artifact.actionData,
    currentTimestamp,
    proof: artifact.proof,
    publicInputs: {
      policyCommitment: artifact.policyCommitment,
      actionType: parseU64(artifact.publicInputs[1], "publicInputs[1]"),
      actionProtocol: [
        parseU64(artifact.publicInputs[2], "publicInputs[2]"),
        parseU64(artifact.publicInputs[3], "publicInputs[3]"),
        parseU64(artifact.publicInputs[4], "publicInputs[4]"),
        parseU64(artifact.publicInputs[5], "publicInputs[5]"),
      ],
      actionToken: [
        parseU64(artifact.publicInputs[6], "publicInputs[6]"),
        parseU64(artifact.publicInputs[7], "publicInputs[7]"),
        parseU64(artifact.publicInputs[8], "publicInputs[8]"),
        parseU64(artifact.publicInputs[9], "publicInputs[9]"),
      ],
      actionValue: value,
      currentTimestamp,
      cumulativeSpend,
    } satisfies AuthorizationPublicInputs,
  };
}

function parseU64(value: number | bigint | string, field: string): bigint {
  const parsed = parseBigInt(value, field);
  if (parsed < 0n || parsed > MAX_U64) {
    throw new Error(`${field} must fit in u64`);
  }
  return parsed;
}

function parsePositiveU64(value: number | bigint | string, field: string): bigint {
  const parsed = parseU64(value, field);
  if (parsed === 0n) {
    throw new Error(`${field} must be between 1 and u64::MAX`);
  }
  return parsed;
}

function parseBigInt(value: number | bigint | string, field: string): bigint {
  if (typeof value === "bigint") return value;
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

function assertHex(hex: string, field: string): void {
  if (!hex.startsWith("0x")) {
    throw new Error(`${field} must be 0x-prefixed hex`);
  }
  const clean = hex.slice(2);
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error(`${field} must be an even-length hex string`);
  }
}

function assertBytes32Hex(hex: string, field: string): void {
  if (!hex.startsWith("0x")) {
    throw new Error(`${field} must be 0x-prefixed hex`);
  }
  if (!/^[0-9a-fA-F]{64}$/.test(hex.slice(2))) {
    throw new Error(`${field} must be a 32-byte hex string`);
  }
}

function hexByteLength(hex: string): number {
  return (hex.length - 2) / 2;
}
