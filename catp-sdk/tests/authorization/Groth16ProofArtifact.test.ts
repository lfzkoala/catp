import { describe, expect, it } from "vitest";
import { groth16ArtifactToAuthorizationCall } from "../../src/authorization/Groth16ProofArtifact.js";
import type { Groth16AuthorizationProofArtifact } from "../../src/authorization/types.js";

const ZERO32 = `0x${"00".repeat(32)}` as `0x${string}`;
const ONE32 = `0x${"00".repeat(31)}01` as `0x${string}`;
const VALUE_500 = `0x${"00".repeat(30)}01f4` as `0x${string}`;
const PROOF_256 = `0x${"11".repeat(256)}` as `0x${string}`;

const artifact = {
  proofVersion: "authorization_groth16_v1",
  policyCommitment: ONE32,
  publicInputs: [
    ONE32,
    ZERO32,
    ZERO32,
    ZERO32,
    ZERO32,
    ZERO32,
    ZERO32,
    ZERO32,
    ZERO32,
    ZERO32,
    VALUE_500,
    `0x${"00".repeat(31)}7b`,
    ZERO32,
  ],
  actionData: `0x${"aa".repeat(128)}`,
  currentTimestamp: "123",
  cumulativeSpend: "0",
  value: "500",
  proof: PROOF_256,
  constraintCount: 13284,
} satisfies Groth16AuthorizationProofArtifact;

describe("groth16ArtifactToAuthorizationCall", () => {
  it("converts a Groth16 artifact into AgentAuthorizer calldata fields", () => {
    const call = groth16ArtifactToAuthorizationCall(artifact);

    expect(call.proofVersion).toBe("authorization_groth16_v1");
    expect(call.policyCommitment).toBe(ONE32);
    expect(call.actionData).toBe(artifact.actionData);
    expect(call.currentTimestamp).toBe(123n);
    expect(call.proof).toBe(PROOF_256);
    expect(call.publicInputs.actionValue).toBe(500n);
    expect(call.publicInputs.currentTimestamp).toBe(123n);
    expect(call.publicInputs.cumulativeSpend).toBe(0n);
  });

  it("rejects a proof with the wrong byte length", () => {
    expect(() =>
      groth16ArtifactToAuthorizationCall({
        ...artifact,
        proof: `0x${"11".repeat(255)}`,
      }),
    ).toThrow("proof must be 256 bytes");
  });

  it("rejects a mismatched policy commitment public input", () => {
    expect(() =>
      groth16ArtifactToAuthorizationCall({
        ...artifact,
        publicInputs: [ZERO32, ...artifact.publicInputs.slice(1)] as Groth16AuthorizationProofArtifact["publicInputs"],
      }),
    ).toThrow("publicInputs[0] must equal policyCommitment");
  });

  it("rejects mismatched timestamp/value/spend fields", () => {
    expect(() =>
      groth16ArtifactToAuthorizationCall({
        ...artifact,
        currentTimestamp: "124",
      }),
    ).toThrow("publicInputs[11] must equal currentTimestamp");

    expect(() =>
      groth16ArtifactToAuthorizationCall({
        ...artifact,
        value: "501",
      }),
    ).toThrow("publicInputs[10] must equal value");

    expect(() =>
      groth16ArtifactToAuthorizationCall({
        ...artifact,
        cumulativeSpend: "1",
      }),
    ).toThrow("publicInputs[12] must equal cumulativeSpend");
  });

  it("rejects malformed hex fields", () => {
    expect(() =>
      groth16ArtifactToAuthorizationCall({
        ...artifact,
        actionData: "aa" as `0x${string}`,
      }),
    ).toThrow("actionData must be 0x-prefixed hex");

    expect(() =>
      groth16ArtifactToAuthorizationCall({
        ...artifact,
        publicInputs: ["0x1234", ...artifact.publicInputs.slice(1)] as Groth16AuthorizationProofArtifact["publicInputs"],
      }),
    ).toThrow("publicInputs[0] must be a 32-byte hex string");
  });
});
