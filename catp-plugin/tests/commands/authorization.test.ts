import { describe, expect, it, afterAll } from "@jest/globals";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  buildAuthorizationProofManifest,
  cmdProveAuthorization,
  validateAuthorizationProofManifest,
  type AuthorizationProofArtifact,
} from "../../src/commands/authorization.js";

const tmpBase = join(tmpdir(), `catp-authorization-test-${Date.now()}`);
mkdirSync(tmpBase, { recursive: true });

afterAll(() => {
  rmSync(tmpBase, { recursive: true, force: true });
});

const bytes32 = (byte: string) => `0x${byte.repeat(32)}`;
const u64Input = (value: bigint | number) => `0x${BigInt(value).toString(16).padStart(64, "0")}`;

const artifact = {
  proofVersion: "authorization_groth16_v1",
  policyCommitment: bytes32("11"),
  publicInputs: [
    bytes32("11"),
    u64Input(0),
    u64Input(1),
    u64Input(2),
    u64Input(3),
    u64Input(4),
    u64Input(5),
    u64Input(6),
    u64Input(7),
    u64Input(8),
    u64Input(500),
    u64Input(1778042846),
    u64Input(25),
  ],
  actionData: "0x1234",
  currentTimestamp: "1778042846",
  cumulativeSpend: "25",
  value: "500",
  proof: `0x${"ab".repeat(256)}`,
  constraintCount: 1234,
} satisfies AuthorizationProofArtifact;

describe("authorization proof manifest", () => {
  it("builds and validates a manifest from a Groth16 artifact", () => {
    const manifest = buildAuthorizationProofManifest(artifact, {
      auditCommitment: "cd".repeat(32),
      verifier: `0x${"12".repeat(20)}`,
      agentAuthorizer: `0x${"34".repeat(20)}`,
      chainId: "11155111",
      sourceArtifact: "authorization_groth16_v1.json",
    });

    expect(manifest).toMatchObject({
      manifestVersion: "catp_authorization_proof_manifest_v1",
      proofVersion: "authorization_groth16_v1",
      auditCommitment: "cd".repeat(32),
      policyCommitment: artifact.policyCommitment,
      currentTimestamp: "1778042846",
      cumulativeSpend: "25",
      value: "500",
      chainId: "11155111",
    });
    expect(() => validateAuthorizationProofManifest(manifest)).not.toThrow();
  });

  it("rejects artifacts with mismatched public inputs", () => {
    expect(() =>
      buildAuthorizationProofManifest({
        ...artifact,
        publicInputs: artifact.publicInputs.map((input, index) => index === 10 ? u64Input(501) : input),
      }),
    ).toThrow("publicInputs[10] must equal value");
  });

  it("writes a manifest file from the command", () => {
    const artifactPath = join(tmpBase, "artifact.json");
    const outPath = join(tmpBase, "manifest.json");
    writeFileSync(artifactPath, JSON.stringify(artifact), "utf8");

    const originalWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = (() => true) as typeof process.stdout.write;
    try {
      cmdProveAuthorization({
        artifact: artifactPath,
        auditCommitment: "ef".repeat(32),
        chainId: "11155111",
        out: outPath,
      });
    } finally {
      process.stdout.write = originalWrite;
    }

    expect(existsSync(outPath)).toBe(true);
    expect(JSON.parse(readFileSync(outPath, "utf8"))).toMatchObject({
      manifestVersion: "catp_authorization_proof_manifest_v1",
      auditCommitment: "ef".repeat(32),
      sourceArtifact: artifactPath,
    });
  });
});
