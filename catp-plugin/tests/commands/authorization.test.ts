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
import { appendAuditEntry, computeCommitment } from "../../src/audit/logger.js";

const tmpBase = join(tmpdir(), `catp-authorization-test-${Date.now()}`);
mkdirSync(tmpBase, { recursive: true });
process.env.CATP_HOME = join(tmpBase, "catp-home");

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

  it("builds a manifest from an audit commitment through the prover bridge", () => {
    const policyPath = join(tmpBase, "audit-policy.toml");
    const manifestPath = join(tmpBase, "audit-manifest.json");
    const fakeProverPath = join(tmpBase, "fake-groth16-prover.sh");
    const commitment = computeCommitment("Bash", "allow", "2026-01-01T00:00:00.000Z", "0", null, "{}");

    writeFileSync(policyPath, `
[agent]
id = "manifest-agent"
version = "1"

[authorization]
allowed_action = "Swap"
allowed_protocol = "${bytes32("aa")}"
allowed_token = "${bytes32("bb")}"
max_value_per_tx = "1000"
max_value_total = "10000"
valid_from = "100"
valid_until = "200"

[[rules]]
tool = "Bash"
allow = true
`, "utf8");

    appendAuditEntry("manifest-agent", {
      ts: "2026-01-01T00:00:00.000Z",
      tool: "Bash",
      decision: "allow",
      rule_matched: null,
      commitment,
      input_summary: "{}",
      authorization: {
        actionType: "Swap",
        protocol: bytes32("aa"),
        token: bytes32("bb"),
        value: "500",
        currentTimestamp: "150",
        cumulativeSpend: "0",
      },
    });

    writeFileSync(fakeProverPath, `#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) out="$2"; shift 2 ;;
    *) shift 2 ;;
  esac
done
cat > "$out" <<'JSON'
${JSON.stringify({
  ...artifact,
  currentTimestamp: "150",
  cumulativeSpend: "0",
  value: "500",
  publicInputs: artifact.publicInputs.map((input, index) => {
    if (index === 10) return u64Input(500);
    if (index === 11) return u64Input(150);
    if (index === 12) return u64Input(0);
    return input;
  }),
})}
JSON
`, "utf8");

    const originalWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = (() => true) as typeof process.stdout.write;
    try {
      cmdProveAuthorization({
        auditCommitment: commitment,
        file: policyPath,
        proverScript: fakeProverPath,
        out: manifestPath,
      });
    } finally {
      process.stdout.write = originalWrite;
    }

    expect(JSON.parse(readFileSync(manifestPath, "utf8"))).toMatchObject({
      manifestVersion: "catp_authorization_proof_manifest_v1",
      auditCommitment: commitment,
      currentTimestamp: "150",
      cumulativeSpend: "0",
      value: "500",
      sourceArtifact: null,
    });
  });
});
