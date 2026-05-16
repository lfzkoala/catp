import { describe, expect, it, afterAll } from "@jest/globals";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  buildAuthorizationProofManifest,
  cmdProveAuthorization,
  cmdVerifyAuthorization,
  formatAuthorizationManifestSummary,
  readDeploymentMetadata,
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
const leU64Bytes = (value: bigint | number) => {
  const bytes: string[] = [];
  let remaining = BigInt(value);
  for (let i = 0; i < 8; i += 1) {
    bytes.push(Number(remaining & 0xffn).toString(16).padStart(2, "0"));
    remaining >>= 8n;
  }
  return bytes.join("");
};
const bytes32FromLeU64Limbs = (limbs: Array<bigint | number>) =>
  `0x${limbs.map(leU64Bytes).join("")}`;
const actionData = (opts: {
  actionType: bigint | number;
  protocol: string;
  token: string;
  value: bigint | number;
}) => `0x${BigInt(opts.actionType).toString(16).padStart(64, "0")}${opts.protocol.slice(2)}${opts.token.slice(2)}${BigInt(opts.value).toString(16).padStart(64, "0")}`;
const artifactProtocol = bytes32FromLeU64Limbs([1, 2, 3, 4]);
const artifactToken = bytes32FromLeU64Limbs([5, 6, 7, 8]);

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
  actionData: actionData({
    actionType: 0,
    protocol: artifactProtocol,
    token: artifactToken,
    value: 500,
  }),
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
      auditAgent: null,
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

  it("rejects invalid manifest and artifact metadata", () => {
    expect(() =>
      validateAuthorizationProofManifest({
        ...buildAuthorizationProofManifest(artifact),
        manifestVersion: "bad" as "catp_authorization_proof_manifest_v1",
      }),
    ).toThrow("manifestVersion must be");

    expect(() =>
      buildAuthorizationProofManifest({
        ...artifact,
        proofVersion: "wrong",
      }),
    ).toThrow("proofVersion must be authorization_groth16_v1");

    expect(() =>
      buildAuthorizationProofManifest({
        ...artifact,
        proof: "0x1234",
      }),
    ).toThrow("proof must be 256 bytes");

    expect(() =>
      buildAuthorizationProofManifest({
        ...artifact,
        actionData: "0x1234",
      }),
    ).toThrow("actionData must be 128 bytes");

    expect(() =>
      buildAuthorizationProofManifest({
        ...artifact,
        actionData: actionData({
          actionType: 1,
          protocol: artifactProtocol,
          token: artifactToken,
          value: 500,
        }),
      }),
    ).toThrow("actionData actionType must equal publicInputs[1]");

    expect(() =>
      buildAuthorizationProofManifest(artifact, { chainId: "sepolia" }),
    ).toThrow("chainId must be a decimal integer string");

    expect(() =>
      buildAuthorizationProofManifest(artifact, { verifier: "0x1234" }),
    ).toThrow("verifier must be an EVM address");
  });

  it("writes a manifest file from the command", () => {
    const artifactPath = join(tmpBase, "artifact.json");
    const outPath = join(tmpBase, "manifest.json");
    writeFileSync(artifactPath, JSON.stringify(artifact), "utf8");

    const originalWrite = process.stdout.write.bind(process.stdout);
    let output = "";
    process.stdout.write = ((chunk: string | Uint8Array) => {
      output += chunk.toString();
      return true;
    }) as typeof process.stdout.write;
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
    expect(output).toContain(`Wrote authorization proof manifest to ${outPath}`);
    expect(output).toContain("proofVersion=authorization_groth16_v1");
    expect(output).toContain("chainId=11155111");
    expect(output).toContain(`sourceArtifact=${artifactPath}`);
    expect(output).toContain("cryptographicVerification=external:EVM-or-offchain-verifier");
    expect(output).toContain(`verifyCommand=catp verify authorization --manifest ${outPath} --check-audit`);
  });

  it("reads verifier metadata from deployment JSON", () => {
    const deploymentPath = join(tmpBase, "deployment.json");
    writeFileSync(deploymentPath, JSON.stringify({
      chainId: 11155111,
      groth16AuthorizationVerifier: `0x${"12".repeat(20)}`,
      agentAuthorizer: `0x${"34".repeat(20)}`,
    }), "utf8");

    expect(readDeploymentMetadata(deploymentPath)).toEqual({
      chainId: "11155111",
      verifier: `0x${"12".repeat(20)}`,
      agentAuthorizer: `0x${"34".repeat(20)}`,
    });
  });

  it("rejects invalid deployment metadata", () => {
    const missingPath = join(tmpBase, "missing-deployment.json");
    expect(() => readDeploymentMetadata(missingPath)).toThrow("deployment not found");

    const invalidAddressPath = join(tmpBase, "invalid-address-deployment.json");
    writeFileSync(invalidAddressPath, JSON.stringify({
      groth16AuthorizationVerifier: "0x1234",
    }), "utf8");
    expect(() => readDeploymentMetadata(invalidAddressPath)).toThrow("deployment.groth16AuthorizationVerifier");

    const invalidChainPath = join(tmpBase, "invalid-chain-deployment.json");
    writeFileSync(invalidChainPath, JSON.stringify({
      chainId: "sepolia",
    }), "utf8");
    expect(() => readDeploymentMetadata(invalidChainPath)).toThrow("deployment.chainId must be a decimal integer");
  });

  it("rejects invalid prove and verify command inputs", () => {
    const artifactPath = join(tmpBase, "command-input-artifact.json");
    const manifestPath = join(tmpBase, "command-input-manifest.json");
    writeFileSync(artifactPath, JSON.stringify(artifact), "utf8");
    writeFileSync(manifestPath, JSON.stringify(buildAuthorizationProofManifest(artifact)), "utf8");

    expect(() =>
      cmdProveAuthorization({
        artifact: artifactPath,
        action: join(tmpBase, "action.json"),
      }),
    ).toThrow("use --artifact or --action");

    expect(() =>
      cmdProveAuthorization({
        artifact: join(tmpBase, "missing-artifact.json"),
      }),
    ).toThrow("artifact not found");

    expect(() =>
      cmdProveAuthorization({
        action: join(tmpBase, "action.json"),
        file: join(tmpBase, "catp-policy.toml"),
        proverScript: join(tmpBase, "missing-prover.sh"),
      }),
    ).toThrow("Full Groth16 proof generation requires a CATP repository checkout");

    expect(() =>
      cmdVerifyAuthorization({
        manifest: manifestPath,
        checkAudit: true,
      }),
    ).toThrow("manifest has no auditCommitment");

    expect(() =>
      cmdVerifyAuthorization({
        manifest: join(tmpBase, "missing-manifest.json"),
      }),
    ).toThrow("manifest not found");
  });

  it("uses deployment metadata when writing a manifest", () => {
    const artifactPath = join(tmpBase, "artifact-with-deployment.json");
    const deploymentPath = join(tmpBase, "manifest-deployment.json");
    const outPath = join(tmpBase, "manifest-with-deployment.json");
    writeFileSync(artifactPath, JSON.stringify(artifact), "utf8");
    writeFileSync(deploymentPath, JSON.stringify({
      chainId: "11155111",
      groth16AuthorizationVerifier: `0x${"12".repeat(20)}`,
      agentAuthorizer: `0x${"34".repeat(20)}`,
    }), "utf8");

    const originalWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = (() => true) as typeof process.stdout.write;
    try {
      cmdProveAuthorization({
        artifact: artifactPath,
        deployment: deploymentPath,
        out: outPath,
      });
    } finally {
      process.stdout.write = originalWrite;
    }

    expect(JSON.parse(readFileSync(outPath, "utf8"))).toMatchObject({
      verifier: `0x${"12".repeat(20)}`,
      agentAuthorizer: `0x${"34".repeat(20)}`,
      chainId: "11155111",
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
allowed_protocol = "${artifactProtocol}"
allowed_token = "${artifactToken}"
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
        protocol: artifactProtocol,
        token: artifactToken,
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
    --proof-only) shift ;;
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
      auditAgent: "manifest-agent",
      currentTimestamp: "150",
      cumulativeSpend: "0",
      value: "500",
      sourceArtifact: null,
    });

    const originalWriteVerify = process.stdout.write.bind(process.stdout);
    let output = "";
    process.stdout.write = ((chunk: string | Uint8Array) => {
      output += chunk.toString();
      return true;
    }) as typeof process.stdout.write;
    try {
      cmdVerifyAuthorization({
        manifest: manifestPath,
        checkAudit: true,
      });
    } finally {
      process.stdout.write = originalWriteVerify;
    }

    expect(output).toContain("auditEntry=found:manifest-agent");
    expect(output).toContain("auditAction=matched");
    expect(output).toContain("currentTimestamp=150");
    expect(output).toContain("cumulativeSpend=0");
    expect(output).toContain("cryptographicVerification=external:EVM-or-offchain-verifier");
  });

  it("rejects audit-linked manifests when action data differs from the audit entry", () => {
    const policyPath = join(tmpBase, "audit-mismatch-policy.toml");
    const manifestPath = join(tmpBase, "audit-mismatch-manifest.json");
    const commitment = computeCommitment("Bash", "allow", "2026-01-02T00:00:00.000Z", "0", null, "{}");

    writeFileSync(policyPath, `
[agent]
id = "manifest-mismatch-agent"
version = "1"

[[rules]]
tool = "Bash"
allow = true
`, "utf8");

    appendAuditEntry("manifest-mismatch-agent", {
      ts: "2026-01-02T00:00:00.000Z",
      tool: "Bash",
      decision: "allow",
      rule_matched: null,
      commitment,
      input_summary: "{}",
      authorization: {
        actionType: "Swap",
        protocol: artifactProtocol,
        token: artifactToken,
        value: "501",
        currentTimestamp: "150",
        cumulativeSpend: "0",
      },
    });

    writeFileSync(manifestPath, JSON.stringify(buildAuthorizationProofManifest(artifact, {
      auditCommitment: commitment,
      auditAgent: "manifest-mismatch-agent",
    })), "utf8");

    expect(() =>
      cmdVerifyAuthorization({
        manifest: manifestPath,
        checkAudit: true,
      }),
    ).toThrow("manifest actionData does not match audit authorization action");
  });

  it("formats a useful manifest summary", () => {
    const manifest = buildAuthorizationProofManifest(artifact, {
      auditCommitment: "cd".repeat(32),
      auditAgent: "summary-agent",
      verifier: `0x${"12".repeat(20)}`,
      agentAuthorizer: `0x${"34".repeat(20)}`,
      chainId: "11155111",
      sourceArtifact: "proof.json",
    });

    const summary = formatAuthorizationManifestSummary(manifest);

    expect(summary).toContain("Authorization proof manifest is structurally valid.");
    expect(summary).toContain("proofVersion=authorization_groth16_v1");
    expect(summary).toContain(`policyCommitment=${artifact.policyCommitment}`);
    expect(summary).toContain("value=500");
    expect(summary).toContain("auditAgent=summary-agent");
    expect(summary).toContain(`verifier=0x${"12".repeat(20)}`);
    expect(summary).toContain(`agentAuthorizer=0x${"34".repeat(20)}`);
    expect(summary).toContain("next=Use the proof artifact with AgentAuthorizer.executeAuthorized");
    expect(summary).not.toContain("verifyCommand=");
  });
});
