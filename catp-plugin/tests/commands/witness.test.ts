import { describe, expect, it, afterAll } from "@jest/globals";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { appendAuditEntry, computeCommitment } from "../../src/audit/logger.js";
import { buildGroth16Witness, cmdWitness, formatGroth16WitnessSummary } from "../../src/commands/witness.js";
import type { CatpPolicy } from "../../src/policy/types.js";

const tmpBase = join(tmpdir(), `catp-witness-test-${Date.now()}`);
const testHome = join(tmpBase, "catp-home");
mkdirSync(tmpBase, { recursive: true });
process.env.CATP_HOME = testHome;

afterAll(() => {
  rmSync(tmpBase, { recursive: true, force: true });
});

const PROTOCOL = `0x${"aa".repeat(32)}`;
const TOKEN = `0x${"bb".repeat(32)}`;

const policy = {
  agent: { id: "test-agent", version: "1" },
  rules: [{ tool: "Bash", allow: true }],
  authorization: {
    allowed_action: "Swap",
    allowed_protocol: PROTOCOL,
    allowed_token: TOKEN,
    max_value_per_tx: "1000",
    max_value_total: "10000",
    valid_from: "100",
    valid_until: "200",
  },
} satisfies CatpPolicy;

describe("buildGroth16Witness", () => {
  it("builds authorization_groth16_v1 witness fields from policy and action", () => {
    expect(
      buildGroth16Witness(
        policy,
        {
          actionType: "Swap",
          protocol: PROTOCOL,
          token: TOKEN,
          value: "500",
        },
        { currentTimestamp: "150", cumulativeSpend: "25" },
      ),
    ).toEqual({
      actionType: "0",
      protocol: PROTOCOL,
      token: TOKEN,
      value: "500",
      currentTimestamp: "150",
      cumulativeSpend: "25",
      allowedAction: "0",
      allowedProtocol: PROTOCOL,
      allowedToken: TOKEN,
      maxValuePerTx: "1000",
      maxValueTotal: "10000",
      validFrom: "100",
      validUntil: "200",
    });
  });

  it("rejects actions that do not match the authorization policy", () => {
    expect(() =>
      buildGroth16Witness(policy, {
        actionType: "Transfer",
        protocol: PROTOCOL,
        token: TOKEN,
        value: "500",
      }),
    ).toThrow("actionType must match");

    expect(() =>
      buildGroth16Witness(policy, {
        actionType: "Swap",
        protocol: `0x${"cc".repeat(32)}`,
        token: TOKEN,
        value: "500",
      }),
    ).toThrow("protocol must match");
  });

  it("rejects missing authorization config", () => {
    expect(() =>
      buildGroth16Witness(
        { agent: policy.agent, rules: policy.rules },
        { actionType: "Swap", protocol: PROTOCOL, token: TOKEN, value: "500" },
      ),
    ).toThrow("missing [authorization]");
  });
});

describe("cmdWitness", () => {
  it("writes witness JSON from policy and action files", () => {
    const policyPath = join(tmpBase, "catp-policy.toml");
    const actionPath = join(tmpBase, "action.json");
    const outPath = join(tmpBase, "witness.json");

    writeFileSync(policyPath, `
[agent]
id = "test-agent"
version = "1"

[authorization]
allowed_action = "Swap"
allowed_protocol = "${PROTOCOL}"
allowed_token = "${TOKEN}"
max_value_per_tx = "1000"
max_value_total = "10000"
valid_from = "100"
valid_until = "200"

[[rules]]
tool = "Bash"
allow = true
`, "utf8");
    writeFileSync(actionPath, JSON.stringify({
      actionType: "Swap",
      protocol: PROTOCOL,
      token: TOKEN,
      value: "500",
    }), "utf8");

    const originalWrite = process.stdout.write.bind(process.stdout);
    let output = "";
    process.stdout.write = ((chunk: string | Uint8Array) => {
      output += chunk.toString();
      return true;
    }) as typeof process.stdout.write;
    try {
      cmdWitness({
        file: policyPath,
        action: actionPath,
        out: outPath,
        currentTimestamp: "150",
        cumulativeSpend: "0",
      });
    } finally {
      process.stdout.write = originalWrite;
    }

    expect(existsSync(outPath)).toBe(true);
    expect(JSON.parse(readFileSync(outPath, "utf8"))).toMatchObject({
      actionType: "0",
      value: "500",
      currentTimestamp: "150",
      cumulativeSpend: "0",
      allowedAction: "0",
    });
    expect(output).toContain(`Wrote Groth16 witness to ${outPath}`);
    expect(output).toContain("proofVersion=authorization_groth16_v1");
    expect(output).toContain("value=500");
    expect(output).toContain("currentTimestamp=150");
    expect(output).toContain("cumulativeSpend=0");
    expect(output).toContain("next=Run catp prove authorization");
    expect(output).toContain(
      `proveCommand=catp prove authorization --file ${policyPath} --action ${actionPath} --current-timestamp 150 --cumulative-spend 0 --artifact-out authorization_groth16_v1.json --deployment catp-contracts/deployments/sepolia-groth16.json --out catp-proof-manifest.json`,
    );
  });

  it("writes witness JSON from an audit entry commitment", () => {
    const policyPath = join(tmpBase, "audit-policy.toml");
    const outPath = join(tmpBase, "audit-witness.json");
    const commitment = computeCommitment("Bash", "allow", "2026-01-01T00:00:00.000Z", "0", null, "{}");

    writeFileSync(policyPath, `
[agent]
id = "test-agent"
version = "1"

[authorization]
allowed_action = "Swap"
allowed_protocol = "${PROTOCOL}"
allowed_token = "${TOKEN}"
max_value_per_tx = "1000"
max_value_total = "10000"
valid_from = "100"
valid_until = "200"

[[rules]]
tool = "Bash"
allow = true
`, "utf8");

    appendAuditEntry("test-agent", {
      ts: "2026-01-01T00:00:00.000Z",
      tool: "Bash",
      decision: "allow",
      rule_matched: null,
      commitment,
      input_summary: "{}",
      authorization: {
        actionType: "Swap",
        protocol: PROTOCOL,
        token: TOKEN,
        value: "500",
        currentTimestamp: "150",
        cumulativeSpend: "0",
      },
    });

    const originalWrite = process.stdout.write.bind(process.stdout);
    let output = "";
    process.stdout.write = ((chunk: string | Uint8Array) => {
      output += chunk.toString();
      return true;
    }) as typeof process.stdout.write;
    try {
      cmdWitness({
        file: policyPath,
        auditCommitment: commitment,
        out: outPath,
      });
    } finally {
      process.stdout.write = originalWrite;
    }

    expect(JSON.parse(readFileSync(outPath, "utf8"))).toMatchObject({
      actionType: "0",
      value: "500",
      currentTimestamp: "150",
      cumulativeSpend: "0",
    });
    expect(output).toContain("proofVersion=authorization_groth16_v1");
    expect(output).toContain("currentTimestamp=150");
    expect(output).toContain(
      `proveCommand=catp prove authorization --file ${policyPath} --audit-commitment ${commitment} --artifact-out authorization_groth16_v1.json --deployment catp-contracts/deployments/sepolia-groth16.json --out catp-proof-manifest.json`,
    );
  });

  it("formats a useful witness summary", () => {
    const witness = buildGroth16Witness(
      policy,
      {
        actionType: "Swap",
        protocol: PROTOCOL,
        token: TOKEN,
        value: "500",
      },
      { currentTimestamp: "150", cumulativeSpend: "25" },
    );

    const summary = formatGroth16WitnessSummary(witness);

    expect(summary).toContain("proofVersion=authorization_groth16_v1");
    expect(summary).toContain("actionType=0");
    expect(summary).toContain("value=500");
    expect(summary).toContain("cumulativeSpend=25");
    expect(summary).toContain("maxValuePerTx=1000");
    expect(summary).toContain("next=Run catp prove authorization");
  });
});
