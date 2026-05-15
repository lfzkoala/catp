import { describe, expect, it } from "@jest/globals";
import { formatValidationSummary } from "../../src/commands/validate.js";
import type { CatpPolicy } from "../../src/policy/types.js";

const policy = {
  agent: { id: "test-agent", version: "1" },
  rules: [{ tool: "Bash", allow: true }],
} satisfies CatpPolicy;

describe("formatValidationSummary", () => {
  it("formats basic policy metadata", () => {
    const summary = formatValidationSummary("/tmp/catp-policy.toml", policy);

    expect(summary).toContain("✓ /tmp/catp-policy.toml");
    expect(summary).toContain("agent: test-agent v1");
    expect(summary).toContain("rules: 1");
    expect(summary).not.toContain("authorization:");
  });

  it("includes authorization proof hints when policy has authorization config", () => {
    const summary = formatValidationSummary("/tmp/catp-policy.toml", {
      ...policy,
      authorization: {
        allowed_action: "Swap",
        allowed_protocol: `0x${"aa".repeat(32)}`,
        allowed_token: `0x${"bb".repeat(32)}`,
        max_value_per_tx: "1000",
        max_value_total: "10000",
        valid_from: "100",
        valid_until: "200",
      },
    });

    expect(summary).toContain("authorization: authorization_groth16_v1-ready");
    expect(summary).toContain("allowedAction: Swap");
    expect(summary).toContain("maxValuePerTx: 1000");
    expect(summary).toContain("maxValueTotal: 10000");
    expect(summary).toContain("validFrom: 100");
    expect(summary).toContain("validUntil: 200");
    expect(summary).toContain("next: catp witness --action <action.json> --out <witness.json>");
  });
});
