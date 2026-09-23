import {
  canonicalizeToolAction,
  computeActionCommitment,
  computePolicyCommitment,
  type CanonicalToolActionV1,
} from "../../src/evidence/commitments.js";
import type { ToolAction } from "../../src/runtime/types.js";
import type { CatpPolicy } from "../../src/policy/types.js";

function makeAction(overrides: Partial<ToolAction> = {}): ToolAction {
  return {
    runtime: "claude-code",
    phase: "pre",
    sessionId: "sess-1",
    toolName: "Bash",
    toolInput: { command: "ls -la" },
    ...overrides,
  };
}

function makePolicy(overrides: Partial<CatpPolicy> = {}): CatpPolicy {
  return {
    agent: { id: "agent-1", version: "1.0.0" },
    rules: [{ tool: "Bash", allow: true, pattern: ["ls*"] }],
    ...overrides,
  };
}

describe("canonicalizeToolAction", () => {
  it("sets the schema and maps normalized fields", () => {
    const canonical = canonicalizeToolAction(makeAction());
    expect(canonical).toEqual({
      schema: "catp_tool_action_v1",
      runtime: "claude-code",
      phase: "pre",
      session_id: "sess-1",
      tool_name: "Bash",
      tool_input: { command: "ls -la" },
    } satisfies CanonicalToolActionV1);
  });

  it("deliberately excludes the raw payload", () => {
    const canonical = canonicalizeToolAction(
      makeAction({ raw: { secret: "super-secret-token", noise: 1 } }),
    );
    expect(canonical).not.toHaveProperty("raw");
    expect(JSON.stringify(canonical)).not.toContain("super-secret-token");
  });

  it("omits an absent optional session_id entirely", () => {
    const canonical = canonicalizeToolAction(makeAction({ sessionId: undefined }));
    expect(canonical).not.toHaveProperty("session_id");
    expect(Object.keys(canonical)).not.toContain("session_id");
  });

  it("omits a non-string session_id (e.g. null from a runtime payload)", () => {
    // Guards the CanonicalToolActionV1 contract: session_id is `string` or
    // absent, never null. A null must not become `session_id: null` and create a
    // commitment distinct from the absent-session_id form.
    const canonical = canonicalizeToolAction(
      makeAction({ sessionId: null as unknown as undefined }),
    );
    expect(canonical).not.toHaveProperty("session_id");
    expect(canonical).toEqual(canonicalizeToolAction(makeAction({ sessionId: undefined })));
  });

  it("includes session_id when present", () => {
    const canonical = canonicalizeToolAction(makeAction({ sessionId: "abc" }));
    expect(canonical.session_id).toBe("abc");
  });
});

describe("computeActionCommitment", () => {
  it("returns a lowercase 64-hex digest and is deterministic", () => {
    const a = computeActionCommitment(canonicalizeToolAction(makeAction()));
    const b = computeActionCommitment(canonicalizeToolAction(makeAction()));
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(a).toBe(b);
  });

  it("is independent of raw payload noise", () => {
    const plain = computeActionCommitment(canonicalizeToolAction(makeAction()));
    const noisy = computeActionCommitment(
      canonicalizeToolAction(makeAction({ raw: { anything: "value" } })),
    );
    expect(plain).toBe(noisy);
  });

  it.each([
    ["runtime", makeAction({ runtime: "codex" })],
    ["phase", makeAction({ phase: "post" })],
    ["sessionId", makeAction({ sessionId: "sess-2" })],
    ["toolName", makeAction({ toolName: "Write" })],
    ["toolInput", makeAction({ toolInput: { command: "rm -rf /" } })],
  ] as Array<[string, ToolAction]>)("changes when the %s field changes", (_label, variant) => {
    const base = computeActionCommitment(canonicalizeToolAction(makeAction()));
    const changed = computeActionCommitment(canonicalizeToolAction(variant));
    expect(changed).not.toBe(base);
  });

  it("gives distinct commitments to actions sharing an identical 200-character prefix", () => {
    // CRITICAL regression: a truncated display summary or a prefix collision
    // must never make two different full actions look identical.
    const prefix = "A".repeat(200);
    const first = makeAction({ toolInput: { command: `${prefix}-SAFE` } });
    const second = makeAction({ toolInput: { command: `${prefix}-DESTRUCTIVE` } });
    expect(first.toolInput.command.slice(0, 200)).toBe(second.toolInput.command.slice(0, 200));
    expect(computeActionCommitment(canonicalizeToolAction(first))).not.toBe(
      computeActionCommitment(canonicalizeToolAction(second)),
    );
  });
});

describe("computePolicyCommitment", () => {
  it("returns a lowercase 64-hex digest and is deterministic", () => {
    const a = computePolicyCommitment(makePolicy());
    const b = computePolicyCommitment(makePolicy());
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(a).toBe(b);
  });

  it.each([
    ["agent.id", makePolicy({ agent: { id: "agent-2", version: "1.0.0" } })],
    ["agent.version", makePolicy({ agent: { id: "agent-1", version: "2.0.0" } })],
    ["rules", makePolicy({ rules: [{ tool: "Bash", allow: false }] })],
  ] as Array<[string, CatpPolicy]>)("changes when %s changes", (_label, variant) => {
    expect(computePolicyCommitment(variant)).not.toBe(computePolicyCommitment(makePolicy()));
  });

  it("is domain-separated from the action commitment", () => {
    // Even if a policy and an action canonicalized to the same bytes (they do
    // not here), the distinct domain strings must produce distinct digests.
    const action = computeActionCommitment(canonicalizeToolAction(makeAction()));
    const policy = computePolicyCommitment(makePolicy());
    expect(action).not.toBe(policy);
  });
});
