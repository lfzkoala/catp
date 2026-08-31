import { describe, it, expect, afterEach, beforeEach } from "@jest/globals";
import { mkdirSync, readFileSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { readCommitments, merkleRoot, cmdAnchor } from "../../src/commands/anchor.js";
import { computeCommitment } from "../../src/audit/logger.js";

const TEST_AGENT = `__test_anchor__${Date.now()}`;
const TEST_HOME = join(tmpdir(), `catp-plugin-anchor-test-${Date.now()}`);

process.env.CATP_HOME = TEST_HOME;

function auditDir(agentId: string, date = "2026-01-01"): string {
  return join(TEST_HOME, "audit", agentId, date);
}

function writeEntries(agentId: string, date: string, commitments: string[]): void {
  const dir = auditDir(agentId, date);
  mkdirSync(dir, { recursive: true });
  const lines = commitments
    .map((c) =>
      JSON.stringify({
        ts: "2026-01-01T00:00:00.000Z",
        tool: "Bash",
        decision: "allow",
        rule_matched: null,
        commitment: c,
        input_summary: "test",
      }),
    )
    .join("\n");
  writeFileSync(join(dir, "actions.jsonl"), lines + "\n", "utf8");
}

function writeValidEntries(agentId: string, count: number): string[] {
  const commitments: string[] = [];
  let prev = "0";
  for (let index = 0; index < count; index++) {
    const commitment = computeCommitment(
      "Bash",
      "allow",
      "2026-01-01T00:00:00.000Z",
      prev,
      null,
      "test",
    );
    commitments.push(commitment);
    prev = commitment;
  }
  writeEntries(agentId, "2026-01-01", commitments);
  return commitments;
}

afterEach(() => {
  const base = join(TEST_HOME, "audit", TEST_AGENT);
  if (existsSync(base)) rmSync(base, { recursive: true, force: true });
});

// ─── readCommitments ────────────────────────────────────────────────────────

describe("readCommitments", () => {
  it("returns empty array when audit dir does not exist", () => {
    expect(readCommitments("__nonexistent_agent__")).toEqual([]);
  });

  it("returns commitments from a single date directory", () => {
    writeEntries(TEST_AGENT, "2026-01-01", ["a".repeat(64), "b".repeat(64)]);
    expect(readCommitments(TEST_AGENT)).toEqual(["a".repeat(64), "b".repeat(64)]);
  });

  it("returns commitments across multiple date directories in sorted order", () => {
    writeEntries(TEST_AGENT, "2026-01-01", ["a".repeat(64)]);
    writeEntries(TEST_AGENT, "2026-01-02", ["b".repeat(64)]);
    expect(readCommitments(TEST_AGENT)).toEqual(["a".repeat(64), "b".repeat(64)]);
  });

  it("rejects malformed JSONL instead of omitting it from the root", () => {
    const dir = auditDir(TEST_AGENT, "2026-01-01");
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, "actions.jsonl"),
      `not-json\n${JSON.stringify({ ts: "t", tool: "Bash", decision: "allow", rule_matched: null, commitment: "c".repeat(64), input_summary: "" })}\n`,
      "utf8",
    );
    expect(() => readCommitments(TEST_AGENT)).toThrow(/invalid JSON/i);
  });

  it("returns empty array when actions.jsonl is empty", () => {
    const dir = auditDir(TEST_AGENT, "2026-01-01");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "actions.jsonl"), "", "utf8");
    expect(readCommitments(TEST_AGENT)).toEqual([]);
  });
});

// ─── merkleRoot ─────────────────────────────────────────────────────────────

describe("merkleRoot", () => {
  it("returns 32 zero bytes for empty input", () => {
    expect(merkleRoot([])).toBe(`0x${"00".repeat(32)}`);
  });

  it("returns a 0x-prefixed 64-char hex string", () => {
    expect(merkleRoot(["a".repeat(64)])).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("single commitment produces a deterministic root", () => {
    expect(merkleRoot(["a".repeat(64)])).toBe(merkleRoot(["a".repeat(64)]));
  });

  it("two different commitments produce different roots", () => {
    expect(merkleRoot(["a".repeat(64)])).not.toBe(merkleRoot(["b".repeat(64)]));
  });

  it("order matters — swapping commitments changes the root", () => {
    const a = "a".repeat(64);
    const b = "b".repeat(64);
    expect(merkleRoot([a, b])).not.toBe(merkleRoot([b, a]));
  });

  it("odd number of leaves duplicates the last leaf and is deterministic", () => {
    const leaves = ["a", "b", "c"].map((c) => c.repeat(64));
    expect(merkleRoot(leaves)).toBe(merkleRoot(leaves));
    expect(merkleRoot(leaves)).not.toBe(merkleRoot(leaves.slice(0, 2)));
  });

  it("four leaves produces a deterministic root", () => {
    const leaves = ["a", "b", "c", "d"].map((c) => c.repeat(64));
    expect(merkleRoot(leaves)).toMatch(/^0x[0-9a-f]{64}$/);
    expect(merkleRoot(leaves)).toBe(merkleRoot(leaves));
  });
});

// ─── cmdAnchor ───────────────────────────────────────────────────────────────

describe("cmdAnchor", () => {
  let output: string;
  let origWrite: typeof process.stdout.write;

  beforeEach(() => {
    output = "";
    origWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((chunk: unknown) => {
      output += String(chunk);
      return true;
    }) as typeof process.stdout.write;
  });

  afterEach(() => {
    process.stdout.write = origWrite;
  });

  it("prints 'No audit entries' when the agent has no log files", async () => {
    await cmdAnchor({ agent: TEST_AGENT });
    expect(output).toContain("No audit entries");
  });

  it("prints agent id, commitment count, and merkle root", async () => {
    writeValidEntries(TEST_AGENT, 2);
    await cmdAnchor({ agent: TEST_AGENT });
    expect(output).toContain(TEST_AGENT);
    expect(output).toContain("2");
    expect(output).toMatch(/0x[0-9a-f]{64}/);
  });

  it("throws when agent id cannot be resolved and no policy file is present", async () => {
    await expect(cmdAnchor({})).rejects.toThrow(/agent ID/i);
  });

  it("resolves agent id from catp-policy.toml when --agent is omitted", async () => {
    const policyDir = join(TEST_HOME, "policy-cwd");
    mkdirSync(policyDir, { recursive: true });
    writeFileSync(
      join(policyDir, "catp-policy.toml"),
      'rules = []\n\n[agent]\nid = "policy-agent"\nversion = "1"\n',
      "utf8",
    );
    const prevCwd = process.cwd();
    process.chdir(policyDir);
    try {
      await cmdAnchor({});
      expect(output).toContain("policy-agent");
      expect(output).toContain("No audit entries");
    } finally {
      process.chdir(prevCwd);
    }
  });

  it("falls through to an error when catp-policy.toml is invalid", async () => {
    const policyDir = join(TEST_HOME, "policy-bad-cwd");
    mkdirSync(policyDir, { recursive: true });
    writeFileSync(
      join(policyDir, "catp-policy.toml"),
      'rules = []\n\n[agent]\nid = ""\nversion = "1"\n',
      "utf8",
    );
    const prevCwd = process.cwd();
    process.chdir(policyDir);
    try {
      await expect(cmdAnchor({})).rejects.toThrow(/agent ID/i);
    } finally {
      process.chdir(prevCwd);
    }
  });

  it("writes a portable audit anchor bundle", async () => {
    const [commitment] = writeValidEntries(TEST_AGENT, 1);
    const out = join(TEST_HOME, "anchor.json");
    await cmdAnchor({ agent: TEST_AGENT, out });

    expect(JSON.parse(readFileSync(out, "utf8"))).toEqual({
      anchorVersion: "catp_audit_anchor_v1",
      agentId: TEST_AGENT,
      commitmentCount: 1,
      merkleRoot: `0x${commitment}`,
    });
  });
});
