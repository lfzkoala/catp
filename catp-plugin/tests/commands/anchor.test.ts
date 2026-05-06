import { describe, it, expect, afterEach, beforeEach } from "@jest/globals";
import { mkdirSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { readCommitments, merkleRoot, cmdAnchor } from "../../src/commands/anchor.js";

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

  it("skips malformed JSONL lines without throwing", () => {
    const dir = auditDir(TEST_AGENT, "2026-01-01");
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, "actions.jsonl"),
      `not-json\n${JSON.stringify({ ts: "t", tool: "Bash", decision: "allow", rule_matched: null, commitment: "c".repeat(64), input_summary: "" })}\n`,
      "utf8",
    );
    expect(readCommitments(TEST_AGENT)).toEqual(["c".repeat(64)]);
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
    delete process.env.CATP_RPC_URL;
    delete process.env.CATP_PRIVATE_KEY;
    delete process.env.CATP_CONTRACT_ADDRESS;
  });

  it("prints 'No audit entries' when the agent has no log files", async () => {
    await cmdAnchor({ agent: TEST_AGENT, dryRun: true });
    expect(output).toContain("No audit entries");
  });

  it("prints agent id, commitment count, and merkle root for dry-run with entries", async () => {
    writeEntries(TEST_AGENT, "2026-01-01", ["a".repeat(64), "b".repeat(64)]);
    await cmdAnchor({ agent: TEST_AGENT, dryRun: true });
    expect(output).toContain(TEST_AGENT);
    expect(output).toContain("2");
    expect(output).toMatch(/0x[0-9a-f]{64}/);
    expect(output).toContain("Dry run");
  });

  it("prompts to set env vars when not dry-run and env vars are missing", async () => {
    writeEntries(TEST_AGENT, "2026-01-01", ["a".repeat(64)]);
    await cmdAnchor({ agent: TEST_AGENT, dryRun: false });
    expect(output).toContain("CATP_RPC_URL");
  });

  it("throws when agent id cannot be resolved and no policy file is present", async () => {
    await expect(cmdAnchor({ dryRun: true })).rejects.toThrow(/agent ID/i);
  });
});
