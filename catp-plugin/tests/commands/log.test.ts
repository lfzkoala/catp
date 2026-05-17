import { afterEach, describe, expect, it } from "@jest/globals";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { computeCommitment } from "../../src/audit/logger.js";
import { buildAuditExport, stableStringify, cmdLogExport } from "../../src/commands/log.js";
import type { AuditEntry } from "../../src/policy/types.js";

const TEST_HOME = join(tmpdir(), `catp-log-command-test-${Date.now()}`);
const TEST_AGENT = "log-export-agent";

process.env.CATP_HOME = TEST_HOME;

afterEach(() => {
  if (existsSync(TEST_HOME)) {
    rmSync(TEST_HOME, { recursive: true, force: true });
  }
});

function writeEntry(agentId: string, date: string, entry: AuditEntry): void {
  const dir = join(TEST_HOME, "audit", agentId, date);
  mkdirSync(dir, { recursive: true });
  const file = join(dir, "actions.jsonl");
  mkdirSync(dir, { recursive: true });
  const existing = existsSync(file) ? readFileSync(file, "utf8") : "";
  writeFileSync(file, existing + JSON.stringify(entry) + "\n", "utf8");
}

function makeEntry(commitment: string): AuditEntry {
  return {
    ts: "2026-01-01T00:00:00.000Z",
    tool: "Bash",
    decision: "allow",
    rule_matched: null,
    commitment,
    input_summary: "{\"command\":\"ls\"}",
  };
}

describe("log export", () => {
  it("builds a deterministic audit export for a commitment", () => {
    const commitment = computeCommitment("Bash", "allow", "2026-01-01T00:00:00.000Z", "0", null, "{\"command\":\"ls\"}");
    writeEntry(TEST_AGENT, "2026-01-01", makeEntry(commitment));

    const first = buildAuditExport(TEST_AGENT, commitment);
    const second = buildAuditExport(TEST_AGENT, commitment.toUpperCase());

    expect(first).toEqual(second);
    expect(first.exportVersion).toBe("catp_audit_export_v1");
    expect(first.agentId).toBe(TEST_AGENT);
    expect(first.logDate).toBe("2026-01-01");
    expect(first.entryIndex).toBe(0);
    expect(first.commitment).toBe(commitment);
    expect(first.entrySha256).toMatch(/^[0-9a-f]{64}$/);
    expect(stableStringify(first)).toBe(stableStringify(second));
  });

  it("throws when the commitment is not found", () => {
    expect(() => buildAuditExport(TEST_AGENT, "a".repeat(64))).toThrow("No audit entry found");
  });

  it("writes audit export JSON to a file", () => {
    const commitment = computeCommitment("Bash", "allow", "2026-01-01T00:00:00.000Z", "0", null, "{\"command\":\"ls\"}");
    writeEntry(TEST_AGENT, "2026-01-01", makeEntry(commitment));
    const outPath = join(TEST_HOME, "audit-export.json");

    const writes: string[] = [];
    const originalWrite = process.stdout.write;
    process.stdout.write = ((chunk: string | Uint8Array) => {
      writes.push(String(chunk));
      return true;
    }) as typeof process.stdout.write;
    try {
      cmdLogExport({ agent: TEST_AGENT, commitment, out: outPath });
    } finally {
      process.stdout.write = originalWrite;
    }

    const parsed = JSON.parse(readFileSync(outPath, "utf8")) as ReturnType<typeof buildAuditExport>;
    expect(parsed.commitment).toBe(commitment);
    expect(writes.join("")).toContain(`Wrote audit export to ${outPath}`);
    expect(writes.join("")).toContain("entrySha256=");
  });
});
