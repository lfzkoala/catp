import { afterEach, describe, expect, it } from "@jest/globals";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { computeCommitment } from "../../src/audit/logger.js";
import { buildAuditExport, stableStringify, cmdLogExport, cmdLogShow } from "../../src/commands/log.js";
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

function makeEntry(
  commitment: string,
  opts: Partial<Pick<AuditEntry, "ts" | "tool" | "decision" | "rule_matched" | "input_summary">> = {}
): AuditEntry {
  return {
    ts: opts.ts ?? "2026-01-01T00:00:00.000Z",
    tool: opts.tool ?? "Bash",
    decision: opts.decision ?? "allow",
    rule_matched: opts.rule_matched ?? null,
    commitment,
    input_summary: opts.input_summary ?? "{\"command\":\"ls\"}",
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

  it("exports the latest audit entry without copying a commitment", () => {
    const firstCommitment = computeCommitment("Bash", "allow", "2026-01-01T00:00:00.000Z", "0", null, "{\"command\":\"ls\"}");
    const secondCommitment = computeCommitment("Read", "allow", "2026-01-01T00:00:01.000Z", firstCommitment, null, "{\"file_path\":\"README.md\"}");
    writeEntry(TEST_AGENT, "2026-01-01", makeEntry(firstCommitment));
    writeEntry(
      TEST_AGENT,
      "2026-01-01",
      makeEntry(secondCommitment, {
        ts: "2026-01-01T00:00:01.000Z",
        tool: "Read",
        input_summary: "{\"file_path\":\"README.md\"}",
      })
    );

    const writes: string[] = [];
    const originalWrite = process.stdout.write;
    process.stdout.write = ((chunk: string | Uint8Array) => {
      writes.push(String(chunk));
      return true;
    }) as typeof process.stdout.write;
    try {
      cmdLogExport({ agent: TEST_AGENT, latest: true });
    } finally {
      process.stdout.write = originalWrite;
    }

    const parsed = JSON.parse(writes.join("")) as ReturnType<typeof buildAuditExport>;
    expect(parsed.commitment).toBe(secondCommitment);
    expect(parsed.entry.tool).toBe("Read");
  });

  it("exports the latest audit entry matching a tool and decision", () => {
    const bashCommitment = computeCommitment("Bash", "allow", "2026-01-01T00:00:00.000Z", "0", null, "{\"command\":\"ls\"}");
    const writeAllowCommitment = computeCommitment("Write", "allow", "2026-01-01T00:00:01.000Z", bashCommitment, null, "{\"file_path\":\"README.md\"}");
    const writeDenyCommitment = computeCommitment("Write", "deny", "2026-01-01T00:00:02.000Z", writeAllowCommitment, "deny-write", "{\"file_path\":\"README.md\"}");
    writeEntry(TEST_AGENT, "2026-01-01", makeEntry(bashCommitment));
    writeEntry(
      TEST_AGENT,
      "2026-01-01",
      makeEntry(writeAllowCommitment, {
        ts: "2026-01-01T00:00:01.000Z",
        tool: "Write",
        input_summary: "{\"file_path\":\"README.md\"}",
      })
    );
    writeEntry(
      TEST_AGENT,
      "2026-01-01",
      makeEntry(writeDenyCommitment, {
        ts: "2026-01-01T00:00:02.000Z",
        tool: "Write",
        decision: "deny",
        rule_matched: "deny-write",
        input_summary: "{\"file_path\":\"README.md\"}",
      })
    );

    const writes: string[] = [];
    const originalWrite = process.stdout.write;
    process.stdout.write = ((chunk: string | Uint8Array) => {
      writes.push(String(chunk));
      return true;
    }) as typeof process.stdout.write;
    try {
      cmdLogExport({ agent: TEST_AGENT, tool: "Write", decision: "allow" });
    } finally {
      process.stdout.write = originalWrite;
    }

    const parsed = JSON.parse(writes.join("")) as ReturnType<typeof buildAuditExport>;
    expect(parsed.commitment).toBe(writeAllowCommitment);
    expect(parsed.commitment).not.toBe(writeDenyCommitment);
    expect(parsed.entry.tool).toBe("Write");
    expect(parsed.entry.decision).toBe("allow");
  });

  it("rejects ambiguous audit export selectors", () => {
    expect(() => cmdLogExport({ agent: TEST_AGENT, latest: true, tool: "Write" })).toThrow("use only one of");
  });

  it("rejects a decision filter with an explicit export commitment", () => {
    const commitment = computeCommitment("Bash", "allow", "2026-01-01T00:00:00.000Z", "0", null, "{\"command\":\"ls\"}");
    expect(() => cmdLogExport({ agent: TEST_AGENT, commitment, decision: "allow" })).toThrow("--decision can only be used with --latest or --tool");
  });

  it("shows full commitments when requested", () => {
    const commitment = computeCommitment("Bash", "allow", "2026-01-01T00:00:00.000Z", "0", null, "{\"command\":\"ls\"}");
    writeEntry(TEST_AGENT, "2026-01-01", makeEntry(commitment));

    const writes: string[] = [];
    const originalWrite = process.stdout.write;
    process.stdout.write = ((chunk: string | Uint8Array) => {
      writes.push(String(chunk));
      return true;
    }) as typeof process.stdout.write;
    try {
      cmdLogShow({ agent: TEST_AGENT, lines: "1", commitments: true });
    } finally {
      process.stdout.write = originalWrite;
    }

    expect(writes.join("")).toContain(`commitment=${commitment}`);
  });

  it("shows recent audit entries as JSON", () => {
    const firstCommitment = computeCommitment("Bash", "allow", "2026-01-01T00:00:00.000Z", "0", null, "{\"command\":\"ls\"}");
    const secondCommitment = computeCommitment("Read", "allow", "2026-01-01T00:00:01.000Z", firstCommitment, null, "{\"file_path\":\"README.md\"}");
    writeEntry(TEST_AGENT, "2026-01-01", makeEntry(firstCommitment));
    writeEntry(TEST_AGENT, "2026-01-01", {
      ...makeEntry(secondCommitment),
      ts: "2026-01-01T00:00:01.000Z",
      tool: "Read",
      input_summary: "{\"file_path\":\"README.md\"}",
    });

    const writes: string[] = [];
    const originalWrite = process.stdout.write;
    process.stdout.write = ((chunk: string | Uint8Array) => {
      writes.push(String(chunk));
      return true;
    }) as typeof process.stdout.write;
    try {
      cmdLogShow({ agent: TEST_AGENT, lines: "1", json: true });
    } finally {
      process.stdout.write = originalWrite;
    }

    const parsed = JSON.parse(writes.join("")) as AuditEntry[];
    expect(parsed).toHaveLength(1);
    expect(parsed[0].commitment).toBe(secondCommitment);
    expect(parsed[0].tool).toBe("Read");
  });

  it("filters shown audit entries by tool and decision", () => {
    const bashCommitment = computeCommitment("Bash", "allow", "2026-01-01T00:00:00.000Z", "0", null, "{\"command\":\"ls\"}");
    const writeAllowCommitment = computeCommitment("Write", "allow", "2026-01-01T00:00:01.000Z", bashCommitment, null, "{\"file_path\":\"README.md\"}");
    const writeDenyCommitment = computeCommitment("Write", "deny", "2026-01-01T00:00:02.000Z", writeAllowCommitment, "deny-write", "{\"file_path\":\"README.md\"}");
    writeEntry(TEST_AGENT, "2026-01-01", makeEntry(bashCommitment));
    writeEntry(
      TEST_AGENT,
      "2026-01-01",
      makeEntry(writeAllowCommitment, {
        ts: "2026-01-01T00:00:01.000Z",
        tool: "Write",
        input_summary: "{\"file_path\":\"README.md\"}",
      })
    );
    writeEntry(
      TEST_AGENT,
      "2026-01-01",
      makeEntry(writeDenyCommitment, {
        ts: "2026-01-01T00:00:02.000Z",
        tool: "Write",
        decision: "deny",
        rule_matched: "deny-write",
        input_summary: "{\"file_path\":\"README.md\"}",
      })
    );

    const writes: string[] = [];
    const originalWrite = process.stdout.write;
    process.stdout.write = ((chunk: string | Uint8Array) => {
      writes.push(String(chunk));
      return true;
    }) as typeof process.stdout.write;
    try {
      cmdLogShow({ agent: TEST_AGENT, lines: "10", tool: "Write", decision: "deny", json: true });
    } finally {
      process.stdout.write = originalWrite;
    }

    const parsed = JSON.parse(writes.join("")) as AuditEntry[];
    expect(parsed).toHaveLength(1);
    expect(parsed[0].commitment).toBe(writeDenyCommitment);
    expect(parsed[0].tool).toBe("Write");
    expect(parsed[0].decision).toBe("deny");
  });

  it("shows filtered entries across audit log dates", () => {
    const oldCommitment = computeCommitment("Write", "deny", "2026-01-01T00:00:00.000Z", "0", "deny-write", "{\"file_path\":\"README.md\"}");
    const newCommitment = computeCommitment("Bash", "allow", "2026-01-02T00:00:00.000Z", oldCommitment, null, "{\"command\":\"ls\"}");
    writeEntry(
      TEST_AGENT,
      "2026-01-01",
      makeEntry(oldCommitment, {
        tool: "Write",
        decision: "deny",
        rule_matched: "deny-write",
        input_summary: "{\"file_path\":\"README.md\"}",
      })
    );
    writeEntry(
      TEST_AGENT,
      "2026-01-02",
      makeEntry(newCommitment, {
        ts: "2026-01-02T00:00:00.000Z",
        tool: "Bash",
      })
    );

    const writes: string[] = [];
    const originalWrite = process.stdout.write;
    process.stdout.write = ((chunk: string | Uint8Array) => {
      writes.push(String(chunk));
      return true;
    }) as typeof process.stdout.write;
    try {
      cmdLogShow({ agent: TEST_AGENT, lines: "10", tool: "Write", decision: "deny", json: true });
    } finally {
      process.stdout.write = originalWrite;
    }

    const parsed = JSON.parse(writes.join("")) as AuditEntry[];
    expect(parsed).toHaveLength(1);
    expect(parsed[0].commitment).toBe(oldCommitment);
  });

  it("rejects an invalid log decision filter", () => {
    expect(() => cmdLogShow({ agent: TEST_AGENT, lines: "1", decision: "block" as unknown as "allow" })).toThrow("--decision must be allow or deny");
  });

  it("shows an empty JSON array when no audit log exists", () => {
    const writes: string[] = [];
    const originalWrite = process.stdout.write;
    process.stdout.write = ((chunk: string | Uint8Array) => {
      writes.push(String(chunk));
      return true;
    }) as typeof process.stdout.write;
    try {
      cmdLogShow({ agent: TEST_AGENT, lines: "1", json: true });
    } finally {
      process.stdout.write = originalWrite;
    }

    expect(writes.join("")).toBe("[]\n");
  });
});
