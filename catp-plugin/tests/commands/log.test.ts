import { afterEach, describe, expect, it } from "@jest/globals";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { appendChainedAuditEntry, buildEntry, computeCommitment } from "../../src/audit/logger.js";
import { buildAuditExport, buildAuditExportV2, stableStringify, cmdLogExport, cmdLogShow } from "../../src/commands/log.js";
import { canonicalizeToolAction, computeActionCommitment, computePolicyCommitment } from "../../src/evidence/commitments.js";
import { actionSidecarPath, auditRoot } from "../../src/audit/paths.js";
import type { AuditEntry, AuditEntryV4, CatpPolicy } from "../../src/policy/types.js";
import type { ToolAction } from "../../src/runtime/types.js";

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

const TEST_POLICY: CatpPolicy = { agent: { id: "test", version: "1" }, rules: [] };

function makeAction(
  tool: string,
  toolInput: Record<string, unknown> = {},
  phase: "pre" | "post" = "pre",
): ToolAction {
  return { runtime: "test-runtime", phase, toolName: tool, toolInput };
}

// Locate the daily audit directory from the filesystem rather than re-deriving
// it from the current time, so the helpers cannot flake across a UTC midnight.
function latestAuditDate(agentId: string): string {
  const dates = readdirSync(auditRoot(agentId)).sort();
  return dates[dates.length - 1];
}

function sidecarFor(agentId: string, entry: AuditEntryV4): string {
  return actionSidecarPath(agentId, latestAuditDate(agentId), entry.action_commitment);
}

// Append a real v4 entry through the durable logger so both the daily chain and
// the content-addressed action sidecar land on disk exactly as the pre-hook
// writes them.
function seedV4(
  agentId: string,
  tool: string,
  toolInput: Record<string, unknown> = {},
  opts: { decision?: "allow" | "deny"; phase?: "pre" | "post"; ruleMatched?: string | null; reason?: string } = {},
): AuditEntryV4 {
  const input = makeAction(tool, toolInput, opts.phase ?? "pre");
  const action = canonicalizeToolAction(input);
  const decision = opts.decision ?? "allow";
  const result = appendChainedAuditEntry(agentId, (prev) => ({
    auditEntry: buildEntry(input, decision, opts.ruleMatched ?? null, prev, {
      reason: opts.reason ?? "test-reason",
      policyCommitment: computePolicyCommitment(TEST_POLICY),
      actionCommitment: computeActionCommitment(action),
    }),
    action,
  }));
  return result.auditEntry;
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

  it("writes a self-contained v2 audit export to a file", () => {
    const entry = seedV4(TEST_AGENT, "Bash", { command: "ls" });
    const outPath = join(TEST_HOME, "audit-export.json");

    const writes: string[] = [];
    const originalWrite = process.stdout.write;
    process.stdout.write = ((chunk: string | Uint8Array) => {
      writes.push(String(chunk));
      return true;
    }) as typeof process.stdout.write;
    try {
      cmdLogExport({ agent: TEST_AGENT, commitment: entry.commitment, out: outPath });
    } finally {
      process.stdout.write = originalWrite;
    }

    const parsed = JSON.parse(readFileSync(outPath, "utf8")) as ReturnType<typeof buildAuditExportV2>;
    expect(parsed.export_version).toBe("catp_audit_export_v2");
    expect(parsed.action.tool_name).toBe("Bash");
    expect(writes.join("")).toContain(`Wrote audit export to ${outPath}`);
    expect(writes.join("")).toContain("exportSha256=");
  });

  it("exports the latest v4 audit entry as a v2 bundle", () => {
    seedV4(TEST_AGENT, "Bash", { command: "ls" });
    const second = seedV4(TEST_AGENT, "Read", { file_path: "README.md" });

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

    const parsed = JSON.parse(writes.join("")) as ReturnType<typeof buildAuditExportV2>;
    expect(parsed.selected_index).toBe(1);
    expect(parsed.entries).toHaveLength(2);
    expect(parsed.entries[parsed.selected_index].commitment).toBe(second.commitment);
    expect(parsed.action.tool_name).toBe("Read");
  });

  it("exports the latest v4 audit entry matching a tool and decision", () => {
    seedV4(TEST_AGENT, "Bash", { command: "ls" });
    const writeAllow = seedV4(TEST_AGENT, "Write", { file_path: "README.md" });
    const writeDeny = seedV4(TEST_AGENT, "Write", { file_path: "/etc/passwd" }, { decision: "deny", ruleMatched: "deny-write" });

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

    const parsed = JSON.parse(writes.join("")) as ReturnType<typeof buildAuditExportV2>;
    const selected = parsed.entries[parsed.selected_index] as AuditEntryV4;
    expect(selected.commitment).toBe(writeAllow.commitment);
    expect(selected.commitment).not.toBe(writeDeny.commitment);
    expect(parsed.action.tool_input).toEqual({ file_path: "README.md" });
  });

  it("builds a deterministic v2 bundle binding the selected entry to its exact action", () => {
    seedV4(TEST_AGENT, "Bash", { command: "ls" });
    const entry = seedV4(TEST_AGENT, "Write", { file_path: "README.md" });

    const first = buildAuditExportV2(TEST_AGENT, entry.commitment);
    const second = buildAuditExportV2(TEST_AGENT, entry.commitment.toUpperCase());

    expect(first).toEqual(second);
    expect(first.export_version).toBe("catp_audit_export_v2");
    expect(first.agent_id).toBe(TEST_AGENT);
    expect(first.selected_index).toBe(1);
    expect(first.entries).toHaveLength(first.selected_index + 1);
    expect((first.entries[first.selected_index] as AuditEntryV4).commitment).toBe(entry.commitment);
    expect(computeActionCommitment(first.action)).toBe(entry.action_commitment);
    expect(first.export_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(stableStringify(first)).toBe(stableStringify(second));
  });

  it("rejects a v2 export when the action sidecar is missing", () => {
    const entry = seedV4(TEST_AGENT, "Bash", { command: "ls" });
    rmSync(sidecarFor(TEST_AGENT, entry));
    expect(() => buildAuditExportV2(TEST_AGENT, entry.commitment)).toThrow("missing action evidence sidecar");
  });

  it("rejects a v2 export when the action sidecar is altered", () => {
    const entry = seedV4(TEST_AGENT, "Bash", { command: "ls" });
    const sidecar = sidecarFor(TEST_AGENT, entry);
    writeFileSync(sidecar, stableStringify({ runtime: "test-runtime", phase: "pre", tool_name: "Bash", tool_input: { command: "rm -rf /" } }), "utf8");
    expect(() => buildAuditExportV2(TEST_AGENT, entry.commitment)).toThrow("does not match the audit entry action_commitment");
  });

  it("rejects a v2 export for a non-v4 selected entry", () => {
    const commitment = computeCommitment("Bash", "allow", "2026-01-01T00:00:00.000Z", "0", null, "{\"command\":\"ls\"}");
    writeEntry(TEST_AGENT, "2026-01-01", makeEntry(commitment));
    expect(() => buildAuditExportV2(TEST_AGENT, commitment)).toThrow("commitment version 4");
  });

  it("exports a selected post entry as a v2 bundle", () => {
    const entry = seedV4(TEST_AGENT, "Bash", { command: "ls" }, { phase: "post" });
    const exported = buildAuditExportV2(TEST_AGENT, entry.commitment);
    expect(exported.action.phase).toBe("post");
    expect(computeActionCommitment(exported.action)).toBe(entry.action_commitment);
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
