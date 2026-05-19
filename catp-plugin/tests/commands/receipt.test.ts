import { afterEach, describe, expect, it } from "@jest/globals";
import { createHash, generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { computeCommitment } from "../../src/audit/logger.js";
import {
  cmdReceiptIssue,
  signAuthorizationReceipt,
  verifyAuthorizationReceipt,
  verifyReceiptAuditExport,
  verifyReceiptPolicy,
  computePolicyCommitment,
  type AuthorizationReceipt,
} from "../../src/commands/receipt.js";
import { stableStringify, type AuditExport } from "../../src/commands/log.js";
import type { CatpPolicy } from "../../src/policy/types.js";

const TEST_HOME = join(tmpdir(), `catp-receipt-command-test-${Date.now()}`);
process.env.CATP_HOME = TEST_HOME;

function keyPair(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}

function auditExport(): AuditExport {
  const ts = "2026-01-01T00:00:00.000Z";
  const inputSummary = "{\"command\":\"ls\"}";
  const entry = {
    ts,
    tool: "Bash",
    decision: "allow" as const,
    rule_matched: null,
    commitment: computeCommitment("Bash", "allow", ts, "0", null, inputSummary),
    input_summary: inputSummary,
  };
  return {
    exportVersion: "catp_audit_export_v1",
    agentId: "receipt-agent",
    logDate: "2026-01-01",
    entryIndex: 0,
    commitment: entry.commitment,
    entrySha256: createHash("sha256").update(stableStringify(entry)).digest("hex"),
    entry,
  };
}

function policy(): CatpPolicy {
  return {
    agent: { id: "receipt-agent", version: "1" },
    rules: [{ tool: "Bash", allow: true }],
  };
}

function writeAuditEntry(agentId: string, date: string, exportedAudit: AuditExport): void {
  const dir = join(TEST_HOME, "audit", agentId, date);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "actions.jsonl"), JSON.stringify(exportedAudit.entry) + "\n", "utf8");
}

function writeAuditEntries(agentId: string, date: string, entries: AuditExport[]): void {
  const dir = join(TEST_HOME, "audit", agentId, date);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "actions.jsonl"), entries.map((entry) => JSON.stringify(entry.entry)).join("\n") + "\n", "utf8");
}

describe("authorization receipt", () => {
  afterEach(() => {
    if (existsSync(TEST_HOME)) {
      rmSync(TEST_HOME, { recursive: true, force: true });
    }
  });

  it("signs and verifies a CATP audit export", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const receipt = signAuthorizationReceipt(auditExport(), privateKeyPem, publicKeyPem, {
      signedAt: "2026-01-01T00:00:01.000Z",
    });

    expect(receipt.receiptVersion).toBe("catp_authorization_receipt_v1");
    expect(receipt.signatureAlgorithm).toBe("Ed25519");
    expect(receipt.auditCommitment).toBe(auditExport().commitment);
    expect(receipt.signature).toEqual(expect.any(String));
    expect(() => verifyAuthorizationReceipt(receipt, publicKeyPem)).not.toThrow();
  });

  it("rejects a tampered receipt payload", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const receipt = signAuthorizationReceipt(auditExport(), privateKeyPem, publicKeyPem, {
      signedAt: "2026-01-01T00:00:01.000Z",
    });
    const tampered: AuthorizationReceipt = { ...receipt, decision: "deny" };

    expect(() => verifyAuthorizationReceipt(tampered, publicKeyPem)).toThrow("signature is invalid");
  });

  it("rejects verification with the wrong public key", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const wrongKey = keyPair();
    const receipt = signAuthorizationReceipt(auditExport(), privateKeyPem, publicKeyPem, {
      signedAt: "2026-01-01T00:00:01.000Z",
    });

    expect(() => verifyAuthorizationReceipt(receipt, wrongKey.publicKeyPem)).toThrow("signature is invalid");
  });

  it("rejects a tampered embedded public key", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const wrongKey = keyPair();
    const receipt = signAuthorizationReceipt(auditExport(), privateKeyPem, publicKeyPem, {
      signedAt: "2026-01-01T00:00:01.000Z",
    });
    const tampered: AuthorizationReceipt = { ...receipt, publicKeyPem: wrongKey.publicKeyPem };

    expect(() => verifyAuthorizationReceipt(tampered, publicKeyPem)).toThrow("signature is invalid");
  });

  it("rejects a tampered signature", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const receipt = signAuthorizationReceipt(auditExport(), privateKeyPem, publicKeyPem, {
      signedAt: "2026-01-01T00:00:01.000Z",
    });
    const tampered: AuthorizationReceipt = { ...receipt, signature: Buffer.from("tampered").toString("base64") };

    expect(() => verifyAuthorizationReceipt(tampered, publicKeyPem)).toThrow("signature is invalid");
  });

  it("checks that a receipt matches its audit export", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const exportedAudit = auditExport();
    const receipt = signAuthorizationReceipt(exportedAudit, privateKeyPem, publicKeyPem, {
      signedAt: "2026-01-01T00:00:01.000Z",
    });

    expect(() => verifyReceiptAuditExport(receipt, exportedAudit)).not.toThrow();
  });

  it("rejects a receipt that does not match the supplied audit export", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const exportedAudit = auditExport();
    const receipt = signAuthorizationReceipt(exportedAudit, privateKeyPem, publicKeyPem, {
      signedAt: "2026-01-01T00:00:01.000Z",
    });
    const differentExport: AuditExport = {
      ...exportedAudit,
      entry: { ...exportedAudit.entry, tool: "Write" },
    };
    differentExport.entrySha256 = createHash("sha256").update(stableStringify(differentExport.entry)).digest("hex");

    expect(() => verifyReceiptAuditExport(receipt, differentExport)).toThrow("auditExportHash does not match");
  });

  it("binds and verifies a policy commitment", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const signedPolicy = policy();
    const receipt = signAuthorizationReceipt(auditExport(), privateKeyPem, publicKeyPem, {
      signedAt: "2026-01-01T00:00:01.000Z",
      policyCommitment: computePolicyCommitment(signedPolicy),
    });

    expect(receipt.policyCommitment).toBe(computePolicyCommitment(signedPolicy));
    expect(() => verifyAuthorizationReceipt(receipt, publicKeyPem)).not.toThrow();
    expect(() => verifyReceiptPolicy(receipt, signedPolicy)).not.toThrow();
  });

  it("rejects a receipt policy mismatch", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const signedPolicy = policy();
    const receipt = signAuthorizationReceipt(auditExport(), privateKeyPem, publicKeyPem, {
      signedAt: "2026-01-01T00:00:01.000Z",
      policyCommitment: computePolicyCommitment(signedPolicy),
    });
    const differentPolicy: CatpPolicy = {
      ...signedPolicy,
      rules: [{ tool: "Write", allow: false }],
    };

    expect(() => verifyReceiptPolicy(receipt, differentPolicy)).toThrow("policyCommitment does not match");
  });

  it("rejects policy verification when a receipt has no policy commitment", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const receipt = signAuthorizationReceipt(auditExport(), privateKeyPem, publicKeyPem, {
      signedAt: "2026-01-01T00:00:01.000Z",
    });

    expect(() => verifyReceiptPolicy(receipt, policy())).toThrow("receipt has no policyCommitment");
  });

  it("produces stable receipt JSON for the same payload", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const first = signAuthorizationReceipt(auditExport(), privateKeyPem, publicKeyPem, {
      signedAt: "2026-01-01T00:00:01.000Z",
    });
    const second = signAuthorizationReceipt(auditExport(), privateKeyPem, publicKeyPem, {
      signedAt: "2026-01-01T00:00:01.000Z",
    });

    expect(stableStringify(first)).toBe(stableStringify(second));
  });

  it("issues a receipt directly from an audit commitment", async () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const exportedAudit = auditExport();
    writeAuditEntry(exportedAudit.agentId, exportedAudit.logDate, exportedAudit);

    const dir = join(TEST_HOME, "issue");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    const receiptPath = join(dir, "receipt.json");
    const auditExportPath = join(dir, "audit-export.json");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");

    const writes: string[] = [];
    const originalWrite = process.stdout.write;
    process.stdout.write = ((chunk: string | Uint8Array) => {
      writes.push(String(chunk));
      return true;
    }) as typeof process.stdout.write;
    try {
      await cmdReceiptIssue({
        agent: exportedAudit.agentId,
        commitment: exportedAudit.commitment,
        privateKey: privateKeyPath,
        out: receiptPath,
        auditExportOut: auditExportPath,
      });
    } finally {
      process.stdout.write = originalWrite;
    }

    const receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as AuthorizationReceipt;
    const issuedAuditExport = JSON.parse(readFileSync(auditExportPath, "utf8")) as AuditExport;
    expect(() => verifyAuthorizationReceipt(receipt, publicKeyPem)).not.toThrow();
    expect(() => verifyReceiptAuditExport(receipt, issuedAuditExport)).not.toThrow();
    expect(writes.join("")).toContain(`Wrote authorization receipt to ${receiptPath}`);
    expect(writes.join("")).toContain(`Wrote audit export to ${auditExportPath}`);
  });

  it("issues a receipt for the latest audit entry", async () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const first = auditExport();
    const secondEntry = {
      ts: "2026-01-01T00:01:00.000Z",
      tool: "Write",
      decision: "allow" as const,
      rule_matched: null,
      commitment: computeCommitment("Write", "allow", "2026-01-01T00:01:00.000Z", first.commitment, null, "{\"file\":\"README.md\"}"),
      input_summary: "{\"file\":\"README.md\"}",
    };
    const second: AuditExport = {
      exportVersion: "catp_audit_export_v1",
      agentId: first.agentId,
      logDate: first.logDate,
      entryIndex: 1,
      commitment: secondEntry.commitment,
      entrySha256: createHash("sha256").update(stableStringify(secondEntry)).digest("hex"),
      entry: secondEntry,
    };
    writeAuditEntries(first.agentId, first.logDate, [first, second]);

    const dir = join(TEST_HOME, "latest-issue");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    const receiptPath = join(dir, "receipt.json");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");

    const originalWrite = process.stdout.write;
    process.stdout.write = (() => true) as typeof process.stdout.write;
    try {
      await cmdReceiptIssue({
        agent: first.agentId,
        latest: true,
        privateKey: privateKeyPath,
        out: receiptPath,
      });
    } finally {
      process.stdout.write = originalWrite;
    }

    const receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as AuthorizationReceipt;
    expect(() => verifyAuthorizationReceipt(receipt, publicKeyPem)).not.toThrow();
    expect(receipt.auditCommitment).toBe(second.commitment);
    expect(receipt.tool).toBe("Write");
  });

  it("issues a receipt for the latest audit entry matching a tool", async () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const first = auditExport();
    const secondEntry = {
      ts: "2026-01-01T00:01:00.000Z",
      tool: "Write",
      decision: "allow" as const,
      rule_matched: null,
      commitment: computeCommitment("Write", "allow", "2026-01-01T00:01:00.000Z", first.commitment, null, "{\"file\":\"README.md\"}"),
      input_summary: "{\"file\":\"README.md\"}",
    };
    const second: AuditExport = {
      exportVersion: "catp_audit_export_v1",
      agentId: first.agentId,
      logDate: first.logDate,
      entryIndex: 1,
      commitment: secondEntry.commitment,
      entrySha256: createHash("sha256").update(stableStringify(secondEntry)).digest("hex"),
      entry: secondEntry,
    };
    writeAuditEntries(first.agentId, first.logDate, [first, second]);

    const dir = join(TEST_HOME, "tool-issue");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    const receiptPath = join(dir, "receipt.json");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");

    const originalWrite = process.stdout.write;
    process.stdout.write = (() => true) as typeof process.stdout.write;
    try {
      await cmdReceiptIssue({
        agent: first.agentId,
        tool: "Bash",
        privateKey: privateKeyPath,
        out: receiptPath,
      });
    } finally {
      process.stdout.write = originalWrite;
    }

    const receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as AuthorizationReceipt;
    expect(() => verifyAuthorizationReceipt(receipt, publicKeyPem)).not.toThrow();
    expect(receipt.auditCommitment).toBe(first.commitment);
    expect(receipt.tool).toBe("Bash");
  });

  it("rejects a receipt tool selector with no matching audit entry", async () => {
    const { privateKeyPem } = keyPair();
    const exportedAudit = auditExport();
    writeAuditEntry(exportedAudit.agentId, exportedAudit.logDate, exportedAudit);

    const dir = join(TEST_HOME, "missing-tool-issue");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");

    await expect(
      cmdReceiptIssue({
        agent: exportedAudit.agentId,
        tool: "Write",
        privateKey: privateKeyPath,
      })
    ).rejects.toThrow('No audit log entry found for agent "receipt-agent" and tool "Write"');
  });

  it("refuses to issue a receipt from a broken audit log", async () => {
    const { privateKeyPem } = keyPair();
    const exportedAudit = auditExport();
    writeAuditEntry(exportedAudit.agentId, exportedAudit.logDate, {
      ...exportedAudit,
      entry: { ...exportedAudit.entry, commitment: "b".repeat(64) },
    });

    const dir = join(TEST_HOME, "broken-issue");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");

    await expect(
      cmdReceiptIssue({
        agent: exportedAudit.agentId,
        commitment: "b".repeat(64),
        privateKey: privateKeyPath,
      })
    ).rejects.toThrow("audit log chain is broken");
  });
});
