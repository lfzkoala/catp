import { afterEach, describe, expect, it } from "@jest/globals";
import { createHash, generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
  const entry = {
    ts: "2026-01-01T00:00:00.000Z",
    tool: "Bash",
    decision: "allow" as const,
    rule_matched: null,
    commitment: "a".repeat(64),
    input_summary: "{\"command\":\"ls\"}",
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
    expect(receipt.auditCommitment).toBe("a".repeat(64));
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

  it("issues a receipt directly from an audit commitment", () => {
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
      cmdReceiptIssue({
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
});
