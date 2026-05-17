import { describe, expect, it } from "@jest/globals";
import { createHash, generateKeyPairSync } from "node:crypto";
import { signAuthorizationReceipt, verifyAuthorizationReceipt, type AuthorizationReceipt } from "../../src/commands/receipt.js";
import { stableStringify, type AuditExport } from "../../src/commands/log.js";

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

describe("authorization receipt", () => {
  it("signs and verifies a CATP audit export", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const receipt = signAuthorizationReceipt(auditExport(), privateKeyPem, publicKeyPem, "2026-01-01T00:00:01.000Z");

    expect(receipt.receiptVersion).toBe("catp_authorization_receipt_v1");
    expect(receipt.signatureAlgorithm).toBe("Ed25519");
    expect(receipt.auditCommitment).toBe("a".repeat(64));
    expect(receipt.signature).toEqual(expect.any(String));
    expect(() => verifyAuthorizationReceipt(receipt, publicKeyPem)).not.toThrow();
  });

  it("rejects a tampered receipt payload", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const receipt = signAuthorizationReceipt(auditExport(), privateKeyPem, publicKeyPem, "2026-01-01T00:00:01.000Z");
    const tampered: AuthorizationReceipt = { ...receipt, decision: "deny" };

    expect(() => verifyAuthorizationReceipt(tampered, publicKeyPem)).toThrow("signature is invalid");
  });

  it("produces stable receipt JSON for the same payload", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const first = signAuthorizationReceipt(auditExport(), privateKeyPem, publicKeyPem, "2026-01-01T00:00:01.000Z");
    const second = signAuthorizationReceipt(auditExport(), privateKeyPem, publicKeyPem, "2026-01-01T00:00:01.000Z");

    expect(stableStringify(first)).toBe(stableStringify(second));
  });
});
