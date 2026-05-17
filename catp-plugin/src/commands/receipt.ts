import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { buildAuditExport, stableStringify, type AuditExport } from "./log.js";
import { findPolicyFile, loadPolicy } from "../policy/loader.js";
import type { CatpPolicy } from "../policy/types.js";

export interface AuthorizationReceiptPayload {
  receiptVersion: "catp_authorization_receipt_v1";
  auditExportHash: string;
  auditCommitment: string;
  entrySha256: string;
  agentId: string;
  tool: string;
  decision: "allow" | "deny";
  timestamp: string;
  policyCommitment: string | null;
  signedAt: string;
  signatureAlgorithm: "Ed25519";
  publicKeyPem: string;
}

export interface AuthorizationReceipt extends AuthorizationReceiptPayload {
  signature: string;
}

export function cmdReceiptKeygen(opts: { privateKey?: string; publicKey?: string }): void {
  const privateKeyPath = opts.privateKey ?? "catp-receipt-private.pem";
  const publicKeyPath = opts.publicKey ?? "catp-receipt-public.pem";
  const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });

  writeFileSync(privateKeyPath, privateKey, { encoding: "utf8", mode: 0o600 });
  writeFileSync(publicKeyPath, publicKey, "utf8");
  process.stdout.write(`Wrote private key to ${privateKeyPath}\n`);
  process.stdout.write(`Wrote public key to ${publicKeyPath}\n`);
}

export function cmdReceiptSign(opts: { auditExport?: string; privateKey?: string; out?: string; file?: string }): void {
  if (!opts.auditExport) {
    throw new Error("missing --audit-export <path>");
  }
  if (!opts.privateKey) {
    throw new Error("missing --private-key <path>");
  }

  const auditExport = readAuditExport(opts.auditExport);
  const privateKeyPem = readFileSync(opts.privateKey, "utf8");
  const publicKeyPem = derivePublicKeyPem(privateKeyPem);
  const policyCommitment = opts.file ? computePolicyCommitment(loadPolicy(opts.file)) : resolvePolicyCommitmentIfPresent();
  const receipt = signAuthorizationReceipt(auditExport, privateKeyPem, publicKeyPem, { policyCommitment });
  const json = stableStringify(receipt, 2) + "\n";

  if (opts.out) {
    writeFileSync(opts.out, json, "utf8");
    process.stdout.write(`Wrote authorization receipt to ${opts.out}\n`);
    process.stdout.write(`auditCommitment=${receipt.auditCommitment}\n`);
    process.stdout.write(`auditExportHash=${receipt.auditExportHash}\n`);
    process.stdout.write(`policyCommitment=${receipt.policyCommitment ?? "none"}\n`);
    return;
  }

  process.stdout.write(json);
}

export function cmdReceiptIssue(opts: {
  commitment?: string;
  agent?: string;
  privateKey?: string;
  out?: string;
  file?: string;
  auditExportOut?: string;
}): void {
  if (!opts.commitment) {
    throw new Error("missing --commitment <hex>");
  }
  if (!opts.privateKey) {
    throw new Error("missing --private-key <path>");
  }

  const policyPath = opts.file ?? findPolicyFile();
  const policy = policyPath ? loadPolicy(policyPath) : null;
  const agentId = opts.agent ?? policy?.agent.id;
  if (!agentId) {
    throw new Error("missing --agent <id>; no catp-policy.toml found");
  }

  const auditExport = buildAuditExport(agentId, opts.commitment);
  const privateKeyPem = readFileSync(opts.privateKey, "utf8");
  const publicKeyPem = derivePublicKeyPem(privateKeyPem);
  const receipt = signAuthorizationReceipt(auditExport, privateKeyPem, publicKeyPem, {
    policyCommitment: policy ? computePolicyCommitment(policy) : null,
  });

  if (opts.auditExportOut) {
    writeFileSync(opts.auditExportOut, stableStringify(auditExport, 2) + "\n", "utf8");
  }

  const json = stableStringify(receipt, 2) + "\n";
  if (opts.out) {
    writeFileSync(opts.out, json, "utf8");
    process.stdout.write(`Wrote authorization receipt to ${opts.out}\n`);
    if (opts.auditExportOut) {
      process.stdout.write(`Wrote audit export to ${opts.auditExportOut}\n`);
    }
    process.stdout.write(`auditCommitment=${receipt.auditCommitment}\n`);
    process.stdout.write(`auditExportHash=${receipt.auditExportHash}\n`);
    process.stdout.write(`policyCommitment=${receipt.policyCommitment ?? "none"}\n`);
    return;
  }

  process.stdout.write(json);
}

export function cmdReceiptVerify(opts: { receipt?: string; publicKey?: string; auditExport?: string; file?: string }): void {
  if (!opts.receipt) {
    throw new Error("missing --receipt <path>");
  }
  const receipt = readAuthorizationReceipt(opts.receipt);
  const publicKeyPem = opts.publicKey ? readFileSync(opts.publicKey, "utf8") : receipt.publicKeyPem;
  verifyAuthorizationReceipt(receipt, publicKeyPem);
  if (opts.auditExport) {
    const auditExport = readAuditExport(opts.auditExport);
    verifyReceiptAuditExport(receipt, auditExport);
  }
  if (opts.file) {
    verifyReceiptPolicy(receipt, loadPolicy(opts.file));
  }
  process.stdout.write("authorizationReceipt=valid\n");
  if (opts.auditExport) {
    process.stdout.write("auditExport=matched\n");
  }
  if (opts.file) {
    process.stdout.write("policy=matched\n");
  }
  process.stdout.write(`auditCommitment=${receipt.auditCommitment}\n`);
  process.stdout.write(`auditExportHash=${receipt.auditExportHash}\n`);
  process.stdout.write(`policyCommitment=${receipt.policyCommitment ?? "none"}\n`);
}

export function signAuthorizationReceipt(
  auditExport: AuditExport,
  privateKeyPem: string,
  publicKeyPem: string,
  opts: { signedAt?: string; policyCommitment?: string | null } = {}
): AuthorizationReceipt {
  validateAuditExport(auditExport);
  if (opts.policyCommitment !== undefined && opts.policyCommitment !== null) {
    assertHex(opts.policyCommitment, "policyCommitment");
  }
  const payload: AuthorizationReceiptPayload = {
    receiptVersion: "catp_authorization_receipt_v1",
    auditExportHash: sha256Hex(stableStringify(auditExport)),
    auditCommitment: auditExport.commitment,
    entrySha256: auditExport.entrySha256,
    agentId: auditExport.agentId,
    tool: auditExport.entry.tool,
    decision: auditExport.entry.decision,
    timestamp: auditExport.entry.ts,
    policyCommitment: opts.policyCommitment ?? null,
    signedAt: opts.signedAt ?? new Date().toISOString(),
    signatureAlgorithm: "Ed25519",
    publicKeyPem,
  };
  const signature = sign(null, Buffer.from(stableStringify(payload)), privateKeyPem).toString("base64");
  return { ...payload, signature };
}

export function verifyAuthorizationReceipt(receipt: AuthorizationReceipt, publicKeyPem: string = receipt.publicKeyPem): void {
  validateReceipt(receipt);
  const { signature, ...payload } = receipt;
  const ok = verify(null, Buffer.from(stableStringify(payload)), publicKeyPem, Buffer.from(signature, "base64"));
  if (!ok) {
    throw new Error("authorization receipt signature is invalid");
  }
}

export function verifyReceiptAuditExport(receipt: AuthorizationReceipt, auditExport: AuditExport): void {
  validateReceipt(receipt);
  validateAuditExport(auditExport);
  const auditExportHash = sha256Hex(stableStringify(auditExport));
  if (receipt.auditExportHash !== auditExportHash) {
    throw new Error("receipt auditExportHash does not match audit export");
  }
  if (receipt.auditCommitment !== auditExport.commitment) {
    throw new Error("receipt auditCommitment does not match audit export");
  }
  if (receipt.entrySha256 !== auditExport.entrySha256) {
    throw new Error("receipt entrySha256 does not match audit export");
  }
  if (receipt.agentId !== auditExport.agentId) {
    throw new Error("receipt agentId does not match audit export");
  }
  if (receipt.tool !== auditExport.entry.tool) {
    throw new Error("receipt tool does not match audit export");
  }
  if (receipt.decision !== auditExport.entry.decision) {
    throw new Error("receipt decision does not match audit export");
  }
  if (receipt.timestamp !== auditExport.entry.ts) {
    throw new Error("receipt timestamp does not match audit export");
  }
}

export function verifyReceiptPolicy(receipt: AuthorizationReceipt, policy: CatpPolicy): void {
  validateReceipt(receipt);
  const policyCommitment = computePolicyCommitment(policy);
  if (receipt.policyCommitment === null) {
    throw new Error("receipt has no policyCommitment");
  }
  if (receipt.policyCommitment !== policyCommitment) {
    throw new Error("receipt policyCommitment does not match policy");
  }
}

export function computePolicyCommitment(policy: CatpPolicy): string {
  return sha256Hex(stableStringify(policy));
}

function readAuditExport(path: string): AuditExport {
  const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
  validateAuditExport(parsed);
  return parsed;
}

function readAuthorizationReceipt(path: string): AuthorizationReceipt {
  const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
  validateReceipt(parsed);
  return parsed;
}

function validateAuditExport(value: unknown): asserts value is AuditExport {
  if (!value || typeof value !== "object") {
    throw new Error("audit export must be an object");
  }
  const auditExport = value as AuditExport;
  if (auditExport.exportVersion !== "catp_audit_export_v1") {
    throw new Error("audit export version must be catp_audit_export_v1");
  }
  if (!auditExport.entry || typeof auditExport.entry !== "object") {
    throw new Error("audit export entry must be an object");
  }
  assertHex(auditExport.commitment, "audit export commitment");
  assertHex(auditExport.entrySha256, "audit export entrySha256");
  if (auditExport.entry.commitment !== auditExport.commitment) {
    throw new Error("audit export commitment must match entry commitment");
  }
  const expectedEntryHash = sha256Hex(stableStringify(auditExport.entry));
  if (auditExport.entrySha256 !== expectedEntryHash) {
    throw new Error("audit export entrySha256 does not match entry");
  }
}

function validateReceipt(value: unknown): asserts value is AuthorizationReceipt {
  if (!value || typeof value !== "object") {
    throw new Error("authorization receipt must be an object");
  }
  const receipt = value as AuthorizationReceipt;
  if (receipt.receiptVersion !== "catp_authorization_receipt_v1") {
    throw new Error("receiptVersion must be catp_authorization_receipt_v1");
  }
  if (receipt.signatureAlgorithm !== "Ed25519") {
    throw new Error("signatureAlgorithm must be Ed25519");
  }
  assertHex(receipt.auditExportHash, "auditExportHash");
  assertHex(receipt.auditCommitment, "auditCommitment");
  assertHex(receipt.entrySha256, "entrySha256");
  if (receipt.decision !== "allow" && receipt.decision !== "deny") {
    throw new Error("decision must be allow or deny");
  }
  for (const field of ["agentId", "tool", "timestamp", "signedAt", "publicKeyPem", "signature"] as const) {
    if (typeof receipt[field] !== "string" || receipt[field] === "") {
      throw new Error(`${field} must be a non-empty string`);
    }
  }
  if (receipt.policyCommitment !== null) {
    assertHex(receipt.policyCommitment, "policyCommitment");
  }
}

function derivePublicKeyPem(privateKeyPem: string): string {
  return createPublicKey(createPrivateKey(privateKeyPem)).export({ type: "spki", format: "pem" }).toString();
}

function resolvePolicyCommitmentIfPresent(): string | null {
  const policyPath = findPolicyFile();
  return policyPath ? computePolicyCommitment(loadPolicy(policyPath)) : null;
}

function assertHex(value: unknown, field: string): void {
  if (typeof value !== "string" || !/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${field} must be a 64-character hex string`);
  }
}

function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}
