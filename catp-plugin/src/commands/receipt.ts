import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import {
  auditLogFiles,
  buildAuditExportV2,
  computeAuditExportV2Sha256,
  latestAuditCommitment,
  selectedAuditExportV2Entry,
  stableStringify,
  type AuditExport,
  type AuditExportV2,
  type AuditExportV2Body,
} from "./log.js";
import { verifyChain, verifyEntryChain } from "../audit/verifier.js";
import { computeActionCommitment, computePolicyCommitment as computeEnforcementPolicyCommitment } from "../evidence/commitments.js";
import { findPolicyFile, loadPolicy } from "../policy/loader.js";
import type { AuditEntryV4, CatpPolicy } from "../policy/types.js";

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

// Domain separators for version-2 receipts. The signature covers the receipt
// body; receipt_sha256 covers the body-plus-signature. Neither includes
// receipt_sha256 itself, so the hash is a stable external fingerprint.
const RECEIPT_SIGNATURE_V2_DOMAIN = "catp:receipt-signature:v2\n";
const RECEIPT_V2_DOMAIN = "catp:receipt:v2\n";

/**
 * Version-2 authorization receipt body. Every security-relevant binding is
 * COPIED from the enforcement-time v4 audit entry: `policy_commitment` and
 * `action_commitment` are never re-derived from the current policy file. The
 * body also pins the exact self-contained v2 audit export via
 * `audit_export_sha256`, and identifies the issuer by `issuer_key_id`
 * (SHA-256 of the public key's DER SubjectPublicKeyInfo).
 */
export interface AuthorizationReceiptV2Body {
  receipt_version: "catp_authorization_receipt_v2";
  audit_commitment: string;
  policy_commitment: string;
  action_commitment: string;
  audit_export_sha256: string;
  agent_id: string;
  tool: string;
  decision: "allow" | "deny";
  phase: "pre";
  rule_matched: string | null;
  reason: string;
  timestamp: string;
  signed_at: string;
  issuer_key_id: string;
  signature_algorithm: "Ed25519";
}

export interface AuthorizationReceiptV2 extends AuthorizationReceiptV2Body {
  signature: string;
  receipt_sha256: string;
}

/** SHA-256 of the public key's DER SubjectPublicKeyInfo bytes. */
export function computeIssuerKeyId(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex");
}

export interface ReceiptVerificationSummary {
  authorizationReceipt: "valid";
  receiptVersion: "catp_authorization_receipt_v1" | "catp_authorization_receipt_v2";
  assurance: "legacy" | "enforcement-time-bound";
  auditExport: "matched" | null;
  policy: "matched" | null;
  auditCommitment: string;
  auditExportHash: string;
  policyCommitment: string | null;
  actionCommitment: string | null;
  agentId: string;
  tool: string;
  decision: "allow" | "deny";
  timestamp: string;
  signedAt: string;
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

  const auditExport = readAuditExportV2(opts.auditExport);
  const selected = selectedPreEnforcementV4Entry(auditExport);
  // --file is verification evidence, never the binding source: it must
  // reproduce the enforcement-time policy_commitment copied from the entry.
  if (opts.file) {
    assertPolicyMatchesEnforcementCommitment(loadPolicy(opts.file), selected.policy_commitment);
  }
  const privateKeyPem = readFileSync(opts.privateKey, "utf8");
  const receipt = signAuthorizationReceiptV2(auditExport, privateKeyPem);
  writeReceiptV2Output(receipt, selected, opts.out);
}

function writeReceiptV2Output(
  receipt: AuthorizationReceiptV2,
  selected: AuditEntryV4,
  out?: string,
  auditExportOut?: string,
): void {
  const json = stableStringify(receipt, 2) + "\n";
  if (out) {
    writeFileSync(out, json, "utf8");
    process.stdout.write(`Wrote authorization receipt to ${out}\n`);
    if (auditExportOut) {
      process.stdout.write(`Wrote audit export to ${auditExportOut}\n`);
    }
    process.stdout.write(`auditCommitment=${receipt.audit_commitment}\n`);
    process.stdout.write(`auditExportSha256=${receipt.audit_export_sha256}\n`);
    process.stdout.write(`policyCommitment=${receipt.policy_commitment}\n`);
    process.stdout.write(`actionCommitment=${receipt.action_commitment}\n`);
    process.stdout.write(`selectedTool=${selected.tool}\n`);
    process.stdout.write(`selectedDecision=${selected.decision}\n`);
    process.stdout.write(`selectedTimestamp=${selected.ts}\n`);
    process.stdout.write(`selectedInputSummary=${selected.input_summary}\n`);
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
  latest?: boolean;
  tool?: string;
  decision?: "allow" | "deny";
}): Promise<void> {
  return issueReceipt(opts);
}

async function issueReceipt(opts: {
  commitment?: string;
  agent?: string;
  privateKey?: string;
  out?: string;
  file?: string;
  auditExportOut?: string;
  latest?: boolean;
  tool?: string;
  decision?: "allow" | "deny";
}): Promise<void> {
  const selectorCount = [opts.commitment, opts.latest ? "latest" : undefined, opts.tool].filter(Boolean).length;
  if (selectorCount > 1) {
    throw new Error("use only one of --commitment <hex>, --latest, or --tool <name>");
  }
  if (selectorCount === 0) {
    throw new Error("missing --commitment <hex>, --latest, or --tool <name>");
  }
  if (!opts.privateKey) {
    throw new Error("missing --private-key <path>");
  }
  if (opts.decision !== undefined && opts.decision !== "allow" && opts.decision !== "deny") {
    throw new Error("--decision must be allow or deny");
  }
  if (opts.commitment && opts.decision) {
    throw new Error("--decision can only be used with --latest or --tool");
  }

  const policyPath = opts.file ?? findPolicyFile();
  const policy = policyPath ? loadPolicy(policyPath) : null;
  const agentId = opts.agent ?? policy?.agent.id;
  if (!agentId) {
    throw new Error("missing --agent <id>; no catp-policy.toml found");
  }

  await verifyAuditLogIntegrity(agentId);
  const commitment = resolveIssueCommitment(agentId, opts);
  // Build the self-contained v2 bundle and require a pre-enforcement v4 entry.
  // The receipt's policy/action commitments are copied from that entry, never
  // re-derived from the current policy file.
  const auditExport = buildAuditExportV2(agentId, commitment);
  const selected = selectedPreEnforcementV4Entry(auditExport);
  // An explicit --file is verification evidence only: it must reproduce the
  // enforcement-time policy_commitment already recorded in the entry.
  if (opts.file) {
    assertPolicyMatchesEnforcementCommitment(loadPolicy(opts.file), selected.policy_commitment);
  }
  const privateKeyPem = readFileSync(opts.privateKey, "utf8");
  const receipt = signAuthorizationReceiptV2(auditExport, privateKeyPem);

  if (opts.auditExportOut) {
    writeFileSync(opts.auditExportOut, stableStringify(auditExport, 2) + "\n", "utf8");
  }

  writeReceiptV2Output(receipt, selected, opts.out, opts.auditExportOut);
}

function resolveIssueCommitment(agentId: string, opts: { commitment?: string; latest?: boolean; tool?: string; decision?: "allow" | "deny" }): string {
  if (opts.commitment) {
    return opts.commitment;
  }
  return latestAuditCommitment(agentId, {
    phase: "pre",
    ...(opts.tool ? { tool: opts.tool } : {}),
    ...(opts.decision ? { decision: opts.decision } : {}),
  });
}

export function cmdReceiptVerify(opts: { receipt?: string; publicKey?: string; auditExport?: string; file?: string; json?: boolean }): void {
  if (!opts.receipt) {
    throw new Error("missing --receipt <path>");
  }
  if (!opts.publicKey) {
    throw new Error("missing --public-key <path>; receipt verification requires a trusted external public key");
  }
  // The trusted public key is supplied independently of the receipt; it is never
  // taken from the receipt itself.
  const publicKeyPem = readFileSync(opts.publicKey, "utf8");
  const receipt = readAuthorizationReceiptAny(opts.receipt);

  if (isReceiptV2(receipt)) {
    // A v2 receipt claims an enforcement-time binding, so verifying one
    // WITHOUT its audit export would reduce that claim to a signature check
    // over self-asserted commitments. Refuse outright (non-zero exit, no
    // summary on either output mode) instead of reporting a weaker result.
    if (!opts.auditExport) {
      throw new Error(
        "catp_authorization_receipt_v2 verification requires --audit-export <path> (the catp_audit_export_v2 bundle from receipt issue/sign or catp log export); signature-only verification cannot establish enforcement-time-bound assurance",
      );
    }
    // Full verification order: trusted-key/signature first, then the export
    // bundle (export hash, chain prefix, selected v4 entry, action commitment,
    // complete canonical action), then the optional policy-file evidence.
    verifyAuthorizationReceiptV2(receipt, publicKeyPem);
    verifyReceiptAuditExportV2(receipt, readAuditExportV2(opts.auditExport));
    if (opts.file) {
      verifyReceiptPolicyV2(receipt, loadPolicy(opts.file));
    }
    emitVerificationSummary(
      receiptVerificationSummaryV2(receipt, {
        policyMatched: Boolean(opts.file),
      }),
      opts,
    );
    return;
  }

  // Legacy version-1 receipts keep their historical semantics and assurance.
  verifyAuthorizationReceipt(receipt, publicKeyPem);
  if (opts.auditExport) {
    verifyReceiptAuditExport(receipt, readAuditExport(opts.auditExport));
  }
  if (opts.file) {
    verifyReceiptPolicy(receipt, loadPolicy(opts.file));
  }
  emitVerificationSummary(
    receiptVerificationSummary(receipt, {
      auditExportMatched: Boolean(opts.auditExport),
      policyMatched: Boolean(opts.file),
    }),
    opts,
  );
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

// ---------------------------------------------------------------------------
// Version-2 receipts: issued only from recorded enforcement-time bindings.
// ---------------------------------------------------------------------------

/**
 * Structural + cryptographic validation of a self-contained v2 audit export.
 * Recomputes `export_sha256` over the body, requires the prefix length to match
 * `selected_index + 1`, requires a commitment-version-4 selected entry, and
 * requires the bundled complete action to reproduce that entry's
 * `action_commitment`.
 */
export function validateAuditExportV2(value: unknown): asserts value is AuditExportV2 {
  if (!value || typeof value !== "object") {
    throw new Error("audit export must be an object");
  }
  const exp = value as AuditExportV2;
  if (exp.export_version !== "catp_audit_export_v2") {
    throw new Error("audit export version must be catp_audit_export_v2");
  }
  if (typeof exp.agent_id !== "string" || exp.agent_id === "") {
    throw new Error("audit export agent_id must be a non-empty string");
  }
  if (typeof exp.log_date !== "string" || exp.log_date === "") {
    throw new Error("audit export log_date must be a non-empty string");
  }
  if (!Number.isInteger(exp.selected_index) || exp.selected_index < 0) {
    throw new Error("audit export selected_index must be a non-negative integer");
  }
  if (!Array.isArray(exp.entries) || exp.entries.length !== exp.selected_index + 1) {
    throw new Error("audit export entries must be the daily prefix through selected_index");
  }
  if (!exp.action || typeof exp.action !== "object") {
    throw new Error("audit export action must be an object");
  }
  assertHex(exp.export_sha256, "audit export export_sha256");
  const { export_sha256, ...body } = exp;
  if (computeAuditExportV2Sha256(body as AuditExportV2Body) !== export_sha256) {
    throw new Error("audit export v2 export_sha256 does not match body");
  }
  const selected = selectedAuditExportV2Entry(exp);
  if (!selected || typeof selected !== "object") {
    throw new Error("audit export selected entry must be an object");
  }
  if (selected.commitment_version !== 4) {
    throw new Error("audit export v2 selected entry must be commitment version 4");
  }
  if (computeActionCommitment(exp.action) !== selected.action_commitment) {
    throw new Error("audit export action does not match the selected entry action_commitment");
  }
  // Enforce the same offline chain integrity here that buildAuditExportV2 and
  // verifyReceiptAuditExportV2 enforce, so `receipt sign` can never sign over a
  // bundle whose recorded prefix was tampered with.
  const chain = verifyEntryChain(exp.entries);
  if (!chain.ok) {
    throw new Error(`audit export chain is broken at entry ${chain.broken_at}: ${chain.message}`);
  }
}

function readAuditExportV2(path: string): AuditExportV2 {
  const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
  validateAuditExportV2(parsed);
  return parsed;
}

// The selected entry must be a pre-enforcement v4 record; post-action and
// legacy entries can never authorize.
function selectedPreEnforcementV4Entry(exp: AuditExportV2): AuditEntryV4 {
  const selected = selectedAuditExportV2Entry(exp);
  if (!selected || selected.commitment_version !== 4) {
    throw new Error("authorization receipts require a commitment version 4 audit entry");
  }
  if (selected.phase !== "pre") {
    throw new Error("authorization receipts require a pre-enforcement audit entry");
  }
  return selected;
}

/**
 * Sign a v2 receipt. `policy_commitment` and `action_commitment` are copied
 * verbatim from the enforcement-time entry — never re-derived from any current
 * policy file.
 */
export function signAuthorizationReceiptV2(
  auditExport: AuditExportV2,
  privateKeyPem: string,
  opts: { signedAt?: string } = {},
): AuthorizationReceiptV2 {
  validateAuditExportV2(auditExport);
  const selected = selectedPreEnforcementV4Entry(auditExport);
  const publicKeyPem = derivePublicKeyPem(privateKeyPem);
  const body: AuthorizationReceiptV2Body = {
    receipt_version: "catp_authorization_receipt_v2",
    audit_commitment: selected.commitment,
    policy_commitment: selected.policy_commitment,
    action_commitment: selected.action_commitment,
    audit_export_sha256: auditExport.export_sha256,
    agent_id: auditExport.agent_id,
    tool: selected.tool,
    decision: selected.decision,
    phase: "pre",
    rule_matched: selected.rule_matched,
    reason: selected.reason,
    timestamp: selected.ts,
    signed_at: opts.signedAt ?? new Date().toISOString(),
    issuer_key_id: computeIssuerKeyId(publicKeyPem),
    signature_algorithm: "Ed25519",
  };
  const signature = sign(null, Buffer.from(RECEIPT_SIGNATURE_V2_DOMAIN + stableStringify(body)), privateKeyPem).toString("base64");
  const receipt_sha256 = sha256Hex(RECEIPT_V2_DOMAIN + stableStringify({ ...body, signature }));
  const receipt: AuthorizationReceiptV2 = { ...body, signature, receipt_sha256 };
  // Fail closed at signing time rather than emitting a receipt that offline
  // verification would later reject.
  validateReceiptV2(receipt);
  return receipt;
}

export function validateReceiptV2(value: unknown): asserts value is AuthorizationReceiptV2 {
  if (!value || typeof value !== "object") {
    throw new Error("authorization receipt must be an object");
  }
  const receipt = value as AuthorizationReceiptV2;
  if (receipt.receipt_version !== "catp_authorization_receipt_v2") {
    throw new Error("receipt_version must be catp_authorization_receipt_v2");
  }
  if (receipt.signature_algorithm !== "Ed25519") {
    throw new Error("signature_algorithm must be Ed25519");
  }
  if (receipt.phase !== "pre") {
    throw new Error("phase must be pre");
  }
  if (receipt.decision !== "allow" && receipt.decision !== "deny") {
    throw new Error("decision must be allow or deny");
  }
  if (receipt.rule_matched !== null && typeof receipt.rule_matched !== "string") {
    throw new Error("rule_matched must be a string or null");
  }
  assertHex(receipt.audit_commitment, "audit_commitment");
  assertHex(receipt.policy_commitment, "policy_commitment");
  assertHex(receipt.action_commitment, "action_commitment");
  assertHex(receipt.audit_export_sha256, "audit_export_sha256");
  assertHex(receipt.issuer_key_id, "issuer_key_id");
  assertHex(receipt.receipt_sha256, "receipt_sha256");
  // `reason` is explanatory metadata copied verbatim from the v4 entry; match
  // that contract (a string, possibly empty) rather than imposing a stricter
  // non-empty rule the recorded entry does not guarantee.
  if (typeof receipt.reason !== "string") {
    throw new Error("reason must be a string");
  }
  for (const field of ["agent_id", "tool", "timestamp", "signed_at", "signature"] as const) {
    if (typeof receipt[field] !== "string" || receipt[field] === "") {
      throw new Error(`${field} must be a non-empty string`);
    }
  }
}

/**
 * Offline-verify a v2 receipt against an INDEPENDENTLY supplied trusted public
 * key. Recomputes `issuer_key_id` from that key and requires an exact match
 * before accepting the signature, then checks `receipt_sha256` and the Ed25519
 * signature over the domain-separated body.
 */
export function verifyAuthorizationReceiptV2(receipt: AuthorizationReceiptV2, trustedPublicKeyPem: string): void {
  validateReceiptV2(receipt);
  const expectedKeyId = computeIssuerKeyId(trustedPublicKeyPem);
  if (receipt.issuer_key_id !== expectedKeyId) {
    throw new Error("receipt issuer_key_id does not match the trusted public key");
  }
  const { receipt_sha256, signature, ...body } = receipt;
  const expectedReceiptSha256 = sha256Hex(RECEIPT_V2_DOMAIN + stableStringify({ ...body, signature }));
  if (receipt_sha256 !== expectedReceiptSha256) {
    throw new Error("receipt_sha256 does not match the signed receipt body");
  }
  const ok = verify(null, Buffer.from(RECEIPT_SIGNATURE_V2_DOMAIN + stableStringify(body)), trustedPublicKeyPem, Buffer.from(signature, "base64"));
  if (!ok) {
    throw new Error("authorization receipt signature is invalid");
  }
}

/**
 * Cross-check a v2 receipt against its self-contained audit export: export hash,
 * selected-entry equality for all three bindings, and the complete-action hash.
 * Offline chain integrity over the prefix is enforced by `validateAuditExportV2`.
 */
export function verifyReceiptAuditExportV2(receipt: AuthorizationReceiptV2, auditExport: AuditExportV2): void {
  validateReceiptV2(receipt);
  validateAuditExportV2(auditExport);
  if (receipt.audit_export_sha256 !== auditExport.export_sha256) {
    throw new Error("receipt audit_export_sha256 does not match audit export");
  }
  if (auditExport.agent_id !== receipt.agent_id) {
    throw new Error("receipt agent_id does not match audit export");
  }
  const selected = selectedPreEnforcementV4Entry(auditExport);
  if (selected.commitment !== receipt.audit_commitment) {
    throw new Error("receipt audit_commitment does not match the selected audit entry");
  }
  if (selected.policy_commitment !== receipt.policy_commitment) {
    throw new Error("receipt policy_commitment does not match the selected audit entry");
  }
  if (selected.action_commitment !== receipt.action_commitment) {
    throw new Error("receipt action_commitment does not match the selected audit entry");
  }
  if (computeActionCommitment(auditExport.action) !== receipt.action_commitment) {
    throw new Error("receipt action_commitment does not match the bundled complete action");
  }
}

/**
 * Optional policy-file check. The supplied file is verification evidence only:
 * it is hashed with the SAME domained enforcement-time scheme and compared with
 * the recorded commitment. A mismatch (e.g. a swapped policy) is rejected.
 */
export function verifyReceiptPolicyV2(receipt: AuthorizationReceiptV2, policy: CatpPolicy): void {
  validateReceiptV2(receipt);
  const policyCommitment = computeEnforcementPolicyCommitment(policy);
  if (receipt.policy_commitment !== policyCommitment) {
    throw new Error("receipt policy_commitment does not match policy");
  }
}

// The supplied --file policy is evidence, never the source of the binding: it
// must reproduce the enforcement-time policy_commitment copied from the entry.
function assertPolicyMatchesEnforcementCommitment(policy: CatpPolicy, enforcementPolicyCommitment: string): void {
  if (computeEnforcementPolicyCommitment(policy) !== enforcementPolicyCommitment) {
    throw new Error("supplied policy file does not match the enforcement-time policy_commitment");
  }
}

function receiptVerificationSummary(
  receipt: AuthorizationReceipt,
  opts: { auditExportMatched: boolean; policyMatched: boolean }
): ReceiptVerificationSummary {
  return {
    authorizationReceipt: "valid",
    receiptVersion: "catp_authorization_receipt_v1",
    // Legacy receipts predate enforcement-time policy/action binding; label
    // their assurance honestly and never imply an exact-action binding.
    assurance: "legacy",
    auditExport: opts.auditExportMatched ? "matched" : null,
    policy: opts.policyMatched ? "matched" : null,
    auditCommitment: receipt.auditCommitment,
    auditExportHash: receipt.auditExportHash,
    policyCommitment: receipt.policyCommitment,
    actionCommitment: null,
    agentId: receipt.agentId,
    tool: receipt.tool,
    decision: receipt.decision,
    timestamp: receipt.timestamp,
    signedAt: receipt.signedAt,
  };
}

// Reached only after cmdReceiptVerify has enforced the mandatory export
// check and the full v2 verification order, so the enforcement-time-bound
// assurance and the matched export are invariants here, not options.
function receiptVerificationSummaryV2(
  receipt: AuthorizationReceiptV2,
  opts: { policyMatched: boolean }
): ReceiptVerificationSummary {
  return {
    authorizationReceipt: "valid",
    receiptVersion: "catp_authorization_receipt_v2",
    assurance: "enforcement-time-bound",
    auditExport: "matched",
    policy: opts.policyMatched ? "matched" : null,
    auditCommitment: receipt.audit_commitment,
    auditExportHash: receipt.audit_export_sha256,
    policyCommitment: receipt.policy_commitment,
    actionCommitment: receipt.action_commitment,
    agentId: receipt.agent_id,
    tool: receipt.tool,
    decision: receipt.decision,
    timestamp: receipt.timestamp,
    signedAt: receipt.signed_at,
  };
}

function emitVerificationSummary(summary: ReceiptVerificationSummary, opts: { json?: boolean }): void {
  if (opts.json) {
    process.stdout.write(stableStringify(summary, 2) + "\n");
    return;
  }
  process.stdout.write("authorizationReceipt=valid\n");
  process.stdout.write(`receiptVersion=${summary.receiptVersion}\n`);
  process.stdout.write(`assurance=${summary.assurance}\n`);
  if (summary.auditExport) {
    process.stdout.write("auditExport=matched\n");
  }
  if (summary.policy) {
    process.stdout.write("policy=matched\n");
  }
  process.stdout.write(`auditCommitment=${summary.auditCommitment}\n`);
  process.stdout.write(`auditExportHash=${summary.auditExportHash}\n`);
  process.stdout.write(`policyCommitment=${summary.policyCommitment ?? "none"}\n`);
  if (summary.actionCommitment) {
    process.stdout.write(`actionCommitment=${summary.actionCommitment}\n`);
  }
}

type AnyAuthorizationReceipt = AuthorizationReceipt | AuthorizationReceiptV2;

function isReceiptV2(value: unknown): value is AuthorizationReceiptV2 {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as { receipt_version?: unknown }).receipt_version === "catp_authorization_receipt_v2"
  );
}

// Read a receipt of either version. A v2 file is validated as v2; anything else
// must satisfy the legacy v1 shape (and is labelled legacy on verification).
function readAuthorizationReceiptAny(path: string): AnyAuthorizationReceipt {
  const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
  if (isReceiptV2(parsed)) {
    validateReceiptV2(parsed);
    return parsed;
  }
  validateReceipt(parsed);
  return parsed;
}

function readAuditExport(path: string): AuditExport {
  const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
  validateAuditExport(parsed);
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

async function verifyAuditLogIntegrity(agentId: string): Promise<void> {
  for (const { file } of auditLogFiles(agentId)) {
    const result = await verifyChain(file);
    if (!result.ok) {
      throw new Error(`audit log chain is broken in ${file} at entry ${result.broken_at}: ${result.message}`);
    }
  }
}

function assertHex(value: unknown, field: string): void {
  if (typeof value !== "string" || !/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${field} must be a 64-character hex string`);
  }
}

function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}
