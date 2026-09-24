# CATP Authorization Security Notes

Status: living security notes for `authorization_groth16_v1`.

This document records the current security model, assumptions, known caveats,
and regression checks for the CATP authorization path. It is not a third-party
audit, certification, or mainnet readiness statement. It must stay current
whenever public inputs, circuit constraints, policy encoding, verifier
generation, or contract state transitions change.

## Scope

Covered components:

- `catp-circuits/groth16`: `authorization_groth16_v1` Groth16/BN254 circuit,
  persisted dev/testnet proving and verifying keys, proof artifact generation.
- `catp-contracts/src/authorization`: `AgentAuthorizer`,
  `Groth16AuthorizationVerifier`, generated `Groth16Verifier`, and action data
  ABI decoding.
- `catp-sdk/src/authorization`: proof artifact validation and calldata helper shape.
- `catp-plugin`: authorization witness generation from policy/action data and
  proof manifest structural validation.
- `scripts`: setup checks, proof generation, calldata encoding, broadcast
  execution, and Sepolia deployment metadata.

Out of scope for this document:

- Mainnet trusted setup ceremony.
- Future output attestation/challenge security.
- Agent identity, key custody, and wallet operational security.
- Economic security of any future open attestor or reputation network.

## Security Invariants

`authorization_groth16_v1` must only verify when all statements below hold:

- The private authorization policy commits to the public `policyCommitment`.
- `actionType == allowed_action`.
- `protocol == allowed_protocol`.
- `token == allowed_token`.
- `value > 0`.
- `value <= max_value_per_tx`.
- `cumulativeSpend + value <= max_value_total`.
- `valid_from <= currentTimestamp`.
- `currentTimestamp <= valid_until`.
- Public inputs use the fixed 13-value layout:
  `policyCommitment`, `actionType`, `protocol[4]`, `token[4]`, `value`,
  `currentTimestamp`, `cumulativeSpend`.
- `protocol` and `token` are four little-endian `u64` limbs each.
- The EVM execution path binds replay prevention to contract state by requiring
  the proof's `cumulativeSpend` to match on-chain cumulative spend before
  incrementing it.
- Each registered policy binds an explicit executor address. Only that address
  can submit an authorization proof, and revocation does not allow another
  delegator to take over the same commitment.
- `registerPolicy` is first-writer-wins per commitment: whoever registers a
  commitment first owns it permanently, even across revocation. See the
  first-writer squatting finding below for the integrator consequences.

## Current Assumptions

- `authorization_groth16_v1` is the active EVM/testnet proof version.
- The checked-in Groth16 keys are stable dev/testnet keys. They are not a
  documented public mainnet ceremony.
- Mainnet requires a circuit-specific ceremony, an accepted ceremony output, or
  a clearly documented weaker trust model.
- Any change to public input layout, policy commitment encoding, proof backend,
  setup keys, or circuit constraints requires a new proof version and verifier
  deployment.
- The EVM path uses MiMC policy commitment version `2`.

## Security Matrix

| Area | Status | Notes |
|------|--------|-------|
| Public input ordering | Reviewed | SDK/script/plugin validators require 13 inputs and check policy/value/timestamp/spend positions. |
| Policy commitment binding | Reviewed | Circuit binds private policy fields to public commitment. MiMC/version choice is specific to Groth16 path. |
| Integer ranges | Reviewed | Circuit and generators constrain integer fields to `u64`; SDK/plugin validators mirror this. |
| Action/protocol/token binding | Reviewed | Public action fields are checked against private allowed policy fields. |
| Timestamp semantics | Reviewed | Circuit proves policy validity window; `AgentAuthorizer` enforces freshness around execution timestamp. |
| Cumulative spend replay binding | Reviewed | Contract checks proof spend against current state, then increments by action value. |
| Executor binding | Reviewed | Registration binds an executor; execution rejects other callers and revoked commitments retain delegator ownership. |
| Proof shape validation | Reviewed | Wrapper/SDK/plugin and calldata encoder require 13 inputs, 128-byte `actionData`, and 256 proof bytes before execution/manifest use. |
| External proof references | Reviewed | Manifest `proofUrl` accepts HTTPS, IPFS, Arweave, or localhost HTTP only. |
| Setup reproducibility | Reviewed with caveat | `npm run groth16:check` verifies key/source/deployment metadata consistency. Mainnet ceremony remains open. |
| Sepolia deployment metadata | Reviewed | `catp-contracts/deployments/sepolia-groth16.json` records addresses, hashes, gas, blocks, and smoke txs; CLI rejects mismatched deployment proof versions. |

The active checked-in Sepolia deployment uses executor-bound policy
registration and has passed registration plus real-proof execution smoke
testing. Its addresses and transaction evidence are recorded in the deployment
metadata.

## Authorization Receipts

CATP signs two receipt versions. Only version 2 carries an enforcement-time
policy and full-action binding.

`catp_authorization_receipt_v2`:

- Is issued only from a self-contained `catp_audit_export_v2` bundle whose
  selected entry is `phase == "pre"` and commitment version 4.
- Copies `policy_commitment` and `action_commitment` verbatim from that
  enforcement-time audit entry. Neither value is ever re-derived from the
  current policy file at signing time.
- Pins the exact export via `audit_export_sha256`, and identifies the issuer by
  `issuer_key_id` (SHA-256 of the public key's DER SubjectPublicKeyInfo).
- Signs `"catp:receipt-signature:v2\n" || stable_json(body)` and computes
  `receipt_sha256` over `"catp:receipt:v2\n" || stable_json(body_with_signature)`;
  neither domain includes `receipt_sha256` itself.
- Offline verification requires an independently supplied trusted public key,
  recomputes `issuer_key_id` from it and requires an exact match, then checks
  the signature, `receipt_sha256`, the export hash and offline chain, selected
  entry equality for all three bindings, the complete-action hash, and the
  optional policy-file hash.
- The `catp_audit_export_v2` bundle is **mandatory** to verify a v2 receipt:
  `catp receipt verify` refuses (non-zero exit, no summary) a v2 receipt
  presented without `--audit-export`. A signature-only check over the
  self-asserted commitments is NOT sufficient and never yields
  `assurance=enforcement-time-bound`; only after the trusted-key/signature,
  the export bundle (export hash, offline chain prefix, selected v4 entry,
  action commitment, complete canonical action), and any `--file` policy
  evidence all verify is that assurance reported. `auditExport` is therefore
  always `matched` in a v2 verification summary.
- A supplied `--file <policy>` is verification evidence only: it is hashed with
  the same domained enforcement-time scheme and must reproduce the recorded
  `policy_commitment`. A swapped policy is rejected; the receipt stays bound to
  the policy in force at enforcement time.

`catp_authorization_receipt_v1` remains verifiable under its historical
semantics, but its assurance is labelled `legacy` and it never claims an
exact-action or enforcement-time policy binding. Legacy records must not be
upgraded into v2 receipts.

## Findings

### Medium: Dev/Testnet Groth16 Setup Is Not Mainnet-Grade

The persisted setup keys are deterministic and suitable for reproducible
dev/testnet verification. They are not a public ceremony.

Decision: accepted for MVP/testnet. Mainnet release is blocked until CATP either
runs and documents a ceremony or explicitly publishes a weaker trust model.

Regression/guard:

- `scripts/check-groth16-setup.sh`
- `CATP_GROTH16_REQUIRE_KEYS=1` in deployment/smoke scripts
- documented setup reset policy in `catp-circuits/groth16/README.md`

### Low: Enum Bounds Are Enforced Outside The Circuit

The circuit range-checks `actionType` and `allowedAction` to `u64` and enforces
equality. It does not independently constrain action enum values to `0..3`.

Decision: accepted for the current EVM path because Solidity ABI enum decoding,
the Go prover input parser, SDK, plugin witness builder, and CLI manifest
validator reject invalid enum values before proof use. Adding in-circuit enum
bounds would require new setup, verifier deployment, and proof-version decision.

Regression/guard:

- `catp-plugin/tests/commands/witness.test.ts`
- `catp-plugin/tests/commands/authorization.test.ts`
- `catp-sdk/tests/authorization/Groth16ProofArtifact.test.ts`
- Solidity action-data decoding tests under `catp-contracts/test/authorization`

### Low: Proof Manifest Validation Is Structural

`catp verify authorization` validates the manifest and embedded Groth16 artifact
shape. The CLI, SDK, and calldata encoder check the contract-facing shape,
including 13 public inputs, 128-byte ABI `actionData`, 256-byte proof bytes, and
consistency between `actionData` and the public action fields. With
`--check-audit`, it also checks that the recorded audit agent's local audit
chain is intact, the manifest's audit commitment exists in that log, and the
audit entry's structured authorization action matches the manifest action data,
value, timestamp, and cumulative spend when those audit fields are present. A
manifest may only bind to a PRE-enforcement entry; a `phase == "post"` record is
rejected and can never authorize. Audit-linked manifests must bind both
`auditCommitment` and `auditAgent`; the
optional `--audit-agent` flag is only a guard and must match the manifest. It
does not perform cryptographic proof verification locally.

Decision: acceptable for the first proof-sharing manifest. Cryptographic
verification remains the responsibility of the EVM verifier or dedicated
off-chain verifier path.

Follow-up:

- Add a verifier-backed mode once CATP exposes a stable local Groth16 verifier
  command/API for proof artifacts.

### Low: registerPolicy Is First-Writer-Wins (Commitment Squatting)

`AgentAuthorizer.registerPolicy` binds a policy commitment to its first
registrant permanently. An attacker who observes a pending commitment
(for example in the mempool or in a published proof manifest) can register it
first. The intended delegator is then locked out of that commitment forever,
including after the squatter revokes: re-registration reverts with
`not delegator` for everyone but the original registrant.

This is a denial-of-binding, not a fund-safety issue: the squatted entry is
owned by the attacker, so it never authorizes actions against the intended
delegator's assets, and the delegator's wallet only ever signs proofs for
policies it committed to.

Decision: accepted as a protocol property. Changing it (for example
commitment salting or delegator pre-authorization) would alter the on-chain
interface and proof binding and is deferred.

Integrator guidance:

- Treat policy commitments as single-use secrets until registered.
- Register the commitment on-chain before publishing it anywhere (manifests,
  receipts, off-chain channels).
- If a commitment is squatted, generate a new policy with a fresh commitment
  instead of attempting to reclaim the original.

Regression/guard:

- `catp-contracts/test/authorization/AgentAuthorizer.t.sol`
  (`test_register_attackerSquatBlocksIntendedDelegator`,
  `test_register_intendedDelegatorLockedOutAfterSquatterRevoke`,
  `test_register_rejectsTakeoverAfterRevoke`)

## Required Regression Tests

Keep these checks green before changing authorization proof code:

```bash
npm run typecheck --workspace catp-plugin
npm test --workspace catp-plugin
npm run test --workspace catp-sdk
npm run groth16:check
cd catp-contracts && forge test --match-path 'test/authorization/*.t.sol'
```

For deployment-affecting changes, also run:

```bash
npm run groth16:size
scripts/execute-groth16-authorization.sh --dry-run
```

## Release Gate

An authorization release candidate must include:

- Updated proof version and verifier address if any proof boundary changed.
- Updated setup manifest and deployment metadata.
- Passing regression tests for every fixed finding.
- Explicit mainnet/testnet trust statement.
- A proof manifest generated from the release artifact with
  `catp prove authorization`.
