# CATP Authorization Security Review

Status: initial living review for `authorization_groth16_v1`.

This document records the current security posture of the CATP authorization
authorization path. It is not a third-party audit. It is the repository-owned
checklist that must stay current whenever public inputs, circuit constraints,
policy encoding, verifier generation, or contract state transitions change.

## Scope

Reviewed components:

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

Out of scope for this review:

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

## Current Assumptions

- `authorization_groth16_v1` is the active EVM/testnet proof version.
- The checked-in Groth16 keys are stable dev/testnet keys. They are not a
  documented public mainnet ceremony.
- Mainnet requires a circuit-specific ceremony, an accepted ceremony output, or
  a clearly documented weaker trust model.
- Any change to public input layout, policy commitment encoding, proof backend,
  setup keys, or circuit constraints requires a new proof version and verifier
  deployment.
- The EVM path uses MiMC policy commitment version `2`; it is intentionally
  separate from the Halo2 off-chain `authorization_v1` path.

## Review Matrix

| Area | Status | Notes |
|------|--------|-------|
| Public input ordering | Reviewed | SDK/script/plugin validators require 13 inputs and check policy/value/timestamp/spend positions. |
| Policy commitment binding | Reviewed | Circuit binds private policy fields to public commitment. MiMC/version choice is specific to Groth16 path. |
| Integer ranges | Reviewed | Circuit and generators constrain integer fields to `u64`; SDK/plugin validators mirror this. |
| Action/protocol/token binding | Reviewed | Public action fields are checked against private allowed policy fields. |
| Timestamp semantics | Reviewed | Circuit proves policy validity window; `AgentAuthorizer` enforces freshness around execution timestamp. |
| Cumulative spend replay binding | Reviewed | Contract checks proof spend against current state, then increments by action value. |
| Proof shape validation | Reviewed | Wrapper/SDK/plugin and calldata encoder require 13 inputs, 128-byte `actionData`, and 256 proof bytes before execution/manifest use. |
| Setup reproducibility | Reviewed with caveat | `npm run groth16:check` verifies key/source/deployment metadata consistency. Mainnet ceremony remains open. |
| Sepolia deployment metadata | Reviewed | `catp-contracts/deployments/sepolia-groth16.json` records addresses, hashes, gas, blocks, and smoke txs. |

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
the Go prover input parser, SDK, and plugin witness builder reject invalid enum
values before proof use. Adding in-circuit enum bounds would require new setup,
verifier deployment, and proof-version decision.

Regression/guard:

- `catp-plugin/tests/commands/witness.test.ts`
- `catp-sdk/tests/authorization/Groth16ProofArtifact.test.ts`
- Solidity action-data decoding tests under `catp-contracts/test/authorization`

### Low: Proof Manifest Validation Is Structural

`catp verify authorization` validates the manifest and embedded Groth16 artifact
shape. The CLI, SDK, and calldata encoder check the contract-facing shape,
including 13 public inputs, 128-byte ABI `actionData`, 256-byte proof bytes, and
consistency between `actionData` and the public action fields. With
`--check-audit`, it also checks that the
manifest's audit commitment exists in the local audit log for the recorded audit
agent and that the audit entry's structured authorization action matches the
manifest action data, value, timestamp, and cumulative spend when those audit
fields are present. It does not perform cryptographic proof verification
locally.

Decision: acceptable for the first proof-sharing manifest. Cryptographic
verification remains the responsibility of the EVM verifier or dedicated
off-chain verifier path.

Follow-up:

- Add a verifier-backed mode once CATP exposes a stable local Groth16 verifier
  command/API for proof artifacts.

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
