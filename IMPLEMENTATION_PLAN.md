# CATP Implementation Plan

## Product Goal

CATP makes autonomous agent activity enforceable locally and provable externally.

The product ladder has two parts:

1. **Enforcement Layer**: a plugin/hook that intercepts agent actions synchronously, checks them against a policy, blocks unauthorized actions, and writes a tamper-evident audit log.
2. **Protocol Layer**: versioned ZK proofs and chain/web2 verifiers that let a third party verify compliance without seeing private policy details.

The enforcement plugin is the adoption wedge. The proof layer is the trust primitive. The current implemented proof-system path is:

```text
authorization_v1 = Halo2/KZG/BN254 + 13 public inputs + off-chain verifier
```

Direct EVM verification for the current generated Halo2 verifier is blocked: the corrected runtime bytecode is about 319 KB, far above the EVM 24,576-byte contract size limit. The active proof-system decision is to keep the authorization statement stable while productizing a compact EVM backend as a new versioned verifier.

Current compact EVM result:

```text
authorization_groth16_v1 = Groth16/BN254 + MiMC commitment + 13 public inputs
Groth16Verifier runtime: ~6.4 KB
Groth16AuthorizationVerifier runtime: ~1.1 KB
local AgentAuthorizer real-proof smoke: passing
Sepolia AgentAuthorizer real-proof smoke: passing
```

Nova/HyperNova/folding is a future R&D track for incremental audit logs, not a dependency for the current MVP.

## Current North Star

The next milestone is a reproducible Layer 0/2 release that a developer can install, run locally, and verify on testnet:

```text
catp-policy.toml
  -> plugin enforcement
  -> local audit log
  -> structured Layer 2 authorization witness
  -> Halo2 authorization proof
  -> catp-verify off-chain or authorization_groth16_v1 on EVM
  -> shareable verification result
```

Success means CATP can demonstrate: "this agent action was allowed by a committed private policy, the spend/time/action fields match the proof, and the verifier can check it without trusting CATP servers."

---

## Completed Foundation

### Phase 0: Enforcement Plugin

Status: complete.

Delivered:

- `catp-policy.toml` schema and parser
- `PreToolUse` / `PostToolUse` hook handlers
- Local audit log with SHA-256 hash chain
- `catp` CLI: `init`, `validate`, `hook`, `log`
- Claude Code integration documented
- One-command install script
- npm package: `@catp-protocol/cli`

Phase 0 intentionally has no ZK and no blockchain dependency. It delivers immediate policy enforcement and creates the audit trail that later proof flows consume.

### Layer 2: Authorization Proof

Status: complete locally for Halo2/off-chain verification; direct Halo2 EVM verification is blocked by verifier bytecode size; compact Groth16 EVM verification has passed Sepolia smoke.

Delivered:

- `ProveAuthorization` Halo2 circuit at `k=12`
- In-circuit Poseidon policy commitment
- 13 public inputs:
  `policyCommitment`, `actionType`, `protocol[4]`, `token[4]`, `value`, `currentTimestamp`, `cumulativeSpend`
- u64 range checks for value, spend, timestamp, and inequality witnesses
- protocol/token binding across all 32 bytes
- shared KZG SRS file for testnet/dev consistency
- historical generated Halo2 Solidity verifier path removed after it exceeded EVM runtime size limits
- `AgentAuthorizer.sol` using `IVerifier`
- WASM source bindings with `compute_policy_commitment`, `prove_authorization`, `verify_authorization`
- `catp-verify` Rust library and REST endpoint
- TypeScript SDK Layer 2 clients and tests

Important design constraints:

- `authorization_v1` stays on Halo2/KZG/BN254 for off-chain verification. `authorization_groth16_v1` is the compact EVM proof version because the proof backend and commitment encoding differ.
- Any change to public inputs, policy encoding, hash layout, circuit constraints, SRS size, transcript, or proof backend creates a new proof version and verifier address.
- `activePolicies` and `cumulativeSpend` remain in-contract until CATP has a canonical state-root, nonce, nullifier, or checkpoint design for proof-centric state.
- The committed `catp-layer2-k12.srs` is acceptable for testnet/dev. Mainnet requires documented SRS provenance or replacement with an accepted ceremony output.

## Immediate Execution Plan

### P0: Release Packaging

Goal: make the current Layer 0/2 slice reproducible for outside users.

Work:

- Audit npm package contents and install flow.
- Keep WASM source in git; generate `catp-circuits/wasm/pkg/` only as a build or package artifact.
- Document contract build/deploy commands.
- Document SRS generation/loading behavior for dev, testnet, and future mainnet.
- Add a "known limits" section for Halo2/KZG, testnet SRS, and proof versioning.

Exit criteria:

- A clean install from npm can run the CLI.
- SDK consumers can import Layer 2 proof helpers.
- A developer can reproduce verifier generation from documented commands.
- Release notes clearly distinguish local enforcement, off-chain verification, and on-chain verification.

### P0: Layer 2 Circuit and Security Review

Status: started. Initial living review is in `docs/SECURITY_REVIEW_LAYER2.md`.

Goal: reduce the risk that the authorization proof accepts an invalid action.

Review scope:

- Public input ordering and ABI encoding
- Poseidon native/in-circuit equivalence
- u64 range checks and inequality witnesses
- protocol/token 32-byte limb layout
- timestamp freshness and stale-proof semantics
- cumulative spend replay binding
- SRS/verifier generation reproducibility
- Solidity calldata construction and `staticcall` behavior
- `AgentAuthorizer` state transitions around register, revoke, execute

Exit criteria:

- Review notes captured in `docs/SECURITY_REVIEW_LAYER2.md` or equivalent.
- All findings are classified.
- Critical/high findings are fixed or explicitly deferred with rationale.
- New regression tests are added for each fixed issue.

### P1: Compact EVM Verifier Spike

Status: complete for the current MVP. `authorization_groth16_v1` is below the
EVM runtime bytecode limit and has passed local and Sepolia smoke tests.

Goal: prove the Layer 2 authorization statement can be verified by an EVM-deployable verifier.

Work:

- Implement the same minimal authorization statement in an EVM-friendly proof backend, starting with Groth16/BN254.
- Generate a Solidity verifier.
- Measure runtime bytecode size with Foundry.
- Wrap the generated verifier behind `IVerifier`.
- Run a local `AgentAuthorizer.executeAuthorized` path with a real proof.
- Run negative tests for tampered public inputs/proof.

Exit criteria:

- Verifier runtime bytecode is below 24,576 bytes.
- Local proof generation and Solidity verification pass.
- `AgentAuthorizer` succeeds with a valid proof and rejects invalid proofs.
- A new proof version is named if the backend or commitment encoding differs from `authorization_v1`.

### P1: Sepolia Smoke Test

Status: complete for the active deployment recorded in
`catp-contracts/deployments/sepolia-groth16.json`. Reproduction steps are in
`docs/E2E_GROTH16_SEPOLIA.md`.

Goal: prove the local path survives a real testnet deployment.

Work:

- Deploy the compact verifier, its `IVerifier` wrapper, and `AgentAuthorizer.sol`.
- Register a policy commitment.
- Generate an `authorization_groth16_v1` proof artifact from the Groth16 prover path.
- Call `executeAuthorized` with matching public inputs.
- Record gas, tx hashes, addresses, chain, and SRS/verifier build metadata.
- Run a negative case with tampered public inputs if gas budget permits.

Exit criteria:

- One successful testnet proof verification using a deployable compact verifier.
- One documented verification failure for tampered inputs, either on-chain or via local fork.
- Gas numbers recorded in this plan or deployment notes.

### P1: Bridge Plugin Audit Logs to Layer 2 Proofs

Goal: connect the product surface to the cryptographic proof surface.

Current gap:

The plugin writes generic tool-call audit entries and a SHA-256 hash chain. Layer 2 proves structured authorization actions: action type, protocol, token, value, timestamp, cumulative spend. These are related, but not yet a single user-facing verification flow.

Work:

- Define the mapping from audit entry to `AuthorizationPolicy` and `Action`.
- First bridge shipped: `catp witness` reads `[authorization]` from
  `catp-policy.toml` plus structured action JSON, and emits the
  `authorization_groth16_v1` witness consumed by the Groth16 prover.
- Audit-linked bridge added: audit entries may carry optional structured
  authorization action data, and `catp witness --audit-commitment <hash>` can
  recover that action to build the same witness.
- One-command repo proof bridge added: `npm run groth16:prove -- ...` composes
  witness generation and Groth16 proof artifact generation.
- Offline execution bridge added: `npm run groth16:encode-execute -- ...`
  validates a Groth16 proof artifact and emits `registerPolicy` plus
  `executeAuthorized` calldata without RPC or broadcast.
- Broadcast execution bridge added: `npm run groth16:execute -- ...` reuses
  the encoded proof artifact, registers inactive policies, checks cumulative
  spend against chain state, and broadcasts `executeAuthorized`.
- Decide which tool/action classes can produce Layer 2 witnesses in the MVP.
- Add a proof manifest format that links:
  - audit log entry id
  - SHA-256 log-chain commitment
  - Poseidon policy commitment
  - `authorization_v1` public inputs
  - proof bytes or proof URL
- Implement `catp prove authorization` or equivalent CLI flow.
- Implement `catp verify authorization` for local/off-chain verification.
- First manifest bridge shipped: `catp prove authorization` can wrap an existing
  `authorization_groth16_v1` artifact or generate one from `--action` /
  `--audit-commitment`, then emit `catp_authorization_proof_manifest_v1`.
- First manifest verifier shipped: `catp verify authorization` validates manifest
  and embedded artifact structure. Cryptographic local verification remains a
  follow-up.

Exit criteria:

- A user can run an agent action, generate a proof from the resulting audit record, and verify it with `catp-verify`.
- The verification output is understandable without exposing private policy fields.

### P1: Layer 3 Resolver and Attestor Trust Model

Goal: make Layer 3's security assumptions explicit before building more machinery.

Work:

- Define resolver role and rotation policy.
- Define what evidence a challenge must include.
- Define how a trusted re-execution result is obtained.
- Define attestor liveness expectations and failure handling.
- Decide whether Phase 3 starts permissioned, semi-permissioned, or open.

Exit criteria:

- Layer 3 trust model documented.
- Contract roles and operational keys are listed.
- Integration-test scenarios are specified before an attestor service implementation.

---

## Post-MVP Tracks

### Track A: `boundary_v1` Output Boundary Proof

Goal: prove that a committed output lies inside a permitted numeric range without revealing the output.

Build:

- Add a dedicated Layer 3 circuit crate when the `boundary_v1` proof statement is finalized.
- Public inputs: `outputCommitment`, `boundarySpecCommitment` or explicit min/max fields.
- Private inputs: output value and salt.
- Constraints:
  - `Poseidon(output, salt) == outputCommitment`
  - `min <= output <= max`
- Add Rust unit tests, proof tests, and SDK wrappers.

Exit criteria:

- `boundary_v1` proof verifies locally.
- Public input schema is versioned.
- Integration path with the future Layer 3 contract surface is documented.

### Track B: MPA Attestor Flow

Goal: run the non-ZK part of Layer 3 end-to-end.

Build:

- Attestor service
- staking and registration flow
- output commitment submission
- consensus finalization
- optimistic challenge integration
- SDK helpers for clients and attestors

Exit criteria:

- Permissioned attestor set can reach consensus in integration tests.
- Challenge path can slash a bad consensus in a controlled test.
- Resolver trust assumptions match the documented model.

### Track C: `reputation_v1`

Goal: let agents prove useful properties about private performance history.

Prerequisite:

Do not start full implementation until Layer 2 and Layer 3 event semantics are stable. Reputation depends on canonical historical records.

Build:

- `AgentReputationState`
- state commitment format
- monotonic update rules
- `ProveReputation` circuit
- `ReputationRegistry.sol`
- SDK `ReputationManager`

Exit criteria:

- Agent can prove a property such as success rate above threshold and violations below threshold.
- Registry rejects non-monotonic or stale updates.
- Layer 2 and Layer 3 events are cross-referenced in tests.

### Track D: Layer 1 Agent Messaging

Goal: encrypted agent-to-agent communication with commitment hooks for later verification.

Build:

- X25519 key exchange
- DID-bound identity proof
- AES-256-GCM message encryption
- forward secrecy design
- per-field commitments for selective disclosure
- MCP/A2A transport wrapper

Exit criteria:

- Two agents establish an encrypted session.
- Messages can be selectively disclosed via commitment openings.
- Message commitments can feed Layer 3/4 proof flows.

### Track E: Layer 5 Registry and Discovery

Goal: discover agents by verified capability and reputation.

Prerequisite:

Do not prioritize until `reputation_v1` has a stable proof statement.

Build:

- `AgentRegistry.sol` or content-addressed registry with on-chain commitments
- `capability_v1` proof statement
- discovery indexer
- SDK Layer 5 helpers

Exit criteria:

- Query returns agents by capability and trust threshold.
- Capability and reputation proofs are independently verifiable.
- Registry avoids hard dependency on EVM-specific principal identifiers.

---

## Proof System Policy

### Current Decision

Keep Halo2/KZG/BN254 for off-chain `authorization_v1`, but do not treat the generated Halo2 Solidity verifier as the EVM backend.

Reasons:

- Existing Halo2 circuit and off-chain verifier path are implemented.
- The generated Halo2 Solidity verifier is not EVM-deployable for this circuit: the corrected runtime is about 319 KB versus the 24,576-byte EVM limit.
- The Layer 2 statement is still small and should be portable to a compact EVM backend.
- The protocol boundary is `IVerifier` plus the public input schema; the proof backend can change through a new proof version.

Immediate EVM backend:

- Primary: Groth16/BN254, because Ethereum has BN254 pairing precompiles and Groth16 verifiers are compact.
- Secondary: Noir/Barretenberg or gnark Groth16 if Circom/snarkjs is unsuitable.
- Do not continue patching the current Halo2 Solidity artifact unless a concrete verifier-size strategy exists.

### Versioning Rules

Create a new proof version when any of these change:

- public input order or count
- policy encoding
- action encoding
- Poseidon layout or parameters
- range-check semantics
- timestamp or replay semantics
- SRS size
- transcript type
- proof backend
- verifier calldata format

Old verifier contracts remain valid for historical proofs. New proof versions get new verifier addresses and SDK version gates.

### Folding / Nova / HyperNova

Folding is a future candidate for incremental audit logs, not the Layer 2 MVP.

Do not adopt folding until CATP has:

- a stable audit state transition function
- canonical log root semantics
- nonce/nullifier or checkpoint design
- revocation semantics
- timestamp/finality model
- credible final verifier path for target hosts
- review capacity for recursive proof complexity

Potential future proof:

```text
audit_ivc_v0:
  state_i + action_i + policy_context_i -> state_{i+1}
```

This should live in an experimental crate/branch until the state machine is stable.

---

## Current Status

| Component | Status |
|-----------|--------|
| Enforcement plugin (`catp-plugin/`) | Complete; published as `@catp-protocol/cli` |
| `ProveAuthorization` Halo2 circuit | Complete locally; formal review pending |
| WASM source bindings (`catp-circuits/wasm`) | Complete; generated `pkg/` excluded from git |
| `AgentAuthorizer.sol` + `ActionData.sol` | Complete |
| `catp-verify` REST verification endpoint | Complete |
| TypeScript SDK Layer 2 | Complete locally |
| Halo2 EVM adapter | Removed from active repository surface after verifier runtime exceeded EVM size limit |
| SRS persistence (`catp-layer2-k12.srs`) | Complete for testnet/dev |
| E2E Rust Layer 2 tests | Complete |
| Compact EVM verifier | Sepolia smoke passed with `authorization_groth16_v1` |
| `catp anchor` Sepolia smoke test | Passed for compact Groth16 verifier path |
| Layer 3 contracts | Not in active repository surface |
| Layer 3 attestor node | Planned |
| `boundary_v1` circuit | Planned |
| Layers 1, 4, 5 | Not in active repository surface |

Current local test count: 214 passing across TypeScript/Jest, Vitest, Rust, and Solidity/Forge.

---

## Dependencies

| Component | Depends On |
|-----------|------------|
| Phase 0 plugin | policy parser, hook runtime, local audit log |
| `authorization_v1` proof | Halo2, Poseidon, MainGate, KZG SRS |
| compact EVM verifier | proof backend, generated verifier, public input order, wrapper calldata format |
| Halo2 EVM adapter | removed; off-chain Halo2 verifier path remains |
| `Groth16AuthorizationVerifier.sol` | compact verifier calldata format, gas cap, generated Groth16 verifier |
| `AgentAuthorizer.sol` | `IVerifier`, policy commitment, action encoding |
| SDK Layer 2 | WASM interface, contract ABIs, public input schema |
| `catp-verify` | Rust verifier path and matching SRS |
| Sepolia smoke test | Groth16 deploy scripts, funded account, RPC, ABI metadata |
| Audit-log-to-proof bridge | Phase 0 audit format + Layer 2 witness format |
| Layer 3 MPA | output commitment schema, attestor set, challenge model, resolver trust model |
| `boundary_v1` | Poseidon, range checks, Layer 3 commitment format |
| `reputation_v1` | stable Layer 2/3 event semantics |
| Layer 5 registry | stable reputation and capability proof statements |

---

## Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Enforcement plugin friction | High | Keep one-command install and clear Claude Code docs |
| Halo2 proving time too slow | High | Benchmark before release; batch where possible; keep `authorization_v1` narrow |
| Circuit soundness bug | High | Formal review, negative tests, public input audit |
| SRS provenance unsuitable for mainnet | High | Treat current SRS as testnet/dev; document ceremony replacement path |
| Public input version drift | High | Version proof statements and verifier addresses |
| Audit logs do not map cleanly to Layer 2 witnesses | High | Define proof manifest and limited MVP action classes |
| Gas too high for user-facing verification | Medium | Target L2s; measure Sepolia/Base/Arbitrum; keep off-chain verifier path |
| Layer 3 resolver centralization | Medium | Start explicit and permissioned; document rotation and challenge model |
| MPA liveness | Medium | Minimum staked set, timeout behavior, optimistic fallback |
| Building Layers 1/4/5 too early | Medium | Gate each track behind proof statement and acceptance criteria |

---

## Out of Scope for Current MVP

- Nova/HyperNova/folding production integration
- Fully proof-centric policy/spend state
- Mainnet SRS ceremony decision
- Decentralized open attestor marketplace
- Full Layer 1 messaging protocol
- Reputation marketplace and discovery registry
- Cross-chain verifier deployments

These are valid protocol directions, but the current execution plan is to ship and harden `authorization_v1` first.
