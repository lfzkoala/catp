# CATP Implementation Plan

## Product Goal

CATP makes autonomous agent activity enforceable locally and provable externally.

The product ladder has two parts:

1. **Enforcement Layer**: a plugin/hook that intercepts agent actions synchronously, checks them against a policy, blocks unauthorized actions, and writes a tamper-evident audit log.
2. **Protocol Layer**: versioned ZK proofs and chain/web2 verifiers that let a third party verify compliance without seeing private policy details.

The enforcement plugin is the adoption wedge. The proof layer is the trust primitive. The current proof-system decision is:

```text
authorization_v1 = Halo2/KZG/BN254 + 13 public inputs + versioned verifier
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
  -> catp-verify or Halo2AuthorizationVerifier
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

Status: complete locally; testnet smoke test and formal review pending.

Delivered:

- `ProveAuthorization` Halo2 circuit at `k=12`
- In-circuit Poseidon policy commitment
- 13 public inputs:
  `policyCommitment`, `actionType`, `protocol[4]`, `token[4]`, `value`, `currentTimestamp`, `cumulativeSpend`
- u64 range checks for value, spend, timestamp, and inequality witnesses
- protocol/token binding across all 32 bytes
- shared KZG SRS file for testnet/dev consistency
- generated `Halo2Verifier.sol`
- `Halo2AuthorizationVerifier.sol` wrapper that forwards public inputs
- `AgentAuthorizer.sol` using `IVerifier`
- WASM bundle with `compute_policy_commitment`, `prove_authorization`, `verify_authorization`
- `catp-verify` Rust library and REST endpoint
- TypeScript SDK Layer 2 clients and tests

Important design constraints:

- `authorization_v1` stays on Halo2/KZG/BN254.
- Any change to public inputs, policy encoding, hash layout, circuit constraints, SRS size, transcript, or proof backend creates a new proof version and verifier address.
- `activePolicies` and `cumulativeSpend` remain in-contract until CATP has a canonical state-root, nonce, nullifier, or checkpoint design for proof-centric state.
- The committed `catp-layer2-k12.srs` is acceptable for testnet/dev. Mainnet requires documented SRS provenance or replacement with an accepted ceremony output.

### Layer 3 Contract Skeleton

Status: partial.

Delivered:

- `CommitRegistry.sol`
- `MPAVerifier.sol`
- `OptimisticChallenge.sol`

Remaining Layer 3 work is mostly operational and integration-heavy: attestor node, resolver trust model, end-to-end flow, and the `boundary_v1` circuit.

---

## Immediate Execution Plan

### P0: Release Packaging

Goal: make the current Layer 0/2 slice reproducible for outside users.

Work:

- Audit npm package contents and install flow.
- Decide whether WASM `pkg/` is committed, generated in CI, or published as a package artifact.
- Document contract build/deploy commands.
- Document SRS generation/loading behavior for dev, testnet, and future mainnet.
- Add a "known limits" section for Halo2/KZG, testnet SRS, and proof versioning.

Exit criteria:

- A clean install from npm can run the CLI.
- SDK consumers can import Layer 2 proof helpers.
- A developer can reproduce verifier generation from documented commands.
- Release notes clearly distinguish local enforcement, off-chain verification, and on-chain verification.

### P0: Layer 2 Circuit and Security Review

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

### P1: Sepolia Smoke Test

Goal: prove the local path survives a real testnet deployment.

Work:

- Deploy `Halo2Verifier.sol`, `Halo2AuthorizationVerifier.sol`, and `AgentAuthorizer.sol`.
- Register a policy commitment.
- Generate an `authorization_v1` proof from the SDK/WASM path.
- Call `executeAuthorized` with matching public inputs.
- Record gas, tx hashes, addresses, chain, and SRS/verifier build metadata.
- Run a negative case with tampered public inputs if gas budget permits.

Exit criteria:

- One successful testnet proof verification.
- One documented verification failure for tampered inputs, either on-chain or via local fork.
- Gas numbers recorded in this plan or deployment notes.

### P1: Bridge Plugin Audit Logs to Layer 2 Proofs

Goal: connect the product surface to the cryptographic proof surface.

Current gap:

The plugin writes generic tool-call audit entries and a SHA-256 hash chain. Layer 2 proves structured authorization actions: action type, protocol, token, value, timestamp, cumulative spend. These are related, but not yet a single user-facing verification flow.

Work:

- Define the mapping from audit entry to `AuthorizationPolicy` and `Action`.
- Decide which tool/action classes can produce Layer 2 witnesses in the MVP.
- Add a proof manifest format that links:
  - audit log entry id
  - SHA-256 log-chain commitment
  - Poseidon policy commitment
  - `authorization_v1` public inputs
  - proof bytes or proof URL
- Implement `catp prove authorization` or equivalent CLI flow.
- Implement `catp verify authorization` for local/off-chain verification.

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
- Integration-test scenarios are specified before `catp-node` implementation.

---

## Post-MVP Tracks

### Track A: `boundary_v1` Output Boundary Proof

Goal: prove that a committed output lies inside a permitted numeric range without revealing the output.

Build:

- Implement `catp-circuits/layer3` beyond scaffold.
- Public inputs: `outputCommitment`, `boundarySpecCommitment` or explicit min/max fields.
- Private inputs: output value and salt.
- Constraints:
  - `Poseidon(output, salt) == outputCommitment`
  - `min <= output <= max`
- Add Rust unit tests, proof tests, and SDK wrappers.

Exit criteria:

- `boundary_v1` proof verifies locally.
- Public input schema is versioned.
- Integration path with `CommitRegistry.sol` is documented.

### Track B: MPA Attestor Flow

Goal: run the non-ZK part of Layer 3 end-to-end.

Build:

- `catp-node` attestor service
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

Keep Halo2/KZG/BN254 for `authorization_v1`.

Reasons:

- Existing circuit and verifier path are implemented.
- EVM verification is available through generated Solidity and BN254 precompiles.
- Current Layer 2 statement is small enough for Halo2 to remain maintainable.
- Migration now would delay the MVP without improving the immediate product surface.

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
| WASM prover bundle (`catp-circuits/wasm`) | Complete |
| `AgentAuthorizer.sol` + `ActionData.sol` | Complete |
| `catp-verify` REST verification endpoint | Complete |
| TypeScript SDK Layer 2 | Complete locally |
| `Halo2Verifier.sol` | Complete for `authorization_v1` testnet/dev SRS |
| `Halo2AuthorizationVerifier.sol` | Complete |
| SRS persistence (`catp-layer2-k12.srs`) | Complete for testnet/dev |
| E2E Rust Layer 2 tests | Complete |
| `catp anchor` Sepolia smoke test | Pending |
| Layer 3 contracts | Partial |
| Layer 3 attestor node | Pending |
| `boundary_v1` circuit | Pending |
| Layers 1, 4, 5 | Scaffold only |

Current local test count: 214 passing across TypeScript/Jest, Vitest, Rust, and Solidity/Forge.

---

## Dependencies

| Component | Depends On |
|-----------|------------|
| Phase 0 plugin | policy parser, hook runtime, local audit log |
| `authorization_v1` proof | Halo2, Poseidon, MainGate, KZG SRS |
| `Halo2Verifier.sol` | generated verifier matching circuit, SRS, transcript, and public input count |
| `Halo2AuthorizationVerifier.sol` | generated verifier calldata format |
| `AgentAuthorizer.sol` | `IVerifier`, policy commitment, action encoding |
| SDK Layer 2 | WASM bundle, contract ABIs, public input schema |
| `catp-verify` | Rust verifier path and matching SRS |
| Sepolia smoke test | deploy scripts, funded account, RPC, ABI metadata |
| Audit-log-to-proof bridge | Phase 0 audit format + Layer 2 witness format |
| Layer 3 MPA | CommitRegistry, MPAVerifier, OptimisticChallenge, resolver trust model |
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
