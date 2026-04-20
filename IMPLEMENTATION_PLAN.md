# CATP Implementation Plan

## Requirements Restatement

Build a 5-layer cryptographic trust stack for AI agents operating on-chain:
- **Layer 1**: Encrypted agent communication (X25519 + AES-256-GCM + Double Ratchet)
- **Layer 2**: ZK-proven delegated authorization (Halo2 circuits + Solidity verifier)
- **Layer 3**: Output verification (commit-and-prove + MPA attestors + optimistic slash)
- **Layer 4**: Privacy-preserving reputation (ZK-proven performance attestations)
- **Layer 5**: Verifiable agent registry and discovery

Shared primitives used across layers: Poseidon commitment, Halo2 ZK system, Sparse Merkle Tree, X25519/AES encryption.

---

## Monorepo Structure

```
catp/
├── catp-circuits/          # Rust — Halo2 ZK circuits
│   ├── primitives/         # Poseidon, range check, Merkle gadgets
│   ├── layer2/             # ProveAuthorization circuit
│   ├── layer3/             # ProveBoundary circuit
│   ├── layer4/             # ProveReputation circuit
│   └── layer5/             # ProveCapability circuit
├── catp-contracts/         # Solidity — on-chain verifiers + state
│   ├── layer2/             # AgentAuthorizer.sol
│   ├── layer3/             # OutputVerifier.sol, MPA.sol, OptimisticSlash.sol
│   ├── layer4/             # ReputationRegistry.sol
│   └── layer5/             # AgentRegistry.sol
├── catp-sdk/               # TypeScript — developer-facing SDK
│   ├── layer1/             # AMP encrypted messaging
│   ├── layer2/             # Policy management + proof generation wrapper
│   ├── layer3/             # Verification helpers + MPA client
│   ├── layer4/             # Reputation state management
│   └── layer5/             # Registry queries + discovery
├── catp-node/              # Rust/TypeScript — MPA attestor node
└── catp-tests/             # Integration tests across layers
```

---

## Phase 1: Foundation + Layer 2 MVP (Month 1–6)

**Goal**: Standalone authorization product. An agent can prove it has permission to act without revealing the full policy.

### 1.1 — Monorepo Setup
- Initialize Cargo workspace (`catp-circuits/`, `catp-node/`)
- Initialize Hardhat/Foundry workspace (`catp-contracts/`)
- Initialize pnpm workspace (`catp-sdk/`)
- CI pipeline: Rust tests, Solidity tests, TypeScript typecheck

### 1.2 — Shared Cryptographic Primitives (Rust)
- **P1**: Poseidon hash gadget using `halo2_gadgets` (ZK-friendly commitment scheme)
- **P2**: `ProofSystem` trait wrapping Halo2 prover/verifier — abstraction layer for future migration
- **P4**: Sparse Merkle Tree implementation for policy trees
- **P5**: X25519 key exchange + AES-256-GCM symmetric encryption utilities

### 1.3 — Layer 2 ZK Circuit (Rust/Halo2)
Implement `ProveAuthorization` circuit in `catp-circuits/layer2/`:
- Public inputs: `policy_commitment`, `action_hash`, `current_timestamp`, `cumulative_spend`
- Private inputs: full `AuthorizationPolicy`, proposed `Action`
- 8 constraints as specified (type membership, protocol/token allowlist, value bounds, time validity)
- Proving key / verification key generation
- Unit tests for satisfying and violating witness cases

### 1.4 — Layer 2 Solidity Contracts
- `AgentAuthorizer.sol`: `registerPolicy`, `executeAuthorized`, `revokePolicy`
- Halo2 on-chain verifier (generated from circuit)
- Cumulative spend tracking per `policy_commitment`
- Deploy scripts (Foundry) targeting local Anvil + testnet

### 1.5 — Layer 2 TypeScript SDK
- `PolicyBuilder`: construct and hash `AuthorizationPolicy` structs
- `ProofClient`: WASM-bundled Halo2 prover (wasm-pack) for browser/node
- `AuthorizerClient`: contract interaction wrapper (ethers.js/viem)
- Documentation + integration example

---

## Phase 2: Layer 3 — Output Verification (Month 6–12)

**Goal**: "Agent was authorized AND its output is trustworthy."

### 2.1 — Defense Layer 1: Commit-and-Prove (Solidity + Rust)
- `CommitRegistry.sol`: `submitPreCommit`, `submitPostCommit`, timestamp enforcement
- Poseidon-based `pre_commit` and `post_commit` chain
- SDK helpers: generate and submit commitments around inference

### 2.2 — Defense Layer 2: MPA Attestor Node (`catp-node/`)
- Attestor node: receives inference requests, executes model, submits `output_commitment`
- `MPAVerifier.sol`: collects attestor submissions, checks ≥ 2/3 consensus
- Attestor staking + slashing logic
- Permissioned attestor set initially (owner-controlled allowlist)

### 2.3 — Defense Layer 3: Optimistic Slash
- `OptimisticChallenge.sol`: challenge window, re-execution submission, slash distribution
- Economic parameters: stake size, window duration, challenger reward ratio

### 2.4 — Layer 3 ZK Circuit: `ProveBoundary`
- Proves output ∈ `[min, max]` range without revealing raw value
- Optional delta-from-previous constraint
- Integrated into post-inference flow

### 2.5 — Combined Verification Flow Integration
- Full 4-step flow (pre-inference commit → inference + MPA → post-inference submit → challenge window)
- End-to-end integration tests with mock model

---

## Phase 3: Layer 4 — Reputation Protocol (Month 12–18)

**Goal**: Agents accumulate private track records and prove properties about them.

### 3.1 — Reputation State Design (Rust + TypeScript)
- `AgentReputationState` struct with all metrics
- Off-chain private state storage (agent's local DB)
- Poseidon commitment scheme for state snapshots

### 3.2 — Layer 4 ZK Circuit: `ProveReputation`
- Proves claims like "success_rate > 95% over > 100 ops" without revealing individual ops
- Constraints: state integrity, ratio bounds, minimum sample size, zero violations
- Monotonicity proof for state updates (ops can only increase)

### 3.3 — `ReputationRegistry.sol`
- Stores `state_commitment` per agent DID
- Verifies update proofs before accepting new commitments
- Cross-references Layer 2 + Layer 3 on-chain events for consistency

### 3.4 — Anti-Gaming Enforcement
- DID binding (new identity resets reputation)
- Monotonic update verification in-circuit
- Minimum sample size gating in `ProveReputation`

---

## Phase 4: Layer 1 + Layer 5 — Communication & Registry (Month 18–24)

**Goal**: CATP becomes a full protocol platform.

### 4.1 — Layer 1: Agent Messaging Protocol (AMP)
- X25519 + DID-bound key exchange
- Double Ratchet state machine for forward secrecy
- Per-field Poseidon commitments on messages (enables selective disclosure)
- MCP transport wrapper + A2A protocol adapter
- TreeKEM extension for multi-party channels

### 4.2 — Layer 5: Agent Registry & Discovery
- `AgentRegistry.sol`: registry CRUD, trust score storage
- `ProveCapability` ZK circuit: proves N successful ops of a type at ≥ threshold success rate
- Discovery query engine (off-chain indexer + on-chain verification of results)
- Audit attestation slot (`audit_attestation` bytes field in registry entry)

### 4.3 — Full Cross-Layer Integration
- End-to-end demo: discover → authorize → communicate → execute + verify → update reputation → refresh registry
- Reference agent implementation (TypeScript)
- SDK bundled documentation site

---

## Dependencies

| Component | Depends On |
|-----------|-----------|
| Layer 2 circuit | P1 Poseidon, P2 Halo2, P4 SMT |
| Layer 3 circuit | P1 Poseidon, Layer 2 circuit |
| Layer 4 circuit | P1 Poseidon, P4 SMT, Layer 2+3 on-chain records |
| Layer 5 circuit | Layer 4 circuit |
| `catp-sdk` | `catp-circuits` WASM bundle, `catp-contracts` ABIs |
| `catp-node` (MPA) | P1 Poseidon, Layer 3 contracts |

---

## Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Halo2 proving time too slow for real-time ops | High | Pre-compute proofs for common patterns; batch; benchmark early in Phase 1 |
| ZK circuit soundness bugs | High | Comprehensive constraint tests; formal review of all circuits before deploy |
| WASM bundle size (browser SDK) | Medium | Code-split by layer; lazy-load prover WASM only when needed |
| MPA attestor liveness | Medium | Fallback to optimistic-only mode; minimum staked set |
| Gas costs (200–400K per verification) | Medium | Target L2 deployment (Arbitrum/Base); batch verifications |
| Adoption chicken-and-egg | High | Phase 1 ships as standalone product; 2–3 design partner protocols |

---

## Complexity Estimate

| Phase | Complexity | Key Deliverable |
|-------|-----------|----------------|
| Phase 1 | High | Layer 2 standalone auth product |
| Phase 2 | High | Layer 3 verification with MPA |
| Phase 3 | Medium | Layer 4 reputation ZK |
| Phase 4 | Medium | Layer 1 + 5, full platform |
