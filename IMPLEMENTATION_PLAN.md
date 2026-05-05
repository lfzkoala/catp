# CATP Implementation Plan

## Product Goal

AI agents (Claude Code, AutoGen, Hermes, OpenClaw, etc.) today operate with broad permissions and no standard mechanism for proving they acted within authorized scope. CATP solves this with a two-product ladder:

**Phase 0 — Enforcement Layer**: a plugin/hook that intercepts agent actions in real time, checks them against a user-defined policy, and blocks unauthorized actions. Fast and synchronous. No ZK, no blockchain. Delivers immediate value: policy enforcement + tamper-evident local audit log.

**Phase 1+ — CATP Protocol Layer**: generates ZK proofs from audit logs and anchors policy commitments on-chain. Upgrades the enforcement plugin from "local policy file" to "cryptographically verifiable compliance" — provable to any third party without trusting the agent developer.

The enforcement plugin is the entry point. The ZK/chain layer is what gives it trustlessness. Neither is useful without the other long-term, but Phase 0 ships standalone value that drives the first adoption milestone.

## First Milestone

**Developers actively using the CATP enforcement plugin in their daily AI agent workflows.**

---

## Phase 0: Enforcement Plugin ✅ Complete

**Goal**: Developers install the CATP plugin into Claude Code (or any agent framework) and get real-time policy enforcement + a local audit log. Zero ZK knowledge required. Zero blockchain wallet required.

### 0.1 — Policy File Format

Define `catp-policy.toml` schema:

```toml
[agent]
id = "my-claude-agent"
version = "1"

[[rules]]
tool = "Bash"
allow = false
pattern = ["rm -rf", "git push", "curl *prod*"]
reason = "Destructive or production-affecting commands blocked"

[[rules]]
tool = "Write"
allow = true
path_allowlist = ["./src/**", "./tests/**"]

[[rules]]
tool = "WebFetch"
allow = false
reason = "External network calls require explicit approval"
```

- Rules evaluated top-to-bottom; first match wins
- `pattern` supports glob matching on command content
- `path_allowlist` / `path_denylist` for file-system tools
- `reason` is returned to the agent in the block message

### 0.2 — Claude Code Hook Integration

Implement `PreToolUse` and `PostToolUse` hook handlers as a CATP CLI:

```
catp hook pre  --tool <name> --input <json>   → prints allow/deny + reason
catp hook post --tool <name> --output <json>  → records commitment hash
```

Hook configuration in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": ".*",
      "command": "catp hook pre --tool $TOOL_NAME --input $TOOL_INPUT"
    }],
    "PostToolUse": [{
      "matcher": ".*",
      "command": "catp hook post --tool $TOOL_NAME --output $TOOL_OUTPUT"
    }]
  }
}
```

### 0.3 — Audit Log

Every intercepted action is recorded locally:

```
~/.catp/audit/<agent-id>/<date>/actions.jsonl

Each entry:
{
  "ts": "<ISO8601>",
  "tool": "<tool name>",
  "decision": "allow" | "deny",
  "rule_matched": "<rule id or none>",
  "commitment": "<Poseidon hash of action + timestamp>",
  "input_summary": "<truncated, no secrets>"
}
```

- Commitment hashes computed using Poseidon from `catp-circuits/primitives`
- Log is append-only; chain breaks in commitment sequence are detectable
- `catp log show` for human-readable output; `catp log verify` to check integrity

### 0.4 — `catp` CLI

```
catp init            # scaffold catp-policy.toml in current directory
catp validate        # validate policy file syntax
catp hook pre/post   # hook handlers (called by agent framework)
catp log show        # display recent audit log
catp log verify      # verify commitment chain integrity
catp anchor          # (Phase 1) submit commitment batch on-chain
```

### 0.5 — Additional Framework Adapters

After Claude Code:
- LangChain: Python middleware wrapper calling `catp hook pre/post`
- AutoGen: agent message interceptor
- OpenAI Assistants: function call wrapper

### Deliverables

- [x] `catp-policy.toml` schema + parser
- [x] `PreToolUse` / `PostToolUse` hook handlers
- [x] Local audit log with Poseidon commitment hashes
- [x] `catp` CLI (init, validate, log, hook)
- [x] Claude Code integration documented in README
- [x] One-command install script
- [x] Published to npm as `@catp-protocol/cli`

---

## Phase 1: ZK Protocol Layer (Month 3–9)

**Goal**: Audit logs become cryptographically verifiable. ZK proofs are generated from the WASM prover and verifiable via a Rust endpoint. On-chain verification is deferred pending stable KZG tooling on crates.io. Upgrades the enforcement plugin from "local policy file" to "provable compliance."

### 1.1 — Web2 Verification Path

Expose `verify_authorization` as a lightweight verification service — the primary verification path for Phase 1:

- Extract a `catp-verify` crate from `catp-circuits/layer2` with lean dependencies
- Expose a REST endpoint: accepts `(proof_bytes, public_inputs_json)`, returns `{ valid: bool }`
- Wire `ProofClient` in the TypeScript SDK to call this endpoint for verification

**Why not on-chain yet**: the IPA/pasta backend used by `halo2_proofs 0.3.x` (crates.io) has no practical Solidity verifier — pasta curves lack EVM precompiles. Switching to KZG requires either a git-pinned dependency (fragile to maintain as APIs drift) or a per-circuit trusted setup (contradicts CATP's trustless principle). On-chain verification is deferred to Phase 2 when the ecosystem matures. The `IVerifier` interface is already in place — swapping to a real verifier requires no changes to `AgentAuthorizer` logic.

### 1.2 — WASM Prover Bundle ✅

`catp-circuits/wasm` built and published via wasm-pack. Exports `prove_authorization` and `verify_authorization` as wasm-bindgen functions. `ProofClient` in the TypeScript SDK is wired to the WASM bundle for proving and to the `catp-verify` REST endpoint for verification.

### 1.3 — `catp anchor` Command

Wire Phase 0 audit logs to on-chain:

- Batch commitment hashes into a Merkle root
- Submit root to `AgentAuthorizer.registerPolicy`
- Return a transaction hash the user can share as proof of compliance
- Target: Arbitrum Sepolia or Base Sepolia (lower gas)

### 1.4 — Layer 2 Circuit Hardening

- Formal review of all 8 constraints in `ProveAuthorization`
- Fuzz witness generator to find edge cases
- Benchmark prover: target < 30s on developer hardware

### Deliverables

- [x] WASM prover bundle built (`catp-circuits/wasm`)
- [x] `catp-verify` crate exposing `verify_authorization` as a Rust library + REST endpoint
- [x] WASM bundle wired into `ProofClient` in TypeScript SDK
- [x] `ProofClient` verification calls routed to `catp-verify` REST endpoint
- [x] `catp anchor` command working end-to-end
- [ ] Circuit formal review complete
- [ ] On-chain Solidity verifier — deferred to Phase 2 (pending stable KZG crates.io release or Nova/HyperNova tooling)

---

## Phase 2: Trustless On-Chain Verification (Month 9–18)

**Goal**: Replace the stub verifier with a real on-chain Halo2 KZG verifier so that policy compliance is provable to any third party without trusting CATP's servers.

### Background: What Was Built vs. What's Needed

Phase 1 shipped a working proof system (GWC + EvmTranscript over BN254, 11/11 Rust tests passing) and a generated Solidity verifier. However several gaps remain before the system is truly trustless:

| Gap | Root Cause |
|-----|-----------|
| SRS mismatch | `proof.rs` and `generate_verifier.rs` each call `ParamsKZG::new(k)` independently — different random SRS every run |
| No public inputs | Circuit passes empty instance columns; `policyCommitment`, `timestamp`, and `spend` are not constrained on-chain |
| `publicInputs` ignored | `Halo2AuthorizationVerifier.verify()` discards the `publicInputs` array and only checks proof bytes |
| `policyCommitment` off-chain | SHA-256 in Rust/TypeScript — incompatible with in-circuit Poseidon; on-chain comparison impossible |

Phases A–G close these gaps in dependency order.

---

### Phase A — In-Circuit Poseidon + Public Inputs

**Goal**: The circuit computes `policyCommitment = Poseidon(policy_fields)` in-circuit and exposes three public values (commitment, timestamp, spend) on the instance column.

**Key facts (empirically confirmed via `poseidon_probe` tests):**
- Both T=5/RATE=4 and T=3/RATE=2 Poseidon require **k=12** (4096 rows); k=11 is insufficient
- `MainGateConfig` allocates 1 instance column; `expose_public(layouter, value, row)` constrains a cell to it
- The existing `pub_cols` approach must be replaced — MainGate owns the single instance column

**Changes to `catp-circuits/layer2/src/circuit.rs`**:

1. Add `MainGateConfig` alongside the existing config:
   ```rust
   pub struct AuthorizationConfig {
       mg: maingate::MainGateConfig,
       // existing advice columns
   }
   ```

2. Implement `poseidon_in_circuit(ctx, gate, spec, inputs)` that:
   - Initialises state from `poseidon::State::<Fr, T>::default()`
   - Runs full/partial/full rounds via `gate.mul`, `gate.mul_add_constant`, `gate.compose`
   - Returns `state[1]` (the digest)

3. In `synthesize`:
   - Assign policy fields as private witnesses
   - Compute `commitment = poseidon_in_circuit(...)`
   - Call `gate.expose_public(layouter, commitment, 0)`
   - Call `gate.expose_public(layouter, timestamp_cell, 1)`
   - Call `gate.expose_public(layouter, spend_cell, 2)`

4. Bump `k` to `12` in `AuthorizationProofSystem`.

**Deliverables:**
- [ ] `MainGate` integrated into `AuthorizationConfig`
- [ ] `poseidon_in_circuit` helper implemented
- [ ] Three values exposed on instance column (rows 0, 1, 2)
- [ ] `MockProver` verifies at k=12 with correct instance values
- [ ] All existing circuit unit tests pass

---

### Phase B — `proof.rs` Update

**Goal**: The prover passes the correct instance slice and uses k=12.

**Changes to `catp-circuits/layer2/src/proof.rs`**:

1. Compute `policy_commitment` using the native (non-circuit) Poseidon:
   ```rust
   let mut h = poseidon::Poseidon::<Fr, T, RATE>::new(R_F, R_P);
   h.update(&policy_fields);
   let commitment = h.squeeze();
   ```

2. Build the instance vector:
   ```rust
   let instance = vec![commitment, Fr::from(timestamp), Fr::from(spend)];
   ```

3. Pass `&[&[instance.as_slice()]]` to both `create_proof` and `verify_proof`.

4. Update `K` constant from its current value to `12`.

**Deliverables:**
- [ ] `prove()` passes instance slice to `create_proof`
- [ ] `verify()` passes same instance slice to `verify_proof`
- [ ] Native Poseidon used to compute `policyCommitment` in `AuthorizationProofSystem`
- [ ] All 11 Rust proof tests pass at k=12

---

### Phase C — SRS Persistence

**Goal**: Prover and Solidity verifier use the same KZG SRS so proofs actually verify on-chain.

**Problem**: `ParamsKZG::new(k)` generates a fresh random SRS on every call. Running it in two separate binaries yields two different SRS values — a proof generated by one will never verify against a verifier generated by the other.

**Changes**:

1. `catp-circuits/layer2/src/bin/generate_verifier.rs`:
   - After generating the SRS, serialize it:
     ```rust
     let mut srs_file = File::create("catp-layer2-k12.srs")?;
     params.write(&mut srs_file)?;
     ```

2. `catp-circuits/layer2/src/proof.rs` (`AuthorizationProofSystem::new`):
   - Accept an optional SRS path; load from file if present:
     ```rust
     let params = if let Some(path) = srs_path {
         let mut f = File::open(path)?;
         ParamsKZG::<Bn256>::read(&mut f)?
     } else {
         ParamsKZG::<Bn256>::new(K)
     };
     ```

3. For development: generate a fresh SRS and commit `catp-layer2-k12.srs` to the repo (acceptable for testnet; production uses a KZG ceremony output).

**Deliverables:**
- [ ] `generate_verifier` writes SRS to `catp-layer2-k12.srs`
- [ ] `AuthorizationProofSystem` loads SRS from file when path is provided
- [ ] Proof generated with loaded SRS verifies against Solidity verifier generated with same SRS
- [ ] SRS file committed for testnet use (with note: replace with ceremony output for mainnet)

---

### Phase D — Regenerate Solidity Verifier

**Goal**: The on-chain verifier reflects the updated circuit (k=12, 3 public inputs).

**Changes to `catp-circuits/layer2/src/bin/generate_verifier.rs`**:

1. Update `num_instance`:
   ```rust
   let num_instance = vec![3]; // policyCommitment, timestamp, spend
   ```

2. Load SRS from `catp-layer2-k12.srs` instead of calling `ParamsKZG::new(k)`.

3. Run the binary and copy the output to `catp-contracts/src/layer2/Halo2Verifier.sol`.

**Deliverables:**
- [ ] `generate_verifier` uses loaded SRS and `num_instance = [3]`
- [ ] `Halo2Verifier.sol` regenerated and updated in contracts
- [ ] `forge build` passes with updated verifier
- [ ] `forge test` — all 43+ tests pass

---

### Phase E — Fix `Halo2AuthorizationVerifier.sol`

**Goal**: The wrapper contract forwards public inputs to the Halo2 verifier instead of ignoring them.

**Background**: The generated `Halo2Verifier.sol` expects calldata in the format `[instance_0, instance_1, instance_2, proof_bytes...]` where instance values are 32-byte big-endian Fr elements prepended to the proof.

**Changes to `catp-contracts/src/layer2/Halo2AuthorizationVerifier.sol`**:

```solidity
function verify(
    bytes32[] calldata publicInputs,
    bytes calldata proof
) external view override returns (bool) {
    // publicInputs[0] = policyCommitment, [1] = timestamp, [2] = spend
    bytes memory callData = abi.encodePacked(
        publicInputs[0],
        publicInputs[1],
        publicInputs[2],
        proof
    );
    (bool ok,) = halo2Verifier.staticcall(callData);
    return ok;
}
```

**Deliverables:**
- [ ] `Halo2AuthorizationVerifier.verify()` encodes and forwards public inputs
- [ ] Unit test: verifier returns `true` for a valid proof + matching public inputs
- [ ] Unit test: verifier returns `false` when public inputs are tampered
- [ ] All forge tests pass

---

### Phase F — Off-Chain Poseidon Commitment

**Goal**: The off-chain `policyCommitment` is computed with the same Poseidon hash as the circuit so the commitment can be verified on-chain.

**Background**: Phase 0 uses SHA-256 (`[u8; 32]`) for `policy_commitment` in `catp-primitives`. This is incompatible with in-circuit Poseidon over BN254 Fr. A commitment computed off-chain with SHA-256 can never match the in-circuit Poseidon digest.

**Changes**:

1. `catp-primitives/src/policy.rs`:
   - Add `compute_policy_commitment(policy: &AuthorizationPolicy) -> Fr`:
     ```rust
     pub fn compute_policy_commitment(policy: &AuthorizationPolicy) -> Fr {
         let fields = policy.to_field_elements(); // [Fr; 9]
         let mut h = poseidon::Poseidon::<Fr, 3, 2>::new(R_F, R_P);
         h.update(&fields);
         h.squeeze()
     }
     ```
   - Update `AuthorizationPolicy::commitment()` to return `Fr` (or a `[u8; 32]` big-endian encoding for ABI compatibility).

2. `catp-sdk/src/layer2/PolicyBuilder.ts`:
   - Replace SHA-256 commitment computation with a call to the WASM-exported `compute_policy_commitment`.
   - Update `AuthorizationPublicInputs` type to accept the Fr-encoded commitment.

3. `catp-sdk/src/layer2/AuthorizerClient.ts`:
   - Pass Fr-encoded `policyCommitment` as `publicInputs[0]` when calling `AgentAuthorizer`.

**Deliverables:**
- [ ] `compute_policy_commitment` in `catp-primitives` using Poseidon Fr
- [ ] WASM export of `compute_policy_commitment`
- [ ] `PolicyBuilder.ts` uses WASM commitment helper
- [ ] `AuthorizerClient.ts` passes Fr commitment in `publicInputs[0]`
- [ ] TypeScript SDK tests updated and passing

---

### Phase G — End-to-End Verification Test

**Goal**: A single test exercises the full trustless path: policy → commitment → proof → on-chain verification.

**New test in `catp-circuits/layer2/tests/e2e.rs`**:

```rust
#[test]
fn e2e_trustless_verification() {
    // 1. Build a policy and compute its Poseidon commitment
    let policy = AuthorizationPolicy { /* ... */ };
    let commitment = compute_policy_commitment(&policy);

    // 2. Prove authorization
    let prover = AuthorizationProofSystem::new(Some("catp-layer2-k12.srs")).unwrap();
    let action = Action { tool: "Bash", timestamp: 1_000_000, spend: 0 };
    let proof = prover.prove(&policy, &action).unwrap();

    // 3. Verify off-chain (Rust VerifierGWC path)
    assert!(prover.verify(&proof).unwrap());

    // 4. Verify on-chain (Solidity via alloy / revm)
    // Deploy Halo2Verifier + Halo2AuthorizationVerifier in a local EVM
    // Call verify(publicInputs, proof_bytes) and assert true
}
```

Also add a negative test: tampered `publicInputs[0]` must return `false`.

**Deliverables:**
- [ ] `tests/e2e.rs` passing with SRS-consistent prover + verifier
- [ ] Negative test: tampered commitment fails verification
- [ ] `catp anchor` smoke test on Sepolia confirming gas usage < 500K

---

### Phase 2 Summary

| Phase | What | Status |
|-------|------|--------|
| A | In-circuit Poseidon + expose 3 public values | 🔜 Next |
| B | proof.rs: k=12, native Poseidon commitment, instance slice | 🔜 Blocked on A |
| C | SRS persistence: write/read `.srs` file | 🔜 Parallel with A |
| D | Regenerate Halo2Verifier.sol with k=12 + num_instance=[3] | 🔜 Blocked on B+C |
| E | Fix Halo2AuthorizationVerifier to forward publicInputs | 🔜 Blocked on D |
| F | Off-chain Poseidon commitment in primitives + SDK | 🔜 Parallel with A–D |
| G | E2E test: policy → proof → on-chain verify | 🔜 Blocked on E+F |

---

## Phase 3: Output Verification (Month 18–24)

**Goal**: "Agent was authorized AND its output is trustworthy." Targets AI-powered DeFi risk engines and any scenario where output correctness matters, not just authorization.

### 3.1 — Defense Layer 1: Commit-and-Prove

- `CommitRegistry.sol` + SDK helpers ✅ (contracts exist, real verifier wired after Phase 2)
- Generate and submit pre/post commitments around inference

### 3.2 — Defense Layer 2: MPA Attestor Node

- `catp-node/`: receives inference request, runs model, submits `output_commitment`
- `MPAVerifier.sol` ✅ (exists, needs real verifier)
- Attestor staking + slashing; permissioned set initially

### 3.3 — Defense Layer 3: Optimistic Slash

- `OptimisticChallenge.sol` ✅ (exists)
- Tune economic parameters: stake size, window duration, challenger reward ratio

### 3.4 — `ProveBoundary` Circuit

- Implement `catp-circuits/layer3/` (currently scaffold)
- Proves output ∈ `[min, max]` without revealing raw value
- Integrated into post-inference flow

### Deliverables

- [ ] End-to-end Layer 3 flow on testnet
- [ ] `ProveBoundary` circuit implemented and tested
- [ ] Permissioned attestor set running
- [ ] Integration tests in `catp-tests/`

---

## Phase 4: Reputation Protocol (Month 24–30)

**Goal**: Agents accumulate private track records and prove properties about them. Activates network effects: agents want reputation → more agents join → protocols trust the system more.

### 4.1 — Reputation State + Off-Chain Storage

- `AgentReputationState` struct + Poseidon commitment scheme
- Local state storage (file or embedded DB)
- SDK `ReputationManager` (currently scaffold in `catp-sdk/src/layer4/`)

### 4.2 — `ProveReputation` Circuit

- Implement `catp-circuits/layer4/` (currently scaffold)
- Constraints: state integrity, ratio bounds, minimum sample, zero violations, monotonic updates

### 4.3 — `ReputationRegistry.sol`

- Stores `state_commitment` per agent DID
- Verifies monotonic update proofs before accepting new commitments
- Cross-references Layer 2 + Layer 3 on-chain events for consistency

### Deliverables

- [ ] `ProveReputation` circuit implemented and tested
- [ ] `ReputationRegistry.sol` deployed on testnet
- [ ] SDK `ReputationManager` complete
- [ ] Anti-gaming enforcement verified via tests

---

## Phase 5: Full Platform (Month 30–36)

**Goal**: CATP becomes a protocol, not just a product.

### 5.1 — Layer 1: Agent Messaging Protocol (AMP)

- X25519 + DID-bound key exchange; Double Ratchet for forward secrecy
- Per-field Poseidon commitments (selective disclosure)
- MCP transport wrapper + A2A protocol adapter
- SDK `catp-sdk/src/layer1/` (currently scaffold)

### 5.2 — Layer 5: Agent Registry & Discovery

- `AgentRegistry.sol`: registry CRUD, trust score storage
- `ProveCapability` circuit (`catp-circuits/layer5/`, currently scaffold)
- Discovery query engine (off-chain indexer + on-chain verification)
- SDK `catp-sdk/src/layer5/` (currently scaffold)

### 5.3 — Full Cross-Layer Demo

- End-to-end: discover → authorize → communicate → execute + verify → update reputation → refresh registry
- Reference agent implementation (TypeScript)
- Documented mainnet deployment (Arbitrum or Base)

### Deliverables

- [ ] Layer 1 AMP implementation
- [ ] Layer 5 registry deployed on mainnet
- [ ] Full cross-layer demo working
- [ ] SDK documentation site

---

## Current Status

| Component | Status |
|-----------|--------|
| Enforcement plugin (`catp-plugin/`) | ✅ Complete (72 tests) — published as `@catp-protocol/cli` |
| `ProveAuthorization` Halo2 circuit — GWC + EvmTranscript (BN254) | ✅ Complete (11 tests) |
| WASM prover bundle (`catp-circuits/wasm`) | ✅ Complete — `prove_authorization` / `verify_authorization` |
| `AgentAuthorizer.sol` + `ActionData.sol` | ✅ Complete (16 tests, stub verifier) |
| `catp-verify` REST verification endpoint | ✅ Complete (3 tests) |
| TypeScript SDK Layer 2 (`PolicyBuilder`, `AuthorizerClient`, `ProofClient`) | ✅ Complete (28 tests) — wired to WASM prover + `catp-verify` REST endpoint |
| `CommitRegistry.sol` (Layer 3) | ✅ Complete (8 tests) |
| `MPAVerifier.sol` (Layer 3) | ✅ Complete (9 tests) |
| `OptimisticChallenge.sol` (Layer 3) | ✅ Complete (10 tests) |
| `Halo2Verifier.sol` generated + compiles | ✅ Complete (via_ir; random SRS — not yet production-safe) |
| `Halo2AuthorizationVerifier.sol` wrapper | ✅ Compiles (ignores publicInputs — fixed in Phase E) |
| `poseidon_probe` k-sizing test | ✅ Complete — k=12 confirmed for T=3/RATE=2 and T=5/RATE=4 |
| In-circuit Poseidon (Phase A) | 🔜 Next task |
| SRS persistence (Phase C) | 🔜 Next task |
| Real trustless on-chain verification (Phases A–G) | 🔜 In progress |
| Layers 1, 4, 5 circuits | 🔜 Scaffold only |
| SDK Layers 1, 3, 4, 5 | 🔜 Scaffold only |

**148 tests passing** across TypeScript/Jest (72), Vitest (28), Rust (14), and Solidity/Forge (34).

---

## Dependencies

| Component | Depends On |
|-----------|-----------|
| `catp-plugin` Phase 0 | `catp-primitives` (Poseidon) |
| `catp-plugin` Phase 1 anchor | `catp-contracts/layer2` + WASM prover |
| Phase A (in-circuit Poseidon) | `poseidon` crate, `maingate` crate — already in Cargo.toml |
| Phase B (proof.rs) | Phase A circuit changes |
| Phase C (SRS persistence) | Parallel; only needs `ParamsKZG` read/write API |
| Phase D (regen verifier) | Phases B + C |
| Phase E (wrapper fix) | Phase D |
| Phase F (off-chain Poseidon) | `catp-primitives` Poseidon, WASM export |
| Phase G (E2E test) | Phases E + F |
| Layer 3 circuit | Poseidon, Layer 2 circuit |
| Layer 4 circuit | Poseidon, SMT, Layer 2+3 on-chain records |
| Layer 5 circuit | Layer 4 circuit |
| `catp-sdk` | `catp-circuits` WASM bundle, `catp-contracts` ABIs |
| `catp-node` (MPA) | Poseidon, Layer 3 contracts |

---

## Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Enforcement plugin friction — developers don't install it | High | One-command install; Claude Code hooks are native and well-documented |
| Halo2 proving time too slow | High | Pre-compute for common patterns; batch; benchmark in Phase 1; k=12 target < 30s |
| ZK circuit soundness bugs | High | Comprehensive constraint tests; formal review before deploy |
| MainGate row budget exceeded at k=12 | Medium | Empirically confirmed safe via `poseidon_probe`; k=13 fallback if needed |
| SRS mismatch in production | High | Phase C pins SRS file; production uses a KZG ceremony output |
| WASM bundle size (browser SDK) | Medium | Code-split by layer; lazy-load prover WASM |
| MPA attestor liveness | Medium | Fallback to optimistic-only mode; minimum staked set |
| Gas costs (200–400K per verification) | Medium | Target L2 (Arbitrum/Base); batch verifications |
| Adoption chicken-and-egg | High | Phase 0 ships standalone value with no protocol dependency |
