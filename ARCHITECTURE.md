# Cryptographic Agent Trust Protocol (CATP)

## Vision

A modular, cryptography-native protocol stack that enables trustworthy autonomous operations — for both AI agents and human actors, on any chain or web2 environment. Each layer is independently deployable, collectively composable.

The protocol treats AI agents and humans as two types of the same abstraction: **principals**. A principal is any entity (human wallet, AI agent, smart contract, DAO multisig) that can be authorized, verified, and reputation-scored. This design ensures CATP is not limited to any single market — it serves any scenario where one entity delegates authority to another with cryptographic trust.

**CATP is a proof-centric protocol, not an Ethereum protocol.** The proof is the portable trust primitive. The current implemented proof backend is Halo2/KZG on BN254 for local and off-chain verification, but the generated Halo2 Solidity verifier is not deployable for the current circuit because the real runtime bytecode exceeds the EVM limit. The protocol boundary is the verifier interface and public input schema, not a specific chain or proof library. Any system that can verify the selected CATP proof version can participate — whether it is an EVM chain, a non-EVM blockchain, or a web2 service. The Ethereum implementation is the reference deployment target, not the protocol boundary.

Identity layer (Layer 0) is ceded to existing players (Kite AI, Lit Protocol, etc. for agents; ENS, Polygon ID, etc. for humans). CATP owns everything above identity: authorization, verification, reputation, discovery, and communication.

---

## Product Architecture

CATP is deployed as two complementary layers:

```
┌───────────────────────────────────────────────────────┐
│                  Enforcement Layer                    │
│   (Plugin / Hook — runs locally, synchronous)         │
│                                                       │
│   User defines policy → Agent action intercepted →   │
│   Local policy check → Allow / Deny + Audit log      │
└────────────────────────┬──────────────────────────────┘
                         │ action commitment hash (async)
                         ▼
┌───────────────────────────────────────────────────────┐
│                  CATP Protocol Layer                  │
│   (ZK proof + blockchain — async, verifiable)         │
│                                                       │
│   ZK proof generated in background →                 │
│   Policy commitment anchored on-chain →               │
│   Anyone can verify agent's compliance               │
│   without seeing the policy details                   │
└───────────────────────────────────────────────────────┘
```

### Sync Enforcement + Async Proof

The two layers run at different speeds and serve different purposes:

```
At action time (milliseconds — blocks the agent)
  Plugin intercepts tool call
  → Local policy check (allow / deny)
  → Record commitment hash of action
  → Agent proceeds or is blocked

In background (seconds — non-blocking)
  ZK proof generated from commitment hash
  → Submitted to CATP protocol layer

If challenged by any party (on demand)
  Proof retrieved
  → Verified cryptographically (no online attestor required)
  → Agent's compliance is mathematically guaranteed
```

This is the same model as ZK rollups: execute optimistically, prove lazily, challenge when needed.

### Enforcement Layer — Integration Points

The plugin integrates with agent frameworks via their native extension hooks:

| Agent Framework | Integration Point |
|----------------|-------------------|
| Claude Code | `PreToolUse` / `PostToolUse` hooks |
| LangChain / LangGraph | Tool middleware / callback handlers |
| AutoGen | Agent message interceptors |
| OpenAI Assistants | Function call wrappers |
| Custom agents | CATP SDK middleware |

Each integration intercepts the agent's action before execution, checks it against the user-defined CATP policy, and records a commitment hash for later proof generation.

### Attack Vectors the Enforcement Layer Addresses

| Attack | Mechanism | CATP mitigation |
|--------|-----------|-----------------|
| Prompt injection → privilege escalation | Injected instructions expand agent's effective scope | `PreToolUse` hook blocks any action outside policy allowlist regardless of instruction source |
| Excessive agency | Agent granted write access to prod DB, email, financial APIs by default | Policy file defines an explicit allowlist; everything else is denied |
| OAuth scope creep | Default OAuth scopes extend agent access to Gmail, Drive, Calendar | Policy rules constrain which external APIs the agent may call |
| Silent exfiltration | Agent reads sensitive files and calls external endpoints without user awareness | `PostToolUse` hook records every action; anomalies visible in audit log |
| Undecommissioned agents | Agents persist with live credentials after their task ends | Policy TTL and session limits enforced at the hook layer |

The ZK proof layer adds one further guarantee: even after the session ends, the audit log can be proven tamper-free to any external party without replaying or exposing raw logs.

---

## Protocol Portability

### The Core Principle

The ZK proof is self-contained for a specific circuit version. It encodes claims about policy compliance, output boundaries, and reputation properties, and can be verified by any system that has the matching verification key and public input schema. The chain or environment is where state is anchored and proofs are submitted. It is an adapter, not the protocol.

```
┌─────────────────────────────────────────────┐
│           CATP Protocol Core                │
│                                             │
│  Versioned ZK circuits (Halo2 off-chain;   │
│  Groth16 compact EVM backend)              │
│  Versioned proof format + public inputs     │
│  Policy encoding (chain-agnostic)           │
│  SDK (TypeScript)                           │
└──────────────────┬──────────────────────────┘
                   │  CATProof
         ┌─────────┼──────────┐
         ▼         ▼          ▼
    EVM Adapter  Web2 Adapter  Future
    (Solidity    (Rust fn,     (Move,
     IVerifier)   REST API)    CosmWasm…)
```

### The IVerifier Interface

Every environment exposes one function to the CATP protocol:

```
verify(publicInputs: bytes32[], proof: bytes) → bool
```

Implementations:
- **EVM**: `authorization_groth16_v1` compact Groth16/BN254 verifier. The current generated `Halo2Verifier.sol` is functionally useful as a generation artifact but not deployable for this circuit: after preventing via-IR from optimizing it into a 67-byte always-reverting runtime, Foundry reports about 319 KB of runtime bytecode, far above the EVM 24,576-byte limit.
- **Web2**: `catp-verify` Rust crate exposing a REST endpoint that verifies proof bytes against the same 13 public inputs — ✅ complete
- **Non-EVM chains**: native verifier library — same circuit version and public input schema, host-specific verifier

The Solidity `AgentAuthorizer` accepts an `IVerifier` at construction time. Swapping the verifier (e.g., from `StubVerifier` in tests to a compact Groth16/Plonk verifier wrapper) requires no changes to authorization control flow as long as the same public input contract is preserved. Changes to the proof statement itself should be released as a new versioned verifier and policy schema.

### Proof-Centric State Design

A key architectural principle: **push state into proofs, not contracts.**

| Concern | Naive (state-in-contract) | Proof-centric (target) |
|---------|--------------------------|------------------------|
| Policy validity | `mapping(bytes32 => bool) activePolicies` | Delegator signature or policy-root checkpoint bound into proof |
| Spend tracking | `mapping(bytes32 => uint256) cumulativeSpend` | Cumulative spend bound to a canonical state root, nonce, or nullifier |
| Reputation | On-chain counters | State commitment in proof, updated off-chain and checkpointed |

The current implementation still keeps policy activation and cumulative spend in the EVM contract for simplicity, while the proof binds the action fields, proven timestamp, and current spend. This is intentional for the MVP: a proof can show that a spend value satisfies a policy, but the host must still know that the value is the latest canonical value. The target architecture can move more state into proofs over time, but only when each proof is also bound to a canonical state root, nonce, nullifier set, or checkpoint that prevents stale-state replay.

### Deployment Environments

| Environment | Verifier | State anchor | Policy identifier |
|-------------|----------|--------------|------------------|
| Ethereum / EVM L2 | `IVerifier` Solidity contract | Smart contract storage | `bytes32` commitment |
| Web2 server | Rust `verify_proof` fn | Database row | UUID or hash |
| Cosmos / CosmWasm | Native Rust verifier | CosmWasm contract | Bytes32 |
| Solana | Native Rust verifier | Account data | Pubkey-derived |
| Offline / air-gapped | Rust binary | File / HSM | Hash |

For a given proof version, the circuit statement and public input schema should be identical across all rows. The concrete verifier implementation may differ by host. EVM is the reference deployment for MVP. Web2 and non-EVM support are post-MVP.

### Architecture Tradeoffs

| Property | ZK proof approach | Alternative (signatures + MPA only) |
|----------|------------------|--------------------------------------|
| Policy privacy | Full — verifier sees only commitment | None — policy visible to verifier |
| Correctness proof | Cryptographic (circuit constraints) | Economic (staking + slashing) |
| Proving time | Seconds to minutes (mitigated by pre-compute) | Milliseconds |
| Portability | Any system with verification key | Any system with signature check |
| Developer complexity | High — circuit expertise required | Low — standard crypto |
| Trusted parties required | No online attestor for authorization; KZG backend depends on a reusable SRS ceremony | Honest attestor majority |
| Auditability of logic | Hard — circuit bugs are subtle | Easy — policy checks are readable |
| Upgrade cost | New circuit + new verifier per change | Update policy schema |

**Why ZK despite the costs**: The privacy guarantee is load-bearing for CATP's value proposition. An agent's policy parameters reveal operational strategy. A reputation history reveals behavioral patterns. These are competitively sensitive for any operator — developer, enterprise, or protocol. Exposing them to on-chain verifiers or attestor nodes undermines the protocol's usefulness in adversarial environments. The signature approach solves correctness but not privacy — and correctness is already handled by MPA + optimistic slash.

**Where MPA + slash is used instead of ZK**: Layer 3 output verification. Model binding and output consistency cannot be proven by ZK alone (ZK proves computation was correct, not that the correct model was used). MPA provides the honest-majority guarantee here; ZK boundary proofs are a supplementary privacy layer, not the primary mechanism.

### Known Gaps in Current Implementation

The following are documented gaps between the current codebase and the target architecture:

1. **Compact EVM authorization verifier** — the current Halo2 EVM path is blocked, and the replacement path is `authorization_groth16_v1`. `Halo2Verifier.sol` (k=12, KZG/BN254, GWC + EvmTranscript) can be generated and matches the off-chain proof system, but the corrected runtime is about 319 KB and cannot be deployed under the EVM 24,576-byte contract size limit. A prior Sepolia deployment compiled to a 67-byte always-reverting runtime and is invalid. `authorization_groth16_v1` keeps the 13-public-input authorization shape, uses a new MiMC commitment version, compiles to about 6.4 KB of verifier runtime plus about 1.1 KB of wrapper runtime, and passed Sepolia `AgentAuthorizer` execution with a real proof.
2. **Policy state in contracts** — `activePolicies` and `cumulativeSpend` mappings should remain in-contract until proof-centric state has a canonical root, nonce, nullifier, or checkpoint mechanism. 🔜 Planned.
3. **EVM address types throughout SDK** — `0x${string}` assumes 20-byte Ethereum addresses. Future: abstract to `PrincipalId` bytes. 🔜 Planned.
4. **Layer 5 registry assumes on-chain storage** — registry entries use EVM addresses and contract mappings. Future: content-addressed off-chain store with on-chain commitments. 🔜 Planned.
5. **Proof system lifecycle** — Halo2/KZG remains useful for the local and off-chain `authorization_v1` path because it has mature Rust tooling, but the current generated Halo2 verifier is not an EVM backend for this circuit. The active EVM backend is the separate `authorization_groth16_v1` Groth16/BN254 verifier. PSE Halo2 is in maintenance mode, KZG requires a reusable SRS, Groth16 requires circuit-specific setup, and each statement change still requires a new circuit/verifier. Keep every proof statement versioned (`authorization_v1`, `authorization_groth16_v1`, `boundary_v1`, `reputation_v1`) and revisit Nova/HyperNova or another folding/recursive backend for incremental audit logs when tooling matures. 🔭 Future consideration.

---

## Protocol Architecture Overview

```
┌─────────────────────────────────────────────────┐
│         Layer 5: Agent Registry & Discovery      │
│   Capability proofs, trust scores, matchmaking   │
├─────────────────────────────────────────────────┤
│         Layer 4: Reputation Protocol             │
│   ZK-proven track records, privacy-preserving    │
├─────────────────────────────────────────────────┤
│         Layer 3: Output Verification             │
│   Input integrity, model binding, boundary proof │
├─────────────────────────────────────────────────┤
│         Layer 2: Authorization Policy Engine     │
│   Delegated permissions, ZK scope proofs         │
├─────────────────────────────────────────────────┤
│         Layer 1: Encrypted Communication         │
│   E2E agent messaging, selective disclosure      │
├ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤
│         Layer 0: Identity (external)             │
│   DID, wallet binding — Kite AI, Lit, NEAR etc.  │
└─────────────────────────────────────────────────┘
```

The enforcement layer plugin sits above all protocol layers as the developer-facing entry point. It is the product surface that agents and developers interact with directly. The protocol layers provide the cryptographic backing that makes the enforcement layer trustworthy to third parties.

---

## Shared Cryptographic Primitives

These primitives are reused across multiple layers. Defining them once ensures consistency.

### P1: Commitment Scheme
- **What**: Poseidon hash (ZK-friendly commitment scheme)
- **Used by**: Layer 1 (message commitments), Layer 2 (policy commitments), Layer 3 (input/output commitments), Layer 4 (performance commitments)
- **Why Poseidon**: ~8x cheaper than SHA-256 inside ZK circuits; already standard in Ethereum ZK ecosystem

### P2: ZK Proof System
- **Current implemented backend**: Halo2/KZG on BN254 (PSE fork) for local and off-chain verification
- **EVM backend status**: compact Groth16/BN254 path passed Sepolia smoke as `authorization_groth16_v1`. Direct verification of the current Halo2-generated Solidity verifier remains blocked by runtime bytecode size.
- **Rationale**:
  - Local/off-chain Halo2 verification works today; direct EVM verification uses the compact Groth16 backend
  - Plonkish constraint system — lookup tables make membership proofs natural, custom gates enable flexible policy constraints
  - Reusable setup — one KZG SRS can support many circuits up to its size bound, but production security depends on the ceremony and SRS provenance
  - Rust-native — first-class Rust support
- **Used by**: Layer 2 (authorization proofs) in the MVP; Layer 3 boundary proofs, Layer 4 reputation proofs, and Layer 5 capability proofs should be added as separately versioned circuits rather than assuming one proof statement covers all layers.
- **Language**: Rust. Circuit implementations in `catp-circuits/`. Proof statements should be exposed behind a small proof-system abstraction so the backend can migrate without rewriting authorization logic.
- **Key libraries**: halo2_proofs, halo2_gadgets (Poseidon, range check, etc.)
- **Backend**: KZG/BN254 (GWC opening, EvmTranscript) for the current off-chain proof path. Uses PSE halo2 (git-pinned, `v0.3.0` tag) with `snark-verifier` for the EVM transcript artifact. PSE Halo2 is a maintenance-mode dependency, so CATP should pin versions, keep verifier generation reproducible, and maintain a migration path to another Halo2 fork or proof system.
- **Verification paths**: (a) off-chain via `catp-verify` REST endpoint using Rust `VerifierGWC`; (b) direct EVM verification through `authorization_groth16_v1`. The off-chain Halo2 path uses the KZG SRS (`catp-layer2-k12.srs`); the Groth16 path uses its own proving/verifying keys and verifier contract.
- **Versioning rule**: Any change to public inputs, policy encoding, hash layout, circuit constraints, SRS size, transcript, or proving backend creates a new proof version and verifier address. Old verifiers remain valid for historical proofs.

### P3: Multi-Party Attestation (MPA)
- **What**: N independent attestor nodes verify AI outputs, ≥ t-of-n agreement required
- **Used by**: Layer 3 (model binding, output consistency)
- **Role**: Replaces TEE for model binding verification. Combined with commit-and-prove and optimistic slash for three-layer defense.
- **Not used for**: Layer 2 authorization (ZK chosen instead for privacy and composability reasons)

### P4: Merkle Tree / Accumulator
- **What**: Sparse Merkle Tree for state commitments
- **Used by**: Layer 2 (policy tree), Layer 4 (reputation state), Layer 5 (registry state)

### P5: Encryption
- **What**: X25519 for key exchange, AES-256-GCM for symmetric encryption, ECIES for hybrid encryption
- **Used by**: Layer 1 (primary), Layer 2 (encrypted policy storage)

---

## Layer 1: Encrypted Agent Communication

### Problem
AI agents communicating via MCP, A2A, or custom protocols transmit data in plaintext. When agents handle sensitive information — source code, credentials, customer data, internal tooling, proprietary instructions — this is unacceptable. Encryption also becomes critical for any multi-agent workflow where one agent coordinates another.

### Design

**Core Protocol: Agent Messaging Protocol (AMP)**

```
Agent A                                           Agent B
   │                                                 │
   │─── 1. Key Exchange (X25519 + Agent DID) ──────→│
   │←── 2. Session Established (shared secret) ─────│
   │                                                 │
   │─── 3. Encrypted Message (AES-256-GCM) ────────→│
   │    ├─ Header: {sender_did, receiver_did,        │
   │    │          session_id, sequence_num}          │
   │    ├─ Payload: encrypted(actual_message)        │
   │    └─ Commitment: Poseidon(plaintext)           │
   │                                                 │
   │←── 4. Encrypted Response ──────────────────────│
```

**Key Features**:

1. **DID-Bound Key Exchange**: Each agent's communication keys are bound to its Layer 0 identity (DID). Key exchange includes a proof that "I control the DID I claim to be." This prevents impersonation.

2. **Message Commitments**: Every message includes a Poseidon commitment to the plaintext. This enables Layer 3 (verification) and Layer 4 (reputation) to reference message content without decryption.

3. **Selective Disclosure**: Agent can reveal specific fields of a message to a third party while keeping the rest encrypted. Each message field gets its own commitment; revealing field X means opening commitment X while keeping others sealed.

4. **Forward Secrecy**: Session keys are ephemeral. Compromise of a long-term key doesn't expose past sessions. Standard Double Ratchet approach adapted for async agent communication.

5. **Multi-Party Channels**: For scenarios where 3+ agents collaborate, extend to group key agreement (based on TreeKEM or similar).

**Data Structures**:

```
AgentSession {
  session_id: bytes32
  agent_a_did: DID
  agent_b_did: DID
  shared_secret: bytes32 (ephemeral)
  ratchet_state: RatchetState
  created_at: timestamp
  expires_at: timestamp
}

EncryptedMessage {
  header: MessageHeader (plaintext)
  ciphertext: bytes (AES-256-GCM encrypted payload)
  field_commitments: Poseidon[] (one per payload field)
  nonce: bytes12
  sequence: uint64
}
```

---

## Layer 2: Authorization Policy Engine

### Problem
When an AI agent operates on behalf of a user or organization, the current options are: (a) grant the agent full access (catastrophically insecure), or (b) approve every action manually (defeats the purpose of autonomous agents). There is no middle ground — no way to say "here is exactly what you are allowed to do, provably, with a time limit and hard constraints."

This applies to any high-stakes agent context: a developer agent with production access, a customer support agent with CRM write permissions, an orchestrator agent delegating to subagents, or an on-chain agent managing assets.

### Design

**Core Concept: ZK-Proven Delegated Authorization**

A principal defines a policy: "Agent X can do Y within constraints Z for duration T." The agent executes actions and generates a ZK proof that each action falls within the authorized scope — without revealing the full policy to the verifier.

**Policy Structure** (on-chain / high-stakes variant):

The enforcement layer uses a tool-based policy schema (see `catp-policy.toml` in Day 1 experience). The on-chain Layer 2 contract uses a value-aware policy schema suited for any context where actions have measurable scope — token transfers, API call budgets, resource consumption limits, etc.

```
AuthorizationPolicy {
  // Who (principal = human or agent)
  principal_id: DID                 // agent DID or human wallet/DID
  principal_type: enum              // AGENT | HUMAN | CONTRACT | MULTISIG
  delegator: address                // who grants the authorization

  // What (context-specific — examples below)
  allowed_actions: Action[]         // e.g., [WRITE_FILE, CALL_API, EXECUTE_TX]
  allowed_targets: bytes32[]        // e.g., allowed contract addresses, API endpoints, file paths
  allowed_resources: bytes32[]      // e.g., token addresses, service identifiers

  // Constraints
  max_value_per_op: uint256         // e.g., max spend or resource per single action
  max_value_total: uint256          // e.g., cumulative budget
  max_frequency: uint256            // e.g., max actions per time window

  // When
  valid_from: timestamp
  valid_until: timestamp

  // Meta
  policy_hash: bytes32              // Poseidon hash of full policy
  nonce: uint256                    // prevents replay
}
```

**ZK Circuit: ProveAuthorization**

```
Public inputs:
  - policy_commitment (Poseidon hash of the full policy)
  - current_timestamp
  - cumulative_spend (from on-chain state)

Private inputs:
  - full AuthorizationPolicy
  - proposed Action details

Constraints:
  1. Poseidon(full_policy) == policy_commitment
  2. action.type == policy.allowed_action
  3. action.protocol == policy.allowed_protocol (all 32 bytes)
  4. action.token == policy.allowed_token (all 32 bytes)
  5. action.value ≤ policy.max_value_per_op
  6. cumulative_spend + action.value ≤ policy.max_value_total
  7. current_timestamp ≥ policy.valid_from
  8. current_timestamp ≤ policy.valid_until

The inequality witnesses are range-checked as `u64` values so the equalities cannot be satisfied by field-wrapped negative differences.

Output: proof π (Halo2)
```

**On-Chain Verifier**:

`AgentAuthorizer` depends on `IVerifier` — a single-function interface that decouples proof verification from authorization logic.

```solidity
interface IVerifier {
    function verify(
        bytes32[] calldata publicInputs,
        bytes calldata proof
    ) external view returns (bool);
}

contract AgentAuthorizer {
    IVerifier public immutable verifier;
    uint256 public constant PROOF_MAX_AGE = 5 minutes;

    mapping(bytes32 => bool)    public activePolicies;
    mapping(bytes32 => uint256) public cumulativeSpend;

    constructor(address verifier_) { verifier = IVerifier(verifier_); }

    function registerPolicy(bytes32 policyCommitment) external { ... }

    function executeAuthorized(
        bytes32 policyCommitment,
        bytes calldata actionData,
        uint256 currentTimestamp,
        bytes calldata proof
    ) external {
        require(activePolicies[policyCommitment], "Policy not active");
        uint256 value = _extractValue(actionData);
        require(value > 0, "Zero-value actions are not replay-safe");
        require(currentTimestamp <= block.timestamp, "Proof from the future");
        require(block.timestamp <= currentTimestamp + PROOF_MAX_AGE, "Proof is stale");
        bytes32[] memory pub = _buildPublicInputs(policyCommitment, actionData, currentTimestamp);
        require(verifier.verify(pub, proof), "Invalid proof");
        cumulativeSpend[policyCommitment] += value;
    }
}
```

Zero-value actions are rejected in the current on-chain adapter because cumulative spend is the replay-binding public input. A future proof-centric design can replace that with an explicit nonce or nullifier if zero-value actions need to be repeatable without replay risk.

**Verifier progression**: Phase 0 — enforcement plugin (local, no proof). Phase 1 — `catp-verify` REST endpoint for off-chain Halo2 verification. Phase 2 — direct Halo2 EVM verification attempted and rejected because the real verifier runtime exceeds the EVM contract-size limit. Phase 2 replacement — `authorization_groth16_v1` compact Groth16/BN254 verifier passed local and Sepolia EVM smoke.

---

## Layer 3: Output Verification

### Problem
Even if an agent is authorized (Layer 2), how do you know its output is correct? An agent might be authorized to take an action but produce an output derived from a tampered model, manipulated input data, or incorrect computation. This matters any time a downstream system — human, on-chain contract, or another agent — acts on the agent's output.

Examples: a code review agent whose suggestions are subtly backdoored, a risk assessment agent whose outputs are manipulated, an orchestrator agent whose routing decisions are compromised.

### Design

**Three-Layer Defense for Model Binding (No TEE)**

**Defense Layer 1: Commit-and-Prove (Cryptographic)**

```
Registration (one-time):
  model_commitment = Poseidon(model_weights_hash, version_nonce)
  → registered on-chain, bound to operator identity

Per-inference:
  pre_commit = Poseidon(input_hash, model_commitment, timestamp, nonce)
  → submitted on-chain BEFORE inference
  post_commit = Poseidon(output, pre_commit)
  → submitted on-chain AFTER inference
```

Guarantees: input-output binding, timeline correctness, model version consistency. Does not prove operator "actually ran the registered model" — addressed by Defense Layers 2 and 3.

**Defense Layer 2: Multi-Party Attestation (MPA)**

Same inference request sent to N independent attestor nodes. ≥ 2/3 must agree on `output_commitment`. Attestors must stake collateral before submitting; incorrect consensus attestations can be slashed once per finalized round/commitment. Security model: honest majority (same as blockchain consensus).

**Defense Layer 3: Optimistic + Economic Stake**

Challenge window after each finalized inference round (currently 1 hour). Anyone can open a challenge with a non-consensus claimed commitment; an authorized resolver supplies the trusted re-execution result. If the result matches the challenge and differs from MPA consensus, the attestors behind the bad consensus are slashed and the challenger receives a reward. Rejected or expired challenges do not permanently block later challenges for the same round.

**Combined security**: breaking all three requires forging a hash + controlling ≥ 2/3 attestors + accepting economic slash loss simultaneously. No hardware trust required.

**ZK Circuit: ProveBoundary**

```
Public inputs:  output_commitment, boundary_specification
Private inputs: actual output value, salt

Constraints:
  1. Poseidon(output, salt) == output_commitment
  2. output ≥ boundary.min
  3. output ≤ boundary.max
```

Ensures the agent's output falls within protocol-defined safe ranges, without revealing the raw value. Applicable to any quantifiable output: confidence scores, resource usage, numeric recommendations, or risk ratings.

---

## Layer 4: Reputation Protocol

### Problem
Any platform or service that wants to selectively trust AI agents faces the same question: how do you distinguish a reliable, well-behaved agent from an untested or malicious one? An agent's track record — success rate, incident history, volume handled — is the natural signal, but it is sensitive operational data. Revealing it exposes the agent operator's strategy and patterns.

### Design

**Core Concept: ZK-Proven Performance Attestations**

An agent accumulates a private history of operations. It can prove statements about its history ("I have >95% success rate over >100 operations") without revealing the individual operations.

**Reputation State**:

```
AgentReputationState {
  agent_did: DID
  total_operations: uint256
  successful_operations: uint256
  total_scope_handled: uint256        // context-specific: value, tokens, API calls, etc.
  authorization_violations: uint256   // from Layer 2
  verification_failures: uint256      // from Layer 3
  active_since: timestamp
  state_commitment: Poseidon(all fields above)
}
```

**ZK Circuit: ProveReputation**

```
Public inputs:  state_commitment, claimed property (e.g., "success_rate > 95%")
Private inputs: full AgentReputationState, operation history Merkle root

Constraints:
  1. Poseidon(full_state) == state_commitment
  2. successful_operations / total_operations > threshold
  3. total_operations > min_threshold (prevents gaming with tiny sample)
  4. authorization_violations == 0
  5. verification_failures ≤ max_allowed
```

**Anti-gaming**: state is DID-bound (new identity resets reputation), total_operations is monotonic (can't forget bad history), cross-referenced with on-chain Layer 2 + Layer 3 records.

---

## Layer 5: Agent Registry & Discovery

### Problem
How does any platform, service, or user find a trustworthy AI agent for a specific task? How does an orchestrator agent discover a capable subagent to delegate to? There is no discoverable, verifiable marketplace for AI agents — no way to evaluate capability claims without either trusting the agent's self-report or running it yourself.

### Design

**Core Concept: Verifiable Agent Registry with Cryptographic Capability Proofs**

```
AgentRegistryEntry {
  agent_did: DID
  supported_actions: Action[]        // what this agent can do
  supported_environments: bytes32[]  // platforms, frameworks, chains, APIs it operates on
  capability_proof: bytes            // ZK proof of claimed capabilities
  reputation_proof: bytes            // from Layer 4
  audit_attestation: bytes           // optional: third-party security audit
  pricing_model: PricingModel
  sla_commitment: bytes32
  registered_at: timestamp
  last_active: timestamp
}
```

**Discovery**: query by capability + success rate + scope threshold → ranked by composite trust score (reputation + audit attestation + tenure). Works for human users, orchestrator agents, and platform integrations alike.

---

## Cross-Layer Data Flow Examples

### Example 1: Developer deploying Claude Code for a client

```
1. AUTHORIZE (Enforcement Layer + Layer 2)
   Developer defines policy: "Agent can read/write ./src, cannot run
   git push, cannot call external APIs"
   → catp-policy.toml loaded by hook
   → policy commitment optionally anchored on-chain

2. EXECUTE (Enforcement Layer)
   Claude Code runs normally
   → each tool call intercepted, checked against policy
   → blocked actions logged with commitment hash
   → allowed actions recorded in audit log

3. PROVE (Layer 1 + ZK)
   Developer runs `catp anchor` at end of engagement
   → commitment batch submitted on-chain
   → client receives a shareable proof URL

4. VERIFY (anyone)
   Client opens proof URL
   → sees: 0 policy violations, commitment chain intact
   → verified on-chain, policy details remain private
```

### Example 2: Orchestrator delegating to a subagent

```
1. DISCOVER (Layer 5)
   Orchestrator queries registry: "data-analysis agent, >98% success,
   handles CSV + SQL"
   → returns Agent X with verified capability + reputation proofs

2. AUTHORIZE (Layer 2)
   Orchestrator delegates to Agent X: "can read these datasets,
   can query this DB, max 1000 rows per query, valid 1 hour"
   → policy commitment registered on-chain

3. COMMUNICATE (Layer 1)
   Orchestrator + Agent X establish encrypted session
   → task instructions transmitted via encrypted channel

4. EXECUTE + VERIFY (Layer 2 + 3)
   Agent X runs analysis
   → Layer 2: ZK proof that queries stayed within authorized scope
   → Layer 3: commit-and-prove + MPA attestors verify output integrity
   → challenge window opens

5. UPDATE REPUTATION (Layer 4)
   → Agent X updates private reputation state, new commitment on-chain

6. REGISTRY REFRESH (Layer 5)
   → Agent X's trust score increases
```

---

## Implementation Phases

See [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for the full phased roadmap.

---

## Technical Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| Enforcement plugin adoption — developers don't install it | High | Optimize for zero-friction installation; Claude Code hooks are native and well-documented |
| ZK proof generation too slow for real-time operations | High | Pre-compute proofs for common patterns; batch proofs; benchmark early |
| MPA attestor network liveness (Layer 3) | Medium | Fallback to optimistic-only mode; minimum staked set |
| MPA attestor collusion (Layer 3) | Medium | Three-layer defense makes simultaneous compromise infeasible |
| ZK circuit soundness bugs | High | Comprehensive constraint tests; formal review before deploy |
| Gas costs for on-chain verification | Medium | ~200-400K gas per verification; target L2 deployment (Arbitrum/Base); batch |
| Adoption chicken-and-egg | High | Phase 0 enforcement plugin ships standalone with no protocol dependency |
| MPA attestor economics not sustainable | Medium | Start permissioned (low cost); token incentive model for decentralized phase |
