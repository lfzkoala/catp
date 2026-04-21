# Cryptographic Agent Trust Protocol (CATP)

## Vision

A modular, cryptography-native protocol stack that enables trustworthy autonomous operations — for both AI agents and human actors, on any chain or web2 environment. Each layer is independently deployable, collectively composable.

The protocol treats AI agents and humans as two types of the same abstraction: **principals**. A principal is any entity (human wallet, AI agent, smart contract, DAO multisig) that can be authorized, verified, and reputation-scored. This design ensures CATP is not limited to the AI agent market — it serves any scenario where one entity delegates authority to another with cryptographic trust.

**CATP is a ZK proof protocol, not an Ethereum protocol.** The ZK proof is the universal trust primitive. Any system that can verify a Halo2 proof can participate in CATP — whether it is an EVM chain, a non-EVM blockchain, or a web2 service. The Ethereum implementation is the reference deployment, not the protocol boundary.

Identity layer (Layer 0) is ceded to existing players (Kite AI, Lit Protocol, etc. for agents; ENS, Polygon ID, etc. for humans). CATP owns everything above identity: authorization, verification, reputation, discovery, and communication.

---

## Protocol Portability

### The Core Principle

The ZK proof is self-contained. It encodes all claims about policy compliance, output correctness, and reputation — and can be verified by any system that has the verification key. The chain or environment is just where state is anchored and proofs are submitted. It is an adapter, not the protocol.

```
┌─────────────────────────────────────────────┐
│           CATP Protocol Core                │
│                                             │
│  ZK circuits (Rust/Halo2)                  │
│  Proof format (universal)                   │
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
- **EVM**: auto-generated Halo2 Solidity verifier contract implementing `IVerifier`
- **Web2**: Rust `halo2_proofs::verify_proof` called from any server
- **Non-EVM chains**: native verifier library — same circuit, same verification key, different host

The Solidity `AgentAuthorizer` accepts an `IVerifier` at construction time. Swapping the verifier (e.g., upgrading from stub to real Halo2 verifier, or replacing with a different proof system) requires no changes to policy or authorization logic.

### Proof-Centric State Design

A key architectural principle: **push state into proofs, not contracts.**

| Concern | Naive (state-in-contract) | Proof-centric (target) |
|---------|--------------------------|------------------------|
| Policy validity | `mapping(bytes32 => bool) activePolicies` | Delegator signature in proof public inputs |
| Spend tracking | `mapping(bytes32 => uint256) cumulativeSpend` | Cumulative spend as proof public input, monotonicity enforced in circuit |
| Reputation | On-chain counters | State commitment in proof, updated off-chain |

The current Phase 1 implementation uses the naive approach for simplicity. The target architecture moves toward proof-centric state, reducing contract surface area to a thin event log + verifier call. A contract with no application state is trivial to port to any chain.

### Deployment Environments

| Environment | Verifier | State anchor | Policy identifier |
|-------------|----------|--------------|------------------|
| Ethereum / EVM L2 | `IVerifier` Solidity contract | Smart contract storage | `bytes32` commitment |
| Web2 server | Rust `verify_proof` fn | Database row | UUID or hash |
| Cosmos / CosmWasm | Native Rust verifier | CosmWasm contract | Bytes32 |
| Solana | Native Rust verifier | Account data | Pubkey-derived |
| Offline / air-gapped | Rust binary | File / HSM | Hash |

The ZK circuit, proof format, and verification key are identical across all rows.

### Architecture Tradeoffs

| Property | ZK proof approach | Alternative (signatures + MPA only) |
|----------|------------------|--------------------------------------|
| Policy privacy | Full — verifier sees only commitment | None — policy visible to verifier |
| Correctness proof | Cryptographic (circuit constraints) | Economic (staking + slashing) |
| Proving time | Seconds to minutes (mitigated by pre-compute) | Milliseconds |
| Portability | Any system with verification key | Any system with signature check |
| Developer complexity | High — circuit expertise required | Low — standard crypto |
| Trusted parties required | None (trustless) | Honest attestor majority |
| Auditability of logic | Hard — circuit bugs are subtle | Easy — policy checks are readable |
| Upgrade cost | New circuit + new verifier per change | Update policy schema |

**Why ZK despite the costs**: The privacy guarantee is load-bearing for CATP's value proposition. An agent's policy parameters (which tokens, which protocols, what limits) reveal trading strategy. A reputation history reveals operational patterns. These are competitively sensitive. Exposing them to on-chain verifiers or attestor nodes undermines the protocol's usefulness in adversarial markets. The signature approach solves correctness but not privacy — and correctness is already handled by MPA + optimistic slash.

**Where MPA + slash is used instead of ZK**: Layer 3 output verification. Model binding and output consistency cannot be proven by ZK alone (ZK proves computation was correct, not that the correct model was used). MPA provides the honest-majority guarantee here; ZK boundary proofs are a supplementary privacy layer, not the primary mechanism.

### Known Gaps in Current Implementation

The following are documented gaps between the current codebase and the target architecture:

1. **`IVerifier` interface** — `AgentAuthorizer` previously used an inline stub. Now accepts `IVerifier` at construction. ✅ Fixed.
2. **Policy state in contracts** — `activePolicies` and `cumulativeSpend` mappings should migrate to proof public inputs over time. 🔜 Planned.
3. **EVM address types throughout SDK** — `0x${string}` assumes 20-byte Ethereum addresses. Future: abstract to `PrincipalId` bytes. 🔜 Planned.
4. **Layer 5 registry assumes on-chain storage** — registry entries use EVM addresses and contract mappings. Future: content-addressed off-chain store with on-chain commitments. 🔜 Planned.
5. **No web2 verification path** — Rust verifier fn not yet exposed as library. Future: `catp-verify` crate with `no_std` support. 🔜 Planned.

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

---

## Shared Cryptographic Primitives

These primitives are reused across multiple layers. Defining them once ensures consistency.

### P1: Commitment Scheme
- **What**: Pedersen commitment or hash-based commitment (Poseidon hash for ZK-friendliness)
- **Used by**: Layer 1 (message commitments), Layer 2 (policy commitments), Layer 3 (input/output commitments), Layer 4 (performance commitments)
- **Why Poseidon**: ~8x cheaper than SHA-256 inside ZK circuits; already standard in Ethereum ZK ecosystem

### P2: ZK Proof System
- **Choice**: Halo2 (PSE/Zcash fork)
- **Rationale**:
  - No trusted setup — aligns with CATP's "trustless from the ground up" philosophy
  - Plonkish constraint system — lookup tables make membership proofs natural, custom gates enable flexible policy constraints
  - Future-proof — new policy constraint types can be added without re-running a ceremony
  - Rust-native — first-class Rust support
- **Used by**: Layer 2 (authorization proofs), Layer 3 (boundary proofs), Layer 4 (reputation proofs), Layer 5 (capability proofs)
- **Language**: Rust. Circuit implementations in `catp-circuits/halo2_impl/`. Proof system abstracted behind `ProofSystem` trait to allow future migration if needed.
- **Key libraries**: halo2_proofs, halo2_gadgets (Poseidon, range check, etc.)
- **MPC + threshold signing evaluated and rejected** for Layer 2: privacy loss (signer nodes see policy), liveness dependency, weaker composability with upper layers.

### P3: Multi-Party Attestation (MPA)
- **What**: N independent attestor nodes verify AI outputs, ≥ t-of-n agreement required
- **Used by**: Layer 3 (model binding, output consistency)
- **Role**: Replaces TEE for model binding verification. Combined with commit-and-prove and optimistic slash for three-layer defense.
- **Not used for**: Layer 2 authorization (ZK chosen instead for privacy and composability reasons)

### P4: Merkle Tree / Accumulator
- **What**: Sparse Merkle Tree for state commitments; RSA accumulator as alternative for membership proofs
- **Used by**: Layer 2 (policy tree), Layer 4 (reputation state), Layer 5 (registry state)

### P5: Encryption
- **What**: X25519 for key exchange, AES-256-GCM for symmetric encryption, ECIES for hybrid encryption
- **Used by**: Layer 1 (primary), Layer 2 (encrypted policy storage)

---

## Layer 1: Encrypted Agent Communication

### Problem
AI agents communicating via MCP, A2A, or custom protocols transmit data in plaintext. When agents handle sensitive information (trading strategies, personal financial data, private keys), this is unacceptable.

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

2. **Message Commitments**: Every message includes a Poseidon commitment to the plaintext. This enables Layer 3 (verification) and Layer 4 (reputation) to reference message content without decryption — an agent can later prove "I sent a message with property X" using the commitment, without revealing the full message.

3. **Selective Disclosure**: Agent can reveal specific fields of a message to a third party (e.g., an on-chain contract or auditor) while keeping the rest encrypted. Implementation: each message field gets its own commitment; revealing field X means opening commitment X while keeping others sealed.

4. **Forward Secrecy**: Session keys are ephemeral. Compromise of a long-term key doesn't expose past sessions. Standard Double Ratchet approach adapted for async agent communication.

5. **Multi-Party Channels**: For scenarios where 3+ agents collaborate (e.g., a portfolio agent coordinating with multiple DeFi agents), extend to group key agreement (based on TreeKEM or similar).

**Integration Points**:
- Compatible with MCP transport layer (wraps existing MCP messages in encrypted envelope)
- Compatible with A2A protocol (can serve as the secure transport for A2A communication)
- Layer 2 uses encrypted channels to transmit authorization policies
- Layer 3 uses message commitments to link input data to verification
- Layer 4 uses message commitments as inputs to reputation calculations

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
When an AI agent operates on behalf of a user, the current options are: (a) give the agent the private key (catastrophically insecure), or (b) approve every transaction manually (defeats the purpose of autonomous agents). There's no middle ground.

### Design

**Core Concept: ZK-Proven Delegated Authorization**

A user defines a policy: "Agent X can do Y within constraints Z for duration T." The agent executes actions and generates a ZK proof that each action falls within the authorized scope — without revealing the full policy to the on-chain verifier.

**Policy Structure**:

```
AuthorizationPolicy {
  // Who (principal = human or agent)
  principal_id: DID                 // agent DID or human wallet/DID
  principal_type: enum              // AGENT | HUMAN | CONTRACT | MULTISIG
  delegator: address                // who grants the authorization
  
  // What
  allowed_actions: Action[]         // e.g., [SWAP, TRANSFER]
  allowed_protocols: address[]      // e.g., [Uniswap, Aave]
  allowed_tokens: address[]         // e.g., [USDC, ETH]
  
  // Constraints
  max_value_per_tx: uint256         // e.g., 1000 USDC
  max_value_total: uint256          // e.g., 10000 USDC cumulative
  max_frequency: uint256            // e.g., 10 tx per day
  
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
  - action_hash (hash of the proposed action)
  - current_timestamp
  - cumulative_spend (from on-chain state)

Private inputs:
  - full AuthorizationPolicy
  - proposed Action details

Constraints:
  1. Poseidon(full_policy) == policy_commitment
  2. action.type ∈ policy.allowed_actions
  3. action.protocol ∈ policy.allowed_protocols
  4. action.token ∈ policy.allowed_tokens
  5. action.value ≤ policy.max_value_per_tx
  6. cumulative_spend + action.value ≤ policy.max_value_total
  7. current_timestamp ≥ policy.valid_from
  8. current_timestamp ≤ policy.valid_until

Output: proof π (Halo2)
```

**On-Chain Verifier**:

`AgentAuthorizer` depends on `IVerifier` — a single-function interface that decouples proof verification from authorization logic. The verifier implementation (stub, real Halo2, or future proof system) is injected at deploy time.

```solidity
// Universal verifier interface — same shape on any chain
interface IVerifier {
    function verify(
        bytes32[] calldata publicInputs,
        bytes calldata proof
    ) external view returns (bool);
}

contract AgentAuthorizer {
    IVerifier public immutable verifier;  // injected — swap without redeploying logic

    mapping(bytes32 => bool)    public activePolicies;
    mapping(bytes32 => uint256) public cumulativeSpend;

    constructor(address verifier_) { verifier = IVerifier(verifier_); }

    function registerPolicy(bytes32 policyCommitment) external { ... }

    function executeAuthorized(
        bytes32 policyCommitment,
        bytes calldata actionData,
        bytes calldata proof
    ) external {
        require(activePolicies[policyCommitment], "Policy not active");
        bytes32[] memory pub = _buildPublicInputs(policyCommitment, actionData);
        require(verifier.verify(pub, proof), "Invalid proof");
        cumulativeSpend[policyCommitment] += _extractValue(actionData);
    }
}
```

**Phase 1 verifier**: stub (`proof.length > 0`). **Phase 2**: auto-generated Halo2 Solidity verifier. **Web2**: same `verify()` signature, implemented in Rust.

**Why ZK here (not just on-chain checks)**:
- Privacy: the full policy (what tokens, what protocols, what limits) is never revealed on-chain. Competitors can't see your agent's strategy parameters.
- Flexibility: policy logic lives in the circuit, not in the smart contract. New constraint types can be added by updating the circuit without redeploying contracts.
- Composability: the policy_commitment is a single bytes32 that other layers can reference.

**Integration Points**:
- Layer 0 (Identity): agent_did in the policy binds to external identity
- Layer 1 (Communication): policies transmitted via encrypted channels
- Layer 3 (Verification): after authorization is proven, output verification ensures the agent actually did what it claimed
- Layer 4 (Reputation): successful authorized executions contribute to reputation score

---

## Layer 3: Output Verification

### Problem
Even if an agent is authorized (Layer 2) and identified (Layer 0), how do you know its output is correct? If an AI risk model says "liquidate this position," how does the on-chain contract verify the model wasn't tampered with?

### Design

**Four Verification Properties**:

**3a. Input Integrity**
```
Prover generates:
  input_commitment = Poseidon(raw_input_data, salt)
  merkle_proof = proof that input_commitment is in the declared input set

On-chain verifier checks:
  - input_commitment matches the commitment registered before inference
  - merkle_proof is valid against the declared input root
```
This ensures the AI actually processed the data it claims to have processed.

**3b. Model Binding (No TEE — Three-Layer Defense)**

Goal: prove that the output came from a specific, known model version, without relying on hardware trust.

**Defense Layer 1: Commit-and-Prove Scheme (Cryptographic)**

```
Registration (one-time):
  1. Model operator publishes model_commitment = Poseidon(model_weights_hash, version_nonce)
  2. model_commitment registered on-chain, bound to operator identity
  3. Optional: operator stakes collateral (for Defense Layer 3)

Per-inference:
  1. Operator receives inference request
  2. Pre-inference: generate pre_commit = Poseidon(input_hash, model_commitment, timestamp, nonce)
  3. Submit pre_commit on-chain (or DA layer) — timestamps the binding BEFORE inference
  4. Execute inference → produce output
  5. Post-inference: generate post_commit = Poseidon(output, pre_commit)
  6. Submit (output_commitment, post_commit) on-chain

Verification logic:
  - pre_commit on-chain before inference → operator cannot fabricate input after seeing output
  - post_commit includes pre_commit → output is bound to input
  - model_commitment locked at registration → cannot silently swap models
  - Timestamp constraint → prevents pre-computation attacks
```

Guarantees: input-output binding (tamper-proof), timeline correctness (no pre-computation), model version declaration consistency.

Limitation: cannot prove operator "actually ran the registered model" — this is addressed by Defense Layers 2 and 3.

**Defense Layer 2: Multi-Party Attestation (MPA)**

```
Design:
  - Same inference request sent to N independent attestor nodes (minimum 3)
  - Each attestor independently runs the model, generates their own output_commitment
  - On-chain contract checks: ≥ 2/3 attestor output_commitments match → pass

Security assumption:
  - Honest majority (>2/3 of N attestors are honest)
  - Same trust model as blockchain consensus — fully accepted by crypto community

Attestor economics:
  - Running an attestor node is a paid role (similar to Chainlink oracle nodes)
  - Attestors must stake collateral; incorrect attestation → slashed
  - Long-term: can evolve into decentralized attestor network
  - Short-term: permissioned attestor set (operator + trusted parties)

Synergy with Layer 2 (Authorization):
  - MPA attestor network can be shared across Layer 3 functions
  - Attestors verify both model binding AND output consistency simultaneously
```

**Defense Layer 3: Optimistic + Economic Stake**

```
Design:
  - Model operator stakes collateral at registration (e.g., $10K-$100K)
  - Each inference result has a configurable challenge window (e.g., 1 hour)
  - Anyone can submit a challenge during the window:
    1. Challenger runs same input through same model
    2. If output differs → operator's stake is slashed, portion rewards challenger
    3. If output matches → challenger pays gas costs
  - After window closes with no challenge → result is finalized

Economic security:
  - Expected loss from cheating (slash) > expected gain → rational operator won't cheat
  - Same security model as Optimistic Rollups — market-validated
```

**Combined Security Model**:

```
┌──────────────────────────────────────┐
│ Defense 1: Commit-and-Prove          │ ← Cryptographic: input-output binding
│   If operator swaps model...         │
├──────────────────────────────────────┤
│ Defense 2: Multi-Party Attestation   │ ← Multi-party: detects inconsistency
│   If majority of attestors collude...│
├──────────────────────────────────────┤
│ Defense 3: Optimistic + Slash        │ ← Economic: cost of cheating > gain
│   Rational actors won't cheat        │
└──────────────────────────────────────┘

To break all three simultaneously requires:
  - Forging commitments (break cryptographic hash — infeasible)
  + Controlling ≥ 2/3 attestors (break honest majority assumption)
  + Accepting economic slash loss (irrational behavior)
```

Trust assumptions (full stack): cryptographic security + honest majority + economic rationality. **No hardware trust.** Every assumption is native to crypto and already validated by existing protocols (blockchains, oracle networks, optimistic rollups).

**3c. Output Consistency (No TEE)**
```
Primary: MPA cross-verification
  - Multiple attestors independently run same input → same output = consistency proven
  - This is a natural byproduct of Defense Layer 2 (MPA) in model binding
  - No additional mechanism needed — if 3 attestors produce matching output_commitments,
    consistency is already demonstrated

Secondary: Optimistic challenge (public reproduction)
  - Anyone can request re-execution with same input during challenge window
  - Deterministic inference (fixed random seed) ensures reproducibility
  - Inconsistent result → slash operator
```

**3d. Boundary Compliance**
```
ZK Circuit: ProveBoundary

Public inputs:
  - output_commitment
  - boundary_specification (e.g., "output must be between 0.5 and 1.5")

Private inputs:
  - actual output value
  - salt

Constraints:
  1. Poseidon(output, salt) == output_commitment
  2. output ≥ boundary.min
  3. output ≤ boundary.max
  4. (optional) output change from previous ≤ max_delta

Output: proof π
```
This ensures the AI output falls within protocol-defined safe ranges.

**Combined Verification Flow (No TEE)**:

```
1. Pre-inference:
   - Register input_commitment on-chain
   - Model operator's model_commitment already on-chain (from registration)
   - Generate and submit pre_commit (binds input + model + timestamp)

2. Inference:
   - Operator executes model with deterministic seed
   - MPA attestors independently execute same inference
   - Each party computes output_commitment

3. Post-inference:
   - Operator submits (output_commitment, post_commit, boundary_proof)
   - MPA attestors submit their output_commitments
   - On-chain verifier checks:
     a. pre_commit was submitted before inference (timestamp)
     b. post_commit is consistent with pre_commit
     c. ≥ 2/3 MPA attestors agree on output_commitment
     d. ZK boundary proof passes (output within allowed range)
   - If all pass → action is executed, challenge window opens
   - If any fail → action is rejected, incident logged for Layer 4
   
4. Challenge window:
   - Anyone can challenge by re-executing inference
   - No challenge after window → result finalized
   - Successful challenge → operator slashed
```

**Integration Points**:
- Layer 2: verification happens after authorization — "agent was allowed to do X" + "agent's output for X is trustworthy"
- Layer 4: verification results (pass/fail, MPA consensus, challenge outcomes) feed into reputation
- Layer 1: input data may be transmitted via encrypted channels; input_commitment links to Layer 1 message commitments
- MPA attestor network: shared infrastructure that can serve both Layer 3 verification and future protocol needs

---

## Layer 4: Reputation Protocol

### Problem
A DeFi protocol wants to allow AI agents to interact with it, but only "good" agents. How do you define "good" in a verifiable, privacy-preserving way? An agent's track record (success rate, incident history, volume) is valuable but sensitive — revealing it exposes the agent's strategy.

### Design

**Core Concept: ZK-Proven Performance Attestations**

An agent accumulates a private history of operations. It can prove statements about its history ("I have >95% success rate over >100 transactions") without revealing the individual transactions.

**Reputation State**:

```
AgentReputationState {
  agent_did: DID
  
  // Aggregated metrics (private, stored off-chain by agent)
  total_operations: uint256
  successful_operations: uint256
  total_value_handled: uint256
  authorization_violations: uint256       // from Layer 2
  verification_failures: uint256          // from Layer 3
  active_since: timestamp
  
  // On-chain commitment
  state_commitment: Poseidon(all fields above)
  last_updated: timestamp
}
```

**ZK Circuit: ProveReputation**

```
Public inputs:
  - state_commitment (current)
  - claimed property (e.g., "success_rate > 95%")

Private inputs:
  - full AgentReputationState
  - operation history Merkle root + relevant proofs

Constraints:
  1. Poseidon(full_state) == state_commitment
  2. successful_operations / total_operations > 0.95 (for this example)
  3. total_operations > min_threshold (prevents gaming with tiny sample)
  4. authorization_violations == 0 (clean record on Layer 2)
  5. verification_failures ≤ max_allowed (tolerance for Layer 3 edge cases)

Output: proof π
```

**State Update Protocol**:

After each operation, the agent updates its private state:
```
1. Agent completes operation (Layer 2 authorized, Layer 3 verified)
2. Agent updates local ReputationState
3. Agent computes new state_commitment
4. Agent submits (old_commitment, new_commitment, update_proof) on-chain
5. On-chain contract verifies:
   - old_commitment matches stored value
   - update_proof shows the transition is valid (monotonic: can't decrease total_operations)
   - new data is consistent with Layer 2 and Layer 3 on-chain records
6. Contract updates stored commitment
```

**Anti-Gaming Measures**:
- Sybil resistance: state is bound to Layer 0 DID; creating a new identity resets reputation
- Monotonic updates: total_operations can only increase; can't "forget" bad history
- Cross-reference with on-chain records: Layer 2 authorization events and Layer 3 verification results are on-chain, reputation must be consistent with them
- Minimum sample size: reputation proofs require minimum N operations to be meaningful

**Integration Points**:
- Layer 0: reputation bound to agent identity
- Layer 2: authorization violations recorded
- Layer 3: verification pass/fail recorded
- Layer 5: reputation proofs are inputs to registry trust scores and discovery ranking

---

## Layer 5: Agent Registry & Discovery

### Problem
How does a DeFi protocol find a trustworthy AI agent for a specific task? How does a user find the right agent for portfolio management? There's no discoverable, verifiable marketplace for AI agents.

### Design

**Core Concept: Verifiable Agent Registry with Cryptographic Capability Proofs**

Agents register with verifiable claims about their capabilities, backed by cryptographic proofs from lower layers.

**Registry Entry**:

```
AgentRegistryEntry {
  // Identity (from Layer 0)
  agent_did: DID
  
  // Capabilities (self-declared + verified)
  supported_actions: Action[]           // what can this agent do
  supported_protocols: address[]        // which DeFi protocols
  supported_chains: uint256[]           // which chains
  
  // Cryptographic proofs
  capability_proof: bytes               // ZK proof that agent can perform claimed actions
  reputation_proof: bytes               // from Layer 4
  audit_attestation: bytes              // optional: third-party security audit (e.g., from Company A!)
  
  // Metadata
  pricing_model: PricingModel           // how the agent charges
  sla_commitment: bytes32               // committed service level (Poseidon hash)
  registered_at: timestamp
  last_active: timestamp
}
```

**ZK Circuit: ProveCapability**

```
Public inputs:
  - capability_commitment (what the agent claims it can do)
  - reputation_state_commitment (from Layer 4)

Private inputs:
  - full capability details
  - reputation state
  - historical evidence of capability (past successful operations of this type)

Constraints:
  1. Agent has completed ≥ N operations of the claimed type
  2. Success rate for this operation type ≥ threshold
  3. No Layer 3 verification failures for this operation type
  4. Reputation state is current (last_updated within acceptable window)

Output: proof π
```

**Discovery Protocol**:

```
Query: "Find me an agent that can execute DeFi swaps on Uniswap 
        with >98% success rate and has handled >$1M in volume"

Registry contract:
  1. Filter by supported_actions contains SWAP
  2. Filter by supported_protocols contains Uniswap
  3. For each candidate, verify reputation_proof against query criteria
  4. Rank by trust_score (composite of reputation + audit attestation + tenure)
  5. Return ranked list
```

**Company A Synergy**:
- Fertile Fields Labs (Company A) can offer "Agent Security Audits" as a premium service
- Agents audited by FFL get an `audit_attestation` in their registry entry
- This creates a direct revenue loop: Company A earns audit fees, Company B's registry benefits from higher trust

**Integration Points**:
- All lower layers: registry is the aggregation point for the entire stack
- Layer 4 reputation proofs are the primary trust signal
- Layer 2 authorization capabilities define what actions an agent can advertise
- Layer 3 verification history validates capability claims

---

## Cross-Layer Data Flow Example

**Scenario: User wants an AI agent to manage a $10K DeFi portfolio**

```
1. DISCOVER (Layer 5)
   User queries registry: "DeFi portfolio agent, >95% success, >$500K managed"
   Registry returns Agent X with verified capability + reputation proofs

2. AUTHORIZE (Layer 2)  
   User creates policy: "Agent X can swap on Uniswap/Aave, max $2K per tx, 
   max $10K total, valid 30 days"
   Policy commitment registered on-chain

3. COMMUNICATE (Layer 1)
   Agent X and user establish encrypted session (X25519 + AES-256-GCM)
   Agent X receives portfolio preferences via encrypted channel
   
4. EXECUTE + VERIFY (Layer 2 + 3)
   Agent X decides to swap $500 USDC → ETH
   - Layer 2: generates Halo2 ZK proof that swap is within authorized scope
   - Layer 3: commit-and-prove binding + MPA attestors verify AI output
     + ZK boundary proof confirms output within safe range
   - On-chain: authorization proof verified + MPA consensus reached → swap executes
   - Challenge window opens for optimistic verification

5. UPDATE REPUTATION (Layer 4)
   Successful operation recorded
   Agent X updates private reputation state
   New state commitment submitted on-chain

6. REGISTRY REFRESH (Layer 5)
   Agent X's registry entry updated with latest reputation proof
   Trust score increases
```

---

## Implementation Phases

### Phase 1: Foundation (Month 1-6)
**Build Layer 2 (Authorization) as standalone product**
- Most immediate market need (agents operating on-chain today)
- Smallest viable scope for MVP
- Generates revenue + design partners
- Establishes the commitment scheme + ZK infrastructure reused by all layers

### Phase 2: Expand (Month 6-12)
**Add Layer 3 (Verification)**
- Natural extension: "agent was authorized" → "agent's output is correct"
- Reuses ZK circuit infrastructure from Phase 1
- Targets AI-powered DeFi risk engines (growing market)

### Phase 3: Network Effects (Month 12-18)
**Add Layer 4 (Reputation)**
- Requires enough agents using Layer 2+3 to have meaningful track records
- Activates network effects: agents want reputation → more agents join → protocols trust the system more

### Phase 4: Platform (Month 18-24)
**Add Layer 5 (Registry) + Layer 1 (Communication)**
- Registry is the aggregation layer — only valuable when lower layers have adoption
- Communication can be added in parallel whenever multi-agent scenarios emerge
- This is when CATP becomes a protocol, not just a product

---

## Technical Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| ZK proof generation too slow for real-time agent operations | High | Use efficient proving system; pre-compute proofs for common patterns; batch proofs where possible |
| MPA attestor network liveness (Layer 3) | Medium | Minimum attestor set with staking requirements; fallback to optimistic-only mode if attestors temporarily unavailable |
| MPA attestor collusion (Layer 3) | Medium | Three-layer defense: even if MPA is compromised, commit-and-prove provides cryptographic binding and optimistic slash provides economic deterrent |
| ZK circuit bugs (soundness issues) | High | Dogfood: use Company A's audit expertise to audit own circuits; formal verification where possible |
| Gas costs for on-chain verification | Medium | ZK verification ~200-400K gas; batch multiple verifications; deploy on L2 |
| Adoption chicken-and-egg (agents won't join without protocols, protocols won't integrate without agents) | High | Start with 2-3 design partner protocols; offer free integration for early adopters; build reference agent implementation |
| MPA attestor economics not sustainable | Medium | Start with permissioned attestor set (low cost); design token incentive model for decentralized phase |

---

## Naming & Positioning

**Protocol name options** (for consideration):
- **CATP** (Cryptographic Agent Trust Protocol) — technical, descriptive
- **Attestor** — focuses on the verification/attestation aspect
- **TrustMesh** — emphasizes the network of trust between agents
- **Arcane** — cryptography connotation, memorable

**Positioning**:
> "The HTTPS of AI agents — you wouldn't send a credit card over HTTP. Why would you let an AI agent manage your assets without cryptographic trust?"

**Tagline options**:
- "Cryptographic trust for autonomous agents"
- "Don't trust agents. Verify them."
- "The missing trust layer for agentic AI"