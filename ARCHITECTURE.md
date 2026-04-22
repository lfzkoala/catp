# Cryptographic Agent Trust Protocol (CATP)

## Vision

A modular, cryptography-native protocol stack that enables trustworthy autonomous operations — for both AI agents and human actors, on any chain or web2 environment. Each layer is independently deployable, collectively composable.

The protocol treats AI agents and humans as two types of the same abstraction: **principals**. A principal is any entity (human wallet, AI agent, smart contract, DAO multisig) that can be authorized, verified, and reputation-scored. This design ensures CATP is not limited to any single market — it serves any scenario where one entity delegates authority to another with cryptographic trust.

**CATP is a ZK proof protocol, not an Ethereum protocol.** The ZK proof is the universal trust primitive. Any system that can verify a Halo2 proof can participate in CATP — whether it is an EVM chain, a non-EVM blockchain, or a web2 service. The Ethereum implementation is the reference deployment, not the protocol boundary.

Identity layer (Layer 0) is ceded to existing players (Kite AI, Lit Protocol, etc. for agents; ENS, Polygon ID, etc. for humans). CATP owns everything above identity: authorization, verification, reputation, discovery, and communication.

---

## Product Strategy

### The Problem

Open-source agent frameworks (Claude Code, AutoGen, Hermes, OpenClaw, etc.) give AI agents broad permissions on local machines and remote systems — file access, shell execution, API calls, browser control — with no standard mechanism for:

1. **Authorization enforcement**: Can you constrain what an agent is allowed to do at runtime?
2. **Compliance proof**: Can the agent prove it stayed within its authorized scope — to you, your client, or a third party?
3. **Tamper-proof audit**: If something goes wrong, can the agent's behavior be verified after the fact — without trusting the agent developer?

Today these are handled by trusting the agent developer, or by blunt OS-level permission grants. Neither is sufficient as agents take higher-stakes actions.

### Product Market Fit

**Who**: AI agent developers and operators who need to constrain, audit, and prove the behavior of the agents they build or deploy.

**Pain**: There is no standard way to enforce policy on an AI agent at runtime, and no way to prove compliance to a client, platform, or regulator without exposing sensitive policy details.

**Solution**: CATP provides a two-product ladder:

1. **Enforcement Layer (first product)** — a plugin that integrates into any agent framework via its native hooks. Install it in Claude Code, LangChain, or AutoGen. Define a policy. Get real-time enforcement and cryptographic audit logs. No blockchain required to start delivering value.

2. **CATP Protocol Layer (trust upgrade)** — generates ZK proofs from audit logs and anchors policy commitments on-chain. Allows any third party to verify compliance cryptographically, without trusting the agent developer or seeing the policy details.

The enforcement layer alone solves the enforcement and audit problem. The ZK/chain layer solves the *trustless verification* problem — proving compliance to parties who cannot see your machine.

**Analogy — HTTPS:**

| HTTPS | CATP |
|-------|------|
| Browser lock icon | Enforcement plugin |
| TLS handshake + certificates | CATP protocol (ZK proof + policy commitment) |
| Certificate Authority | Blockchain (immutable policy anchor) |

Without TLS, the lock icon means nothing. Without CATP protocol, the plugin is just a local access control list — it can be bypassed or silently disabled. The ZK proof layer is what gives the enforcement layer its trustlessness.

### First Milestone

**Developers actively using the CATP enforcement plugin in their daily AI agent workflows.**

Specifically: a Claude Code user installs the CATP plugin, defines a policy (e.g., "this agent cannot run shell commands that delete files, push to production branches, or call external APIs outside this allowlist"), and the agent is visibly constrained with a tamper-evident audit trail. No blockchain configuration required.

### Go-to-Market Path

1. **Phase 0**: Enforcement plugin for Claude Code. Zero friction — TOML policy file + hook installation. Immediate value: policy enforcement + local audit log.
2. **Phase 1**: ZK proof layer wired to enforcement plugin. Audit logs become verifiable ZK proofs. On-chain anchoring optional.
3. **Phase 2+**: Full protocol (output verification, reputation, registry). Required for multi-agent ecosystems and high-stakes integrations.

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
│   (ZK proof + blockchain — async, trustless)          │
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
  → Verified trustlessly (no honest party required)
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

### Day 1 Developer Experience (Claude Code)

```
1. Install the CATP plugin:
   Add hook entries to ~/.claude/settings.json pointing at the CATP CLI

2. Define a policy (catp-policy.toml):
   [agent]
   id = "my-claude-agent"

   [[rules]]
   tool = "Bash"
   allow = false
   pattern = ["rm -rf", "git push", "curl *prod*"]
   reason = "Destructive or production-affecting commands blocked"

   [[rules]]
   tool = "Write"
   allow = true
   path_allowlist = ["./src/**", "./tests/**"]

3. Run Claude Code as normal.
   → Blocked actions are logged and rejected with a clear reason
   → All actions are recorded with Poseidon commitment hashes
   → Optional: anchor commitment log on-chain with `catp anchor`
```

No ZK proof knowledge required to start. No blockchain wallet required.

### Why Not a System Prompt?

A natural question: why not just tell the agent what it's allowed to do in the system prompt?

System prompts ask the model to comply. The CATP enforcement layer runs as a separate process and cannot be bypassed by the model at all.

```
User prompt
    ↓
AI reasoning ("I should run git push...")
    ↓
Claude Code attempts Bash tool call
    ↓
CATP hook intercepts ← policy evaluated HERE, outside the model
    ↓
BLOCKED — model receives "CATP: blocked [reason]"
    ↓
Model adjusts behavior ("I need explicit approval to push")
```

| | System prompt | CATP enforcement |
|---|---|---|
| Who evaluates the policy | The AI model | The CATP process (external) |
| Can be bypassed by prompt injection | Yes | No |
| Can be bypassed by jailbreak | Yes | No |
| Produces audit trail | No | Yes — commitment hash per action |
| Upgrades to cryptographic proof | No | Yes — Phase 1 |
| Verifiable by third parties | No | Yes — Phase 1+ |

The enforcement layer is closer to a firewall or file permission system than to a policy document. The model does receive the block reason so it can respond gracefully — but enforcement has already happened before the model can respond.

This distinction is also why the ZK proof layer is meaningful: you cannot generate a cryptographically verifiable compliance proof from a system prompt. The commitment hashes that feed the ZK proof come from the enforcement layer's action log — a record that exists independent of what the model said or thought.

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

The ZK circuit, proof format, and verification key are identical across all rows. EVM is the reference deployment for MVP. Web2 and non-EVM support are post-MVP.

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

**Why ZK despite the costs**: The privacy guarantee is load-bearing for CATP's value proposition. An agent's policy parameters reveal operational strategy. A reputation history reveals behavioral patterns. These are competitively sensitive for any operator — developer, enterprise, or protocol. Exposing them to on-chain verifiers or attestor nodes undermines the protocol's usefulness in adversarial environments. The signature approach solves correctness but not privacy — and correctness is already handled by MPA + optimistic slash.

**Where MPA + slash is used instead of ZK**: Layer 3 output verification. Model binding and output consistency cannot be proven by ZK alone (ZK proves computation was correct, not that the correct model was used). MPA provides the honest-majority guarantee here; ZK boundary proofs are a supplementary privacy layer, not the primary mechanism.

### Known Gaps in Current Implementation

The following are documented gaps between the current codebase and the target architecture:

1. **Enforcement layer plugin** — no code exists yet. This is Phase 0 and the highest-priority deliverable. 🔴 Not started.
2. **Real Halo2 on-chain verifier** — `AgentAuthorizer` uses a stub verifier (`proof.length > 0`). Must be replaced with the generated Halo2 Solidity verifier before any production use. 🔜 Planned.
3. **WASM prover bridge** — `ProofClient` in the SDK references a WASM bundle that doesn't exist yet. 🔜 Planned.
4. **Policy state in contracts** — `activePolicies` and `cumulativeSpend` mappings should migrate to proof public inputs over time. 🔜 Planned.
5. **EVM address types throughout SDK** — `0x${string}` assumes 20-byte Ethereum addresses. Future: abstract to `PrincipalId` bytes. 🔜 Planned.
6. **Layer 5 registry assumes on-chain storage** — registry entries use EVM addresses and contract mappings. Future: content-addressed off-chain store with on-chain commitments. 🔜 Planned.
7. **No web2 verification path** — Rust verifier fn not yet exposed as library. Future: `catp-verify` crate with `no_std` support. 🔜 Planned.
8. **Proof system: consider Nova/HyperNova for incremental audit logs** — Halo2 is the current choice (no trusted setup, mature tooling). Nova/HyperNova (Microsoft Research) uses a folding scheme architecturally better suited to CATP's incremental audit log model: each agent tool call is one fold, the running proof accumulates cheaply, and final proof size is small regardless of action count. The `IVerifier` interface already decouples proof verification from authorization logic, so a proof system swap requires no changes to policy or contract code. Revisit when Nova/HyperNova tooling matures. 🔭 Future consideration.

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
- **Choice**: Halo2 (PSE/Zcash fork)
- **Rationale**:
  - No trusted setup — aligns with CATP's "trustless from the ground up" philosophy
  - Plonkish constraint system — lookup tables make membership proofs natural, custom gates enable flexible policy constraints
  - Future-proof — new policy constraint types can be added without re-running a ceremony
  - Rust-native — first-class Rust support
- **Used by**: Layer 2 (authorization proofs), Layer 3 (boundary proofs), Layer 4 (reputation proofs), Layer 5 (capability proofs)
- **Language**: Rust. Circuit implementations in `catp-circuits/`. Proof system abstracted behind `ProofSystem` trait to allow future migration if needed.
- **Key libraries**: halo2_proofs, halo2_gadgets (Poseidon, range check, etc.)

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
  - action_hash (hash of the proposed action)
  - current_timestamp
  - cumulative_spend (from on-chain state)

Private inputs:
  - full AuthorizationPolicy
  - proposed Action details

Constraints:
  1. Poseidon(full_policy) == policy_commitment
  2. action.type ∈ policy.allowed_actions
  3. action.target ∈ policy.allowed_targets
  4. action.resource ∈ policy.allowed_resources
  5. action.value ≤ policy.max_value_per_op
  6. cumulative_spend + action.value ≤ policy.max_value_total
  7. current_timestamp ≥ policy.valid_from
  8. current_timestamp ≤ policy.valid_until

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

**Verifier progression**: Phase 0 — enforcement plugin (local, no proof). Phase 1 — stub (`proof.length > 0`). Phase 2 — auto-generated Halo2 Solidity verifier. Web2 (future) — same `verify()` signature, implemented in Rust.

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

Same inference request sent to N independent attestor nodes. ≥ 2/3 must agree on `output_commitment`. Attestors stake collateral; incorrect attestation → slashed. Security model: honest majority (same as blockchain consensus).

**Defense Layer 3: Optimistic + Economic Stake**

Model operator stakes collateral at registration. Challenge window after each inference (e.g., 1 hour). Anyone can challenge by re-executing — successful challenge slashes operator. Same security model as Optimistic Rollups.

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

### Phase 0: Enforcement Plugin (current priority)
Build the Claude Code enforcement plugin. Zero ZK, zero blockchain. Developers install it, define a policy file, and get real-time agent action enforcement + local audit logs. This is the deliverable that drives the first adoption milestone.

### Phase 1: ZK Protocol Layer
Wire real Halo2 proofs to the enforcement layer. Audit logs become verifiable ZK proofs. On-chain anchoring via `AgentAuthorizer` on EVM testnet.

### Phase 2: Output Verification
Add Layer 3 (commit-and-prove + MPA + optimistic slash). Targets any scenario where the correctness of agent outputs matters, not just their authorization.

### Phase 3: Reputation
Add Layer 4. Activates network effects once enough agents have meaningful track records.

### Phase 4: Full Platform
Add Layer 5 (Registry) and Layer 1 (Communication). CATP becomes a protocol, not just a product.

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

---

## Naming & Positioning

**Protocol name**: CATP (Cryptographic Agent Trust Protocol)

**Positioning**:
> "The HTTPS of AI agents — you wouldn't send a credit card over HTTP. Why would you let an AI agent operate with unconstrained access and no audit trail?"

**Taglines**:
- "Cryptographic trust for autonomous agents"
- "Don't trust agents. Verify them."
- "The missing trust layer for agentic AI"
