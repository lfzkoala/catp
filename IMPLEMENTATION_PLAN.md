# CATP Implementation Plan

## Product Goal

AI agents (Claude Code, AutoGen, Hermes, OpenClaw, etc.) today operate with broad permissions and no standard mechanism for proving they acted within authorized scope. CATP solves this with a two-product ladder:

**Phase 0 — Enforcement Layer**: a plugin/hook that intercepts agent actions in real time, checks them against a user-defined policy, and blocks unauthorized actions. Fast and synchronous. No ZK, no blockchain. Delivers immediate value: policy enforcement + tamper-evident local audit log.

**Phase 1+ — CATP Protocol Layer**: generates ZK proofs from audit logs and anchors policy commitments on-chain. Upgrades the enforcement plugin from "local policy file" to "cryptographically verifiable compliance" — provable to any third party without trusting the agent developer.

The enforcement plugin is the entry point. The ZK/chain layer is what gives it trustlessness. Neither is useful without the other long-term, but Phase 0 ships standalone value that drives the first adoption milestone.

## First Milestone

**Developers actively using the CATP enforcement plugin in their daily AI agent workflows.**

---

## Monorepo Structure

```
catp/
├── catp-plugin/            # TypeScript — enforcement layer CLI + hooks
│   ├── src/                # policy loader, action interceptor, audit logger
│   └── integrations/       # Claude Code, LangChain, AutoGen adapters
├── catp-circuits/          # Rust — Halo2 ZK circuits
│   ├── primitives/         # Poseidon hash, SMT, X25519/AES, ProofSystem trait
│   ├── layer2/             # ProveAuthorization circuit
│   ├── layer3/             # ProveBoundary circuit
│   ├── layer4/             # ProveReputation circuit
│   └── layer5/             # ProveCapability circuit
├── catp-contracts/         # Solidity — on-chain verifiers + state
│   ├── src/layer2/         # AgentAuthorizer, ActionData, IAgentAuthorizer, IVerifier
│   └── src/layer3/         # CommitRegistry, MPAVerifier, OptimisticChallenge
├── catp-sdk/               # TypeScript — developer-facing SDK
│   └── src/layer2/         # types, PolicyBuilder, AuthorizerClient, ProofClient
├── catp-node/              # Rust — MPA attestor node (scaffold)
└── catp-tests/             # Integration tests across layers
```

---

## Phase 0: Enforcement Plugin (current priority)

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

- [ ] `catp-policy.toml` schema + parser
- [ ] `PreToolUse` / `PostToolUse` hook handlers
- [ ] Local audit log with Poseidon commitment hashes
- [ ] `catp` CLI (init, validate, log, hook)
- [ ] Claude Code integration documented in README
- [ ] One-command install script

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

`catp-circuits/wasm` built and published via wasm-pack. Exports `prove_authorization` and `verify_authorization` as wasm-bindgen functions.

Remaining:
- Wire `ProofClient` in TypeScript SDK to the WASM bundle (currently returns placeholder)
- Test in both Node.js and browser environments
- Measure proving time; document latency expectations for developers

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

### 1.5 — Regulatory Alignment Audit

NIST launched the AI Agent Standards Initiative (CAISI) in February 2026, focusing on agent authentication, authorization interoperability, and auditability. As CAISI publishes draft specifications, verify CATP's interfaces remain compatible:

- Map CATP's policy commitment → NIST's agent authorization model
- Map CATP's audit log + ZK proof → NIST's auditability requirements
- Document any gaps; open issues for any required interface changes
- Track IETF Agent Name Service (ANS) draft for identity interoperability

This is a research + documentation task, not a code change. Output: one-page compatibility matrix added to `ARCHITECTURE.md`.

### Deliverables

- [x] WASM prover bundle built (`catp-circuits/wasm`)
- [ ] `catp-verify` crate exposing `verify_authorization` as a Rust library + REST endpoint
- [ ] WASM bundle wired into `ProofClient` in TypeScript SDK
- [ ] `ProofClient` verification calls routed to `catp-verify` REST endpoint
- [ ] `catp anchor` command working end-to-end
- [ ] Circuit review complete
- [ ] NIST CAISI compatibility matrix documented
- [ ] Updated README with Phase 1 flow
- [ ] On-chain Solidity verifier — deferred to Phase 2 (pending stable KZG crates.io release or Nova/HyperNova tooling)

---

## Phase 2: Output Verification (Month 9–15)

**Goal**: "Agent was authorized AND its output is trustworthy." Targets AI-powered DeFi risk engines and any scenario where output correctness matters, not just authorization.

### 2.1 — Defense Layer 1: Commit-and-Prove

- `CommitRegistry.sol` + SDK helpers ✅ (contracts exist, need real verifier wired)
- Generate and submit pre/post commitments around inference

### 2.2 — Defense Layer 2: MPA Attestor Node

- `catp-node/`: receives inference request, runs model, submits `output_commitment`
- `MPAVerifier.sol` ✅ (exists, needs real verifier)
- Attestor staking + slashing; permissioned set initially

### 2.3 — Defense Layer 3: Optimistic Slash

- `OptimisticChallenge.sol` ✅ (exists)
- Tune economic parameters: stake size, window duration, challenger reward ratio

### 2.4 — `ProveBoundary` Circuit

- Implement `catp-circuits/layer3/` (currently scaffold)
- Proves output ∈ `[min, max]` without revealing raw value
- Integrated into post-inference flow

### Deliverables

- [ ] End-to-end Layer 3 flow on testnet
- [ ] `ProveBoundary` circuit implemented and tested
- [ ] Permissioned attestor set running
- [ ] Integration tests in `catp-tests/`

---

## Phase 3: Reputation Protocol (Month 15–21)

**Goal**: Agents accumulate private track records and prove properties about them. Activates network effects: agents want reputation → more agents join → protocols trust the system more.

### 3.1 — Reputation State + Off-Chain Storage

- `AgentReputationState` struct + Poseidon commitment scheme
- Local state storage (file or embedded DB)
- SDK `ReputationManager` (currently scaffold in `catp-sdk/src/layer4/`)

### 3.2 — `ProveReputation` Circuit

- Implement `catp-circuits/layer4/` (currently scaffold)
- Constraints: state integrity, ratio bounds, minimum sample, zero violations, monotonic updates

### 3.3 — `ReputationRegistry.sol`

- Stores `state_commitment` per agent DID
- Verifies monotonic update proofs before accepting new commitments
- Cross-references Layer 2 + Layer 3 on-chain events for consistency

### Deliverables

- [ ] `ProveReputation` circuit implemented and tested
- [ ] `ReputationRegistry.sol` deployed on testnet
- [ ] SDK `ReputationManager` complete
- [ ] Anti-gaming enforcement verified via tests

---

## Phase 4: Full Platform (Month 21–27)

**Goal**: CATP becomes a protocol, not just a product.

### 4.1 — Layer 1: Agent Messaging Protocol (AMP)

- X25519 + DID-bound key exchange; Double Ratchet for forward secrecy
- Per-field Poseidon commitments (selective disclosure)
- MCP transport wrapper + A2A protocol adapter
- SDK `catp-sdk/src/layer1/` (currently scaffold)

### 4.2 — Layer 5: Agent Registry & Discovery

- `AgentRegistry.sol`: registry CRUD, trust score storage
- `ProveCapability` circuit (`catp-circuits/layer5/`, currently scaffold)
- Discovery query engine (off-chain indexer + on-chain verification)
- SDK `catp-sdk/src/layer5/` (currently scaffold)

### 4.3 — Full Cross-Layer Demo

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
| `ProveAuthorization` Halo2 circuit — prove + real verify | ✅ Complete (11 tests) |
| WASM prover bundle (`catp-circuits/wasm`) | ✅ Complete — `prove_authorization` / `verify_authorization` |
| `AgentAuthorizer.sol` + `ActionData.sol` | ✅ Complete (16 tests, stub verifier) |
| TypeScript SDK Layer 2 (`PolicyBuilder`, `AuthorizerClient`, `ProofClient`) | ⚠️ API complete; `ProofClient` not yet wired to WASM bundle |
| `catp-verify` REST verification endpoint | 🔜 Next — Phase 1 primary verification path |
| `CommitRegistry.sol` (Layer 3) | ✅ Complete (8 tests) |
| `MPAVerifier.sol` (Layer 3) | ✅ Complete (9 tests) |
| `OptimisticChallenge.sol` (Layer 3) | ✅ Complete (10 tests) |
| Enforcement plugin (`catp-plugin/`) | 🔴 Not started — **Phase 0 priority** |
| Real Halo2 on-chain verifier | 🔜 Deferred to Phase 2 — pending stable KZG tooling |
| Layers 1, 4, 5 circuits | 🔜 Scaffold only |
| SDK Layers 1, 3, 4, 5 | 🔜 Scaffold only |

**45 tests passing** across Rust (11) and Solidity/Forge (34).

---

## Dependencies

| Component | Depends On |
|-----------|-----------|
| `catp-plugin` Phase 0 | `catp-circuits/primitives` (Poseidon) |
| `catp-plugin` Phase 1 anchor | `catp-contracts/layer2` + WASM prover |
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
| Enforcement plugin friction — developers don't install it | High | One-command install; Claude Code hooks are native and well-documented |
| Halo2 proving time too slow | High | Pre-compute for common patterns; batch; benchmark in Phase 1 |
| ZK circuit soundness bugs | High | Comprehensive constraint tests; formal review before deploy |
| WASM bundle size (browser SDK) | Medium | Code-split by layer; lazy-load prover WASM |
| MPA attestor liveness | Medium | Fallback to optimistic-only mode; minimum staked set |
| Gas costs (200–400K per verification) | Medium | Target L2 (Arbitrum/Base); batch verifications |
| Adoption chicken-and-egg | High | Phase 0 ships standalone value with no protocol dependency |
