# CATP — Cryptographic Agent Trust Protocol

A 5-layer cryptographic trust stack for AI agents operating on-chain. Agents can prove authorization, verify outputs, and accumulate private reputation — without revealing sensitive policy or operational details.

## Architecture

```
Layer 1  Encrypted agent communication    (X25519 + AES-256-GCM + Double Ratchet)
Layer 2  ZK-proven delegated authorization (Halo2 circuits + Solidity verifier)
Layer 3  Output verification              (commit-and-prove + MPA attestors + optimistic slash)
Layer 4  Privacy-preserving reputation    (ZK-proven performance attestations)
Layer 5  Verifiable agent registry        (capability proofs + discovery)
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for full design and [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for the phased roadmap.

## Quick Start — Claude Code Enforcement (Phase 0)

`catp-plugin` is a local enforcement layer that runs as Claude Code hooks. It evaluates every tool call against a TOML policy file and writes a tamper-evident audit log with a SHA-256 commitment chain.

### Install

```bash
bash install.sh
```

This builds the plugin, installs the `catp` binary to `~/.local/bin/`, and prints the hook config.

### Wire up Claude Code hooks

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": ".*",
      "command": "catp hook pre"
    }],
    "PostToolUse": [{
      "matcher": ".*",
      "command": "catp hook post"
    }]
  }
}
```

### Configure a project policy

```bash
cd your-project/
catp init          # creates catp-policy.toml
catp validate      # syntax-checks the policy
```

The generated `catp-policy.toml` looks like:

```toml
[agent]
id = "my-agent"
version = 1

[[rules]]
tool = "Bash"
allow = false
pattern = ["rm -rf *", "sudo *", "curl * | bash"]
reason = "Destructive or remote-execution commands are blocked"

[[rules]]
tool = "Write"
allow = true
path_allowlist = ["src/**", "tests/**"]
reason = "Writes allowed only inside src/ and tests/"

[[rules]]
tool = "WebFetch"
allow = true
reason = "Web reads are unrestricted"
```

Rules are evaluated top-to-bottom; first match wins. Unmatched tools are **allowed by default**.

### View the audit log

```bash
catp log show         # recent tool calls with allow/deny verdicts
catp log verify       # verify the commitment chain hasn't been tampered with
```

Logs are written to `~/.catp/audit/<agentId>/<YYYY-MM-DD>/actions.jsonl`. Each entry chains on the previous via SHA-256, forming a tamper-evident sequence that Phase 1 will upgrade to Poseidon hashes verified on-chain.

---

## Repository Structure

```
catp/
├── catp-plugin/            # TypeScript — Claude Code enforcement plugin (Phase 0)
│   └── src/
│       ├── policy/         # TOML loader, rule engine
│       ├── audit/          # Commitment chain logger and verifier
│       ├── hook/           # pre.ts / post.ts hook handlers
│       └── commands/       # init, validate, log CLI commands
├── catp-circuits/          # Rust — Halo2 ZK circuits
│   ├── primitives/         # Poseidon hash, SMT, X25519/AES, ProofSystem trait
│   └── layer2/             # ProveAuthorization circuit
├── catp-contracts/         # Solidity — on-chain verifiers + state
│   ├── src/layer2/         # AgentAuthorizer, ActionData, IAgentAuthorizer
│   └── src/layer3/         # CommitRegistry, MPAVerifier, OptimisticChallenge
├── catp-sdk/               # TypeScript — developer-facing SDK
│   └── src/layer2/         # types, PolicyBuilder, AuthorizerClient, ProofClient
├── catp-node/              # Rust — MPA attestor node (scaffold)
└── catp-tests/             # Integration tests (scaffold)
```

## Current Status

| Phase | Component | Status |
|-------|-----------|--------|
| 0 | `catp-plugin` — Claude Code enforcement + audit log | ✅ Complete |
| 2 | `ProveAuthorization` Halo2 circuit | ✅ Complete (9 tests) |
| 2 | `AgentAuthorizer.sol` + `ActionData.sol` | ✅ Complete (16 tests) |
| 2 | TypeScript SDK (`PolicyBuilder`, `AuthorizerClient`, `ProofClient`) | ✅ Complete |
| 3 | `CommitRegistry.sol` | ✅ Complete (8 tests) |
| 3 | `MPAVerifier.sol` | ✅ Complete (9 tests) |
| 3 | `OptimisticChallenge.sol` | ✅ Complete (10 tests) |
| 1, 4, 5 | All layers | 🔜 Planned |

**43 tests passing** across Rust (MockProver) and Solidity (Forge).

> The Halo2 on-chain verifier and WASM prover are stubs in the current phase. They will be replaced with the generated Halo2 Solidity verifier and wasm-pack bundle when the real on-chain verifier is ready.

## Prerequisites

| Tool | Version |
|------|---------|
| Rust | stable via `rust-toolchain.toml` |
| Foundry | latest (`curl -L https://foundry.paradigm.xyz | bash`) |
| Node.js | ≥ 20 |
| npm | ≥ 10 (bundled with Node.js 20) |

## Getting Started

### Rust circuits and primitives

```bash
cargo test --workspace
```

### Solidity contracts

```bash
cd catp-contracts
forge test
```

### TypeScript SDK

```bash
cd catp-sdk
NODE_ENV=development pnpm install
pnpm tsc --noEmit
```

## How Layer 2 Works

1. A delegator calls `AgentAuthorizer.registerPolicy(policyCommitment)` to register a policy hash on-chain.
2. The agent uses `PolicyBuilder` to construct an `AuthorizationPolicy` and `ProofClient` to generate a ZK proof that its action satisfies the policy.
3. The agent calls `AgentAuthorizer.executeAuthorized(policyCommitment, actionData, proof)`.
4. The contract verifies the proof, tracks cumulative spend, and emits `AuthorizedExecution`.

## How Layer 3 Works

1. Before inference, the agent submits a `preCommitment` hash to `CommitRegistry`.
2. After inference, it submits a `postCommitment`; MPA attestors submit `outputCommitments` to `MPAVerifier`.
3. Once ≥ 2/3 of attestors agree, the round is finalized.
4. Any party can open a challenge via `OptimisticChallenge` within the challenge window. A successful challenge upheld by re-execution awards the challenger 30% of the slashed attestor stake.

## License

MIT
