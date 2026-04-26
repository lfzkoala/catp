# CATP — Cryptographic Agent Trust Protocol

A 5-layer cryptographic trust stack for AI agents operating on-chain. Agents can prove authorization, verify outputs, and accumulate private reputation — without revealing sensitive policy or operational details.

## Architecture

```
Layer 0  Local enforcement plugin          (Claude Code hooks + TOML policy + audit log)
Layer 1  Encrypted agent communication     (X25519 + AES-256-GCM + Double Ratchet)
Layer 2  ZK-proven delegated authorization (Halo2 circuits + Solidity verifier)
Layer 3  Output verification               (commit-and-prove + MPA attestors + optimistic slash)
Layer 4  Privacy-preserving reputation     (ZK-proven performance attestations)
Layer 5  Verifiable agent registry         (capability proofs + discovery)
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design and [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for the phased roadmap.

---

## Quick Start — Claude Code Enforcement (Layer 0)

`catp-plugin` is a local enforcement layer that runs as Claude Code hooks. It evaluates every tool call against a TOML policy file and writes a tamper-evident audit log with a SHA-256 commitment chain. **No blockchain or ZK required** — this works today with any Claude Code installation.

### Install

```bash
git clone https://github.com/lfzkoala/catp.git
cd catp
bash install.sh
```

This installs dependencies, compiles the plugin, and symlinks the `catp` binary to `~/.local/bin/`.

If `catp` is not found after install, add `~/.local/bin` to your PATH:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
# or for bash:
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
```

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

Example `catp-policy.toml`:

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
catp log verify       # verify the SHA-256 commitment chain is intact
```

Logs are written to `~/.catp/audit/<agentId>/<YYYY-MM-DD>/actions.jsonl`. Each entry chains on the previous commitment hash, forming a tamper-evident sequence. Layer 2 will upgrade this to Poseidon hashes verifiable on-chain.

---

## Repository Structure

```
catp/
├── catp-plugin/            # TypeScript — Layer 0 enforcement plugin
│   └── src/
│       ├── policy/         # TOML loader, rule engine
│       ├── audit/          # Commitment chain logger and verifier
│       ├── hook/           # pre.ts / post.ts hook handlers
│       └── commands/       # init, validate, log CLI commands
├── catp-circuits/          # Rust — Halo2 ZK circuits
│   ├── primitives/         # Poseidon hash, SMT, X25519/AES, ProofSystem trait
│   └── layer2/             # ProveAuthorization circuit
├── catp-contracts/         # Solidity — on-chain verifiers + state
│   ├── src/layer2/         # AgentAuthorizer, IVerifier, StubVerifier
│   └── src/layer3/         # CommitRegistry, MPAVerifier, OptimisticChallenge
├── catp-sdk/               # TypeScript — developer-facing SDK
│   └── src/layer2/         # types, PolicyBuilder, AuthorizerClient, ProofClient
├── catp-node/              # Rust — MPA attestor node (scaffold)
└── catp-tests/             # Integration tests (scaffold)
```

---

## Current Status

| Layer | Component | Status |
|-------|-----------|--------|
| 0 | `catp-plugin` — Claude Code enforcement + audit log | ✅ Complete |
| 2 | `ProveAuthorization` Halo2 circuit | ✅ Complete (9 tests) |
| 2 | `AgentAuthorizer.sol` + `ActionData.sol` | ✅ Complete (16 tests) |
| 2 | TypeScript SDK — types, `PolicyBuilder`, `AuthorizerClient`, `ProofClient` | ⚠️ API complete; ZK prover is a stub |
| 3 | `CommitRegistry.sol` | ✅ Complete (8 tests) |
| 3 | `MPAVerifier.sol` | ✅ Complete (9 tests) |
| 3 | `OptimisticChallenge.sol` | ✅ Complete (10 tests) |
| 1, 4, 5 | All layers | 🔜 Planned |

**43 tests passing** across Rust (MockProver) and Solidity (Forge).

> **Stub notice:** The Halo2 on-chain verifier (`IVerifier`) and WASM prover (`ProofClient`) are intentional stubs. They will be replaced with the generated Halo2 Solidity verifier and a `wasm-pack` bundle in the next phase. Do not use the Layer 2 SDK in production.

---

## Prerequisites

**Layer 0 only (catp-plugin):**

| Tool | Version |
|------|---------|
| Node.js | ≥ 20 |
| npm | ≥ 10 (bundled with Node.js 20) |

**Full stack (circuits + contracts + SDK):**

| Tool | Version | Used by |
|------|---------|---------|
| Node.js | ≥ 20 | catp-plugin, catp-sdk |
| npm | ≥ 10 | catp-plugin |
| pnpm | ≥ 9 | catp-sdk |
| Rust | stable via `rust-toolchain.toml` | catp-circuits, catp-node |
| Foundry | latest | catp-contracts |

Install Foundry: `curl -L https://foundry.paradigm.xyz | bash`

---

## Getting Started

### Layer 0 — enforcement plugin

```bash
bash install.sh
```

See the [Quick Start](#quick-start--claude-code-enforcement-layer-0) section above.

### Layer 2 — Halo2 circuits

```bash
cargo test --workspace
```

### Layer 2 — Solidity contracts

```bash
cd catp-contracts
forge test
```

### Layer 2 — TypeScript SDK

```bash
cd catp-sdk
NODE_ENV=development pnpm install
pnpm tsc --noEmit
```

---

## How Layer 2 Works

1. A delegator calls `AgentAuthorizer.registerPolicy(policyCommitment)` to register a policy hash on-chain.
2. The agent uses `PolicyBuilder` to construct an `AuthorizationPolicy` and `ProofClient` to generate a ZK proof that its action satisfies the policy.
3. The agent calls `AgentAuthorizer.executeAuthorized(policyCommitment, actionData, proof)`.
4. The contract verifies the proof, tracks cumulative spend, and emits `AuthorizedExecution`.

## How Layer 3 Works

1. Before inference, the agent submits a `preCommitment` hash to `CommitRegistry`.
2. After inference, it submits a `postCommitment`; MPA attestors submit `outputCommitments` to `MPAVerifier`.
3. Once ≥ 2/3 of attestors agree, the round is finalized.
4. Any party can open a challenge via `OptimisticChallenge` within the challenge window. A successful challenge awards the challenger 30% of the slashed attestor stake.

---

## Contributing

Contributions are welcome. Please open an issue before starting significant work so we can coordinate.

- **Layer 0 (`catp-plugin`)**: TypeScript, Node.js ≥ 20, npm workspaces
- **Circuits (`catp-circuits`)**: Rust, Halo2 (PSE fork), `cargo test`
- **Contracts (`catp-contracts`)**: Solidity ^0.8.24, Foundry (`forge test`)
- **SDK (`catp-sdk`)**: TypeScript, pnpm

All PRs should include tests. The Layer 0 plugin targets 80% coverage; contract PRs require Forge tests.

---

## License

[MIT](LICENSE)
