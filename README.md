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

**Option A — npm:**

```bash
npm install -g @catp-protocol/cli
```

**Option B — clone and build:**

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
version = "1"

[[rules]]
tool = "Bash"
allow = false
pattern = ["rm -rf *", "sudo *", "curl * | bash"]
reason = "Destructive or remote-execution commands are blocked"

[[rules]]
tool = "Write"
allow = false
path_allowlist = ["src/**", "tests/**"]
reason = "Deny writes to paths outside src/ and tests/"

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

Logs are written to `~/.catp/audit/<agentId>/<YYYY-MM-DD>/actions.jsonl`. Each entry chains on the previous commitment hash, forming a tamper-evident sequence. `catp anchor` can submit a Merkle root of these local commitments on-chain; structured Layer 2 authorization proofs use the separate Poseidon policy commitment path verified by `Halo2Verifier.sol`.

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
│   ├── layer2/             # ProveAuthorization circuit + SRS + e2e integration tests
│   └── wasm/               # wasm-pack bindings — compute_policy_commitment / prove_authorization / verify_authorization
├── catp-contracts/         # Solidity — on-chain verifiers + state
│   ├── src/layer2/         # AgentAuthorizer, Halo2Verifier, Halo2AuthorizationVerifier
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
| 0 | `catp-plugin` — Claude Code enforcement + audit log | ✅ Complete (72 tests) |
| 2 | `ProveAuthorization` Halo2 circuit — full protocol/token binding, range checks, 13 public inputs, k=12 | ✅ Complete (15 unit tests + 3 E2E tests) |
| 2 | WASM prover bundle (`catp-circuits/wasm`) | ✅ Complete — shared SRS, `compute_policy_commitment` / `prove_authorization` / `verify_authorization` |
| 2 | `AgentAuthorizer.sol` + `ActionData.sol` | ✅ Complete (19 tests) |
| 2 | `Halo2Verifier.sol` — k=12, 13 public inputs, shared KZG SRS | ✅ Complete |
| 2 | `Halo2AuthorizationVerifier.sol` — encodes + forwards public inputs | ✅ Complete (5 tests) |
| 2 | `catp-verify` — Rust REST verification endpoint | ✅ Complete (3 tests) — verifies proof + public inputs |
| 2 | TypeScript SDK — `PolicyBuilder`, `AuthorizerClient`, `ProofClient` | ✅ Complete (36 tests) — sends proof + public inputs to verifier |
| 2 | E2E Rust test — policy → Poseidon → proof → off-chain verify | ✅ Complete (3 tests) |
| 3 | `CommitRegistry.sol` | ✅ Complete (10 tests) |
| 3 | `MPAVerifier.sol` | ✅ Complete (12 tests) |
| 3 | `OptimisticChallenge.sol` | ✅ Complete (13 tests) |
| 1, 4, 5 | All layers | 🔜 Planned |

**214 tests passing** across TypeScript/Jest (72), Vitest (36), Rust (47), and Solidity/Forge (59).

> The Layer 2 ZK path is fully wired: policies are committed via Poseidon (BN254), proofs are generated by the WASM bundle or Rust prover, and verified either off-chain via the `catp-verify` REST endpoint or on-chain via the deployed `Halo2Verifier.sol`. Both verification paths use the same 13 public inputs: `policyCommitment`, public action fields, `currentTimestamp`, and `cumulativeSpend`. A shared KZG SRS (`catp-layer2-k12.srs`) ensures prover and verifier are consistent.

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

## Contributing

Contributions are welcome. Please open an issue before starting significant work so we can coordinate.

See [CONTRIBUTING.md](CONTRIBUTING.md) for per-component dev setup, coding conventions, and commit message format.

---

## License

[MIT](LICENSE)
