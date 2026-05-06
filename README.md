# CATP — Cryptographic Agent Trust Protocol

CATP makes autonomous agent activity enforceable locally and provable externally.

Today, CATP ships two connected pieces:

1. **Local enforcement**: a Claude Code hook plugin that blocks tool calls outside a project policy and writes a tamper-evident audit log.
2. **Layer 2 authorization proofs**: Halo2/KZG off-chain verification and a Groth16/BN254 EVM path that prove a structured action satisfies a committed private policy.

The broader protocol roadmap adds encrypted agent communication, output verification, private reputation, and agent discovery. Those layers are part of the architecture, but the current MVP is the enforcement plugin plus Layer 2 authorization proofs.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design and [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for the current execution plan.

---

## Current Stack

```text
Shipped
Layer 0  Local enforcement plugin          Claude Code hooks + TOML policy + audit log
Layer 2  ZK delegated authorization        authorization_v1 = Halo2/KZG/BN254 off-chain; authorization_groth16_v1 passed Sepolia smoke

Partial
Layer 3  Output verification               commit registry + MPA/challenge contracts; attestor flow pending

Planned
Layer 1  Encrypted agent communication     X25519 + AES-256-GCM + forward secrecy
Layer 4  Privacy-preserving reputation     ZK-proven performance properties
Layer 5  Verifiable agent registry         capability proofs + discovery
```

The Ethereum contracts are the reference deployment for Layer 2, not the protocol boundary. The proof interface and public input schema are the portability boundary.

---

## Quick Start — Claude Code Enforcement

`catp-plugin` runs as Claude Code hooks. It evaluates every tool call against a TOML policy file and writes a tamper-evident audit log with a SHA-256 commitment chain.

No blockchain or ZK setup is required for local enforcement.

### Install

Option A — npm:

```bash
npm install -g @catp-protocol/cli
```

Option B — clone and build:

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

### Wire Claude Code Hooks

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

### Configure a Policy

```bash
cd your-project/
catp init
catp validate
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

Rules are evaluated top-to-bottom; first match wins. Unmatched tools are allowed by default.

### View the Audit Log

```bash
catp log show
catp log verify
```

Logs are written to `${CATP_HOME:-~/.catp}/audit/<agentId>/<YYYY-MM-DD>/actions.jsonl`. Each entry chains on the previous commitment hash, forming a tamper-evident sequence.

`catp anchor` can submit a Merkle root of local audit commitments on-chain. Structured Layer 2 authorization proofs use a separate Poseidon policy commitment path verified by `catp-verify` off-chain or by `authorization_groth16_v1` on EVM. Direct EVM verification for the current Halo2 verifier is blocked by verifier bytecode size.

### Build a Layer 2 Witness

For the Groth16 EVM path, add a structured authorization section to
`catp-policy.toml`:

```toml
[authorization]
allowed_action = "Swap"
allowed_protocol = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
allowed_token = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
max_value_per_tx = "1000"
max_value_total = "10000"
valid_from = "1778042786"
valid_until = "1778129246"
```

Then create an action JSON:

```json
{
  "actionType": "Swap",
  "protocol": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "token": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "value": "500"
}
```

Build the prover witness:

```bash
catp witness \
  --action action.json \
  --current-timestamp 1778042846 \
  --cumulative-spend 0 \
  --out witness.json
```

If an audit entry was recorded with `tool_input.catp_authorization` or
`tool_input.authorization`, the same witness can be built from its commitment:

```bash
catp witness \
  --audit-commitment <64-char-audit-commitment> \
  --out witness.json
```

Generate the proof artifact:

```bash
bash scripts/generate-groth16-verifier.sh \
  --witness witness.json \
  --out authorization_groth16_v1.json
```

Or build the witness and proof artifact in one repo command:

```bash
npm run groth16:prove -- \
  --action action.json \
  --current-timestamp 1778042846 \
  --cumulative-spend 0 \
  --out authorization_groth16_v1.json
```

---

## Layer 2 Proof Path

The current proof statement is versioned as:

```text
authorization_v1
```

It proves that an action is authorized by a committed private policy.

Public inputs:

- `policyCommitment`
- `actionType`
- `protocol[4]`
- `token[4]`
- `value`
- `currentTimestamp`
- `cumulativeSpend`

Current backend:

- Halo2/KZG on BN254
- `k=12`
- GWC opening
- EVM transcript
- 13 public inputs
- generated Solidity verifier exists but is not EVM-deployable for this circuit

Verification paths:

- Off-chain: `catp-verify` Rust library / REST endpoint
- On-chain: `authorization_groth16_v1` has a compact Groth16/BN254 verifier path that passed Sepolia smoke; current generated `Halo2Verifier.sol` exceeds the EVM runtime bytecode limit
- SDK: `groth16ArtifactToAuthorizationCall` converts generated Groth16 proof artifacts into `AgentAuthorizer.executeAuthorized` calldata fields

The committed `catp-layer2-k12.srs` is for development and testnet consistency. Mainnet deployment requires documented SRS provenance or replacement with an accepted ceremony output.

Any change to public inputs, policy encoding, circuit constraints, SRS size, transcript, or proof backend should create a new proof version and verifier address.

---

## Repository Structure

```text
catp/
├── catp-plugin/            # TypeScript — Layer 0 enforcement plugin
│   └── src/
│       ├── policy/         # TOML loader, rule engine
│       ├── audit/          # Commitment chain logger and verifier
│       ├── hook/           # pre.ts / post.ts hook handlers
│       └── commands/       # init, validate, log CLI commands
├── catp-circuits/          # Rust/Go — ZK circuits and verifier generators
│   ├── primitives/         # Poseidon, SMT, encryption primitives, proof abstractions
│   ├── layer2/             # ProveAuthorization circuit + SRS + e2e tests
│   ├── groth16/            # gnark Groth16 authorization verifier path
│   └── wasm/               # wasm-pack bindings
├── catp-contracts/         # Solidity — verifiers + protocol contracts
│   ├── src/layer2/         # AgentAuthorizer, verifier wrappers, proof adapters
│   └── src/layer3/         # CommitRegistry, MPAVerifier, OptimisticChallenge
├── catp-sdk/               # TypeScript — developer-facing SDK
│   └── src/layer2/         # types, PolicyBuilder, AuthorizerClient, ProofClient
├── catp-verify/            # Rust — off-chain proof verification endpoint
├── catp-node/              # Rust — MPA attestor node scaffold
└── catp-tests/             # Integration test scaffold
```

---

## Current Status

| Layer | Component | Status |
|-------|-----------|--------|
| 0 | `catp-plugin` — Claude Code enforcement + audit log | Complete; published as `@catp-protocol/cli` |
| 2 | `ProveAuthorization` Halo2 circuit | Complete locally; formal review pending |
| 2 | WASM prover bundle | Complete |
| 2 | `AgentAuthorizer.sol` + `ActionData.sol` | Complete |
| 2 | `Halo2Verifier.sol` | Generated, but blocked for EVM deployment: real runtime is ~319 KB versus the 24,576-byte EVM limit |
| 2 | `Halo2AuthorizationVerifier.sol` | Complete wrapper, but not usable on EVM until paired with a deployable verifier |
| 2 | `catp-verify` Rust endpoint | Complete |
| 2 | TypeScript SDK Layer 2 | Complete locally |
| 2 | `authorization_groth16_v1` compact EVM verifier | Sepolia smoke passed: generated verifier runtime ~6.4 KB, wrapper ~1.1 KB, real proof execution passing |
| 2 | Sepolia smoke test | Passed for compact Groth16 path |
| 3 | `CommitRegistry.sol`, `MPAVerifier.sol`, `OptimisticChallenge.sol` | Partial |
| 3 | attestor node + `boundary_v1` circuit | Pending |
| 1, 4, 5 | messaging, reputation, registry | Scaffold/planned |

Current local test count: 214 passing across TypeScript/Jest, Vitest, Rust, and Solidity/Forge.

---

## Prerequisites

Layer 0 only:

| Tool | Version |
|------|---------|
| Node.js | >= 20 |
| npm | >= 10 |

Full stack:

| Tool | Version | Used by |
|------|---------|---------|
| Node.js | >= 20 | catp-plugin, catp-sdk |
| npm | >= 10 | catp-plugin |
| pnpm | >= 9 | catp-sdk |
| Rust | stable via `rust-toolchain.toml` | catp-circuits, catp-verify, catp-node |
| Foundry | latest | catp-contracts |

Install Foundry:

```bash
curl -L https://foundry.paradigm.xyz | bash
```

---

## Contributing

Contributions are welcome. Please open an issue before starting significant work so we can coordinate.

See [CONTRIBUTING.md](CONTRIBUTING.md) for per-component dev setup, coding conventions, and commit message format.

---

## License

[MIT](LICENSE)
