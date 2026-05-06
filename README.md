# CATP - Cryptographic Agent Trust Protocol

CATP makes autonomous agent activity enforceable locally and provable externally.

The current MVP has two connected surfaces:

1. **Local enforcement**: a Claude Code hook plugin blocks tool calls outside a project policy and writes a tamper-evident audit log.
2. **Verifiable authorization**: a Groth16/BN254 EVM proof path proves that a structured agent action satisfies a committed private policy.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design and [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for the execution plan.

---

## What Works Today

```text
Shipped
Layer 0  Local enforcement plugin          Claude Code hooks + TOML policy + SHA-256 audit log
Layer 2  EVM delegated authorization       authorization_groth16_v1 = Groth16/BN254, Sepolia smoke passed
Layer 2  Off-chain authorization path      authorization_v1 = Halo2/KZG/BN254, not EVM-deployable

Partial
Layer 3  Output verification               commit registry + MPA/challenge contracts; attestor flow pending

Planned
Layer 1  Encrypted agent communication     X25519 + AES-256-GCM + forward secrecy
Layer 4  Privacy-preserving reputation     ZK-proven performance properties
Layer 5  Verifiable agent registry         capability proofs + discovery
```

The protocol boundary is the authorization proof statement and public input schema, not Ethereum itself. Ethereum/Sepolia is the current reference deployment target.

---

## Layer 2 Proof Systems

CATP currently contains two Layer 2 authorization proof paths.

| Path | Role | Status |
|------|------|--------|
| `authorization_groth16_v1` | Current EVM verifier path | Works on Sepolia; compact verifier runtime is about 6.4 KB and wrapper runtime is about 1.1 KB |
| `authorization_v1` Halo2 | Off-chain verifier / research path | Works locally; generated Solidity verifier runtime is about 319 KB and does not fit under the EVM 24,576-byte runtime limit |

Groth16 does require a circuit-specific trusted setup. The keys currently checked into `catp-circuits/groth16/keys/` are stable dev/testnet keys, not a mainnet ceremony. A mainnet release must either run and document a proper ceremony or explicitly choose a weaker trust model.

Any change to public inputs, policy encoding, circuit constraints, commitment hash, proof backend, or setup keys should create a new proof version and verifier address.

---

## Quick Start - Local Enforcement

`catp-plugin` runs as Claude Code hooks. It evaluates every tool call against a TOML policy file and writes a tamper-evident audit log with a SHA-256 commitment chain.

No blockchain or ZK setup is required for local enforcement.

### Install

Option A - npm:

```bash
npm install -g @catp-protocol/cli
```

Option B - clone and build:

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

`catp anchor` can submit a Merkle root of local audit commitments on-chain. Structured Layer 2 authorization proofs use a separate private policy commitment path verified by `authorization_groth16_v1` on EVM or by the off-chain verifier path.

---

## End-to-End Groth16 Authorization

This is the current EVM path. It proves that an action is allowed by a private committed policy, then executes that proof through `AgentAuthorizer.executeAuthorized`.

The proof statement is versioned as:

```text
authorization_groth16_v1
```

Public inputs:

- `policyCommitment`
- `actionType`
- `protocol[4]`
- `token[4]`
- `value`
- `currentTimestamp`
- `cumulativeSpend`

The Solidity execution path is:

```text
AgentAuthorizer
  -> Groth16AuthorizationVerifier
    -> Groth16Verifier
```

### 1. Add Authorization Policy Fields

Add a structured `[authorization]` section to `catp-policy.toml`:

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

### 2. Create Action JSON

```json
{
  "actionType": "Swap",
  "protocol": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "token": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "value": "500"
}
```

### 3. Generate a Proof Artifact

Use a fresh timestamp near execution time. `AgentAuthorizer` rejects proofs older than five minutes.

```bash
npm run groth16:prove -- \
  --action action.json \
  --current-timestamp 1778042846 \
  --cumulative-spend 0 \
  --out authorization_groth16_v1.json
```

The script builds a witness with `catp witness` and passes it to the Groth16 prover.

You can also build a witness from an audit entry that recorded `tool_input.catp_authorization` or `tool_input.authorization`:

```bash
catp witness \
  --audit-commitment <64-char-audit-commitment> \
  --out witness.json
```

### 4. Encode Calldata Without Broadcasting

```bash
npm run groth16:encode-execute -- \
  --artifact authorization_groth16_v1.json \
  --out execute-authorized.calldata.json
```

This validates the proof artifact and emits calldata for:

- `registerPolicy(bytes32)`
- `executeAuthorized(bytes32,bytes,uint256,bytes)`

### 5. Dry-Run Execution

```bash
npm run groth16:execute -- \
  --artifact authorization_groth16_v1.json \
  --dry-run
```

Dry-run does not require RPC credentials and does not broadcast.

### 6. Execute on Sepolia

Load RPC credentials from `catp-contracts/.env` or your shell:

```bash
set -a
source catp-contracts/.env
set +a
```

Then broadcast:

```bash
npm run groth16:execute -- \
  --artifact authorization_groth16_v1.json \
  --out execute-authorized.receipt.json
```

The script:

- reads `AgentAuthorizer` from `catp-contracts/deployments/sepolia-groth16.json` unless `--authorizer` is passed
- registers the policy only if inactive
- checks that the proof artifact's `cumulativeSpend` matches on-chain state
- broadcasts `executeAuthorized`
- writes receipt metadata when `--out` is provided

---

## Deployment and Verification Commands

Generate or refresh the Groth16 verifier, proof fixture, and setup manifest:

```bash
npm run groth16:generate
```

Check the persisted Groth16 setup, verifier source, wrapper source, build artifacts, and Sepolia metadata:

```bash
npm run groth16:check
```

Check verifier runtime sizes:

```bash
npm run groth16:size
```

Deploy the compact Groth16 verifier path:

```bash
scripts/deploy-groth16-sepolia.sh --dry-run
scripts/deploy-groth16-sepolia.sh
```

Run the Sepolia smoke script:

```bash
scripts/smoke-groth16-sepolia.sh
```

Run the Solidity Groth16 adapter tests:

```bash
cd catp-contracts
forge test --match-path test/layer2/Groth16AuthorizationVerifier.t.sol
```

---

## Halo2 Path

The Halo2 Layer 2 proof version is:

```text
authorization_v1
```

It uses:

- Halo2/KZG on BN254
- `k=12`
- GWC opening
- EVM transcript
- 13 public inputs

This path is available for off-chain verification and proof-system research. It is not the current EVM deployment path because the generated Solidity verifier exceeds the EVM runtime bytecode limit.

The committed `catp-layer2-k12.srs` is for development and testnet consistency. Mainnet Halo2 usage would require documented SRS provenance or replacement with accepted ceremony output.

---

## Repository Structure

```text
catp/
├── catp-plugin/            # TypeScript — Layer 0 enforcement plugin
│   └── src/
│       ├── policy/         # TOML loader, rule engine
│       ├── audit/          # Commitment chain logger and verifier
│       ├── hook/           # pre.ts / post.ts hook handlers
│       └── commands/       # init, validate, log, witness CLI commands
├── catp-circuits/          # Rust/Go — ZK circuits and verifier generators
│   ├── primitives/         # Poseidon, SMT, encryption primitives, proof abstractions
│   ├── layer2/             # Halo2 ProveAuthorization circuit + SRS + e2e tests
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
| 0 | `catp-plugin` - Claude Code enforcement + audit log | Complete; published as `@catp-protocol/cli` |
| 2 | `authorization_groth16_v1` compact EVM verifier | Sepolia smoke passed; real proof execution passing |
| 2 | `Groth16Verifier.sol` | Generated verifier runtime about 6.4 KB |
| 2 | `Groth16AuthorizationVerifier.sol` | Wrapper runtime about 1.1 KB |
| 2 | `AgentAuthorizer.sol` + `ActionData.sol` | Complete |
| 2 | Groth16 proof/execution scripts | Complete for testnet flow: prove, encode, dry-run, execute |
| 2 | TypeScript SDK Layer 2 | Complete locally |
| 2 | `authorization_v1` Halo2 circuit | Complete locally; EVM verifier blocked by bytecode size |
| 2 | `catp-verify` Rust endpoint | Complete |
| 3 | `CommitRegistry.sol`, `MPAVerifier.sol`, `OptimisticChallenge.sol` | Partial |
| 3 | attestor node + `boundary_v1` circuit | Pending |
| 1, 4, 5 | messaging, reputation, registry | Scaffold/planned |

Last recorded full-stack baseline: 214 passing tests across TypeScript/Jest, Vitest, Rust, and Solidity/Forge.

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
| npm | >= 10 | root scripts, catp-plugin |
| pnpm | >= 9 | catp-sdk |
| Rust | stable via `rust-toolchain.toml` | catp-circuits, catp-verify, catp-node |
| Go | >= 1.23 | gnark Groth16 prover |
| Foundry | latest | catp-contracts, deploy/smoke scripts |
| jq | any modern version | shell scripts |

Install Foundry:

```bash
curl -L https://foundry.paradigm.xyz | bash
```

---

## Mainnet Readiness

The current Groth16 path is suitable for deterministic development and testnet validation. It is not yet a mainnet release.

Before mainnet, the project should:

- run and document a circuit-specific Groth16 ceremony, or explicitly publish a weaker trust model
- complete an external review of the Groth16 circuit and Solidity verifier adapter
- decide whether `authorization_groth16_v1` is the long-term proof version or a stepping stone to another EVM-friendly proof system
- add operational tooling for deployment metadata, receipt updates, and proof artifact retention

---

## Contributing

Contributions are welcome. Please open an issue before starting significant work so we can coordinate.

See [CONTRIBUTING.md](CONTRIBUTING.md) for per-component dev setup, coding conventions, and commit message format.

---

## License

[MIT](LICENSE)
