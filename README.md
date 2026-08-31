# CATP - Cryptographic Agent Trust Protocol

CATP is a local-first authorization and audit protocol for AI agents.

It gives an agent runtime a simple trust boundary:

```text
policy -> enforcement -> audit log -> signed receipt -> external verification
```

The current CLI focuses on three things:

- **Local enforcement**: evaluate tool calls against `catp-policy.toml`.
- **Tamper-evident audit**: append SHA-256 chained audit entries.
- **Signed receipts**: turn committed audit entries into portable evidence.

Groth16/EVM verification is available as an optional advanced backend. It is not
required for the default CATP workflow.

## Install

```bash
npm install -g @catp-protocol/cli@0.5.0
catp --version
```

For the full setup guide, see [docs/INSTALL.md](docs/INSTALL.md).

## Quick Start

Initialize a project policy:

```bash
catp init
catp validate
```

Wire Claude Code hooks in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": ".*",
      "command": "catp hook pre --runtime claude-code"
    }],
    "PostToolUse": [{
      "matcher": ".*",
      "command": "catp hook post --runtime claude-code"
    }]
  }
}
```

Check supported runtime adapters:

```bash
catp hook runtimes
```

Today the only built-in adapter is `claude-code`. The enforcement core is
runtime-neutral; future runtimes should map their tool events into CATP
`ToolAction` events.

The pre-hook is inactive when no `catp-policy.toml` is found. Once a policy is
discovered, CATP blocks the action if the hook payload or policy is invalid, or
if the audit decision cannot be appended safely.

## Policy

CATP policies are TOML files. Rules are evaluated top-to-bottom; first match
wins. Unmatched tools are allowed by default.

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
reason = "Deny writes outside src/ and tests/"

[[rules]]
tool = "WebFetch"
allow = true
reason = "Web reads are unrestricted"
```

## Audit Logs

CATP writes audit entries to:

```text
${CATP_HOME:-~/.catp}/audit/<agentId>/<YYYY-MM-DD>/actions.jsonl
```

Each entry chains to the previous commitment.

```bash
catp log show
catp log show --json
catp log show --tool Write --decision deny
catp log export --latest --out catp-audit-export.json
catp log show --commitments
catp log verify
catp anchor --out catp-audit-anchor.json
```

`catp anchor` verifies the local chains and exports a Merkle-root bundle for an
external anchoring system. It does not register the audit root as an
authorization policy or submit a transaction itself.

## Signed Receipts

Signed receipts are the default external verification path. They do not require
ZK, contracts, or a prover.

```bash
catp receipt keygen \
  --private-key catp-receipt-private.pem \
  --public-key catp-receipt-public.pem

catp receipt issue \
  --latest \
  --file catp-policy.toml \
  --private-key catp-receipt-private.pem \
  --audit-export-out catp-audit-export.json \
  --out catp-authorization-receipt.json

catp receipt verify \
  --receipt catp-authorization-receipt.json \
  --public-key catp-receipt-public.pem \
  --file catp-policy.toml \
  --audit-export catp-audit-export.json \
  --json
```

`catp receipt issue` verifies the local audit chain before signing. Use
`--latest` for the newest pre-enforcement decision, or `--commitment <hex>` for
a specific pre-enforcement decision. Use `--tool <name>` for the newest entry
from a specific tool, and
`--decision allow|deny` with `--latest` or `--tool` when you want a matching
allow/deny entry.

Receipts use `catp_authorization_receipt_v1` and Ed25519 signatures. The signed
payload binds the audit export hash, audit commitment, entry hash, agent id,
tool, decision, timestamp, policy commitment, and signer public key.
Verification requires a separately obtained trusted public key; the key embedded
in a receipt is signed data, not a trust anchor.

For a minimal fixture, see [examples/receipt-basic](examples/receipt-basic).

## Optional Groth16/EVM Verification

CATP also includes an optional `authorization_groth16_v1` backend for compact
EVM verification.

Use this path when you need a Groth16 proof and on-chain authorization check:

```bash
npm run groth16:check
npm run groth16:prove -- --action action.json --out authorization_groth16_v1.json
npm run groth16:encode-execute -- --artifact authorization_groth16_v1.json
```

The checked-in Groth16 proving and verifying keys are deterministic dev/testnet
keys, not a mainnet ceremony.

For the full Sepolia flow, see
[docs/E2E_GROTH16_SEPOLIA.md](docs/E2E_GROTH16_SEPOLIA.md). For authorization
security assumptions and caveats, see
[docs/AUTHORIZATION_SECURITY_NOTES.md](docs/AUTHORIZATION_SECURITY_NOTES.md).

## Repository Map

```text
catp-plugin/            npm CLI: enforcement, audit, receipts, manifests
catp-sdk/               TypeScript authorization helpers
catp-circuits/groth16/  optional gnark Groth16 backend
catp-contracts/         Solidity authorizer and verifier contracts
scripts/                Groth16 setup, proof, calldata, deploy, smoke helpers
examples/               small runnable fixtures
docs/                   install, release, E2E, and security docs
```

## Development

```bash
npm install
npm run typecheck --workspace catp-plugin
npm test --workspace catp-plugin
npm run smoke:receipt
npm run typecheck --workspace catp-sdk
npm test --workspace catp-sdk
npm run groth16:check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for component-specific setup and
contribution guidelines.

## License

[MIT](LICENSE)
