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
npm install -g @catp-protocol/cli@0.7.5
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

For OpenAI Codex CLI, enable hooks in `$CODEX_HOME/config.toml`
(`[features] hooks = true`) and wire `~/.codex/hooks.json`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "hooks": [{ "type": "command", "command": "catp hook pre --runtime codex" }]
    }],
    "PostToolUse": [{
      "hooks": [{ "type": "command", "command": "catp hook post --runtime codex" }]
    }]
  }
}
```

See [docs/INSTALL.md](docs/INSTALL.md) for the full setup, including the Codex
`/hooks` trust step and the enforcement surface each runtime supports.

Check supported runtime adapters:

```bash
catp hook runtimes
```

Built-in adapters are `claude-code` and `codex`. The enforcement core is
runtime-neutral; future runtimes should map their tool events into CATP
`ToolAction` events.

The pre-hook is inactive when no `catp-policy.toml` is found. Once a policy is
discovered, CATP blocks the action if the hook payload or policy is invalid, or
if the audit decision cannot be appended safely.

## Policy

CATP policies are TOML files. Rules are evaluated top-to-bottom; first match
wins. Unmatched tools are allowed by default.

Command patterns match the raw command string as a shell-style glob (`*`
matches any characters including `/`, `?` matches one) or as a plain substring;
CATP does not parse shell syntax. A prefix allow rule such as `echo*` therefore
also matches compound commands like `echo hi && rm -rf ~`. If you allowlist
shell commands, place a control-operator deny rule first:

```toml
[[rules]]
tool = "Bash"
allow = false
pattern = ["&&", ";", "|", "`", "$("]
reason = "Compound shell commands are blocked"
```

Path rules normalize `.`/`..` dot segments before matching, but they operate on
the path reported by the runtime, not the filesystem, so symlinks are not
resolved.

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

Receipts use `catp_authorization_receipt_v2` and Ed25519 signatures. The signed
body copies the enforcement-time bindings verbatim from the selected
pre-enforcement v4 audit entry — the audit commitment, the policy commitment,
and the action commitment (a digest over the complete canonical action, not the
display summary) — together with the audit-export bundle hash, agent id, tool,
decision, phase, matched rule, reason, timestamp, and the issuer key id (a
digest of the signer's public key). Verification requires a separately obtained
trusted public key (the issuer key id must match it; a key embedded in a receipt
is signed data, not a trust anchor) **and** the `catp_audit_export_v2` bundle via
`--audit-export`, which is mandatory for v2: without it `receipt verify` exits
non-zero rather than report `assurance=enforcement-time-bound`. Only after the
signature, the export bundle (export hash, chain prefix, selected entry, and
complete action), and any `--file` policy evidence all verify does a v2 receipt
report enforcement-time-bound assurance. Legacy `catp_authorization_receipt_v1`
receipts are still accepted, keep their historical optional-export semantics,
and are labelled `assurance=legacy`.

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
