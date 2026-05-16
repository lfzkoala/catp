# CATP Installation Guide

CATP has two installation paths:

- npm install for local enforcement, audit logs, witness generation, and proof
  manifest tooling.
- repository checkout for full Groth16 proving, Sepolia execution, contracts,
  circuits, and protocol development.

## Requirements

For npm CLI usage:

- Node.js `>=20`
- Claude Code, if you want hook-based local enforcement

For the full proof/development flow:

- Node.js `>=20`
- Rust toolchain from `rust-toolchain.toml`
- Go, for the Groth16/Gnark prover path
- Foundry, for Solidity contract tests/deployment
- `jq` and `cast`, for calldata/execution scripts

## Option A: npm CLI Install

Use this path if you want CATP local enforcement and audit-log tooling.

```bash
npm install -g @catp-protocol/cli@0.2.1
catp --version
```

The npm package includes:

- `catp init`
- `catp validate`
- `catp hook pre`
- `catp hook post`
- `catp log show`
- `catp log verify`
- `catp witness`
- `catp prove authorization` for existing proof artifacts
- `catp verify authorization`

The npm package does not bundle the full Groth16 prover stack. Full proof
generation from `--action` or `--audit-commitment` requires a repository
checkout because it depends on `scripts/`, `catp-circuits/groth16`, and the
Go/Gnark toolchain.

### Wire Claude Code Hooks

Add CATP to `~/.claude/settings.json`:

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

Then initialize CATP in a project:

```bash
cd your-project
catp init
catp validate
```

For a starter policy that also includes authorization proof fields:

```bash
catp init --authorization
catp validate
```

Check audit logs:

```bash
catp log show
catp log verify
```

### npm CLI Smoke Test

Use a temporary directory:

```bash
mkdir -p /tmp/catp-user-test
cd /tmp/catp-user-test
export CATP_HOME="$PWD/.catp-home"
catp init
catp validate
catp log verify
catp prove authorization --help
catp verify authorization --help
```

This confirms the installed CLI is available and the local policy/audit surface
works without a repository checkout. `CATP_HOME` keeps the smoke test isolated
from any existing audit logs under `~/.catp`.

The `0.2.1` npm smoke test has been verified with:

```text
catp --version
catp init
catp validate
catp log verify
catp prove authorization --help
catp verify authorization --help
```

## Option B: Repository Checkout

Use this path if you want the full authorization proof flow or you are developing
CATP itself.

```bash
git clone https://github.com/lfzkoala/catp.git
cd catp
bash install.sh
```

`install.sh` installs dependencies, builds `catp-plugin`, and symlinks `catp`
to a user-accessible bin directory.

If `catp` is not found after install, add `~/.local/bin` to your PATH:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

For bash:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

Run basic checks:

```bash
npm run typecheck --workspace catp-plugin
npm test --workspace catp-plugin
npm run build --workspace catp-plugin
npm run groth16:check
```

## Full Groth16 Proof Flow

From a repository checkout, create or provide an authorization action and run:

```bash
catp prove authorization \
  --action action.json \
  --current-timestamp 1778042846 \
  --cumulative-spend 0 \
  --artifact-out authorization_groth16_v1.json \
  --deployment catp-contracts/deployments/sepolia-groth16.json \
  --out catp-proof-manifest.json
```

Validate the manifest:

```bash
catp verify authorization --manifest catp-proof-manifest.json
```

When `catp prove authorization --out <manifest>` succeeds, the command prints a
ready-to-run `catp verify authorization --manifest ...` line. If the manifest is
linked to an audit commitment, the suggested command includes `--check-audit`.

For audit-linked manifests:

```bash
catp verify authorization \
  --manifest catp-proof-manifest.json \
  --check-audit
```

If you are starting from an audit log entry, run:

```bash
catp witness --audit-commitment <commitment> --out witness.json
```

The witness summary prints a ready-to-edit `proveCommand=catp prove
authorization ...` line that preserves the same audit source.

`--check-audit` verifies that the audit commitment exists for the recorded audit
agent and that the audit entry's structured authorization action matches the
manifest action data, value, timestamp, and cumulative spend when those fields
were recorded in the audit entry.

For the complete Sepolia flow, see
[`docs/E2E_GROTH16_SEPOLIA.md`](E2E_GROTH16_SEPOLIA.md).

For a minimal policy/action fixture, see
[`examples/authorization-basic`](../examples/authorization-basic).

## Troubleshooting

If `npm pack` or `npm publish` fails with local cache permissions, use a
temporary npm cache:

```bash
npm_config_cache=/private/tmp/catp-npm-cache npm pack --dry-run --workspace catp-plugin
```

If `catp prove authorization --action` fails from a global npm install, use a
repository checkout. That command path needs the prover scripts and circuit
assets that are intentionally not bundled into the npm CLI package.

Run it from the repository root, or pass `--prover-script <path>` if you keep
the Groth16 prover script elsewhere.
