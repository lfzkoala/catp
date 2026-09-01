# CATP CLI 0.6.0 Release Checklist

Status: release candidate; local checks passed. Publish from the `v0.6.0` Git
tag after main CI is green.

Package:

```text
@catp-protocol/cli@0.6.0
```

## Release Goal

`0.6.0` consolidates the enforcement, audit, receipt, and on-chain
authorization security fixes made after `0.5.0`. It does not add a new proof
system or expand CATP beyond its current mainline.

## Security Changes

- Policy-enabled pre-hooks fail closed when runtime input, policy loading, or
  audit persistence fails.
- Audit commitment version `3` binds the runtime phase and structured
  authorization action.
- Concurrent audit appends are serialized so they cannot fork the local chain.
- Audit agent ids are constrained before they are used in filesystem paths.
- Authorization receipts can be issued only from pre-enforcement decisions.
- Receipt verification requires an externally supplied trusted Ed25519 public
  key instead of trusting the key embedded in the receipt.
- Audit anchoring exports a verified `catp_audit_anchor_v1` bundle and no longer
  treats an audit root as an authorization policy commitment.
- `AgentAuthorizer` binds every policy to an executor, rejects other callers,
  and prevents delegator takeover after revocation.

## Deployment And Proof Compatibility

- Proof version remains `authorization_groth16_v1`.
- Public input layout, setup keys, circuit constraints, and verifier source are
  unchanged.
- Existing audit commitment versions `1` and `2` remain verifiable; new entries
  use version `3`.
- Existing receipt files remain structurally valid, but verification now
  requires `--public-key <trusted-public-key.pem>`.
- The old Sepolia `AgentAuthorizer` ABI is superseded by the executor-bound
  deployment recorded in `catp-contracts/deployments/sepolia-groth16.json`.
- The current Sepolia deployment has passed policy registration and real
  Groth16 proof execution smoke testing.

## Pre-Publish Checklist

Run from the repository root:

```bash
bash check.sh
npm run groth16:check
npm run smoke:receipt
npm run build --workspace catp-plugin
npm_config_cache=/private/tmp/catp-npm-cache \
  npm pack --dry-run --workspace catp-plugin
```

## Local Package Smoke Test

```bash
rm -rf /tmp/catp-0.6.0
mkdir -p /tmp/catp-0.6.0

npm pack \
  --workspace catp-plugin \
  --pack-destination /tmp/catp-0.6.0

npm install -g \
  --prefix /tmp/catp-0.6.0/install \
  /tmp/catp-0.6.0/catp-protocol-cli-0.6.0.tgz

PATH="/tmp/catp-0.6.0/install/bin:$PATH" catp --version
PATH="/tmp/catp-0.6.0/install/bin:$PATH" catp hook runtimes
PATH="/tmp/catp-0.6.0/install/bin:$PATH" catp receipt verify --help
PATH="/tmp/catp-0.6.0/install/bin:$PATH" catp verify authorization --help
```

## Publish

Do not publish this version manually. Push the release commit to `main`, wait
for CI, then trigger the release workflow with the matching tag:

```bash
git tag -a v0.6.0 -m "CATP CLI v0.6.0"
git push origin v0.6.0
```

The release workflow checks that the package and tag versions match, runs the
CLI checks, and publishes to npm with provenance. After it succeeds, verify a
fresh registry install before marking this document released.
