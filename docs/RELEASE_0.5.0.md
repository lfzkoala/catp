# CATP CLI 0.5.0 Release Checklist

Package:

```text
@catp-protocol/cli@0.5.0
```

## Release Goal

`0.5.0` hardens the audit-linked authorization proof path without changing the
`authorization_groth16_v1` proof boundary or verifier deployment.

## Security Changes

- Audit-linked manifests must bind both `auditCommitment` and `auditAgent`.
- `--audit-agent` is an optional guard and cannot override the manifest agent.
- `catp verify authorization --check-audit` verifies the local audit chain
  before trusting an audit entry.
- Audit-linked verification checks the structured authorization action against
  manifest action data, value, timestamp, and cumulative spend.
- Manifest validation rejects authorization action enum values outside `0..3`,
  even when `actionData` and `publicInputs[1]` agree.

These are stricter validation rules. An older audit-linked manifest without an
`auditAgent` must be regenerated or updated with the correct agent id.

## Proof Compatibility

- Proof version remains `authorization_groth16_v1`.
- Public input layout remains unchanged at 13 values.
- Groth16 setup keys and verifier contracts remain unchanged.
- Sepolia deployment metadata remains valid.

## Pre-Publish Checklist

Run from the repository root:

```bash
npm run typecheck --workspace catp-plugin
npm run build --workspace catp-plugin
npm run test:coverage --workspace catp-plugin
npm run typecheck --workspace catp-sdk
npm run build --workspace catp-sdk
npm run test --workspace catp-sdk
cd catp-contracts
forge build
forge test
cd ..
npm run groth16:check
npm run smoke:receipt
npm_config_cache=/private/tmp/catp-npm-cache npm pack --dry-run --workspace catp-plugin
```

## Local Package Smoke Test

Pack the release candidate, install it into an isolated prefix, and verify the
public CLI surface before publishing:

```bash
npm pack --workspace catp-plugin --pack-destination /tmp/catp-0.5.0
npm install -g \
  --prefix /tmp/catp-0.5.0/install \
  /tmp/catp-0.5.0/catp-protocol-cli-0.5.0.tgz

PATH="/tmp/catp-0.5.0/install/bin:$PATH" catp --version
PATH="/tmp/catp-0.5.0/install/bin:$PATH" catp hook runtimes
PATH="/tmp/catp-0.5.0/install/bin:$PATH" catp verify authorization --help
```

## Publish

```bash
cd catp-plugin
npm publish --access public
```

After publishing, verify the registry package in a clean temporary directory,
then create and push Git tag `v0.5.0`.
