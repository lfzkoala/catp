# CATP CLI 0.3.0 Release Checklist

Package:

```text
@catp-protocol/cli@0.3.0
```

## Release Goal

`0.3.0` promotes signed authorization receipts to CATP's default external
verification path.

The npm package should support:

- local policy enforcement
- tamper-evident audit logs
- deterministic audit export
- signed authorization receipts
- receipt verification against public key, audit export, and policy commitment
- authorization witness and proof manifest tooling

Groth16 remains an optional advanced verification backend that requires a
repository checkout for full proof generation.

## Pre-Publish Checklist

Run from the repository root:

```bash
npm run typecheck --workspace catp-plugin
npm test --workspace catp-plugin
npm run build --workspace catp-plugin
npm run test --workspace catp-sdk
npm run typecheck --workspace catp-sdk
npm run build --workspace catp-sdk
npm run groth16:check
npm_config_cache=/private/tmp/catp-npm-cache npm pack --dry-run --workspace catp-plugin
```

## Smoke Test

Use a clean temporary directory after installing the published package:

```bash
rm -rf /tmp/catp-user-test
mkdir -p /tmp/catp-user-test
cd /tmp/catp-user-test
export CATP_HOME="$PWD/.catp-home"

catp init
catp validate
catp hook runtimes
catp log verify
catp receipt keygen \
  --private-key catp-receipt-private.pem \
  --public-key catp-receipt-public.pem
catp receipt verify --help
catp prove authorization --help
catp verify authorization --help
```

For a complete receipt issuance path, run
[examples/receipt-basic](../examples/receipt-basic).

## Publish

```bash
cd catp-plugin
npm publish --access public
```

After publishing:

```bash
npm view @catp-protocol/cli version
npm_config_cache=/private/tmp/catp-npm-cache npm install -g @catp-protocol/cli@0.3.0
catp --version
catp hook runtimes
catp receipt verify --help
```
