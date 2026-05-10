# CATP CLI 0.2.0 Release Notes

Package:

```text
@catp-protocol/cli@0.2.0
```

## Why This Release

This release publishes the updated CATP CLI surface for local enforcement,
authorization proof manifests, and audit-linked manifest validation.

The npm package is intended for:

- Claude Code hook enforcement.
- TOML policy validation.
- Tamper-evident audit log viewing and verification.
- Authorization witness generation.
- Proof manifest generation from an existing Groth16 artifact.
- Proof manifest structural validation.
- Local audit log presence checks for audit-linked manifests.

Full Groth16 proof generation from `--action` or `--audit-commitment` still
requires a repository checkout because it depends on:

- `scripts/generate-groth16-verifier.sh`
- `catp-circuits/groth16`
- the Go/Gnark prover toolchain

## User-Facing Changes

- Added `catp prove authorization`.
- Added `catp verify authorization`.
- Added audit-linked proof manifest support.
- Added `catp verify authorization --check-audit`.
- Added `catp prove authorization --deployment` to read verifier metadata from
  deployment JSON.

## Pre-Publish Checklist

Run from the repository root:

```bash
npm run typecheck --workspace catp-plugin
npm test --workspace catp-plugin
npm run build --workspace catp-plugin
npm_config_cache=/private/tmp/catp-npm-cache npm pack --dry-run --workspace catp-plugin
```

Expected package contents include:

```text
dist/cli.js
dist/commands/authorization.js
dist/commands/witness.js
dist/audit/*
dist/hook/*
dist/policy/*
package.json
```

## Publish

Publishing requires npm authentication with permission to publish
`@catp-protocol/cli`:

```bash
cd catp-plugin
npm publish --access public
```

After publishing:

```bash
npm view @catp-protocol/cli version
npm install -g @catp-protocol/cli@0.2.0
catp --version
```
