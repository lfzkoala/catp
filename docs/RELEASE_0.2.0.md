# CATP CLI 0.2.2 Release Notes

Package:

```text
@catp-protocol/cli@0.2.2
```

`0.2.2` is the current published patch release for the `0.2.x` MVP line. It
keeps the npm package focused on the installable CLI surface while folding in
the hardening and proof UX work completed after `0.2.1`.

## Why This Release

This release publishes the updated CATP CLI surface for local enforcement,
tamper-evident audit logs, authorization proof manifests, and audit-linked
manifest validation. CATP remains authorization/audit-first; Groth16 is the
current optional EVM verification backend.

The npm package is intended for:

- Claude Code hook enforcement.
- TOML policy validation.
- Tamper-evident audit log viewing and verification.
- Authorization witness generation.
- Proof manifest generation from an existing authorization proof artifact.
- Proof manifest structural validation.
- Audit-linked proof manifest validation.
- Runtime adapter hook entrypoints for Claude Code.

Full Groth16 proof generation from `--action` or `--audit-commitment` is
available as the current EVM verifier backend, but still requires a repository
checkout because it depends on:

- `scripts/generate-groth16-verifier.sh`
- `catp-circuits/groth16`
- the Go/Gnark prover toolchain

## User-Facing Changes

Published in `0.2.1`:

- Added `catp prove authorization`.
- Added `catp verify authorization`.
- Added audit-linked proof manifest support.
- Added `catp verify authorization --check-audit`.
- Added `catp prove authorization --deployment` to read verifier metadata from
  deployment JSON.
- Fixed `catp --version` to report the published package version.

Published in `0.2.2`:

- `catp verify authorization --check-audit` now checks that the audit entry's
  structured authorization action matches the manifest action data, value,
  timestamp, and cumulative spend when those fields are present.
- Manifest validation now checks 13 public inputs, 128-byte ABI `actionData`,
  256-byte Groth16 proof bytes, and consistency between `actionData` and public
  action fields.
- Manifest `proofUrl` is restricted to HTTPS, IPFS, Arweave, or localhost HTTP.
- Deployment metadata is rejected if `authorizationProofVersion` does not match
  `authorization_groth16_v1`.
- The calldata encoder validates the same contract-facing artifact shape before
  emitting `registerPolicy` / `executeAuthorized` calldata.
- `catp witness --out` prints a ready-to-edit `proveCommand=...` line.
- `catp prove authorization --out` prints a ready-to-run `verifyCommand=...`
  line, including `--check-audit` for audit-linked manifests.
- Claude Code hook commands now accept `--runtime claude-code`, and
  `catp hook runtimes` lists supported runtime adapters.
- Package boundaries are documented: npm CLI remains light; full Groth16
  proving, calldata encoding, execution, contracts, and setup checks remain
  repository-based.
- The release was verified from a fresh global npm install with
  `catp --version`, `catp hook runtimes`, `catp init`, `catp validate`,
  `catp log verify`, and authorization proof help commands.

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

Expected package contents include:

```text
dist/cli.js
dist/commands/authorization.js
dist/commands/witness.js
dist/audit/*
dist/adapters/*
dist/enforcement/*
dist/hook/*
dist/policy/*
dist/runtime/*
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
npm install -g @catp-protocol/cli@0.2.2
catp --version
catp hook runtimes
catp init
catp validate
catp prove authorization --help
catp verify authorization --help
```
