# CATP CLI 0.7.4 Release Checklist

Status: **released and verified.** Published from the `v0.7.4` Git tag through
npm Trusted Publishing (Release workflow run `35846548362`, conclusion
`success`). The registry tarball was downloaded into an isolated temporary
directory and its version, SHA-256, sha1 (`dist.shasum`), and unpacked file
manifest were verified against a clean local build; a fresh-install smoke test
with an isolated `CATP_HOME` issued and verified a v2 receipt end-to-end.

Release commit: `86eff07ce674aa5c180ce7f8a831bc85646ac976`. Tag `v0.7.4` points
at the same commit (`git rev-list -n 1 v0.7.4` ==
`86eff07ce674aa5c180ce7f8a831bc85646ac976`). Main CI on the release commit
(run `35846285993`) and the tag Release run both concluded `success`.

Package:

```text
@catp-protocol/cli@0.7.4
```

## Release Goal

`0.7.4` is the enforcement-evidence security convergence release. It binds every
recorded decision to the exact policy and the complete action it was evaluated
against, makes that evidence durable before it can be relied on, and fails closed
when the evidence cannot be persisted. It also introduces self-contained v2 audit
exports and v2 authorization receipts whose policy/action bindings are copied
verbatim from the enforcement-time audit entry.

This is the fixed release the paper experiments are pinned to. See
`docs/superpowers/plans/2026-09-23-paper-security-remediation.md` (Phases 1-4)
and the `Enforcement-Time Evidence And Durability` section of
`IMPLEMENTATION_PLAN.md`.

## Intentional Format Changes

- **v4 audit entries.** New audit entries use commitment version `4`, a
  domain-separated (`catp:audit-entry:v4`) SHA-256 commitment that binds the
  enforcement-time `policy_commitment` (`catp:policy:v1` over the normalized
  policy) and the `action_commitment` (`catp:action:v1` over the complete
  normalized action), together with phase (`pre`/`post`), reason, the
  display-only `input_summary`, the previous commitment, and any structured
  authorization action.
- **Durable content-addressed action sidecar.** The complete canonical action is
  written as a content-addressed sidecar (fsync'd, newly created directories
  persisted) before the audit entry is appended, under the same per-agent,
  per-day lock. The append path re-checks that the sidecar action hashes to the
  entry's `action_commitment`.
- **Fail-closed pre-hook.** An action-sidecar write, audit append, or fsync
  failure returns exit code `2` with a block response on both stdout and stderr,
  records nothing, and does not allow the action to execute.
- **v2 self-contained audit export (`catp_audit_export_v2`).** Carries the entry
  prefix plus the complete action sidecar, hash-chained and re-verifiable
  offline.
- **v2 authorization receipt (`catp_authorization_receipt_v2`).** Copies
  `policy_commitment` and `action_commitment` verbatim from the selected
  enforcement-time v4 entry. `--file` only checks that a candidate policy hashes
  to the already-recorded `policy_commitment`; bindings are never regenerated
  from the current policy file at signing time.
- **Legacy verification support retained.** Audit logs at commitment versions
  `1`-`3` and `catp_authorization_receipt_v1` receipts remain verifiable.
- **No legacy upgrade to strong receipts.** A legacy (non-v4) entry cannot be
  issued as a v2 receipt with enforcement-time bindings; issuance refuses such
  entries rather than silently weakening the guarantee.

## Deployment And Proof Compatibility

- Proof version remains `authorization_groth16_v1`; setup keys, circuit, and
  verifier source are unchanged (`npm run groth16:check` reports the setup
  manifest and deployment metadata as ok).
- Audit logs at commitment versions `1`-`3` remain verifiable; only newly
  written entries use version `4`.
- Existing `catp-policy.toml` files remain valid; the command/path glob
  semantics shipped in `0.7.3` are unchanged.

## Pre-Publish Checklist

Run from the repository root. All commands were green on the release candidate:

```bash
bash check.sh                                # All checks passed
npm run groth16:check                        # setup manifest + deployment metadata ok
npm run smoke:receipt                        # receiptSmoke=ok
npm run build --workspace catp-plugin        # exit 0 (@catp-protocol/cli@0.7.4)
npm_config_cache=/private/tmp/catp-npm-cache \
  npm pack --dry-run --workspace catp-plugin  # 113 files, 70.1 kB packed
```

Additional CLI verification (from `catp-plugin`):

```bash
npm run typecheck        # exit 0
npm test -- --runInBand  # 316 passed
npm run test:coverage    # 316 passed; 91.08/82.48/99.43/91.43
```

## Tarball Provenance And Reconciliation

The **registry tarball is authoritative** for the paper experiments. It was
published by the Release workflow from a fresh checkout of tag `v0.7.4` and
downloaded back for verification:

```text
source:          https://registry.npmjs.org/@catp-protocol/cli/-/cli-0.7.4.tgz
version:         0.7.4
sha256:          b4da728f43ee9e36d2c035d756de04d3b1ea7a6f93c355ab9c4ca5728077c0d3
sha1 (dist.shasum): 3cba3c282ba2a234e749f19db76060cb606f1ffc
integrity (sha512): sha512-w04iZPqPz8u3fSkbXTLVZNhJlsnAuXZ+ExrVvqTv5mfQTINZZ+hQjRfq4D7PoarvSHvtIKaHw8xNAXPmCWIcaQ==
size:            67189 bytes
unpacked size:   310239 bytes
file count:      101
manifest sha256: 56f4222ba4d3c4bd3e7d1350f2d8205bfeef38ff89a215e93c11225876d0fdc4
                 (sha256 of the sorted file list below)
```

The downloaded tarball's sha1 equals the registry `dist.shasum`, confirming an
authentic, unmodified download.

### Reconciliation with the local build

The first local `npm pack` of the release candidate produced a 113-file tarball
(sha256 `62f942f0136234210e30621eb5f7103cf02725269f92d854383ae11390d715b9`,
manifest sha256 `e2b6b29c4e0e5ae002d787411a42cec3f413374982c5ab8632c053769a4965a5`).
The 12 extra files were stale `tsc` outputs in the local `dist/` for three
modules that no longer exist in `src/` (`adapters/registry`, `commands/event`,
`runtime/validate`); `tsc` does not prune removed modules, and the fresh CI
checkout correctly omitted them. After deleting those 12 stale artifacts, a clean
local repack matches the registry exactly:

```text
clean local repack sha256:  7272ff221e4907f03c4a4823ae86fc76db2e6059ab6cd4d1e9c33474da349267
clean local repack size:    67264 bytes
clean local file count:     101
clean local manifest sha256: 56f4222ba4d3c4bd3e7d1350f2d8205bfeef38ff89a215e93c11225876d0fdc4  (IDENTICAL to registry)
```

The packed tarball bytes differ from the registry's (npm repacks with its own
tar metadata/timestamps), so the SHA-256 values legitimately differ. The unpacked
file manifests are identical (same manifest sha256), and all 101 unpacked files
are byte-identical between the registry tarball and the clean local build
(`content_diffs=0`, `local_missing=0`, `package.json` identical). The 101 files
are exactly the 25 current `src/` modules x 4 build outputs (.js, .js.map,
.d.ts, .d.ts.map) plus `package.json`.

Complete file list (sorted, `package/` prefix stripped):

```text
dist/adapters/claude-code.d.ts
dist/adapters/claude-code.d.ts.map
dist/adapters/claude-code.js
dist/adapters/claude-code.js.map
dist/adapters/codex.d.ts
dist/adapters/codex.d.ts.map
dist/adapters/codex.js
dist/adapters/codex.js.map
dist/adapters/index.d.ts
dist/adapters/index.d.ts.map
dist/adapters/index.js
dist/adapters/index.js.map
dist/audit/durable.d.ts
dist/audit/durable.d.ts.map
dist/audit/durable.js
dist/audit/durable.js.map
dist/audit/logger.d.ts
dist/audit/logger.d.ts.map
dist/audit/logger.js
dist/audit/logger.js.map
dist/audit/paths.d.ts
dist/audit/paths.d.ts.map
dist/audit/paths.js
dist/audit/paths.js.map
dist/audit/verifier.d.ts
dist/audit/verifier.d.ts.map
dist/audit/verifier.js
dist/audit/verifier.js.map
dist/cli.d.ts
dist/cli.d.ts.map
dist/cli.js
dist/cli.js.map
dist/commands/anchor.d.ts
dist/commands/anchor.d.ts.map
dist/commands/anchor.js
dist/commands/anchor.js.map
dist/commands/authorization.d.ts
dist/commands/authorization.d.ts.map
dist/commands/authorization.js
dist/commands/authorization.js.map
dist/commands/init.d.ts
dist/commands/init.d.ts.map
dist/commands/init.js
dist/commands/init.js.map
dist/commands/log.d.ts
dist/commands/log.d.ts.map
dist/commands/log.js
dist/commands/log.js.map
dist/commands/receipt.d.ts
dist/commands/receipt.d.ts.map
dist/commands/receipt.js
dist/commands/receipt.js.map
dist/commands/validate.d.ts
dist/commands/validate.d.ts.map
dist/commands/validate.js
dist/commands/validate.js.map
dist/commands/witness.d.ts
dist/commands/witness.d.ts.map
dist/commands/witness.js
dist/commands/witness.js.map
dist/enforcement/core.d.ts
dist/enforcement/core.d.ts.map
dist/enforcement/core.js
dist/enforcement/core.js.map
dist/evidence/canonical.d.ts
dist/evidence/canonical.d.ts.map
dist/evidence/canonical.js
dist/evidence/canonical.js.map
dist/evidence/commitments.d.ts
dist/evidence/commitments.d.ts.map
dist/evidence/commitments.js
dist/evidence/commitments.js.map
dist/hook/post.d.ts
dist/hook/post.d.ts.map
dist/hook/post.js
dist/hook/post.js.map
dist/hook/pre.d.ts
dist/hook/pre.d.ts.map
dist/hook/pre.js
dist/hook/pre.js.map
dist/hook/runtime.d.ts
dist/hook/runtime.d.ts.map
dist/hook/runtime.js
dist/hook/runtime.js.map
dist/policy/engine.d.ts
dist/policy/engine.d.ts.map
dist/policy/engine.js
dist/policy/engine.js.map
dist/policy/loader.d.ts
dist/policy/loader.d.ts.map
dist/policy/loader.js
dist/policy/loader.js.map
dist/policy/types.d.ts
dist/policy/types.d.ts.map
dist/policy/types.js
dist/policy/types.js.map
dist/runtime/types.d.ts
dist/runtime/types.d.ts.map
dist/runtime/types.js
dist/runtime/types.js.map
package.json
```

## Publish (COMPLETED)

Published through npm Trusted Publishing (OIDC, `id-token: write`), triggered by
pushing the annotated tag. No ad-hoc local npm credential flow was used:

```bash
git push origin main                         # be99b15..86eff07
git tag -a v0.7.4 -m "CATP CLI v0.7.4"
git push origin v0.7.4                       # triggered Release run 35846548362
```

The Release workflow validated that the tag version equals
`catp-plugin/package.json` version (`0.7.4`) and that the checked-out commit
matched the tag commit, then ran typecheck + tests + build and published
`@catp-protocol/cli@0.7.4` (run conclusion `success`).

## Post-Publish Verification (COMPLETED)

- [x] Registry query for `@catp-protocol/cli@0.7.4`: version `0.7.4`; tarball
      downloaded into an isolated temporary directory; sha256
      `b4da728f43ee9e36d2c035d756de04d3b1ea7a6f93c355ab9c4ca5728077c0d3`, sha1
      `3cba3c282ba2a234e749f19db76060cb606f1ffc` (== `dist.shasum`), 101 files,
      unpacked 310239 bytes. The registry repacked the tarball, so both the
      registry and clean-local SHA-256 are recorded above and their unpacked
      file manifests are proven identical (manifest sha256
      `56f4222ba4d3c4bd3e7d1350f2d8205bfeef38ff89a215e93c11225876d0fdc4`) with
      all 101 files byte-identical.
- [x] Fresh-install smoke test with an isolated `CATP_HOME`: installed
      `@catp-protocol/cli@0.7.4` into an isolated prefix; `catp --version`
      reported `0.7.4`; resolved executable realpath
      `<prefix>/lib/node_modules/@catp-protocol/cli/dist/cli.js` (sha256
      `507662ce91e936e8fb07cb08de674462ff77b8c19228cbe634245db2bbe77b9a`);
      `scripts/smoke-receipt.sh` driven by that binary printed
      `receiptSmoke=ok`, issuing a `catp_authorization_receipt_v2` receipt
      (phase `pre`, Ed25519) whose verify summary reported
      `authorizationReceipt=valid`, `auditExport=matched`, `policy=matched`,
      `assurance=enforcement-time-bound`.
- [x] `git rev-list -n 1 v0.7.4` == `86eff07ce674aa5c180ce7f8a831bc85646ac976`
      == the release commit.

## Release Gate

Crossed. The registry tarball, tag `v0.7.4`, release commit `86eff07`, and the
clean local packed tarball now have a complete auditable relationship (identical
unpacked manifest sha256 and byte-identical contents; tag == commit). Phase 5
experiment reruns may pin to `@catp-protocol/cli@0.7.4` using the registry
tarball sha256 `b4da728f43ee9e36d2c035d756de04d3b1ea7a6f93c355ab9c4ca5728077c0d3`.

## Process Deviation (recorded, not rewritten)

The sequence above was tag-before-verification. The annotated tag `v0.7.4` was
created and pushed first; pushing it triggered the Release workflow that ran
typecheck + tests + build and published to npm. The registry-tarball download,
SHA-256/sha1/manifest comparison, and the fresh-install smoke test were then
performed AFTER publication. The release succeeded and every check passed, but
the verification was post-hoc rather than a gate that had to pass before the
immutable artifact already existed on the registry.

This is recorded honestly and the history above is left unchanged. Future
releases (starting with `0.7.5`) run the full verification on the release commit
BEFORE tagging and publishing (verify-before-tag), so a failing check prevents
the publish instead of being discovered afterward. See `docs/RELEASE_0.7.5.md`.
