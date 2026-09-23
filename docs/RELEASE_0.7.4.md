# CATP CLI 0.7.4 Release Checklist

Status: **prepared, pending publish authorization.** The release commit, local
packed tarball, and this document are ready. The release gate has NOT been
crossed: the release commit has not been pushed, the package has not been
published through npm Trusted Publishing, and the annotated tag `v0.7.4` has not
been created. Those three external state changes require explicit authorization.

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

## Local Packed Tarball Provenance

Packed from the release candidate working tree into an isolated temporary
directory (the tarball is not committed):

```text
filename:        catp-protocol-cli-0.7.4.tgz
sha256:          62f942f0136234210e30621eb5f7103cf02725269f92d854383ae11390d715b9
npm shasum (sha1): c52321380112e7d43604669c49d6353a1ac2b4a6
size:            70103 bytes (70.1 kB packed, 323.4 kB unpacked)
file count:      113
manifest sha256: e2b6b29c4e0e5ae002d787411a42cec3f413374982c5ab8632c053769a4965a5
                 (sha256 of the sorted file list below)
```

The registry may repack the tarball, so the published tarball SHA-256 can differ
from the local one. In that case both hashes are recorded and the unpacked file
manifests and contents must be proven to match (compare the manifest sha256
above against the registry tarball's sorted file list).

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
dist/adapters/registry.d.ts
dist/adapters/registry.d.ts.map
dist/adapters/registry.js
dist/adapters/registry.js.map
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
dist/commands/event.d.ts
dist/commands/event.d.ts.map
dist/commands/event.js
dist/commands/event.js.map
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
dist/runtime/validate.d.ts
dist/runtime/validate.d.ts.map
dist/runtime/validate.js
dist/runtime/validate.js.map
package.json
```

## Publish (PENDING AUTHORIZATION)

Do not publish this version manually. The release workflow publishes through npm
Trusted Publishing (OIDC, `id-token: write`) when the matching tag is pushed.
These steps are blocked at the release gate until explicitly authorized:

```bash
# 1. push the release commit (requires authorization)
git push origin main

# 2. create and push the annotated tag after main CI passes (requires authorization)
git tag -a v0.7.4 -m "CATP CLI v0.7.4"
git push origin v0.7.4
```

The release workflow validates that the tag version equals
`catp-plugin/package.json` version (`0.7.4`) and that the checked-out commit
matches the tag commit before publishing.

## Post-Publish Verification (PENDING)

To be completed only after the registry package exists, then recorded here and
committed as `docs: record verified 0.7.4 publication`:

- [ ] Query the registry for `@catp-protocol/cli@0.7.4`; download its tarball
      into an isolated temporary directory; verify its SHA-256, npm shasum, and
      package version. If the registry repacked the tarball, record both the
      local and registry SHA-256 and prove the unpacked file manifests match the
      manifest sha256 above.
- [ ] Fresh-install smoke test with an isolated `CATP_HOME`: issue and verify a
      v2 receipt end-to-end and retain the command transcript.
- [ ] Verify `git rev-list -n 1 v0.7.4` equals the release commit hash.

## Release Gate

Do not begin the paper experiment rerun (Phase 5) until the registry tarball,
tag, release commit, and local packed tarball have an auditable relationship.
Until publish/tag authorization is granted, this release stops here.
