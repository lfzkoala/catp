# CATP CLI 0.7.2 Release Checklist

Status: released, superseded by `0.7.3`. Published from the `v0.7.2`
Git tag through npm Trusted Publishing. The fresh registry install
verification uncovered a pre-existing engine gap: command glob patterns
(micromatch path semantics) never matched commands containing absolute paths,
so template deny rules like `rm -rf*` were silently inert there. Fixed in
`0.7.3` (see `docs/SECURITY_AUDIT_2026-09.md`, finding 8). Users should skip
`0.7.2` and install `0.7.3`.

Package:

```text
@catp-protocol/cli@0.7.2
```

## Release Goal

`0.7.2` ships the fixes from the 2026-09 self security audit
(`docs/SECURITY_AUDIT_2026-09.md`): CLI hardening, honest policy-matching
semantics, and a safer default policy template. CI/release workflow and
deployment-script hardening are repository-side and ship alongside.

## Changes Since 0.7.1

CLI (`catp-plugin`):

- Hook stdin reads are bounded: 1 MiB byte cap and a 10 s deadline
  (`hook.stdin.unbounded-buffer`). Oversize or slow payloads fail closed on
  the pre-hook instead of buffering indefinitely.
- Audit tail recovery reads only the last 64 KiB of the daily JSONL file
  (constant-space) instead of scanning the whole file on every append
  (`audit.tail.whole-file-scan`).
- Policy path rules normalize `.`/`..` dot segments on both the reported path
  and allow/denylist patterns before matching (`policy.path.canonical-target`).
- The `catp init` template ships a leading control-operator deny rule
  (`&&`, `;`, `|`, backtick, `$(`) so command allow prefixes cannot be chained
  into other commands (`policy.command.shell-equivalence`).

Repository:

- `release.yml`: dispatch tag input is validated, checkout is restricted to
  `refs/tags/`, HEAD is verified against the tag commit, and actions are pinned
  by digest.
- `deploy-groth16-sepolia.sh`: chain id must equal 11155111 before broadcast,
  deployed bytecode is compared against local build artifacts, and recorded
  keccak hashes are computed locally (now including `AgentAuthorizer`).
- Contracts tests pin `registerPolicy` first-writer squatting behavior; the
  property is documented in `docs/AUTHORIZATION_SECURITY_NOTES.md`.
- README / ARCHITECTURE state command and path matching semantics honestly;
  `examples/receipt-basic` policy ships the control-operator deny rule.

## Deployment And Proof Compatibility

- Proof version remains `authorization_groth16_v1`.
- Setup keys, circuit constraints, and verifier source are unchanged.
- Existing audit logs (commitment versions `1`-`3`) remain verifiable; the
  commitment scheme is unchanged.
- Existing `catp-policy.toml` files remain valid. The path dot-segment
  normalization only tightens matching; policies relying on `..` segments to
  match were relying on undefined behavior.

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

## Publish

Do not publish this version manually. Push the matching tag after main CI
passes; the release workflow publishes through npm Trusted Publishing:

```bash
git tag -a v0.7.2 -m "CATP CLI v0.7.2"
git push origin v0.7.2
```

The workflow validates the tag, checks out `refs/tags/v0.7.2`, verifies HEAD
matches the tag commit, checks that the package and tag versions agree, runs
the CLI checks, and skips publishing if the version already exists on the
registry. After it succeeds, verify a fresh registry install before marking
this document released.
