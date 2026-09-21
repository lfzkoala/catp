# CATP CLI 0.7.3 Release Checklist

Status: released. Published from the `v0.7.3` Git tag through npm Trusted
Publishing. A fresh registry install was verified in an isolated temporary
directory (tarball shasum `711eeb47…` matched the registry; version,
runtimes, and — with the default `catp init` template — deny of `rm -rf
/tmp/whatever`, allow of `ls -la`, deny of the compound `echo hi && rm -rf
~`, deny of a dot-segment write outside the allowlist, and audit chain verify
all passed).

Package:

```text
@catp-protocol/cli@0.7.3
```

## Release Goal

`0.7.3` fixes a pre-existing policy engine gap uncovered during the `0.7.2`
registry install verification: command `pattern` globs were evaluated with
micromatch path semantics, where `*` does not cross `/`. Deny patterns shipped
in the README and the `catp init` template (for example `rm -rf*`) therefore
never matched commands containing absolute paths such as `rm -rf /tmp/x`.

See `docs/SECURITY_AUDIT_2026-09.md`, finding 8.

## Changes Since 0.7.2

- Command patterns now use a dedicated shell-style glob compiled to an
  anchored regex: `*` matches any run of characters including `/` and
  newlines, `?` matches one character, and regex metacharacters in patterns
  are escaped. The substring matching arm is unchanged.
- Path allow/denylist rules keep micromatch segment-aware semantics (correct
  for file paths).
- README / ARCHITECTURE updated with the precise command glob semantics.
- New `command glob semantics` test suite (absolute paths, embedded
  destructive commands, literal operators, multi-line commands, `?`,
  metacharacter escaping). 218 CLI tests total.

## Behavior Change Notice

- Deny globs that were silently inert against absolute-path commands now fire
  (fail-safe direction).
- Allow globs containing `*` can match more commands than before. A policy
  relying on the broken segment semantics for an allow rule would need review;
  no shipped template or example relies on it.

## Deployment And Proof Compatibility

- Proof version remains `authorization_groth16_v1`; setup keys, circuit, and
  verifier source are unchanged.
- Audit logs (commitment versions `1`-`3`) remain verifiable; the commitment
  scheme is unchanged.
- Existing `catp-policy.toml` files remain valid; see the behavior change
  notice above.

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
git tag -a v0.7.3 -m "CATP CLI v0.7.3"
git push origin v0.7.3
```

After it succeeds, verify a fresh registry install — including a deny path
against an absolute-path command with the default `catp init` template —
before marking this document released.
