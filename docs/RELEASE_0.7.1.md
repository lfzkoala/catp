# CATP CLI 0.7.1 Release Checklist

Status: released. Published from the `v0.7.1` Git tag through npm Trusted
Publishing; a fresh registry install was verified in an isolated temporary
directory (version, runtime adapters, codex deny path with stderr reason,
audit chain verify).

Package:

```text
@catp-protocol/cli@0.7.1
```

## Release Goal

`0.7.1` ships the OpenAI Codex CLI runtime adapter plus the blocking-protocol
fix found during real-device smoke testing. `0.7.0` was never published to npm,
so this release covers everything since `0.6.0`.

## Changes Since 0.6.0

- New `codex` runtime adapter: parses Codex CLI `PreToolUse` / `PostToolUse`
  hook payloads, normalizes argv-array `command` values into a single string,
  and registers under `catp hook pre/post --runtime codex`.
- The pre-hook now writes the deny reason to stderr in addition to the stdout
  JSON decision. Codex CLI ignores stdout JSON on non-zero exit and treats
  exit 2 with empty stderr as a hook failure (fail-open), so stderr is the
  blocking channel there; the dual write is also valid for Claude Code.
- Codex setup and enforcement-surface documentation (README, INSTALL,
  ARCHITECTURE) based on real-device observations on Codex v0.155.1.
- Policy engine, audit logger, witness/receipt paths, and commitment version
  `3` are unchanged.

## Deployment And Proof Compatibility

- Proof version remains `authorization_groth16_v1`.
- Setup keys, circuit constraints, and verifier source are unchanged.
- Existing audit logs (commitment versions `1`-`3`) remain verifiable.
- Claude Code behavior is unchanged.

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

## Real-Device Codex Smoke Test

Performed against Codex CLI v0.155.1 with `~/.codex/hooks.json` wired to
`catp hook pre/post --runtime codex`:

- Deny: a `Bash` command matching a deny pattern is blocked with the policy
  reason surfaced by Codex; the audit log records the deny entry.
- Allow: permitted commands are recorded; `catp log verify` reports the chain
  intact.
- File edits: `apply_patch` fires `PreToolUse` / `PostToolUse` with the patch
  text in `tool_input.command`, so file-level deny rules apply on Codex.

## Publish

Do not publish this version manually. Push the matching tag after main CI
passes; the release workflow publishes through npm Trusted Publishing:

```bash
git tag -a v0.7.1 -m "CATP CLI v0.7.1"
git push origin v0.7.1
```

The workflow checks that the package and tag versions match, runs the CLI
checks, and skips publishing if the version already exists on the registry.
After it succeeds, verify a fresh registry install before marking this
document released.
