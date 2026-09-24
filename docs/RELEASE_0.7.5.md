# CATP CLI 0.7.5 Release Checklist

Status: **prepared — publish PENDING (not authorized this session).** All code,
test, and documentation fixes are complete and committed, and the full local
verification suite passes on the prepared tree. This release stopped at the
release gate: no `npm publish`, no `git push`, and no remote tag were performed.
The steps below are the exact actions to run once publish authorization is
granted.

Package (prepared, not yet published):

```text
@catp-protocol/cli@0.7.5
```

## Why 0.7.5 (behavior changed vs the immutable 0.7.4)

`0.7.4` is published and immutable. The security review
(`docs/SECURITY_AUDIT_2026-09.md` follow-up) confirmed defects whose fixes
**change CATP runtime behavior**, so the published `0.7.4` artifact no longer
represents current code and a new immutable release is required before the paper
can re-pin:

- **Idempotent durable-write retries skipped the durability barrier** — a retry
  of an identical content-addressed write returned early without re-establishing
  the file + parent-directory fsync barrier.
- **Torn appends had no safe recovery** — a partial write followed by an error
  left an incomplete tail line with no rollback and no repair path.
- **v2 receipt verification accepted a signature-only proof** — `receipt verify`
  reported `assurance=enforcement-time-bound` without requiring the audit export,
  so the enforcement-time policy/action bindings were not actually re-checked.

## Fixes in this release

Behavior changes (require a new immutable artifact):

- **#1 `fix(audit): re-establish fsync barrier on idempotent durable-write
  retries`** — the identical-bytes path in `durableWriteContentAddressed` and
  `durableCreateEmptyFile` now re-runs the file fsync + parent-directory fsync
  before returning, and fails closed if any durability step fails. Covered by
  fault-injection tests in `catp-plugin/tests/audit/durable.test.ts`.
- **#10 `fix(audit): roll back torn appends and add explicit log tail repair`** —
  `durableAppendLine` records the pre-append length and, on a write/fsync
  failure, `ftruncate`s back to it and fsyncs, preserving the original error
  (aggregating any rollback error). A new lock-protected `catp log repair`
  truncates only a non-parseable tail fragment and refuses to delete a complete
  entry whose hash-chain/commitment is wrong. Append stays fail-closed and never
  auto-repairs.
- **#3 `fix(receipt): require --audit-export for v2 receipt verification`** —
  `catp_authorization_receipt_v2` verification now requires `--audit-export` and
  exits non-zero without it; `assurance=enforcement-time-bound` is emitted only
  after the receipt hash + trusted external key + signature + export hash +
  audit-chain prefix + selected v4 entry + action commitment + complete
  canonical action all verify (and the enforcement-time policy commitment when
  `--file` is supplied). v1 stays `legacy`.

Test / documentation only (no runtime behavior change):

- **#4 `test(hook): cover CLI fail-closed contract with a real child process`** —
  spawns the built `dist/cli.js` (`hook pre`) against an unusable `CATP_HOME` and
  asserts a real exit code 2, a `block` decision on stdout (never `allow`),
  diagnosable stderr, and that the action did not execute.
- **#9 `docs: correct receipt version, install version, and v2 export
  requirement`** — README v1→v2 receipt, INSTALL 0.7.3→0.7.4 install version,
  and `docs/AUTHORIZATION_SECURITY_NOTES.md` clarifying the external trusted key,
  the mandatory v2 export, policy/action commitments, legacy v1 semantics, and
  that signature-only is no longer `enforcement-time-bound`.

## Verification performed (local, this session)

Run on the prepared 0.7.5 working tree:

- [x] `catp-plugin` `npm run typecheck` — pass.
- [x] `catp-plugin` `npm run build` — pass; `dist/cli.js` produced.
- [x] `catp-plugin` `npm test -- --runInBand` — 21 suites, 330 tests, all pass
      (including the durable fault-injection, torn-append repair, v2 receipt
      positive/negative, and CLI child-process fail-closed tests).
- [x] `npm run smoke:receipt` — `receiptSmoke=ok`; v2 receipt verify summary
      reported `authorizationReceipt=valid`, `auditExport=matched`,
      `policy=matched`, `assurance=enforcement-time-bound`.
- [x] **Full repository check on the exact release commit** — `bash check.sh`
      run in a clean detached worktree checked out at
      `077c5997245f1c52961a03c9f3b3be1f8d06ba6f` (not merely the branch tip):
      Foundry compiled with Solc 0.8.26 and `forge test` passed 33/33;
      `catp-plugin` typecheck + `test:coverage` passed 21 suites / 330 tests;
      `catp-sdk` `pnpm install --frozen-lockfile` + typecheck + `vitest` passed
      26 tests; the script exited `0` with `All checks passed.` No Foundry or
      keychain failures. This is the pre-tag release-candidate gate.

Not yet run (inherently post-tag; pending publish authorization): the
tag-triggered Release workflow (typecheck + tests + build + Trusted Publishing)
and the registry-tarball + fresh-install verification below. These can only run
after the tag exists, because pushing the tag is what triggers the publish.

## Release commit

`077c5997245f1c52961a03c9f3b3be1f8d06ba6f` (`077c599`) — the commit that lands
this 0.7.5 version bump (`catp-plugin/package.json`, root `package-lock.json`)
together with these release notes. The SHA could not be embedded inside that same
commit, so it is transcribed here from a later documentation-only commit. The
`v0.7.5` tag MUST point at this exact commit. The only commits after it on `main`
are documentation-only (the #14/#15 governance records and this correction); they
change no built source, so the npm artifact is identical whether published from
`077c599` or the current tip — but the tag target is `077c599` so that
`git rev-list -n 1 v0.7.5` == the release commit.

## Publish (PENDING — NOT AUTHORIZED)

Release order — the enforceable invariant. npm Trusted Publishing is *triggered
by* pushing the tag, so registry verification can never precede the tag. The gate
that runs before the tag is the **pre-tag release-candidate verification**: the
full local check on the exact release commit. The sequence is:

```text
exact release commit (077c599) local full verification   <- pre-tag gate (done)
  -> create and push tag v0.7.5 (pinned to 077c599)
  -> tag-triggered Trusted Publishing (Release workflow: typecheck+tests+build+publish)
  -> registry tarball + fresh-install verification          <- necessarily post-publish
  -> Phase 6 (paper re-pin + reruns)
```

Do NOT describe this as "verify the published artifact before tagging" — that is
impossible with tag-triggered publishing. What is verified before the tag is the
release-candidate commit, locally.

```bash
# 1. Pre-tag release-candidate verification on the EXACT release commit.
#    Already run this session in a clean worktree at 077c599 (exit 0). Re-run on
#    a clean checkout of 077c599 if the tree has since changed.
git worktree add /tmp/catp-0.7.5-release-check 077c5997245f1c52961a03c9f3b3be1f8d06ba6f
( cd /tmp/catp-0.7.5-release-check && bash check.sh )   # forge + plugin coverage + sdk

# 2. Push main, then create the annotated tag PINNED TO THE EXACT RELEASE COMMIT.
#    Never `git tag -a v0.7.5` bare at the tip: that could tag a later commit.
git push origin main
git tag -a v0.7.5 077c5997245f1c52961a03c9f3b3be1f8d06ba6f -m "CATP CLI v0.7.5"

# 3. Pushing the tag triggers Trusted Publishing -> the Release workflow.
git push origin v0.7.5
```

The Release workflow validates that the tag version equals
`catp-plugin/package.json` (`0.7.5`) and that the checked-out commit matches the
tag commit, then publishes `@catp-protocol/cli@0.7.5`.

## Post-Publish Verification (PENDING)

- [ ] Registry query for `@catp-protocol/cli@0.7.5`: download the tarball into an
      isolated temporary directory; verify version, SHA-256, sha1
      (`dist.shasum`), and the unpacked file manifest against a clean local
      build; record the registry and clean-local tarball SHA-256.
- [ ] Fresh-install smoke test with an isolated `CATP_HOME`: install
      `@catp-protocol/cli@0.7.5` into an isolated prefix; `catp --version`
      reports `0.7.5`; record the resolved executable realpath and its
      `dist/cli.js` SHA-256; `scripts/smoke-receipt.sh` driven by that binary
      prints `receiptSmoke=ok` and a v2 receipt verify summary with
      `assurance=enforcement-time-bound`.
- [ ] `git rev-list -n 1 v0.7.5` ==
      `077c5997245f1c52961a03c9f3b3be1f8d06ba6f` (the release commit above).

## Release Gate

NOT crossed this session — no publish authorization. The release commit `077c599`
exists and has passed the pre-tag release-candidate verification (`bash check.sh`,
exit 0); the tag `v0.7.5` and the registry tarball do NOT yet exist and are
created only at publish time. README/INSTALL keep the install version at the
published, verifiable `0.7.4` until `0.7.5` is published and verified (they are
bumped in the deferred paper re-pin step).

## Paper coordination (deferred)

Because CATP behavior changed (#1/#10/#3), the paper's pinned `0.7.4` artifact
no longer matches current code. The companion `catp_paper` harness fixes
(#5 artifact gate, #11 RQ1b scorer, #6 RQ2, #7 RQ3, #8 RQ4) are already
committed, but their measured data is still `0.7.4`. After `0.7.5` is published
and verified from the registry, the deferred step re-pins the artifact
(`common.sh` `PINNED_VERSION`/`PINNED_COMMIT`/`PINNED_CLI_SHA256`, lockfile,
manifest, tarball/cli hashes), reruns RQ1-RQ4 + the Groth16 case study, and
regenerates `raw`/`processed`/tables/text. Until then the paper is in a
"scripts corrected + data still 0.7.4" intermediate state and is **not**
submission-ready.
