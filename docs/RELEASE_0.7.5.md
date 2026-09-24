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

Not yet run (pending publish authorization): main CI on the release commit and
the tag-triggered Release workflow (typecheck + tests + build + publish), plus
the registry-tarball and fresh-install verification below.

## Release commit

PENDING — the release commit is the commit that lands this 0.7.5 version bump
(`catp-plugin/package.json`, root `package-lock.json`) together with these release
notes. Its exact SHA cannot be embedded in a file inside that same commit; it is
recorded in the release-gate report and must be transcribed here (and tagged
`v0.7.5`) at publish time.

## Publish (PENDING — NOT AUTHORIZED)

Per the #14 process-deviation lesson (verify before tagging), run the full check
suite on the release commit **first**, then tag:

```bash
# 1. Full verification on the release commit (already run locally this session).
bash check.sh                       # solidity (forge) + plugin typecheck/tests/coverage + sdk

# 2. Publish via Trusted Publishing by pushing the annotated tag.
git push origin main
git tag -a v0.7.5 -m "CATP CLI v0.7.5"
git push origin v0.7.5              # triggers the Release workflow -> typecheck+tests+build+publish
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
- [ ] `git rev-list -n 1 v0.7.5` == the release commit recorded above.

## Release Gate

NOT crossed this session — no publish authorization. The registry tarball, tag
`v0.7.5`, and release commit do not yet exist. README/INSTALL keep the install
version at the published, verifiable `0.7.4` until `0.7.5` is published and
verified (they are bumped in the deferred paper re-pin step).

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
