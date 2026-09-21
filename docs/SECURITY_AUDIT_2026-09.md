# CATP Security Audit Disposition (2026-09)

Status: disposition record for the self-audit run at
`security-audit-skill/catp/run-1` (REPORT.md, NEEDS-VALIDATION.md,
FINDINGS-DETAIL.md, findings.json, coverage-ledger.json).

Audit result: 0 confirmed vulnerabilities, 1 rejected lead, 7 leads requiring
maintainer validation. This document records the validation outcome and
disposition for each lead, plus hardening items and deferred follow-ups.
Version shipped with the fixes: `@catp-protocol/cli` 0.7.2.

## Lead Dispositions

### 1. `hook.stdin.unbounded-buffer` — Fixed

The pre/post hook buffered stdin into a growing string with no limit and no
deadline, waiting for EOF before deciding.

Fix: `readStdin`/`readStream` in `catp-plugin/src/hook/runtime.ts` now enforce
a 1 MiB byte cap (`HOOK_STDIN_MAX_BYTES`) and a 10 s deadline
(`HOOK_STDIN_DEADLINE_MS`). Exceeding either rejects the read; the CLI catch
path then fails closed (pre-hook blocks with a reason, post-hook exits 0
without corrupting the chain).

Tests: `catp-plugin/tests/hook/runtime.test.ts` (oversize reject, deadline
reject, normal read within limits).

### 2. `audit.tail.whole-file-scan` — Fixed

`getLastCommitmentFromFile` read and split the entire daily JSONL file on every
append, making each pre-hook decision O(file size).

Fix: `readLastAuditLine` in `catp-plugin/src/audit/logger.ts` reads only the
last 64 KiB of the file with `readSync` at an offset (constant-space tail
read). A tail chunk with no newline in an oversized file raises an error,
which the pre-hook turns into a fail-closed block rather than a silent
mis-chain.

Tests: `catp-plugin/tests/audit/logger.test.ts` (chain recovery across 3000
entries, oversized single-line tail rejects).

### 3. `release.workflow-dispatch.unqualified-ref-publication` — Fixed

`release.yml` passed `workflow_dispatch` `inputs.tag` directly as the checkout
ref, so a dispatch with an arbitrary branch/ref name (with a matching
package.json version) could be published to npm as that "tag", with OIDC
id-token write in the job.

Fix in `.github/workflows/release.yml`:

- A validation step rejects any `RELEASE_TAG` not matching
  `^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$` before checkout.
- Checkout ref is qualified to `refs/tags/{tag}` for dispatch runs
  (`github.ref` for tag pushes).
- A post-checkout step verifies `refs/tags/$TAG^{commit}` equals HEAD.
- `actions/checkout` and `actions/setup-node` are pinned to immutable commit
  digests.

Owner-side controls (outside the repo, verify on GitHub): restrict
`workflow_dispatch` for this workflow to trusted roles via repository rulesets
or environment protection.

### 4. `groth16.rpc.unbound-chain-and-deployment-replies` — Fixed (script scope)

`scripts/deploy-groth16-sepolia.sh` trusted an operator-supplied RPC: no chain
id check, deployed-code checks compared only lengths, and recorded
`deployedRuntimeCodeKeccak256` hashes were computed from RPC-returned code
(self-certifying), with `chainId: 11155111` hardcoded in the metadata output.

Fix:

- The script verifies `cast chain-id` equals `EXPECTED_CHAIN_ID` (11155111)
  before broadcasting, and the metadata `chainId` is emitted from that verified
  value.
- Deployed runtime code for Groth16Verifier, Groth16AuthorizationVerifier, and
  AgentAuthorizer is now compared byte-for-byte (case-insensitive) against the
  local build artifacts; mismatches abort.
- Recorded keccak hashes are computed from the local artifact bytes, not from
  RPC responses, and `agentAuthorizer` was added to
  `deployedRuntimeCodeKeccak256`.

Verified with `bash -n` and `--dry-run` (generation, size checks, metadata
hash consistency). Live-path behavior is covered by the next Sepolia
deployment.

Residual (documented, not fixed): `scripts/smoke-groth16-sepolia.sh` compares
RPC code against committed metadata; after this fix the metadata originates
from local artifacts, which breaks the self-certification loop. Existing
committed metadata predates the `agentAuthorizer` hash field; it will appear
in the next deployment metadata.

### 5. `AgentAuthorizer.registerPolicy.first-writer-squatting` — Accepted protocol property, tested + documented

Any account can register an unclaimed commitment and own it permanently
(first-writer-wins, surviving revocation). This is a denial-of-binding against
the intended delegator, not a fund-safety issue: the squatted entry is owned by
the attacker and never authorizes actions against the intended delegator's
assets.

Disposition: accepted as a protocol property (changing it alters the on-chain
interface and proof binding — see IMPLEMENTATION_PLAN deferred items).

- Tests added: `test_register_attackerSquatBlocksIntendedDelegator`,
  `test_register_intendedDelegatorLockedOutAfterSquatterRevoke` in
  `catp-contracts/test/authorization/AgentAuthorizer.t.sol`.
- Documented in `docs/AUTHORIZATION_SECURITY_NOTES.md` (new Low finding +
  integrator guidance: treat commitments as single-use secrets, register
  before publishing, re-generate on squat).

### 6. `policy.command.shell-equivalence` — Mitigated + honestly documented

Command patterns match the raw string (glob or substring) with first-match-wins
and no shell parsing, so an allow prefix like `echo*` also matches
`echo hi && rm -rf ~`.

Disposition: CATP will not grow a shell parser; the supported mitigation is a
control-operator deny rule placed before allow rules.

- `catp init` template and `examples/receipt-basic/catp-policy.toml` now ship a
  leading deny rule for `&&`, `;`, `|`, backtick, `$(`.
- Semantics tests added in `catp-plugin/tests/policy/engine.test.ts`
  (ordering semantics + mitigation pattern).
- README and ARCHITECTURE.md state the matching semantics and the mitigation
  explicitly.

### 7. `policy.path.canonical-target` — Partially fixed + honestly documented

The engine matched the first of `file_path`/`path`/`filePath` with no
normalization, so `src/../secrets/key.pem` could evade a `src/**` allowlist
inversion.

Fix: both the extracted path and allowlist/denylist patterns are normalized
with POSIX `path.normalize` before micromatch (dot segments collapsed on both
sides).

Documented limit: matching is lexical against the runtime-reported path —
symlinks are not resolved and absolute/relative forms are not unified.
Filesystem-level canonicalization is deferred (IMPLEMENTATION_PLAN).

Tests: `catp-plugin/tests/policy/engine.test.ts` (dot-segment collapse,
`./`-prefixed pattern equivalence).

### 8. Command glob patterns silently failed on absolute paths — Fixed in 0.7.3

Found during the 0.7.2 registry install verification (after this audit run):
command `pattern` globs were evaluated with `micromatch.isMatch`, which treats
`/` as a path-segment boundary. Deny patterns shipped in the README and the
`catp init` template (for example `rm -rf*`) therefore never matched commands
containing absolute paths such as `rm -rf /tmp/x`; only the substring arm or
segment-free commands matched. This weakened every glob-style command deny
rule in default templates since their introduction.

Fix: command patterns now use a dedicated shell-style glob (compiled to an
anchored regex): `*` matches any run of characters including `/` and newlines,
`?` matches one character, and all regex metacharacters in patterns are
escaped. The substring arm is unchanged. Path rules keep micromatch semantics
(segment-aware matching is correct for file paths).

Behavior change: deny globs that were silently inert against absolute-path
commands now fire (fail-safe direction); allow globs containing `*` can match
more commands, so an allow pattern relying on the broken segment semantics
would need review — no shipped template or example relies on it.

Tests: `catp-plugin/tests/policy/engine.test.ts` (`command glob semantics`
suite: absolute paths, embedded destructive commands, literal operators,
multi-line commands, `?`, metacharacter escaping).

## Rejected Lead

- `receipt.prephase.positive-binding`: rejected during the audit; receipt
  issuance remains bound to pre-phase enforcement decisions. No action.

## Hardening Items Verified Already Satisfied

- No embedded keys or secrets in `catp-sdk` sources.
- `catp receipt verify` requires an externally supplied `--public-key`; there
  is no trusted-key shortcut.
- Pre-hook fail-closed semantics on policy/audit errors remain intact
  (exercised by `tests/hook/pre.test.ts`).

## Owner-Side Verification Checklist (outside repository)

- GitHub: repository/org role membership limited to trusted maintainers;
  branch protection on `main`; `workflow_dispatch` restricted.
- npm: package ownership for `@catp-protocol/cli` limited to maintainers;
  Trusted Publishing (OIDC) configured for the release workflow only.
- Runtime hooks: CATP hook commands are invoked with the maintainer-installed
  CLI binary; `~/.claude/settings.json` and `~/.codex/hooks.json` are
  user-writable by design and are part of the local trust root.

## Deferred Follow-Ups

Tracked in `IMPLEMENTATION_PLAN.md` under "Security Audit Follow-Ups
(2026-09)": `tool_use_id` in commitment v4, filesystem path canonicalization,
and `registerPolicy` salting/pre-authorization.

## Verification Performed

- `catp-plugin`: `npm test` — 218 tests passed (17 suites) after the 0.7.3
  command-glob fix (212 at the initial audit-fix commit).
- `catp-contracts`: `forge test` — 33 tests passed (including 2 new
  first-writer tests).
- `scripts/deploy-groth16-sepolia.sh`: `bash -n` + `--dry-run` passed.
- Full gate: `bash check.sh` (see commit history for the release commit).
