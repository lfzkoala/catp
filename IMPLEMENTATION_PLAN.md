# CATP Implementation Plan

## Product Goal

CATP makes autonomous agent activity enforceable locally and verifiable
externally.

The current repository is intentionally scoped to two connected surfaces:

1. **Local enforcement**: Claude Code hooks evaluate tool calls against
   `catp-policy.toml` and write a tamper-evident SHA-256 audit log.
2. **External verification**: structured actions are linked to audit
   commitments, authorization witnesses, proof manifests, and optional verifier
   backends.

This is now treated as a standalone project scope. Messaging, output
verification, reputation, and registry/discovery are future extensions, not
required layers.

---

## Current Mainline

```text
catp-policy.toml
  -> catp hook pre/post
  -> local audit log
  -> structured authorization action
  -> audit export / signed receipt
  -> optional witness / proof manifest
  -> optional verifier backend
```

Current verification surfaces:

| Surface | Role | Status |
|---------|------|--------|
| Audit log | Tamper-evident local evidence | Active npm CLI path |
| Authorization witness/manifest | Portable authorization artifact | Active npm CLI path |
| Signed authorization receipt | Non-ZK external verification | Active npm CLI path |
| ZK verifier backend | Privacy-preserving compact verification | Optional advanced path |

Current proof backend versions:

| Proof version | Backend | Role |
|---------------|---------|------|
| `authorization_groth16_v1` | Groth16/BN254 + MiMC | Active EVM/testnet path |

`authorization_groth16_v1` is the active optional EVM backend. ZK is not
required for CATP local enforcement, audit-log integrity, or the signed receipt
path.

---

## Completed

### Local Enforcement

- `catp-policy.toml` schema and parser
- Runtime-neutral `ToolAction` enforcement core with a Claude Code adapter
- `PreToolUse` / `PostToolUse` hook handlers
- Local audit log with commitment-chain verification
- CLI commands: `init`, `validate`, `hook`, `log`, and audit-root bundle export via `anchor`
- npm package: `@catp-protocol/cli`
- install documentation and smoke-test flow

### Authorization Proofs

- Groth16 `authorization_groth16_v1` circuit and gnark prover
- Generated Groth16 Solidity verifier and CATP wrapper
- `AgentAuthorizer.sol` policy registry and proof execution flow
- Sepolia Groth16 deployment metadata and smoke-test record
- TypeScript SDK proof artifact adapters
- `catp witness`
- `catp prove authorization`
- `catp verify authorization`
- `examples/authorization-basic`
- Manifest validation checks proof version, 13 public inputs, 128-byte
  `actionData`, 256-byte proof bytes, and public input mirrors.
- Audit-linked manifest validation checks local audit chain integrity, audit
  entry presence, and structured authorization action consistency.
- Calldata encoder validates the contract-facing artifact shape before emitting
  `registerPolicy` / `executeAuthorized` calldata.

### Repository Cleanup

- Removed inactive placeholder crates/modules.
- Removed inactive off-chain verifier code from the active repository surface.
- Removed committed WASM build output.
- Moved test-only Solidity stubs out of production sources.
- Removed unused primitives crate and inactive output-verification contracts.

### Release Hygiene And Proof UX

- README, INSTALL, ARCHITECTURE, examples, and authorization security notes aligned to
  the current enforcement + authorization scope.
- npm CLI package boundary documented: local enforcement, audit logs, witness
  generation, proof manifest tooling, and artifact validation are in npm; full
  Groth16 proof generation requires a repository checkout.
- `catp witness --out` prints a ready-to-edit `proveCommand=...` line for
  action and audit-linked sources.
- `catp prove authorization --out` prints a ready-to-run `verifyCommand=...`
  line, including `--check-audit` when applicable.
- Global npm install smoke path documented and verified for `0.3.0`, including
  receipt issue/verify.
- Missing repo checkout/prover script errors now explain how to proceed.
- `examples/authorization-basic` remains the first user-facing proof fixture.
- `npm run groth16:check` remains the canonical setup integrity check.

### Signed Authorization Receipts

- `catp log export` writes deterministic `catp_audit_export_v1` bundles for
  individual audit commitments.
- `catp log show --json`, `--tool`, and `--decision` make audit inspection
  scriptable and selector-aligned with receipt issuance.
- `catp log export --latest`, `--tool`, and `--decision` export audit evidence
  without manually copying commitments.
- `catp receipt keygen` creates local Ed25519 signing keys.
- `catp receipt sign` signs an existing audit export.
- `catp receipt issue` is the main path: it verifies the local audit chain,
  exports the audit entry, binds the policy commitment, and signs
  `catp_authorization_receipt_v1`.
- `catp receipt issue --latest`, `--tool`, and `--decision` let users select
  audit entries without manually copying commitments.
- `catp receipt verify` validates the signature and can also check the receipt
  against the audit export and `catp-policy.toml`.
- `catp receipt verify --json` emits a machine-readable verification summary.
- Receipt verification has regression tests for tampered signatures, wrong
  public keys, mismatched audit exports, missing policy commitments, and policy
  mismatches.
- `examples/receipt-basic` documents and exercises the default non-ZK external
  verification path.
- `npm run smoke:receipt` validates the default receipt path end-to-end.

### Enforcement-Time Evidence And Durability

Security convergence work that binds every decision to the exact policy and the
complete action it was evaluated against, and makes that evidence durable before
it can be relied on.

- Canonical evidence primitives (`catp-plugin/src/evidence`): domain-separated
  `catp:policy:v1` and `catp:action:v1` commitments over canonical JSON, with
  `input_summary` kept as a display-only truncation that never participates in a
  security binding.
- Audit commitment version `4`: each entry binds the enforcement-time
  `policy_commitment`, the full-action `action_commitment`, phase, and reason.
  Versions `1`-`3` remain verifiable; legacy entries are never upgraded into
  enforcement-bound v2 receipts.
- Durable storage: the complete canonical action is written as a
  content-addressed sidecar (fsync'd, newly created directories persisted)
  before the audit entry is appended, under the same per-agent, per-day lock,
  with the append path re-checking `action_commitment`.
- Fail-closed pre-hook: an action-sidecar write, audit append, or fsync failure
  returns exit code `2` with a block on both streams and records nothing, so an
  otherwise-allowable action never slips through when its evidence cannot be
  persisted.
- Self-contained v2 audit export (`catp_audit_export_v2`): the entry prefix plus
  the complete action sidecar, hash-chained and re-verifiable offline.
- v2 authorization receipt (`catp_authorization_receipt_v2`): copies
  `policy_commitment` and `action_commitment` verbatim from the selected
  enforcement-time entry; `--file` only checks a candidate policy against the
  recorded commitment and never regenerates bindings at signing time.

Completion evidence (all commands green during the Task 7 verification pass):

```text
cd catp-plugin && npm run build            # exit 0
cd catp-plugin && npm run typecheck        # exit 0
cd catp-plugin && npm test -- --runInBand  # 316 passed
cd catp-plugin && npm run test:coverage    # 316 passed; 91.08/82.48/99.43/91.43
bash check.sh                              # All checks passed
npm run groth16:check                      # setup manifest + deployment metadata ok
npm run smoke:receipt                      # receiptSmoke=ok
```

### Universal Agent Runtime Adapters

- Runtime-neutral `ToolAction` and `RuntimeAdapter` contracts are documented in
  code and architecture docs.
- Claude Code `PreToolUse` / `PostToolUse` parsing is isolated in the
  `claude-code` adapter.
- OpenAI Codex CLI `PreToolUse` / `PostToolUse` parsing is isolated in the
  `codex` adapter, including argv-array command normalization. Real-device
  smoke on v0.155.1 confirmed deny blocking (exit 2 + stderr reason), the
  `Bash` / `apply_patch` tool names, and `PreToolUse` coverage for apply_patch
  edits; dropped `ask` responses remain the documented upstream gap.
- Hook stdin parsing is centralized and tested.
- `catp hook pre/post` accept an injectable adapter internally and expose
  `--runtime claude-code` and `--runtime codex` in the CLI.
- `catp hook runtimes` lists supported runtime adapter ids.
- README and ARCHITECTURE describe the adapter model, supported runtimes, and
  per-runtime enforcement surface.

### Packaging Decision For Proving

- `@catp-protocol/cli` stays light.
- Full `authorization_groth16_v1` proving, calldata encoding, Sepolia execution,
  contracts, and setup checks stay repository-based.
- Hosted prover/verifier service is deferred until there is a concrete product
  reason, threat model, and operational plan.

---

## Active Milestones

### P0: Receipt/Entry Consistency Follow-Up (Unreleased)

The 2026-09-26 paper mechanism review found that published 0.7.5 accepts
validly signed receipts whose copied decision, tool, reason, matched rule, or
timestamp disagrees with the selected audit entry. This requires a signer able
to create inconsistent evidence; it is not an unprivileged signature forgery.
Local verification now compares these fields, with five regression cases.
See `docs/RECEIPT_CONSISTENCY_REVIEW.md` for evidence and validation.

Release gate: obtain publication authorization, assign a new immutable release
identity, verify the registry artifact, and rerun affected paper verification
experiments before claiming the complete receipt contract. Do not move v0.7.5
or present this local repair as the published 0.7.5 artifact. The paper is
currently **unsealed**; the content-freeze and seal listed below are historical.

### P0: 0.7.5 Security-Remediation Release

Status: **released and verified (2026-09-24).** Published from the `v0.7.5` Git
tag (`077c5997245f1c52961a03c9f3b3be1f8d06ba6f`) through npm Trusted Publishing;
`@catp-protocol/cli@0.7.5` is on the registry with `dist-tags.latest` = `0.7.5`,
and the registry tarball plus a fresh-install receipt smoke test were verified
afterward (see `docs/RELEASE_0.7.5.md`).

Goal: publish the confirmed security-review fixes that CHANGE runtime behavior
(#1 idempotent durable-write retries re-establish the fsync barrier, #10
torn-append rollback + explicit `log repair`, #3 v2 receipt verify requires
`--audit-export`) as the next immutable release, because the published 0.7.4
artifact no longer matches current code and the paper must re-pin.

Work:

- #1/#10/#3 behavior fixes plus #4 (CLI child-process fail-closed test) and #9
  (docs corrections) are implemented, tested, and committed.
- The companion `catp_paper` harness fixes (#5 artifact gate, #11 RQ1b scorer,
  #6 RQ2, #7 RQ3, #8 RQ4) are committed in that repository (script-only; no
  experiment data regenerated).
- Package version, lockfile, and `docs/RELEASE_0.7.5.md` are bumped to `0.7.5`.

Exit criteria:

- Full repository checks, CLI coverage, and receipt smoke pass on the release
  commit `077c599` (done locally in a clean worktree checked out at that exact
  commit: `bash check.sh` exit 0 — forge 33/33, plugin typecheck + 330 tests /
  21 suites + coverage, sdk 26 tests; plus `build` and `smoke:receipt`). This is
  the pre-tag release-candidate gate.
- After publish authorization: registry tarball + fresh-install verified, and
  `git rev-list -n 1 v0.7.5` == the release commit. **DONE (2026-09-24):**
  remote tag `v0.7.5^{}` == `077c599`; tarball SHA-256
  `b6d3f5e4f9ad7a7154ebfaeb900fe2dbb141d22b07ee1dea9ec9632da2466790`; installed
  `dist/cli.js` SHA-256
  `6fc34688e8e54c0a824ade6c5b5b7aade6271399d209171cfa885ecd1c754c56`; fresh-install
  `catp --version` = `0.7.5`; `scripts/smoke-receipt.sh` driven by the registry
  binary printed `receiptSmoke=ok` (exit 0).
- **DONE (2026-09-25):** the paper re-pinned the artifact to
  `@catp-protocol/cli@0.7.5` and reran RQ1a/RQ1b/RQ2/RQ3/RQ4 + Groth16 from the
  sealed, self-contained inputs (deferred Phase 6 step complete). The
  `catp_paper` reproducibility package is re-sealed at content-freeze commit
  `ea6981f2742238c70abb29ab77f54b718f0e0b26` / sealing commit
  `3b5f163d699fcfd5313c92e5d4a3868bcb1c8b70`, deterministic archive SHA-256
  `45d8a9bc5da1e38b777197c069cfcabc30d1ad317d362c6e91017fcdd309ca54` (237 tracked
  files), behind a pre-seal anonymity gate that rejects any host per-user temp
  root; see `catp_paper/artifact/README.md` for the authoritative seal record.

### P0: 0.7.4 Enforcement-Evidence Release

Status: **released and verified.** Published from the `v0.7.4` Git tag
(`86eff07ce674aa5c180ce7f8a831bc85646ac976`) through npm Trusted Publishing;
the registry tarball and a fresh-install smoke test were verified afterward (see
`docs/RELEASE_0.7.4.md`).

Goal: publish the enforcement-time policy + full-action bindings, durable
append, fail-closed pre-hook, v2 self-contained export, and v2 receipt as one
immutable fixed release. (Superseded as the paper's pin: the experiments are now
pinned to `0.7.5` -- see the 0.7.5 Security-Remediation Release milestone above.)

Work:

- Phases 1-3 of `docs/superpowers/plans/2026-09-23-paper-security-remediation.md`
  were implemented, tested, and committed (see Enforcement-Time Evidence And
  Durability above).
- Package version, lockfile, and release notes were bumped to `0.7.4`, and the
  packed tarball was validated.

Exit criteria (met):

- Full repository checks, CLI coverage, Groth16 setup checks, and receipt smoke
  passed on the release commit.
- Package version, release notes, Git tag, and npm version agree on `0.7.4`.
- Registry package, release commit, and tag correspondence were verified. The
  paper was pinned to `@catp-protocol/cli@0.7.4` at this release; that pin is now
  **superseded** by `@catp-protocol/cli@0.7.5` (see the 0.7.5 milestone above), so
  maintainers should not treat 0.7.4 as the current paper artifact.

### P0: 0.6.0 Security Convergence Release

Status: release candidate ready for main CI and tag.

Goal: publish the enforcement, audit, receipt, and executor-binding fixes made
after `0.5.0` as one focused security release.

Work:

- Keep policy-enabled pre-enforcement fail-closed when runtime input, policy
  loading, or audit persistence fails.
- Bind audit commitments to phase and structured authorization data while
  retaining verification support for earlier commitment versions.
- Require an externally trusted public key for receipt verification and issue
  authorization receipts only from pre-enforcement decisions.
- Serialize concurrent audit-chain appends and constrain audit agent ids used in
  filesystem paths.
- Keep audit anchoring separate from authorization policy registration.
- Ship executor-bound `AgentAuthorizer` contracts with current, smoke-tested
  Sepolia deployment metadata.

Exit criteria:

- Full repository checks, CLI coverage, Groth16 setup checks, and receipt smoke
  pass.
- The packed npm CLI passes an isolated global-install smoke test.
- Package version, release notes, Git tag, and npm version agree on `0.6.0`.

### Ongoing: Authorization Proof Security Hardening

Status: release guardrail.

Goal: keep `authorization_groth16_v1` from accepting invalid actions or drifting
from its documented public input schema.

Work:

- Keep `docs/AUTHORIZATION_SECURITY_NOTES.md` current as the living security
  notes for `authorization_groth16_v1`.
- Add regression tests for any new issue found in policy encoding, witness
  generation, proof artifact validation, calldata encoding, or contract state
  checks.
- Treat changes to public input order, action encoding, commitment hash, proof
  backend, verifier calldata format, or setup keys as a new proof version.

Exit criteria:

- Critical/high review findings are fixed or explicitly deferred with rationale.
- Groth16 setup hashes, verifier source hash, wrapper hash, and deployment
  metadata remain reproducible through `npm run groth16:check`.

## Deferred Decisions

### Additional Runtime Adapters

Claude Code and OpenAI Codex CLI are the supported runtime adapters today.
Add future runtime adapters only when there is a concrete payload shape and
test fixture, such as OpenAI Agents SDK, LangGraph/LangChain, Cursor-style tool
runners, MCP tool gateways, or local shell/tool executors.

### Local Cryptographic Verification For Groth16 Manifests

`catp verify authorization` intentionally performs structural and audit-linked
manifest validation today. Cryptographic verification remains the job of the EVM
verifier.

Do not add local Groth16 cryptographic verification to the CLI until the project
chooses a stable verifier implementation and package boundary.

### Hosted Prover

Hosted prover/verifier services are out of the current package surface. Revisit
only with a concrete product reason, threat model, and operations plan.

### Security Audit Follow-Ups (2026-09)

Deferred from the 2026-09 self-audit (see `docs/SECURITY_AUDIT_2026-09.md`):

- Commitment version 4 now exists and binds the enforcement-time policy and
  full-action commitments. Binding `tool_use_id` into audit commitments remains
  deferred until a concrete correlation requirement justifies another change.
- Filesystem-level path canonicalization (symlink/realpath resolution) for path
  rules; the engine normalizes dot segments only and matches the runtime-
  reported path string.
- `registerPolicy` commitment salting or delegator pre-authorization to remove
  first-writer squatting; changes the on-chain interface and proof binding
  (documented as an accepted protocol property in
  `docs/AUTHORIZATION_SECURITY_NOTES.md`).

---

## Proof System Policy

Create a new proof version when any of these change:

- public input order or count
- policy encoding
- action encoding
- commitment hash or parameters
- range-check semantics
- timestamp or replay semantics
- setup keys
- transcript type
- proof backend
- verifier calldata format

Old verifier contracts remain valid for historical proofs. New proof versions
get new verifier addresses, metadata, and SDK/CLI gates.

---

## Out of Scope for Current Repo Surface

- Production mainnet trusted setup ceremony
- Fully proof-centric policy/spend state
- Nova/HyperNova/folding production integration
- Encrypted agent communication
- Output verification and attestor/challenge contracts
- Reputation proofs
- Registry/discovery
- Cross-chain verifier deployments

These are valid protocol directions, but they should re-enter the repository
only with a concrete proof statement, integration plan, and test strategy.
