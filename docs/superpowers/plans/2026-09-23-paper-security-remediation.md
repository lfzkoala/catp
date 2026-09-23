# CATP Paper Security Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make CATP's central paper claim true in the implementation and artifact: every pre-execution decision is durably bound to the exact policy and complete normalized action used at enforcement time, and a verifier can validate that binding offline from a pinned release artifact.

**Architecture:** Introduce one canonical evidence layer shared by enforcement, audit export, and receipt verification. A version-4 audit entry records enforcement-time `policy_commitment` and `action_commitment`; the complete canonical action is stored as a content-addressed, durable sidecar and included in a version-2 export. A version-2 receipt copies commitments from the selected audit entry instead of recomputing them from mutable files. Existing v1--v3 logs and version-1 receipts remain verifiable, but they cannot be upgraded into the stronger claim.

**Tech Stack:** TypeScript/Node.js, Jest, npm, Bash, Python 3, Solidity/Foundry, LaTeX/latexmk.

**Spec:** This document is the execution specification. Product boundaries remain those in `README.md`, `IMPLEMENTATION_PLAN.md`, and `ARCHITECTURE.md`; CATP stays an authorization and audit protocol rather than expanding into a hosted platform.

## Global Constraints

- Execute phases in the numbered order. Do not publish or rerun paper experiments before the security and durability gates pass.
- Use SHA-256 hex digests with an explicit domain string and schema version in every new commitment. Never hash display summaries as security evidence.
- Canonical action input is the adapter-normalized `ToolAction`, not the runtime's unparsed payload. Exclude `raw`, which may contain runtime-specific noise and secrets.
- The policy commitment is computed from the normalized `CatpPolicy` returned by the loader at the same enforcement invocation that produced the decision.
- Fail closed on evidence persistence failure: a pre-hook must not return allow or deny as a successful policy decision unless its action evidence and audit entry have been durably written.
- Treat fsync as local-filesystem durability, not proof against a malicious kernel, storage controller, or administrator.
- Preserve verification support for historical audit commitment versions 1--3 and receipt version 1. Do not issue a version-2 receipt from a legacy entry because the missing enforcement-time bindings cannot be reconstructed.
- Every experiment must consume an immutable packed release, never a working-tree `dist` directory or symlink.
- Store repository-relative paths in committed artifacts. Raw output must not contain usernames, home directories, access tokens, or machine-specific temporary paths.
- Commit after each task's tests pass. Suggested commit subjects appear below.

## Definition of Done

- A policy-swap regression proves that changing the policy after enforcement cannot change the receipt's policy binding.
- A long-prefix collision regression proves that two actions with identical first 200 characters have distinct commitments and exported full actions.
- Failure injection proves the pre-hook exits with the internal-error code when action or audit fsync fails.
- The published package version, npm tarball SHA-256, git tag, source commit, installed package realpath, and executed CLI hash all agree.
- `run_all.sh` executes both synthetic adapter conformance and runtime-in-the-loop tests and aborts on a version or hash mismatch.
- All processed results and LaTeX tables are regenerated only from the new pinned artifact.
- The paper states only the guarantees and runtime paths demonstrated by the resulting evidence.

---

## Phase 1: Enforcement-time policy and full-action commitments

### Task 1: Add canonical evidence primitives

**Files:**

- Create: `catp-plugin/src/evidence/canonical.ts`
- Create: `catp-plugin/src/evidence/commitments.ts`
- Create: `catp-plugin/tests/evidence/canonical.test.ts`
- Create: `catp-plugin/tests/evidence/commitments.test.ts`
- Modify: `catp-plugin/src/commands/log.ts`

- [ ] Write failing canonicalization tests for recursive object-key ordering, preserved array ordering, Unicode strings, booleans, nulls, and numeric values.
- [ ] Write a failing test proving objects with different insertion order produce identical bytes and SHA-256 digests.
- [ ] Move the existing deterministic JSON and SHA-256 helpers out of `commands/log.ts`; make audit export and the new commitment code import the shared implementation.
- [ ] Define the exact action evidence type:

```ts
export interface CanonicalToolActionV1 {
  schema: "catp_tool_action_v1";
  runtime: ToolAction["runtime"];
  phase: ToolAction["phase"];
  session_id?: string;
  tool_name: string;
  tool_input: Record<string, unknown>;
}
```

- [ ] Implement `canonicalizeToolAction(action: ToolAction): CanonicalToolActionV1`, deliberately excluding `raw`.
- [ ] Define canonical JSON behavior explicitly: sort object keys recursively, preserve array order, encode as UTF-8 without insignificant whitespace, omit the absent optional `session_id`, and reject non-JSON numeric values rather than silently changing evidence.
- [ ] Implement domain-separated commitments over UTF-8 bytes:

```text
action_commitment = SHA256("catp:action:v1\n" || stable_json(canonical_action))
policy_commitment = SHA256("catp:policy:v1\n" || stable_json(normalized_policy))
```

- [ ] Add tests proving a change to any action field or policy field changes the corresponding digest.
- [ ] Add the critical regression: two `tool_input` values with an identical 200-character prefix must have different action commitments.
- [ ] Run `npm test -- --runInBand tests/evidence tests/commands/log.test.ts` from `catp-plugin`; expect all selected suites to pass.
- [ ] Run `npm run typecheck` from `catp-plugin`; expect exit code 0.
- [ ] Commit as `feat(audit): add canonical policy and action commitments`.

### Task 2: Extend the audit schema without weakening legacy verification

**Files:**

- Modify: `catp-plugin/src/policy/types.ts`
- Modify: `catp-plugin/src/audit/logger.ts`
- Modify: `catp-plugin/src/audit/verifier.ts`
- Modify: `catp-plugin/src/enforcement/core.ts`
- Modify: `catp-plugin/tests/audit/logger.test.ts`
- Modify: `catp-plugin/tests/audit/verifier.test.ts`
- Modify: `catp-plugin/tests/enforcement/core.test.ts`

- [ ] Add an explicit version-4 audit-entry type with required lowercase-hex fields:

```ts
interface AuditEntryV4 extends AuditEntryBase {
  commitment_version: 4;
  reason: string;
  policy_commitment: string;
  action_commitment: string;
}
```

- [ ] Keep distinct legacy types for versions 1--3. Do not make the new fields optional on v4.
- [ ] Define version-4 entry commitment input with a domain separator and every security-relevant field, including `prev_commitment`, phase, decision, reason, rule, policy commitment, and action commitment. `input_summary` may remain for display but must not be the action binding.
- [ ] Change `evaluatePreAction` so it receives the normalized policy actually passed to the engine and computes both commitments before constructing the entry.
- [ ] Change `recordPostAction` to receive the normalized policy as well, and emit v4 with `phase === "post"`. Receipt issuance must accept only `phase === "pre"` entries.
- [ ] Extend `EnforcementResult` with the canonical action evidence. Before storage, require its recomputed digest to equal `auditEntry.action_commitment`; this prevents the logger from pairing an entry with a different sidecar.
- [ ] Add logger tests asserting v4 entries always contain both bindings and that changing only the display summary does not substitute for changing action evidence.
- [ ] Add verifier fixtures for valid v1, v2, v3, and v4 chains; retain valid legacy behavior.
- [ ] Add tamper tests for v4 `policy_commitment`, `action_commitment`, `phase`, `decision`, and `prev_commitment`.
- [ ] Run `npm test -- --runInBand tests/audit tests/enforcement/core.test.ts` from `catp-plugin`; expect all selected suites to pass.
- [ ] Commit as `feat(enforcement): bind decisions to policy and full action`.

---

## Phase 2: Real durable append

### Task 3: Implement durable local storage primitives

**Files:**

- Create: `catp-plugin/src/audit/durable.ts`
- Create: `catp-plugin/tests/audit/durable.test.ts`
- Modify: `catp-plugin/src/audit/paths.ts`

- [ ] Implement `durableAppendLine(path, line)` with this exact successful sequence: create parent directories, open with append/create mode and `0o600`, write the complete UTF-8 line plus one newline, `fsyncSync(fd)`, close the descriptor, and fsync the parent directory when the file was newly created.
- [ ] Implement `ensureDirectoryDurable(path)`: identify missing path components before recursive creation, create them with `0o700`, then fsync each newly created directory and its existing parent from the deepest component upward.
- [ ] Treat partial writes correctly by looping until every byte is written; do not assume one `writeSync` call consumes the whole buffer.
- [ ] Implement `durableWriteContentAddressed(path, bytes)` using a same-directory uniquely named temporary file, mode `0o600`, full write, file fsync, close, atomic rename, then parent-directory fsync.
- [ ] Expose these operations through an `AuditStorage` interface and a production `nodeAuditStorage` implementation. Thread an optional storage dependency through the logger and `HookOptions` solely as a test seam; CLI execution always uses `nodeAuditStorage`.
- [ ] If the target content-addressed file already exists, read and compare its bytes. Return success only for identical bytes; otherwise report corruption.
- [ ] Ensure descriptors are closed in failure paths while preserving the original write/fsync exception.
- [ ] Unit-test operation order through an injected narrow filesystem interface. Cover partial writes, file-fsync failure, rename failure, directory-fsync failure, and an existing mismatched target.
- [ ] Add a real-filesystem test in a temporary directory that checks the exact bytes and `0o600` mode.
- [ ] Run `npm test -- --runInBand tests/audit/durable.test.ts`; expect all tests to pass.
- [ ] Commit as `feat(audit): add fsync-backed durable storage`.

### Task 4: Persist full action evidence before the audit entry

**Files:**

- Modify: `catp-plugin/src/audit/logger.ts`
- Modify: `catp-plugin/src/audit/paths.ts`
- Modify: `catp-plugin/src/enforcement/core.ts`
- Modify: `catp-plugin/src/hook/pre.ts`
- Modify: `catp-plugin/tests/audit/logger.test.ts`
- Modify: `catp-plugin/tests/hook/pre.test.ts`

- [ ] Store canonical actions at `$CATP_HOME/audit/<agent>/<YYYY-MM-DD>/actions/<action_commitment>.json`.
- [ ] Write the action sidecar before appending the audit entry. This ordering permits an unreferenced sidecar after a crash but never a committed entry whose referenced action was not flushed first.
- [ ] Replace `appendFileSync` in the logger with `durableAppendLine`.
- [ ] Replace the current pre-lock `openSync(file, "a")` creation with a durable empty-file creation that fsyncs the new file and parent directory before `proper-lockfile` uses it. This prevents lock setup from bypassing the new-file durability path.
- [ ] Persist the action sidecar while holding the same per-log lock used to choose `prev_commitment`; then append its entry before releasing the lock. Apply the same storage path to pre and post v4 actions.
- [ ] Keep `input_summary` capped for operator readability; add a comment and test that it is non-authoritative.
- [ ] Make pre-hook behavior fail closed on action-sidecar, audit-write, file-fsync, or directory-fsync errors. The process must emit a concise error to stderr and return CATP's existing internal-error exit code, currently 2.
- [ ] Add an integration test that runs the pre-hook, parses the v4 audit entry, loads its action sidecar, recomputes the digest, and checks equality.
- [ ] Add failure-injection tests for both sidecar fsync and log fsync; neither may produce a successful allow response.
- [ ] Run `npm test -- --runInBand tests/audit/logger.test.ts tests/hook/pre.test.ts`; expect all tests to pass.
- [ ] Run `npm run typecheck` from `catp-plugin`; expect exit code 0.
- [ ] Commit as `feat(hook): durably persist enforcement evidence`.

---

## Phase 3: Offline export and signed receipt binding

### Task 5: Introduce a self-contained version-2 audit export

**Files:**

- Modify: `catp-plugin/src/commands/log.ts`
- Modify: `catp-plugin/src/audit/verifier.ts`
- Modify: `catp-plugin/src/cli.ts`
- Modify: `catp-plugin/tests/commands/log.test.ts`
- Modify: `catp-plugin/tests/audit/verifier.test.ts`
- Modify: `docs/INSTALL.md`

- [ ] Define the exact self-contained export shape below. `entries` is the daily chain prefix from index 0 through `selected_index`, so the selected entry is always the final element. Keep v1 parsing for historical verification.

```ts
interface AuditExportV2Body {
  export_version: "catp_audit_export_v2";
  agent_id: string;
  log_date: string;
  selected_index: number;
  entries: AuditEntry[];
  action: CanonicalToolActionV1;
}

interface AuditExportV2 extends AuditExportV2Body {
  export_sha256: string;
}
```

- [ ] Verify every entry in the included prefix offline and require `entries.length === selected_index + 1`. Describe this narrowly as proving the selected entry's position in the supplied daily prefix, not proving absence of later entries or undisclosed logs.
- [ ] Refactor the verifier so the same pure chain-validation function accepts parsed entries for offline exports and the existing file wrapper delegates to it.
- [ ] Before export, verify the log chain, load the selected entry's sidecar, require `computeActionCommitment(action) === entry.action_commitment`, and reject missing or mismatched evidence.
- [ ] Compute `export_sha256` over the export body excluding only the hash field, using shared stable JSON and the `catp:audit-export:v2` domain.
- [ ] Add CLI tests for a valid v2 export, missing sidecar, altered sidecar, non-v4 selected entry, and a selected post entry.
- [ ] Document that v2 export is the portable evidence bundle and that the local summary alone does not establish exact-action binding.
- [ ] Run `npm test -- --runInBand tests/commands/log.test.ts`; expect all tests to pass.
- [ ] Commit as `feat(export): include exact action evidence in audit bundles`.

### Task 6: Issue receipts only from recorded enforcement-time bindings

**Files:**

- Modify: `catp-plugin/src/commands/receipt.ts`
- Modify: `catp-plugin/src/commands/authorization.ts`
- Modify: `catp-plugin/src/cli.ts`
- Modify: `catp-plugin/tests/commands/receipt.test.ts`
- Modify: `catp-plugin/tests/commands/authorization.test.ts`
- Modify: `docs/AUTHORIZATION_SECURITY_NOTES.md`

- [ ] Define `catp_authorization_receipt_v2` with `audit_commitment`, `policy_commitment`, `action_commitment`, `audit_export_sha256`, decision metadata, `signed_at`, `issuer_key_id`, `signature_algorithm`, `signature`, and `receipt_sha256`. Set `issuer_key_id` to SHA-256 of the public key's DER SubjectPublicKeyInfo bytes.
- [ ] On issue, require a v2 export whose selected entry is `phase === "pre"` and commitment version 4. Copy the policy and action commitments from that entry; never derive them from the current policy file.
- [ ] If `--file <policy>` is supplied, normalize and hash it, compare it with the recorded enforcement-time commitment, and reject a mismatch. The file is verification evidence, not the source of the receipt commitment.
- [ ] Sign a domain-separated canonical receipt body that includes all three bindings: policy, action, and audit entry.
- [ ] Compute the Ed25519 signature over `"catp:receipt-signature:v2\n" || stable_json(receipt_body)`. Compute `receipt_sha256` over `"catp:receipt:v2\n" || stable_json(receipt_body_with_signature)`; neither computation includes `receipt_sha256` itself.
- [ ] On offline verify, first require an independently supplied trusted public key, then verify signature and receipt hash, audit-export hash and chain, selected entry equality, full-action hash, and optional policy-file hash.
- [ ] Recompute `issuer_key_id` from the independently supplied key and require an exact match before accepting the signature.
- [ ] Continue verifying version-1 receipts under their historical semantics, but label their assurance as legacy and do not imply enforcement-time policy/action binding.
- [ ] Add the policy-swap exploit regression: enforce under Policy A, replace it with Policy B, then attempt issue/verify. The receipt must remain bound to A and `--file B` must fail.
- [ ] Add the 200-character-prefix regression at receipt level: two full actions that share the displayed summary must produce different receipts and each must reject the other's export.
- [ ] Add tests for an untrusted key, modified complete action, modified policy, modified selected entry, missing sidecar, v3 entry, and post entry.
- [ ] Run `npm test -- --runInBand tests/commands/receipt.test.ts tests/commands/authorization.test.ts`; expect all tests to pass.
- [ ] Run `npm run smoke:receipt` from the repository root; expect successful issue and offline verification.
- [ ] Commit as `fix(receipt): use enforcement-time evidence bindings`.

### Task 7: Verify the complete security change before release work

**Files:**

- Modify: `catp-plugin/tests/hook/pre.test.ts`
- Modify: `catp-plugin/tests/audit/verifier.test.ts`
- Modify: `IMPLEMENTATION_PLAN.md`
- Modify: `ARCHITECTURE.md`

- [ ] Add one CLI-level persistence-failure case, not merely a unit-test mock: point `CATP_HOME` at an unwritable or structurally invalid target and assert exit 2, no allow response, and no action execution.
- [ ] Run `npm run build`, `npm run typecheck`, `npm test -- --runInBand`, and `npm run test:coverage` from `catp-plugin`; all must exit 0.
- [ ] Run `bash check.sh` from the repository root; expect all available repository checks to pass.
- [ ] Run `npm run groth16:check` from the repository root; expect the verifier consistency checks to pass.
- [ ] Update architecture diagrams/text to show `normalized policy + normalized action -> v4 audit entry -> v2 export -> v2 receipt` and to state the durability boundary precisely.
- [ ] Update the active implementation plan with completion evidence and the exact commands run.
- [ ] Commit as `docs: specify enforcement evidence and durability guarantees`.

---

## Phase 4: Publish one immutable fixed release

### Task 8: Prepare and publish version 0.7.4

**Files:**

- Modify: `catp-plugin/package.json`
- Modify: `package-lock.json`
- Create: `docs/RELEASE_0.7.4.md`
- Modify: `README.md`

- [ ] Set the package version to `0.7.4`; update lockfiles using the package manager rather than hand-editing dependency resolution.
- [ ] Record the intentional format changes: v4 audit entries, v2 exports, v2 receipts, legacy verification support, and the refusal to issue strong receipts from legacy entries.
- [ ] Run from a clean working tree: `bash check.sh`, `npm run groth16:check`, `npm run smoke:receipt`, and `npm pack --dry-run` using the commands and working directories documented by the existing release guides.
- [ ] Run `npm pack` and record the resulting tarball SHA-256, size, and complete file list in `docs/RELEASE_0.7.4.md`.
- [ ] Commit as `release: prepare catp 0.7.4` and push the release commit.
- [ ] Publish through the repository's Trusted Publishing workflow. Do not switch to an ad-hoc local npm credential flow.
- [ ] Query the registry for `@catp/claude-code@0.7.4`, download its tarball into an isolated temporary directory, and verify its SHA-256 and package version.
- [ ] Perform a fresh-install smoke test with an isolated `CATP_HOME`; issue and verify a v2 receipt and retain the command transcript.
- [ ] Create and push annotated tag `v0.7.4` only after registry verification. Verify `git rev-list -n 1 v0.7.4` equals the release commit.
- [ ] Update `docs/RELEASE_0.7.4.md` with registry and tag evidence, then commit as `docs: record verified 0.7.4 publication`.

Release gate: do not begin the experiment rerun until the registry tarball, tag, commit, and local packed tarball have an auditable relationship. If registry repacking makes tarball hashes differ, record both hashes and prove their unpacked file manifests and contents match.

---

## Phase 5: Rebuild the paper artifact and rerun every experiment

The following tasks modify the sibling repository `/Users/zhoulinfeng/catp_paper`. Commit them there separately. Preserve the pre-fix results under a clearly named archive or git tag; do not mix old measurements into new processed data.

### Task 9: Make artifact provenance strict and machine-checkable

**Files:**

- Modify: `/Users/zhoulinfeng/catp_paper/experiments/scripts/build_artifact.sh`
- Modify: `/Users/zhoulinfeng/catp_paper/experiments/scripts/common.sh`
- Modify: `/Users/zhoulinfeng/catp_paper/experiments/artifact/manifest.json`
- Modify: `/Users/zhoulinfeng/catp_paper/experiments/README.md`
- Modify: `/Users/zhoulinfeng/catp_paper/artifact/README.md`
- Modify: `/Users/zhoulinfeng/catp_paper/experiments/artifact/.gitignore`

- [ ] Change the artifact builder to accept only the verified `0.7.4` npm tarball or an exact registry package reference. Reject directories, symlinks, working-tree `dist`, and a package version other than `0.7.4`.
- [ ] Use `npm ci` with a committed lockfile inside the isolated artifact installation. Do not use a caret-resolving `npm install` during an experiment run.
- [ ] Resolve and record: paper commit, CATP release commit, git tag, npm package/version, source tarball SHA-256, resolved executable realpath, executable SHA-256, Node/npm versions, exact installed dependency versions, and lockfile SHA-256.
- [ ] Store paths relative to the artifact root in committed JSON. If absolute paths are needed while running, keep them in uncommitted ephemeral state.
- [ ] Add `verify_artifact` in `common.sh`; every RQ script must call it before executing and abort on any version, realpath, or hash mismatch.
- [ ] Include the pinned tarball or a cryptographically pinned retrieval recipe, lockfile, manifest, scripts, and checksums in the companion artifact. A reader must not need the author's CATP checkout.
- [ ] Add a test invocation that deliberately replaces the executable with a symlink to a local `dist`; expect `verify_artifact` to fail before any case runs.
- [ ] Commit as `artifact: pin experiments to verified catp 0.7.4`.

### Task 10: Correct RQ1 coverage and integrate it into the full run

**Files:**

- Modify: `/Users/zhoulinfeng/catp_paper/experiments/scripts/rq1_adapter_conformance.sh`
- Modify: `/Users/zhoulinfeng/catp_paper/experiments/scripts/rq1b_runtime_in_the_loop.sh`
- Modify: `/Users/zhoulinfeng/catp_paper/experiments/scripts/run_all.sh`
- Modify: `/Users/zhoulinfeng/catp_paper/tables/runtime-coverage.tex`
- Modify: `/Users/zhoulinfeng/catp_paper/tables/runtime-in-the-loop.tex`

- [ ] Retain synthetic payload-to-CLI conformance as RQ1a and describe it only as parser/adapter conformance.
- [ ] Make RQ1b assert exact tested runtime versions, resolved binary paths, and hashes before execution. Record the values in raw metadata and the artifact manifest.
- [ ] Relabel the Codex file case as `Bash-mediated file mutation` unless the tested Codex release exposes and the harness exercises a native file-tool hook event. Do not infer native file mediation from an `exec_command` that invokes `apply_patch`.
- [ ] For every allow case, require the intended side effect and a valid v4 pre-entry/action sidecar. For every deny case, require no side effect and a valid deny entry.
- [ ] Add RQ1b to `run_all.sh` immediately after RQ1a. Abort unless both processed summaries report all cases passed.
- [ ] Regenerate both runtime tables from processed JSON; do not hand-copy case counts.
- [ ] Commit as `experiments: separate adapter and runtime coverage evidence`.

### Task 11: Expand RQ2 for the new fail-closed evidence path

**Files:**

- Modify: `/Users/zhoulinfeng/catp_paper/experiments/scripts/rq2_failure_matrix.sh`
- Modify: `/Users/zhoulinfeng/catp_paper/tables/failure-matrix.tex`

- [ ] Add CLI-observed cases for action-sidecar creation failure, audit append failure, missing sidecar during export, altered sidecar during verification, policy swap after enforcement, and long-prefix action substitution. Keep injected file-fsync and directory-fsync failures in the automated TypeScript suite and import its machine-readable pass/fail summary into RQ2 rather than presenting them as OS-level CLI faults.
- [ ] For persistence failures, assert exit 2 and absence of an allow response. For evidence tampering, assert offline verification rejects the bundle.
- [ ] Keep unit-level fsync call-order evidence separate from CLI-observed failure behavior in processed results.
- [ ] Generate the table from the complete new matrix and state the tested fault boundary rather than implying arbitrary kernel-crash coverage.
- [ ] Commit as `experiments: test binding and durability failures end to end`.

### Task 12: Correct RQ3, Groth16, and anchoring methodology

**Files:**

- Modify: `/Users/zhoulinfeng/catp_paper/experiments/scripts/rq3_overhead.sh`
- Modify: `/Users/zhoulinfeng/catp_paper/experiments/scripts/rq4_verification_cost.sh`
- Move: `/Users/zhoulinfeng/catp_paper/experiments/scripts/rq5_anchoring_tradeoff.sh` -> `/Users/zhoulinfeng/catp_paper/experiments/scripts/anchoring_limitation.sh`
- Modify: `/Users/zhoulinfeng/catp_paper/experiments/scripts/run_all.sh`
- Modify: `/Users/zhoulinfeng/catp_paper/tables/overhead.tex`
- Modify: `/Users/zhoulinfeng/catp_paper/tables/groth16-case-study.tex`
- Modify: `/Users/zhoulinfeng/catp_paper/tables/anchoring-tradeoff.tex`

- [ ] Rename the RQ3 comparison to `CATP Node CLI no-policy baseline`. Do not call it a universal process-spawn floor or generalize its cost to every external-command mediator.
- [ ] Benchmark the new durable action-plus-audit path. Report sample count, warmup, median, p95, dispersion, hardware, filesystem, power state, and whether caches were warm.
- [ ] Make RQ4 consume circuits, verifier artifacts, and deployment metadata copied into the pinned companion artifact. Reject references to the live CATP checkout.
- [ ] Report Groth16 proving time, native verification time, and on-chain gas as distinct metrics. Remove cross-unit claims such as gas being orders of magnitude larger than milliseconds.
- [ ] Make `anchoring_limitation.sh` consume only pinned artifact code and data. Describe CATP as producing an anchor bundle; a deployment-supplied publisher submits it. Do not claim the released CLI periodically publishes anchors.
- [ ] Remove anchoring as RQ5. Rename the harness to `anchoring_limitation.sh`, keep its reproducible measurements as supplemental evidence, and discuss them only as mitigation for the local-log truncation/rollback limitation.
- [ ] Commit as `experiments: align cost studies with measured mechanisms`.

### Task 13: Rerun from a clean, pinned environment

**Files:**

- Replace generated data under `/Users/zhoulinfeng/catp_paper/experiments/raw/`
- Replace generated summaries under `/Users/zhoulinfeng/catp_paper/experiments/processed/`
- Regenerate `/Users/zhoulinfeng/catp_paper/tables/*.tex`

- [ ] Record machine metadata: OS/build, architecture, CPU model and core count, RAM, filesystem, power mode, Node/npm, Claude Code, Codex CLI, Foundry/Solidity, Python, and LaTeX versions.
- [ ] Start from a newly built artifact directory and verify it before running cases.
- [ ] Run `/Users/zhoulinfeng/catp_paper/experiments/scripts/run_all.sh`; require a nonzero exit on any failed assertion.
- [ ] Confirm every raw metadata file names package `0.7.4`, the verified release commit/tag, and the same executable hash.
- [ ] Scan committed artifact and result files with `rg -n '/Users/|/home/|token|api[_-]?key'`; after allowlisting field names and documented redacted examples, expect no personal path or secret values.
- [ ] Independently recompute processed counts and hashes from raw JSON/JSONL; require exact agreement with generated summaries and tables.
- [ ] Commit as `experiments: rerun evaluation on pinned catp 0.7.4`.

---

## Phase 6: Narrow claims, anonymize, and finish the paper

### Task 14: Rewrite claims around demonstrated evidence

**Files:**

- Modify: `/Users/zhoulinfeng/catp_paper/sections/01-introduction.tex`
- Modify: `/Users/zhoulinfeng/catp_paper/sections/03-threat-model.tex`
- Modify: `/Users/zhoulinfeng/catp_paper/sections/04-design.tex`
- Modify: `/Users/zhoulinfeng/catp_paper/sections/05-implementation.tex`
- Modify: `/Users/zhoulinfeng/catp_paper/sections/06-security-analysis.tex`
- Modify: `/Users/zhoulinfeng/catp_paper/sections/07-evaluation.tex`
- Modify: `/Users/zhoulinfeng/catp_paper/sections/08-related-work.tex`
- Modify: `/Users/zhoulinfeng/catp_paper/sections/09-conclusion.tex`

- [ ] State the main contribution as cross-runtime pre-execution authorization with exact policy/action/audit binding and offline-verifiable signed receipts.
- [ ] Enumerate the exact tested runtime event paths. Replace `complete mediation`, `every supported event`, and equivalent universals with claims bounded to those paths.
- [ ] Specify the byte-level/domain-separated constructions of action, policy, audit-entry, export, and receipt commitments, including schema versions.
- [ ] Distinguish chain verification from receipt scope: the audit export proves the selected entry's place in the supplied chain; the signature attests to the selected receipt body, not every future log entry.
- [ ] State that 113 bytes is the independently trusted public-key material only. Offline verification also consumes the receipt, audit export, canonical action, and optionally the policy evidence.
- [ ] Present Groth16 as an alternative-verifier case study rather than a core protocol dependency.
- [ ] Present anchoring only as mitigation for local-log truncation/rollback and as a deployment responsibility; the evaluation must not label it RQ5.
- [ ] Limit RQ3 conclusions to the evaluated CATP implementation and measured baselines.
- [ ] Compare most directly with SAGA and Notarized Agents on enforcement point, exact-action binding, policy binding, signer trust, and offline verification.
- [ ] Ensure abstract, contributions, evaluation answers, and conclusion use the same narrowed scope and terminology.
- [ ] Commit as `paper: narrow claims to verifiable authorization evidence`.

### Task 15: Tighten artifact anonymity and layout

**Files:**

- Modify: `/Users/zhoulinfeng/catp_paper/main.tex`
- Modify: `/Users/zhoulinfeng/catp_paper/bibliography/references.bib`
- Modify: `/Users/zhoulinfeng/catp_paper/bibliography/references-audit.md`
- Modify: `/Users/zhoulinfeng/catp_paper/sections/07-evaluation.tex`
- Modify: `/Users/zhoulinfeng/catp_paper/tables/anchoring-tradeoff.tex`
- Modify: `/Users/zhoulinfeng/catp_paper/tables/failure-matrix.tex`
- Modify: `/Users/zhoulinfeng/catp_paper/tables/groth16-case-study.tex`
- Modify: `/Users/zhoulinfeng/catp_paper/tables/overhead.tex`
- Modify: `/Users/zhoulinfeng/catp_paper/tables/related-work.tex`
- Modify: `/Users/zhoulinfeng/catp_paper/tables/runtime-coverage.tex`
- Modify: `/Users/zhoulinfeng/catp_paper/tables/runtime-in-the-loop.tex`
- Modify: `/Users/zhoulinfeng/catp_paper/tables/security-matrix.tex`
- Modify: `/Users/zhoulinfeng/catp_paper/tables/verification-cost.tex`

- [ ] Keep bibliography-review notes only in `references-audit.md`; remove audit annotations from rendered BibTeX fields.
- [ ] Remove author-identifying filesystem paths and local repository descriptions from paper text, scripts, manifests, raw metadata, and supplemental instructions.
- [ ] Reformat the RQ/environment description so it does not overlap in the compiled two-column PDF.
- [ ] Shorten table captions; move methodology details into surrounding prose or table notes.
- [ ] Check all tables at actual ACSAC column widths and eliminate overfull boxes without shrinking body text below venue norms.
- [ ] Build with `latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex`; expect exit code 0 and no undefined references or citations.
- [ ] Inspect every PDF page at normal zoom for overlap, clipping, illegible tables, accidental deanonymization, and orphan headings.
- [ ] Commit as `paper: finalize anonymous artifact and acsac layout`.

### Task 16: Final reproducibility and submission gate

**Files:**

- Modify: `/Users/zhoulinfeng/catp_paper/README.md`
- Modify: `/Users/zhoulinfeng/catp_paper/artifact/README.md`

- [ ] From a fresh temporary directory, follow only the artifact README to verify checksums, install the pinned package, run the fast test subset, verify a receipt offline, and reproduce every processed table.
- [ ] Confirm no script resolves `/Users/zhoulinfeng/catp`, a local `dist`, or an unpinned registry range.
- [ ] Confirm the paper's numerical claims match processed JSON and generated tables exactly.
- [ ] Run shell syntax checks over all experiment scripts and Python compilation checks over both runtime stubs.
- [ ] Run the full LaTeX build twice and confirm stable references and bibliography.
- [ ] Record the final paper commit, artifact archive SHA-256, CATP `v0.7.4` commit, package tarball SHA-256, and experiment executable SHA-256 in the artifact README.
- [ ] Commit as `artifact: seal acsac reproducibility package`.

## Claim-to-Evidence Acceptance Matrix

| Paper claim | Required implementation evidence | Required experiment evidence |
|---|---|---|
| Enforcement uses an exact policy | v4 entry contains policy hash computed inside the enforcement call | Policy-swap case preserves Policy A binding and rejects Policy B |
| Authorization binds the complete action | v4 entry and sidecar use canonical full-action hash | Same-prefix actions have distinct hashes and reject substitution |
| Decision evidence is durable before return | Action file and log append are file-fsynced; new paths are directory-fsynced | CLI persistence faults fail closed; call-order unit tests pass |
| Receipt is offline verifiable | v2 signature covers policy, action, and audit bindings; trusted key is external | Fresh machine verifies from sealed artifact without CATP checkout |
| Runtime coverage is demonstrated | Named adapters and pre-hook paths exist | RQ1a parser cases plus RQ1b real runtime cases, with exact versions/hashes |
| Artifact corresponds to release | Package/version/tag/commit and executable hashes are linked | Every RQ metadata file carries the same pinned provenance |
| Groth16 is supported | Verifier consistency checks pass | Separate latency and gas results, presented as case study |
| Anchoring mitigates rollback | Anchor-bundle construction is tested | Publisher is explicitly deployment-supplied; no periodic-publication claim |

## Stop Conditions

- Stop release preparation if any policy/action substitution regression succeeds.
- Stop experiment execution if the CLI realpath, hash, version, tag, or source commit does not match the sealed manifest.
- Stop paper editing if results still contain mixed versions; regenerate the full set instead of patching individual numbers.
- Stop submission packaging if an anonymous artifact scan finds a personal path, account identifier, token, or unredacted runtime configuration.
- If native runtime hooks cannot expose a claimed event, narrow the coverage statement; do not simulate the event and label it native.
