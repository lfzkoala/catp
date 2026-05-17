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
| Signed authorization receipt | Non-ZK external verification | 0.3.0 release candidate |
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
- CLI commands: `init`, `validate`, `hook`, `log`, `anchor`
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
- Audit-linked manifest validation checks audit entry presence and structured
  authorization action consistency.
- Calldata encoder validates the contract-facing artifact shape before emitting
  `registerPolicy` / `executeAuthorized` calldata.

### Repository Cleanup

- Removed inactive placeholder crates/modules.
- Removed inactive off-chain verifier code from the active repository surface.
- Removed committed WASM build output.
- Moved test-only Solidity stubs out of production sources.
- Removed unused primitives crate and inactive output-verification contracts.

### Release Hygiene And Proof UX

- README, INSTALL, ARCHITECTURE, examples, and security review docs aligned to
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
- `catp log show --commitments` exposes full commitments for receipt issuance.
- `catp receipt keygen` creates local Ed25519 signing keys.
- `catp receipt sign` signs an existing audit export.
- `catp receipt issue` is the main path: it verifies the local audit chain,
  exports the audit entry, binds the policy commitment, and signs
  `catp_authorization_receipt_v1`.
- `catp receipt verify` validates the signature and can also check the receipt
  against the audit export and `catp-policy.toml`.
- Receipt verification has regression tests for tampered signatures, wrong
  public keys, mismatched audit exports, missing policy commitments, and policy
  mismatches.
- `examples/receipt-basic` documents and exercises the default non-ZK external
  verification path.

### Universal Agent Runtime Adapters

- Runtime-neutral `ToolAction` and `RuntimeAdapter` contracts are documented in
  code and architecture docs.
- Claude Code `PreToolUse` / `PostToolUse` parsing is isolated in the
  `claude-code` adapter.
- Hook stdin parsing is centralized and tested.
- `catp hook pre/post` accept an injectable adapter internally and expose
  `--runtime claude-code` in the CLI.
- `catp hook runtimes` lists supported runtime adapter ids.
- README and ARCHITECTURE describe the adapter model and current supported
  runtime.

### Packaging Decision For Proving

- `@catp-protocol/cli` stays light.
- Full `authorization_groth16_v1` proving, calldata encoding, Sepolia execution,
  contracts, and setup checks stay repository-based.
- Hosted prover/verifier service is deferred until there is a concrete product
  reason, threat model, and operational plan.

---

## Active Milestones

### P0: 0.3.0 Release Hygiene

Status: active.

Goal: close the signed receipt mainline as an npm release.

Work:

- Keep README / INSTALL / examples aligned around the three verification levels:
  local audit, signed receipt, optional ZK proof manifest.
- Run the npm CLI smoke path for receipt issuance and verification from a clean
  directory.
- Bump `@catp-protocol/cli` to `0.3.0`.
- Run package checks, `npm pack --dry-run`, publish, tag, and verify install.

Exit criteria:

- Fresh install can run `catp init`, produce an audit entry, issue a receipt,
  and verify it against audit export and policy.
- CI is green for the release tag.
- npm returns `@catp-protocol/cli@0.3.0` and `catp --version` reports `0.3.0`.

### P0: Authorization Proof Security Hardening

Status: ongoing guardrail work.

Goal: keep `authorization_groth16_v1` from accepting invalid actions or drifting
from its documented public input schema.

Work:

- Keep `docs/SECURITY_REVIEW_AUTHORIZATION.md` current as the living review.
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

Claude Code is the only supported runtime adapter today. Add future runtime
adapters only when there is a concrete payload shape and test fixture, such as
OpenAI Agents SDK, LangGraph/LangChain, Cursor-style tool runners, MCP tool
gateways, or local shell/tool executors.

### Local Cryptographic Verification For Groth16 Manifests

`catp verify authorization` intentionally performs structural and audit-linked
manifest validation today. Cryptographic verification remains the job of the EVM
verifier.

Do not add local Groth16 cryptographic verification to the CLI until the project
chooses a stable verifier implementation and package boundary.

### Hosted Prover

Hosted prover/verifier services are out of the current package surface. Revisit
only with a concrete product reason, threat model, and operations plan.

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
