# CATP Implementation Plan

## Product Goal

CATP makes autonomous agent activity enforceable locally and provable externally.

The current repository is intentionally scoped to two connected surfaces:

1. **Local enforcement**: Claude Code hooks evaluate tool calls against
   `catp-policy.toml` and write a tamper-evident SHA-256 audit log.
2. **Authorization proofs**: a structured action is proven against a
   committed private policy, then verified either off-chain or by the compact
   Groth16 EVM path.

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
  -> catp witness / catp prove authorization
  -> authorization_groth16_v1 proof manifest
  -> catp verify authorization or AgentAuthorizer.executeAuthorized
```

Current proof versions:

| Proof version | Backend | Role |
|---------------|---------|------|
| `authorization_groth16_v1` | Groth16/BN254 + MiMC | Active EVM/testnet path |
| `authorization_v1` | Halo2/KZG/BN254 + Poseidon | Off-chain/research path |

`authorization_groth16_v1` is the active EVM path because the generated Halo2
Solidity verifier for `authorization_v1` exceeded the EVM runtime bytecode
limit. The Halo2 path remains useful for off-chain verification and proof-system
research.

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

- Halo2 `ProveAuthorization` circuit at `k=12`
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
- Removed blocked Halo2 EVM adapter code.
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
- Global npm install smoke path documented and verified for `0.2.2`.
- Missing repo checkout/prover script errors now explain how to proceed.
- `examples/authorization-basic` remains the first user-facing proof fixture.
- `npm run groth16:check` remains the canonical setup integrity check.

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

### Packaging Decision For WASM And Proving

- `@catp-protocol/cli` stays light.
- Full `authorization_groth16_v1` proving, calldata encoding, Sepolia execution,
  contracts, and setup checks stay repository-based.
- `catp-circuits/wasm` and SDK `ProofClient` remain local Halo2/off-chain
  `authorization_v1` artifacts.
- `catp-wasm` is not published yet.
- Hosted prover/verifier service is deferred until there is a concrete product
  reason, threat model, and operational plan.

---

## Active Milestones

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
verifier or a dedicated off-chain verifier path.

Do not add local Groth16 cryptographic verification to the CLI until the project
chooses a stable verifier implementation and package boundary.

### Published WASM Package Or Hosted Prover

`catp-wasm` and hosted prover/verifier services are out of the current package
surface. Revisit only with a concrete product reason, threat model, and
operations plan.

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
