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

### Repository Cleanup

- Removed inactive placeholder crates/modules.
- Removed blocked Halo2 EVM adapter code.
- Removed committed WASM build output.
- Moved test-only Solidity stubs out of production sources.
- Removed unused primitives crate and inactive output-verification contracts.

---

## Next Milestones

### P0: Release Hygiene

Goal: make the current 0.2.x surface boring to install, test, and explain.

Work:

- Keep README, INSTALL, ARCHITECTURE, and release notes aligned with the current
  enforcement + authorization scope.
- Document npm package limits clearly: local enforcement and manifest tooling are
  in npm; full Groth16 proof generation requires a repo checkout.
- Keep `examples/authorization-basic` working as the first user-facing proof
  fixture.
- Keep `npm run groth16:check` as the canonical setup integrity check.

Exit criteria:

- A new user can install `@catp-protocol/cli`, run `catp init`, `catp validate`,
  and understand when they need the repo checkout.
- A developer can reproduce the Groth16 proof artifact and verify/deploy path
  from documented commands.

### P0: Authorization Proof Security Hardening

Goal: reduce the chance that `authorization_groth16_v1` verifies an invalid
action or drifts from its documented public input schema.

Work:

- Keep `docs/SECURITY_REVIEW_AUTHORIZATION.md` current.
- Add regression tests for any issue found in policy encoding, witness
  generation, proof artifact validation, calldata encoding, or contract state
  checks.
- Treat changes to public input order, action encoding, commitment hash, proof
  backend, verifier calldata format, or setup keys as a new proof version.

Exit criteria:

- Critical/high review findings are fixed or explicitly deferred with rationale.
- Groth16 setup hashes, verifier source hash, wrapper hash, and deployment
  metadata remain reproducible through `npm run groth16:check`.

### P1: Proof UX

Goal: make audit-linked authorization proofs feel like one product flow instead
of several scripts.

Work:

- Improve CLI messages for `catp witness`, `catp prove authorization`, and
  `catp verify authorization`.
- Decide whether cryptographic local verification of Groth16 manifests belongs
  in the CLI, SDK, or a separate verifier binary/service.
- Add a short “copy this flow” example for audit-linked proof manifests.

Exit criteria:

- A user can move from an audit entry to a proof manifest without reading the
  prover internals.
- Manifest verification output is understandable without exposing private policy
  fields.

### P1: Universal Agent Runtime Adapters

Goal: make CATP a runtime-neutral agent authorization protocol, with Claude Code
as the first adapter rather than the product boundary.

Work:

- Define a runtime-neutral tool/action event shape for enforcement decisions,
  audit logging, and optional authorization proof generation.
- Split Claude Code `PreToolUse` / `PostToolUse` parsing from the core policy
  engine and audit writer.
- Keep the existing Claude Code hook behavior stable while routing it through
  the generic runtime interface.
- Document the adapter model for future integrations such as OpenAI Agents SDK,
  LangGraph/LangChain, Cursor-style tool runners, MCP tool gateways, and local
  shell/tool executors.

Exit criteria:

- The core enforcement path can be tested without Claude Code hook fixtures.
- Adding a new agent runtime only requires implementing an adapter that maps
  its tool-call event into CATP's common event shape.
- README and ARCHITECTURE describe CATP as a universal authorization protocol
  with Claude Code as the first supported adapter.

### P1: Packaging Decision for WASM and Proving

Goal: decide how much proving capability belongs in published packages.

Options:

- Keep npm CLI light and repo-based for proving.
- Publish `catp-wasm` as a separate generated package artifact.
- Provide a hosted or local verifier/prover service.

Exit criteria:

- The package boundary is explicit and reflected in README, INSTALL, and SDK
  examples.

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
