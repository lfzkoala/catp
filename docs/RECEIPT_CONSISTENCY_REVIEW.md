# Receipt consistency review (2026-09-26)

The paper's controlled mechanism experiment found a missing validation step in
published `@catp-protocol/cli@0.7.5`. A receipt can have a valid Ed25519 signature,
valid receipt hash and correct policy/action/export commitments while its copied
`decision`, `tool`, `reason`, `rule_matched`, or `timestamp` contradicts the
selected audit entry. The verifier previously compared commitments but not these
copies; its output could therefore describe a different decision from the entry.

This is a consistency-contract defect, not a signature forgery or evidence of
key compromise. Normal CATP issuance copies the fields correctly. Reproduction
uses a temporary research signer to isolate signature validity from consistency.
The paper retains every signed example and diagnostic in
`experiments/mechanism/run-20260926-02` (13 checks; five inconsistencies accepted
by the published release). The optional Groth16 backend is not involved.

## Local repair and verification

`verifyReceiptAuditExportV2` now requires equality for the copied fields and
phase, and maps receipt `timestamp` to entry `ts`. Valid v2 receipts and legacy
v1 semantics remain covered by the existing tests. New tests authenticate each
inconsistent body with a valid research signature before expecting rejection.

Validation: plugin typecheck and build, all 335 tests in 21 suites, and
`npm run smoke:receipt` pass. Independent model code review checked the
consistency fix; this is not an external security audit.

## Unreleased boundary

Package version and release tags have not changed. This source repair is not
published 0.7.5 and must not be substituted into the paper's pinned artifact.
A new authorized release, registry identity verification and affected paper
remeasurement are required. No publish, push or tag movement was performed.
