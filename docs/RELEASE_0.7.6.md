# CATP CLI 0.7.6 release candidate

Status: **UNPUBLISHED**. Prepared 2026-09-26. Registry readback on that date
reported latest 0.7.5 and no 0.7.6. The version increment identifies a behavior
change; it is not a retry of a failed publish. Existing tags remain unchanged.

## Change and security scope

The v2 receipt verifier now rejects a validly signed receipt if its copied tool,
decision, phase, matched rule, reason or timestamp differs from the selected
audit entry. The timestamp comparison maps receipt `timestamp` to entry `ts`.
The earlier policy/action/export and full-action checks remain in force. Legacy
v1 behavior and ordinary issuance are unchanged.

The published 0.7.5 verifier accepts five of the inconsistent fields in the
paper's controlled signer experiment. This is an evidence-consistency defect,
not an unprivileged signature forgery: reproducing it requires signing authority.
Five regression cases first establish valid signatures and then assert rejection.
See `docs/RECEIPT_CONSISTENCY_REVIEW.md` for the original finding.

## Candidate validation

The behavior repair at `b518320` passed typecheck, build, 335 plugin tests in
21 suites, and the receipt smoke. The versioned candidate must additionally pass
`bash check.sh`, build and a fresh tarball install/smoke on its exact committed
source. The subsequent validation record will identify that commit and results.
Local tarball checks are release engineering evidence, not registry experiments.

## Authorized local work versus publication gate

No npm publish, push, new release tag, or external artifact upload is authorized
by the current task. The candidate is prepared locally for review. The install
instructions continue to point at the actual published version 0.7.5.

After explicit publication authorization, the existing tag-triggered Release
workflow can publish this candidate: push the approved commit, create a new
annotated `v0.7.6` pinned to the exact verified candidate, and push that new tag.
Never move `v0.7.5` or silently tag a later branch tip. The workflow checks the
tag/checkout identity and package version, runs tests/build and uses npm Trusted
Publishing. Registry verification necessarily follows the tag-triggered publish.

The remaining sequence is: read registry version/integrity; fetch and verify the
tarball and complete installed package; fresh-install receipt smoke; preserve
paper 0.7.5 evidence; pin 0.7.6 as a distinct artifact; rerun the 13 consistency
cases, affected receipt security checks and absolute receipt-cost measurements;
regenerate affected tables/text; run artifact/PDF/anonymous checks; freeze and
seal only after all gates pass. Unchanged runtime/overhead/Groth16 results keep
their original 0.7.5 provenance and are never relabeled as 0.7.6 measurements.
