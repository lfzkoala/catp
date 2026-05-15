# Authorization Basic Example

This example is the smallest CATP Layer 2 authorization flow:

```text
catp-policy.toml + action.json
  -> Groth16 witness
  -> authorization_groth16_v1 proof artifact
  -> CATP proof manifest
  -> manifest validation
```

It uses the same example policy fields as the checked-in
`authorization_groth16_v1` fixture.

## Files

```text
catp-policy.toml  Private authorization policy fields and local CATP agent metadata
action.json       Public structured action to prove against the policy
```

The policy allows:

- action: `Swap`
- protocol: `0xaaaa...aaaa`
- token: `0xbbbb...bbbb`
- max value per transaction: `1000`
- max cumulative spend: `10000`
- validity window: `1778042786` to `1778129246`

The action spends `500`, so it satisfies the policy when
`currentTimestamp=1778042846` and `cumulativeSpend=0`.

## Generate A Witness

From the repository root:

```bash
catp witness \
  --file examples/authorization-basic/catp-policy.toml \
  --action examples/authorization-basic/action.json \
  --current-timestamp 1778042846 \
  --cumulative-spend 0 \
  --out /tmp/catp-authorization-basic.witness.json
```

The generated witness should match the current Groth16 fixture shape:

```text
actionType
protocol
token
value
currentTimestamp
cumulativeSpend
allowedAction
allowedProtocol
allowedToken
maxValuePerTx
maxValueTotal
validFrom
validUntil
```

## Generate A Proof Manifest

Full Groth16 proof generation requires a repository checkout because it uses the
Go/Gnark prover and circuit assets under `catp-circuits/groth16`.

From the repository root:

```bash
catp prove authorization \
  --file examples/authorization-basic/catp-policy.toml \
  --action examples/authorization-basic/action.json \
  --current-timestamp 1778042846 \
  --cumulative-spend 0 \
  --artifact-out /tmp/catp-authorization-basic.proof.json \
  --deployment catp-contracts/deployments/sepolia-groth16.json \
  --out /tmp/catp-authorization-basic.manifest.json
```

This command writes the proof artifact and manifest only; it should not modify
the repository worktree.

Validate the manifest:

```bash
catp verify authorization \
  --manifest /tmp/catp-authorization-basic.manifest.json
```

This manifest validation is structural. Cryptographic verification is performed
by the EVM verifier or a dedicated off-chain verifier path.
