# Authorization Basic Example

This example is the smallest CATP authorization flow:

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
catp validate --file examples/authorization-basic/catp-policy.toml
```

The validation summary should include:

```text
authorization: authorization_groth16_v1-ready
allowedAction: Swap
maxValuePerTx: 1000
maxValueTotal: 10000
```

Then generate the witness:

```bash
catp witness \
  --file examples/authorization-basic/catp-policy.toml \
  --action examples/authorization-basic/action.json \
  --current-timestamp 1778042846 \
  --cumulative-spend 0 \
  --out /tmp/catp-authorization-basic.witness.json
```

The generated witness should contain:

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

The command summary should include:

```text
proofVersion=authorization_groth16_v1
actionType=0
value=500
currentTimestamp=1778042846
cumulativeSpend=0
maxValuePerTx=1000
maxValueTotal=10000
```

## Generate And Validate A Proof Manifest

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
the repository worktree. The summary should include:

```text
proofVersion=authorization_groth16_v1
value=500
currentTimestamp=1778042846
cumulativeSpend=0
chainId=11155111
verifier=0xeeebbf575556cd673209525573334934a4f1c3f1
agentAuthorizer=0xb5290d2c376d84c15de4fbfde64a9a5499eee23e
sourceArtifact=/tmp/catp-authorization-basic.proof.json
cryptographicVerification=external:EVM-or-offchain-verifier
```

Validate the manifest:

```bash
catp verify authorization \
  --manifest /tmp/catp-authorization-basic.manifest.json
```

The validation summary should repeat the same proof version, policy commitment,
deployment metadata, value, timestamp, and cumulative spend.

This manifest validation is structural. Cryptographic verification is performed
by the EVM verifier or a dedicated off-chain verifier path.

## Optional: Prepare On-Chain Execution

To build calldata without broadcasting:

```bash
npm run groth16:encode-execute -- \
  --artifact /tmp/catp-authorization-basic.proof.json \
  --out /tmp/catp-authorization-basic.calldata.json
```

To dry-run or broadcast with the checked-in Sepolia deployment metadata, use:

```bash
npm run groth16:execute -- \
  --artifact /tmp/catp-authorization-basic.proof.json \
  --dry-run
```
