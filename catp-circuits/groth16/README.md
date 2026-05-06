# CATP Groth16 Authorization Verifier

This directory contains the compact EVM verifier path for `authorization_groth16_v1`.

`authorization_groth16_v1` is intentionally a separate proof version from the Halo2
`authorization_v1` path. It keeps the 13 public authorization inputs but uses a
Groth16/BN254 proof and a MiMC policy commitment version (`2`) so the EVM verifier
fits under the contract-size limit.

## Stable Dev/Testnet Setup

The current persisted setup lives in `keys/`:

- `authorization_groth16_v1.pk`
- `authorization_groth16_v1.vk`
- `authorization_groth16_v1.manifest.json`

Current hashes:

```text
proving key:   c0c4a7cc5d2c0366893a318c6b4eed319e34e609055f10b7aca06a07a53485fe
verifying key: 72b85681f01fa064b495b8ac40085b98b32db951376d76340d7729fb2ee23557
verifier sol:  04dee515888e5aacc7e2250150019afac1c2a58e10780e698eb998ab0ca0a1eb
```

These keys are suitable for deterministic dev/testnet verification. They are not
a mainnet ceremony. A production release should either run and document a proper
Groth16 circuit-specific ceremony or explicitly ship with a different trust model.

## Commands

Generate the verifier, smoke fixture, proof JSON, and setup manifest:

```bash
npm run groth16:generate
```

Generate from a specific witness file:

```bash
bash scripts/generate-groth16-verifier.sh \
  --witness catp-circuits/groth16/fixtures/authorization_groth16_v1.witness.example.json \
  --out /tmp/authorization_groth16_v1.json
```

Witness files use root-level policy and action fields:

```json
{
  "actionType": "0",
  "protocol": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "token": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "value": "500",
  "currentTimestamp": "1778042846",
  "cumulativeSpend": "0",
  "allowedAction": "0",
  "allowedProtocol": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "allowedToken": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "maxValuePerTx": "1000",
  "maxValueTotal": "10000",
  "validFrom": "1778042786",
  "validUntil": "1778129246"
}
```

All integer fields may be JSON numbers or strings. Strings are preferred for
SDK-generated JSON because JavaScript numbers cannot safely represent every
`u64` value. `protocol`, `token`, `allowedProtocol`, and `allowedToken` must be
32-byte hex strings.

Check runtime sizes:

```bash
npm run groth16:size
```

Check the persisted setup, generated verifier, wrapper source, build artifacts,
and Sepolia deployment metadata agree:

```bash
npm run groth16:check
```

Build a witness, proof artifact, and offline execution calldata:

```bash
npm run groth16:prove -- \
  --action action.json \
  --current-timestamp 1778042846 \
  --cumulative-spend 0 \
  --out authorization_groth16_v1.json

npm run groth16:encode-execute -- \
  --artifact authorization_groth16_v1.json \
  --out execute-authorized.calldata.json
```

Run the Solidity proof adapter tests:

```bash
cd catp-contracts
forge test --match-path test/layer2/Groth16AuthorizationVerifier.t.sol
```

## SDK Consumption

The TypeScript SDK can consume the generated `authorization_groth16_v1.json`
artifact and convert it into the fields needed by
`AgentAuthorizer.executeAuthorized`:

```ts
import {
  executeAuthorizedArgsFromGroth16Call,
  groth16ArtifactToAuthorizationCall,
} from "@catp/sdk/layer2";

const call = groth16ArtifactToAuthorizationCall(artifact);
const args = executeAuthorizedArgsFromGroth16Call(call);

// Pass args to AgentAuthorizer.executeAuthorized:
// [policyCommitment, actionData, currentTimestamp, proof]
```

This is an artifact-consumption bridge, not an embedded browser/node Groth16
prover. Packaging the gnark prover as a service, CLI, or native module is a
separate production decision.

## Security Review Notes

Current review decision: keep `authorization_groth16_v1` as the testnet EVM
proof version without rotating the verifier.

Reviewed assumptions:

- Public input order is fixed at 13 values:
  `policyCommitment`, `actionType`, `protocol[4]`, `token[4]`, `value`,
  `currentTimestamp`, `cumulativeSpend`.
- The circuit range-checks all public and private integer fields to 64 bits.
- The circuit binds public action fields to private allowed policy fields.
- The circuit enforces:
  - `value > 0`
  - `value <= maxValuePerTx`
  - `cumulativeSpend + value <= maxValueTotal`
  - `validFrom <= currentTimestamp <= validUntil`
  - MiMC policy commitment over the private policy fields, domain tag `"CATP"`,
    and commitment version `2`
- The Solidity adapter rejects malformed proof shape before calling the generated
  verifier: 13 public inputs and 256 proof bytes are required.
- `AgentAuthorizer` rejects stale/future proofs and binds replay prevention to
  `cumulativeSpend`.
- The Solidity ABI enum decoder rejects invalid `ActionData.ActionType` values
  before proof verification.
- The SDK and Go witness parser reject invalid action enum values before proof
  generation.

Known non-mainnet assumption:

- The persisted Groth16 setup is stable for dev/testnet, but it is not a public
  mainnet ceremony. Mainnet requires a documented circuit-specific ceremony or
  an explicit weaker-trust-model decision.

Known design choice:

- The circuit currently proves `actionType == allowedAction` and range-checks
  both values to 64 bits. It does not independently constrain the enum to
  `0..3` inside the circuit. That is acceptable for the current EVM path because
  invalid enum values are rejected by Solidity ABI decoding, and by SDK/prover
  validation before proof generation. Adding in-circuit enum bounds would require
  a new setup, verifier, deployment, and proof-version decision.

## Setup Reset Guard

The generator reuses persisted keys by default. Resetting the setup changes the
proving key, verifying key, generated verifier, and every deployment bound to
that verifier.

To reset intentionally:

```bash
CATP_GROTH16_RESET_SETUP=1 CATP_GROTH16_ALLOW_RESET=1 npm run groth16:generate
```

Deployment and smoke scripts run with `CATP_GROTH16_REQUIRE_KEYS=1`, so they
refuse to create a new setup implicitly.
