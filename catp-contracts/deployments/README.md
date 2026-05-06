# Deployment Artifacts

This directory records CATP Layer 2 testnet deployment metadata.

## Active Layer 2 EVM Path

The active Sepolia EVM deployment is:

```text
sepolia-groth16.json
```

It uses `authorization_groth16_v1`:

- proof backend: Groth16/BN254
- policy commitment hash: MiMC
- commitment version: `2`
- public inputs: `13`
- proof bytes: `256`
- setup manifest: `catp-circuits/groth16/keys/authorization_groth16_v1.manifest.json`

The historical `sepolia.example.json` Halo2 schema is retained only as a failure
reference. Do not use it for live authorization verification: the prior Halo2
Sepolia attempt used an invalid tiny verifier runtime before the bytecode-size
guard was added.

## Required Environment

Create `catp-contracts/.env` from `catp-contracts/.env.example`, or export:

```bash
export CATP_RPC_URL=https://...
export CATP_PRIVATE_KEY=0x...
```

Never commit real RPC credentials or private keys.

## Preflight

From the repository root:

```bash
npm run groth16:generate
npm run groth16:check
cd catp-contracts
forge test --match-path test/layer2/Groth16AuthorizationVerifier.t.sol
cd ..
scripts/deploy-groth16-sepolia.sh --dry-run
```

Expected key hashes for the current dev/testnet setup:

```text
proving key:   c0c4a7cc5d2c0366893a318c6b4eed319e34e609055f10b7aca06a07a53485fe
verifying key: 72b85681f01fa064b495b8ac40085b98b32db951376d76340d7729fb2ee23557
verifier sol:  04dee515888e5aacc7e2250150019afac1c2a58e10780e698eb998ab0ca0a1eb
```

## Deploy

```bash
set -a
source catp-contracts/.env
set +a
scripts/deploy-groth16-sepolia.sh
```

The script:

1. Regenerates the Groth16 verifier and smoke fixture using persisted keys.
2. Requires the existing setup keys.
3. Checks the setup manifest.
4. Builds deployment targets.
5. Checks runtime sizes.
6. Broadcasts `Groth16Verifier`, `Groth16AuthorizationVerifier`, and `AgentAuthorizer`.

After deployment, update or create a deployment JSON using
`sepolia-groth16.example.json` as the schema. Record:

- deployed addresses
- deployment transactions
- gas used
- source hashes
- proving/verifying key hashes
- runtime byte sizes
- deployment log path

## Smoke Test

```bash
set -a
source catp-contracts/.env
set +a
scripts/smoke-groth16-sepolia.sh
```

The smoke script:

1. Refreshes the smoke proof with the persisted setup keys.
2. Refuses to run if local verifier/key hashes differ from deployment metadata.
3. Checks deployed verifier code size.
4. Registers a fresh policy commitment.
5. Executes an authorized action with a real Groth16 proof.
6. Reads cumulative spend.

After smoke succeeds, update the `smoke` block in `sepolia-groth16.json` with
the policy commitment, proof timestamp, register/execute transactions, blocks,
gas, and cumulative spend.

## Setup Reset Policy

The Groth16 setup is circuit-specific. Resetting it changes the proving key,
verifying key, generated verifier, and every deployment bound to that verifier.

Deployment and smoke scripts run with `CATP_GROTH16_REQUIRE_KEYS=1`, so they
will not create a new setup implicitly.

An intentional reset requires both flags:

```bash
CATP_GROTH16_RESET_SETUP=1 CATP_GROTH16_ALLOW_RESET=1 npm run groth16:generate
```

After any reset, deploy a new verifier and create a new deployment metadata
record. Do not reuse an old deployment JSON with new keys.
