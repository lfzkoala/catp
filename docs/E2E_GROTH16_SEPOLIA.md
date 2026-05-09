# E2E Groth16 Sepolia Flow

This guide reproduces the current CATP Layer 0/2 slice:

```text
catp-policy.toml
  -> structured action
  -> Groth16 witness
  -> authorization_groth16_v1 proof artifact
  -> offline calldata or Sepolia execution
  -> shareable proof manifest
```

The active Sepolia deployment is recorded in:

```text
catp-contracts/deployments/sepolia-groth16.json
```

Current addresses:

```text
Groth16Verifier:              0xb90ab689ac39c83271a3b630844cf71d77071d60
Groth16AuthorizationVerifier: 0xeeebbf575556cd673209525573334934a4f1c3f1
AgentAuthorizer:              0xb5290d2c376d84c15de4fbfde64a9a5499eee23e
chainId:                      11155111
```

## 1. Install And Build

From the repository root:

```bash
npm install
npm run build --workspace catp-plugin
npm run build --workspace catp-sdk
```

Check the Groth16 setup and deployment metadata:

```bash
npm run groth16:check
```

## 2. Create Policy And Action

Create `catp-policy.toml`:

```toml
[agent]
id = "demo-agent"
version = "1"

[authorization]
allowed_action = "Swap"
allowed_protocol = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
allowed_token = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
max_value_per_tx = "1000"
max_value_total = "10000"
valid_from = "1778042786"
valid_until = "1778129246"

[[rules]]
tool = "Bash"
allow = true
```

Create `action.json`:

```json
{
  "actionType": "Swap",
  "protocol": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "token": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "value": "500"
}
```

## 3. Generate Proof Artifact

Use a timestamp accepted by the policy window:

```bash
npm run groth16:prove -- \
  --action action.json \
  --current-timestamp 1778042846 \
  --cumulative-spend 0 \
  --out authorization_groth16_v1.json
```

This command builds a witness through `catp witness`, then generates an
`authorization_groth16_v1` Groth16 proof artifact.

## 4. Encode Offline Calldata

```bash
npm run groth16:encode-execute -- \
  --artifact authorization_groth16_v1.json \
  --deployment catp-contracts/deployments/sepolia-groth16.json \
  --out execute-authorized.calldata.json
```

This validates artifact shape and emits calldata for:

- `registerPolicy(bytes32)`
- `executeAuthorized(bytes32,bytes,uint256,bytes)`

It does not read RPC state and does not broadcast.

## 5. Execute On Sepolia

Export credentials:

```bash
export CATP_RPC_URL=https://...
export CATP_PRIVATE_KEY=0x...
```

Broadcast:

```bash
npm run groth16:execute -- \
  --artifact authorization_groth16_v1.json \
  --deployment catp-contracts/deployments/sepolia-groth16.json \
  --out execute-authorized.receipt.json
```

The script registers the policy if inactive, checks on-chain cumulative spend,
executes the authorization proof, and writes receipt metadata.

## 6. Create A Proof Manifest

Build a shareable structural manifest:

```bash
node catp-plugin/dist/cli.js prove authorization \
  --artifact authorization_groth16_v1.json \
  --verifier 0xeeebbf575556cd673209525573334934a4f1c3f1 \
  --agent-authorizer 0xb5290d2c376d84c15de4fbfde64a9a5499eee23e \
  --chain-id 11155111 \
  --out catp-proof-manifest.json
```

If the proof came from an audit-linked action, include:

```bash
--audit-commitment <64-character-audit-commitment>
```

Validate manifest structure:

```bash
node catp-plugin/dist/cli.js verify authorization \
  --manifest catp-proof-manifest.json
```

Current `verify authorization` checks manifest and artifact consistency. It does
not perform cryptographic proof verification locally; cryptographic verification
is performed by the EVM verifier or a dedicated off-chain verifier.

## Known Limits

- The Groth16 setup keys are stable dev/testnet keys, not a mainnet ceremony.
- Proof artifacts are bound to `authorization_groth16_v1`; any proof-boundary
  change requires a new version and verifier address.
- The manifest is a portable envelope for proof sharing and indexing. It is not
  a replacement for verifier execution.
