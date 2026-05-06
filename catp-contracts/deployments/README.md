# Deployment Artifacts

Record testnet and mainnet deployment metadata in this directory.

Suggested file names:

- `sepolia.json`
- `base-sepolia.json`
- `arbitrum-sepolia.json`

Suggested fields:

```json
{
  "chainId": 11155111,
  "network": "sepolia",
  "deployedAt": "2026-05-05T00:00:00Z",
  "deployer": "0x...",
  "halo2Verifier": "0x...",
  "halo2AuthorizationVerifier": "0x...",
  "agentAuthorizer": "0x...",
  "authorizationProofVersion": "authorization_v1",
  "srs": "catp-layer2-k12.srs",
  "srsSha256": "...",
  "halo2VerifierCodeHash": "0x...",
  "transactions": {
    "halo2Verifier": "0x...",
    "halo2AuthorizationVerifier": "0x...",
    "agentAuthorizer": "0x..."
  },
  "gasUsed": {
    "halo2VerifierDeploy": "0",
    "halo2AuthorizationVerifierDeploy": "0",
    "agentAuthorizerDeploy": "0",
    "executeAuthorized": "0"
  }
}
```
