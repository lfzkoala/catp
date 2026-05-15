#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACTS_DIR="$ROOT_DIR/catp-contracts"
DEPLOYMENT_FILE="$CONTRACTS_DIR/deployments/sepolia-groth16.json"
VERIFIER_FILE="$CONTRACTS_DIR/src/authorization/Groth16Verifier.sol"
FIXTURE_FILE="$CONTRACTS_DIR/test/authorization/Groth16SmokeFixture.sol"
SMOKE_JSON="$ROOT_DIR/catp-circuits/groth16/build/authorization_groth16_v1.json"
SETUP_MANIFEST="$ROOT_DIR/catp-circuits/groth16/keys/authorization_groth16_v1.manifest.json"

if [[ ! -f "$DEPLOYMENT_FILE" ]]; then
  echo "Missing deployment file: $DEPLOYMENT_FILE" >&2
  exit 1
fi

if [[ -z "${CATP_RPC_URL:-}" ]]; then
  echo "Missing CATP_RPC_URL" >&2
  exit 1
fi

if [[ -z "${CATP_PRIVATE_KEY:-}" ]]; then
  echo "Missing CATP_PRIVATE_KEY" >&2
  exit 1
fi

echo "==> Refreshing Groth16 smoke proof"
CATP_GROTH16_REQUIRE_KEYS=1 bash "$ROOT_DIR/scripts/generate-groth16-verifier.sh"

if [[ ! -f "$SETUP_MANIFEST" ]]; then
  echo "Missing Groth16 setup manifest: $SETUP_MANIFEST" >&2
  exit 1
fi

EXPECTED_VERIFIER_SHA256="$(jq -r '.groth16VerifierSourceSha256' "$DEPLOYMENT_FILE")"
LOCAL_VERIFIER_SHA256="$(shasum -a 256 "$VERIFIER_FILE" | awk '{print $1}')"
MANIFEST_VERIFIER_SHA256="$(jq -r '.verifierSourceSha256' "$SETUP_MANIFEST")"
if [[ "$EXPECTED_VERIFIER_SHA256" != "$LOCAL_VERIFIER_SHA256" ]]; then
  echo "Local Groth16 verifier source does not match deployment metadata." >&2
  echo "Expected: $EXPECTED_VERIFIER_SHA256" >&2
  echo "Actual:   $LOCAL_VERIFIER_SHA256" >&2
  echo "Refusing to run smoke test against a verifier/proving-key mismatch." >&2
  exit 1
fi
if [[ "$EXPECTED_VERIFIER_SHA256" != "$MANIFEST_VERIFIER_SHA256" ]]; then
  echo "Groth16 setup manifest does not match deployment metadata." >&2
  echo "Expected: $EXPECTED_VERIFIER_SHA256" >&2
  echo "Manifest: $MANIFEST_VERIFIER_SHA256" >&2
  exit 1
fi

EXPECTED_PK_SHA256="$(jq -r '.provingKeySha256' "$DEPLOYMENT_FILE")"
EXPECTED_VK_SHA256="$(jq -r '.verifyingKeySha256' "$DEPLOYMENT_FILE")"
MANIFEST_PK_SHA256="$(jq -r '.provingKeySha256' "$SETUP_MANIFEST")"
MANIFEST_VK_SHA256="$(jq -r '.verifyingKeySha256' "$SETUP_MANIFEST")"
if [[ "$EXPECTED_PK_SHA256" != "$MANIFEST_PK_SHA256" || "$EXPECTED_VK_SHA256" != "$MANIFEST_VK_SHA256" ]]; then
  echo "Groth16 setup key hashes do not match deployment metadata." >&2
  echo "Expected pk: $EXPECTED_PK_SHA256" >&2
  echo "Manifest pk: $MANIFEST_PK_SHA256" >&2
  echo "Expected vk: $EXPECTED_VK_SHA256" >&2
  echo "Manifest vk: $MANIFEST_VK_SHA256" >&2
  exit 1
fi

if [[ ! -f "$SMOKE_JSON" || ! -f "$FIXTURE_FILE" ]]; then
  echo "Groth16 smoke fixture generation did not create required outputs." >&2
  exit 1
fi

GROTH16_VERIFIER="$(jq -r '.groth16Verifier' "$DEPLOYMENT_FILE")"
GROTH16_AUTHORIZATION_VERIFIER="$(jq -r '.groth16AuthorizationVerifier' "$DEPLOYMENT_FILE")"
AUTHORIZER="$(jq -r '.agentAuthorizer' "$DEPLOYMENT_FILE")"

echo "==> Checking deployed Groth16 verifier"
DEPLOYED_CODE="$(cast code "$GROTH16_VERIFIER" --rpc-url "$CATP_RPC_URL")"
DEPLOYED_HEX="${DEPLOYED_CODE#0x}"
DEPLOYED_BYTES=$(( ${#DEPLOYED_HEX} / 2 ))
DEPLOYED_HASH="$(cast keccak "$DEPLOYED_CODE")"
echo "Groth16Verifier:   $GROTH16_VERIFIER"
echo "Runtime code size: ${DEPLOYED_BYTES} bytes"
if (( DEPLOYED_BYTES == 0 )); then
  echo "No code found at Groth16Verifier address." >&2
  exit 1
fi
if (( DEPLOYED_BYTES > 24576 )); then
  echo "Deployed Groth16Verifier exceeds EVM runtime limit." >&2
  exit 1
fi
EXPECTED_DEPLOYED_HASH="$(jq -r '.deployedRuntimeCodeKeccak256.groth16Verifier // empty' "$DEPLOYMENT_FILE")"
if [[ -n "$EXPECTED_DEPLOYED_HASH" && "$EXPECTED_DEPLOYED_HASH" != "$DEPLOYED_HASH" ]]; then
  echo "Deployed Groth16Verifier runtime hash does not match metadata." >&2
  echo "Expected: $EXPECTED_DEPLOYED_HASH" >&2
  echo "Actual:   $DEPLOYED_HASH" >&2
  exit 1
fi

echo "==> Checking deployed Groth16 authorization wrapper"
WRAPPER_CODE="$(cast code "$GROTH16_AUTHORIZATION_VERIFIER" --rpc-url "$CATP_RPC_URL")"
WRAPPER_HEX="${WRAPPER_CODE#0x}"
WRAPPER_BYTES=$(( ${#WRAPPER_HEX} / 2 ))
WRAPPER_HASH="$(cast keccak "$WRAPPER_CODE")"
echo "Groth16AuthorizationVerifier: $GROTH16_AUTHORIZATION_VERIFIER"
echo "Runtime code size:            ${WRAPPER_BYTES} bytes"
if (( WRAPPER_BYTES == 0 )); then
  echo "No code found at Groth16AuthorizationVerifier address." >&2
  exit 1
fi
if (( WRAPPER_BYTES > 24576 )); then
  echo "Deployed Groth16AuthorizationVerifier exceeds EVM runtime limit." >&2
  exit 1
fi
EXPECTED_WRAPPER_HASH="$(jq -r '.deployedRuntimeCodeKeccak256.groth16AuthorizationVerifier // empty' "$DEPLOYMENT_FILE")"
if [[ -n "$EXPECTED_WRAPPER_HASH" && "$EXPECTED_WRAPPER_HASH" != "$WRAPPER_HASH" ]]; then
  echo "Deployed Groth16AuthorizationVerifier runtime hash does not match metadata." >&2
  echo "Expected: $EXPECTED_WRAPPER_HASH" >&2
  echo "Actual:   $WRAPPER_HASH" >&2
  exit 1
fi

POLICY_COMMITMENT="$(jq -r '.policyCommitment' "$SMOKE_JSON")"
ACTION_DATA="$(jq -r '.actionData' "$SMOKE_JSON")"
CURRENT_TIMESTAMP="$(jq -r '.currentTimestamp' "$SMOKE_JSON")"
PROOF="$(jq -r '.proof' "$SMOKE_JSON")"

echo "AgentAuthorizer:   $AUTHORIZER"
echo "PolicyCommitment:  $POLICY_COMMITMENT"
echo "Timestamp:         $CURRENT_TIMESTAMP"

echo "==> Registering policy"
cast send "$AUTHORIZER" \
  "registerPolicy(bytes32)" \
  "$POLICY_COMMITMENT" \
  --rpc-url "$CATP_RPC_URL" \
  --private-key "$CATP_PRIVATE_KEY"

echo "==> Executing authorized action"
cast send "$AUTHORIZER" \
  "executeAuthorized(bytes32,bytes,uint256,bytes)" \
  "$POLICY_COMMITMENT" \
  "$ACTION_DATA" \
  "$CURRENT_TIMESTAMP" \
  "$PROOF" \
  --rpc-url "$CATP_RPC_URL" \
  --private-key "$CATP_PRIVATE_KEY"

echo "==> Reading cumulative spend"
cast call "$AUTHORIZER" \
  "getCumulativeSpend(bytes32)(uint256)" \
  "$POLICY_COMMITMENT" \
  --rpc-url "$CATP_RPC_URL"

echo "Groth16 execution smoke test complete."
