#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_ARTIFACT="$ROOT_DIR/catp-circuits/groth16/build/authorization_groth16_v1.json"
DEFAULT_DEPLOYMENT="$ROOT_DIR/catp-contracts/deployments/sepolia-groth16.json"
PROOF_VERSION="authorization_groth16_v1"
ARTIFACT="$DEFAULT_ARTIFACT"
DEPLOYMENT_FILE=""
AUTHORIZER=""
OUT=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/encode-groth16-execute.sh [options]

Options:
  --artifact <path>       Groth16 proof artifact JSON.
                          Defaults to catp-circuits/groth16/build/authorization_groth16_v1.json.
  --deployment <path>     Deployment metadata JSON. Reads .agentAuthorizer when present.
  --authorizer <address>  AgentAuthorizer address to include in the output.
  --out <path>            Write encoded call JSON to this path.
  -h, --help              Show this help.

This is an offline dry-run encoder. It does not read RPC state and does not
broadcast a transaction.
USAGE
}

fail() {
  echo "Groth16 execution encoding failed: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

is_hex() {
  local value="$1"
  [[ "$value" =~ ^0x[0-9a-fA-F]+$ ]]
}

is_bytes32() {
  local value="$1"
  [[ "$value" =~ ^0x[0-9a-fA-F]{64}$ ]]
}

is_address() {
  local value="$1"
  [[ "$value" =~ ^0x[0-9a-fA-F]{40}$ ]]
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact)
      [[ $# -ge 2 ]] || fail "missing value for --artifact"
      ARTIFACT="$2"
      shift 2
      ;;
    --deployment)
      [[ $# -ge 2 ]] || fail "missing value for --deployment"
      DEPLOYMENT_FILE="$2"
      shift 2
      ;;
    --authorizer)
      [[ $# -ge 2 ]] || fail "missing value for --authorizer"
      AUTHORIZER="$2"
      shift 2
      ;;
    --out)
      [[ $# -ge 2 ]] || fail "missing value for --out"
      OUT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

require_command jq
require_command cast

[[ -f "$ARTIFACT" ]] || fail "missing artifact: $ARTIFACT"
jq . "$ARTIFACT" >/dev/null

if [[ -z "$DEPLOYMENT_FILE" && -f "$DEFAULT_DEPLOYMENT" ]]; then
  DEPLOYMENT_FILE="$DEFAULT_DEPLOYMENT"
fi

if [[ -n "$DEPLOYMENT_FILE" ]]; then
  [[ -f "$DEPLOYMENT_FILE" ]] || fail "missing deployment file: $DEPLOYMENT_FILE"
  jq . "$DEPLOYMENT_FILE" >/dev/null
  deployment_authorizer="$(jq -r '.agentAuthorizer // empty' "$DEPLOYMENT_FILE")"
  if [[ -z "$AUTHORIZER" && -n "$deployment_authorizer" ]]; then
    AUTHORIZER="$deployment_authorizer"
  fi
fi

artifact_proof_version="$(jq -r '.proofVersion // empty' "$ARTIFACT")"
[[ "$artifact_proof_version" == "$PROOF_VERSION" ]] || fail "expected proofVersion $PROOF_VERSION, got ${artifact_proof_version:-<missing>}"

policy_commitment="$(jq -r '.policyCommitment // empty' "$ARTIFACT")"
action_data="$(jq -r '.actionData // empty' "$ARTIFACT")"
current_timestamp="$(jq -r '.currentTimestamp // empty' "$ARTIFACT")"
proof="$(jq -r '.proof // empty' "$ARTIFACT")"

is_bytes32 "$policy_commitment" || fail "policyCommitment must be bytes32 hex"
is_hex "$action_data" || fail "actionData must be hex"
is_hex "$proof" || fail "proof must be hex"
[[ $(( (${#action_data} - 2) % 2 )) -eq 0 ]] || fail "actionData hex must have an even byte length"
[[ "${#proof}" -eq 514 ]] || fail "proof must be 256 bytes"
[[ "$current_timestamp" =~ ^[0-9]+$ ]] || fail "currentTimestamp must be a decimal integer"

public_input_count="$(jq -r '.publicInputs | length' "$ARTIFACT")"
[[ "$public_input_count" == "13" ]] || fail "expected 13 public inputs, got $public_input_count"
public_policy_commitment="$(jq -r '.publicInputs[0] // empty' "$ARTIFACT")"
public_timestamp="$(jq -r '.publicInputs[11] // empty' "$ARTIFACT")"
[[ "$public_policy_commitment" == "$policy_commitment" ]] || fail "publicInputs[0] does not match policyCommitment"
[[ "$public_timestamp" == "$(printf '0x%064x' "$current_timestamp")" ]] || fail "publicInputs[11] does not match currentTimestamp"

if [[ -n "$AUTHORIZER" ]]; then
  is_address "$AUTHORIZER" || fail "authorizer must be an EVM address"
fi

register_calldata="$(cast calldata \
  "registerPolicy(bytes32)" \
  "$policy_commitment")"

execute_calldata="$(cast calldata \
  "executeAuthorized(bytes32,bytes,uint256,bytes)" \
  "$policy_commitment" \
  "$action_data" \
  "$current_timestamp" \
  "$proof")"

output="$(jq -n \
  --arg proofVersion "$PROOF_VERSION" \
  --arg artifact "${ARTIFACT#$ROOT_DIR/}" \
  --arg deployment "${DEPLOYMENT_FILE#$ROOT_DIR/}" \
  --arg authorizer "$AUTHORIZER" \
  --arg policyCommitment "$policy_commitment" \
  --arg actionData "$action_data" \
  --arg currentTimestamp "$current_timestamp" \
  --arg proof "$proof" \
  --arg registerCalldata "$register_calldata" \
  --arg executeCalldata "$execute_calldata" \
  '{
    proofVersion: $proofVersion,
    artifact: $artifact,
    deployment: (if $deployment == "" then null else $deployment end),
    agentAuthorizer: (if $authorizer == "" then null else $authorizer end),
    registerPolicy: {
      signature: "registerPolicy(bytes32)",
      args: [$policyCommitment],
      calldata: $registerCalldata
    },
    executeAuthorized: {
      signature: "executeAuthorized(bytes32,bytes,uint256,bytes)",
      args: [$policyCommitment, $actionData, $currentTimestamp, $proof],
      calldata: $executeCalldata
    }
  }')"

if [[ -n "$OUT" ]]; then
  mkdir -p "$(dirname "$OUT")"
  printf '%s\n' "$output" > "$OUT"
  echo "Groth16 execution calldata written to $OUT"
else
  printf '%s\n' "$output"
fi
