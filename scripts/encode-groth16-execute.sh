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

lower_hex() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

hex_byte_length() {
  local value="$1"
  echo $(( (${#value} - 2) / 2 ))
}

public_input() {
  local index="$1"
  jq -r ".publicInputs[$index] // empty" "$ARTIFACT"
}

assert_public_input() {
  local index="$1"
  local value
  value="$(public_input "$index")"
  is_bytes32 "$value" || fail "publicInputs[$index] must be bytes32 hex"
}

u256_hex_from_decimal() {
  local value="$1"
  cast --to-uint256 "$value"
}

u256_hex_from_action_word() {
  local word_hex="$1"
  echo "0x$word_hex"
}

u64_limb_public_hex_from_word() {
  local word_hex="$1"
  local limb_index="$2"
  local offset=$((limb_index * 16))
  local chunk="${word_hex:$offset:16}"
  local reversed=""
  local i
  for ((i = 7; i >= 0; i -= 1)); do
    reversed+="${chunk:$((i * 2)):2}"
  done
  echo "0x000000000000000000000000000000000000000000000000$reversed"
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
[[ "$(hex_byte_length "$action_data")" == "128" ]] || fail "actionData must be 128 bytes"
[[ "$(hex_byte_length "$proof")" == "256" ]] || fail "proof must be 256 bytes"
[[ "$current_timestamp" =~ ^[0-9]+$ ]] || fail "currentTimestamp must be a decimal integer"

public_input_count="$(jq -r '.publicInputs | length' "$ARTIFACT")"
[[ "$public_input_count" == "13" ]] || fail "expected 13 public inputs, got $public_input_count"
for index in $(seq 0 12); do
  assert_public_input "$index"
done

value="$(jq -r '.value // empty' "$ARTIFACT")"
cumulative_spend="$(jq -r '.cumulativeSpend // empty' "$ARTIFACT")"
[[ "$value" =~ ^[0-9]+$ ]] || fail "value must be a decimal integer"
[[ "$value" != "0" ]] || fail "value must be greater than zero"
[[ "$cumulative_spend" =~ ^[0-9]+$ ]] || fail "cumulativeSpend must be a decimal integer"

public_policy_commitment="$(public_input 0)"
public_timestamp="$(public_input 11)"
public_value="$(public_input 10)"
public_cumulative_spend="$(public_input 12)"
[[ "$(lower_hex "$public_policy_commitment")" == "$(lower_hex "$policy_commitment")" ]] || fail "publicInputs[0] does not match policyCommitment"
[[ "$(lower_hex "$public_value")" == "$(lower_hex "$(u256_hex_from_decimal "$value")")" ]] || fail "publicInputs[10] does not match value"
[[ "$(lower_hex "$public_timestamp")" == "$(lower_hex "$(u256_hex_from_decimal "$current_timestamp")")" ]] || fail "publicInputs[11] does not match currentTimestamp"
[[ "$(lower_hex "$public_cumulative_spend")" == "$(lower_hex "$(u256_hex_from_decimal "$cumulative_spend")")" ]] || fail "publicInputs[12] does not match cumulativeSpend"

action_data_hex="${action_data:2}"
action_type_word="${action_data_hex:0:64}"
protocol_word="${action_data_hex:64:64}"
token_word="${action_data_hex:128:64}"
value_word="${action_data_hex:192:64}"

[[ "$(lower_hex "$(u256_hex_from_action_word "$action_type_word")")" == "$(lower_hex "$(public_input 1)")" ]] || fail "actionData actionType does not match publicInputs[1]"
for limb in 0 1 2 3; do
  public_index=$((2 + limb))
  [[ "$(lower_hex "$(u64_limb_public_hex_from_word "$protocol_word" "$limb")")" == "$(lower_hex "$(public_input "$public_index")")" ]] || fail "actionData protocol limb $limb does not match publicInputs[$public_index]"
done
for limb in 0 1 2 3; do
  public_index=$((6 + limb))
  [[ "$(lower_hex "$(u64_limb_public_hex_from_word "$token_word" "$limb")")" == "$(lower_hex "$(public_input "$public_index")")" ]] || fail "actionData token limb $limb does not match publicInputs[$public_index]"
done
[[ "$(lower_hex "$(u256_hex_from_action_word "$value_word")")" == "$(lower_hex "$public_value")" ]] || fail "actionData value does not match publicInputs[10]"

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
  --arg cumulativeSpend "$cumulative_spend" \
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
    },
    validation: {
      publicInputs: "matched",
      actionData: "matched",
      cumulativeSpend: $cumulativeSpend
    }
  }')"

if [[ -n "$OUT" ]]; then
  mkdir -p "$(dirname "$OUT")"
  printf '%s\n' "$output" > "$OUT"
  echo "Groth16 execution calldata written to $OUT"
else
  printf '%s\n' "$output"
fi
