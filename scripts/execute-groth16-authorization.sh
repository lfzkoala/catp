#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_ARTIFACT="$ROOT_DIR/catp-circuits/groth16/build/authorization_groth16_v1.json"
DEFAULT_DEPLOYMENT="$ROOT_DIR/catp-contracts/deployments/sepolia-groth16.json"
ARTIFACT="$DEFAULT_ARTIFACT"
DEPLOYMENT_FILE="$DEFAULT_DEPLOYMENT"
AUTHORIZER=""
OUT=""
DRY_RUN=0
SKIP_REGISTER=0

usage() {
  cat <<'USAGE'
Usage:
  scripts/execute-groth16-authorization.sh [options]

Options:
  --artifact <path>       Groth16 proof artifact JSON.
                          Defaults to catp-circuits/groth16/build/authorization_groth16_v1.json.
  --deployment <path>     Deployment metadata JSON. Defaults to Sepolia Groth16 metadata.
  --authorizer <address>  Override AgentAuthorizer address.
  --out <path>            Write transaction metadata JSON to this path.
  --skip-register         Do not register the policy if it is inactive.
  --dry-run               Validate and print planned calls without RPC or broadcast.
  -h, --help              Show this help.

Required env for live execution:
  CATP_RPC_URL       RPC endpoint for Sepolia or another testnet
  CATP_PRIVATE_KEY   0x-prefixed sender private key

Live execution:
  1. Validates and encodes the Groth16 proof artifact.
  2. Registers the policy only if it is not already active.
  3. Checks on-chain cumulative spend matches the proof artifact.
  4. Broadcasts executeAuthorized.
USAGE
}

fail() {
  echo "Groth16 execution failed: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

is_address() {
  local value="$1"
  [[ "$value" =~ ^0x[0-9a-fA-F]{40}$ ]]
}

normalize_bool() {
  case "$1" in
    true|1|0x1) echo "true" ;;
    false|0|0x0) echo "false" ;;
    *) echo "$1" ;;
  esac
}

tx_field() {
  local json="$1"
  local filter="$2"
  echo "$json" | jq -r "$filter // empty"
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
    --skip-register)
      SKIP_REGISTER=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
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
if [[ -n "$DEPLOYMENT_FILE" ]]; then
  [[ -f "$DEPLOYMENT_FILE" ]] || fail "missing deployment file: $DEPLOYMENT_FILE"
fi

TMP_CALLS="$(mktemp "${TMPDIR:-/tmp}/catp-groth16-calls.XXXXXX.json")"
cleanup() {
  rm -f "$TMP_CALLS"
}
trap cleanup EXIT

encode_args=(--artifact "$ARTIFACT" --out "$TMP_CALLS")
if [[ -n "$DEPLOYMENT_FILE" ]]; then
  encode_args+=(--deployment "$DEPLOYMENT_FILE")
fi
if [[ -n "$AUTHORIZER" ]]; then
  encode_args+=(--authorizer "$AUTHORIZER")
fi

bash "$ROOT_DIR/scripts/encode-groth16-execute.sh" "${encode_args[@]}" >/dev/null

AUTHORIZER="$(jq -r '.agentAuthorizer // empty' "$TMP_CALLS")"
POLICY_COMMITMENT="$(jq -r '.registerPolicy.args[0]' "$TMP_CALLS")"
EXPECTED_CUMULATIVE_SPEND="$(cast --to-dec "$(jq -r '.publicInputs[12] // empty' "$ARTIFACT")")"
REGISTER_CALLDATA="$(jq -r '.registerPolicy.calldata' "$TMP_CALLS")"
EXECUTE_CALLDATA="$(jq -r '.executeAuthorized.calldata' "$TMP_CALLS")"

[[ -n "$AUTHORIZER" && "$AUTHORIZER" != "null" ]] || fail "missing AgentAuthorizer address; pass --authorizer or --deployment"
is_address "$AUTHORIZER" || fail "invalid AgentAuthorizer address: $AUTHORIZER"

if [[ "$DRY_RUN" -eq 1 ]]; then
  jq -n \
    --arg mode "dry-run" \
    --arg authorizer "$AUTHORIZER" \
    --arg policyCommitment "$POLICY_COMMITMENT" \
    --arg expectedCumulativeSpend "$EXPECTED_CUMULATIVE_SPEND" \
    --arg registerCalldata "$REGISTER_CALLDATA" \
    --arg executeCalldata "$EXECUTE_CALLDATA" \
    '{
      mode: $mode,
      agentAuthorizer: $authorizer,
      policyCommitment: $policyCommitment,
      expectedCumulativeSpend: $expectedCumulativeSpend,
      calls: [
        {
          name: "registerPolicy",
          to: $authorizer,
          calldata: $registerCalldata,
          note: "live script sends this only when the policy is not already active"
        },
        {
          name: "executeAuthorized",
          to: $authorizer,
          calldata: $executeCalldata
        }
      ]
    }'
  exit 0
fi

if [[ -z "${CATP_RPC_URL:-}" ]]; then
  fail "missing CATP_RPC_URL"
fi

if [[ -z "${CATP_PRIVATE_KEY:-}" ]]; then
  fail "missing CATP_PRIVATE_KEY"
fi

SENDER="$(cast wallet address --private-key "$CATP_PRIVATE_KEY")"
echo "AgentAuthorizer:          $AUTHORIZER"
echo "Sender:                   $SENDER"
echo "PolicyCommitment:         $POLICY_COMMITMENT"
echo "Expected cumulativeSpend: $EXPECTED_CUMULATIVE_SPEND"

ACTIVE_RAW="$(cast call "$AUTHORIZER" \
  "isPolicyActive(bytes32)(bool)" \
  "$POLICY_COMMITMENT" \
  --rpc-url "$CATP_RPC_URL")"
ACTIVE="$(normalize_bool "$ACTIVE_RAW")"

REGISTER_TX=""
REGISTER_BLOCK=""
REGISTER_GAS=""
if [[ "$ACTIVE" == "true" ]]; then
  echo "==> Policy already active; skipping registration"
elif [[ "$ACTIVE" == "false" ]]; then
  if [[ "$SKIP_REGISTER" -eq 1 ]]; then
    fail "policy is not active and --skip-register was set"
  fi
  echo "==> Registering policy"
  REGISTER_JSON="$(cast send "$AUTHORIZER" \
    "registerPolicy(bytes32)" \
    "$POLICY_COMMITMENT" \
    --rpc-url "$CATP_RPC_URL" \
    --private-key "$CATP_PRIVATE_KEY" \
    --json)"
  echo "$REGISTER_JSON"
  REGISTER_TX="$(tx_field "$REGISTER_JSON" '.transactionHash // .transaction_hash // .hash')"
  REGISTER_BLOCK="$(tx_field "$REGISTER_JSON" '.blockNumber // .block_number')"
  REGISTER_GAS="$(tx_field "$REGISTER_JSON" '.gasUsed // .gas_used')"
else
  fail "unexpected isPolicyActive response: $ACTIVE_RAW"
fi

CHAIN_CUMULATIVE_SPEND="$(cast call "$AUTHORIZER" \
  "getCumulativeSpend(bytes32)(uint256)" \
  "$POLICY_COMMITMENT" \
  --rpc-url "$CATP_RPC_URL")"
CHAIN_CUMULATIVE_SPEND="$(cast --to-dec "$CHAIN_CUMULATIVE_SPEND")"
if [[ "$CHAIN_CUMULATIVE_SPEND" != "$EXPECTED_CUMULATIVE_SPEND" ]]; then
  fail "proof cumulativeSpend $EXPECTED_CUMULATIVE_SPEND does not match chain state $CHAIN_CUMULATIVE_SPEND"
fi

echo "==> Executing authorized action"
EXECUTE_JSON="$(cast send "$AUTHORIZER" \
  "executeAuthorized(bytes32,bytes,uint256,bytes)" \
  "$(jq -r '.executeAuthorized.args[0]' "$TMP_CALLS")" \
  "$(jq -r '.executeAuthorized.args[1]' "$TMP_CALLS")" \
  "$(jq -r '.executeAuthorized.args[2]' "$TMP_CALLS")" \
  "$(jq -r '.executeAuthorized.args[3]' "$TMP_CALLS")" \
  --rpc-url "$CATP_RPC_URL" \
  --private-key "$CATP_PRIVATE_KEY" \
  --json)"
echo "$EXECUTE_JSON"

EXECUTE_TX="$(tx_field "$EXECUTE_JSON" '.transactionHash // .transaction_hash // .hash')"
EXECUTE_BLOCK="$(tx_field "$EXECUTE_JSON" '.blockNumber // .block_number')"
EXECUTE_GAS="$(tx_field "$EXECUTE_JSON" '.gasUsed // .gas_used')"

FINAL_CUMULATIVE_SPEND="$(cast call "$AUTHORIZER" \
  "getCumulativeSpend(bytes32)(uint256)" \
  "$POLICY_COMMITMENT" \
  --rpc-url "$CATP_RPC_URL")"
FINAL_CUMULATIVE_SPEND="$(cast --to-dec "$FINAL_CUMULATIVE_SPEND")"

RESULT="$(jq -n \
  --arg agentAuthorizer "$AUTHORIZER" \
  --arg sender "$SENDER" \
  --arg policyCommitment "$POLICY_COMMITMENT" \
  --arg expectedCumulativeSpend "$EXPECTED_CUMULATIVE_SPEND" \
  --arg registerPolicyTx "$REGISTER_TX" \
  --arg registerPolicyBlock "$REGISTER_BLOCK" \
  --arg registerPolicyGasUsed "$REGISTER_GAS" \
  --arg executeAuthorizedTx "$EXECUTE_TX" \
  --arg executeAuthorizedBlock "$EXECUTE_BLOCK" \
  --arg executeAuthorizedGasUsed "$EXECUTE_GAS" \
  --arg cumulativeSpendAfter "$FINAL_CUMULATIVE_SPEND" \
  '{
    agentAuthorizer: $agentAuthorizer,
    sender: $sender,
    policyCommitment: $policyCommitment,
    expectedCumulativeSpendBefore: $expectedCumulativeSpend,
    registerPolicyTx: (if $registerPolicyTx == "" then null else $registerPolicyTx end),
    registerPolicyBlock: (if $registerPolicyBlock == "" then null else $registerPolicyBlock end),
    registerPolicyGasUsed: (if $registerPolicyGasUsed == "" then null else $registerPolicyGasUsed end),
    executeAuthorizedTx: $executeAuthorizedTx,
    executeAuthorizedBlock: $executeAuthorizedBlock,
    executeAuthorizedGasUsed: $executeAuthorizedGasUsed,
    cumulativeSpendAfter: $cumulativeSpendAfter
  }')"

if [[ -n "$OUT" ]]; then
  mkdir -p "$(dirname "$OUT")"
  printf '%s\n' "$RESULT" > "$OUT"
  echo "Groth16 execution metadata written to $OUT"
else
  printf '%s\n' "$RESULT"
fi
