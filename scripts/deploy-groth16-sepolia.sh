#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACTS_DIR="$ROOT_DIR/catp-contracts"
VERIFIER_FILE="$CONTRACTS_DIR/src/authorization/Groth16Verifier.sol"
WRAPPER_FILE="$CONTRACTS_DIR/src/authorization/Groth16AuthorizationVerifier.sol"
SETUP_MANIFEST="$ROOT_DIR/catp-circuits/groth16/keys/authorization_groth16_v1.manifest.json"
DEPLOY_LOG_DIR="$CONTRACTS_DIR/deployments/logs"
MAX_EVM_RUNTIME_BYTES=24576
DRY_RUN=0

usage() {
  cat <<'USAGE'
Usage:
  scripts/deploy-groth16-sepolia.sh [--dry-run]

Required env for live deploy:
  CATP_RPC_URL       RPC endpoint for Sepolia or another testnet
  CATP_PRIVATE_KEY   0x-prefixed deployer private key

What this does:
  1. Regenerates authorization_groth16_v1 verifier/proof fixture
  2. Checks Groth16 verifier runtime size
  3. Builds the compact Groth16 deployment targets
  4. Broadcasts raw deployment transactions with cast

Dry run:
  --dry-run runs generation + size/build + metadata only, with no RPC or broadcast.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
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

echo "==> Generating Groth16 verifier and smoke fixture"
CATP_GROTH16_REQUIRE_KEYS=1 bash "$ROOT_DIR/scripts/generate-groth16-verifier.sh"

if [[ ! -f "$SETUP_MANIFEST" ]]; then
  echo "Missing Groth16 setup manifest: $SETUP_MANIFEST" >&2
  exit 1
fi

echo "==> Building Groth16 deployment targets"
(
  cd "$CONTRACTS_DIR"
  forge build \
    src/authorization/Groth16Verifier.sol \
    src/authorization/Groth16AuthorizationVerifier.sol \
    src/authorization/AgentAuthorizer.sol
)

echo "==> Checking Groth16 verifier sizes"
bash "$ROOT_DIR/scripts/check-groth16-verifier-size.sh"
GROTH16_RUNTIME_BYTES="$(jq -r '.deployedBytecode.object' "$CONTRACTS_DIR/out/Groth16Verifier.sol/Groth16Verifier.json" | awk '{ gsub(/^0x/, ""); print length($0) / 2 }')"
WRAPPER_RUNTIME_BYTES="$(jq -r '.deployedBytecode.object' "$CONTRACTS_DIR/out/Groth16AuthorizationVerifier.sol/Groth16AuthorizationVerifier.json" | awk '{ gsub(/^0x/, ""); print length($0) / 2 }')"
GROTH16_RUNTIME_HASH="$(cast keccak "$(jq -r '.deployedBytecode.object' "$CONTRACTS_DIR/out/Groth16Verifier.sol/Groth16Verifier.json")")"
WRAPPER_RUNTIME_HASH="$(cast keccak "$(jq -r '.deployedBytecode.object' "$CONTRACTS_DIR/out/Groth16AuthorizationVerifier.sol/Groth16AuthorizationVerifier.json")")"
if (( GROTH16_RUNTIME_BYTES > MAX_EVM_RUNTIME_BYTES || WRAPPER_RUNTIME_BYTES > MAX_EVM_RUNTIME_BYTES )); then
  echo "One or more Groth16 deployment targets exceed the EVM runtime size limit." >&2
  exit 1
fi

echo "==> Deployment metadata"
VERIFIER_SHA256="$(shasum -a 256 "$VERIFIER_FILE" | awk '{print $1}')"
WRAPPER_SHA256="$(shasum -a 256 "$WRAPPER_FILE" | awk '{print $1}')"
PK_SHA256="$(jq -r '.provingKeySha256' "$SETUP_MANIFEST")"
VK_SHA256="$(jq -r '.verifyingKeySha256' "$SETUP_MANIFEST")"
MANIFEST_VERIFIER_SHA256="$(jq -r '.verifierSourceSha256' "$SETUP_MANIFEST")"
if [[ "$VERIFIER_SHA256" != "$MANIFEST_VERIFIER_SHA256" ]]; then
  echo "Groth16 verifier source hash does not match setup manifest." >&2
  echo "Verifier: $VERIFIER_SHA256" >&2
  echo "Manifest: $MANIFEST_VERIFIER_SHA256" >&2
  exit 1
fi
echo "Groth16Verifier SHA-256:              $VERIFIER_SHA256"
echo "Groth16AuthorizationVerifier SHA-256: $WRAPPER_SHA256"
echo "Proving key SHA-256:                  $PK_SHA256"
echo "Verifying key SHA-256:                $VK_SHA256"

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "Dry run complete. No deployment broadcast."
  exit 0
fi

if [[ -z "${CATP_RPC_URL:-}" ]]; then
  echo "Missing CATP_RPC_URL" >&2
  exit 1
fi

if [[ -z "${CATP_PRIVATE_KEY:-}" ]]; then
  echo "Missing CATP_PRIVATE_KEY" >&2
  exit 1
fi

mkdir -p "$DEPLOY_LOG_DIR"
LOG_FILE="$DEPLOY_LOG_DIR/sepolia-groth16-$(date -u +%Y%m%dT%H%M%SZ).log"

echo "==> Broadcasting Groth16 deployment"
echo "Log: $LOG_FILE"
{
  cd "$CONTRACTS_DIR"

  echo "Deploying Groth16Verifier..."
  GROTH16_INITCODE="$(jq -r '.bytecode.object' out/Groth16Verifier.sol/Groth16Verifier.json)"
  GROTH16_CREATE_JSON="$(cast send \
    --rpc-url "$CATP_RPC_URL" \
    --private-key "$CATP_PRIVATE_KEY" \
    --json \
    --create "$GROTH16_INITCODE")"
  echo "$GROTH16_CREATE_JSON"
  GROTH16_ADDRESS="$(echo "$GROTH16_CREATE_JSON" | jq -r '.contractAddress // .contract_address // .deployedTo // .address')"
  GROTH16_TX="$(echo "$GROTH16_CREATE_JSON" | jq -r '.transactionHash // .transaction_hash // .hash')"
  GROTH16_BLOCK="$(echo "$GROTH16_CREATE_JSON" | jq -r '.blockNumber // .block_number')"
  GROTH16_GAS="$(echo "$GROTH16_CREATE_JSON" | jq -r '.gasUsed // .gas_used')"

  echo "Deploying Groth16AuthorizationVerifier..."
  WRAPPER_BYTECODE="$(jq -r '.bytecode.object' out/Groth16AuthorizationVerifier.sol/Groth16AuthorizationVerifier.json)"
  WRAPPER_ARGS="$(cast abi-encode "constructor(address)" "$GROTH16_ADDRESS")"
  WRAPPER_INITCODE="${WRAPPER_BYTECODE}${WRAPPER_ARGS#0x}"
  WRAPPER_CREATE_JSON="$(cast send \
    --rpc-url "$CATP_RPC_URL" \
    --private-key "$CATP_PRIVATE_KEY" \
    --json \
    --create "$WRAPPER_INITCODE")"
  echo "$WRAPPER_CREATE_JSON"
  WRAPPER_ADDRESS="$(echo "$WRAPPER_CREATE_JSON" | jq -r '.contractAddress // .contract_address // .deployedTo // .address')"
  WRAPPER_TX="$(echo "$WRAPPER_CREATE_JSON" | jq -r '.transactionHash // .transaction_hash // .hash')"
  WRAPPER_BLOCK="$(echo "$WRAPPER_CREATE_JSON" | jq -r '.blockNumber // .block_number')"
  WRAPPER_GAS="$(echo "$WRAPPER_CREATE_JSON" | jq -r '.gasUsed // .gas_used')"

  echo "Deploying AgentAuthorizer..."
  AUTHORIZER_BYTECODE="$(jq -r '.bytecode.object' out/AgentAuthorizer.sol/AgentAuthorizer.json)"
  AUTHORIZER_ARGS="$(cast abi-encode "constructor(address)" "$WRAPPER_ADDRESS")"
  AUTHORIZER_INITCODE="${AUTHORIZER_BYTECODE}${AUTHORIZER_ARGS#0x}"
  AUTHORIZER_CREATE_JSON="$(cast send \
    --rpc-url "$CATP_RPC_URL" \
    --private-key "$CATP_PRIVATE_KEY" \
    --json \
    --create "$AUTHORIZER_INITCODE")"
  echo "$AUTHORIZER_CREATE_JSON"
  AUTHORIZER_ADDRESS="$(echo "$AUTHORIZER_CREATE_JSON" | jq -r '.contractAddress // .contract_address // .deployedTo // .address')"
  AUTHORIZER_TX="$(echo "$AUTHORIZER_CREATE_JSON" | jq -r '.transactionHash // .transaction_hash // .hash')"
  AUTHORIZER_BLOCK="$(echo "$AUTHORIZER_CREATE_JSON" | jq -r '.blockNumber // .block_number')"
  AUTHORIZER_GAS="$(echo "$AUTHORIZER_CREATE_JSON" | jq -r '.gasUsed // .gas_used')"

  echo "Groth16Verifier deployed at:              $GROTH16_ADDRESS"
  echo "Groth16AuthorizationVerifier deployed at: $WRAPPER_ADDRESS"
  echo "AgentAuthorizer deployed at:              $AUTHORIZER_ADDRESS"

  echo "== Metadata skeleton =="
  jq -n \
    --arg deployedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg deployer "$(cast wallet address --private-key "$CATP_PRIVATE_KEY")" \
    --arg groth16Verifier "$GROTH16_ADDRESS" \
    --arg wrapper "$WRAPPER_ADDRESS" \
    --arg authorizer "$AUTHORIZER_ADDRESS" \
    --arg verifierSha "$VERIFIER_SHA256" \
    --arg wrapperSha "$WRAPPER_SHA256" \
    --arg pkSha "$PK_SHA256" \
    --arg vkSha "$VK_SHA256" \
    --arg verifierRuntime "$GROTH16_RUNTIME_BYTES" \
    --arg wrapperRuntime "$WRAPPER_RUNTIME_BYTES" \
    --arg groth16RuntimeHash "$GROTH16_RUNTIME_HASH" \
    --arg wrapperRuntimeHash "$WRAPPER_RUNTIME_HASH" \
    --arg groth16Tx "$GROTH16_TX" \
    --arg wrapperTx "$WRAPPER_TX" \
    --arg authorizerTx "$AUTHORIZER_TX" \
    --argjson groth16Block "$GROTH16_BLOCK" \
    --argjson wrapperBlock "$WRAPPER_BLOCK" \
    --argjson authorizerBlock "$AUTHORIZER_BLOCK" \
    --arg groth16Gas "$GROTH16_GAS" \
    --arg wrapperGas "$WRAPPER_GAS" \
    --arg authorizerGas "$AUTHORIZER_GAS" \
    --arg deploymentLog "${LOG_FILE#$CONTRACTS_DIR/}" \
    '{
      chainId: 11155111,
      network: "sepolia",
      status: "deployed_pending_smoke",
      deployedAt: $deployedAt,
      deployer: $deployer,
      groth16Verifier: $groth16Verifier,
      groth16AuthorizationVerifier: $wrapper,
      agentAuthorizer: $authorizer,
      authorizationProofVersion: "authorization_groth16_v1",
      constraintCount: 13284,
      groth16VerifierSourceSha256: $verifierSha,
      groth16AuthorizationVerifierSourceSha256: $wrapperSha,
      provingKeySha256: $pkSha,
      verifyingKeySha256: $vkSha,
      groth16VerifierRuntimeBytes: $verifierRuntime,
      groth16AuthorizationVerifierRuntimeBytes: $wrapperRuntime,
      deployedRuntimeCodeKeccak256: {
        groth16Verifier: $groth16RuntimeHash,
        groth16AuthorizationVerifier: $wrapperRuntimeHash
      },
      blocks: {
        groth16Verifier: $groth16Block,
        groth16AuthorizationVerifier: $wrapperBlock,
        agentAuthorizer: $authorizerBlock
      },
      transactions: {
        groth16Verifier: $groth16Tx,
        groth16AuthorizationVerifier: $wrapperTx,
        agentAuthorizer: $authorizerTx
      },
      gasUsed: {
        groth16VerifierDeploy: $groth16Gas,
        groth16AuthorizationVerifierDeploy: $wrapperGas,
        agentAuthorizerDeploy: $authorizerGas
      },
      smoke: {
        policyCommitment: "",
        proofTimestamp: "",
        registerPolicyTx: "",
        executeAuthorizedTx: "",
        registerPolicyBlock: null,
        executeAuthorizedBlock: null,
        registerPolicyGasUsed: "",
        executeAuthorizedGasUsed: "",
        cumulativeSpendAfter: ""
      },
      foundryBroadcast: null,
      deploymentLog: $deploymentLog
    }'
} | tee "$LOG_FILE"

echo "Deployment complete. Copy deployed addresses and tx metadata into:"
echo "  $CONTRACTS_DIR/deployments/sepolia-groth16.json"
