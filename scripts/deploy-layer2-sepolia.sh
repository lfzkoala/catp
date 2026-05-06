#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACTS_DIR="$ROOT_DIR/catp-contracts"
SRS_FILE="$ROOT_DIR/catp-circuits/layer2/catp-layer2-k12.srs"
VERIFIER_FILE="$CONTRACTS_DIR/src/layer2/Halo2Verifier.sol"
DEPLOY_LOG_DIR="$CONTRACTS_DIR/deployments/logs"
DRY_RUN=0

usage() {
  cat <<'USAGE'
Usage:
  scripts/deploy-layer2-sepolia.sh [--dry-run]

Required env for live deploy:
  CATP_RPC_URL       RPC endpoint for Sepolia or another testnet
  CATP_PRIVATE_KEY   0x-prefixed deployer private key

What this does:
  1. Regenerates and syncs Halo2Verifier.sol from the checked-in layer2 SRS
  2. Builds contracts
  3. Prints SRS/verifier metadata
  4. Runs the Foundry deployment script

Dry run:
  --dry-run runs sync + build + metadata only, with no RPC or broadcast.
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

echo "==> Syncing Halo2 verifier"
bash "$ROOT_DIR/scripts/sync-halo2-verifier.sh"

echo "==> Building contracts"
(
  cd "$CONTRACTS_DIR"
  forge build
)

echo "==> Deployment metadata"
SRS_SHA256="$(shasum -a 256 "$SRS_FILE" | awk '{print $1}')"
VERIFIER_SHA256="$(shasum -a 256 "$VERIFIER_FILE" | awk '{print $1}')"
echo "SRS SHA-256:       $SRS_SHA256"
echo "Verifier SHA-256:  $VERIFIER_SHA256"

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
LOG_FILE="$DEPLOY_LOG_DIR/sepolia-$(date -u +%Y%m%dT%H%M%SZ).log"

echo "==> Broadcasting deployment"
echo "Log: $LOG_FILE"
(
  cd "$CONTRACTS_DIR"
  PRIVATE_KEY="$CATP_PRIVATE_KEY" forge script \
    script/DeployHalo2Authorizer.s.sol:DeployHalo2Authorizer \
    --rpc-url "$CATP_RPC_URL" \
    --broadcast
) | tee "$LOG_FILE"

echo "Deployment complete. Copy deployed addresses and gas metadata into:"
echo "  $CONTRACTS_DIR/deployments/sepolia.json"
