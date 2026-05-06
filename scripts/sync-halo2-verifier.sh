#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAYER2_DIR="$ROOT_DIR/catp-circuits/layer2"
SOURCE_VERIFIER="$LAYER2_DIR/Halo2SolidityVerifier.sol"
CONTRACT_VERIFIER="$ROOT_DIR/catp-contracts/src/layer2/Halo2Verifier.sol"
SRS_FILE="$LAYER2_DIR/catp-layer2-k12.srs"

if [[ ! -f "$SRS_FILE" ]]; then
  echo "Missing SRS file: $SRS_FILE" >&2
  exit 1
fi

(
  cd "$LAYER2_DIR"
  cargo run --bin generate_verifier
)

cp "$SOURCE_VERIFIER" "$CONTRACT_VERIFIER"

echo "Synced Halo2 verifier:"
echo "  source:   $SOURCE_VERIFIER"
echo "  contract: $CONTRACT_VERIFIER"
