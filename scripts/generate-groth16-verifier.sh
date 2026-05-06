#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GROTH16_DIR="$ROOT_DIR/catp-circuits/groth16"

if [[ "${CATP_GROTH16_RESET_SETUP:-}" == "1" && "${CATP_GROTH16_ALLOW_RESET:-}" != "1" ]]; then
  echo "CATP_GROTH16_RESET_SETUP=1 requires CATP_GROTH16_ALLOW_RESET=1." >&2
  echo "Refusing to replace the persisted Groth16 setup accidentally." >&2
  exit 1
fi

mkdir -p "$ROOT_DIR/.cache/go-build"

(
  cd "$GROTH16_DIR"
  GOCACHE="$ROOT_DIR/.cache/go-build" go run ./cmd/catp-groth16 "$@"
)
