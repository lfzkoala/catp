#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CATP_CLI="$ROOT_DIR/catp-plugin/dist/cli.js"
WITNESS_OUT=""
PROOF_OUT=""
KEEP_WITNESS=0
WITNESS_ARGS=()

usage() {
  cat <<'USAGE'
Usage:
  scripts/prove-groth16-authorization.sh [witness options] --out <proof.json>

Witness options:
  --action <path>               Structured action JSON.
  --audit-commitment <hex>      Build witness from logged audit entry commitment.
  --agent <id>                  Agent id for --audit-commitment.
  -f, --file <path>             catp-policy.toml path.
  --current-timestamp <u64>     Override currentTimestamp.
  --cumulative-spend <u64>      Override cumulativeSpend.
  --witness-out <path>          Keep witness JSON at this path.

Proof options:
  --out <path>                  Proof artifact output path.

This script builds an authorization_groth16_v1 witness with catp-plugin, then
passes it to scripts/generate-groth16-verifier.sh.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --action|--audit-commitment|--agent|-f|--file|--current-timestamp|--cumulative-spend)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for $1" >&2
        exit 1
      fi
      WITNESS_ARGS+=("$1" "$2")
      shift 2
      ;;
    --witness-out)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --witness-out" >&2
        exit 1
      fi
      WITNESS_OUT="$2"
      KEEP_WITNESS=1
      shift 2
      ;;
    --out)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --out" >&2
        exit 1
      fi
      PROOF_OUT="$2"
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

if [[ -z "$PROOF_OUT" ]]; then
  echo "Missing --out <proof.json>" >&2
  usage >&2
  exit 1
fi

if [[ ! -f "$CATP_CLI" ]]; then
  echo "==> Building catp-plugin CLI"
  (cd "$ROOT_DIR/catp-plugin" && npm run build)
fi

TMP_DIR=""
if [[ -z "$WITNESS_OUT" ]]; then
  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/catp-groth16-witness.XXXXXX")"
  WITNESS_OUT="$TMP_DIR/witness.json"
fi

cleanup() {
  if [[ "$KEEP_WITNESS" -eq 0 && -n "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT

echo "==> Building Groth16 witness"
node "$CATP_CLI" witness "${WITNESS_ARGS[@]}" --out "$WITNESS_OUT"

echo "==> Generating Groth16 proof artifact"
bash "$ROOT_DIR/scripts/generate-groth16-verifier.sh" \
  --witness "$WITNESS_OUT" \
  --out "$PROOF_OUT" \
  --proof-only

echo "Groth16 proof artifact written to $PROOF_OUT"
