#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACTS_DIR="$ROOT_DIR/catp-contracts"
MAX_EVM_RUNTIME_BYTES=24576

runtime_size() {
  local artifact="$1"
  if [[ ! -f "$artifact" ]]; then
    echo "Missing artifact: $artifact" >&2
    exit 1
  fi
  local bytecode
  bytecode="$(jq -r '.deployedBytecode.object' "$artifact")"
  local hexchars
  hexchars="$(printf '%s' "${bytecode#0x}" | tr -d '\n' | wc -c | tr -d ' ')"
  echo $((hexchars / 2))
}

verifier_size="$(runtime_size "$CONTRACTS_DIR/out/Groth16Verifier.sol/Groth16Verifier.json")"
wrapper_size="$(runtime_size "$CONTRACTS_DIR/out/Groth16AuthorizationVerifier.sol/Groth16AuthorizationVerifier.json")"

echo "Groth16Verifier runtime bytes:              $verifier_size"
echo "Groth16AuthorizationVerifier runtime bytes: $wrapper_size"

if (( verifier_size > MAX_EVM_RUNTIME_BYTES )); then
  echo "Groth16Verifier exceeds EVM runtime limit ($MAX_EVM_RUNTIME_BYTES bytes)" >&2
  exit 1
fi

if (( wrapper_size > MAX_EVM_RUNTIME_BYTES )); then
  echo "Groth16AuthorizationVerifier exceeds EVM runtime limit ($MAX_EVM_RUNTIME_BYTES bytes)" >&2
  exit 1
fi
