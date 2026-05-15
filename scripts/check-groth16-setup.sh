#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACTS_DIR="$ROOT_DIR/catp-contracts"
PROOF_VERSION="authorization_groth16_v1"
KEY_DIR="$ROOT_DIR/catp-circuits/groth16/keys"
MANIFEST="$KEY_DIR/$PROOF_VERSION.manifest.json"
PK_FILE="$KEY_DIR/$PROOF_VERSION.pk"
VK_FILE="$KEY_DIR/$PROOF_VERSION.vk"
VERIFIER_FILE="$CONTRACTS_DIR/src/authorization/Groth16Verifier.sol"
WRAPPER_FILE="$CONTRACTS_DIR/src/authorization/Groth16AuthorizationVerifier.sol"
DEPLOYMENT_FILE="$CONTRACTS_DIR/deployments/sepolia-groth16.json"
MAX_EVM_RUNTIME_BYTES=24576

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

fail() {
  echo "Groth16 setup check failed: $*" >&2
  exit 1
}

require_file() {
  local file="$1"
  [[ -f "$file" ]] || fail "missing $file"
}

assert_eq() {
  local label="$1"
  local expected="$2"
  local actual="$3"
  if [[ "$expected" != "$actual" ]]; then
    fail "$label mismatch; expected $expected, got $actual"
  fi
}

runtime_size() {
  local artifact="$1"
  local bytecode
  bytecode="$(jq -r '.deployedBytecode.object' "$artifact")"
  local hexchars
  hexchars="$(printf '%s' "${bytecode#0x}" | tr -d '\n' | wc -c | tr -d ' ')"
  echo $((hexchars / 2))
}

require_file "$MANIFEST"
require_file "$PK_FILE"
require_file "$VK_FILE"
require_file "$VERIFIER_FILE"
require_file "$WRAPPER_FILE"

jq . "$MANIFEST" >/dev/null

manifest_proof_version="$(jq -r '.proofVersion' "$MANIFEST")"
manifest_backend="$(jq -r '.backend' "$MANIFEST")"
manifest_curve="$(jq -r '.curve' "$MANIFEST")"
manifest_commitment_hash="$(jq -r '.commitmentHash' "$MANIFEST")"
manifest_commitment_version="$(jq -r '.commitmentVersion' "$MANIFEST")"
manifest_public_inputs="$(jq -r '.publicInputCount' "$MANIFEST")"
manifest_proof_bytes="$(jq -r '.proofBytes' "$MANIFEST")"
manifest_constraints="$(jq -r '.constraintCount' "$MANIFEST")"

assert_eq "proofVersion" "$PROOF_VERSION" "$manifest_proof_version"
assert_eq "backend" "groth16" "$manifest_backend"
assert_eq "curve" "bn254" "$manifest_curve"
assert_eq "commitmentHash" "mimc" "$manifest_commitment_hash"
assert_eq "commitmentVersion" "2" "$manifest_commitment_version"
assert_eq "publicInputCount" "13" "$manifest_public_inputs"
assert_eq "proofBytes" "256" "$manifest_proof_bytes"
assert_eq "constraintCount" "13284" "$manifest_constraints"

pk_sha="$(sha256_file "$PK_FILE")"
vk_sha="$(sha256_file "$VK_FILE")"
verifier_sha="$(sha256_file "$VERIFIER_FILE")"
wrapper_sha="$(sha256_file "$WRAPPER_FILE")"

assert_eq "provingKeySha256" "$(jq -r '.provingKeySha256' "$MANIFEST")" "$pk_sha"
assert_eq "verifyingKeySha256" "$(jq -r '.verifyingKeySha256' "$MANIFEST")" "$vk_sha"
assert_eq "verifierSourceSha256" "$(jq -r '.verifierSourceSha256' "$MANIFEST")" "$verifier_sha"

echo "Groth16 setup manifest: ok"
echo "  proof version: $PROOF_VERSION"
echo "  proving key:   $pk_sha"
echo "  verifying key: $vk_sha"
echo "  verifier sol:  $verifier_sha"
echo "  wrapper sol:   $wrapper_sha"

verifier_artifact="$CONTRACTS_DIR/out/Groth16Verifier.sol/Groth16Verifier.json"
wrapper_artifact="$CONTRACTS_DIR/out/Groth16AuthorizationVerifier.sol/Groth16AuthorizationVerifier.json"
if [[ -f "$verifier_artifact" && -f "$wrapper_artifact" ]]; then
  verifier_size="$(runtime_size "$verifier_artifact")"
  wrapper_size="$(runtime_size "$wrapper_artifact")"
  if (( verifier_size > MAX_EVM_RUNTIME_BYTES )); then
    fail "Groth16Verifier runtime exceeds $MAX_EVM_RUNTIME_BYTES bytes: $verifier_size"
  fi
  if (( wrapper_size > MAX_EVM_RUNTIME_BYTES )); then
    fail "Groth16AuthorizationVerifier runtime exceeds $MAX_EVM_RUNTIME_BYTES bytes: $wrapper_size"
  fi
  echo "  verifier runtime bytes: $verifier_size"
  echo "  wrapper runtime bytes:  $wrapper_size"
else
  echo "  runtime sizes: skipped; build artifacts not found"
fi

if [[ -f "$DEPLOYMENT_FILE" ]]; then
  jq . "$DEPLOYMENT_FILE" >/dev/null
  assert_eq "deployment proofVersion" "$PROOF_VERSION" "$(jq -r '.authorizationProofVersion' "$DEPLOYMENT_FILE")"
  assert_eq "deployment verifier source" "$verifier_sha" "$(jq -r '.groth16VerifierSourceSha256' "$DEPLOYMENT_FILE")"
  assert_eq "deployment wrapper source" "$wrapper_sha" "$(jq -r '.groth16AuthorizationVerifierSourceSha256' "$DEPLOYMENT_FILE")"
  assert_eq "deployment proving key" "$pk_sha" "$(jq -r '.provingKeySha256' "$DEPLOYMENT_FILE")"
  assert_eq "deployment verifying key" "$vk_sha" "$(jq -r '.verifyingKeySha256' "$DEPLOYMENT_FILE")"
  echo "Groth16 deployment metadata: ok"
fi
