#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'EOF'
Halo2 EVM deployment is blocked for the current CATP Layer 2 circuit.

Reason:
  The corrected Halo2 verifier runtime exceeds the EVM 24,576-byte contract
  size limit. The historical Sepolia Halo2 deployment is invalid and must not
  be used for authorization verification.

Use instead:
  scripts/deploy-groth16-sepolia.sh [--dry-run]
EOF

exit 1
