#!/bin/bash
set -e

echo "==> cargo fmt"
cargo fmt --check

echo "==> cargo clippy"
cargo clippy --workspace -- -D warnings

echo "==> cargo check"
cargo check --workspace

echo "==> cargo test"
cargo test --workspace

echo "==> solidity (forge)"
if command -v forge &>/dev/null; then
  (cd catp-contracts && forge build && forge test)
else
  echo "    forge not installed — skipping solidity checks"
fi

echo "==> catp-plugin install + typecheck + tests"
NODE_ENV=development npm install
(cd catp-plugin && npm run typecheck)
(cd catp-plugin && npm run test:coverage)

echo "==> catp-sdk install + typecheck"
(cd catp-sdk && NODE_ENV=development pnpm install --frozen-lockfile && pnpm run typecheck)

echo "All checks passed."
