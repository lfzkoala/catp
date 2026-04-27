#!/bin/bash
set -e

echo "==> cargo fmt"
cargo fmt --check

echo "==> cargo clippy"
cargo clippy --workspace -- -D warnings

echo "==> catp-plugin typecheck"
(cd catp-plugin && npm run typecheck)

echo "==> catp-sdk typecheck"
(cd catp-sdk && NODE_ENV=development pnpm install --frozen-lockfile && pnpm run typecheck)

echo "All checks passed."
