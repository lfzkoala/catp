#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/catp-receipt-smoke.XXXXXX")"

catp_cmd() {
  if [[ -n "${CATP_BIN:-}" ]]; then
    "$CATP_BIN" "$@"
  else
    node "$ROOT/catp-plugin/dist/cli.js" "$@"
  fi
}

export CATP_HOME="$WORKDIR/.catp-home"
cp "$ROOT/examples/receipt-basic/catp-policy.toml" "$WORKDIR/catp-policy.toml"
cp "$ROOT/examples/receipt-basic/hook-pre.json" "$WORKDIR/hook-pre.json"

cd "$WORKDIR"

catp_cmd validate --file catp-policy.toml
catp_cmd hook pre --runtime claude-code < hook-pre.json
catp_cmd log show --agent receipt-basic-agent --json > log.json
catp_cmd log export --agent receipt-basic-agent --latest --out audit-export.json
catp_cmd receipt keygen \
  --private-key receipt-private.pem \
  --public-key receipt-public.pem
catp_cmd receipt issue \
  --agent receipt-basic-agent \
  --latest \
  --file catp-policy.toml \
  --private-key receipt-private.pem \
  --audit-export-out issued-audit-export.json \
  --out receipt.json
catp_cmd receipt verify \
  --receipt receipt.json \
  --public-key receipt-public.pem \
  --file catp-policy.toml \
  --audit-export issued-audit-export.json \
  --json > receipt-verify.json

node -e 'const fs = require("node:fs"); const log = JSON.parse(fs.readFileSync("log.json", "utf8")); if (!Array.isArray(log) || log.length !== 1) throw new Error("expected one audit entry"); const summary = JSON.parse(fs.readFileSync("receipt-verify.json", "utf8")); if (summary.authorizationReceipt !== "valid" || summary.auditExport !== "matched" || summary.policy !== "matched") throw new Error("receipt verification summary did not match");'

echo "receiptSmoke=ok"
echo "workdir=$WORKDIR"
