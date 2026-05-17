# Receipt Basic Example

This example shows the default non-ZK CATP verification path:

```text
catp-policy.toml + Claude Code-style tool event
  -> local policy decision
  -> tamper-evident audit entry
  -> signed authorization receipt
  -> receipt verification against audit export and policy
```

It does not require the Groth16 prover, contracts, or a repository checkout
beyond this example.

## Files

```text
catp-policy.toml  Minimal policy for the example agent
hook-pre.json     Claude Code-style PreToolUse payload
```

The policy allows only `Bash` commands matching `echo*` and denies other shell
commands.

## Run The Flow

From the repository root:

```bash
export CATP_HOME=/tmp/catp-receipt-basic-home
rm -rf "$CATP_HOME"

catp validate --file examples/receipt-basic/catp-policy.toml
```

Run the hook from the example directory so CATP discovers the example policy:

```bash
cd examples/receipt-basic
catp hook pre --runtime claude-code < hook-pre.json
```

If your shell does not have a `catp` binary on `PATH`, use the workspace build:

```bash
node ../../catp-plugin/dist/cli.js hook pre --runtime claude-code < hook-pre.json
```

Show the audit entry and copy the full commitment:

```bash
catp log show --agent receipt-basic-agent --commitments
catp log verify --agent receipt-basic-agent
```

Generate a signing key:

```bash
catp receipt keygen \
  --private-key /tmp/catp-receipt-basic-private.pem \
  --public-key /tmp/catp-receipt-basic-public.pem
```

Issue a receipt directly from the audit commitment:

```bash
catp receipt issue \
  --agent receipt-basic-agent \
  --commitment <64-char-audit-commitment> \
  --file catp-policy.toml \
  --private-key /tmp/catp-receipt-basic-private.pem \
  --audit-export-out /tmp/catp-receipt-basic-audit-export.json \
  --out /tmp/catp-receipt-basic-receipt.json
```

`catp receipt issue` verifies the local audit log commitment chain before it
signs the receipt.

Verify the receipt against the signer public key, audit export, and policy:

```bash
catp receipt verify \
  --receipt /tmp/catp-receipt-basic-receipt.json \
  --public-key /tmp/catp-receipt-basic-public.pem \
  --audit-export /tmp/catp-receipt-basic-audit-export.json \
  --file catp-policy.toml
```

Expected verification summary:

```text
authorizationReceipt=valid
auditExport=matched
policy=matched
```

## Tamper Checks

Changing the receipt, audit export, public key, signature, or policy should make
verification fail. This is the intended security boundary for the signed receipt
path.
