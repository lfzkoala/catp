# CATP CLI 0.4.0 Release Checklist

Package:

```text
@catp-protocol/cli@0.4.0
```

## Release Goal

`0.4.0` makes the signed receipt path easier to use in day-to-day agent
workflows.

The release keeps CATP's default verification path focused on:

```text
policy -> enforcement -> audit log -> signed receipt -> external verification
```

Groth16/EVM remains an optional advanced backend.

## User-Facing Changes

- `catp log show --json`
- `catp log show --tool <name>`
- `catp log show --decision allow|deny`
- `catp log export --latest`
- `catp log export --tool <name>`
- `catp log export --decision allow|deny`
- `catp receipt issue --latest`
- `catp receipt issue --tool <name>`
- `catp receipt issue --decision allow|deny`
- `catp receipt verify --json`
- `npm run smoke:receipt`

`log show`, `log export`, and `receipt issue` now share the same latest-entry
selector semantics for tool and decision filters.

## Pre-Publish Checklist

Run from the repository root:

```bash
npm run typecheck --workspace catp-plugin
npm test --workspace catp-plugin
npm run build --workspace catp-plugin
npm run smoke:receipt
npm run test --workspace catp-sdk
npm run typecheck --workspace catp-sdk
npm run build --workspace catp-sdk
npm run groth16:check
npm_config_cache=/private/tmp/catp-npm-cache npm pack --dry-run --workspace catp-plugin
```

## Published Package Smoke Test

Use a clean temporary directory after installing the published package:

```bash
rm -rf /tmp/catp-user-test
mkdir -p /tmp/catp-user-test
cd /tmp/catp-user-test
export CATP_HOME="$PWD/.catp-home"

catp init
catp validate
catp hook runtimes
catp log verify
catp receipt keygen --help
catp receipt issue --help
catp receipt verify --help
catp prove authorization --help
catp verify authorization --help
```

To exercise the complete receipt path against a global install from a repository
checkout:

```bash
CATP_BIN=catp npm run smoke:receipt
```

## Publish

```bash
cd catp-plugin
npm publish --access public
```

After publishing:

```bash
npm view @catp-protocol/cli version
npm_config_cache=/private/tmp/catp-npm-cache npm install -g @catp-protocol/cli@0.4.0
catp --version
catp hook runtimes
catp log export --help
catp receipt verify --help
```
