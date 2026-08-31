# Contributing to CATP

Contributions are welcome. Open an issue before starting significant work so we can coordinate.

## Repository Layout

```
catp/
├── catp-plugin/     # TypeScript — local enforcement plugin (npm)
├── catp-circuits/   # Go        — optional Groth16 prover/verifier path
├── catp-contracts/  # Solidity  — on-chain verifiers (Foundry)
└── catp-sdk/        # TypeScript — developer SDK (pnpm)
```

## Component Dev Setup

### catp-plugin (local enforcement)

**Toolchain:** Node.js ≥ 20, npm ≥ 10

```bash
cd catp-plugin
NODE_ENV=development npm install   # installs devDependencies
npm run typecheck                  # tsc --noEmit
npm test                           # jest
npm run test:coverage              # jest with coverage report
npm run build                      # compiles src/ → dist/
```

Tests live in `catp-plugin/tests/`. Coverage targets: 80% lines/functions/statements, 75% branches.

### catp-sdk (authorization TypeScript SDK)

**Toolchain:** Node.js ≥ 20, pnpm ≥ 9

```bash
cd catp-sdk
NODE_ENV=development pnpm install
pnpm run typecheck
pnpm test
```

### catp-contracts (Solidity)

**Toolchain:** Foundry (install: `curl -L https://foundry.paradigm.xyz | bash`)

```bash
cd catp-contracts
forge build
forge test                         # authorization contract tests
```

## Pre-Push Checks

Before pushing or opening a PR, run:

```bash
bash check.sh
```

This runs Solidity checks and typechecks/tests both TypeScript packages. CI runs
the same checks, so catching failures locally saves a round-trip.

## Pull Requests

- All PRs must include tests.
- **catp-plugin**: maintain ≥ 80% coverage (`npm run test:coverage`).
- **catp-contracts**: include Forge tests for any new contract logic.
- CI runs automatically on every PR (see `.github/workflows/ci.yml`).

## Coding Conventions

- TypeScript: strict mode, `"type": "module"` ESM, no `any`.
- Solidity: `^0.8.24`, follow existing NatSpec style.

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add Poseidon hash commitment to audit log
fix: correct path_allowlist match semantics in engine
test: add verifier chain-tamper tests
docs: update installation guide
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`, `ci`

## Reporting Issues

Use [GitHub Issues](https://github.com/lfzkoala/catp/issues). For security vulnerabilities, email directly rather than opening a public issue.
