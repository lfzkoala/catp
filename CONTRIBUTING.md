# Contributing to CATP

Contributions are welcome. Open an issue before starting significant work so we can coordinate.

## Repository Layout

```
catp/
├── catp-plugin/     # TypeScript — Layer 0 enforcement plugin (npm)
├── catp-circuits/   # Rust      — Halo2 ZK circuits (cargo)
├── catp-contracts/  # Solidity  — on-chain verifiers (Foundry)
├── catp-sdk/        # TypeScript — developer SDK (pnpm)
├── catp-node/       # Rust      — MPA attestor node (cargo)
└── catp-tests/      # Integration tests (scaffold)
```

## Component Dev Setup

### catp-plugin (Layer 0 enforcement)

**Toolchain:** Node.js ≥ 20, npm ≥ 10

```bash
cd catp-plugin
NODE_ENV=development npm install   # installs devDependencies
npm run typecheck                  # tsc --noEmit
npm test                           # jest (56 tests)
npm run test:coverage              # jest with coverage report
npm run build                      # compiles src/ → dist/
```

Tests live in `catp-plugin/tests/`. Coverage targets: 80% lines/functions/statements, 75% branches.

### catp-sdk (Layer 2 TypeScript SDK)

**Toolchain:** Node.js ≥ 20, pnpm ≥ 9

```bash
cd catp-sdk
NODE_ENV=development pnpm install
pnpm tsc --noEmit                  # type-check only (no runtime tests yet)
```

### catp-circuits (Halo2 ZK circuits)

**Toolchain:** Rust stable (see `rust-toolchain.toml`)

```bash
cargo test --workspace             # runs MockProver tests (9 tests)
cargo clippy --workspace -- -D warnings
cargo fmt --check
```

### catp-contracts (Solidity)

**Toolchain:** Foundry (install: `curl -L https://foundry.paradigm.xyz | bash`)

```bash
cd catp-contracts
forge build
forge test                         # 34 tests across Layer 2 + Layer 3
```

## Pull Requests

- All PRs must include tests.
- **catp-plugin**: maintain ≥ 80% coverage (`npm run test:coverage`).
- **catp-contracts**: include Forge tests for any new contract logic.
- **catp-circuits**: include MockProver tests for new circuits.
- CI runs automatically on every PR (see `.github/workflows/ci.yml`).

## Coding Conventions

- TypeScript: strict mode, `"type": "module"` ESM, no `any`.
- Solidity: `^0.8.24`, follow existing NatSpec style.
- Rust: `cargo fmt` + `cargo clippy` must pass before merging.

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add Poseidon hash commitment to audit log
fix: correct path_allowlist match semantics in engine
test: add verifier chain-tamper tests
docs: update CONTRIBUTING with catp-node setup
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`, `ci`

## Reporting Issues

Use [GitHub Issues](https://github.com/lfzkoala/catp/issues). For security vulnerabilities, email directly rather than opening a public issue.
