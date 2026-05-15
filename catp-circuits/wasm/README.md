# CATP WASM Bindings

This crate exposes the Halo2/off-chain authorization helpers to JavaScript:

- `compute_policy_commitment`
- `prove_authorization`
- `verify_authorization`

The generated `pkg/` directory is intentionally excluded from git. Build it as
a local package artifact when needed:

```bash
npm run wasm:build
```

The bindings embed `../layer2/catp-layer2-k12.srs`, which is suitable for
development and testnet consistency only. Mainnet Halo2 usage requires
documented SRS provenance or replacement with an accepted ceremony output.
