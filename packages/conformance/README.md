# @tinfoilsh/conformance

Tinfoil cross-SDK conformance binary for the JS SDK. Implements the CLI contract defined in [tinfoil-conformance](https://github.com/lsd-cat/tinfoil-conformance).

## Build

```bash
npm install
npm run build -w @tinfoilsh/conformance
```

The binary lands at `packages/conformance/dist/cli.js` (Node ESM, shebang for direct execution).

## Run

```bash
./packages/conformance/dist/cli.js capabilities
./packages/conformance/dist/cli.js verify-sigstore < input.json
```

Subcommands and I/O schema: see `tinfoil-conformance/schemas/`.

This binary is **separate** from any future upstream sigstore-conformance binary — it tests the Tinfoil policy layer on top of Sigstore, plus future SEV/TDX/TLS/EHBP stages.
