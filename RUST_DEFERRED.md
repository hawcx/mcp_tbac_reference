# Rust Implementation — Deferred

SEP r41 (wire-compatible with r40) is wire-format-interoperable regardless of implementation language. An early discussion considered shipping a Rust crate (`tbac-core-rs`) alongside the TypeScript packages to match the HAAP canonical spec's reference language.

**Decision for v1:** TypeScript only.

## Rationale

1. The primary consumers of this reference implementation are MCP SDK authors and MCP server authors. The official MCP SDK is TypeScript; the idiomatic wire format for MCP `_meta` is JSON-RPC. A TypeScript library binds directly into that ecosystem with no FFI.
2. A Rust port would be a parallel implementation, not a dependency — the TypeScript packages do not consume Rust via WebAssembly. Shipping both would double the test matrix, double the conformance-vector generation pipeline, and double the attack surface for clean-room contamination (since the existing Hawcx Rust codebase is where most of the proprietary `haap-*` material lives).
3. The conformance test vectors in [`test-vectors/v1/`](test-vectors/v1/) are language-neutral. A future Rust crate can consume the same `expected.json` byte-for-byte — no protocol change is required to add one later.

## What this does NOT mean

- This is **not** a statement that Rust is unsuitable for TBAC. The SEP's cryptographic primitives (Ristretto255 Schnorr, HKDF-SHA-256, AES-256-GCM) all have mature, audited Rust implementations in the `dalek` and `aes-gcm` ecosystems.
- The conformance test vectors are the authoritative bridge. If a Rust implementation appears in the future, it will be validated against [`test-vectors/v1/expected.json`](test-vectors/v1/expected.json) and [`test-vectors/v1/r40-attenuation.json`](test-vectors/v1/r40-attenuation.json) — not against this TypeScript library.

## Revisiting

Add a Rust package to the workspace if any of the following become true:
- An MCP server runtime emerges in Rust that wants in-process TBAC verification.
- A latency-sensitive edge deployment cannot tolerate the Node.js AEAD throughput.
- The conformance test vectors uncover a behavior that is hard to express in TypeScript's crypto stack but easy in Rust.

Until then, the TypeScript implementation is the reference for SEP r41.
