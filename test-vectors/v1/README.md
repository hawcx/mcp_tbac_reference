# Conformance test vectors v1

These vectors fix canonical byte-exact expected outputs for an SEP r40 reference implementation under the `tbac-*` domain strings from §A.5 and §12.2.

| File | Purpose |
|---|---|
| [`inputs.json`](inputs.json) | Fixed test inputs (verbatim from SEP §A.5.1) |
| [`expected.json`](expected.json) | Byte-exact expected outputs (generated) |
| [`token.hex`](token.hex) | A complete minted token (hex-encoded) |
| [`r40-attenuation.json`](r40-attenuation.json) | r40 §8.1 widening-attack vector (two-layer rejection) |
| [`derivations.md`](derivations.md) | Prose walk-through |
| [`schema.json`](schema.json) | JSON Schema for `expected.json` |
| [`generate.ts`](generate.ts) | Regeneration script |

## Regenerating

```bash
pnpm vectors:regen
```

CI (`.github/workflows/conformance.yml`) regenerates on every PR and fails on any diff, catching accidental drift in HKDF inputs, canonicalization order, or curve operations.

## Using these vectors as an interop bridge

Any conformant SEP r40 implementation (Rust, Go, etc.) can load `inputs.json`, compute its own derivations using the SEP's normative formulas, and compare against `expected.json`. A failure here is a conformance bug in the other implementation (or this one — the CI fails either way).
