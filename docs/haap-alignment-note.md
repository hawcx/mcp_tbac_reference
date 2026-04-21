# HAAP alignment note (SEP §12)

SEP r40 §12 directly discusses alignment and divergence between the TBAC extension and the HAAP Canonical Specification v6.0.0. This note exists because the SEP itself references HAAP by name; it documents, from the reference implementation's side, how the two fit together.

If you are not implementing against HAAP, you can skip this document — the SEP and this implementation stand on their own.

## What is shared

Per §12, the following are aligned with HAAP v6.0.0 Build 885a9acf16a78e4a:

- Protocol design and verification cascade structure (17-step enterprise)
- Key schedule topology (HKDF derivations from `K_session`, per-token Schnorr + AEAD)
- Trust model (Profile E Assembler boundary, zero-crypto agent)
- Scope-field semantics (§3.2 fields, §A.2 TLV tags)
- Three-layer intent verification (§4.7)
- Assembler architecture and Profile E IPC inventory
- `HaapRequestEnvelope` schema (§3.6, outside base conformance on both sides)
- `request_format` byte-3 encoding

## What deliberately diverges (§12.1, §12.2)

The SEP makes two intentional deviations to make tokens first-class MCP citizens:

| Axis | HAAP v6.0.0 | SEP r40 |
|---|---|---|
| Token attachment | `Authorization: HAAP <token>` HTTP header | `_meta["io.modelcontextprotocol/tbac"].token` |
| PoP proof | `HAAP-PoP` HTTP header | `_meta[...].pop.sig` |
| Encrypted payload | HTTP body | `_meta[...].enc.ct` |
| Domain strings (HKDF, AAD, transcripts) | `hawcx-*` / `haap-*` | `tbac-*` |

The transport change ensures tokens remain visible to MCP message-processing layers across all MCP transports (Streamable HTTP, stdio, SSE). The domain-string change prevents accidental cross-implementation token confusion — both constructions are cryptographically equivalent given their respective string namespaces.

## Byte-level interop

A conformant SEP r40 implementation and a current HAAP v6.0.0 implementation do NOT interoperate byte-level out of the box. They agree on cryptographic construction and cascade logic but disagree on both transport framing and domain-separation labels. Byte-level interop requires either:

- A conformance mode in the HAAP SDK that swaps in the `tbac-*` strings and the MCP `_meta` wire format, or
- A protocol adapter that translates between the two wire formats at a trust boundary.

The first path is documented as future work in the SEP.

## SEP-side tables

See SEP §12.1 (transport framing divergence table) and §12.2 (domain-separation string migration table) for the full per-label mapping. SEP §3.4 has a migration note for implementations that bind against the HAAP SDK directly during this transition.

## For this repository specifically

This reference implementation was built from the SEP text only. It does not link against, port from, or copy any material from a HAAP implementation. The `tbac-*` domain strings in `packages/tbac-core-ts/src/crypto/hkdf.ts` are the sole normative source for this codebase; `haap-*` strings appear only in the §12.2 migration comment for reader clarity.
