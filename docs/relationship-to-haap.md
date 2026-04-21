# Relationship to Hawcx HAAP

This repository (`hx_mcp_tbac`) and Hawcx's HAAP codebase are two distinct artifacts with distinct licenses, distinct scopes, and distinct audiences. Understanding the boundary matters for interop, clean-room reviews, and legal posture.

## The two-repo model

|  | `hx_mcp_tbac` (this repo) | Hawcx HAAP (`hx_labs`) |
|---|---|---|
| License | Apache 2.0 | Proprietary |
| Scope | SEP r40 normative requirements only | Full HAAP Canonical Specification v6.0.0 |
| Purpose | Reference implementation + interop vectors | Production implementation with patented optimizations |
| Language | TypeScript | Rust |
| Domain strings | `tbac-*` (§12.2 this column) | `haap-*` (§12.2 HAAP column) |
| Clean-room? | Yes — no access to HAAP source | — |

## SEP §12 divergence — intentional

Per SEP r40 §12.1 / §12.2, this SEP deliberately diverges from HAAP in two axes:

1. **Transport framing.** HAAP uses HTTP headers (`Authorization: HAAP …`, `HAAP-PoP`); this SEP uses `_meta["io.modelcontextprotocol/tbac"]` so tokens are visible to MCP message-processing layers across all transports (Streamable HTTP, stdio, SSE).
2. **Domain-separation string naming.** HAAP uses `haap-token-enc-v3` etc.; this SEP uses `tbac-token-enc-v1` etc. Both constructions are cryptographically equivalent; the strings differ to prevent accidental cross-implementation token confusion.

Byte-level interop with HAAP requires an explicit conformance mode in the HAAP SDK. The SEP documents this as future work.

## Clean-room guarantee

This repository was built from `spec/0000-tbac-task-based-access-control-r40.md` alone. It does not incorporate, port, or reference any source code, type definitions, test vectors, or proprietary constants from HAAP. Every domain-separation label in this repository uses the `tbac-*` prefix normative to SEP r40 §A.5 and §12.2.

Enforcement:
- The CI job [`no-haap-prefix`](../.github/workflows/no-haap-prefix.yml) fails any PR that introduces the literal string `haap-` into source files outside a single tightly-scoped comment in [`packages/tbac-core-ts/src/crypto/hkdf.ts`](../packages/tbac-core-ts/src/crypto/hkdf.ts) (which references both strings for §12.2 migration clarity, not for use).
- All dependencies are maintained audited third-party libraries (`@noble/curves`, `@noble/ciphers`, `@noble/hashes`). No code from Hawcx or its proprietary distributions is linked.

## Patent posture

Hawcx holds patent applications covering specific implementation techniques — the proprietary signcryption construction, TQS architecture optimizations, Assembler architecture, and bidirectional response encryption mechanisms. Per SEP r40's patent notice and [`NOTICE`](../NOTICE), Hawcx commits to not asserting patent claims against implementations that conform solely to SEP r40's normative requirements. The `alg_id = 0x01` opaque profile defines a fixed algorithm suite; alternative constructions would require a new profile in a future revision.

## When to use which

- Building an MCP server/client that needs TBAC? **Use this repo.**
- Building on Hawcx's HAAP platform directly? Use the HAAP SDK.
- Validating interop across implementations? Use this repo's conformance vectors — they are the single source of truth for SEP r40 byte-level expectations.
