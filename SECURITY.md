# Security Policy

This is a **pre-review reference implementation** of MCP TBAC SEP r41 (wire-compatible with r40). It is not yet recommended for production use.

## Reporting a vulnerability

Please do not file public GitHub issues for security vulnerabilities. Report them privately to `security@hawcx.com`. Include a clear description, reproduction steps, and any artifacts (token hex, stack traces) that help triage.

If the vulnerability is in the SEP itself (protocol design bug), please also open a discussion on the MCP extension repository once it is assigned; the repo maintainers will coordinate a coordinated disclosure.

## Scope

- Clean-room library code: `packages/tbac-core-ts`, `packages/tbac-mcp-auth`.
- Test vectors in `test-vectors/v1/`.
- CI workflows, guard scripts.

## Out of scope

- `spec/` document (upstream SEP authoring — file bugs on the SEP itself in the extension repository once assigned).
- Any proprietary TBAC implementation that is not this codebase.

## Known non-goals

- Non-JSON PoP (`request_format = 0x01`) is deliberately rejected per §3.6.1. A report that a valid-looking `0x01` token is rejected is expected behavior, not a vulnerability.
- Consumer profile (`msg_type = 0x08`) and T0 ephemeral (`0x09`) are hook interfaces only; they are not enforced by this implementation.

## Clean-room posture (for strict provenance reviewers)

Library source under `packages/` is clean-room relative to proprietary HAAP code; the `scripts/no-haap-prefix.sh` guard enforces the absence of `haap-*` strings and runs in CI on every push. The following **non-source-code** references to Hawcx Inc. are intentional and will remain through the pre-review phase:

- **`security@hawcx.com`** (this file) — the working vulnerability-disclosure channel during the SEP's pre-review phase. `security@modelcontextprotocol.io` does not exist yet; removing this contact without a replacement would eliminate responsible-disclosure routing.
- **`NOTICE`** — Apache 2.0 attribution and patent non-assertion commitment are in Hawcx Inc.'s name by license requirement.
- **SEP r41 §Reference Implementation** — the SEP itself names `github.com/hawcx/mcp_tbac_reference` as the reference repo and `Hawcx Inc.` as the author. Documentation pointing to this URL mirrors the SEP.
- **`docs/haap-alignment-note.md`** — SEP §12 defines alignment/divergence between TBAC and the HAAP Canonical Specification by design; this document is a reader-facing aid for that section.

These are presentation/provenance choices, not source-code contamination. If the SEP is accepted into `modelcontextprotocol/ext-auth`, the vulnerability-disclosure address and the repo URL can be rehomed at that point.
