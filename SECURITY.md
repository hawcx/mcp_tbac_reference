# Security Policy

This is a **pre-review reference implementation** of MCP TBAC SEP r40. It is not yet recommended for production use.

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
