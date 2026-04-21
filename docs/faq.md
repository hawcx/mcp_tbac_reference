# FAQ

## How does TBAC relate to OAuth 2.1?

TBAC *layers on top of* MCP's existing OAuth 2.1 authorization. OAuth answers "who is this client and what broad permissions do they have?"; TBAC answers "what specific task is this request, and does the token authorize exactly this invocation?". You need both: OAuth establishes the session; TBAC scopes each tool call within that session.

## Can I use this in production today?

This is a pre-review reference implementation. Use it for interop testing, prototyping, and spec validation. For production, wait for the first officially accepted revision in the `ext-auth` repository, then pin to that version.

## Why not JWT?

Two practical reasons:

1. JWTs are at least a kilobyte for anything meaningful; the opaque TBAC token is ~260 bytes. At Agentforce scale (11M calls/day cited by the SEP), that difference compounds.
2. JWT scope fields are opaque strings. TBAC scope JSON is structured — `tool`, `action`, `resource`, `constraints` — and TLV-canonicalized so `priv_sig` binds exact semantics. A future revision may define a JOSE profile (§3.4 canonicalization note); for now the native opaque format is the sole normative wire.

## What's the performance story?

Per §4.3, the enterprise cascade targets <490 µs. This reference implementation is not latency-optimized but clears the same bar in CI for the §A.5.1 fixture (≤5 ms including allocation). Production deployments should use Redis for the replay/session stores.

## What changed in r41?

r41 is a documentation/submission-readiness revision. No wire format change, no new scope fields, no new denial codes, no cascade changes. Six text-level fixes: §A.3.1 now specifies the `allowed_parameters` inner TLV encoding; §A.4 clause 4 adds the unknown-tag partition policy; §8.1 gets a version-string typo fix and a non-transitivity clarification; the r39→r40 deprecation window is re-anchored to close after r41; and the §Reference Implementation section is rewritten to point at this repo. r41 peers and r40 peers MUST interoperate (§Preamble P2.1).

## What changed in r40?

See [`R40_MIGRATION.md`](../R40_MIGRATION.md). Short version: `resource` is REQUIRED; the canonical widening attack is rejected at both TQS mint-gate and RS cascade.

## Is this the final version of the SEP?

No — pre-review revisions r26–r41 are draft. Breaking changes may still occur. Version strings are exact-match (§2.1) specifically to ensure implementations negotiate to compatible peers during this phase.

## Where can I discuss bugs or propose changes?

- Implementation bugs in this repo: open an issue at `https://github.com/hawcx/mcp_tbac_reference`.
- SEP design questions: engage with the MCP extension-repo discussion once the SEP is submitted.
- Security issues: `security@hawcx.com` per [`SECURITY.md`](../SECURITY.md).

## Does this implement the entire SEP?

Base conformance only. Consumer profile (`msg_type = 0x08`), T0 ephemeral (`0x09`), response encryption (`K_req`/`K_resp`), intent verification Step 13.7, non-JSON PoP (`request_format = 0x01`), HAAPI billing, and cipher-suite negotiation are hook interfaces with the SEP's default behaviors. See the "OUT OF SCOPE" section in the main [`README.md`](../README.md).
