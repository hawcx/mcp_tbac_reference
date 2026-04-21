# r40 §8.1 — Resource attenuation under glob subset semantics

This is the section that motivated SEP revision r40. r39 left delegation attenuation on the `resource` field ambiguous; a single widening-attack pattern could pass both the field-semantic rule and the attenuation rule, resulting in delegation-chain privilege escalation. r40 fixes the ambiguity by making `resource` REQUIRED, spelling out the glob-subset predicate, and requiring defense-in-depth enforcement at both the TQS mint-gate and the RS cascade.

## The canonical widening attack

```
parent: resource = "public/*"
child:  resource = "*"
```

The child's pattern (a single-segment wildcard matching every top-level segment) is strictly broader than the parent's. A naive implementation that read absence-as-wildcard (r39) or that only checked attenuation at one site could let the child through.

**r40 requires rejection at BOTH sites.** The reference implementation demonstrates this via [`pnpm demo:widening`](../packages/hawcx-mcp-auth/src/demo/delegation_widening_demo.ts):

```
[widening-demo] TBAC §8.1 defense-in-depth (SEP 2026-04-20-r40)
[widening-demo] layer-1 TQS mint-gate REJECTED: ScopeCeilingExceeded
[widening-demo] layer-2 RS cascade REJECTED: code=INSUFFICIENT_PRIVILEGE
                                              failed_check=TBAC_SCOPE_EVALUATION
                                              tag=r40.8.1.rs_cascade.widening_attack
[widening-demo] BOTH LAYERS REJECTED — §8.1 defense-in-depth verified
```

The named unit test `widening_attack_star_under_public_star` in [`packages/tbac-core-ts/src/scope/glob.test.ts`](../packages/tbac-core-ts/src/scope/glob.test.ts) is the ground-truth regression signal. If that test ever passes `true`, the r40 defense has been regressed and the demo will fail closed.

## Glob-subset semantics

From §8.1 verbatim:

- `"*"` (single-segment wildcard) is a subset of `"*"`, and is a subset of `"**"` at the same path depth.
- `"**"` (multi-segment wildcard) is a subset of `"**"` only.
- Any literal pattern (e.g., `"public/docs"`) is a subset of any wildcard pattern that matches it (`"public/*"`, `"public/**"`, `"*"`, `"**"`).
- Two literal patterns are in a subset relationship only when one is an exact prefix of the other at a path-segment boundary (`"public/docs/api"` is a subset of `"public/docs"` but not of `"public/do"`).
- `\*` escapes a literal asterisk in a segment.

The subset predicate lives at [`packages/tbac-core-ts/src/scope/glob.ts`](../packages/tbac-core-ts/src/scope/glob.ts) as `isSubset(child, parent)`. It is implemented from scratch — do not substitute `minimatch` or `picomatch`; their semantics differ.

## Worked examples

| Child | Parent | Subset? | Why |
|---|---|---|---|
| `*` | `*` | ✓ | equal wildcards |
| `public/*` | `public/*` | ✓ | equal |
| `public/docs` | `public/*` | ✓ | literal under single wildcard at matching depth |
| `public/docs/api` | `public/**` | ✓ | literal under double wildcard |
| `public/docs/api` | `public/*` | ✗ | three segments vs. two — single wildcard is one segment |
| `public/docs` | `public/do` | ✗ | not path-segment aligned |
| `*` | `public/*` | ✗ **widening attack** | single wildcard matches more than `public/*` |
| `**` | `*` | ✗ | double wildcard matches more than single |
| `\*name` | `*` | ✓ | escaped literal, one segment |

## Delegation attenuation

The full attenuation check is `checkAttenuation(child, parent, site)` in [`attenuation.ts`](../packages/tbac-core-ts/src/scope/attenuation.ts). It verifies:

- `tool` byte-equal
- `org_id` byte-equal
- `delegation_depth` strictly decreasing
- `trust_level` ≤ parent
- `action` set ⊆ parent
- **`resource`** glob-subset under §8.1
- `constraints.max_rows`, `max_calls`, `time_window_sec` each ≤ parent
- `require_channel_encryption`: if parent required it, child must too

`site = 'mint'` and `site = 'rs'` return the same `INSUFFICIENT_PRIVILEGE` / `TBAC_SCOPE_EVALUATION` denial publicly. They differ in the `internalTag` — `r40.8.1.mint_gate.*` vs `r40.8.1.rs_cascade.*` — used only in telemetry, never in the response envelope.

## r39 transition window

`acceptR39Tokens` (default `true` in `TbacTokenVerifier`) lets you accept r39-format tokens (with absent `resource`) from peers that advertise the r39 version. When the fallback fires, a structured warning log is emitted:

```json
{ "level": "warn", "event": "tbac.r39_resource_fallback",
  "jti": "<jti>", "agent_instance_id": "<id>",
  "message": "r39-format token with absent resource coerced to '*'; update producer to r40" }
```

Close the window at r41 by setting `acceptR39Tokens: false`.

## Conformance vector

[`test-vectors/v1/r40-attenuation.json`](../test-vectors/v1/r40-attenuation.json) fixes the canonical attack pattern. A conforming implementation that has broken r40 will fail this vector even if its crypto primitives are byte-identical to ours — attenuation is a separate axis from the derivations.
