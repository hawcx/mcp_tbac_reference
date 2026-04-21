# r39 → r40 Migration

SEP r40 introduces one breaking semantic change, driven by an external security audit on 2026-04-20. This document explains the change, the transition window, and how to migrate both producers (TQS) and consumers (RS).

## TL;DR

| Aspect | r39 | r40 |
|---|---|---|
| `scope.resource` | OPTIONAL; absence meant "tool-wide" | REQUIRED; use explicit `"*"` for tool-wide |
| Widening attack (child `"*"` under parent `"public/*"`) | Ambiguous — some impls permitted | MUST be rejected at both TQS mint-gate and RS cascade Step 13 (defense-in-depth) |
| Delegation attenuation on `resource` | Informally described | Formal glob-subset predicate in §8.1 |
| Capability `version` string | `"2026-04-17-r39"` | `"2026-04-20-r40"` |

## The widening attack

In r39, a policy could author a parent token with `resource: "public/*"`, and a downstream delegating agent could mint a child token that omitted `resource` entirely. The r39 field-semantic rule read absence as unrestricted tool-wide grant — a superset of `"public/*"`. The r39 attenuation rule required child ⊆ parent. These two rules gave opposite verdicts on the same token. A conforming r39 implementation that honored the field-semantic rule at authorization time could pass a widened child through delegation.

r40 resolves the inconsistency. `resource` is REQUIRED; there is no "absence" case; the glob-subset predicate in §8.1 is normative; the widening pattern MUST be rejected.

## The `acceptR39Tokens` flag

The `TbacTokenVerifier` exposes an `acceptR39Tokens` flag (default `true`). When enabled, a token that (a) carries a peer advertising capability version `"2026-04-17-r39"` **and** (b) omits `resource` will be processed with the coerced value `"*"` and a single structured warning log:

```json
{
  "level": "warn",
  "event": "tbac.r39_resource_fallback",
  "jti": "<jti>",
  "agent_instance_id": "<id>",
  "message": "r39-format token with absent resource coerced to '*'; update producer to r40"
}
```

The fallback is **version-gated** — an r40-version token that omits `resource` is a denial, not a fallback.

The deprecation window closes at the revision after r40. At that point:
- Set `acceptR39Tokens: false` explicitly.
- The flag will be removed in a subsequent release.

## Producer migration (TQS)

1. Bump your capability-advertisement `version` to `"2026-04-20-r40"`.
2. In your scope-authoring path, add a required `resource` field. Use `"*"` when you intend tool-wide grant.
3. When minting a delegated token, compute the subset predicate (library function `checkAttenuation(child, parent, 'mint')`) and reject with `InvocationRejected{ reason: 'ScopeCeilingExceeded' }` on violation. This is load-bearing — the reference implementation's stub TQS demonstrates this; your production TQS MUST do it.

## Consumer migration (RS)

1. Bump your capability-advertisement `version` to `"2026-04-20-r40"`.
2. Enable the §8.1 check at cascade Step 13. The reference cascade in this repo does this automatically — the denial code is `TBAC_SCOPE_EVALUATION` / `failed_check: TBAC_SCOPE_EVALUATION` with distinguishing internal telemetry (not visible in the denial response).
3. Decide your policy on r39 tokens during the transition:
   - Permissive (default): `acceptR39Tokens: true`, accept r39-version tokens, emit the deprecation log.
   - Strict: `acceptR39Tokens: false`, reject any r39-version token that omits `resource`.

## Observing the change in this repo

- Run `pnpm demo:widening` — prints the two rejection events in order.
- Read [`docs/resource-attenuation.md`](docs/resource-attenuation.md) for the worked walk-through.
- See `packages/tbac-core-ts/src/scope/glob.ts` and `packages/tbac-core-ts/src/scope/attenuation.ts` — these two modules are the r40 attack defense.

## Version string typo observation (for the SEP authors)

SEP r40 §8.1's transition paragraph refers to `"2026-04-17-r40"`. The Preamble, §2.1, and §2.2 all use `"2026-04-20-r40"`. This reference implementation treats the Preamble/§2.1 form as normative. Recommend the §8.1 transition paragraph be corrected in r41.
