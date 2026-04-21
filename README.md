# mcp-tbac-reference

Reference implementation of the **MCP Task-Based Access Control extension (SEP r41)**.
Apache 2.0 · Pre-review draft · TypeScript · Interoperable with any SEP r40/r41-conformant peer.

> **SEP version:** `2026-04-21-r41` (wire-compatible with `2026-04-20-r40`; both versions interoperate per §Preamble P2.1)
> **Spec source:** [`spec/0000-tbac-task-based-access-control-r41.md`](spec/0000-tbac-task-based-access-control-r41.md) (the single normative input to this implementation)
> **IP posture:** Apache 2.0 throughout with SPDX headers on every source file; copyright and patent non-assertion documented in [`NOTICE`](NOTICE).

TBAC binds each tool invocation to a **single-use, parameter-bound, cryptographically sealed authorization token**. Instead of session-scoped OAuth bearer tokens, every `tools/call` carries a token whose scope was authored by the policy component and sealed by the TQS at mint time, then verified by a 17-step cascade at the Resource Server. If an agent is compromised, the attacker inherits authorization for **one call** — not the session.

> **For reviewers:** See [`IMPLEMENTATION_SUMMARY.md`](IMPLEMENTATION_SUMMARY.md) for a single-page orientation covering coverage-by-SEP-section, deferred items, and reproduction commands.

## Quickstart

```bash
pnpm install
pnpm typecheck
pnpm test
pnpm demo                # happy path + scope denial + replay denial
pnpm demo:widening       # §8.1 delegation widening-attack — must fail closed at BOTH layers
```

## Packages

| Package | Purpose |
|---|---|
| `tbac-core` — [`packages/tbac-core-ts`](packages/tbac-core-ts) | Wire format, crypto primitives, 17-step cascade, scope canonicalization, §8.1 glob-subset attenuation, 11 denial codes, pluggable stores |
| `tbac-mcp-auth` — [`packages/tbac-mcp-auth`](packages/tbac-mcp-auth) | MCP SDK integration: `TbacAuthProvider` (client), `TbacTokenVerifier` (server, Express + Hono), capability negotiation, demo-only stub TQS with mint-gate attenuation, two demos |

## Documentation

| Audience | File |
|---|---|
| Landing | this README |
| New MCP integrator | [`docs/getting-started.md`](docs/getting-started.md) |
| Architect | [`docs/architecture.md`](docs/architecture.md) |
| Server author | [`docs/integration-guide.md`](docs/integration-guide.md) |
| Security reviewer | [`docs/verification-cascade.md`](docs/verification-cascade.md), [`docs/resource-attenuation.md`](docs/resource-attenuation.md) |
| SDK author | [`docs/capability-negotiation.md`](docs/capability-negotiation.md) |
| HAAP alignment (SEP §12) | [`docs/haap-alignment-note.md`](docs/haap-alignment-note.md) |
| Migration from r39 | [`R40_MIGRATION.md`](R40_MIGRATION.md) |
| Everyone | [`docs/faq.md`](docs/faq.md) |

## What changed in r41 (text-only)

r41 is a documentation and submission-readiness revision. No wire format change, no new scope fields, no new denial codes, no cascade changes. r41 implementations are normatively equivalent on the wire to r40 implementations and MUST interoperate with them (§Preamble P2.1). This codebase now advertises `"2026-04-21-r41"` and continues to accept `"2026-04-20-r40"` peers.

The r41 text fixes this codebase picked up:

- **§A.3.1** — `allowed_parameters` inner TLV encoding (inner tag `0x01`=key, `0x02`=pattern, lex byte-order sort, duplicate-key rejection, empty-object handling). Implemented in [`scope/canonical.ts`](packages/tbac-core-ts/src/scope/canonical.ts).
- **§A.4 clause 4** — unknown-tag partition policy (strict-reject `0x01`–`0x7F`, silent-skip `0x80`–`0xFE`, reject `0xFF`) enforced at every nesting level (scope, constraints, allowed_parameters inner entries).
- **§8.1 version-string typo fix** — spec-side edit, no code impact.

## What changed in r40 (previous breaking revision)

r40 closed an externally-reported widening-attack gap in the delegation attenuation path:

1. **`scope.resource` is REQUIRED.** Use `"*"` for tool-wide authorization. Absent/null → denial.
2. **§8.1 glob-subset semantics** — child `resource` MUST be equal to or a subset of parent `resource`.
3. **Canonical widening attack** — child `"*"` under parent `"public/*"` — MUST be rejected at **both** TQS mint-gate AND RS cascade Step 13.
4. **Transition window** — `acceptR39Tokens` flag (default `true`) coerces missing `resource` to `"*"` with a deprecation warning, but only when the peer advertises r39. See [`R40_MIGRATION.md`](R40_MIGRATION.md).

The `pnpm demo:widening` script is the ground-truth regression test: it fails closed at both the mint-gate and the RS cascade.

## Scope (IN / OUT)

**IN:** Profile E (Assembler, enterprise, `msg_type = 0x03`) and Profile S (direct-attach) tokens; 17-step cascade; HKDF / Ristretto255 Schnorr / AES-256-GCM with the `tbac-*` domain strings from SEP §A.5 and §12.2; `_meta["io.modelcontextprotocol/tbac"]` transport with `experimental` fallback; §8.1 glob-subset predicate with defense-in-depth at both sites; §A.3.1 `allowed_parameters` inner TLV encoding and §A.4 clause-4 unknown-tag partition; `max_ttl` + token-minted-within-session enforcement (§3.0, §4.3 Step 4); `require_channel_encryption` enforcement (§3.3); T3 `approval_digest` recomputation + CIBA freshness (§3.2); Step 13.7 intent-hash integrity (§4.3); conformance test vectors derived from §A.5; two demos.

**OUT (hook interfaces only):** Consumer profile (`0x08`), T0 ephemeral profile (`0x09`), response encryption (`K_req`/`K_resp` — plaintext in the demo), Step 13.7 intent-action comparison modes `keyword_match` and `classifier` (hash-integrity portion IS enforced; action-comparison default is `log_only`), non-JSON PoP (`request_format = 0x01` — rejected at mint-gate per §3.6.1), HAAPI billing, cipher-suite negotiation. Rust is deferred; see [`RUST_DEFERRED.md`](RUST_DEFERRED.md).

## License and patents

Apache 2.0 throughout; see [`LICENSE`](LICENSE). The SEP author's patent non-assertion commitment for normative-only implementations is mirrored into [`NOTICE`](NOTICE). The SEP describes its normative requirements at the interface level so that conforming implementations do not need to use any specific patented method.
