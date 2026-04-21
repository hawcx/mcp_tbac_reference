# hx-mcp-tbac

Clean-room TypeScript reference implementation of **MCP Task-Based Access Control (SEP r40)**.
Apache 2.0 · Pre-review draft · Interoperable with any SEP r40-conformant peer.

> **SEP version:** `2026-04-20-r40`
> **Spec source:** [`spec/0000-tbac-task-based-access-control-r40.md`](spec/0000-tbac-task-based-access-control-r40.md) (the single normative input)
> **Clean-room:** Built from the SEP alone; no code or constants from Hawcx's proprietary HAAP (`haap-*`) codebase.

TBAC binds each tool invocation to a **single-use, parameter-bound, cryptographically sealed authorization token**. Instead of session-scoped OAuth bearer tokens, every `tools/call` carries a token whose scope was authored by the policy component and sealed by the TQS at mint time, then verified by a 17-step cascade at the Resource Server. If an agent is compromised, the attacker inherits authorization for **one call** — not the session.

## Quickstart

```bash
pnpm install
pnpm typecheck
pnpm test
pnpm demo                # happy path + scope denial + replay denial
pnpm demo:widening       # r40 §8.1 delegation widening-attack — must fail closed at BOTH layers
```

## Packages

| Package | Purpose |
|---|---|
| [`packages/tbac-core-ts`](packages/tbac-core-ts) — `@hawcx/tbac-core` | Wire format, crypto primitives, 17-step cascade, scope canonicalization, `§8.1` glob-subset attenuation, 11 denial codes, pluggable stores |
| [`packages/hawcx-mcp-auth`](packages/hawcx-mcp-auth) — `hawcx-mcp-auth` | MCP SDK integration: `TbacAuthProvider` (client), `TbacTokenVerifier` (server, Express + Hono), capability negotiation, stub TQS with mint-gate attenuation, two demos |

## Documentation

| Audience | File |
|---|---|
| Landing | this README |
| New MCP integrator | [`docs/getting-started.md`](docs/getting-started.md) |
| Architect | [`docs/architecture.md`](docs/architecture.md) |
| Server author | [`docs/integration-guide.md`](docs/integration-guide.md) |
| Security reviewer | [`docs/verification-cascade.md`](docs/verification-cascade.md), [`docs/resource-attenuation.md`](docs/resource-attenuation.md) |
| SDK author | [`docs/capability-negotiation.md`](docs/capability-negotiation.md) |
| Standards / boundaries | [`docs/relationship-to-haap.md`](docs/relationship-to-haap.md) |
| Migration from r39 | [`R40_MIGRATION.md`](R40_MIGRATION.md) |
| Everyone | [`docs/faq.md`](docs/faq.md) |

## What changed in r40 (breaking)

r40 closes an externally-reported widening-attack gap in the delegation attenuation path:

1. **`scope.resource` is now REQUIRED.** Use `"*"` for tool-wide authorization. Absent/null → denial.
2. **§8.1 glob-subset semantics** — child `resource` MUST be equal to or a subset of parent `resource`.
3. **Canonical widening attack** — child `"*"` under parent `"public/*"` — MUST be rejected at **both** TQS mint-gate AND RS cascade Step 13.
4. **Transition window** — `acceptR39Tokens` flag (default `true`) coerces missing `resource` to `"*"` with a deprecation warning, but only when the peer advertises r39. See [`R40_MIGRATION.md`](R40_MIGRATION.md).

The `pnpm demo:widening` script is the ground-truth regression test: it fails closed at both the mint-gate and the RS cascade.

## Scope (IN / OUT)

**IN:** Profile E (Assembler, enterprise, `msg_type = 0x03`) and Profile S (direct-attach) tokens; 17-step cascade; HKDF / Ristretto255 Schnorr / AES-256-GCM with the `tbac-*` domain strings from SEP §A.5 and §12.2; `_meta["io.modelcontextprotocol/tbac"]` transport with `experimental` fallback; r40 §8.1 glob-subset predicate with defense-in-depth at both sites; conformance test vectors derived from §A.5; two demos.

**OUT (hook interfaces only):** Consumer profile (`0x08`), T0 ephemeral profile (`0x09`), response encryption (`K_req`/`K_resp` — plaintext in the demo), intent verification Step 13.7 (default `log_only` no-op), non-JSON PoP (`request_format = 0x01` — rejected at mint-gate per §3.6.1), HAAPI billing, cipher-suite negotiation. Rust is deferred; see [`RUST_DEFERRED.md`](RUST_DEFERRED.md).

## License and patents

Apache 2.0 throughout. See [`LICENSE`](LICENSE). The SEP's patent non-assertion commitment for normative-only implementations is copied into [`NOTICE`](NOTICE). Normative requirements are described at the interface level and do not require patented methods.
