# Architecture

TBAC sits between an MCP client/server's existing OAuth 2.1 session and the tool invocation itself. Instead of "here is my session token, please execute this tool", each `tools/call` carries "here is a token whose scope was authored by policy, sealed by TQS, and good for *this specific invocation only*".

## Components

```
┌──────────────┐   plaintext IPC   ┌──────────────┐    HTTPS     ┌─────────────┐
│ Agent / LLM  │ ◄────────────────►│  Assembler   │ ───────────► │  Resource   │
│ (zero crypto)│ ToolCallRequest / │ (one of N in │ token in     │  Server     │
│              │ ToolCallResponse  │ Pool §11.1.1)│ _meta        │  (cascade)  │
└──────────────┘                   └──────┬───────┘              └──────▲──────┘
                                          │ IPC                         │
                                          │ PrepareInvocation /         │
                                          │ TokenDelivery               │
                                   ┌──────▼───────┐                     │
                                   │     TQS      │                     │
                                   │  (mints      │                     │
                                   │   tokens)    │                     │
                                   └──────▲───────┘                     │
                                          │ IPC                         │
                                          │ SetSessionContext,          │
                                          │ MintPolicy, etc.            │
                                   ┌──────┴───────┐                     │
                                   │ Authenticator│                     │
                                   │ (X3DH ident. │                     │
                                   │  key mat.)   │                     │
                                   └──────▲───────┘                     │
                                          │ X3DH 4-DH                   │
                                          ▼                             │
                                   ┌──────────────┐                     │
                                   │  Auth Server │─────────────────────┘
                                   └──────────────┘   provisions {K_session,
                                                      verifier_secret,
                                                      mutual_auth, session_id}
                                                      out-of-band
```

**Trust architecture (Profile E).** The Agent/LLM holds zero cryptographic material. It communicates with the Assembler over plaintext local IPC (Unix domain sockets). The Assembler holds the minted token and `response_key` for the duration of a single in-flight call, and is the only component that opens an HTTPS connection to the RS. The TQS mints tokens on request from the Assembler using session material provisioned by the Authenticator, which in turn completed X3DH with the AS at session setup. The AS provisions the RS's session key-table entry out-of-band at session setup; the RS never contacts the AS for per-token verification. The AS and TQS never communicate directly.

**Profile E (recommended, default)** — each Assembler in the pool holds `response_key` for the single in-flight call it is handling. Individual Assemblers are single-flight, but the Assembler Pool (N default 1, max 8 per `maxAssemblersPerAgent` in SEP §2.1) supports concurrent tool invocations across the pool. The Agent holds zero cryptographic material.

**Profile S (constrained)** — direct-attach; the Agent holds `response_key` briefly during a request/response cycle.

This reference implementation exercises Profile E's data flow on one Assembler. The Pool (§11.1.1) is supported structurally (stub TQS + N Assemblers) but not demonstrated in the demo.

## Trust boundaries

Client-side trust hierarchy per SEP §11.1. The table below lists each component in the client's trust boundary, the key material it holds, and why it sits at that trust level. The Resource Server's trust posture on the server side is described separately below.

| Component | Key material | Why this tier |
|---|---|---|
| Authenticator | X3DH identity key material (IK private key) | Small binary, IPC-only; performs X3DH 4-DH key agreement with the AS and relays `session_id`, `verifier_secret`, `mutual_auth` to TQS via authenticated local IPC. Highest crypto trust. |
| TQS | `K_session`, SEK, `K_priv[epoch]` | Small binary, IPC-only; mints tokens, never makes egress HTTP. High crypto trust. |
| Assembler | Per-token `response_key` (ephemeral) | Small binary, IPC + egress HTTP; holds crypto only for the duration of one call. Medium crypto trust. |
| Supervisor/Scheduler | none | Process lifecycle and dispatch only; holds no key material and does not participate in token verification. No crypto trust. |
| Agent/LLM | **none** | LLM, plugins, prompt context — the most prompt-injection-vulnerable component; holds no credentials. No crypto trust. |

**Server-side trust note.** The Resource Server is outside the client-side trust hierarchy above because it sits in a different trust boundary. On the server side, the RS holds its session key-table — `{K_session, verifier_secret, mutual_auth, SEK_PK}` per session — provisioned by the AS out-of-band at session setup (SEP §4.1). The RS's trust posture is distinct from the client components: it verifies tokens minted by the client's TQS using material provisioned by the AS, with no per-token communication with either the AS or the TQS.

If an attacker fully compromises the Agent, all they can do is send plaintext to the Assembler. They cannot mint tokens, forge PoP, or decrypt stored traffic.

## Verify-then-decrypt

Cascade ordering is load-bearing. Step 6 (Schnorr verify) MUST complete before Step 7 (AEAD decrypt) — authenticating the ciphertext before decrypting it prevents decryption-oracle attacks. The meta-test at [`packages/tbac-core-ts/src/cascade/verify.order.test.ts`](../packages/tbac-core-ts/src/cascade/verify.order.test.ts) exists to catch any future refactor that reverses this ordering.

The step numbers reflect the current r41 cascade ordering; SEP §6 warns that numeric step references are not stable across revisions — stable identifiers are in the `failed_check` column of the denial-code table (e.g., `SCHNORR_VERIFICATION`, `AEAD_DECRYPTION`).

## Two-phase replay

Steps 10 and 15 split replay into reserve/commit. Step 10 is a non-destructive `GET` — fast-reject known replays. Step 15 is the atomic `SETNX` after all validation gates pass. Together they prevent "token-burn DoS" where an attacker who has the token but cannot pass PoP would otherwise permanently consume it.

## §8.1 defense-in-depth

Delegation attenuation runs at two independent sites:

1. **TQS mint-gate** — the stub TQS ([`DemoOnlyStubTqsClient.ts`](../packages/tbac-mcp-auth/src/provider/DemoOnlyStubTqsClient.ts)) calls `checkAttenuation(child, parent, 'mint')` before issuing any delegated token.
2. **RS cascade Step 13** — the reference cascade ([`verify.ts`](../packages/tbac-core-ts/src/cascade/verify.ts)) calls `checkAttenuation(child, parent, 'rs')` against the parent scope fetched from the consumed-token log.

Both must reject independently. A single layer is not enough — `pnpm demo:widening` proves both layers fire.

SEP r41 §8.1 also requires that the subset predicate respect non-transitivity across literal-prefix and wildcard rules. A transitive chain `child ⊆ intermediate ⊆ parent` does NOT imply `child ⊆ parent` when the intermediate subset relationships arise from different rules. For example, single-segment `*` requires segment-count equality, so `"public/docs/api"` is not a subset of `"public/*"` even though it is a subset of `"public/docs"` which is itself a subset of `"public/*"`. The `checkAttenuation` helper in both sites enforces this by evaluating each (child, parent) pair directly rather than chaining subset judgments. See SEP §8.1 r41 clarifying paragraph (P2.2) for the design rationale.
