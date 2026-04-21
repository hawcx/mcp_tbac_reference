# Architecture

TBAC sits between an MCP client/server's existing OAuth 2.1 session and the tool invocation itself. Instead of "here is my session token, please execute this tool", each `tools/call` carries "here is a token whose scope was authored by policy, sealed by TQS, and good for *this specific invocation only*".

## Components

```
┌──────────────┐                ┌─────────────┐
│ Agent / LLM  │                │ Resource    │
│ (zero crypto │ ────HTTPS────► │ Server      │
│  in Profile E)│                │ (cascade)   │
└──────┬───────┘                └──────┬──────┘
       │                                │
       │ IPC                            │
       │                                │
┌──────▼───────┐   IPC   ┌──────┐       │
│ Assembler    │────────►│ TQS  │       │
│ (one per     │         │      │       │
│  in-flight   │         └──┬───┘       │
│  call)       │            │ IPC       │
└──────────────┘            │           │
                    ┌───────▼───────┐   │
                    │ Authenticator │   │
                    └───────┬───────┘   │
                            │ X3DH      │
                            │           │
                    ┌───────▼───────┐   │
                    │ Auth Server   │───┤ provisions K_session,
                    └───────────────┘   │ verifier_secret, mutual_auth
                                        │ out-of-band
```

**Profile E (recommended, default)** — the Assembler holds `response_key` for one in-flight call at a time; the Agent holds zero crypto material.

**Profile S (constrained)** — direct-attach; the Agent holds `response_key` briefly during a request/response cycle.

This reference implementation exercises Profile E's data flow on one Assembler. The Pool (§11.1.1) is supported structurally (stub TQS + N Assemblers) but not demonstrated in the demo.

## Trust boundaries

Four trust tiers per §11.1:

| Component | Key material | Why this tier |
|---|---|---|
| Authenticator | IK private key | Holds the root identity; only runs X3DH |
| TQS | `K_session`, SEK, `K_priv[epoch]` | Mints tokens; never makes egress HTTP |
| Assembler | Per-token `response_key` | Holds crypto only for the duration of one call |
| Agent/LLM | **none** | The most prompt-injection-vulnerable component holds no credentials |

If an attacker fully compromises the Agent, all they can do is send plaintext to the Assembler. They cannot mint tokens, forge PoP, or decrypt stored traffic.

## Verify-then-decrypt

Cascade ordering is load-bearing. Step 6 (Schnorr verify) MUST complete before Step 7 (AEAD decrypt) — authenticating the ciphertext before decrypting it prevents decryption-oracle attacks. The meta-test at [`packages/tbac-core-ts/src/cascade/verify.order.test.ts`](../packages/tbac-core-ts/src/cascade/verify.order.test.ts) exists to catch any future refactor that reverses this ordering.

## Two-phase replay

Steps 10 and 15 split replay into reserve/commit. Step 10 is a non-destructive `GET` — fast-reject known replays. Step 15 is the atomic `SETNX` after all validation gates pass. Together they prevent "token-burn DoS" where an attacker who has the token but cannot pass PoP would otherwise permanently consume it.

## r40 §8.1 defense-in-depth

Delegation attenuation runs at two independent sites:

1. **TQS mint-gate** — the stub TQS ([`TqsClient.ts`](../packages/hawcx-mcp-auth/src/provider/TqsClient.ts)) calls `checkAttenuation(child, parent, 'mint')` before issuing any delegated token.
2. **RS cascade Step 13** — the reference cascade ([`verify.ts`](../packages/tbac-core-ts/src/cascade/verify.ts)) calls `checkAttenuation(child, parent, 'rs')` against the parent scope fetched from the consumed-token log.

Both must reject independently. A single layer is not enough — `pnpm demo:widening` proves both layers fire.
