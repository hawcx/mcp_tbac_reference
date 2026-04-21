# Getting started

15 minutes from clone to a running demo of all three TBAC outcomes: happy path, scope denial, replay denial.

## Prerequisites

- Node.js 20+
- pnpm 9+

## Clone and install

```bash
git clone https://github.com/hawcx/mcp_tbac_reference
cd mcp_tbac_reference
pnpm install
```

## Run the demo

```bash
pnpm demo
```

Expected output:

```
[demo] TBAC reference implementation (SEP 2026-04-21-r41)
[demo] case 1 PASS — valid token, scope resource="billing-api/*"
[demo] case 2 PASS — denial code=INSUFFICIENT_PRIVILEGE failed_check=TBAC_SCOPE_EVALUATION
[demo] case 3 PASS — replay of jti="..." denied: TOKEN_REPLAYED
[demo] ALL CASES PASS
```

## Run the §8.1 widening-attack demo

This is the ground-truth regression test for §8.1 (introduced in r40, unchanged in r41). It fails closed at BOTH the TQS mint-gate and the RS cascade Step 13:

```bash
pnpm demo:widening
```

## Next steps

- Read [`verification-cascade.md`](verification-cascade.md) to understand the 17-step cascade.
- Read [`resource-attenuation.md`](resource-attenuation.md) for §8.1 glob-subset semantics and the widening attack.
- Read [`integration-guide.md`](integration-guide.md) to add `TbacTokenVerifier` to your MCP server.
