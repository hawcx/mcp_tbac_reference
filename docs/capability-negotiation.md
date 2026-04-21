# Capability negotiation

Per §2.1 and §2.2, TBAC peers advertise support for the extension via `capabilities.extensions["io.modelcontextprotocol/tbac"]`. Peers that predate SEP-2133's `extensions` mechanism may use `capabilities.experimental` as a transitional fallback.

## Version matching is exact

Per §2.1, "Implementations MUST use **exact string matching** for version recognition; lexicographic or numeric ordering of version strings is NOT defined and MUST NOT be used." Unrecognized versions → proceed without TBAC (not connection failure). This is the `negotiatePeer(...).enabled = false` branch.

## This implementation's version

```
2026-04-21-r41
```

r41 is wire-compatible with r40. The negotiator accepts peers advertising either `"2026-04-21-r41"` or `"2026-04-20-r40"` per §Preamble P2.1; peers that have not bumped continue to negotiate correctly.

## Server advertisement

```ts
import { buildServerCapability } from 'tbac-mcp-auth';

const capability = buildServerCapability({
  deploymentProfile: 'E',
  supportsPolicyTemplateDiscovery: true,
  maxDelegationDepth: 3,
});
// ⇒ { capabilities: { extensions: { 'io.modelcontextprotocol/tbac': { version: '2026-04-21-r41', ... } } } }
```

## Client advertisement

```ts
import { buildClientCapability } from 'tbac-mcp-auth';

const capability = buildClientCapability({ deploymentProfile: 'E', hasTqs: true });
```

## Peer inspection

```ts
import { negotiatePeer } from 'tbac-mcp-auth';

const r = negotiatePeer(incomingInitResponse);
if (!r.enabled) {
  console.log(`TBAC disabled: ${r.why}`);
} else {
  // pass r.acceptR39Tokens into TbacTokenVerifier
}
```

`negotiatePeer` returns:

| Field | Meaning |
|---|---|
| `enabled` | True iff we recognize the peer's version string |
| `peerVersion` | The peer's advertised version (may be r41, r40, r39, or unrecognized) |
| `acceptR39Tokens` | True iff the peer advertised r39 — enables the transition-window coercion |
| `usedExperimentalFallback` | True iff we found the extension under `experimental` rather than `extensions` |
| `why` | Human-readable reason; useful for logging |
