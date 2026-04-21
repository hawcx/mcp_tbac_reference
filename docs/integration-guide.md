# Integration guide (server author)

You already have an MCP server. This guide shows how to add `TbacTokenVerifier` to it with minimal wiring.

## Install

```bash
pnpm add tbac-mcp-auth tbac-core
```

## Wire up stores

In production you'll back these with Redis / PostgreSQL / your own infra. The in-memory impls are fine for tests and single-process deployments.

```ts
import {
  MemoryConsumedTokenLog,
  MemoryPolicyTemplateStore,
  MemoryReplayStore,
  MemorySessionStore,
} from 'tbac-core';

const sessions = new MemorySessionStore();
const replay = new MemoryReplayStore();
const templates = new MemoryPolicyTemplateStore();
const consumedLog = new MemoryConsumedTokenLog();
```

Provision each session from your Authenticator's X3DH handshake (out of band). Populate `templates` with per-agent, per-tool policy ceilings.

## Create the verifier

```ts
import { TbacTokenVerifier, buildServerCapability } from 'tbac-mcp-auth';

const verifier = new TbacTokenVerifier({
  rsIdentifier: 'https://rs.example.com/mcp',
  rsCurrentEpoch: 1n,
  sessions,
  replay,
  templates,
  consumedLog,
  acceptR39Tokens: true, // default; opt out at the r41 revision
});

const capability = buildServerCapability({
  deploymentProfile: 'E',
  supportsPolicyTemplateDiscovery: true,
});
// Merge `capability.capabilities` into your MCP initialize response.
```

## Per-tool-call verification

In your `tools/call` handler, pull the `_meta` field and the tool identity:

```ts
const result = await verifier.verify({
  meta: params._meta,
  requestedAction: deriveAction(toolName, params), // 'read' | 'write' | 'execute'
  requestedResource: deriveResource(toolName, params),
  peerVersion: negotiatedPeerVersion, // from the capability-negotiation handshake
});

if (!result.ok) {
  // Return the denial envelope directly to the client as a CallToolResult.
  return result.denialEnvelope.result;
}

// Success — scope is available.
const scope = result.scope;
// Apply per-tool policy (max_rows, allowed_parameters, etc.) as needed.
```

## r39 transition window

The `acceptR39Tokens` flag (default `true`) lets you accept r39-format tokens (with absent `resource`) from peers that advertise the r39 capability version. The verifier emits a structured deprecation log line each time the fallback fires. Set `acceptR39Tokens: false` at the r41 revision when the transition window closes.

## Hono adapter

```ts
import { tbacHono } from 'tbac-mcp-auth';

app.post('/mcp',
  tbacHono(verifier, {
    getMeta: (body) => body?.params?._meta,
    getRequestedAction: (body) => 'read', // map from your tool dispatch table
    getRequestedResource: (body) => body?.params?.resource_uri ?? '*',
  }),
  yourToolsCallHandler,
);
```

## Express adapter

```ts
import { tbacExpress } from 'tbac-mcp-auth';

app.post('/mcp',
  tbacExpress(verifier, {
    getMeta: (req) => (req.body as any)?.params?._meta,
    getRequestedAction: () => 'read',
    getRequestedResource: (req) => (req.body as any)?.params?.resource_uri ?? '*',
  }),
  yourToolsCallHandler,
);
```
