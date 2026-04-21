# tbac-mcp-auth

MCP SDK integration for TBAC (SEP r41; wire-compatible with r40). Provides:

- `TbacAuthProvider` — client-side; attaches a TBAC token to each tool call in `_meta["io.modelcontextprotocol/tbac"]`.
- `TbacTokenVerifier` — server-side middleware. Express and Hono adapters provided.
- Capability negotiation helpers (`extensions.io.modelcontextprotocol/tbac`, with `experimental` fallback). Accepts r41 and r40 peers per §Preamble P2.1 interop rule.
- An in-memory stub TQS for demos and tests that enforces §8.1 attenuation at mint-time.

Two demos:

```bash
pnpm demo             # happy path, scope denial, replay denial
pnpm demo:widening    # §8.1 delegation widening attack — must fail closed at BOTH layers
```
