# tbac-core

Core library for MCP TBAC (SEP r41; wire-compatible with r40). Wire format, crypto primitives, 17-step verification cascade, scope canonicalization (including §A.3.1 `allowed_parameters` inner TLV and §A.4 clause-4 unknown-tag partition), §8.1 glob-subset attenuation, 11 normative denial codes, pluggable in-memory stores.

```
import {
  SEP_VERSION,
  parseToken,
  verifyToken,
  checkAttenuation,
  isSubset,
  MemorySessionStore,
  MemoryReplayStore,
  MemoryPolicyTemplateStore,
  MemoryConsumedTokenLog,
  DENIAL_CODES,
} from 'tbac-core';
```

See the repo root [`README.md`](../../README.md) for package layout and [`docs/verification-cascade.md`](../../docs/verification-cascade.md) for step-by-step cascade documentation.
