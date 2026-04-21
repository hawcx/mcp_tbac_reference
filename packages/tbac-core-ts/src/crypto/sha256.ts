// SPDX-License-Identifier: Apache-2.0
//
// Re-export SHA-256 so downstream tools that live outside a package boundary
// (e.g., `test-vectors/v1/generate.ts`) can depend on tbac-core rather than
// reaching directly into `@noble/hashes`. All SHA-256 uses in this repo go
// through this export.
export { sha256 } from '@noble/hashes/sha2';
