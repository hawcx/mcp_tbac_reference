// SPDX-License-Identifier: Apache-2.0

/**
 * Normative SEP version string. Per §2.1, implementations MUST use exact
 * string matching for capability negotiation — not lexicographic comparison.
 *
 * r41 is wire-compatible with r40 (P2.1): peers that have not bumped MUST
 * continue to negotiate correctly. `SEP_VERSION_R40` is retained as an
 * accepted interop alias alongside `SEP_VERSION`.
 */
export const SEP_VERSION = '2026-04-21-r41';

/** Prior revision advertised version. Accepted during negotiation for interop. */
export const SEP_VERSION_R40 = '2026-04-20-r40';

/** The r39 version string. Used by the transition-window fallback logic. */
export const R39_VERSION = '2026-04-17-r39';

/** The extension namespace key for `_meta` and capability advertisements. */
export const EXTENSION_KEY = 'io.modelcontextprotocol/tbac';
