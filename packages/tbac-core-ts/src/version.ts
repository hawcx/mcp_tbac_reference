// SPDX-License-Identifier: Apache-2.0

/**
 * Normative SEP version string. Per §2.1, implementations MUST use exact
 * string matching for capability negotiation — not lexicographic comparison.
 *
 * Note: §8.1 of the SEP has a drafting typo that refers to "2026-04-17-r40";
 * the Preamble and §2.1/§2.2 all use "2026-04-20-r40", which we treat as
 * normative. See R40_MIGRATION.md for the observation to flag in r41.
 */
export const SEP_VERSION = '2026-04-20-r40';

/** The r39 version string. Used by the transition-window fallback logic. */
export const R39_VERSION = '2026-04-17-r39';

/** The extension namespace key for `_meta` and capability advertisements. */
export const EXTENSION_KEY = 'io.modelcontextprotocol/tbac';
