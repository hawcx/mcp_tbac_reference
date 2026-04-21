// SPDX-License-Identifier: Apache-2.0
//
// Capability negotiation per SEP §2.1, §2.2. Version matching is exact
// string equality; §2.1 transitional rule says unrecognized versions mean
// "proceed without TBAC" — not connection failure. The experimental fallback
// mechanism is honored per §2.2 for SDKs that do not yet expose the
// `capabilities.extensions` mechanism.

import { EXTENSION_KEY, R39_VERSION, SEP_VERSION } from 'tbac-core';

export interface PeerCapability {
  readonly version: string;
  readonly tokenFormats: readonly string[];
  readonly [k: string]: unknown;
}

export interface CapabilityAdvertisement {
  readonly capabilities: {
    readonly extensions?: Record<string, PeerCapability>;
    readonly experimental?: Record<string, PeerCapability>;
  };
}

export interface ServerCapabilityOpts {
  readonly maxDelegationDepth?: number;
  readonly supportsStepUp?: boolean;
  readonly supportsPolicyTemplateDiscovery?: boolean;
  readonly deploymentProfile?: 'E' | 'S';
  readonly maxAssemblersPerAgent?: number;
}

export function buildServerCapability(
  opts: ServerCapabilityOpts = {},
): CapabilityAdvertisement {
  return {
    capabilities: {
      extensions: {
        [EXTENSION_KEY]: {
          version: SEP_VERSION,
          tokenFormats: ['opaque'],
          maxDelegationDepth: opts.maxDelegationDepth ?? 3,
          supportsStepUp: opts.supportsStepUp ?? true,
          supportsPolicyTemplateDiscovery: opts.supportsPolicyTemplateDiscovery ?? false,
          supportsConsumerProfile: false,
          supportsEphemeralProfile: false,
          supportsIntentVerification: false,
          intentVerificationMode: 'log_only',
          supportsTransactions: false,
          deploymentProfile: opts.deploymentProfile ?? 'E',
          maxAssemblersPerAgent: opts.maxAssemblersPerAgent ?? 8,
        },
      },
    },
  };
}

export function buildClientCapability(
  opts: { deploymentProfile?: 'E' | 'S'; hasTqs?: boolean; hasAssembler?: boolean } = {},
): CapabilityAdvertisement {
  return {
    capabilities: {
      extensions: {
        [EXTENSION_KEY]: {
          version: SEP_VERSION,
          tokenFormats: ['opaque'],
          hasTqs: opts.hasTqs ?? true,
          hasAssembler: opts.hasAssembler ?? (opts.deploymentProfile ?? 'E') === 'E',
          deploymentProfile: opts.deploymentProfile ?? 'E',
        },
      },
    },
  };
}

export interface NegotiationResult {
  readonly enabled: boolean;
  readonly peerVersion?: string;
  readonly acceptR39Tokens: boolean;
  /** Whether the `experimental` fallback mechanism was needed. */
  readonly usedExperimentalFallback: boolean;
  readonly why: string;
}

/**
 * Inspect peer capabilities and decide whether TBAC is enabled for this
 * connection. Per §2.1: unrecognized version → proceed without TBAC.
 */
export function negotiatePeer(peer: CapabilityAdvertisement): NegotiationResult {
  const ext = peer.capabilities?.extensions?.[EXTENSION_KEY];
  const exp = peer.capabilities?.experimental?.[EXTENSION_KEY];
  const raw = ext ?? exp;
  const usedExperimentalFallback = ext === undefined && exp !== undefined;
  if (raw === undefined) {
    return {
      enabled: false,
      acceptR39Tokens: false,
      usedExperimentalFallback: false,
      why: 'peer did not advertise io.modelcontextprotocol/tbac',
    };
  }
  if (raw.version === SEP_VERSION) {
    return {
      enabled: true,
      peerVersion: raw.version,
      acceptR39Tokens: false,
      usedExperimentalFallback,
      why: 'exact version match',
    };
  }
  if (raw.version === R39_VERSION) {
    return {
      enabled: true,
      peerVersion: raw.version,
      acceptR39Tokens: true,
      usedExperimentalFallback,
      why: 'r39 peer — transition-window fallback enabled',
    };
  }
  return {
    enabled: false,
    peerVersion: raw.version,
    acceptR39Tokens: false,
    usedExperimentalFallback,
    why: `unrecognized TBAC version "${raw.version}" — proceed without TBAC (§2.1)`,
  };
}
