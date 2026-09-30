/**
 * IPv6 Extension Header walker.
 *
 * This module re-exports the public API from core.js for consumers who want a
 * single entry point: `walkIpv6ExtensionHeaders` and the `Ipv6HeaderType`
 * constants.  Keeping the index thin avoids accidental circular imports and
 * gives a stable surface for the package.
 */

export {
  walkIpv6ExtensionHeaders,
  Ipv6HeaderType
} from './core.js';
