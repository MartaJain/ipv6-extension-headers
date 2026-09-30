/**
 * Core implementation for walking an IPv6 extension header chain.
 *
 * The brief: given a buffer holding an IPv6 packet starting at the fixed
 * 40-byte base header, walk through the chain of extension headers and yield
 * the next-header type and the payload offset at each step.
 *
 * The hardest part is that extension headers have wildly different length
 * conventions. We support the types that follow the standard TLV encoding
 * (Hop-by-Hop Options, Routing, Destination Options, Fragment) plus AH, which
 * has its own length convention, because these are the ones you see on the
 * public Internet. We deliberately do not implement ESP: it encrypts its
 * contents, so there is nothing to walk past without a key, and a silent skip
 * would mislead the caller into thinking the whole chain was visible.
 */

/**
 * Next-Header values as used in RFC 8200.  Only the subset relevant to this
 * walker is listed here; callers can compare against Ipv6HeaderType.NO_NEXT_HEADER
 * to detect chain termination.
 */
export const Ipv6HeaderType = Object.freeze({
  HOP_BY_HOP_OPTIONS: 0,
  ROUTING: 43,
  FRAGMENT: 44,
  ESP: 50,
  AH: 51,
  NO_NEXT_HEADER: 59,
  DESTINATION_OPTIONS: 60,
  MOBILITY: 135
});

/**
 * Headers that follow the RFC 8200 TLV encoding, where length is measured in
 * 8-octet units and includes the first 8 octets.  Used by Hop-by-Hop Options,
 * Routing, Destination Options, and Mobility.
 */
const TLV_HEADER_TYPES = new Set([
  Ipv6HeaderType.HOP_BY_HOP_OPTIONS,
  Ipv6HeaderType.ROUTING,
  Ipv6HeaderType.DESTINATION_OPTIONS,
  Ipv6HeaderType.MOBILITY
]);

/**
 * @typedef {Object} HeaderSegment
 * @property {number} type        The next-header type value at this segment.
 * @property {number} offset     Byte offset from the start of the buffer where
 *                               this extension header begins.
 * @property {number} length      Total length in bytes of this extension header.
 */

/**
 * Compute the total byte length of an extension header given its type and the
 * value of its Length field.
 *
 * For TLV headers, the Length field stores the size in 8-octet units minus one
 * (so a Length of 0 means 8 bytes). For AH, the Length field stores the size in
 * 4-octet units minus two (so a Length of 0 means 12 bytes).  For Fragment, the
 * header is always exactly 8 bytes regardless of its contents.
 *
 * @param {number} type      The next-header type.
 * @param {number} lengthField  The raw Length field value read from the header.
 * @returns {number} The header's total length in bytes.
 */
function headerLengthBytes(type, lengthField) {
  if (type === Ipv6HeaderType.FRAGMENT) {
    return 8;
  }
  if (type === Ipv6HeaderType.AH) {
    // (lengthField + 2) * 4, per RFC 4302. A length of 0 thus means 12 bytes.
    return (lengthField + 2) * 4;
  }
  // Standard TLV: (lengthField + 1) * 8.
  return (lengthField + 1) * 8;
}

/**
 * Determine whether a next-header type corresponds to an extension header this
 * walker can traverse.
 *
 * @param {number} type  The next-header type value.
 * @returns {boolean}
 */
function isWalkable(type) {
  return (
    TLV_HEADER_TYPES.has(type) ||
    type === Ipv6HeaderType.FRAGMENT ||
    type === Ipv6HeaderType.AH
  );
}

/**
 * Walk an IPv6 extension header chain and yield each segment.
 *
 * The buffer must begin with the 40-byte IPv6 base header. The walker starts
 * at the first extension header (offset 40) and follows the chain via the
 * Next-Header fields until it encounters a non-extension header (e.g. TCP,
 * UDP, ICMPv6) or NO_NEXT_HEADER (59).
 *
 * Each yielded segment describes one extension header: its type, the byte
 * offset where it begins in the buffer, and its length in bytes. The final
 * segment (the upper-layer protocol or NO_NEXT_HEADER) is NOT yielded — only
 * extension headers are. The offset after the last yielded header tells the
 * caller where the upper-layer payload begins.
 *
 * ESP (50) is intentionally unsupported: its contents are encrypted, so the
 * chain cannot be walked without a key. When ESP is encountered, the walker
 * yields it as a terminal segment and stops, so the caller knows exactly where
 * the opaque region begins.
 *
 * @param {Uint8Array} buffer  The IPv6 packet, starting at the fixed base header.
 * @returns {Generator<HeaderSegment, void, void>}
 * @throws {RangeError} If the buffer is shorter than the fixed 40-byte base header,
 *                     or if a header's length field would run past the end of
 *                     the buffer.
 */
export function* walkIpv6ExtensionHeaders(buffer) {
  if (!(buffer instanceof Uint8Array)) {
    throw new TypeError('buffer must be a Uint8Array');
  }

  const BASE_HEADER_LEN = 40;
  if (buffer.length < BASE_HEADER_LEN) {
    throw new RangeError(
      `buffer too short for IPv6 base header: got ${buffer.length}, need ${BASE_HEADER_LEN}`
    );
  }

  // The Next-Header field of the fixed base header lives at byte 6 and tells
  // us what comes after the first 40 bytes.
  let currentType = buffer[6];
  let offset = BASE_HEADER_LEN;

  while (isWalkable(currentType) || currentType === Ipv6HeaderType.ESP) {
    // Every walkable header has its own Next-Header field at byte offset+0 and
    // its Length field at byte offset+1. Fragment stores its Length field too,
    // though it is fixed and we ignore it.
    if (offset + 2 > buffer.length) {
      throw new RangeError(
        `truncated header at offset ${offset}: need 2 bytes, have ${buffer.length - offset}`
      );
    }

    const nextHeader = buffer[offset];
    const lengthField = buffer[offset + 1];
    const hdrLen = headerLengthBytes(currentType, lengthField);

    if (hdrLen < 2) {
      // This cannot happen for the types we support, but a guard prevents an
      // infinite loop if a future header type is added with a degenerate length.
      throw new RangeError(
        `computed header length ${hdrLen} is below the minimum of 2 bytes`
      );
    }

    if (offset + hdrLen > buffer.length) {
      throw new RangeError(
        `header of type ${currentType} at offset ${offset} declares ` +
        `${hdrLen} bytes but only ${buffer.length - offset} remain`
      );
    }

    yield { type: currentType, offset, length: hdrLen };

    if (currentType === Ipv6HeaderType.ESP) {
      // ESP encrypts everything after its own header. We cannot continue.
      return;
    }

    offset += hdrLen;
    currentType = nextHeader;
  }
}
