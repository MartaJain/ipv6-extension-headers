import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { walkIpv6ExtensionHeaders, Ipv6HeaderType } from '../src/index.js';

/**
 * Helper to build a minimal IPv6 packet with a given chain of extension
 * headers. Each header in `chain` is [type, lengthField]. For Fragment,
 * lengthField is ignored (the header is always 8 bytes) but is still written
 * into byte offset+1 for consistency with the on-wire format.
 */
function buildPacket(chain) {
  const BASE = 40;
  const hdrSizes = chain.map(([type, len]) => {
    if (type === Ipv6HeaderType.FRAGMENT) return 8;
    if (type === Ipv6HeaderType.AH) return (len + 2) * 4;
    return (len + 1) * 8;
  });
  const total = BASE + hdrSizes.reduce((a, b) => a + b, 0) + 4;
  const buf = new Uint8Array(total);

  // Fixed base header: version 6, traffic class 0, flow label 0, payload length
  // (we don't enforce it), next header = first chain type, hop limit 64.
  buf[0] = 0x60; // version 6
  let firstType = chain.length ? chain[0][0] : Ipv6HeaderType.NO_NEXT_HEADER;
  buf[6] = firstType;
  buf[7] = 64; // hop limit

  let off = BASE;
  for (let i = 0; i < chain.length; i++) {
    const [type, lenField] = chain[i];
    const nextType = i + 1 < chain.length ? chain[i + 1][0] : Ipv6HeaderType.NO_NEXT_HEADER;
    buf[off] = nextType;
    buf[off + 1] = lenField;
    const size = hdrSizes[i];
    // Fill the rest of the header with a recognisable pattern so tests can
    // verify offsets if needed.
    for (let j = 2; j < size; j++) buf[off + j] = 0xa5;
    off += size;
  }

  // A trailing 4-byte pseudo-payload so the buffer isn't exactly header-sized.
  for (let k = 0; k < 4; k++) buf[off + k] = 0x0b;
  return buf;
}

describe('walkIpv6ExtensionHeaders', () => {
  it('yields nothing when the base header points straight to NO_NEXT_HEADER', () => {
    const buf = new Uint8Array(44);
    buf[0] = 0x60;
    buf[6] = Ipv6HeaderType.NO_NEXT_HEADER;
    buf[7] = 64;
    const segments = [...walkIpv6ExtensionHeaders(buf)];
    assert.deepEqual(segments, []);
  });

  it('yields nothing when the base header points to an upper-layer protocol (TCP)', () => {
    const buf = new Uint8Array(44);
    buf[0] = 0x60;
    buf[6] = 6; // TCP
    buf[7] = 64;
    const segments = [...walkIpv6ExtensionHeaders(buf)];
    assert.deepEqual(segments, []);
  });

  it('walks a single Hop-by-Hop Options header (length 0 => 8 bytes)', () => {
    const buf = buildPacket([[Ipv6HeaderType.HOP_BY_HOP_OPTIONS, 0]]);
    const segments = [...walkIpv6ExtensionHeaders(buf)];
    assert.equal(segments.length, 1);
    assert.deepEqual(segments[0], {
      type: Ipv6HeaderType.HOP_BY_HOP_OPTIONS,
      offset: 40,
      length: 8
    });
  });

  it('walks a Hop-by-Hop Options header with length 1 => 16 bytes', () => {
    const buf = buildPacket([[Ipv6HeaderType.HOP_BY_HOP_OPTIONS, 1]]);
    const segments = [...walkIpv6ExtensionHeaders(buf)];
    assert.equal(segments.length, 1);
    assert.equal(segments[0].length, 16);
    assert.equal(segments[0].offset, 40);
  });

  it('walks a chain of three TLV headers with correct offsets', () => {
    const chain = [
      [Ipv6HeaderType.HOP_BY_HOP_OPTIONS, 0],   // 8 bytes,  offset 40
      [Ipv6HeaderType.ROUTING, 2],              // 24 bytes, offset 48
      [Ipv6HeaderType.DESTINATION_OPTIONS, 0]  // 8 bytes,  offset 72
    ];
    const buf = buildPacket(chain);
    const segments = [...walkIpv6ExtensionHeaders(buf)];
    assert.equal(segments.length, 3);
    assert.deepEqual(segments.map(s => s.type), [
      Ipv6HeaderType.HOP_BY_HOP_OPTIONS,
      Ipv6HeaderType.ROUTING,
      Ipv6HeaderType.DESTINATION_OPTIONS
    ]);
    assert.deepEqual(segments.map(s => s.offset), [40, 48, 72]);
    assert.deepEqual(segments.map(s => s.length), [8, 24, 8]);
  });

  it('walks a Fragment header which is always 8 bytes regardless of length field', () => {
    // Fragment uses a fixed 8-byte format; the second byte is not a length
    // field but we still store 0xff there to prove we ignore it.
    const buf = buildPacket([[Ipv6HeaderType.FRAGMENT, 0xff]]);
    const segments = [...walkIpv6ExtensionHeaders(buf)];
    assert.equal(segments.length, 1);
    assert.equal(segments[0].length, 8);
  });

  it('walks an AH header using the (length+2)*4 convention', () => {
    // AH length 0 => 8 bytes; length 4 => 24 bytes.
    const buf = buildPacket([[Ipv6HeaderType.AH, 4]]);
    const segments = [...walkIpv6ExtensionHeaders(buf)];
    assert.equal(segments.length, 1);
    assert.equal(segments[0].length, 24);
    assert.equal(segments[0].type, Ipv6HeaderType.AH);
  });

  it('walks AH length 0 as 8 bytes (the (0+2)*4 minimum)', () => {
    const buf = buildPacket([[Ipv6HeaderType.AH, 0]]);
    const segments = [...walkIpv6ExtensionHeaders(buf)];
    assert.equal(segments[0].length, 8);
  });

  it('stops at ESP and yields it as a terminal segment', () => {
    const chain = [
      [Ipv6HeaderType.HOP_BY_HOP_OPTIONS, 0], // 8 bytes
      [Ipv6HeaderType.ESP, 0]                // yielded, then we stop
    ];
    const buf = buildPacket(chain);
    const segments = [...walkIpv6ExtensionHeaders(buf)];
    assert.equal(segments.length, 2);
    assert.equal(segments[0].type, Ipv6HeaderType.HOP_BY_HOP_OPTIONS);
    assert.equal(segments[1].type, Ipv6HeaderType.ESP);
    assert.equal(segments[1].offset, 48);
    // ESP is yielded with a length of 8 (the minimum we can read), and the
    // walker does not continue past it.
    assert.equal(segments[1].length, 8);
  });

  it('throws RangeError when buffer is shorter than the 40-byte base header', () => {
    const buf = new Uint8Array(30);
    assert.throws(() => [...walkIpv6ExtensionHeaders(buf)], RangeError);
  });

  it('throws TypeError when given a non-Uint8Array', () => {
    assert.throws(() => [...walkIpv6ExtensionHeaders([1, 2, 3])], TypeError);
    assert.throws(() => [...walkIpv6ExtensionHeaders('not a buffer')], TypeError);
  });

  it('throws RangeError when a header declares more bytes than remain', () => {
    // Build a packet that claims a Hop-by-Hop Options header with length 5
    // (=> 48 bytes) but truncate the buffer so only 10 bytes are available
    // after the base header.
    const buf = new Uint8Array(50);
    buf[0] = 0x60;
    buf[6] = Ipv6HeaderType.HOP_BY_HOP_OPTIONS;
    buf[40] = Ipv6HeaderType.NO_NEXT_HEADER;
    buf[41] = 5; // length field => 48 bytes needed
    assert.throws(() => [...walkIpv6ExtensionHeaders(buf)], RangeError);
  });

  it('throws RangeError when the buffer is truncated mid-header (no length field)', () => {
    // Only one byte after the base header: not enough for the two-byte header
    // fields we need to read.
    const buf = new Uint8Array(41);
    buf[0] = 0x60;
    buf[6] = Ipv6HeaderType.HOP_BY_HOP_OPTIONS;
    assert.throws(() => [...walkIpv6ExtensionHeaders(buf)], RangeError);
  });

  it('correctly reports the offset where the upper-layer payload begins', () => {
    // Two 8-byte TLV headers means the payload starts at offset 56.
    const chain = [
      [Ipv6HeaderType.HOP_BY_HOP_OPTIONS, 0],
      [Ipv6HeaderType.DESTINATION_OPTIONS, 0]
    ];
    const buf = buildPacket(chain);
    const segments = [...walkIpv6ExtensionHeaders(buf)];
    const last = segments[segments.length - 1];
    const payloadStart = last.offset + last.length;
    assert.equal(payloadStart, 56);
    // The byte at payloadStart should be our trailing marker 0x0b.
    assert.equal(buf[payloadStart], 0x0b);
  });
});
