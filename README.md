# ipv6-extension-headers

Walks an IPv6 packet through its extension header chain, yielding each next-header type and the byte offset where that header begins.

## Usage

```js
import { walkIpv6ExtensionHeaders, Ipv6HeaderType } from 'ipv6-extension-headers';

// `packet` is a Uint8Array starting at the 40-byte IPv6 base header.
const packet = new Uint8Array(64);
packet[0] = 0x60; // version 6
packet[6] = Ipv6HeaderType.HOP_BY_HOP_OPTIONS;
packet[40] = Ipv6HeaderType.NO_NEXT_HEADER; // next header after this one
packet[41] = 0; // length field: 0 => 8 bytes

for (const segment of walkIpv6ExtensionHeaders(packet)) {
  console.log(segment.type, segment.offset, segment.length);
}
```

`walkIpv6ExtensionHeaders` is a generator. Each yielded segment has three fields: `type` (the next-header number), `offset` (byte position in the buffer where this extension header starts), and `length` (total bytes of this header). Only extension headers are yielded — the upper-layer protocol that terminates the chain is not. Add the last segment's `offset + length` to find where the transport payload begins.

## Why this exists

Parsing IPv6 extension headers is fiddly because different header types use different length conventions: TLV headers count in 8-octet units, AH counts in 4-octet units with a different offset, and Fragment is a fixed 8 bytes. This library handles that dispatch for you so you do not have to keep a table of per-type length formulas in your application code.

The trade-off is scope. We support the headers you will actually see on the public Internet: Hop-by-Hop Options, Routing, Destination Options, Fragment, and AH. ESP (type 50) is yielded as a terminal segment and the walk stops — its contents are encrypted and cannot be traversed without a key, so silently skipping past it would mislead callers into thinking the whole chain was visible.

## The awkward edge

Every walkable header is expected to have a Length field in its second byte. We read it, compute the header size, and bounds-check it against the buffer. If a header declares a length that runs past the end of the buffer, the generator throws a `RangeError` rather than yielding a truncated segment. This means a malformed or deliberately crafted packet will halt the walk; if you prefer to inspect whatever survived, catch the error and use the segments yielded before it.

Pass a `Uint8Array` that begins at the fixed 40-byte base header. Anything shorter than 40 bytes throws immediately. The `Ipv6HeaderType` object is exported so you can compare against named constants (e.g. `Ipv6HeaderType.HOP_BY_HOP_OPTIONS`, `Ipv6HeaderType.NO_NEXT_HEADER`) rather than magic numbers.
