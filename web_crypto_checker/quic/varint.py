"""QUIC variable-length integers (RFC 9000 section 16).

The two most-significant bits of the first byte give the length -- 00, 01, 10, 11
mean 1, 2, 4, 8 bytes -- and the remaining 62 bits carry the value, big-endian.
Almost every field in a QUIC packet is one of these.
"""

from __future__ import annotations

from typing import Tuple

MAX_VALUE = (1 << 62) - 1


def decode(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """Decode the varint at ``offset``; return ``(value, offset_after)``."""
    prefix = data[offset] >> 6
    length = 1 << prefix
    value = data[offset] & 0x3F
    for index in range(1, length):
        value = (value << 8) | data[offset + index]
    return value, offset + length


def encode(value: int) -> bytes:
    """Encode a non-negative integer as a QUIC varint in its shortest form."""
    if value < 0 or value > MAX_VALUE:
        raise ValueError(f"value out of QUIC varint range: {value}")
    if value <= 0x3F:
        length, prefix = 1, 0
    elif value <= 0x3FFF:
        length, prefix = 2, 1
    elif value <= 0x3FFFFFFF:
        length, prefix = 4, 2
    else:
        length, prefix = 8, 3
    raw = value.to_bytes(length, "big")
    return bytes([raw[0] | (prefix << 6)]) + raw[1:]
