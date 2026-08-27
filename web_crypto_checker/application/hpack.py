"""HPACK header compression for HTTP/2 (RFC 7541) -- enough to read what a server sends.

HTTP/2 (and so gRPC) carries its headers HPACK-compressed: a static table of common
header fields, a per-connection dynamic table, integers and strings on the wire, and
an optional Huffman coding of those strings. This decodes a server's HEADERS block --
indexed and literal fields, Huffman values, dynamic-table updates -- which is what
tells a plain h2 endpoint from a gRPC one. Encoding is the trivial subset a probe
needs: literal fields with raw (un-Huffman'd) strings, which every decoder accepts.

The Huffman table (Appendix B) is embedded reference data, generated and cross-checked
against the RFC 7541 Appendix C vectors and a real encoder; see tests/test_hpack.py.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

Header = Tuple[str, str]


class HpackError(Exception):
    """A header block that does not decode."""


# --------------------------------------------------------------------------- #
# Huffman coding (RFC 7541 Appendix B) -- code and bit-length per symbol 0..255
# --------------------------------------------------------------------------- #

_HUFFMAN_CODES: List[int] = [8184, 8388568, 268435426, 268435427, 268435428, 268435429, 268435430, 268435431, 268435432, 16777194, 1073741820, 268435433, 268435434, 1073741821, 268435435, 268435436, 268435437, 268435438, 268435439, 268435440, 268435441, 268435442, 1073741822, 268435443, 268435444, 268435445, 268435446, 268435447, 268435448, 268435449, 268435450, 268435451, 20, 1016, 1017, 4090, 8185, 21, 248, 2042, 1018, 1019, 249, 2043, 250, 22, 23, 24, 0, 1, 2, 25, 26, 27, 28, 29, 30, 31, 92, 251, 32764, 32, 4091, 1020, 8186, 33, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 252, 115, 253, 8187, 524272, 8188, 16380, 34, 32765, 3, 35, 4, 36, 5, 37, 38, 39, 6, 116, 117, 40, 41, 42, 7, 43, 118, 44, 8, 9, 45, 119, 120, 121, 122, 123, 32766, 2044, 16381, 8189, 268435452, 1048550, 4194258, 1048551, 1048552, 4194259, 4194260, 4194261, 8388569, 4194262, 8388570, 8388571, 8388572, 8388573, 8388574, 16777195, 8388575, 16777196, 16777197, 4194263, 8388576, 16777198, 8388577, 8388578, 8388579, 8388580, 2097116, 4194264, 8388581, 4194265, 8388582, 8388583, 16777199, 4194266, 2097117, 1048553, 4194267, 4194268, 8388584, 8388585, 2097118, 8388586, 4194269, 4194270, 16777200, 2097119, 4194271, 8388587, 8388588, 2097120, 2097121, 4194272, 2097122, 8388589, 4194273, 8388590, 8388591, 1048554, 4194274, 4194275, 4194276, 8388592, 4194277, 4194278, 8388593, 67108832, 67108833, 1048555, 524273, 4194279, 8388594, 4194280, 33554412, 67108834, 67108835, 67108836, 134217694, 134217695, 67108837, 16777201, 33554413, 524274, 2097123, 67108838, 134217696, 134217697, 67108839, 134217698, 16777202, 2097124, 2097125, 67108840, 67108841, 268435453, 134217699, 134217700, 134217701, 1048556, 16777203, 1048557, 2097126, 4194281, 2097127, 2097128, 8388595, 4194282, 4194283, 33554414, 33554415, 16777204, 16777205, 67108842, 8388596, 67108843, 134217702, 67108844, 67108845, 134217703, 134217704, 134217705, 134217706, 134217707, 268435454, 134217708, 134217709, 134217710, 134217711, 134217712, 67108846]  # noqa: E501
_HUFFMAN_BITS: List[int] = [13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26]  # noqa: E501
_HUFFMAN_DECODE: Dict[Tuple[int, int], int] = {
    (bits, code): symbol
    for symbol, (code, bits) in enumerate(zip(_HUFFMAN_CODES, _HUFFMAN_BITS))
}


def _huffman_decode(data: bytes) -> str:
    """Decode a Huffman-coded string; the trailing bits must be EOS padding."""
    result = bytearray()
    length = 0
    code = 0
    for byte in data:
        for shift in range(7, -1, -1):
            code = (code << 1) | ((byte >> shift) & 1)
            length += 1
            symbol = _HUFFMAN_DECODE.get((length, code))
            if symbol is not None:
                result.append(symbol)
                length = 0
                code = 0
            elif length > 30:
                raise HpackError("invalid Huffman code")
    if length > 7 or (length and code != (1 << length) - 1):
        raise HpackError("invalid Huffman padding")
    return result.decode("latin1")


# --------------------------------------------------------------------------- #
# Integers and strings (RFC 7541 sections 5.1 and 5.2)
# --------------------------------------------------------------------------- #


def _decode_integer(data: bytes, offset: int, prefix_bits: int) -> Tuple[int, int]:
    mask = (1 << prefix_bits) - 1
    value = data[offset] & mask
    offset += 1
    if value < mask:
        return value, offset
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value += (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, offset


def _encode_integer(value: int, prefix_bits: int, prefix_byte: int) -> bytes:
    mask = (1 << prefix_bits) - 1
    if value < mask:
        return bytes([prefix_byte | value])
    out = bytearray([prefix_byte | mask])
    value -= mask
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _decode_string(data: bytes, offset: int) -> Tuple[str, int]:
    huffman = bool(data[offset] & 0x80)
    length, offset = _decode_integer(data, offset, 7)
    raw = data[offset : offset + length]
    if len(raw) < length:
        raise HpackError("truncated string")
    offset += length
    return (_huffman_decode(raw) if huffman else raw.decode("latin1")), offset


def _encode_string(text: str) -> bytes:
    raw = text.encode("latin1")
    return _encode_integer(len(raw), 7, 0x00) + raw  # Huffman flag 0: raw octets


# --------------------------------------------------------------------------- #
# The static table (RFC 7541 Appendix A), 1-indexed; [0] is unused
# --------------------------------------------------------------------------- #

_STATIC: List[Header] = [
    ("", ""),
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
]
_STATIC_COUNT = len(_STATIC) - 1  # 61 real entries
_ENTRY_OVERHEAD = 32  # RFC 7541 4.1: each dynamic entry's size includes 32 bytes


def encode(headers: List[Header]) -> bytes:
    """Encode ``headers`` as literal fields with raw strings -- all a probe sends."""
    out = bytearray()
    for name, value in headers:
        out.append(0x00)  # literal header field without indexing, new name
        out += _encode_string(name)
        out += _encode_string(value)
    return bytes(out)


class Decoder:
    """Decode HPACK header blocks, keeping the dynamic table across a connection."""

    def __init__(self, max_size: int = 4096) -> None:
        self._dynamic: List[Header] = []
        self._max_size = max_size
        self._size = 0

    def _entry(self, index: int) -> Header:
        if index <= 0:
            raise HpackError(f"invalid header index {index}")
        if index <= _STATIC_COUNT:
            return _STATIC[index]
        position = index - _STATIC_COUNT - 1
        if position >= len(self._dynamic):
            raise HpackError(f"header index {index} out of range")
        return self._dynamic[position]

    def _insert(self, name: str, value: str) -> None:
        self._dynamic.insert(0, (name, value))
        self._size += len(name) + len(value) + _ENTRY_OVERHEAD
        self._evict()

    def _resize(self, max_size: int) -> None:
        self._max_size = max_size
        self._evict()

    def _evict(self) -> None:
        while self._size > self._max_size:
            name, value = self._dynamic.pop()
            self._size -= len(name) + len(value) + _ENTRY_OVERHEAD

    def _literal(self, data: bytes, offset: int, prefix_bits: int) -> Tuple[str, str, int]:
        index, offset = _decode_integer(data, offset, prefix_bits)
        if index == 0:
            name, offset = _decode_string(data, offset)
        else:
            name = self._entry(index)[0]
        value, offset = _decode_string(data, offset)
        return name, value, offset

    def decode(self, block: bytes) -> List[Header]:
        headers: List[Header] = []
        offset = 0
        try:
            while offset < len(block):
                lead = block[offset]
                if lead & 0x80:  # 6.1 indexed header field
                    index, offset = _decode_integer(block, offset, 7)
                    headers.append(self._entry(index))
                elif lead & 0x40:  # 6.2.1 literal with incremental indexing
                    name, value, offset = self._literal(block, offset, 6)
                    self._insert(name, value)
                    headers.append((name, value))
                elif lead & 0x20:  # 6.3 dynamic table size update
                    new_size, offset = _decode_integer(block, offset, 5)
                    self._resize(new_size)
                else:  # 6.2.2 / 6.2.3 literal without / never indexed
                    name, value, offset = self._literal(block, offset, 4)
                    headers.append((name, value))
        except IndexError as exc:
            raise HpackError("truncated header block") from exc
        return headers
