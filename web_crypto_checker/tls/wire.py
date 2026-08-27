"""Reading and writing the TLS wire format.

Every length in TLS is a fixed-width big-endian integer prefixing a run of
bytes. :class:`Reader` and :class:`Writer` express exactly that and nothing
else, so the message code reads like the struct definitions in the RFCs and a
truncated or oversized field is refused in one place rather than crashing
somewhere downstream.
"""

from __future__ import annotations

from typing import List


class TlsError(Exception):
    """A TLS message could not be built or, more often, parsed.

    Parsing runs on bytes a hostile peer chose, so every shortfall raises this
    rather than an IndexError from somewhere deep in the parser.
    """


class Reader:
    """A cursor over a byte string that refuses to read past the end."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    @property
    def bytes_left(self) -> int:
        return len(self._data) - self._pos

    def eof(self) -> bool:
        return self._pos >= len(self._data)

    def read(self, count: int) -> bytes:
        if count < 0:
            raise TlsError(f"cannot read a negative number of bytes ({count})")
        end = self._pos + count
        if end > len(self._data):
            raise TlsError(
                f"truncated: wanted {count} bytes, {self.bytes_left} left"
            )
        chunk = self._data[self._pos : end]
        self._pos = end
        return chunk

    def read_u8(self) -> int:
        return self.read(1)[0]

    def read_u16(self) -> int:
        return int.from_bytes(self.read(2), "big")

    def read_u24(self) -> int:
        return int.from_bytes(self.read(3), "big")

    def read_vector(self, length_bytes: int) -> bytes:
        """Read a ``length_bytes``-byte length prefix, then that many bytes."""
        length = int.from_bytes(self.read(length_bytes), "big")
        return self.read(length)

    def remaining(self) -> bytes:
        chunk = self._data[self._pos :]
        self._pos = len(self._data)
        return chunk


class Writer:
    """Accumulates bytes, with helpers for the length-prefixed vectors TLS uses."""

    def __init__(self) -> None:
        self._chunks: List[bytes] = []

    def raw(self, data: bytes) -> None:
        self._chunks.append(bytes(data))

    def u8(self, value: int) -> None:
        if not 0 <= value <= 0xFF:
            raise TlsError(f"value {value} does not fit in one byte")
        self._chunks.append(bytes([value]))

    def u16(self, value: int) -> None:
        if not 0 <= value <= 0xFFFF:
            raise TlsError(f"value {value} does not fit in two bytes")
        self._chunks.append(value.to_bytes(2, "big"))

    def u24(self, value: int) -> None:
        if not 0 <= value <= 0xFFFFFF:
            raise TlsError(f"value {value} does not fit in three bytes")
        self._chunks.append(value.to_bytes(3, "big"))

    def vector(self, length_bytes: int, data: bytes) -> None:
        """Write a ``length_bytes``-byte length prefix, then ``data``."""
        maximum = (1 << (8 * length_bytes)) - 1
        if len(data) > maximum:
            raise TlsError(f"vector of {len(data)} bytes overflows a {length_bytes}-byte length")
        self._chunks.append(len(data).to_bytes(length_bytes, "big"))
        self._chunks.append(bytes(data))

    def getvalue(self) -> bytes:
        return b"".join(self._chunks)
