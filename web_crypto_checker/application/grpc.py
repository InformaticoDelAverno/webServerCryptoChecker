"""gRPC detection over the audited TLS session.

gRPC runs over HTTP/2: a POST with ``content-type: application/grpc`` to a
``/Service/Method`` path. This negotiates h2, sends one gRPC call to a health/probe
method, and reads the response HEADERS -- a content-type of ``application/grpc`` (or
a ``grpc-status``) marks the endpoint as gRPC, even when that method is
unimplemented. Reuses the h2/TLS transport and the HPACK codec.
"""

from __future__ import annotations

from typing import Optional

from ..models import GrpcInfo, Target
from ..tls.tls12 import exchange_over_tls12
from ..tls.tls13 import exchange_over_tls13
from . import hpack

_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"  # RFC 9113 3.4
_PROBE_PATH = "/grpc.health.v1.Health/Check"
_EMPTY_MESSAGE = b"\x00\x00\x00\x00\x00"  # a gRPC length-prefixed message of length 0
_FRAME_DATA = 0x00
_FRAME_HEADERS = 0x01
_FRAME_RST_STREAM = 0x03
_FRAME_SETTINGS = 0x04
_FRAME_GOAWAY = 0x07
_FLAG_END_STREAM = 0x01
_FLAG_END_HEADERS = 0x04
_FLAG_PADDED = 0x08
_FLAG_PRIORITY = 0x20


def _frame(frame_type: int, flags: int, stream: int, payload: bytes) -> bytes:
    """An HTTP/2 frame (RFC 9113 4.1): 3-byte length, type, flags, 4-byte stream id."""
    prefix = len(payload).to_bytes(3, "big") + bytes([frame_type, flags])
    return prefix + stream.to_bytes(4, "big") + payload


def _request(host: str, path: str) -> bytes:
    """The client bytes for one gRPC call on stream 1: preface, SETTINGS, HEADERS, DATA."""
    block = hpack.encode(
        [
            (":method", "POST"),
            (":scheme", "https"),
            (":path", path),
            (":authority", host),
            ("content-type", "application/grpc"),
            ("te", "trailers"),
        ]
    )
    return (
        _PREFACE
        + _frame(_FRAME_SETTINGS, 0, 0, b"")
        + _frame(_FRAME_HEADERS, _FLAG_END_HEADERS, 1, block)
        + _frame(_FRAME_DATA, _FLAG_END_STREAM, 1, _EMPTY_MESSAGE)
    )


def _response_headers(buffer: bytes) -> Optional[bytes]:
    """The HPACK block of the first HEADERS frame in ``buffer``, or None."""
    position = 0
    while position + 9 <= len(buffer):
        length = int.from_bytes(buffer[position : position + 3], "big")
        if position + 9 + length > len(buffer):
            return None
        frame_type, flags = buffer[position + 3], buffer[position + 4]
        if frame_type == _FRAME_HEADERS:
            block = buffer[position + 9 : position + 9 + length]
            if flags & _FLAG_PRIORITY:
                block = block[5:]  # stream dependency (4) + weight (1)
            if flags & _FLAG_PADDED:
                block = block[1 : len(block) - block[0]]
            return block
        position += 9 + length
    return None


def _response_ready(buffer: bytes) -> bool:
    """Stop reading once the server answered: a HEADERS, or a stream/connection error."""
    position = 0
    while position + 9 <= len(buffer):
        length = int.from_bytes(buffer[position : position + 3], "big")
        if position + 9 + length > len(buffer):
            return False
        if buffer[position + 3] in (_FRAME_HEADERS, _FRAME_RST_STREAM, _FRAME_GOAWAY):
            return True
        position += 9 + length
    return False


def _is_grpc(headers: list) -> bool:
    return any(
        (name == "content-type" and value.startswith("application/grpc")) or name == "grpc-status"
        for name, value in headers
    )


def check_grpc(
    target: Target, address: str, timeout: float, supports_tls13: bool
) -> Optional[GrpcInfo]:
    """Probe ``target`` for gRPC support, over TLS 1.3 or 1.2, or None if not measurable."""
    if target.scheme != "https":
        return None  # gRPC rides h2 over TLS, whether the server negotiates 1.3 or 1.2
    host = target.effective_sni or target.host
    exchange = exchange_over_tls13 if supports_tls13 else exchange_over_tls12
    alpn, response, error = exchange(
        address, target.port, _request(host, _PROBE_PATH), target.effective_sni, timeout,
        ["h2"], _response_ready,
    )
    if error is not None:
        return GrpcInfo(error=error)
    if alpn != "h2":
        return GrpcInfo(supported=False)
    block = _response_headers(response)
    if block is None:
        return GrpcInfo(supported=False)
    try:
        headers = hpack.Decoder().decode(block)
    except hpack.HpackError:
        return GrpcInfo(supported=False)
    return GrpcInfo(supported=_is_grpc(headers))
