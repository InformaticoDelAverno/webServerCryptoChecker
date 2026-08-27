"""Assembling a QUIC v1 Initial packet that carries an HTTP/3 ClientHello.

The client's first flight is a single Initial: a long-header packet whose payload
is a CRYPTO frame carrying a TLS 1.3 ClientHello -- with QUIC transport parameters
and the ``h3`` ALPN -- padded to at least 1200 bytes so the server will answer
(RFC 9000 14.1). It is protected with the Initial keys from ``keys.py``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from ..crypto.x25519 import x25519_base
from ..tls.constants import PROTOCOL_VERSIONS
from ..tls.messages import build_client_hello
from . import varint
from .keys import VERSION_1, QuicVersion, initial_keys
from .packet import protect

_TLS13 = PROTOCOL_VERSIONS[0]
_X25519 = 0x001D
_OFFERED = [0x1301, 0x1302, 0x1303]  # TLS 1.3 AES-128-GCM, AES-256-GCM, ChaCha20
_SIGNATURE_SCHEMES = [0x0804, 0x0805, 0x0806, 0x0401, 0x0403, 0x0503, 0x0807]
_PN_LENGTH = 4
_MIN_INITIAL = 1200  # RFC 9000 14.1: a client Initial is padded to at least this
_TP_INITIAL_SOURCE_CONNECTION_ID = 0x0F  # RFC 9000 18.2


@dataclass
class Initial:
    """A protected client Initial, plus what is needed to read the server's reply.

    ``private`` is the client's ephemeral X25519 key (to derive the ECDHE secret
    with the server's key share) and ``client_hello`` is the ClientHello handshake
    message (for the ``ClientHello || ServerHello`` transcript hash).
    """

    packet: bytes
    packet_number_offset: int
    private: bytes
    client_hello: bytes


def _transport_parameters(source_connection_id: bytes) -> bytes:
    """The one parameter a client must send (RFC 9000 7.3): initial_source_connection_id."""
    return (
        varint.encode(_TP_INITIAL_SOURCE_CONNECTION_ID)
        + varint.encode(len(source_connection_id))
        + source_connection_id
    )


def _crypto_frame(data: bytes) -> bytes:
    """A CRYPTO frame (RFC 9000 19.6): type 0x06, offset, length, then the data."""
    return b"\x06" + varint.encode(0) + varint.encode(len(data)) + data


def client_hello(source_connection_id: bytes, server_name: str, private: bytes) -> bytes:
    """A QUIC-shaped TLS 1.3 ClientHello (handshake message, no record layer)."""
    record = build_client_hello(
        _TLS13,
        _OFFERED,
        server_name=server_name,
        groups=[_X25519],
        signature_schemes=_SIGNATURE_SCHEMES,
        key_share=(_X25519, x25519_base(private)),
        alpn=["h3"],
        quic_transport_parameters=_transport_parameters(source_connection_id),
    )
    return record[5:]  # drop the TLS record header; the CRYPTO frame carries the message


def build_initial(
    destination_connection_id: bytes,
    source_connection_id: bytes,
    server_name: str,
    packet_number: int = 0,
    version: QuicVersion = VERSION_1,
) -> Initial:
    """Build and protect a client Initial carrying an HTTP/3 ClientHello for ``version``
    (RFC 9000 for v1, RFC 9369 for v2) -- its salt, labels and Initial type byte. Passing a
    reserved version forces a Version Negotiation reply (the server ignores the body)."""
    private = os.urandom(32)
    keys = initial_keys(destination_connection_id, version).client
    hello = client_hello(source_connection_id, server_name, private)
    payload = _crypto_frame(hello)
    prefix = (
        bytes([0xC0 | version.initial_type | (_PN_LENGTH - 1)])
        + version.number.to_bytes(4, "big")
        + bytes([len(destination_connection_id)]) + destination_connection_id
        + bytes([len(source_connection_id)]) + source_connection_id
        + varint.encode(0)  # token length
    )

    def assemble(body: bytes) -> tuple:
        length = _PN_LENGTH + len(body) + 16
        header = prefix + varint.encode(length) + packet_number.to_bytes(_PN_LENGTH, "big")
        return header, len(header) + len(body) + 16

    _header, total = assemble(payload)
    payload = payload + bytes(max(0, _MIN_INITIAL - total))  # pad with PADDING frames (zeros)
    header, _total = assemble(payload)
    packet = protect(keys, header, payload, packet_number)
    return Initial(
        packet=packet,
        packet_number_offset=len(header) - _PN_LENGTH,
        private=private,
        client_hello=hello,
    )
