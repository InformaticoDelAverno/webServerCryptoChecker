"""Reading what a QUIC server negotiates: the ServerHello and transport parameters.

The server's Initial (protected with keys derived from the client's original DCID)
carries the TLS 1.3 ServerHello -- the negotiated cipher and key-share group. From
that key share and the client's ephemeral key we derive the ECDHE secret and the
QUIC Handshake keys, decrypt the server's Handshake packets, and read the
EncryptedExtensions -- which carry the ``quic_transport_parameters``: the
connection limits the server offers. So this reads what HTTP/3 actually negotiates,
end to end, not just that the server answered.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable, Dict, Iterator, Optional, Tuple

from ..crypto.x25519 import x25519
from ..models import QuicTransportParameters
from ..tls.constants import EXT_KEY_SHARE, HANDSHAKE_TYPE_SERVER_HELLO
from ..tls.messages import ServerHello, parse_server_hello
from ..tls.wire import Reader, TlsError
from . import varint
from .keys import VERSION_1, PacketKeys, QuicVersion, server_handshake_keys
from .packet import AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305, Cipher, unprotect

_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 8
_EXT_QUIC_TRANSPORT_PARAMETERS = 0x39
_Hash = Callable[..., "hashlib._Hash"]


@dataclass(frozen=True)
class _Suite:
    """A negotiated TLS 1.3 suite: its Handshake-packet AEAD and its key-schedule hash."""

    aead: Cipher
    hashmod: _Hash
    hash_length: int


# The suite each cipher a QUIC server may negotiate (the Initial is always AES-128-GCM).
# AES-256-GCM runs the SHA-384 schedule; the other two run SHA-256.
_HANDSHAKE_CIPHERS: Dict[int, _Suite] = {
    0x1301: _Suite(AES_128_GCM, hashlib.sha256, 32),
    0x1302: _Suite(AES_256_GCM, hashlib.sha384, 48),
    0x1303: _Suite(CHACHA20_POLY1305, hashlib.sha256, 32),
}


def _parse_initial_header(datagram: bytes) -> Optional[Tuple[int, int]]:
    """``(packet_number_offset, length)`` of a long-header Initial, or None."""
    try:
        offset = 5  # first byte + 4-byte version
        offset += 1 + datagram[offset]  # DCID (length prefix + id)
        offset += 1 + datagram[offset]  # SCID
        token_length, offset = varint.decode(datagram, offset)
        offset += token_length
        length, offset = varint.decode(datagram, offset)
        return offset, length
    except IndexError:
        return None


def _iter_long_packets(
    datagram: bytes, version: QuicVersion
) -> Iterator[Tuple[int, int, int, int]]:
    """Yield ``(first_byte, start, packet_number_offset, length)`` for each long-header
    packet coalesced in a datagram (RFC 9000 12.2). Offsets are absolute."""
    position = 0
    while position < len(datagram) and datagram[position] & 0x80:
        try:
            first = datagram[position]
            offset = position + 5  # first byte + version
            offset += 1 + datagram[offset]  # DCID
            offset += 1 + datagram[offset]  # SCID
            if first & 0x30 == version.initial_type:  # an Initial carries a token length
                token_length, offset = varint.decode(datagram, offset)
                offset += token_length
            length, offset = varint.decode(datagram, offset)
        except IndexError:
            return
        yield first, position, offset, length
        position = offset + length


def _collect_crypto(payload: bytes, chunks: Dict[int, bytes]) -> None:
    """Add the CRYPTO frames of a decrypted payload to ``chunks``, keyed by offset.

    A truncated or malformed frame stream just stops collection, keeping whatever was
    read: the payload comes from a possibly-hostile server (Initial keys are public, so
    it need not be genuine), and running off the end must not crash the scan.
    """
    position = 0
    try:
        while position < len(payload):
            frame_type, position = varint.decode(payload, position)
            if frame_type in (0x00, 0x01):  # PADDING, PING
                continue
            if frame_type in (0x02, 0x03):  # ACK (RFC 9000 19.3)
                _largest, position = varint.decode(payload, position)
                _delay, position = varint.decode(payload, position)
                range_count, position = varint.decode(payload, position)
                _first_range, position = varint.decode(payload, position)
                for _ in range(range_count):  # gap + length per additional range
                    _gap, position = varint.decode(payload, position)
                    _length, position = varint.decode(payload, position)
                if frame_type == 0x03:  # ECT(0), ECT(1), CE counts
                    for _ in range(3):
                        _count, position = varint.decode(payload, position)
                continue
            if frame_type == 0x06:  # CRYPTO
                crypto_offset, position = varint.decode(payload, position)
                crypto_length, position = varint.decode(payload, position)
                chunks[crypto_offset] = payload[position : position + crypto_length]
                position += crypto_length
                continue
            break  # a frame this reader does not model -- stop, keep what we have
    except IndexError:
        return  # a frame ran past the end of the payload -- stop, keep what we have


def _reassemble_crypto(payload: bytes) -> bytes:
    """Concatenate the CRYPTO frames of one decrypted payload, in offset order."""
    chunks: Dict[int, bytes] = {}
    _collect_crypto(payload, chunks)
    return b"".join(chunks[offset] for offset in sorted(chunks))


def _server_initial_crypto(datagram: bytes, server_keys: PacketKeys) -> Optional[bytes]:
    """The reassembled CRYPTO of the server's Initial (its ServerHello message)."""
    header = _parse_initial_header(datagram)
    if header is None:
        return None
    packet_number_offset, length = header
    packet = datagram[: packet_number_offset + length]
    opened = unprotect(server_keys, packet, packet_number_offset)
    if opened is None:
        return None
    return _reassemble_crypto(opened[1])


def read_server_hello(datagram: bytes, server_keys: PacketKeys) -> Optional[ServerHello]:
    """The ServerHello a QUIC server sent in its Initial, or None if unreadable."""
    crypto = _server_initial_crypto(datagram, server_keys)
    if crypto is None or len(crypto) < 4 or crypto[0] != HANDSHAKE_TYPE_SERVER_HELLO:
        return None
    body_length = int.from_bytes(crypto[1:4], "big")
    try:
        return parse_server_hello(crypto[4 : 4 + body_length])
    except TlsError:
        return None


def _server_key_share(extension: Optional[bytes]) -> Optional[bytes]:
    """The server's key-share public value from the ServerHello key_share extension."""
    if extension is None:
        return None
    reader = Reader(extension)
    try:
        reader.read_u16()  # the selected group
        return reader.read_vector(2)
    except TlsError:
        return None


def _encrypted_extensions_body(handshake: bytes) -> Optional[bytes]:
    """The body of the EncryptedExtensions message in reassembled handshake bytes."""
    position = 0
    while position + 4 <= len(handshake):
        length = int.from_bytes(handshake[position + 1 : position + 4], "big")
        if position + 4 + length > len(handshake):
            return None
        if handshake[position] == _HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS:
            return handshake[position + 4 : position + 4 + length]
        position += 4 + length
    return None


def _build_parameters(data: bytes) -> QuicTransportParameters:
    """Parse a quic_transport_parameters extension body into the named limits."""
    raw: Dict[int, bytes] = {}
    position = 0
    while position < len(data):
        parameter_id, position = varint.decode(data, position)
        parameter_length, position = varint.decode(data, position)
        raw[parameter_id] = data[position : position + parameter_length]
        position += parameter_length

    def number(parameter_id: int) -> Optional[int]:
        value = raw.get(parameter_id)
        return varint.decode(value, 0)[0] if value else None

    return QuicTransportParameters(
        max_idle_timeout=number(0x01),
        max_udp_payload_size=number(0x03),
        initial_max_data=number(0x04),
        max_streams_bidi=number(0x08),
        max_streams_uni=number(0x09),
        max_ack_delay=number(0x0B),
        active_connection_id_limit=number(0x0E),
        disable_active_migration=0x0C in raw,
    )


def _quic_transport_parameters(encrypted_extensions: bytes) -> Optional[QuicTransportParameters]:
    extensions = Reader(Reader(encrypted_extensions).read_vector(2))
    while not extensions.eof():
        extension_type = extensions.read_u16()
        extension_body = extensions.read_vector(2)
        if extension_type == _EXT_QUIC_TRANSPORT_PARAMETERS:
            return _build_parameters(extension_body)
    return None


def read_transport_parameters(
    datagrams: list, keys: PacketKeys, cipher: Cipher, version: QuicVersion = VERSION_1
) -> Optional[QuicTransportParameters]:
    """Decrypt the server's Handshake packets and read its transport parameters."""
    chunks: Dict[int, bytes] = {}
    try:
        for datagram in datagrams:
            for first, start, packet_number_offset, length in _iter_long_packets(datagram, version):
                if first & 0x30 != version.handshake_type:
                    continue
                packet = datagram[start : packet_number_offset + length]
                opened = unprotect(keys, packet, packet_number_offset - start, cipher)
                if opened is not None:
                    _collect_crypto(opened[1], chunks)
        handshake = b"".join(chunks[offset] for offset in sorted(chunks))
        body = _encrypted_extensions_body(handshake)
        if body is None:
            return None
        return _quic_transport_parameters(body)
    except (IndexError, TlsError):
        return None


def read_negotiation(
    datagrams: list, private: bytes, client_hello: bytes, server_initial_keys: PacketKeys,
    version: QuicVersion = VERSION_1,
) -> Tuple[Optional[ServerHello], Optional[QuicTransportParameters]]:
    """The ServerHello and transport parameters from a QUIC server's flight (v1 or v2)."""
    if not datagrams:
        return None, None
    crypto = _server_initial_crypto(datagrams[0], server_initial_keys)
    if crypto is None or len(crypto) < 4 or crypto[0] != HANDSHAKE_TYPE_SERVER_HELLO:
        return None, None
    body_length = int.from_bytes(crypto[1:4], "big")
    try:
        server_hello = parse_server_hello(crypto[4 : 4 + body_length])
    except TlsError:
        return None, None
    suite = _HANDSHAKE_CIPHERS.get(server_hello.cipher_suite)
    server_public = _server_key_share(server_hello.extensions.get(EXT_KEY_SHARE))
    if suite is None or server_public is None:
        return server_hello, None
    shared = x25519(private, server_public)
    transcript = suite.hashmod(client_hello + crypto).digest()
    keys = server_handshake_keys(
        shared, transcript, suite.aead.key_length, suite.hashmod, suite.hash_length, version
    )
    return server_hello, read_transport_parameters(datagrams, keys, suite.aead, version)
