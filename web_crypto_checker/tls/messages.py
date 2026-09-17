"""Building a ClientHello and parsing the ServerHello or alert it draws out.

Only the client side of the handshake is built, and only up to the first thing
the server says back. That is all enumeration needs: the server answers a
ClientHello with exactly one chosen version and cipher suite, or with an alert,
and either answer is the datum. Nothing here completes a handshake or touches a
cipher, so no key material is involved and none of it has to be constant time.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .constants import (
    CONTENT_TYPE_HANDSHAKE,
    EXT_ALPN,
    EXT_EC_POINT_FORMATS,
    EXT_EXTENDED_MASTER_SECRET,
    EXT_HEARTBEAT,
    EXT_KEY_SHARE,
    EXT_QUIC_TRANSPORT_PARAMETERS,
    EXT_RENEGOTIATION_INFO,
    EXT_SERVER_NAME,
    EXT_SESSION_TICKET,
    EXT_SIGNATURE_ALGORITHMS,
    EXT_STATUS_REQUEST,
    EXT_SUPPORTED_GROUPS,
    EXT_SUPPORTED_VERSIONS,
    HANDSHAKE_TYPE_CLIENT_HELLO,
    HELLO_RETRY_REQUEST_RANDOM,
    ProtocolVersionSpec,
)
from .wire import Reader, TlsError, Writer


@dataclass
class ServerHello:
    """The parsed ServerHello (or HelloRetryRequest)."""

    legacy_version: int
    negotiated_version: int
    """The real version: the supported_versions extension when present, which is
    how TLS 1.3 is signalled, otherwise ``legacy_version``."""
    cipher_suite: int
    is_hello_retry_request: bool
    random: bytes
    extensions: Dict[int, bytes] = field(default_factory=dict)
    selected_group: Optional[int] = None
    legacy_compression: int = 0
    """The negotiated legacy_compression_method byte. Non-zero means the server
    agreed to compress, which is the CRIME side channel."""
    session_id: bytes = b""
    """The legacy_session_id_echo. A non-empty one in a 1.2 ServerHello offers
    session-id resumption."""
    """The group from the key_share extension: the server's choice in a normal
    ServerHello, or the group it is asking for in a HelloRetryRequest."""


def _encode_sni(name: str) -> bytes:
    """Encode a server name for the SNI extension.

    Almost every name is ASCII already. A non-ASCII name should arrive as an
    A-label (punycode); if it has not, UTF-8 at least puts something on the wire
    rather than raising in the middle of building a probe.
    """
    try:
        return name.encode("ascii")
    except UnicodeEncodeError:
        return name.encode("utf-8")


def _write_extensions(
    writer: Writer,
    version: ProtocolVersionSpec,
    server_name: str,
    groups: List[int],
    signature_schemes: List[int],
    key_share: Optional[Tuple[int, bytes]],
    key_shares: Optional[List[Tuple[int, bytes]]],
    alpn: Optional[List[str]],
    empty_key_share: bool,
    heartbeat: bool,
    extended_master_secret: bool,
    session_ticket: bool,
    status_request: bool,
    quic_transport_parameters: Optional[bytes],
    renegotiation_info: Optional[bytes],
    extra_extensions: Optional[List[Tuple[int, bytes]]],
) -> None:
    entries: List[Tuple[int, bytes]] = []

    if server_name:
        host = Writer()
        host.u8(0)  # NameType host_name
        host.vector(2, _encode_sni(server_name))
        name_list = Writer()
        name_list.vector(2, host.getvalue())
        entries.append((EXT_SERVER_NAME, name_list.getvalue()))

    if groups:
        codes = Writer()
        for code in groups:
            codes.u16(code)
        group_list = Writer()
        group_list.vector(2, codes.getvalue())
        entries.append((EXT_SUPPORTED_GROUPS, group_list.getvalue()))
        # ec_point_formats: uncompressed only. Some older servers refuse ECDHE
        # without it.
        entries.append((EXT_EC_POINT_FORMATS, b"\x01\x00"))

    if signature_schemes:
        schemes = Writer()
        for code in signature_schemes:
            schemes.u16(code)
        scheme_list = Writer()
        scheme_list.vector(2, schemes.getvalue())
        entries.append((EXT_SIGNATURE_ALGORITHMS, scheme_list.getvalue()))

    if version.is_tls13:
        supported = Writer()
        supported.vector(1, (0x0304).to_bytes(2, "big"))
        entries.append((EXT_SUPPORTED_VERSIONS, supported.getvalue()))
        offered = key_shares if key_shares is not None else (
            [key_share] if key_share is not None else None)
        if offered is not None:
            entry = Writer()
            for group_code, public in offered:  # a CH may carry a key_share per offered group
                entry.u16(group_code)
                entry.vector(2, public)
            shares = Writer()
            shares.vector(2, entry.getvalue())
            entries.append((EXT_KEY_SHARE, shares.getvalue()))
        elif empty_key_share:
            # An empty client_shares asks the server to name its preferred group in
            # a HelloRetryRequest, at the cost of a round trip (RFC 8446 4.2.8).
            entries.append((EXT_KEY_SHARE, b"\x00\x00"))

    if alpn:
        protocols = Writer()
        for name in alpn:
            protocols.vector(1, name.encode("ascii"))
        alpn_list = Writer()
        alpn_list.vector(2, protocols.getvalue())
        entries.append((EXT_ALPN, alpn_list.getvalue()))

    if heartbeat:
        # HeartbeatMode.peer_allowed_to_send (RFC 6520): needed to negotiate the
        # heartbeat the Heartbleed probe then abuses.
        entries.append((EXT_HEARTBEAT, b"\x01"))

    if extended_master_secret:
        # RFC 7627: an empty extension. Only offered by the feature probe, which
        # never completes the handshake -- a completing hello must not offer it
        # without also doing the extended-master-secret key derivation.
        entries.append((EXT_EXTENDED_MASTER_SECRET, b""))

    if session_ticket:
        # RFC 5077: an empty session_ticket asks the server to echo it (and later
        # send a NewSessionTicket) if it supports ticket resumption.
        entries.append((EXT_SESSION_TICKET, b""))

    if status_request:
        # RFC 6066 CertificateStatusRequest: status_type=ocsp(1), empty responder
        # id list and empty request extensions. Asks the server to staple OCSP.
        entries.append((EXT_STATUS_REQUEST, b"\x01\x00\x00\x00\x00"))

    if quic_transport_parameters is not None:
        # RFC 9001: QUIC carries its transport parameters in this ClientHello extension.
        entries.append((EXT_QUIC_TRANSPORT_PARAMETERS, quic_transport_parameters))

    # Signal support for secure renegotiation. A few servers refuse a hello
    # without it, and offering it costs nothing. An initial hello carries an empty
    # renegotiation_info; a renegotiation hello (RFC 5746) carries the previous
    # handshake's client verify_data, so the caller can pass it in.
    reneg = b"\x00" if renegotiation_info is None else (
        bytes([len(renegotiation_info)]) + renegotiation_info
    )
    entries.append((EXT_RENEGOTIATION_INFO, reneg))

    # Arbitrary extra extensions, e.g. a GREASE extension (RFC 8701) a conformant
    # server must ignore.
    if extra_extensions:
        entries.extend(extra_extensions)

    for extension_type, extension_data in entries:
        writer.u16(extension_type)
        writer.vector(2, extension_data)


def build_client_hello(
    version: ProtocolVersionSpec,
    cipher_suites: List[int],
    server_name: str = "",
    groups: Optional[List[int]] = None,
    signature_schemes: Optional[List[int]] = None,
    key_share: Optional[Tuple[int, bytes]] = None,
    key_shares: Optional[List[Tuple[int, bytes]]] = None,
    alpn: Optional[List[str]] = None,
    empty_key_share: bool = False,
    heartbeat: bool = False,
    compression_methods: bytes = b"\x00",
    offer_extended_master_secret: bool = False,
    offer_session_ticket: bool = False,
    offer_status_request: bool = False,
    quic_transport_parameters: Optional[bytes] = None,
    renegotiation_info: Optional[bytes] = None,
    extra_extensions: Optional[List[Tuple[int, bytes]]] = None,
) -> bytes:
    """Build one complete TLS record carrying a ClientHello for ``version``."""
    body = Writer()
    body.u16(0x0303 if version.is_tls13 else version.code)
    body.raw(os.urandom(32))
    # A 1.3 ClientHello carries a fake session id for middlebox compatibility;
    # older versions do not, and QUIC (RFC 9001 8.4) requires it empty.
    legacy_session = version.is_tls13 and quic_transport_parameters is None
    body.vector(1, os.urandom(32) if legacy_session else b"")

    suites = Writer()
    for suite in cipher_suites:
        suites.u16(suite)
    body.vector(2, suites.getvalue())

    body.vector(1, compression_methods)  # compression_methods: null only by default

    extensions = Writer()
    _write_extensions(
        extensions,
        version,
        server_name,
        groups or [],
        signature_schemes or [],
        key_share,
        key_shares,
        alpn,
        empty_key_share,
        heartbeat,
        offer_extended_master_secret,
        offer_session_ticket,
        offer_status_request,
        quic_transport_parameters,
        renegotiation_info,
        extra_extensions,
    )
    body.vector(2, extensions.getvalue())

    handshake = Writer()
    handshake.u8(HANDSHAKE_TYPE_CLIENT_HELLO)
    handshake.vector(3, body.getvalue())

    record = Writer()
    record.u8(CONTENT_TYPE_HANDSHAKE)
    # Record legacy_version: the probed version for <= 1.2, and TLS 1.0 for the
    # 1.3 probe (the real version travels in supported_versions).
    record.u16(0x0301 if version.is_tls13 else version.code)
    record.vector(2, handshake.getvalue())
    return record.getvalue()


def read_handshake(reader: Reader) -> Tuple[int, bytes]:
    """Read one handshake message: its type and its body."""
    message_type = reader.read_u8()
    body = reader.read_vector(3)
    return message_type, body


def parse_alert(fragment: bytes) -> Tuple[int, int]:
    """Parse an alert record fragment into ``(level, description)``."""
    reader = Reader(fragment)
    level = reader.read_u8()
    description = reader.read_u8()
    return level, description


def parse_server_hello(body: bytes) -> ServerHello:
    """Parse the body of a ServerHello handshake message."""
    reader = Reader(body)
    legacy_version = reader.read_u16()
    random = reader.read(32)
    session_id = reader.read_vector(1)  # legacy_session_id_echo
    cipher_suite = reader.read_u16()
    legacy_compression = reader.read_u8()  # 0 is null; non-zero is the CRIME channel

    negotiated_version = legacy_version
    extensions: Dict[int, bytes] = {}
    selected_group: Optional[int] = None

    # SSL 3.0 and bare TLS 1.0 ServerHellos can end here, with no extensions.
    if reader.bytes_left > 0:
        block = Reader(reader.read_vector(2))
        while not block.eof():
            extension_type = block.read_u16()
            extensions[extension_type] = block.read_vector(2)

        supported = extensions.get(EXT_SUPPORTED_VERSIONS)
        if supported is not None:
            if len(supported) < 2:
                raise TlsError("supported_versions in ServerHello is too short")
            negotiated_version = int.from_bytes(supported[:2], "big")

        key_share = extensions.get(EXT_KEY_SHARE)
        if key_share is not None:
            if len(key_share) < 2:
                raise TlsError("key_share in ServerHello is too short")
            selected_group = int.from_bytes(key_share[:2], "big")

    return ServerHello(
        legacy_version=legacy_version,
        negotiated_version=negotiated_version,
        cipher_suite=cipher_suite,
        is_hello_retry_request=random == HELLO_RETRY_REQUEST_RANDOM,
        random=random,
        extensions=extensions,
        selected_group=selected_group,
        legacy_compression=legacy_compression,
        session_id=session_id,
    )
