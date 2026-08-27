"""Reading handshake features from what the server puts in its ServerHello.

A TLS 1.2 server that omits the ``renegotiation_info`` extension (RFC 5746) does
not support secure renegotiation, and so is open to the CVE-2009-3555 prefix
injection if it renegotiates at all. Every ClientHello this tool builds already
offers the extension, so one 1.2 handshake, read only as far as the ServerHello,
tells whether the server echoes it.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from ..models import TlsCompressionStatus
from .constants import (
    ALERT_INAPPROPRIATE_FALLBACK,
    EXT_ENCRYPT_THEN_MAC,
    EXT_EXTENDED_MASTER_SECRET,
    EXT_RENEGOTIATION_INFO,
    EXT_SESSION_TICKET,
    LEGACY_CIPHER_SUITES,
    PROTOCOL_VERSIONS,
    TLS_FALLBACK_SCSV,
)
from .messages import build_client_hello
from .probe import DEFAULT_TIMEOUT, send_client_hello
from .tls13 import retrieve_tls13_certificate

_TLS12 = PROTOCOL_VERSIONS[1]
_BY_ID = {version.id: version for version in PROTOCOL_VERSIONS}
_TLS10_CODE = 0x0301  # do not offer SSL 3.0 as a fallback floor
_GROUPS = [0x0017, 0x0018, 0x0019, 0x001D]
_SIGNATURE_SCHEMES = [0x0401, 0x0403, 0x0501, 0x0503, 0x0601, 0x0804]
_TLS12_VERSION = 0x0303
# DEFLATE (0x01) offered ahead of null (0x00): a server that echoes the non-null
# byte agreed to compress, which is CRIME. A null-only client can never see it.
_DEFLATE_THEN_NULL = b"\x01\x00"


def detect_secure_renegotiation(
    host: str, port: int, sni: str = "", timeout: float = DEFAULT_TIMEOUT
) -> Optional[bool]:
    """Whether a TLS 1.2 server supports secure renegotiation (RFC 5746).

    ``None`` when the server does not answer with a 1.2 ServerHello, since
    renegotiation is a 1.2-and-below concern that does not apply otherwise.
    """
    hello = build_client_hello(
        _TLS12,
        list(LEGACY_CIPHER_SUITES),
        server_name=sni,
        groups=_GROUPS,
        signature_schemes=_SIGNATURE_SCHEMES,
    )
    result = send_client_hello(host, port, hello, timeout)
    server_hello = result.server_hello
    if server_hello is None or server_hello.negotiated_version != _TLS12_VERSION:
        return None
    return EXT_RENEGOTIATION_INFO in server_hello.extensions


def detect_extended_master_secret(
    host: str, port: int, sni: str = "", timeout: float = DEFAULT_TIMEOUT
) -> Optional[bool]:
    """Whether a TLS 1.2 server supports the extended master secret (RFC 7627).

    EMS binds the master secret to the whole handshake, closing the Triple
    Handshake attack. The probe offers the extension (safe here because it never
    completes the handshake) and checks the echo. ``None`` when the server does
    not answer with a 1.2 ServerHello, as 1.3 has the guarantee built in.
    """
    hello = build_client_hello(
        _TLS12,
        list(LEGACY_CIPHER_SUITES),
        server_name=sni,
        groups=_GROUPS,
        signature_schemes=_SIGNATURE_SCHEMES,
        offer_extended_master_secret=True,
    )
    result = send_client_hello(host, port, hello, timeout)
    server_hello = result.server_hello
    if server_hello is None or server_hello.negotiated_version != _TLS12_VERSION:
        return None
    return EXT_EXTENDED_MASTER_SECRET in server_hello.extensions


def detect_encrypt_then_mac(
    host: str, port: int, sni: str = "", timeout: float = DEFAULT_TIMEOUT
) -> Optional[bool]:
    """Whether a TLS 1.2 server hardens its CBC cipher suites with Encrypt-then-MAC (RFC
    7366) instead of the MAC-then-encrypt that Lucky13 and other padding-oracle attacks
    target. Only CBC suites are offered, with the extension; a ServerHello therefore means a
    CBC suite was chosen. ``True`` it also echoed EtM (hardened), ``False`` it did not (the
    weak construction), ``None`` no CBC suite was negotiated (AEAD-only or not 1.2, so EtM
    does not apply -- nothing to report)."""
    cbc = [code for code, name in LEGACY_CIPHER_SUITES.items() if "CBC" in name]
    hello = build_client_hello(
        _TLS12, cbc, server_name=sni, groups=_GROUPS,
        signature_schemes=_SIGNATURE_SCHEMES,
        extra_extensions=[(EXT_ENCRYPT_THEN_MAC, b"")],
    )
    result = send_client_hello(host, port, hello, timeout)
    server_hello = result.server_hello
    if server_hello is None or server_hello.negotiated_version != _TLS12_VERSION:
        return None
    return EXT_ENCRYPT_THEN_MAC in server_hello.extensions


def detect_ocsp_stapling(
    host: str, port: int, sni: str = "", timeout: float = DEFAULT_TIMEOUT
) -> Tuple[Optional[bool], Optional[bytes]]:
    """Whether a TLS 1.3 server staples an OCSP response, and the response itself.

    Completing the 1.3 handshake with a status_request and inspecting the leaf's
    CertificateEntry is the only way to see it, since 1.3 encrypts the flight. Returns
    ``(stapled, response)``: ``(None, None)`` when the handshake does not complete (e.g.
    the server is not 1.3), otherwise whether a response was stapled and its DER.
    """
    _ders, stapled, error = retrieve_tls13_certificate(host, port, sni, timeout)
    if error is not None:
        return None, None
    return stapled is not None, stapled


def detect_session_resumption(
    host: str, port: int, sni: str = "", timeout: float = DEFAULT_TIMEOUT
) -> Tuple[Optional[bool], Optional[bool]]:
    """``(session-id resumption, session-ticket resumption)`` from a 1.2 ServerHello.

    A non-empty session_id echo offers stateful id resumption; an echoed
    session_ticket extension (RFC 5077) offers stateless ticket resumption. Both
    ``None`` when the server does not answer with a 1.2 ServerHello.
    """
    hello = build_client_hello(
        _TLS12,
        list(LEGACY_CIPHER_SUITES),
        server_name=sni,
        groups=_GROUPS,
        signature_schemes=_SIGNATURE_SCHEMES,
        offer_session_ticket=True,
    )
    result = send_client_hello(host, port, hello, timeout)
    server_hello = result.server_hello
    if server_hello is None or server_hello.negotiated_version != _TLS12_VERSION:
        return None, None
    by_id = len(server_hello.session_id) > 0
    by_ticket = EXT_SESSION_TICKET in server_hello.extensions
    return by_id, by_ticket


def detect_fallback_scsv(
    host: str,
    port: int,
    supported_ids: List[str],
    sni: str = "",
    timeout: float = DEFAULT_TIMEOUT,
) -> Optional[bool]:
    """Whether the server honours TLS_FALLBACK_SCSV (RFC 7507) downgrade protection.

    Offers the highest TLS version below the server's maximum, marked with the
    fallback SCSV; a server that knows it could do better must answer
    ``inappropriate_fallback``. ``None`` when there is no lower version to fall
    back from, or the answer is inconclusive.
    """
    supported = [_BY_ID[version_id] for version_id in supported_ids if version_id in _BY_ID]
    if not supported:
        return None
    highest = max(version.code for version in supported)
    below = [version for version in PROTOCOL_VERSIONS if _TLS10_CODE <= version.code < highest]
    if not below:
        return None
    fallback = max(below, key=lambda version: version.code)
    hello = build_client_hello(
        fallback,
        [*LEGACY_CIPHER_SUITES, TLS_FALLBACK_SCSV],
        server_name=sni,
        groups=_GROUPS,
        signature_schemes=_SIGNATURE_SCHEMES,
    )
    result = send_client_hello(host, port, hello, timeout)
    if result.alert is not None and result.alert[1] == ALERT_INAPPROPRIATE_FALLBACK:
        return True
    if result.server_hello is not None:
        return False
    return None


#: The value a TLS 1.3 server must write into the last 8 bytes of ServerHello.random when
#: it negotiates TLS 1.2, so a 1.3-capable client can detect a downgrade (RFC 8446 4.1.3).
_DOWNGRADE_SENTINEL_TLS12 = b"DOWNGRD\x01"


def detect_downgrade_protection(
    host: str,
    port: int,
    supported_ids: List[str],
    sni: str = "",
    timeout: float = DEFAULT_TIMEOUT,
) -> Optional[bool]:
    """Whether a TLS 1.3-capable server sets the RFC 8446 4.1.3 downgrade sentinel when it
    negotiates TLS 1.2. ``None`` when the check does not apply (the server is not both 1.3-
    and 1.2-capable) or the answer is inconclusive; ``False`` is a real gap -- a downgrade
    to 1.2 would then be invisible to a 1.3-capable client."""
    if not {"tls1_2", "tls1_3"} <= set(supported_ids):
        return None
    hello = build_client_hello(
        _TLS12,
        list(LEGACY_CIPHER_SUITES),
        server_name=sni,
        groups=_GROUPS,
        signature_schemes=_SIGNATURE_SCHEMES,
    )
    server_hello = send_client_hello(host, port, hello, timeout).server_hello
    if server_hello is None or server_hello.negotiated_version != _TLS12_VERSION:
        return None
    return server_hello.random[24:32] == _DOWNGRADE_SENTINEL_TLS12


#: ECDHE curves plus ffdhe2048/3072, so the cipher-preference probe can complete
#: whether the server does ECDHE or DHE key exchange.
_PREFERENCE_GROUPS = [*_GROUPS, 0x0100, 0x0101]


def _negotiated_cipher(
    host: str, port: int, cipher_ids: List[int], sni: str, timeout: float
) -> Optional[int]:
    """The cipher a TLS 1.2 server picks from ``cipher_ids``, or ``None`` if it does not
    answer with a 1.2 ServerHello."""
    hello = build_client_hello(
        _TLS12, cipher_ids, server_name=sni, groups=_PREFERENCE_GROUPS,
        signature_schemes=_SIGNATURE_SCHEMES,
    )
    server_hello = send_client_hello(host, port, hello, timeout).server_hello
    if server_hello is None or server_hello.negotiated_version != _TLS12_VERSION:
        return None
    return server_hello.cipher_suite


def detect_cipher_preference(
    host: str, port: int, sni: str = "", timeout: float = DEFAULT_TIMEOUT
) -> Optional[bool]:
    """Whether a TLS 1.2 server imposes its own cipher order rather than the client's.

    Learns the server's top two suites, then offers exactly those two with the server's
    *second* choice first: a server with a preference still picks its first, one that
    honours the client takes whichever came first. ``True`` means the server decides
    (the safe posture); ``False`` means the client does, so an attacker steering a
    client can pull the connection to the weakest suite both sides share. ``None`` when
    it cannot be told -- not a 1.2 server, or fewer than two mutually-supported suites.
    """
    top = _negotiated_cipher(host, port, list(LEGACY_CIPHER_SUITES), sni, timeout)
    if top is None:
        return None
    without_top = [cipher for cipher in LEGACY_CIPHER_SUITES if cipher != top]
    second = _negotiated_cipher(host, port, without_top, sni, timeout)
    if second is None:
        return None  # only one mutually-supported suite: there is no order to impose
    chosen = _negotiated_cipher(host, port, [second, top], sni, timeout)
    if chosen is None:
        return None  # inconclusive rather than a guess
    return chosen == top


#: One of the RFC 8701 GREASE values (the 0x?A?A pattern); a conformant server must
#: ignore it wherever it appears.
_GREASE = 0x0A0A


def _greased_handshake(host: str, port: int, sni: str, timeout: float, grease: bool) -> bool:
    """Whether a TLS 1.2 ClientHello -- optionally salted with GREASE values -- draws a
    ServerHello."""
    ciphers = list(LEGACY_CIPHER_SUITES)
    groups = list(_GROUPS)
    extra = None
    if grease:
        ciphers = [_GREASE, *ciphers]
        groups = [_GREASE, *groups]
        extra = [(_GREASE, b"")]  # a GREASE extension the server must ignore
    hello = build_client_hello(
        _TLS12, ciphers, server_name=sni, groups=groups,
        signature_schemes=_SIGNATURE_SCHEMES, extra_extensions=extra,
    )
    return send_client_hello(host, port, hello, timeout).server_hello is not None


def detect_grease_tolerance(
    host: str, port: int, sni: str = "", timeout: float = DEFAULT_TIMEOUT
) -> Optional[bool]:
    """Whether the server tolerates GREASE (RFC 8701): unknown cipher, group and extension
    values a conformant server must ignore. ``True`` when a greased hello still handshakes;
    ``False`` when a plain hello handshakes but a greased one does not (the server is
    intolerant and may break as TLS grows); ``None`` when neither handshakes (not reachable
    over 1.2)."""
    if _greased_handshake(host, port, sni, timeout, grease=True):
        return True
    if _greased_handshake(host, port, sni, timeout, grease=False):
        return False
    return None


def detect_tls_compression(
    host: str, port: int, sni: str = "", timeout: float = DEFAULT_TIMEOUT
) -> TlsCompressionStatus:
    """Whether the server agrees to TLS-level compression (the CRIME channel).

    Offers DEFLATE ahead of null in a TLS 1.2 ClientHello; a server that echoes a
    non-null compression method has compression on. ``UNKNOWN`` when no
    ServerHello comes back (a 1.3-only server rejects a 1.2, compression-offering
    hello, and 1.3 has no compression to worry about anyway).
    """
    hello = build_client_hello(
        _TLS12,
        list(LEGACY_CIPHER_SUITES),
        server_name=sni,
        groups=_GROUPS,
        signature_schemes=_SIGNATURE_SCHEMES,
        compression_methods=_DEFLATE_THEN_NULL,
    )
    result = send_client_hello(host, port, hello, timeout)
    server_hello = result.server_hello
    if server_hello is None:
        return TlsCompressionStatus.UNKNOWN
    if server_hello.legacy_compression != 0:
        return TlsCompressionStatus.ENABLED
    return TlsCompressionStatus.DISABLED
