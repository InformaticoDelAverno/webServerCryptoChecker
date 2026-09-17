"""Completing a TLS 1.3 handshake: to read the certificate, and to fetch HTTP.

A TLS 1.3 server sends its certificate -- and everything after -- encrypted, so
a cleartext probe cannot see it. This offers all three mandatory cipher suites
(AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305) over an X25519 key share and runs
whichever the server picks, on its SHA-256 or SHA-384 key schedule. It decrypts
the server flight and either pulls the certificate out or completes the handshake
(client Finished plus application keys) to send one HTTP request and read the
response headers.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import socket
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from ..crypto import aesgcm, chacha, ec, hkdf
from ..crypto.x25519 import x25519, x25519_base
from .constants import (
    CONTENT_TYPE_ALERT,
    CONTENT_TYPE_APPLICATION_DATA,
    CONTENT_TYPE_CHANGE_CIPHER_SPEC,
    CONTENT_TYPE_HANDSHAKE,
    EXT_ALPN,
    EXT_KEY_SHARE,
    EXT_STATUS_REQUEST,
    HANDSHAKE_TYPE_CERTIFICATE,
    HANDSHAKE_TYPE_SERVER_HELLO,
    PROTOCOL_VERSIONS,
    alert_description,
)
from .messages import build_client_hello, parse_server_hello, read_handshake
from .probe import DEFAULT_TIMEOUT, Connect, _recv_exact
from .wire import Reader, TlsError

_TLS13 = PROTOCOL_VERSIONS[0]
_X25519 = 0x001D
_SECP256R1 = 0x0017
_SECP384R1 = 0x0018
#: The NIST curves offered alongside X25519 on every 1.3 probe, by their supported_groups code.
_NIST_CURVES = {_SECP256R1: ec.P256, _SECP384R1: ec.P384}
#: Every group the 1.3 probes offer a key share for, so a server that does not do X25519 (a
#: FIPS deployment restricted to the NIST curves) still finds a common group without a retry.
_GROUPS = [_X25519, _SECP256R1, _SECP384R1]
_SIGNATURE_SCHEMES = [0x0804, 0x0805, 0x0806, 0x0401, 0x0403, 0x0503, 0x0807]
_HANDSHAKE_TYPE_FINISHED = 20
_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 8
_HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13
_HANDSHAKE_TYPE_NEW_SESSION_TICKET = 4
_EXT_EARLY_DATA = 0x2A
_CLIENT_CHANGE_CIPHER_SPEC = b"\x14\x03\x03\x00\x01\x01"


# --------------------------------------------------------------------------- #
# Cipher suites: the AEAD for each, so the record layer is agnostic to it
# --------------------------------------------------------------------------- #


_Hash = Callable[..., "hashlib._Hash"]  # a hashlib constructor, with or without initial data


@dataclass
class _Cipher:
    """One TLS 1.3 cipher suite: its AEAD and the hash its key schedule runs on."""

    key_length: int
    hashmod: _Hash  # the suite's hash: SHA-256, or SHA-384 for AES-256-GCM
    hash_length: int
    seal: Callable[[bytes, bytes, bytes, bytes], Tuple[bytes, bytes]]
    open: Callable[[bytes, bytes, bytes, bytes, bytes], Optional[bytes]]


# All three mandatory TLS 1.3 suites. AES-256-GCM pairs with SHA-384, a second key
# schedule; the other two run on SHA-256. The AEADs come from crypto/.
_CIPHERS = {
    0x1301: _Cipher(16, hashlib.sha256, 32, aesgcm.encrypt, aesgcm.decrypt),  # AES-128-GCM
    0x1302: _Cipher(32, hashlib.sha384, 48, aesgcm.encrypt, aesgcm.decrypt),  # AES-256-GCM
    0x1303: _Cipher(32, hashlib.sha256, 32, chacha.encrypt, chacha.decrypt),  # ChaCha20
}
_OFFERED = list(_CIPHERS)


# --------------------------------------------------------------------------- #
# Key schedule and record protection
# --------------------------------------------------------------------------- #


def _derive_secret(secret: bytes, label: bytes, context: bytes, cipher: _Cipher) -> bytes:
    """A hash-length secret under the suite's hash (HKDF-Expand-Label, RFC 8446 7.1)."""
    return hkdf.expand_label(secret, label, context, cipher.hash_length, cipher.hashmod)


def _keys(secret: bytes, cipher: _Cipher) -> Tuple[bytes, bytes]:
    key = hkdf.expand_label(secret, b"key", b"", cipher.key_length, cipher.hashmod)
    return key, hkdf.expand_label(secret, b"iv", b"", 12, cipher.hashmod)


def _handshake_secret(shared_secret: bytes, cipher: _Cipher) -> bytes:
    zeros = b"\x00" * cipher.hash_length
    early = hkdf.extract(zeros, zeros, cipher.hashmod)
    derived = _derive_secret(early, b"derived", cipher.hashmod(b"").digest(), cipher)
    return hkdf.extract(derived, shared_secret, cipher.hashmod)


def _master_secret(handshake_secret: bytes, cipher: _Cipher) -> bytes:
    """The master secret the application-traffic secrets derive from (RFC 8446 7.1)."""
    derived = _derive_secret(handshake_secret, b"derived", cipher.hashmod(b"").digest(), cipher)
    return hkdf.extract(derived, b"\x00" * cipher.hash_length, cipher.hashmod)


def _finished_message(traffic_secret: bytes, transcript: bytes, cipher: _Cipher) -> bytes:
    """A Finished handshake message: HMAC of the transcript under the finished key."""
    finished_key = _derive_secret(traffic_secret, b"finished", b"", cipher)
    verify_data = hmac.new(finished_key, transcript, cipher.hashmod).digest()
    return bytes([_HANDSHAKE_TYPE_FINISHED]) + len(verify_data).to_bytes(3, "big") + verify_data


def _server_handshake_keys(
    shared_secret: bytes, transcript_hash: bytes, cipher: _Cipher = _CIPHERS[0x1303]
) -> Tuple[bytes, bytes]:
    """The server handshake write key and IV (kept as a stable entry point)."""
    handshake_secret = _handshake_secret(shared_secret, cipher)
    secret = _derive_secret(handshake_secret, b"s hs traffic", transcript_hash, cipher)
    return _keys(secret, cipher)


def _record_nonce(iv: bytes, sequence: int) -> bytes:
    return bytes(a ^ b for a, b in zip(iv, sequence.to_bytes(12, "big")))


def _decrypt_record(
    cipher: _Cipher, key: bytes, iv: bytes, sequence: int, header: bytes, encrypted: bytes
) -> Optional[Tuple[int, bytes]]:
    if len(encrypted) < 16:
        return None
    plaintext = cipher.open(
        key, _record_nonce(iv, sequence), encrypted[:-16], header, encrypted[-16:]
    )
    if plaintext is None:
        return None
    trimmed = plaintext.rstrip(b"\x00")
    if not trimmed:
        return None
    return trimmed[-1], trimmed[:-1]


def _encrypt_record(cipher: _Cipher, key: bytes, iv: bytes, sequence: int, inner: bytes) -> bytes:
    header = bytes([CONTENT_TYPE_APPLICATION_DATA, 3, 3]) + (len(inner) + 16).to_bytes(2, "big")
    ciphertext, tag = cipher.seal(key, _record_nonce(iv, sequence), inner, header)
    return header + ciphertext + tag


# --------------------------------------------------------------------------- #
# Handshake
# --------------------------------------------------------------------------- #


@dataclass
class _Negotiated:
    server_hello: bytes
    shared_secret: bytes
    transcript: bytes  # Hash(ClientHello || ServerHello)
    cipher: _Cipher


def _server_key_share(extension: Optional[bytes]) -> Optional[Tuple[int, bytes]]:
    """The ``(group, public)`` the server chose in its key_share, or ``None`` if unreadable."""
    if extension is None:
        return None
    reader = Reader(extension)
    try:
        return reader.read_u16(), reader.read_vector(2)
    except TlsError:
        return None


def _key_exchange() -> Tuple[Dict[int, object], List[Tuple[int, bytes]]]:
    """Ephemeral private keys keyed by group, and the ``(group, public)`` key shares to offer for
    every group the client supports -- X25519 and the NIST curves P-256/P-384 -- so a server that
    does not speak X25519 still finds a common group in the first flight (no HelloRetryRequest)."""
    x_private = os.urandom(32)
    privates: Dict[int, object] = {_X25519: x_private}
    shares: List[Tuple[int, bytes]] = [(_X25519, x25519_base(x_private))]
    for group, curve in _NIST_CURVES.items():
        scalar, point = ec.generate_keypair(curve)
        privates[group] = scalar
        shares.append((group, ec.encode_public(curve, point)))
    return privates, shares


def _derive_shared(group: int, private: object, server_public: bytes) -> Optional[bytes]:
    """The ECDHE shared secret for the group the server selected, or ``None`` if it is one the
    client did not offer a usable private for, or the peer's share is not a valid point."""
    if group == _X25519:
        assert isinstance(private, bytes)
        shared = x25519(private, server_public)
        # RFC 8446 7.4.2 / RFC 7748 6.1: a low-order server share yields an all-zero shared
        # secret, which a client MUST reject -- otherwise keys derive from an attacker-known
        # (fully predictable) value. ec.ecdh_shared already rejects the NIST analogue.
        return None if shared == bytes(32) else shared
    curve = _NIST_CURVES.get(group)
    if curve is None:
        return None
    assert isinstance(private, int)
    return ec.ecdh_shared(curve, private, server_public)


def _negotiate(
    sock: socket.socket, client_hello_handshake: bytes, privates: Dict[int, object]
) -> Tuple[Optional[_Negotiated], Optional[str]]:
    header = _recv_exact(sock, 5)
    if header is None:
        return None, "no response to the ClientHello"
    length = int.from_bytes(header[3:5], "big")
    fragment = _recv_exact(sock, length) if length else b""
    if fragment is None:
        return None, "truncated ServerHello"
    if header[0] == CONTENT_TYPE_ALERT and len(fragment) >= 2:
        return None, f"server sent an alert: {alert_description(fragment[1])}"
    if header[0] != CONTENT_TYPE_HANDSHAKE:
        return None, f"unexpected TLS record type {header[0]}"

    try:
        message_type, body = read_handshake(Reader(fragment))
    except TlsError as exc:
        return None, f"malformed handshake: {exc}"
    if message_type != HANDSHAKE_TYPE_SERVER_HELLO:
        return None, "expected a ServerHello"
    try:
        server_hello = parse_server_hello(body)
    except TlsError as exc:
        return None, f"malformed ServerHello: {exc}"
    if server_hello.negotiated_version != 0x0304:
        return None, "the server did not negotiate TLS 1.3"
    cipher = _CIPHERS.get(server_hello.cipher_suite)
    if cipher is None:
        return None, "the server did not select an offered cipher suite"

    share = _server_key_share(server_hello.extensions.get(EXT_KEY_SHARE))
    if share is None:
        return None, "the ServerHello carried no usable key share"
    group, server_public = share
    private = privates.get(group)
    if private is None:
        return None, "the server selected a key-exchange group the client did not offer"
    shared = _derive_shared(group, private, server_public)
    if shared is None:
        return None, "the server's key share is not a valid point for the selected group"
    transcript = cipher.hashmod(client_hello_handshake + fragment).digest()
    negotiated = _Negotiated(
        server_hello=fragment, shared_secret=shared, transcript=transcript, cipher=cipher
    )
    return negotiated, None


def _has_finished(buffer: bytes) -> bool:
    position = 0
    while position + 4 <= len(buffer):
        length = int.from_bytes(buffer[position + 1 : position + 4], "big")
        if position + 4 + length > len(buffer):
            return False
        if buffer[position] == _HANDSHAKE_TYPE_FINISHED:
            return True
        position += 4 + length
    return False


def _read_record(sock: socket.socket) -> Optional[Tuple[bytes, bytes]]:
    """One TLS record as (5-byte header, fragment), or None if closed or truncated."""
    header = _recv_exact(sock, 5)
    if header is None:
        return None
    length = int.from_bytes(header[3:5], "big")
    fragment = _recv_exact(sock, length) if length else b""
    if fragment is None:
        return None
    return header, fragment


def _read_server_flight(
    sock: socket.socket, cipher: _Cipher, key: bytes, iv: bytes
) -> Tuple[bytes, Optional[str]]:
    """Read and decrypt the server flight up to and including its Finished."""
    buffer = b""
    sequence = 0
    while not _has_finished(buffer):
        record = _read_record(sock)
        if record is None:
            return b"", "connection closed or truncated during the TLS 1.3 handshake"
        header, fragment = record
        if header[0] == CONTENT_TYPE_CHANGE_CIPHER_SPEC:
            continue
        if header[0] != CONTENT_TYPE_APPLICATION_DATA:
            return b"", f"unexpected TLS record type {header[0]}"
        decrypted = _decrypt_record(cipher, key, iv, sequence, header, fragment)
        sequence += 1
        if decrypted is None:
            return b"", "could not decrypt the server's handshake"
        buffer += decrypted[1]
    return buffer, None


def _stapled_ocsp(extensions: Reader) -> Optional[bytes]:
    """The OCSP response stapled to a CertificateEntry (RFC 8446 4.4.2.1), or None."""
    while not extensions.eof():
        extension_type = extensions.read_u16()
        extension_body = extensions.read_vector(2)
        if extension_type == EXT_STATUS_REQUEST:
            status = Reader(extension_body)
            status.read_u8()  # CertificateStatusType = ocsp(1)
            return status.read(status.read_u24())  # the OCSPResponse DER
    return None


def _parse_certificate_message(body: bytes) -> Tuple[List[bytes], Optional[bytes]]:
    reader = Reader(body)
    reader.read_vector(1)  # certificate_request_context
    entries = Reader(reader.read(reader.read_u24()))
    certificates: List[bytes] = []
    stapled: Optional[bytes] = None
    while not entries.eof():
        certificates.append(entries.read_vector(3))
        extensions = entries.read_vector(2)  # per-certificate extensions
        if len(certificates) == 1:  # the leaf may carry a stapled OCSP response
            stapled = _stapled_ocsp(Reader(extensions))
    return certificates, stapled


def _extract_certificate(buffer: bytes) -> Tuple[List[bytes], Optional[bytes]]:
    position = 0
    while position + 4 <= len(buffer):
        length = int.from_bytes(buffer[position + 1 : position + 4], "big")
        if position + 4 + length > len(buffer):
            break
        if buffer[position] == HANDSHAKE_TYPE_CERTIFICATE:
            try:
                return _parse_certificate_message(buffer[position + 4 : position + 4 + length])
            except TlsError:
                return [], None  # a malformed Certificate is treated as none
        position += 4 + length
    return [], None


def _server_flight(
    host: str, port: int, sni: str, timeout: float,
    signature_schemes: Optional[List[int]] = None, connect: Optional[Connect] = None,
    **hello_kwargs: object,
) -> Tuple[bytes, Optional[str]]:
    """Handshake with a TLS 1.3 server and return its decrypted flight (or an error).

    The flight -- EncryptedExtensions, an optional CertificateRequest, Certificate,
    CertificateVerify, Finished -- is all a probe needs to read what the server
    offers, without completing the handshake. ``signature_schemes`` narrows what the
    client will accept in a CertificateVerify, which is how the server is steered to
    pick one key type's certificate over another (RFC 8446 4.4.2.2). ``connect`` opens
    the connection (direct, or a STARTTLS upgrade), so the probe reaches a mail service
    behind STARTTLS, not only an implicit-TLS port.
    """
    privates, shares = _key_exchange()
    hello = build_client_hello(
        _TLS13, _OFFERED, server_name=sni, groups=_GROUPS,
        signature_schemes=signature_schemes or _SIGNATURE_SCHEMES,
        key_shares=shares,
        **hello_kwargs,  # type: ignore[arg-type]
    )
    opener: Connect = connect if connect is not None else socket.create_connection
    try:
        sock = opener((host, port), timeout)
    except OSError as exc:
        return b"", f"connection failed: {exc}"
    try:
        sock.settimeout(timeout)
        sock.sendall(hello)
        negotiated, error = _negotiate(sock, hello[5:], privates)
        if error is not None:
            return b"", error
        assert negotiated is not None
        key, iv = _server_handshake_keys(
            negotiated.shared_secret, negotiated.transcript, negotiated.cipher
        )
        return _read_server_flight(sock, negotiated.cipher, key, iv)
    except OSError as exc:
        return b"", f"network error: {exc}"
    finally:
        sock.close()


def retrieve_tls13_certificate(
    host: str, port: int, sni: str = "", timeout: float = DEFAULT_TIMEOUT,
    signature_schemes: Optional[List[int]] = None, connect: Optional[Connect] = None,
) -> Tuple[List[bytes], Optional[bytes], Optional[str]]:
    """Fetch a TLS 1.3 server's certificates (and any stapled OCSP), decrypting the flight.

    ``signature_schemes`` narrows the accepted CertificateVerify schemes to steer which
    key type's certificate a dual-certificate server returns; default offers all.
    ``connect`` opens the connection (direct, or a STARTTLS upgrade)."""
    flight, error = _server_flight(
        host, port, sni, timeout,
        signature_schemes=signature_schemes, connect=connect, offer_status_request=True,
    )
    if error is not None:
        return [], None, error
    certificates, stapled = _extract_certificate(flight)
    return certificates, stapled, None


def _flight_has_certificate_request(flight: bytes) -> bool:
    """Whether the server flight carries a CertificateRequest (RFC 8446 4.3.2)."""
    position = 0
    while position + 4 <= len(flight):
        length = int.from_bytes(flight[position + 1 : position + 4], "big")
        if position + 4 + length > len(flight):
            break
        if flight[position] == _HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
            return True
        position += 4 + length
    return False


def _certificate_request_context(flight: bytes) -> bytes:
    """The certificate_request_context the client must echo (RFC 8446 4.3.2)."""
    position = 0
    while position + 4 <= len(flight):
        length = int.from_bytes(flight[position + 1 : position + 4], "big")
        if position + 4 + length > len(flight):
            break
        if flight[position] == _HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
            body = flight[position + 4 : position + 4 + length]
            return body[1 : 1 + body[0]]
        position += 4 + length
    return b""


def _empty_certificate_message(context: bytes) -> bytes:
    """A Certificate message carrying no certificates (RFC 8446 4.4.2)."""
    body = bytes([len(context)]) + context + b"\x00\x00\x00"  # context + empty certificate_list
    return bytes([HANDSHAKE_TYPE_CERTIFICATE]) + len(body).to_bytes(3, "big") + body


def _read_client_auth_verdict(
    sock: socket.socket, cipher: _Cipher, key: bytes, iv: bytes
) -> Optional[bool]:
    """True if the server rejects our empty certificate (requires one), False if it accepts."""
    sequence = 0
    for _ in range(4):
        record = _read_record(sock)
        if record is None:
            return None  # closed with nothing to read -- enforcement undetermined
        header, fragment = record
        if header[0] == CONTENT_TYPE_ALERT:
            return True  # a cleartext alert -- the empty certificate was refused
        decrypted = _decrypt_record(cipher, key, iv, sequence, header, fragment)
        sequence += 1
        if decrypted is None:
            continue
        return decrypted[0] == CONTENT_TYPE_ALERT  # alert = required; anything else = accepted
    return None


def _classify_client_auth(
    sock: socket.socket,
    negotiated: _Negotiated,
    client_hello_handshake: bytes,
    handshake_secret: bytes,
    flight: bytes,
) -> Optional[bool]:
    """Send an empty client Certificate and Finished, then read whether it was refused."""
    cipher = negotiated.cipher
    client_hs = _derive_secret(handshake_secret, b"c hs traffic", negotiated.transcript, cipher)
    certificate = _empty_certificate_message(_certificate_request_context(flight))
    transcript = cipher.hashmod(
        client_hello_handshake + negotiated.server_hello + flight + certificate
    ).digest()
    finished = _finished_message(client_hs, transcript, cipher)
    client_key, client_iv = _keys(client_hs, cipher)
    sock.sendall(_CLIENT_CHANGE_CIPHER_SPEC)
    inner = certificate + finished + bytes([CONTENT_TYPE_HANDSHAKE])
    sock.sendall(_encrypt_record(cipher, client_key, client_iv, 0, inner))

    server_transcript = cipher.hashmod(
        client_hello_handshake + negotiated.server_hello + flight
    ).digest()
    master_secret = _master_secret(handshake_secret, cipher)
    server_ap = _derive_secret(master_secret, b"s ap traffic", server_transcript, cipher)
    key, iv = _keys(server_ap, cipher)
    return _read_client_auth_verdict(sock, cipher, key, iv)


def probe_client_certificate(
    host: str, port: int, sni: str = "", timeout: float = DEFAULT_TIMEOUT,
    connect: Optional[Connect] = None,
) -> Tuple[Optional[bool], Optional[bool], Optional[str]]:
    """Whether a TLS 1.3 server requests a client certificate, and whether it requires one.

    Returns ``(requested, required, error)``. ``required`` is True when the server
    refuses a certificate-less handshake, False when it accepts one, and None when it
    was requested but enforcement could not be determined (or was not requested).
    ``connect`` opens the connection (direct, or a STARTTLS upgrade).
    """
    privates, shares = _key_exchange()
    hello = build_client_hello(
        _TLS13, _OFFERED, server_name=sni, groups=_GROUPS,
        signature_schemes=_SIGNATURE_SCHEMES, key_shares=shares,
    )
    opener: Connect = connect if connect is not None else socket.create_connection
    try:
        sock = opener((host, port), timeout)
    except OSError as exc:
        return None, None, f"connection failed: {exc}"
    try:
        sock.settimeout(timeout)
        sock.sendall(hello)
        negotiated, error = _negotiate(sock, hello[5:], privates)
        if error is not None:
            return None, None, error
        assert negotiated is not None
        cipher = negotiated.cipher
        handshake_secret = _handshake_secret(negotiated.shared_secret, cipher)
        server_hs = _derive_secret(handshake_secret, b"s hs traffic", negotiated.transcript, cipher)
        key, iv = _keys(server_hs, cipher)
        flight, error = _read_server_flight(sock, negotiated.cipher, key, iv)
        if error is not None:
            return None, None, error
        if not _flight_has_certificate_request(flight):
            return False, None, None
        required = _classify_client_auth(
            sock, negotiated, hello[5:], handshake_secret, flight
        )
        return True, required, None
    except OSError as exc:
        return None, None, f"network error: {exc}"
    finally:
        sock.close()


def _ticket_has_early_data(body: bytes) -> bool:
    """Whether a NewSessionTicket body carries the early_data extension (0-RTT)."""
    reader = Reader(body)
    reader.read(4)  # ticket_lifetime
    reader.read(4)  # ticket_age_add
    reader.read_vector(1)  # ticket_nonce
    reader.read_vector(2)  # ticket
    extensions = Reader(reader.read_vector(2))
    while not extensions.eof():
        extension_type = extensions.read_u16()
        extensions.read_vector(2)
        if extension_type == _EXT_EARLY_DATA:
            return True
    return False


def _new_session_ticket_early_data(handshake: bytes) -> Optional[bool]:
    """Scan reassembled handshake bytes for a NewSessionTicket and its 0-RTT offer.

    None means no complete ticket is present yet (read more); True/False once one is.
    """
    position = 0
    while position + 4 <= len(handshake):
        length = int.from_bytes(handshake[position + 1 : position + 4], "big")
        if position + 4 + length > len(handshake):
            return None
        if handshake[position] == _HANDSHAKE_TYPE_NEW_SESSION_TICKET:
            try:
                return _ticket_has_early_data(handshake[position + 4 : position + 4 + length])
            except TlsError:
                return False
        position += 4 + length
    return None


def _read_early_data_offer(sock: socket.socket, established: _Established) -> Optional[bool]:
    """Read post-handshake records for a NewSessionTicket; whether it offers 0-RTT."""
    handshake = b""
    sequence = 0
    for _ in range(4):
        record = _read_record(sock)
        if record is None:
            break
        header, fragment = record
        decrypted = _decrypt_record(
            established.cipher, established.server_ap_key, established.server_ap_iv,
            sequence, header, fragment,
        )
        sequence += 1
        if decrypted is None or decrypted[0] != CONTENT_TYPE_HANDSHAKE:
            continue
        handshake += decrypted[1]
        verdict = _new_session_ticket_early_data(handshake)
        if verdict is not None:
            return verdict
    return None


def probe_early_data(
    host: str, port: int, sni: str = "", timeout: float = DEFAULT_TIMEOUT,
    connect: Optional[Connect] = None,
) -> Tuple[Optional[bool], Optional[str]]:
    """Whether a TLS 1.3 server offers 0-RTT early data, read from its NewSessionTicket.
    ``connect`` opens the connection (direct, or a STARTTLS upgrade)."""
    privates, shares = _key_exchange()
    hello = build_client_hello(
        _TLS13, _OFFERED, server_name=sni, groups=_GROUPS,
        signature_schemes=_SIGNATURE_SCHEMES, key_shares=shares,
        alpn=["http/1.1"],
    )
    opener: Connect = connect if connect is not None else socket.create_connection
    try:
        sock = opener((host, port), timeout)
    except OSError as exc:
        return None, f"connection failed: {exc}"
    try:
        sock.settimeout(timeout)
        sock.sendall(hello)
        negotiated, error = _negotiate(sock, hello[5:], privates)
        if error is not None:
            return None, error
        assert negotiated is not None
        established, error = _complete_handshake(sock, negotiated, hello[5:])
        if error is not None:
            return None, error
        assert established is not None
        return _read_early_data_offer(sock, established), None
    except OSError as exc:
        return None, f"network error: {exc}"
    finally:
        sock.close()


def fetch_over_tls13(
    host: str, port: int, request: bytes, sni: str = "", timeout: float = DEFAULT_TIMEOUT
) -> Tuple[bytes, Optional[str]]:
    """Complete a TLS 1.3 handshake, send ``request``, and return the response bytes."""
    _alpn, response, error = exchange_over_tls13(
        host, port, request, sni, timeout, ["http/1.1"], lambda reply: b"\r\n\r\n" in reply
    )
    return response, error


def exchange_over_tls13(
    host: str,
    port: int,
    request: bytes,
    sni: str,
    timeout: float,
    alpn: List[str],
    is_complete: Callable[[bytes], bool],
    connect: Optional[Connect] = None,
) -> Tuple[Optional[str], bytes, Optional[str]]:
    """Handshake offering ``alpn``, send ``request``, read until ``is_complete``.

    Returns ``(negotiated_alpn, response, error)``: it exposes the ALPN the server
    chose and lets the caller decide when the reply is complete -- what a binary
    protocol like HTTP/2 needs. ``connect`` opens the connection (direct, or a
    STARTTLS upgrade), so the exchange reaches a mail service.
    """
    privates, shares = _key_exchange()
    hello = build_client_hello(
        _TLS13, _OFFERED, server_name=sni, groups=_GROUPS,
        signature_schemes=_SIGNATURE_SCHEMES, key_shares=shares,
        alpn=alpn,
    )
    opener: Connect = connect if connect is not None else socket.create_connection
    try:
        sock = opener((host, port), timeout)
    except OSError as exc:
        return None, b"", f"connection failed: {exc}"
    try:
        sock.settimeout(timeout)
        sock.sendall(hello)
        negotiated, error = _negotiate(sock, hello[5:], privates)
        if error is not None:
            return None, b"", error
        assert negotiated is not None
        established, error = _complete_handshake(sock, negotiated, hello[5:])
        if error is not None:
            return None, b"", error
        assert established is not None
        selected = _extract_alpn(established.flight)
        response, error = _exchange(sock, established, request, is_complete)
        return selected, response, error
    except OSError as exc:
        return None, b"", f"network error: {exc}"
    finally:
        sock.close()


@dataclass
class _Established:
    """A completed TLS 1.3 session: the decrypted flight and the app-data keys."""

    cipher: _Cipher
    flight: bytes  # the decrypted server flight (EncryptedExtensions..Finished)
    client_ap_key: bytes
    client_ap_iv: bytes
    server_ap_key: bytes
    server_ap_iv: bytes


def _complete_handshake(
    sock: socket.socket, negotiated: _Negotiated, client_hello_handshake: bytes
) -> Tuple[Optional[_Established], Optional[str]]:
    """Read the server flight, send the client Finished, derive application keys."""
    cipher = negotiated.cipher
    handshake_secret = _handshake_secret(negotiated.shared_secret, cipher)
    server_hs = _derive_secret(handshake_secret, b"s hs traffic", negotiated.transcript, cipher)
    client_hs = _derive_secret(handshake_secret, b"c hs traffic", negotiated.transcript, cipher)
    server_key, server_iv = _keys(server_hs, cipher)

    flight, error = _read_server_flight(sock, cipher, server_key, server_iv)
    if error is not None:
        return None, error

    transcript = cipher.hashmod(
        client_hello_handshake + negotiated.server_hello + flight
    ).digest()

    finished = _finished_message(client_hs, transcript, cipher)
    client_key, client_iv = _keys(client_hs, cipher)
    sock.sendall(_CLIENT_CHANGE_CIPHER_SPEC)
    finished_inner = finished + bytes([CONTENT_TYPE_HANDSHAKE])
    sock.sendall(_encrypt_record(cipher, client_key, client_iv, 0, finished_inner))

    master_secret = _master_secret(handshake_secret, cipher)
    client_ap = _derive_secret(master_secret, b"c ap traffic", transcript, cipher)
    server_ap = _derive_secret(master_secret, b"s ap traffic", transcript, cipher)
    client_ap_key, client_ap_iv = _keys(client_ap, cipher)
    server_ap_key, server_ap_iv = _keys(server_ap, cipher)
    return (
        _Established(
            cipher, flight, client_ap_key, client_ap_iv, server_ap_key, server_ap_iv
        ),
        None,
    )


def _extract_alpn(flight: bytes) -> Optional[str]:
    """The protocol the server selected via ALPN, from its EncryptedExtensions."""
    position = 0
    while position + 4 <= len(flight):
        length = int.from_bytes(flight[position + 1 : position + 4], "big")
        if position + 4 + length > len(flight):
            break
        if flight[position] == _HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS:
            try:
                message = Reader(flight[position + 4 : position + 4 + length])
                extensions = Reader(message.read_vector(2))
                while not extensions.eof():
                    extension_type = extensions.read_u16()
                    extension_body = extensions.read_vector(2)
                    if extension_type == EXT_ALPN:
                        names = Reader(Reader(extension_body).read_vector(2))
                        return names.read_vector(1).decode("latin1")
            except TlsError:
                return None
            return None
        position += 4 + length
    return None


def _exchange(
    sock: socket.socket,
    established: _Established,
    request: bytes,
    is_complete: Callable[[bytes], bool],
) -> Tuple[bytes, Optional[str]]:
    """Send one application-data record and read the reply until ``is_complete``."""
    request_inner = request + bytes([CONTENT_TYPE_APPLICATION_DATA])
    cipher, key, iv = established.cipher, established.client_ap_key, established.client_ap_iv
    sock.sendall(_encrypt_record(cipher, key, iv, 0, request_inner))
    response = b""
    sequence = 0
    while True:
        record = _read_record(sock)
        if record is None:
            break
        header, fragment = record
        # A post-handshake message (e.g. NewSessionTicket) still consumes a
        # sequence number, so decrypt every record but keep only application data.
        decrypted = _decrypt_record(
            established.cipher, established.server_ap_key, established.server_ap_iv,
            sequence, header, fragment,
        )
        sequence += 1
        if decrypted is not None and decrypted[0] == CONTENT_TYPE_APPLICATION_DATA:
            response += decrypted[1]
            if is_complete(response):
                break
    return response, None
