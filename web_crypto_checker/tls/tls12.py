"""Completing a TLS 1.2 handshake, so the HTTP layer reaches a 1.2-only server.

Where ``tls13.py`` completes a 1.3 handshake, this does the classic ECDHE one:
read the server's flight, take its ephemeral point from the ServerKeyExchange, do
the ECDH with ``crypto/ec.py``, run the TLS 1.2 PRF to the traffic keys, send the
ClientKeyExchange/Finished and protect records with AES-128-GCM. Offers only
ECDHE with AES-128-GCM-SHA256 (RSA or ECDSA certificate), so the only cipher and
curve it needs are the ones already written. The server's signature over its
parameters is not checked -- this exists to fetch a page, not to authenticate.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import socket
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

from ..crypto import aesgcm, ec
from .constants import (
    CONTENT_TYPE_ALERT,
    CONTENT_TYPE_APPLICATION_DATA,
    CONTENT_TYPE_CHANGE_CIPHER_SPEC,
    CONTENT_TYPE_HANDSHAKE,
    EXT_ALPN,
    EXT_RENEGOTIATION_INFO,
    PROTOCOL_VERSIONS,
    alert_description,
)
from .messages import build_client_hello, parse_server_hello
from .probe import DEFAULT_TIMEOUT, _recv_exact
from .wire import Reader, TlsError

_TLS12 = PROTOCOL_VERSIONS[1]
_P256_GROUP = 0x0017
_CIPHERS = [0xC02F, 0xC02B]  # ECDHE-RSA / ECDHE-ECDSA with AES-128-GCM-SHA256
_SIGNATURE_SCHEMES = [0x0401, 0x0804, 0x0403, 0x0503, 0x0805]
_CHANGE_CIPHER_SPEC = bytes([CONTENT_TYPE_CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1])
_HS_SERVER_HELLO = 2
_HS_CERTIFICATE = 11
_HS_CERTIFICATE_REQUEST = 13
_HS_SERVER_KEY_EXCHANGE = 12
_HS_SERVER_HELLO_DONE = 14
_HS_FINISHED = 20
_HS_CERTIFICATE_STATUS = 22


# --------------------------------------------------------------------------- #
# The TLS 1.2 PRF and the AES-128-GCM record protection
# --------------------------------------------------------------------------- #


def _prf(secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
    """The TLS 1.2 PRF, P_SHA256 (RFC 5246 5)."""
    full_seed = label + seed
    output = b""
    a = full_seed
    while len(output) < length:
        a = hmac.new(secret, a, hashlib.sha256).digest()
        output += hmac.new(secret, a + full_seed, hashlib.sha256).digest()
    return output[:length]


def _seal(key: bytes, iv: bytes, sequence: int, content_type: int, plaintext: bytes) -> bytes:
    explicit = sequence.to_bytes(8, "big")
    aad = explicit + bytes([content_type, 3, 3]) + len(plaintext).to_bytes(2, "big")
    ciphertext, tag = aesgcm.encrypt(key, iv + explicit, plaintext, aad)
    payload = explicit + ciphertext + tag
    return bytes([content_type, 3, 3]) + len(payload).to_bytes(2, "big") + payload


def _open(
    key: bytes, iv: bytes, sequence: int, content_type: int, payload: bytes
) -> Optional[bytes]:
    if len(payload) < 24:  # 8-byte explicit nonce + 16-byte tag
        return None
    explicit, ciphertext, tag = payload[:8], payload[8:-16], payload[-16:]
    header = bytes([content_type, 3, 3]) + len(ciphertext).to_bytes(2, "big")
    aad = sequence.to_bytes(8, "big") + header
    return aesgcm.decrypt(key, iv + explicit, ciphertext, aad, tag)


# --------------------------------------------------------------------------- #
# The server flight
# --------------------------------------------------------------------------- #


def _read_record(sock: socket.socket) -> Optional[Tuple[bytes, bytes]]:
    header = _recv_exact(sock, 5)
    if header is None:
        return None
    length = int.from_bytes(header[3:5], "big")
    fragment = _recv_exact(sock, length)
    if fragment is None:
        return None
    return header, fragment


def _has_server_hello_done(buffer: bytes) -> bool:
    position = 0
    while position + 4 <= len(buffer):
        length = int.from_bytes(buffer[position + 1 : position + 4], "big")
        if position + 4 + length > len(buffer):
            return False
        if buffer[position] == _HS_SERVER_HELLO_DONE:
            return True
        position += 4 + length
    return False


def _server_ecdhe_point(message: bytes) -> Optional[bytes]:
    """The server's ephemeral EC point from a ServerKeyExchange, if it is P-256."""
    if len(message) < 4 or message[0] != 3:  # ECCurveType.named_curve
        return None
    if int.from_bytes(message[1:3], "big") != _P256_GROUP:
        return None
    length = message[3]
    point = message[4 : 4 + length]
    if length == 0 or len(point) != length:
        return None
    return point


def _parse_flight(buffer: bytes) -> Tuple[Optional[bytes], Optional[bytes], Optional[str]]:
    """Pull the server random and ECDHE point out of the accumulated flight."""
    server_random: Optional[bytes] = None
    server_point: Optional[bytes] = None
    position = 0
    while position + 4 <= len(buffer):
        length = int.from_bytes(buffer[position + 1 : position + 4], "big")
        message = buffer[position + 4 : position + 4 + length]
        if buffer[position] == _HS_SERVER_HELLO:
            server_random = message[2:34]
        elif buffer[position] == _HS_SERVER_KEY_EXCHANGE:
            server_point = _server_ecdhe_point(message)
        position += 4 + length
    if server_random is None or len(server_random) != 32:
        return None, None, "the server did not send a usable ServerHello"
    if server_point is None:
        return None, None, "the server offered no usable ECDHE parameters"
    return server_random, server_point, None


def _flight_requests_certificate(buffer: bytes) -> bool:
    """Whether the flight includes a CertificateRequest -- the server wants a client cert."""
    position = 0
    while position + 4 <= len(buffer):
        length = int.from_bytes(buffer[position + 1 : position + 4], "big")
        if buffer[position] == _HS_CERTIFICATE_REQUEST:
            return True
        position += 4 + length
    return False


def _read_flight(sock: socket.socket) -> Tuple[bytes, Optional[str]]:
    """Read handshake records up to ServerHelloDone; return the handshake bytes."""
    buffer = b""
    while not _has_server_hello_done(buffer):
        record = _read_record(sock)
        if record is None:
            return b"", "connection closed during the handshake"
        header, fragment = record
        if header[0] == CONTENT_TYPE_ALERT and len(fragment) >= 2:
            return b"", f"server sent an alert: {alert_description(fragment[1])}"
        if header[0] != CONTENT_TYPE_HANDSHAKE:
            return b"", f"unexpected TLS record type {header[0]}"
        buffer += fragment
    return buffer, None


# --------------------------------------------------------------------------- #
# The handshake and one request
# --------------------------------------------------------------------------- #


def _ecdh_premaster(private: int, point: bytes) -> Optional[bytes]:
    if len(point) != 65 or point[0] != 4:  # uncompressed X and Y
        return None
    peer = (int.from_bytes(point[1:33], "big"), int.from_bytes(point[33:], "big"))
    if not ec.on_curve(ec.P256, peer):
        return None
    shared = ec.scalar_mul(ec.P256, private, peer)
    if shared is None:
        return None
    return shared[0].to_bytes(32, "big")


def _read_response(
    sock: socket.socket, key: bytes, iv: bytes, is_complete: Callable[[bytes], bool]
) -> bytes:
    response = b""
    sequence = 0
    while not is_complete(response):
        record = _read_record(sock)
        if record is None:
            break
        header, payload = record
        if header[0] == CONTENT_TYPE_CHANGE_CIPHER_SPEC:
            sequence = 0  # the server's AEAD sequence restarts after its CCS
            continue
        if header[0] == CONTENT_TYPE_APPLICATION_DATA:
            response += _open(key, iv, sequence, CONTENT_TYPE_APPLICATION_DATA, payload) or b""
        sequence += 1
    return response


@dataclass
class _Secrets:
    client_random: bytes
    server_random: bytes
    private: int
    premaster: bytes


def _read_auth_verdict(sock: socket.socket) -> bool:
    """Read the server's reply to our certificate-less flight and say whether it *required*
    a client certificate: a fatal alert, a close or a reset means it refused (True); its
    first record after our Finished (its ChangeCipherSpec) means it accepted (False)."""
    try:
        record = _read_record(sock)
    except OSError:
        return True  # the server reset the connection: it refused the empty certificate
    if record is None:
        return True  # closed without completing
    return record[0][0] == CONTENT_TYPE_ALERT


def _classify_client_auth(
    sock: socket.socket, client_hello_body: bytes, flight: bytes, secrets: _Secrets
) -> bool:
    """Complete the handshake with an *empty* client certificate and watch: a server that
    requires one refuses it, one that merely requests it completes anyway."""
    master, client_key, _server_key, client_iv, _server_iv = _derive_keys(secrets)
    empty_certificate = bytes([_HS_CERTIFICATE]) + (3).to_bytes(3, "big") + (0).to_bytes(3, "big")
    cke = _client_key_exchange(secrets.private)
    finished = _client_finished(master, client_hello_body + flight + empty_certificate + cke)
    try:
        sock.sendall(_plaintext_record(CONTENT_TYPE_HANDSHAKE, empty_certificate))
        sock.sendall(_plaintext_record(CONTENT_TYPE_HANDSHAKE, cke))
        sock.sendall(_CHANGE_CIPHER_SPEC)
        sock.sendall(_seal(client_key, client_iv, 0, CONTENT_TYPE_HANDSHAKE, finished))
    except OSError:
        return True  # refused mid-flight -> a client certificate is required
    return _read_auth_verdict(sock)


def probe_client_certificate(
    host: str, port: int, sni: str = "", timeout: float = DEFAULT_TIMEOUT
) -> Tuple[Optional[bool], Optional[bool], Optional[str]]:
    """Whether a TLS 1.2 server requests a client certificate, and whether it requires one.

    Returns ``(requested, required, error)``. The CertificateRequest is a cleartext message
    in the server's first flight, so ``requested`` is read from that flight. To learn
    ``required``, the handshake is completed with an empty certificate: a server that
    enforces client auth refuses it (True), one that merely asks completes it (False).
    """
    hello = build_client_hello(
        _TLS12, _CIPHERS, server_name=sni, groups=[_P256_GROUP],
        signature_schemes=_SIGNATURE_SCHEMES,
    )
    try:
        sock = socket.create_connection((host, port), timeout)
    except OSError as exc:
        return None, None, f"connection failed: {exc}"
    try:
        secrets, flight, error = _run_handshake(sock, hello, timeout)
        if error is not None:
            return None, None, error
        if not _flight_requests_certificate(flight):
            return False, None, None
        assert secrets is not None  # no error means the ECDHE secrets were derived
        return True, _classify_client_auth(sock, hello[5:], flight, secrets), None
    except OSError as exc:
        return None, None, f"network error: {exc}"
    finally:
        sock.close()


def _flight_certificate_status(buffer: bytes) -> Optional[bytes]:
    """The OCSP response a CertificateStatus message staples to the flight (RFC 6066 8:
    status_type ocsp(1), then a 3-byte-length OCSPResponse), or ``None`` if absent."""
    position = 0
    while position + 4 <= len(buffer):
        length = int.from_bytes(buffer[position + 1 : position + 4], "big")
        if buffer[position] == _HS_CERTIFICATE_STATUS:
            body = buffer[position + 4 : position + 4 + length]
            if len(body) >= 4 and body[0] == 1:  # CertificateStatusType.ocsp
                return body[4 : 4 + int.from_bytes(body[1:4], "big")]
            return None
        position += 4 + length
    return None


def probe_ocsp_stapling(
    host: str, port: int, sni: str = "", timeout: float = DEFAULT_TIMEOUT
) -> Tuple[Optional[bool], Optional[bytes]]:
    """Whether a TLS 1.2 server staples an OCSP response, and the response itself.

    Offering a status_request makes a stapling server send a CertificateStatus message in
    its cleartext flight (RFC 6066 8), so reading that flight reveals it without finishing
    the handshake. Returns ``(stapled, response)``: ``(None, None)`` on error, otherwise
    ``stapled`` is whether a response was stapled and ``response`` its DER (for verifying)."""
    hello = build_client_hello(
        _TLS12, _CIPHERS, server_name=sni, groups=[_P256_GROUP],
        signature_schemes=_SIGNATURE_SCHEMES, offer_status_request=True,
    )
    try:
        sock = socket.create_connection((host, port), timeout)
    except OSError:
        return None, None
    try:
        sock.settimeout(timeout)
        sock.sendall(hello)
        flight, error = _read_flight(sock)
        if error is not None:
            return None, None
        response = _flight_certificate_status(flight)
        return response is not None, response
    except OSError:
        return None, None
    finally:
        sock.close()


def _headers_complete(reply: bytes) -> bool:
    """A one-request HTTP fetch is done once the response header block has arrived."""
    return b"\r\n\r\n" in reply


def _negotiated_alpn(flight: bytes) -> Optional[str]:
    """The ALPN protocol the server chose, from the ServerHello at the head of the flight.

    The ServerHello is always the flight's first handshake message (and ``_parse_flight``
    has already accepted one), so its ALPN extension -- if any -- is read straight from it.
    """
    try:
        length = int.from_bytes(flight[1:4], "big")
        server_hello = parse_server_hello(flight[4 : 4 + length])
        body = server_hello.extensions.get(EXT_ALPN)
        if body is None:
            return None
        return Reader(Reader(body).read_vector(2)).read_vector(1).decode("latin1")
    except (TlsError, IndexError):
        return None


def _run_handshake(
    sock: socket.socket, hello: bytes, timeout: float
) -> Tuple[Optional[_Secrets], bytes, Optional[str]]:
    """Send the ClientHello over an open ``sock``, read the flight, derive the ECDHE
    secrets. Returns ``(secrets, flight, error)``; ``OSError`` propagates to the caller."""
    sock.settimeout(timeout)
    sock.sendall(hello)
    flight, error = _read_flight(sock)
    if error is not None:
        return None, flight, error
    server_random, server_point, error = _parse_flight(flight)
    if error is not None:
        return None, flight, error
    assert server_random is not None and server_point is not None
    private = int.from_bytes(os.urandom(32), "big") % ec.P256.n
    premaster = _ecdh_premaster(private, server_point)
    if premaster is None:
        return None, flight, "the server's ECDHE point was invalid"
    return _Secrets(hello[11:43], server_random, private, premaster), flight, None


def fetch_over_tls12(
    host: str, port: int, request: bytes, sni: str = "", timeout: float = DEFAULT_TIMEOUT
) -> Tuple[bytes, Optional[str]]:
    """Complete a TLS 1.2 ECDHE handshake, send ``request`` and read the response."""
    hello = build_client_hello(
        _TLS12, _CIPHERS, server_name=sni, groups=[_P256_GROUP],
        signature_schemes=_SIGNATURE_SCHEMES,
    )
    try:
        sock = socket.create_connection((host, port), timeout)
    except OSError as exc:
        return b"", f"connection failed: {exc}"
    try:
        secrets, flight, error = _run_handshake(sock, hello, timeout)
        if error is not None:
            return b"", error
        assert secrets is not None
        return _finish(sock, hello[5:], flight, secrets, request, _headers_complete)
    except OSError as exc:
        return b"", f"network error: {exc}"
    finally:
        sock.close()


def exchange_over_tls12(
    host: str,
    port: int,
    request: bytes,
    sni: str,
    timeout: float,
    alpn: List[str],
    is_complete: Callable[[bytes], bool],
) -> Tuple[Optional[str], bytes, Optional[str]]:
    """Handshake offering ``alpn``, send ``request``, read until ``is_complete``.

    The TLS 1.2 counterpart of :func:`tls13.exchange_over_tls13`: returns
    ``(negotiated_alpn, response, error)`` so a caller can run a protocol chosen by
    ALPN (HTTP/2, a WebSocket upgrade, gRPC) over a 1.2-only server.
    """
    hello = build_client_hello(
        _TLS12, _CIPHERS, server_name=sni, groups=[_P256_GROUP],
        signature_schemes=_SIGNATURE_SCHEMES, alpn=alpn,
    )
    try:
        sock = socket.create_connection((host, port), timeout)
    except OSError as exc:
        return None, b"", f"connection failed: {exc}"
    try:
        secrets, flight, error = _run_handshake(sock, hello, timeout)
        if error is not None:
            return None, b"", error
        assert secrets is not None
        response, error = _finish(sock, hello[5:], flight, secrets, request, is_complete)
        return _negotiated_alpn(flight), response, error
    except OSError as exc:
        return None, b"", f"network error: {exc}"
    finally:
        sock.close()


def _derive_keys(secrets: _Secrets) -> Tuple[bytes, bytes, bytes, bytes, bytes]:
    """The master secret and the four AES-128-GCM keys/IVs from the ECDHE premaster."""
    randoms = secrets.client_random + secrets.server_random
    master = _prf(secrets.premaster, b"master secret", randoms, 48)
    key_block = _prf(master, b"key expansion", secrets.server_random + secrets.client_random, 40)
    return master, key_block[0:16], key_block[16:32], key_block[32:36], key_block[36:40]


def _client_key_exchange(private: int) -> bytes:
    """The ClientKeyExchange handshake message carrying our ephemeral ECDH point."""
    public = ec.scalar_mul(ec.P256, private, ec.P256.g)
    assert public is not None
    point = b"\x04" + public[0].to_bytes(32, "big") + public[1].to_bytes(32, "big")
    cke_body = bytes([len(point)]) + point
    return bytes([16]) + len(cke_body).to_bytes(3, "big") + cke_body


def _plaintext_record(content_type: int, payload: bytes) -> bytes:
    return bytes([content_type, 3, 3]) + len(payload).to_bytes(2, "big") + payload


def _client_verify_data(master: bytes, transcript: bytes) -> bytes:
    """The 12-byte client verify_data over the handshake ``transcript`` (RFC 5246 7.4.9)."""
    return _prf(master, b"client finished", hashlib.sha256(transcript).digest(), 12)


def _client_finished(master: bytes, transcript: bytes) -> bytes:
    """The client Finished handshake message over the handshake ``transcript`` so far."""
    verify_data = _client_verify_data(master, transcript)
    return bytes([_HS_FINISHED]) + len(verify_data).to_bytes(3, "big") + verify_data


def _finish(
    sock: socket.socket, client_hello_body: bytes, flight: bytes,
    secrets: _Secrets, request: bytes, is_complete: Callable[[bytes], bool],
) -> Tuple[bytes, Optional[str]]:
    master, client_key, server_key, client_iv, server_iv = _derive_keys(secrets)
    cke = _client_key_exchange(secrets.private)
    sock.sendall(_plaintext_record(CONTENT_TYPE_HANDSHAKE, cke))

    finished = _client_finished(master, client_hello_body + flight + cke)
    sock.sendall(_CHANGE_CIPHER_SPEC)
    sock.sendall(_seal(client_key, client_iv, 0, CONTENT_TYPE_HANDSHAKE, finished))

    sock.sendall(_seal(client_key, client_iv, 1, CONTENT_TYPE_APPLICATION_DATA, request))
    return _read_response(sock, server_key, server_iv, is_complete), None


# --------------------------------------------------------------------------- #
# Active probe: client-initiated renegotiation (CVE-2009-3555 / CVE-2011-1473)
# --------------------------------------------------------------------------- #


@dataclass
class RenegotiationResult:
    """The outcome of asking an established connection to renegotiate."""

    tested: bool  # whether a first handshake completed, so the probe could run at all
    accepted: bool = False  # the server began a new handshake (a ServerHello came back)
    secure: bool = False  # the first handshake negotiated RFC 5746 secure renegotiation
    detail: str = ""


def _flight_secure_renegotiation(flight: bytes) -> bool:
    """Whether the server's ServerHello carried renegotiation_info (RFC 5746 support)."""
    position = 0
    while position + 4 <= len(flight):
        length = int.from_bytes(flight[position + 1 : position + 4], "big")
        if flight[position] == _HS_SERVER_HELLO:
            hello = parse_server_hello(flight[position + 4 : position + 4 + length])
            return EXT_RENEGOTIATION_INFO in hello.extensions
        position += 4 + length
    return False


def _drain_server_finished(
    sock: socket.socket, server_key: bytes, server_iv: bytes
) -> Optional[int]:
    """Read the server's second flight through its encrypted Finished, so both ends are in
    the steady state. Returns the server's next AEAD sequence number, or ``None`` if the
    handshake did not complete (an alert, a close, or a Finished that does not decrypt)."""
    sequence = 0
    seen_ccs = False
    while True:
        record = _read_record(sock)
        if record is None:
            return None
        header, fragment = record
        if header[0] == CONTENT_TYPE_CHANGE_CIPHER_SPEC:
            seen_ccs = True  # the server's write cipher (and AEAD sequence) starts now
            sequence = 0
            continue
        if header[0] == CONTENT_TYPE_HANDSHAKE and not seen_ccs:
            continue  # a plaintext NewSessionTicket, sent before the server's CCS
        if header[0] == CONTENT_TYPE_HANDSHAKE and seen_ccs:
            if _open(server_key, server_iv, sequence, CONTENT_TYPE_HANDSHAKE, fragment) is None:
                return None  # the Finished did not decrypt: the derived keys are wrong
            return sequence + 1
        return None  # an alert, premature application data, or an unexpected record


def _classify_renegotiation(
    sock: socket.socket, server_key: bytes, server_iv: bytes, sequence: int
) -> Tuple[bool, str]:
    """Read the server's answer to a renegotiation ClientHello: a ServerHello means it
    accepted, an alert (or a close) means it refused."""
    record = _read_record(sock)
    if record is None:
        return False, "the server closed the connection instead of renegotiating"
    header, fragment = record
    opened = _open(server_key, server_iv, sequence, header[0], fragment)
    if header[0] == CONTENT_TYPE_HANDSHAKE and opened and opened[0] == _HS_SERVER_HELLO:
        return True, "the server began a new handshake (renegotiation accepted)"
    if header[0] == CONTENT_TYPE_ALERT and opened is not None and len(opened) >= 2:
        return False, f"the server refused to renegotiate: {alert_description(opened[1])}"
    return False, "the server did not renegotiate"


def probe_client_renegotiation(
    host: str, port: int, sni: str = "", timeout: float = DEFAULT_TIMEOUT
) -> RenegotiationResult:
    """Whether the server permits a client-initiated renegotiation on an open connection.

    Completes one ECDHE handshake, then sends a fresh ClientHello as an encrypted
    handshake record. A server that answers with a ServerHello renegotiates on demand: a
    denial-of-service surface (CVE-2011-1473), and -- if the first handshake did not
    negotiate RFC 5746 secure renegotiation -- the plaintext-injection hole of
    CVE-2009-3555. A server that refuses answers with an alert or closes.
    """
    hello = build_client_hello(
        _TLS12, _CIPHERS, server_name=sni, groups=[_P256_GROUP],
        signature_schemes=_SIGNATURE_SCHEMES,
    )
    try:
        sock = socket.create_connection((host, port), timeout)
    except OSError as exc:
        return RenegotiationResult(tested=False, detail=f"connection failed: {exc}")
    try:
        secrets, flight, error = _run_handshake(sock, hello, timeout)
        if error is not None:
            return RenegotiationResult(tested=False, detail=error)
        assert secrets is not None
        secure = _flight_secure_renegotiation(flight)
        master, client_key, server_key, client_iv, server_iv = _derive_keys(secrets)
        cke = _client_key_exchange(secrets.private)
        sock.sendall(_plaintext_record(CONTENT_TYPE_HANDSHAKE, cke))
        transcript = hello[5:] + flight + cke
        verify_data = _client_verify_data(master, transcript)
        sock.sendall(_CHANGE_CIPHER_SPEC)
        sock.sendall(_seal(client_key, client_iv, 0, CONTENT_TYPE_HANDSHAKE,
                           _client_finished(master, transcript)))
        server_sequence = _drain_server_finished(sock, server_key, server_iv)
        if server_sequence is None:
            return RenegotiationResult(tested=False, detail="the first handshake did not complete")
        # RFC 5746: a renegotiation hello to a secure-reneg server must carry the previous
        # client verify_data; to a legacy server, an ordinary (empty renegotiation_info) hello.
        reneg = build_client_hello(
            _TLS12, _CIPHERS, server_name=sni, groups=[_P256_GROUP],
            signature_schemes=_SIGNATURE_SCHEMES,
            renegotiation_info=verify_data if secure else None,
        )
        sock.sendall(_seal(client_key, client_iv, 1, CONTENT_TYPE_HANDSHAKE, reneg[5:]))
        accepted, detail = _classify_renegotiation(sock, server_key, server_iv, server_sequence)
        return RenegotiationResult(tested=True, accepted=accepted, secure=secure, detail=detail)
    except OSError as exc:
        return RenegotiationResult(tested=False, detail=f"network error: {exc}")
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# Finite-field DH parameter strength (Logjam, CVE-2015-4000)
# --------------------------------------------------------------------------- #

#: DHE_RSA suites, including the 40-bit export one, offered to make the server reveal its
#: finite-field DH prime in the ServerKeyExchange.
_DHE_CIPHERS = [0x009F, 0x009E, 0x006B, 0x0067, 0x0039, 0x0033, 0x0016, 0x0015, 0x0014]
_FFDHE_GROUPS = [0x0100, 0x0101, 0x0102, 0x0103, 0x0104]  # ffdhe2048..ffdhe8192 (RFC 7919)


def _dhe_prime_bits(message: bytes) -> Optional[int]:
    """The bit length of the dh_p in a DHE ServerKeyExchange body, or ``None``."""
    if len(message) < 2:
        return None
    prime_length = int.from_bytes(message[:2], "big")
    if prime_length == 0 or len(message) < 2 + prime_length:
        return None
    return int.from_bytes(message[2 : 2 + prime_length], "big").bit_length()


def _dhe_prime_bits_from_flight(flight: bytes) -> Optional[int]:
    position = 0
    while position + 4 <= len(flight):
        length = int.from_bytes(flight[position + 1 : position + 4], "big")
        if flight[position] == _HS_SERVER_KEY_EXCHANGE:
            return _dhe_prime_bits(flight[position + 4 : position + 4 + length])
        position += 4 + length
    return None


def probe_dh_parameters(
    host: str, port: int, sni: str = "", timeout: float = DEFAULT_TIMEOUT
) -> Optional[int]:
    """The bit length of the finite-field DH prime a TLS 1.2 server uses for DHE.

    Offers DHE_RSA suites (including the export one) and reads the prime the server sends
    in its ServerKeyExchange -- so a weak or Logjam-class prime (CVE-2015-4000) is caught
    without completing the exchange. ``None`` when the server negotiates no DHE suite, so
    there is no finite-field prime to weigh (an ECDHE-only server is not at issue)."""
    hello = build_client_hello(
        _TLS12, _DHE_CIPHERS, server_name=sni, groups=_FFDHE_GROUPS,
        signature_schemes=_SIGNATURE_SCHEMES,
    )
    try:
        sock = socket.create_connection((host, port), timeout)
    except OSError:
        return None
    try:
        sock.settimeout(timeout)
        sock.sendall(hello)
        flight, error = _read_flight(sock)
        if error is not None:
            return None
        return _dhe_prime_bits_from_flight(flight)
    except OSError:
        return None
    finally:
        sock.close()
