"""Detecting SSL 2.0 support -- the prerequisite for DROWN (CVE-2016-0800).

SSL 2.0 is catastrophically broken (weak MACs, no handshake integrity, export
ciphers) and, worse, a server that still speaks it lets an attacker decrypt *modern*
TLS_RSA sessions that share the RSA key: the DROWN cross-protocol attack. So any hint
of SSL 2.0 is a critical finding on its own.

It cannot ride the TLS version enumeration: an SSL 2.0 CLIENT-HELLO is not a TLS
record but the older SSLv2 message framing (a 2-byte, high-bit-set length header). So
this sends one by hand and looks for the one unambiguous positive: an SSLv2
SERVER-HELLO in reply. Anything else -- a TLS alert, a close, silence -- means the
server does not speak SSL 2.0.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from typing import List

from .probe import DEFAULT_TIMEOUT

_SSL2_CLIENT_HELLO = 0x01
_SSL2_SERVER_HELLO = 0x04
_SSL2_VERSION = 0x0002
#: A handful of SSL 2.0 cipher specs (3 bytes each) to make the CLIENT-HELLO well-formed;
#: the exact set does not matter, only that the server answers with a SERVER-HELLO.
_SSL2_CIPHERS = [0x010080, 0x020080, 0x030080, 0x040080, 0x060040, 0x0700C0]
#: The 40-bit export SSL 2.0 ciphers: their presence makes the DROWN attack practical.
_SSL2_EXPORT_CIPHERS = {0x020080, 0x040080}
_MAX_RECORD = 16384  # cap the SERVER-HELLO read (it carries the server certificate)


@dataclass
class Sslv2Result:
    """The outcome of the SSL 2.0 probe."""

    supported: bool = False
    reached: bool = False  # the server answered at all (an SSL-2.0-only server is reachable)
    export_ciphers: bool = False  # the server offers 40-bit export ciphers (practical DROWN)
    error: str | None = None


def _client_hello() -> bytes:
    """A well-formed SSL 2.0 CLIENT-HELLO in the SSLv2 record framing."""
    ciphers = b"".join(spec.to_bytes(3, "big") for spec in _SSL2_CIPHERS)
    challenge = os.urandom(16)
    body = (
        bytes([_SSL2_CLIENT_HELLO])
        + _SSL2_VERSION.to_bytes(2, "big")
        + len(ciphers).to_bytes(2, "big")  # cipher-spec length
        + (0).to_bytes(2, "big")  # session-id length (none)
        + len(challenge).to_bytes(2, "big")  # challenge length
        + ciphers
        + challenge
    )
    return bytes([0x80 | (len(body) >> 8), len(body) & 0xFF]) + body  # 2-byte SSLv2 header


def _recv(sock: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            break
        data += chunk
    return data


def _read_record(sock: socket.socket) -> bytes:
    """Read one SSLv2 short record: a 2-byte length header (high bit set) then its body."""
    header = _recv(sock, 2)
    if len(header) < 2 or not header[0] & 0x80:
        return header  # not an SSLv2 short record
    length = ((header[0] & 0x7F) << 8) | header[1]
    return header + _recv(sock, min(length, _MAX_RECORD))


def _server_ciphers(record: bytes) -> List[int]:
    """The 3-byte cipher specs a SERVER-HELLO lists (RFC-less SSLv2 wire), or []."""
    body = record[2:]  # after the 2-byte record header
    if len(body) < 11 or body[0] != _SSL2_SERVER_HELLO:
        return []
    certificate_length = int.from_bytes(body[5:7], "big")
    specs_length = int.from_bytes(body[7:9], "big")
    start = 11 + certificate_length  # past the fixed fields and the certificate
    specs = body[start : start + specs_length]
    return [int.from_bytes(specs[i : i + 3], "big") for i in range(0, len(specs) - 2, 3)]


def probe_sslv2(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> Sslv2Result:
    """Whether ``host:port`` speaks SSL 2.0, and whether it offers export ciphers. The
    server answering with an SSLv2 SERVER-HELLO means it is supported (and DROWN-exposed);
    an export cipher in that SERVER-HELLO makes the attack practical."""
    try:
        sock = socket.create_connection((host, port), timeout)
    except OSError as exc:
        return Sslv2Result(error=f"connection failed: {exc}")
    try:
        sock.settimeout(timeout)
        sock.sendall(_client_hello())
        response = _read_record(sock)
    except OSError as exc:
        return Sslv2Result(error=f"network error: {exc}")
    finally:
        sock.close()
    if not response:
        return Sslv2Result()  # connected, but the server said nothing
    # "Reached" must mean the server answered in SSL/TLS framing -- an SSLv2 record (high bit
    # set) or a TLS record (content type 20-24, version 0x03xx). A server that replies to our
    # SSLv2 hello in cleartext (an HTTP 400) is NOT a reachable TLS endpoint, and treating it
    # as one would wrongly suppress the plaintext-HTTP check for a server serving HTTP on 443.
    sslv2_framing = bool(response[0] & 0x80)
    tls_framing = len(response) >= 2 and 20 <= response[0] <= 24 and response[1] == 0x03
    reached = sslv2_framing or tls_framing
    # An SSLv2 record with a SERVER-HELLO message type means SSL 2.0 is actually supported.
    supported = sslv2_framing and len(response) >= 3 and response[2] == _SSL2_SERVER_HELLO
    export = supported and bool(set(_server_ciphers(response)) & _SSL2_EXPORT_CIPHERS)
    return Sslv2Result(supported=supported, reached=reached, export_ciphers=export)
