"""Probing a server for HTTP/3 reachability over QUIC.

Send one client Initial (``initial.py``) over UDP and watch for an answer. A
server that speaks QUIC replies with a QUIC version-1 long-header packet -- its
own Initial or a Retry; anything else, or silence, means no HTTP/3 here. This is
a live dial, not the Alt-Svc *advertisement* the HTTP layer reads.
"""

from __future__ import annotations

import os
import socket
from typing import List, Optional, Tuple

from ..models import QuicTransportParameters
from ..tls.messages import ServerHello
from ..tls.probe import DEFAULT_TIMEOUT
from .handshake import read_negotiation
from .initial import build_initial
from .keys import VERSION_1, VERSION_2, QuicVersion, initial_keys

_KNOWN_VERSIONS = (VERSION_1.number.to_bytes(4, "big"), VERSION_2.number.to_bytes(4, "big"))


def _is_quic_long_header(data: bytes) -> bool:
    """Whether ``data`` starts a QUIC v1 or v2 long-header packet (RFC 9000/9369)."""
    return len(data) >= 5 and (data[0] & 0xC0) == 0xC0 and data[1:5] in _KNOWN_VERSIONS


def probe_http3(
    host: str, port: int, sni: str = "", timeout: float = DEFAULT_TIMEOUT
) -> Optional[bool]:
    """Whether the server answers a QUIC Initial on ``port`` -- i.e. speaks HTTP/3.

    ``True`` when a QUIC packet comes back, ``False`` on silence or a non-QUIC
    reply, ``None`` when the probe could not even be sent.
    """
    initial = build_initial(os.urandom(8), os.urandom(8), sni or host)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        # Connect so the kernel reports ICMP port-unreachable as a refusal, rather
        # than making a closed UDP port wait out the whole timeout.
        sock.connect((host, port))
        sock.send(initial.packet)
        response = sock.recv(2048)
    except (socket.timeout, ConnectionRefusedError):
        return False
    except OSError:
        return None
    finally:
        sock.close()
    return _is_quic_long_header(response)


def _negotiate_version(
    host: str, port: int, sni: str, timeout: float, version: QuicVersion
) -> Tuple[Optional[ServerHello], Optional[QuicTransportParameters]]:
    """Dial one QUIC ``version`` and read what it negotiates."""
    destination_connection_id = os.urandom(8)
    initial = build_initial(destination_connection_id, os.urandom(8), sni or host, version=version)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    datagrams: List[bytes] = []
    try:
        sock.connect((host, port))
        sock.send(initial.packet)
        datagrams.append(sock.recv(2048))  # the first reply, up to the full timeout
        sock.settimeout(min(timeout, 0.5))  # the rest of the flight arrives in a burst
        while True:
            try:
                datagrams.append(sock.recv(2048))
            except OSError:
                break
    except OSError:
        return None, None
    finally:
        sock.close()
    return read_negotiation(
        datagrams, initial.private, initial.client_hello,
        initial_keys(destination_connection_id, version).server, version,
    )


def negotiated_http3(
    host: str, port: int, sni: str = "", timeout: float = DEFAULT_TIMEOUT
) -> Tuple[Optional[ServerHello], Optional[QuicTransportParameters]]:
    """What a QUIC/HTTP-3 server negotiates on ``port``: its ServerHello and params.

    A deeper dial than :func:`probe_http3`: it reads the whole server flight, decrypts
    the Initial for the cipher and key-share group HTTP/3 chose, then completes the
    key schedule to decrypt the Handshake packets and read the transport parameters.
    QUIC v1 (RFC 9000) is tried first, then v2 (RFC 9369) for a v2-only server.
    ``(None, None)`` when the server does not answer or is not QUIC; the parameters
    are ``None`` when the Handshake could not be completed.
    """
    server_hello, parameters = _negotiate_version(host, port, sni, timeout, VERSION_1)
    if server_hello is None:  # not v1: a v2-only server answers a v2 Initial instead
        return _negotiate_version(host, port, sni, timeout, VERSION_2)
    return server_hello, parameters
