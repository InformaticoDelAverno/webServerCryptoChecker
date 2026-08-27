"""The network layer: send a ClientHello, read the first thing the server says.

One probe is one TCP connection. It writes the ClientHello it is given and
reads records until it has a whole ServerHello or an alert, then stops -- it
never speaks again, so it never authenticates and never completes a handshake.
Every network and parsing failure is turned into a :class:`ProbeResult` with an
``error`` rather than an exception, so a scan of thousands of endpoints is not
ended by one that misbehaves.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .constants import (
    CONTENT_TYPE_ALERT,
    CONTENT_TYPE_HANDSHAKE,
    HANDSHAKE_TYPE_SERVER_HELLO,
)
from .messages import ServerHello, parse_alert, parse_server_hello, read_handshake
from .wire import Reader, TlsError

DEFAULT_TIMEOUT = 6.0


@dataclass
class ProbeResult:
    """What one ClientHello drew out of the server."""

    server_hello: Optional[ServerHello] = None
    alert: Optional[Tuple[int, int]] = None
    error: Optional[str] = None

    @property
    def accepted(self) -> bool:
        """The server answered with a ServerHello (or HelloRetryRequest)."""
        return self.server_hello is not None


def _recv_exact(sock: socket.socket, count: int) -> Optional[bytes]:
    """Read exactly ``count`` bytes, or ``None`` if the peer stops first."""
    chunks: List[bytes] = []
    remaining = count
    while remaining > 0:
        try:
            chunk = sock.recv(remaining)
        except socket.timeout:
            return None
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_response(sock: socket.socket) -> ProbeResult:
    """Read records until a ServerHello or alert is in hand."""
    handshake = b""
    while True:
        header = _recv_exact(sock, 5)
        if header is None:
            return ProbeResult(error="server closed the connection without responding")
        content_type = header[0]
        length = int.from_bytes(header[3:5], "big")
        fragment = _recv_exact(sock, length) if length else b""
        if fragment is None:
            return ProbeResult(error="truncated TLS record")

        if content_type == CONTENT_TYPE_ALERT:
            try:
                return ProbeResult(alert=parse_alert(fragment))
            except TlsError as exc:
                return ProbeResult(error=f"malformed alert: {exc}")

        if content_type != CONTENT_TYPE_HANDSHAKE:
            return ProbeResult(error=f"unexpected TLS record type {content_type}")

        handshake += fragment
        try:
            message_type, body = read_handshake(Reader(handshake))
        except TlsError:
            continue  # the ServerHello spans more records; read another
        if message_type != HANDSHAKE_TYPE_SERVER_HELLO:
            return ProbeResult(error=f"unexpected handshake message {message_type}")
        try:
            return ProbeResult(server_hello=parse_server_hello(body))
        except TlsError as exc:
            return ProbeResult(error=f"malformed ServerHello: {exc}")


def send_client_hello(
    host: str,
    port: int,
    client_hello: bytes,
    timeout: float = DEFAULT_TIMEOUT,
) -> ProbeResult:
    """Connect, send ``client_hello`` and return the classified response."""
    try:
        sock = socket.create_connection((host, port), timeout)
    except OSError as exc:
        return ProbeResult(error=f"connection failed: {exc}")
    try:
        sock.settimeout(timeout)
        sock.sendall(client_hello)
        return _read_response(sock)
    except OSError as exc:
        return ProbeResult(error=f"network error: {exc}")
    finally:
        sock.close()
