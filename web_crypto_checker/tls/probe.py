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
from typing import Callable, List, Optional, Tuple

from .constants import (
    CONTENT_TYPE_ALERT,
    CONTENT_TYPE_HANDSHAKE,
    HANDSHAKE_TYPE_SERVER_HELLO,
)
from .messages import ServerHello, parse_alert, parse_server_hello, read_handshake
from .wire import Reader, TlsError

DEFAULT_TIMEOUT = 6.0

_ALERT_LEVEL_FATAL = 2  # AlertLevel.fatal (RFC 5246 7.2); level 1 is warning
_ALERT_CLOSE_NOTIFY = 0  # AlertDescription.close_notify: a warning that still ends the connection

#: How a probe opens its TCP connection: ``(address, timeout) -> socket``, the
#: shape of ``socket.create_connection``. The default connects directly, for a
#: port that speaks TLS from the first byte. A caller can pass its own to reach
#: TLS a different way -- the mail scanner passes one that drives the SMTP/IMAP/
#: POP3 STARTTLS dialogue first and returns the upgraded socket, so the same
#: enumeration runs unchanged over an in-place upgrade.
Connect = Callable[[Tuple[str, int], float], socket.socket]


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
                level, description = parse_alert(fragment)
            except TlsError as exc:
                return ProbeResult(error=f"malformed alert: {exc}")
            # A warning-level alert does not end the handshake (RFC 5246 7.2 / RFC 8446 6.1): a
            # server that does not recognise the SNI may send a warning unrecognized_name(112) and
            # then proceed with the ServerHello. Treating that as terminal blanked the whole probe,
            # so the endpoint's real (possibly weak) TLS went unseen and graded UNKNOWN, slipping
            # past --fail-on-insecure. Only a fatal alert or close_notify actually stops the server.
            if level == _ALERT_LEVEL_FATAL or description == _ALERT_CLOSE_NOTIFY:
                return ProbeResult(alert=(level, description))
            continue

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
    connect: Optional[Connect] = None,
) -> ProbeResult:
    """Connect, send ``client_hello`` and return the classified response.

    ``connect`` opens the connection; it defaults to a direct TCP connection.
    Passing one that first drives a STARTTLS upgrade lets the same probe reach a
    server that speaks TLS only after an in-place upgrade.
    """
    opener: Connect = connect if connect is not None else socket.create_connection
    try:
        sock = opener((host, port), timeout)
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
