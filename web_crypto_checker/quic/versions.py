"""Discovering which QUIC versions a server offers, via Version Negotiation (RFC 9000 6).

A client that sends an Initial naming a version the server does not support gets back a
Version Negotiation packet listing every version the server *does* support. So sending an
Initial with a reserved (GREASE) version -- one no server implements -- forces the server
to enumerate its versions, revealing QUIC v1 (RFC 9000), QUIC v2 (RFC 9369) and any
drafts without the client having to speak each one.
"""

from __future__ import annotations

import os
import socket
from typing import List, Optional

from ..tls.probe import DEFAULT_TIMEOUT
from .initial import build_initial
from .keys import INITIAL_SALT_V1, QuicVersion

QUIC_V1 = 0x00000001  # RFC 9000
QUIC_V2 = 0x6B3343CF  # RFC 9369
# A reserved version (RFC 9000 15 forces the pattern 0x?a?a?a?a to stay unassigned): no
# server implements it, so an Initial naming it forces a Version Negotiation reply. The
# framing does not matter -- the server rejects on the version before reading the body --
# so it borrows v1's salt and labels.
_FORCE_VN = QuicVersion(0x1A1A1A1A, INITIAL_SALT_V1, b"quic", 0x00, 0x20)


def is_reserved_version(version: int) -> bool:
    """Whether a version is a reserved GREASE value (RFC 9000 15), meant to be ignored."""
    return version & 0x0F0F0F0F == 0x0A0A0A0A


def _parse_version_negotiation(data: bytes) -> Optional[List[int]]:
    """The versions listed in a Version Negotiation packet -- a long-header packet whose
    version field is zero (RFC 9000 17.2.1) -- or ``None`` when ``data`` is not one."""
    if len(data) < 7 or not (data[0] & 0x80) or data[1:5] != b"\x00\x00\x00\x00":
        return None
    try:
        offset = 5
        offset += 1 + data[offset]  # Destination Connection ID (length prefix + id)
        offset += 1 + data[offset]  # Source Connection ID
    except IndexError:
        return None
    versions = []
    while offset + 4 <= len(data):  # the rest is a list of 4-byte versions
        versions.append(int.from_bytes(data[offset : offset + 4], "big"))
        offset += 4
    return versions


def probe_quic_versions(
    host: str, port: int, sni: str = "", timeout: float = DEFAULT_TIMEOUT
) -> Optional[List[int]]:
    """The QUIC versions ``host:port`` offers, from a forced Version Negotiation, or
    ``None`` when it sends none (not QUIC, or silent)."""
    initial = build_initial(os.urandom(8), os.urandom(8), sni or host, version=_FORCE_VN)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.send(initial.packet)
        response = sock.recv(2048)
    except OSError:
        return None
    finally:
        sock.close()
    return _parse_version_negotiation(response)
