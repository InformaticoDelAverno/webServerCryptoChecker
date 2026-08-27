"""Enumerating what a server offers: which protocol versions, which suites.

The method is the one every scanner uses and none can avoid: a ServerHello
names one cipher suite, so to learn the whole set you offer everything, note the
choice, drop it, and ask again until the server runs out of things it likes and
sends a handshake_failure. The order the choices come back in is the server's
own preference, which is worth as much as the set itself.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..models import CipherSuite, ProtocolSupport
from .constants import (
    LEGACY_CIPHER_SUITES,
    PROTOCOL_VERSIONS,
    SIGNATURE_SCHEMES,
    TLS13_CIPHER_SUITES,
    ProtocolVersionSpec,
    cipher_suite_name,
)
from .messages import build_client_hello
from .probe import DEFAULT_TIMEOUT, ProbeResult, send_client_hello

_X25519_CODE = 0x001D
#: Groups offered on every probe: x25519, secp256r1/384r1/521r1, ffdhe2048/3072.
#: Written as codes rather than looked up, so there is no "unknown group" arm
#: that never runs to leave a branch uncovered.
_DEFAULT_GROUP_CODES = [0x001D, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]
_ALL_SIGNATURE_SCHEMES = list(SIGNATURE_SCHEMES)


@dataclass
class EnumerationResult:
    """The protocol and cipher findings for one endpoint."""

    protocols: List[ProtocolSupport] = field(default_factory=list)
    cipher_suites: List[CipherSuite] = field(default_factory=list)
    reachable: bool = False
    error: Optional[str] = None


def _cipher_ids_for(version: ProtocolVersionSpec) -> List[int]:
    return list(TLS13_CIPHER_SUITES) if version.is_tls13 else list(LEGACY_CIPHER_SUITES)


def _probe(
    host: str,
    port: int,
    sni: str,
    version: ProtocolVersionSpec,
    cipher_ids: List[int],
    timeout: float,
) -> ProbeResult:
    key_share = (_X25519_CODE, os.urandom(32)) if version.is_tls13 else None
    hello = build_client_hello(
        version,
        cipher_ids,
        server_name=sni,
        groups=_DEFAULT_GROUP_CODES,
        signature_schemes=_ALL_SIGNATURE_SCHEMES,
        key_share=key_share,
    )
    return send_client_hello(host, port, hello, timeout)


def _enumerate_version(
    host: str,
    port: int,
    sni: str,
    version: ProtocolVersionSpec,
    timeout: float,
) -> Tuple[List[int], bool, Optional[str]]:
    """Return ``(cipher_ids_in_server_order, reached, error)`` for one version."""
    remaining = _cipher_ids_for(version)
    chosen: List[int] = []
    reached = False
    error: Optional[str] = None

    # Each turn either removes one suite from ``remaining`` or breaks, so the
    # loop ends when the server likes nothing left (it exits here) or refuses
    # (it breaks) -- never spins.
    while remaining:
        result = _probe(host, port, sni, version, remaining, timeout)
        server_hello = result.server_hello
        if server_hello is None:
            if result.alert is None:
                error = result.error  # a network or parse failure, not a refusal
            else:
                reached = True  # an alert is still a response
            break
        reached = True
        if server_hello.negotiated_version != version.code:
            break  # the server negotiated a different version: not this one
        suite = server_hello.cipher_suite
        if suite not in remaining:
            break  # the server picked something it was not offered; do not loop
        chosen.append(suite)
        remaining.remove(suite)

    return chosen, reached, error


def enumerate_endpoint(
    host: str,
    port: int,
    sni: str = "",
    timeout: float = DEFAULT_TIMEOUT,
) -> EnumerationResult:
    """Enumerate protocol versions and cipher suites for one endpoint."""
    protocols: List[ProtocolSupport] = []
    cipher_map: Dict[int, CipherSuite] = {}
    reachable = False
    first_error: Optional[str] = None

    for version in PROTOCOL_VERSIONS:
        chosen, reached, error = _enumerate_version(host, port, sni, version, timeout)
        reachable = reachable or reached
        if error is not None and first_error is None:
            first_error = error
        protocols.append(
            ProtocolSupport(name=version.name, id=version.id, supported=bool(chosen), error=error)
        )
        for suite_id in chosen:
            suite = cipher_map.get(suite_id)
            if suite is None:
                suite = CipherSuite(name=cipher_suite_name(suite_id), id=f"0x{suite_id:04X}")
                cipher_map[suite_id] = suite
            suite.protocols.append(version.id)

    error = None if reachable else (first_error or "no TLS response on any version")
    return EnumerationResult(
        protocols=protocols,
        cipher_suites=list(cipher_map.values()),
        reachable=reachable,
        error=error,
    )
