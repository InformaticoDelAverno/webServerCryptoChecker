"""Enumerating which TLS 1.3 signature schemes a server will sign with.

One scheme at a time: offer only that scheme, with a real key share so the server
would complete rather than ask to retry, and read the answer. A ServerHello means
the server's certificate key can sign with it; a handshake_failure means it
cannot. The set that comes back is what the server would put in its
CertificateVerify -- and shows, for instance, whether it still accepts the legacy
PKCS#1 schemes that TLS 1.3 was meant to retire.
"""

from __future__ import annotations

import os
from typing import List, Optional, Tuple

from ..crypto.x25519 import x25519_base
from .constants import PROTOCOL_VERSIONS, SIGNATURE_SCHEMES, TLS13_CIPHER_SUITES
from .messages import build_client_hello
from .probe import DEFAULT_TIMEOUT, Connect, ProbeResult, send_client_hello

_TLS13 = PROTOCOL_VERSIONS[0]
_X25519 = 0x001D
_TLS13_CIPHER_IDS = list(TLS13_CIPHER_SUITES)
_TLS13_VERSION_CODE = 0x0304


def _probe(
    host: str,
    port: int,
    sni: str,
    scheme: int,
    timeout: float,
    connect: Optional[Connect] = None,
) -> ProbeResult:
    hello = build_client_hello(
        _TLS13,
        _TLS13_CIPHER_IDS,
        server_name=sni,
        groups=[_X25519],
        signature_schemes=[scheme],
        key_share=(_X25519, x25519_base(os.urandom(32))),
    )
    return send_client_hello(host, port, hello, timeout, connect=connect)


def enumerate_signature_algorithms(
    host: str,
    port: int,
    sni: str = "",
    timeout: float = DEFAULT_TIMEOUT,
    connect: Optional[Connect] = None,
) -> Tuple[List[str], Optional[str]]:
    """Return ``(schemes_the_server_will_sign_with, error)`` -- error only when no
    probe drew any response at all."""
    supported: List[str] = []
    reached = False
    error: Optional[str] = None
    for code, name in SIGNATURE_SCHEMES.items():
        result = _probe(host, port, sni, code, timeout, connect=connect)
        server_hello = result.server_hello
        if server_hello is None:
            if result.alert is not None:
                reached = True  # a handshake_failure is still a response
            elif error is None:
                error = result.error
            continue
        reached = True
        if server_hello.is_hello_retry_request:
            continue  # asked to retry rather than accept outright
        if server_hello.negotiated_version != _TLS13_VERSION_CODE:
            continue  # negotiated something other than 1.3: not a 1.3 capability
        supported.append(name)

    if not reached:
        return [], error
    return supported, None
