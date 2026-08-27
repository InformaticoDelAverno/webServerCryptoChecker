"""Enumerating the key-exchange groups a TLS 1.3 server accepts, and its PQ stance.

The trick avoids generating a single elliptic-curve point. A ClientHello with an
empty ``key_share`` but a full ``supported_groups`` forces the server to answer
with a HelloRetryRequest naming its preferred group (RFC 8446 4.2.8). Offer
everything, note the group it asks for, drop it, and ask again: the groups come
back in the server's own preference order, and the server sends a
handshake_failure once it likes nothing left. From that list falls out whether
the server offers a post-quantum hybrid -- the thing that makes 1.3 quantum-safe.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ..models import KeyExchangeGroup, PostQuantumStatus
from .constants import (
    NAMED_GROUPS,
    PROTOCOL_VERSIONS,
    SIGNATURE_SCHEMES,
    TLS13_CIPHER_SUITES,
    NamedGroup,
)
from .messages import build_client_hello
from .probe import DEFAULT_TIMEOUT, ProbeResult, send_client_hello

_TLS13 = PROTOCOL_VERSIONS[0]
_TLS13_CIPHER_IDS = list(TLS13_CIPHER_SUITES)
_ALL_SIGNATURE_SCHEMES = list(SIGNATURE_SCHEMES)


def _probe(host: str, port: int, sni: str, offered: List[int], timeout: float) -> ProbeResult:
    hello = build_client_hello(
        _TLS13,
        _TLS13_CIPHER_IDS,
        server_name=sni,
        groups=offered,
        signature_schemes=_ALL_SIGNATURE_SCHEMES,
        empty_key_share=True,
    )
    return send_client_hello(host, port, hello, timeout)


def _post_quantum_status(total: int, post_quantum: int) -> PostQuantumStatus:
    if total == 0:
        return PostQuantumStatus.UNKNOWN
    if post_quantum == 0:
        return PostQuantumStatus.NOT_READY
    if post_quantum == total:
        return PostQuantumStatus.ENFORCED
    return PostQuantumStatus.READY


def enumerate_groups(
    host: str, port: int, sni: str = "", timeout: float = DEFAULT_TIMEOUT
) -> Tuple[List[KeyExchangeGroup], PostQuantumStatus, Optional[str]]:
    """Return ``(groups_in_server_preference, post_quantum_status, error)``."""
    remaining: Dict[int, NamedGroup] = {group.code: group for group in NAMED_GROUPS}
    chosen: List[KeyExchangeGroup] = []
    post_quantum = 0
    error: Optional[str] = None

    # Each turn removes one group from ``remaining`` or breaks: it ends when the
    # server likes nothing left (a handshake_failure, so no ServerHello) or gives
    # a plain ServerHello -- never spins.
    while remaining:
        result = _probe(host, port, sni, list(remaining), timeout)
        server_hello = result.server_hello
        if server_hello is None:
            if result.alert is None:
                error = result.error  # a network or parse failure, not a refusal
            break
        if not server_hello.is_hello_retry_request:
            break  # a normal ServerHello: not a 1.3 group negotiation
        code = server_hello.selected_group
        if code is None or code not in remaining:
            break  # asked for nothing, or a group it was not offered; do not loop
        spec = remaining.pop(code)
        if spec.post_quantum:
            post_quantum += 1
        chosen.append(
            KeyExchangeGroup(name=spec.name, id=code, bits=spec.bits, protocols=["tls1_3"])
        )

    return chosen, _post_quantum_status(len(chosen), post_quantum), error
