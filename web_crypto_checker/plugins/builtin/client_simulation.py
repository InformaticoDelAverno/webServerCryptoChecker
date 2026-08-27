"""Which well-known clients could complete a handshake with this server.

SSL Labs and testssl.sh answer this by re-negotiating with each client's real
ClientHello. A read-only plugin cannot open a socket, but it does not need to: the
scan already enumerated every protocol version, cipher suite and key-exchange group
the server accepts, so the answer is a *computation* over what was observed -- a
client connects when it shares a protocol version and a cipher family with the
server. That is exactly what a plugin is for.

This is an approximate capability model (each client is a curated profile of the
protocol versions and cipher families it supports), reported as an observation --
it never changes the grade. Clients that cannot connect are usually meant to be
dropped (an ancient browser), so the finding is informational: it says who would
be turned away, and why, so the compatibility trade-off is visible.
"""

from __future__ import annotations

from typing import Any, List, Optional

from web_crypto_checker.plugins import Detected, ServerView

ID = "CLIENT-SIMULATION"
NAME = "Client compatibility (simulated)"
SEVERITY = "info"
DESCRIPTION = (
    "Well-known clients that could not complete a handshake with this server, from an "
    "approximate model of each client's protocol and cipher-family support. Turning away an "
    "obsolete client is often intended; this only makes the trade-off visible."
)
REMEDIATION = (
    "If a client that must be supported cannot connect, offer a protocol version and cipher "
    "family it accepts; if it is an obsolete client, no action is needed."
)
KIND = "check"


def _family(cipher: str) -> str:
    """A cipher suite's family: the key exchange, authentication and AEAD/CBC/stream shape
    that decides whether a client can use it. Names come from the tool's own tables."""
    if cipher.startswith(("TLS_AES_", "TLS_CHACHA20_")):
        return "tls13"
    if "RC4" in cipher:
        return "rc4"
    if "3DES" in cipher:
        return "3des"
    aead = "_GCM_" in cipher or "CHACHA20" in cipher
    if "ECDHE_ECDSA" in cipher:
        exchange = "ecdhe_ecdsa"
    elif "ECDHE_RSA" in cipher:
        exchange = "ecdhe_rsa"
    else:
        exchange = "rsa"
    return f"{exchange}_{'aead' if aead else 'cbc'}"


# Curated clients: the protocol versions and cipher families each supports. Kept to
# widely-cited, unambiguous profiles; a client connects iff it shares a protocol AND a
# cipher family with the server.
_MODERN_AEAD = ("tls13", "ecdhe_ecdsa_aead", "ecdhe_rsa_aead")
_ECDHE_ANY = (*_MODERN_AEAD, "ecdhe_ecdsa_cbc", "ecdhe_rsa_cbc")


class _Client:
    __slots__ = ("families", "name", "protocols")

    def __init__(self, name: str, protocols: tuple, families: tuple) -> None:
        self.name = name
        self.protocols = frozenset(protocols)
        self.families = frozenset(families)


_CLIENTS = [
    _Client("Modern browsers (Chrome/Firefox/Edge/Safari)", ("tls1_2", "tls1_3"), _MODERN_AEAD),
    _Client("Java 11+ / OpenSSL 3", ("tls1_2", "tls1_3"), _ECDHE_ANY),
    _Client("Java 8u161+", ("tls1_2",), (*_ECDHE_ANY[1:], "rsa_aead", "rsa_cbc")),
    _Client("Android 5.0", ("tls1_1", "tls1_2"), ("ecdhe_ecdsa_aead", "ecdhe_rsa_aead",
                                                  "ecdhe_ecdsa_cbc", "ecdhe_rsa_cbc", "rsa_cbc")),
    _Client("OpenSSL 1.0.2 / older curl", ("tls1_0", "tls1_1", "tls1_2"),
            (*_ECDHE_ANY[1:], "rsa_aead", "rsa_cbc", "3des")),
    _Client("IE 11 / Windows 10", ("tls1_0", "tls1_1", "tls1_2"),
            ("ecdhe_ecdsa_aead", "ecdhe_rsa_aead", "ecdhe_ecdsa_cbc", "ecdhe_rsa_cbc",
             "rsa_aead", "rsa_cbc", "3des")),
    _Client("IE 8 / Windows XP", ("tls1_0",), ("rsa_cbc", "3des", "rc4")),
]


def check(server: ServerView) -> Optional[Any]:
    if not server.supported_protocols:
        return None  # nothing was negotiated (e.g. a cleartext or unreachable endpoint)
    server_protocols = set(server.supported_protocols)
    server_families = {_family(cipher) for cipher in server.offered_ciphers}
    turned_away: List[str] = []
    for client in _CLIENTS:
        shared_protocols = client.protocols & server_protocols
        if not shared_protocols:
            turned_away.append(f"{client.name}: no shared protocol version")
        elif not (client.families & server_families):
            turned_away.append(f"{client.name}: no shared cipher (needs another key type/suite)")
    if not turned_away:
        return None
    return Detected(evidence=turned_away)
