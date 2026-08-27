"""QUIC v1 Initial packet keys (RFC 9001 section 5.2).

The Initial keys are not secret -- both endpoints derive them from the client's
Destination Connection ID with a fixed salt -- so a probe can protect its own
Initial and read the server's. The derivation is TLS 1.3 HKDF (reused from
``crypto/hkdf.py``) with QUIC's labels; the results match RFC 9001 Appendix A.1.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable

from ..crypto import hkdf

_Hash = Callable[..., "hashlib._Hash"]

# RFC 9001 5.2 / RFC 9369 3.3.1: the Initial salts for QUIC v1 and v2.
INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
INITIAL_SALT_V2 = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")


@dataclass(frozen=True)
class QuicVersion:
    """A QUIC version's wire differences (RFC 9369 3): its number, its Initial salt, the
    HKDF label prefix (``quic`` v1, ``quicv2`` v2), and the long-header type bits (in the
    first byte) for Initial and Handshake packets, which v2 renumbers."""

    number: int
    initial_salt: bytes
    label_prefix: bytes
    initial_type: int
    handshake_type: int


VERSION_1 = QuicVersion(0x00000001, INITIAL_SALT_V1, b"quic", 0x00, 0x20)
VERSION_2 = QuicVersion(0x6B3343CF, INITIAL_SALT_V2, b"quicv2", 0x10, 0x30)


@dataclass
class PacketKeys:
    """The AEAD key, IV and header-protection key for one direction."""

    key: bytes
    iv: bytes
    hp: bytes


@dataclass
class InitialKeys:
    """Both directions of the Initial packet keys."""

    client: PacketKeys
    server: PacketKeys


def _packet_keys(
    secret: bytes, version: QuicVersion = VERSION_1,
    key_length: int = 16, hashmod: _Hash = hashlib.sha256,
) -> PacketKeys:
    prefix = version.label_prefix
    return PacketKeys(
        key=hkdf.expand_label(secret, prefix + b" key", b"", key_length, hashmod),
        iv=hkdf.expand_label(secret, prefix + b" iv", b"", 12, hashmod),
        hp=hkdf.expand_label(secret, prefix + b" hp", b"", key_length, hashmod),
    )


def initial_keys(
    destination_connection_id: bytes, version: QuicVersion = VERSION_1
) -> InitialKeys:
    """Derive the Initial keys from the client's DCID (RFC 9001 5.2, RFC 9369 3.3.1)."""
    initial = hkdf.extract(version.initial_salt, destination_connection_id)
    client_secret = hkdf.expand_label(initial, b"client in", b"", 32)
    server_secret = hkdf.expand_label(initial, b"server in", b"", 32)
    return InitialKeys(
        client=_packet_keys(client_secret, version),
        server=_packet_keys(server_secret, version),
    )


def server_handshake_keys(
    shared_secret: bytes,
    transcript: bytes,
    key_length: int,
    hashmod: _Hash = hashlib.sha256,
    hash_length: int = 32,
    version: QuicVersion = VERSION_1,
) -> PacketKeys:
    """The server's Handshake packet keys, from the ECDHE secret and the CH||SH transcript.

    This is the TLS 1.3 key schedule (RFC 8446 7.1) with QUIC's packet labels: the
    handshake secret from the shared secret, the ``s hs traffic`` secret bound to the
    transcript, then the version's ``key``/``iv``/``hp`` labels. ``hashmod``/``hash_length``
    and ``transcript`` are the negotiated suite's hash -- SHA-256 for AES-128-GCM and
    ChaCha20, SHA-384 for AES-256-GCM.
    """
    zeros = b"\x00" * hash_length
    early = hkdf.extract(zeros, zeros, hashmod)
    derived = hkdf.expand_label(early, b"derived", hashmod(b"").digest(), hash_length, hashmod)
    handshake = hkdf.extract(derived, shared_secret, hashmod)
    server_secret = hkdf.expand_label(handshake, b"s hs traffic", transcript, hash_length, hashmod)
    return _packet_keys(server_secret, version, key_length, hashmod)
