"""HKDF (RFC 5869) and the HKDF-Expand-Label of TLS 1.3 (RFC 8446).

Built on the standard library's HMAC and hashlib, so there is nothing to get
wrong beyond the wiring. This is the key schedule's engine: from a shared secret
to the traffic keys that decrypt the server's handshake messages.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Callable

_Hash = Callable[[], "hashlib._Hash"]


def extract(salt: bytes, ikm: bytes, hashmod: _Hash = hashlib.sha256) -> bytes:
    return hmac.new(salt, ikm, hashmod).digest()


def expand(prk: bytes, info: bytes, length: int, hashmod: _Hash = hashlib.sha256) -> bytes:
    hash_length = hashmod().digest_size
    blocks = (length + hash_length - 1) // hash_length
    previous = b""
    output = b""
    for counter in range(1, blocks + 1):
        previous = hmac.new(prk, previous + info + bytes([counter]), hashmod).digest()
        output += previous
    return output[:length]


def expand_label(
    secret: bytes, label: bytes, context: bytes, length: int, hashmod: _Hash = hashlib.sha256
) -> bytes:
    """HKDF-Expand-Label as TLS 1.3 defines it (RFC 8446 section 7.1)."""
    full_label = b"tls13 " + label
    info = (
        length.to_bytes(2, "big")
        + bytes([len(full_label)]) + full_label
        + bytes([len(context)]) + context
    )
    return expand(secret, info, length, hashmod)
