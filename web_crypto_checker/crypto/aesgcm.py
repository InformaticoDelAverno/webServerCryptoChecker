"""AES-GCM (RFC 5116 / NIST SP 800-38D), by hand, for the TLS 1.3 AES suites.

Same shape as ``chacha.py`` so the record layer can treat them interchangeably:
``encrypt`` returns ``(ciphertext, tag)`` and ``decrypt`` returns the plaintext or
``None`` when the tag does not verify. The nonce is the 96-bit record nonce TLS
builds, so only that IV length is supported. Verified against the NIST GCM test
vectors for AES-128 and AES-256.
"""

from __future__ import annotations

import hmac
from typing import Optional, Tuple

from . import aes

_R = 0xE1 << 120  # the GCM reduction polynomial, top byte first


def _gf_mul(x: int, y: int) -> int:
    """Multiply two 128-bit field elements in GF(2^128), GCM bit order."""
    product = 0
    for i in range(128):
        if (x >> (127 - i)) & 1:
            product ^= y
        if y & 1:
            y = (y >> 1) ^ _R
        else:
            y >>= 1
    return product


def _ghash(subkey: int, data: bytes) -> int:
    accumulator = 0
    for offset in range(0, len(data), 16):
        block = int.from_bytes(data[offset : offset + 16], "big")
        accumulator = _gf_mul(accumulator ^ block, subkey)
    return accumulator


def _pad(data: bytes) -> bytes:
    return data + b"\x00" * ((-len(data)) % 16)


def _keystream_xor(schedule: object, counter_start: int, data: bytes) -> bytes:
    counter = counter_start
    out = bytearray()
    for offset in range(0, len(data), 16):
        counter = (counter & ~0xFFFFFFFF) | ((counter + 1) & 0xFFFFFFFF)
        block = aes.encrypt_block(counter.to_bytes(16, "big"), schedule)  # type: ignore[arg-type]
        chunk = data[offset : offset + 16]
        out += bytes(a ^ b for a, b in zip(chunk, block))
    return bytes(out)


def _tag(schedule: object, subkey: int, j0: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    lengths = (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
    hashed = _ghash(subkey, _pad(aad) + _pad(ciphertext) + lengths)
    mask = int.from_bytes(aes.encrypt_block(j0, schedule), "big")  # type: ignore[arg-type]
    return (hashed ^ mask).to_bytes(16, "big")


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes]:
    schedule = aes.expand_key(key)
    subkey = int.from_bytes(aes.encrypt_block(bytes(16), schedule), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    ciphertext = _keystream_xor(schedule, int.from_bytes(j0, "big"), plaintext)
    return ciphertext, _tag(schedule, subkey, j0, aad, ciphertext)


def decrypt(
    key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, tag: bytes
) -> Optional[bytes]:
    """Return the plaintext, or ``None`` when the tag does not verify."""
    schedule = aes.expand_key(key)
    subkey = int.from_bytes(aes.encrypt_block(bytes(16), schedule), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    if not hmac.compare_digest(_tag(schedule, subkey, j0, aad, ciphertext), tag):
        return None
    return _keystream_xor(schedule, int.from_bytes(j0, "big"), ciphertext)
