"""ChaCha20-Poly1305 AEAD (RFC 8439).

The one AEAD this tool implements for itself, chosen because it is the simplest
to get right from the specification. Offering only this suite lets a TLS 1.3
handshake be completed without AES. It is not constant time and must not protect
real traffic.
"""

from __future__ import annotations

import hmac
from typing import List, Optional, Tuple

_MASK = 0xFFFFFFFF


def _rotl(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & _MASK


def _quarter_round(state: List[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & _MASK
    state[d] = _rotl(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & _MASK
    state[b] = _rotl(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & _MASK
    state[d] = _rotl(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & _MASK
    state[b] = _rotl(state[b] ^ state[c], 7)


def _block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += [int.from_bytes(key[i : i + 4], "little") for i in range(0, 32, 4)]
    state.append(counter)
    state += [int.from_bytes(nonce[i : i + 4], "little") for i in range(0, 12, 4)]

    working = list(state)
    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)

    return b"".join(((working[i] + state[i]) & _MASK).to_bytes(4, "little") for i in range(16))


def chacha20(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    for offset in range(0, len(data), 64):
        keystream = _block(key, counter + offset // 64, nonce)
        chunk = data[offset : offset + 64]
        out += bytes(byte ^ keystream[index] for index, byte in enumerate(chunk))
    return bytes(out)


def poly1305(key: bytes, message: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    prime = (1 << 130) - 5
    accumulator = 0
    for offset in range(0, len(message), 16):
        block = message[offset : offset + 16]
        accumulator = ((accumulator + int.from_bytes(block + b"\x01", "little")) * r) % prime
    accumulator = (accumulator + s) & ((1 << 128) - 1)
    return accumulator.to_bytes(16, "little")


def _pad16(data: bytes) -> bytes:
    return b"\x00" * ((16 - len(data) % 16) % 16)


def _mac_data(aad: bytes, ciphertext: bytes) -> bytes:
    return (
        aad + _pad16(aad) + ciphertext + _pad16(ciphertext)
        + len(aad).to_bytes(8, "little") + len(ciphertext).to_bytes(8, "little")
    )


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes]:
    one_time_key = _block(key, 0, nonce)[:32]
    ciphertext = chacha20(key, 1, nonce, plaintext)
    tag = poly1305(one_time_key, _mac_data(aad, ciphertext))
    return ciphertext, tag


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, tag: bytes) -> Optional[bytes]:
    """Return the plaintext, or ``None`` when the tag does not verify."""
    one_time_key = _block(key, 0, nonce)[:32]
    expected = poly1305(one_time_key, _mac_data(aad, ciphertext))
    if not hmac.compare_digest(expected, tag):
        return None
    return chacha20(key, 1, nonce, ciphertext)
