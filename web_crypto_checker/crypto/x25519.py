"""X25519 (RFC 7748): the Diffie-Hellman function on Curve25519.

Implemented here so a TLS 1.3 handshake can be completed without a crypto
library. It is not constant time and must not protect real traffic; for a
scanner that only needs the shared secret to derive keys and read the server's
encrypted messages, that is fine.
"""

from __future__ import annotations

from typing import Tuple

_P = 2**255 - 19
_A24 = 121665


def _decode_scalar(scalar: bytes) -> int:
    clamped = bytearray(scalar[:32])
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    return int.from_bytes(clamped, "little")


def _decode_u(u: bytes) -> int:
    trimmed = bytearray(u[:32])
    trimmed[31] &= 127
    return int.from_bytes(trimmed, "little") % _P


def _cswap(swap: int, a: int, b: int) -> Tuple[int, int]:
    # Branchless: swap is 0 or 1, and the result is (a, b) or (b, a) exactly.
    return a + swap * (b - a), b + swap * (a - b)


def x25519(scalar: bytes, u: bytes) -> bytes:
    """The X25519 function: scalar multiplication on Curve25519."""
    k = _decode_scalar(scalar)
    x1 = _decode_u(u)
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in range(254, -1, -1):
        bit = (k >> t) & 1
        swap ^= bit
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = bit

        a = (x2 + z2) % _P
        aa = (a * a) % _P
        b = (x2 - z2) % _P
        bb = (b * b) % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = (d * a) % _P
        cb = (c * b) % _P
        x3 = ((da + cb) ** 2) % _P
        z3 = (x1 * ((da - cb) ** 2 % _P)) % _P
        x2 = (aa * bb) % _P
        z2 = (e * ((aa + (_A24 * e) % _P) % _P)) % _P

    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)
    result = (x2 * pow(z2, _P - 2, _P)) % _P
    return result.to_bytes(32, "little")


def x25519_base(scalar: bytes) -> bytes:
    """The public key for a private scalar: X25519(scalar, 9)."""
    return x25519(scalar, (9).to_bytes(32, "little"))
