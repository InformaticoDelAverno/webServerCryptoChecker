"""The AES (Rijndael) block cipher, by hand -- just the encrypt direction.

AES-GCM (``aesgcm.py``) only ever encrypts blocks: it XORs a keystream for the
data and derives its authentication key and tag mask from encrypted blocks too.
So decryption of a TLS record needs no inverse cipher, and none is written here.

Supports 128- and 256-bit keys, the two the TLS 1.3 AES suites use. Verified
against the FIPS-197 worked example and, through ``aesgcm.py``, the NIST GCM
vectors.
"""

from __future__ import annotations

from typing import List

# The Rijndael S-box (FIPS-197). A table, not a computation, so the substitution
# stays obviously the standard one.
_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime2(byte: int, multiplier: int) -> int:
    """Multiply in GF(2^8) with the AES reduction polynomial 0x11B."""
    product = 0
    for _ in range(8):
        if multiplier & 1:
            product ^= byte
        high = byte & 0x80
        byte = (byte << 1) & 0xFF
        if high:
            byte ^= 0x1B
        multiplier >>= 1
    return product


def expand_key(key: bytes) -> List[List[int]]:
    """The AES key schedule as a list of 4-byte words."""
    words = [list(key[4 * i : 4 * i + 4]) for i in range(len(key) // 4)]
    key_words = len(words)
    total = 4 * (key_words + 6 + 1)
    for i in range(key_words, total):
        temp = list(words[i - 1])
        if i % key_words == 0:
            temp = [_SBOX[b] for b in temp[1:] + temp[:1]]
            temp[0] ^= _RCON[i // key_words - 1]
        elif key_words > 6 and i % key_words == 4:
            temp = [_SBOX[b] for b in temp]
        words.append([words[i - key_words][j] ^ temp[j] for j in range(4)])
    return words


def encrypt_block(block: bytes, round_keys: List[List[int]]) -> bytes:
    """Encrypt one 16-byte block with an expanded key."""
    rounds = len(round_keys) // 4 - 1
    state = [[block[row + 4 * col] for col in range(4)] for row in range(4)]

    def add_round_key(index: int) -> None:
        for col in range(4):
            word = round_keys[index + col]
            for row in range(4):
                state[row][col] ^= word[row]

    add_round_key(0)
    for rnd in range(1, rounds):
        for row in range(4):
            for col in range(4):
                state[row][col] = _SBOX[state[row][col]]
        for row in range(1, 4):
            state[row] = state[row][row:] + state[row][:row]
        for col in range(4):
            column = [state[row][col] for row in range(4)]
            state[0][col] = _xtime2(column[0], 2) ^ _xtime2(column[1], 3) ^ column[2] ^ column[3]
            state[1][col] = column[0] ^ _xtime2(column[1], 2) ^ _xtime2(column[2], 3) ^ column[3]
            state[2][col] = column[0] ^ column[1] ^ _xtime2(column[2], 2) ^ _xtime2(column[3], 3)
            state[3][col] = _xtime2(column[0], 3) ^ column[1] ^ column[2] ^ _xtime2(column[3], 2)
        add_round_key(4 * rnd)
    for row in range(4):
        for col in range(4):
            state[row][col] = _SBOX[state[row][col]]
    for row in range(1, 4):
        state[row] = state[row][row:] + state[row][:row]
    add_round_key(4 * rounds)
    return bytes(state[row][col] for col in range(4) for row in range(4))
