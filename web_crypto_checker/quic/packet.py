"""QUIC packet protection (RFC 9001 sections 5.3 and 5.4).

The payload is sealed with an AEAD -- the nonce is the IV XOR the packet number,
the packet header is the associated data. Then header protection masks the packet
number and the low bits of the first byte with a five-byte mask taken from a
sixteen-byte sample of the ciphertext. Initial packets always use AES-128-GCM
(``AES_128_GCM``, the default); Handshake and 1-RTT packets use the AEAD the TLS
handshake negotiated, so the cipher is a parameter -- ChaCha20 masks the header
with its keystream (5.4.4) instead of AES-ECB (5.4.3). The results interoperate
with a real QUIC stack.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from ..crypto import aes, aesgcm, chacha
from .keys import PacketKeys

_SAMPLE_LENGTH = 16
_TAG_LENGTH = 16

_Seal = Callable[[bytes, bytes, bytes, bytes], Tuple[bytes, bytes]]
_Open = Callable[[bytes, bytes, bytes, bytes, bytes], Optional[bytes]]
_Mask = Callable[[bytes, bytes], bytes]


def _aes_mask(hp_key: bytes, sample: bytes) -> bytes:
    """The header-protection mask for the AES AEADs: AES-ECB of the sample (5.4.3)."""
    return aes.encrypt_block(sample, aes.expand_key(hp_key))[:5]


def _chacha_mask(hp_key: bytes, sample: bytes) -> bytes:
    """The header-protection mask for ChaCha20 (5.4.4): its keystream over five zeros.

    The sample's first four bytes are the block counter (little-endian) and the
    remaining twelve are the nonce.
    """
    counter = int.from_bytes(sample[:4], "little")
    return chacha.chacha20(hp_key, counter, sample[4:16], b"\x00" * 5)


@dataclass(frozen=True)
class Cipher:
    """An AEAD plus its header-protection, so packet protection is cipher-agnostic."""

    key_length: int
    seal: _Seal
    open: _Open
    mask: _Mask


AES_128_GCM = Cipher(16, aesgcm.encrypt, aesgcm.decrypt, _aes_mask)
AES_256_GCM = Cipher(32, aesgcm.encrypt, aesgcm.decrypt, _aes_mask)
CHACHA20_POLY1305 = Cipher(32, chacha.encrypt, chacha.decrypt, _chacha_mask)


def _nonce(iv: bytes, packet_number: int) -> bytes:
    counter = packet_number.to_bytes(len(iv), "big")
    return bytes(left ^ right for left, right in zip(iv, counter))


def protect(
    keys: PacketKeys,
    header: bytes,
    payload: bytes,
    packet_number: int,
    cipher: Cipher = AES_128_GCM,
) -> bytes:
    """Protect a long-header packet whose ``header`` ends with the packet number."""
    pn_length = (header[0] & 0x03) + 1
    pn_offset = len(header) - pn_length
    ciphertext, tag = cipher.seal(keys.key, _nonce(keys.iv, packet_number), payload, header)
    protected_payload = ciphertext + tag
    sample = protected_payload[4 - pn_length : 4 - pn_length + _SAMPLE_LENGTH]
    mask = cipher.mask(keys.hp, sample)
    first = header[0] ^ (mask[0] & 0x0F)
    masked_pn = bytes(header[pn_offset + i] ^ mask[1 + i] for i in range(pn_length))
    return bytes([first]) + header[1:pn_offset] + masked_pn + protected_payload


def unprotect(
    keys: PacketKeys, packet: bytes, pn_offset: int, cipher: Cipher = AES_128_GCM
) -> Optional[Tuple[bytes, bytes]]:
    """Recover ``(header, payload)`` from a protected long-header packet, or None.

    ``pn_offset`` is the packet-number offset relative to the start of ``packet`` --
    so a packet coalesced into a larger datagram must be sliced out first.
    """
    sample = packet[pn_offset + 4 : pn_offset + 4 + _SAMPLE_LENGTH]
    mask = cipher.mask(keys.hp, sample)
    first = packet[0] ^ (mask[0] & 0x0F)
    pn_length = (first & 0x03) + 1
    pn_bytes = bytes(packet[pn_offset + i] ^ mask[1 + i] for i in range(pn_length))
    packet_number = int.from_bytes(pn_bytes, "big")
    header = bytes([first]) + packet[1:pn_offset] + pn_bytes
    protected_payload = packet[pn_offset + pn_length :]
    ciphertext, tag = protected_payload[:-_TAG_LENGTH], protected_payload[-_TAG_LENGTH:]
    payload = cipher.open(keys.key, _nonce(keys.iv, packet_number), ciphertext, header, tag)
    if payload is None:
        return None
    return header, payload
