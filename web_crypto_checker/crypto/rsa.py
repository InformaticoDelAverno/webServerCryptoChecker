"""RSA signature verification, for certificate chains.

Both schemes a CA certificate is signed with: RSASSA-PKCS1-v1_5 and RSASSA-PSS,
each with SHA-2 (RFC 8017). It is public-key math -- a modular exponentiation and
a comparison -- so nothing here is secret. Only verification, never signing.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Dict

#: The DigestInfo DER header that precedes the raw hash in a PKCS#1 v1.5 block.
_DIGEST_INFO: Dict[str, bytes] = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def verify_pkcs1(
    modulus: int, exponent: int, signature: bytes, message: bytes, hash_name: str
) -> bool:
    """Verify an RSASSA-PKCS1-v1_5 signature over ``message``."""
    prefix = _DIGEST_INFO.get(hash_name)
    if prefix is None:
        return False
    key_length = (modulus.bit_length() + 7) // 8
    if len(signature) != key_length or modulus <= 0:
        return False
    opened = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(key_length, "big")
    digest = hashlib.new(hash_name, message).digest()
    padding_length = key_length - 3 - len(prefix) - len(digest)
    if padding_length < 8:  # PKCS#1 requires at least eight 0xFF padding bytes
        return False
    expected = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + prefix + digest
    return hmac.compare_digest(opened, expected)


def _mgf1(seed: bytes, length: int, hash_name: str) -> bytes:
    """The MGF1 mask generation function (RFC 8017 B.2.1): hash the seed in counter blocks."""
    hash_length = hashlib.new(hash_name).digest_size
    block_count = (length + hash_length - 1) // hash_length
    mask = b"".join(
        hashlib.new(hash_name, seed + counter.to_bytes(4, "big")).digest()
        for counter in range(block_count)
    )
    return mask[:length]


def verify_pss(
    modulus: int,
    exponent: int,
    signature: bytes,
    message: bytes,
    hash_name: str,
    mgf_hash_name: str,
    salt_length: int,
) -> bool:
    """Verify an RSASSA-PSS signature over ``message`` (RFC 8017 8.1.2, 9.1.2)."""
    key_length = (modulus.bit_length() + 7) // 8
    if len(signature) != key_length or modulus <= 0:
        return False
    encoded_bits = modulus.bit_length() - 1  # emBits: one less than the modulus
    encoded_length = (encoded_bits + 7) // 8
    representative = pow(int.from_bytes(signature, "big"), exponent, modulus)
    try:
        encoded = representative.to_bytes(encoded_length, "big")  # I2OSP, fails if too large
    except OverflowError:
        return False

    hash_length = hashlib.new(hash_name).digest_size
    message_hash = hashlib.new(hash_name, message).digest()
    if encoded_length < hash_length + salt_length + 2:
        return False  # inconsistent: no room for the salt and hash
    if encoded[-1] != 0xBC:
        return False  # the trailer field
    masked_db = encoded[: encoded_length - hash_length - 1]
    signed_hash = encoded[encoded_length - hash_length - 1 : encoded_length - 1]
    # The leftmost spare bits (one, for any byte-aligned modulus) must be zero. When
    # there are none the masks below fold to no-ops, so no special case is needed.
    spare_bits = 8 * encoded_length - encoded_bits
    if masked_db[0] & (0xFF << (8 - spare_bits) & 0xFF):
        return False
    db_mask = _mgf1(signed_hash, encoded_length - hash_length - 1, mgf_hash_name)
    data_block = bytes(left ^ right for left, right in zip(masked_db, db_mask))
    data_block = bytes([data_block[0] & (0xFF >> spare_bits)]) + data_block[1:]

    padding_length = encoded_length - hash_length - salt_length - 2
    if data_block[:padding_length] != b"\x00" * padding_length:
        return False  # the padding string must be all zeros
    if data_block[padding_length] != 0x01:
        return False  # ...followed by a single 0x01
    salt = data_block[padding_length + 1 :]
    candidate = hashlib.new(hash_name, b"\x00" * 8 + message_hash + salt).digest()
    return hmac.compare_digest(signed_hash, candidate)
