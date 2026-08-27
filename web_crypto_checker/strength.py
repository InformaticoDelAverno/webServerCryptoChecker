"""Effective security strength in bits: the weakest link a server would use.

Per NIST SP 800-57 Part 1, each algorithm class carries a security strength in
bits; the effective strength of a server is the smallest across the classes it
would accept, because an attacker steers toward the weakest. The bit values and
the level bands are policy data (``security_strength`` in ``algorithms.json``),
so re-tuning them never touches this code. Protocol and compression carry no
bit strength, so only cipher, key-exchange group, signature and certificate key
take part.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .models import CertificateInfo, SecurityStrength, TargetResult


def _keyword_bits(text: str, table: List[Any]) -> Optional[int]:
    """Bits for the first keyword in ``table`` (most specific first) found in ``text``."""
    for keyword, bits in table:
        if keyword in text:
            return int(bits)
    return None


def _certificate_bits(leaf: CertificateInfo, asymmetric: Dict[str, Any]) -> Optional[int]:
    """NIST-equivalent bits for the leaf key: a named curve, an EC field, or an RSA/DH modulus."""
    named = asymmetric.get("named", {})
    if leaf.key_type in named:
        return int(named[leaf.key_type])
    if leaf.key_bits is None:
        return None
    if leaf.key_type == "EC":
        return leaf.key_bits // int(asymmetric.get("ec_divisor", 2))
    strength: Optional[int] = None
    for threshold, bits in asymmetric.get("rsa_thresholds", []):
        if leaf.key_bits >= threshold:
            strength = int(bits)
    return strength


def _level(effective: int, levels: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The highest level whose ``min_bits`` the effective strength reaches."""
    chosen: Dict[str, Any] = {}
    for entry in levels:
        if effective >= entry["min_bits"]:
            chosen = entry
    return chosen


def compute_security_strength(result: TargetResult, config: Dict[str, Any]) -> SecurityStrength:
    """The effective security strength of a scanned endpoint, per the policy data."""
    reference = str(config.get("reference", ""))
    per_class: Dict[str, Optional[int]] = {}

    cipher_bits = [
        _keyword_bits(suite.name.upper(), config.get("symmetric", []))
        for suite in result.cipher_suites
    ]
    known_cipher = [bits for bits in cipher_bits if bits is not None]
    if known_cipher:
        per_class["cipher"] = min(known_cipher)

    group_bits = [group.bits for group in result.groups if group.bits is not None]
    if group_bits:
        per_class["group"] = min(group_bits)

    signature_bits = [
        _keyword_bits(scheme.lower(), config.get("hash", []))
        for scheme in result.signature_algorithms
    ]
    known_signature = [bits for bits in signature_bits if bits is not None]
    if known_signature:
        per_class["signature"] = min(known_signature)

    if result.certificate is not None and result.certificate.leaf is not None:
        certificate_bits = _certificate_bits(
            result.certificate.leaf, config.get("asymmetric", {})
        )
        if certificate_bits is not None:
            per_class["certificate"] = certificate_bits

    values = [bits for bits in per_class.values() if bits is not None]
    if not values:
        return SecurityStrength(reference=reference)

    effective = min(values)
    limiting = [name for name, bits in per_class.items() if bits == effective]
    level = _level(effective, config.get("levels", []))
    return SecurityStrength(
        effective_bits=effective,
        level_id=str(level.get("id", "unknown")),
        level_label=str(level.get("label", "Unknown")),
        level_description=str(level.get("description", "")),
        per_class=per_class,
        limiting=limiting,
        reference=reference,
    )
