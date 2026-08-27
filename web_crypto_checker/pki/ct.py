"""Certificate Transparency: verifying a certificate's embedded SCTs (RFC 6962).

A publicly-trusted certificate carries Signed Certificate Timestamps -- signed
promises from public CT logs that the certificate was submitted to them. Each SCT
is a log's signature over the *precertificate*: this certificate with the SCT
extension removed, bound to a hash of its issuer's key. This module rebuilds that
signed structure and verifies the signature against a snapshot of known logs
(``data/ct_logs.json``), so an SCT is reported *verified* only when a known log's
key actually signs it -- never taken on trust.

An SCT from a log absent from the snapshot reads as "not verified against a known
log", never as invalid: the snapshot is a point-in-time list, and a missing log is
our blind spot, not the certificate's fault.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..crypto import asn1, ec, ecdsa, rsa

_OID_SCT = "1.3.6.1.4.1.11129.2.4.2"
_SIG_RSA = 1
_SIG_ECDSA = 3
# TLS SignatureAndHashAlgorithm hash codes (RFC 5246 7.4.1.4.1) a CT log may use.
_HASHES = {4: "sha256", 5: "sha384", 6: "sha512"}


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(content)) + content


def _oid(node: asn1.Node) -> str:
    return asn1.decode_oid(node.content)


_LOGS: Optional[Dict[bytes, Tuple[str, bytes]]] = None


def _logs_path() -> Path:
    # ``ct.py`` lives in the ``pki`` subpackage now, so the package's ``data``
    # directory is one level up from this file.
    return Path(__file__).resolve().parent.parent / "data" / "ct_logs.json"


def _load_logs() -> Dict[bytes, Tuple[str, bytes]]:
    """The known CT logs, ``log_id -> (name, SubjectPublicKeyInfo)``; loaded once."""
    global _LOGS
    if _LOGS is None:
        raw = json.loads(_logs_path().read_text(encoding="utf-8"))["logs"]
        _LOGS = {
            bytes.fromhex(log_id): (entry["name"], base64.b64decode(entry["key"]))
            for log_id, entry in raw.items()
        }
    return _LOGS


@dataclass
class Sct:
    """One parsed Signed Certificate Timestamp (RFC 6962 3.2)."""

    version: int
    log_id: bytes
    timestamp: bytes  # the raw 8-byte big-endian uint64, as it is signed
    ct_extensions: bytes
    hash_alg: int
    sig_alg: int
    signature: bytes


@dataclass
class SctResult:
    """A verdict on one embedded SCT."""

    log_name: Optional[str]  # the log that signed it, or None if the log is unknown
    verified: bool


def _sct_extension_value(leaf_der: bytes) -> Optional[bytes]:
    """The raw value octets of a certificate's SCT extension, or ``None``.

    This is the extnValue (a DER OCTET STRING wrapping the TLS SCT list);
    :func:`parse_sct_list` unwraps it, exactly as ``certificates._count_scts`` does."""
    tbs = asn1.parse(leaf_der).children[0]
    for child in tbs.children:
        if child.tag_class == asn1.CLASS_CONTEXT and child.tag_number == 3:
            for extension in child.children[0].children:
                if _oid(extension.children[0]) == _OID_SCT:
                    return extension.children[-1].content
    return None


def precertificate_tbs(leaf_der: bytes) -> bytes:
    """The certificate's TBSCertificate with the SCT extension removed and re-encoded.

    This is exactly what the log signed: the certificate as it was submitted, before
    the SCTs it returned were folded back in (RFC 6962 3.2)."""
    tbs = asn1.parse(leaf_der).children[0]
    rebuilt = b""
    for child in tbs.children:
        if child.tag_class == asn1.CLASS_CONTEXT and child.tag_number == 3:
            kept = b"".join(
                extension.raw
                for extension in child.children[0].children
                if _oid(extension.children[0]) != _OID_SCT
            )
            rebuilt += _der(0xA3, _der(0x30, kept))  # [3] EXPLICIT { SEQUENCE OF Extension }
        else:
            rebuilt += child.raw
    return _der(0x30, rebuilt)


def _subject_public_key_info(cert_der: bytes) -> bytes:
    """The raw SubjectPublicKeyInfo of a certificate (a SEQUENCE of AlgId + BIT STRING)."""
    for child in asn1.parse(cert_der).children[0].children:
        if (
            child.tag_number == 0x10
            and len(child.children) == 2
            and child.children[1].tag_number == 0x03
        ):
            return child.raw
    raise ValueError("no SubjectPublicKeyInfo")


def _parse_sct(body: bytes) -> Optional[Sct]:
    if len(body) < 43:  # version(1) + log_id(32) + timestamp(8) + extensions_length(2)
        return None
    extensions_length = int.from_bytes(body[41:43], "big")
    end_of_extensions = 43 + extensions_length
    if len(body) < end_of_extensions + 4:  # + hash(1) + sig(1) + signature_length(2)
        return None
    signature_length = int.from_bytes(body[end_of_extensions + 2 : end_of_extensions + 4], "big")
    return Sct(
        version=body[0],
        log_id=body[1:33],
        timestamp=body[33:41],
        ct_extensions=body[43:end_of_extensions],
        hash_alg=body[end_of_extensions],
        sig_alg=body[end_of_extensions + 1],
        signature=body[end_of_extensions + 4 : end_of_extensions + 4 + signature_length],
    )


def parse_sct_list(ext_value: bytes) -> List[Sct]:
    """Parse the SerializedSCT list from an SCT extension value (RFC 6962 3.3)."""
    listed = asn1.parse(ext_value).content  # inner OCTET STRING wraps the TLS list
    if len(listed) < 2:
        return []
    blob = listed[2 : 2 + int.from_bytes(listed[:2], "big")]
    scts: List[Sct] = []
    position = 0
    while position + 2 <= len(blob):
        length = int.from_bytes(blob[position : position + 2], "big")
        entry = _parse_sct(blob[position + 2 : position + 2 + length])
        if entry is not None:
            scts.append(entry)
        position += 2 + length
    return scts


def _signed_entry(sct: Sct, issuer_key_hash: bytes, precert_tbs: bytes) -> bytes:
    """The bytes a log signs for an embedded (precert) SCT (RFC 6962 3.2)."""
    return (
        bytes([sct.version, 0])  # sct_version, signature_type = certificate_timestamp(0)
        + sct.timestamp
        + bytes([0, 1])  # entry_type = precert_entry(1)
        + issuer_key_hash
        + len(precert_tbs).to_bytes(3, "big")
        + precert_tbs
        + len(sct.ct_extensions).to_bytes(2, "big")
        + sct.ct_extensions
    )


def _verify_log_signature(
    spki_der: bytes, hash_alg: int, sig_alg: int, signature: bytes, message: bytes
) -> bool:
    """Verify one SCT signature under a log's SubjectPublicKeyInfo."""
    hash_name = _HASHES.get(hash_alg)
    if hash_name is None:
        return False
    info = asn1.parse(spki_der)
    algorithm = info.children[0]
    key_bits = info.children[1].content[1:]  # drop the BIT STRING's unused-bits byte
    if sig_alg == _SIG_ECDSA:
        curve = ec.CURVES_BY_OID.get(_oid(algorithm.children[1]))
        if curve is None:
            return False
        parsed = asn1.parse(signature)
        r, s = parsed.children[0].integer(), parsed.children[1].integer()
        return ecdsa.verify(curve, key_bits, r, s, message, hash_name)
    if sig_alg == _SIG_RSA:
        key = asn1.parse(key_bits)
        return rsa.verify_pkcs1(
            key.children[0].integer(), key.children[1].integer(), signature, message, hash_name
        )
    return False


def verify_embedded_scts(leaf_der: bytes, issuer_der: bytes) -> List[SctResult]:
    """Verify every SCT embedded in ``leaf_der`` against the known CT logs.

    Needs the issuer certificate, since an embedded SCT is signed over a hash of the
    issuer's key. Returns one result per SCT (empty if the certificate carries none,
    or if anything about the structure cannot be parsed -- a malformed certificate is
    never reported as having *verified* transparency)."""
    try:
        ext_value = _sct_extension_value(leaf_der)
        if ext_value is None:
            return []
        precert_tbs = precertificate_tbs(leaf_der)
        issuer_key_hash = hashlib.sha256(_subject_public_key_info(issuer_der)).digest()
        scts = parse_sct_list(ext_value)
    except (asn1.Asn1Error, IndexError, ValueError):
        return []
    logs = _load_logs()
    results: List[SctResult] = []
    for sct in scts:
        entry = logs.get(sct.log_id)
        if entry is None:
            results.append(SctResult(log_name=None, verified=False))
            continue
        name, spki = entry
        message = _signed_entry(sct, issuer_key_hash, precert_tbs)
        try:
            verified = _verify_log_signature(
                spki, sct.hash_alg, sct.sig_alg, sct.signature, message
            )
        except (asn1.Asn1Error, IndexError, ValueError):
            verified = False
        results.append(SctResult(log_name=name, verified=verified))
    return results
