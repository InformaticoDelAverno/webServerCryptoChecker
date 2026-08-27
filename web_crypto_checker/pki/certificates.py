"""Retrieving and parsing the certificate a web server presents.

The certificate is what a web server is, far more than its cipher list: a name,
a validity window, a key, an issuer. It is fetched over a TLS 1.2 handshake,
where the Certificate message travels in the clear, and parsed by hand from DER
-- so this needs no certificate library and reaches a server a modern OpenSSL
would refuse to negotiate with.

It also verifies the presented chain's **internal signatures** -- that each
certificate really is signed by the next one up (and a self-signed one by
itself), with the hand-rolled RSA and ECDSA in ``crypto/`` -- and reads the
revocation and transparency a certificate *advertises*: its OCSP responder and
CRL URLs, whether it is must-staple, and how many SCTs it carries (Certificate
Transparency). It also builds the chain to a **trusted root** from a CA bundle -- the system
trust store by default, or a path given on the command line. Actually *querying*
the OCSP responder (which touches the network) lives in ``ocsp.py``, behind
``--active``.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from ..crypto import asn1, ec, ecdsa, ed25519, rsa
from ..crypto.asn1 import Asn1Error, Node
from ..models import CertificateChain, CertificateInfo, TrustStatus
from ..tls.constants import (
    CONTENT_TYPE_ALERT,
    CONTENT_TYPE_HANDSHAKE,
    HANDSHAKE_TYPE_CERTIFICATE,
    HANDSHAKE_TYPE_SERVER_HELLO_DONE,
    LEGACY_CIPHER_SUITES,
    PROTOCOL_VERSIONS,
    alert_description,
)
from ..tls.messages import build_client_hello, read_handshake
from ..tls.probe import DEFAULT_TIMEOUT, _recv_exact
from ..tls.wire import Reader, TlsError
from . import ct
from .roca import is_roca_vulnerable

_TLS12 = PROTOCOL_VERSIONS[1]
_DEFAULT_GROUPS = [0x001D, 0x0017, 0x0018, 0x0019]
_DEFAULT_SIGNATURE_SCHEMES = [0x0804, 0x0805, 0x0806, 0x0401, 0x0403, 0x0503, 0x0807]

_SIGNATURE_ALGORITHMS = {
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsassaPss",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.2.840.10045.4.3.1": "ecdsa-with-SHA1",
    "1.3.101.112": "Ed25519",
}
_KEY_ALGORITHMS = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.10045.2.1": "EC",
    "1.3.101.112": "Ed25519",
}
_CURVES = {
    "1.2.840.10045.3.1.7": ("P-256", 256),
    "1.3.132.0.34": ("P-384", 384),
    "1.3.132.0.35": ("P-521", 521),
    "1.3.132.0.33": ("P-224", 224),
    "1.2.840.10045.3.1.1": ("P-192", 192),
}
_ATTRIBUTES = {"2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.6": "C"}
_OID_KEY_USAGE = "2.5.29.15"
_OID_SAN = "2.5.29.17"
_OID_BASIC_CONSTRAINTS = "2.5.29.19"
_OID_NAME_CONSTRAINTS = "2.5.29.30"
_OID_EKU = "2.5.29.37"
#: ExtendedKeyUsage purposes worth naming (RFC 5280 4.2.1.12); the rest stay dotted.
_EKU_NAMES: Dict[str, str] = {
    "1.3.6.1.5.5.7.3.1": "serverAuth",
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
    "1.3.6.1.5.5.7.3.9": "OCSPSigning",
    "2.5.29.37.0": "anyExtendedKeyUsage",
}
_OID_AIA = "1.3.6.1.5.5.7.1.1"
_OID_OCSP = "1.3.6.1.5.5.7.48.1"
_OID_CA_ISSUERS = "1.3.6.1.5.5.7.48.2"
_OID_CRL_DISTRIBUTION = "2.5.29.31"
_OID_SCT = "1.3.6.1.4.1.11129.2.4.2"
_OID_TLS_FEATURE = "1.3.6.1.5.5.7.1.24"
_TLS_FEATURE_STATUS_REQUEST = 5  # the value that makes a certificate "must-staple"
_GENERAL_NAME_EMAIL = 1
_GENERAL_NAME_DNS = 2
_GENERAL_NAME_DIR = 4
_GENERAL_NAME_URI = 6
_GENERAL_NAME_IP = 7


class CertificateError(Exception):
    """A certificate could not be retrieved or parsed."""


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def _oid(node: Node) -> str:
    return asn1.decode_oid(node.content)


def _name(node: Node) -> str:
    parts: List[str] = []
    for rdn in node.children:
        for attribute in rdn.children:
            oid = _oid(attribute.children[0])
            value = attribute.children[1].content.decode("utf-8", "replace")
            parts.append(f"{_ATTRIBUTES.get(oid, oid)}={value}")
    return ", ".join(parts)


def _time(node: Node) -> int:
    text = node.content.decode("ascii")
    if node.tag_number == asn1.TAG_UTC_TIME:
        year = int(text[0:2])
        year += 2000 if year < 50 else 1900
        rest = text[2:]
    else:
        year = int(text[0:4])
        rest = text[4:]
    moment = datetime(
        year, int(rest[0:2]), int(rest[2:4]),
        int(rest[4:6]), int(rest[6:8]), int(rest[8:10]),
        tzinfo=timezone.utc,
    )
    return int(moment.timestamp())


def _public_key(spki: Node, info: CertificateInfo) -> None:
    algorithm = spki.children[0]
    key_type = _KEY_ALGORITHMS.get(_oid(algorithm.children[0]), _oid(algorithm.children[0]))
    info.key_type = key_type
    if key_type == "RSA":
        # The BIT STRING's first octet is the count of unused bits (always 0
        # here); the rest is a DER RSAPublicKey SEQUENCE { modulus, exponent }.
        rsa_key = asn1.parse(spki.children[1].content[1:])
        modulus = rsa_key.children[0].integer()
        info.key_bits = modulus.bit_length()
        info.roca_vulnerable = is_roca_vulnerable(modulus)
    elif key_type == "EC":
        curve_name, curve_bits = _CURVES.get(_oid(algorithm.children[1]), ("", None))
        info.curve = curve_name
        info.key_bits = curve_bits


def _general_name_uri(name: Node) -> Optional[str]:
    """The URL of a ``[6] uniformResourceIdentifier`` GeneralName, else ``None``."""
    if name.tag_number == _GENERAL_NAME_URI:
        return name.content.decode("ascii", "replace")
    return None


def _parse_aia(value: bytes, info: CertificateInfo) -> None:
    """The OCSP responder and caIssuers URLs from an Authority Information Access ext."""
    for access in asn1.parse(value).children:
        method = _oid(access.children[0])
        if method == _OID_OCSP:
            info.ocsp_url = _general_name_uri(access.children[1]) or info.ocsp_url
        elif method == _OID_CA_ISSUERS:
            info.ca_issuers_url = _general_name_uri(access.children[1]) or info.ca_issuers_url


def _parse_crl_distribution(value: bytes, info: CertificateInfo) -> None:
    """The CRL URLs from the distribution points' full names."""
    for point in asn1.parse(value).children:
        names = point.children[0].children[0].children  # DistributionPoint [0][0] fullName
        info.crl_urls.extend(filter(None, (_general_name_uri(name) for name in names)))


def _count_scts(value: bytes) -> int:
    """Count the SCTs in a SignedCertificateTimestampList extension."""
    listed = asn1.parse(value).content  # the inner OCTET STRING's TLS-serialized list
    if len(listed) < 2:
        return 0
    entries = listed[2 : 2 + int.from_bytes(listed[:2], "big")]
    count = 0
    position = 0
    while position + 2 <= len(entries):
        position += 2 + int.from_bytes(entries[position : position + 2], "big")
        count += 1
    return count


def _tls_feature_must_staple(value: bytes) -> bool:
    features = [feature.integer() for feature in asn1.parse(value).children]
    return _TLS_FEATURE_STATUS_REQUEST in features


def _basic_constraints(value: bytes) -> Tuple[bool, Optional[int]]:
    """The (cA, pathLenConstraint) of a BasicConstraints extension (RFC 5280 4.2.1.9).

    ``cA`` defaults to FALSE (absent when false, in DER); the path length is the
    optional INTEGER that bounds how many CA certificates may follow in a path.
    """
    is_ca = False
    path_length: Optional[int] = None
    for element in asn1.parse(value).children:
        if element.tag_number == 1:  # the cA BOOLEAN
            is_ca = element.content != b"\x00"
        elif element.tag_number == 2:  # the pathLenConstraint INTEGER
            path_length = element.integer()
    return is_ca, path_length


def _key_usage_cert_sign(value: bytes) -> bool:
    """Whether a KeyUsage BIT STRING asserts keyCertSign (bit 5, RFC 5280 4.2.1.3)."""
    content = asn1.parse(value).content  # one unused-bits byte, then the bits
    return len(content) >= 2 and bool(content[1] & 0x04)


def _extended_key_usages(value: bytes) -> List[str]:
    """The ExtendedKeyUsage purposes, named where known and dotted OIDs otherwise."""
    oids = [_oid(child) for child in asn1.parse(value).children]
    return [_EKU_NAMES.get(usage, usage) for usage in oids]


_CONSTRAINED_NAME_FORMS = (
    _GENERAL_NAME_EMAIL, _GENERAL_NAME_DNS, _GENERAL_NAME_URI, _GENERAL_NAME_IP,
)


def _general_name_pair(name: Node) -> Optional[Tuple[int, bytes]]:
    """A GeneralName as ``(form, value)`` for the name forms this constrains -- rfc822Name,
    dNSName, URI and iPAddress carry their value directly; directoryName ([4]) is EXPLICITly
    tagged, so its value is the wrapped Name. Other forms are not constrained (``None``)."""
    if name.tag_class != asn1.CLASS_CONTEXT:
        return None
    if name.tag_number == _GENERAL_NAME_DIR:
        return _GENERAL_NAME_DIR, name.children[0].raw
    if name.tag_number in _CONSTRAINED_NAME_FORMS:
        return name.tag_number, name.content
    return None


def _general_names(value: bytes) -> List[Tuple[int, bytes]]:
    """The GeneralNames in a SubjectAltName as ``(form, value)`` pairs (RFC 5280 4.2.1.6)."""
    pairs = []
    for general_name in asn1.parse(value).children:
        pair = _general_name_pair(general_name)
        if pair is not None:
            pairs.append(pair)
    return pairs


def _general_subtrees(value: bytes) -> Tuple[List[Tuple[int, bytes]], List[Tuple[int, bytes]]]:
    """The (permitted, excluded) subtrees of a NameConstraints extension as ``(form, base)``
    pairs (RFC 5280 4.2.1.10). permittedSubtrees is [0] and excludedSubtrees is [1]."""
    permitted: List[Tuple[int, bytes]] = []
    excluded: List[Tuple[int, bytes]] = []
    for subtrees in asn1.parse(value).children:
        if subtrees.tag_class != asn1.CLASS_CONTEXT:
            continue
        bases = []
        for subtree in subtrees.children:  # each GeneralSubtree SEQUENCE; base is child 0
            pair = _general_name_pair(subtree.children[0])
            if pair is not None:
                bases.append(pair)
        if subtrees.tag_number == 0:  # permittedSubtrees
            permitted = bases
        elif subtrees.tag_number == 1:  # excludedSubtrees
            excluded = bases
    return permitted, excluded


def _extensions(extensions: Node, info: CertificateInfo) -> None:
    for extension in extensions.children:
        oid = _oid(extension.children[0])
        value = extension.children[-1].content  # skips the optional 'critical' BOOLEAN
        if oid == _OID_SAN:
            for general_name in asn1.parse(value).children:
                if general_name.tag_class == asn1.CLASS_CONTEXT and (
                    general_name.tag_number == _GENERAL_NAME_DNS
                ):
                    info.sans.append(general_name.content.decode("ascii", "replace"))
        elif oid == _OID_BASIC_CONSTRAINTS:
            info.is_ca, info.path_length = _basic_constraints(value)
        elif oid == _OID_KEY_USAGE:
            info.key_cert_sign = _key_usage_cert_sign(value)
        elif oid == _OID_EKU:
            info.extended_key_usages = _extended_key_usages(value)
        elif oid == _OID_AIA:
            _parse_aia(value, info)
        elif oid == _OID_CRL_DISTRIBUTION:
            _parse_crl_distribution(value, info)
        elif oid == _OID_SCT:
            info.sct_count = _count_scts(value)
        elif oid == _OID_TLS_FEATURE:
            info.ocsp_must_staple = _tls_feature_must_staple(value)


def _split_certificate(der: bytes) -> Tuple[Node, int]:
    """Parse a Certificate; return it and the tbs child offset a version tag adds."""
    certificate = asn1.parse(der)
    first = certificate.children[0].children[0]
    index = 1 if first.tag_class == asn1.CLASS_CONTEXT and first.tag_number == 0 else 0
    return certificate, index


def spki_der(der: bytes) -> bytes:
    """The raw SubjectPublicKeyInfo DER of a certificate (DANE selector 1, RFC 6698).

    The DANE ``selector`` chooses what a TLSA record binds to: the whole certificate
    (0) or just its public key (1). Selector 1 is the common one -- it survives a
    certificate renewal that keeps the key -- so validating it needs these bytes.
    """
    try:
        certificate, index = _split_certificate(der)
        return certificate.children[0].children[index + 5].raw
    except (Asn1Error, IndexError, ValueError) as exc:
        raise CertificateError(f"cannot read public key info: {exc}") from exc


def parse_certificate(der: bytes) -> CertificateInfo:
    """Parse one DER certificate into a :class:`CertificateInfo`."""
    try:
        certificate, index = _split_certificate(der)
        tbs = certificate.children[0]
        signature_algorithm = certificate.children[1]

        serial = tbs.children[index]
        issuer = tbs.children[index + 2]
        validity = tbs.children[index + 3]
        subject = tbs.children[index + 4]
        spki = tbs.children[index + 5]

        info = CertificateInfo()
        info.serial = format(serial.integer(), "X")
        info.signature_algorithm = _SIGNATURE_ALGORITHMS.get(
            _oid(signature_algorithm.children[0]), _oid(signature_algorithm.children[0])
        )
        info.issuer = _name(issuer)
        info.subject = _name(subject)
        info.not_before = _time(validity.children[0])
        info.not_after = _time(validity.children[1])
        info.is_self_signed = issuer.content == subject.content
        _public_key(spki, info)
        for extra in tbs.children[index + 6 :]:
            if extra.tag_class == asn1.CLASS_CONTEXT and extra.tag_number == 3:
                _extensions(extra.children[0], info)
        info.fingerprint_sha256 = hashlib.sha256(der).hexdigest()
        return info
    except (Asn1Error, IndexError, ValueError) as exc:
        raise CertificateError(f"cannot parse certificate: {exc}") from exc


# --------------------------------------------------------------------------- #
# Retrieval
# --------------------------------------------------------------------------- #


def _parse_certificate_message(body: bytes) -> List[bytes]:
    reader = Reader(body)
    entries = Reader(reader.read(reader.read_u24()))
    certificates: List[bytes] = []
    while not entries.eof():
        certificates.append(entries.read_vector(3))
    return certificates


def _collect_certificate(sock: socket.socket) -> Tuple[List[bytes], Optional[str]]:
    buffer = b""
    consumed = 0
    while True:
        header = _recv_exact(sock, 5)
        if header is None:
            return [], "server closed the connection before the certificate"
        length = int.from_bytes(header[3:5], "big")
        fragment = _recv_exact(sock, length) if length else b""
        if fragment is None:
            return [], "truncated TLS record"
        if header[0] == CONTENT_TYPE_ALERT and len(fragment) >= 2:
            return [], f"server sent an alert: {alert_description(fragment[1])}"
        if header[0] != CONTENT_TYPE_HANDSHAKE:
            return [], f"unexpected TLS record type {header[0]}"

        buffer += fragment
        while True:
            try:
                message_type, message_body = read_handshake(Reader(buffer[consumed:]))
            except TlsError:
                break  # the message spans more records; read another
            consumed += 4 + len(message_body)
            if message_type == HANDSHAKE_TYPE_CERTIFICATE:
                try:
                    return _parse_certificate_message(message_body), None
                except TlsError as exc:
                    return [], f"malformed Certificate message: {exc}"
            if message_type == HANDSHAKE_TYPE_SERVER_HELLO_DONE:
                return [], "server finished the handshake without a certificate"


def retrieve_certificate_chain(
    host: str,
    port: int,
    sni: str = "",
    timeout: float = DEFAULT_TIMEOUT,
    cipher_suites: Optional[List[int]] = None,
) -> Tuple[List[bytes], Optional[str]]:
    """Fetch the DER certificates a server presents, over a TLS 1.2 handshake.

    ``cipher_suites`` narrows the offer; a list restricted to one authentication type
    (RSA or ECDSA) steers which certificate a dual-certificate server returns."""
    hello = build_client_hello(
        _TLS12,
        cipher_suites if cipher_suites is not None else list(LEGACY_CIPHER_SUITES),
        server_name=sni,
        groups=_DEFAULT_GROUPS,
        signature_schemes=_DEFAULT_SIGNATURE_SCHEMES,
    )
    try:
        sock = socket.create_connection((host, port), timeout)
    except OSError as exc:
        return [], f"connection failed: {exc}"
    try:
        sock.settimeout(timeout)
        sock.sendall(hello)
        return _collect_certificate(sock)
    except OSError as exc:
        return [], f"network error: {exc}"
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# Chain analysis
# --------------------------------------------------------------------------- #


def cn_of(subject: str) -> str:
    """The common name from a subject string, or empty if it has none."""
    for part in subject.split(", "):
        if part.startswith("CN="):
            return part[3:]
    return ""


def name_matches(pattern: str, host: str) -> bool:
    """Whether a certificate name (possibly a ``*.`` wildcard) covers a host."""
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]
        if host.endswith(suffix):
            head = host[: -len(suffix)]
            return bool(head) and "." not in head
    return False


def hostname_matches(host: str, leaf: CertificateInfo) -> bool:
    candidates = list(leaf.sans)
    if not candidates:
        common_name = cn_of(leaf.subject)
        if common_name:
            candidates = [common_name]
    host_lower = host.lower()
    return any(name_matches(candidate.lower(), host_lower) for candidate in candidates)


# --------------------------------------------------------------------------- #
# Chain signature verification (internal consistency, without a trust store)
# --------------------------------------------------------------------------- #

_RSA_KEY_OID = "1.2.840.113549.1.1.1"
_EC_KEY_OID = "1.2.840.10045.2.1"
_ED25519_OID = "1.3.101.112"  # RFC 8410: the OID for both the key and the signature
_RSA_PKCS1_HASHES = {
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
}
_ECDSA_HASHES = {
    "1.2.840.10045.4.3.2": "sha256",
    "1.2.840.10045.4.3.3": "sha384",
    "1.2.840.10045.4.3.4": "sha512",
}
_RSA_PSS_OID = "1.2.840.113549.1.1.10"
#: Hash OIDs that can appear inside RSASSA-PSS parameters (RFC 4055).
_PSS_HASHES = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}
_PSS_DEFAULTS = ("sha1", "sha1", 20)  # RFC 4055: the DEFAULTs when a field is omitted


@dataclass
class _SignedCert:
    """Just the fields a chain-signature check needs, pre-parsed."""

    tbs: bytes
    signature_oid: str
    rsa_signature: bytes  # the raw signatureValue octets (a DER SEQUENCE for ECDSA)
    self_signed: bool
    is_ca: bool  # whether BasicConstraints marks it a CA -- required to sign a child
    path_length: Optional[int]  # BasicConstraints pathLenConstraint, None when absent
    key_cert_sign: Optional[bool]  # KeyUsage keyCertSign, None when no KeyUsage extension
    not_before: Optional[int]  # validity start (Unix time), for path validity
    not_after: Optional[int]  # validity end (Unix time)
    issuer: bytes  # the issuer Name, DER-encoded, for chaining to its signer
    subject: bytes  # the subject Name, DER-encoded, for a trust store to key on
    rsa_key: Optional[Tuple[int, int]]  # (modulus, exponent) if the key is RSA
    ec_curve: Optional[ec.Curve]  # the curve if the key is a supported EC one
    ec_point: bytes  # the uncompressed EC public point
    ed_public: bytes  # the 32-byte public key if the key is Ed25519
    pss_params: Optional[Tuple[str, str, int]]  # (hash, MGF1 hash, salt) if PSS-signed
    # NameConstraints (RFC 5280 4.2.1.10), as (GeneralName form, value) pairs:
    identities: List[Tuple[int, bytes]] = field(default_factory=list)  # this cert's own names
    permitted: List[Tuple[int, bytes]] = field(default_factory=list)  # permittedSubtrees bases
    excluded: List[Tuple[int, bytes]] = field(default_factory=list)  # excludedSubtrees bases


def _pss_parameters(algorithm: Node) -> Optional[Tuple[str, str, int]]:
    """(hash, MGF1 hash, salt length) from an RSASSA-PSS signature AlgorithmIdentifier.

    The parameters are optional, context-tagged fields (RFC 4055); an omitted one takes
    its RFC default and an unrecognised hash makes the signature unverifiable here (None).
    """
    hash_name, mgf_hash_name, salt_length = _PSS_DEFAULTS
    if len(algorithm.children) > 1:  # the RSASSA-PSS-params SEQUENCE is present
        for element in algorithm.children[1].children:
            if element.tag_class != asn1.CLASS_CONTEXT:
                continue
            if element.tag_number == 0:  # hashAlgorithm
                found = _PSS_HASHES.get(_oid(element.children[0].children[0]))
                if found is None:
                    return None
                hash_name = found
            elif element.tag_number == 1:  # maskGenAlgorithm: MGF1 over its own hash
                found = _PSS_HASHES.get(_oid(element.children[0].children[1].children[0]))
                if found is None:
                    return None
                mgf_hash_name = found
            elif element.tag_number == 2:  # saltLength
                salt_length = element.children[0].integer()
    return hash_name, mgf_hash_name, salt_length


def _find_extension(tbs: Node, index: int, oid: str) -> Optional[bytes]:
    """The value octets of the extension with ``oid`` in a TBSCertificate, or ``None``."""
    for extra in tbs.children[index + 6 :]:
        if extra.tag_class == asn1.CLASS_CONTEXT and extra.tag_number == 3:  # [3] extensions
            for extension in extra.children[0].children:
                if _oid(extension.children[0]) == oid:
                    return extension.children[-1].content  # after the optional 'critical'
    return None


def _signed_cert(der: bytes) -> Optional[_SignedCert]:
    """Extract the verification material, or ``None`` if the DER cannot be parsed."""
    try:
        parsed = parse_certificate(der)  # extension-level facts: BasicConstraints, validity
        certificate, index = _split_certificate(der)
        tbs = certificate.children[0]
        signature_oid = _oid(certificate.children[1].children[0])
        signature = certificate.children[2].content[1:]  # drop the unused-bits byte
        issuer = tbs.children[index + 2]
        subject = tbs.children[index + 4]
        spki = tbs.children[index + 5]
        key_oid = _oid(spki.children[0].children[0])
        key_bits = spki.children[1].content[1:]

        # NameConstraints material: the cert's own names (its SANs plus its subject as a
        # directoryName) and, if it is a constraining CA, its permitted/excluded subtrees.
        san = _find_extension(tbs, index, _OID_SAN)
        identities = _general_names(san) if san is not None else []
        identities.append((_GENERAL_NAME_DIR, subject.raw))
        constraints = _find_extension(tbs, index, _OID_NAME_CONSTRAINTS)
        permitted, excluded = (
            _general_subtrees(constraints) if constraints is not None else ([], [])
        )

        pss_params = None
        if signature_oid == _RSA_PSS_OID:
            pss_params = _pss_parameters(certificate.children[1])

        rsa_key = None
        ec_curve = None
        ec_point = b""
        ed_public = b""
        if key_oid == _RSA_KEY_OID:
            key = asn1.parse(key_bits)
            rsa_key = (key.children[0].integer(), key.children[1].integer())
        elif key_oid == _EC_KEY_OID:
            ec_curve = ec.CURVES_BY_OID.get(_oid(spki.children[0].children[1]))
            ec_point = key_bits
        elif key_oid == _ED25519_OID:
            ed_public = key_bits  # the raw 32-byte public key

        return _SignedCert(
            tbs=tbs.raw,
            signature_oid=signature_oid,
            rsa_signature=signature,
            self_signed=issuer.raw == subject.raw,
            is_ca=parsed.is_ca,
            path_length=parsed.path_length,
            key_cert_sign=parsed.key_cert_sign,
            not_before=parsed.not_before,
            not_after=parsed.not_after,
            issuer=issuer.raw,
            subject=subject.raw,
            rsa_key=rsa_key,
            ec_curve=ec_curve,
            ec_point=ec_point,
            ed_public=ed_public,
            pss_params=pss_params,
            identities=identities,
            permitted=permitted,
            excluded=excluded,
        )
    except (Asn1Error, CertificateError, IndexError, ValueError):
        return None


def verify_signature(
    signed: bytes, signature_oid: str, signature: bytes, signer: _SignedCert,
    pss_params: Optional[Tuple[str, str, int]] = None,
) -> Optional[bool]:
    """Whether ``signed`` bears a valid signature by ``signer``'s key under
    ``signature_oid``. ``None`` when the algorithm or the signer's key is one this does
    not verify -- a caller must read None as *unverified*, never as valid. Used for both
    certificate chains and the tbs of an OCSP response or a CRL.
    """
    rsa_hash = _RSA_PKCS1_HASHES.get(signature_oid)
    if rsa_hash is not None:
        if signer.rsa_key is None:
            return None
        modulus, exponent = signer.rsa_key
        return rsa.verify_pkcs1(modulus, exponent, signature, signed, rsa_hash)
    if signature_oid == _RSA_PSS_OID:
        if signer.rsa_key is None or pss_params is None:
            return None
        modulus, exponent = signer.rsa_key
        hash_name, mgf_hash_name, salt_length = pss_params
        return rsa.verify_pss(
            modulus, exponent, signature, signed, hash_name, mgf_hash_name, salt_length
        )
    ecdsa_hash = _ECDSA_HASHES.get(signature_oid)
    if ecdsa_hash is not None:
        if signer.ec_curve is None:
            return None
        try:
            pair = asn1.parse(signature)
            r, s = pair.children[0].integer(), pair.children[1].integer()
        except (Asn1Error, IndexError):
            return None
        return ecdsa.verify(signer.ec_curve, signer.ec_point, r, s, signed, ecdsa_hash)
    if signature_oid == _ED25519_OID:
        if not signer.ed_public:
            return None
        return ed25519.verify(signer.ed_public, signed, signature)
    return None  # a signature algorithm this does not verify


def _verify_link(cert: _SignedCert, issuer: _SignedCert) -> Optional[bool]:
    """Whether ``cert``'s signature verifies under ``issuer``'s key; ``None`` if the
    algorithm is one this does not check."""
    return verify_signature(
        cert.tbs, cert.signature_oid, cert.rsa_signature, issuer, cert.pss_params
    )


def verify_chain_signatures(ders: List[bytes]) -> Tuple[Optional[bool], str]:
    """Verify each presented link (cert signed by the next, a self-signed one by
    itself). Returns ``(valid, note)`` -- valid is ``None`` when nothing could be
    checked without the issuing root."""
    parsed = [_signed_cert(der) for der in ders]
    if any(cert is None for cert in parsed):
        return None, "a certificate could not be parsed to verify its signature"
    certs = [cert for cert in parsed if cert is not None]  # all present, now non-optional

    verdicts: List[Optional[bool]] = []
    for position, cert in enumerate(certs):
        if position + 1 < len(certs):
            issuer = certs[position + 1]
        elif cert.self_signed:
            issuer = cert
        else:
            continue  # top of the presented chain, not self-signed: needs the root
        verdicts.append(_verify_link(cert, issuer))

    if not verdicts:
        return None, "the presented chain offers no link to verify without its root"
    if False in verdicts:
        return False, "a certificate signature did not verify against its issuer"
    if None in verdicts:
        return None, "a chain signature uses an algorithm not verified here"
    return True, "every presented certificate signature verifies"


# --------------------------------------------------------------------------- #
# Trust: does the presented chain build to a root we trust?
# --------------------------------------------------------------------------- #

TrustStore = Dict[bytes, _SignedCert]  # subject Name (DER) -> the trusted root

#: Where common systems keep their CA bundle; the first that exists is used.
_SYSTEM_TRUST_PATHS = [
    "/etc/ssl/certs/ca-certificates.crt",  # Debian, Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",  # Fedora, RHEL
    "/etc/ssl/cert.pem",  # Alpine, the BSDs, macOS
]


def _pem_certificates(text: str) -> List[bytes]:
    """Every certificate DER in a PEM bundle (blocks that do not decode are skipped)."""
    ders: List[bytes] = []
    for block in text.split("-----BEGIN CERTIFICATE-----")[1:]:
        body = block.split("-----END CERTIFICATE-----")[0]
        with contextlib.suppress(binascii.Error, ValueError):
            ders.append(base64.b64decode("".join(body.split())))
    return ders


def system_trust_path() -> Optional[Path]:
    """The system CA bundle path, or ``None`` if no known location exists."""
    for candidate in _SYSTEM_TRUST_PATHS:
        path = Path(candidate)
        if path.exists():
            return path
    return None


def load_trust_store(path: Optional[str] = None) -> TrustStore:
    """Load trusted roots from a PEM bundle, defaulting to the system store."""
    source = Path(path) if path is not None else system_trust_path()
    if source is None or not source.exists():
        return {}
    store: TrustStore = {}
    for der in _pem_certificates(source.read_text(encoding="utf-8", errors="replace")):
        root = _signed_cert(der)
        if root is not None:
            store[root.subject] = root
    return store


def _path_length_ok(path: List[_SignedCert]) -> bool:
    """Whether every CA's pathLenConstraint holds over the walked path (RFC 5280 4.2.1.9).

    A CA's constraint bounds how many non-self-issued CA certificates may sit between
    it and the end entity; ``pathlen:0`` means it may only sign end-entity certificates.
    ``path`` is leaf-first, so the CAs below ``path[position]`` are ``path[1:position]``.
    """
    for position in range(1, len(path)):
        limit = path[position].path_length
        if limit is None:
            continue
        below = sum(1 for middle in path[1:position] if not middle.self_signed)
        if below > limit:
            return False
    return True


def _path_validity(path: List[_SignedCert], now: float) -> Optional[TrustStatus]:
    """EXPIRED or NOT_YET_VALID if a certificate in the walked path is outside its
    validity period at ``now`` (RFC 5280 6.1.3: every path certificate must be current);
    ``None`` when the whole path is within its dates."""
    for cert in path:
        if cert.not_after is not None and cert.not_after < now:
            return TrustStatus.EXPIRED
        if cert.not_before is not None and cert.not_before > now:
            return TrustStatus.NOT_YET_VALID
    return None


def _dns_within(name: str, base: str) -> bool:
    """Whether a dNSName falls within a NameConstraints subtree base (RFC 5280 4.2.1.10):
    case-insensitive; an empty base matches every name; otherwise the name must equal the
    base or be a subdomain of it on a label boundary (``a.example.com`` is within
    ``example.com`` but ``notexample.com`` is not)."""
    name, base = name.lower().rstrip("."), base.lower().rstrip(".")
    if base == "":
        return True
    return name == base or name.endswith("." + base)


def _ip_within(address: bytes, base: bytes) -> bool:
    """Whether an iPAddress falls within an iPAddress constraint (RFC 5280 4.2.1.10): the
    base is the network address followed by its mask (8 bytes for IPv4, 32 for IPv6)."""
    half = len(address)
    if len(base) != 2 * half:  # a v4 address cannot match a v6 constraint or vice versa
        return False
    network, mask = base[:half], base[half:]
    return all(address[i] & mask[i] == network[i] & mask[i] for i in range(half))


def _email_within(email: str, base: str) -> bool:
    """rfc822Name matching (RFC 5280 4.2.1.10): a base with a local part matches that exact
    mailbox; a bare host matches every mailbox at it; a leading-dot base matches subdomains."""
    email, base = email.lower(), base.lower()
    if "@" in base:
        return email == base
    host = email.rpartition("@")[2]
    if base.startswith("."):
        return host.endswith(base)
    return host == base


def _uri_within(uri: str, base: str) -> bool:
    """uniformResourceIdentifier matching (RFC 5280 4.2.1.10): the constraint applies to the
    host of the URI, matched like a dNSName."""
    authority = uri.split("://", 1)[-1].split("/", 1)[0]
    host = authority.rpartition("@")[2].split(":", 1)[0]
    return _dns_within(host, base)


def _dir_within(name: bytes, base: bytes) -> bool:
    """directoryName matching (RFC 5280 4.2.1.10): the base's RDN sequence is an initial
    sub-sequence of the certificate's -- an empty base matches every name."""
    try:
        name_rdns = [rdn.raw for rdn in asn1.parse(name).children]
        base_rdns = [rdn.raw for rdn in asn1.parse(base).children]
    except (Asn1Error, IndexError):
        return False
    return name_rdns[: len(base_rdns)] == base_rdns


def _name_within(form: int, name: bytes, base: bytes) -> bool:
    """Whether ``name`` falls within constraint ``base``, dispatched on the GeneralName form
    (both were collected by ``_general_name_pair``, so the form is one of the five)."""
    if form == _GENERAL_NAME_DNS:
        return _dns_within(name.decode("ascii", "replace"), base.decode("ascii", "replace"))
    if form == _GENERAL_NAME_IP:
        return _ip_within(name, base)
    if form == _GENERAL_NAME_EMAIL:
        return _email_within(name.decode("ascii", "replace"), base.decode("ascii", "replace"))
    if form == _GENERAL_NAME_URI:
        return _uri_within(name.decode("ascii", "replace"), base.decode("ascii", "replace"))
    return _dir_within(name, base)  # _GENERAL_NAME_DIR


def _cert_within_constraints(cert: _SignedCert, ca: _SignedCert) -> bool:
    """Whether every name ``cert`` carries respects ``ca``'s NameConstraints: within the
    permitted subtrees of its own form (if that form is constrained) and outside every
    excluded one (RFC 5280 4.2.1.10)."""
    for form, name in cert.identities:
        if any(_name_within(form, name, base) for kind, base in ca.excluded if kind == form):
            return False
        permitted = [base for kind, base in ca.permitted if kind == form]
        if permitted and not any(_name_within(form, name, base) for base in permitted):
            return False
    return True


def _name_constraints_ok(path: List[_SignedCert], root: _SignedCert) -> bool:
    """Whether every certificate's names satisfy the NameConstraints of every CA above it
    (RFC 5280 6.1.4) -- across all GeneralName forms and every certificate in the path,
    not just the leaf's dNSNames."""
    for position, cert in enumerate(path):
        for ca in [*path[position + 1 :], root]:
            if not _cert_within_constraints(cert, ca):
                return False
    return True


def evaluate_trust(
    ders: List[bytes], store: TrustStore, now: Optional[float] = None
) -> TrustStatus:
    """Whether the presented chain builds to a root in ``store``.

    A path that reaches a trusted root but contains a presented certificate outside
    its validity period is EXPIRED or NOT_YET_VALID rather than TRUSTED -- an expired
    intermediate fails path validation just as an expired leaf does. The store root
    itself is a trust anchor, taken on the user's word, so its dates are not judged.
    """
    moment = now if now is not None else time.time()
    if not store:
        return TrustStatus.NOT_CHECKED
    parsed = [_signed_cert(der) for der in ders]
    if any(cert is None for cert in parsed):
        return TrustStatus.UNKNOWN
    chain = [cert for cert in parsed if cert is not None]
    if chain[0].self_signed:
        return TrustStatus.SELF_SIGNED
    for position, cert in enumerate(chain):
        root = store.get(cert.issuer)
        if root is not None and _verify_link(cert, root) is True:
            path = chain[: position + 1]
            # The signature path reaches a trusted root. It must also respect every
            # CA's pathLenConstraint and NameConstraints (structural, so untrusted)...
            if not _path_length_ok(path) or not _name_constraints_ok(path, root):
                return TrustStatus.UNTRUSTED
            # ...and every walked certificate must be within its validity dates.
            problem = _path_validity(path, moment)
            return TrustStatus.TRUSTED if problem is None else problem
        if position + 1 < len(chain):
            issuer = chain[position + 1]
            # A presented intermediate must be a CA (a non-CA signing another cert is
            # the classic BasicConstraints bypass), must not carry a KeyUsage that
            # withholds keyCertSign, and must actually sign the child.
            if (
                not issuer.is_ca
                or issuer.key_cert_sign is False
                or _verify_link(cert, issuer) is not True
            ):
                return TrustStatus.UNTRUSTED
    return TrustStatus.UNTRUSTED  # walked the chain without reaching a trusted root


def build_certificate_chain(
    host: str, ders: List[bytes], trust_store: Optional[TrustStore] = None
) -> CertificateChain:
    """Parse the presented DERs and note what can be told without a trust store."""
    if not ders:
        return CertificateChain(error="the server presented no certificate")
    certificates: List[CertificateInfo] = []
    for der in ders:
        try:
            certificates.append(parse_certificate(der))
        except CertificateError as exc:
            return CertificateChain(error=str(exc))
    leaf = certificates[0]  # ders was non-empty, so there is always a leaf
    if len(ders) >= 2 and leaf.sct_count:
        # Verify the embedded SCTs against the known CT logs. Needs the issuer (ders[1])
        # to rebuild the precertificate the log signed; unverifiable ones simply do not
        # count -- a certificate is never *credited* with transparency it cannot prove.
        verdicts = ct.verify_embedded_scts(ders[0], ders[1])
        leaf.verified_scts = sum(1 for verdict in verdicts if verdict.verified)
        leaf.sct_logs = sorted(
            {verdict.log_name for verdict in verdicts if verdict.verified and verdict.log_name}
        )
    chain = CertificateChain(certificates=certificates)
    chain.hostname_matches = hostname_matches(host, leaf)
    if trust_store is None:
        chain.trust = TrustStatus.SELF_SIGNED if leaf.is_self_signed else TrustStatus.NOT_CHECKED
    else:
        chain.trust = evaluate_trust(ders, trust_store)
    # "Complete" is structural: the chain builds to a trusted root, even when a date
    # problem (EXPIRED / NOT_YET_VALID) keeps that path from actually validating.
    chain.complete = chain.trust in (
        TrustStatus.TRUSTED, TrustStatus.EXPIRED, TrustStatus.NOT_YET_VALID
    )
    chain.signatures_valid, chain.signature_note = verify_chain_signatures(ders)
    return chain


def _ca_issuers_url(der: bytes) -> Optional[str]:
    """The AIA caIssuers URL a certificate names for its own issuer, or ``None``."""
    try:
        return parse_certificate(der).ca_issuers_url or None
    except CertificateError:
        return None


def _issuer_already_present(child: _SignedCert, ders: List[bytes]) -> bool:
    """Whether some certificate in ``ders`` already signs ``child`` -- so its issuer is in
    hand and the chain is merely short a root or misordered, not missing an intermediate."""
    for der in ders:
        candidate = _signed_cert(der)
        if candidate is not None and _verify_link(child, candidate) is True:
            return True
    return False


def complete_chain_via_aia(
    ders: List[bytes], fetch: Callable[[str], Optional[bytes]]
) -> Tuple[List[bytes], bool]:
    """Fetch a missing intermediate named in the top certificate's AIA caIssuers URL.

    Standard client behaviour (RFC 5280 4.2.2.1): when a server omits the intermediate,
    the top presented certificate points at its issuer's certificate over ``http://``.
    The fetched certificate is appended ONLY when it truly is that issuer -- its subject
    is the child's issuer AND its key verifies the child's signature -- so a wrong or
    hostile certificate at that URL can never enter the chain. And an appended
    intermediate can only help reach a root that is *already* trusted; it never confers
    trust of its own. One intermediate is fetched (the common single-omission case);
    returns ``(possibly_extended_ders, fetched)``.
    """
    if not ders:
        return ders, False
    top = _signed_cert(ders[-1])
    if top is None or top.self_signed or _issuer_already_present(top, ders[:-1]):
        return ders, False
    url = _ca_issuers_url(ders[-1])
    if url is None:
        return ders, False
    fetched = fetch(url)
    if fetched is None:
        return ders, False
    issuer = _signed_cert(fetched)
    if issuer is None or issuer.subject != top.issuer or _verify_link(top, issuer) is not True:
        return ders, False
    return [*ders, fetched], True
