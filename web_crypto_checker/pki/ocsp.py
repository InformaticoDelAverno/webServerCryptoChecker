"""Asking an OCSP responder whether a certificate has been revoked, and trusting the
answer only when it is authentic.

It POSTs an OCSP request to the responder the certificate names (its AIA), so it runs
only behind ``--active``. The request and response are built and parsed by hand. The
answer is trusted only if the response's signature verifies under an authorised key --
the issuer itself, or a delegated responder the issuer signed and marked
id-kp-OCSPSigning -- AND the response is about *this* certificate (a matching CertID)
AND it is current. An unauthenticated, mismatched, or stale response yields an error,
never a ``good``/``revoked`` a man in the middle could forge.
"""

from __future__ import annotations

import hashlib
import time
from typing import List, Optional, Tuple

from .. import webclient
from ..crypto import asn1
from ..crypto.asn1 import CLASS_CONTEXT, Asn1Error, Node
from ..tls.probe import DEFAULT_TIMEOUT
from .certificates import (
    _oid,
    _pss_parameters,
    _signed_cert,
    _SignedCert,
    _time,
    parse_certificate,
    verify_signature,
)

_SHA1_OID = bytes.fromhex("2b0e03021a")  # 1.3.14.3.2.26
_SHA1_OID_DOTTED = "1.3.14.3.2.26"
_RSA_PSS_OID = "1.2.840.113549.1.1.10"
_OCSP_SIGNING = "OCSPSigning"
_OCSP_STATUS = {0: "good", 1: "revoked", 2: "unknown"}


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(content)) + content


def _certificate_fields(der: bytes) -> Tuple[Node, int]:
    certificate = asn1.parse(der)
    tbs = certificate.children[0]
    first = tbs.children[0]
    index = 1 if first.tag_class == CLASS_CONTEXT and first.tag_number == 0 else 0
    return tbs, index


def _cert_id(leaf_der: bytes, issuer_der: bytes) -> Optional[Tuple[bytes, bytes, int]]:
    """The (issuer-name SHA-1, issuer-key SHA-1, serial) that identifies the leaf."""
    try:
        leaf_tbs, leaf_index = _certificate_fields(leaf_der)
        issuer_tbs, issuer_index = _certificate_fields(issuer_der)
        issuer_name = leaf_tbs.children[leaf_index + 2].raw  # the leaf's issuer Name
        serial = leaf_tbs.children[leaf_index].integer()
        issuer_key = issuer_tbs.children[issuer_index + 5].children[1].content[1:]
    except (Asn1Error, IndexError):
        return None
    return hashlib.sha1(issuer_name).digest(), hashlib.sha1(issuer_key).digest(), serial


def build_request(leaf_der: bytes, issuer_der: bytes) -> Optional[bytes]:
    """Build a DER OCSP request for ``leaf_der`` issued by ``issuer_der``."""
    fields = _cert_id(leaf_der, issuer_der)
    if fields is None:
        return None
    name_hash, key_hash, serial = fields
    algorithm = _der(0x30, _der(0x06, _SHA1_OID) + _der(0x05, b""))
    serial_der = _der(0x02, serial.to_bytes(max(1, (serial.bit_length() + 8) // 8), "big"))
    cert_id = _der(0x30, algorithm + _der(0x04, name_hash) + _der(0x04, key_hash) + serial_der)
    return _der(0x30, _der(0x30, _der(0x30, _der(0x30, cert_id))))


def _embedded_certs(basic: Node) -> List[bytes]:
    """The DER of any responder certificates the BasicOCSPResponse carries ([0] certs).

    The certs field is the only element that may follow the signature, so it is at index
    3 when present (RFC 6960 4.2.1)."""
    if len(basic.children) > 3 and basic.children[3].tag_class == CLASS_CONTEXT:
        return [cert.raw for cert in basic.children[3].children[0].children]
    return []


def _authorised_signers(basic: Node, issuer: _SignedCert) -> List[_SignedCert]:
    """The signers whose signature would make the response authentic: the issuer, plus
    any embedded certificate the issuer signed and marked for OCSP signing (RFC 6960
    4.2.2.2). Each returned item is a parsed signer usable with ``verify_signature``."""
    signers = [issuer]
    for cert_der in _embedded_certs(basic):
        responder = _signed_cert(cert_der)
        if responder is None:
            continue
        signed_by_issuer = verify_signature(
            responder.tbs, responder.signature_oid, responder.rsa_signature,
            issuer, responder.pss_params,
        )
        purposes = parse_certificate(cert_der).extended_key_usages
        if signed_by_issuer is True and _OCSP_SIGNING in purposes:
            signers.append(responder)
    return signers


def _response_is_authentic(basic: Node, issuer: _SignedCert) -> bool:
    """Whether the BasicOCSPResponse signature verifies under an authorised signer."""
    tbs = basic.children[0]
    algorithm = basic.children[1]
    oid = _oid(algorithm.children[0])
    signature = basic.children[2].content[1:]  # BIT STRING, drop the unused-bits byte
    pss = _pss_parameters(algorithm) if oid == _RSA_PSS_OID else None
    return any(
        verify_signature(tbs.raw, oid, signature, signer, pss) is True
        for signer in _authorised_signers(basic, issuer)
    )


def _single_response_status(
    tbs: Node, expected: Tuple[bytes, bytes, int], now: float
) -> Optional[str]:
    """The status of the SingleResponse whose CertID matches ``expected`` and that is
    current, or ``None`` when there is no matching, fresh response."""
    responses = next(child for child in tbs.children if child.tag == 0x30)
    for single in responses.children:
        cert_id = single.children[0]
        if _oid(cert_id.children[0].children[0]) != _SHA1_OID_DOTTED:
            continue  # a CertID hash this does not compute
        fields = (cert_id.children[1].content, cert_id.children[2].content,
                  cert_id.children[3].integer())
        if fields != expected:
            continue
        this_update = _time(single.children[2])
        # nextUpdate is the optional [0] element right after thisUpdate (RFC 6960 4.2.1).
        next_update = None
        if len(single.children) > 3 and single.children[3].tag_class == CLASS_CONTEXT \
                and single.children[3].tag_number == 0:
            next_update = _time(single.children[3].children[0])
        if this_update > now or (next_update is not None and now > next_update):
            return None  # stale: outside the response's validity window
        return _OCSP_STATUS.get(single.children[1].tag_number, "unknown")
    return None


def authenticated_status(
    der: bytes, leaf_der: bytes, issuer_der: bytes, now: Optional[float] = None
) -> Tuple[str, Optional[str]]:
    """The leaf's status from an OCSP response, trusted only if the response is
    authentic, about this leaf, and current. Returns ``(status, error)``."""
    moment = now if now is not None else time.time()
    expected = _cert_id(leaf_der, issuer_der)
    issuer = _signed_cert(issuer_der)
    if expected is None or issuer is None:
        return "", "could not read the certificate"
    try:
        response = asn1.parse(der)
        if response.children[0].integer() != 0:  # OCSPResponseStatus, 0 == successful
            return "", "OCSP responder returned an error status"
        response_bytes = response.children[1].children[0]  # [0] EXPLICIT -> ResponseBytes
        basic = asn1.parse(response_bytes.children[1].content)  # BasicOCSPResponse
        if not _response_is_authentic(basic, issuer):
            return "", "OCSP response signature did not verify"
        status = _single_response_status(basic.children[0], expected, moment)
    except (Asn1Error, IndexError, StopIteration, ValueError):
        return "", "malformed OCSP response"
    if status is None:
        return "", "OCSP response does not cover this certificate, or is stale"
    return status, None


def check_ocsp(
    leaf_der: bytes, issuer_der: bytes, url: str, timeout: float = DEFAULT_TIMEOUT
) -> Tuple[str, Optional[str]]:
    """Query the responder for the leaf's status, trusting only an authentic answer."""
    request = build_request(leaf_der, issuer_der)
    if request is None:
        return "", "could not build the OCSP request"
    body, error = webclient.http_request(
        url, "POST", timeout, request, "application/ocsp-request"
    )
    if error is not None:
        return "", error
    assert body is not None  # a body comes back whenever there is no error
    return authenticated_status(body, leaf_der, issuer_der)
