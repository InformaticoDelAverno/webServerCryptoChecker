"""Fetching a CRL and checking whether the certificate's serial is on it, trusting the
list only when it is authentic.

The OCSP fallback: where OCSP asks about one certificate, a CRL is the whole list of
serials a CA has revoked. This GETs the DER CRL the certificate's distribution point
names and looks for the leaf's serial -- but only after checking the CRL is signed by
the certificate's issuer, is that issuer's CRL, and is current. An unauthenticated,
wrong-issuer, or stale CRL yields an error, never a ``good`` an attacker could serve to
hide a revocation.
"""

from __future__ import annotations

import time
from typing import Optional, Set, Tuple

from .. import webclient
from ..crypto import asn1
from ..crypto.asn1 import Asn1Error, Node
from ..tls.probe import DEFAULT_TIMEOUT
from .certificates import (
    _oid,
    _pss_parameters,
    _signed_cert,
    _split_certificate,
    _time,
    verify_signature,
)

_TIME_TAGS = (0x17, 0x18)  # UTCTime, GeneralizedTime
_SEQUENCE = 0x30
_INTEGER = 0x02
_RSA_PSS_OID = "1.2.840.113549.1.1.10"


def _tbs_offset(tbs: Node) -> int:
    """The index of the signature AlgorithmIdentifier in a TBSCertList (0, or 1 when the
    optional version INTEGER precedes it)."""
    return 1 if tbs.children[0].tag == _INTEGER else 0


def parse_crl(der: bytes) -> Set[int]:
    """The set of revoked serial numbers in a DER CertificateList."""
    try:
        tbs = asn1.parse(der).children[0]
        start = _tbs_offset(tbs)
        position = start + 3  # past signature, issuer and thisUpdate
        if position < len(tbs.children) and tbs.children[position].tag in _TIME_TAGS:
            position += 1  # past the optional nextUpdate
        if position < len(tbs.children) and tbs.children[position].tag == _SEQUENCE:
            return {entry.children[0].integer() for entry in tbs.children[position].children}
        return set()
    except (Asn1Error, IndexError):
        return set()


def _serial(leaf_der: bytes) -> Optional[int]:
    try:
        certificate, index = _split_certificate(leaf_der)
        return certificate.children[0].children[index].integer()
    except (Asn1Error, IndexError):
        return None


def _crl_is_authentic(der: bytes, issuer_der: bytes, now: float) -> bool:
    """Whether the CRL is signed by ``issuer_der``, names it as the issuer, and is
    current (RFC 5280 5): every precondition for trusting its revoked-serial list."""
    issuer = _signed_cert(issuer_der)
    if issuer is None:
        return False
    try:
        crl = asn1.parse(der)
        tbs = crl.children[0]
        start = _tbs_offset(tbs)
        # The cheap structural checks first, so a wrong-issuer or stale CRL is rejected
        # without an expensive signature verification; the signature still gates the True.
        if tbs.children[start + 1].raw != issuer.subject:  # the CRL's issuer Name
            return False
        if _time(tbs.children[start + 2]) > now:  # thisUpdate is in the future
            return False
        next_update = tbs.children[start + 3] if start + 3 < len(tbs.children) else None
        if next_update is not None and next_update.tag in _TIME_TAGS and _time(next_update) < now:
            return False  # the CRL has expired
        oid = _oid(crl.children[1].children[0])
        signature = crl.children[2].content[1:]  # BIT STRING, drop the unused-bits byte
        pss = _pss_parameters(crl.children[1]) if oid == _RSA_PSS_OID else None
        return verify_signature(tbs.raw, oid, signature, issuer, pss) is True
    except (Asn1Error, IndexError, ValueError):
        return False


def check_crl(
    leaf_der: bytes, issuer_der: bytes, url: str, timeout: float = DEFAULT_TIMEOUT,
    now: Optional[float] = None,
) -> Tuple[str, Optional[str]]:
    """Fetch the CRL at ``url`` and say whether the leaf's serial is on it, trusting the
    list only when it is an authentic, current CRL from the leaf's issuer."""
    serial = _serial(leaf_der)
    if serial is None:
        return "", "could not read the certificate serial"
    body, error = webclient.http_request(url, "GET", timeout)
    if error is not None:
        return "", error
    assert body is not None  # a body comes back whenever there is no error
    if not _crl_is_authentic(body, issuer_der, now if now is not None else time.time()):
        return "", "CRL is not an authentic, current list from the issuer"
    return ("revoked" if serial in parse_crl(body) else "good"), None
