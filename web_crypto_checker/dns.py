"""A minimal DNS client for the PKI controls that live in DNS: CAA and DANE/TLSA.

CAA (RFC 8659) says which certificate authorities a domain authorises to issue for
it; DANE/TLSA (RFC 6698) pins the certificate or key a domain expects to present.
Both live in DNS, not in the TLS handshake, so ``getaddrinfo`` cannot reach them.
This builds each DNS query by hand, sends it to the system resolver over UDP, and
parses the records out of the answer -- then, for DANE, checks the presented chain
against the TLSA records across every usage, selector and matching type. Zero
dependencies, like the rest of the tool; a bare-IP target has no domain and is not
queried.
"""

from __future__ import annotations

import hashlib
import os
import socket
import struct
import time
from typing import List, Optional, Tuple

from . import dnssec, resolver
from .models import (
    CaaInfo,
    CaaRecord,
    DaneInfo,
    HttpsRecord,
    Target,
    TlsaRecord,
    is_ip_literal,
)
from .pki.certificates import CertificateError, spki_der
from .tls.probe import DEFAULT_TIMEOUT

_TYPE_CAA = 257
_TYPE_TLSA = 52
_TYPE_HTTPS = 65
_CLASS_IN = 1
_RECURSION_DESIRED = 0x0100


def _nameserver() -> Optional[str]:
    """The first ``nameserver`` in /etc/resolv.conf, or None if there is none."""
    try:
        with open("/etc/resolv.conf") as conf:
            for line in conf:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    return parts[1]
    except OSError:
        return None
    return None


def _encode_name(name: str) -> bytes:
    """A DNS name as length-prefixed labels ending in a zero byte."""
    encoded = bytearray()
    for label in name.rstrip(".").split("."):
        octets = label.encode("ascii")
        encoded.append(len(octets))
        encoded += octets
    encoded.append(0)
    return bytes(encoded)


def build_query(name: str, query_id: bytes, record_type: int = _TYPE_CAA) -> bytes:
    """A DNS query for ``name``'s ``record_type`` records (recursion desired)."""
    header = query_id + struct.pack(">HHHHH", _RECURSION_DESIRED, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack(">HH", record_type, _CLASS_IN)
    return header + question


def _skip_name(data: bytes, offset: int) -> int:
    """The offset just past a DNS name, following the one compression pointer that ends it."""
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:  # a pointer is two bytes and terminates the name
            return offset + 2
        offset += 1
        if length == 0:
            return offset
        offset += length


def _parse_caa_rdata(rdata: bytes) -> Optional[CaaRecord]:
    """A CAA resource record's RDATA: flags, a tag, and its value (RFC 8659 4.1)."""
    if len(rdata) < 2:
        return None
    tag_length = rdata[1]
    tag = rdata[2 : 2 + tag_length].decode("latin1")
    value = rdata[2 + tag_length :].decode("latin1")
    return CaaRecord(flags=rdata[0], tag=tag, value=value)


def _answer_rdata(response: bytes, record_type: int) -> List[bytes]:
    """The RDATA of every answer of ``record_type`` in a DNS response."""
    _query_id, _flags, question_count, answer_count = struct.unpack(">HHHH", response[:8])
    offset = 12
    for _ in range(question_count):
        offset = _skip_name(response, offset) + 4  # name + qtype + qclass
    rdatas: List[bytes] = []
    for _ in range(answer_count):
        offset = _skip_name(response, offset)
        answer_type, _class, _ttl, rdlength = struct.unpack(">HHIH", response[offset : offset + 10])
        offset += 10
        rdata = response[offset : offset + rdlength]
        offset += rdlength
        if answer_type == record_type:
            rdatas.append(rdata)
    return rdatas


def parse_caa(response: bytes) -> List[CaaRecord]:
    """The CAA records in a DNS response, skipping any other record types."""
    records = [_parse_caa_rdata(rdata) for rdata in _answer_rdata(response, _TYPE_CAA)]
    return [record for record in records if record is not None]


def _parse_tlsa_rdata(rdata: bytes) -> Optional[TlsaRecord]:
    """A TLSA resource record's RDATA: usage, selector, matching type, data (RFC 6698 2.1)."""
    if len(rdata) < 3:
        return None
    return TlsaRecord(usage=rdata[0], selector=rdata[1], matching=rdata[2], data=rdata[3:])


def parse_tlsa(response: bytes) -> List[TlsaRecord]:
    """The TLSA records in a DNS response, skipping any other record types."""
    records = [_parse_tlsa_rdata(rdata) for rdata in _answer_rdata(response, _TYPE_TLSA)]
    return [record for record in records if record is not None]


_SVCB_ALPN = 1
_SVCB_PORT = 3
_SVCB_ECH = 5


def _decode_name(data: bytes) -> str:
    """A dotted name from uncompressed length-prefixed labels (RFC 1035 3.1)."""
    labels: List[str] = []
    offset = 0
    while offset < len(data) and data[offset] != 0:
        length = data[offset]
        labels.append(data[offset + 1 : offset + 1 + length].decode("latin1"))
        offset += 1 + length
    return ".".join(labels)


def _parse_https_rdata(rdata: bytes) -> Optional[HttpsRecord]:
    """An HTTPS/SVCB record's RDATA: priority, target and SvcParams (RFC 9460 2.2)."""
    if len(rdata) < 3:
        return None
    priority = int.from_bytes(rdata[0:2], "big")
    params_start = _skip_name(rdata, 2)  # the TargetName is uncompressed here
    target = _decode_name(rdata[2:params_start])
    alpn: List[str] = []
    port: Optional[int] = None
    ech = False
    offset = params_start
    while offset + 4 <= len(rdata):
        key, length = struct.unpack(">HH", rdata[offset : offset + 4])
        value = rdata[offset + 4 : offset + 4 + length]
        offset += 4 + length
        if key == _SVCB_ALPN:
            position = 0
            while position < len(value):
                size = value[position]
                alpn.append(value[position + 1 : position + 1 + size].decode("latin1"))
                position += 1 + size
        elif key == _SVCB_PORT and len(value) >= 2:
            port = int.from_bytes(value[:2], "big")
        elif key == _SVCB_ECH:
            ech = True
    return HttpsRecord(priority=priority, target=target, alpn=alpn, port=port, ech=ech)


def parse_https(response: bytes) -> Optional[HttpsRecord]:
    """The first HTTPS/SVCB record in a DNS response, or ``None`` if there is none."""
    for rdata in _answer_rdata(response, _TYPE_HTTPS):
        record = _parse_https_rdata(rdata)
        if record is not None:
            return record
    return None


def _send_query(
    name: str, record_type: int, timeout: float
) -> Tuple[Optional[bytes], Optional[str]]:
    """Send one DNS query to the system resolver and return the raw response."""
    server = _nameserver()
    if server is None:
        return None, "no DNS resolver configured"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((server, 53))
        sock.send(build_query(name, os.urandom(2), record_type))
        return sock.recv(2048), None
    except OSError as exc:
        return None, f"DNS query failed: {exc}"
    finally:
        sock.close()


def query_caa(
    name: str, timeout: float = DEFAULT_TIMEOUT
) -> Tuple[List[CaaRecord], Optional[str]]:
    """The CAA records for ``name`` from the system resolver, or an error."""
    response, error = _send_query(name, _TYPE_CAA, timeout)
    if error is not None:
        return [], error
    assert response is not None
    try:
        return parse_caa(response), None
    except (IndexError, struct.error, UnicodeDecodeError):
        return [], "malformed DNS response"


def query_tlsa(
    name: str, timeout: float = DEFAULT_TIMEOUT
) -> Tuple[List[TlsaRecord], Optional[str]]:
    """The TLSA (DANE) records for ``name`` from the system resolver, or an error."""
    response, error = _send_query(name, _TYPE_TLSA, timeout)
    if error is not None:
        return [], error
    assert response is not None
    try:
        return parse_tlsa(response), None
    except (IndexError, struct.error):
        return [], "malformed DNS response"


def query_https(
    name: str, timeout: float = DEFAULT_TIMEOUT
) -> Tuple[Optional[HttpsRecord], Optional[str]]:
    """The HTTPS/SVCB record for ``name`` from the system resolver, or an error."""
    response, error = _send_query(name, _TYPE_HTTPS, timeout)
    if error is not None:
        return None, error
    assert response is not None
    try:
        return parse_https(response), None
    except (IndexError, struct.error):
        return None, "malformed DNS response"


def _authenticated_fetch(timeout: float) -> resolver.Fetch:
    """A DNSSEC-record fetcher that depends on no third party: resolve iteratively from the
    authoritative servers, falling back to the system resolver only. Transport only -- every
    signature is verified here, against the IANA root key."""
    return resolver.fetch_with_fallback(
        resolver.iterative_fetch(timeout),
        dnssec.live_fetch(timeout, _nameserver(), include_public=False),
    )


def check_caa(target: Target, timeout: float = DEFAULT_TIMEOUT) -> Optional[CaaInfo]:
    """The CAA policy a target's domain publishes, or None for a bare IP.

    When records are present, they are DNSSEC-authenticated to the root: an unsigned CAA
    policy can be spoofed toward a CA at issuance time, so ``dnssec_validated`` records
    whether the policy the tool reports is cryptographically genuine.
    """
    if is_ip_literal(target.host):
        return None  # CAA is keyed by domain name; an address literal has none
    records, error = query_caa(target.host, timeout)
    if error is not None:
        return CaaInfo(error=error)
    dnssec_validated = None
    if records:
        dnssec_validated = dnssec.validate_records(
            target.host, _TYPE_CAA, int(time.time()), _authenticated_fetch(timeout)
        )
    return CaaInfo(records=records, dnssec_validated=dnssec_validated)


def check_https(target: Target, timeout: float = DEFAULT_TIMEOUT) -> Optional[HttpsRecord]:
    """The HTTPS/SVCB record a target's domain publishes (ALPN, ECH), or None when there
    is none or the target is a bare IP.

    A present record is DNSSEC-authenticated to the root: the ECH configuration a client
    would trust is only genuine if the record is signed, so ``dnssec_validated`` records
    whether the ALPN/ECH offer the tool reports is cryptographically genuine.
    """
    if is_ip_literal(target.host):
        return None
    record, _error = query_https(target.host, timeout)
    if record is not None:
        record.dnssec_validated = dnssec.validate_records(
            target.host, _TYPE_HTTPS, int(time.time()), _authenticated_fetch(timeout)
        )
    return record


# TLSA certificate-usage fields (RFC 6698 2.1.1): where the association is anchored.
_DANE_EE_USAGES = (1, 3)  # PKIX-EE, DANE-EE -- bind the end-entity (leaf) certificate
_DANE_CA_USAGES = (0, 2)  # PKIX-TA, DANE-TA -- bind a CA/anchor in the presented chain
_DANE_PKIX_USAGES = (0, 1)  # PKIX-* additionally require ordinary PKIX validation to pass


def _association_data(certificate_der: bytes, selector: int, matching: int) -> Optional[bytes]:
    """A cert's TLSA association data for one (selector, matching), or None if unknown.

    ``selector`` picks the bytes -- the whole certificate (0) or its SubjectPublicKeyInfo
    (1) -- and ``matching`` how they are compared: verbatim (0), SHA-256 (1) or SHA-512
    (2). Together these are every form a TLSA record can take (RFC 6698 2.1.2-2.1.3).
    """
    if selector == 0:
        base = certificate_der
    elif selector == 1:
        try:
            base = spki_der(certificate_der)
        except CertificateError:
            return None  # a certificate whose key we cannot read
    else:
        return None  # a selector this tool does not know
    if matching == 0:
        return base
    if matching == 1:
        return hashlib.sha256(base).digest()
    if matching == 2:
        return hashlib.sha512(base).digest()
    return None  # a matching type this tool does not know


def _record_matches(
    record: TlsaRecord, chain_ders: List[bytes], pkix_valid: Optional[bool]
) -> Optional[bool]:
    """Whether one TLSA record is satisfied: True matched, False not, None indeterminate."""
    if record.usage in _DANE_EE_USAGES:
        candidates = chain_ders[:1]  # the end-entity certificate the server presented
    elif record.usage in _DANE_CA_USAGES:
        candidates = chain_ders  # any CA / trust anchor in the presented chain
    else:
        return None  # a usage this tool does not know
    associations = [
        association
        for association in (
            _association_data(certificate_der, record.selector, record.matching)
            for certificate_der in candidates
        )
        if association is not None
    ]
    if not associations:
        return None  # a selector/matching (or chain) this tool cannot evaluate
    if not any(association == record.data for association in associations):
        return False
    if record.usage in _DANE_PKIX_USAGES and pkix_valid is not True:
        return None  # the binding matches, but its required PKIX validation is unconfirmed
    return True


def _matches_tlsa(
    records: List[TlsaRecord], chain_ders: List[bytes], pkix_valid: Optional[bool]
) -> Optional[bool]:
    """Whether the presented chain satisfies the TLSA records (RFC 6698 2.1).

    DANE authenticates when *any* record matches, so True as soon as one does; False
    when a record we can fully evaluate contradicts the chain and none matches; None
    when no record could be evaluated (unknown fields, or a required PKIX check we did
    not run).
    """
    results = [_record_matches(record, chain_ders, pkix_valid) for record in records]
    if any(result is True for result in results):
        return True
    if any(result is False for result in results):
        return False
    return None


def check_dane(
    target: Target,
    port: int,
    chain_ders: List[bytes],
    pkix_valid: Optional[bool],
    timeout: float = DEFAULT_TIMEOUT,
) -> Optional[DaneInfo]:
    """The DANE/TLSA policy at ``_<port>._tcp.<domain>``, and whether the chain matches.

    ``chain_ders`` is the presented certificate chain (leaf first) and ``pkix_valid``
    whether ordinary PKIX validation succeeded (None when it was not run) -- both needed
    to judge every TLSA usage, selector and matching type, not just the common one.
    """
    if is_ip_literal(target.host):
        return None  # TLSA is keyed by domain name
    records, error = query_tlsa(f"_{port}._tcp.{target.host}", timeout)
    if error is not None:
        return DaneInfo(error=error)
    # DANE is only trustworthy when DNSSEC authenticates it; validate the chain to the root
    # key ourselves, over a fetcher that depends on no third-party recursive resolver.
    fetch = _authenticated_fetch(timeout)
    now = int(time.time())
    if records:
        dnssec_validated: Optional[bool] = dnssec.validate_tlsa(target.host, port, now, fetch)
    else:
        # No TLSA seen: prove it is *authentically* absent (DNSSEC denial), so "no DANE" is
        # a verified fact, not a stripped or missed lookup. Unproven absence stays None.
        dnssec_validated = dnssec.validate_denial(target.host, port, now, fetch) or None
    return DaneInfo(
        records=records,
        matches=_matches_tlsa(records, chain_ders, pkix_valid),
        dnssec_validated=dnssec_validated,
    )
