"""Data structures shared by the scanner, the analyser and the reporters.

Everything here is a plain dataclass so a scan result can be turned into JSON
with :func:`to_jsonable` without custom serialisation logic scattered around the
code base. The shapes are specific to the subject: TLS and the web.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


class Category(str, Enum):
    """Security classification of a single algorithm, version or property."""

    RECOMMENDED = "recommended"
    ACCEPTABLE = "acceptable"
    WEAK = "weak"
    INSECURE = "insecure"
    INFORMATIONAL = "informational"
    UNKNOWN = "unknown"

    @property
    def is_scored(self) -> bool:
        """Whether the category contributes to the numeric score."""
        return self in _SCORED_CATEGORIES


_SCORED_CATEGORIES = frozenset(
    {Category.RECOMMENDED, Category.ACCEPTABLE, Category.WEAK, Category.INSECURE}
)

#: Ordering from best to worst, used to compute "the worst thing on offer".
CATEGORY_ORDER: List[Category] = [
    Category.RECOMMENDED,
    Category.ACCEPTABLE,
    Category.WEAK,
    Category.INSECURE,
]


class Severity(str, Enum):
    """Severity of a finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER: List[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


class Verdict(str, Enum):
    """Overall judgement for a scanned server."""

    SECURE = "secure"
    ACCEPTABLE = "acceptable"
    WEAK = "weak"
    INSECURE = "insecure"

    UNKNOWN = "unknown"
    """Reached the server, but the policy could not classify anything it offers.

    Never guess in this case: an unjudgeable server must not be reported as
    either safe or broken.
    """

    ERROR = "error"


class PostQuantumStatus(str, Enum):
    """Post-quantum readiness of the key-exchange offer.

    Determined from the key-exchange groups a server accepts: a hybrid group
    such as ``X25519MLKEM768`` is what makes a TLS 1.3 handshake quantum-safe.
    """

    ENFORCED = "enforced"
    """Every key-exchange group offered is a post-quantum hybrid."""

    READY = "ready"
    """At least one post-quantum hybrid group is offered."""

    NOT_READY = "not-ready"
    """No post-quantum key exchange is offered."""

    UNKNOWN = "unknown"
    """The key-exchange offer could not be retrieved."""


class TlsCompressionStatus(str, Enum):
    """Whether TLS-level compression is enabled.

    The safe answer is simply "off": TLS compression is the CRIME
    side channel, and every current recommendation is to disable it.
    """

    DISABLED = "disabled"
    """No TLS compression method other than null was negotiated."""
    ENABLED = "enabled"
    """The server agreed to compress, exposing the CRIME side channel."""
    UNKNOWN = "unknown"


class ScanStatus(str, Enum):
    """Outcome of the network part of the scan."""

    OK = "ok"
    ERROR = "error"


class ComplianceStatus(str, Enum):
    """Outcome of evaluating a server against one conformance profile."""

    PASS = "pass"
    FAIL = "fail"
    NOT_ASSESSED = "not-assessed"
    """The profile needs data this scan did not collect."""


class TrustStatus(str, Enum):
    """Whether the presented certificate chain builds to a trusted root."""

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    """A chain was built, but not to any root in the trust store."""
    SELF_SIGNED = "self-signed"
    EXPIRED = "expired"
    """The chain reaches a trusted root, but a certificate in that path has expired."""
    NOT_YET_VALID = "not-yet-valid"
    """The chain reaches a trusted root, but a certificate in that path is not yet valid."""
    HOSTNAME_MISMATCH = "hostname-mismatch"
    INCOMPLETE = "incomplete"
    """The server did not send enough of the chain to build a path."""
    NOT_CHECKED = "not-checked"
    UNKNOWN = "unknown"


#: Algorithm classes, in report order (TLS has six). ``certificate`` and
#: ``compression``
#: are presented as classes but observed as structured objects rather than as a
#: list of offered names.
_CLASS_LABELS = {
    "protocol": "Protocol versions",
    "cipher": "Cipher suites",
    "group": "Key-exchange groups",
    "signature": "Signature algorithms",
    "certificate": "Certificate",
    "compression": "Compression",
}

ALGORITHM_CLASSES: List[str] = list(_CLASS_LABELS)


def class_label(algorithm_class: str) -> str:
    """The human-readable label for one of :data:`ALGORITHM_CLASSES`."""
    return _CLASS_LABELS[algorithm_class]


# --------------------------------------------------------------------------- #
# Targets
# --------------------------------------------------------------------------- #


def is_ip_literal(host: str) -> bool:
    """Whether ``host`` is a numeric IPv4 or IPv6 address rather than a name.

    It matters because SNI carries a host *name*: RFC 6066 forbids sending a
    literal address in the server_name extension, so the default SNI for a bare
    IP target is no SNI at all.
    """
    import ipaddress

    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class Target:
    """A server endpoint to scan: one host, one port."""

    host: str
    port: int = 443
    scheme: str = "https"
    sni: Optional[str] = None
    """The server name to send. ``None`` means "derive it": the host when it is
    a name, and nothing when it is a bare IP address."""
    path: str = "/"
    """The request path used by the HTTP-layer checks."""
    label: Optional[str] = None
    source: Optional[str] = None
    """Where the target came from, e.g. a file name and line number."""

    def __str__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"

    @property
    def display_name(self) -> str:
        return self.label or str(self)

    @property
    def effective_sni(self) -> str:
        """The server name actually sent, after applying the default rule.

        An explicit ``sni`` wins. Otherwise a host name is sent as-is and a bare
        IP literal is sent as no SNI at all.
        """
        if self.sni is not None:
            return self.sni
        if is_ip_literal(self.host):
            return ""
        return self.host


# --------------------------------------------------------------------------- #
# What the TLS handshake reveals
# --------------------------------------------------------------------------- #


@dataclass
class ProtocolSupport:
    """Whether the server accepts one protocol version."""

    name: str
    """Human-readable, e.g. ``TLS 1.2``."""
    id: str
    """Stable identifier used by the policy, e.g. ``tls1_2``."""
    supported: bool = False
    error: Optional[str] = None
    """Why support could not be determined, when it could not."""


@dataclass
class CipherSuite:
    """A cipher suite the server accepts."""

    name: str
    """IANA or OpenSSL name, e.g. ``TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256``."""
    id: str = ""
    """Wire identifier as hex, e.g. ``0xC02F``."""
    protocols: List[str] = field(default_factory=list)
    """The protocol version ids under which the suite was accepted."""

    @property
    def has_forward_secrecy(self) -> bool:
        """Whether the key exchange gives forward secrecy.

        Read from the suite name: ECDHE/DHE do, static RSA and static DH do not.
        TLS 1.3 suites do not name their key exchange (it is negotiated
        separately) and are always forward secret.
        """
        upper = self.name.upper()
        if "TLS_AES_" in upper or "TLS_CHACHA20" in upper:
            return True
        # "DHE" catches both ECDHE and DHE, in the IANA (TLS_ECDHE_/TLS_DHE_)
        # and OpenSSL (ECDHE-/DHE-) spellings; "EDH" is OpenSSL's old name for
        # DHE. Static RSA, DH and ECDH suites match none of these.
        return "DHE" in upper or "EDH" in upper


@dataclass
class KeyExchangeGroup:
    """A key-exchange group (named curve or finite-field group) the server accepts."""

    name: str
    """e.g. ``x25519``, ``secp256r1``, ``ffdhe2048``, ``X25519MLKEM768``."""
    id: Optional[int] = None
    """The IANA NamedGroup code point, when known."""
    bits: Optional[int] = None
    """Approximate security strength in bits, for the strength calculation."""
    protocols: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Certificates
# --------------------------------------------------------------------------- #


@dataclass
class RevocationStatus:
    """Result of checking whether the leaf certificate has been revoked."""

    checked: bool = False
    ocsp: str = ""
    """``good``, ``revoked``, ``unknown``, ``stapled`` or empty when not asked."""
    crl: str = ""
    error: Optional[str] = None


@dataclass
class CertificateInfo:
    """Fields extracted from one X.509 certificate in the chain."""

    subject: str = ""
    issuer: str = ""
    serial: str = ""
    sans: List[str] = field(default_factory=list)
    key_type: str = ""
    """``RSA``, ``EC`` or ``Ed25519``."""
    key_bits: Optional[int] = None
    curve: str = ""
    """The named curve for an EC key, e.g. ``P-256``."""
    roca_vulnerable: bool = False
    """Whether an RSA key bears the ROCA fingerprint (CVE-2017-15361): its private key is
    recoverable by a Coppersmith attack, so the certificate is effectively compromised."""
    signature_algorithm: str = ""
    not_before: Optional[int] = None
    """Validity start, as Unix time."""
    not_after: Optional[int] = None
    """Validity end, as Unix time."""
    is_self_signed: bool = False
    is_ca: bool = False
    path_length: Optional[int] = None
    """BasicConstraints pathLenConstraint: how many CA certificates may follow this one
    in a path (RFC 5280 4.2.1.9). ``None`` when the constraint is absent."""
    key_cert_sign: Optional[bool] = None
    """Whether KeyUsage asserts keyCertSign -- required of a CA that signs certificates
    when the extension is present. ``None`` when there is no KeyUsage extension."""
    extended_key_usages: List[str] = field(default_factory=list)
    """ExtendedKeyUsage purposes, by name where known (``serverAuth``, ``clientAuth``,
    ``anyExtendedKeyUsage``...) and dotted OID otherwise. Empty when the extension is
    absent -- which RFC 5280 reads as unrestricted."""
    fingerprint_sha256: str = ""
    sct_count: int = 0
    """Embedded signed certificate timestamps (Certificate Transparency)."""
    verified_scts: int = 0
    """How many of those SCTs cryptographically verify against a known CT log."""
    sct_logs: List[str] = field(default_factory=list)
    """The distinct CT logs whose signature over an embedded SCT verified."""
    ocsp_must_staple: bool = False
    ocsp_url: str = ""
    """The OCSP responder URL from the Authority Information Access extension."""
    ca_issuers_url: str = ""
    """The caIssuers URL from the Authority Information Access extension: where the
    issuer's certificate can be fetched to complete a chain the server left short."""
    crl_urls: List[str] = field(default_factory=list)
    """CRL distribution point URLs, where a revocation list can be fetched."""

    def is_expired(self, now: float) -> bool:
        return self.not_after is not None and self.not_after < now

    def is_not_yet_valid(self, now: float) -> bool:
        return self.not_before is not None and self.not_before > now

    def days_until_expiry(self, now: float) -> Optional[int]:
        if self.not_after is None:
            return None
        return int((self.not_after - now) // 86400)


@dataclass
class CertificateChain:
    """The certificate chain the server presented, and what was made of it."""

    certificates: List[CertificateInfo] = field(default_factory=list)
    trust: TrustStatus = TrustStatus.UNKNOWN
    hostname_matches: Optional[bool] = None
    """Whether the leaf's names cover the target host; ``None`` when not checked."""
    complete: Optional[bool] = None
    """Whether the chain builds to a trusted root; ``None`` when not checked."""
    signatures_valid: Optional[bool] = None
    """Whether every presented link's signature verifies (each cert signed by the
    next, a self-signed one by itself). ``None`` when not checkable -- an
    algorithm not handled, or no issuer present without a trust store."""
    signature_note: str = ""
    revocation: Optional[RevocationStatus] = None
    stapled_ocsp: str = ""
    """The authenticated status of an OCSP response the server stapled to its certificate:
    ``good``/``revoked``/``unknown`` when the staple verifies, ``invalid`` when one was
    stapled but is not authentic or is stale, empty when none was stapled."""
    aia_completed: bool = False
    """Whether a missing intermediate had to be fetched via the AIA caIssuers URL to
    build the chain: the server presented an incomplete chain (RFC 5280 4.2.2.1)."""
    error: Optional[str] = None

    @property
    def leaf(self) -> Optional[CertificateInfo]:
        """The end-entity certificate, which the server sends first."""
        return self.certificates[0] if self.certificates else None


# --------------------------------------------------------------------------- #
# TLS features and the HTTP layer
# --------------------------------------------------------------------------- #


@dataclass
class TlsFeatures:
    """Handshake-level properties that are not algorithm choices.

    Each is ``None`` when the scan did not establish it, so "off" and "not
    measured" stay distinct -- reporting the second as the first is exactly the
    silent false negative this tool is built to avoid.
    """

    secure_renegotiation: Optional[bool] = None
    session_resumption_id: Optional[bool] = None
    session_resumption_ticket: Optional[bool] = None
    ocsp_stapling: Optional[bool] = None
    extended_master_secret: Optional[bool] = None
    encrypt_then_mac: Optional[bool] = None
    """Whether the 1.2 server hardens its CBC suites with Encrypt-then-MAC (RFC 7366).
    ``False`` means its CBC records use MAC-then-encrypt, the Lucky13 padding-oracle target;
    ``None`` when no CBC suite was negotiated (AEAD-only or not 1.2), so it does not apply."""
    fallback_scsv: Optional[bool] = None
    enforces_cipher_preference: Optional[bool] = None
    """Whether the 1.2 server imposes its own cipher order (True) or takes the client's
    (False). ``False`` lets an attacker-steered client pull the connection to the weakest
    suite both sides share. ``None`` when not measured (not 1.2, or one suite only)."""
    downgrade_sentinel: Optional[bool] = None
    """A TLS 1.3-capable server writes the RFC 8446 4.1.3 sentinel into
    ServerHello.random when it negotiates TLS 1.2, so a 1.3 client detects a
    forced downgrade. ``False`` means a downgrade to 1.2 would be invisible."""
    dh_prime_bits: Optional[int] = None
    """The bit length of the finite-field DH prime a DHE cipher uses. ``None`` when
    the server negotiates no DHE suite; below 2048 is weak (Logjam, CVE-2015-4000)."""
    grease_tolerant: Optional[bool] = None
    """Whether the server ignores GREASE values (RFC 8701) as it must. ``False`` means a
    greased hello was rejected -- an intolerant server that may break as TLS evolves."""
    heartbeat: Optional[bool] = None
    """The heartbeat extension is advertised: the Heartbleed attack surface."""
    early_data: Optional[bool] = None
    """The TLS 1.3 server offers 0-RTT early data (a NewSessionTicket early_data
    extension). Early data is replayable, so it is a posture worth surfacing."""
    alpn: List[str] = field(default_factory=list)
    """Application protocols the server is willing to speak, e.g. ``h2``, ``h3``."""


@dataclass
class CookieInfo:
    """The security-relevant flags on one Set-Cookie header."""

    name: str
    secure: bool = False
    http_only: bool = False
    same_site: str = ""
    path: str = ""
    domain: str = ""


@dataclass
class MixedContent:
    """Insecure ``http://`` subresources an HTTPS page pulls in (RFC-agnostic; the browser
    security model). ``active`` resources (scripts, stylesheets, iframes, framed objects,
    form targets) are *blocked* by browsers and let an on-path attacker run code; ``passive``
    ones (images, media) are downgrade-warned and can be watched or swapped."""

    active: List[str] = field(default_factory=list)
    passive: List[str] = field(default_factory=list)

    def any(self) -> bool:
        return bool(self.active or self.passive)


@dataclass
class HttpSecurity:
    """What the HTTP layer reveals once the TLS session is up."""

    reached: bool = False
    cleartext: bool = False
    """The response came over plain, unencrypted HTTP -- there was no TLS at all."""
    status_code: Optional[int] = None
    redirects_to_https: Optional[bool] = None
    cleartext_redirect: Optional[bool] = None
    """Whether the cleartext HTTP port (80) redirects to HTTPS. ``False`` means it serves
    cleartext without upgrading; ``None`` when it was not probed or is not serving HTTP."""
    hsts: Optional[str] = None
    """The raw Strict-Transport-Security header value, or ``None`` when absent."""
    hsts_max_age: Optional[int] = None
    hsts_preload: bool = False
    hsts_include_subdomains: bool = False
    """Whether HSTS covers subdomains; without it they are not protected and the
    policy is ineligible for the preload list."""
    headers: Dict[str, str] = field(default_factory=dict)
    """Security-relevant response headers, lower-cased."""
    missing_headers: List[str] = field(default_factory=list)
    cookies: List[CookieInfo] = field(default_factory=list)
    server: str = ""
    """The Server header. Often hidden or faked, so it is a hint, never a verdict."""
    alt_svc: Optional[str] = None
    """The raw Alt-Svc header value, or ``None`` when absent."""
    http3_advertised: bool = False
    """Whether Alt-Svc advertises an HTTP/3 (``h3``) endpoint. Advertised, not dialled."""
    mixed_content: Optional[MixedContent] = None
    """Insecure ``http://`` subresources found in the HTTPS page body, or ``None`` when the
    body was not scanned (cleartext, or the layer was not reached)."""
    subresources_without_sri: List[str] = field(default_factory=list)
    """Cross-origin scripts/stylesheets in the body that carry no Subresource Integrity."""
    cors_allow_origin: Optional[str] = None
    """The Access-Control-Allow-Origin the server returned to a probe Origin, or None."""
    cors_allow_credentials: bool = False
    """Whether Access-Control-Allow-Credentials: true accompanied the CORS response."""
    error: Optional[str] = None


@dataclass
class QuicTransportParameters:
    """The QUIC transport parameters a server advertises (RFC 9000 18.2).

    Read from the EncryptedExtensions in the server's Handshake packets -- the
    connection limits it offers, decoded from their variable-length integers.
    """

    max_idle_timeout: Optional[int] = None
    max_udp_payload_size: Optional[int] = None
    initial_max_data: Optional[int] = None
    max_streams_bidi: Optional[int] = None
    max_streams_uni: Optional[int] = None
    active_connection_id_limit: Optional[int] = None
    max_ack_delay: Optional[int] = None
    disable_active_migration: bool = False


@dataclass
class Http3Negotiation:
    """What a QUIC/HTTP-3 handshake settled on, read from the server's packets.

    Beyond mere reachability: the cipher suite and key-share group the server
    chose (from the ServerHello in its Initial) and the transport parameters it
    advertises (from the EncryptedExtensions in its Handshake packets). ``group``
    is ``None`` when the ServerHello carried no key_share; ``transport_parameters``
    is ``None`` when the Handshake could not be completed (e.g. an unsupported
    cipher).
    """

    cipher_suite: str
    group: Optional[str] = None
    transport_parameters: Optional[QuicTransportParameters] = None


@dataclass
class WebSocketInfo:
    """What a WebSocket (wss) opening handshake reveals (RFC 6455).

    The result of one Upgrade request over the audited TLS session: whether the
    endpoint speaks WebSocket, whether it computed Sec-WebSocket-Accept correctly,
    any negotiated subprotocol, and -- when the active foreign-Origin probe runs --
    whether it validates the Origin (an unvalidated one is the cross-site
    WebSocket hijacking, CSWSH, exposure).
    """

    supported: bool = False
    """A 101 Switching Protocols with a correct Sec-WebSocket-Accept."""
    status_code: Optional[int] = None
    accept_valid: Optional[bool] = None
    """Whether Sec-WebSocket-Accept matched the key we sent. None when no 101 came."""
    subprotocol: Optional[str] = None
    """The Sec-WebSocket-Protocol the server selected, if any."""
    origin_checked: bool = False
    """Whether the active foreign-Origin probe ran (it needs ``--active``)."""
    origin_enforced: Optional[bool] = None
    """True if a foreign Origin was refused; False if accepted (CSWSH risk)."""
    error: Optional[str] = None


@dataclass
class SseInfo:
    """What a Server-Sent Events (text/event-stream) endpoint reveals.

    The result of one ``Accept: text/event-stream`` request: whether the endpoint
    streams events, and -- when the active foreign-Origin probe runs -- whether it
    reflects an arbitrary Origin into Access-Control-Allow-Origin, which lets a
    cross-site page read the stream (with credentials, a data-exfiltration path).
    """

    supported: bool = False
    """A response whose Content-Type is text/event-stream."""
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    allow_origin: Optional[str] = None
    """The Access-Control-Allow-Origin the endpoint returned, if any."""
    origin_checked: bool = False
    """Whether the active foreign-Origin probe ran (it needs ``--active``)."""
    cross_origin_open: Optional[bool] = None
    """True if a foreign Origin was reflected into Access-Control-Allow-Origin."""
    error: Optional[str] = None


@dataclass
class Http2Info:
    """What an HTTP/2 (h2) connection negotiates (RFC 9113).

    The result of negotiating the ``h2`` ALPN and reading the server's SETTINGS
    frame: whether h2 is offered and the limits it advertises. A very high or
    absent concurrent-stream limit is what the Rapid Reset attack
    (CVE-2023-44487) amplifies.
    """

    supported: bool = False
    """ALPN negotiated ``h2``."""
    alpn: Optional[str] = None
    """The protocol the server actually selected, whatever it was."""
    max_concurrent_streams: Optional[int] = None
    initial_window_size: Optional[int] = None
    max_frame_size: Optional[int] = None
    header_table_size: Optional[int] = None
    max_header_list_size: Optional[int] = None
    enable_push: Optional[bool] = None
    error: Optional[str] = None


@dataclass
class MutualTls:
    """Whether the server asks clients to authenticate with a certificate (mTLS).

    Read from the handshake: a CertificateRequest in the server's flight means the
    endpoint expects a client certificate. Whether it is *enforced* (required vs
    merely requested) is not distinguished here.
    """

    requested: Optional[bool] = None
    """True if the server sent a CertificateRequest; None when it could not be read."""
    required: Optional[bool] = None
    """True if the server refuses a certificate-less handshake; False if it accepts one;
    None when it merely requested (enforcement undetermined) or did not request at all."""
    error: Optional[str] = None


@dataclass
class GrpcInfo:
    """Whether the endpoint serves gRPC (application/grpc over HTTP/2).

    The result of one gRPC call to a probe method: a response whose content-type is
    application/grpc (or that carries a grpc-status) marks the endpoint as gRPC,
    even when the method itself is unimplemented.
    """

    supported: bool = False
    error: Optional[str] = None


@dataclass
class CaaRecord:
    """One CAA DNS record (RFC 8659): a policy on who may issue for the domain."""

    flags: int
    tag: str
    value: str


@dataclass
class CaaInfo:
    """The CAA records a domain publishes -- which CAs it authorises to issue.

    ``records`` empty with no ``error`` means the domain publishes no CAA at all, so
    any CA may issue. A bare-IP target has no CAA and is not queried.
    """

    records: List[CaaRecord] = field(default_factory=list)
    error: Optional[str] = None
    dnssec_validated: Optional[bool] = None  # records present and DNSSEC-authentic (None: no query)


@dataclass
class HttpsRecord:
    """A DNS HTTPS/SVCB record (RFC 9460, type 65): how a browser discovers a service's
    ALPN, alternative port and -- notably -- its Encrypted Client Hello configuration.

    ``ech`` True means the domain publishes an ECH config, so a client can encrypt the SNI
    and hide which host it is visiting. ``None`` (the whole record) when the domain
    publishes no HTTPS record or the target is a bare IP.
    """

    priority: int = 0
    target: str = ""
    alpn: List[str] = field(default_factory=list)
    port: Optional[int] = None
    ech: bool = False
    dnssec_validated: Optional[bool] = None  # this record is DNSSEC-authentic (None: not judged)


@dataclass
class TlsaRecord:
    """One TLSA DNS record (RFC 6698 2.1): a DANE binding for the endpoint's cert."""

    usage: int
    selector: int
    matching: int
    data: bytes


@dataclass
class DaneInfo:
    """The DANE/TLSA policy at ``_<port>._tcp.<domain>``, and the chain's compliance.

    ``matches`` is True when the presented chain satisfies a TLSA record (any usage,
    selector or matching type -- RFC 6698 2.1), False when a record that can be fully
    evaluated contradicts the chain and none matches (a violation), and None when there
    are no records, or none could be evaluated (unknown fields, or a required PKIX
    check that was not run).
    """

    records: List[TlsaRecord] = field(default_factory=list)
    matches: Optional[bool] = None
    dnssec_validated: Optional[bool] = None
    """Whether the TLSA record is authenticated by DNSSEC to the root key. ``None`` when
    there are no records to validate; ``False`` means the pin is present but unauthenticated
    (spoofable), so a DANE match cannot be trusted; ``True`` means the pin is genuine."""
    error: Optional[str] = None


# --------------------------------------------------------------------------- #
# Assessment
# --------------------------------------------------------------------------- #


@dataclass
class AlgorithmAssessment:
    """One offered algorithm, version or property, classified against the policy."""

    name: str
    category: Category = Category.UNKNOWN
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    score: Optional[int] = None


@dataclass
class ClassAssessment:
    """All entries offered for a single algorithm class."""

    key: str
    label: str
    algorithms: List[AlgorithmAssessment] = field(default_factory=list)
    score: Optional[int] = None
    worst_category: Optional[Category] = None
    preferred: Optional[str] = None
    """The server's first choice, which is what a permissive client negotiates."""

    def by_category(self, category: Category) -> List[AlgorithmAssessment]:
        return [a for a in self.algorithms if a.category is category]


@dataclass
class Finding:
    """An actionable issue detected on a server."""

    id: str
    severity: Severity
    title: str
    description: str
    remediation: str = ""
    items: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


@dataclass
class ScoreBreakdown:
    """How the final score was reached, so the grade can be justified."""

    class_scores: Dict[str, Optional[int]] = field(default_factory=dict)
    class_weights: Dict[str, int] = field(default_factory=dict)
    total_weight: int = 0
    base_score: int = 0
    applied_caps: List[str] = field(default_factory=list)
    final_score: int = 0


@dataclass
class ComplianceViolation:
    """One reason a server does not conform to a profile."""

    algorithm_class: str
    subject: str
    reason: str


@dataclass
class ComplianceResult:
    """Verdict for a single conformance profile."""

    profile_id: str
    name: str
    authority: str
    reference: str
    edition: str = ""
    url: str = ""
    summary: str = ""
    notes: str = ""
    kind: str = "algorithm-strength"
    status: ComplianceStatus = ComplianceStatus.NOT_ASSESSED
    violations: List[ComplianceViolation] = field(default_factory=list)
    unverified: List[str] = field(default_factory=list)
    """Requirements the scan could not test at all. Non-empty means the answer
    is 'not assessed' rather than 'pass'."""

    @property
    def conforms(self) -> bool:
        return self.status is ComplianceStatus.PASS


@dataclass
class SecurityStrength:
    """Effective security strength of a server, per NIST SP 800-57."""

    effective_bits: Optional[int] = None
    level_id: str = "unknown"
    level_label: str = "Unknown"
    level_description: str = ""
    per_class: Dict[str, Optional[int]] = field(default_factory=dict)
    limiting: List[str] = field(default_factory=list)
    """The algorithms that hold the effective strength down."""
    reference: str = ""


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #


@dataclass
class TargetResult:
    """Everything known about one scanned endpoint."""

    target: Target
    status: ScanStatus = ScanStatus.ERROR
    error: Optional[str] = None
    ip: Optional[str] = None
    """The resolved address this result is about, so a domain behind several
    addresses reports each one separately."""
    duration_ms: int = 0
    scanned_at: str = ""

    protocols: List[ProtocolSupport] = field(default_factory=list)
    cipher_suites: List[CipherSuite] = field(default_factory=list)
    groups: List[KeyExchangeGroup] = field(default_factory=list)
    signature_algorithms: List[str] = field(default_factory=list)
    certificate: Optional[CertificateChain] = None
    alternate_certificate: Optional[CertificateChain] = None
    """A second leaf certificate of a different key type (RSA vs ECDSA) the server also
    serves -- a dual-certificate deployment -- or ``None`` when it serves only one. Kept
    separate so a weak or expired alternate cannot hide behind the strong default."""
    features: Optional[TlsFeatures] = None
    http: Optional[HttpSecurity] = None
    websocket: Optional[WebSocketInfo] = None
    sse: Optional[SseInfo] = None
    http2: Optional[Http2Info] = None
    mtls: Optional[MutualTls] = None
    grpc: Optional[GrpcInfo] = None
    caa: Optional[CaaInfo] = None
    dane: Optional[DaneInfo] = None
    https_record: Optional[HttpsRecord] = None

    assessments: List[ClassAssessment] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    compliance: List[ComplianceResult] = field(default_factory=list)
    vulnerabilities: List[Any] = field(default_factory=list)
    security_strength: Optional[SecurityStrength] = None

    score: Optional[int] = None
    grade: Optional[str] = None
    verdict: Verdict = Verdict.ERROR
    post_quantum: PostQuantumStatus = PostQuantumStatus.UNKNOWN
    compression: TlsCompressionStatus = TlsCompressionStatus.UNKNOWN
    http3_reachable: Optional[bool] = None
    """Whether the server answered a QUIC Initial -- HTTP/3 dialled, not just advertised."""
    http3_negotiation: Optional[Http3Negotiation] = None
    """The cipher and group HTTP/3 negotiated, read from the server's Initial."""
    quic_versions: List[int] = field(default_factory=list)
    """The QUIC versions the server offers (RFC 9000 v1 = 0x1, RFC 9369 v2 = 0x6b3343cf,
    plus any drafts), from a forced Version Negotiation. Empty when none was elicited."""
    sslv2_export_ciphers: bool = False
    """Whether an SSL 2.0 server offers 40-bit export ciphers, which make DROWN practical."""
    score_breakdown: Optional[ScoreBreakdown] = None

    @property
    def ok(self) -> bool:
        return self.status is ScanStatus.OK

    def assessment(self, key: str) -> Optional[ClassAssessment]:
        for assessment in self.assessments:
            if assessment.key == key:
                return assessment
        return None

    def worst_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return min(self.findings, key=lambda f: SEVERITY_ORDER.index(f.severity)).severity


@dataclass
class ScanSummary:
    """Aggregate counters across all scanned targets."""

    total: int = 0
    succeeded: int = 0
    failed: int = 0
    by_verdict: Dict[str, int] = field(default_factory=dict)
    by_grade: Dict[str, int] = field(default_factory=dict)
    by_severity: Dict[str, int] = field(default_factory=dict)
    post_quantum_ready: int = 0
    vulnerable: int = 0
    """Targets matching at least one known vulnerability."""
    by_vulnerability: Dict[str, int] = field(default_factory=dict)
    """Vulnerability id -> how many targets matched it, worst severity first."""
    average_score: Optional[float] = None
    by_strength_level: Dict[str, int] = field(default_factory=dict)
    by_profile: Dict[str, Dict[str, int]] = field(default_factory=dict)


@dataclass
class ScanReport:
    """The complete result of a run, and the root object of the JSON output."""

    tool: str
    version: str
    started_at: str
    finished_at: str = ""
    duration_ms: int = 0
    policy: Dict[str, Any] = field(default_factory=dict)
    command_line: str = ""
    results: List[TargetResult] = field(default_factory=list)
    summary: ScanSummary = field(default_factory=ScanSummary)


# --------------------------------------------------------------------------- #
# Serialisation
# --------------------------------------------------------------------------- #


#: Field and key names whose value is never written to a report, whatever it
#: holds, so a secret cannot reach a report through a path nobody thought about.
_REDACTED_FIELDS = frozenset({"password", "passphrase", "secret", "token", "private_key"})


def to_jsonable(value: Any) -> Any:
    """Recursively convert dataclasses, enums and sets into JSON-safe values.

    Fields whose name suggests a secret are redacted rather than serialised.
    """
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            f.name: (
                "[redacted]"
                if f.name in _REDACTED_FIELDS
                else to_jsonable(getattr(value, f.name))
            )
            for f in dataclasses.fields(value)
        }
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {
            str(k): ("[redacted]" if str(k) in _REDACTED_FIELDS else to_jsonable(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [to_jsonable(v) for v in value]
    if isinstance(value, bytes):
        return value.hex()
    return value
