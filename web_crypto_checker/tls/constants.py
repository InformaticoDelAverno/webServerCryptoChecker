"""TLS protocol constants: versions, cipher suites, groups, extensions, alerts.

The cipher-suite and group tables are deliberately curated rather than
exhaustive: every entry that matters to a security verdict is here -- the modern
AEAD suites, and the CBC, 3DES, RC4, DES, export, anon and NULL suites a finding
is written about -- and an id the table does not know is reported by its hex
code rather than guessed at.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

# --------------------------------------------------------------------------- #
# Record and handshake framing
# --------------------------------------------------------------------------- #

CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20
CONTENT_TYPE_ALERT = 21
CONTENT_TYPE_HANDSHAKE = 22

# RFC 7507: a client retrying at a lower version puts this signalling value in its
# cipher list; a server that knows it could do better answers inappropriate_fallback.
TLS_FALLBACK_SCSV = 0x5600
ALERT_INAPPROPRIATE_FALLBACK = 86
CONTENT_TYPE_APPLICATION_DATA = 23
CONTENT_TYPE_HEARTBEAT = 24

HANDSHAKE_TYPE_CLIENT_HELLO = 1
HANDSHAKE_TYPE_SERVER_HELLO = 2
HANDSHAKE_TYPE_CERTIFICATE = 11
HANDSHAKE_TYPE_SERVER_HELLO_DONE = 14

#: The magic ServerHello.random that marks a HelloRetryRequest (RFC 8446 4.1.3).
HELLO_RETRY_REQUEST_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)

# --------------------------------------------------------------------------- #
# Protocol versions
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ProtocolVersionSpec:
    """One negotiable protocol version."""

    name: str
    id: str
    code: int
    is_tls13: bool = False


#: Best to worst, which is the order they are probed and reported in. SSL 2.0 is
#: absent: its ClientHello is a different format, so DROWN gets its own probe.
PROTOCOL_VERSIONS: List[ProtocolVersionSpec] = [
    ProtocolVersionSpec("TLS 1.3", "tls1_3", 0x0304, is_tls13=True),
    ProtocolVersionSpec("TLS 1.2", "tls1_2", 0x0303),
    ProtocolVersionSpec("TLS 1.1", "tls1_1", 0x0302),
    ProtocolVersionSpec("TLS 1.0", "tls1_0", 0x0301),
    ProtocolVersionSpec("SSL 3.0", "ssl3", 0x0300),
]

_VERSION_BY_CODE: Dict[int, ProtocolVersionSpec] = {v.code: v for v in PROTOCOL_VERSIONS}


def version_name(code: int) -> str:
    spec = _VERSION_BY_CODE.get(code)
    return spec.name if spec is not None else f"0x{code:04X}"


# --------------------------------------------------------------------------- #
# Extensions
# --------------------------------------------------------------------------- #

EXT_SERVER_NAME = 0
EXT_STATUS_REQUEST = 5
EXT_SUPPORTED_GROUPS = 10
EXT_EC_POINT_FORMATS = 11
EXT_SIGNATURE_ALGORITHMS = 13
EXT_HEARTBEAT = 15
EXT_ALPN = 16
EXT_ENCRYPT_THEN_MAC = 22
EXT_EXTENDED_MASTER_SECRET = 23
EXT_SESSION_TICKET = 35
EXT_SUPPORTED_VERSIONS = 43
EXT_KEY_SHARE = 51
EXT_QUIC_TRANSPORT_PARAMETERS = 57
EXT_RENEGOTIATION_INFO = 0xFF01

# --------------------------------------------------------------------------- #
# Alerts
# --------------------------------------------------------------------------- #

ALERT_DESCRIPTIONS: Dict[int, str] = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    40: "handshake_failure",
    42: "bad_certificate",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    50: "decode_error",
    51: "decrypt_error",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    86: "inappropriate_fallback",
    109: "missing_extension",
    112: "unrecognized_name",
}


def alert_description(code: int) -> str:
    return ALERT_DESCRIPTIONS.get(code, f"alert-{code}")


# --------------------------------------------------------------------------- #
# Named groups (curves and finite-field groups)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class NamedGroup:
    name: str
    code: int
    bits: Optional[int] = None
    """Approximate security strength in bits, for the strength calculation."""
    post_quantum: bool = False


NAMED_GROUPS: List[NamedGroup] = [
    NamedGroup("secp256r1", 0x0017, 128),
    NamedGroup("secp384r1", 0x0018, 192),
    NamedGroup("secp521r1", 0x0019, 256),
    NamedGroup("x25519", 0x001D, 128),
    NamedGroup("x448", 0x001E, 224),
    NamedGroup("ffdhe2048", 0x0100, 112),
    NamedGroup("ffdhe3072", 0x0101, 128),
    NamedGroup("ffdhe4096", 0x0102, 152),
    NamedGroup("ffdhe6144", 0x0103, 176),
    NamedGroup("ffdhe8192", 0x0104, 200),
    # Deprecated small/attack-prone curves, kept so offering them is a finding.
    NamedGroup("secp192r1", 0x0013, 96),
    NamedGroup("secp224r1", 0x0015, 112),
    # Post-quantum hybrids.
    NamedGroup("X25519MLKEM768", 0x11EC, 128, post_quantum=True),
    NamedGroup("SecP256r1MLKEM768", 0x11EB, 128, post_quantum=True),
    NamedGroup("X25519Kyber768Draft00", 0x6399, 128, post_quantum=True),
]

_GROUP_BY_CODE: Dict[int, NamedGroup] = {g.code: g for g in NAMED_GROUPS}
_GROUP_BY_NAME: Dict[str, NamedGroup] = {g.name: g for g in NAMED_GROUPS}


def named_group(code: int) -> Optional[NamedGroup]:
    return _GROUP_BY_CODE.get(code)


def group_by_name(name: str) -> Optional[NamedGroup]:
    return _GROUP_BY_NAME.get(name)


# --------------------------------------------------------------------------- #
# Signature schemes
# --------------------------------------------------------------------------- #

SIGNATURE_SCHEMES: Dict[int, str] = {
    0x0401: "rsa_pkcs1_sha256",
    0x0501: "rsa_pkcs1_sha384",
    0x0601: "rsa_pkcs1_sha512",
    0x0403: "ecdsa_secp256r1_sha256",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0603: "ecdsa_secp521r1_sha512",
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    0x0807: "ed25519",
    0x0808: "ed448",
    0x0809: "rsa_pss_pss_sha256",
    0x080A: "rsa_pss_pss_sha384",
    0x080B: "rsa_pss_pss_sha512",
    # Legacy, SHA-1 and MD5: kept so accepting them is a finding.
    0x0201: "rsa_pkcs1_sha1",
    0x0203: "ecdsa_sha1",
    0x0101: "rsa_pkcs1_md5",
}


def signature_scheme_name(code: int) -> str:
    return SIGNATURE_SCHEMES.get(code, f"0x{code:04X}")


# --------------------------------------------------------------------------- #
# Cipher suites
# --------------------------------------------------------------------------- #

#: TLS 1.3 suites, named separately because they are offered on the 1.3 probe
#: only and negotiate no key exchange or authentication in the name itself.
TLS13_CIPHER_SUITES: Dict[int, str] = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
}

#: Pre-1.3 suites. Not exhaustive; every category that changes a verdict is here.
LEGACY_CIPHER_SUITES: Dict[int, str] = {
    # ECDHE, AEAD.
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    # DHE, AEAD.
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    # ECDHE, CBC.
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    # DHE, CBC.
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    # RSA, AEAD.
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    # RSA, CBC (no forward secrecy).
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    # 3DES (Sweet32).
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    # RC4 (biased keystream).
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    # Single DES.
    0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
    0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA",
    # Export grade (FREAK / Logjam).
    0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0014: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    # Anonymous (no authentication).
    0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    0x006C: "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
    0xC018: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
    # NULL (no encryption).
    0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x003B: "TLS_RSA_WITH_NULL_SHA256",
}

#: Signalling suite values, which are never negotiated as a real suite.
SIGNALLING_SUITES: Dict[int, str] = {
    0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    0x5600: "TLS_FALLBACK_SCSV",
}

_ALL_CIPHER_SUITES: Dict[int, str] = {
    **TLS13_CIPHER_SUITES,
    **LEGACY_CIPHER_SUITES,
    **SIGNALLING_SUITES,
}


def cipher_suite_name(code: int) -> str:
    return _ALL_CIPHER_SUITES.get(code, f"UNKNOWN-0x{code:04X}")


def cipher_suite_tags(name: str) -> List[str]:
    """The shape-tags of a cipher suite, read from its standardised name.

    The policy maps these tags to a category, so a rule written about ``cbc`` or
    ``rc4`` keeps working for a suite nobody has catalogued yet. Deriving them
    from the name is mechanical -- the names are structured on purpose -- which
    is why it lives here rather than as a hand-kept table.
    """
    upper = name.upper()
    is_tls13 = upper.startswith("TLS_AES_") or upper.startswith("TLS_CHACHA20")
    forward_secret = is_tls13 or "DHE" in upper or "EDH" in upper
    aead = is_tls13 or "GCM" in upper or "CCM" in upper or "POLY1305" in upper

    tags: List[str] = []
    if "NULL" in upper:
        tags.append("null")
    if "ANON" in upper:
        tags.append("anon")
    if "EXPORT" in upper:
        tags.append("export")
    if "RC4" in upper:
        tags.append("rc4")
    if "3DES" in upper:
        tags.append("3des")
    elif "DES_CBC" in upper or "WITH_DES" in upper:
        tags.append("des")
    if "MD5" in upper:
        tags.append("md5")
    if "CBC" in upper:
        tags.append("cbc")
    if aead:
        tags.append("aead")
    tags.append("pfs" if forward_secret else "no-forward-secrecy")
    # A trailing "_SHA" (not _SHA256/384/512) is an HMAC-SHA1 MAC.
    if upper.endswith("_SHA") and not is_tls13:
        tags.append("sha1")
    return tags
