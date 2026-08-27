"""The ROBOT probe: is the server a Bleichenbacher (RSA padding) oracle?

ROBOT (Return Of Bleichenbacher's Oracle Threat, 2017) is the Bleichenbacher attack
reborn: a server that does RSA key exchange (a ``TLS_RSA_*`` suite, static RSA key
transport) and answers *differently* to a ClientKeyExchange whose PKCS#1 v1.5 padding
is valid versus invalid leaks one bit per query -- enough to decrypt a recorded session
or forge a signature with the server's key.

The probe sends several ClientKeyExchange messages that differ only in whether their
padding is well-formed, each followed by a ChangeCipherSpec and a deliberately-wrong
Finished, and watches how the server answers. A hardened server answers every one the
same way (it treats invalid padding as a random premaster and fails the Finished check
identically, RFC 5246 7.4.7.1); a server that distinguishes them is an oracle. A
differential is only reported when it *reproduces*, so a one-off network hiccup does not
read as a finding.

This sends crafted, handshake-breaking traffic, so it runs only behind ``--active`` and
against a server you are authorised to test. It detects a direct response oracle (a
different alert, close or silence); a timing-only oracle is out of scope.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from ..pki.certificates import _parse_certificate_message, _signed_cert
from .active import _read_record
from .constants import (
    CONTENT_TYPE_ALERT,
    CONTENT_TYPE_CHANGE_CIPHER_SPEC,
    CONTENT_TYPE_HANDSHAKE,
    PROTOCOL_VERSIONS,
)
from .messages import build_client_hello, parse_server_hello
from .probe import DEFAULT_TIMEOUT
from .tls12 import _read_flight
from .wire import TlsError

_TLS12 = PROTOCOL_VERSIONS[1]
#: TLS_RSA_WITH_AES_128_GCM_SHA256 / _256_GCM / _128_CBC / _256_CBC -- the static-RSA suites.
_STATIC_RSA_CIPHERS = [0x009C, 0x009D, 0x002F, 0x0035]
_GROUPS = [0x001D, 0x0017, 0x0018]
_SIGNATURE_SCHEMES = [0x0403, 0x0503, 0x0804, 0x0805, 0x0401, 0x0501]
_CHANGE_CIPHER_SPEC = bytes([CONTENT_TYPE_CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1])
#: A handshake record where an encrypted Finished should be: 40 bytes the server cannot
#: authenticate, so the only thing that varies its reaction is the ClientKeyExchange above.
_GARBAGE_FINISHED = bytes([CONTENT_TYPE_HANDSHAKE, 3, 3, 0, 40]) + b"\x00" * 40
_HS_CLIENT_KEY_EXCHANGE = 16
_HS_CERTIFICATE = 11
_TLS_VERSION = b"\x03\x03"


@dataclass
class RobotResult:
    """The outcome of the ROBOT (Bleichenbacher oracle) probe."""

    vulnerable: bool = False
    tested: bool = False  # whether the oracle test actually ran (the server offered RSA kx)
    detail: str = ""


def _pkcs1(modulus_length: int, message: bytes) -> bytes:
    """A well-formed PKCS#1 v1.5 type-2 block: 00 02, nonzero padding, 00, then message."""
    padding = b"\x42" * (modulus_length - len(message) - 3)  # >= 8 nonzero bytes
    return b"\x00\x02" + padding + b"\x00" + message


def _padded_blocks(modulus_length: int) -> List[Tuple[str, bytes]]:
    """The plaintext blocks whose only difference is PKCS#1 padding validity, before RSA
    encryption. The first two are well-formed padding, the last three malformed."""
    premaster = _TLS_VERSION + b"\x00" * 46  # a fixed 48-byte premaster (version + zeros)
    filler = b"\x42" * (modulus_length - 2)
    return [
        ("correct", _pkcs1(modulus_length, premaster)),
        ("wrong_version", _pkcs1(modulus_length, b"\x02\x02" + b"\x00" * 46)),
        ("bad_second_byte", b"\x00\x01" + filler),  # not 00 02
        ("no_null_delimiter", b"\x00\x02" + filler),  # 00 02 but never a 00 to end padding
        ("null_in_padding", b"\x00\x02\x00" + b"\x42" * (modulus_length - 3)),  # 00 too early
    ]


def _encrypted_vectors(modulus: int, exponent: int) -> List[Tuple[str, bytes]]:
    """The ClientKeyExchange messages for each padding block, RSA-encrypted to the key."""
    modulus_length = (modulus.bit_length() + 7) // 8
    vectors = []
    for name, block in _padded_blocks(modulus_length):
        ciphertext = pow(int.from_bytes(block, "big"), exponent, modulus)
        encrypted = ciphertext.to_bytes(modulus_length, "big")
        body = len(encrypted).to_bytes(2, "big") + encrypted  # EncryptedPreMasterSecret
        message = bytes([_HS_CLIENT_KEY_EXCHANGE]) + len(body).to_bytes(3, "big") + body
        vectors.append((name, message))
    return vectors


def _client_hello(sni: str) -> bytes:
    return build_client_hello(
        _TLS12, _STATIC_RSA_CIPHERS, server_name=sni, groups=_GROUPS,
        signature_schemes=_SIGNATURE_SCHEMES,
    )


def _server_hello_cipher(flight: bytes) -> Optional[int]:
    """The cipher suite the server chose, from the ServerHello at the head of the flight."""
    try:
        length = int.from_bytes(flight[1:4], "big")
        return parse_server_hello(flight[4 : 4 + length]).cipher_suite
    except (TlsError, IndexError):
        return None


def _classify(sock: socket.socket) -> str:
    """A compact label for how the server answered our ClientKeyExchange flight."""
    record = _read_record(sock)  # None on a close or a timeout
    if record is None:
        return "no-response"
    if record[0] == CONTENT_TYPE_ALERT and len(record) >= 7:
        return f"alert:{record[6]}"  # the alert description byte -- the useful distinction
    return f"record:{record[0]}"


def _leaf_rsa_from_flight(flight: bytes) -> Optional[Tuple[int, int]]:
    """The leaf certificate's RSA ``(modulus, exponent)`` from the flight's Certificate
    message, or ``None`` when there is no certificate or it is not an RSA key."""
    position = 0
    while position + 4 <= len(flight):
        length = int.from_bytes(flight[position + 1 : position + 4], "big")
        if flight[position] == _HS_CERTIFICATE:
            ders = _parse_certificate_message(flight[position + 4 : position + 4 + length])
            signed = _signed_cert(ders[0]) if ders else None
            return signed.rsa_key if signed is not None else None
        position += 4 + length
    return None


def _negotiate(
    host: str, port: int, sni: str, timeout: float
) -> Tuple[Optional[int], Optional[Tuple[int, int]]]:
    """The cipher the server chose and the leaf's RSA key, from one handshake -- so a
    server that speaks *only* static RSA is still tested with its own certificate."""
    try:
        sock = socket.create_connection((host, port), timeout)
    except OSError:
        return None, None
    try:
        sock.settimeout(timeout)
        sock.sendall(_client_hello(sni))
        flight, error = _read_flight(sock)
        if error is not None:
            return None, None
        return _server_hello_cipher(flight), _leaf_rsa_from_flight(flight)
    except OSError:
        return None, None
    finally:
        sock.close()


def _probe_round(
    host: str, port: int, sni: str, timeout: float, vectors: List[Tuple[str, bytes]]
) -> Dict[str, str]:
    """Send each padding vector on its own connection and label the server's answer."""
    responses: Dict[str, str] = {}
    for name, cke in vectors:
        try:
            sock = socket.create_connection((host, port), timeout)
        except OSError:
            responses[name] = "no-connection"
            continue
        try:
            sock.settimeout(timeout)
            sock.sendall(_client_hello(sni))
            _flight, error = _read_flight(sock)
            if error is not None:
                responses[name] = "no-flight"
            else:
                record = bytes([CONTENT_TYPE_HANDSHAKE, 3, 3]) + len(cke).to_bytes(2, "big") + cke
                sock.sendall(record)
                sock.sendall(_CHANGE_CIPHER_SPEC)
                sock.sendall(_GARBAGE_FINISHED)
                responses[name] = _classify(sock)
        except OSError:
            responses[name] = "error"
        finally:
            sock.close()
    return responses


def check_robot(
    host: str, port: int, sni: str = "", timeout: float = DEFAULT_TIMEOUT
) -> RobotResult:
    """Probe for a Bleichenbacher/ROBOT oracle in RSA key exchange (CVE-2017-13099 et al.).

    One handshake tells whether the server offers RSA key exchange and gives its leaf's
    RSA key (needed to encrypt the padding vectors); the probe only runs when it does. A
    padding differential is reported only when it reproduces on a second round.
    """
    cipher, leaf_rsa = _negotiate(host, port, sni, timeout)
    if cipher not in _STATIC_RSA_CIPHERS:
        return RobotResult(detail="the server does not offer RSA key exchange")
    if leaf_rsa is None:
        return RobotResult(detail="the certificate does not use an RSA key")
    vectors = _encrypted_vectors(*leaf_rsa)
    first = _probe_round(host, port, sni, timeout, vectors)
    if len(set(first.values())) == 1:
        return RobotResult(tested=True, detail="the server answers every padding alike")
    second = _probe_round(host, port, sni, timeout, vectors)
    if first != second:
        return RobotResult(
            tested=True, detail="a padding differential appeared but did not reproduce"
        )
    return RobotResult(
        vulnerable=True, tested=True,
        detail="the server tells valid from invalid PKCS#1 padding apart (a Bleichenbacher oracle)",
    )
