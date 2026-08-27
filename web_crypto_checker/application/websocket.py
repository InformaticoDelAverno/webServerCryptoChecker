"""WebSocket Secure (wss) detection over the audited TLS session (RFC 6455).

Send one Upgrade request over a completed TLS handshake and read the answer: a
``101 Switching Protocols`` with a correct ``Sec-WebSocket-Accept`` means the
endpoint speaks WebSocket. Reusing the hand-rolled TLS transport means wss
inherits the very TLS posture this tool already grades -- there is no separate
crypto to audit, only the upgrade itself.

The opening handshake is a benign HTTP request, so basic detection runs like the
HTTP GET does. The foreign-Origin probe -- which reveals cross-site WebSocket
hijacking (CSWSH) -- sends a second, spoofed request, so it is gated behind
``--active``.
"""

from __future__ import annotations

import base64
import hashlib
import os
from typing import Dict, List, Optional, Tuple

from ..i18n import DEFAULT_LANGUAGE, Translator
from ..messages import MESSAGES
from ..models import Finding, Severity, Target, WebSocketInfo
from ..tls.tls12 import fetch_over_tls12
from ..tls.tls13 import fetch_over_tls13

#: Default English translator for direct callers (e.g. unit tests); ``assess`` passes
#: the report's own translator instead.
_EN = Translator(DEFAULT_LANGUAGE, MESSAGES)

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"  # RFC 6455 section 1.3
_FOREIGN_ORIGIN = "https://cross-site.invalid"


def _accept_token(key: str) -> str:
    """The ``Sec-WebSocket-Accept`` a compliant server must return for ``key``."""
    return base64.b64encode(hashlib.sha1((key + _GUID).encode()).digest()).decode()


def build_upgrade(host: str, path: str, key: str, origin: Optional[str] = None) -> bytes:
    """A WebSocket opening-handshake request (RFC 6455 section 4.1)."""
    lines = [
        f"GET {path or '/'} HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
        "User-Agent: web-crypto-checker",
    ]
    if origin is not None:
        lines.append(f"Origin: {origin}")
    lines.extend(["", ""])
    return "\r\n".join(lines).encode("latin1")


def _parse_response(raw: bytes) -> Tuple[Optional[int], Dict[str, str]]:
    """The status code and lower-cased headers of an HTTP response, best-effort."""
    text = raw.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace")
    lines = text.split("\r\n")
    status: Optional[int] = None
    parts = lines[0].split(" ", 2)
    if len(parts) >= 2 and parts[1].isdigit():
        status = int(parts[1])
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        if separator:
            headers[name.strip().lower()] = value.strip()
    return status, headers


def _upgrade(
    target: Target, address: str, key: str, origin: str, timeout: float, supports_tls13: bool
) -> Tuple[bytes, Optional[str]]:
    """Complete a TLS handshake and send one WebSocket Upgrade, returning the response."""
    host = target.effective_sni or target.host
    request = build_upgrade(host, target.path, key, origin)
    sni = target.effective_sni
    if supports_tls13:
        return fetch_over_tls13(address, target.port, request, sni, timeout)
    return fetch_over_tls12(address, target.port, request, sni, timeout)


def check_websocket(
    target: Target, address: str, timeout: float, supports_tls13: bool, active: bool = False
) -> Optional[WebSocketInfo]:
    """Probe ``target`` for WebSocket support and, with ``active``, Origin validation."""
    if target.scheme != "https":
        return None  # wss rides TLS; a cleartext ws:// probe is out of scope
    host = target.effective_sni or target.host
    key = base64.b64encode(os.urandom(16)).decode()
    raw, error = _upgrade(target, address, key, f"https://{host}", timeout, supports_tls13)
    if error is not None:
        return WebSocketInfo(error=error)
    status, headers = _parse_response(raw)
    accept_valid: Optional[bool] = None
    if status == 101:
        accept_valid = headers.get("sec-websocket-accept") == _accept_token(key)
    info = WebSocketInfo(
        supported=status == 101 and accept_valid is True,
        status_code=status,
        accept_valid=accept_valid,
        subprotocol=headers.get("sec-websocket-protocol"),
    )
    if active and info.supported:
        info.origin_checked = True
        foreign_key = base64.b64encode(os.urandom(16)).decode()
        foreign_raw, foreign_error = _upgrade(
            target, address, foreign_key, _FOREIGN_ORIGIN, timeout, supports_tls13
        )
        if foreign_error is None:
            foreign_status, _headers = _parse_response(foreign_raw)
            info.origin_enforced = foreign_status != 101
    return info


def websocket_findings(
    info: Optional[WebSocketInfo], t: Optional[Translator] = None
) -> List[Finding]:
    """The WebSocket findings for a result, or none when wss was not offered."""
    if info is None or not info.supported:
        return []
    t = t or _EN
    findings: List[Finding] = []
    if info.origin_checked and info.origin_enforced is False:
        findings.append(
            Finding(
                "WSS-OPEN-ORIGIN",
                Severity.MEDIUM,
                t("find.wss_open_origin.title"),
                t("find.wss_open_origin.desc"),
                remediation=t("find.wss_open_origin.rem"),
            )
        )
    return findings
