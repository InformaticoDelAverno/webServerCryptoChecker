"""HTTP/2 (h2) detection over the audited TLS session (RFC 9113).

Negotiate the ``h2`` ALPN, send the connection preface and an empty SETTINGS
frame, and read the server's SETTINGS -- what HTTP/2 offers and the limits it
advertises. Reuses the TLS 1.3 transport, so h2 inherits the graded TLS posture.

h2 here means h2-over-TLS-1.3 (the modern norm); h2 over TLS 1.2 and cleartext
h2c are out of scope. The Rapid Reset flag is heuristic -- a high or absent
concurrent-stream limit -- not an active flood; a behavioural probe would need an
HPACK encoder and is left for later.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from ..i18n import DEFAULT_LANGUAGE, Translator
from ..messages import MESSAGES
from ..models import Finding, Http2Info, Severity, Target
from ..tls.tls12 import exchange_over_tls12
from ..tls.tls13 import exchange_over_tls13

#: Default English translator for direct callers (e.g. unit tests); ``assess`` passes
#: the report's own translator instead.
_EN = Translator(DEFAULT_LANGUAGE, MESSAGES)

# RFC 9113 3.4: the client connection preface, then an (empty) SETTINGS frame.
_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
_CLIENT_SETTINGS = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
_FRAME_SETTINGS = 0x04
_FLAG_ACK = 0x01
_SETTINGS_NAMES = {  # RFC 9113 6.5.2
    0x01: "header_table_size",
    0x02: "enable_push",
    0x03: "max_concurrent_streams",
    0x04: "initial_window_size",
    0x05: "max_frame_size",
    0x06: "max_header_list_size",
}
# A very high or absent concurrent-stream cap is what Rapid Reset amplifies; a
# modest cap is the primary mitigation.
_RAPID_RESET_STREAMS = 1000


def _server_settings_present(buffer: bytes) -> bool:
    """Whether ``buffer`` holds a complete, non-ACK SETTINGS frame (RFC 9113 4.1)."""
    position = 0
    while position + 9 <= len(buffer):
        length = int.from_bytes(buffer[position : position + 3], "big")
        if position + 9 + length > len(buffer):
            return False
        if buffer[position + 3] == _FRAME_SETTINGS and not (buffer[position + 4] & _FLAG_ACK):
            return True
        position += 9 + length
    return False


def _done(buffer: bytes) -> bool:
    """Stop reading once the server's SETTINGS is in, or it fell back to HTTP/1.1."""
    return _server_settings_present(buffer) or buffer.startswith(b"HTTP/")


def _parse_settings(buffer: bytes) -> Dict[str, int]:
    """The identifiers and values from the server's SETTINGS frame."""
    settings: Dict[str, int] = {}
    position = 0
    while position + 9 <= len(buffer):
        length = int.from_bytes(buffer[position : position + 3], "big")
        if position + 9 + length > len(buffer):
            break
        payload = buffer[position + 9 : position + 9 + length]
        if buffer[position + 3] == _FRAME_SETTINGS and not (buffer[position + 4] & _FLAG_ACK):
            for offset in range(0, len(payload) - 5, 6):
                identifier = int.from_bytes(payload[offset : offset + 2], "big")
                name = _SETTINGS_NAMES.get(identifier)
                if name is not None:
                    settings[name] = int.from_bytes(payload[offset + 2 : offset + 6], "big")
        position += 9 + length
    return settings


def check_http2(
    target: Target, address: str, timeout: float, supports_tls13: bool
) -> Optional[Http2Info]:
    """Probe ``target`` for HTTP/2 support and read its SETTINGS (over TLS 1.3 or 1.2)."""
    if target.scheme != "https":
        return None  # cleartext h2c is out of scope; h2 rides TLS, over 1.3 or 1.2 alike
    exchange = exchange_over_tls13 if supports_tls13 else exchange_over_tls12
    alpn, response, error = exchange(
        address,
        target.port,
        _PREFACE + _CLIENT_SETTINGS,
        target.effective_sni,
        timeout,
        ["h2", "http/1.1"],
        _done,
    )
    if error is not None:
        return Http2Info(error=error)
    if alpn != "h2":
        return Http2Info(supported=False, alpn=alpn)
    settings = _parse_settings(response)
    push = settings.get("enable_push")
    return Http2Info(
        supported=True,
        alpn=alpn,
        max_concurrent_streams=settings.get("max_concurrent_streams"),
        initial_window_size=settings.get("initial_window_size"),
        max_frame_size=settings.get("max_frame_size"),
        header_table_size=settings.get("header_table_size"),
        max_header_list_size=settings.get("max_header_list_size"),
        enable_push=None if push is None else bool(push),
    )


def http2_findings(info: Optional[Http2Info], t: Optional[Translator] = None) -> List[Finding]:
    """The HTTP/2 findings for a result, or none when h2 was not offered."""
    if info is None or not info.supported:
        return []
    t = t or _EN
    findings: List[Finding] = []
    streams = info.max_concurrent_streams
    if streams is None or streams > _RAPID_RESET_STREAMS:
        advertised = t("find.http2_high_concurrency.no_limit") if streams is None else str(streams)
        findings.append(
            Finding(
                "HTTP2-HIGH-CONCURRENCY",
                Severity.LOW,
                t("find.http2_high_concurrency.title"),
                t("find.http2_high_concurrency.desc", advertised=advertised),
                remediation=t("find.http2_high_concurrency.rem"),
            )
        )
    return findings
