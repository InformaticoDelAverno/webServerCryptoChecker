"""Server-Sent Events (SSE / EventSource) detection over the audited TLS session.

Send one ``Accept: text/event-stream`` request and read the response head: a
Content-Type of ``text/event-stream`` means the endpoint streams events. Reuses
the hand-rolled TLS transport, so SSE inherits the TLS posture already graded.

The request is a benign GET. The foreign-Origin probe -- which reveals a stream
readable cross-site (Access-Control-Allow-Origin reflecting an arbitrary Origin,
a data-exfiltration path once credentials ride along) -- is gated behind
``--active``.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from ..i18n import DEFAULT_LANGUAGE, Translator
from ..messages import MESSAGES
from ..models import Finding, Severity, SseInfo, Target
from ..tls.tls12 import fetch_over_tls12
from ..tls.tls13 import fetch_over_tls13
from .websocket import _parse_response  # a plain HTTP status/header split, shared

#: Default English translator for direct callers (e.g. unit tests); ``assess`` passes
#: the report's own translator instead.
_EN = Translator(DEFAULT_LANGUAGE, MESSAGES)

_EVENT_STREAM = "text/event-stream"
_FOREIGN_ORIGIN = "https://cross-site.invalid"


def build_request(host: str, path: str, origin: Optional[str] = None) -> bytes:
    """A GET that asks for an event stream (RFC-less, but the EventSource contract)."""
    lines = [
        f"GET {path or '/'} HTTP/1.1",
        f"Host: {host}",
        "Accept: text/event-stream",
        "User-Agent: web-crypto-checker",
        "Connection: close",
    ]
    if origin is not None:
        lines.append(f"Origin: {origin}")
    lines.extend(["", ""])
    return "\r\n".join(lines).encode("latin1")


def _fetch(
    target: Target, address: str, origin: str, timeout: float, supports_tls13: bool
) -> Tuple[bytes, Optional[str]]:
    """Complete a TLS handshake and send one event-stream request."""
    host = target.effective_sni or target.host
    request = build_request(host, target.path, origin)
    sni = target.effective_sni
    if supports_tls13:
        return fetch_over_tls13(address, target.port, request, sni, timeout)
    return fetch_over_tls12(address, target.port, request, sni, timeout)


def check_sse(
    target: Target, address: str, timeout: float, supports_tls13: bool, active: bool = False
) -> Optional[SseInfo]:
    """Probe ``target`` for SSE support and, with ``active``, cross-origin exposure."""
    if target.scheme != "https":
        return None  # SSE rides the audited HTTPS; a cleartext probe is out of scope
    host = target.effective_sni or target.host
    raw, error = _fetch(target, address, f"https://{host}", timeout, supports_tls13)
    if error is not None:
        return SseInfo(error=error)
    status, headers = _parse_response(raw)
    content_type = headers.get("content-type")
    media_type = content_type.split(";")[0].strip().lower() if content_type else None
    info = SseInfo(
        supported=media_type == _EVENT_STREAM,
        status_code=status,
        content_type=content_type,
        allow_origin=headers.get("access-control-allow-origin"),
    )
    if active and info.supported:
        info.origin_checked = True
        foreign_raw, foreign_error = _fetch(
            target, address, _FOREIGN_ORIGIN, timeout, supports_tls13
        )
        if foreign_error is None:
            _status, foreign_headers = _parse_response(foreign_raw)
            info.cross_origin_open = (
                foreign_headers.get("access-control-allow-origin") == _FOREIGN_ORIGIN
            )
    return info


def sse_findings(info: Optional[SseInfo], t: Optional[Translator] = None) -> List[Finding]:
    """The SSE findings for a result, or none when no event stream was offered."""
    if info is None or not info.supported:
        return []
    t = t or _EN
    findings: List[Finding] = []
    if info.origin_checked and info.cross_origin_open:
        findings.append(
            Finding(
                "SSE-REFLECTED-ORIGIN",
                Severity.MEDIUM,
                t("find.sse_reflected_origin.title"),
                t("find.sse_reflected_origin.desc"),
                remediation=t("find.sse_reflected_origin.rem"),
            )
        )
    return findings
