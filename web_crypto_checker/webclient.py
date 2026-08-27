"""A tiny plaintext HTTP/1.1 client for the revocation checks (OCSP and CRL).

OCSP responders and CRL distribution points are nearly always plain ``http://``,
so this GETs or POSTs to one and returns the response body. Deliberately minimal:
no redirects, no TLS, no chunked decoding -- just enough to fetch a DER blob from a
URL the certificate itself named.
"""

from __future__ import annotations

import socket
from typing import Optional, Tuple


def http_request(
    url: str, method: str, timeout: float, body: bytes = b"", content_type: str = ""
) -> Tuple[Optional[bytes], Optional[str]]:
    """Fetch ``url``; return ``(response_body, error)`` with exactly one set."""
    if not url.startswith("http://"):
        return None, "the URL is not plain HTTP"
    authority, _, path = url[len("http://") :].partition("/")
    host, _, port_text = authority.partition(":")
    try:
        port = int(port_text) if port_text else 80
    except ValueError:
        return None, "the URL has a bad port"

    lines = [f"{method} /{path} HTTP/1.1", f"Host: {host}", "Connection: close"]
    if body:
        lines += [f"Content-Type: {content_type}", f"Content-Length: {len(body)}"]
    request = ("\r\n".join(lines) + "\r\n\r\n").encode("latin1") + body

    try:
        sock = socket.create_connection((host, port), timeout)
    except OSError as exc:
        return None, f"connection failed: {exc}"
    try:
        sock.settimeout(timeout)
        sock.sendall(request)
        raw = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
    except OSError as exc:
        return None, f"network error: {exc}"
    finally:
        sock.close()

    if b"\r\n\r\n" not in raw:
        return None, "malformed HTTP response"
    return raw.split(b"\r\n\r\n", 1)[1], None
