"""The HTTP layer: one request over the session, then read the response back.

The tool asks a single ``GET``. It reads the response *headers* to see what the site
tells a browser about its own security -- HSTS, the security headers, cookie flags and
where an entry point redirects -- and, over HTTPS, a bounded amount of the *body* to
find insecure ``http://`` subresources (mixed content). Parsing is a pure function so
it is tested without a socket; the fetch that feeds it is covered against a real server.

It rides on the hand-rolled handshakes: ``tls/tls13.py`` for a TLS 1.3 endpoint and
``tls/tls12.py`` (ECDHE, AES-128-GCM) for a 1.2-only one. When *no* TLS can be
established, ``check_cleartext_http`` asks the same ``GET`` over a plain socket: a
server that answers HTTP in the clear is judged (an unconditional insecurity), not
dismissed as unreachable. A server whose handshake neither completes nor answers in
the clear is reported as *not measured*, never as *no problem found*.
"""

from __future__ import annotations

import socket
from typing import Dict, List, Optional, Tuple

from .i18n import DEFAULT_LANGUAGE, Translator
from .messages import MESSAGES
from .mixed_content import scan_mixed_content
from .models import CookieInfo, Finding, HttpSecurity, Severity, Target
from .subresource_integrity import scan_subresource_integrity
from .tls.probe import DEFAULT_TIMEOUT
from .tls.tls12 import exchange_over_tls12
from .tls.tls13 import exchange_over_tls13

#: Default English translator for callers (e.g. unit tests) that invoke the finding
#: functions directly; ``assess`` passes the report's own translator instead.
_EN = Translator(DEFAULT_LANGUAGE, MESSAGES)

_MAX_RESPONSE = 65536  # only the headers are needed; stop well before a large body
_MAX_BODY = 512 * 1024  # scan at most this much page body for mixed content

# Headers a browser-facing HTTPS endpoint is expected to send. Absence of any is
# reported (``missing_headers``); a subset also raise a finding (below).
RECOMMENDED_HEADERS: List[str] = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
]
# Extra headers worth recording when present, even though their absence is not
# itself flagged.
_ALSO_RECORDED: List[str] = ["permissions-policy", "cross-origin-opener-policy"]
_RECORDED = RECOMMENDED_HEADERS + _ALSO_RECORDED

# An HSTS max-age below this (180 days, in seconds) is too short to matter.
_MIN_HSTS_MAX_AGE = 15_552_000
# The HSTS preload list (hstspreload.org) requires at least a one-year max-age and
# includeSubDomains; a `preload` token without both is ignored by the list.
_PRELOAD_MIN_MAX_AGE = 31_536_000

# Missing-header findings, kept as data: (header, id, severity, title message-key). The
# description and remediation share one template (find.missing_header.*) keyed on the header.
_MISSING_HEADER_FINDINGS: List[Tuple[str, str, Severity, str]] = [
    ("content-security-policy", "HTTP-NO-CSP", Severity.LOW, "find.http_no_csp.title"),
    ("x-content-type-options", "HTTP-NO-XCTO", Severity.LOW, "find.http_no_xcto.title"),
    ("x-frame-options", "HTTP-NO-XFO", Severity.LOW, "find.http_no_xfo.title"),
    (
        "referrer-policy",
        "HTTP-NO-REFERRER-POLICY",
        Severity.LOW,
        "find.http_no_referrer_policy.title",
    ),
]


# An Origin no real site would use, sent so the server's CORS response can be read. If it
# comes back in Access-Control-Allow-Origin, the server reflects any origin (RFC 2606 .invalid
# guarantees this is never a genuine origin).
CORS_PROBE_ORIGIN = "https://web-crypto-checker.invalid"


def build_request(host: str, path: str) -> bytes:
    """A minimal, closing HTTP/1.1 GET for ``path`` on ``host``.

    Carries a probe ``Origin`` (as a cross-origin browser request would) so the server's CORS
    policy is visible in the response -- see ``CORS_PROBE_ORIGIN``."""
    lines = [
        f"GET {path or '/'} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: web-crypto-checker",
        "Accept: */*",
        f"Origin: {CORS_PROBE_ORIGIN}",
        "Connection: close",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("latin1")


def _parse_hsts(value: str) -> Tuple[Optional[int], bool, bool]:
    max_age: Optional[int] = None
    preload = False
    include_subdomains = False
    for token in value.split(";"):
        token = token.strip()
        lowered = token.lower()
        if lowered == "preload":
            preload = True
        elif lowered == "includesubdomains":
            include_subdomains = True
        elif lowered.startswith("max-age="):
            digits = token.split("=", 1)[1].strip().strip('"')
            if digits.isdigit():
                max_age = int(digits)
    return max_age, preload, include_subdomains


def _prefix_ok(cookie: CookieInfo) -> bool:
    """Whether a cookie honours its ``__Secure-``/``__Host-`` name-prefix contract (RFC
    6265bis 4.1.3): __Secure- requires Secure; __Host- also requires Path=/ and no Domain."""
    lowered = cookie.name.lower()
    if lowered.startswith("__secure-"):
        return cookie.secure
    if lowered.startswith("__host-"):
        return cookie.secure and cookie.path == "/" and cookie.domain == ""
    return True


def _parse_cookie(value: str) -> CookieInfo:
    parts = [part.strip() for part in value.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    secure = False
    http_only = False
    same_site = ""
    path = ""
    domain = ""
    for attribute in parts[1:]:
        lowered = attribute.lower()
        if lowered == "secure":
            secure = True
        elif lowered == "httponly":
            http_only = True
        elif lowered.startswith("samesite="):
            same_site = attribute.split("=", 1)[1].strip()
        elif lowered.startswith("path="):
            path = attribute.split("=", 1)[1].strip()
        elif lowered.startswith("domain="):
            domain = attribute.split("=", 1)[1].strip()
    return CookieInfo(
        name=name,
        secure=secure,
        http_only=http_only,
        same_site=same_site,
        path=path,
        domain=domain,
    )


def _advertises_http3(value: str) -> bool:
    """Whether an Alt-Svc header advertises an HTTP/3 (``h3``) endpoint.

    Alt-Svc (RFC 7838) is a comma-separated list of ``protocol-id=authority``;
    HTTP/3 is the final ``h3`` or a draft ``h3-NN``. This says the server *offers*
    HTTP/3 over QUIC, not that the tool dialled it -- the QUIC engine is its own
    thing.
    """
    for entry in value.split(","):
        token = entry.strip().split("=", 1)[0].strip()
        if token == "h3" or token.startswith("h3-"):
            return True
    return False


def _redirect_target(status_code: Optional[int], location: Optional[str]) -> Optional[bool]:
    if status_code is None or not 300 <= status_code < 400 or location is None:
        return None
    lowered = location.strip().lower()
    if lowered.startswith("https:"):
        return True
    if lowered.startswith("http:"):
        return False
    return None


def parse_http_response(raw: bytes) -> HttpSecurity:
    """Turn raw response bytes into the security-relevant view. Pure, no socket."""
    head = raw.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace")
    lines = head.split("\r\n")

    status_code: Optional[int] = None
    status_line = lines[0].split(" ", 2) if lines[0] else []
    if len(status_line) >= 2 and status_line[1].isdigit():
        status_code = int(status_line[1])

    recorded: Dict[str, str] = {}
    cookies: List[CookieInfo] = []
    server = ""
    hsts: Optional[str] = None
    location: Optional[str] = None
    alt_svc: Optional[str] = None
    cors_origin: Optional[str] = None
    cors_credentials = False
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip().lower()
        value = value.strip()
        if name == "set-cookie":
            cookies.append(_parse_cookie(value))
        elif name == "server":
            server = value
        elif name == "location":
            location = value
        elif name == "alt-svc":
            alt_svc = value
        elif name == "access-control-allow-origin":
            cors_origin = value
        elif name == "access-control-allow-credentials":
            cors_credentials = value.lower() == "true"
        elif name == "strict-transport-security":
            hsts = value
            recorded[name] = value
        elif name in _RECORDED:
            recorded[name] = value

    max_age, preload, include_subdomains = (
        _parse_hsts(hsts) if hsts is not None else (None, False, False)
    )
    missing = [header for header in RECOMMENDED_HEADERS if header not in recorded]
    return HttpSecurity(
        reached=True,
        status_code=status_code,
        redirects_to_https=_redirect_target(status_code, location),
        hsts=hsts,
        hsts_max_age=max_age,
        hsts_preload=preload,
        hsts_include_subdomains=include_subdomains,
        headers=recorded,
        missing_headers=missing,
        cookies=cookies,
        server=server,
        alt_svc=alt_svc,
        http3_advertised=_advertises_http3(alt_svc) if alt_svc is not None else False,
        cors_allow_origin=cors_origin,
        cors_allow_credentials=cors_credentials,
    )


def _content_length(head: bytes) -> Optional[int]:
    """The Content-Length of a response header block, or ``None`` when it is absent or
    not a plain number."""
    for line in head.split(b"\r\n")[1:]:
        name, separator, value = line.partition(b":")
        if separator and name.strip().lower() == b"content-length":
            digits = value.strip()
            if digits.isdigit():
                return int(digits)
    return None


def _page_complete(reply: bytes) -> bool:
    """Whether enough of the response is in to stop reading: the body cap is reached, or
    the whole Content-Length body has arrived. With no Content-Length the connection
    close (``Connection: close``) ends the read instead."""
    if len(reply) >= _MAX_BODY:
        return True
    head, separator, body = reply.partition(b"\r\n\r\n")
    if not separator:
        return False  # the header block is not even complete yet
    length = _content_length(head)
    return length is not None and len(body) >= length


def check_http(
    target: Target, address: str, timeout: float, supports_tls13: bool
) -> Optional[HttpSecurity]:
    """Fetch and assess the HTTP layer for one endpoint, or explain why it could not."""
    if target.scheme != "https":
        return None  # the cleartext path is handled by check_cleartext_http when TLS fails
    request = build_request(target.effective_sni or target.host, target.path)
    exchange = exchange_over_tls13 if supports_tls13 else exchange_over_tls12
    _alpn, raw, error = exchange(
        address,
        target.port,
        request,
        target.effective_sni,
        timeout,
        ["http/1.1"],
        _page_complete,
    )
    if error is not None:
        return HttpSecurity(reached=False, error=error)
    response = parse_http_response(raw)
    _head, _separator, body = raw.partition(b"\r\n\r\n")
    response.mixed_content = scan_mixed_content(body)
    response.subresources_without_sri = scan_subresource_integrity(
        body, target.effective_sni or target.host
    )
    response.cleartext_redirect = check_cleartext_redirect(target, address, timeout)
    return response


def check_cleartext_redirect(
    target: Target, address: str, timeout: float = DEFAULT_TIMEOUT
) -> Optional[bool]:
    """Whether the cleartext HTTP port (80) redirects to HTTPS.

    A browser's first, un-cached visit reaches ``http://`` and must be bounced to
    ``https://``; a site that answers HTTP on port 80 without upgrading leaves that first
    request in cleartext. Only meaningful for a standard HTTPS target (port 443). Returns
    ``True`` when port 80 redirects to HTTPS, ``False`` when it serves cleartext (or
    redirects to another ``http://`` URL) without upgrading, and ``None`` when port 80 is
    not serving HTTP or the target is not standard HTTPS -- there is nothing to judge.
    """
    if target.scheme != "https" or target.port != 443:
        return None
    request = build_request(target.effective_sni or target.host, "/")
    raw, error = fetch_cleartext(address, 80, request, timeout)
    if error is not None or not raw:
        return None  # nothing answers on port 80 -- no cleartext service to flag
    response = parse_http_response(raw)
    if response.status_code is None:
        return None  # something answered, but not with an HTTP response
    return bool(response.redirects_to_https)


def fetch_cleartext(
    host: str, port: int, request: bytes, timeout: float = DEFAULT_TIMEOUT
) -> Tuple[bytes, Optional[str]]:
    """Send ``request`` over a plain TCP socket and read the response, headers first."""
    try:
        sock = socket.create_connection((host, port), timeout)
    except OSError as exc:
        return b"", f"connection failed: {exc}"
    try:
        sock.settimeout(timeout)
        sock.sendall(request)
        response = b""
        while len(response) < _MAX_RESPONSE:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            response += chunk
            if b"\r\n\r\n" in response:  # the header block is complete; the body is not read
                break
        return response, None
    except OSError as exc:
        return b"", f"read failed: {exc}"
    finally:
        sock.close()


def check_cleartext_http(
    target: Target, address: str, timeout: float = DEFAULT_TIMEOUT
) -> Optional[HttpSecurity]:
    """Whether the endpoint serves *unencrypted* HTTP, and what its headers say.

    Called only when no TLS could be established: a reply that parses as HTTP means the
    traffic is in cleartext -- an unconditional insecurity, returned with ``cleartext``
    set so the assessment judges the endpoint rather than dismissing it as unreachable.
    ``None`` when nothing answers or the answer is not HTTP.
    """
    request = build_request(target.effective_sni or target.host, target.path)
    raw, error = fetch_cleartext(address, target.port, request, timeout)
    if error is not None or not raw:
        return None
    response = parse_http_response(raw)
    if response.status_code is None:
        return None  # something answered, but not with an HTTP response
    response.cleartext = True
    return response


# Script sources that let scripts load from essentially anywhere (CSP Level 3 4.2.1):
# a bare wildcard, a scheme-only source, or the data: scheme (XSS via data URIs).
_CSP_BROAD_SOURCES = {"*", "http:", "https:", "data:"}
# Prefixes in a script-src that neutralise 'unsafe-inline' for a compliant browser (CSP3):
# a nonce or a hash makes the browser ignore 'unsafe-inline', as does 'strict-dynamic'.
_CSP_NEUTRALISERS = ("'nonce-", "'sha256-", "'sha384-", "'sha512-", "'strict-dynamic'")


def _csp_directives(value: str) -> Dict[str, List[str]]:
    """A Content-Security-Policy parsed into ``{directive: [source, ...]}``. Directive names
    are lower-cased (they are case-insensitive); the first occurrence of a repeated directive
    wins (RFC-less, but what browsers do). Source expressions keep their original case."""
    directives: Dict[str, List[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            directives.setdefault(tokens[0].lower(), tokens[1:])
    return directives


def _csp_script_sources(value: str) -> List[str]:
    """The sources that govern scripts: ``script-src`` if present, else the ``default-src``
    fallback, else empty (the policy does not restrict scripts at all)."""
    directives = _csp_directives(value)
    if "script-src" in directives:
        return directives["script-src"]
    return directives.get("default-src", [])


def _csp_findings(value: str, t: Translator) -> List[Finding]:
    """Findings for a present but permissive Content-Security-Policy: a policy that still
    allows inline script, ``eval``, or scripts from any host gives little XSS protection."""
    sources = _csp_script_sources(value)
    lowered = [source.lower() for source in sources]
    findings: List[Finding] = []
    neutralised = any(token.startswith(_CSP_NEUTRALISERS) for token in lowered)
    if "'unsafe-inline'" in lowered and not neutralised:
        findings.append(
            Finding(
                "HTTP-CSP-UNSAFE-INLINE",
                Severity.MEDIUM,
                t("find.http_csp_unsafe_inline.title"),
                t("find.http_csp_unsafe_inline.desc"),
                remediation=t("find.http_csp_unsafe_inline.rem"),
            )
        )
    if "'unsafe-eval'" in lowered:
        findings.append(
            Finding(
                "HTTP-CSP-UNSAFE-EVAL",
                Severity.LOW,
                t("find.http_csp_unsafe_eval.title"),
                t("find.http_csp_unsafe_eval.desc"),
                remediation=t("find.http_csp_unsafe_eval.rem"),
            )
        )
    broad = [source for source in sources if source.lower() in _CSP_BROAD_SOURCES]
    if broad:
        findings.append(
            Finding(
                "HTTP-CSP-BROAD-SCRIPT-SRC",
                Severity.MEDIUM,
                t("find.http_csp_broad_script_src.title"),
                t("find.http_csp_broad_script_src.desc"),
                remediation=t("find.http_csp_broad_script_src.rem"),
                items=broad,
            )
        )
    return findings


def http_findings(http: Optional[HttpSecurity], t: Optional[Translator] = None) -> List[Finding]:
    """The HTTP-layer findings for a result, or none when the layer was not reached."""
    if http is None or not http.reached:
        return []
    t = t or _EN
    if http.cleartext:
        return [
            Finding(
                "HTTP-CLEARTEXT",
                Severity.CRITICAL,
                t("find.http_cleartext.title"),
                t("find.http_cleartext.desc"),
                remediation=t("find.http_cleartext.rem"),
            )
        ]
    findings: List[Finding] = []

    if http.hsts is None:
        findings.append(
            Finding(
                "HTTP-NO-HSTS",
                Severity.MEDIUM,
                t("find.http_no_hsts.title"),
                t("find.http_no_hsts.desc"),
                remediation=t("find.http_no_hsts.rem"),
            )
        )
    elif http.hsts_max_age is not None and http.hsts_max_age < _MIN_HSTS_MAX_AGE:
        findings.append(
            Finding(
                "HTTP-WEAK-HSTS",
                Severity.LOW,
                t("find.http_weak_hsts.title"),
                t("find.http_weak_hsts.desc", max_age=http.hsts_max_age),
                remediation=t("find.http_weak_hsts.rem"),
            )
        )
    if http.hsts is not None and not http.hsts_include_subdomains:
        findings.append(
            Finding(
                "HTTP-HSTS-NO-SUBDOMAINS",
                Severity.LOW,
                t("find.http_hsts_no_subdomains.title"),
                t("find.http_hsts_no_subdomains.desc"),
                remediation=t("find.http_hsts_no_subdomains.rem"),
            )
        )
    if http.hsts_preload and (
        http.hsts_max_age is None
        or http.hsts_max_age < _PRELOAD_MIN_MAX_AGE
        or not http.hsts_include_subdomains
    ):
        findings.append(
            Finding(
                "HTTP-HSTS-PRELOAD-INELIGIBLE",
                Severity.LOW,
                t("find.http_hsts_preload_ineligible.title"),
                t("find.http_hsts_preload_ineligible.desc"),
                remediation=t("find.http_hsts_preload_ineligible.rem"),
            )
        )
    if http.cleartext_redirect is False:
        findings.append(
            Finding(
                "HTTP-NO-HTTPS-REDIRECT",
                Severity.MEDIUM,
                t("find.http_no_https_redirect.title"),
                t("find.http_no_https_redirect.desc"),
                remediation=t("find.http_no_https_redirect.rem"),
            )
        )

    csp = http.headers.get("content-security-policy")
    if csp is not None:
        findings.extend(_csp_findings(csp, t))

    if http.subresources_without_sri:
        findings.append(
            Finding(
                "HTTP-SUBRESOURCE-NO-SRI",
                Severity.LOW,
                t("find.http_subresource_no_sri.title"),
                t("find.http_subresource_no_sri.desc"),
                remediation=t("find.http_subresource_no_sri.rem"),
                items=http.subresources_without_sri,
            )
        )

    reflects = http.cors_allow_origin == CORS_PROBE_ORIGIN
    wildcard = http.cors_allow_origin == "*"
    if reflects and http.cors_allow_credentials:
        findings.append(
            Finding(
                "HTTP-CORS-CREDENTIALED",
                Severity.HIGH,
                t("find.http_cors_credentialed.title"),
                t("find.http_cors_credentialed.desc"),
                remediation=t("find.http_cors_credentialed.rem"),
            )
        )
    elif reflects or wildcard:
        findings.append(
            Finding(
                "HTTP-CORS-OPEN",
                Severity.LOW,
                t("find.http_cors_open.title"),
                t("find.http_cors_open.desc"),
                remediation=t("find.http_cors_open.rem"),
            )
        )

    xcto = http.headers.get("x-content-type-options")
    if xcto is not None and xcto.strip().lower() != "nosniff":
        findings.append(
            Finding(
                "HTTP-XCTO-INEFFECTIVE",
                Severity.LOW,
                t("find.http_xcto_ineffective.title"),
                t("find.http_xcto_ineffective.desc"),
                remediation=t("find.http_xcto_ineffective.rem"),
                items=[xcto],
            )
        )

    xfo = http.headers.get("x-frame-options")
    if xfo is not None and xfo.strip().upper() not in ("DENY", "SAMEORIGIN"):
        # Ineffective only if CSP frame-ancestors is not there to cover clickjacking anyway.
        frame_ancestors = csp is not None and "frame-ancestors" in _csp_directives(csp)
        if not frame_ancestors:
            findings.append(
                Finding(
                    "HTTP-XFO-INEFFECTIVE",
                    Severity.LOW,
                    t("find.http_xfo_ineffective.title"),
                    t("find.http_xfo_ineffective.desc"),
                    remediation=t("find.http_xfo_ineffective.rem"),
                    items=[xfo],
                )
            )

    insecure = [cookie.name for cookie in http.cookies if not cookie.secure]
    if insecure:
        findings.append(
            Finding(
                "HTTP-INSECURE-COOKIE",
                Severity.MEDIUM,
                t("find.http_insecure_cookie.title"),
                t("find.http_insecure_cookie.desc"),
                remediation=t("find.http_insecure_cookie.rem"),
                items=insecure,
            )
        )

    no_http_only = [cookie.name for cookie in http.cookies if not cookie.http_only]
    if no_http_only:
        findings.append(
            Finding(
                "HTTP-COOKIE-NO-HTTPONLY",
                Severity.LOW,
                t("find.http_cookie_no_httponly.title"),
                t("find.http_cookie_no_httponly.desc"),
                remediation=t("find.http_cookie_no_httponly.rem"),
                items=no_http_only,
            )
        )

    weak_same_site = [
        cookie.name
        for cookie in http.cookies
        if not cookie.same_site or (cookie.same_site.lower() == "none" and not cookie.secure)
    ]
    if weak_same_site:
        findings.append(
            Finding(
                "HTTP-COOKIE-WEAK-SAMESITE",
                Severity.LOW,
                t("find.http_cookie_weak_samesite.title"),
                t("find.http_cookie_weak_samesite.desc"),
                remediation=t("find.http_cookie_weak_samesite.rem"),
                items=weak_same_site,
            )
        )

    bad_prefix = [cookie.name for cookie in http.cookies if not _prefix_ok(cookie)]
    if bad_prefix:
        findings.append(
            Finding(
                "HTTP-COOKIE-PREFIX-INVALID",
                Severity.MEDIUM,
                t("find.http_cookie_prefix_invalid.title"),
                t("find.http_cookie_prefix_invalid.desc"),
                remediation=t("find.http_cookie_prefix_invalid.rem"),
                items=bad_prefix,
            )
        )

    for header, identifier, severity, title_key in _MISSING_HEADER_FINDINGS:
        if header in http.missing_headers:
            findings.append(
                Finding(
                    identifier,
                    severity,
                    t(title_key),
                    t("find.missing_header.desc", header=header),
                    remediation=t("find.missing_header.rem", header=header),
                )
            )

    mixed = http.mixed_content
    if mixed is not None and mixed.active:
        findings.append(
            Finding(
                "HTTP-MIXED-ACTIVE",
                Severity.HIGH,
                t("find.http_mixed_active.title"),
                t("find.http_mixed_active.desc"),
                remediation=t("find.http_mixed_active.rem"),
                items=mixed.active,
            )
        )
    if mixed is not None and mixed.passive:
        findings.append(
            Finding(
                "HTTP-MIXED-PASSIVE",
                Severity.LOW,
                t("find.http_mixed_passive.title"),
                t("find.http_mixed_passive.desc"),
                remediation=t("find.http_mixed_passive.rem"),
                items=mixed.passive,
            )
        )
    return findings
