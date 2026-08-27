"""Cross-origin scripts and stylesheets served without Subresource Integrity (SRI).

A page that loads a ``<script>`` or a stylesheet ``<link>`` from another origin is trusting
that host completely: if it is compromised (or the connection to it is), attacker code runs
in this page's origin. Subresource Integrity (an ``integrity="sha384-..."`` attribute) pins
the expected content so the browser refuses a tampered file (W3C SRI).

Only *cross-origin* subresources are flagged: a relative or same-host URL is served by the
page's own origin, where SRI adds nothing. The HTML is tokenised with the standard library's
lenient ``html.parser`` (no runtime dependency); as with mixed content, CSS ``url()`` and
script-built URLs are not in the served HTML and so are out of scope.
"""

from __future__ import annotations

from html.parser import HTMLParser
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

_MAX_URLS = 20  # a bounded sample -- enough to show the problem, not the whole page


def _cross_origin(url: str, page_host: str) -> bool:
    """Whether ``url`` points at a host other than the page's own (so SRI would matter).

    A relative URL has no host and is same-origin; an absolute or protocol-relative URL to a
    different host is cross-origin."""
    host = urlsplit(url.strip()).hostname
    return host is not None and host.lower() != page_host.lower()


class _SriParser(HTMLParser):
    """Collects cross-origin script/stylesheet URLs that carry no integrity attribute."""

    def __init__(self, page_host: str) -> None:
        super().__init__(convert_charrefs=True)
        self.page_host = page_host
        self.missing: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        values = {name: (value or "") for name, value in attrs}
        if tag == "script":
            url = values.get("src", "")
        elif tag == "link" and "stylesheet" in values.get("rel", "").lower():
            url = values.get("href", "")
        else:
            return
        if url and _cross_origin(url, self.page_host) and not values.get("integrity", "").strip():
            self.missing.append(url.strip())


def scan_subresource_integrity(body: bytes, page_host: str) -> List[str]:
    """The cross-origin subresource URLs in ``body`` that lack Subresource Integrity."""
    parser = _SriParser(page_host)
    parser.feed(body.decode("utf-8", "replace"))
    return list(dict.fromkeys(parser.missing))[:_MAX_URLS]  # dedupe, keep order, cap
