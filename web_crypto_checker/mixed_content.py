"""Finding insecure ``http://`` subresources in an HTTPS page (mixed content).

An HTTPS page that pulls a subresource over plain ``http://`` breaks its own guarantee:
the resource travels in the clear, so an on-path attacker can read or tamper with it.
Browsers treat two classes differently, and so do we:

* *active* mixed content -- scripts, stylesheets, iframes, framed objects, form targets
  -- lets the attacker run code in the page's origin, so browsers **block** it outright;
* *passive* mixed content -- images, audio, video -- can be watched or swapped but not
  scripted, so browsers **warn** and try to upgrade it.

The HTML is tokenised with the standard library's lenient ``html.parser`` (no runtime
dependency), and only genuinely insecure references are reported: a protocol-relative
(``//host``) or relative URL inherits the page's ``https`` scheme, so it is not mixed
content; only an explicit ``http://`` is. CSS ``url()`` references and script-built URLs
are out of scope -- they are not visible in the served HTML.
"""

from __future__ import annotations

from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple

from .models import MixedContent

#: HTML element -> attributes whose ``http://`` value is *active* (blockable) mixed content.
_ACTIVE: Dict[str, Tuple[str, ...]] = {
    "script": ("src",),
    "iframe": ("src",),
    "object": ("data",),
    "embed": ("src",),
    "form": ("action",),
}
#: HTML element -> attributes whose ``http://`` value is *passive* (display) mixed content.
_PASSIVE: Dict[str, Tuple[str, ...]] = {
    "img": ("src",),
    "audio": ("src",),
    "video": ("src", "poster"),
    "source": ("src",),
    "track": ("src",),
}
_MAX_URLS = 20  # a bounded sample per bucket -- enough to prove the point, not the whole page


def _is_insecure(url: str) -> bool:
    """Whether a URL is an explicit, insecure ``http://`` reference."""
    return url.strip().lower().startswith("http://")


class _MixedContentParser(HTMLParser):
    """Collects the insecure http:// subresource URLs, split into active and passive."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.active: List[str] = []
        self.passive: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        values = {name: (value or "") for name, value in attrs}
        for bucket, table in ((self.active, _ACTIVE), (self.passive, _PASSIVE)):
            for attribute in table.get(tag, ()):
                if _is_insecure(values.get(attribute, "")):
                    bucket.append(values[attribute].strip())
        # A stylesheet <link> loads active content; other relations (icons, preconnect,
        # dns-prefetch) do not, so they are not mixed content worth blocking.
        if (
            tag == "link"
            and "stylesheet" in values.get("rel", "").lower()
            and _is_insecure(values.get("href", ""))
        ):
            self.active.append(values["href"].strip())


def scan_mixed_content(body: bytes) -> MixedContent:
    """The insecure ``http://`` subresources referenced in an HTML ``body``."""
    parser = _MixedContentParser()
    parser.feed(body.decode("utf-8", "replace"))
    return MixedContent(
        active=list(dict.fromkeys(parser.active))[:_MAX_URLS],  # dedupe, keep order, cap
        passive=list(dict.fromkeys(parser.passive))[:_MAX_URLS],
    )
