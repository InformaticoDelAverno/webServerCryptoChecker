"""The report formats, and a small registry to pick one by name.

Each format is a module with a ``render`` function; this ties them to a name and
a file extension so the command line can offer ``--format`` without knowing what
any one of them does.

The human formats (console, text, html) render in the caller's language: a
:class:`~web_crypto_checker.i18n.Translator` is built here and threaded into
them. The machine formats (json, csv, sarif, inventory, openmetrics) keep their
English enum values and keys so downstream parsers are unaffected, so they take
no translator at all.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

from ..i18n import DEFAULT_LANGUAGE, Translator
from ..messages import MESSAGES
from ..models import ScanReport
from . import console, csv_report, html, inventory, json_report, openmetrics, sarif, text
from .options import RenderOptions

__all__ = ["EXTENSIONS", "FORMATS", "RenderOptions", "available_formats", "render"]

#: Mixed signatures on purpose: the human renderers take ``(report, translator)``
#: and the machine renderers take ``(report)``. ``render`` below dispatches on
#: membership of ``_HUMAN_FORMATS``, so the language never reaches a parser format.
FORMATS: Dict[str, Callable[..., str]] = {
    "console": console.render,
    "text": text.render,
    "json": json_report.render,
    "csv": csv_report.render,
    "html": html.render,
    "sarif": sarif.render,
    "inventory": inventory.render,
    "openmetrics": openmetrics.render,
}

#: The formats that render human prose, and so take a translator.
_HUMAN_FORMATS = frozenset({"console", "text", "html"})

#: The human formats that additionally honour :class:`RenderOptions` (colour,
#: summary-only, per-algorithm notes). HTML is human but structured, so it takes
#: the translator without the text-shaping options.
_OPTIONED_FORMATS = frozenset({"console", "text"})

EXTENSIONS: Dict[str, str] = {
    "console": "txt",
    "text": "txt",
    "json": "json",
    "csv": "csv",
    "html": "html",
    "sarif": "sarif.json",
    "inventory": "csv",
    "openmetrics": "prom",
}


def available_formats() -> List[str]:
    return sorted(FORMATS)


def render(
    report: ScanReport,
    name: str,
    language: str = DEFAULT_LANGUAGE,
    options: Optional[RenderOptions] = None,
) -> str:
    """Render ``report`` in the format ``name``, human prose in ``language``.

    ``options`` shapes the console and text formats (colour, summary-only, notes);
    it is ignored by every other format. ``None`` means the defaults, so an
    existing caller that passes no options gets byte-identical output.
    """
    renderer = FORMATS[name]
    if name in _OPTIONED_FORMATS:
        return renderer(report, Translator(language, MESSAGES), options or RenderOptions())
    if name in _HUMAN_FORMATS:
        return renderer(report, Translator(language, MESSAGES))
    return renderer(report)
