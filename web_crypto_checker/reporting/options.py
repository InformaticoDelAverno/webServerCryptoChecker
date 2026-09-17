"""Presentation choices for the human text reports.

Kept in its own module so both the format registry and the individual text
renderers (``console``, ``text``) can import it without a cycle through the
package ``__init__``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RenderOptions:
    """How to shape the console and text reports.

    ``color`` wraps the grade and each severity in ANSI escapes; ``summary_only``
    drops the per-endpoint detail and keeps just the header (and, for the text
    format, its aggregate footer); ``notes`` appends the policy's per-algorithm
    explanation under each offered cipher suite. Every flag is off by default, so
    a caller that renders without options gets exactly the previous output.
    """

    color: bool = False
    summary_only: bool = False
    notes: bool = False
