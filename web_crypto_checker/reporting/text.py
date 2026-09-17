"""Plain text: the console report plus an aggregate summary footer.

Meant to be attached to a ticket or an email -- no escape sequences, and the
whole-scan counts at the end so a reader sees the shape of a fleet at a glance.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Optional

from ..i18n import Translator
from ..models import ScanReport
from . import console
from .options import RenderOptions


def render(report: ScanReport, t: Translator, options: Optional[RenderOptions] = None) -> str:
    options = options or RenderOptions()
    summary = report.summary
    lines = [
        # A text report is meant for a ticket or an email, so it never carries
        # escape sequences even when the caller asked for colour on the console.
        console.render(report, t, replace(options, color=False)),
        "",
        t("rep.txt.summary"),
        t(
            "rep.txt.counts",
            total=summary.total,
            reachable=summary.succeeded,
            failed=summary.failed,
        ),
    ]
    if summary.average_score is not None:
        lines.append(t("rep.txt.average_score", score=summary.average_score))
    if summary.by_grade:
        grades = ", ".join(f"{grade}:{count}" for grade, count in sorted(summary.by_grade.items()))
        lines.append(t("rep.txt.grades", grades=grades))
    if summary.vulnerable:
        lines.append(t("rep.txt.vulnerable", n=summary.vulnerable))
    return "\n".join(lines)
