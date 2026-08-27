"""OpenMetrics (Prometheus) exposition, so a scan can be scraped and alerted on.

A gauge per endpoint (reachable, score, vulnerable) with target/ip labels, plus
the run totals. The point is a dashboard that goes red when a server's grade
drops or a vulnerability appears -- the same numbers the other formats show, in
the shape a time-series database wants. Ends with the required ``# EOF``.
"""

from __future__ import annotations

from typing import List

from ..models import ScanReport

_PREFIX = "web_crypto_checker"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _labels(**pairs: str) -> str:
    return ",".join(f'{name}="{_escape(value)}"' for name, value in pairs.items())


def _family(name: str, help_text: str, samples: List[str]) -> List[str]:
    return [f"# HELP {name} {help_text}", f"# TYPE {name} gauge", *samples]


def render(report: ScanReport) -> str:
    summary = report.summary
    lines: List[str] = []
    lines += _family(
        f"{_PREFIX}_scan_endpoints", "Endpoints scanned.",
        [f"{_PREFIX}_scan_endpoints {summary.total}"],
    )
    lines += _family(
        f"{_PREFIX}_scan_reachable", "Endpoints that responded.",
        [f"{_PREFIX}_scan_reachable {summary.succeeded}"],
    )
    lines += _family(
        f"{_PREFIX}_scan_vulnerable", "Endpoints with a known vulnerability.",
        [f"{_PREFIX}_scan_vulnerable {summary.vulnerable}"],
    )
    if summary.average_score is not None:
        lines += _family(
            f"{_PREFIX}_scan_average_score", "Mean score across reachable endpoints.",
            [f"{_PREFIX}_scan_average_score {summary.average_score}"],
        )

    reachable: List[str] = []
    score: List[str] = []
    vulnerable: List[str] = []
    for result in report.results:
        labels = _labels(target=str(result.target), ip=result.ip or "")
        reachable.append(f"{_PREFIX}_endpoint_reachable{{{labels}}} {1 if result.ok else 0}")
        if not result.ok:
            continue
        vulnerable.append(
            f"{_PREFIX}_endpoint_vulnerable{{{labels}}} {1 if result.vulnerabilities else 0}"
        )
        if result.score is not None:
            scored = _labels(
                target=str(result.target), ip=result.ip or "",
                grade=result.grade or "", verdict=result.verdict.value,
            )
            score.append(f"{_PREFIX}_endpoint_score{{{scored}}} {result.score}")

    lines += _family(f"{_PREFIX}_endpoint_reachable", "1 if the endpoint responded.", reachable)
    lines += _family(f"{_PREFIX}_endpoint_score", "Endpoint score, 0-100.", score)
    lines += _family(
        f"{_PREFIX}_endpoint_vulnerable", "1 if a known vulnerability matched.", vulnerable
    )
    lines.append("# EOF")
    return "\n".join(lines) + "\n"
