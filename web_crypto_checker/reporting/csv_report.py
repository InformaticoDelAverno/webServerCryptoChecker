"""One row per finding, with the endpoint's columns repeated on each.

This is what filters a fleet by severity in a spreadsheet, or imports the
backlog into an issue tracker. An endpoint with nothing wrong still gets a row,
so a clean server is distinguishable from one that was never scanned.
"""

from __future__ import annotations

import csv
import io

from ..models import ScanReport

_HEADER = ["target", "ip", "status", "grade", "verdict", "kind", "severity", "id", "detail"]


def render(report: ScanReport) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(_HEADER)
    for result in report.results:
        base = [
            str(result.target),
            result.ip or "",
            result.status.value,
            result.grade or "",
            result.verdict.value,
        ]
        if not result.ok:
            writer.writerow([*base, "error", "", "", result.error or ""])
            continue
        wrote_row = False
        for finding in result.findings:
            writer.writerow([*base, "finding", finding.severity.value, finding.id, finding.title])
            wrote_row = True
        for vulnerability in result.vulnerabilities:
            writer.writerow(
                [*base, "vulnerability", vulnerability.severity.value, vulnerability.id,
                 vulnerability.name]
            )
            wrote_row = True
        if not wrote_row:
            writer.writerow([*base, "ok", "", "", ""])
    return output.getvalue()
