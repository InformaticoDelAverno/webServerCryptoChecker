"""A rolling history of scans, for watching a fleet's grades over time.

Each scan appends one compact JSON line per endpoint to a file; reading them back,
grouped by endpoint, shows how a grade has moved. It is the accumulating cousin of
``--compare``: ``--compare`` diffs against a single baseline, ``--history`` keeps
the whole series so a slow drift is visible, not just the last step.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from .models import ScanReport


def append(report: ScanReport, path: Path) -> None:
    """Append one JSON line per endpoint of ``report`` to the history at ``path``."""
    with path.open("a", encoding="utf-8") as handle:
        for result in report.results:
            record = {
                "at": report.started_at,
                "target": str(result.target),
                "ip": result.ip or "",
                "grade": result.grade,
                "score": result.score,
                "verdict": result.verdict.value,
                "vulnerabilities": len(result.vulnerabilities),
            }
            handle.write(json.dumps(record) + "\n")


def _load(path: Path) -> List[Dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def trend(report: ScanReport, path: Path) -> List[str]:
    """One line per current endpoint: its grade across every recorded scan."""
    history = _load(path)
    lines: List[str] = []
    for result in report.results:
        key = (str(result.target), result.ip or "")
        grades = [
            record["grade"] or "?"
            for record in history
            if (record["target"], record["ip"]) == key
        ]
        lines.append(f"{result.target.display_name} [{result.ip or '-'}]: {' -> '.join(grades)}")
    return lines
