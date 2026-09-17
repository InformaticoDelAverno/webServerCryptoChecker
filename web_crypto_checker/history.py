"""A rolling history of scans, for watching a fleet's grades over time.

Each scan appends one compact JSON line per endpoint to a file; reading them back,
grouped by endpoint, shows how a grade has moved. It is the accumulating cousin of
``--compare``: ``--compare`` diffs against a single baseline, ``--history`` keeps
the whole series so a slow drift is visible, not just the last step.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

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


def summarise(report: ScanReport, path: Path) -> List[str]:
    """How the estate moved across the recorded scans (for ``--history-report``).

    Where ``trend`` prints the raw grade series, this reads the *movement*: for
    each current endpoint, its first recorded grade against its last and whether
    its score rose or fell, plus a one-line estate roll-up. Direction is taken
    from the numeric score, so ``A`` to ``A`` with a lower score still reads as a
    regression the letter alone would hide.
    """
    records = _load(path)
    series: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for record in records:
        series.setdefault((record["target"], record["ip"]), []).append(record)

    lines: List[str] = []
    improved = regressed = steady = 0
    for result in report.results:
        entries = series.get((str(result.target), result.ip or ""))
        if not entries:
            continue
        first, last = entries[0], entries[-1]
        first_score, last_score = first.get("score"), last.get("score")
        if first_score is not None and last_score is not None:
            delta = last_score - first_score
        else:
            delta = 0
        if delta > 0:
            improved += 1
            move = f"improved +{delta}"
        elif delta < 0:
            regressed += 1
            move = f"regressed {delta}"
        else:
            steady += 1
            move = "no change"
        lines.append(
            f"{result.target.display_name} [{result.ip or '-'}]: "
            f"{first['grade'] or '?'} -> {last['grade'] or '?'} "
            f"({move}, {len(entries)} scan(s))"
        )
    lines.append(f"Estate: {improved} improved, {regressed} regressed, {steady} unchanged")
    return lines
