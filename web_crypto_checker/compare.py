"""Comparing a scan against an earlier JSON report.

A report says how a server is today. What a fleet usually needs to know is what
*changed* -- what appeared since the last audit, what was fixed, and what got
worse in silence after a package update nobody announced. This reads a JSON
report as the baseline and reports the movement, keyed on identifiers rather than
on text so a finding that reappears is not mistaken for a new one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Set

from .models import ScanReport

_GRADE_ORDER = ["A+", "A", "B", "C", "D", "E", "F"]


class CompareError(Exception):
    """A baseline report could not be read."""


def _rank(grade: Any) -> int:
    """A grade's position, worst for anything ungraded (None, unknown)."""
    return _GRADE_ORDER.index(grade) if grade in _GRADE_ORDER else len(_GRADE_ORDER)


def _key(host: str, port: Any, ip: Any) -> str:
    return f"{host}:{port}@{ip}"


@dataclass
class _Endpoint:
    grade: Any = None
    findings: Set[str] = field(default_factory=set)
    vulnerabilities: Set[str] = field(default_factory=set)
    algorithms: Dict[str, Set[str]] = field(default_factory=dict)
    """Offered algorithms per class (cipher, protocol, group, signature ...)."""
    certificate: str = ""
    """The leaf certificate's SHA-256 fingerprint, or '' when there is none."""


@dataclass
class Comparison:
    """The differences between a scan and its baseline."""

    changes: List[str] = field(default_factory=list)
    regressed: bool = False


def load_baseline(path: Path) -> Dict[str, Any]:
    """Read a JSON report, accepting either the wrapped or the bare form."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        report = data.get("report", data)
    except (OSError, json.JSONDecodeError, AttributeError) as exc:
        raise CompareError(f"cannot read baseline {path}: {exc}") from exc
    if not isinstance(report, dict):
        raise CompareError(f"baseline {path} does not contain a report")
    return report


def _current_endpoints(report: ScanReport) -> Dict[str, _Endpoint]:
    endpoints: Dict[str, _Endpoint] = {}
    for result in report.results:
        leaf = result.certificate.leaf if result.certificate is not None else None
        endpoints[_key(result.target.host, result.target.port, result.ip)] = _Endpoint(
            grade=result.grade,
            findings={finding.id for finding in result.findings},
            vulnerabilities={vulnerability.id for vulnerability in result.vulnerabilities},
            algorithms={
                assessment.key: {alg.name for alg in assessment.algorithms}
                for assessment in result.assessments
            },
            certificate=leaf.fingerprint_sha256 if leaf is not None else "",
        )
    return endpoints


def _baseline_endpoints(baseline: Dict[str, Any]) -> Dict[str, _Endpoint]:
    endpoints: Dict[str, _Endpoint] = {}
    for result in baseline.get("results", []):
        target = result.get("target", {})
        certificates = (result.get("certificate") or {}).get("certificates") or []
        endpoints[_key(target.get("host"), target.get("port"), result.get("ip"))] = _Endpoint(
            grade=result.get("grade"),
            findings={finding["id"] for finding in result.get("findings", [])},
            vulnerabilities={item["id"] for item in result.get("vulnerabilities", [])},
            algorithms={
                assessment.get("key", ""): {
                    alg.get("name", "") for alg in assessment.get("algorithms") or []
                }
                for assessment in result.get("assessments") or []
            },
            certificate=certificates[0].get("fingerprint_sha256", "") if certificates else "",
        )
    return endpoints


def compare(current: ScanReport, baseline: Dict[str, Any]) -> Comparison:
    """Report every change from ``baseline`` to ``current``."""
    now = _current_endpoints(current)
    before = _baseline_endpoints(baseline)
    comparison = Comparison()

    for key in sorted(set(now) | set(before)):
        here = now.get(key)
        there = before.get(key)
        if there is None:
            comparison.changes.append(f"{key}: new endpoint")
            continue
        if here is None:
            comparison.changes.append(f"{key}: gone from the scan")
            continue

        if here.grade != there.grade:
            regressed = _rank(here.grade) > _rank(there.grade)
            comparison.regressed = comparison.regressed or regressed
            direction = "regressed" if regressed else "improved"
            comparison.changes.append(
                f"{key}: {direction}, grade {there.grade} -> {here.grade}"
            )

        for new in sorted(here.findings - there.findings):
            comparison.changes.append(f"{key}: NEW finding {new}")
            comparison.regressed = True
        for resolved in sorted(there.findings - here.findings):
            comparison.changes.append(f"{key}: resolved finding {resolved}")
        for new in sorted(here.vulnerabilities - there.vulnerabilities):
            comparison.changes.append(f"{key}: NEW vulnerability {new}")
            comparison.regressed = True
        for resolved in sorted(there.vulnerabilities - here.vulnerabilities):
            comparison.changes.append(f"{key}: resolved vulnerability {resolved}")

        for class_key in sorted(set(here.algorithms) | set(there.algorithms)):
            old = there.algorithms.get(class_key, set())
            new_offered = here.algorithms.get(class_key, set())
            for name in sorted(new_offered - old):
                comparison.changes.append(f"{key}: now offers {class_key} {name}")
            for name in sorted(old - new_offered):
                comparison.changes.append(f"{key}: no longer offers {class_key} {name}")

        # A leaf certificate that changed is worth a line -- on a server nobody
        # reissued, a new fingerprint is a reason to stop and find out why -- but
        # not a regression by itself.
        if here.certificate and there.certificate and here.certificate != there.certificate:
            comparison.changes.append(
                f"{key}: certificate changed {there.certificate} -> {here.certificate}"
            )

    return comparison
