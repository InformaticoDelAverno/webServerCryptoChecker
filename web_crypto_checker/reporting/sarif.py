"""SARIF 2.1.0: the format GitHub code scanning and Azure DevOps ingest.

Each endpoint is an artifact addressed by its URL, each finding and each
vulnerability a result keyed on its identifier, so a dashboard can tell a
problem that reappears from a new one.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from ..models import ScanReport, Severity

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _result_entry(rule_id: str, severity: Severity, message: str, uri: str) -> Dict[str, Any]:
    return {
        "ruleId": rule_id,
        "level": _LEVEL[severity],
        "message": {"text": message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
    }


def render(report: ScanReport) -> str:
    rules: Dict[str, str] = {}
    results: List[Dict[str, Any]] = []
    for result in report.results:
        if not result.ok:
            continue
        uri = f"{result.target.scheme}://{result.target}"
        for finding in result.findings:
            rules.setdefault(finding.id, finding.title)
            results.append(_result_entry(finding.id, finding.severity, finding.title, uri))
        for vulnerability in result.vulnerabilities:
            rules.setdefault(vulnerability.id, vulnerability.name)
            results.append(
                _result_entry(vulnerability.id, vulnerability.severity, vulnerability.name, uri)
            )

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": report.tool,
                        "version": report.version,
                        "rules": [
                            {"id": rule_id, "shortDescription": {"text": name}}
                            for rule_id, name in rules.items()
                        ],
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2)
