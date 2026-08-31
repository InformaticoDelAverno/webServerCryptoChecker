"""Running loaded plugins and folding their results into the report.

Plugins run *after* the grade is computed, and each is handed a
:class:`ServerView` with no score in it, so a plugin -- absent, broken or
third-party -- cannot move the number an auditor relies on. A plugin that raises
becomes a finding that names it, never a dead scan.
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence, cast

from ..models import Finding, Severity, TargetResult
from ..vulnerabilities import VulnerabilityMatch
from . import Detected, FleetView, ForTarget, Plugin, ServerView, Undetermined


def run_plugins(results: Sequence[TargetResult], plugins: Sequence[Plugin]) -> None:
    for result in results:
        if not result.ok:
            continue
        view = ServerView.from_result(result)
        for plugin in plugins:
            if plugin.kind == "fleet":
                continue  # a fleet check sees the whole scan; run_fleet handles it
            _run_one(plugin, view, result)


def _run_one(plugin: Plugin, view: ServerView, result: TargetResult) -> None:
    try:
        outcome = cast(Any, plugin.check)(view)
    except Exception as exc:  # a broken plugin must not break the scan
        result.findings.append(
            Finding(
                id=f"PLUGIN-ERROR-{plugin.id}",
                severity=Severity.INFO,
                title=f"Plugin {plugin.id} failed",
                description=str(exc),
            )
        )
        return
    _record(plugin, outcome, result)


def _record(plugin: Plugin, outcome: Any, result: TargetResult) -> None:
    if outcome is None or outcome is False:
        return

    if isinstance(outcome, Undetermined):
        needs = ", ".join(outcome.needs) or "more data"
        result.findings.append(
            Finding(
                id=f"{plugin.id}-UNDETERMINED",
                severity=Severity.INFO,
                title=f"{plugin.name}: not determined",
                description=f"Needs {needs}.",
            )
        )
        return

    if isinstance(outcome, Detected):
        severity = Severity(outcome.severity) if outcome.severity else plugin.severity
        evidence = list(outcome.evidence)
        note = f" {outcome.note}" if outcome.note else ""
    else:  # any other truthy value (e.g. True): affected, no evidence
        severity = plugin.severity
        evidence = []
        note = ""

    description = plugin.description + note
    if plugin.kind == "vulnerability":
        result.vulnerabilities.append(
            VulnerabilityMatch(
                id=plugin.id,
                name=plugin.name,
                severity=severity,
                description=description,
                remediation=plugin.remediation,
                references=list(plugin.references),
                evidence=evidence,
            )
        )
    else:
        result.findings.append(
            Finding(
                id=plugin.id,
                severity=severity,
                title=plugin.name,
                description=description,
                remediation=plugin.remediation,
                items=evidence,
                references=list(plugin.references),
            )
        )


def run_fleet(plugins: Sequence[Plugin], fleet: FleetView) -> Dict[str, List[Finding]]:
    """Run the fleet checks, returning findings keyed by target.

    Separate from :func:`run_plugins` because it happens at a different time:
    after every server, once, over all of them. A fleet check returns
    :class:`ForTarget` values saying which server each finding belongs to; one
    naming a server the scan never produced is dropped rather than invented, and
    a fleet check that raises becomes a finding on the first server, never a dead
    scan.
    """
    by_target: Dict[str, List[Finding]] = {}
    known = {server.target for server in fleet.servers}

    for plugin in plugins:
        if plugin.kind != "fleet":
            continue
        try:
            returned = cast(Any, plugin.check)(fleet)
        except Exception as exc:  # a broken plugin must not break the scan
            if fleet.servers:
                by_target.setdefault(fleet.servers[0].target, []).append(
                    Finding(
                        id=f"PLUGIN-ERROR-{plugin.id}",
                        severity=Severity.INFO,
                        title=f"Plugin {plugin.id} failed",
                        description=str(exc),
                    )
                )
            continue

        outcomes = returned if isinstance(returned, list) else [returned]
        for outcome in outcomes:
            if not isinstance(outcome, ForTarget):
                continue
            if outcome.target not in known:
                continue
            finding = outcome.finding
            if not isinstance(finding, Finding):
                finding = Finding(
                    id=plugin.id,
                    severity=plugin.severity,
                    title=plugin.name,
                    description=plugin.description,
                    remediation=plugin.remediation,
                    references=list(plugin.references),
                )
            by_target.setdefault(outcome.target, []).append(finding)
    return by_target
