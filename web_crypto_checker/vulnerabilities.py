"""Matching known vulnerabilities against what a server was seen to offer.

The detection is data, never code: each entry in the policy carries a small tree
of conditions -- a protocol version is supported, an offered cipher suite has a
shape-tag -- combined with all/any/not. Adding a vulnerability is adding an entry
to ``algorithms.json``; this module only evaluates the tree that is already
there. Detections that need an active probe or a protocol the tool does not yet
speak live in later phases, not here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from .models import Severity, TargetResult
from .tls.constants import cipher_suite_tags


@dataclass
class VulnerabilityMatch:
    """One known vulnerability a server matched, and what showed it."""

    id: str
    name: str
    severity: Severity
    description: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)


def evaluate(result: TargetResult, definitions: List[Dict[str, Any]]) -> List[VulnerabilityMatch]:
    """Every vulnerability whose detection tree matches this result."""
    supported = {protocol.id for protocol in result.protocols if protocol.supported}
    cipher_tags = {suite.name: cipher_suite_tags(suite.name) for suite in result.cipher_suites}

    matches: List[VulnerabilityMatch] = []
    for entry in definitions:
        detected, evidence = _match(entry["detection"], supported, cipher_tags)
        if detected:
            matches.append(
                VulnerabilityMatch(
                    id=entry["id"],
                    name=entry["name"],
                    severity=Severity(entry["severity"]),
                    description=entry.get("description", ""),
                    remediation=entry.get("remediation", ""),
                    references=list(entry.get("references", [])),
                    evidence=sorted(set(evidence)),
                )
            )
    return matches


def _match(
    condition: Dict[str, Any],
    supported: set,
    cipher_tags: Dict[str, List[str]],
) -> Tuple[bool, List[str]]:
    if "protocol" in condition:
        protocol = condition["protocol"]
        return (protocol in supported, [protocol] if protocol in supported else [])

    if "cipher_tag" in condition:
        tag = condition["cipher_tag"]
        hits = [name for name, tags in cipher_tags.items() if tag in tags]
        return (bool(hits), hits)

    if "all" in condition:
        evidence: List[str] = []
        for sub in condition["all"]:
            matched, found = _match(sub, supported, cipher_tags)
            if not matched:
                return (False, [])
            evidence.extend(found)
        return (True, evidence)

    if "any" in condition:
        evidence = []
        matched_any = False
        for sub in condition["any"]:
            matched, found = _match(sub, supported, cipher_tags)
            if matched:
                matched_any = True
                evidence.extend(found)
        return (matched_any, evidence)

    # The only remaining validated key is "not".
    matched, _found = _match(condition["not"], supported, cipher_tags)
    return (not matched, [])
