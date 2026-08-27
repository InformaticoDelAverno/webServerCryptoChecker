"""A versioned JSON document with everything the scan observed and concluded.

The whole report is serialised through :func:`to_jsonable`, so every field --
the raw algorithm lists, the score breakdown, the certificate, the
vulnerabilities -- travels, and any field whose name suggests a secret is
redacted on the way out. For dashboards and history, not for a person.
"""

from __future__ import annotations

import json

from ..models import ScanReport, to_jsonable

SCHEMA_VERSION = "1.0"


def render(report: ScanReport) -> str:
    document = {"schema_version": SCHEMA_VERSION, "report": to_jsonable(report)}
    return json.dumps(document, indent=2)
