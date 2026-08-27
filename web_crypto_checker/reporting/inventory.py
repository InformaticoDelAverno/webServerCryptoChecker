"""One row per endpoint: the crypto asset inventory, not the finding backlog.

Where ``csv_report`` is a row per problem, this is a row per server -- what it
speaks, what certificate it presents and when it expires -- so a fleet's estate
lands in a spreadsheet or a CMDB. An unreachable endpoint keeps its row, with the
crypto columns blank.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import Optional

from ..models import CaaInfo, CertificateInfo, HttpSecurity, ScanReport
from .protocols import offered_protocols

_HEADER = [
    "target", "ip", "status", "grade", "verdict", "tls_versions", "cipher_suites",
    "certificate", "expires", "key", "hsts", "post_quantum", "protocols", "caa",
]


def _caa(caa: Optional[CaaInfo]) -> str:
    if caa is None or caa.error is not None:
        return ""
    return ";".join(record.value for record in caa.records if record.tag in ("issue", "issuewild"))


def _expiry(not_after: Optional[int]) -> str:
    if not_after is None:
        return ""
    return datetime.fromtimestamp(not_after, timezone.utc).date().isoformat()


def _key(leaf: CertificateInfo) -> str:
    if leaf.curve:
        return f"{leaf.key_type} {leaf.curve}"
    if leaf.key_bits:
        return f"{leaf.key_type} {leaf.key_bits}"
    return leaf.key_type


def _hsts(http: Optional[HttpSecurity]) -> str:
    if http is None or not http.reached:
        return ""
    return "yes" if http.hsts else "no"


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
            writer.writerow([*base, *[""] * (len(_HEADER) - len(base))])
            continue
        versions = ";".join(protocol.name for protocol in result.protocols if protocol.supported)
        leaf = result.certificate.leaf if result.certificate else None
        writer.writerow([
            *base,
            versions,
            str(len(result.cipher_suites)),
            leaf.subject if leaf else "",
            _expiry(leaf.not_after) if leaf else "",
            _key(leaf) if leaf else "",
            _hsts(result.http),
            result.post_quantum.value,
            ";".join(offered_protocols(result)),
            _caa(result.caa),
        ])
    return output.getvalue()
