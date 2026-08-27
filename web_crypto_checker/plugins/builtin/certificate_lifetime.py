"""A certificate valid for longer than the CA/Browser Forum permits.

This is a plugin rather than a policy rule because it has to *compute* something
the rule language cannot: the number of days between two dates. Since September
2020 a publicly-trusted certificate must be valid for no more than 398 days; a
much longer window is a sign of a private or misissued certificate and, if the
key is ever exposed, a much longer exposure.
"""

from __future__ import annotations

from typing import Any, Optional

from web_crypto_checker.plugins import Detected, ServerView

ID = "CERT-EXCESSIVE-LIFETIME"
NAME = "Certificate valid for longer than 398 days"
SEVERITY = "low"
DESCRIPTION = "The certificate's validity window is longer than the CA/Browser Forum maximum."
REMEDIATION = "Reissue with a validity period of at most 398 days and automate renewal."
REFERENCES = ["CA/Browser Forum Baseline Requirements"]
KIND = "check"

_MAXIMUM_DAYS = 398


def check(server: ServerView) -> Optional[Any]:
    leaf = server.certificate()
    if leaf is None or leaf.not_before is None or leaf.not_after is None:
        return None
    days = (leaf.not_after - leaf.not_before) // 86400
    if days > _MAXIMUM_DAYS:
        return Detected(evidence=[f"valid for {days} days"])
    return None
