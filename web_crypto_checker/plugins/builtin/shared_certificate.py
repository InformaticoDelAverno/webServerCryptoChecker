"""The same certificate presented by more than one server in the scan.

A fleet check, and the reason that kind exists. Two servers sharing a
certificate is not a property of either one -- it is a property of the pair --
so no per-server check can find it, however thorough.

It is often deliberate: one certificate on a load-balanced fleet, or the same
service reachable at several addresses. It is worth surfacing anyway, because a
shared certificate means a shared *private key*: whoever extracts it from the
least important of those hosts can impersonate every one of them, and clients
cannot tell the difference.
"""

from typing import Any, Dict, List

from web_crypto_checker.models import Finding, Severity
from web_crypto_checker.plugins import ForTarget

ID = "shared-certificate"
NAME = "This certificate is shared with another scanned server"
KIND = "fleet"
SEVERITY = "info"
DESCRIPTION = (
    "The same certificate (same SHA-256 fingerprint) is presented by more than one server "
    "in this scan. It is often deliberate -- one certificate on a load-balanced fleet -- but "
    "it means the private key is shared: whoever extracts it from any one of those servers "
    "can impersonate all of them."
)
REMEDIATION = (
    "If the sharing is intentional (a load balancer, or one service at several addresses), "
    "nothing need change. If it is not, issue a separate certificate and key per server, so "
    "that compromising one does not compromise the rest."
)


def check(fleet: Any) -> Any:
    by_fingerprint: Dict[str, List[Any]] = {}
    for server in fleet.servers:
        leaf = server.view.leaf
        if leaf is None or not leaf.fingerprint_sha256:
            continue  # unreachable or no certificate: nothing to compare
        by_fingerprint.setdefault(leaf.fingerprint_sha256, []).append(server)

    found = []
    for fingerprint, sharing in by_fingerprint.items():
        names = sorted({server.target for server in sharing})
        if len(names) < 2:
            continue  # the same address scanned twice is not a shared certificate
        for server in sharing:
            peers = [name for name in names if name != server.target]
            found.append(
                ForTarget(
                    target=server.target,
                    finding=Finding(
                        id=ID,
                        severity=Severity.INFO,
                        title=NAME,
                        description=DESCRIPTION,
                        remediation=REMEDIATION,
                        items=[fingerprint, "also presented by: " + ", ".join(peers)],
                    ),
                )
            )
    return found
