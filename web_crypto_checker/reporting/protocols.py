"""The application protocols an endpoint offers, named for the reports.

The console spells each out in full; the endpoint-oriented reports (HTML, the
inventory) want a short, shared list of what a server speaks beyond TLS/HTTP so a
reader sees its surface at a glance. Findings about those protocols travel through
the findings list separately.
"""

from __future__ import annotations

from typing import List

from ..models import TargetResult


def offered_protocols(result: TargetResult) -> List[str]:
    """The extra application protocols ``result`` was found to offer."""
    offered: List[str] = []
    if result.http3_reachable:
        offered.append("HTTP/3")
    if result.http2 is not None and result.http2.supported:
        offered.append("HTTP/2")
    if result.websocket is not None and result.websocket.supported:
        offered.append("WebSocket")
    if result.sse is not None and result.sse.supported:
        offered.append("SSE")
    if result.grpc is not None and result.grpc.supported:
        offered.append("gRPC")
    if result.mtls is not None and result.mtls.requested:
        offered.append("mTLS (required)" if result.mtls.required else "mTLS (requested)")
    return offered
