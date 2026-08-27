"""Mutual TLS (client-certificate authentication) detection.

A server that authenticates its clients with certificates sends a
CertificateRequest during the handshake, which tells us it *requests* one. To learn
whether it *requires* one, we finish the handshake with an empty certificate and
watch: a server that enforces client auth refuses it (an alert), one that merely
requests it completes anyway.

Over TLS 1.3 both come from a single handshake. Over TLS 1.2 the CertificateRequest is
a cleartext message in the server's first flight, and completing that handshake with an
empty certificate reveals enforcement too -- so both are determined on either version.
"""

from __future__ import annotations

from typing import Optional

from ..models import MutualTls, Target
from ..tls.tls12 import probe_client_certificate as probe_client_certificate_tls12
from ..tls.tls13 import probe_client_certificate


def check_mtls(
    target: Target, address: str, timeout: float, supports_tls13: bool
) -> Optional[MutualTls]:
    """Whether ``target`` asks clients for a certificate (and enforces it), or None."""
    if target.scheme != "https":
        return None
    probe = probe_client_certificate if supports_tls13 else probe_client_certificate_tls12
    requested, required, error = probe(address, target.port, target.effective_sni, timeout)
    if error is not None:
        return MutualTls(error=error)
    return MutualTls(requested=requested, required=required)
