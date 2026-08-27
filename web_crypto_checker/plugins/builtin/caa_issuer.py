"""Whether the CA that issued the leaf appears to be one the CAA policy authorises.

The core scanner deliberately does NOT decide this: a CA's CAA identifier (e.g.
``letsencrypt.org``) and a certificate's issuer are linked only by each CA's own
declaration, with no algorithmic mapping, so any table is incomplete -- and an
incomplete table driving a *verdict* would be a misleading signal, which the tool
forbids. A plugin, though, cannot change the grade: it emits an *observation*. That
is what makes a conservative heuristic safe to ship here.

Conservative on purpose, to avoid a false accusation: it fires only when the leaf's
issuer is a **well-known** CA (matched by organisation name) whose known CAA
identifiers are **all absent** from the authorised set -- and even then not if the
CA's name appears inside an authorised identifier. An unknown issuer, or any doubt,
is left alone.
"""

from __future__ import annotations

from typing import Any, List, Optional, Tuple

from web_crypto_checker.plugins import Detected, ServerView

ID = "CAA-ISSUER-NOT-AUTHORISED"
NAME = "Certificate issuer may not be authorised by CAA"
SEVERITY = "low"
DESCRIPTION = (
    "The domain's CAA policy authorises specific CAs, but the certificate was issued by a "
    "well-known CA whose identifiers are not among them -- a possible stale policy or a "
    "mis-issuance. Heuristic (matched by issuer name), reported as an observation only."
)
REMEDIATION = (
    "Confirm the issuing CA is intended; if so, add its CAA identifier to the issue/issuewild "
    "records, otherwise investigate how the certificate was issued."
)
KIND = "check"

# Well-known CAs: organisation-name tokens that appear in an issuer DN, and the CAA
# identifier domains that authorise them (RFC 8659). Conservative and incomplete on
# purpose -- only high-confidence, widely-used CAs, so an unlisted issuer is never accused.
_KNOWN_CAS: List[Tuple[Tuple[str, ...], frozenset]] = [
    (("let's encrypt", "letsencrypt"), frozenset({"letsencrypt.org"})),
    (("digicert",), frozenset({"digicert.com"})),
    (("sectigo", "comodo"), frozenset({"sectigo.com", "comodoca.com"})),
    (("globalsign",), frozenset({"globalsign.com"})),
    (("google trust services", "google trust"), frozenset({"pki.goog"})),
    (("amazon",), frozenset({"amazon.com", "amazontrust.com", "awstrust.com"})),
    (("go daddy", "godaddy"), frozenset({"godaddy.com"})),
    (("entrust",), frozenset({"entrust.net"})),
    (("actalis",), frozenset({"actalis.it"})),
    (("buypass",), frozenset({"buypass.com", "buypass.no"})),
    (("certainly",), frozenset({"certainly.com"})),
    (("microsoft",), frozenset({"microsoft.com"})),
]


def _authorised_domains(server: ServerView) -> set:
    """The non-empty issuer domains a CAA issue/issuewild property names."""
    domains = set()
    for record in server.caa_records:
        if record.tag.lower() in ("issue", "issuewild"):
            domain = record.value.split(";", 1)[0].strip().lower()
            if domain:
                domains.add(domain)
    return domains


def check(server: ServerView) -> Optional[Any]:
    leaf = server.certificate()
    if leaf is None:
        return None
    authorised = _authorised_domains(server)
    if not authorised:
        return None  # no authorising CAA (absent, or forbid-all -- the core handles forbid)
    issuer = leaf.issuer.lower()
    for tokens, ca_domains in _KNOWN_CAS:
        if not any(token in issuer for token in tokens):
            continue  # not this CA
        if ca_domains & authorised:
            return None  # the issuing CA is explicitly authorised
        # Safety net: an authorised identifier that simply contains the CA's name counts too.
        if any(token in domain for domain in authorised for token in tokens):
            return None
        allowed = ", ".join(sorted(authorised))
        return Detected(evidence=[f"issuer {leaf.issuer}", f"CAA authorises: {allowed}"])
    return None  # an issuer the plugin does not know -- left alone, never accused
