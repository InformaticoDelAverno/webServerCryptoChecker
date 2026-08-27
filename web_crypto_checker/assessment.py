"""Turning what a server offers into a classification, a score and a grade.

The score is a weighted average of each algorithm class, taken at its *worst*
offered member, because that is what an attacker gets to negotiate. The grade is
that score as a letter -- except that a set of named conditions can cap it, so a
server offering something insecure, or presenting an expired or mismatched
certificate, cannot hide behind an otherwise good average. The verdict is
decided separately, from the worst category on offer, so the letter and the word
can never contradict each other.
"""

from __future__ import annotations

import time
from typing import Callable, List, Optional, Sequence, Tuple

from .application.http2 import http2_findings
from .application.sse import sse_findings
from .application.websocket import websocket_findings
from .http_layer import http_findings
from .i18n import DEFAULT_LANGUAGE, Translator
from .messages import MESSAGES
from .models import (
    CATEGORY_ORDER,
    AlgorithmAssessment,
    CaaInfo,
    CaaRecord,
    Category,
    CertificateChain,
    CertificateInfo,
    ClassAssessment,
    DaneInfo,
    Finding,
    HttpsRecord,
    ProtocolSupport,
    ScoreBreakdown,
    Severity,
    TargetResult,
    TlsCompressionStatus,
    TlsFeatures,
    TrustStatus,
    Verdict,
    class_label,
)
from .policy import Classification, Policy, worst_category
from .strength import compute_security_strength

_CATEGORY_SEVERITY = {Category.INSECURE: Severity.HIGH, Category.WEAK: Severity.MEDIUM}
#: EKU values that permit TLS server authentication (RFC 5280 4.2.1.12).
_SERVER_AUTH_EKUS = {"serverAuth", "anyExtendedKeyUsage"}
#: The CA/Browser Forum maximum TLS certificate validity since 2020-09-01; Safari and
#: Chrome reject a longer one (RFC-less policy, but hard-enforced by browsers).
_MAX_VALIDITY_DAYS = 398
_VERDICT_BY_CATEGORY = {
    Category.RECOMMENDED: Verdict.SECURE,
    Category.ACCEPTABLE: Verdict.ACCEPTABLE,
    Category.WEAK: Verdict.WEAK,
    Category.INSECURE: Verdict.INSECURE,
}
_REPORTABLE = (Category.INSECURE, Category.WEAK)


def assess(
    result: TargetResult,
    policy: Policy,
    now: Optional[float] = None,
    language: str = DEFAULT_LANGUAGE,
) -> None:
    """Populate a reachable result's assessments, findings, score and verdict.

    ``language`` selects the language of the finding prose (title/description/
    remediation) built here, so the result object carries translated text that
    every renderer emits. The default English keeps existing callers unchanged.
    """
    moment = now if now is not None else time.time()
    t = Translator(language, MESSAGES)

    negotiation: List[ClassAssessment] = []
    supported = [protocol for protocol in result.protocols if protocol.supported]
    if supported:
        negotiation.append(
            _assess_class(
                "protocol",
                [(protocol.id, protocol.name) for protocol in supported],
                policy.classify_protocol,
            )
        )
    if result.cipher_suites:
        negotiation.append(
            _assess_class(
                "cipher",
                [(suite.name, suite.name) for suite in result.cipher_suites],
                policy.classify_cipher,
            )
        )

    host = result.target.effective_sni or result.target.host
    certificate, certificate_findings, certificate_caps = _assess_certificate(
        result.certificate, host, moment, t
    )
    alternate_findings, alternate_caps = _alternate_certificate_findings(
        result.alternate_certificate, host, moment, t
    )
    certificate_caps = certificate_caps + alternate_caps

    assessments = list(negotiation)
    if certificate is not None:
        assessments.append(certificate)

    result.assessments = assessments
    result.findings = (
        _findings(negotiation, t)
        + certificate_findings
        + alternate_findings
        + http_findings(result.http, t)
        + websocket_findings(result.websocket, t)
        + sse_findings(result.sse, t)
        + http2_findings(result.http2, t)
        + _dane_findings(result.dane, t)
        + _caa_findings(result.caa, result.certificate, t)
        + _https_findings(result.https_record, t)
        + _feature_findings(result.features, t)
        + _compression_findings(result.compression, t)
        + _stapling_findings(result.certificate, result.features, t)
        + _sslv2_export_findings(result, t)
    )
    result.score, result.grade, result.verdict, result.score_breakdown = _score(
        assessments, supported, certificate_caps, policy
    )
    if "certificate_invalid" in alternate_caps:
        # The default certificate may be valid, but the server also serves an alternate one a
        # browser rejects; a client negotiating that key type gets an insecure connection, so
        # the verdict must say so (the grade is already capped by the folded cap above).
        result.verdict = Verdict.INSECURE
    if result.http is not None and result.http.cleartext:
        # Unencrypted transport is an unconditional failure, whatever else was measured.
        result.score, result.grade, result.verdict = 0, policy.grade_for(0), Verdict.INSECURE
    result.security_strength = compute_security_strength(result, policy.security_strength())


def _assess_class(
    key: str,
    items: Sequence[Tuple[str, str]],
    classify: Callable[[str], Classification],
) -> ClassAssessment:
    algorithms: List[AlgorithmAssessment] = []
    for identifier, display in items:
        classification = classify(identifier)
        algorithms.append(
            AlgorithmAssessment(
                name=display,
                category=classification.category,
                tags=classification.tags,
                notes=classification.note,
            )
        )
    worst = worst_category([algorithm.category for algorithm in algorithms])
    return ClassAssessment(
        key=key,
        label=class_label(key),
        algorithms=algorithms,
        worst_category=worst,
        preferred=items[0][1],
    )


# --------------------------------------------------------------------------- #
# Certificate
# --------------------------------------------------------------------------- #


def _key_category(certificate: CertificateInfo) -> Category:
    if certificate.key_type == "RSA":
        if certificate.key_bits is None:
            return Category.UNKNOWN
        if certificate.key_bits < 1024:
            return Category.INSECURE
        if certificate.key_bits < 2048:
            return Category.WEAK
        return Category.RECOMMENDED
    if certificate.key_type == "EC":
        if certificate.key_bits is not None and certificate.key_bits < 256:
            return Category.WEAK
        return Category.RECOMMENDED
    if certificate.key_type == "Ed25519":
        return Category.RECOMMENDED
    return Category.UNKNOWN


def _signature_category(signature_algorithm: str) -> Category:
    lower = signature_algorithm.lower()
    if "md5" in lower or "sha1" in lower:
        return Category.INSECURE
    if not signature_algorithm:
        return Category.UNKNOWN
    return Category.RECOMMENDED


def _certificate_finding(
    identifier: str, severity: Severity, title: str, description: str, items: List[str]
) -> Finding:
    return Finding(
        id=identifier, severity=severity, title=title, description=description, items=items
    )


def _assess_certificate(
    chain: Optional[CertificateChain], host: str, now: float, t: Translator
) -> Tuple[Optional[ClassAssessment], List[Finding], List[str]]:
    if chain is None or chain.leaf is None:
        return None, [], []

    leaf = chain.leaf
    key_category = _key_category(leaf)
    signature_category = _signature_category(leaf.signature_algorithm)
    category = worst_category([key_category, signature_category]) or Category.UNKNOWN

    label = leaf.key_type or "unknown key"
    if leaf.key_bits:
        label += f" {leaf.key_bits}-bit"
    label += f", {leaf.signature_algorithm or 'unknown signature'}"
    assessment = ClassAssessment(
        key="certificate",
        label=class_label("certificate"),
        algorithms=[AlgorithmAssessment(label, category)],
        worst_category=category if category in CATEGORY_ORDER else None,
        preferred=leaf.subject,
    )

    findings: List[Finding] = []
    caps: List[str] = []
    if leaf.is_expired(now):
        findings.append(
            _certificate_finding(
                "CERT-EXPIRED",
                Severity.HIGH,
                t("find.cert_expired.title"),
                t("find.cert_expired.desc"),
                [leaf.subject],
            )
        )
        caps.append("certificate_invalid")
    if leaf.is_not_yet_valid(now):
        findings.append(
            _certificate_finding(
                "CERT-NOT-YET-VALID",
                Severity.HIGH,
                t("find.cert_not_yet_valid.title"),
                t("find.cert_not_yet_valid.desc"),
                [leaf.subject],
            )
        )
        caps.append("certificate_invalid")
    if chain.hostname_matches is False:
        findings.append(
            _certificate_finding(
                "CERT-HOSTNAME-MISMATCH",
                Severity.HIGH,
                t("find.cert_hostname_mismatch.title"),
                t("find.cert_hostname_mismatch.desc", host=host),
                sorted(leaf.sans) or [leaf.subject],
            )
        )
        caps.append("certificate_invalid")
    if chain.trust in (TrustStatus.EXPIRED, TrustStatus.NOT_YET_VALID) and not (
        leaf.is_expired(now) or leaf.is_not_yet_valid(now)
    ):
        # The leaf's own dates are fine, so the invalid certificate is upstream: an
        # intermediate outside its validity period breaks the path all the same.
        stale = [
            certificate.subject
            for certificate in chain.certificates[1:]
            if certificate.is_expired(now) or certificate.is_not_yet_valid(now)
        ]
        findings.append(
            _certificate_finding(
                "CERT-CHAIN-EXPIRED",
                Severity.HIGH,
                t("find.cert_chain_expired.title"),
                t("find.cert_chain_expired.desc"),
                stale or [chain.trust.value],
            )
        )
        caps.append("certificate_invalid")
    if leaf.extended_key_usages and not _SERVER_AUTH_EKUS.intersection(leaf.extended_key_usages):
        findings.append(
            _certificate_finding(
                "CERT-EKU-NO-SERVER-AUTH",
                Severity.HIGH,
                t("find.cert_eku_no_server_auth.title"),
                t("find.cert_eku_no_server_auth.desc"),
                leaf.extended_key_usages,
            )
        )
        caps.append("certificate_invalid")
    if not leaf.sans:
        findings.append(
            _certificate_finding(
                "CERT-NO-SAN",
                Severity.MEDIUM,
                t("find.cert_no_san.title"),
                t("find.cert_no_san.desc"),
                [leaf.subject],
            )
        )
    if leaf.not_before is not None and leaf.not_after is not None:
        validity_days = (leaf.not_after - leaf.not_before) // 86400
        if validity_days > _MAX_VALIDITY_DAYS:
            findings.append(
                _certificate_finding(
                    "CERT-VALIDITY-TOO-LONG",
                    Severity.MEDIUM,
                    t("find.cert_validity_too_long.title"),
                    t(
                        "find.cert_validity_too_long.desc",
                        days=validity_days,
                        max_days=_MAX_VALIDITY_DAYS,
                    ),
                    [leaf.subject],
                )
            )
    if chain.trust is TrustStatus.UNTRUSTED:
        findings.append(
            _certificate_finding(
                "CERT-UNTRUSTED",
                Severity.HIGH,
                t("find.cert_untrusted.title"),
                t("find.cert_untrusted.desc"),
                [leaf.subject],
            )
        )
        caps.append("certificate_invalid")
    revocation = chain.revocation
    revoked = chain.stapled_ocsp == "revoked" or (
        revocation is not None and "revoked" in (revocation.ocsp, revocation.crl)
    )
    if revoked:
        findings.append(
            _certificate_finding(
                "CERT-REVOKED",
                Severity.HIGH,
                t("find.cert_revoked.title"),
                t("find.cert_revoked.desc"),
                [leaf.subject],
            )
        )
        caps.append("certificate_invalid")
    if chain.stapled_ocsp == "invalid":
        findings.append(
            _certificate_finding(
                "OCSP-STAPLE-INVALID",
                Severity.MEDIUM,
                t("find.ocsp_staple_invalid.title"),
                t("find.ocsp_staple_invalid.desc"),
                [leaf.subject],
            )
        )
    if chain.aia_completed:
        findings.append(
            _certificate_finding(
                "CERT-CHAIN-INCOMPLETE",
                Severity.LOW,
                t("find.cert_chain_incomplete.title"),
                t("find.cert_chain_incomplete.desc"),
                [leaf.subject],
            )
        )
    anchors = [cert.subject for cert in chain.certificates[1:] if cert.is_self_signed]
    if anchors:
        findings.append(
            _certificate_finding(
                "CERT-CHAIN-CONTAINS-ANCHOR",
                Severity.LOW,
                t("find.cert_chain_contains_anchor.title"),
                t("find.cert_chain_contains_anchor.desc"),
                anchors,
            )
        )
    if leaf.is_self_signed:
        findings.append(
            _certificate_finding(
                "CERT-SELF-SIGNED",
                Severity.MEDIUM,
                t("find.cert_self_signed.title"),
                t("find.cert_self_signed.desc"),
                [leaf.subject],
            )
        )
        caps.append("self_signed")
    if chain.signatures_valid is False:
        findings.append(
            _certificate_finding(
                "CERT-BAD-SIGNATURE",
                Severity.HIGH,
                t("find.cert_bad_signature.title"),
                t("find.cert_bad_signature.desc"),
                [chain.signature_note],
            )
        )
        caps.append("certificate_invalid")
    if leaf.roca_vulnerable:
        findings.append(
            _certificate_finding(
                "CERT-ROCA",
                Severity.HIGH,
                t("find.cert_roca.title"),
                t("find.cert_roca.desc"),
                [leaf.subject],
            )
        )
        caps.append("certificate_invalid")
    if key_category in _REPORTABLE:
        findings.append(
            _certificate_finding(
                "CERT-WEAK-KEY",
                Severity.HIGH,
                t("find.cert_weak_key.title"),
                t("find.cert_weak_key.desc", key_type=leaf.key_type),
                [label],
            )
        )
    if signature_category is Category.INSECURE:
        findings.append(
            _certificate_finding(
                "CERT-WEAK-SIGNATURE",
                Severity.HIGH,
                t("find.cert_weak_signature.title"),
                t("find.cert_weak_signature.desc", algorithm=leaf.signature_algorithm),
                [leaf.signature_algorithm],
            )
        )
    weak_intermediates = [
        certificate.subject
        for certificate in chain.certificates[1:]
        if not certificate.is_self_signed
        and _signature_category(certificate.signature_algorithm) is Category.INSECURE
    ]
    if weak_intermediates:
        findings.append(
            _certificate_finding(
                "CERT-CHAIN-WEAK-SIGNATURE",
                Severity.HIGH,
                t("find.cert_chain_weak_signature.title"),
                t("find.cert_chain_weak_signature.desc"),
                weak_intermediates,
            )
        )
    if leaf.is_ca:
        findings.append(
            _certificate_finding(
                "CERT-LEAF-IS-CA",
                Severity.MEDIUM,
                t("find.cert_leaf_is_ca.title"),
                t("find.cert_leaf_is_ca.desc"),
                [leaf.subject],
            )
        )
    if "certificate_invalid" in caps:
        # Expired/not-yet-valid, wrong host, an unverifiable chain, or a non-serverAuth
        # purpose all make a browser reject the certificate: the verdict must be insecure
        # regardless of how strong the key and signature algorithm are.
        assessment.worst_category = Category.INSECURE
    return assessment, findings, caps


# --------------------------------------------------------------------------- #
# Findings and scoring
# --------------------------------------------------------------------------- #


def _findings(assessments: Sequence[ClassAssessment], t: Translator) -> List[Finding]:
    findings: List[Finding] = []
    for assessment in assessments:
        for category in _REPORTABLE:
            names = sorted(item.name for item in assessment.by_category(category))
            if names:
                base = f"find.class.{assessment.key}.{category.value}"
                findings.append(
                    Finding(
                        id=f"{assessment.key}-{category.value}".upper(),
                        severity=_CATEGORY_SEVERITY[category],
                        title=t(f"{base}.title"),
                        description=t(f"{base}.desc", n=len(names)),
                        items=names,
                    )
                )
    return findings


def _dane_findings(dane: Optional[DaneInfo], t: Translator) -> List[Finding]:
    if dane is None or not dane.records:
        return []
    if dane.dnssec_validated is False:
        # A pin that DNSSEC does not authenticate is spoofable, so a DANE client ignores it
        # and a "mismatch" against it is not enforceable: report the missing authentication.
        return [
            Finding(
                id="DANE-NOT-DNSSEC",
                severity=Severity.MEDIUM,
                title=t("find.dane_not_dnssec.title"),
                description=t("find.dane_not_dnssec.desc"),
                remediation=t("find.dane_not_dnssec.rem"),
            )
        ]
    if dane.matches is False:
        return [
            Finding(
                id="DANE-MISMATCH",
                severity=Severity.HIGH,
                title=t("find.dane_mismatch.title"),
                description=t("find.dane_mismatch.desc"),
                remediation=t("find.dane_mismatch.rem"),
            )
        ]
    return []


def _caa_forbids(records: List[CaaRecord], tag: str) -> bool:
    """Whether a CAA property forbids issuance outright: at least one record of ``tag`` and
    every one names an empty issuer. An empty ``issue``/``issuewild`` value authorises no CA
    at all (RFC 8659 4.2), so a certificate that exists anyway was issued against the policy.
    The issuer domain is the text before any ``;`` parameters."""
    relevant = [record for record in records if record.tag.lower() == tag]
    return bool(relevant) and all(not record.value.split(";", 1)[0].strip() for record in relevant)


def _caa_findings(
    caa: Optional[CaaInfo], chain: Optional[CertificateChain], t: Translator
) -> List[Finding]:
    # A CAA policy the tool could not authenticate to the root is spoofable toward a CA at
    # issuance time; only report the gap for a policy that actually exists (dnssec_validated
    # is set to False only when records were seen but their chain did not validate).
    if caa is None or not caa.records:
        return []
    if caa.dnssec_validated is False:
        return [
            Finding(
                id="CAA-NOT-DNSSEC",
                severity=Severity.LOW,
                title=t("find.caa_not_dnssec.title"),
                description=t("find.caa_not_dnssec.desc"),
                remediation=t("find.caa_not_dnssec.rem"),
            )
        ]
    # The policy is DNSSEC-authentic. A CAA that forbids issuance of the certificate actually
    # being served is an unambiguous anomaly -- possible mis-issuance, or a policy tightened
    # after the certificate was issued so it cannot be renewed. This needs no CA-identity
    # table (see _caa_forbids), so it is reported without the false positives that matching a
    # certificate's issuer against a CAA identifier would incur.
    leaf = chain.certificates[0] if chain and chain.certificates else None
    if caa.dnssec_validated is not True or leaf is None:
        return []
    if any(name.startswith("*.") for name in leaf.sans):
        has_issuewild = any(record.tag.lower() == "issuewild" for record in caa.records)
        # Wildcards are governed by issuewild when present, otherwise by issue (RFC 8659 4.3).
        forbidden = _caa_forbids(caa.records, "issuewild") or (
            not has_issuewild and _caa_forbids(caa.records, "issue")
        )
        if forbidden:
            return [
                Finding(
                    id="CAA-FORBIDS-WILDCARD",
                    severity=Severity.HIGH,
                    title=t("find.caa_forbids_wildcard.title"),
                    description=t("find.caa_forbids_wildcard.desc"),
                    remediation=t("find.caa_forbids_wildcard.rem"),
                )
            ]
    elif _caa_forbids(caa.records, "issue"):
        return [
            Finding(
                id="CAA-FORBIDS-ISSUANCE",
                severity=Severity.HIGH,
                title=t("find.caa_forbids_issuance.title"),
                description=t("find.caa_forbids_issuance.desc"),
                remediation=t("find.caa_forbids_issuance.rem"),
            )
        ]
    return []


def _https_findings(record: Optional[HttpsRecord], t: Translator) -> List[Finding]:
    # ECH's SNI privacy rests on the client trusting the published config; an unsigned HTTPS
    # record can be stripped on-path, forcing the SNI back into cleartext.
    if record is None or not record.ech or record.dnssec_validated is not False:
        return []
    return [
        Finding(
            id="HTTPS-ECH-NOT-DNSSEC",
            severity=Severity.LOW,
            title=t("find.https_ech_not_dnssec.title"),
            description=t("find.https_ech_not_dnssec.desc"),
            remediation=t("find.https_ech_not_dnssec.rem"),
        )
    ]


def _alternate_certificate_findings(
    alternate: Optional[CertificateChain],
    host: str,
    moment: float,
    t: Translator,
) -> Tuple[List[Finding], List[str]]:
    """Assess a second (alternate key type) certificate the server serves. Reuses the leaf
    assessment, then summarises its problems as one finding so a weak or invalid alternate is
    not hidden behind a valid default. Returns (findings, caps to fold into the grade)."""
    if alternate is None or alternate.leaf is None:
        return [], []
    _assessment, findings, caps = _assess_certificate(alternate, host, moment, t)
    if not findings:
        return [], []  # a clean second certificate is fine
    reasons = [finding.title for finding in findings]
    if "certificate_invalid" in caps:
        return [
            _certificate_finding(
                "CERT-ALTERNATE-INVALID",
                Severity.HIGH,
                t("find.cert_alternate_invalid.title"),
                t(
                    "find.cert_alternate_invalid.desc",
                    key_type=alternate.leaf.key_type,
                    reasons="; ".join(reasons),
                ),
                reasons,
            )
        ], ["certificate_invalid"]
    return [
        _certificate_finding(
            "CERT-ALTERNATE-WEAK",
            Severity.MEDIUM,
            t("find.cert_alternate_weak.title"),
            t(
                "find.cert_alternate_weak.desc",
                key_type=alternate.leaf.key_type,
                reasons="; ".join(reasons),
            ),
            reasons,
        )
    ], []


def _feature_findings(features: Optional[TlsFeatures], t: Translator) -> List[Finding]:
    if features is None:
        return []
    findings: List[Finding] = []
    if features.secure_renegotiation is False:
        findings.append(
            Finding(
                id="TLS-INSECURE-RENEGOTIATION",
                severity=Severity.MEDIUM,
                title=t("find.tls_insecure_renegotiation.title"),
                description=t("find.tls_insecure_renegotiation.desc"),
                remediation=t("find.tls_insecure_renegotiation.rem"),
            )
        )
    if features.extended_master_secret is False:
        findings.append(
            Finding(
                id="TLS-NO-EXTENDED-MASTER-SECRET",
                severity=Severity.LOW,
                title=t("find.tls_no_extended_master_secret.title"),
                description=t("find.tls_no_extended_master_secret.desc"),
                remediation=t("find.tls_no_extended_master_secret.rem"),
            )
        )
    if features.encrypt_then_mac is False:
        findings.append(
            Finding(
                id="TLS-NO-ENCRYPT-THEN-MAC",
                severity=Severity.LOW,
                title=t("find.tls_no_encrypt_then_mac.title"),
                description=t("find.tls_no_encrypt_then_mac.desc"),
                remediation=t("find.tls_no_encrypt_then_mac.rem"),
            )
        )
    if features.fallback_scsv is False:
        findings.append(
            Finding(
                id="TLS-NO-FALLBACK-SCSV",
                severity=Severity.LOW,
                title=t("find.tls_no_fallback_scsv.title"),
                description=t("find.tls_no_fallback_scsv.desc"),
                remediation=t("find.tls_no_fallback_scsv.rem"),
            )
        )
    if features.downgrade_sentinel is False:
        findings.append(
            Finding(
                id="TLS-NO-DOWNGRADE-SENTINEL",
                severity=Severity.LOW,
                title=t("find.tls_no_downgrade_sentinel.title"),
                description=t("find.tls_no_downgrade_sentinel.desc"),
                remediation=t("find.tls_no_downgrade_sentinel.rem"),
            )
        )
    if features.enforces_cipher_preference is False:
        findings.append(
            Finding(
                id="TLS-NO-CIPHER-PREFERENCE",
                severity=Severity.LOW,
                title=t("find.tls_no_cipher_preference.title"),
                description=t("find.tls_no_cipher_preference.desc"),
                remediation=t("find.tls_no_cipher_preference.rem"),
            )
        )
    if features.grease_tolerant is False:
        findings.append(
            Finding(
                id="TLS-GREASE-INTOLERANT",
                severity=Severity.LOW,
                title=t("find.tls_grease_intolerant.title"),
                description=t("find.tls_grease_intolerant.desc"),
                remediation=t("find.tls_grease_intolerant.rem"),
            )
        )
    if features.dh_prime_bits is not None and features.dh_prime_bits < 2048:
        findings.append(
            Finding(
                id="TLS-WEAK-DH-PARAMS",
                severity=Severity.HIGH if features.dh_prime_bits < 1024 else Severity.MEDIUM,
                title=t("find.tls_weak_dh_params.title"),
                description=t("find.tls_weak_dh_params.desc", bits=features.dh_prime_bits),
                remediation=t("find.tls_weak_dh_params.rem"),
            )
        )
    if features.early_data:
        findings.append(
            Finding(
                id="TLS-0RTT-ENABLED",
                severity=Severity.LOW,
                title=t("find.tls_0rtt_enabled.title"),
                description=t("find.tls_0rtt_enabled.desc"),
                remediation=t("find.tls_0rtt_enabled.rem"),
            )
        )
    return findings


def _sslv2_export_findings(result: TargetResult, t: Translator) -> List[Finding]:
    """An SSL 2.0 server offering export ciphers makes DROWN practical, not just possible."""
    if not result.sslv2_export_ciphers:
        return []
    return [
        Finding(
            id="SSLV2-EXPORT-CIPHERS",
            severity=Severity.HIGH,
            title=t("find.sslv2_export_ciphers.title"),
            description=t("find.sslv2_export_ciphers.desc"),
            remediation=t("find.sslv2_export_ciphers.rem"),
        )
    ]


def _stapling_findings(
    certificate: Optional[CertificateChain], features: Optional[TlsFeatures], t: Translator
) -> List[Finding]:
    leaf = certificate.leaf if certificate is not None else None
    stapled = features.ocsp_stapling if features is not None else None
    if leaf is not None and leaf.ocsp_must_staple and stapled is False:
        return [
            Finding(
                id="OCSP-MUST-STAPLE-VIOLATED",
                severity=Severity.HIGH,
                title=t("find.ocsp_must_staple_violated.title"),
                description=t("find.ocsp_must_staple_violated.desc"),
                remediation=t("find.ocsp_must_staple_violated.rem"),
            )
        ]
    return []


def _compression_findings(compression: TlsCompressionStatus, t: Translator) -> List[Finding]:
    if compression is TlsCompressionStatus.ENABLED:
        return [
            Finding(
                id="TLS-COMPRESSION",
                severity=Severity.HIGH,
                title=t("find.tls_compression.title"),
                description=t("find.tls_compression.desc"),
                remediation=t("find.tls_compression.rem"),
            )
        ]
    return []


def _score(
    assessments: Sequence[ClassAssessment],
    supported: Sequence[ProtocolSupport],
    certificate_caps: List[str],
    policy: Policy,
) -> Tuple[Optional[int], Optional[str], Verdict, Optional[ScoreBreakdown]]:
    class_scores = {}
    weights = {}
    for assessment in assessments:
        if assessment.worst_category is None:
            continue
        score = policy.category_score(assessment.worst_category)
        if score is None:
            continue
        assessment.score = score
        class_scores[assessment.key] = score
        weights[assessment.key] = policy.class_weight(assessment.key)

    total_weight = sum(weights.values())
    if total_weight == 0:
        return None, None, Verdict.UNKNOWN, None

    base = round(sum(class_scores[key] * weights[key] for key in weights) / total_weight)

    overall_worst = worst_category(
        [a.worst_category for a in assessments if a.worst_category is not None]
    )
    verdict = _VERDICT_BY_CATEGORY.get(overall_worst or Category.UNKNOWN, Verdict.UNKNOWN)

    grade, applied = _apply_caps(
        policy.grade_for(base), assessments, supported, certificate_caps, policy
    )

    breakdown = ScoreBreakdown(
        class_scores=dict(class_scores),
        class_weights=weights,
        total_weight=total_weight,
        base_score=base,
        applied_caps=applied,
        final_score=base,
    )
    return base, grade, verdict, breakdown


def _apply_caps(
    grade: str,
    assessments: Sequence[ClassAssessment],
    supported: Sequence[ProtocolSupport],
    certificate_caps: List[str],
    policy: Policy,
) -> Tuple[str, List[str]]:
    supported_ids = {protocol.id for protocol in supported}
    caps = policy.grade_caps()
    has_insecure = any(a.worst_category is Category.INSECURE for a in assessments)
    active_names = [
        name
        for active, name in [
            (has_insecure, "any_insecure_offered"),
            ("ssl2" in supported_ids, "sslv2_supported"),
            ("ssl3" in supported_ids, "sslv3_supported"),
            (not {"tls1_2", "tls1_3"} & supported_ids, "no_tls12_or_higher"),
            (bool({"tls1_0", "tls1_1"} & supported_ids), "weak_protocol_supported"),
        ]
        if active
    ]
    active_names.extend(certificate_caps)

    applied: List[str] = []
    for name in active_names:
        cap = caps.get(name)
        if cap is not None and name not in applied:
            applied.append(name)
            grade = policy.worse_grade(grade, cap)
    return grade, applied
