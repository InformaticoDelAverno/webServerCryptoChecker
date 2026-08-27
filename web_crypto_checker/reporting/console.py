"""The default human-readable report: one block per endpoint."""

from __future__ import annotations

from typing import Dict, List, Optional

from ..i18n import Translator
from ..models import (
    CertificateInfo,
    QuicTransportParameters,
    RevocationStatus,
    ScanReport,
    TlsCompressionStatus,
)
from .labels import (
    category_label,
    compliance_label,
    post_quantum_label,
    severity_label,
    trust_label,
    verdict_label,
)

#: Value -> message key maps. A dict lookup (not a branch) keeps the renderer at
#: 100% coverage without a test for every possible value: the literal is one
#: covered statement, and only the values a sample exercises are ever indexed.
_SIGNATURE_KEYS: Dict[Optional[bool], str] = {
    True: "rep.con.sig_verified",
    False: "rep.con.sig_invalid",
    None: "rep.con.sig_unchecked",
}
_RENEGOTIATION_KEYS: Dict[bool, str] = {True: "rep.con.yes", False: "rep.con.no_reneg"}
_EMS_KEYS: Dict[bool, str] = {True: "rep.con.yes", False: "rep.con.no_ems"}
_SCSV_KEYS: Dict[bool, str] = {True: "rep.con.yes", False: "rep.con.no_scsv"}
_RESUMPTION_KEYS: Dict[Optional[bool], str] = {
    True: "rep.con.yes",
    False: "rep.con.no",
    None: "rep.con.unknown",
}
_STAPLING_KEYS: Dict[bool, str] = {True: "rep.con.yes", False: "rep.con.no"}
_HTTP3_REACHABLE_KEYS: Dict[bool, str] = {
    True: "rep.con.http3_reachable",
    False: "rep.con.http3_not_reachable",
}
_DANE_KEYS: Dict[Optional[bool], str] = {
    True: "rep.con.dane_matches",
    False: "rep.con.dane_mismatch",
    None: "rep.con.dane_not_validated",
}
_DNSSEC_KEYS: Dict[Optional[bool], str] = {
    True: "rep.con.dnssec_yes",
    False: "rep.con.dnssec_no",
    None: "rep.con.dnssec_unchecked",
}
_COMPRESSION_KEYS: Dict[TlsCompressionStatus, str] = {
    TlsCompressionStatus.DISABLED: "rep.con.compression_disabled",
    TlsCompressionStatus.ENABLED: "rep.con.compression_enabled",
}


def _revocation_line(revocation: RevocationStatus, t: Translator) -> str:
    """A compact line of what the OCSP and CRL checks found."""
    parts = [
        f"OCSP {revocation.ocsp}" if revocation.ocsp else "",
        f"CRL {revocation.crl}" if revocation.crl else "",
    ]
    return ", ".join(part for part in parts if part) or revocation.error or t("rep.con.no_answer")


def _quic_parameters(parameters: QuicTransportParameters, t: Translator) -> str:
    """A compact line of the notable QUIC transport parameters a server advertises."""
    parts: List[str] = []
    if parameters.max_idle_timeout is not None:
        parts.append(t("rep.con.quic_idle", ms=parameters.max_idle_timeout))
    if parameters.max_streams_bidi is not None:
        parts.append(t("rep.con.quic_bidi", n=parameters.max_streams_bidi))
    if parameters.active_connection_id_limit is not None:
        parts.append(t("rep.con.quic_cid", n=parameters.active_connection_id_limit))
    if parameters.disable_active_migration:
        parts.append(t("rep.con.quic_migration_disabled"))
    return ", ".join(parts) if parts else t("rep.con.none_advertised")


_QUIC_VERSION_NAMES: Dict[int, str] = {0x00000001: "v1", 0x6B3343CF: "v2"}


def _name_quic_versions(versions: List[int], t: Translator) -> str:
    """Name the QUIC versions a server offers, skipping the reserved GREASE values
    (RFC 9000 15) a server echoes for anti-ossification."""
    named = [
        _QUIC_VERSION_NAMES.get(version, f"0x{version:08x}")
        for version in versions
        if version & 0x0F0F0F0F != 0x0A0A0A0A
    ]
    return ", ".join(named) if named else t("rep.con.none_recognised")


def _revocation_summary(leaf: CertificateInfo, t: Translator) -> str:
    """A compact line of the revocation and transparency a certificate advertises."""
    parts = []
    if leaf.sct_count:
        verified = t("rep.con.ct_verified", n=leaf.verified_scts) if leaf.verified_scts else ""
        parts.append(t("rep.con.ct", n=leaf.sct_count, verified=verified))
    if leaf.ocsp_url:
        parts.append("OCSP")
    if leaf.crl_urls:
        parts.append("CRL")
    if leaf.ocsp_must_staple:
        parts.append("must-staple")
    return ", ".join(parts) if parts else t("rep.con.none_advertised")


def _key_description(leaf: CertificateInfo, t: Translator) -> str:
    """``RSA 2048-bit`` (or ``Ed25519`` when the key carries no bit length)."""
    if leaf.key_bits:
        return t("rep.con.key_bits", type=leaf.key_type, bits=leaf.key_bits)
    return leaf.key_type


def render(report: ScanReport, t: Translator) -> str:
    lines = [
        t(
            "rep.con.header",
            tool=report.tool,
            version=report.version,
            total=report.summary.total,
            reachable=report.summary.succeeded,
        )
    ]
    for result in report.results:
        lines.append("")
        address = f"  [{result.ip}]" if result.ip and result.ip != result.target.host else ""
        lines.append(f"{result.target.display_name}{address}")
        if not result.ok:
            lines.append(t("rep.con.error", error=result.error))
            continue
        lines.append(
            f"  {t('rep.field.grade')}: {result.grade or t('rep.con.na')}"
            f"    {t('rep.field.verdict')}: {verdict_label(t, result.verdict)}"
        )
        strength = result.security_strength
        if strength is not None and strength.effective_bits is not None:
            lines.append(
                t(
                    "rep.con.security_strength",
                    bits=strength.effective_bits,
                    label=strength.level_label,
                    limiting=", ".join(strength.limiting),
                )
            )
        supported = [protocol.name for protocol in result.protocols if protocol.supported]
        versions = ", ".join(supported) if supported else t("rep.con.none")
        lines.append(t("rep.con.tls_versions", versions=versions))
        cipher = result.assessment("cipher")
        if cipher is not None:
            lines.append(t("rep.con.cipher_suites", n=len(cipher.algorithms)))
            for algorithm in cipher.algorithms:
                lines.append(f"    [{category_label(t, algorithm.category)}] {algorithm.name}")
        if result.groups:
            names = ", ".join(group.name for group in result.groups)
            lines.append(t("rep.con.key_exchange_groups", names=names))
            lines.append(
                t("rep.con.post_quantum", status=post_quantum_label(t, result.post_quantum))
            )
        if result.signature_algorithms:
            lines.append(
                t("rep.con.signature_schemes", schemes=", ".join(result.signature_algorithms))
            )
        features = result.features
        if features is not None and features.secure_renegotiation is not None:
            word = t(_RENEGOTIATION_KEYS[features.secure_renegotiation])
            lines.append(t("rep.con.secure_renegotiation", value=word))
        if features is not None and features.extended_master_secret is not None:
            word = t(_EMS_KEYS[features.extended_master_secret])
            lines.append(t("rep.con.extended_master_secret", value=word))
        if features is not None and features.fallback_scsv is not None:
            word = t(_SCSV_KEYS[features.fallback_scsv])
            lines.append(t("rep.con.downgrade_protection", value=word))
        if features is not None and features.session_resumption_id is not None:
            lines.append(
                t(
                    "rep.con.session_resumption",
                    id=t(_RESUMPTION_KEYS[features.session_resumption_id]),
                    ticket=t(_RESUMPTION_KEYS[features.session_resumption_ticket]),
                )
            )
        if features is not None and features.ocsp_stapling is not None:
            word = t(_STAPLING_KEYS[features.ocsp_stapling])
            lines.append(t("rep.con.ocsp_stapling", value=word))
        if features is not None and features.early_data is not None:
            value = t("rep.con.yes") if features.early_data else t("rep.con.no")
            lines.append(t("rep.con.early_data", value=value))
        if result.compression is not TlsCompressionStatus.UNKNOWN:
            lines.append(
                t("rep.con.compression", value=t(_COMPRESSION_KEYS[result.compression]))
            )
        certificate = result.certificate
        if certificate is not None:
            leaf = certificate.leaf
            if leaf is not None:
                lines.append(t("rep.con.certificate", subject=leaf.subject))
                lines.append(
                    t(
                        "rep.con.cert_detail",
                        keydesc=_key_description(leaf, t),
                        sig=leaf.signature_algorithm,
                        trust=trust_label(t, certificate.trust),
                        hostname=certificate.hostname_matches,
                        signatures=t(_SIGNATURE_KEYS[certificate.signatures_valid]),
                    )
                )
                lines.append(
                    t("rep.con.revocation_summary", detail=_revocation_summary(leaf, t))
                )
                revocation = certificate.revocation
                if revocation is not None and revocation.checked:
                    lines.append(
                        t("rep.con.revocation", detail=_revocation_line(revocation, t))
                    )
            else:
                lines.append(t("rep.con.certificate_not_retrieved", error=certificate.error))
        alternate = result.alternate_certificate
        if alternate is not None and alternate.leaf is not None:
            lines.append(
                t(
                    "rep.con.alternate_certificate",
                    keydesc=_key_description(alternate.leaf, t),
                    sig=alternate.leaf.signature_algorithm,
                    trust=trust_label(t, alternate.trust),
                )
            )
        caa = result.caa
        if caa is not None and caa.error is None:
            if caa.records:
                issuers = ", ".join(f"{record.tag} {record.value}" for record in caa.records)
                lines.append(t("rep.con.caa", issuers=issuers))
            else:
                lines.append(t("rep.con.caa_none"))
        dane = result.dane
        if dane is not None and dane.error is None and dane.records:
            lines.append(
                t(
                    "rep.con.dane",
                    n=len(dane.records),
                    match=t(_DANE_KEYS[dane.matches]),
                    dnssec=t(_DNSSEC_KEYS[dane.dnssec_validated]),
                )
            )
        elif dane is not None and dane.error is None and dane.dnssec_validated:
            lines.append(t("rep.con.dane_absent"))
        https_record = result.https_record
        if https_record is not None:
            parts = []
            if https_record.alpn:
                parts.append(t("rep.con.https_rr_alpn", names=",".join(https_record.alpn)))
            if https_record.ech:
                parts.append(t("rep.con.https_rr_ech"))
            if https_record.port:
                parts.append(t("rep.con.https_rr_port", port=https_record.port))
            detail = ", ".join(parts) or t("rep.con.https_rr_published")
            lines.append(t("rep.con.https_rr", detail=detail))
        http = result.http
        if http is not None and http.cleartext:
            server = http.server or t("rep.con.server_hidden")
            lines.append(
                t("rep.con.http_cleartext", status=http.status_code, server=server)
            )
        elif http is not None and http.reached:
            hsts = http.hsts if http.hsts is not None else t("rep.con.hsts_absent")
            http3 = t("rep.con.http3_advertised") if http.http3_advertised else ""
            line = t(
                "rep.con.http",
                status=http.status_code,
                hsts=hsts,
                server=http.server or t("rep.con.server_hidden"),
                http3=http3,
            )
            mixed = http.mixed_content
            if mixed is not None and mixed.any():
                line += t(
                    "rep.con.mixed_content", active=len(mixed.active), passive=len(mixed.passive)
                )
            lines.append(line)
        elif http is not None:
            lines.append(t("rep.con.http_not_measured", error=http.error))
        if result.http3_reachable is not None:
            line = t("rep.con.http3_label", value=t(_HTTP3_REACHABLE_KEYS[result.http3_reachable]))
            negotiation = result.http3_negotiation
            if negotiation is not None:
                detail = negotiation.cipher_suite
                if negotiation.group is not None:
                    detail += f", {negotiation.group}"
                line += f" ({detail})"
            lines.append(line)
            if negotiation is not None and negotiation.transport_parameters is not None:
                summary = _quic_parameters(negotiation.transport_parameters, t)
                lines.append(t("rep.con.quic_parameters", detail=summary))
            if result.quic_versions:
                lines.append(
                    t("rep.con.quic_versions", detail=_name_quic_versions(result.quic_versions, t))
                )
        websocket = result.websocket
        if websocket is not None and websocket.supported:
            detail = t("rep.con.supported")
            if websocket.subprotocol:
                detail += t("rep.con.ws_subprotocol", name=websocket.subprotocol)
            if websocket.origin_checked:
                detail += (
                    t("rep.con.ws_origin_enforced")
                    if websocket.origin_enforced
                    else t("rep.con.ws_origin_not_enforced")
                )
            lines.append(t("rep.con.websocket", detail=detail))
        sse = result.sse
        if sse is not None and sse.supported:
            detail = t("rep.con.supported")
            if sse.origin_checked:
                detail += (
                    t("rep.con.sse_cross_origin")
                    if sse.cross_origin_open
                    else t("rep.con.sse_same_origin")
                )
            lines.append(t("rep.con.sse", detail=detail))
        http2 = result.http2
        if http2 is not None and http2.supported:
            detail = t("rep.con.supported")
            if http2.max_concurrent_streams is not None:
                detail += t("rep.con.http2_max_streams", n=http2.max_concurrent_streams)
            lines.append(t("rep.con.http2", detail=detail))
        if result.mtls is not None and result.mtls.requested:
            enforcement = (
                t("rep.con.mtls_required") if result.mtls.required else t("rep.con.mtls_requested")
            )
            lines.append(t("rep.con.mtls", enforcement=enforcement))
        if result.grpc is not None and result.grpc.supported:
            lines.append(t("rep.con.grpc", value=t("rep.con.supported")))
        for finding in result.findings:
            items = ", ".join(finding.items)
            lines.append(
                t(
                    "rep.con.finding",
                    severity=severity_label(t, finding.severity),
                    title=finding.title,
                    items=items,
                )
            )
        for vulnerability in result.vulnerabilities:
            evidence = f" ({', '.join(vulnerability.evidence)})" if vulnerability.evidence else ""
            lines.append(
                t(
                    "rep.con.vuln",
                    severity=severity_label(t, vulnerability.severity),
                    id=vulnerability.id,
                    name=vulnerability.name,
                    evidence=evidence,
                )
            )
        for compliance in result.compliance:
            lines.append(
                t(
                    "rep.con.compliance",
                    id=compliance.profile_id,
                    status=compliance_label(t, compliance.status),
                )
            )
            for violation in compliance.violations:
                lines.append(
                    t("rep.con.violation", subject=violation.subject, reason=violation.reason)
                )
    return "\n".join(lines)
