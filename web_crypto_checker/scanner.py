"""Driving the TLS engine across targets: resolve, enumerate, assemble.

A target names a host; a host can resolve to several addresses, and a domain
behind a load balancer or a CDN can be configured differently on each. So one
target becomes one result *per address*, the way SSL Labs and sslyze scan, and
the SNI carried on the wire stays the host name whichever address answered.
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Callable, List, Optional, Sequence, Tuple

from . import PRODUCT_NAME, __version__, webclient
from .application.grpc import check_grpc
from .application.http2 import check_http2
from .application.mtls import check_mtls
from .application.sse import check_sse
from .application.websocket import check_websocket
from .assessment import assess
from .compliance import Profile, evaluate_profile
from .dns import check_caa, check_dane, check_https
from .http_layer import check_cleartext_http, check_http
from .i18n import DEFAULT_LANGUAGE, Translator
from .messages import MESSAGES
from .models import (
    CaaInfo,
    CertificateChain,
    CertificateInfo,
    Http3Negotiation,
    HttpsRecord,
    PostQuantumStatus,
    ProtocolSupport,
    RevocationStatus,
    ScanReport,
    ScanStatus,
    ScanSummary,
    Severity,
    Target,
    TargetResult,
    TlsFeatures,
    TrustStatus,
    Verdict,
)
from .models import is_ip_literal as _is_ip_literal
from .pki.certificates import (
    TrustStore,
    build_certificate_chain,
    complete_chain_via_aia,
    retrieve_certificate_chain,
)
from .pki.crl import check_crl
from .pki.ocsp import authenticated_status, check_ocsp
from .plugins import Plugin
from .plugins.runner import run_plugins
from .policy import Policy
from .quic.reachability import negotiated_http3, probe_http3
from .quic.versions import probe_quic_versions
from .tls.active import check_ccs_injection, check_heartbleed
from .tls.constants import LEGACY_CIPHER_SUITES, cipher_suite_name, named_group
from .tls.enumerate import enumerate_endpoint
from .tls.features import (
    detect_cipher_preference,
    detect_downgrade_protection,
    detect_encrypt_then_mac,
    detect_extended_master_secret,
    detect_fallback_scsv,
    detect_grease_tolerance,
    detect_ocsp_stapling,
    detect_secure_renegotiation,
    detect_session_resumption,
    detect_tls_compression,
)
from .tls.groups import enumerate_groups
from .tls.probe import DEFAULT_TIMEOUT
from .tls.robot import check_robot
from .tls.signatures import enumerate_signature_algorithms
from .tls.sslv2 import probe_sslv2
from .tls.tls12 import probe_client_renegotiation, probe_dh_parameters, probe_ocsp_stapling
from .tls.tls13 import probe_early_data, retrieve_tls13_certificate
from .vulnerabilities import VulnerabilityMatch, evaluate

#: Default English translator for callers (e.g. unit tests) that invoke the active-probe
#: helper directly; ``scan`` passes the report's own translator instead.
_EN = Translator(DEFAULT_LANGUAGE, MESSAGES)


class ScanError(Exception):
    """A target could not be scanned before the TLS engine was even reached."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def resolve(host: str) -> List[str]:
    """Every distinct address a host resolves to, or the literal itself.

    Both address families are returned, de-duplicated and in the order the
    resolver gave them, so a dual-stacked name is scanned on each address it
    answers on rather than on whichever one happened to come first.
    """
    if _is_ip_literal(host):
        return [host]
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ScanError(f"cannot resolve {host}: {exc}") from exc
    addresses: List[str] = []
    seen = set()
    for info in infos:
        address = str(info[4][0])
        if address not in seen:
            seen.add(address)
            addresses.append(address)
    return addresses


def _scan_address(
    target: Target,
    address: str,
    caa: Optional[CaaInfo],
    https_record: Optional[HttpsRecord],
    timeout: float,
    trust_store: Optional[TrustStore],
    active: bool,
) -> TargetResult:
    """Probe one resolved address of a target and assemble its raw result."""
    started = time.monotonic()
    enumeration = enumerate_endpoint(address, target.port, target.effective_sni, timeout)
    # SSL 2.0 speaks a different wire format than TLS, so it is a probe of its own; a
    # positive is catastrophic (DROWN), so a rare SSL-2.0-only server still counts as
    # reachable rather than being written off.
    sslv2 = probe_sslv2(address, target.port, timeout)
    enumeration.protocols.append(
        ProtocolSupport(name="SSL 2.0", id="ssl2", supported=sslv2.supported, error=sslv2.error)
    )
    duration_ms = int((time.monotonic() - started) * 1000)
    result = TargetResult(
        target=target,
        ip=address,
        caa=caa,
        https_record=https_record,
        scanned_at=_now_iso(),
        duration_ms=duration_ms,
        protocols=enumeration.protocols,
        cipher_suites=enumeration.cipher_suites,
        sslv2_export_ciphers=sslv2.export_ciphers,
    )
    if not (enumeration.reachable or sslv2.reached):
        cleartext = check_cleartext_http(target, address, timeout)
        if cleartext is not None:
            # No TLS, but it serves plain HTTP: judge it (insecure), do not skip it.
            result.status = ScanStatus.OK
            result.verdict = Verdict.INSECURE
            result.http = cleartext
        else:
            result.status = ScanStatus.ERROR
            result.error = enumeration.error
        return result

    result.status = ScanStatus.OK
    result.verdict = Verdict.UNKNOWN
    supports_tls13 = any(p.id == "tls1_3" and p.supported for p in enumeration.protocols)
    result.certificate, chain_ders = _retrieve_certificate(
        target, address, timeout, supports_tls13, trust_store, active
    )
    leaf = result.certificate.leaf if result.certificate else None
    if leaf is not None:
        result.alternate_certificate = _retrieve_alternate_chain(
            target,
            address,
            timeout,
            supports_tls13,
            leaf,
            trust_store,
        )
        result.dane = check_dane(
            target,
            target.port,
            chain_ders,
            _pkix_valid(result.certificate.trust),
            timeout,
        )
    result.http = check_http(target, address, timeout, supports_tls13)
    result.websocket = check_websocket(target, address, timeout, supports_tls13, active)
    result.sse = check_sse(target, address, timeout, supports_tls13, active)
    result.http2 = check_http2(target, address, timeout, supports_tls13)
    result.mtls = check_mtls(target, address, timeout, supports_tls13)
    result.grpc = check_grpc(target, address, timeout, supports_tls13)
    resumption_id, resumption_ticket = detect_session_resumption(
        address, target.port, target.effective_sni, timeout
    )
    if supports_tls13:
        ocsp_stapling, stapled_response = detect_ocsp_stapling(
            address, target.port, target.effective_sni, timeout
        )
    else:
        ocsp_stapling, stapled_response = probe_ocsp_stapling(
            address, target.port, target.effective_sni, timeout
        )
    early_data = (
        probe_early_data(address, target.port, target.effective_sni, timeout)[0]
        if supports_tls13
        else None
    )
    supported_ids = [p.id for p in enumeration.protocols if p.supported]
    result.features = TlsFeatures(
        secure_renegotiation=detect_secure_renegotiation(
            address, target.port, target.effective_sni, timeout
        ),
        extended_master_secret=detect_extended_master_secret(
            address, target.port, target.effective_sni, timeout
        ),
        encrypt_then_mac=detect_encrypt_then_mac(
            address, target.port, target.effective_sni, timeout
        ),
        fallback_scsv=detect_fallback_scsv(
            address,
            target.port,
            supported_ids,
            target.effective_sni,
            timeout,
        ),
        downgrade_sentinel=detect_downgrade_protection(
            address,
            target.port,
            supported_ids,
            target.effective_sni,
            timeout,
        ),
        enforces_cipher_preference=detect_cipher_preference(
            address,
            target.port,
            target.effective_sni,
            timeout,
        ),
        dh_prime_bits=probe_dh_parameters(
            address,
            target.port,
            target.effective_sni,
            timeout,
        ),
        grease_tolerant=detect_grease_tolerance(
            address,
            target.port,
            target.effective_sni,
            timeout,
        ),
        session_resumption_id=resumption_id,
        session_resumption_ticket=resumption_ticket,
        ocsp_stapling=ocsp_stapling,
        early_data=early_data,
    )
    if stapled_response is not None and result.certificate is not None and len(chain_ders) >= 2:
        # A stapled response is only worth its word if it is authentic and current.
        status, error = authenticated_status(stapled_response, chain_ders[0], chain_ders[1])
        result.certificate.stapled_ocsp = status if error is None else "invalid"
    result.compression = detect_tls_compression(address, target.port, target.effective_sni, timeout)
    result.http3_reachable = probe_http3(address, target.port, target.effective_sni, timeout)
    if result.http3_reachable:
        result.http3_negotiation = _read_http3_negotiation(
            address, target.port, target.effective_sni, timeout
        )
        result.quic_versions = (
            probe_quic_versions(address, target.port, target.effective_sni, timeout) or []
        )
    if supports_tls13:
        groups, post_quantum, _ = enumerate_groups(
            address, target.port, target.effective_sni, timeout
        )
        result.groups = groups
        result.post_quantum = post_quantum
        result.signature_algorithms, _ = enumerate_signature_algorithms(
            address, target.port, target.effective_sni, timeout
        )
    return result


def scan_target(
    target: Target,
    timeout: float = DEFAULT_TIMEOUT,
    trust_store: Optional[TrustStore] = None,
    active: bool = False,
) -> List[TargetResult]:
    """Scan one target, returning one result per resolved address."""
    try:
        addresses = resolve(target.host)
    except ScanError as exc:
        return [
            TargetResult(
                target=target,
                status=ScanStatus.ERROR,
                error=str(exc),
                scanned_at=_now_iso(),
            )
        ]
    caa = check_caa(target, timeout)  # a domain-level DNS property, shared by every address
    https_record = check_https(target, timeout)  # likewise the HTTPS/SVCB record (ALPN, ECH)
    results: List[TargetResult] = []
    for address in addresses:
        try:
            results.append(
                _scan_address(target, address, caa, https_record, timeout, trust_store, active)
            )
        except Exception as exc:
            # A hostile or broken endpoint must not abort the whole scan: report it as an
            # error result (faithfully, with the reason) rather than crash the run.
            results.append(
                TargetResult(
                    target=target,
                    ip=address,
                    status=ScanStatus.ERROR,
                    error=f"scan failed: {exc}",
                    scanned_at=_now_iso(),
                )
            )
    return results


def _read_http3_negotiation(
    address: str, port: int, sni: str, timeout: float
) -> Optional[Http3Negotiation]:
    """The cipher, group and transport parameters HTTP/3 negotiated, or None."""
    server_hello, transport_parameters = negotiated_http3(address, port, sni, timeout)
    if server_hello is None:
        return None
    group = named_group(server_hello.selected_group) if server_hello.selected_group else None
    return Http3Negotiation(
        cipher_suite=cipher_suite_name(server_hello.cipher_suite),
        group=group.name if group else None,
        transport_parameters=transport_parameters,
    )


def _retrieve_certificate(
    target: Target,
    address: str,
    timeout: float,
    try_tls13: bool,
    trust_store: Optional[TrustStore],
    active: bool,
) -> Tuple[CertificateChain, List[bytes]]:
    """The parsed chain and the raw DERs it was built from (leaf first, empty on error)."""
    sni = target.effective_sni
    ders, error = retrieve_certificate_chain(address, target.port, sni, timeout)
    if not ders and try_tls13:
        # A TLS 1.3-only server sends its certificate encrypted, so the cleartext
        # 1.2 handshake never sees it; complete a 1.3 handshake instead.
        ders, _stapled, error = retrieve_tls13_certificate(address, target.port, sni, timeout)
    if not ders:
        return CertificateChain(error=error), []
    chain, ders = _build_and_complete_chain(sni or target.host, ders, trust_store, timeout)
    if active:
        _check_revocation(chain, ders, timeout)
    return chain, ders


def _build_and_complete_chain(
    host: str,
    ders: List[bytes],
    trust_store: Optional[TrustStore],
    timeout: float,
) -> Tuple[CertificateChain, List[bytes]]:
    """Build the chain and, if it does not reach a trusted root, try to complete it via AIA."""
    chain = build_certificate_chain(host, ders, trust_store)
    if trust_store is not None and chain.trust == TrustStatus.UNTRUSTED:
        # The presented chain did not reach a trusted root. It may only be missing an
        # intermediate the server should have sent; fetch it from the AIA caIssuers URL
        # (as a browser would) and rebuild. Completion never confers trust on its own --
        # a fetched intermediate only helps reach a root already in the store.
        extended, fetched = complete_chain_via_aia(
            ders, lambda url: webclient.http_request(url, "GET", timeout)[0]
        )
        if fetched:
            ders = extended
            chain = build_certificate_chain(host, ders, trust_store)
            chain.aia_completed = True
    return chain, ders


# Signature schemes / cipher suites restricted to one certificate key type, used to steer a
# dual-certificate server into presenting its RSA and its ECDSA certificate in turn.
_ECDSA_SIGNATURE_SCHEMES = [0x0403, 0x0503, 0x0603]
_RSA_SIGNATURE_SCHEMES = [0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601]


def _retrieve_alternate_chain(
    target: Target,
    address: str,
    timeout: float,
    try_tls13: bool,
    primary_leaf: CertificateInfo,
    trust_store: Optional[TrustStore],
) -> Optional[CertificateChain]:
    """A second leaf certificate, of a different key type, the server also serves, or None.

    A dual-certificate server presents an ECDSA certificate to a client that offers ECDSA
    and an RSA one otherwise; the default scan sees only whichever it prefers. This steers
    it to the *other* key type and, if a distinct certificate comes back, returns its chain
    so a weak or expired alternate cannot hide behind the strong default. Only the common
    RSA<->ECDSA pairing is steered.
    """
    if primary_leaf.key_type not in ("RSA", "EC"):
        return None
    want_ecdsa = primary_leaf.key_type == "RSA"
    sni = target.effective_sni
    ciphers = [
        code for code, name in LEGACY_CIPHER_SUITES.items() if ("_ECDSA_" in name) == want_ecdsa
    ]
    ders, _error = retrieve_certificate_chain(address, target.port, sni, timeout, ciphers)
    if not ders and try_tls13:
        schemes = _ECDSA_SIGNATURE_SCHEMES if want_ecdsa else _RSA_SIGNATURE_SCHEMES
        ders, _stapled, _error = retrieve_tls13_certificate(
            address, target.port, sni, timeout, schemes
        )
    if not ders:
        return None  # the server serves only the one key type
    chain, _ders = _build_and_complete_chain(sni or target.host, ders, trust_store, timeout)
    leaf = chain.leaf
    if leaf is None or leaf.fingerprint_sha256 == primary_leaf.fingerprint_sha256:
        return None  # unparseable, or the very same certificate -- not a second one
    return chain


def _pkix_valid(trust: TrustStatus) -> Optional[bool]:
    """Whether ordinary PKIX validation passed, for the DANE PKIX-* usages (RFC 6698).

    ``None`` when trust was not established either way -- no trust store was given, so a
    PKIX-* TLSA record can be neither confirmed nor refused.
    """
    if trust == TrustStatus.TRUSTED:
        return True
    if trust in (TrustStatus.NOT_CHECKED, TrustStatus.UNKNOWN):
        return None
    return False


def _check_revocation(chain: CertificateChain, ders: List[bytes], timeout: float) -> None:
    """Ask the leaf's OCSP responder and CRL whether it is revoked (an active probe)."""
    leaf = chain.leaf
    if leaf is None or len(ders) < 2 or not (leaf.ocsp_url or leaf.crl_urls):
        return
    revocation = RevocationStatus(checked=True)
    if leaf.ocsp_url:
        revocation.ocsp, revocation.error = check_ocsp(ders[0], ders[1], leaf.ocsp_url, timeout)
    if leaf.crl_urls:
        revocation.crl, crl_error = check_crl(ders[0], ders[1], leaf.crl_urls[0], timeout)
        revocation.error = revocation.error or crl_error
    chain.revocation = revocation


def _summarise(results: Sequence[TargetResult]) -> ScanSummary:
    summary = ScanSummary(total=len(results))
    scores: List[int] = []
    for result in results:
        if result.ok:
            summary.succeeded += 1
        else:
            summary.failed += 1
        verdict_key = result.verdict.value
        summary.by_verdict[verdict_key] = summary.by_verdict.get(verdict_key, 0) + 1
        if result.grade is not None:
            summary.by_grade[result.grade] = summary.by_grade.get(result.grade, 0) + 1
        if result.post_quantum in (PostQuantumStatus.READY, PostQuantumStatus.ENFORCED):
            summary.post_quantum_ready += 1
        strength = result.security_strength
        if strength is not None and strength.level_id != "unknown":
            summary.by_strength_level[strength.level_id] = (
                summary.by_strength_level.get(strength.level_id, 0) + 1
            )
        if result.score is not None:
            scores.append(result.score)
        for finding in result.findings:
            key = finding.severity.value
            summary.by_severity[key] = summary.by_severity.get(key, 0) + 1
        if result.vulnerabilities:
            summary.vulnerable += 1
        for vulnerability in result.vulnerabilities:
            summary.by_vulnerability[vulnerability.id] = (
                summary.by_vulnerability.get(vulnerability.id, 0) + 1
            )
        for compliance in result.compliance:
            bucket = summary.by_profile.setdefault(compliance.profile_id, {})
            bucket[compliance.status.value] = bucket.get(compliance.status.value, 0) + 1
    if scores:
        summary.average_score = round(sum(scores) / len(scores), 1)
    return summary


def _run_active_probes(
    result: TargetResult, timeout: float, t: Optional[Translator] = None
) -> None:
    """Send the active (crafted, potentially disruptive) probes at a reachable result."""
    t = t or _EN
    address, port, sni = result.ip or "", result.target.port, result.target.effective_sni
    heartbleed = check_heartbleed(address, port, sni, timeout)
    if heartbleed.vulnerable:
        result.vulnerabilities.append(
            VulnerabilityMatch(
                id="HEARTBLEED",
                name=t("find.heartbleed.name"),
                severity=Severity.CRITICAL,
                description=t("find.heartbleed.desc"),
                references=["CVE-2014-0160"],
                evidence=[heartbleed.detail],
            )
        )
    ccs = check_ccs_injection(address, port, sni, timeout)
    if ccs.vulnerable:
        result.vulnerabilities.append(
            VulnerabilityMatch(
                id="CCS-INJECTION",
                name=t("find.ccs_injection.name"),
                severity=Severity.HIGH,
                description=t("find.ccs_injection.desc"),
                references=["CVE-2014-0224"],
                evidence=[ccs.detail],
            )
        )
    robot = check_robot(address, port, sni, timeout)
    if robot.vulnerable:
        result.vulnerabilities.append(
            VulnerabilityMatch(
                id="ROBOT",
                name=t("find.robot.name"),
                severity=Severity.HIGH,
                description=t("find.robot.desc"),
                references=["CVE-2017-13099"],
                evidence=[robot.detail],
            )
        )
    reneg = probe_client_renegotiation(address, port, sni, timeout)
    if reneg.accepted and not reneg.secure:
        result.vulnerabilities.append(
            VulnerabilityMatch(
                id="INSECURE-RENEGOTIATION",
                name=t("find.insecure_renegotiation.name"),
                severity=Severity.HIGH,
                description=t("find.insecure_renegotiation.desc"),
                references=["CVE-2009-3555"],
                evidence=[reneg.detail],
            )
        )
    elif reneg.accepted:
        result.vulnerabilities.append(
            VulnerabilityMatch(
                id="CLIENT-RENEGOTIATION",
                name=t("find.client_renegotiation.name"),
                severity=Severity.LOW,
                description=t("find.client_renegotiation.desc"),
                references=["CVE-2011-1473"],
                evidence=[reneg.detail],
            )
        )


def scan(
    targets: Sequence[Target],
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = 1,
    profiles: Sequence[Profile] = (),
    plugins: Sequence[Plugin] = (),
    active: bool = False,
    trust_store: Optional[TrustStore] = None,
    command_line: str = "",
    progress: Optional[Callable[[], None]] = None,
    language: str = DEFAULT_LANGUAGE,
) -> ScanReport:
    """Scan every target and assemble the full report.

    ``progress``, when given, is called once for each target that finishes -- in
    both the serial and the concurrent path -- so a caller such as the web front
    end can report how far along a long scan is. The default of ``None`` leaves
    the command-line path unchanged.

    ``language`` selects the language of the finding and vulnerability prose the
    result carries: it loads the matching policy-data overlay (translated
    vulnerability text and strength labels) and builds the code-generated
    findings in that language, so every renderer -- machine formats included --
    emits translated values while keys and enum codes stay English. The default
    English keeps every existing caller byte-identical.
    """
    policy = Policy.load(language=language)
    translator = Translator(language, MESSAGES)
    started_at = _now_iso()
    started = time.monotonic()

    results: List[TargetResult] = []
    if concurrency > 1 and len(targets) > 1:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:

            def _one(target: Target) -> List[TargetResult]:
                return scan_target(target, timeout, trust_store, active)

            for group in pool.map(_one, targets):
                results.extend(group)
                if progress is not None:
                    progress()
    else:
        for target in targets:
            results.extend(scan_target(target, timeout, trust_store, active))
            if progress is not None:
                progress()

    for result in results:
        if result.ok:
            assess(result, policy, language=language)
            result.vulnerabilities = evaluate(result, policy.vulnerabilities())
            result.compliance = [evaluate_profile(result, profile) for profile in profiles]
            if active:
                _run_active_probes(result, timeout, translator)

    run_plugins(results, plugins)

    duration_ms = int((time.monotonic() - started) * 1000)
    return ScanReport(
        tool=PRODUCT_NAME,
        version=__version__,
        started_at=started_at,
        finished_at=_now_iso(),
        duration_ms=duration_ms,
        command_line=command_line,
        results=results,
        summary=_summarise(results),
    )
