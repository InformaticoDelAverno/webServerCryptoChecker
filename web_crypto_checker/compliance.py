"""Measuring a server against published TLS profiles.

A profile is a document somebody else maintains -- Mozilla's server-side TLS,
NIST SP 800-52, PCI DSS, the CIS web-server benchmarks -- so each lives in its
own JSON file under ``data/profiles/`` and is evaluated, never compiled in. A
profile says which protocol versions it permits, which cipher-suite shapes it
forbids or which exact suites it authorises, which key-exchange groups and
signature algorithms it allows, how strong a certificate key (and the effective
security strength) must be, and whether the HTTP layer must assert HSTS or the
server must staple OCSP. Evaluation reports every requirement the server failed,
and says *not assessed* rather than *pass* when the scan could not see enough to
judge -- an unrun check that reads as conformance is worse than no check at all.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .models import (
    ComplianceResult,
    ComplianceStatus,
    ComplianceViolation,
    TargetResult,
)
from .tls.constants import cipher_suite_tags


class ComplianceError(Exception):
    """A profile file could not be read or parsed."""


@dataclass
class Profile:
    """One published rule set, loaded from a profile file."""

    id: str
    name: str
    authority: str = ""
    kind: str = "algorithm-strength"
    """``algorithm-strength`` (the default: check what the server offers against the
    document's rules) or ``policy-conformance`` (check what the server offers against
    this tool's own policy categories -- for a standard that names no algorithms)."""
    edition: str = ""
    edition_id: str = ""
    """The short name the edition answers to: ``--profile <id>@<edition_id>``. It
    is the file the edition lives in (without ``.json``) and nothing else."""
    current: bool = True
    """Whether this is the edition in force, which a bare ``--profile <id>`` gets."""
    reference: str = ""
    url: str = ""
    summary: str = ""
    notes: str = ""
    allowed_protocols: Optional[List[str]] = None
    disallowed_protocols: List[str] = field(default_factory=list)
    disallowed_cipher_tags: List[str] = field(default_factory=list)
    allowed_cipher_suites: Optional[List[str]] = None
    """An allowlist of exact IANA cipher-suite names. A document that publishes a table
    of authorised suites (BSI Table 3/13, CCN-STIC-807 Tables 4-1/4-2, CNSA, FIPS) is
    encoded here rather than by shape-tag, because a tag cannot tell AES from ChaCha20."""
    allowed_groups: Optional[List[str]] = None
    disallowed_groups: List[str] = field(default_factory=list)
    allowed_signature_algorithms: Optional[List[str]] = None
    disallowed_signature_algorithms: List[str] = field(default_factory=list)
    min_rsa_bits: Optional[int] = None
    min_ec_bits: Optional[int] = None
    disallow_sha1_certificate: bool = False
    min_security_strength: Optional[int] = None
    """The minimum effective security strength in bits the server must reach, read from
    ``result.security_strength`` (NIST SP 800-57 Part 1). ``None`` when the document
    states no single figure (ANSSI publishes none on purpose)."""
    require_hsts: bool = False
    hsts_min_age: Optional[int] = None
    require_ocsp_stapling: bool = False
    forbidden_local_categories: List[str] = field(default_factory=list)
    """For a ``policy-conformance`` profile: the local-policy categories (``weak``,
    ``insecure``) that any offered algorithm falling into is a non-conformance."""


def default_profiles_directory() -> Path:
    return Path(__file__).resolve().parent / "data" / "profiles"


def _profile_from(
    data: dict, profile_id: str, edition_id: str = "", current: bool = True
) -> Profile:
    protocols = data.get("protocols", {})
    cipher_tags = data.get("cipher_tags", {})
    cipher_suites = data.get("cipher_suites", {})
    groups = data.get("groups", {})
    signatures = data.get("signature_algorithms", {})
    certificate = data.get("certificate", {})
    hsts = data.get("hsts", {})
    ocsp = data.get("ocsp_stapling", {})
    return Profile(
        id=profile_id,
        name=data["name"],
        authority=data.get("authority", ""),
        kind=data.get("kind", "algorithm-strength"),
        edition=data.get("edition", ""),
        edition_id=edition_id,
        current=current,
        reference=data.get("reference", ""),
        url=data.get("url", ""),
        summary=data.get("summary", ""),
        notes=data.get("notes", ""),
        allowed_protocols=protocols.get("allow"),
        disallowed_protocols=list(protocols.get("disallow", [])),
        disallowed_cipher_tags=list(cipher_tags.get("disallow", [])),
        allowed_cipher_suites=cipher_suites.get("allow"),
        allowed_groups=groups.get("allow"),
        disallowed_groups=list(groups.get("disallow", [])),
        allowed_signature_algorithms=signatures.get("allow"),
        disallowed_signature_algorithms=list(signatures.get("disallow", [])),
        min_rsa_bits=certificate.get("min_rsa_bits"),
        min_ec_bits=certificate.get("min_ec_bits"),
        disallow_sha1_certificate=bool(certificate.get("disallow_sha1", False)),
        min_security_strength=data.get("minimum_security_strength"),
        require_hsts=bool(hsts.get("require", False)),
        hsts_min_age=hsts.get("min_age"),
        require_ocsp_stapling=bool(ocsp.get("require", False)),
        forbidden_local_categories=list(data.get("forbid_local_categories", [])),
    )


_EDITION_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]*$")


def _load_profile_directory(location: Path) -> Tuple[Dict[str, Profile], Dict[str, Profile]]:
    """One directory per profile, one file per edition.

    A standard is a document someone else revises on their own calendar, so an
    edition is a file that can be added and asked for by name -- ``id@edition`` --
    rather than a paragraph edited in place. Returns the edition in force per id,
    and every edition keyed ``id@edition``.
    """
    current_by_id: Dict[str, Profile] = {}
    all_editions: Dict[str, Profile] = {}
    for folder in sorted(p for p in location.iterdir() if p.is_dir()):
        profile_id = folder.name
        editions: Dict[str, Profile] = {}
        for path in sorted(folder.glob("*.json")):
            edition_id = path.stem
            if not _EDITION_NAME.match(edition_id):
                raise ComplianceError(
                    f"profiles/{profile_id}/{path.name}: an edition is named by its "
                    "file, so use lower-case letters, digits, dots and dashes"
                )
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ComplianceError(f"cannot read profile {path}: {exc}") from exc
            editions[edition_id] = _profile_from(
                data, profile_id, edition_id=edition_id, current=bool(data.get("current", False))
            )
        if not editions:
            continue
        _mark_edition_in_force(profile_id, editions)
        for edition_id, profile in editions.items():
            all_editions[f"{profile_id}@{edition_id}"] = profile
            if profile.current:
                current_by_id[profile_id] = profile
    return current_by_id, all_editions


def _mark_edition_in_force(profile_id: str, editions: Dict[str, Profile]) -> None:
    """Which edition a bare ``--profile <id>`` means. With one there is nothing to
    decide; with more than one the file has to say, because which edition is in
    force is exactly what a compliance tool must not guess."""
    if len(editions) == 1:
        only = next(iter(editions))
        editions[only] = replace(editions[only], current=True)
        return
    declared = [edition_id for edition_id, profile in editions.items() if profile.current]
    if len(declared) != 1:
        which = "none" if not declared else "several (" + ", ".join(sorted(declared)) + ")"
        raise ComplianceError(
            f"profiles/{profile_id} has {len(editions)} editions and {which} declare "
            '"current": true; exactly one must be in force'
        )


def load_profiles(directory: Optional[Path] = None) -> Dict[str, Profile]:
    """The edition in force of every profile, keyed by profile id."""
    location = directory or default_profiles_directory()
    return _load_profile_directory(location)[0]


def load_profile_editions(directory: Optional[Path] = None) -> Dict[str, Profile]:
    """Every edition of every profile, keyed ``id@edition`` -- for ``--profile id@edition``."""
    location = directory or default_profiles_directory()
    return _load_profile_directory(location)[1]


def _protocol_violations(
    supported: List[str], profile: Profile, violations: List[ComplianceViolation]
) -> None:
    for protocol_id in supported:
        if profile.allowed_protocols is not None and protocol_id not in profile.allowed_protocols:
            violations.append(
                ComplianceViolation("protocol", protocol_id, "not in the permitted set")
            )
        elif protocol_id in profile.disallowed_protocols:
            violations.append(ComplianceViolation("protocol", protocol_id, "explicitly disallowed"))


def _cipher_violations(
    result: TargetResult,
    profile: Profile,
    violations: List[ComplianceViolation],
    unverified: List[str],
) -> None:
    allow = profile.allowed_cipher_suites
    for suite in result.cipher_suites:
        offending = sorted(
            tag for tag in cipher_suite_tags(suite.name) if tag in profile.disallowed_cipher_tags
        )
        if offending:
            violations.append(
                ComplianceViolation("cipher", suite.name, f"disallowed: {', '.join(offending)}")
            )
        elif allow is not None and suite.name not in allow:
            violations.append(
                ComplianceViolation("cipher", suite.name, "not in the authorised set")
            )
    if allow is not None and not result.cipher_suites:
        unverified.append("requires specific cipher suites and none were observed")


def _group_violations(
    result: TargetResult,
    profile: Profile,
    violations: List[ComplianceViolation],
    unverified: List[str],
) -> None:
    allow = profile.allowed_groups
    for group in result.groups:
        if allow is not None and group.name not in allow:
            violations.append(
                ComplianceViolation("group", group.name, "not in the permitted set")
            )
        elif group.name in profile.disallowed_groups:
            violations.append(ComplianceViolation("group", group.name, "explicitly disallowed"))
    if allow is not None and not result.groups:
        unverified.append("requires specific key-exchange groups and none were observed")


def _signature_violations(
    result: TargetResult,
    profile: Profile,
    violations: List[ComplianceViolation],
    unverified: List[str],
) -> None:
    allow = profile.allowed_signature_algorithms
    for name in result.signature_algorithms:
        if allow is not None and name not in allow:
            violations.append(
                ComplianceViolation("signature", name, "not in the permitted set")
            )
        elif name in profile.disallowed_signature_algorithms:
            violations.append(ComplianceViolation("signature", name, "explicitly disallowed"))
    if allow is not None and not result.signature_algorithms:
        unverified.append("requires specific signature algorithms and none were observed")


def _certificate_violations(
    result: TargetResult, profile: Profile, violations: List[ComplianceViolation]
) -> None:
    chain = result.certificate
    if chain is None or chain.leaf is None:
        return
    leaf = chain.leaf
    if (
        profile.min_rsa_bits
        and leaf.key_type == "RSA"
        and leaf.key_bits is not None
        and leaf.key_bits < profile.min_rsa_bits
    ):
        violations.append(
            ComplianceViolation("certificate", f"RSA {leaf.key_bits}-bit",
                                f"below the required {profile.min_rsa_bits} bits")
        )
    if (
        profile.min_ec_bits
        and leaf.key_type == "EC"
        and leaf.key_bits is not None
        and leaf.key_bits < profile.min_ec_bits
    ):
        violations.append(
            ComplianceViolation("certificate", f"EC {leaf.key_bits}-bit",
                                f"below the required {profile.min_ec_bits} bits")
        )
    if profile.disallow_sha1_certificate and "sha1" in leaf.signature_algorithm.lower():
        violations.append(
            ComplianceViolation("certificate", leaf.signature_algorithm, "SHA-1 signature")
        )


def _strength_violation(
    result: TargetResult,
    profile: Profile,
    violations: List[ComplianceViolation],
    unverified: List[str],
) -> None:
    minimum = profile.min_security_strength
    if minimum is None:
        return
    strength = result.security_strength
    if strength is None or strength.effective_bits is None:
        unverified.append(
            f"requires at least {minimum}-bit security strength and it could not be established"
        )
        return
    if strength.effective_bits < minimum:
        violations.append(
            ComplianceViolation(
                "strength",
                f"{strength.effective_bits}-bit effective security strength",
                f"below the required {minimum} bits",
            )
        )


def _http_violations(
    result: TargetResult,
    profile: Profile,
    violations: List[ComplianceViolation],
    unverified: List[str],
) -> None:
    if profile.require_hsts:
        http = result.http
        if http is None or not http.reached:
            unverified.append("requires HSTS and the HTTP layer was not reached")
        elif http.hsts is None:
            violations.append(
                ComplianceViolation("http", "Strict-Transport-Security", "HSTS header is not set")
            )
        elif profile.hsts_min_age is not None and (
            http.hsts_max_age is None or http.hsts_max_age < profile.hsts_min_age
        ):
            got = http.hsts_max_age if http.hsts_max_age is not None else 0
            violations.append(
                ComplianceViolation(
                    "http", "Strict-Transport-Security",
                    f"max-age {got} below the required {profile.hsts_min_age}",
                )
            )
    if profile.require_ocsp_stapling:
        features = result.features
        if features is None or features.ocsp_stapling is None:
            unverified.append("requires OCSP stapling and it could not be determined")
        elif not features.ocsp_stapling:
            violations.append(
                ComplianceViolation(
                    "certificate", "OCSP stapling", "the server did not staple an OCSP response"
                )
            )


def _local_policy_violations(
    result: TargetResult,
    profile: Profile,
    violations: List[ComplianceViolation],
    unverified: List[str],
) -> None:
    if not result.assessments:
        unverified.append("measures against the local policy and nothing was assessed")
        return
    forbidden = set(profile.forbidden_local_categories)
    for assessment in result.assessments:
        for algorithm in assessment.algorithms:
            if algorithm.category.value in forbidden:
                violations.append(
                    ComplianceViolation(
                        assessment.key, algorithm.name,
                        f"classified {algorithm.category.value} by the local policy",
                    )
                )


def evaluate_profile(result: TargetResult, profile: Profile) -> ComplianceResult:
    """Evaluate one server against one profile."""
    outcome = ComplianceResult(
        profile_id=profile.id,
        name=profile.name,
        authority=profile.authority,
        reference=profile.reference,
        edition=profile.edition,
        url=profile.url,
        summary=profile.summary,
        notes=profile.notes,
        kind=profile.kind,
    )

    supported = [protocol.id for protocol in result.protocols if protocol.supported]
    if not supported:
        outcome.status = ComplianceStatus.NOT_ASSESSED
        outcome.unverified = ["no protocol versions were negotiated"]
        return outcome

    violations: List[ComplianceViolation] = []
    unverified: List[str] = []

    if profile.kind == "policy-conformance":
        _local_policy_violations(result, profile, violations, unverified)
    else:
        _protocol_violations(supported, profile, violations)
        _cipher_violations(result, profile, violations, unverified)
        _group_violations(result, profile, violations, unverified)
        _signature_violations(result, profile, violations, unverified)
        _certificate_violations(result, profile, violations)
        _strength_violation(result, profile, violations, unverified)
        _http_violations(result, profile, violations, unverified)

    outcome.violations = violations
    outcome.unverified = unverified
    # A violation is proof and settles the question. Without one, a profile is a
    # pass only when every requirement it makes was actually testable: a check the
    # scan could not run has not been met, it has been skipped, and reporting the
    # two the same way is how a scanner certifies a server it never understood.
    if violations:
        outcome.status = ComplianceStatus.FAIL
    elif unverified:
        outcome.status = ComplianceStatus.NOT_ASSESSED
    else:
        outcome.status = ComplianceStatus.PASS
    return outcome
