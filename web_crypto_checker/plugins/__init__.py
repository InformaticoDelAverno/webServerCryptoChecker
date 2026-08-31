"""Detections that need code rather than a data rule.

Most checks are matched declaratively from the policy file. What that cannot
express is a check that has to *compute* something -- factor a modulus, correlate
two observations, decide from arithmetic. This is for those. A plugin is one
file:

    ID = "EXAMPLE-1"
    NAME = "Something a rule cannot express"
    SEVERITY = "high"
    DESCRIPTION = "What is wrong, and why it matters."
    REMEDIATION = "What to do about it."

    def check(server):
        if server.offers_cipher("TLS_RSA_WITH_RC4_128_SHA"):
            return Detected(evidence=["RC4"])
        return None

Two properties matter more than the convenience. *A plugin cannot change the
grade:* it is handed a :class:`ServerView` of what was observed -- never the
score -- and its result becomes a report item, added after the grade is already
computed. *A broken plugin cannot break the scan:* anything it raises is caught
and reported as a finding that names it. Loading code is loading code, so plugin
directories are explicit, never the working directory, and one writable by
others is refused rather than trusted.
"""

from __future__ import annotations

import importlib.util
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, cast

from ..models import CaaRecord, CertificateInfo, ClassAssessment, Severity, TargetResult
from ..tls.constants import cipher_suite_tags

__all__ = [
    "Detected",
    "FleetView",
    "ForTarget",
    "Plugin",
    "PluginError",
    "ScannedServer",
    "ServerView",
    "Undetermined",
    "builtin_directory",
    "default_plugin_directories",
    "load_plugins",
]

KINDS = ("vulnerability", "check", "fleet")


class PluginError(Exception):
    """A plugin could not be loaded."""


@dataclass
class Detected:
    """Something a plugin found, with the evidence that showed it."""

    evidence: List[str] = field(default_factory=list)
    severity: Optional[str] = None
    note: str = ""


@dataclass
class Undetermined:
    """The plugin could not decide, and says what would settle it."""

    needs: List[str] = field(default_factory=list)


@dataclass
class ServerView:
    """What was observed, and nothing that was concluded.

    A plugin can see the protocols and suites a server offered and the
    certificate it presented; it cannot see the score, the grade or the verdict,
    because they are not here. That boundary is the point.
    """

    supported_protocols: List[str] = field(default_factory=list)
    offered_ciphers: List[str] = field(default_factory=list)
    key_exchange_groups: List[str] = field(default_factory=list)
    signature_algorithms: List[str] = field(default_factory=list)
    leaf: Optional[CertificateInfo] = None
    caa_records: List[CaaRecord] = field(default_factory=list)
    assessments: List[ClassAssessment] = field(default_factory=list)

    @classmethod
    def from_result(cls, result: TargetResult) -> ServerView:
        return cls(
            supported_protocols=[p.id for p in result.protocols if p.supported],
            offered_ciphers=[suite.name for suite in result.cipher_suites],
            key_exchange_groups=[group.name for group in result.groups],
            signature_algorithms=list(result.signature_algorithms),
            leaf=result.certificate.leaf if result.certificate is not None else None,
            caa_records=list(result.caa.records) if result.caa is not None else [],
            assessments=list(result.assessments),
        )

    def supports(self, protocol_id: str) -> bool:
        return protocol_id in self.supported_protocols

    def offers_cipher(self, name: str) -> bool:
        return name in self.offered_ciphers

    def cipher_tags(self, name: str) -> List[str]:
        return cipher_suite_tags(name)

    def certificate(self) -> Optional[CertificateInfo]:
        return self.leaf

    def assessment(self, key: str) -> Optional[ClassAssessment]:
        for assessment in self.assessments:
            if assessment.key == key:
                return assessment
        return None


@dataclass
class ForTarget:
    """A fleet finding, and which server it is about.

    A fleet check sees every server, so it has to say who each result belongs
    to. ``target`` is the address as the report prints it (``str(target)``);
    anything naming a server the scan did not produce is dropped, not invented.
    """

    target: str
    finding: Any


@dataclass
class ScannedServer:
    """One server in a fleet view: what it is called, and what was seen."""

    target: str
    """The address as the report prints it."""
    label: str = ""
    view: ServerView = field(default_factory=ServerView)
    """Always present, even for a target that could not be reached.

    An unreachable server has an empty view rather than no view, so a fleet
    check that walks the scan sees every target it was asked about. The
    alternative -- dropping the failures -- makes "do all my servers present the
    same certificate" answer from whichever ones happened to be up.
    """


@dataclass
class FleetView:
    """Every server in the scan, for a check that needs more than one.

    Holds the same observations as a :class:`ServerView`, one per server, and
    the same boundary applies: no score, no grade, no verdict. A fleet check can
    see that two servers present the same certificate; it cannot see, or change,
    what either of them was graded.
    """

    servers: List[ScannedServer] = field(default_factory=list)
    policy: Any = None

    def __iter__(self) -> Iterator[ScannedServer]:
        return iter(self.servers)

    def __len__(self) -> int:
        return len(self.servers)

    def with_certificates(self) -> List[ScannedServer]:
        """The servers that actually presented a leaf certificate."""
        return [server for server in self.servers if server.view.leaf is not None]


@dataclass
class Plugin:
    """One loaded detection."""

    id: str
    name: str
    severity: Severity
    description: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    kind: str = "vulnerability"
    source: str = ""
    check: Optional[Callable[[ServerView], Any]] = None


def builtin_directory() -> Path:
    return Path(__file__).resolve().parent / "builtin"


def default_plugin_directories() -> List[Path]:
    """Where plugins are looked for. Deliberately not the working directory."""
    directories = [builtin_directory()]
    configured = os.environ.get("WCC_PLUGIN_DIR")
    if configured:
        directories += [Path(part) for part in configured.split(os.pathsep) if part]
    home = Path(os.path.expanduser("~"))
    directories.append(home / ".config" / "webcryptochecker" / "plugins")
    return directories


def _refuse_if_writable_by_others(path: Path) -> Optional[str]:
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        return f"cannot be read: {exc}"
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        return (
            "is writable by group or others, so anyone in that group could run code as "
            f"whoever runs the scan; fix it with 'chmod go-w {path}'"
        )
    return None


def load_plugins(
    directories: Optional[List[Path]] = None,
    include_builtin: bool = True,
) -> tuple:
    """Load every plugin found, returning ``(plugins, problems)``. Never raises."""
    search: List[Path] = []
    if directories is None:
        search = list(default_plugin_directories())
    else:
        if include_builtin:
            search.append(builtin_directory())
        search += [Path(directory) for directory in directories]

    plugins: List[Plugin] = []
    problems: List[str] = []
    seen: Dict[str, str] = {}
    builtin = builtin_directory()

    for directory in search:
        if not directory.is_dir():
            continue
        external = directory.resolve() != builtin.resolve()
        if external:
            refusal = _refuse_if_writable_by_others(directory)
            if refusal is not None:
                problems.append(f"{directory} {refusal}")
                continue
        for path in sorted(directory.glob("*.py")):
            if path.name.startswith("_"):
                continue
            if external:
                refusal = _refuse_if_writable_by_others(path)
                if refusal is not None:
                    problems.append(f"{path} {refusal}")
                    continue
            try:
                plugin = _load_one(path)
            except PluginError as exc:
                problems.append(str(exc))
                continue
            previous = seen.get(plugin.id)
            if previous is not None:
                problems.append(
                    f"{path}: id '{plugin.id}' is already defined by {previous}, so it was skipped"
                )
                continue
            seen[plugin.id] = str(path)
            plugins.append(plugin)
    return plugins, problems


def _load_one(path: Path) -> Plugin:
    module_name = f"_wcc_plugin_{path.stem}_{abs(hash(str(path))) & 0xFFFFFF:x}"
    # A '.py' path that exists always yields a spec with a source loader, so
    # there is no None case to guard once the path is known to be a file.
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(cast(Any, spec))
    try:
        cast(Any, cast(Any, spec).loader).exec_module(module)
    except Exception as exc:  # any failure is the plugin's, not ours
        raise PluginError(f"{path}: failed to import: {exc}") from exc

    missing = [
        field_name
        for field_name in ("ID", "NAME", "SEVERITY", "DESCRIPTION")
        if not getattr(module, field_name, None)
    ]
    if missing:
        raise PluginError(f"{path}: missing {', '.join(missing)}")

    check = getattr(module, "check", None)
    if not callable(check):
        raise PluginError(f"{path}: has no check(server) function")

    try:
        severity = Severity(str(module.SEVERITY).lower())
    except ValueError:
        raise PluginError(f"{path}: SEVERITY {module.SEVERITY!r} is not valid") from None

    kind = str(getattr(module, "KIND", "vulnerability")).lower()
    if kind not in KINDS:
        raise PluginError(f"{path}: KIND must be one of {', '.join(KINDS)}, not {kind!r}")

    return Plugin(
        id=str(module.ID),
        name=str(module.NAME),
        severity=severity,
        description=str(module.DESCRIPTION),
        remediation=str(getattr(module, "REMEDIATION", "")),
        references=[str(item) for item in getattr(module, "REFERENCES", []) or []],
        kind=kind,
        source=str(path),
        check=check,
    )
