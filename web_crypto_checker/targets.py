"""Parsing of the target specifications accepted on the command line.

Supported forms::

    example.com                 # default port 443
    example.com:8443
    https://example.com/path    # scheme and path are kept
    http://example.com          # default port 80
    192.0.2.10
    192.0.2.10:8443
    [2001:db8::1]:443           # IPv6 with an explicit port
    2001:db8::1                 # bare IPv6, default port
    admin@example.com           # the user part is ignored

A host given without a port is expanded across every port in ``ports`` (from
``-p``), so "one host, several ports" produces one target per port. A host that
names its own port keeps it and is not expanded.

Files use one target per line. ``#`` starts a comment; anything after the first
whitespace-separated token becomes the target's label.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, TextIO, Tuple

from .models import Target

__all__ = [
    "DEFAULT_PORT",
    "TargetError",
    "build_targets",
    "parse_ports",
    "parse_target",
    "read_target_file",
]

DEFAULT_PORT = 443
_SCHEME_PORTS = {"https": 443, "http": 80}
_MAX_PORT = 65535


class TargetError(ValueError):
    """Raised when a target specification cannot be understood."""


@dataclass(frozen=True)
class _Spec:
    """A parsed specification, before the port is resolved to a number."""

    scheme: str
    scheme_explicit: bool
    host: str
    port: Optional[int]
    path: str


def parse_ports(text: str) -> List[int]:
    """Parse a ``-p`` value such as ``443,8443`` into a list of port numbers."""
    ports: List[int] = []
    for piece in text.split(","):
        token = piece.strip()
        if not token:
            continue
        ports.append(_parse_port(token, text))
    if not ports:
        raise TargetError(f"no port numbers in '{text}'")
    return ports


def parse_target(
    spec: str,
    default_port: int = DEFAULT_PORT,
    sni: Optional[str] = None,
    label: Optional[str] = None,
    source: Optional[str] = None,
) -> Target:
    """Turn one specification string into a single :class:`~.models.Target`."""
    parsed = _parse_spec(spec)
    port = parsed.port if parsed.port is not None else _default_port(parsed, default_port)
    return Target(
        host=parsed.host,
        port=port,
        scheme=parsed.scheme,
        sni=sni,
        path=parsed.path,
        label=label,
        source=source,
    )


def _default_port(parsed: _Spec, fallback: int) -> int:
    """The port to use when the specification named none.

    An explicit scheme fixes the port it implies; a bare host takes the caller's
    fallback, which is 443 unless ``-p`` supplied something else.
    """
    if parsed.scheme_explicit:
        return _SCHEME_PORTS[parsed.scheme]
    return fallback


def _parse_spec(spec: str) -> _Spec:
    """Split a specification into scheme, host, optional port and path."""
    text = spec.strip()
    if not text:
        raise TargetError("empty target")

    scheme = "https"
    scheme_explicit = False
    for candidate in ("https://", "http://"):
        if text.lower().startswith(candidate):
            scheme = candidate[:-3]
            scheme_explicit = True
            text = text[len(candidate) :]
            break

    path = "/"
    slash = text.find("/")
    if slash >= 0:
        # slash >= 0 means text[slash:] starts with '/', so it is never empty.
        path = text[slash:]
        text = text[:slash]

    if "@" in text:
        _user, _, text = text.rpartition("@")
        if not text:
            raise TargetError(f"missing host name in '{spec}'")

    host, port = _split_host_port(text, spec)

    if not host:
        raise TargetError(f"missing host name in '{spec}'")
    if any(character.isspace() for character in host):
        raise TargetError(f"host name contains whitespace: '{spec}'")
    # The port range is enforced in _parse_port, the single place a port number
    # is produced, so there is no second check to drift out of step with it.

    return _Spec(scheme=scheme, scheme_explicit=scheme_explicit, host=host, port=port, path=path)


def _split_host_port(text: str, spec: str) -> Tuple[str, Optional[int]]:
    """Split a ``host[:port]`` string, coping with IPv6 literals."""
    if text.startswith("["):
        closing = text.find("]")
        if closing < 0:
            raise TargetError(f"unbalanced '[' in '{spec}'")
        host = text[1:closing]
        remainder = text[closing + 1 :]
        if not remainder:
            return host, None
        if not remainder.startswith(":"):
            raise TargetError(f"unexpected text after ']' in '{spec}'")
        return host, _parse_port(remainder[1:], spec)

    # More than one colon means a bare IPv6 literal: there is no way to tell a
    # port apart from another group, so the whole string is the address.
    if text.count(":") > 1:
        return text, None

    if ":" in text:
        host, _, port_text = text.partition(":")
        return host, _parse_port(port_text, spec)

    return text, None


def _parse_port(text: str, spec: str) -> int:
    port_text = text.strip()
    if not port_text:
        raise TargetError(f"missing port number after ':' in '{spec}'")
    # Deliberately not str.isdigit(): that accepts superscripts and other
    # Unicode digits, which either crash int() or silently parse as a different
    # number than the one that was typed.
    if not all(character in "0123456789" for character in port_text):
        raise TargetError(f"invalid port '{port_text}' in '{spec}'")
    port = int(port_text)
    if not 1 <= port <= _MAX_PORT:
        raise TargetError(f"port out of range in '{spec}': {port}")
    return port


def _expand(parsed: _Spec, ports: Sequence[int], sni: Optional[str],
            label: Optional[str], source: str) -> List[Target]:
    """One target per port: the named port if any, else every port in ``ports``."""
    if parsed.port is not None:
        chosen: List[int] = [parsed.port]
    elif ports:
        chosen = list(ports)
    else:
        chosen = [_default_port(parsed, DEFAULT_PORT)]
    return [
        Target(
            host=parsed.host,
            port=port,
            scheme=parsed.scheme,
            sni=sni,
            path=parsed.path,
            label=label,
            source=source,
        )
        for port in chosen
    ]


def read_target_file(
    path: Path,
    ports: Sequence[int] = (),
    sni: Optional[str] = None,
) -> Tuple[List[Target], List[str]]:
    """Read a target list file, returning ``(targets, errors)``.

    A single malformed line does not abort the run: the error is collected and
    reported so a long inventory can still be scanned.
    """
    targets: List[Target] = []
    errors: List[str] = []

    handle: TextIO
    if str(path) == "-":
        handle = sys.stdin
        display_name = "<stdin>"
        close_handle = False
    else:
        try:
            handle = path.open("r", encoding="utf-8")
        except OSError as exc:
            raise TargetError(f"cannot read target file {path}: {exc}") from exc
        display_name = str(path)
        close_handle = True

    try:
        for number, raw_line in enumerate(handle, start=1):
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            fields = line.split()
            spec = fields[0]
            label = " ".join(fields[1:]) or None
            source = f"{display_name}:{number}"
            try:
                parsed = _parse_spec(spec)
            except TargetError as exc:
                # _parse_spec never names the line, so the source is always
                # added here; there is no already-prefixed case to guard.
                errors.append(f"{source}: {exc}")
                continue
            targets.extend(_expand(parsed, ports, sni, label, source))
    finally:
        if close_handle:
            handle.close()

    return targets, errors


def build_targets(
    specs: Sequence[str],
    files: Iterable[Path] = (),
    ports: Sequence[int] = (),
    sni: Optional[str] = None,
) -> Tuple[List[Target], List[str]]:
    """Collect targets from command line arguments and files.

    Each host without its own port is expanded across ``ports``. Duplicates
    (same host and port) are removed, keeping the first occurrence so its label
    and path survive.
    """
    targets: List[Target] = []
    errors: List[str] = []

    for spec in specs:
        try:
            parsed = _parse_spec(spec)
        except TargetError as exc:
            errors.append(str(exc))
            continue
        targets.extend(_expand(parsed, ports, sni, None, "command line"))

    for path in files:
        file_targets, file_errors = read_target_file(path, ports=ports, sni=sni)
        targets.extend(file_targets)
        errors.extend(file_errors)

    seen = set()
    unique: List[Target] = []
    for target in targets:
        key = (target.host.lower(), target.port)
        if key in seen:
            continue
        seen.add(key)
        unique.append(target)

    return unique, errors
