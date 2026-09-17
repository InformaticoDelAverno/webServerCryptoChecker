"""Command line interface.

Resolves targets, scans them, and writes one or more reports. The formats live
in :mod:`web_crypto_checker.reporting`; this only parses the command line, runs
the scan and hands the result to the format the caller asked for.
"""

from __future__ import annotations

import argparse
import socket
import sys
from pathlib import Path
from typing import Callable, List, Optional, Sequence

from . import PRODUCT_NAME, __version__, history, reporting
from .compare import CompareError, compare, load_baseline
from .compliance import load_profile_editions, load_profiles
from .i18n import DEFAULT_LANGUAGE, Translator, resolve_language
from .messages import MESSAGES
from .models import SEVERITY_ORDER, ScanReport, Severity
from .pki.certificates import load_trust_store
from .plugins import load_plugins
from .policy import Policy, PolicyError, default_policy_path
from .reporting import RenderOptions
from .scanner import scan
from .targets import TargetError, build_targets, parse_ports
from .tls.probe import DEFAULT_TIMEOUT

__all__ = ["build_parser", "main"]


def build_parser(t: Optional[Translator] = None) -> argparse.ArgumentParser:
    """Build the argument parser, with help text in the translator's language.

    ``t`` defaults to English, which is what the documentation tests, the MCP
    server (whose tool schema is derived from this parser) and any other caller
    that does not care about language get. ``main`` passes a translator resolved
    from ``--lang`` (or the locale) so ``--help`` comes out in the chosen
    language. Public on purpose.
    """
    if t is None:
        t = Translator(DEFAULT_LANGUAGE, MESSAGES)
    parser = argparse.ArgumentParser(
        prog="web-crypto-checker",
        description=t("cli.desc"),
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help=t("cli.h.targets"),
    )
    parser.add_argument(
        "-w",
        "--wizard",
        action="store_true",
        help=t("cli.wizard.help"),
    )
    parser.add_argument(
        "--lang",
        metavar=t("cli.mv.lang"),
        help=t("cli.lang.help"),
    )
    parser.add_argument(
        "-p",
        "--port",
        metavar=t("cli.mv.port"),
        help=t("cli.h.port"),
    )
    parser.add_argument(
        "-f",
        "--file",
        action="append",
        default=[],
        metavar=t("cli.mv.path"),
        help=t("cli.h.file"),
    )
    parser.add_argument(
        "--sni",
        help=t("cli.h.sni"),
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        metavar=t("cli.mv.seconds"),
        help=t("cli.h.timeout", default=f"{DEFAULT_TIMEOUT:g}"),
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=1,
        metavar=t("cli.mv.n"),
        help=t("cli.h.concurrency"),
    )
    parser.add_argument(
        "--format",
        default="console",
        metavar=t("cli.mv.names"),
        help=t("cli.h.format", formats=", ".join(reporting.available_formats())),
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar=t("cli.mv.path"),
        help=t("cli.h.output"),
    )
    parser.add_argument(
        "--profile",
        action="append",
        default=[],
        metavar=t("cli.mv.id"),
        help=t("cli.h.profile"),
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help=t("cli.h.list_profiles"),
    )
    parser.add_argument(
        "--list-vulnerabilities",
        action="store_true",
        help=t("cli.h.list_vulnerabilities"),
    )
    parser.add_argument(
        "--show-policy",
        action="store_true",
        help=t("cli.h.show_policy"),
    )
    parser.add_argument(
        "--plugin-dir",
        action="append",
        default=[],
        metavar=t("cli.mv.dir"),
        help=t("cli.h.plugin_dir"),
    )
    parser.add_argument(
        "--list-plugins",
        action="store_true",
        help=t("cli.h.list_plugins"),
    )
    parser.add_argument(
        "--compare",
        metavar=t("cli.mv.baseline"),
        help=t("cli.h.compare"),
    )
    parser.add_argument(
        "--history",
        metavar=t("cli.mv.path"),
        help=t("cli.h.history"),
    )
    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help=t("cli.h.fail_on_regression"),
    )
    parser.add_argument(
        "--active",
        action="store_true",
        help=t("cli.h.active"),
    )
    parser.add_argument(
        "--ca-bundle",
        metavar=t("cli.mv.path"),
        help=t("cli.h.ca_bundle"),
    )
    parser.add_argument(
        "--no-trust",
        action="store_true",
        help=t("cli.h.no_trust"),
    )
    parser.add_argument(
        "-r",
        "--retries",
        type=int,
        default=1,
        metavar=t("cli.mv.n"),
        help=t("cli.h.retries"),
    )
    family = parser.add_mutually_exclusive_group()
    family.add_argument(
        "-4",
        "--ipv4",
        action="store_true",
        help=t("cli.h.ipv4"),
    )
    family.add_argument(
        "-6",
        "--ipv6",
        action="store_true",
        help=t("cli.h.ipv6"),
    )
    parser.add_argument(
        "--require-profile",
        dest="require_profile",
        action="append",
        default=[],
        metavar=t("cli.mv.id"),
        help=t("cli.h.require_profile"),
    )
    parser.add_argument(
        "--fail-on",
        choices=["never", "critical", "high", "medium", "low", "info"],
        default="never",
        help=t("cli.h.fail_on"),
    )
    parser.add_argument(
        "--history-report",
        action="store_true",
        help=t("cli.h.history_report"),
    )
    parser.add_argument(
        "--export-policy",
        metavar=t("cli.mv.path"),
        help=t("cli.h.export_policy"),
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help=t("cli.h.quiet"),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help=t("cli.h.verbose"),
    )
    parser.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help=t("cli.h.color"),
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help=t("cli.h.no_color"),
    )
    parser.add_argument(
        "-s",
        "--summary-only",
        action="store_true",
        help=t("cli.h.summary_only"),
    )
    parser.add_argument(
        "--notes",
        action="store_true",
        help=t("cli.h.notes"),
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help=t("cli.h.version"),
    )
    return parser


def _parse_formats(value: str) -> Optional[List[str]]:
    """The requested formats, or ``None`` if one is not a real format."""
    formats: List[str] = []
    for chunk in value.split(","):
        name = chunk.strip()
        if not name:
            continue
        if name not in reporting.FORMATS:
            available = ", ".join(reporting.available_formats())
            print(f"error: unknown format '{name}' (choose from {available})", file=sys.stderr)
            return None
        formats.append(name)
    return formats or ["console"]


def _emit(
    report: ScanReport,
    formats: List[str],
    output: Optional[str],
    language: str,
    options: Optional[RenderOptions] = None,
) -> None:
    for name in formats:
        rendered = reporting.render(report, name, language, options)
        if output is None:
            print(rendered)
        elif len(formats) == 1:
            Path(output).write_text(rendered + "\n", encoding="utf-8")
        else:
            Path(f"{output}.{reporting.EXTENSIONS[name]}").write_text(
                rendered + "\n", encoding="utf-8"
            )


def _prescan_language(argv: Optional[Sequence[str]]) -> Optional[str]:
    """Read ``--lang`` off the raw argv before argparse builds its (translated) help."""
    tokens = list(sys.argv[1:] if argv is None else argv)
    for index, token in enumerate(tokens):
        if token == "--lang" and index + 1 < len(tokens):
            return tokens[index + 1]
        if token.startswith("--lang="):
            return token[len("--lang=") :]
    return None


def _print_vulnerabilities(policy: Policy) -> None:
    """List the known vulnerabilities the policy checks (for ``--list-vulnerabilities``)."""
    for vulnerability in policy.vulnerabilities():
        severity = vulnerability.get("severity", "?")
        print(f"{vulnerability.get('id', '?')}  [{severity}]")
        if vulnerability.get("name"):
            print(f"  {vulnerability['name']}")
        if vulnerability.get("description"):
            print(f"  {vulnerability['description']}")
        references = vulnerability.get("references") or []
        if references:
            print(f"  see: {', '.join(references)}")
        print()


def _threshold_exceeded(report: ScanReport, fail_on: str) -> bool:
    """Whether any endpoint carries a finding at or above the ``--fail-on`` severity."""
    if fail_on == "never":
        return False
    limit = SEVERITY_ORDER.index(Severity(fail_on))
    for result in report.results:
        worst = result.worst_severity()
        if worst is not None and SEVERITY_ORDER.index(worst) <= limit:
            return True
    return False


def _profile_not_met(report: ScanReport, required: Sequence[str]) -> bool:
    """Whether any scanned endpoint fails a profile the caller demanded with --require-profile.

    Asked of the compliance result, not of an absence: a profile that could not be
    tested (``not-assessed``) has not conformed, so a scan that never gathered the
    evidence must not pass a gate the way a scan that proved conformance does.
    """
    if not required:
        return False
    return any(
        not entry.conforms
        for result in report.results
        for entry in result.compliance
        if entry.profile_id in required
    )


def _use_color(color: str, no_color: bool, output: Optional[str]) -> bool:
    """Resolve --color / --no-color to a yes/no for the terminal report.

    ``never`` (or ``--no-color``) is off; a file destination is always off (escape
    sequences do not belong in one); otherwise ``always`` is on and ``auto`` colours
    only a real terminal.
    """
    if no_color or color == "never":
        return False
    if output is not None:
        return False
    if color == "always":
        return True
    return sys.stdout.isatty()


def _progress_callback(quiet: bool, total: int) -> Optional[Callable[[], None]]:
    """A per-target progress counter on stderr, or ``None`` when --quiet asked for silence."""
    if quiet:
        return None
    state = {"done": 0}

    def on_finish() -> None:
        state["done"] += 1
        sys.stderr.write(f"\r[{state['done']}/{total}] scanning...")
        if state["done"] == total:
            sys.stderr.write("\r" + " " * 32 + "\r")
        sys.stderr.flush()

    return on_finish


def _export_policy(destination: Path) -> int:
    """Write a copy of the bundled scoring policy to ``destination`` and exit."""
    if destination.exists():
        print(f"error: {destination} already exists; refusing to overwrite it", file=sys.stderr)
        return 2
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            default_policy_path().read_text(encoding="utf-8"), encoding="utf-8"
        )
    except OSError as exc:
        print(f"error: could not write {destination}: {exc}", file=sys.stderr)
        return 2
    print(f"Wrote {destination}", file=sys.stderr)
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    translator = Translator(resolve_language(_prescan_language(argv)), MESSAGES)
    parser = build_parser(translator)
    args = parser.parse_args(argv)

    if args.wizard:
        if not sys.stdin.isatty():
            print(translator("cli.err.wizard_needs_tty"), file=sys.stderr)
            return 2
        from .wizard import run_wizard

        profiles_available = load_profiles()
        fmt_options = ["console", *sorted(n for n in reporting.FORMATS if n != "console")]
        profile_labels = {pid: profile.name for pid, profile in profiles_available.items()}
        built = run_wizard(
            sorted(profiles_available),
            fmt_options,
            ask=input,
            emit=lambda line: print(line),
            t=translator,
            profile_labels=profile_labels,
        )
        if built is None:
            return 0
        return main(built)

    if args.version:
        print(f"{PRODUCT_NAME} {__version__}")
        return 0

    if args.export_policy:
        return _export_policy(Path(args.export_policy))

    available_profiles = load_profiles()
    profile_editions = load_profile_editions()
    if args.list_profiles:
        for profile_id in sorted(available_profiles):
            profile = available_profiles[profile_id]
            edition = f"  [{profile.edition_id}]" if profile.edition_id else ""
            print(f"{profile_id}  {profile.name}{edition}")
        return 0

    if args.show_policy or args.list_vulnerabilities:
        try:
            policy = Policy.load(language=translator.language)
        except PolicyError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if args.show_policy:
            for line in policy.describe():
                print(line)
        else:
            _print_vulnerabilities(policy)
        return 0

    plugin_dirs = [Path(directory) for directory in args.plugin_dir]
    plugins, plugin_problems = load_plugins(plugin_dirs or None)
    for problem in plugin_problems:
        print(f"warning: {problem}", file=sys.stderr)
    if args.list_plugins:
        for plugin in plugins:
            print(f"{plugin.id}  [{plugin.kind}]  {plugin.name}")
        return 0

    formats = _parse_formats(args.format)
    if formats is None:
        return 2

    if not args.targets and not args.file:
        parser.print_help(sys.stderr)
        return 2

    selected_profiles = []
    for selector in args.profile:
        resolved = available_profiles.get(selector) or profile_editions.get(selector)
        if resolved is None:
            print(f"error: unknown profile '{selector}' (see --list-profiles)", file=sys.stderr)
            return 2
        selected_profiles.append(resolved)

    # --require-profile is --profile plus a gate: the profile has to be evaluated
    # (so it joins the selected set) and every endpoint has to conform, or the run
    # exits 1.
    required_profile_ids: List[str] = []
    for selector in args.require_profile:
        resolved = available_profiles.get(selector) or profile_editions.get(selector)
        if resolved is None:
            print(f"error: unknown profile '{selector}' (see --list-profiles)", file=sys.stderr)
            return 2
        if resolved not in selected_profiles:
            selected_profiles.append(resolved)
        if resolved.id not in required_profile_ids:
            required_profile_ids.append(resolved.id)

    ports: List[int] = []
    if args.port:
        try:
            ports = parse_ports(args.port)
        except TargetError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    files = [Path(name) for name in args.file]
    try:
        targets, errors = build_targets(args.targets, files=files, ports=ports, sni=args.sni)
    except TargetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for error in errors:
        print(f"warning: {error}", file=sys.stderr)

    if not targets:
        print("no targets to scan", file=sys.stderr)
        return 1

    if args.active:
        print(
            "warning: --active sends crafted, possibly disruptive probes; "
            "run it only against servers you are authorised to test",
            file=sys.stderr,
        )
    trust_store = None if args.no_trust else load_trust_store(args.ca_bundle)
    command_line = " ".join(sys.argv)  # the real invocation of this CLI entry point
    address_family = (
        socket.AF_INET if args.ipv4 else socket.AF_INET6 if args.ipv6 else socket.AF_UNSPEC
    )
    if not args.quiet:
        print(f"Scanning {len(targets)} target(s)...", file=sys.stderr)
    report = scan(
        targets,
        timeout=args.timeout,
        concurrency=args.concurrency,
        profiles=selected_profiles,
        plugins=plugins,
        active=args.active,
        trust_store=trust_store,
        command_line=command_line,
        language=translator.language,
        retries=args.retries,
        address_family=address_family,
        progress=_progress_callback(args.quiet, len(targets)),
    )
    if args.verbose and not args.quiet:
        for index, result in enumerate(report.results, start=1):
            status = result.grade if result.ok else "unreachable"
            print(
                f"[{index}/{len(report.results)}] "
                f"{result.target.display_name} [{result.ip or '-'}]: {status}",
                file=sys.stderr,
            )
    options = RenderOptions(
        color=_use_color(args.color, args.no_color, args.output),
        summary_only=args.summary_only,
        notes=args.notes,
    )
    _emit(report, formats, args.output, translator.language, options)

    exit_code = 0 if report.summary.succeeded else 1
    if args.history:
        history_path = Path(args.history)
        history.append(report, history_path)
        print("\nGrade history:")
        for line in history.trend(report, history_path):
            print(f"  {line}")
    if args.history_report:
        if args.history:
            print("\nEstate movement:")
            for line in history.summarise(report, Path(args.history)):
                print(f"  {line}")
        else:
            print("warning: --history-report needs --history", file=sys.stderr)
    if args.compare:
        try:
            baseline = load_baseline(Path(args.compare))
        except CompareError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        comparison = compare(report, baseline)
        if comparison.changes:
            print("\nChanges since the baseline:")
            for change in comparison.changes:
                print(f"  {change}")
        else:
            print("\nNo changes since the baseline.")
        if args.fail_on_regression and comparison.regressed:
            exit_code = 1
    if _profile_not_met(report, required_profile_ids):
        exit_code = 1
    if _threshold_exceeded(report, args.fail_on):
        exit_code = 1
    return exit_code
