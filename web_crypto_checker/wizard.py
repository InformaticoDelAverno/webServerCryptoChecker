"""Interactive wizard: build a command line by answering questions.

The wizard never scans anything itself. It assembles the exact ``argv`` a normal
invocation would take, prints it back as a copy-pasteable command, and hands it
to :func:`web_crypto_checker.cli.main` to run -- so what it shows and what it
runs are the same thing by construction, and the printed command can be saved
and re-run later without the wizard.

``ask`` and ``emit`` are injected so the whole flow is testable without a
terminal: ``ask(prompt)`` returns a line of input, ``emit(line)`` writes a line
of output. ``t`` is a :class:`web_crypto_checker.i18n.Translator`, so every
string comes out in the chosen language.
"""

from __future__ import annotations

import shlex
from typing import Callable, List, Optional, Sequence

from .i18n import Translator

Ask = Callable[[str], str]
Emit = Callable[[str], None]

#: Accepted inputs, language-independent so either language's user is understood.
_YES = frozenset({"s", "si", "sí", "y", "yes"})
_NO = frozenset({"n", "no"})
_ALL = frozenset({"a", "all", "todas", "*"})
_NONE = frozenset({"n", "none", "ninguna"})

#: The default TLS port; the wizard only adds -p when the user picks another.
_DEFAULT_PORT = 443
_DEFAULT_TIMEOUT = 10
_DEFAULT_CONCURRENCY = 1


# --------------------------------------------------------------------------- #
# Prompt primitives
# --------------------------------------------------------------------------- #


def _ask_text(ask: Ask, prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    raw = ask(f"{prompt}{suffix}: ").strip()
    return raw if raw else default


def _ask_yes_no(ask: Ask, emit: Emit, t: Translator, prompt: str, default: bool = False) -> bool:
    hint = t("ui.yes_no_default_yes") if default else t("ui.yes_no_default_no")
    while True:
        raw = ask(f"{prompt} [{hint}]: ").strip().lower()
        if not raw:
            return default
        if raw in _YES:
            return True
        if raw in _NO:
            return False
        emit(t("ui.yes_no_retry"))


def _ask_int(ask: Ask, emit: Emit, t: Translator, prompt: str, default: int) -> int:
    while True:
        raw = ask(f"{prompt} [{default}]: ").strip()
        if not raw:
            return default
        try:
            return int(raw)
        except ValueError:
            emit(t("ui.int_retry"))


def _ask_multi(
    ask: Ask,
    emit: Emit,
    t: Translator,
    prompt: str,
    options: Sequence[str],
    *,
    default_all: bool,
) -> List[str]:
    """Multi-select with all/none. Returns the chosen subset (order preserved)."""
    emit(prompt)
    for i, opt in enumerate(options, 1):
        emit(f"  {i}) {opt}")
    default_label = t("ui.default_label_all") if default_all else t("ui.default_label_none")
    emit(t("ui.multi_hint"))
    while True:
        raw = ask(t("ui.multi_prompt", label=default_label)).strip().lower()
        if not raw:
            return list(options) if default_all else []
        if raw in _ALL:
            return list(options)
        if raw in _NONE:
            return []
        picked: List[str] = []
        ok = True
        for tok in raw.replace(" ", "").split(","):
            if tok.isdigit() and 1 <= int(tok) <= len(options):
                choice = options[int(tok) - 1]
                if choice not in picked:
                    picked.append(choice)
            else:
                emit(t("ui.multi_bad_token", token=tok, n=len(options)))
                ok = False
                break
        if ok:
            return picked


# --------------------------------------------------------------------------- #
# The wizard
# --------------------------------------------------------------------------- #


def run_wizard(
    profile_ids: Sequence[str],
    formats: Sequence[str],
    *,
    ask: Ask,
    emit: Emit,
    t: Translator,
    profile_labels: Optional[dict] = None,
) -> Optional[List[str]]:
    """Ask the questions and return the argv to run, or None if cancelled/declined.

    ``profile_ids`` are the conformance profile identifiers, ``formats`` the
    available output formats, ``t`` the translator, and ``profile_labels`` maps
    an id to a human-readable description so the menu shows what each profile is;
    the id is still what the command uses.
    """
    argv: List[str] = []
    labels = profile_labels or {}

    def _option(pid: str) -> str:
        return f"{pid}   {labels[pid]}" if pid in labels else pid

    emit("")
    emit(t("wiz.title"))
    emit(t("wiz.intro"))
    emit(t("wiz.default_hint"))
    emit("")

    # 1. Targets -----------------------------------------------------------
    emit(t("wiz.sec_targets"))
    hosts = _ask_text(ask, t("wiz.target_prompt"), default="")
    targets = hosts.split() if hosts else []
    argv.extend(targets)

    inventory = _ask_text(ask, t("wiz.inventory_prompt"), default="")
    if inventory:
        argv += ["-f", inventory]

    if not targets and not inventory:
        emit(t("wiz.no_target_hint"))
        hosts = _ask_text(ask, t("wiz.target_reprompt"), default="")
        if hosts:
            targets = hosts.split()
            argv[:0] = targets  # positionals go first
        else:
            emit(t("wiz.cancelled_no_target"))
            return None

    sni = _ask_text(ask, t("wiz.sni_prompt"), default="")
    if sni:
        argv += ["--sni", sni]

    port = _ask_int(ask, emit, t, t("wiz.port_prompt"), _DEFAULT_PORT)
    if port != _DEFAULT_PORT:
        argv += ["-p", str(port)]

    # 2. Profiles ----------------------------------------------------------
    emit("")
    emit(t("wiz.sec_profiles"))
    emit(t("wiz.profiles_intro"))
    if profile_ids:
        emit("")
        chosen = _ask_multi(
            ask,
            emit,
            t,
            t("wiz.evaluate_prompt"),
            [_option(pid) for pid in profile_ids],
            default_all=False,
        )
        for option in chosen:
            argv += ["--profile", option.split()[0]]

    # 3. Output ------------------------------------------------------------
    emit("")
    emit(t("wiz.sec_output"))
    chosen_formats = _ask_multi(
        ask,
        emit,
        t,
        t("wiz.format_prompt"),
        list(formats),
        default_all=False,
    )
    if chosen_formats and chosen_formats != ["console"]:
        argv += ["--format", ",".join(chosen_formats)]

    needs_file = bool(chosen_formats) and chosen_formats != ["console"]
    if needs_file or _ask_yes_no(ask, emit, t, t("wiz.write_file_gate"), default=needs_file):
        path = _ask_text(ask, t("wiz.output_path_prompt"), default="report")
        argv += ["-o", path]

    # 4. Scanning ----------------------------------------------------------
    if _ask_yes_no(ask, emit, t, t("wiz.scanning_gate"), default=False):
        emit("")
        emit(t("wiz.sec_scanning"))
        timeout = _ask_int(ask, emit, t, t("wiz.timeout_prompt"), _DEFAULT_TIMEOUT)
        if timeout != _DEFAULT_TIMEOUT:
            argv += ["-t", str(timeout)]
        concurrency = _ask_int(ask, emit, t, t("wiz.concurrency_prompt"), _DEFAULT_CONCURRENCY)
        if concurrency != _DEFAULT_CONCURRENCY:
            argv += ["-c", str(concurrency)]

    # 5. Trust store -------------------------------------------------------
    if _ask_yes_no(ask, emit, t, t("wiz.trust_gate"), default=False):
        emit("")
        emit(t("wiz.sec_trust"))
        if _ask_yes_no(ask, emit, t, t("wiz.no_trust_gate"), default=False):
            argv += ["--no-trust"]
        else:
            ca_bundle = _ask_text(ask, t("wiz.ca_bundle_prompt"), default="")
            if ca_bundle:
                argv += ["--ca-bundle", ca_bundle]

    # 6. Active probes -----------------------------------------------------
    emit("")
    emit(t("wiz.active_warning"))
    if _ask_yes_no(ask, emit, t, t("wiz.active_gate"), default=False):
        argv += ["--active"]

    # 7. History / compare -------------------------------------------------
    if _ask_yes_no(ask, emit, t, t("wiz.history_gate"), default=False):
        emit("")
        emit(t("wiz.sec_history"))
        history_path = _ask_text(ask, t("wiz.history_prompt"), default="")
        if history_path:
            argv += ["--history", history_path]
        compare_path = _ask_text(ask, t("wiz.compare_prompt"), default="")
        if compare_path:
            argv += ["--compare", compare_path]
            if _ask_yes_no(ask, emit, t, t("wiz.regression_gate"), default=False):
                argv += ["--fail-on-regression"]

    # 8. Plugins -----------------------------------------------------------
    if _ask_yes_no(ask, emit, t, t("wiz.plugins_gate"), default=False):
        plugin_dir = _ask_text(ask, t("wiz.plugin_dir_prompt"), default="")
        if plugin_dir:
            argv += ["--plugin-dir", plugin_dir]

    # 9. Show and offer to run --------------------------------------------
    # The wizard's language travels into the command it builds: without this, a
    # wizard run with --lang es would assemble a command whose reports come out
    # in whatever the machine's locale says on any machine it is later run on.
    argv += ["--lang", t.language]
    command = "web-crypto-checker " + " ".join(shlex.quote(tok) for tok in argv)
    emit("")
    emit(t("wiz.command_header"))
    emit(f"  {command}")
    emit("")
    emit(t("wiz.command_save"))

    if _ask_yes_no(ask, emit, t, t("wiz.launch_gate"), default=True):
        return argv
    emit(t("wiz.declined"))
    return None
