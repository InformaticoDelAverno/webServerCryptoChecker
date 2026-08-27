"""A small web front end over the same scan the command line runs.

An ADDITIONAL way in, not a replacement: the page collects the same options the
CLI takes, the scan is the same ``scan()`` evaluating the same compliance
profiles, and the report is the same ``render()`` -- downloadable in every
format the tool defines. Zero dependencies, like everything else here: the
server is ``http.server`` from the standard library.

Run it with::

    python -m web_crypto_checker.web [--host 127.0.0.1] [--port 8443]

Deployment-time functionality arrives the way containers expect, not through
web forms:

- **Detection plugins**: set ``WEB_CRYPTO_CHECKER_WEB_PLUGIN_DIR`` (path-separated
  directories); loaded once at start-up, exactly as ``--plugin-dir`` would.
- **Access token** (optional): set ``WEB_CRYPTO_CHECKER_WEB_TOKEN`` and every
  ``/api/*`` request must carry it (``X-Auth-Token`` header, constant-time
  compare). Leave it unset -- the default -- for **open access**: anyone who
  reaches the port uses it, on any interface, no accounts, no sign-in. That is
  the frictionless shape on a trusted LAN; setting the token is the one switch
  that closes it. For an internet-facing deployment pair the token with the
  private-target filter below and a TLS-terminating proxy.
- **Refuse internal targets**: set ``WEB_CRYPTO_CHECKER_WEB_BLOCK_PRIVATE=1``
  and a target that resolves to a private, loopback, link-local or reserved
  address is turned away. Defence in depth for an internet-facing deployment.
- **Trust store**: chains validate against the system store by default. Point
  ``WEB_CRYPTO_CHECKER_WEB_CA_BUNDLE`` at a PEM file to use your own roots, or
  set ``WEB_CRYPTO_CHECKER_WEB_NO_TRUST=1`` to skip chain validation entirely
  (the ``--ca-bundle`` / ``--no-trust`` of the CLI).

What deliberately stays CLI-only: ``--active`` (the crafted, possibly disruptive
probes) is OFF in the web unless a deployment opts in with
``WEB_CRYPTO_CHECKER_WEB_ALLOW_ACTIVE=1`` -- an open service that fires attack
traffic at whatever host a stranger names is an abuse amplifier, so the switch
is a deployment decision, never a form field. History and comparison stay on the
command line: they live on the operator's filesystem.

Security posture (what this layer is, and is not):

- The web layer caps every dimension an anonymous caller could inflate -- body
  size, target count, concurrency, timeout, and the number of scans running at
  once -- so a request cannot exhaust the service. Responses carry ``nosniff``,
  ``X-Frame-Options: DENY``, a strict ``Content-Security-Policy`` and
  ``Referrer-Policy: no-referrer``; reports download as attachments; the token
  compare is constant time; the report renderer escapes everything a scanned
  server controls (a hostile banner cannot inject script). ``tests/test_web.py``
  holds all of this.
- Two things it cannot fix in code, only at the boundary. First, scanning
  arbitrary hosts IS the tool's function, so an open deployment is an SSRF
  machine: gate it with the token, the private-target filter, and network
  placement (an egress firewall with no route to your internal ranges is the
  hard guarantee the app-level filter only approximates). Second,
  ``http.server`` is the standard library's basic server, not a hardened edge:
  for the open internet put it behind a reverse proxy that terminates TLS,
  rate-limits, and rejects malformed requests. Treat this as an internal tool
  unless you have done both.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import tempfile
import threading
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .. import PRODUCT_NAME, __version__
from ..compliance import Profile, load_profiles
from ..models import ScanReport, ScanSummary
from ..pki.certificates import TrustStore, load_trust_store
from ..plugins import Plugin, load_plugins
from ..reporting import EXTENSIONS, FORMATS, render
from ..scanner import scan
from ..targets import DEFAULT_PORT, TargetError, build_targets, parse_ports

__all__ = ["create_server", "main"]

#: Set truthy to REQUIRE a token: every /api request must then carry a matching
#: X-Auth-Token. Unset (the default) the API is OPEN -- anyone who can reach the
#: port uses it, no accounts, no sign-in. Setting a token is the one switch that
#: closes it; on a public edge pair it with BLOCK_PRIVATE_VAR and a TLS proxy.
TOKEN_VAR = "WEB_CRYPTO_CHECKER_WEB_TOKEN"
PLUGIN_VAR = "WEB_CRYPTO_CHECKER_WEB_PLUGIN_DIR"
#: When set to a truthy value, a target that resolves to a private, loopback,
#: link-local or otherwise-reserved address is refused. Defence in depth for an
#: internet-facing deployment: it stops the obvious "use your scanner to reach
#: my internal network / 169.254.169.254" abuse. It is BEST EFFORT (a name can
#: rebind between this check and the scan's own resolve); the hard guarantee is
#: network egress control, documented beside it.
BLOCK_PRIVATE_VAR = "WEB_CRYPTO_CHECKER_WEB_BLOCK_PRIVATE"
#: A PEM bundle of roots to validate chains against, in place of the system
#: store (the CLI's --ca-bundle).
CA_BUNDLE_VAR = "WEB_CRYPTO_CHECKER_WEB_CA_BUNDLE"
#: Truthy: do not validate the certificate chain against any store (--no-trust).
NO_TRUST_VAR = "WEB_CRYPTO_CHECKER_WEB_NO_TRUST"
#: Truthy: allow the active (crafted, possibly disruptive) probes. OFF by
#: default because an open service firing attack traffic at arbitrary hosts is
#: an abuse amplifier; turning it on is a deployment decision.
ALLOW_ACTIVE_VAR = "WEB_CRYPTO_CHECKER_WEB_ALLOW_ACTIVE"

#: Finished jobs kept for download. Oldest evicted beyond this; a container
#: serving one team does not need more, and unbounded memory is a bug.
MAX_JOBS = 64

# --- Resource ceilings. Every dimension an anonymous caller could inflate has
# a cap, because "publish it on the internet" means someone will try. Generous
# for real use, finite against abuse. --------------------------------------- #
#: Largest request body accepted, before it is read (a huge Content-Length must
#: not turn into a huge allocation). Covers targets + a pasted inventory.
MAX_BODY_BYTES = 2 * 1024 * 1024
#: Most targets one request may ask for. Beyond this it is a scan of somebody
#: else's estate, or an attempt to tie up the service.
MAX_TARGETS = 2048
#: Scans allowed to run at once across all callers. Past this the answer is
#: 503, not an unbounded pile of threads and sockets.
MAX_RUNNING_JOBS = 8
#: Handler threads (TCP connections) allowed at once. Bounds the one dimension
#: the token cannot -- a connection is accepted, and its thread spawned, before
#: auth runs -- so a flood cannot exhaust threads/FDs anonymously. The reverse
#: proxy is still the real edge; this is the in-process floor.
MAX_CONNECTIONS = 64
#: Upper bounds on the numeric knobs, so none can be set to "occupy a worker
#: forever". Lower than the CLI's, on purpose: a shared public form is not an
#: operator tuning their own ulimit.
LIMITS = {
    "timeout": (0.1, 120.0),
    "concurrency": (1, 32),
}

_PAGE = Path(__file__).with_name("page.html")

#: The Content-Type each report format downloads as. Keyed by format name; the
#: file extension is EXTENSIONS[name], appended after a dot at download time.
_CONTENT_TYPES = {
    "console": "text/plain; charset=utf-8",
    "text": "text/plain; charset=utf-8",
    "json": "application/json; charset=utf-8",
    "sarif": "application/json; charset=utf-8",
    "csv": "text/csv; charset=utf-8",
    "inventory": "text/csv; charset=utf-8",
    "html": "text/html; charset=utf-8",
    "openmetrics": "text/plain; charset=utf-8",
}


class Job:
    """One scan: its progress while running, its report when done."""

    def __init__(self, total: int):
        self.id = secrets.token_urlsafe(8)
        self.total = total
        self.done = 0
        self.status = "running"
        self.error = ""
        self.report: Optional[ScanReport] = None
        #: Rendered output, cached per format: a report is re-requested (each
        #: format is a separate download) and rendering is O(targets), so the
        #: same bytes are produced once, not on every GET.
        self.rendered: Dict[str, bytes] = {}
        self._lock = threading.Lock()

    def tick(self) -> None:
        """One target finished. Called from the scan as it progresses; the
        increment is locked -- an unlocked += drops updates."""
        with self._lock:
            self.done += 1

    def as_status(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "id": self.id,
            "status": self.status,
            "done": self.done,
            "total": self.total,
        }
        if self.status == "error":
            payload["error"] = self.error
        if self.report is not None:
            payload["summary"] = _summary_payload(self.report.summary)
        return payload


def _summary_payload(summary: ScanSummary) -> Dict[str, Any]:
    """The overview the page shows when a scan finishes."""
    return {
        "total": summary.total,
        "unreachable": summary.failed,
        "average_score": summary.average_score,
        "profiles_failed": _any_profile_failed(summary.by_profile),
    }


def _any_profile_failed(by_profile: Dict[str, Dict[str, int]]) -> bool:
    """Whether any evaluated profile failed on any endpoint, for the page's
    at-a-glance flag (the full detail is in the downloadable report)."""
    return any(counts.get("fail", 0) for counts in by_profile.values())


class TooBusyError(Exception):
    """Raised when the concurrent-scan ceiling is reached; becomes a 503."""


class _State:
    """What the handler needs beyond the request: jobs and configuration."""

    def __init__(
        self,
        token: str,
        plugins: Tuple[Plugin, ...],
        block_private: bool,
        trust_store: Optional[TrustStore],
        allow_active: bool,
        profiles: Dict[str, Profile],
    ):
        self.token = token
        self.plugins = plugins
        self.block_private = block_private
        self.trust_store = trust_store
        self.allow_active = allow_active
        self.profiles = profiles
        self.jobs: OrderedDict[str, Job] = OrderedDict()
        self.running = 0
        self.lock = threading.Lock()

    def reserve(self) -> None:
        """Claim one of the concurrent-scan slots, or refuse."""
        with self.lock:
            if self.running >= MAX_RUNNING_JOBS:
                raise TooBusyError(f"{MAX_RUNNING_JOBS} scans already running; try again shortly")
            self.running += 1

    def release(self) -> None:
        with self.lock:
            self.running = max(0, self.running - 1)

    def add(self, job: Job) -> None:
        with self.lock:
            self.jobs[job.id] = job
            while len(self.jobs) > MAX_JOBS:
                self.jobs.popitem(last=False)

    def get(self, job_id: str) -> Optional[Job]:
        with self.lock:
            return self.jobs.get(job_id)

    def remove(self, job_id: str) -> None:
        with self.lock:
            self.jobs.pop(job_id, None)


def _parse_request(body: Dict[str, Any]) -> Dict[str, Any]:
    """Validate the scan request into plain values, or raise ValueError.

    The names mirror the CLI options on purpose: the page is a form over the
    same vocabulary, not a second vocabulary.
    """
    if not isinstance(body, dict):
        raise ValueError("the request body must be a JSON object")

    def _list_of_str(name: str, cap: int) -> List[str]:
        value = body.get(name, [])
        if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
            raise ValueError(f"'{name}' must be a list of strings")
        cleaned = [x.strip() for x in value if x.strip()]
        if len(cleaned) > cap:
            raise ValueError(f"'{name}' has {len(cleaned)} entries; at most {cap} allowed")
        return cleaned

    targets = _list_of_str("targets", MAX_TARGETS)
    inventory = body.get("inventory", "")
    if not isinstance(inventory, str):
        raise ValueError("'inventory' must be text")
    if inventory.count("\n") + 1 > MAX_TARGETS:
        raise ValueError(f"the inventory has more than {MAX_TARGETS} lines")
    if not targets and not inventory.strip():
        raise ValueError("nothing to scan: give at least one target or an inventory")

    def _number(name: str, default: float) -> float:
        low, high = LIMITS[name]
        value = body.get(name, default)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"'{name}' must be a number")
        if not (low <= value <= high):
            raise ValueError(f"'{name}' must be between {low} and {high}")
        return float(value)

    sni = body.get("sni", "")
    if not isinstance(sni, str):
        raise ValueError("'sni' must be text")

    return {
        "targets": targets,
        "inventory": inventory,
        "ports": _ports(body),
        "sni": sni.strip() or None,
        "timeout": _number("timeout", 10.0),
        "concurrency": int(_number("concurrency", 4)),
        "profiles": _list_of_str("profiles", 128),
    }


def _ports(body: Dict[str, Any]) -> List[int]:
    """The default port(s) for hosts that name none, as the CLI's ``-p`` (a
    single number or a comma-separated list), or raise ValueError."""
    value = body.get("port", DEFAULT_PORT)
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError("'port' must be a port number or a comma-separated list")
    try:
        return parse_ports(str(value))
    except TargetError as exc:
        raise ValueError(str(exc)) from exc


def _body_length(header_value: Optional[str]) -> int:
    """The validated request-body length, or raise ValueError.

    A pure helper so the malformed cases are testable without a socket (and so
    a handler thread's coverage never hides them).
    """
    try:
        length = int(header_value or 0)
    except ValueError:
        raise ValueError("invalid Content-Length") from None
    if length < 0:
        raise ValueError("invalid Content-Length")
    return length


def _is_private_address(address: str) -> bool:
    import ipaddress

    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _refuse_private_targets(targets: List[Any]) -> None:
    """Refuse any target that resolves to an internal address.

    Best effort, on by ``BLOCK_PRIVATE_VAR``: a name can rebind between here and
    the scan's own resolve, so this is defence in depth, not the guarantee --
    that is network egress control. It does stop the obvious abuse of a public
    scanner: 127.0.0.1, 169.254.169.254, 10.0.0.0/8 and the rest.
    """
    import socket

    for target in targets:
        try:
            infos = socket.getaddrinfo(target.host, target.port, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            continue  # a name that does not resolve is the scanner's problem, not a bypass
        for info in infos:
            if _is_private_address(str(info[4][0])):
                raise ValueError(
                    f"target '{target.host}' resolves to a private or reserved "
                    "address, which this deployment refuses to scan"
                )


def _resolve_profiles(available: Dict[str, Profile], wanted: List[str]) -> List[Profile]:
    """The CLI's rule, held here too: every requested profile id must exist."""
    resolved: List[Profile] = []
    for profile_id in wanted:
        profile = available.get(profile_id)
        if profile is None:
            raise ValueError(f"unknown profile '{profile_id}'")
        resolved.append(profile)
    return resolved


def _start_scan(state: _State, request: Dict[str, Any]) -> Job:
    """Build everything the scan needs and launch it on its own thread."""
    profiles = _resolve_profiles(state.profiles, request["profiles"])

    files: List[Path] = []
    inventory_path = ""
    if request["inventory"].strip():
        # The inventory is staged to a temp file so read_target_file parses it
        # exactly as the CLI parses -f: same labels, comments and per-line rules.
        # It must outlive this scope (build_targets reads it below), so it is
        # created delete-on-nobody and unlinked by hand in the finally.
        handle, inventory_path = tempfile.mkstemp(suffix=".txt", prefix="wcc-web-")
        os.close(handle)
        try:
            Path(inventory_path).write_text(request["inventory"], encoding="utf-8")
        except OSError:
            os.unlink(inventory_path)
            raise ValueError("could not stage the inventory") from None
        files = [Path(inventory_path)]
    try:
        targets, errors = build_targets(request["targets"], files, request["ports"], request["sni"])
    finally:
        if inventory_path:
            os.unlink(inventory_path)
    if errors:
        # The parser labels inventory errors with the temp path; the caller has
        # no business seeing it (it names the tempdir and the naming scheme).
        # Only when there IS a temp path -- replacing "" would corrupt every
        # message.
        if inventory_path:
            errors = [e.replace(inventory_path, "inventory") for e in errors]
        raise ValueError("; ".join(errors))
    if not targets:
        raise ValueError("nothing to scan: no valid target survived parsing")
    # The two target sources are capped apart; their sum must not exceed the cap.
    if len(targets) > MAX_TARGETS:
        raise ValueError(f"more than {MAX_TARGETS} targets in total")
    if state.block_private:
        _refuse_private_targets(targets)

    job = Job(total=len(targets))
    # Claim a concurrency slot last, once the request is known good, so a
    # rejected request never consumes one. TooBusy propagates to a 503.
    state.reserve()
    state.add(job)

    def _run() -> None:
        try:
            job.report = scan(
                targets,
                timeout=request["timeout"],
                concurrency=request["concurrency"],
                profiles=profiles,
                plugins=state.plugins,
                active=state.allow_active,
                trust_store=state.trust_store,
                progress=job.tick,
            )
            job.status = "done"
        except Exception as exc:
            job.status = "error"
            job.error = str(exc)
        finally:
            state.release()

    try:
        threading.Thread(target=_run, daemon=True).start()
    except BaseException as exc:
        # start() can raise (thread/memory exhaustion). Without this the slot
        # reserved above would leak, and eight leaks wedge the service until a
        # restart. Give it back and drop the job, then let it become a 503.
        state.release()
        state.remove(job.id)
        raise TooBusyError("could not start the scan; the server is out of capacity") from exc
    return job


def _render_job(job: Job, output_format: str) -> bytes:
    if output_format not in FORMATS:
        raise ValueError(f"unknown format '{output_format}'; valid: {', '.join(sorted(FORMATS))}")
    cached = job.rendered.get(output_format)
    if cached is not None:
        return cached
    assert job.report is not None  # guarded by the caller
    body = render(job.report, output_format).encode("utf-8")
    job.rendered[output_format] = body
    return body


def _meta(state: _State) -> Dict[str, Any]:
    return {
        "tool": PRODUCT_NAME,
        "version": __version__,
        "formats": ["console", *sorted(n for n in FORMATS if n != "console")],
        "profiles": [
            {
                "id": profile.id,
                "name": profile.name,
                "authority": profile.authority,
                "edition": profile.edition,
            }
            for profile in state.profiles.values()
        ],
    }


#: Locks in the browser: no framing, no sniffing, and a policy that forbids
#: loading anything off-origin. The page is entirely self-contained, so the
#: strictest CSP that still lets its own inline script run is the right one; a
#: downloaded report is served ``attachment`` and never rendered in this origin.
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
}


def _make_handler(state: _State) -> type:
    class Handler(BaseHTTPRequestHandler):
        server_version = f"{PRODUCT_NAME}-web/{__version__}"
        protocol_version = "HTTP/1.1"
        #: A slow client must not pin a thread forever (a slow-loris hedge; the
        #: real edge protection is a reverse proxy, documented in server.py).
        timeout = 30

        def version_string(self) -> str:
            return self.server_version  # not the Python version too; free fingerprint

        def log_message(self, format: str, *args: Any) -> None:
            pass  # a scan target in every access-log line helps nobody

        # -- plumbing --------------------------------------------------- #

        def _send(
            self, code: int, body: bytes, content_type: str, extra: Optional[Dict[str, str]] = None
        ) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for name, value in _SECURITY_HEADERS.items():
                self.send_header(name, value)
            for name, value in (extra or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, payload: Dict[str, Any]) -> None:
            self._send(code, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")

        def _authorised(self) -> bool:
            if not state.token:
                return True
            supplied = self.headers.get("X-Auth-Token", "")
            # Constant time: a plain == leaks the token one character at a time
            # to anyone who can measure the reply.
            if secrets.compare_digest(supplied, state.token):
                return True
            self._json(401, {"error": "missing or wrong X-Auth-Token"})
            return False

        def _path_and_query(self) -> Tuple[str, Dict[str, str]]:
            path, _, query = self.path.partition("?")
            params = {}
            for pair in query.split("&"):
                name, _, value = pair.partition("=")
                if name:
                    params[name] = value
            return path, params

        # -- routes ----------------------------------------------------- #

        def do_GET(self) -> None:  # http.server dispatch name
            path, params = self._path_and_query()
            if path == "/" or path == "/index.html":
                self._send(200, _PAGE.read_bytes(), "text/html; charset=utf-8")
                return
            if not path.startswith("/api/"):
                self._json(404, {"error": "not found"})
                return
            if not self._authorised():
                return
            if path == "/api/meta":
                self._json(200, _meta(state))
                return
            parts = path.split("/")  # '', 'api', 'scan', <id>[, 'report']
            if len(parts) == 4 and parts[2] == "scan":
                job = state.get(parts[3])
                if job is None:
                    self._json(404, {"error": "no such scan"})
                    return
                self._json(200, job.as_status())
                return
            if len(parts) == 5 and parts[2] == "scan" and parts[4] == "report":
                job = state.get(parts[3])
                if job is None:
                    self._json(404, {"error": "no such scan"})
                    return
                if job.report is None:
                    self._json(409, {"error": f"scan is {job.status}; no report yet"})
                    return
                name = params.get("format", "console")
                try:
                    body = _render_job(job, name)
                except ValueError as exc:
                    self._json(400, {"error": str(exc)})
                    return
                filename = f"scan-{job.id}.{EXTENSIONS[name]}"
                self._send(
                    200,
                    body,
                    _CONTENT_TYPES[name],
                    {
                        "Content-Disposition": f'attachment; filename="{filename}"',
                    },
                )
                return
            self._json(404, {"error": "not found"})

        def do_POST(self) -> None:  # http.server dispatch name
            path, _params = self._path_and_query()
            if path != "/api/scan":
                self._json(404, {"error": "not found"})
                return
            if not self._authorised():
                # The body was not read: on a keep-alive socket the next request
                # would be parsed starting mid-body. Close instead of desyncing.
                self.close_connection = True
                return
            try:
                length = _body_length(self.headers.get("Content-Length"))
            except ValueError as exc:
                self.close_connection = True  # body unread; same desync hazard
                self._json(400, {"error": str(exc)})
                return
            if length > MAX_BODY_BYTES:
                # Do not read the oversized body: reject and drop the connection
                # rather than allocate it or leave it half-read for the next
                # request on a keep-alive socket to trip over.
                self.close_connection = True
                self._json(413, {"error": f"request body over {MAX_BODY_BYTES} bytes"})
                return
            raw = self.rfile.read(length) if length else b""
            try:
                request = _parse_request(json.loads(raw.decode("utf-8") or "null"))
                job = _start_scan(state, request)
            except (ValueError, json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
                # RecursionError: deeply nested JSON, well under the size cap.
                message = str(exc) or exc.__class__.__name__
                self._json(400, {"error": message})
                return
            except TooBusyError as exc:
                self._json(503, {"error": str(exc)})
                return
            self._json(202, {"id": job.id})

    return Handler


class _BoundedServer(ThreadingHTTPServer):
    """A ThreadingHTTPServer that will not spawn more than MAX_CONNECTIONS
    handler threads at once.

    ``http.server`` starts a thread per connection, before any auth runs, so
    without this a flood of open sockets exhausts threads and file descriptors
    anonymously -- the one dimension the token cannot guard. Excess connections
    are closed at once instead of queued, so a slow flood cannot bank them. The
    reverse proxy remains the real edge; this is the in-process floor.
    """

    daemon_threads = True

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            self.close_request(request)  # over capacity: drop it, do not queue
            return
        super().process_request(request, client_address)

    def shutdown_request(self, request: Any) -> None:
        # Runs in the handler thread's finally, once per accepted connection --
        # exactly the ones that acquired a slot, so releases balance acquires.
        try:
            super().shutdown_request(request)
        finally:
            self._slots.release()


def _trust_store_from_env() -> Optional[TrustStore]:
    """The store chains validate against: the system store by default, a named
    PEM bundle if given, or nothing when trust is switched off."""
    if _is_truthy(os.environ.get(NO_TRUST_VAR, "")):
        return None
    bundle = os.environ.get(CA_BUNDLE_VAR, "").strip()
    return load_trust_store(bundle or None)


def create_server(host: str, port: int) -> ThreadingHTTPServer:
    """Build the configured server (not yet serving); tests drive it directly."""
    token = os.environ.get(TOKEN_VAR, "")
    plugin_dirs = [Path(part) for part in os.environ.get(PLUGIN_VAR, "").split(os.pathsep) if part]
    plugins, problems = load_plugins(plugin_dirs or None)
    for problem in problems:
        print(f"warning: plugin not loaded: {problem}")
    state = _State(
        token=token,
        plugins=tuple(plugins),
        block_private=_is_truthy(os.environ.get(BLOCK_PRIVATE_VAR, "")),
        trust_store=_trust_store_from_env(),
        allow_active=_is_truthy(os.environ.get(ALLOW_ACTIVE_VAR, "")),
        profiles=load_profiles(),
    )
    return _BoundedServer((host, port), _make_handler(state))


def _is_truthy(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m web_crypto_checker.web",
        description="Web front end for webServerCryptoChecker (same scan, same reports).",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="bind address (default: %(default)s; 0.0.0.0 in a container)",
    )
    parser.add_argument("--port", type=int, default=8443, help="listen port (default: %(default)s)")
    args = parser.parse_args(argv)

    # Open by default: with no token anyone who can reach the port uses it, on
    # any interface -- that is the frictionless local deployment. Setting a token
    # is the switch that closes it; the internet-exposure guidance lives in the
    # docs, not in a startup nag.
    guard = "token required" if os.environ.get(TOKEN_VAR) else "OPEN - no token"
    server = create_server(args.host, args.port)
    print(f"{PRODUCT_NAME} web {__version__} on http://{args.host}:{args.port}/  [{guard}]")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
