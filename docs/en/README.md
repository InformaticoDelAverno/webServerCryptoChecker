# webServerCryptoChecker

Audit the cryptography **and the protocols** your **web** servers offer: TLS
versions, cipher suites, key-exchange groups, signature algorithms, the
**certificate** (chain, trust, expiry, revocation, transparency and — over DNS —
**CAA** and **DANE/TLSA**), **compression** (the CRIME channel), TLS 1.3
**0-RTT**, the **HTTP layer** (HSTS, CSP, cookies, redirects) and **every
application protocol** it exposes: **HTTP/2** (with its SETTINGS and Rapid
Reset), **HTTP/3** over QUIC (with the cipher, group and transport parameters it
negotiates), **secure WebSocket (wss)**, **SSE**, **gRPC** and **mTLS** (client
certificate authentication). It grades each server as **secure**, **acceptable**,
**weak** or **insecure**, says whether it is **post-quantum ready**, and checks
known vulnerabilities and conformance with the published standards.

> The code is in English (the native vocabulary of TLS and security); the
> documentation comes in both languages. The tool is **bilingual**
> (`--lang en|es`): the wizard, the command help and the human-readable reports
> come out in the chosen language; the machine-readable formats (JSON, CSV, SARIF,
> OpenMetrics) stay in English.

---

> **Español:** este manual también está disponible en [español](../es/README.md).

## Index

- [Features](#features)
- [Requirements and installation](#requirements-and-installation)
- [Quick start](#quick-start)
- [Ways to name a target](#ways-to-name-a-target)
- [The interactive wizard (--wizard)](#the-interactive-wizard---wizard)
- [Languages (--lang)](#languages---lang)
- [Report formats](#report-formats)
- [The three interfaces](#the-three-interfaces)
- [The web interface](#the-web-interface)
- [The MCP interface](#the-mcp-interface)
- [Standards conformance (NIST, FIPS, ENS, PCI DSS, CIS…)](#standards-conformance-nist-fips-ens-pci-dss-cis)
- [Detection plugins](#detection-plugins)
- [Exactly what it checks](#exactly-what-it-checks)
- [Exit codes and CI integration](#exit-codes-and-ci-integration)
- [Options reference](#options-reference)
- [Cookbook: one example per option](#cookbook-one-example-per-option)
- [Limitations and legal notes](#limitations-and-legal-notes)
- [License](#license)
- [Extension guides included](#extension-guides-included)

---

## Features

- **Zero dependencies.** Just Python 3.9 or later. The TLS records and the
  cryptography needed to enumerate what a server offers are implemented in the
  package itself — not taken from OpenSSL — so the same probe reaches an old
  server that a modern OpenSSL would refuse to speak to.
- **Enumerates the four dimensions of TLS**: versions (SSL 2/3, TLS 1.0–1.3),
  cipher suites, key-exchange groups and signature schemes.
- **Per-server grade** (A+…F) and **verdict** (secure / acceptable / weak /
  insecure), with the **effective security strength in bits** (NIST SP 800-57,
  the weakest link).
- **Post-quantum readiness**: detects the hybrids (X25519MLKEM768 and others).
- **Certificate in depth**: chain, name match, key strength, trust up to a system
  root, expiry, revocation (OCSP/CRL/stapling), **transparency (CT)** with SCT
  signature verification, and over DNS **CAA** and **DANE/TLSA** validated by
  **DNSSEC**.
- **HTTP layer**: HSTS, CSP (parsed, not just counted), cookies, HTTPS redirect,
  mixed content, Subresource Integrity and CORS.
- **Every application protocol**: HTTP/2, HTTP/3 (QUIC), secure WebSocket (wss),
  SSE, gRPC and mTLS.
- **Data-driven known vulnerabilities** (POODLE, Sweet32, RC4, FREAK/Logjam,
  DROWN, BEAST, ROBOT…) and optional **active probes** (`--active`: Heartbleed,
  CCS injection, the ROBOT oracle, real revocation…).
- **Conformance with 14 standards** cited from real documents (Mozilla, NIST,
  PCI DSS, BSI, ANSSI, ENS, CNSA, FIPS 140-3, ISO/IEC 27002 and the CIS
  benchmarks).
- **Eight report formats**: console, text, JSON, CSV, HTML, SARIF, inventory and
  OpenMetrics (Prometheus).
- **Bilingual** (`--lang en|es`), with an **interactive wizard** (`--wizard`) and
  an optional **web interface** in Docker.

---

## Requirements and installation

**Python 3.9 or later. Nothing else.** The tool has no runtime dependencies.

```bash
# Clone and use without installing, from the repository itself
git clone https://github.com/CHANGEME/webServerCryptoChecker.git
cd webServerCryptoChecker
./web-crypto-checker example.com

# Or install it (leaves the `web-crypto-checker` command on the PATH)
pip install .
web-crypto-checker example.com
```

The `web-crypto-checker` launcher in the repository lets you use the tool
**without installing it**; installed, `pip install .` leaves the same command
available.

---

## Quick start

```bash
# One server on 443
./web-crypto-checker example.com

# Several at once, with more parallelism
./web-crypto-checker web01 web02 api.example.com -c 4

# A different port, and a specific path
./web-crypto-checker example.com:8443
./web-crypto-checker https://example.com/login
```

A scan produces, on the console, one block per endpoint with its grade, verdict,
versions and offered suites, and the findings with their severity:

```
webServerCryptoChecker 0.1.0 — 1 endpoint(s), 1 reachable

servidor.example.com  [192.0.2.10]
  grade: F    verdict: weak
  TLS versions: TLS 1.2, TLS 1.1, TLS 1.0
  cipher suites (2):
    [weak] TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    [weak] TLS_RSA_WITH_AES_128_CBC_SHA
  [medium] Weak protocol versions offered: TLS 1.0, TLS 1.1
  [medium] Weak cipher suites offered: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA
```

---

## Ways to name a target

| Form | Example | Port |
|---|---|---|
| DNS name | `example.com` | 443 (or `-p`) |
| Name and port | `example.com:8443` | 8443 |
| URL with path | `https://example.com/login` | 443, path `/login` |
| http URL | `http://example.com` | 80 |
| IPv4 | `192.0.2.10` | 443 |
| IPv6 in brackets | `[2001:db8::1]:443` | 443 |
| IPv6 without brackets | `2001:db8::1` | 443 |
| With user (ignored) | `admin@example.com` | 443 |

A host with no port expands to **each port in `-p`** (`-p 443,8443` → two
targets). A host that brings its own port does not expand. The default **SNI** is
the host name; a bare IP is sent no SNI (RFC 6066 forbids it), and `--sni` forces
one. With `-f/--file` targets are read from a file (one per line, `#` for
comments); see [`examples/servers.txt`](../../examples/servers.txt) and its
[guide](../../examples/README.md).

---

## The interactive wizard (--wizard)

If you would rather not learn the options, the wizard (`-w` / `--wizard`) asks
them one at a time — targets and inventory, SNI and port, standards to evaluate,
output formats and file, timing and concurrency, trust store, active probes,
history and comparison, and plugins — **shows the command** it has built and
offers to run it:

```bash
./web-crypto-checker --wizard
./web-crypto-checker -w            # shortcut
```

The wizard **scans nothing on its own**: it assembles the exact `argv` a normal
invocation would use, prints it as a copyable command and hands it to the CLI
itself. So what it shows and what it runs are the same by construction, and the
printed command can be **saved and rerun** later without the wizard. The command
it builds ends in `--lang`, so that copied to another machine it produces the
same report. It needs an interactive terminal (if the input is not a TTY, it
exits with a notice).

---

## Languages (--lang)

The tool is **bilingual**: English (by default) and Spanish from Spain.
Everything a person reads comes out in the chosen language: the **wizard**
(`--wizard`), the **full CLI help** (`--help`: the description, each option's
help and the metavariables) and the **body of the human-readable reports** (the
`console`, `text` and `html` formats). The language is chosen like this:

```bash
./web-crypto-checker example.com --lang es      # Spanish
./web-crypto-checker example.com --lang en      # English (default)
```

If `--lang` is not passed, Spanish is chosen when the system **locale** is
Spanish (`LANG`/`LC_ALL`/`LC_MESSAGES` starts with `es`); otherwise, English.
`--lang` always wins over the locale, and accepts forms like `es_ES` or `en-GB`
(the prefix is taken). The **machine-readable formats** (JSON, SARIF, CSV,
inventory, OpenMetrics) keep their keys and values in English whatever the
language: they are a contract for tools, not prose for people. The `argparse`
scaffolding words (`usage:`, `options:` and the syntax errors) also stay in
English, because Python does not ship their translation.

---

## Report formats

One scan, **eight formats**. They are chosen with `--format` (one, or several
comma-separated) and written with `-o` (with several formats, `-o` is the base
name and each format adds its extension):

| Format | `--format` | For what |
|---|---|---|
| Console | `console` | The default human-readable output, one block per endpoint. |
| Text | `text` | Plain-text summary, no colour. |
| JSON | `json` | The full report, machine-readable. |
| CSV | `csv` | One row per finding, for spreadsheets. |
| HTML | `html` | A browsable, self-contained report. |
| SARIF | `sarif` | For a forge's code-scanning view (GitHub/GitLab). |
| Inventory | `inventory` | One row per endpoint (grade, verdict, versions…). |
| OpenMetrics | `openmetrics` | Metrics for Prometheus. |

```bash
# JSON and HTML in a single pass
./web-crypto-checker -f inventory.txt --format json,html -o audit
# → audit.json and audit.html
```

In addition, `--compare` contrasts the scan with an earlier JSON report and
shows what changed: new or vanished endpoints, grade movement, new or resolved
findings and vulnerabilities, **algorithms added or removed** (by class:
versions, suites, groups, signatures) and **certificate fingerprint change** — on
a server nobody reissued, a new fingerprint is a reason to stop and find out why.
With `--fail-on-regression` a regression fails the run. And `--history` appends
the scan to a history file and shows each endpoint's grade over time.

---

## The three interfaces

The same audit is offered three ways, with identical results:

- **CLI** — the command line of this manual (`./web-crypto-checker`).
- **MCP** — a JSON-RPC 2.0 server over *stdio* for agents, with
  `web-crypto-checker-mcp` (or `python -m web_crypto_checker.mcp`). It exposes a
  `scan` tool (which takes the CLI's own `argv`) plus `help`, `list_profiles`,
  `list_plugins`, `list_vulnerabilities` and `show_policy`.
- **Web** — a single-scan web interface with `python -m web_crypto_checker.web`
  (hardened: security headers, a job queue with a ceiling, and an optional token).
  The `docker-compose.yml` brings it up in a container.

## The web interface

An **additional** way to use the tool, not a replacement: the same `scan()`,
evaluating the same standards, and the same `render()` — the report downloads in
**any of the eight formats**, in the chosen language — from a form. Zero
dependencies here too: the server is `http.server` from the standard library.

```bash
# Locally (by default it listens only on 127.0.0.1:8443)
python3 -m web_crypto_checker.web
# → http://127.0.0.1:8443/

# In a container, in one go (uses the root docker-compose.yml)
make web-up      # docker compose up -d --build → http://localhost:8443/
make web-logs    # follow the log
make web-down    # stop and clean up
```

The API is minimal: `GET /api/meta` (available options and formats),
`POST /api/scan` (launches a scan and returns a job id with its progress) and the
report downloads per format. The single page (`page.html`) is self-contained,
with no external resources (the CSP forbids them).

**Open access by default (no token, no users, no sign-up).** It is the most
convenient thing for an internal deployment: anyone who reaches the port uses it.
The token is the **only switch** that closes it — set it and every `/api` request
will require `X-Auth-Token` (constant-time comparison):

```bash
# Open, on your internal LAN (what `make web-up` does with nothing more)
docker compose up -d --build

# Closed with a token
WEB_CRYPTO_CHECKER_WEB_TOKEN=a-secret docker compose up -d
```

What in the CLI are deployment options come in through **environment variables
and volumes**, not through the form (so no secret or dangerous decision travels
through the browser):

| Variable | What it does |
|---|---|
| `WEB_CRYPTO_CHECKER_WEB_TOKEN` | Requires `X-Auth-Token` on every `/api` request. Empty = open. |
| `WEB_CRYPTO_CHECKER_WEB_BLOCK_PRIVATE` | Rejects targets that resolve to private/loopback/reserved addresses. |
| `WEB_CRYPTO_CHECKER_WEB_PLUGIN_DIR` | Plugin directories (equivalent to `--plugin-dir`). |
| `WEB_CRYPTO_CHECKER_WEB_CA_BUNDLE` | PEM of your own roots (equivalent to `--ca-bundle`). |
| `WEB_CRYPTO_CHECKER_WEB_NO_TRUST` | Do not validate the chain (equivalent to `--no-trust`). |
| `WEB_CRYPTO_CHECKER_WEB_ALLOW_ACTIVE` | Enables the active probes (**off** by default). |

### Web security

The web layer is hardened and there are tests that pin it (`tests/test_web.py`):
it caps everything an anonymous user could inflate (body size, number of targets,
concurrency, timeout and simultaneous scans), adds defensive headers (`nosniff`,
`X-Frame-Options: DENY`, a strict CSP, `Referrer-Policy: no-referrer`), downloads
the reports as attachments, compares the token in constant time and **escapes**
everything the scanned server controls (a hostile banner cannot inject script).
The active probes are **off** unless a deployment enables them: an open service
that fires offensive traffic at any host is an abuse amplifier.

Two things are not fixed in the code, only at the **deployment edge**:

1. **Scanning arbitrary hosts is the tool's job.** Published without a token it is
   an SSRF machine: close it with the token, turn on
   `WEB_CRYPTO_CHECKER_WEB_BLOCK_PRIVATE=1` and, for the hard guarantee, start it
   **with no network route** to your internal ranges (an egress firewall is the
   only infallible thing; the app filter only approximates it).
2. **`http.server` is the stdlib's basic server**, not a hardened edge: for the
   internet, put it **behind a reverse proxy** that terminates TLS, rate-limits
   and rejects malformed requests.

> In one sentence: treat it as an **internal** tool unless you have set
> token/filter **and** a proxy with TLS in front.

---

## The MCP interface

A **third** way to use the tool, alongside the command line and the web, so that
a **language model** can drive it: an **MCP** server (*Model Context Protocol*).
The same `scan()` and the same `render()` as the other two, spoken over
**JSON-RPC 2.0 on stdio** — one JSON message per line, the MCP stdio transport.
Zero dependencies here too: only the standard library, **no SDK or framework**.

### Requirements

**Python 3.9 or later. Nothing else** — same as the CLI. The MCP server needs no
network to start, no keys, no configuration file of its own: it launches, speaks
JSON-RPC over its standard input/output, and inherits the environment of the
client that starts it.

### Installation

Two paths, depending on whether you prefer to install the package or use it from
the repository.

**a) Installed (recommended for configuring a client).** `pip install .` leaves
**two** commands on the `PATH`: the CLI and the MCP server. With the command on
the `PATH`, the client configuration is just its name.

```bash
pip install .            # inside the repository (or `pipx install .`)
web-crypto-checker-mcp --version     # check that it was installed
```

> Tip: `pipx install .` installs it isolated in its own environment and leaves
> the commands on the global `PATH`, which is exactly what an MCP client needs to
> find them without activating any *virtualenv*.

**b) From the repository, without installing.** Equivalent to the above but
running the module; you have to tell Python where the package is (with `-m` from
the repository root, or with `PYTHONPATH`):

```bash
cd /path/to/webServerCryptoChecker
python3 -m web_crypto_checker.mcp --version
```

### Configuration in an MCP client

The server **is not launched by hand** in a terminal — it speaks JSON-RPC, not to
a person: you **register its command** in an MCP client, which starts it for you
and speaks the protocol to it. The canonical form, common to almost every client,
is an entry under `mcpServers`:

```json
{
  "mcpServers": {
    "web-crypto-checker": {
      "command": "web-crypto-checker-mcp"
    }
  }
}
```

**Claude Desktop.** Edit the `claude_desktop_config.json` file (Settings →
Developer → Edit Config), add the entry above and **restart** the application.
Its location:

| System | Path |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

**Claude Code.** Register it with a command (choose the scope with `-s`
`local`/`user`/`project`), or drop a `.mcp.json` in the project root with the same
`mcpServers` block:

```bash
claude mcp add web-crypto-checker -- web-crypto-checker-mcp
claude mcp list                     # check that it appears and connects
```

**Other clients** (Cursor, VS Code, Zed…). They all consume the same
`command`/`args`/`env` form; only where the file lives changes (e.g.
`.cursor/mcp.json` in Cursor). See the client's documentation for the exact path.

**Ollama.** Ollama runs models **locally**, but it is **not itself an MCP
host**: it does not start MCP servers on its own. To give it this tool, use an
MCP client or bridge that also talks to Ollama. The most direct is **mcphost** (an
open-source MCP host that works with Ollama models): point its config at the
server command,

```json
{ "mcpServers": { "web-crypto-checker": { "command": "web-crypto-checker-mcp" } } }
```

and launch it with `mcphost -m ollama:llama3.1 --config that-file.json`. Other
clients that pair Ollama with MCP are oterm, LibreChat and Open WebUI.

**Without installing (using the repository).** If you prefer not to install the
package, point the client at `python3 -m` and tell it which directory to run in:

```json
{
  "mcpServers": {
    "web-crypto-checker": {
      "command": "python3",
      "args": ["-m", "web_crypto_checker.mcp"],
      "cwd": "/path/to/webServerCryptoChecker"
    }
  }
}
```

> If your client does not support `cwd`, use `"env": { "PYTHONPATH": "/path/to/webServerCryptoChecker" }`
> instead. With the package **installed** none of this is needed: the command
> name is enough.

### Checking that it works

Before configuring the client you can verify the server by hand: you pass it one
or two JSON-RPC messages on standard input and it answers on standard output.

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | web-crypto-checker-mcp
```

It must print two JSON lines: the first with `serverInfo`
(`web-crypto-checker-mcp` and the version), the second with the list of tools. If
you see an import error instead, the package is not on the `PATH`/`PYTHONPATH`
(check the installation). Once in the client, `scan` with `args: ["example.com"]`
launches a real scan.

### Why it loses no option

Parity with the CLI is **by construction, not by maintenance**: every tool call
ends up running the same `web_crypto_checker.cli.main` that the terminal runs,
with its output captured. The `scan` tool receives the CLI's own `argv`, so
**everything the command does the MCP does** — there is no parallel schema for
someone to keep in sync.

### The tools it exposes

| Tool | What it does |
|---|---|
| `scan` | Scans. `args` is the CLI argument vector: `["example.com", "--format", "json"]`. Any option of the command works. |
| `help` | The full CLI help (all the options), in the chosen language (`lang`). |
| `list_profiles` | Lists the available conformance profiles. |
| `list_plugins` | Lists the detection plugins that would load. |

It implements the MCP methods `initialize`, `tools/list`, `tools/call` and
`ping`. The **exit codes are information, not failures**: a scan that finds a weak
server exits with a non-zero code **on purpose**, so a complete run is never
reported as a tool error — the code is added to the text. `isError` is left for a
call that could not be made (malformed arguments) or an unexpected exception,
which is caught so that **a tool cannot bring the server down**.

> ⚠️ An MCP gives a language model the ability to **launch scans** — and, with
> `scan` and `--active` in `args`, offensive traffic. The same legal limits apply
> as in the CLI (see [Limitations and legal notes](#limitations-and-legal-notes)):
> scan only what you are authorised to test. The MCP server does **not** open any
> port or listen on the network (unlike the web interface): it only speaks over
> stdio with the client that starts it, so the `WEB_CRYPTO_CHECKER_WEB_*`
> variables do **not** apply to it.

---

## Standards conformance (NIST, FIPS, ENS, PCI DSS, CIS…)

A standard is not code of this tool: it is a document someone else maintains and
revises on their own calendar. That is why each standard lives in **its own
directory** under
[`web_crypto_checker/data/profiles/`](../../web_crypto_checker/data/profiles/README.md),
**one file per edition**, and is **evaluated**, not compiled. When the scan does
not see enough to judge, the result is **not assessed**, never *pass*: a check
that could not run was not passed, it was skipped.

Profiles are selected with `--profile <id>` (the edition **in force**) or with
`--profile <id>@<edition>` to pin a specific edition (repeatable), and listed with
`--list-profiles`. The **14 built-in profiles**:

| `--profile` | Standard | Authority |
|---|---|---|
| `mozilla-modern` | Mozilla Server Side TLS, Modern (TLS 1.3 only) | Mozilla |
| `mozilla-intermediate` | Mozilla Server Side TLS, Intermediate | Mozilla |
| `nist-sp-800-52r2` | NIST SP 800-52 Rev. 2 (TLS guidance) | NIST (USA) |
| `nist-sp-800-131a` | NIST SP 800-131A Rev. 2 | NIST (USA) |
| `fips-140-3` | FIPS 140-3 (approved algorithms) | NIST (USA) |
| `pci-dss-4` | PCI DSS v4.0.1 | PCI SSC |
| `ens` | ENS — Esquema Nacional de Seguridad | CCN (Spain) |
| `cnsa-1.0` | CNSA 1.0 (transitional suite) | NSA (USA) |
| `bsi-tr-02102-2` | BSI TR-02102-2 (use of TLS) | BSI (Germany) |
| `anssi` | ANSSI, cryptographic rules by mechanism | ANSSI (France) |
| `iso-27002-8-24` | ISO/IEC 27002:2022, control 8.24 | ISO/IEC |
| `cis-nginx` | CIS NGINX Benchmark | CIS |
| `cis-apache-2.4` | CIS Apache HTTP Server 2.4 Benchmark | CIS |
| `cis-iis-10` | CIS Microsoft IIS 10 Benchmark | CIS |

**Every rule refers back to an exact section or table of a real document**, cited
in the profile's `reference` and `notes` fields. The source documents are cited
(URL, date and SHA-256) in [`docs/estandares/`](../estandares/README.md); not all
of them may be redistributed (PCI DSS and ISO/IEC are paid; NIST is public domain;
CIS is CC BY-NC-SA), so they are **cited** and obtained from their publisher, not
included. To understand what each profile measures and how to write your own, see
[`docs/politica-normativas.md`](politica-normativas.md) and the
[`data/` README](../../web_crypto_checker/data/README.md).

```bash
# Evaluate against two profiles
./web-crypto-checker example.com --profile mozilla-intermediate --profile pci-dss-4

# See the available profiles
./web-crypto-checker --list-profiles
```

---

## Detection plugins

A policy rule *matches* (a name, a tag, a version). What it cannot do is
**compute**. That is what plugins are for: a file dropped in a plugin directory
and it just runs. Two guarantees, and they are tested:

- **A plugin cannot change the grade.** It receives a `ServerView` of what was
  *observed* — never the score, the grade or the verdict — and its result is added
  to the report *after* the score is computed.
- **A plugin cannot bring the scan down.** Whatever it raises is caught and
  reported as a finding that names it.

Loading code is loading code, so plugin directories are **explicit** (never the
working directory) and one that others can write to is rejected. Three ship: the
**client simulation** (which known clients would complete the handshake), the
**certificate lifetime ceiling** (398 days) and the **issuer authorisation by
CAA** (a conservative heuristic).

```bash
./web-crypto-checker example.com --plugin-dir ./my-plugins
./web-crypto-checker --list-plugins
```

How to write one, with the full contract, in [`docs/plugins.md`](plugins.md).

---

## Exactly what it checks

**On the wire, without authenticating:**

- **Versions**: SSL 2.0 (with its own message format), SSL 3.0 and TLS 1.0–1.3,
  each marked offered or not.
- **Cipher suites**, **key-exchange groups** (in the server's preference order,
  via `HelloRetryRequest`) and **signature schemes** (one by one), with their
  classification by the policy.
- **Post-quantum readiness** (hybrids such as X25519MLKEM768) and TLS 1.3
  **0-RTT / early data**.
- **Certificate**: chain and name match, key type and strength, internal
  signature verified (RSA PKCS#1 v1.5 and PSS, ECDSA, Ed25519, in-house),
  **trust up to a system root** (`--ca-bundle` for another bundle, `--no-trust`
  to turn it off) with `NameConstraints`, `pathLenConstraint` and the whole
  path's validity, **hygiene** (no SAN, validity > 398 days, chain with the
  anchor), **transparency (CT)** with SCT signature verification, and what the
  certificate **announces** about revocation (OCSP/CRL/must-staple) and whether
  the server **staples** OCSP (authenticated). The **ROCA fingerprint**
  (CVE-2017-15361) and the **alternative certificate** (RSA hidden behind an
  ECDSA) too.
- **HTTP layer**: HSTS (with `max-age`, `preload`, `includeSubDomains`), CSP
  **parsed** (inline/eval/broad origins), `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`, cookie flags, port 80 to HTTPS redirect,
  **mixed content** (active/passive), **Subresource Integrity** and **CORS**
  (reflection with credentials).
- **Over DNS** (with an in-house client and iterative *resolver*): **CAA** (RFC
  8659) and **DANE/TLSA** (RFC 6698), both **validated by DNSSEC** up to the IANA
  root — including **authenticated absence** (NSEC/NSEC3) — and the
  **HTTPS/SVCB** record (RFC 9460, with ALPN and ECH).
- **Application protocols**: **HTTP/2** (SETTINGS), **HTTP/3** over QUIC (with an
  in-house engine: cipher, group and transport parameters), **secure WebSocket
  (wss)**, **SSE**, **gRPC** (with an in-house HPACK codec) and **mTLS** (if the
  client certificate is *requested* or *required*).

**Data-driven known vulnerabilities**: POODLE, Sweet32, RC4, FREAK/Logjam,
NULL/anonymous/DES ciphers, BEAST, the static-RSA surface of
ROBOT/Bleichenbacher, and **DROWN** (SSL 2.0 with export-cipher detection).

**With `--active`** (and an authorisation notice): Heartbleed (CVE-2014-0160),
CCS injection (CVE-2014-0224), the **active ROBOT oracle**, the **real revocation
query** (OCSP/CRL), **client-initiated renegotiation**, and passively RFC 5746,
extended master secret, Encrypt-then-MAC, anti-downgrade (TLS_FALLBACK_SCSV and
the TLS 1.3 sentinel), server cipher preference, Diffie-Hellman parameters
(Logjam), GREASE tolerance, TLS compression (CRIME) and session resumption.

---

## Exit codes and CI integration

| Code | Meaning |
|---|---|
| `0` | Every target was scanned successfully |
| `1` | Some target could not be scanned (unreachable or error); a **regression** with `--compare --fail-on-regression`; a finding that meets the `--fail-on` threshold; or an endpoint that fails a profile demanded with `--require-profile` |
| `2` | Usage or configuration error (invalid format, profile or target; `--wizard` with no terminal) |

```yaml
# .gitlab-ci.yml — audit your fleet from CI
web-audit:
  image: python:3.12-slim
  script:
    - pip install .
    - web-crypto-checker -f inventory.txt --format json,html -o report
  artifacts:
    when: always
    paths: [report.json, report.html]
```

To detect regressions against a saved baseline, combine
`--compare previous-report.json --fail-on-regression`: the run exits with code
`1` if any endpoint got worse.

---

## Options reference

```
Interactive mode
  -w, --wizard              build the command by answering questions, then run it

Language
  --lang LANG               language of the wizard, the help and the reports (en, es)

Targets
  TARGET...                 host, host:port, https://host/path, IP, [IPv6]:port
  -f, --file PATH           read targets from a file ('-' for stdin); repeatable
  -p, --port PORT           port, or comma list, for hosts that do not carry one
  --sni NAME                server name to send instead of the host (useful for an IP)

Scanning
  -t, --timeout SECONDS     maximum time per connection (default 6)
  -c, --concurrency N       targets in parallel (default 1)
  -r, --retries N           retries per target when a scan fails (default 1)
  -4, --ipv4                resolve target names to IPv4 addresses only
  -6, --ipv6                resolve target names to IPv6 addresses only
  --active                  active probes (offensive traffic; only with authorisation)

Trust (certificates)
  --ca-bundle PATH          PEM of trusted roots (default: the system store)
  --no-trust                do not validate the chain against any store

Conformance and plugins
  --profile ID              evaluate each endpoint against a profile (repeatable)
  --list-profiles           list the conformance profiles and exit
  --list-vulnerabilities    list the known vulnerabilities the policy checks, and exit
  --show-policy             show the active scoring policy (categories, weights, grade scale) and exit
  --plugin-dir DIR          load detection plugins from a directory (repeatable)
  --list-plugins            list the plugins that would load and exit

Output
  --format NAMES            console, text, json, csv, html, sarif, inventory, openmetrics
  -o, --output PATH         write the report to a file (base name with several formats)
  -q, --quiet               suppress the per-target progress on standard error
  -v, --verbose             report each endpoint and its grade when the scan finishes
  --color {auto,always,never}  colourise terminal output (default auto)
  --no-color                shorthand for --color never
  -s, --summary-only        print only the summary, without the per-target detail
  --notes                   include the policy's per-algorithm notes in console and text

CI gates
  --fail-on SEVERITY        exit with code 1 on a finding of that severity or worse
  --require-profile ID      exit with code 1 unless every endpoint conforms to the profile (repeatable)

Comparison and history
  --compare BASELINE        compare with a previous JSON report and show what changed
  --fail-on-regression      exit with code 1 if any endpoint got worse (with --compare)
  --history PATH            append this scan to a history file and show the grade trend
  --history-report          with --history, print how the estate moved across the scans

Policy
  --export-policy FILE      write a copy of the scoring policy to FILE and exit

Information
  --version                 show the version and exit
```

---

## Cookbook: one example per option

Everything that follows is copyable as-is. It is ordered by what you want to
achieve, not by the order of `--help`.

### The easiest way: the wizard

```bash
# Interactive mode                                   # -w, --wizard
./web-crypto-checker --wizard
./web-crypto-checker -w

# In Spanish (the wizard, the help and the reports)  # --lang
./web-crypto-checker --wizard --lang es
./web-crypto-checker example.com --lang en           # force English
```

### Choosing who to scan

```bash
# One server on 443
./web-crypto-checker example.com

# Explicit port, or a list of ports for hosts with no port         # -p, --port
./web-crypto-checker example.com:8443
./web-crypto-checker example.com -p 443,8443

# A URL with a path
./web-crypto-checker https://example.com/login

# IPv6 (in brackets if it carries a port), and a forced SNI         # --sni
./web-crypto-checker '[2001:db8::1]:443'
./web-crypto-checker 192.0.2.10 --sni example.com

# Several targets at once
./web-crypto-checker web01 web02 api.example.com

# From an inventory file (or from stdin)                            # -f, --file
./web-crypto-checker -f inventory.txt
awk '$1=="server_name"{print $2}' /etc/nginx/sites-enabled/*.conf | ./web-crypto-checker -f -
```

### Tuning the scan

```bash
# More time per connection and more parallelism      # -t, -c
./web-crypto-checker -f inventory.txt -t 15 -c 8

# Active probes (only against authorised servers)     # --active
./web-crypto-checker example.com --active
```

### Certificate trust

```bash
# Your own roots instead of the system store          # --ca-bundle
./web-crypto-checker example.com --ca-bundle ./roots.pem

# Do not validate the chain against any store          # --no-trust
./web-crypto-checker example.com --no-trust
```

### Conformance and plugins

```bash
# Evaluate against specific standards                  # --profile
./web-crypto-checker example.com --profile mozilla-modern --profile pci-dss-4
./web-crypto-checker --list-profiles                   # --list-profiles

# Inspect the policy before scanning                    # --list-vulnerabilities, --show-policy
./web-crypto-checker --list-vulnerabilities
./web-crypto-checker --show-policy

# Load your own detection plugins                      # --plugin-dir
./web-crypto-checker example.com --plugin-dir ./my-plugins
./web-crypto-checker --list-plugins                    # --list-plugins
```

### Reports

```bash
# Several formats in one pass (base + extension)      # --format, -o
./web-crypto-checker -f inventory.txt --format json,html -o audit

# Compare with a baseline and fail if it gets worse    # --compare, --fail-on-regression
./web-crypto-checker -f inventory.txt --format json -o today.json
./web-crypto-checker -f inventory.txt --compare today.json --fail-on-regression

# Historical series of grades per endpoint             # --history
./web-crypto-checker -f inventory.txt --history history.json

# How the estate moved across the recorded scans       # --history-report
./web-crypto-checker -f inventory.txt --history history.json --history-report
```

### CI gates: severity and conformance

```bash
# Fail (code 1) on a finding of this severity or worse         # --fail-on
./web-crypto-checker example.com --fail-on high

# Require every endpoint to conform to a profile               # --require-profile
./web-crypto-checker example.com --require-profile mozilla-modern
```

### Resolution and retries

```bash
# Retry each target that fails                          # --retries
./web-crypto-checker example.com --retries 2
./web-crypto-checker example.com -r 2

# Resolve to a single address family                    # --ipv4 / --ipv6
./web-crypto-checker example.com --ipv4
./web-crypto-checker example.com -4
./web-crypto-checker example.com --ipv6
./web-crypto-checker example.com -6
```

### Shaping the output

```bash
# Silence or expand the progress                        # --quiet / --verbose
./web-crypto-checker -f inventory.txt --quiet
./web-crypto-checker -f inventory.txt -q
./web-crypto-checker -f inventory.txt --verbose
./web-crypto-checker -f inventory.txt -v

# Explicit terminal colour                               # --color / --no-color
./web-crypto-checker example.com --color always
./web-crypto-checker example.com --no-color

# Only the summary, or with the per-algorithm notes      # --summary-only / --notes
./web-crypto-checker -f inventory.txt --summary-only
./web-crypto-checker -f inventory.txt -s
./web-crypto-checker example.com --notes
```

### Policy

```bash
# Export the policy to a file to edit it                 # --export-policy
./web-crypto-checker --export-policy policy.json
```

### Information

```bash
./web-crypto-checker --version                         # --version
```

---

## Limitations and legal notes

**Authorisation.** Scanning a server that is not yours can be illegal without
permission, and `--active` sends manipulated and potentially disruptive traffic
(Heartbleed, CCS injection, the ROBOT oracle…). Use `--active` **only** against
servers you are authorised to test. The tool reminds you when you launch it.

**What it does NOT do, on purpose and for a reason.** The hard rule is *never
emit a security signal without validating it*: when a check cannot be validated
or would not change any verdict, it is documented instead of faked.

- **Active *special DROWN* oracle** (CVE-2016-0703): there is no reproducible
  vulnerable server to validate it against, and supporting SSL 2.0 is already
  catastrophic on its own (it is detected and scored **F**).
- **CONTINUATION flood** (CVE-2024-27316) and **Rapid Reset** (CVE-2023-44487) of
  HTTP/2: the only reliable detection is to trigger the denial-of-service attack
  itself; a bounded heuristic false-positives on modern servers, so no verdict is
  emitted.
- **Key reuse in DROWN across hosts**: it requires querying an external service
  and scanning other hosts, incompatible with the zero-dependency, single-target
  design. The local precondition is detected (SSL 2.0 + export ciphers); the
  cross-host correlation is left out.

**Personal data.** A saved report contains details of the scanned server
(certificate fingerprints, headers). Treat it accordingly; the repository's
`.gitignore` keeps a report from being versioned by accident.

---

## License

MIT. See [`LICENSE`](../../LICENSE). The changelog is in
[`CHANGELOG.md`](../../CHANGELOG.md).

---

## Extension guides included

The categorized index of the extension manuals is
[`extender.md`](extender.md); these are its guides, installed beside this manual,
each in both languages (its Spanish version has the same file name):

- [`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md)
- [`politicas.md`](politicas.md)
- [`politica-algoritmos.md`](politica-algoritmos.md)
- [`politica-vulnerabilidades.md`](politica-vulnerabilidades.md)
- [`politica-configuracion.md`](politica-configuracion.md)
- [`politica-puntuacion.md`](politica-puntuacion.md)
- [`politica-normativas.md`](politica-normativas.md)
- [`auditoria-integridad.md`](auditoria-integridad.md)
- [`plugins.md`](plugins.md)
- [`plugin-check.md`](plugin-check.md)
- [`plugin-fleet.md`](plugin-fleet.md)
- [`plugin-vulnerability.md`](plugin-vulnerability.md)
- [`uso-avanzado.md`](uso-avanzado.md)
- [`desarrollo.md`](desarrollo.md)
