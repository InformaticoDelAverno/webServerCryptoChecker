# Development manual

Back to the [manual](README.md) · related: [advanced usage](uso-avanzado.md) ·
[plugins](plugins.md) · [conformance profiles](politica-normativas.md) ·
[Español](../es/desarrollo.md).

> The repository map and the user guides are in the [README](README.md); each
> directory also has its own `README.md`.

## Structure

```
web_crypto_checker/
├── cli.py             Command line and exit codes
├── wizard.py          The interactive wizard (--wizard)
├── targets.py         Target parsing (host:port, IPv6, URL, files)
├── scanner.py         Orchestration: resolve, enumerate, assemble the report
├── assessment.py      Grade (A+…F), verdict and findings
├── strength.py        Effective security strength in bits (NIST SP 800-57)
├── policy.py          Loading and querying the editable policy
├── vulnerabilities.py Engine of the declarative vulnerability rules
├── compliance.py      Evaluation against the standards in data/profiles/
├── compare.py         Compare against an earlier report (--compare)
├── history.py         Grade history series (--history)
├── dns.py             DNS client: CAA, DANE/TLSA, HTTPS/SVCB
├── dnssec.py          DNSSEC validation up to the IANA root
├── resolver.py        Own iterative DNS resolver (root hints)
├── http_layer.py      The HTTP layer: HSTS, CSP, cookies, redirect
├── mixed_content.py   Active/passive mixed content
├── subresource_integrity.py   Missing Subresource Integrity
├── webclient.py       Cleartext HTTP/1.1 client (OCSP and CRL share it)
├── models.py          Shared dataclasses and JSON serialization with redaction
├── i18n.py / messages.py   The translator and the bilingual catalogue
├── tls/               The by-hand TLS engine (codec, probe, enumeration, active probes)
├── quic/              The by-hand QUIC / HTTP-3 engine (RFC 9000/9001)
├── pki/               Certificates, chain, ROCA, CT, OCSP, CRL
├── crypto/            Own primitives (AES, GCM, ChaCha, ECDSA, Ed25519, RSA, X25519, DER…)
├── application/       Application protocols: HTTP/2, HPACK, gRPC, wss, SSE, mTLS
├── reporting/         One renderer per format (eight)
├── plugins/           Checks that need code (not a rule)
├── web/               The web interface (http.server, no dependencies)
├── mcp/               The MCP interface (JSON-RPC over stdio, no dependencies)
└── data/
    ├── algorithms.json  The default policy (algorithms, rules, thresholds)
    ├── profiles/        The standards, one directory each, one file per edition
    ├── ct_logs.json     The known Certificate Transparency logs
    └── i18n/            The translatable overlay of the policy
```

Data flow:

```
targets.py  ->  scanner.py  ->  tls/ · quic/ · pki/ · dns/ · application/   (network)
                     |
                     v
     assessment.py + strength.py + vulnerabilities.py + compliance.py       (judgement)
                     |            (+ policy.py, data/algorithms.json)
                     v
                 models.py                                            (TargetResult)
                     |
                     v
                reporting/*                                            (presentation)
```

Design rules worth respecting:

- **Zero runtime dependencies.** Only the Python 3.9+ standard library. The TLS
  records, the QUIC engine, the DNS client and all the cryptography needed to
  enumerate what a server offers are in the package itself — not taken from OpenSSL —
  so the same probe reaches an old server a modern OpenSSL would refuse to speak to.
- **Data, not code.** The algorithms, the vulnerabilities, the scoring, the caps and
  the standards live in editable JSON. If you are writing an algorithm's name inside a
  `.py`, it probably belongs in `algorithms.json`. What has to be **computed** — and
  only that — is a plugin.
- **Renderers do not judge.** They receive an already-analyzed `TargetResult` and
  only present it. All the grade-and-verdict logic lives in `assessment.py`.
- **The errors of one target do not abort the scan.** `scan_target` captures its own
  exceptions and returns a result with `status=error`, with the reason, rather than
  bringing the run down. A hostile or broken endpoint does not take the rest of the
  fleet with it.

## Coverage: two gates that do not fall

**Two things are measured separately, and they answer different questions.**

| Measurement | How | What it answers | Figure |
|---|---|---|---|
| Combined (unit + lab) | `.coveragerc`, `fail_under = 100` | How much of the code *some* test runs | **100 %** |
| The lab e2e alone | `tools/e2e_floor.py` | How much runs **against real TLS servers** | **~98 %** (a per-module ratchet) |

### The first: 100 %, without a single exclusion

`.coveragerc` measures with `--branch` and requires
`fail_under = 100`: **100 % of statements and 100 % of branches**, with no
`exclude_also` and no `exclude_lines`. There is nothing in that file that tells
coverage to look the other way. An exclusion is a piece of code nobody has ever run,
wearing a note that says not to worry; there are none here, and that is the goal. A
change that stops exercising a path fails **at once**, not a year later; lowering the
threshold demands an explanation in the commit message.

`source` in `.coveragerc` includes **two** trees: the `web_crypto_checker` package
and `lab/` (the lab runner, `lab/audit.py`, which is code and
is tested with the network mocked in `tests/test_lab_audit.py`). Both at 100 %.

```bash
pip install coverage        # the only development dependency; the tool has none
python3 -m coverage run --branch --source=web_crypto_checker -m unittest discover -s tests -t .
python3 -m coverage report -m
```

The unit suite reaches that 100 % **on its own**, with no Docker and no network:
`tests/fake_tls_server.py` brings up a minimal, scriptable TLS server on `127.0.0.1`
— it reads a `ClientHello` and answers with whatever it is told: a `ServerHello`, an
alert, a certificate or garbage — to drive the probe through all of its branches
without a real TLS stack.

### The second: the e2e alone, a floor that does not fall

The combined figure blends the unit tests (against doubles and vectors) with the run
of the *tool instrumented inside the lab*, and `lab/coverage.sh` **merges** them with
`coverage combine` into one figure — `.coveragerc`'s `relative_files = True` is what
lets a run on the host and one inside the container (where the tree is at `/src`)
produce identical names and merge.

But a combined percentage does not protect against the lab quietly stopping
exercising a path: the unit tests would mask it and the 100 % would not move. So
there is a **second, independent gate** on the lab e2e **alone**
(`tools/e2e_floor.py` +
`tests/e2e-coverage-floor.json`). It is a
**per-module ratchet**: it records how many items (statements + branches) the e2e run
leaves **uncovered** today, and fails if any module exercises **less** than before.

```bash
( cd lab && docker compose up -d )   # the lab must be up
./lab/e2e-gate.sh                     # sweep, merge with coverage combine, enforce the floor
./lab/e2e-gate.sh --update            # re-baseline the floor (only for genuinely unit-only code)
```

The ratchet only **tightens** on its own (a run that covers more) or is **raised by
hand**, and raising it wants a reason in the commit, exactly like lowering
`fail_under`. Adding code no scan can reach (import surface, error branches that are
only simulated) legitimately raises a module's uncovered count; when that happens, it
is re-baselined with `--update` and the reason is stated.

**The e2e does not reach 100 %, and cannot.** There are branches **no real server
produces**: signature verification with Ed25519/RSA-PSS/ECDSA vectors, `CERT-ROCA`,
DANE/DNSSEC validated up to the IANA root (the root key cannot be forged), SCT
verification against known CT logs, the positive ROBOT oracle, the ASN.1/wire parse
error paths, and the ciphers this OpenSSL no longer ships (RC4, 3DES, export, SSLv2).
That is exactly what the unit tests cover; that is why the 100 % is the **combined**
one.

### The lab

`lab/` is a set of web servers with **known postures** in
Docker, to test end to end against real servers rather than doubles. It has two
halves:

- **Protocol servers** (`lab/docker-compose.yml`): a Caddy (TLS 1.2/1.3, HTTP/2,
  HTTP/3, wss and SSE), an nginx (TLS 1.2/1.3, no HTTP/3), a WebSocket echo backend
  and a `grpcbin` (gRPC over TLS). Scanned with SNI `localhost`.
- **Audit lab** (good vs bad): nginx serving each scenario on its own port — valid,
  expired, wrong host, self-signed, untrusted, SHA-1 signature, bad HTTP headers,
  cleartext HTTP — with certificates generated on the fly by its own lab CA.
  `lab/audit.py` scans each one and **checks the expected
  verdict and findings**, printing PASS/FAIL and exiting non-zero if anything is off.
  It is the best hunt for false positives and negatives.

`lab/e2e.sh` is the full sweep that feeds the second gate: it exercises the CLI for
**each report format** and **each profile**, `--compare`/`--history`/`-f`/`-p`, URLs,
`--active` probes, and stands up the infrastructure the network paths need — a DNS
leg with `bind9` for CAA/TLSA/HTTPS, pre-signed OCSP/CRL responses and AIA chain
completion, hostile and malformed endpoints for the error handling, a QUIC responder
built with the tool's own crypto, captured DNSSEC fixtures. The detail of each piece
is in the lab README.

The integration tests (`tests/test_lab.py`) are **skipped** if the lab is not up, so
the usual CI gate (no Docker) is unaffected.

## That a line runs does not mean anyone is watching it

Coverage records that the interpreter went through a line, not that anyone would
notice if that line did something else. A 100 % built out of lines like that protects
nothing, so there is a second question and a tool that answers it
(`tools/mutation_gate.py`; its per-file cousin, for
quick manual passes, is `tools/mutants.py`):

```bash
python3 tools/mutation_gate.py            # check against the baseline
python3 tools/mutation_gate.py --update   # record what survives now
python3 tools/mutation_gate.py --only policy   # one module, while you work
```

It breaks the code on purpose, one small change at a time, and runs the tests. What
makes a test fail is **dead**: someone was watching. What nobody notices **survives**,
and it is a line the suite visits without looking.

| The change | And it is a real bug |
|---|---|
| `<` becomes `<=` | an off-by-one at a boundary |
| `==` becomes `!=` | an inverted condition |
| `and` becomes `or` | a widened guard |
| `0` becomes `1` | a changed default |
| `+` becomes `-` | an arithmetic slip |
| **a `raise` disappears** | a swallowed error: bad input accepted, broken policy loaded, malformed record read as if it made sense |
| **a `return` returns `None`** | a forgotten answer: whoever uses it finds out, whoever ignores it never used it |

Three decisions worth knowing about, all learned by getting them wrong:

- **There is no source-file-to-test-module map.** Each mutant faces the **whole
  suite**. A map is an optimisation that fails in the flattering direction: a
  cipher's vectors need not live in the module named after it, so a mutant in that
  cipher would be judged by tests that do not touch it and reported as unnoticed.
  Parallelism buys the speed the map was trying to buy.
- **The sandbox compiles with `-B`.** A sandbox is reused between mutants, and on a
  filesystem with coarse mtime a same-size edit (`==`↔`!=`, `+0`↔`-0`, `and`↔`or`,
  one digit for another) leaves date and size intact, so CPython would run the old
  `.pyc` and the mutation **would never execute**. `-B` forces a fresh compile every
  time.
- **A survivor is confirmed with the machine quiet**, and the lab has the last word:
  a candidate — something the unit suite did not kill — is handed to
  `LabIntegrationTests` before being written into the list, so that "survivor" means
  "nothing catches it", not "the fast half does not catch it".

The survivors are listed in
`tests/mutation-baseline.json`; the list **may
only get shorter**, and the gate fails the moment a new one appears or one on the list
becomes killed (the list would no longer be true). Each survivor is additionally
pinned by a real assertion in the `tests/test_mut_*.py`, each verified by applying the
exact mutation with fresh bytecode.

## Running the tests

```bash
python3 -m unittest discover -s tests -t .     # everything
python3 -m unittest tests.test_assessment -v   # one module
python3 -m unittest tests.test_crypto.CurveTests.test_generator_is_on_the_curve
```

No dependencies and no network are needed. The inventory of what each file tests is in
`tests/README.md`; two deserve a mention:

- **`tests/test_crypto.py`** compares the constants of the curves and the primes not
  against a copy of themselves — that would detect nothing — but against their
  **mathematical properties**: that the generator is on the curve, that `n·G` is the
  point at infinity, that the moduli are prime. A typo in any digit makes the test
  fail.
- **`tests/test_coverage_gates.py`** is this chapter's warden: it checks that
  `.coveragerc` still has no exclusions and keeps branches on, that the e2e floor and
  the mutation baseline still hold, and that there are no duplicate tests.

## Where each thing lives

| | |
|---|---|
| `scanner.py` | The **orchestrator**: what is probed, in what order, and what is assembled. It decides no grade |
| `assessment.py` | The **grade model**: it classifies, computes the letter, the verdict and the findings, with caps by named conditions. **Not extensible by plugins** |
| `strength.py` | The **effective strength in bits**: the weakest link among the classes the server would use |
| `policy.py` + `data/algorithms.json` | The **algorithms, the rules and the thresholds**: classify a version, a suite, a group or a signature |
| `vulnerabilities.py` | The **engine** of the declarative vulnerability rules (`all`/`any`/`not`) |
| `compliance.py` + `data/profiles/` | The **conformance** with each standard, one edition per file |
| `plugins/__init__.py` | What a plugin **is**: metadata, return types, the read-only `ServerView` it receives |
| `plugins/runner.py` | How a plugin's answer becomes a result |
| `plugins/builtin/` | The built-in checks, one per subject |

## Adding a check

A check lives in one of two places, and choosing well is half the work.

- **If it is decided by comparing something the server announces** — an algorithm
  name, a suite tag, a version — it is a **declarative rule** in the JSON, no code:
  the algorithms and their tags in `data/algorithms.json`, and the vulnerabilities as
  a tree of conditions (`all`/`any`/`not`) in the same file. A standard is a profile
  in `data/profiles/`; see [conformance profiles](politica-normativas.md).
- **If it has to *compute* something** — factor a modulus, subtract two dates,
  correlate two observations — it is a **plugin**: see [plugins](plugins.md), where
  the full contract separates what `check(server)` sees from what the runner does with
  its answer.

When in doubt, try a rule first: it runs no code, can be edited by a non-programmer
and cannot break a scan. Both forms are tested against the lab.

## The house rules

Four things the system guarantees, with a test that fails if you break them:

1. **A broken plugin does not break a scan.** Whatever it raises is caught and
   reported as a finding that names it.
2. **No plugin changes the grade.** It receives a read-only `ServerView` of what was
   *observed* — never the score, the grade or the verdict — and its result is added
   **after** scoring. A test scans with all the plugins and with none and requires
   `score`, `grade` and `verdict` to match.
3. **Not looking is not not finding.** If a check could not be done, it is said
   (*not assessed*); it is never reported as "not affected" nor as *pass*.
4. **No vulnerability gets special treatment.** Renaming one changes neither the
   analysis nor any of the eight reports, and no policy field belongs to a single
   entry (`tests/test_no_privileged_vulnerability.py`).

## Adding an output format

Create `reporting/my_format.py` with a `render` function and register it in `FORMATS`
and `EXTENSIONS` of
[`reporting/__init__.py`](../../web_crypto_checker/reporting/__init__.py). There are
two signatures on purpose: the **human** formats (`console`, `text`, `html`) take
`(report, translator)` and render in the scanner's language; the **machine** formats
(`json`, `csv`, `sarif`, `inventory`, `openmetrics`) take `(report)` and keep their
keys and values in English, because they are a contract for other tools, not prose for
people. The contract tests in `tests/test_reporting.py` pick the new format up
automatically and require that none says anything different about the same scan.

## Style

```bash
pip install -e '.[dev]'
ruff check . && ruff format --check .
mypy web_crypto_checker
```

100-column lines, type annotations on all public functions,
`from __future__ import annotations` in all modules (compatibility with Python 3.9,
the oldest interpreter it claims to support and that `tests/test_portability.py`
genuinely checks).

## Continuous integration

`.gitlab-ci.yml` has three stages — `test`, `lint`, `package`
— and eight jobs:

| Job | What it does |
|---|---|
| `tests` | The full suite with coverage, `fail_under = 100` |
| `tests:python3.9` | The same suite on the oldest supported interpreter |
| `coverage:gates` | The ratchets: `.coveragerc` with no exclusions, the e2e floor and the mutation baseline, and the gate itself. It costs seconds and runs **on every push** |
| `coverage:mutation` | The whole-package mutation testing against its baseline |
| `coverage:lab` | Brings up the lab and takes **both** measurements (the combined 100 % and the e2e floor); it is many containers, so it runs by hand or on a schedule. It shares its script with `make ci-lab` via `lab/ci-lab.sh` |
| `lint` | `ruff` + `mypy` |
| `package` | Builds the wheel and sdist and checks the console script |
| `release:dist` | The public distribution, packaged by `tools/release.py`, which is **outside** the covered code (so it does not enter the 100 % gate) |
