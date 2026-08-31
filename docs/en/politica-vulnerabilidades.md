# Policy manual — vulnerabilities

Back to the [manual](README.md) · related:
[algorithms](politica-algoritmos.md) · [configuration](politica-configuracion.md) ·
[conformance profiles](politica-normativas.md) · [Español](../es/politica-vulnerabilidades.md).

A known vulnerability is written entirely as data in the `vulnerabilities` list of
[`algorithms.json`](../../web_crypto_checker/data/algorithms.json). No programming
is needed: [`vulnerabilities.py`](../../web_crypto_checker/vulnerabilities.py) only
evaluates the tree of conditions already in the file. That is why it is the place
for everything detectable **from what a server offers on the wire**.

---

## The shape of an entry

```json
{
  "id": "SWEET32",
  "name": "Sweet32 (64-bit block cipher)",
  "severity": "medium",
  "description": "What happens and why it matters, for somebody meeting it cold.",
  "remediation": "Exactly what to do. An order, not advice.",
  "references": ["CVE-2016-2183"],
  "detection": { "cipher_tag": "3des" }
}
```

| Field | Required | Notes |
|---|---|---|
| `id` | **yes** | The stable report title and the translation key. |
| `name` | **yes** | Readable name. |
| `severity` | **yes** | `critical`, `high`, `medium`, `low`, `info`. Validated on load. |
| `description` | yes in practice | Write it for the person who reads it at two in the morning. |
| `remediation` | yes in practice | Without it, this is a complaint. |
| `references` | yes in practice | **Without a reference it is an opinion.** |
| `detection` | **yes** | The condition. Everything else in this manual. |

---

## The detection grammar

A condition is an object with **exactly one** key. There are two conditions that
look at something and three that combine others.
[`_validate_detection`](../../web_crypto_checker/policy.py) walks the tree **on
load**: a node with zero or two keys, or a badly written combination, gives an
error with the vulnerability's id instead of a rule that never matches and nobody
notices.

### `protocol` — a version is supported

```json
"detection": { "protocol": "ssl2" }
```

Matches if the server **supports** that version. The identifier is the same as in
the `protocols` class (`ssl2`, `ssl3`, `tls1_0`, `tls1_1`, `tls1_2`, `tls1_3`).
This is how DROWN (`ssl2`) and POODLE (`ssl3`) are detected: the presence of a
broken version is the vulnerability, and no suite configuration fixes it.

### `cipher_tag` — an offered suite carries a tag

```json
"detection": { "cipher_tag": "3des" }
```

Matches if **any** of the suites the server offers carries that shape-tag. The
tags are the same ones that classify the suites, derived from the name by
[`cipher_suite_tags`](../../web_crypto_checker/tls/constants.py) —see
[`politica-algoritmos.md`](politica-algoritmos.md).

> **Detecting by tag is what keeps the rule from ageing.** `{"cipher_tag": "cbc"}`
> still holds when a CBC suite that does not exist today appears; a list of names
> does not. It is also what leaves the evidence ready: the report names the
> concrete suites that fired the finding.

### `all`, `any`, `not` — for combining

```json
"detection": {
  "all": [
    { "any": [ {"protocol": "tls1_0"}, {"protocol": "tls1_1"} ] },
    { "cipher_tag": "cbc" }
  ]
}
```

That is the real BEAST: an old version (**TLS 1.0 or 1.1**) **and** a CBC suite.
`all` matches if every branch matches; `any`, if any does; `not`, if its branch
does not. They nest without limit. The evidence of an `all`/`any` is the union of
what matched below.

---

## Everything is observed on the wire

The ten entries are detected in a single way: **by looking at what the server
actually offers**. There is no by-product-version detection and no inference from
a banner, so there is no margin of error and no backport warning to give.
[`evaluate`](../../web_crypto_checker/vulnerabilities.py) builds the set of
supported protocols and the tags of every offered suite, and evaluates each tree
against them.

| id | Detection |
|---|---|
| `CVE-2016-0800` — DROWN | `protocol: ssl2` |
| `CVE-2014-3566` — POODLE | `protocol: ssl3` |
| `SWEET32` — 64-bit block | `cipher_tag: 3des` |
| `RC4` — keystream bias | `cipher_tag: rc4` |
| `FREAK-LOGJAM` — export grade | `cipher_tag: export` |
| `NULL-CIPHER` — no encryption | `cipher_tag: null` |
| `ANON-CIPHER` — no authentication | `cipher_tag: anon` |
| `DES` — single DES | `cipher_tag: des` |
| `CVE-2011-3389` — BEAST | `all[ any[tls1_0, tls1_1], cbc ]` |
| `NO-FORWARD-SECRECY` — no PFS | `cipher_tag: no-forward-secrecy` |

### What is detected here and what is detected elsewhere

This list covers the **passive** part: what is visible from merely negotiating.
Three related detections live outside, on purpose, because they are not a tree of
conditions:

- **DROWN / SSL 2.0.** The SSL 2.0 ClientHello has a different format, so it is
  not a TLS record: it is probed separately and surfaced as the `ssl2` protocol,
  which is what the condition above matches. That it also offers export ciphers
  (what makes DROWN practical, not merely possible) is its own finding,
  `SSLV2-EXPORT-CIPHERS`.
- **ROBOT / Bleichenbacher.** The surface is here, flagged passively: a suite
  without forward secrecy uses static RSA, which is exactly ROBOT's padding
  oracle. Confirming a **live** oracle is a separate active probe
  ([`tls/robot.py`](../../web_crypto_checker/tls/robot.py), behind `--active`),
  like Heartbleed or CCS injection.
- The other TLS-behaviour checks (renegotiation, CRIME compression, downgrade…)
  are findings, not vulnerabilities in this list; they are in
  [`politica-configuracion.md`](politica-configuracion.md).

> **Not looking is not the same as looking and finding nothing.** A detection that
> needs `--active` is not silently evaluated to "not vulnerable" when it was not
> asked for: the active probe simply did not run, and the report says so.
> Reporting a server as unaffected because nobody asked the question is the one
> failure mode this module cannot have.

---

## From detection to report

When a tree matches, [`evaluate`](../../web_crypto_checker/vulnerabilities.py)
produces a `VulnerabilityMatch` with the id, name, severity, description,
remediation, references and the **evidence**: the sorted list of the concrete
protocols and suites that fired the rule. The severity is what a vulnerability
weighs —there are no per-CVE modifiers or special caps—, and the ten sit alongside
the certificate, behaviour and HTTP-layer findings in the same report.

The grade is **not** moved directly by these entries: the ceiling is set by the
algorithm classes and the named caps (`any_insecure_offered`, `sslv2_supported`,
`sslv3_supported`, `weak_protocol_supported`…), which in practice cover the same
ground —an RC4 suite is `insecure` and fires DROWN at once. See
[`politica-algoritmos.md`](politica-algoritmos.md).

---

## Writing a new one, step by step

1. **Find the reference first.** The CVE, the advisory, the commit. If you cannot
   find it, do not write it.
2. **Decide what actually detects it, and that it is observable on the wire.** Is
   it a supported version? Is it a tag of an offered suite? Both? Write the
   narrowest condition that is correct.
3. **Prefer `cipher_tag` over names.** If the tag you need does not exist yet, it
   is added in [`cipher_suite_tags`](../../web_crypto_checker/tls/constants.py),
   not in this list: that way classification and detection share the same truth.
4. **Write `remediation` as an order.** "Disable 3DES suites", not "consider
   reviewing".
5. **Test it both ways**: that it fires on a server with the defect and that it
   does **not** fire on a modern one.

```bash
web-crypto-checker --config my-policy.json vulnerable-example.test
web-crypto-checker --config my-policy.json example.com   # must not appear
```

---

## The three mistakes people make

**Detecting by name what should be detected by property.** If you write out the
list of the CBC suites you know today, your rule ages. Use `cipher_tag`.

**Putting here what needs an active probe.** This grammar only sees what is
offered. A live oracle, Heartbleed or CCS injection are confirmed with `--active`,
not with a `cipher_tag`.

**Forgetting the remediation.** A report with ten findings and no instructions
changes nothing on any server.
</content>
