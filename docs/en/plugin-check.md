# Guide to `check` plugins

> Before this, read [`plugins.md`](plugins.md): the metadata, what can be
> returned and the two guarantees (a plugin cannot change the grade, a plugin
> cannot bring the scan down) are common to both kinds. · [Español](../es/plugin-check.md).

A `check` looks at **one server** and gives an opinion about it. Its result
appears in the report as a finding (`Finding`), next to the ones the core
analysis produces. The three built-in plugins the tool ships with are all of
this kind.

```python
KIND = "check"

def check(server):   # `server` is a ServerView
    ...
```

---

## What `server` is

A `ServerView`: **what was observed**, and none of what was concluded. It has no
score, no grade, no verdict, and it never will. That boundary is the point: as
an observation, a plugin cannot cause a false fail.

Everything below has an answer even if the scan collected little. An endpoint
that negotiated nothing gives empty lists, not an error.

### The protocols

| | |
|---|---|
| `server.supported_protocols` | The ids of the versions the server accepts: `"tls1_0"`, `"tls1_1"`, `"tls1_2"`, `"tls1_3"`. Only the accepted ones. |
| `server.supports("tls1_0")` | Whether it accepts that specific version. |

### The cipher suites

| | |
|---|---|
| `server.offered_ciphers` | The names of every suite the server accepts, e.g. `"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"`. |
| `server.offers_cipher(name)` | Whether it offers that specific suite. |
| `server.cipher_tags(name)` | The **shape-tags** of a suite, read mechanically from its name: `cbc`, `aead`, `rc4`, `3des`, `des`, `md5`, `sha1`, `null`, `anon`, `export`, and `pfs` or `no-forward-secrecy`. Reasoning by tag instead of by name keeps your plugin working when a suite that does not exist today shows up. |

> Unlike the algorithm policy, `cipher_tags` consults no table: it derives them
> from the standardised name, which is structured on purpose. An uncatalogued
> suite has its tags all the same.

### The groups and signatures

| | |
|---|---|
| `server.key_exchange_groups` | The offered key-exchange groups, by name. |
| `server.signature_algorithms` | The advertised signature algorithms. |

### The certificate

`server.certificate()` (the same as `server.leaf`) is the leaf certificate, or
`None` if none was collected. **Check for `None` before using the rest.**

The object is a `CertificateInfo` ([`../../web_crypto_checker/models.py`](../../web_crypto_checker/models.py)).
The most-used fields:

| | |
|---|---|
| `leaf.subject`, `leaf.issuer` | The subject and issuer DNs. |
| `leaf.sans` | The subject alternative names. |
| `leaf.key_type` | `"RSA"`, `"EC"` or `"Ed25519"`. |
| `leaf.key_bits`, `leaf.curve` | The key size, and the curve (`"P-256"`…) if it is EC. |
| `leaf.not_before`, `leaf.not_after` | Validity start and end, **as Unix time** (`int`) or `None`. The date arithmetic is yours. |
| `leaf.signature_algorithm` | The algorithm it was signed with. |
| `leaf.roca_vulnerable` | Whether the RSA key bears the ROCA fingerprint. |
| `leaf.is_self_signed`, `leaf.is_ca`, `leaf.path_length`, `leaf.key_cert_sign`, `leaf.extended_key_usages` | Basic constraints, key usage and extended key usages. |
| `leaf.fingerprint_sha256` | The fingerprint, to cite as evidence. |
| `leaf.sct_count`, `leaf.verified_scts`, `leaf.sct_logs` | The embedded SCTs (Certificate Transparency) and how many verify. |
| `leaf.ocsp_must_staple`, `leaf.ocsp_url`, `leaf.ca_issuers_url`, `leaf.crl_urls` | Must-staple, and the OCSP, issuer and CRL URLs. |

It also carries methods: `leaf.is_expired(now)`, `leaf.is_not_yet_valid(now)`
and `leaf.days_until_expiry(now)`, all taking the moment as Unix time.

### The CAA records

`server.caa_records` is the list of the domain's CAA records; each has `flags`,
`tag` (`"issue"`, `"issuewild"`, `"iodef"`…) and `value`. An empty list means
the domain publishes no CAA.

### The assessments

`server.assessment(key)` returns how a class came out against the policy, or
`None` if it was not evaluated. The keys are `"protocol"`, `"cipher"` and
`"certificate"`. The object (`ClassAssessment`) carries `worst_category`,
`score` and, most useful to a plugin, `preferred`: **the server's first
choice**, which is what a permissive client negotiates.

---

## A complete example

A server can offer a modern AEAD suite and still **prefer** a CBC one. Detecting
that is not "offers CBC" (that is a policy rule): it is correlating what it
prefers with what it has available, which can only be done in code. Note that it
reasons by **tags**, so it will still hold when someone adds a suite that does
not exist today.

```python
"""The server prefers a CBC suite while AEAD ones are available."""

from web_crypto_checker.plugins import Detected, ServerView

ID = "prefers-cbc-over-available-aead"
NAME = "Server prefers a CBC suite while it could prefer AEAD"
KIND = "check"
SEVERITY = "low"
DESCRIPTION = (
    "The server's first choice is a CBC-mode suite, even though it also offers "
    "AEAD suites a modern client would prefer. Not insecure on its own, but it "
    "leaves permissive clients out of authenticated encryption."
)
REMEDIATION = (
    "Order the server's suite list to prefer AEAD suites "
    "(GCM or ChaCha20-Poly1305) ahead of the CBC ones."
)
REFERENCES = ["https://datatracker.ietf.org/doc/html/rfc7525#section-4.2"]


def check(server):
    ciphers = server.assessment("cipher")
    if ciphers is None or not ciphers.preferred:
        return None
    preferred = ciphers.preferred
    if "aead" in server.cipher_tags(preferred):
        return None                    # already prefers an AEAD, nothing to say
    aead = [c for c in server.offered_ciphers if "aead" in server.cipher_tags(c)]
    if not aead:
        return None                    # no better option to offer: not this
    return Detected(evidence=[
        f"preferred: {preferred} [{', '.join(server.cipher_tags(preferred))}]",
        f"AEAD available: {', '.join(sorted(aead))}",
    ])
```

Note the three decisions:

1. **It returns `None` when there is nothing to say**, which is the normal case.
2. **The alternative is checked before reporting**: complaining about a
   preferred CBC suite when there is no AEAD to offer would be noise, and noise
   gets everything else ignored.
3. **The evidence says exactly which suites**, not "prefers CBC".

---

## Always wrap the evidence in `Detected`

The runner understands only four answers ([`../../web_crypto_checker/plugins/runner.py`](../../web_crypto_checker/plugins/runner.py)):

- `None` or `False` — nothing to report.
- `Detected(evidence=[...], severity=None, note="")` — a finding, with its
  evidence. `severity` optionally overrides the plugin's; `note` appends text.
- `Undetermined(needs=[...])` — it could not decide, and says what would settle it.
- Any other truthy value — taken as "affected, no evidence".

That last row is the trap: **returning a list of strings attaches no evidence**,
it reads as a bare `True`. If you want the evidence lines in the report, they go
inside `Detected(evidence=[...])`. And one file produces **one** finding with
the plugin's `ID`; there is no way to emit several findings with distinct ids
from the same file.

---

## When **not** to write a `check`

- **If the check is "this suite or this version is bad"**: that is a declarative
  policy rule, not code — a name, a tag, a version window — and someone who does
  not program can add it. See [`plugins.md`](plugins.md) and the
  [conformance profiles](politica-normativas.md).
- **If it is just reading a field and comparing it to a fixed value**: that
  almost always fits as a rule too. Write a plugin when something has to be
  **computed**: date arithmetic, correlating two observations, parsing bytes.
