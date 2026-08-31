# Advanced usage manual

Back to the [manual](README.md) · related: [development](desarrollo.md) ·
[plugins](plugins.md) · [conformance profiles](politica-normativas.md) ·
[Español](../es/uso-avanzado.md).

> Every option also has its example in the [README](README.md) "Cookbook".

The basics — one target, a grade, a report — are in the README. What lives here is
what you do not use on day one: comparing against an earlier audit, scanning a fleet
from a file, and what the tool checks **on its own** without being asked — mTLS, the
controls that live in DNS, certificate trust — plus the probes that only fire **with
permission**.

## Comparing against an earlier scan

A report says how a server stands today. What you usually need to know is **what
changed**: what appeared since the last audit, what got fixed, and what quietly got
worse after a package update nobody announced.

`--compare` takes an earlier JSON report as a baseline
([`compare.py`](../../web_crypto_checker/compare.py)):

```bash
# Save the baseline
web-crypto-checker -f inventario.txt --format json -o base.json

# ... weeks later ...
web-crypto-checker -f inventario.txt --compare base.json
```

```
Changes since the baseline:
  example.com:443@192.0.2.10: regressed, grade A -> C
  example.com:443@192.0.2.10: NEW finding HTTP-MIXED-ACTIVE
  example.com:443@192.0.2.10: NEW vulnerability SWEET32
  example.com:443@192.0.2.10: now offers cipher TLS_RSA_WITH_3DES_EDE_CBC_SHA
  example.com:443@192.0.2.10: no longer offers protocol TLS 1.3
  example.com:443@192.0.2.10: certificate changed 4f2a… -> 9b71…
```

It reports, for each endpoint (keyed by `host:port@address`):

- **Grade movement**, saying whether it improved or got worse.
- **New and resolved findings and vulnerabilities**, by **identifier**, not by
  text: a finding that reappears is not mistaken for a new one, and rewording a
  message does not muddy the comparison.
- **Algorithms added and withdrawn**, by class (protocol, cipher…).
- **The leaf certificate's fingerprint changing**: on a server nobody reissued, a
  new fingerprint is a reason to stop and find out why. It earns a line, but it is
  **not** a regression by itself.
- **New endpoints** (`new endpoint`) and **endpoints that were in the baseline and
  no longer appear** (`gone from the scan`).

A **new** finding or vulnerability marks the comparison as a **regression**; a grade
that drops does too. The comparison is done over the JSON, so the baseline can be a
stored artifact from an earlier CI run: the tool does not need to store anything, and
`load_baseline` accepts both the bare JSON and one wrapped in `{"report": …}`.

With `--fail-on-regression` the process exits with **code 1** if any endpoint got
worse, even if its absolute state is still acceptable. It is the difference between
"this does not comply" and "this has got worse", and on a large fleet the second is
the one you catch in time:

```yaml
# .gitlab-ci.yml — fail the pipeline if any server regresses
web-audit:
  script:
    - web-crypto-checker -f inventario.txt --format json -o informe.json
                         --compare base.json --fail-on-regression
```

### History: the series, not just the jump

`--compare` answers "what changed since that report". What it cannot answer is
"since when has this been the case", because a baseline is a single point.
`--history` accumulates each scan into a file — one JSON line per endpoint and run —
and, when it finishes, shows the **grade series** of every endpoint in the current
scan ([`history.py`](../../web_crypto_checker/history.py)):

```bash
web-crypto-checker -f inventario.txt --history historico.jsonl
```

```
Grade history:
  web01.example.com [192.0.2.10]: A -> A -> B
  web02.example.com [192.0.2.11]: A+ -> A+ -> A+
  api.example.com [192.0.2.20]: C -> B -> A
```

It is **JSON Lines** and not an array, because appending to an array forces
rewriting the whole file, and a scan interrupted midway through that rewrite leaves
you **with no history**. Each line keeps just enough — timestamp, target, IP, grade,
score, verdict and vulnerability count — to draw the trend without dragging the whole
report along. `--history` and `--compare` are cousins: use the first to watch the
whole fleet's drift over time, and the second for the exact diff against one specific
point.

---

## Inventory file and standard input

One target per line ([`targets.py`](../../web_crypto_checker/targets.py)). `#` starts
a comment. Whatever follows the first whitespace-separated token is used as the
**label** in the report (there is a sample inventory ready to copy in
[`examples/`](../../examples/README.md)):

```
# Production inventory
web01.example.com            web frontend
web02.example.com:8443       web frontend (alternate port)
https://api.example.com/health   API with a specific path
192.0.2.10                   database
[2001:db8::1]:443            edge router
example.com                  # just a comment, no label
```

```bash
web-crypto-checker -f inventario.txt
```

It can be read from standard input with `-f -`, which fits any pipeline that
produces host names:

```bash
awk '$1=="server_name"{print $2}' /etc/nginx/sites-enabled/*.conf \
    | web-crypto-checker -f -
```

The ways to name a target — a name, `host:port`, a URL with scheme and path, IPv4,
IPv6 with or without brackets, `user@host` (the user is ignored) — are the same in
the file as on the command line. Three details worth knowing:

- **`-f` is repeatable** and mixes with the loose targets on the command line;
  everything joins one list.
- **Duplicates are removed** (same host — case-insensitive — and same port), keeping
  the first occurrence so its label and path survive.
- **A malformed line does not abort the file**: it is reported on `stderr` and
  processing continues, so a long inventory is scanned in full even if one line is
  broken.

### One host, several ports

A host **with no port of its own** expands across **each port in `-p`**, so "one
host, several ports" produces one target per port. A host that carries its own port
(`example.com:8443`) does not expand.

```bash
# Scan both 443 and 8443 of every host that names no port
web-crypto-checker -f inventario.txt -p 443,8443
```

The default **SNI** is the host name; a bare IP is sent no SNI (RFC 6066 forbids
it), and `--sni NAME` forces one — which leads to the next section.

---

## Behind a load balancer or a CDN: one IP per address

A domain behind a load balancer or a CDN can be **configured differently on each
machine** that answers. That is why a target does not resolve to "an" address: the
tool resolves **every** address of the host — IPv4 and IPv6 — and produces **one
result per address**, the way SSL Labs and sslyze do
([`scanner.py`](../../web_crypto_checker/scanner.py)). The SNI on the wire stays the
host name whichever address answered, so every copy behind the balancer is judged
separately without fooling the negotiation.

When you want to audit a **specific** machine by its address — the node you suspect
was left unpatched — pass it as an IP and **force the SNI** with `--sni`, because a
bare IP carries none and a server doing name-based virtual hosting would present the
wrong certificate (or none):

```bash
# The exact address, but with the name the server expects in the SNI
web-crypto-checker 192.0.2.10 --sni example.com
web-crypto-checker '[2001:db8::1]:443' --sni example.com
```

It is the web analogue of "hopping through an intermediary": there is no client or
tunnel to configure here — the tool opens its own sockets — what you need is to
**point at the right address with the right name**.

---

## mTLS: client-certificate authentication

A server that authenticates its clients with certificates sends a
`CertificateRequest` during the handshake. The tool detects it **on its own**, with
no option to enable, on every `https` scan
([`application/mtls.py`](../../web_crypto_checker/application/mtls.py)), and it tells
two things apart that are not the same:

| State | What it means |
|---|---|
| **Requested** (`requested`) | The server **asks** for a client certificate, but completes the handshake without one |
| **Required** (`required`) | The server **refuses**, with an alert, a handshake finished with an empty certificate |

Which of the two it is matters: a server that "requests" but does not "require" lets
an anonymous client through, which is almost never what its administrator thinks they
configured. The probe learns it **without credentials**: it finishes the handshake
with an empty certificate and watches whether the server accepts or rejects it. It
works on TLS 1.3 — where both come from a single handshake — and on TLS 1.2 — where
the `CertificateRequest` travels in cleartext in the server's first flight — so
enforcement is determined on either version. An `http://` target negotiates no
certificate and is not probed.

---

## The controls that live in DNS: CAA, DANE/TLSA and HTTPS/SVCB

Not everything that protects a certificate is in the handshake. Three controls live
in **DNS**, and `getaddrinfo` does not reach them, so the tool brings its own **DNS
client** ([`dns.py`](../../web_crypto_checker/dns.py)) that builds each query by
hand. They are **automatic** too: checked on every target that has a domain (a bare
IP has none, and is not queried).

| Control | RFC | What it is |
|---|---|---|
| **CAA** | 8659 | Which authorities a domain authorises to **issue** for it |
| **DANE/TLSA** | 6698 | The certificate or key pin, at `_<port>._tcp.<host>` |
| **HTTPS/SVCB** | 9460 | The **ALPN**, the alternative port and whether the domain publishes **ECH** (encrypted SNI) |

For DANE, the tool does not just look at whether the record exists: it checks the
**presented chain** against the TLSA records **fully** — every usage (end-entity or
CA anchor, with the PKIX condition of the `PKIX-*` usages), both selectors
(certificate or public key) and all three matching types (exact, SHA-256, SHA-512) —
not just the common form.

### And it is all authenticated by DNSSEC

An unsigned DNS record can be **forged** by whoever controls the path: a fake CAA
would fool a CA at issuance time, a fake TLSA pinned by an attacker undoes the point
of DANE. So, when records are present, the tool **validates their DNSSEC signature up
to the IANA root key itself, in code**
([`dnssec.py`](../../web_crypto_checker/dnssec.py)) — verifying every RRSIG and every
DS — rather than trusting a resolver's *authenticated data* bit. It queries with the
DO + *Checking Disabled* bits so it is handed the raw records, and it obtains them
over its own **iterative resolver** ([`resolver.py`](../../web_crypto_checker/resolver.py))
that walks the delegation from the root hints, **without going through any
third-party recursive resolver**.

Two consequences that show up in the report:

- **It fails closed.** Any doubt in the chain → *not validated*, never a false
  *validated*. `CaaInfo.dnssec_validated`, `DaneInfo.dnssec_validated` and
  `HttpsRecord.dnssec_validated` tell "genuine" from "could be tampered with".
- **Absence is proven too.** When there is no TLSA, the tool does not shrug: it
  verifies the **authenticated denial** (NSEC/NSEC3) so that "no DANE" is a proven
  fact and not a record someone stripped along the way.

---

## Active probes (`--active`)

Everything above is **passive**: it opens connections and reads what the server
offers, as any client would. `--active` adds probes that **send crafted, potentially
disruptive traffic**, so it is off by default and the tool prints an authorisation
notice when you launch it:

```bash
web-crypto-checker example.com --active
```

What it adds ([`scanner.py`](../../web_crypto_checker/scanner.py),
[`tls/active.py`](../../web_crypto_checker/tls/active.py),
[`tls/robot.py`](../../web_crypto_checker/tls/robot.py)):

- **Heartbleed** (CVE-2014-0160) and **CCS injection** (CVE-2014-0224).
- The **active ROBOT oracle** (CVE-2017-13099), which confirms the static-RSA
  Bleichenbacher surface the passive detection only suspects.
- **Client-initiated renegotiation**: insecure (CVE-2009-3555) if the server does
  not require the secure mode, or worth a low-severity notice (CVE-2011-1473) if it
  accepts it at all.
- The **real revocation query** (OCSP/CRL): with `--active`, the tool does not just
  read what the certificate *announces* about revocation but **asks** the OCSP
  responder and downloads the CRL to learn whether the leaf is actually revoked.

> ⚠️ Scanning a server that is not yours can be illegal without permission, and
> these probes are offensive. Use `--active` **only** against servers you are
> authorised to test.

---

## Certificate trust: `--ca-bundle` and `--no-trust`

By default, the certificate chain is validated up to a **root in the system store**,
with `NameConstraints`, `pathLenConstraint` and the whole path's validity
([`pki/certificates.py`](../../web_crypto_checker/pki/certificates.py)). Two options
change that anchoring:

```bash
# Validate against YOUR roots (an internal PKI) instead of the system store
web-crypto-checker interno.example.com --ca-bundle ./roots.pem

# Do not validate the chain against any store (just enumerate the cryptography)
web-crypto-checker example.com --no-trust
```

`--ca-bundle` is what you need to audit servers signed by a **corporate CA** the
system does not know: without it they would come out as *untrusted* for a reason that
has nothing to do with their cryptographic posture. `--no-trust` disables the trust
check entirely — useful when you only care about versions, suites and groups, or when
the target is a lab server with a deliberately mismatched certificate.

When the presented chain does not reach a trusted root but may only be **missing an
intermediate**, the tool **fetches it via AIA** (the certificate's own `caIssuers`
URL, as a browser would) and rebuilds the chain. Completing it this way never
**confers** trust on its own: a fetched intermediate only helps reach a root that was
already in the store.
