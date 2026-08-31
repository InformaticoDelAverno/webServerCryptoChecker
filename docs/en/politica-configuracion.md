# Policy manual — configuration checks

Back to the [manual](README.md) · related:
[algorithms](politica-algoritmos.md) ·
[vulnerabilities](politica-vulnerabilidades.md) ·
[conformance profiles](politica-normativas.md) · [Español](../es/politica-configuracion.md).

These checks look at **how the service is set up**, not which algorithms it
offers: what the site tells a browser about its own security, how the TLS behaves
beyond the list of suites, and what the certificate says apart from its key's
strength. They are the web equivalent of what, in other auditors, would be a
daemon's configuration directives.

> **There is no configuration file to audit here.** There is no effective-configuration
> dump to read, and the tool does not authenticate to the machine or inspect its
> files. Everything in this manual is observed **from the outside**, on the
> same scan connection. And so, unlike the algorithm or vulnerability policy,
> **these checks are code, not JSON data**: they live in
> [`http_layer.py`](../../web_crypto_checker/http_layer.py),
> [`assessment.py`](../../web_crypto_checker/assessment.py),
> [`pki/certificates.py`](../../web_crypto_checker/pki/certificates.py),
> [`mixed_content.py`](../../web_crypto_checker/mixed_content.py) and
> [`subresource_integrity.py`](../../web_crypto_checker/subresource_integrity.py).
> Adding one is editing one of these functions, not a list.

---

## The shape of a finding

They all produce the same object, a `Finding` with id, severity, title,
description, remediation and, where it applies, the concrete `items` (the cookies,
the URLs, the origins) that fired it:

```python
Finding(
    "HTTP-NO-HSTS",
    Severity.MEDIUM,
    t("find.http_no_hsts.title"),
    t("find.http_no_hsts.desc"),
    remediation=t("find.http_no_hsts.rem"),
)
```

The severity is **fixed in code** (there is no configurable expectation like
`expect`), and the prose is translated by its message key. The condition that
decides whether the finding is produced is Python, not a policy comparator.

---

## The HTTP layer

Over an established HTTPS connection, the tool sends **one** `GET`, reads the
response headers and a bounded slice of the body, and from that draws what the site
tells a browser. It lives in
[`http_layer.py`](../../web_crypto_checker/http_layer.py).

### HSTS (`Strict-Transport-Security`)

| id | Severity | When |
|---|---|---|
| `HTTP-NO-HSTS` | medium | No HSTS header. |
| `HTTP-WEAK-HSTS` | low | `max-age` below 180 days. |
| `HTTP-HSTS-NO-SUBDOMAINS` | low | HSTS without `includeSubDomains`. |
| `HTTP-HSTS-PRELOAD-INELIGIBLE` | low | Asks for `preload` but does not meet its requirements (a one-year `max-age` **and** `includeSubDomains`). |

### Port-80 redirect

`HTTP-NO-HTTPS-REDIRECT` (medium) fires when port 80 serves cleartext HTTP or
redirects to another `http://` URL without upgrading to HTTPS. A browser's first,
un-cached visit arrives in cleartext; if nothing bounces it to `https://`, that
request travels exposed. Judged only on a standard HTTPS target (443).

### `Content-Security-Policy`, parsed

The CSP is not merely recorded: it is **parsed** (`_csp_findings`). Over the
sources that govern scripts (`script-src`, or `default-src` as a fallback):

| id | Severity | When |
|---|---|---|
| `HTTP-CSP-UNSAFE-INLINE` | medium | `'unsafe-inline'` without a nonce, hash or `'strict-dynamic'` neutralising it. |
| `HTTP-CSP-UNSAFE-EVAL` | low | `'unsafe-eval'`. |
| `HTTP-CSP-BROAD-SCRIPT-SRC` | medium | A wildcard source (`*`, `http:`, `https:`, `data:`). |

### Other security headers

`x-content-type-options`, `x-frame-options` and `referrer-policy` are checked by
absence (findings `HTTP-NO-XCTO`, `HTTP-NO-XFO`, `HTTP-NO-REFERRER-POLICY`, all
low, defined as data in `_MISSING_HEADER_FINDINGS`) and also by ineffective
presence:

- `HTTP-XCTO-INEFFECTIVE` (low): the header is there but its value is not
  `nosniff`.
- `HTTP-XFO-INEFFECTIVE` (low): the value is neither `DENY` nor `SAMEORIGIN`
  —**and** the CSP carries no `frame-ancestors`, which would cover clickjacking
  anyway.

### Cookies

From each `Set-Cookie`:

| id | Severity | When |
|---|---|---|
| `HTTP-INSECURE-COOKIE` | medium | No `Secure`. |
| `HTTP-COOKIE-NO-HTTPONLY` | low | No `HttpOnly`. |
| `HTTP-COOKIE-WEAK-SAMESITE` | low | No `SameSite`, or `SameSite=None` without `Secure`. |
| `HTTP-COOKIE-PREFIX-INVALID` | medium | Breaks its `__Secure-`/`__Host-` name-prefix contract (RFC 6265bis). |

### CORS

An `Origin` no real site would use (`…​.invalid`) is sent to see how the server
responds. If the server reflects it in `Access-Control-Allow-Origin`:

- `HTTP-CORS-CREDENTIALED` (high): reflects the origin **and** allows credentials
  —the worst case.
- `HTTP-CORS-OPEN` (low): reflects any origin, or answers `*`, without
  credentials.

### Mixed content and Subresource Integrity

From the (bounded) page body, two HTML scanners built on the standard library:

- **Mixed content**
  ([`mixed_content.py`](../../web_crypto_checker/mixed_content.py)): an explicit
  `http://` subresource on an HTTPS page. `HTTP-MIXED-ACTIVE` (high) for what runs
  code —`<script>`, stylesheet, `<iframe>`, `<object>`, a form's `action`—, which
  the browser **blocks**; `HTTP-MIXED-PASSIVE` (low) for image, audio or video,
  which it **warns** about. A relative or protocol-relative URL inherits the
  page's `https` and does not count.
- **SRI**
  ([`subresource_integrity.py`](../../web_crypto_checker/subresource_integrity.py)):
  `HTTP-SUBRESOURCE-NO-SRI` (low) for a `<script>` or stylesheet **from another
  origin** with no `integrity` attribute. A same-origin resource does not need it.

### Cleartext HTTP

If **no** TLS could be established and the server answers HTTP over a plain socket,
`HTTP-CLEARTEXT` (**critical**): the traffic goes unencrypted. A server whose
handshake neither completes nor answers in the clear is reported as **not
measured**, never as "no problem found".

---

## TLS behaviour

Beyond the list of suites, how the server negotiates. These findings come from
`_feature_findings` in
[`assessment.py`](../../web_crypto_checker/assessment.py); most are gathered by the
extended probe that `--active` enables:

| id | Severity | What |
|---|---|---|
| `TLS-0RTT-ENABLED` | low | TLS 1.3 with early data (0-RTT), which an attacker can replay. |
| `TLS-INSECURE-RENEGOTIATION` | medium | No secure renegotiation (RFC 5746). |
| `TLS-NO-EXTENDED-MASTER-SECRET` | low | No extended master secret. |
| `TLS-NO-ENCRYPT-THEN-MAC` | low | No encrypt-then-MAC. |
| `TLS-NO-FALLBACK-SCSV` / `TLS-NO-DOWNGRADE-SENTINEL` | low | No anti-downgrade protection. |
| `TLS-NO-CIPHER-PREFERENCE` | low | The server does not enforce its suite order. |
| `TLS-GREASE-INTOLERANT` | low | Does not tolerate GREASE values. |
| `TLS-WEAK-DH-PARAMS` | medium/high | Diffie-Hellman prime < 2048 bits (high if < 1024). |
| `TLS-COMPRESSION` | high | TLS compression enabled (the CRIME surface). |
| `SSLV2-EXPORT-CIPHERS` | high | SSL 2.0 offering export ciphers (makes DROWN practical). |

---

## The certificate, beyond the key

The certificate's key strength and signature algorithm **are** a scored algorithm
class (see [`politica-algoritmos.md`](politica-algoritmos.md)). Everything else
about the certificate —validity, chain, trust, hygiene— is these checks, in
[`assessment.py`](../../web_crypto_checker/assessment.py) and
[`pki/certificates.py`](../../web_crypto_checker/pki/certificates.py):

- **Validity and matching:** `CERT-EXPIRED`, `CERT-NOT-YET-VALID`,
  `CERT-HOSTNAME-MISMATCH`, `CERT-CHAIN-EXPIRED` (an intermediate outside its
  validity breaks the path even if the leaf is fine).
- **Purpose and shape:** `CERT-EKU-NO-SERVER-AUTH` (not usable to authenticate a
  server), `CERT-NO-SAN` (medium), `CERT-VALIDITY-TOO-LONG` (validity > 398 days,
  medium), `CERT-LEAF-IS-CA` (medium).
- **Trust and chain:** `CERT-UNTRUSTED` (does not chain to a system root),
  `CERT-SELF-SIGNED` (medium), `CERT-CHAIN-INCOMPLETE` (low, had to be completed
  via AIA), `CERT-CHAIN-CONTAINS-ANCHOR` (low, the root travels in the chain),
  `CERT-BAD-SIGNATURE` (an internal signature on the path does not verify).
- **Weaknesses:** `CERT-ROCA` (CVE-2017-15361), `CERT-WEAK-KEY`,
  `CERT-WEAK-SIGNATURE`, `CERT-CHAIN-WEAK-SIGNATURE` (an intermediate with an
  insecure signature).
- **Revocation and stapling:** `CERT-REVOKED`, `OCSP-STAPLE-INVALID`,
  `OCSP-MUST-STAPLE-VIOLATED` (high: the certificate requires stapling and the
  server does not do it).
- **Alternate certificate:** a server may hold a second certificate (an RSA hidden
  behind an ECDSA); it is assessed the same way, and its problems surface as
  `CERT-ALTERNATE-INVALID` / `CERT-ALTERNATE-WEAK` so they are not hidden behind
  the valid default certificate.

### The ones that do move the grade

Unlike everything above, a few certificate findings **force a grade cap**, because
a browser would reject the certificate outright:

- Anything that marks the certificate invalid (`CERT-EXPIRED`,
  `CERT-HOSTNAME-MISMATCH`, `CERT-UNTRUSTED`, `CERT-REVOKED`, `CERT-BAD-SIGNATURE`,
  `CERT-ROCA`, `CERT-EKU-NO-SERVER-AUTH`…) activates the `certificate_invalid` cap
  → **F**.
- `CERT-SELF-SIGNED` activates `self_signed` → **C**.

The named caps live in `scoring.grade_caps` of
[`algorithms.json`](../../web_crypto_checker/data/algorithms.json) and are applied
in `_apply_caps`.

---

## What these checks do **not** do

- **They are not configured in the JSON policy.** Their severity and condition are
  in code; `algorithms.json` only holds the `grade_caps` a few of them activate.
  That is the difference from the algorithm classes and the vulnerabilities, which
  are data.
- **The HTTP layer and TLS behaviour do not move the letter on their own.** They
  produce findings with their severity —which count toward `--fail-on` and the
  report—, but the algorithmic grade is set by the five classes and the named
  caps. Only the certificate, through those caps, downgrades the letter.
- **They do not invent what they did not see.** If `--active` did not run, the
  behaviour checks that depend on it are not evaluated to "fine": they simply do
  not appear, and the report distinguishes "not measured" from "no problem found".
</content>
