# Conformance profiles

Back to the [manual](README.md) · related: [plugins](plugins.md) ·
[document provenance](../estandares/README.md) · [Español](../politica-normativas.md).

A standard is not code of this tool: it is a document someone else maintains and
revises on their own calendar. That is why **each standard is a directory** under
[`web_crypto_checker/data/profiles/`](../../web_crypto_checker/data/profiles/README.md)
and **each file inside it is an edition**; it is **evaluated**, not compiled.
Adding next year's edition is adding a file; last year's stays and can still be
measured against. With more than one edition, exactly one carries
`"current": true`; the loader refuses if none or several do.

## How it is evaluated

Profiles are selected with `--profile <id>` (the edition **in force**) or with
`--profile <id>@<edition>` for a specific edition (repeatable), and listed with
`--list-profiles`. The standard's identifier is the directory name; the
edition's, its file name without `.json`.

```bash
web-crypto-checker example.com --profile mozilla-intermediate --profile pci-dss-4
web-crypto-checker --list-profiles
```

A profile produces, per endpoint, one of three results:

- **PASS** — everything the profile requires was checkable and was met.
- **FAIL** — there is at least one violation (it is a test, and it settles the
  question).
- **NOT ASSESSED** — no violations, but some requirement **could not be
  checked** (the scan did not see enough). It is not a pass: a check that could
  not run was not passed, it was skipped, and reporting the two the same would
  certify a server that was never understood.

## What a profile can require

A profile file is JSON with these sections (all optional):

| Key | Meaning |
|---|---|
| `name`, `authority`, `edition`, `reference`, `url`, `summary`, `notes` | Metadata and the exact **citation** of the document. |
| `kind` | `algorithm-strength` (default: measure what the server offers against the document's rules) or `policy-conformance` (measure against the categories of the tool's own policy, for a document that does not name algorithms). |
| `protocols.allow` / `protocols.disallow` | TLS versions allowed or forbidden. |
| `cipher_tags.disallow` | Suite shapes forbidden by **tag** (e.g. `rc4`, `3des`, `cbc`). |
| `cipher_suites.allow` | **Allowlist** of exact IANA suites (for a document that publishes its table of authorised suites: BSI, CCN-STIC-807, CNSA, FIPS). |
| `groups.allow` / `groups.disallow` | Key-exchange groups. |
| `signature_algorithms.allow` / `.disallow` | Signature schemes. |
| `certificate.min_rsa_bits` / `min_ec_bits` / `disallow_sha1` | Minimum key and signature strength of the certificate. |
| `minimum_security_strength` | Minimum effective security strength in bits (NIST SP 800-57). `null` when the document publishes no figure (ANSSI, on purpose). |
| `hsts.require` / `hsts.min_age` | Require HSTS (and a minimum `max-age`). |
| `ocsp_stapling.require` | Require the server to **staple** OCSP. |
| `forbid_local_categories` | For `policy-conformance`: the local categories (`weak`, `insecure`) that any offered algorithm must not carry. |

**Tags versus allowlists.** A document that publishes a table of authorised
suites is encoded with `cipher_suites.allow` (exact IANA names), because a tag
does not tell AES from ChaCha20 and these documents turn on exactly that (BSI and
FIPS exclude ChaCha20; ENS authorises it). A document that forbids weak *shapes*
is encoded with `cipher_tags.disallow`. Both mechanisms exist and each profile
uses the one its document really is.

## Citing the sources

**Every rule refers back to an exact section or table of a real document**, cited
in `reference`/`notes`. The source documents (URL, date and SHA-256, and which
profile each one feeds) are in [`docs/estandares/`](../estandares/README.md). Not
all of them may be redistributed (PCI DSS and ISO/IEC are paid; NIST is public
domain; CIS is CC BY-NC-SA), so they are **cited** and obtained from their
publisher. The full profile table is in the
[`data/profiles/` README](../../web_crypto_checker/data/profiles/README.md).

## Writing your own

Create a `data/profiles/<id>/` directory with a `<edition>.json` file inside it
(copying the closest profile), adjust the keys and cite the source in
`reference`/`notes`. The directory name is the standard's identifier; the file
name, the edition (lowercase letters, digits, dots and hyphens). With a single
edition it is the one in force; with several, mark one with `"current": true`.
Like everything else in this tool: **data, not code**.
