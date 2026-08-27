# `data/profiles/` — the standards

A standard is not code of this tool: it is a document somebody else maintains
and revises on its own calendar. So:

- **The directory is the standard's id.**
- **Each file inside it is one edition**, asked for by writing it:
  `--profile ens@2022-05`.
- A bare id (`--profile ens`) means **the edition in force**.
- With more than one edition, exactly one declares `"current": true`; the loader
  refuses if none or several do, because which edition is in force is precisely
  what a compliance tool must not guess.

A profile says which protocol versions it permits (`protocols.allow`/`disallow`),
which cipher-suite shapes it forbids (`cipher_tags.disallow`) or which exact
suites it authorises (`cipher_suites.allow`), which key-exchange groups and
signature algorithms it allows or forbids, how strong a certificate key and the
effective security strength must be, and whether the HTTP layer must assert HSTS
or the server must staple OCSP. Adding next year's edition is adding a file; last
year's stays put, to keep measuring against.

Every rule traces to an exact section/table of a real document, quoted in the
profile's `reference` and `notes`; the documents themselves are archived in
[`../../../docs/estandares/`](../../../docs/estandares/README.md) with their
SHA-256. Profiles are selected with `--profile <id>` or `--profile <id>@<edition>`
(repeatable) and listed with `--list-profiles`. When the scan cannot see enough to
judge, the result is *not-assessed*, never *pass*.

## Subdirectorios

Un directorio por norma, un fichero por edición. La edición codificada hoy y la
fuerza de seguridad mínima que exige (cuando el documento nombra una):

| Directorio | Norma | Autoridad | Edición | Mínimo |
|---|---|---|---|---|
| [`anssi/`](anssi/README.md) | ANSSI (règles cryptographiques) | ANSSI (France) | `pg-083-v3-00` | — (lista negra) |
| [`bsi-tr-02102-2/`](bsi-tr-02102-2/README.md) | BSI TR-02102-2 (TLS) | BSI (Germany) | `2026-01` | 120 bits |
| [`cis-apache-2.4/`](cis-apache-2.4/README.md) | CIS Apache HTTP Server 2.4 Benchmark | Center for Internet Security | `v2-3-0` | — (lista negra) |
| [`cis-iis-10/`](cis-iis-10/README.md) | CIS Microsoft IIS 10 Benchmark | Center for Internet Security | `v1-2-1` | — (lista negra) |
| [`cis-nginx/`](cis-nginx/README.md) | CIS NGINX Benchmark | Center for Internet Security | `v3-0-0` | — (lista negra) |
| [`cnsa-1.0/`](cnsa-1.0/README.md) | CNSA 1.0 (transitional suite) | NSA | `2016` | 192 bits |
| [`ens/`](ens/README.md) | ENS (Esquema Nacional de Seguridad) | CCN (Spain) | `2022-05` | 128 bits |
| [`fips-140-3/`](fips-140-3/README.md) | FIPS 140-3 approved algorithms | NIST | `annex-a` | 112 bits |
| [`iso-27002-8-24/`](iso-27002-8-24/README.md) | ISO/IEC 27002:2022 8.24 | ISO/IEC | `2022` | — (conformidad) |
| [`mozilla-intermediate/`](mozilla-intermediate/README.md) | Mozilla TLS — Intermediate | Mozilla | `5-7` | — (lista negra) |
| [`mozilla-modern/`](mozilla-modern/README.md) | Mozilla TLS — Modern | Mozilla | `5-7` | — (lista negra) |
| [`nist-sp-800-131a/`](nist-sp-800-131a/README.md) | NIST SP 800-131A Rev. 2 | NIST | `rev-2-2019` | 112 bits |
| [`nist-sp-800-52r2/`](nist-sp-800-52r2/README.md) | NIST SP 800-52 Rev. 2 | NIST | `rev-2-2019` | 112 bits |
| [`pci-dss-4/`](pci-dss-4/README.md) | PCI DSS v4.0.1 | PCI Security Standards Council | `v4-0-1` | 112 bits |

## Kinds

Most profiles are `algorithm-strength`: they measure what the server offers
against the document's rules. `iso-27002-8-24` is `policy-conformance`: ISO/IEC
27002:2022 names no algorithms (control 8.24 requires only that "Rules for the
effective use of cryptography ... should be defined and implemented"), so the
profile measures the server against *this tool's own policy categories* — the
documented rule set — flagging anything the policy rates weak or insecure.

## A note on allowlists vs. shape-tags

A document that publishes a table of authorised cipher suites (BSI, CCN-STIC-807,
CNSA, FIPS) is encoded with `cipher_suites.allow` — a list of exact IANA suite
names — rather than by shape-tag, because a tag cannot tell AES from ChaCha20 and
these documents turn precisely on that distinction (BSI and FIPS exclude
ChaCha20; ENS authorises it). A document that forbids weak *shapes* (Mozilla's
weak-cipher exclusions, the CIS denylists, PCI/NIST "no RC4/3DES/…") is encoded
with `cipher_tags.disallow`. Both mechanisms are available and a profile uses
whichever its document actually is.
