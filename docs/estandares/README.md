# `docs/estandares/` — the documents the profiles come from

> **Nota de la distribución:** esta distribución **cita** los documentos fuente pero **no los incluye** (PDF/JSON). Sus licencias no permiten toda la redistribución: PCI DSS e ISO/IEC son de pago; NIST es de dominio público; CIS es CC BY-NC-SA; el resto se descargan de la fuente. Obtén cada documento de la URL indicada y verifica su SHA-256 con la lista del final.

Each conformance profile of this tool encodes a document published by a
standards body or a national agency. This directory keeps **those documents**,
so a profile can be verified and maintained against the source rather than
against the memory of the source. Its layout: flattened standard filenames,
with the CIS web-server benchmarks under `cis/`. `CITATION_MAP.md` ties each profile back to the
exact clause of the document it encodes.

Every entry below records the exact URL it came from, its SHA-256 as it arrived,
and **which profile it feeds**. The hashes let anyone check the file is still
the one that was stored, and detect when the editor publishes a new edition
(several editors serve "the version in force" from a stable URL: if the hash
changes on re-download, there is a new edition and the profile needs review).

Most files are downloaded from the public sources recorded below and carry their recorded hashes (downloaded 2026-08-11/12). Three TLS documents
were added by this effort and downloaded **2026-08-21**: NIST SP 800-52r2, BSI
TR-02102-2, and the Mozilla 5.7 guideline. Each download was checked on arrival
(a real `%PDF`/JSON header and the edition/title the profile cites).

---

## Mozilla — Server Side TLS

| File | Downloaded from | Date | Feeds |
|---|---|---|---|
| `mozilla-server-side-tls-5.7.json` | <https://ssl-config.mozilla.org/guidelines/5.7.json> | 2026-08-21 | `mozilla-modern`, `mozilla-intermediate` |

The machine-readable Server Side TLS guideline, version 5.7 (the exact form the
config generator consumes). Its `configurations.modern` is TLS 1.3-only and
`configurations.intermediate` is AEAD/forward-secret-only (5.x dropped CBC),
which is what the two Mozilla profiles now encode.

## NIST (United States) — public domain

| File | Downloaded from | Date | Feeds |
|---|---|---|---|
| `NIST.SP.800-52r2.pdf` | <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf> | 2026-08-21 | `nist-sp-800-52r2` |
| `NIST.SP.800-131Ar2.pdf` | <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf> | 2026-08-11 | `nist-sp-800-131a` |
| `NIST.FIPS.140-3.pdf` | <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.140-3.pdf> | 2026-08-11 | `fips-140-3` |
| `NIST.SP.800-140Cr2.pdf` | <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-140Cr2.pdf> | 2026-08-11 | `fips-140-3` (Annex A approved functions) |
| `NIST.FIPS.186-5.pdf` | <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf> | 2026-08-11 | `fips-140-3` (approved signatures) |
| `NIST.SP.800-56Ar3.pdf` | <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf> | 2026-08-11 | `fips-140-3` (approved curves/groups) |
| `NIST.SP.800-38D.pdf` | <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf> | 2026-08-11 | `fips-140-3` (GCM AEAD mode) |
| `NIST.FIPS.203.pdf` | <https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf> | 2026-08-11 | `fips-140-3` (ML-KEM context) |
| `NIST.SP.800-57pt1r5.pdf` | <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf> | 2026-08-11 | the `security_strength` table (key-size ↔ bits) |

SP 800-52r2 §3.1/§3.2/§3.3 is the TLS guideline itself; it requires TLS 1.2/1.3,
NIST-approved cipher suites and ≥112-bit security. The rest supply FIPS 140-3's
approved-function set for `fips-140-3`. SP 800-57pt1r5 Table 2 is the key-size ↔
effective-bits map behind the strength figure, not a profile of its own.

## NSA (United States)

| File | Downloaded from | Date | Feeds |
|---|---|---|---|
| `CSA_CNSA_2.0_ALGORITHMS.pdf` | <https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF> (Wayback snapshot) | 2026-08-11 | `cnsa-1.0` (Table V) |
| `CSA_CNSA_2.0_FAQ_v2.1.pdf` | Wayback snapshot (see the CSA source URL) | 2026-08-11 | `cnsa-1.0` (context) |

Table V of the ALGORITHMS CSA is the classical CNSA 1.0 suite (AES-256, P-384,
SHA-384, RSA/DH ≥ 3072) that `cnsa-1.0` encodes. The CDN has since retired the
original URL; the exact Wayback snapshot used is recorded with its hash below.

## BSI (Germany)

| File | Downloaded from | Date | Feeds |
|---|---|---|---|
| `BSI-TR-02102-2-en.pdf` | <https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-2.pdf?__blob=publicationFile> | 2026-08-21 | `bsi-tr-02102-2` |

Technical Guideline TR-02102-2, *Use of Transport Layer Security (TLS)*, version
2026-01 (official English translation). Tables 2/3/4/13 (versions, suites),
6/10 (groups), 11 (signatures), 14 (key lengths); §3.1.2 (120-bit level).

## ANSSI (France)

| File | Downloaded from | Date | Feeds |
|---|---|---|---|
| `anssi-guide-mecanismes-crypto-3.00.pdf` | <https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-mecanismes-crypto-3.00.pdf> | 2026-08-11 | `anssi` |

ANSSI-PG-083 v3.00, *Guide des mécanismes cryptographiques*. Rules by mechanism
(RègleFactorisation, RègleCourbeElliptiqueGFp, RègleHachage, …). It publishes no
TLS cipher-suite list and, per §1.5, no summary key-size table — which is why the
`anssi` profile is encoded by mechanism and sets no single strength floor.

## Spain — ENS (CCN)

| File | Downloaded from | Date | Feeds |
|---|---|---|---|
| `CCN-STIC-807-criptologia-de-empleo-en-el-ens.pdf` | <https://www.ccn-cert.cni.es/es/series-ccn-stic/800-guia-esquema-nacional-de-seguridad/513-ccn-stic-807-criptologia-de-empleo-en-el-ens.html> (Wayback snapshot) | 2026-08-11 | `ens` |
| `boe-ens-rd-311-2022-consolidado.pdf` | <https://www.boe.es/buscar/pdf/2022/BOE-A-2022-7191-consolidado.pdf> | 2026-08-11 | `ens` (legal basis) |

CCN-STIC-807 (Mayo 2022) §4.1: ¶61 (TLS 1.2/1.3 only), Tablas 4-1/4-2 (authorised
suites), §3 tables (RSA/curves). RD 311/2022 is the legal ENS decree.

## PCI SSC — internal reference copy, not redistributable

| File | Downloaded from | Date | Feeds |
|---|---|---|---|
| `PCI-DSS-v4_0_1.pdf` | <https://www.pcisecuritystandards.org/document_library/> (owner-supplied copy) | 2026-08-11 | `pci-dss-4` |

PCI DSS v4.0.1: Req 4.2.1 (strong cryptography/secure protocols) and the
Appendix G glossary "Strong Cryptography" (≥112-bit effective key strength).
A paid/registration-gated, non-redistributable standard kept as an internal
reference copy in this private repository.

## ISO/IEC — paid standard, internal reference copies

| File | What it is | Feeds |
|---|---|---|
| `ISO_27002_2022.pdf` | ISO/IEC 27002:2022, control 8.24 *Use of cryptography* (the control text + guidance). | `iso-27002-8-24` |
| `iso-27001.pdf` | ISO/IEC 27001 (**2005 edition** — Annex A uses A.12.3, has no 8.24). Kept for reference. | — (see flag) |

The `iso-27002-8-24` profile is grounded on ISO/IEC 27002:2022 §8.24, the copy
actually held here. **FLAG:** the archived `iso-27001.pdf` is the 2005 edition,
whose Annex A predates the 8.24 numbering; ISO/IEC 27001:2022 (which lists 8.24 in
its Annex A) is a paid standard not held here, so the profile cites 27002:2022.
ISO/IEC standards are paid; these are non-redistributable internal reference copies.

## CIS — web-server benchmarks (CC BY-NC-SA 4.0)

| File | Downloaded from | Date | Feeds |
|---|---|---|---|
| `cis/CIS_NGINX_Benchmark_v3.0.0.pdf` | <https://downloads.cisecurity.org> (official portal) | 2026-08-12 | `cis-nginx` |
| `cis/CIS_Apache_HTTP_Server_2.4_Benchmark_V2.3.0.pdf` | <https://downloads.cisecurity.org> | 2026-08-12 | `cis-apache-2.4` |
| `cis/CIS_Microsoft_IIS_10_Benchmark_v1.2.1.pdf` | <https://downloads.cisecurity.org> | 2026-08-12 | `cis-iis-10` |

© Center for Internet Security, Inc., licensed CC BY-NC-SA 4.0 (may be stored and
redistributed with attribution for non-commercial use). The TLS-protocol,
cipher, HSTS and OCSP-stapling recommendations of each are what the CIS profiles cite.

---

## SHA-256 of every file

```
1baf13e8ae81bd476f09aed12885587850429a6925a182b6b8d5c76b31b288ec  anssi-guide-mecanismes-crypto-3.00.pdf
07a74608dce3a146890f444c73ef8f2ee04f49c101114e2e2642941e53a92211  boe-ens-rd-311-2022-consolidado.pdf
a7f55c3403d45719287415d2698bf51e629aafe841e2e9867e8afe8749d238e5  BSI-TR-02102-2-en.pdf
a8f1a3e09e0fbf88299a3af05a1806433610039d9c556fe33d5900f7549b8faa  CCN-STIC-807-criptologia-de-empleo-en-el-ens.pdf
64dcd25e32319a2a016aa5da035f008a3f4d4adaa6755c8b4b282f7f266c4eed  CSA_CNSA_2.0_ALGORITHMS.pdf
ca447adb27af022f6bcca70873ef3404a7db0758fa0626fe9cd994451d86f5e0  CSA_CNSA_2.0_FAQ_v2.1.pdf
9dc30f01fe908c54c422ba5232b508d52ba0641dec40522d3821d1a7d160df69  iso-27001.pdf
1da41b305cce13c7d9150e8ceb520eb13d082d8a80080f9768a5dc9f2900b7e2  ISO_27002_2022.pdf
c75b1f21a932b556654f6b52bef9e6c460c12e626ae0f62e17f83c1816bb42d6  mozilla-server-side-tls-5.7.json
942a4f929dfbd2b4af2e4e03df7f6e6377054346afd9bee346ed0ebac5db384b  NIST.FIPS.140-3.pdf
fbb9c7c2ba442f03c57b63b43c888311903c9d0f29f89b06efdebd9b619140c5  NIST.FIPS.186-5.pdf
fe1f12f32a7e44ec9fdebbf400cda843a40b506dee676725234dc6f7923b6cac  NIST.FIPS.203.pdf
5c81a1095e0eee35ce0e627b8cc672c1c2239367b0de9bb53d7271c9ab9d7d27  NIST.SP.800-131Ar2.pdf
76e32694d67dfb7e8199365f120e78563d659d0ca8df17d85c6116b0ab70465d  NIST.SP.800-140Cr2.pdf
d99f3921ccebca049e7522426553aba071dae14ec3d5b6041e8c111a6cb57bba  NIST.SP.800-38D.pdf
f9a4dbb9cc6ac6778bb9f4e6be9272c2f14d113f3ad241a295684ac6bd71f257  NIST.SP.800-52r2.pdf
6b315e3a91012981f9a88ad62c97ea7d4b170a7746e713f34dd29538ee46f403  NIST.SP.800-56Ar3.pdf
cc32391022c1382ac7c91490f6bcc8838e0f889925270da23ef4e800e2ecb7ad  NIST.SP.800-57pt1r5.pdf
5e6b9093b84007b973097d20126a3768ea2f0a1d4200255c849b0fb3bf04ebc7  PCI-DSS-v4_0_1.pdf
619eb63bad05e2b38ed64ff0676a5500f77d5c8db958ecbeffb25501fd77fe9d  cis/CIS_Apache_HTTP_Server_2.4_Benchmark_V2.3.0.pdf
bdf1caaabe813880b36a99dc4e968d312565e43afe73b0af66b19ea542ae09ba  cis/CIS_Microsoft_IIS_10_Benchmark_v1.2.1.pdf
6a9129f18264591a0da29929a8196c5d1d0c57c033e575fcfc004c767fca9119  cis/CIS_NGINX_Benchmark_v3.0.0.pdf
```

Verification: `cd docs/estandares && sha256sum -c <(grep -E '^[0-9a-f]{64}' README.md)`.
