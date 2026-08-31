# Integrity audit — does everything the tool asserts come from a document?

**Date:** 2026-08-28 · **Scope:** 14 profiles + base policy
`algorithms.json` (categories, strengths, vulnerabilities, configuration checks
and scoring).

**Question it answers:** does the tool call something "good" or "bad" without a
document to back it? That is, did we make anything up?

## Method

Three independent verifications, each returning **evidence** (file:key → the
exact section of the document that backs it, or "not found"), not a rubber stamp:

1. **All 14 profiles** against the document each one cites, cross-checking what
   the profile requires (protocols, suites, groups, signatures, certificate
   requirements, HSTS/OCSP) against the section/table recorded in
   `estandares/CITATION_MAP.md` and against the
   provenance record (URL, date, SHA-256) in
   [`estandares/README.md`](../estandares/README.md).
2. **The base policy classification** in `algorithms.json` (protocols, cipher
   shape-tags, groups, signatures, strength table) against the documents present
   in [`estandares/`](../estandares/README.md).
3. **The vulnerabilities and the configuration checks** — does each one name its
   source (CVE, RFC, guideline rule)?

Profiles are grouped by family (the two Mozilla, the two NIST, the three CIS
web-server benchmarks, etc.), as the catalogue itself does.

## Verdict in one sentence

**There are no invented lists.** All 14 profiles trace to a document that is
**archived and SHA-256-fingerprinted** in `estandares/`, and every rule points to
a concrete section or table. **No behavioural error was found** in this audit.
The only real gap is minor and honest: **three of the ten vulnerabilities**
(`NULL-CIPHER`, `ANON-CIPHER`, `DES`) have an **empty** `references` list. And the
**scoring** — weights, letter scale, caps — is the tool's own methodology,
already declared as such.

---

## 1. Profiles (14) — they trace to their document

All 14 profiles are `algorithm-strength` except `iso-27002-8-24`, which is
`policy-conformance`. **Every one** cites a document that is **physically
present** in `estandares/`, with its SHA-256 recorded; no profile rests on a
missing document. What was checked, family by family:

### Mozilla (2/2) — VERIFIED
`mozilla-modern` and `mozilla-intermediate` come from
`mozilla-server-side-tls-5.7.json` (the machine-readable guideline, archived).
- `mozilla-modern`: `protocols.allow=[tls1_3]` and the **three** TLS 1.3 suites
  match `configurations.modern` (which is TLS-1.3-only in 5.7); `min_ec_bits=256`
  comes from `certificate_curves`/`ecdh_param_size`. Its own `notes` documents the
  correction from the pre-5.0 version ("Modern" once allowed TLS 1.2 and RSA) and
  **declares** that 5.7 is ECDSA-only and that the schema cannot express
  "RSA certificate forbidden", so it asserts no `min_rsa_bits`. A declared schema
  limit, not an invention.
- `mozilla-intermediate`: 12 AEAD/PFS suites, `min_rsa_bits=2048`,
  `min_ec_bits=256`, no CBC — exactly the `ciphers.iana` list of 5.7.

### NIST (2/2) — VERIFIED
- `nist-sp-800-52r2` (from `NIST.SP.800-52r2.pdf`): disallows ssl3/tls1_0/tls1_1
  and the rc4/3des/des/export/null/anon/md5 tags; `minimum_security_strength=112`.
  **Declared citation nuance:** the TLS 1.1 ban rests on a *should-not* (§3.1,
  government audience), not a *shall-not*.
- `nist-sp-800-131a` (from `NIST.SP.800-131Ar2.pdf`): same disallowed tags,
  strength 112, SHA-1/MD5 signatures forbidden (Table 8). It sets no TLS version,
  because the document governs algorithms, not versions — declared.

### FIPS 140-3 (1/1) — VERIFIED
`fips-140-3` encodes 28 non-anonymous AES suites, P-curve + ffdhe groups, and
RSA/ECDSA/EdDSA signatures, each traced to its archived source (SP 800-38D for
GCM, SP 800-56Ar3 Tables 24/26 for groups, FIPS 186-5 for signatures). ChaCha20
and x25519/x448 are excluded **because they have no NIST approval** — verifiable
in the documents present. The `notes` declares the underlying limit: FIPS 140-3
validates a *module*, not just algorithm names; a PASS is necessary, not
sufficient.

### CNSA 1.0 (1/1) — VERIFIED
`cnsa-1.0` comes from Table V of `CSA_CNSA_2.0_ALGORITHMS.pdf`:
AES-256-GCM-SHA384, P-384, DH ≥ 3072, RSA ≥ 3072, strength 192. The
SHA-384-only/P-384-only reading is literal ("Use … for all classification
levels"). It does not restrict the TLS version — declared — because CNSA is an
algorithm suite.

### BSI (1/1) — VERIFIED
`bsi-tr-02102-2` (from `BSI-TR-02102-2-en.pdf`, edition 2026-01): tls1_2/tls1_3,
39 suites from Tables 3+4+13, NIST+Brainpool+ffdhe3072/4096 groups, RSA-PSS and
ECDSA signatures (Table 11), strength 120 (§3.1.2). No ChaCha20 in any table — the
list excludes it, and the `notes` contrasts this with ENS, which does authorise it.

### ANSSI (1/1) — VERIFIED
`anssi` (from `anssi-guide-mecanismes-crypto-3.00.pdf`, PG-083 v3.00) is encoded
**by mechanism**, not by a suite list, because the document publishes none. The
prohibitions (3des for its 64-bit block, rc4/des/export for key size, sha1/md5 for
RègleHachage) trace to their numbered rules. **Two absences are declared, not
gaps:** it sets no TLS version and no suite allowlist (PG-083 is not TLS-specific),
and it sets **no `minimum_security_strength`** because §1.5 states the document
"ne comporte volontairement aucune table récapitulative des tailles minimales".
Synthesising a figure would be ours, which is why it is not done.

### ENS (1/1) — VERIFIED
`ens` comes from CCN-STIC-807 (May 2022) plus `boe-ens-rd-311-2022-consolidado.pdf`
as the legal basis, both archived. TLS 1.2/1.3 (¶61), the 8 R suites of Table 4-1
+ the 5 of Table 4-2, RSA ≥ 3000 (Table 3-2 R), strength 128, no SHA-1 except HMAC
(¶25). The Legacy rows are omitted because their validity window closed in 2025
(§3 ¶10) — traced. **Declared nuance:** CCN's RSA floor "n ≥ 3000" sits marginally
below the 3072→128-bit threshold that `strength.py` uses, so a hypothetical
3000–3071-bit RSA key (not used in practice) could pass `min_rsa_bits` yet still
trip the strength gate. Real 3072-bit keys satisfy both.

### PCI DSS 4 (1/1) — VERIFIED
`pci-dss-4` (from `PCI-DSS-v4_0_1.pdf`): strength 112 (Appendix G "Strong
Cryptography"), disallows ssl3/tls1_0/tls1_1 and the weak tags.
**Declared nuance:** PCI does not name TLS 1.1 explicitly; it is derived from the
"insecure versions" clause of Req 4.2.1 + RFC 8996. **Provenance:** the PDF is a
**non-redistributable** internal reference copy (a paid standard); it is present
and fingerprinted for local audit, but does not travel in the distribution.

### ISO/IEC 27002:2022 §8.24 (1/1) — VERIFIED
`iso-27002-8-24` is the only `policy-conformance`: since control 8.24 names no
algorithm, the profile measures against **the tool's own** policy categories
(it forbids anything the local policy rates `weak`/`insecure`), and its `summary`
says so. It rests on `ISO_27002_2022.pdf` (present). **Honest flag already on
record:** the archived `iso-27001.pdf` is the **2005 edition** (its Annex A uses
A.12.3, no 8.24); that is why the citation is to 27002:2022, the copy that **is**
held. Like PCI, ISO/IEC is a paid standard: a non-redistributable internal copy.

### CIS web-server (3/3) — VERIFIED
All three come from their CIS benchmarks archived in `estandares/cis/`
(CC BY-NC-SA, redistributable with attribution):
- `cis-nginx` (v3.0.0): tls1_3 only (Rec. 4.1.4), weak tags disallowed
  (Rec. 4.1.5), OCSP stapling required (4.1.7), HSTS `min_age=31536000` (4.1.8).
- `cis-apache-2.4` (v2.3.0): tls1_2/tls1_3 (Rec. 7.4), disallows export/null/des/
  rc4/anon (7.5), **3des** (7.8) and **no-forward-secrecy** (7.12), OCSP (7.10),
  HSTS `min_age=480` (7.11 L2).
- `cis-iis-10` (v1.2.1): disallows ssl3/tls1_0/tls1_1 (Rec. 7.3/7.4/7.5), null/des/
  rc4 (7.7/7.8/7.9), HSTS `min_age=1` (7.1 L2). **Declared:** it uses a *disallow*
  list (not an allowlist) for protocols because this edition has no TLS 1.3 rule,
  so it must not penalise a server that also offers it; and it requires no OCSP
  because v1.2.1 carries no such recommendation.

**No document gaps.** Unlike other catalogues, here **no** profile invokes a
missing document: all 14 have their source archived and SHA-256-recorded in
`estandares/`. The only provenance caveats are about **redistribution**, not
absence: PCI DSS and ISO/IEC are paid standards kept as internal reference copies
(present, locally auditable, not packaged).

---

## 2. Base policy `algorithms.json`

### What is well anchored
- **Protocols:** TLS 1.0/1.1 *weak* cite RFC 8996 in their `note`; SSL 3.0
  *insecure* cites POODLE; SSL 2.0 *insecure* cites DROWN. Traceable.
- **Groups and signatures:** the recommended/acceptable/weak/insecure curves,
  groups and signature schemes match the NIST, BSI and FIPS tables that **are
  archived** (P-curves, ffdhe, RSA-PSS vs PKCS#1, SHA-1 insecure).
- **Strength table** (`security_strength`): the RSA thresholds
  `[1024,80] [2048,112] [3072,128] [7680,192] [15360,256]` are those of NIST SP
  800-57 Part 1 Rev. 5, **present** (`NIST.SP.800-57pt1r5.pdf`), cited in the
  block itself.

### The soft spot: the shape-tag suite classification (correct judgement, public anchor)
The web equivalent of the classic "hole" in these auditors is
`cipher_tag_categories`: the tag→category map (`rc4`/`des`/`md5` insecure,
`3des`/`sha1` weak, `cbc`/`no-forward-secrecy` acceptable, `aead` recommended).
The verdicts are correct, but they **do not come from a single archived
document**: the `metadata` block anchors them to Mozilla Server Side TLS
(archived), NIST SP 800-52r2 (archived) and **IETF BCP 195 / RFC 9325** (a public
reference, not archived — same criterion as the CVEs). Moreover, every weak/insecure
tag is backed in turn by its vulnerability (RC4, Sweet32, FREAK/Logjam), so there
is no orphan verdict; all that is missing locally is RFC 9325.

### Vulnerabilities (10) — 7 with a CVE, **3 with an empty `references`**
This is the audit's one real finding. Of the ten entries in the
`vulnerabilities` list:

| id | `references` |
|---|---|
| `CVE-2016-0800` (DROWN) | `["CVE-2016-0800"]` ✅ |
| `CVE-2014-3566` (POODLE) | `["CVE-2014-3566"]` ✅ |
| `SWEET32` | `["CVE-2016-2183"]` ✅ |
| `RC4` | `["CVE-2013-2566","CVE-2015-2808"]` ✅ |
| `FREAK-LOGJAM` | `["CVE-2015-0204","CVE-2015-4000"]` ✅ |
| `CVE-2011-3389` (BEAST) | `["CVE-2011-3389"]` ✅ |
| `NO-FORWARD-SECRECY` | `["CVE-2017-13099"]` ✅ |
| **`NULL-CIPHER`** | **`[]`** ⚠️ |
| **`ANON-CIPHER`** | **`[]`** ⚠️ |
| **`DES`** | **`[]`** ⚠️ |

The three without a reference are "definitional" (NULL = no encryption, ANON = no
authentication, DES = a brute-forceable 56-bit key), not CVE-tracked phenomena;
their truth is self-evident. But the vulnerabilities manual itself says "**no
reference means it's an opinion**", so, by its own rules, **these three should cite
their source** (e.g. RFC 8996/RFC 7568 for the deprecation framing, or the null/
anonymous-suite catalogue). A minor, bounded gap, not an invented verdict.

### Configuration checks (HTTP / TLS behaviour / certificate) — code, not data
These checks are **not** JSON: they live in code (`http_layer.py`,
`assessment.py`, `pki/certificates.py`, `mixed_content.py`,
`subresource_integrity.py`) and their severity is **fixed in the code**, not in a
configurable `expect` field. Their provenance *is* documented, but in the **prose**
of [`politica-configuracion.md`](politica-configuracion.md) and in code comments
(RFC 5280, 4055, 8410, 6698, 8659, 7838, 2606; RFC 5746 for secure renegotiation;
RFC 6265bis for the cookie contract; CVE-2017-15361 for ROCA), not as a
machine-readable `reference` field like the one the vulnerabilities do carry.
Honestly: **the existence** of each check maps to a public standard or a browser
behaviour; **the severity** of each one is the tool's own criterion.

### The tool's own methodology — already declared
It comes from no document — and it should not, it is legitimate design:
- `scoring`: the per-class weights (`protocol` 3, `cipher` 3, `certificate` 3,
  `group` 2, `signature` 1), the letter scale (A+…F, with an E) and the caps
  (`grade_caps`).
- `categories`: the `score` values 100/80/40/0.
- `security_strength.levels`: the bit **thresholds** are indeed NIST's, but the
  **names** (broken/legacy/transitional/acceptable/strong/top) are our own
  presentation.

It is already declared: [`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md)
opens with "Where these numbers come from (and where they don't)", separating the
documentary backing of the categories from the tool's own scoring criterion.

---

## 3. Actions — status

This audit **documents**; it does not modify data or code (the owner decides the
changes). Real status of each front:

**No action needed (already correct):**
- [x] **All 14 profiles trace to an archived document** with a SHA-256 in
  `estandares/`. None cites a missing document.
- [x] **No behavioural error** to fix: each profile matches the cited
  section/table, and the caveats (TLS 1.1 in NIST-52r2/PCI, the ENS RSA floor,
  the ANSSI absences, the CIS-IIS *disallow*) are **declared in the profile's own
  `notes`**, not hidden.
- [x] **Scoring is declared as the tool's own methodology** (a section in
  `como-se-calcula-la-nota.md` and `_comment_*` comments in `algorithms.json`).
- [x] **Public CVEs and RFCs:** the 7 CVE-bearing vulnerabilities and the
  configuration checks rest on verifiable public references (NVD/MITRE, RFC); by
  provenance policy they are **cited, not archived**.

**Open recommendations (findings of this audit):**
- [ ] **Fill in `references` for `NULL-CIPHER`, `ANON-CIPHER` and `DES`.** They
  are empty today; by the manual's own "no reference means it's an opinion" rule,
  they should cite their public source.
- [ ] **(Optional) Archive or formally cite RFC 9325 (BCP 195)** to fully anchor
  `cipher_tag_categories`, today held up by Mozilla + NIST SP 800-52r2 (archived)
  plus that public RFC.
- [ ] **(Optional) Consider a machine-readable `reference` field** on the
  configuration checks, like the one the vulnerabilities already carry, instead of
  leaving provenance only in the prose and the code comments.

---

## Conclusion

The tool **invents nothing**: all 14 profiles trace to a document that is
**present and fingerprinted** in `estandares/`, every rule points to its exact
section or table, and **no behavioural error was found**. The citation caveats
(TLS 1.1, the ENS RSA floor, ANSSI's deliberate absences) are declared in the
profiles themselves, not concealed. The only real gap is minor: three of the ten
vulnerabilities (`NULL-CIPHER`, `ANON-CIPHER`, `DES`) have an empty `references`
list and should cite their source. The shape-tag suite classification and the
configuration checks rest on **public** references (RFC 9325, the HTTP/TLS-layer
RFCs, CVEs) that — by provenance decision — are cited, not archived. And the
scoring, which is the tool's own criterion, is already declared as such.
