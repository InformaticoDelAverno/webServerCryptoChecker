# Policy manual — algorithms

Back to the [manual](README.md) · related:
[vulnerabilities](politica-vulnerabilidades.md) ·
[configuration](politica-configuracion.md) · [conformance profiles](politica-normativas.md) ·
[Español](../es/politica-algoritmos.md).

This is the part of the policy that decides **what the tool thinks of everything
a server offers**: the TLS version, the cipher suite, the key-exchange group, the
signature scheme and the certificate. Almost all of it lives in
[`web_crypto_checker/data/algorithms.json`](../../web_crypto_checker/data/algorithms.json),
and it is the part that gets edited most and ages fastest. Changing the criterion
is editing that file, on a server at three in the morning if need be, not shipping
a new release.

---

## The six categories

They are defined in the `categories` key. Each has a label and a **score**:

| Category | Points | What it means |
|---|---|---|
| `recommended` | 100 | Modern, with no known practical weakness. |
| `acceptable` | 80 | It works, but there is something better. |
| `weak` | 40 | Known weakness; it has to go. |
| `insecure` | 0 | Broken. Nothing should offer it. |
| `informational` | *(no points)* | Reported, not scored. For what is neither good nor bad. |
| `unknown` | *(no points)* | The policy does not know it. **Not scored, on purpose.** |

```json
"categories": {
  "weak": {"label": "Weak", "score": 40}
}
```

> **`unknown` does not penalize, and that is deliberate.** A `null` score means
> "does not score". Servers offer names nobody has catalogued all the time: a
> suite whose hex code the table does not know, a new group, an experimental
> signature. Lowering the grade for something the policy does not recognize
> punishes whoever uses something new and good exactly the same as whoever uses
> something odd and bad.

---

## What decides the grade: the worst member

The rule that governs the whole file is a single one,
[`worst_category`](../../web_crypto_checker/policy.py). Of everything a server
offers in a class, **the one that counts is the worst scored category**. It does
not matter that it offers ten impeccable suites: if the eleventh is `insecure`,
that is what an attacker gets to negotiate, and that is what scores.
`informational` and `unknown` do not enter the count.

---

## The five classes and their weight

The grade is a weighted average of five classes, using the weights in
`scoring.class_weights`:

| Class | JSON key | Weight | How it is classified |
|---|---|---|---|
| Protocol | `protocols` | 3 | `id → category` list. |
| Cipher suite | `cipher_tag_categories` | 3 | **By tags** derived from the name. |
| Certificate | *(in code)* | 3 | The certificate's key + signature. |
| Group | `groups` | 2 | `name → category` list. |
| Signature | `signatures` | 1 | `name → category` list. |

Four of the five are edited in `algorithms.json`; the **certificate** is assessed
in code ([`assessment.py`](../../web_crypto_checker/assessment.py),
[`pki/certificates.py`](../../web_crypto_checker/pki/certificates.py)) from the
key's type and size and its signature algorithm, and the hygiene and trust checks
that are not algorithm categories are described in
[`politica-configuracion.md`](politica-configuracion.md).

---

## Protocols, groups and signatures: name → category

Three classes are flat lists. Each entry is a name and a category, plus an
optional `note` shown in the report:

```json
"protocols": [
  {"id": "tls1_3", "category": "recommended"},
  {"id": "tls1_2", "category": "acceptable"},
  {"id": "tls1_0", "category": "weak", "note": "Deprecated by RFC 8996."},
  {"id": "ssl3",    "category": "insecure", "note": "POODLE; SSL 3.0 must not be used."}
]
```

```json
"groups": [
  {"name": "x25519", "category": "recommended"},
  {"name": "ffdhe2048", "category": "acceptable"},
  {"name": "secp224r1", "category": "weak"},
  {"name": "secp192r1", "category": "insecure"}
]
```

Signatures are the same (`ed25519` recommended, `rsa_pkcs1_sha256` acceptable,
`rsa_pkcs1_sha1` insecure). The identifiers are the standardized codes the tool
observes on the wire —the same ones as
[`tls/constants.py`](../../web_crypto_checker/tls/constants.py)—, not invented
names. A name the list does not mention falls into `unknown`, which does not
penalize: that is why the post-quantum hybrids (`X25519MLKEM768`,
`SecP256r1MLKEM768`, `X25519Kyber768Draft00`) are in the groups list as
`recommended`, so that offering them counts in favour rather than as something
unknown.

---

## Cipher suites: by tag, not by name

Here is the important difference. **There is no entry per suite.** A suite is
classified by its **shape-tags**, and the tags are derived mechanically from its
standardized name in
[`cipher_suite_tags`](../../web_crypto_checker/tls/constants.py). The name
`TLS_RSA_WITH_3DES_EDE_CBC_SHA` produces, without anyone writing it by hand, the
tags `3des`, `cbc`, `no-forward-secrecy` and `sha1`.

`cipher_tag_categories` is the only thing edited: it maps each tag to a category.

```json
"cipher_tag_categories": {
  "null": "insecure",  "anon": "insecure", "export": "insecure",
  "rc4": "insecure",   "des": "insecure",  "md5": "insecure",
  "3des": "weak",      "sha1": "weak",
  "cbc": "acceptable", "no-forward-secrecy": "acceptable",
  "aead": "recommended"
}
```

The suite's category is the **worst** of its tags' categories (`worst_category`
again). An AEAD suite with ECDHE carries `aead` and `pfs` and comes out
`recommended`; an RC4 suite carries `rc4` and comes out `insecure` even though it
is also `pfs`.

### The tags that exist

`cipher_suite_tags` recognizes these properties by reading the name:

| Tag | Set when the name… | Default category |
|---|---|---|
| `null` | contains `NULL` (no encryption) | insecure |
| `anon` | contains `ANON` (no authentication) | insecure |
| `export` | contains `EXPORT` (deliberately small keys) | insecure |
| `rc4` | contains `RC4` | insecure |
| `des` | is single DES (`DES_CBC`/`WITH_DES`) | insecure |
| `md5` | contains `MD5` | insecure |
| `3des` | contains `3DES` | weak |
| `sha1` | ends in `_SHA` (HMAC-SHA1, not TLS 1.3) | weak |
| `cbc` | contains `CBC` | acceptable |
| `no-forward-secrecy` | is not DHE/EDH nor TLS 1.3 | acceptable |
| `aead` | is GCM, CCM, POLY1305 or TLS 1.3 | recommended |
| `pfs` | is DHE/EDH or TLS 1.3 | *(unmapped: informational)* |

Only tags that appear in `cipher_tag_categories` score; `pfs` is not mapped, so it
does not score (it contributes forward secrecy, but the grade is set by the worst
trait). A tag not listed is ignored, without error.

> **Why the tags are derived from the name rather than written one by one.** TLS
> suite names are structured on purpose: `WITH_3DES`, `_CBC_`, `_GCM_` always mean
> the same thing. A rule written against the `cbc` tag still holds the day a CBC
> suite that
> [`constants.py`](../../web_crypto_checker/tls/constants.py) does not list yet
> appears; a list of names does not. It is also what connects this classification
> with vulnerability detection, which reasons over the same tags —see
> [`politica-vulnerabilidades.md`](politica-vulnerabilidades.md).

---

## Strength in bits: `security_strength`

Besides the category, the report gives an **effective strength in bits**: the
weakest link across the classes the server would actually use (NIST SP 800-57
Part 1 Rev. 5). It is computed from the `security_strength` key, and re-tuning the
numbers here re-tunes the report without touching code:

```json
"security_strength": {
  "symmetric": [["AES_256", 256], ["AES_128", 128], ["3DES", 112], ["RC4", 38], ...],
  "hash": [["sha512", 256], ["sha256", 128], ["sha1", 80], ["md5", 0], ...],
  "asymmetric": {
    "rsa_thresholds": [[0, 0], [1024, 80], [2048, 112], [3072, 128], [7680, 192], [15360, 256]],
    "ec_divisor": 2,
    "named": {"Ed25519": 128, "Ed448": 224}
  },
  "levels": [ {"min_bits": 112, "id": "transitional", "label": "Transitional", ...}, ... ]
}
```

- `symmetric` and `hash` are `keyword → bits` pairs scanned **in order** (most
  specific first) against the cipher-suite and signature-scheme names.
- `asymmetric` maps the certificate key to bits: the RSA/DH modulus via the
  ascending thresholds, an EC field size divided by `ec_divisor`, or a named
  curve.
- `levels` bucket the effective bits (ascending, the highest match wins):
  `broken` < 80, `legacy` 80, `transitional` 112, `acceptable` 128, `strong` 192,
  `top` 256.

---

## Scoring and the caps

The `scoring` block closes the file. Besides `class_weights`, it defines the
letter scale and the **grade caps** (`grade_caps`): named conditions that put a
ceiling on the letter however high the average comes out.

```json
"grades": [{"min": 95, "grade": "A+"}, {"min": 90, "grade": "A"}, ...],
"grade_caps": {
  "any_insecure_offered": "F",
  "sslv2_supported": "F",   "sslv3_supported": "F",
  "no_tls12_or_higher": "F",
  "weak_protocol_supported": "C",
  "certificate_invalid": "F", "self_signed": "C"
}
```

Offering a single `insecure` thing forces **F** even if the average is 90;
speaking TLS 1.0/1.1 caps at **C**; a certificate a browser would reject forces
**F**. The certificate caps (`certificate_invalid`, `self_signed`) are explained
in [`politica-configuracion.md`](politica-configuracion.md).

---

## Adding or reclassifying something: the recipe

1. **Check whether it is already there.** `--show-policy` counts what each class
   recognizes. A protocol, group or signature is added with one `{"name": …,
   "category": …}` line in the right list.
2. **For a suite, think in tags, not names.** You almost never need to touch
   `cipher_tag_categories`: if the suite is a new CBC, it already carries the
   `cbc` tag. You edit this map only to change the *opinion* about a whole family
   (e.g. downgrade `cbc` from `acceptable` to `weak`). If the suite name is not in
   [`constants.py`](../../web_crypto_checker/tls/constants.py), the tool reports it
   by its hex code rather than guessing.
3. **Use the real on-the-wire identifiers**, the same ones the report prints; do
   not invent names.
4. **Check it against a server** and see that the classification is what you
   expected:

```bash
web-crypto-checker --config my-policy.json --show-policy
web-crypto-checker --config my-policy.json example.com
```

---

## Languages

The translatable prose (category labels, strength-level descriptions and each
vulnerability's name/description/remediation) is overlaid from
`data/i18n/algorithms.<language>.json`, matched by stable identifiers. A missing,
broken or partial overlay silently falls back to English; **ids, codes and
algorithm names are never translated**. The detail is in
[`policy.py`](../../web_crypto_checker/policy.py).
</content>
