# Policy manual — scoring, grades, and caps

Back to the [manual](README.md) · related: [how the grade is calculated](como-se-calcula-la-nota.md) ·
[policy file](politicas.md) · [Español](../es/politica-puntuacion.md).

> Before this, read [`politicas.md`](politicas.md).

This is where **the grade a server gets** is decided. It is the part of the file
with the most consequences: changing one weight changes every report.

---

## How it is calculated, in order

1. **Each class earns a score** from the categories of what the server offers,
   taken at its **worst member**.
2. **The scores are combined using the weights** in `class_weights`.
3. **The resulting number becomes a grade** using the `grades` scale.
4. **The caps are applied**: a `grade_caps` condition can lower the grade however
   much the number says otherwise.

There is no **modifier** step: this policy does not add or subtract stray points
for isolated facts. What a server loses for something serious is decided by the
caps. The verdict (`secure`, `acceptable`, `weak`, `insecure`) is decided
**separately** from the number, from the worst category offered.

---

## The weights

```json
"class_weights": { "protocol": 3, "cipher": 3, "certificate": 3, "group": 2, "signature": 1 }
```

They do not have to add up to 100; they are normalized by dividing by the sum of
the weights of the classes that actually score. A class with no scored category
drops out of the divisor.

Today the classes that carry a category that **moves the letter** are the
**protocol**, the **cipher suites** and the **certificate**. The key-exchange
**groups** and the **signatures** are classified and shown, they feed the
effective security strength and the profiles, and their weights are declared in
the file.

---

## The grade scale

```json
"grades": [
  {"min": 95, "grade": "A+"},
  {"min": 90, "grade": "A"},
  {"min": 80, "grade": "B"},
  {"min": 70, "grade": "C"},
  {"min": 60, "grade": "D"},
  {"min": 50, "grade": "E"},
  {"min":  0, "grade": "F"}
]
```

It is walked from top to bottom and the first entry whose `min` is reached wins.
The list **cannot be empty**: without a scale there is no grade, and the loader
rejects it with `policy has no grade scale`. Unlike some tools, here a grade is
just its threshold: there are no extra conditions to meet for an `A+`.

---

## The grade caps

A cap says: **whatever happens with the number, the grade cannot rise above this
point.** It is a dictionary of condition → maximum grade:

```json
"grade_caps": {
  "any_insecure_offered": "F",
  "sslv2_supported": "F",
  "sslv3_supported": "F",
  "no_tls12_or_higher": "F",
  "weak_protocol_supported": "C",
  "certificate_invalid": "F",
  "self_signed": "C"
}
```

They exist because an average lies. A server with many excellent things and one
broken one has a very good average and a very serious problem. The cap cuts
through that arithmetic.

### The conditions

| Condition | It holds when |
|---|---|
| `any_insecure_offered` | Some evaluated class ends up in category `insecure`. |
| `sslv2_supported` | The server speaks SSL 2.0. |
| `sslv3_supported` | The server speaks SSL 3.0. |
| `no_tls12_or_higher` | It supports neither TLS 1.2 nor TLS 1.3. |
| `weak_protocol_supported` | It supports TLS 1.0 or TLS 1.1. |
| `certificate_invalid` | The certificate is invalid: expired or not yet valid, the name does not match, the chain does not build to a trusted root, the purpose does not authorise `serverAuth`, revoked, the signature does not verify, or ROCA-vulnerable. |
| `self_signed` | The certificate is self-signed. |

A condition only bites if its key is in `grade_caps` with a maximum grade.
Changing a ceiling is changing its value; deleting the key disables the cap.
Vulnerabilities have no cap of their own: they are reported as findings and what
punishes them is the category of the algorithm or protocol that permits them.

---

## Effective security strength

Besides the grade, the tool reports **how many effective bits of security** the
connection has: the weakest link in the chain, the minimum across the classes
that carry bits (cipher, group, signature and the certificate key). Protocol and
compression carry no bits and do not take part.

```json
"security_strength": {
  "reference": "NIST SP 800-57 Part 1 Rev. 5",
  "symmetric": [ ["AES_256", 256], ["AES_128", 128], ["CHACHA20", 256], ["3DES", 112], ["RC4", 38], ["DES", 56], ["NULL", 0] ],
  "hash":      [ ["sha512", 256], ["sha384", 192], ["sha256", 128], ["sha224", 112], ["ed25519", 128], ["ed448", 224], ["sha1", 80], ["md5", 0] ],
  "asymmetric": {
    "rsa_thresholds": [[0, 0], [1024, 80], [2048, 112], [3072, 128], [7680, 192], [15360, 256]],
    "ec_divisor": 2,
    "named": {"Ed25519": 128, "Ed448": 224}
  },
  "levels": [ ... ]
}
```

- **`symmetric`** and **`hash`** are `keyword → bits` pairs scanned in order (most
  specific first) against the suite name and the signature scheme. The first one
  that appears wins.
- **`asymmetric`** maps the certificate key to bits: a named curve (`named`), an
  EC field divided by `ec_divisor`, or an RSA/DH modulus by the largest
  `rsa_thresholds` entry that does not exceed it.
- **`levels`** are the bands the result is labeled with; the highest one whose
  `min_bits` is reached wins.

| Band | From | What it means |
|---|---|---|
| `broken` | 0 | Under 80 bits; no meaningful protection. |
| `legacy` | 80 | 80-bit; disallowed by NIST since 2013. |
| `transitional` | 112 | 112-bit; acceptable through 2030 (NIST SP 800-57). |
| `acceptable` | 128 | 128-bit; the modern baseline. |
| `strong` | 192 | 192-bit. |
| `top` | 256 | 256-bit. |

Re-tuning any of these numbers re-tunes the report without touching code.

---

## Before you touch any of this

Changing the weights or the caps changes **every** report you produce, and the
historical ones will stop being comparable. If you maintain a time series:

1. Change the policy in
   [`web_crypto_checker/data/algorithms.json`](../../web_crypto_checker/data/algorithms.json).
2. Rescan the entire fleet with the new one.
3. Start the series from there, and write down why.

And check it by scanning: a file that does not add up fails at load, and one that
does already reflects the new criterion.

```bash
web-crypto-checker example.com --format json -o test.json
```
