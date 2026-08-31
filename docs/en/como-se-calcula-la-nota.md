# How the grade is calculated

Back to the [manual](README.md) · related: [scoring and caps](politica-puntuacion.md) ·
[policy file](politicas.md) · [Español](../es/como-se-calcula-la-nota.md).

This document is **the complete, public scoring system**. Nothing is hidden:
every number comes from the policy file
[`web_crypto_checker/data/algorithms.json`](../../web_crypto_checker/data/algorithms.json),
which can be read and changed.

If what you want is to **change** those numbers, go to
[`politica-puntuacion.md`](politica-puntuacion.md). This explains **how it
works** and **why**, which is what someone needs when a C has just landed on
them and they want to know whether it is fair.

## Where these numbers come from (and where they do not)

Two things are worth separating, because they have different origins:

- **Which algorithm is good or bad** — that TLS 1.0 is *weak* or that an AEAD
  cipher is *recommended* — **comes from documents**: Mozilla Server Side TLS,
  NIST SP 800-52 Rev. 2, IETF BCP 195 (RFC 9325), the retirement of TLS 1.0/1.1
  by RFC 8996, POODLE for SSL 3.0, DROWN for SSL 2.0. Each protocol, group or
  signature says so in its `note` inside the file, and the `metadata` block
  cites the policy's references.
- **How those judgements become a letter** — the per-class weights (protocol,
  cipher and certificate 3; group 2; signature 1), the grade scale (A+…F, with
  an E in between) and the caps — **is this tool's own judgement**, not taken
  from any external document. It is a methodology: legitimate, but a **choice**.
  That is why it is written out in full here and justified, so it can be debated
  or changed, not mistaken for a documented requirement.

The only scoring figure that **does** come from a document is the **strength
bands in bits**: they are those of NIST SP 800-57 Part 1 Rev. 5. The **names**
of those bands (broken, legacy, transitional, acceptable, strong, top) are our
own presentation.

---

## Two answers, not one

The tool gives **two different things** about each server, and it pays not to
confuse them:

| | What it is | What it is for |
|---|---|---|
| **The grade** (`A+` … `F`) | A number compressed into a letter. | Comparing, tracking over time, putting on a dashboard. |
| **The verdict** (`secure`, `acceptable`, `weak`, `insecure`) | A judgement about the state. | Deciding whether action is needed. |

They are computed along different paths on purpose: **a high average does not
erase a broken thing**. The grade is a weighted average; the verdict is the
worst category the server offers, with no averaging.

Even so, they cannot contradict each other on the worst case: offering something
`insecure` leaves that class in the `insecure` category, which **at once** fixes
the verdict at `insecure` and fires the `any_insecure_offered` cap, which lowers
the grade to `F`. It is the same condition seen twice, so the letter and the word
agree where it matters most.

### The verdict table

| Verdict | When |
|---|---|
| `secure` | The worst thing it offers is `recommended`. |
| `acceptable` | The worst is `acceptable`: nothing weak or insecure, but something could be better. |
| `weak` | It offers something in category `weak`. |
| `insecure` | It offers something in category `insecure`. |
| `unknown` | The server was reached but the policy recognises **nothing** it offers. |
| `error` | It could not be scanned. |

On `unknown`: if the policy classifies none of the server's algorithms, the tool
**does not invent a grade**. It returns `score` and `grade` as `null` and marks
the verdict `unknown`. An `F` would suggest the server is insecure and an `A`
that it is fine; neither is backed by the evidence.

There are also two cases that force `insecure` no matter what: a **cleartext**
transport (unencrypted HTTP) sends the grade to `0`/`F` and the verdict to
`insecure` with no further arithmetic, and an **alternate certificate** a browser
rejects also leaves the verdict at `insecure`.

---

## The steps

The computation is direct: category → worst member per class → weighted average →
letter → caps. **There is no modifier phase** adding or subtracting stray points;
what a server loses for a serious fact is decided by the caps.

### 1. Every algorithm gets a category

From the lists in the policy file. Each category is worth points:

| Category | Points |
|---|---|
| `recommended` | 100 |
| `acceptable` | 80 |
| `weak` | 40 |
| `insecure` | 0 |
| `informational` | *not scored* |
| `unknown` | *not scored* |

**`unknown` does not penalize**, and that is deliberate: servers are forever
offering names nobody has catalogued, and punishing them would treat someone
using something new and good the same as someone using something odd and bad. It
appears in the report as "unclassified" so that someone takes a look.

### 2. Each class is scored by **its worst member**

```
class score = minimum of the scores of what it offers
```

It is not the average, and this is what surprises people most. The reason is the
protocol itself: **the client is the one that chooses the algorithm**, from among
those the server offers. A server with twelve excellent ciphers and one broken
one can be steered onto the broken one by any misconfigured client — or by
whoever sits in the middle. To offer it is to allow it.

The TLS classes are the **protocol** versions, the **cipher suites**, the
key-exchange **groups**, the **signature** algorithms, and the **certificate**. A
cipher suite is classified by its **shape tags** (`3des`, `cbc`, `rc4`, `aead`,
`no-forward-secrecy`…) and keeps the worst. The certificate is judged as a single
object: the worst category between its **key strength** and its **signature
algorithm**.

### 3. The classes are combined with their weights

```json
"class_weights": { "protocol": 3, "cipher": 3, "certificate": 3, "group": 2, "signature": 1 }
```

```
base = Σ (class score × weight) / Σ weights
```

They do not have to add up to anything in particular; they are normalized by
dividing by the sum of the weights present. A class that produces no scored
category **drops out of the divisor**: it neither adds nor subtracts.

An honest nuance: the classes that today carry a category that **moves the
letter** are the protocol, the cipher suites and the certificate. The key-exchange
groups and the signature algorithms are classified and shown in the report, they
feed the **effective security strength** and the **conformance profiles**, and
their weights are declared in the file; the grade today weighs the first three
classes.

### 4. The number becomes a letter, and then the caps come down

```json
"grades": [
  {"min": 95, "grade": "A+"}, {"min": 90, "grade": "A"}, {"min": 80, "grade": "B"},
  {"min": 70, "grade": "C"}, {"min": 60, "grade": "D"}, {"min": 50, "grade": "E"},
  {"min": 0, "grade": "F"}
]
```

| Grade | From |
|---|---|
| `A+` | 95 |
| `A` | 90 |
| `B` | 80 |
| `C` | 70 |
| `D` | 60 |
| `E` | 50 |
| `F` | 0 |

And then, **the caps**: conditions that put a ceiling on the grade no matter what
happens with the number.

| If… | The grade cannot exceed |
|---|---|
| It offers something `insecure` (`any_insecure_offered`) | `F` |
| It speaks SSL 2.0 (`sslv2_supported`) | `F` |
| It speaks SSL 3.0 (`sslv3_supported`) | `F` |
| It offers neither TLS 1.2 nor 1.3 (`no_tls12_or_higher`) | `F` |
| It offers TLS 1.0 or 1.1 (`weak_protocol_supported`) | `C` |
| The certificate is invalid (`certificate_invalid`) | `F` |
| The certificate is self-signed (`self_signed`) | `C` |

The caps exist because **an average lies**. A server with twenty excellent things
and one broken one has a very good average and a very serious problem.

> `certificate_invalid` covers a range: expired or not yet valid, the name does
> not match, the chain does not build to a trusted root, the certificate's purpose
> does not authorise `serverAuth`, it is revoked, its signature does not verify, or
> the key is ROCA-vulnerable. Any of these makes a browser reject the certificate,
> so the class becomes `insecure` and the grade `F`.

Known vulnerabilities (DROWN, POODLE, Sweet32, RC4, FREAK/Logjam, BEAST…) are
detected and reported as **findings** with their severity, but they **do not cap
the grade on their own**: what punishes them is the category of the algorithm or
protocol that makes them possible, which is already in the lists.

---

## A complete example, actually calculated

A server with only TLS 1.2, which among its ciphers offers a 3DES suite, with an
RSA 2048-bit certificate signed with SHA-256:

```
classes: protocol 80   cipher 40   certificate 100
weights: protocol  3   cipher  3   certificate   3

base = (80×3 + 40×3 + 100×3) / (3 + 3 + 3) = 660 / 9 = 73

73 sits in the C band (≥ 70)
caps: none fire (3DES is 'weak', not 'insecure', and there is no weak cap)
grade: C          verdict: weak
```

Notice that **the 3DES suite is worth 40 and drags the whole cipher class down to
40**, even though the server also offers perfect AEAD ciphers. That is step 2,
and it is the one that costs the most grade. The verdict is `weak` because `weak`
is the worst thing on the table; the grade stays at C not because a cap lowers it
but because the average already lands there.

Change one detail and you will see the caps bite:

- If the same server **also spoke TLS 1.0**, `weak_protocol_supported` would pin
  the ceiling at `C` — right where it already was.
- If it offered an **RC4 or NULL** suite, that cipher class would be `insecure`
  (0 points), `any_insecure_offered` would drop the grade to `F` and the verdict
  would become `insecure`.

You can reproduce it with:

```bash
web-crypto-checker example.com --format json -o report.json
```

The `score_breakdown` object in the JSON carries the per-class scores
(`class_scores`), the weights (`class_weights`), the base (`base_score`) and the
applied caps (`applied_caps`). **There is no arithmetic the tool does not show.**

---

## What to do if you disagree

The numbers are not sacred: they are a file. The tool loads
[`web_crypto_checker/data/algorithms.json`](../../web_crypto_checker/data/algorithms.json)
and there is no modifier phase nor a hidden layer; edit
`scoring.class_weights`, `scoring.grades` or `scoring.grade_caps` there and
rescan.

If your organization believes the signature should weigh more, or that TLS 1.1
should not stop at C, change it and document why. The only thing you should not
do is change it halfway through a historical series without rescanning the fleet:
the grades would stop being comparable with one another. How to edit it, with
which rules and what the loader checks, is in
[`politica-puntuacion.md`](politica-puntuacion.md) and [`politicas.md`](politicas.md).
