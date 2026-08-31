# Policy file manual — overview

Back to the [manual](README.md) · related: [how the grade is calculated](como-se-calcula-la-nota.md) ·
[scoring and caps](politica-puntuacion.md) · [conformance profiles](politica-normativas.md) ·
[Español](../es/politicas.md).

The policy file is **the tool's judgement written as data**. Which TLS version is
good, which cipher is weak, which vulnerability exists, how much each class weighs
in the grade: all of that is edited without touching Python.

The reason is practical. What is secure today may not be tomorrow, and updating
the criterion must mean **editing a JSON file**, not deploying a new release. It
is the principle of the whole tool: data, not code.

---

## Where it lives and how it loads

There is **one** policy file, the one shipped with the package:
[`web_crypto_checker/data/algorithms.json`](../../web_crypto_checker/data/algorithms.json).
The tool locates it next to the package itself and loads it on every scan. To
change the criterion you **edit that file**: there is no `--config` option nor an
environment variable pointing elsewhere, so an installation's criterion is that
of its copy of `algorithms.json`.

The format is **JSON**. The loader accepts neither TOML nor YAML: the policy is
read as JSON or it is not read.

### Languages: prose overlays

The translatable prose (category labels, the names and descriptions of the
strength bands, and each vulnerability's name, description and remediation) can
arrive in another language from
[`web_crypto_checker/data/i18n/`](../../web_crypto_checker/data/i18n/), in an
`algorithms.<language>.json` file. `--lang` selects which one is overlaid,
matching each entry **by its identifier**. Only prose is translated: identifiers,
enum codes and algorithm names never change, and a missing, unreadable or partial
overlay silently falls back to English.

---

## What is inside

| Key | What it defines | Manual |
|---|---|---|
| `categories` | What each category means (`recommended`, `acceptable`, `weak`, `insecure`, `informational`, `unknown`) and how many points it is worth. | [`politica-puntuacion.md`](politica-puntuacion.md) |
| `scoring` | Per-class weights (`class_weights`), the grade scale (`grades`) and **grade caps** (`grade_caps`). | [`politica-puntuacion.md`](politica-puntuacion.md) |
| `protocols` | Each TLS/SSL version and its category. | [`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md) |
| `cipher_tag_categories` | How each **shape tag** of a suite (`3des`, `cbc`, `rc4`, `aead`…) maps to a category. | [`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md) |
| `groups` | The key-exchange groups (curves, finite-field groups and post-quantum hybrids) and their category. | [`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md) |
| `signatures` | The signature schemes and their category. | [`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md) |
| `security_strength` | The strength bits per algorithm and the level bands (NIST SP 800-57). | [`politica-puntuacion.md`](politica-puntuacion.md) |
| `vulnerabilities` | The known vulnerabilities and their detection tree. | (in this same file) |

Also: `schema_version` (starts with `1.`) and `metadata` (the file's name,
version, description and references). Beside it, two directories: the conformance
**profiles** in
[`data/profiles/`](../../web_crypto_checker/data/profiles/README.md) (see
[`politica-normativas.md`](politica-normativas.md)) and the translations in
[`data/i18n/`](../../web_crypto_checker/data/i18n/).

---

## Vulnerabilities and their detection

Each `vulnerabilities` entry carries an `id`, `name`, `severity`
(`critical`/`high`/`medium`/`low`/`info`), a description, a remediation and
references. What makes it detectable is its `detection`: a **tree of conditions**
the tool evaluates against what the server offers on the wire. Each node is
exactly **one** of these keys:

| Key | It holds when |
|---|---|
| `protocol` | The server supports that version (e.g. `{"protocol": "ssl2"}` → DROWN). |
| `cipher_tag` | Some offered suite carries that shape tag (e.g. `{"cipher_tag": "3des"}` → Sweet32). |
| `all` | Every child condition holds. |
| `any` | Some child holds. |
| `not` | The child condition does not hold. |

So BEAST is `{"all": [{"any": [{"protocol": "tls1_0"}, {"protocol": "tls1_1"}]}, {"cipher_tag": "cbc"}]}`:
CBC under TLS 1.0 or 1.1. Adding a vulnerability is adding an entry with its tree,
not touching the code.

---

## How what you write is checked

**The loader is strict on purpose.** A file that does not add up does not run
half-way; it fails at load, with the reason:

- **An invalid category is rejected.** If a protocol, group or signature declares
  a category that does not exist, the message says which (`'x' is not a valid category`).
- **The grade scale cannot be empty** (`policy has no grade scale`): without a
  scale there is no grade.
- **A vulnerability's severity must be valid**, one of the five.
- **Each detection node needs exactly one** of `protocol`, `cipher_tag`, `all`,
  `any` or `not`; not zero, not two.
- An **algorithm the policy does not know** is not an error: servers offer names
  nobody has catalogued all the time. It comes out as *unknown*, which is an
  answer, and it does not penalize.

The way to test what you edit is to scan with it: if the file does not add up, the
error fires at startup; if it does, the report already reflects the new criterion.

```bash
web-crypto-checker example.com --format json -o test.json
```

---

## The rule you should not break

**Do not invent content.** If you add a vulnerability, put in the real reference
(its CVE, its advisory). If you change a category, back it with a document. A
policy file with invented entries produces reports that someone is going to
believe, and whoever wrote them is not the one who pays for the damage.
