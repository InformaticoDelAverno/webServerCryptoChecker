# Detection plugins

Back to the [manual](README.md) · related:
[conformance profiles](politica-normativas.md) · [Español](../plugins.md).

Most checks are matched declaratively from the policy (a name, a tag, a version).
What a rule cannot do is **compute**: factor a modulus, correlate two
observations, decide from arithmetic. That is what plugins are for.

## Two guarantees

- **A plugin cannot change the grade.** It receives a `ServerView` of what was
  *observed* — never the score, the grade or the verdict — and its result is
  added to the report *after* the score is computed. That is why it is the safe
  place for whatever must be computed: as an observation it cannot cause a false
  fail.
- **A plugin cannot bring the scan down.** Whatever it raises is caught and
  reported as a finding that names it.

Loading code is loading code: plugin directories are **explicit** (never the
working directory), and one that the group or others can write to is
**rejected** (it stops someone from running code as whoever launched the scan).

## A plugin is a file

```python
ID = "EXAMPLE-1"
NAME = "Something a rule cannot express"
SEVERITY = "high"          # info | low | medium | high | critical
DESCRIPTION = "What is wrong and why it matters."
REMEDIATION = "What to do about it."   # optional
KIND = "vulnerability"     # optional: "vulnerability" (default) or "check"
REFERENCES = ["CVE-2017-15361"]          # optional

def check(server):
    # `server` is a read-only ServerView.
    if server.offers_cipher("TLS_RSA_WITH_RC4_128_SHA"):
        return Detected(evidence=["RC4 offered"])
    return None            # None = nothing to report
```

Required fields: `ID`, `NAME`, `SEVERITY`, `DESCRIPTION` and a `check(server)`
function. If the plugin lacks the data to decide, it can return
`Undetermined(needs=[...])` instead of `Detected(...)`, saying what would settle
it (better than a silent false negative).

## What `check(server)` sees

The `ServerView` exposes **what was observed, and nothing that was concluded**:

- `server.supported_protocols` and `server.supports(protocol_id)`
- `server.offered_ciphers` and `server.offers_cipher(name)`
- `server.cipher_tags(name)` (the tags of a suite)
- `server.key_exchange_groups`, `server.signature_algorithms`
- `server.certificate()` (the leaf certificate) and `server.leaf`
- `server.caa_records`
- `server.assessment(key)` and `server.assessments`

There is no score, grade or verdict in there: that boundary is the point.

## Loading them

```bash
web-crypto-checker example.com --plugin-dir ./my-plugins
web-crypto-checker --list-plugins        # see the ones that would load, and exit
```

In the [web interface](README.md#the-web-interface) they come in by deployment,
through the `WEB_CRYPTO_CHECKER_WEB_PLUGIN_DIR` variable, not through the form.

## The built-in ones

Three ship, loaded exactly like a third-party plugin (so they are also worked
examples):

- **Client simulation**: which known clients (current browsers, Java 8/11,
  Android 5, IE8/XP…) would complete the handshake, crossing what was enumerated
  with a profile of each client. It is an observation (INFO), not a grade.
- **Certificate lifetime**: a leaf valid for more than 398 days (the CA/Browser
  Forum ceiling). It is a plugin because the days between two dates have to be
  **computed**.
- **Issuer authorisation by CAA**: a conservative heuristic (only very
  well-known CAs, and only when none of their identifiers is among the
  authorised ones), safe precisely because as an observation it cannot change
  the grade.
