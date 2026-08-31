# `fleet` plugin manual

> Before this, read [`plugins.md`](plugins.md): the metadata, what you can
> return and the two guarantees (a plugin cannot change the grade, a plugin
> cannot break the scan) are common to every type. · [Español](../es/plugin-fleet.md).

A `fleet` sees **every server in the scan at once**. It exists for what you
cannot see by looking at one machine, however hard you look.

The canonical example is the **shared certificate**: two servers presenting the
same certificate -- and therefore the same private key -- is not a property of
either one, it is a property **of the pair**. No per-server check can ever find
it, and the consequence matters: extracting the private key from the least
important of those hosts is enough to impersonate all of them, and no client can
tell the difference.

```python
KIND = "fleet"

def check(fleet):   # `fleet` is a FleetView, not a ServerView
    ...
```

It runs **once per scan**, after everything has been scanned.

## What `fleet` is

A `FleetView`, which is a collection of servers:

| | |
|---|---|
| `for server in fleet` | Walk **every** target. |
| `len(fleet)` | How many there were. |
| `fleet.with_certificates()` | Only the ones that presented a leaf certificate. |
| `fleet.policy` | The policy, in case you need to ask it for thresholds. |

Each item is a `ScannedServer`:

| | |
|---|---|
| `server.target` | The address as the report prints it. |
| `server.label` | The inventory label, if it had one. |
| `server.view` | A `ServerView` identical to the one a `check` receives. |

> **The targets that failed are here too.** A server that refused the connection
> has an **empty** view, not a missing one. This matters more than it looks: if
> the unreachable ones dropped off the list, a check like "do all my servers
> present the same certificate?" would answer from whichever ones happened to be
> up, and say yes.

So, while walking, decide what to do with the ones that did not answer:

```python
for server in fleet:
    if server.view.leaf is None:
        continue          # or count it, but decide
```

## What you return: each finding says whose it is

A `fleet` sees everything, so it has to say **which server** each result is
about. Return a list of `ForTarget`:

```python
from web_crypto_checker.models import Finding, Severity
from web_crypto_checker.plugins import ForTarget

return [
    ForTarget(
        target=server.target,                 # the address, as the report prints it
        finding=Finding(
            id="my-finding",
            severity=Severity.INFO,
            title="…",
            description="…",
            items=["the evidence"],
        ),
    )
]
```

`target` has to be an address the scan produced (a `server.target`); a
`ForTarget` naming a server the scan never saw is **dropped**, not invented. The
finding is inserted at the front of that server's findings: a shared certificate
changes how everything else should be read.

## A worked example

The built-in `shared-certificate` plugin is the first `fleet`, and the reason
the type exists. It groups the servers by the **SHA-256 fingerprint** of their
certificate and reports each group with more than one distinct address:

```python
"""The same certificate presented by more than one server in the scan."""

from typing import Any, Dict, List

from web_crypto_checker.models import Finding, Severity
from web_crypto_checker.plugins import ForTarget

ID = "shared-certificate"
NAME = "This certificate is shared with another scanned server"
KIND = "fleet"
SEVERITY = "info"
DESCRIPTION = "The same certificate is presented by more than one server…"
REMEDIATION = "If the sharing is intentional (a load balancer), nothing need change…"


def check(fleet: Any) -> Any:
    by_fingerprint: Dict[str, List[Any]] = {}
    for server in fleet.servers:
        leaf = server.view.leaf
        if leaf is None or not leaf.fingerprint_sha256:
            continue                          # unreachable or no certificate
        by_fingerprint.setdefault(leaf.fingerprint_sha256, []).append(server)

    found = []
    for fingerprint, sharing in by_fingerprint.items():
        names = sorted({server.target for server in sharing})
        if len(names) < 2:
            continue                          # the same address twice is not sharing
        for server in sharing:
            peers = [name for name in names if name != server.target]
            found.append(
                ForTarget(
                    target=server.target,
                    finding=Finding(
                        id=ID, severity=Severity.INFO, title=NAME,
                        description=DESCRIPTION, remediation=REMEDIATION,
                        items=[fingerprint, "also presented by: " + ", ".join(peers)],
                    ),
                )
            )
    return found
```

Note the `len(names) < 2` over the **distinct** addresses: an inventory can name
the same host twice, and that is not a shared certificate.

## The same boundary, with more reason

A `fleet` sees more, but **can do no more**: the same boundary as a `check`. It
sees that two servers present the same certificate; it does not see, or change,
the grade either of them got. The result is a report finding, added after the
grades are computed. And if your `check(fleet)` raises, it is caught and reported
as a finding that names the plugin, exactly as in the per-server case: a broken
`fleet` does not break the scan.

## When **not** to write a `fleet`

Almost always what you want is a [`check`](plugin-check.md): it looks at one
server, runs once per target, and is 90% of the cases. A `fleet` is justified
only when what you are after **is not a property of a machine but of the set** --
shared keys or certificates, "are they all on the same TLS version?",
correlations across targets. If the check makes sense looking at a single
server, it is a `check`, not a `fleet`.
