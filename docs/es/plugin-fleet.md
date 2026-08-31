# Manual de plugins de tipo `fleet`

> Antes de esto, lee [`plugins.md`](plugins.md): los metadatos, lo que se puede
> devolver y las dos garantías (un plugin no cambia la nota, un plugin no tumba
> el escaneo) son comunes a todos los tipos. · [English](../en/plugin-fleet.md).

Un `fleet` ve **todos los servidores del escaneo a la vez**. Existe para lo que
no se puede ver mirando una máquina, por bien que la mires.

El ejemplo canónico es el **certificado compartido**: que dos servidores
presenten el mismo certificado —y por tanto la misma clave privada— no es una
propiedad de ninguno de los dos, es una propiedad **de la pareja**. Ninguna
comprobación por servidor lo encontrará jamás, y la consecuencia importa: sacar
la clave privada del menos importante de esos hosts basta para suplantar a
todos, y ningún cliente nota la diferencia.

```python
KIND = "fleet"

def check(fleet):   # `fleet` es un FleetView, no una ServerView
    ...
```

Se ejecuta **una vez por escaneo**, cuando ya se ha escaneado todo.

## Qué es `fleet`

Un `FleetView`, que es una colección de servidores:

| | |
|---|---|
| `for server in fleet` | Recorre **todos** los objetivos. |
| `len(fleet)` | Cuántos había. |
| `fleet.with_certificates()` | Solo aquellos que presentaron un certificado hoja. |
| `fleet.policy` | La política, por si necesitas pedir umbrales. |

Cada elemento es un `ScannedServer`:

| | |
|---|---|
| `server.target` | La dirección tal y como el informe la imprime. |
| `server.label` | La etiqueta del inventario, si tenía. |
| `server.view` | Una `ServerView` idéntica a la que recibe un `check`. |

> **Los objetivos que fallaron también están.** Un servidor que rechazó la
> conexión tiene una vista **vacía**, no ausente. Esto importa más de lo que
> parece: si los inalcanzables se cayeran de la lista, una comprobación como
> «¿presentan todos mis servidores el mismo certificado?» contestaría desde los
> que casualmente estaban levantados, y diría que sí.

Por eso, al recorrer, decide qué hacer con los que no contestaron:

```python
for server in fleet:
    if server.view.leaf is None:
        continue          # o cuéntalo, pero decídelo
```

## Qué se devuelve: cada hallazgo dice de quién es

Un `fleet` lo ve todo, así que tiene que decir **de qué servidor** es cada
resultado. Devuelve una lista de `ForTarget`:

```python
from web_crypto_checker.models import Finding, Severity
from web_crypto_checker.plugins import ForTarget

return [
    ForTarget(
        target=server.target,                 # la dirección, tal cual la imprime el informe
        finding=Finding(
            id="mi-hallazgo",
            severity=Severity.INFO,
            title="…",
            description="…",
            items=["la evidencia"],
        ),
    )
]
```

`target` tiene que ser una dirección que el escaneo produjo (la de un
`server.target`); un `ForTarget` que nombre a un servidor que el escaneo nunca
vio se **descarta**, no se inventa. El hallazgo se inserta al principio de los de
ese servidor: un certificado compartido cambia cómo se lee todo lo demás.

## Un ejemplo completo

El plugin de serie `shared-certificate` es el primer `fleet`, y la razón de que
el tipo exista. Agrupa los servidores por la **huella SHA-256** de su
certificado y reporta cada grupo con más de una dirección distinta:

```python
"""El mismo certificado presentado por más de un servidor del escaneo."""

from typing import Any, Dict, List

from web_crypto_checker.models import Finding, Severity
from web_crypto_checker.plugins import ForTarget

ID = "shared-certificate"
NAME = "Este certificado se comparte con otro servidor del escaneo"
KIND = "fleet"
SEVERITY = "info"
DESCRIPTION = "El mismo certificado lo presenta más de un servidor…"
REMEDIATION = "Si el reparto es intencionado (un balanceador), nada que cambiar…"


def check(fleet: Any) -> Any:
    by_fingerprint: Dict[str, List[Any]] = {}
    for server in fleet.servers:
        leaf = server.view.leaf
        if leaf is None or not leaf.fingerprint_sha256:
            continue                          # inalcanzable o sin certificado
        by_fingerprint.setdefault(leaf.fingerprint_sha256, []).append(server)

    found = []
    for fingerprint, sharing in by_fingerprint.items():
        names = sorted({server.target for server in sharing})
        if len(names) < 2:
            continue                          # la misma dirección dos veces no es compartir
        for server in sharing:
            peers = [name for name in names if name != server.target]
            found.append(
                ForTarget(
                    target=server.target,
                    finding=Finding(
                        id=ID, severity=Severity.INFO, title=NAME,
                        description=DESCRIPTION, remediation=REMEDIATION,
                        items=[fingerprint, "también lo presenta: " + ", ".join(peers)],
                    ),
                )
            )
    return found
```

Fíjate en `len(names) < 2` sobre las direcciones **distintas**: un inventario
puede nombrar el mismo host dos veces, y eso no es un certificado compartido.

## La misma frontera, con más razón

Un `fleet` ve más, pero **no puede más**: la misma frontera que un `check`. Ve
que dos servidores presentan el mismo certificado; no ve, ni cambia, la nota que
sacó ninguno de los dos. El resultado es un hallazgo del informe, añadido después
de calcular las notas. Y si tu `check(fleet)` lanza una excepción, se captura y
se informa como un hallazgo que nombra al plugin, igual que en el caso por
servidor: un `fleet` roto no tumba el escaneo.

## Cuándo **no** escribir un `fleet`

Casi siempre lo que quieres es un [`check`](plugin-check.md): mira un servidor,
corre una vez por objetivo, y es el 90 % de los casos. Un `fleet` solo se
justifica cuando lo que buscas **no es propiedad de una máquina sino del
conjunto** —claves o certificados compartidos, «¿están todos en la misma versión
de TLS?», correlaciones entre objetivos—. Si la comprobación tiene sentido
mirando un solo servidor, es un `check`, no un `fleet`.
