# Manual de plugins de tipo `check`

> Antes de esto, lee [`plugins.md`](plugins.md): los metadatos, lo que se puede
> devolver y las dos garantías (un plugin no cambia la nota, un plugin no tumba
> el escaneo) son comunes a los dos tipos. · [English](../en/plugin-check.md).

Un `check` mira **un servidor** y opina sobre él. Su resultado aparece en el
informe como un hallazgo (`Finding`), junto a los que produce el análisis del
núcleo. Los tres plugins de serie que trae la herramienta son de este tipo.

```python
KIND = "check"

def check(server):   # `server` es un ServerView
    ...
```

---

## Qué es `server`

Un `ServerView`: **lo que se observó**, y nada de lo que se concluyó. No tiene
puntuación, ni grado, ni veredicto, y nunca los tendrá. Esa frontera es el
punto: como observación, un plugin no puede provocar un falso suspenso.

Todo lo de abajo tiene respuesta aunque el escaneo recogiera poco. Un endpoint
que no negoció nada da listas vacías, no un error.

### Los protocolos

| | |
|---|---|
| `server.supported_protocols` | Los identificadores de las versiones que el servidor acepta: `"tls1_0"`, `"tls1_1"`, `"tls1_2"`, `"tls1_3"`. Solo las aceptadas. |
| `server.supports("tls1_0")` | Si acepta esa versión en concreto. |

### Las suites de cifrado

| | |
|---|---|
| `server.offered_ciphers` | Los nombres de todas las suites que el servidor acepta, p. ej. `"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"`. |
| `server.offers_cipher(nombre)` | Si ofrece esa suite en concreto. |
| `server.cipher_tags(nombre)` | Las **etiquetas de forma** de una suite, leídas mecánicamente de su nombre: `cbc`, `aead`, `rc4`, `3des`, `des`, `md5`, `sha1`, `null`, `anon`, `export`, y `pfs` o `no-forward-secrecy`. Razonar por etiqueta en vez de por nombre hace que tu plugin siga funcionando cuando aparezca una suite que hoy no existe. |

> A diferencia de la política de algoritmos, `cipher_tags` no consulta ninguna
> tabla: las deriva del nombre estandarizado, que está estructurado a propósito.
> Una suite sin catalogar tiene sus etiquetas igualmente.

### Los grupos y las firmas

| | |
|---|---|
| `server.key_exchange_groups` | Los grupos de intercambio de claves ofrecidos, por nombre. |
| `server.signature_algorithms` | Los algoritmos de firma anunciados. |

### El certificado

`server.certificate()` (equivale a `server.leaf`) es el certificado hoja, o
`None` si no se recogió ninguno. **Comprueba `None` antes de usar el resto.**

El objeto es un `CertificateInfo` ([`../web_crypto_checker/models.py`](../../web_crypto_checker/models.py)).
Los campos que más se usan:

| | |
|---|---|
| `leaf.subject`, `leaf.issuer` | Los DN de sujeto y emisor. |
| `leaf.sans` | Los nombres alternativos (SAN). |
| `leaf.key_type` | `"RSA"`, `"EC"` o `"Ed25519"`. |
| `leaf.key_bits`, `leaf.curve` | El tamaño de la clave, y la curva (`"P-256"`…) si es EC. |
| `leaf.not_before`, `leaf.not_after` | Inicio y fin de validez, **en tiempo Unix** (`int`) o `None`. La aritmética de fechas es tuya. |
| `leaf.signature_algorithm` | El algoritmo con que se firmó. |
| `leaf.roca_vulnerable` | Si la clave RSA lleva la huella de ROCA. |
| `leaf.is_self_signed`, `leaf.is_ca`, `leaf.path_length`, `leaf.key_cert_sign`, `leaf.extended_key_usages` | Restricciones básicas, usos de clave y usos extendidos. |
| `leaf.fingerprint_sha256` | La huella, para citarla como evidencia. |
| `leaf.sct_count`, `leaf.verified_scts`, `leaf.sct_logs` | Los SCT embebidos (Certificate Transparency) y cuántos verifican. |
| `leaf.ocsp_must_staple`, `leaf.ocsp_url`, `leaf.ca_issuers_url`, `leaf.crl_urls` | Grapado obligatorio y las URL de OCSP, emisor y CRL. |

También trae métodos: `leaf.is_expired(ahora)`, `leaf.is_not_yet_valid(ahora)` y
`leaf.days_until_expiry(ahora)`, todos con el momento en tiempo Unix.

### Los registros CAA

`server.caa_records` es la lista de registros CAA del dominio; cada uno tiene
`flags`, `tag` (`"issue"`, `"issuewild"`, `"iodef"`…) y `value`. Lista vacía
significa que el dominio no publica CAA.

### Las clasificaciones

`server.assessment(clave)` devuelve cómo quedó una clase contra la política, o
`None` si no se evaluó. Las claves son `"protocol"`, `"cipher"` y
`"certificate"`. El objeto (`ClassAssessment`) trae `worst_category`,
`score` y, lo más útil para un plugin, `preferred`: **la primera elección del
servidor**, que es lo que negocia un cliente permisivo.

---

## Un ejemplo completo

Un servidor puede ofrecer una suite AEAD moderna y aun así **preferir** una en
modo CBC. Detectarlo no es «ofrece CBC» (eso es una regla de la política): es
correlacionar lo que prefiere con lo que tiene disponible, que solo se puede
hacer con código. Fíjate en que razona por **etiquetas**, así que seguirá
valiendo cuando alguien añada una suite que hoy no existe.

```python
"""El servidor prefiere una suite CBC teniendo AEAD disponibles."""

from web_crypto_checker.plugins import Detected, ServerView

ID = "prefers-cbc-over-available-aead"
NAME = "El servidor prefiere una suite CBC pudiendo preferir AEAD"
KIND = "check"
SEVERITY = "low"
DESCRIPTION = (
    "La primera elección del servidor es una suite en modo CBC, pese a ofrecer "
    "también suites AEAD que un cliente moderno preferiría. No es inseguro por "
    "sí solo, pero deja fuera del cifrado autenticado a los clientes permisivos."
)
REMEDIATION = (
    "Ordena la lista de suites del servidor para preferir las AEAD "
    "(GCM o ChaCha20-Poly1305) por delante de las CBC."
)
REFERENCES = ["https://datatracker.ietf.org/doc/html/rfc7525#section-4.2"]


def check(server):
    cifrados = server.assessment("cipher")
    if cifrados is None or not cifrados.preferred:
        return None
    preferida = cifrados.preferred
    if "aead" in server.cipher_tags(preferida):
        return None                    # ya prefiere un AEAD, nada que decir
    aead = [c for c in server.offered_ciphers if "aead" in server.cipher_tags(c)]
    if not aead:
        return None                    # no tiene alternativa mejor: no es esto
    return Detected(evidence=[
        f"preferida: {preferida} [{', '.join(server.cipher_tags(preferida))}]",
        f"AEAD disponibles: {', '.join(sorted(aead))}",
    ])
```

Fíjate en las tres decisiones:

1. **Devuelve `None` cuando no hay nada que decir**, que es lo normal.
2. **La alternativa se comprueba antes de informar**: quejarse de una suite CBC
   preferida cuando no hay AEAD que ofrecer sería ruido, y el ruido hace que se
   ignore el resto.
3. **La evidencia dice qué suites exactamente**, no «prefiere CBC».

---

## Envolver siempre la evidencia en `Detected`

El *runner* solo entiende cuatro respuestas ([`../web_crypto_checker/plugins/runner.py`](../../web_crypto_checker/plugins/runner.py)):

- `None` o `False` — nada que informar.
- `Detected(evidence=[...], severity=None, note="")` — un hallazgo, con su
  evidencia. `severity` opcional sobreescribe la del plugin; `note` añade texto.
- `Undetermined(needs=[...])` — no se pudo decidir, y con qué se decidiría.
- Cualquier otro valor verdadero — se toma como «afectado, sin evidencia».

Esa última fila es la trampa: **devolver una lista de cadenas no adjunta
evidencia**, se lee como un `True` pelado. Si quieres que las líneas de
evidencia salgan en el informe, van dentro de `Detected(evidence=[...])`. Y un
fichero produce **un** hallazgo con el `ID` del plugin; no hay forma de emitir
varios hallazgos con identificadores distintos desde el mismo fichero.

---

## Cuándo **no** escribir un `check`

- **Si la comprobación es «esta suite o esta versión es mala»**: eso es una
  regla declarativa de la política, no código —un nombre, una etiqueta, una
  ventana de versión—, y la puede añadir alguien que no programe. Ver
  [`plugins.md`](plugins.md) y los [perfiles de conformidad](politica-normativas.md).
- **Si solo es leer un campo y compararlo con un valor fijo**: casi siempre cabe
  también como regla. Escribe un plugin cuando haya que **calcular**: aritmética
  de fechas, correlacionar dos observaciones, interpretar bytes.
