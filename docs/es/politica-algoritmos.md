# Manual de política — algoritmos

Volver al [manual](README.md) · relacionado:
[vulnerabilidades](politica-vulnerabilidades.md) ·
[configuración](politica-configuracion.md) · [normativas](politica-normativas.md) ·
[English](../en/politica-algoritmos.md).

Esta es la parte de la política que decide **qué opina la herramienta de cada
cosa que un servidor ofrece**: la versión de TLS, la suite de cifrado, el grupo
de intercambio de claves, el esquema de firma y el certificado. Vive casi entera
en [`web_crypto_checker/data/algorithms.json`](../../web_crypto_checker/data/algorithms.json),
y es lo que más se edita y lo que envejece más rápido. Cambiar el criterio es
editar ese fichero, en un servidor a las tres de la madrugada si hace falta, no
sacar una versión nueva.

---

## Las seis categorías

Se definen en la clave `categories`. Cada una tiene una etiqueta y una
**puntuación**:

| Categoría | Puntos | Qué significa |
|---|---|---|
| `recommended` | 100 | Moderno, sin debilidad práctica conocida. |
| `acceptable` | 80 | Sirve, pero hay algo mejor. |
| `weak` | 40 | Debilidad conocida; hay que quitarlo. |
| `insecure` | 0 | Roto. Nada debería ofrecerlo. |
| `informational` | *(sin puntos)* | Se informa, no puntúa. Para lo que no es bueno ni malo. |
| `unknown` | *(sin puntos)* | La política no lo conoce. **No puntúa a propósito.** |

```json
"categories": {
  "weak": {"label": "Weak", "score": 40}
}
```

> **`unknown` no penaliza, y es deliberado.** Un `score` a `null` significa «no
> puntúa». Los servidores ofrecen nombres que nadie ha catalogado todo el tiempo:
> una suite con un código hexadecimal que la tabla no conoce, un grupo nuevo, una
> firma experimental. Bajar la nota por algo que la política no reconoce castiga a
> quien usa algo nuevo y bueno igual que a quien usa algo raro y malo.

---

## Lo que decide la nota: el peor miembro

La regla que gobierna todo el fichero es una sola:
[`worst_category`](../../web_crypto_checker/policy.py). De todo lo que un servidor
ofrece en una clase, **la que cuenta es la peor categoría con puntos**. Da igual
que ofrezca diez suites impecables: si la undécima es `insecure`, esa es la que
un atacante consigue negociar, y esa es la que puntúa. `informational` y
`unknown` no entran en la cuenta.

---

## Las cinco clases y su peso

La nota es una media ponderada de cinco clases, con los pesos de
`scoring.class_weights`:

| Clase | Clave JSON | Peso | Cómo se clasifica |
|---|---|---|---|
| Protocolo | `protocols` | 3 | Lista `id → categoría`. |
| Suite de cifrado | `cipher_tag_categories` | 3 | **Por etiquetas** derivadas del nombre. |
| Certificado | *(en código)* | 3 | Clave + firma del certificado. |
| Grupo | `groups` | 2 | Lista `nombre → categoría`. |
| Firma | `signatures` | 1 | Lista `nombre → categoría`. |

Cuatro de las cinco se editan en `algorithms.json`; el **certificado** se evalúa
en el código ([`assessment.py`](../../web_crypto_checker/assessment.py),
[`pki/certificates.py`](../../web_crypto_checker/pki/certificates.py)) a partir del
tipo y tamaño de la clave y su algoritmo de firma, y las comprobaciones de higiene
y confianza que no son categorías de algoritmo se describen en
[`politica-configuracion.md`](politica-configuracion.md).

---

## Protocolos, grupos y firmas: nombre → categoría

Tres clases son listas planas. Cada entrada es un nombre y una categoría, y una
`note` opcional que sale en el informe:

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

Las firmas son iguales (`ed25519` recomendada, `rsa_pkcs1_sha256` aceptable,
`rsa_pkcs1_sha1` insegura). Los identificadores son los códigos estandarizados
que la herramienta observa en el cable —los mismos de
[`tls/constants.py`](../../web_crypto_checker/tls/constants.py)—, no nombres
inventados. Un nombre que la lista no menciona cae en `unknown`, que no penaliza:
por eso los híbridos post-cuánticos (`X25519MLKEM768`, `SecP256r1MLKEM768`,
`X25519Kyber768Draft00`) están en la lista de grupos como `recommended`, para que
ofrecerlos cuente a favor y no como algo desconocido.

---

## Las suites de cifrado: por etiqueta, no por nombre

Aquí está la diferencia importante. **No hay una entrada por cada suite.** Una
suite se clasifica por sus **etiquetas de forma**, y las etiquetas se derivan
mecánicamente de su nombre estandarizado en
[`cipher_suite_tags`](../../web_crypto_checker/tls/constants.py). El nombre
`TLS_RSA_WITH_3DES_EDE_CBC_SHA` produce, sin que nadie lo escriba a mano, las
etiquetas `3des`, `cbc`, `no-forward-secrecy` y `sha1`.

`cipher_tag_categories` es lo único que se edita: mapea cada etiqueta a una
categoría.

```json
"cipher_tag_categories": {
  "null": "insecure",  "anon": "insecure", "export": "insecure",
  "rc4": "insecure",   "des": "insecure",  "md5": "insecure",
  "3des": "weak",      "sha1": "weak",
  "cbc": "acceptable", "no-forward-secrecy": "acceptable",
  "aead": "recommended"
}
```

La categoría de la suite es la **peor** de las categorías de sus etiquetas
(`worst_category` otra vez). Una suite AEAD con ECDHE lleva `aead` y `pfs` y sale
`recommended`; una suite RC4 lleva `rc4` y sale `insecure` aunque también sea
`pfs`.

### Las etiquetas que existen

`cipher_suite_tags` reconoce estas propiedades leyendo el nombre:

| Etiqueta | Se pone cuando el nombre… | Categoría por defecto |
|---|---|---|
| `null` | contiene `NULL` (sin cifrado) | insegura |
| `anon` | contiene `ANON` (sin autenticación) | insegura |
| `export` | contiene `EXPORT` (claves recortadas) | insegura |
| `rc4` | contiene `RC4` | insegura |
| `des` | es DES simple (`DES_CBC`/`WITH_DES`) | insegura |
| `md5` | contiene `MD5` | insegura |
| `3des` | contiene `3DES` | débil |
| `sha1` | acaba en `_SHA` (HMAC-SHA1, no TLS 1.3) | débil |
| `cbc` | contiene `CBC` | aceptable |
| `no-forward-secrecy` | no es DHE/EDH ni TLS 1.3 | aceptable |
| `aead` | es GCM, CCM, POLY1305 o TLS 1.3 | recomendada |
| `pfs` | es DHE/EDH o TLS 1.3 | *(no mapeada: informativa)* |

Solo las etiquetas que aparecen en `cipher_tag_categories` puntúan; `pfs` no está
mapeada, así que no puntúa (aporta forward secrecy, pero la nota la fija el peor
rasgo). Una etiqueta no listada se ignora sin error.

> **Por qué las etiquetas se derivan del nombre y no se escriben una a una.** Los
> nombres de las suites TLS están estructurados a propósito: `WITH_3DES`,
> `_CBC_`, `_GCM_` significan siempre lo mismo. Una regla escrita sobre la
> etiqueta `cbc` sigue valiendo el día que aparezca una suite CBC que la tabla de
> [`constants.py`](../../web_crypto_checker/tls/constants.py) no lista todavía; una
> lista de nombres, no. Es también lo que conecta esta clasificación con la
> detección de vulnerabilidades, que razona sobre las mismas etiquetas —ver
> [`politica-vulnerabilidades.md`](politica-vulnerabilidades.md).

---

## La fuerza en bits: `security_strength`

Aparte de la categoría, el informe da una **fuerza efectiva en bits**: el
eslabón más débil entre las clases que el servidor usaría de verdad (NIST SP
800-57 Part 1 Rev. 5). Se calcula con la clave `security_strength`, y afinar los
números aquí reafinar el informe sin tocar código:

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

- `symmetric` y `hash` son pares `palabra → bits` que se buscan **en orden** (lo
  más específico primero) contra el nombre de la suite y del esquema de firma.
- `asymmetric` traduce la clave del certificado a bits: el módulo RSA/DH por los
  umbrales ascendentes, el tamaño de campo de una curva EC dividido por
  `ec_divisor`, o una curva con nombre.
- `levels` agrupa los bits efectivos en niveles (ascendente, gana el más alto):
  `broken` < 80, `legacy` 80, `transitional` 112, `acceptable` 128, `strong`
  192, `top` 256.

---

## La puntuación y los topes

El bloque `scoring` cierra el fichero. Además de `class_weights`, define la
escala de letras y los **topes de nota** (`grade_caps`): condiciones con nombre
que ponen un techo a la letra por muy alta que salga la media.

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

Ofrecer una sola cosa `insecure` fuerza **F** aunque la media sea 90; hablar TLS
1.0/1.1 topa en **C**; un certificado que un navegador rechazaría fuerza **F**.
Los topes de certificado (`certificate_invalid`, `self_signed`) se explican en
[`politica-configuracion.md`](politica-configuracion.md).

---

## Añadir o reclasificar algo: la receta

1. **Mira si ya está.** `--show-policy` cuenta lo que cada clase reconoce. Un
   protocolo, un grupo o una firma se añaden con una línea `{"name": …,
   "category": …}` en la lista que toca.
2. **Para una suite, piensa en etiquetas, no en nombres.** Casi nunca hace falta
   tocar `cipher_tag_categories`: si la suite es un CBC nuevo, ya lleva la
   etiqueta `cbc`. Solo se edita este mapa para cambiar la *opinión* sobre una
   familia entera (p. ej. degradar `cbc` de `acceptable` a `weak`). Si el nombre
   de la suite no está en [`constants.py`](../../web_crypto_checker/tls/constants.py),
   la herramienta la informa por su código hexadecimal en vez de adivinar.
3. **Usa los identificadores reales del cable**, los mismos que imprime el
   informe; no inventes nombres.
4. **Compruébalo contra un servidor** y mira que la clasificación es la que
   esperabas:

```bash
web-crypto-checker --config mi-politica.json --show-policy
web-crypto-checker --config mi-politica.json example.com
```

---

## Idiomas

La prosa traducible (etiquetas de categoría, descripciones de los niveles de
fuerza y el nombre/descripción/remediación de cada vulnerabilidad) se superpone
desde `data/i18n/algorithms.<idioma>.json`, casada por identificadores estables.
Un overlay ausente, roto o parcial cae en silencio al inglés; **los ids, los
códigos y los nombres de algoritmo no se traducen nunca**. El detalle está en
[`policy.py`](../../web_crypto_checker/policy.py).
</content>
