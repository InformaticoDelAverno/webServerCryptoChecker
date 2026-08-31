# Manual de política — vulnerabilidades

Volver al [manual](README.md) · relacionado:
[algoritmos](politica-algoritmos.md) · [configuración](politica-configuracion.md) ·
[normativas](politica-normativas.md) · [English](../en/politica-vulnerabilidades.md).

Una vulnerabilidad conocida se escribe entera como un dato en la lista
`vulnerabilities` de
[`algorithms.json`](../../web_crypto_checker/data/algorithms.json). No hace falta
programar: [`vulnerabilities.py`](../../web_crypto_checker/vulnerabilities.py) solo
evalúa el árbol de condiciones que ya está en el fichero. Por eso es el sitio
donde debe ir todo lo que se pueda detectar **de lo que un servidor ofrece en el
cable**.

---

## La forma de una entrada

```json
{
  "id": "SWEET32",
  "name": "Sweet32 (64-bit block cipher)",
  "severity": "medium",
  "description": "Qué pasa y por qué importa, para quien no lo conoce.",
  "remediation": "Qué hacer exactamente. Un mandato, no un consejo.",
  "references": ["CVE-2016-2183"],
  "detection": { "cipher_tag": "3des" }
}
```

| Campo | Obligatorio | Notas |
|---|---|---|
| `id` | **sí** | El título estable en el informe y la clave de traducción. |
| `name` | **sí** | Nombre legible. |
| `severity` | **sí** | `critical`, `high`, `medium`, `low`, `info`. Se valida al cargar. |
| `description` | sí en la práctica | Escríbela para quien la lee a las dos de la mañana. |
| `remediation` | sí en la práctica | Sin esto, es una queja. |
| `references` | sí en la práctica | **Sin referencia es una opinión.** |
| `detection` | **sí** | La condición. Todo lo demás de este manual. |

---

## La gramática de detección

Una condición es un objeto con **exactamente una** clave. Hay dos condiciones que
miran algo y tres que combinan otras.
[`_validate_detection`](../../web_crypto_checker/policy.py) recorre el árbol **al
cargar** la política: un nodo con cero o dos claves, o una combinación mal
escrita, da un error con el id de la vulnerabilidad en vez de una regla que no
casa nunca y nadie nota.

### `protocol` — una versión está soportada

```json
"detection": { "protocol": "ssl2" }
```

Casa si el servidor **soporta** esa versión. El identificador es el mismo que en
la clase `protocols` (`ssl2`, `ssl3`, `tls1_0`, `tls1_1`, `tls1_2`, `tls1_3`).
Así se detectan DROWN (`ssl2`) y POODLE (`ssl3`): la presencia de una versión
rota es la vulnerabilidad, y ninguna configuración de suites la arregla.

### `cipher_tag` — una suite ofrecida lleva una etiqueta

```json
"detection": { "cipher_tag": "3des" }
```

Casa si **alguna** de las suites que el servidor ofrece lleva esa etiqueta de
forma. Las etiquetas son las mismas que clasifican las suites, derivadas del
nombre por [`cipher_suite_tags`](../../web_crypto_checker/tls/constants.py) —ver
[`politica-algoritmos.md`](politica-algoritmos.md).

> **Detectar por etiqueta es lo que hace que la regla no envejezca.** `{"cipher_tag":
> "cbc"}` sigue valiendo cuando aparezca una suite CBC que hoy no existe; una
> lista de nombres, no. Es también lo que deja la evidencia lista: el informe
> nombra las suites concretas que dispararon el hallazgo.

### `all`, `any`, `not` — para combinar

```json
"detection": {
  "all": [
    { "any": [ {"protocol": "tls1_0"}, {"protocol": "tls1_1"} ] },
    { "cipher_tag": "cbc" }
  ]
}
```

Eso es BEAST de verdad: una versión antigua (**TLS 1.0 o 1.1**) **y** una suite
CBC. `all` casa si todas sus ramas casan; `any`, si alguna; `not`, si su rama no
casa. Se anidan sin límite. La evidencia de un `all`/`any` es la unión de lo que
casó por debajo.

---

## Todo se observa en el cable

Las diez entradas se detectan de una sola forma: **mirando lo que el servidor
ofrece de verdad**. No hay detección por versión del producto ni deducción a
partir de un *banner*, así que no hay margen de error ni advertencia de
retroportado que dar. [`evaluate`](../../web_crypto_checker/vulnerabilities.py)
construye el conjunto de protocolos soportados y las etiquetas de cada suite
ofrecida, y evalúa cada árbol contra ellos.

| id | Detección |
|---|---|
| `CVE-2016-0800` — DROWN | `protocol: ssl2` |
| `CVE-2014-3566` — POODLE | `protocol: ssl3` |
| `SWEET32` — bloque de 64 bits | `cipher_tag: 3des` |
| `RC4` — sesgo del *keystream* | `cipher_tag: rc4` |
| `FREAK-LOGJAM` — exportación | `cipher_tag: export` |
| `NULL-CIPHER` — sin cifrado | `cipher_tag: null` |
| `ANON-CIPHER` — sin autenticación | `cipher_tag: anon` |
| `DES` — DES simple | `cipher_tag: des` |
| `CVE-2011-3389` — BEAST | `all[ any[tls1_0, tls1_1], cbc ]` |
| `NO-FORWARD-SECRECY` — sin PFS | `cipher_tag: no-forward-secrecy` |

### Lo que se detecta aquí y lo que se detecta en otra parte

Esta lista cubre lo **pasivo**: lo que se ve sin más que negociar. Tres detecciones
relacionadas viven fuera, a propósito, porque no son un árbol de condiciones:

- **DROWN / SSL 2.0.** El ClientHello de SSL 2.0 tiene otro formato, así que no
  es un registro TLS: se prueba aparte y se expone como el protocolo `ssl2`, que
  es lo que casa la condición de arriba. Que además ofrezca cifrados de
  exportación (lo que hace DROWN práctico, no solo posible) es un hallazgo propio,
  `SSLV2-EXPORT-CIPHERS`.
- **ROBOT / Bleichenbacher.** La superficie está aquí, marcada de forma pasiva:
  una suite sin forward secrecy usa RSA estático, que es justo el oráculo de
  relleno de ROBOT. Confirmar un oráculo **vivo** es una sonda activa aparte
  ([`tls/robot.py`](../../web_crypto_checker/tls/robot.py), tras `--active`), como
  Heartbleed o CCS injection.
- El resto de comprobaciones de comportamiento de TLS (renegociación, compresión
  CRIME, downgrade…) son hallazgos, no vulnerabilidades de esta lista; están en
  [`politica-configuracion.md`](politica-configuracion.md).

> **No mirar no es lo mismo que mirar y no encontrar nada.** Una detección que
> necesita `--active` no se evalúa a «no vulnerable» en silencio si no se pidió:
> la sonda activa sencillamente no corrió, y el informe lo dice. Informar de un
> servidor como no afectado porque nadie hizo la pregunta es el único modo de
> fallo que este módulo no puede tener.

---

## De la detección al informe

Cuando un árbol casa, [`evaluate`](../../web_crypto_checker/vulnerabilities.py)
produce un `VulnerabilityMatch` con el id, el nombre, la severidad, la
descripción, la remediación, las referencias y la **evidencia**: la lista
ordenada de protocolos y suites concretos que dispararon la regla. La severidad
es lo que pesa la vulnerabilidad —no hay modificadores ni topes especiales por
CVE—, y las diez conviven con los hallazgos de certificado, de comportamiento y
de capa HTTP en el mismo informe.

La nota **no** la mueven directamente estas entradas: el techo lo ponen las
clases de algoritmo y los topes con nombre (`any_insecure_offered`,
`sslv2_supported`, `sslv3_supported`, `weak_protocol_supported`…), que en la
práctica cubren lo mismo —una suite RC4 es `insecure` y dispara DROWN a la vez.
Ver [`politica-algoritmos.md`](politica-algoritmos.md).

---

## Escribir una nueva, paso a paso

1. **Busca la referencia primero.** El CVE, el aviso, el commit. Si no la
   encuentras, no la escribas.
2. **Decide qué la detecta de verdad, y que sea observable en el cable.** ¿Es una
   versión soportada? ¿Es una etiqueta de una suite ofrecida? ¿Las dos? Escribe
   la condición más estrecha que sea correcta.
3. **Prefiere `cipher_tag` a nombres.** Si la etiqueta que necesitas no existe
   todavía, se añade en
   [`cipher_suite_tags`](../../web_crypto_checker/tls/constants.py), no en esta
   lista: así la clasificación y la detección comparten la misma verdad.
4. **Escribe `remediation` como una orden.** «Desactiva las suites 3DES», no
   «considere revisar».
5. **Pruébala en los dos sentidos**: que salta en un servidor con el defecto y que
   **no** salta en uno moderno.

```bash
web-crypto-checker --config mi-politica.json ejemplo-vulnerable.test
web-crypto-checker --config mi-politica.json example.com   # no debe aparecer
```

---

## Los tres errores que se cometen

**Detectar por nombre lo que se debería detectar por propiedad.** Si escribes la
lista de las suites CBC que conoces hoy, tu regla envejece. Usa `cipher_tag`.

**Meter aquí lo que necesita una sonda activa.** Esta gramática solo ve lo que se
ofrece. Un oráculo vivo, Heartbleed o CCS injection se confirman con `--active`,
no con un `cipher_tag`.

**Olvidar la remediación.** Un informe con diez hallazgos y ninguna instrucción
no cambia nada en ningún servidor.
</content>
