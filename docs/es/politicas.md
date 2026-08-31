# Manual del fichero de política — visión general

Volver al [manual](README.md) · relacionado: [cómo se calcula la nota](como-se-calcula-la-nota.md) ·
[puntuación y topes](politica-puntuacion.md) · [normativas](politica-normativas.md) ·
[English](../en/politicas.md).

El fichero de política es **el criterio de la herramienta escrito como datos**.
Qué versión de TLS es buena, qué cifrado es débil, qué vulnerabilidad existe,
cuánto pesa cada clase en la nota: todo eso se edita sin tocar Python.

La razón es práctica. Lo que hoy es seguro mañana puede no serlo, y actualizar el
criterio debe ser **editar un JSON**, no desplegar una versión nueva. Es el
principio de toda la herramienta: datos, no código.

---

## Dónde vive y cómo se carga

Hay **un** fichero de política, el que trae el paquete:
[`web_crypto_checker/data/algorithms.json`](../../web_crypto_checker/data/algorithms.json).
La herramienta lo localiza junto al propio paquete y lo carga en cada escaneo.
Para cambiar el criterio se **edita ese fichero**: no hay una opción `--config`
ni una variable de entorno que apunte a otro sitio, así que el criterio de una
instalación es el de su copia de `algorithms.json`.

El formato es **JSON**. El cargador no acepta TOML ni YAML: la política se lee
como JSON o no se lee.

### Idiomas: superposiciones de prosa

La prosa traducible (etiquetas de categoría, nombres y descripciones de las
bandas de fuerza, y el nombre, la descripción y la remediación de cada
vulnerabilidad) puede venir en otro idioma desde
[`web_crypto_checker/data/i18n/`](../../web_crypto_checker/data/i18n/), en un fichero
`algorithms.<idioma>.json`. `--lang` elige cuál se superpone, casando cada
entrada **por su identificador**. Solo se traduce la prosa: los identificadores,
los códigos de enumeración y los nombres de algoritmo nunca cambian, y una
superposición ausente, ilegible o parcial cae en silencio al inglés.

---

## Las cosas que hay dentro

| Clave | Qué define | Manual |
|---|---|---|
| `categories` | Qué significa cada categoría (`recommended`, `acceptable`, `weak`, `insecure`, `informational`, `unknown`) y cuántos puntos vale. | [`politica-puntuacion.md`](politica-puntuacion.md) |
| `scoring` | Pesos por clase (`class_weights`), escala de notas (`grades`) y **topes de nota** (`grade_caps`). | [`politica-puntuacion.md`](politica-puntuacion.md) |
| `protocols` | Cada versión de TLS/SSL y su categoría. | [`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md) |
| `cipher_tag_categories` | Cómo cada **etiqueta de forma** de una suite (`3des`, `cbc`, `rc4`, `aead`…) se traduce en una categoría. | [`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md) |
| `groups` | Los grupos de intercambio de claves (curvas, grupos de campo finito e híbridos post-cuánticos) y su categoría. | [`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md) |
| `signatures` | Los esquemas de firma y su categoría. | [`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md) |
| `security_strength` | Los bits de fuerza por algoritmo y las bandas de nivel (NIST SP 800-57). | [`politica-puntuacion.md`](politica-puntuacion.md) |
| `vulnerabilities` | Las vulnerabilidades conocidas y su árbol de detección. | (en este mismo fichero) |

Además: `schema_version` (empieza por `1.`) y `metadata` (el nombre, la versión,
la descripción y las referencias del fichero). Al lado, dos directorios: los
**perfiles** de conformidad en
[`data/profiles/`](../../web_crypto_checker/data/profiles/README.md) (ver
[`politica-normativas.md`](politica-normativas.md)) y las traducciones en
[`data/i18n/`](../../web_crypto_checker/data/i18n/).

---

## Las vulnerabilidades y su detección

Cada entrada de `vulnerabilities` lleva `id`, `name`, `severity`
(`critical`/`high`/`medium`/`low`/`info`), una descripción, la remediación y las
referencias. Lo que la hace detectable es su `detection`: un **árbol de
condiciones** que la herramienta evalúa contra lo que el servidor ofrece en la
red. Cada nodo es exactamente **una** de estas claves:

| Clave | Se cumple cuando |
|---|---|
| `protocol` | El servidor admite esa versión (p. ej. `{"protocol": "ssl2"}` → DROWN). |
| `cipher_tag` | Alguna suite ofrecida lleva esa etiqueta de forma (p. ej. `{"cipher_tag": "3des"}` → Sweet32). |
| `all` | Se cumplen todas las condiciones hijas. |
| `any` | Se cumple alguna. |
| `not` | No se cumple la condición hija. |

Así, BEAST es `{"all": [{"any": [{"protocol": "tls1_0"}, {"protocol": "tls1_1"}]}, {"cipher_tag": "cbc"}]}`:
CBC bajo TLS 1.0 o 1.1. Añadir una vulnerabilidad es añadir una entrada con su
árbol, no tocar el código.

---

## Cómo se comprueba lo que escribes

**El cargador es estricto a propósito.** Un fichero que no cuadra no se ejecuta a
medias; falla al cargar, con el motivo:

- **Una categoría inválida se rechaza.** Si un protocolo, grupo o firma declara
  una categoría que no existe, el mensaje dice cuál (`'x' is not a valid category`).
- **La escala de notas no puede estar vacía** (`policy has no grade scale`): sin
  escala no hay nota.
- **La severidad de una vulnerabilidad debe ser válida**, una de las cinco.
- **Cada nodo de detección necesita exactamente una** de `protocol`,
  `cipher_tag`, `all`, `any` o `not`; ni cero ni dos.
- Un **algoritmo que la política no conoce** no es un error: los servidores
  ofrecen nombres que nadie ha catalogado continuamente. Sale como *desconocido*,
  que es una respuesta, y no penaliza.

La forma de probar lo que editas es escanear con ello: si el fichero no cuadra,
el error salta al arrancar; si cuadra, el informe refleja ya el criterio nuevo.

```bash
web-crypto-checker example.com --format json -o prueba.json
```

---

## La regla que no conviene romper

**No inventes contenido.** Si añades una vulnerabilidad, pon la referencia real
(su CVE, su aviso). Si cambias una categoría, apóyala en un documento. Un fichero
de política con entradas inventadas produce informes que alguien va a creerse, y
el daño no lo paga quien lo escribió.
