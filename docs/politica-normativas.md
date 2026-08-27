# Política de conformidad: los perfiles

Volver al [manual](../README.md) · relacionado: [plugins](plugins.md) ·
[procedencia de los documentos](estandares/README.md) · [English](en/politica-normativas.md).

Una normativa no es código de esta herramienta: es un documento que mantiene otra
gente y revisa en su propio calendario. Por eso **cada normativa es un directorio**
bajo
[`web_crypto_checker/data/profiles/`](../web_crypto_checker/data/profiles/README.md)
y **cada fichero dentro es una edición**; se **evalúa**, no se compila. Añadir la
edición del año que viene es añadir un fichero; la del año pasado se queda y se
sigue pudiendo medir contra ella. Con más de una edición, exactamente una lleva
`"current": true`; el cargador se niega si ninguna o varias lo hacen.

## Cómo se evalúa

Se seleccionan con `--profile <id>` (la edición **en vigor**) o con
`--profile <id>@<edición>` para una edición concreta (repetible), y se listan con
`--list-profiles`. El identificador de la normativa es el nombre del directorio; el
de la edición, el nombre de su fichero sin `.json`.

```bash
web-crypto-checker example.com --profile mozilla-intermediate --profile pci-dss-4
web-crypto-checker --list-profiles
```

Un perfil produce, por endpoint, uno de tres resultados:

- **PASS** — todo lo que el perfil exige era comprobable y se cumplió.
- **FAIL** — hay al menos una infracción (es una prueba y zanja la cuestión).
- **NO EVALUADO** — sin infracciones, pero alguna exigencia **no se pudo
  comprobar** (el escaneo no vio lo suficiente). No es un aprobado: una
  comprobación que no se pudo ejecutar no se ha superado, se ha omitido, y
  reportar las dos igual sería certificar un servidor que no se llegó a entender.

## Qué puede exigir un perfil

Un fichero de perfil es JSON con estas secciones (todas opcionales):

| Clave | Significado |
|---|---|
| `name`, `authority`, `edition`, `reference`, `url`, `summary`, `notes` | Metadatos y la **cita** exacta del documento. |
| `kind` | `algorithm-strength` (por defecto: medir lo que ofrece el servidor contra las reglas del documento) o `policy-conformance` (medir contra las categorías de la política propia, para un documento que no nombra algoritmos). |
| `protocols.allow` / `protocols.disallow` | Versiones de TLS permitidas o prohibidas. |
| `cipher_tags.disallow` | Formas de suite prohibidas por **etiqueta** (p. ej. `rc4`, `3des`, `cbc`). |
| `cipher_suites.allow` | **Lista blanca** de suites IANA exactas (para un documento que publica su tabla de suites autorizadas: BSI, CCN-STIC-807, CNSA, FIPS). |
| `groups.allow` / `groups.disallow` | Grupos de intercambio de claves. |
| `signature_algorithms.allow` / `.disallow` | Esquemas de firma. |
| `certificate.min_rsa_bits` / `min_ec_bits` / `disallow_sha1` | Fuerza mínima de clave y firma del certificado. |
| `minimum_security_strength` | Fuerza de seguridad efectiva mínima en bits (NIST SP 800-57). `null` cuando el documento no publica una cifra (ANSSI, a propósito). |
| `hsts.require` / `hsts.min_age` | Exigir HSTS (y un `max-age` mínimo). |
| `ocsp_stapling.require` | Exigir que el servidor **grape** OCSP. |
| `forbid_local_categories` | Para `policy-conformance`: las categorías locales (`weak`, `insecure`) que cualquier algoritmo ofrecido no debe tener. |

**Etiquetas frente a listas blancas.** Un documento que publica una tabla de
suites autorizadas se codifica con `cipher_suites.allow` (nombres IANA exactos),
porque una etiqueta no distingue AES de ChaCha20 y estos documentos giran
justamente sobre eso (BSI y FIPS excluyen ChaCha20; ENS lo autoriza). Un documento
que prohíbe *formas* débiles se codifica con `cipher_tags.disallow`. Ambos
mecanismos existen y cada perfil usa el que su documento realmente es.

## Cita de las fuentes

**Cada regla se remite a una sección o tabla exactas de un documento real**,
citadas en `reference`/`notes`. Los documentos fuente (URL, fecha y SHA-256, y
qué perfil alimenta cada uno) están en
[`docs/estandares/`](estandares/README.md). No todos permiten redistribuirse
(PCI DSS e ISO/IEC son de pago; NIST es de dominio público; CIS es
CC BY-NC-SA), así que se **citan** y se obtienen de su editor. La tabla completa
de perfiles está en el
[README de `data/profiles/`](../web_crypto_checker/data/profiles/README.md).

## Escribir el tuyo

Crea un directorio `data/profiles/<id>/` con un fichero `<edición>.json` dentro
(copiando el perfil más parecido), ajusta las claves y cita la fuente en
`reference`/`notes`. El nombre del directorio es el identificador de la normativa;
el del fichero, la edición (letras minúsculas, dígitos, puntos y guiones). Con una
sola edición es la que rige; con varias, marca una con `"current": true`. Como
todo lo demás en esta herramienta: **datos, no código**.
