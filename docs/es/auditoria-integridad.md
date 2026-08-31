# Auditoría de integridad — ¿todo lo que afirma la herramienta sale de un documento?

**Fecha:** 2026-08-28 · **Alcance:** 14 perfiles + política base
`algorithms.json` (categorías, fuerzas, vulnerabilidades, comprobaciones de
configuración y puntuación).

**Pregunta que responde:** ¿la herramienta dice que algo está «bien» o «mal» sin
un documento que lo respalde? Es decir, ¿nos hemos inventado algo?

## Método

Tres verificaciones independientes, cada una devolviendo **evidencia**
(fichero:clave → la sección exacta del documento que lo respalda, o «no
encontrado»), no un visto bueno:

1. **Los 14 perfiles** contra el documento que cada uno cita, cruzando lo que el
   perfil exige (protocolos, suites, grupos, firmas, requisitos de certificado,
   HSTS/OCSP) con la sección/tabla registrada en
   `estandares/CITATION_MAP.md` y con la ficha de
   procedencia (URL, fecha, SHA-256) de [`estandares/README.md`](../estandares/README.md).
2. **La clasificación de la política base** `algorithms.json` (protocolos,
   etiquetas de cifrado, grupos, firmas, tabla de fuerza) contra los documentos
   presentes en [`estandares/`](../estandares/README.md).
3. **Las vulnerabilidades y las comprobaciones de configuración** —¿cada una
   nombra su fuente (CVE, RFC, regla de guía)?

Los perfiles se agrupan por familia (las dos Mozilla, las dos NIST, las tres CIS
de servidor web, etc.), como el propio catálogo.

## Veredicto en una frase

**No hay listas inventadas.** Los 14 perfiles trazan a un documento **archivado
y con huella SHA-256** en `estandares/`, y cada regla remite a una sección o
tabla concreta. **No se encontró ningún error de comportamiento** en esta
auditoría. El único hueco real es menor y honesto: **tres de las diez
vulnerabilidades** (`NULL-CIPHER`, `ANON-CIPHER`, `DES`) tienen su lista
`references` **vacía**. Y la **puntuación** —pesos, escala de letras, topes— es
metodología propia, ya declarada como tal.

---

## 1. Perfiles (14) — trazan a su documento

Los 14 perfiles son `algorithm-strength` salvo `iso-27002-8-24`, que es
`policy-conformance`. **Todos** citan un documento que está **físicamente
presente** en `estandares/`, con su SHA-256 registrado; no hay ningún perfil
apoyado en un documento ausente. Lo comprobado, familia a familia:

### Mozilla (2/2) — VERIFICADO
`mozilla-modern` y `mozilla-intermediate` salen de
`mozilla-server-side-tls-5.7.json` (la guía legible por máquina, archivada).
- `mozilla-modern`: `protocols.allow=[tls1_3]` y las **tres** suites TLS 1.3
  coinciden con `configurations.modern` (que es TLS 1.3 puro en 5.7);
  `min_ec_bits=256` sale de `certificate_curves`/`ecdh_param_size`. El propio
  `notes` documenta la corrección respecto a la versión pre-5.0 («Modern»
  permitía TLS 1.2 y RSA) y **declara** que 5.7 es solo-ECDSA y que el esquema
  no puede expresar «certificado RSA prohibido», por lo que no afirma
  `min_rsa_bits`. Es un límite de esquema declarado, no una invención.
- `mozilla-intermediate`: 12 suites AEAD/PFS, `min_rsa_bits=2048`,
  `min_ec_bits=256`, sin CBC — exactamente la lista `ciphers.iana` de 5.7.

### NIST (2/2) — VERIFICADO
- `nist-sp-800-52r2` (de `NIST.SP.800-52r2.pdf`): prohíbe ssl3/tls1_0/tls1_1 y
  las etiquetas rc4/3des/des/export/null/anon/md5; `minimum_security_strength=112`.
  **Matiz de cita declarado:** la prohibición de TLS 1.1 se apoya en un
  *should-not* (§3.1, audiencia gubernamental), no en un *shall-not*.
- `nist-sp-800-131a` (de `NIST.SP.800-131Ar2.pdf`): mismas etiquetas prohibidas,
  strength 112, firmas SHA-1/MD5 prohibidas (Tabla 8). No fija versión de TLS,
  porque el documento gobierna algoritmos, no versiones — declarado.

### FIPS 140-3 (1/1) — VERIFICADO
`fips-140-3` codifica 28 suites AES no anónimas, grupos P-curve + ffdhe, y firmas
RSA/ECDSA/EdDSA, cada una trazada a su fuente archivada (SP 800-38D para GCM, SP
800-56Ar3 Tablas 24/26 para grupos, FIPS 186-5 para firmas). ChaCha20 y x25519/x448
se excluyen **porque no tienen aprobación NIST** — verificable en los documentos
presentes. El `notes` declara la limitación de fondo: FIPS 140-3 valida un
*módulo*, no solo nombres de algoritmo; un PASS es necesario, no suficiente.

### CNSA 1.0 (1/1) — VERIFICADO
`cnsa-1.0` sale de la Tabla V de `CSA_CNSA_2.0_ALGORITHMS.pdf`: AES-256-GCM-SHA384,
P-384, DH ≥ 3072, RSA ≥ 3072, strength 192. La lectura solo-SHA-384/solo-P-384 es
literal («Use … for all classification levels»). No restringe la versión de TLS
—declarado— porque CNSA es una suite de algoritmos.

### BSI (1/1) — VERIFICADO
`bsi-tr-02102-2` (de `BSI-TR-02102-2-en.pdf`, edición 2026-01): tls1_2/tls1_3, 39
suites de las Tablas 3+4+13, grupos NIST+Brainpool+ffdhe3072/4096, firmas RSA-PSS
y ECDSA (Tabla 11), strength 120 (§3.1.2). Sin ChaCha20 en ninguna tabla — la
lista lo excluye, y el `notes` lo contrasta con ENS, que sí lo autoriza.

### ANSSI (1/1) — VERIFICADO
`anssi` (de `anssi-guide-mecanismes-crypto-3.00.pdf`, PG-083 v3.00) está codificado
**por mecanismo**, no por lista de suites, porque el documento no publica ninguna.
Las prohibiciones (3des por bloque de 64 bits, rc4/des/export por tamaño de clave,
sha1/md5 por RègleHachage) trazan a sus reglas numeradas. **Dos ausencias son
declaradas, no huecos:** no fija versión de TLS ni allowlist de suites (PG-083 no
es específico de TLS), y **no fija `minimum_security_strength`** porque §1.5 dice
que el documento «ne comporte volontairement aucune table récapitulative des
tailles minimales». Sintetizar una cifra sería nuestro, y por eso no se hace.

### ENS (1/1) — VERIFICADO
`ens` sale de CCN-STIC-807 (Mayo 2022) más `boe-ens-rd-311-2022-consolidado.pdf`
como base legal, ambos archivados. TLS 1.2/1.3 (¶61), las 8 suites R de Tabla 4-1
+ las 5 de Tabla 4-2, RSA ≥ 3000 (Tabla 3-2 R), strength 128, sin SHA-1 salvo
HMAC (¶25). Las filas Legacy se omiten porque su ventana de validez venció en 2025
(§3 ¶10) — trazado. **Matiz declarado:** el suelo RSA «n ≥ 3000» de CCN queda
milimétricamente por debajo del umbral 3072→128 bits que usa `strength.py`, así
que una clave RSA hipotética de 3000–3071 bits (que no se usa en la práctica)
podría pasar `min_rsa_bits` y aun así tropezar con la puerta de fuerza. Las claves
reales de 3072 bits satisfacen ambas.

### PCI DSS 4 (1/1) — VERIFICADO
`pci-dss-4` (de `PCI-DSS-v4_0_1.pdf`): strength 112 (Apéndice G «Strong
Cryptography»), prohíbe ssl3/tls1_0/tls1_1 y las etiquetas débiles.
**Matiz declarado:** TLS 1.1 no lo nombra PCI explícitamente; se deriva de la
cláusula «insecure versions» de Req 4.2.1 + RFC 8996. **Procedencia:** el PDF es
una copia de referencia interna **no redistribuible** (estándar de pago); está
presente y con huella para auditar en local, pero no viaja en la distribución.

### ISO/IEC 27002:2022 §8.24 (1/1) — VERIFICADO
`iso-27002-8-24` es el único `policy-conformance`: como el control 8.24 no nombra
ningún algoritmo, el perfil mide contra las categorías de **la propia política**
(prohíbe lo `weak`/`insecure` local), y así lo dice su `summary`. Se apoya en
`ISO_27002_2022.pdf` (presente). **Aviso honesto ya registrado:** el
`iso-27001.pdf` archivado es la **edición 2005** (su Anexo A usa A.12.3, sin 8.24);
por eso la cita es a 27002:2022, que es la copia que **sí** se tiene. Como PCI,
ISO/IEC es de pago: copia interna no redistribuible.

### CIS de servidor web (3/3) — VERIFICADO
Las tres salen de sus benchmarks CIS archivados en `estandares/cis/`
(CC BY-NC-SA, redistribuibles con atribución):
- `cis-nginx` (v3.0.0): solo tls1_3 (Rec. 4.1.4), etiquetas débiles prohibidas
  (Rec. 4.1.5), OCSP stapling exigido (4.1.7), HSTS `min_age=31536000` (4.1.8).
- `cis-apache-2.4` (v2.3.0): tls1_2/tls1_3 (Rec. 7.4), prohíbe export/null/des/
  rc4/anon (7.5), **3des** (7.8) y **no-forward-secrecy** (7.12), OCSP (7.10),
  HSTS `min_age=480` (7.11 L2).
- `cis-iis-10` (v1.2.1): prohíbe ssl3/tls1_0/tls1_1 (Rec. 7.3/7.4/7.5), null/des/
  rc4 (7.7/7.8/7.9), HSTS `min_age=1` (7.1 L2). **Declarado:** usa *disallow* (no
  allowlist) de protocolos porque esta edición no tiene regla de TLS 1.3, así que
  no debe penalizar a un servidor que además lo ofrezca; y no exige OCSP porque la
  v1.2.1 no tiene esa recomendación.

**Sin huecos de documento.** A diferencia de otros catálogos, aquí **ningún**
perfil invoca un documento ausente: los 14 tienen su fuente archivada y con
SHA-256 en `estandares/`. Las únicas salvedades de procedencia son de
**redistribución**, no de ausencia: PCI DSS e ISO/IEC son de pago y se guardan
como copia de referencia interna (presentes, auditables en local, no empaquetadas).

---

## 2. Política base `algorithms.json`

### Lo que está bien anclado
- **Protocolos:** TLS 1.0/1.1 *weak* citan RFC 8996 en su `note`; SSL 3.0
  *insecure* cita POODLE; SSL 2.0 *insecure* cita DROWN. Trazable.
- **Grupos y firmas:** las curvas/grupos y esquemas de firma recomendados/
  aceptables/débiles/inseguros coinciden con las tablas de NIST, BSI y FIPS que
  **sí están archivadas** (P-curves, ffdhe, RSA-PSS vs PKCS#1, SHA-1 inseguro).
- **Tabla de fuerza** (`security_strength`): los umbrales RSA
  `[1024,80] [2048,112] [3072,128] [7680,192] [15360,256]` son los de NIST SP
  800-57 Part 1 Rev. 5, **presente** (`NIST.SP.800-57pt1r5.pdf`), citado en el
  propio bloque.

### El punto blando: la clasificación de suites por etiqueta (juicio correcto, ancla pública)
El equivalente web del «agujero» clásico de estos auditores es
`cipher_tag_categories`: el mapa etiqueta→categoría (`rc4`/`des`/`md5`
inseguras, `3des`/`sha1` débiles, `cbc`/`no-forward-secrecy` aceptables, `aead`
recomendada). Los veredictos son correctos, pero **no salen de un único documento
archivado**: el bloque `metadata` los ancla a Mozilla Server Side TLS (archivado),
NIST SP 800-52r2 (archivado) e **IETF BCP 195 / RFC 9325** (referencia pública, no
archivada — igual criterio que los CVE). Además, cada etiqueta débil/insegura está
respaldada de rebote por su vulnerabilidad (RC4, Sweet32, FREAK/Logjam), así que
no hay veredicto huérfano; lo que falta en local es solo el RFC 9325.

### Vulnerabilidades (10) — 7 con CVE, **3 con `references` vacía**
Aquí está el único hallazgo real de esta auditoría. De las diez entradas de la
lista `vulnerabilities`:

| id | `references` |
|---|---|
| `CVE-2016-0800` (DROWN) | `["CVE-2016-0800"]` ✅ |
| `CVE-2014-3566` (POODLE) | `["CVE-2014-3566"]` ✅ |
| `SWEET32` | `["CVE-2016-2183"]` ✅ |
| `RC4` | `["CVE-2013-2566","CVE-2015-2808"]` ✅ |
| `FREAK-LOGJAM` | `["CVE-2015-0204","CVE-2015-4000"]` ✅ |
| `CVE-2011-3389` (BEAST) | `["CVE-2011-3389"]` ✅ |
| `NO-FORWARD-SECRECY` | `["CVE-2017-13099"]` ✅ |
| **`NULL-CIPHER`** | **`[]`** ⚠️ |
| **`ANON-CIPHER`** | **`[]`** ⚠️ |
| **`DES`** | **`[]`** ⚠️ |

Las tres sin referencia son «definicionales» (NULL = sin cifrado, ANON = sin
autenticación, DES = clave de 56 bits forzable), no fenómenos con CVE; su verdad
es evidente. Pero el propio manual de vulnerabilidades dice «**sin referencia es
una opinión**», así que, por sus propias reglas, **estas tres deberían citar su
fuente** (p. ej. RFC 8996/RFC 7568 para el marco de retirada, o el catálogo de
suites nulas/anónimas). Es un hueco menor y acotado, no un veredicto inventado.

### Comprobaciones de configuración (HTTP / comportamiento TLS / certificado) — código, no datos
Estas comprobaciones **no** son JSON: viven en el código (`http_layer.py`,
`assessment.py`, `pki/certificates.py`, `mixed_content.py`,
`subresource_integrity.py`) y su severidad va **fija en el código**, no en un campo
`expect` configurable. Su procedencia sí está documentada, pero en la **prosa** de
[`politica-configuracion.md`](politica-configuracion.md) y en comentarios del
código (RFC 5280, 4055, 8410, 6698, 8659, 7838, 2606; RFC 5746 para renegociación
segura; RFC 6265bis para el contrato de cookies; CVE-2017-15361 para ROCA), no
como un campo `reference` legible por máquina como el que sí llevan las
vulnerabilidades. Honestamente: **la existencia** de cada comprobación mapea a un
estándar público o a un comportamiento de navegador; **la severidad** de cada una
es criterio de la herramienta.

### Metodología propia — ya declarada
No sale de ningún documento —y no debería, es diseño legítimo—:
- `scoring`: los pesos por clase (`protocol` 3, `cipher` 3, `certificate` 3,
  `group` 2, `signature` 1), la escala de letras (A+…F, con E) y los topes
  (`grade_caps`).
- `categories`: los `score` 100/80/40/0.
- `security_strength.levels`: los **umbrales** en bits sí son de NIST, pero los
  **nombres** (broken/legacy/transitional/acceptable/strong/top) son presentación
  propia.

Ya está declarado: [`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md) abre
con «De dónde salen estos números (y de dónde no)», que separa el respaldo
documental de las categorías del criterio propio de la puntuación.

---

## 3. Acciones — estado

Esta auditoría **documenta**; no modifica datos ni código (el propietario decide
los cambios). Estado real de cada frente:

**Sin acción necesaria (ya correcto):**
- [x] **Los 14 perfiles trazan a un documento archivado** con SHA-256 en
  `estandares/`. Ninguno cita un documento ausente.
- [x] **No hay error de comportamiento** que corregir: cada perfil coincide con
  la sección/tabla citada, y las salvedades (TLS 1.1 en NIST-52r2/PCI, el suelo
  RSA de ENS, las ausencias de ANSSI, el *disallow* de CIS-IIS) están **declaradas
  en el propio `notes` del perfil**, no ocultas.
- [x] **La puntuación queda declarada como metodología propia** (sección en
  `como-se-calcula-la-nota.md` y comentarios `_comment_*` en `algorithms.json`).
- [x] **CVE y RFC públicos:** las 7 vulnerabilidades con CVE y las comprobaciones
  de configuración se apoyan en referencias públicas verificables (NVD/MITRE,
  RFC); por política de procedencia se **citan, no se archivan**.

**Recomendaciones abiertas (hallazgos de esta auditoría):**
- [ ] **Rellenar `references` en `NULL-CIPHER`, `ANON-CIPHER` y `DES`.** Hoy están
  vacías; por la regla «sin referencia es una opinión» del propio manual, deberían
  citar su fuente pública.
- [ ] **(Opcional) Archivar o citar formalmente RFC 9325 (BCP 195)** para anclar
  del todo `cipher_tag_categories`, hoy sostenida por Mozilla + NIST SP 800-52r2
  (archivados) más ese RFC público.
- [ ] **(Opcional) Considerar un campo `reference` legible por máquina** en las
  comprobaciones de configuración, como el que ya llevan las vulnerabilidades, en
  vez de dejar la procedencia solo en la prosa y los comentarios del código.

---

## Conclusión

La herramienta **no se inventa nada**: los 14 perfiles trazan a un documento
**presente y con huella** en `estandares/`, cada regla remite a su sección o tabla
exacta, y **no se halló ningún error de comportamiento**. Las salvedades de cita
(TLS 1.1, el suelo RSA de ENS, las ausencias deliberadas de ANSSI) están
declaradas en los propios perfiles, no encubiertas. El único hueco real es menor:
tres de las diez vulnerabilidades (`NULL-CIPHER`, `ANON-CIPHER`, `DES`) tienen su
lista `references` vacía y deberían citar su fuente. La clasificación de suites por
etiqueta y las comprobaciones de configuración descansan en referencias
**públicas** (RFC 9325, RFCs de la capa HTTP/TLS, CVE) que —por decisión de
procedencia— se citan, no se archivan. Y la puntuación, que es criterio propio,
ya está declarada como tal.
