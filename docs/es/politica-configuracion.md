# Manual de política — comprobaciones de configuración

Volver al [manual](README.md) · relacionado:
[algoritmos](politica-algoritmos.md) ·
[vulnerabilidades](politica-vulnerabilidades.md) · [normativas](politica-normativas.md) ·
[English](../en/politica-configuracion.md).

Estas comprobaciones miran **cómo está montado el servicio**, no qué algoritmos
ofrece: qué le dice la web al navegador sobre su propia seguridad, cómo se comporta
el TLS más allá de la lista de suites, y qué dice el certificado aparte de la
fuerza de su clave. Son el equivalente web de lo que en otros auditores serían las
directivas de configuración de un demonio.

> **Aquí no hay un fichero de configuración que auditar.** No hay un volcado de la
> configuración efectiva del servidor que leer, y la herramienta no se autentica en
> la máquina ni inspecciona sus ficheros. Todo lo de este manual se observa **desde
> fuera**, en la
> misma conexión del escaneo. Y por eso, a diferencia de la política de algoritmos
> o de vulnerabilidades, **estas comprobaciones son código, no datos JSON**: viven
> en [`http_layer.py`](../../web_crypto_checker/http_layer.py),
> [`assessment.py`](../../web_crypto_checker/assessment.py),
> [`pki/certificates.py`](../../web_crypto_checker/pki/certificates.py),
> [`mixed_content.py`](../../web_crypto_checker/mixed_content.py) y
> [`subresource_integrity.py`](../../web_crypto_checker/subresource_integrity.py).
> Añadir una es editar una de estas funciones, no una lista.

---

## La forma de un hallazgo

Todas producen el mismo objeto, un `Finding` con id, severidad, título,
descripción, remediación y, cuando aplica, los `items` concretos (las cookies, las
URLs, los orígenes) que lo dispararon:

```python
Finding(
    "HTTP-NO-HSTS",
    Severity.MEDIUM,
    t("find.http_no_hsts.title"),
    t("find.http_no_hsts.desc"),
    remediation=t("find.http_no_hsts.rem"),
)
```

La severidad va **fija en el código** (no hay una expectativa configurable como
`expect`), y la prosa se traduce por su clave de mensaje. La condición que decide
si el hallazgo se produce es Python, no un comparador de la política.

---

## La capa HTTP

Sobre una conexión HTTPS establecida, la herramienta pide **un** `GET`, lee las
cabeceras de la respuesta y un trozo acotado del cuerpo, y de ahí saca lo que la
web le cuenta a un navegador. Vive en
[`http_layer.py`](../../web_crypto_checker/http_layer.py).

### HSTS (`Strict-Transport-Security`)

| id | Severidad | Cuándo |
|---|---|---|
| `HTTP-NO-HSTS` | media | No hay cabecera HSTS. |
| `HTTP-WEAK-HSTS` | baja | `max-age` por debajo de 180 días. |
| `HTTP-HSTS-NO-SUBDOMAINS` | baja | HSTS sin `includeSubDomains`. |
| `HTTP-HSTS-PRELOAD-INELIGIBLE` | baja | Pide `preload` pero no cumple sus requisitos (un año de `max-age` **e** `includeSubDomains`). |

### Redirección del puerto 80

`HTTP-NO-HTTPS-REDIRECT` (media) salta cuando el puerto 80 sirve HTTP en claro o
redirige a otra URL `http://` sin subir a HTTPS. La primera visita sin caché de un
navegador llega en claro; si nadie la rebota a `https://`, esa petición viaja
expuesta. Solo se juzga en un objetivo HTTPS estándar (443).

### `Content-Security-Policy`, analizada

La CSP no solo se registra: se **analiza** (`_csp_findings`). Sobre las fuentes que
gobiernan los scripts (`script-src`, o `default-src` como respaldo):

| id | Severidad | Cuándo |
|---|---|---|
| `HTTP-CSP-UNSAFE-INLINE` | media | `'unsafe-inline'` sin un nonce, hash o `'strict-dynamic'` que lo neutralice. |
| `HTTP-CSP-UNSAFE-EVAL` | baja | `'unsafe-eval'`. |
| `HTTP-CSP-BROAD-SCRIPT-SRC` | media | Una fuente comodín (`*`, `http:`, `https:`, `data:`). |

### Otras cabeceras de seguridad

`x-content-type-options`, `x-frame-options` y `referrer-policy` se comprueban por
ausencia (hallazgos `HTTP-NO-XCTO`, `HTTP-NO-XFO`, `HTTP-NO-REFERRER-POLICY`, todos
bajos, definidos como datos en `_MISSING_HEADER_FINDINGS`) y también por presencia
inútil:

- `HTTP-XCTO-INEFFECTIVE` (baja): la cabecera está pero su valor no es `nosniff`.
- `HTTP-XFO-INEFFECTIVE` (baja): el valor no es `DENY` ni `SAMEORIGIN` —**y** la CSP
  no lleva `frame-ancestors`, que cubriría el *clickjacking* de todas formas.

### Cookies

De cada `Set-Cookie`:

| id | Severidad | Cuándo |
|---|---|---|
| `HTTP-INSECURE-COOKIE` | media | Sin `Secure`. |
| `HTTP-COOKIE-NO-HTTPONLY` | baja | Sin `HttpOnly`. |
| `HTTP-COOKIE-WEAK-SAMESITE` | baja | Sin `SameSite`, o `SameSite=None` sin `Secure`. |
| `HTTP-COOKIE-PREFIX-INVALID` | media | Incumple el contrato de su prefijo `__Secure-`/`__Host-` (RFC 6265bis). |

### CORS

Se manda un `Origin` que ningún sitio real usaría (`…​.invalid`) para ver cómo
responde. Si el servidor lo refleja en `Access-Control-Allow-Origin`:

- `HTTP-CORS-CREDENTIALED` (alta): refleja el origen **y** permite credenciales —el
  peor caso.
- `HTTP-CORS-OPEN` (baja): refleja cualquier origen, o responde `*`, sin
  credenciales.

### Contenido mixto y Subresource Integrity

Del cuerpo de la página (acotado), dos escáneres de HTML con la biblioteca estándar:

- **Contenido mixto** ([`mixed_content.py`](../../web_crypto_checker/mixed_content.py)):
  un subrecurso `http://` explícito en una página HTTPS. `HTTP-MIXED-ACTIVE` (alta)
  para lo que ejecuta código —`<script>`, hoja de estilo, `<iframe>`, `<object>`,
  `action` de un formulario—, que el navegador **bloquea**; `HTTP-MIXED-PASSIVE`
  (baja) para imagen, audio o vídeo, que **avisa**. Una URL relativa o
  protocol-relative hereda el `https` de la página y no cuenta.
- **SRI** ([`subresource_integrity.py`](../../web_crypto_checker/subresource_integrity.py)):
  `HTTP-SUBRESOURCE-NO-SRI` (baja) para un `<script>` u hoja de estilo **de otro
  origen** sin atributo `integrity`. Un recurso del propio origen no lo necesita.

### HTTP en claro

Si **ningún** TLS se pudo establecer y el servidor contesta HTTP por un socket
plano, `HTTP-CLEARTEXT` (**crítica**): el tráfico va sin cifrar. Un servidor cuyo
*handshake* ni completa ni contesta en claro se informa como **no medido**, nunca
como «sin problemas».

---

## El comportamiento de TLS

Más allá de la lista de suites, cómo negocia el servidor. Estos hallazgos salen de
`_feature_findings` en [`assessment.py`](../../web_crypto_checker/assessment.py); la
mayoría se obtienen con la sonda extendida que activa `--active`:

| id | Severidad | Qué |
|---|---|---|
| `TLS-0RTT-ENABLED` | baja | TLS 1.3 con *early data* (0-RTT), que un atacante puede reenviar. |
| `TLS-INSECURE-RENEGOTIATION` | media | Sin renegociación segura (RFC 5746). |
| `TLS-NO-EXTENDED-MASTER-SECRET` | baja | Sin extended master secret. |
| `TLS-NO-ENCRYPT-THEN-MAC` | baja | Sin encrypt-then-MAC. |
| `TLS-NO-FALLBACK-SCSV` / `TLS-NO-DOWNGRADE-SENTINEL` | baja | Sin protección anti-downgrade. |
| `TLS-NO-CIPHER-PREFERENCE` | baja | El servidor no impone su orden de suites. |
| `TLS-GREASE-INTOLERANT` | baja | No tolera valores GREASE. |
| `TLS-WEAK-DH-PARAMS` | media/alta | Primo Diffie-Hellman < 2048 bits (alta si < 1024). |
| `TLS-COMPRESSION` | alta | Compresión TLS activa (superficie de CRIME). |
| `SSLV2-EXPORT-CIPHERS` | alta | SSL 2.0 ofreciendo cifrados de exportación (hace DROWN práctico). |

---

## El certificado, más allá de la clave

La fuerza de la clave y el algoritmo de firma del certificado **sí** son una clase
de algoritmo con nota (ver [`politica-algoritmos.md`](politica-algoritmos.md)).
Todo lo demás del certificado —validez, cadena, confianza, higiene— son estas
comprobaciones, en [`assessment.py`](../../web_crypto_checker/assessment.py) y
[`pki/certificates.py`](../../web_crypto_checker/pki/certificates.py):

- **Validez y coincidencia:** `CERT-EXPIRED`, `CERT-NOT-YET-VALID`,
  `CERT-HOSTNAME-MISMATCH`, `CERT-CHAIN-EXPIRED` (un intermedio fuera de vigencia
  rompe la ruta aunque la hoja esté bien).
- **Propósito y forma:** `CERT-EKU-NO-SERVER-AUTH` (no sirve para autenticar un
  servidor), `CERT-NO-SAN` (media), `CERT-VALIDITY-TOO-LONG` (validez > 398 días,
  media), `CERT-LEAF-IS-CA` (media).
- **Confianza y cadena:** `CERT-UNTRUSTED` (no encadena hasta una raíz del
  sistema), `CERT-SELF-SIGNED` (media), `CERT-CHAIN-INCOMPLETE` (baja, hubo que
  completar por AIA), `CERT-CHAIN-CONTAINS-ANCHOR` (baja, la raíz viaja en la
  cadena), `CERT-BAD-SIGNATURE` (una firma interna de la ruta no verifica).
- **Debilidades:** `CERT-ROCA` (CVE-2017-15361), `CERT-WEAK-KEY`,
  `CERT-WEAK-SIGNATURE`, `CERT-CHAIN-WEAK-SIGNATURE` (un intermedio con firma
  insegura).
- **Revocación y grapado:** `CERT-REVOKED`, `OCSP-STAPLE-INVALID`,
  `OCSP-MUST-STAPLE-VIOLATED` (alta: el certificado exige grapado y el servidor no
  lo hace).
- **Certificado alternativo:** un servidor puede tener un segundo certificado (un
  RSA escondido tras un ECDSA); se evalúa igual, y sus problemas salen como
  `CERT-ALTERNATE-INVALID` / `CERT-ALTERNATE-WEAK` para que no queden ocultos tras
  el certificado por defecto válido.

### Los que sí mueven la nota

A diferencia de todo lo anterior, unos pocos hallazgos de certificado **fuerzan un
tope de nota**, porque un navegador rechazaría directamente el certificado:

- Cualquiera que marque el certificado como inválido (`CERT-EXPIRED`,
  `CERT-HOSTNAME-MISMATCH`, `CERT-UNTRUSTED`, `CERT-REVOKED`, `CERT-BAD-SIGNATURE`,
  `CERT-ROCA`, `CERT-EKU-NO-SERVER-AUTH`…) activa el tope `certificate_invalid` →
  **F**.
- `CERT-SELF-SIGNED` activa `self_signed` → **C**.

Los topes con nombre están en `scoring.grade_caps` de
[`algorithms.json`](../../web_crypto_checker/data/algorithms.json) y se aplican en
`_apply_caps`.

---

## Lo que estas comprobaciones **no** hacen

- **No se configuran en la política JSON.** Su severidad y su condición están en el
  código; `algorithms.json` solo aloja los `grade_caps` que unas pocas activan. Es
  la diferencia con las clases de algoritmo y las vulnerabilidades, que sí son
  datos.
- **La capa HTTP y el comportamiento de TLS no mueven la letra por sí solos.**
  Producen hallazgos con su severidad —que cuentan para `--fail-on` y para el
  informe—, pero la nota algorítmica la fijan las cinco clases y los topes con
  nombre. Solo el certificado, a través de esos topes, degrada la letra.
- **No inventan lo que no vieron.** Si `--active` no corrió, las comprobaciones de
  comportamiento que dependen de él no se evalúan a «bien»: sencillamente no salen,
  y el informe distingue «no medido» de «sin problemas».
</content>
