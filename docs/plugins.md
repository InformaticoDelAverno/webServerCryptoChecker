# Plugins de detección

Volver al [manual](../README.md) · relacionado:
[política de conformidad](politica-normativas.md) · [English](en/plugins.md).

La mayoría de las comprobaciones se emparejan de forma declarativa desde la
política (un nombre, una etiqueta, una versión). Lo que una regla no puede hacer
es **calcular**: factorizar un módulo, correlacionar dos observaciones, decidir a
partir de una aritmética. Para eso están los plugins.

## Dos garantías

- **Un plugin no puede cambiar la nota.** Recibe una `ServerView` de lo
  *observado* —nunca la nota, el grado ni el veredicto—, y su resultado se añade
  al informe *después* de calcular la nota. Por eso es el sitio seguro para lo que
  hay que calcular: como observación no puede provocar un falso suspenso.
- **Un plugin no puede tumbar el escaneo.** Lo que lance se captura y se informa
  como un hallazgo que lo nombra.

Cargar código es cargar código: los directorios de plugins son **explícitos**
(nunca el directorio de trabajo), y uno que el grupo u otros puedan escribir se
**rechaza** (evita que alguien ejecute código como quien lanza el escaneo).

## Un plugin es un fichero

```python
ID = "EXAMPLE-1"
NAME = "Algo que una regla no puede expresar"
SEVERITY = "high"          # info | low | medium | high | critical
DESCRIPTION = "Qué está mal y por qué importa."
REMEDIATION = "Qué hacer al respecto."   # opcional
KIND = "vulnerability"     # opcional: "vulnerability" (por defecto) o "check"
REFERENCES = ["CVE-2017-15361"]          # opcional

def check(server):
    # `server` es una ServerView de solo lectura.
    if server.offers_cipher("TLS_RSA_WITH_RC4_128_SHA"):
        return Detected(evidence=["RC4 ofrecido"])
    return None            # None = nada que informar
```

Campos obligatorios: `ID`, `NAME`, `SEVERITY`, `DESCRIPTION` y una función
`check(server)`. Si al plugin le faltan datos para decidir, puede devolver
`Undetermined(needs=[...])` en lugar de `Detected(...)`, diciendo qué lo
resolvería (mejor que un falso negativo silencioso).

## Qué ve `check(server)`

La `ServerView` expone **lo observado, y nada de lo concluido**:

- `server.supported_protocols` y `server.supports(protocol_id)`
- `server.offered_ciphers` y `server.offers_cipher(name)`
- `server.cipher_tags(name)` (las etiquetas de una suite)
- `server.key_exchange_groups`, `server.signature_algorithms`
- `server.certificate()` (el certificado hoja) y `server.leaf`
- `server.caa_records`
- `server.assessment(key)` y `server.assessments`

No hay ahí ninguna nota, grado ni veredicto: esa frontera es el punto.

## Cargarlos

```bash
web-crypto-checker example.com --plugin-dir ./mis-plugins
web-crypto-checker --list-plugins        # ver los que se cargarían, y salir
```

En la [interfaz web](../README.md#la-interfaz-web) entran por despliegue, con la
variable `WEB_CRYPTO_CHECKER_WEB_PLUGIN_DIR`, no por el formulario.

## Los de serie

Vienen tres, cargados igual que un plugin de terceros (así son también ejemplos
trabajados):

- **Simulación de clientes**: qué clientes conocidos (navegadores actuales, Java
  8/11, Android 5, IE8/XP…) completarían el handshake, cruzando lo enumerado con
  un perfil de cada cliente. Es una observación (INFO), no una nota.
- **Vigencia del certificado**: una hoja válida más de 398 días (el tope del
  CA/Browser Forum). Es un plugin porque hay que **calcular** los días entre dos
  fechas.
- **Autorización del emisor por CAA**: heurística conservadora (solo CAs muy
  conocidas, y solo cuando ninguno de sus identificadores está entre los
  autorizados), segura precisamente porque como observación no puede cambiar la
  nota.
