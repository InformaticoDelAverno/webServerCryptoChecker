# webServerCryptoChecker

Auditoría de la criptografía **y de los protocolos** que ofrecen tus servidores
**web**: versiones de TLS, suites de cifrado, grupos de intercambio de claves,
algoritmos de firma, el **certificado** (cadena, confianza, caducidad, revocación,
transparencia y —por DNS— **CAA** y **DANE/TLSA**), la **compresión** (el canal
CRIME), el **0-RTT** de TLS 1.3, la **capa HTTP** (HSTS, CSP, cookies,
redirecciones) y **todos los protocolos de aplicación** que expone: **HTTP/2**
(con sus SETTINGS y Rapid Reset), **HTTP/3** sobre QUIC (con el cifrado, el grupo
y los parámetros de transporte que negocia), **WebSocket seguro (wss)**, **SSE**,
**gRPC** y **mTLS** (autenticación por certificado de cliente). Clasifica cada
servidor como **seguro**, **aceptable**, **débil** o **inseguro**, indica si está
**preparado para post-cuántico**, y comprueba vulnerabilidades conocidas y
conformidad con las normas publicadas.

> El código está en inglés (el vocabulario propio de TLS y de seguridad) y esta
> documentación en castellano. La herramienta es **bilingüe** (`--lang en|es`):
> el asistente, la ayuda del comando y los informes legibles salen en el idioma
> elegido; los formatos legibles por máquina (JSON, CSV, SARIF, OpenMetrics)
> se mantienen en inglés.

---

> **English:** this manual is also available in [English](../en/README.md).

## Índice

- [Características](#características)
- [Requisitos e instalación](#requisitos-e-instalación)
- [Uso rápido](#uso-rápido)
- [Formas de indicar un objetivo](#formas-de-indicar-un-objetivo)
- [El asistente interactivo (--wizard)](#el-asistente-interactivo---wizard)
- [Idiomas (--lang)](#idiomas---lang)
- [Formatos de informe](#formatos-de-informe)
- [La interfaz web](#la-interfaz-web)
- [La interfaz MCP](#la-interfaz-mcp)
- [Conformidad con estándares (NIST, FIPS, ENS, PCI DSS, CIS…)](#conformidad-con-estándares-nist-fips-ens-pci-dss-cis)
- [Plugins de detección](#plugins-de-detección)
- [Qué comprueba exactamente](#qué-comprueba-exactamente)
- [Códigos de salida e integración en CI](#códigos-de-salida-e-integración-en-ci)
- [Referencia de opciones](#referencia-de-opciones)
- [Recetario: un ejemplo por opción](#recetario-un-ejemplo-por-opción)
- [Limitaciones y notas legales](#limitaciones-y-notas-legales)
- [Licencia](#licencia)
- [Guías de extensión incluidas](#guías-de-extensión-incluidas)

---

## Características

- **Cero dependencias.** Solo Python 3.9 o superior. Los registros TLS y la
  criptografía necesaria para enumerar lo que un servidor ofrece se implementan
  en el propio paquete —no se toman de OpenSSL—, así la misma sonda alcanza a un
  servidor antiguo que un OpenSSL moderno se negaría a hablar.
- **Enumera las cuatro dimensiones de TLS**: versiones (SSL 2/3, TLS 1.0–1.3),
  suites de cifrado, grupos de intercambio de claves y esquemas de firma.
- **Nota por servidor** (A+…F) y **veredicto** (seguro / aceptable / débil /
  inseguro), con la **fuerza de seguridad efectiva en bits** (NIST SP 800-57, el
  eslabón más débil).
- **Preparación post-cuántica**: detecta los híbridos (X25519MLKEM768 y otros).
- **Certificado a fondo**: cadena, coincidencia de nombre, fuerza de clave,
  confianza hasta una raíz del sistema, caducidad, revocación (OCSP/CRL/grapado),
  **transparencia (CT)** con verificación de firma de los SCT, y por DNS **CAA**
  y **DANE/TLSA** validados por **DNSSEC**.
- **Capa HTTP**: HSTS, CSP (analizada, no solo contada), cookies, redirección a
  HTTPS, contenido mixto, Subresource Integrity y CORS.
- **Todos los protocolos de aplicación**: HTTP/2, HTTP/3 (QUIC), WebSocket seguro
  (wss), SSE, gRPC y mTLS.
- **Vulnerabilidades conocidas** dirigidas por datos (POODLE, Sweet32, RC4,
  FREAK/Logjam, DROWN, BEAST, ROBOT…) y **sondas activas** opcionales
  (`--active`: Heartbleed, CCS injection, el oráculo ROBOT, revocación real…).
- **Conformidad con 14 normativas** citadas de documentos reales (Mozilla, NIST,
  PCI DSS, BSI, ANSSI, ENS, CNSA, FIPS 140-3, ISO/IEC 27002 y los benchmarks CIS).
- **Ocho formatos de informe**: consola, texto, JSON, CSV, HTML, SARIF,
  inventario y OpenMetrics (Prometheus).
- **Bilingüe** (`--lang en|es`), con un **asistente interactivo** (`--wizard`) y
  una **interfaz web** opcional en Docker.

---

## Requisitos e instalación

**Python 3.9 o superior. Nada más.** La herramienta no tiene dependencias en
tiempo de ejecución.

```bash
# Clonar y usar sin instalar, desde el propio repositorio
git clone https://github.com/CHANGEME/webServerCryptoChecker.git
cd webServerCryptoChecker
./web-crypto-checker example.com

# O instalarla (deja el comando `web-crypto-checker` en el PATH)
pip install .
web-crypto-checker example.com
```

El lanzador `web-crypto-checker` del repositorio permite usar la herramienta
**sin instalarla**; instalada, `pip install .` deja el mismo comando disponible.

---

## Uso rápido

```bash
# Un servidor en el 443
./web-crypto-checker example.com

# Varios a la vez, con más paralelismo
./web-crypto-checker web01 web02 api.example.com -c 4

# Un puerto distinto, y una ruta concreta
./web-crypto-checker example.com:8443
./web-crypto-checker https://example.com/login
```

Un escaneo produce, en la consola, un bloque por endpoint con su nota, veredicto,
versiones y suites ofrecidas, y los hallazgos con su severidad:

```
webServerCryptoChecker 0.1.0 — 1 endpoint(s), 1 reachable

servidor.example.com  [192.0.2.10]
  grade: F    verdict: weak
  TLS versions: TLS 1.2, TLS 1.1, TLS 1.0
  cipher suites (2):
    [weak] TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    [weak] TLS_RSA_WITH_AES_128_CBC_SHA
  [medium] Weak protocol versions offered: TLS 1.0, TLS 1.1
  [medium] Weak cipher suites offered: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA
```

---

## Formas de indicar un objetivo

| Forma | Ejemplo | Puerto |
|---|---|---|
| Nombre DNS | `example.com` | 443 (o `-p`) |
| Nombre y puerto | `example.com:8443` | 8443 |
| URL con ruta | `https://example.com/login` | 443, ruta `/login` |
| URL http | `http://example.com` | 80 |
| IPv4 | `192.0.2.10` | 443 |
| IPv6 entre corchetes | `[2001:db8::1]:443` | 443 |
| IPv6 sin corchetes | `2001:db8::1` | 443 |
| Con usuario (se ignora) | `admin@example.com` | 443 |

Un host sin puerto se expande a **cada puerto de `-p`** (`-p 443,8443` → dos
objetivos). Un host que trae su propio puerto no se expande. El **SNI** por
defecto es el nombre del host; a una IP desnuda no se le manda SNI (lo prohíbe
RFC 6066), y `--sni` lo fuerza. Con `-f/--file` se leen objetivos de un fichero
(uno por línea, `#` para comentarios); ver [`examples/servers.txt`](../../examples/servers.txt)
y su [guía](../../examples/README.md).

---

## El asistente interactivo (--wizard)

Si no te quieres aprender las opciones, el asistente (`-w` / `--wizard`) las
pregunta una a una —objetivos e inventario, SNI y puerto, normativas a evaluar,
formatos de salida y fichero, tiempos y concurrencia, almacén de confianza,
sondas activas, histórico y comparación, y plugins—, **muestra el comando** que
ha construido y ofrece lanzarlo:

```bash
./web-crypto-checker --wizard
./web-crypto-checker -w            # atajo
```

El asistente **no escanea nada por su cuenta**: ensambla el `argv` exacto que
usaría una invocación normal, lo imprime como una orden copiable y se la pasa a
la propia CLI. Así lo que muestra y lo que ejecuta son lo mismo por construcción,
y el comando impreso se puede **guardar y volver a lanzar** después sin el
asistente. El comando que construye termina en `--lang`, para que copiado a otra
máquina produzca el mismo informe. Necesita un terminal interactivo (si la
entrada no es un TTY, sale con un aviso).

---

## Idiomas (--lang)

La herramienta es **bilingüe**: inglés (por defecto) y español de España. Todo
lo que lee una persona sale en el idioma elegido: el **asistente** (`--wizard`),
la **ayuda completa de la CLI** (`--help`: la descripción, la ayuda de cada
opción y las metavariables) y el **cuerpo de los informes** legibles (los
formatos `console`, `text` y `html`). El idioma se elige así:

```bash
./web-crypto-checker example.com --lang es      # español
./web-crypto-checker example.com --lang en      # inglés (por defecto)
```

Si no se pasa `--lang`, se elige el español cuando el **locale** del sistema es
español (`LANG`/`LC_ALL`/`LC_MESSAGES` empieza por `es`); en cualquier otro caso,
inglés. `--lang` manda siempre sobre el locale, y admite formas como `es_ES` o
`en-GB` (se toma el prefijo). Los **formatos legibles por máquina** (JSON, SARIF,
CSV, inventory, OpenMetrics) conservan sus claves y valores en inglés sea cual
sea el idioma: son un contrato para herramientas, no prosa para personas. Las palabras
del armazón de `argparse` (`usage:`, `options:` y los errores de sintaxis) también
quedan en inglés, porque Python no trae su traducción.

---

## Formatos de informe

Un escaneo, **ocho formatos**. Se eligen con `--format` (uno, o varios separados
por comas) y se escriben con `-o` (con varios formatos, `-o` es el nombre base y
cada formato añade su extensión):

| Formato | `--format` | Para qué |
|---|---|---|
| Consola | `console` | La salida legible por defecto, un bloque por endpoint. |
| Texto | `text` | Resumen en texto plano, sin color. |
| JSON | `json` | El informe completo, legible por máquina. |
| CSV | `csv` | Una fila por hallazgo, para hojas de cálculo. |
| HTML | `html` | Un informe navegable y autocontenido. |
| SARIF | `sarif` | Para la vista de code-scanning de un forge (GitHub/GitLab). |
| Inventario | `inventory` | Una fila por endpoint (nota, veredicto, versiones…). |
| OpenMetrics | `openmetrics` | Métricas para Prometheus. |

```bash
# JSON y HTML de una sola pasada
./web-crypto-checker -f inventario.txt --format json,html -o auditoria
# → auditoria.json y auditoria.html
```

Además, `--compare` contrasta el escaneo con un informe JSON anterior y muestra
lo que cambió: endpoints nuevos o desaparecidos, movimiento de nota, hallazgos y
vulnerabilidades nuevos o resueltos, **algoritmos añadidos o retirados** (por
clase: versiones, suites, grupos, firmas) y **cambio de huella del certificado**
—en un servidor que nadie reemitió, una huella nueva es motivo para parar y
averiguar por qué—. Con `--fail-on-regression` una regresión falla la ejecución.
Y `--history` añade el escaneo a un histórico y muestra la evolución de la nota de
cada endpoint.

---

## La interfaz web

Una forma **adicional** de usar la herramienta, no un sustituto: el mismo
`scan()`, evaluando las mismas normativas, y el mismo `render()` —el informe se
descarga en **cualquiera de los ocho formatos**, en el idioma elegido—, desde un
formulario. Cero dependencias también aquí: el servidor es `http.server` de la
librería estándar.

```bash
# En local (por defecto escucha solo en 127.0.0.1:8443)
python3 -m web_crypto_checker.web
# → http://127.0.0.1:8443/

# En contenedor, de un tirón (usa docker-compose.yml de la raíz)
make web-up      # docker compose up -d --build → http://localhost:8443/
make web-logs    # sigue el log
make web-down    # para y limpia
```

La API es mínima: `GET /api/meta` (opciones y formatos disponibles),
`POST /api/scan` (lanza un escaneo y devuelve un identificador de trabajo con su
progreso) y las descargas del informe por formato. La página única (`page.html`)
es autocontenida, sin recursos externos (la CSP los prohíbe).

**Acceso abierto por defecto (sin token, sin usuarios, sin registro).** Es lo más
cómodo para un despliegue interno: cualquiera que alcance el puerto la usa. El
token es el **único interruptor** que la cierra —ponlo y cada petición de `/api`
exigirá `X-Auth-Token` (comparación en tiempo constante):

```bash
# Abierta, en tu LAN interna (lo que hace `make web-up` sin más)
docker compose up -d --build

# Cerrada con token
WEB_CRYPTO_CHECKER_WEB_TOKEN=un-secreto docker compose up -d
```

Lo que en la CLI son opciones de despliegue entra por **variables de entorno y
volúmenes**, no por el formulario (así ningún secreto ni decisión peligrosa viaja
por el navegador):

| Variable | Qué hace |
|---|---|
| `WEB_CRYPTO_CHECKER_WEB_TOKEN` | Exige `X-Auth-Token` en cada petición de `/api`. Vacío = abierta. |
| `WEB_CRYPTO_CHECKER_WEB_BLOCK_PRIVATE` | Rechaza objetivos que resuelvan a direcciones privadas/loopback/reservadas. |
| `WEB_CRYPTO_CHECKER_WEB_PLUGIN_DIR` | Directorios de plugins (equivale a `--plugin-dir`). |
| `WEB_CRYPTO_CHECKER_WEB_CA_BUNDLE` | PEM de raíces propias (equivale a `--ca-bundle`). |
| `WEB_CRYPTO_CHECKER_WEB_NO_TRUST` | No validar la cadena (equivale a `--no-trust`). |
| `WEB_CRYPTO_CHECKER_WEB_ALLOW_ACTIVE` | Habilita las sondas activas (**desactivadas** por defecto). |

### Seguridad de la web

La capa web está endurecida y hay pruebas que lo fijan (`tests/test_web.py`):
topa todo lo que un anónimo podría inflar (tamaño del cuerpo, número de objetivos,
concurrencia, timeout y escaneos simultáneos), añade cabeceras defensivas
(`nosniff`, `X-Frame-Options: DENY`, una CSP estricta, `Referrer-Policy:
no-referrer`), descarga los informes como adjuntos, compara el token en tiempo
constante y **escapa** todo lo que controla el servidor escaneado (un banner
hostil no puede inyectar script). Las sondas activas están **desactivadas** salvo
que un despliegue las habilite: un servicio abierto que lanza tráfico ofensivo
contra cualquier host es un amplificador de abuso.

Dos cosas no se arreglan en el código, solo en el **borde del despliegue**:

1. **Escanear hosts arbitrarios es la función de la herramienta.** Publicada sin
   token es una máquina de SSRF: ciérrala con el token, activa
   `WEB_CRYPTO_CHECKER_WEB_BLOCK_PRIVATE=1` y, para la garantía dura, arráncala
   **sin ruta de red** a tus rangos internos (un cortafuegos de salida es lo
   único infalible; el filtro de la app solo lo aproxima).
2. **`http.server` es el servidor básico de la stdlib**, no un borde endurecido:
   para internet, ponla **detrás de un proxy inverso** que termine TLS, limite la
   tasa y rechace peticiones malformadas.

> En una frase: trátala como herramienta **interna** salvo que hayas puesto
> token/filtro **y** un proxy con TLS delante.

---

## La interfaz MCP

Una **tercera** forma de usar la herramienta, junto a la línea de órdenes y la
web, para que la maneje un **modelo de lenguaje**: un servidor **MCP** (*Model
Context Protocol*). El mismo `scan()` y el mismo `render()` que las otras dos,
hablados por **JSON-RPC 2.0 sobre stdio** —un mensaje JSON por línea, el
transporte stdio de MCP—. Cero dependencias también aquí: solo la biblioteca
estándar, **sin SDK ni framework**.

### Requisitos

**Python 3.9 o superior. Nada más** —igual que la CLI—. El servidor MCP no
necesita red para arrancar, ni claves, ni un fichero de configuración propio: se
lanza, habla JSON-RPC por su entrada/salida estándar y hereda el entorno del
cliente que lo arranca.

### Instalación

Dos caminos, según prefieras instalar el paquete o usarlo desde el repositorio.

**a) Instalado (recomendado para configurar un cliente).** `pip install .` deja
**dos** comandos en el `PATH`: la CLI y el servidor MCP. Con el comando en el
`PATH`, la configuración del cliente es solo su nombre.

```bash
pip install .            # dentro del repositorio (o `pipx install .`)
web-crypto-checker-mcp --version     # comprueba que quedó instalado
```

> Consejo: `pipx install .` lo instala aislado en su propio entorno y deja los
> comandos en el `PATH` global, que es justo lo que un cliente MCP necesita para
> encontrarlos sin activar ningún *virtualenv*.

**b) Desde el repositorio, sin instalar.** Equivale a lo anterior pero ejecutando
el módulo; hay que decirle a Python dónde está el paquete (con `-m` desde la raíz
del repositorio, o con `PYTHONPATH`):

```bash
cd /ruta/a/webServerCryptoChecker
python3 -m web_crypto_checker.mcp --version
```

### Configuración en un cliente MCP

El servidor **no se lanza a mano** en un terminal —habla JSON-RPC, no con una
persona—: se **registra su comando** en un cliente MCP, que lo arranca por ti y
le habla el protocolo. La forma canónica, común a casi todos los clientes, es una
entrada bajo `mcpServers`:

```json
{
  "mcpServers": {
    "web-crypto-checker": {
      "command": "web-crypto-checker-mcp"
    }
  }
}
```

**Claude Desktop.** Edita el fichero `claude_desktop_config.json` (Ajustes →
Developer → Edit Config), añade la entrada de arriba y **reinicia** la aplicación.
Su ubicación:

| Sistema | Ruta |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

**Claude Code.** Regístralo con un comando (elige el alcance con `-s`
`local`/`user`/`project`), o deja un `.mcp.json` en la raíz del proyecto con el
mismo bloque `mcpServers`:

```bash
claude mcp add web-crypto-checker -- web-crypto-checker-mcp
claude mcp list                     # comprueba que aparece y conecta
```

**Otros clientes** (Cursor, VS Code, Zed…). Todos consumen la misma forma
`command`/`args`/`env`; cambia solo dónde vive el fichero (p. ej. `.cursor/mcp.json`
en Cursor). Consulta la documentación del cliente para la ruta exacta.

**Sin instalar (usando el repositorio).** Si prefieres no instalar el paquete,
apunta el cliente a `python3 -m` y dile en qué directorio ejecutarlo:

```json
{
  "mcpServers": {
    "web-crypto-checker": {
      "command": "python3",
      "args": ["-m", "web_crypto_checker.mcp"],
      "cwd": "/ruta/a/webServerCryptoChecker"
    }
  }
}
```

> Si tu cliente no admite `cwd`, usa `"env": { "PYTHONPATH": "/ruta/a/webServerCryptoChecker" }`
> en su lugar. Con el paquete **instalado** nada de esto hace falta: basta el
> nombre del comando.

### Comprobar que funciona

Antes de configurar el cliente puedes verificar el servidor a mano: se le pasan
uno o dos mensajes JSON-RPC por la entrada estándar y responde por la salida.

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | web-crypto-checker-mcp
```

Debe imprimir dos líneas JSON: la primera con `serverInfo`
(`web-crypto-checker-mcp` y la versión), la segunda con la lista de herramientas.
Si en su lugar ves un error de import, el paquete no está en el `PATH`/`PYTHONPATH`
(revisa la instalación). Ya en el cliente, `scan` con `args: ["example.com"]`
lanza un escaneo real.

### Por qué no pierde ninguna opción

La paridad con la CLI es **de construcción, no de mantenimiento**: cada llamada a
una herramienta termina ejecutando el mismo `web_crypto_checker.cli.main` que
ejecuta el terminal, con su salida capturada. La herramienta `scan` recibe el
propio `argv` de la CLI, así que **todo lo que hace el comando lo hace el MCP** —no
hay un esquema paralelo que alguien tenga que mantener sincronizado.

### Las herramientas que expone

| Herramienta | Qué hace |
|---|---|
| `scan` | Escanea. `args` es el vector de argumentos de la CLI: `["example.com", "--format", "json"]`. Cualquier opción del comando vale. |
| `help` | La ayuda completa de la CLI (todas las opciones), en el idioma elegido (`lang`). |
| `list_profiles` | Lista los perfiles de conformidad disponibles. |
| `list_plugins` | Lista los plugins de detección que se cargarían. |

Implementa los métodos MCP `initialize`, `tools/list`, `tools/call` y `ping`.
Los **códigos de salida son información, no fallos**: un escaneo que encuentra un
servidor débil sale con código distinto de cero **a propósito**, así que una
ejecución completa nunca se informa como error de herramienta —el código se añade
al texto—. `isError` queda para una llamada que no se pudo hacer (argumentos mal
formados) o una excepción inesperada, que se captura para que **una herramienta no
pueda tumbar el servidor**.

> ⚠️ Un MCP le da a un modelo de lenguaje la capacidad de **lanzar escaneos** —y,
> con `scan` y `--active` en `args`, tráfico ofensivo—. Rigen los mismos límites
> legales que en la CLI (ver [Limitaciones y notas legales](#limitaciones-y-notas-legales)):
> escanea solo lo que estés autorizado a probar. El servidor MCP **no** abre
> ningún puerto ni escucha en la red (a diferencia de la interfaz web): solo habla
> por stdio con el cliente que lo arranca, así que las variables `WEB_CRYPTO_CHECKER_WEB_*`
> **no** le aplican.

---

## Conformidad con estándares (NIST, FIPS, ENS, PCI DSS, CIS…)

Una normativa no es código de esta herramienta: es un documento que mantiene otra
gente y revisa en su propio calendario. Por eso cada normativa vive en **su propio
directorio** bajo
[`web_crypto_checker/data/profiles/`](../../web_crypto_checker/data/profiles/README.md),
**un fichero por edición**, y se **evalúa**, no se compila. Cuando el escaneo no ve
lo suficiente para juzgar, el resultado es **no evaluado**, nunca *cumple*: una
comprobación que no se pudo ejecutar no se ha superado, se ha omitido.

Se seleccionan con `--profile <id>` (la edición **en vigor**) o con
`--profile <id>@<edición>` para fijar una edición concreta (repetible), y se
listan con `--list-profiles`. Los **14 perfiles** de serie:

| `--profile` | Normativa | Autoridad |
|---|---|---|
| `mozilla-modern` | Mozilla Server Side TLS, Modern (solo TLS 1.3) | Mozilla |
| `mozilla-intermediate` | Mozilla Server Side TLS, Intermediate | Mozilla |
| `nist-sp-800-52r2` | NIST SP 800-52 Rev. 2 (guía de TLS) | NIST (EE. UU.) |
| `nist-sp-800-131a` | NIST SP 800-131A Rev. 2 | NIST (EE. UU.) |
| `fips-140-3` | FIPS 140-3 (algoritmos aprobados) | NIST (EE. UU.) |
| `pci-dss-4` | PCI DSS v4.0.1 | PCI SSC |
| `ens` | ENS — Esquema Nacional de Seguridad | CCN (España) |
| `cnsa-1.0` | CNSA 1.0 (suite transitoria) | NSA (EE. UU.) |
| `bsi-tr-02102-2` | BSI TR-02102-2 (uso de TLS) | BSI (Alemania) |
| `anssi` | ANSSI, reglas criptográficas por mecanismo | ANSSI (Francia) |
| `iso-27002-8-24` | ISO/IEC 27002:2022, control 8.24 | ISO/IEC |
| `cis-nginx` | CIS NGINX Benchmark | CIS |
| `cis-apache-2.4` | CIS Apache HTTP Server 2.4 Benchmark | CIS |
| `cis-iis-10` | CIS Microsoft IIS 10 Benchmark | CIS |

**Cada regla se remite a una sección o tabla exactas de un documento real**,
citadas en los campos `reference` y `notes` del perfil. Los documentos fuente se
citan (URL, fecha y SHA-256) en
[`docs/estandares/`](../estandares/README.md); no todos permiten redistribuirse
(PCI DSS e ISO/IEC son de pago; NIST es de dominio público; CIS es CC BY-NC-SA),
así que se **citan** y se obtienen de su editor, no se incluyen. Para entender qué
mide cada perfil y cómo escribir el tuyo, ver
[`docs/politica-normativas.md`](politica-normativas.md) y el
[README de `data/`](../../web_crypto_checker/data/README.md).

```bash
# Evaluar contra dos perfiles
./web-crypto-checker example.com --profile mozilla-intermediate --profile pci-dss-4

# Ver los perfiles disponibles
./web-crypto-checker --list-profiles
```

---

## Plugins de detección

Una regla de la política *empareja* (un nombre, una etiqueta, una versión). Lo
que no puede hacer es **calcular**. Para eso están los plugins: un fichero que se
deja en un directorio de plugins y ya se ejecuta. Dos garantías, y están
comprobadas:

- **Un plugin no puede cambiar la nota.** Recibe una `ServerView` de lo
  *observado* —nunca la nota, el grado ni el veredicto—, y su resultado se añade
  al informe *después* de calcular la nota.
- **Un plugin no puede tumbar el escaneo.** Lo que lance se captura y se informa
  como un hallazgo que lo nombra.

Cargar código es cargar código, así que los directorios de plugins son
**explícitos** (nunca el directorio de trabajo) y uno que otros puedan escribir se
rechaza. De serie vienen la **simulación de clientes** (qué clientes conocidos
completarían el handshake), el **tope de vigencia del certificado** (398 días) y
la **autorización del emisor por CAA** (heurística conservadora).

```bash
./web-crypto-checker example.com --plugin-dir ./mis-plugins
./web-crypto-checker --list-plugins
```

Cómo escribir uno, con el contrato completo, en
[`docs/plugins.md`](plugins.md).

---

## Qué comprueba exactamente

**Sobre el cable, sin autenticarse:**

- **Versiones**: SSL 2.0 (con su propio formato de mensaje), SSL 3.0 y TLS
  1.0–1.3, cada una marcada como ofrecida o no.
- **Suites de cifrado**, **grupos de intercambio de claves** (en orden de
  preferencia del servidor, vía `HelloRetryRequest`) y **esquemas de firma** (uno
  a uno), con su clasificación por la política.
- **Preparación post-cuántica** (híbridos como X25519MLKEM768) y **0-RTT / early
  data** de TLS 1.3.
- **Certificado**: cadena y coincidencia de nombre, tipo y fuerza de clave, firma
  interna verificada (RSA PKCS#1 v1.5 y PSS, ECDSA, Ed25519, propios), **confianza
  hasta una raíz** del sistema (`--ca-bundle` para otro *bundle*, `--no-trust`
  para desactivarla) con `NameConstraints`, `pathLenConstraint` y vigencia de
  toda la ruta, **higiene** (sin SAN, validez > 398 días, cadena con el ancla),
  **transparencia (CT)** con verificación de la firma de los SCT, y lo que el
  certificado **anuncia** sobre revocación (OCSP/CRL/must-staple) y si el servidor
  **grapa** OCSP (autenticado). La **huella ROCA** (CVE-2017-15361) y el
  **certificado alternativo** (RSA oculto tras un ECDSA) también.
- **Capa HTTP**: HSTS (con `max-age`, `preload`, `includeSubDomains`), CSP
  **analizada** (inline/eval/orígenes amplios), `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`, banderas de cookies, redirección del
  puerto 80 a HTTPS, **contenido mixto** (activo/pasivo), **Subresource
  Integrity** y **CORS** (reflejo con credenciales).
- **Por DNS** (con un cliente y un *resolver* iterativo propios): **CAA** (RFC
  8659) y **DANE/TLSA** (RFC 6698), ambos **validados por DNSSEC** hasta la raíz
  de IANA —incluida la **ausencia autenticada** (NSEC/NSEC3)—, y el registro
  **HTTPS/SVCB** (RFC 9460, con ALPN y ECH).
- **Protocolos de aplicación**: **HTTP/2** (SETTINGS), **HTTP/3** sobre QUIC (con
  un motor propio: cifrado, grupo y parámetros de transporte), **WebSocket seguro
  (wss)**, **SSE**, **gRPC** (con un códec HPACK propio) y **mTLS** (si se *pide* o
  se *exige* el certificado de cliente).

**Vulnerabilidades conocidas** dirigidas por datos: POODLE, Sweet32, RC4,
FREAK/Logjam, cifrados NULL/anónimos/DES, BEAST, la superficie estática-RSA de
ROBOT/Bleichenbacher, y **DROWN** (SSL 2.0 con detección de cifrados de
exportación).

**Con `--active`** (y un aviso de autorización): Heartbleed (CVE-2014-0160), CCS
injection (CVE-2014-0224), el **oráculo activo de ROBOT**, la **consulta real de
revocación** (OCSP/CRL), la **renegociación iniciada por el cliente**, y de forma
pasiva RFC 5746, extended master secret, Encrypt-then-MAC, anti-downgrade
(TLS_FALLBACK_SCSV y el centinela de TLS 1.3), preferencia de cifrado del
servidor, parámetros Diffie-Hellman (Logjam), tolerancia a GREASE, compresión TLS
(CRIME) y reanudación de sesión.

---

## Códigos de salida e integración en CI

| Código | Significado |
|---|---|
| `0` | Todos los objetivos se escanearon correctamente |
| `1` | Algún objetivo no se pudo escanear (inalcanzable o error), o hubo una **regresión** con `--compare --fail-on-regression` |
| `2` | Error de uso o de configuración (formato, perfil u objetivo inválido; `--wizard` sin terminal) |

```yaml
# .gitlab-ci.yml — auditar tu parque desde CI
auditoria-web:
  image: python:3.12-slim
  script:
    - pip install .
    - web-crypto-checker -f inventario.txt --format json,html -o informe
  artifacts:
    when: always
    paths: [informe.json, informe.html]
```

Para detectar regresiones frente a una línea base guardada, combina
`--compare informe-anterior.json --fail-on-regression`: la ejecución sale con
código `1` si algún endpoint empeoró.

---

## Referencia de opciones

```
Modo interactivo
  -w, --wizard              construir el comando respondiendo preguntas y lanzarlo

Idioma
  --lang LANG               idioma del asistente, la ayuda y los informes (en, es)

Objetivos
  TARGET...                 host, host:puerto, https://host/ruta, IP, [IPv6]:puerto
  -f, --file PATH           leer objetivos de un fichero ('-' para stdin); repetible
  -p, --port PUERTO         puerto, o lista con comas, para los hosts que no lo traen
  --sni NOMBRE              nombre de servidor a enviar en lugar del host (útil por IP)

Escaneo
  -t, --timeout SEGUNDOS    tiempo máximo por conexión (por defecto 6)
  -c, --concurrency N       objetivos en paralelo (por defecto 1)
  --active                  sondas activas (tráfico ofensivo; solo con autorización)

Confianza (certificados)
  --ca-bundle PATH          PEM de raíces de confianza (por defecto: el almacén del sistema)
  --no-trust                no validar la cadena contra ningún almacén

Conformidad y plugins
  --profile ID              evaluar cada endpoint contra un perfil (repetible)
  --list-profiles           listar los perfiles de conformidad y salir
  --plugin-dir DIR          cargar plugins de detección de un directorio (repetible)
  --list-plugins            listar los plugins que se cargarían y salir

Salida
  --format NAMES            console, text, json, csv, html, sarif, inventory, openmetrics
  -o, --output PATH         escribir el informe a un fichero (nombre base con varios formatos)

Comparación e histórico
  --compare BASELINE        comparar con un informe JSON anterior y mostrar lo que cambió
  --fail-on-regression      salir con código 1 si algún endpoint empeoró (con --compare)
  --history PATH            añadir este escaneo a un histórico y mostrar la evolución de notas

Información
  --version                 mostrar la versión y salir
```

---

## Recetario: un ejemplo por opción

Todo lo que sigue es copiable tal cual. Está ordenado por lo que quieres
conseguir, no por el orden del `--help`.

### La forma más fácil: el asistente

```bash
# Modo interactivo                                   # -w, --wizard
./web-crypto-checker --wizard
./web-crypto-checker -w

# En español (el asistente, la ayuda y los informes) # --lang
./web-crypto-checker --wizard --lang es
./web-crypto-checker example.com --lang en           # forzar inglés
```

### Elegir a quién escanear

```bash
# Un servidor en el 443
./web-crypto-checker example.com

# Puerto explícito, o una lista de puertos para hosts sin puerto   # -p, --port
./web-crypto-checker example.com:8443
./web-crypto-checker example.com -p 443,8443

# Una URL con ruta
./web-crypto-checker https://example.com/login

# IPv6 (entre corchetes si lleva puerto), y un SNI forzado          # --sni
./web-crypto-checker '[2001:db8::1]:443'
./web-crypto-checker 192.0.2.10 --sni example.com

# Varios objetivos a la vez
./web-crypto-checker web01 web02 api.example.com

# Desde un fichero de inventario (o desde stdin)                    # -f, --file
./web-crypto-checker -f inventario.txt
awk '$1=="server_name"{print $2}' /etc/nginx/sites-enabled/*.conf | ./web-crypto-checker -f -
```

### Ajustar el escaneo

```bash
# Más tiempo por conexión y más paralelismo          # -t, -c
./web-crypto-checker -f inventario.txt -t 15 -c 8

# Sondas activas (solo contra servidores autorizados) # --active
./web-crypto-checker example.com --active
```

### Confianza del certificado

```bash
# Raíces propias en lugar del almacén del sistema     # --ca-bundle
./web-crypto-checker example.com --ca-bundle ./raices.pem

# No validar la cadena contra ningún almacén          # --no-trust
./web-crypto-checker example.com --no-trust
```

### Conformidad y plugins

```bash
# Evaluar contra normativas concretas                 # --profile
./web-crypto-checker example.com --profile mozilla-modern --profile pci-dss-4
./web-crypto-checker --list-profiles                  # --list-profiles

# Cargar plugins de detección propios                 # --plugin-dir
./web-crypto-checker example.com --plugin-dir ./mis-plugins
./web-crypto-checker --list-plugins                   # --list-plugins
```

### Informes

```bash
# Varios formatos de una pasada (base + extensión)    # --format, -o
./web-crypto-checker -f inventario.txt --format json,html -o auditoria

# Comparar con una línea base y fallar si empeora      # --compare, --fail-on-regression
./web-crypto-checker -f inventario.txt --format json -o hoy.json
./web-crypto-checker -f inventario.txt --compare hoy.json --fail-on-regression

# Serie histórica de notas por endpoint                # --history
./web-crypto-checker -f inventario.txt --history historial.json
```

### Información

```bash
./web-crypto-checker --version                        # --version
```

---

## Limitaciones y notas legales

**Autorización.** Escanear un servidor que no es tuyo puede ser ilegal sin
permiso, y `--active` envía tráfico manipulado y potencialmente disruptivo
(Heartbleed, CCS injection, el oráculo ROBOT…). Usa `--active` **solo** contra
servidores que estés autorizado a probar. La herramienta te lo recuerda al
lanzarlo.

**Lo que NO hace, a propósito y con motivo.** La regla dura es *nunca emitir una
señal de seguridad sin validar*: cuando una comprobación no se puede validar o no
cambiaría ningún veredicto, se documenta en vez de fingirla.

- **Oráculo activo del *special DROWN*** (CVE-2016-0703): no hay servidor
  vulnerable reproducible con el que validarlo, y soportar SSL 2.0 ya es
  catastrófico de por sí (se detecta y puntúa **F**).
- **CONTINUATION flood** (CVE-2024-27316) y **Rapid Reset** (CVE-2023-44487) de
  HTTP/2: la única detección fiable es provocar el propio ataque de denegación de
  servicio; una heurística acotada da falso positivo en servidores modernos, así
  que no se emite veredicto.
- **Reutilización de clave en DROWN entre hosts**: requiere consultar un servicio
  externo y escanear otros hosts, incompatible con el diseño de cero dependencias
  y un solo objetivo. Se detecta la precondición local (SSL 2.0 + cifrados de
  exportación); el cruce entre hosts queda fuera.

**Datos personales.** Un informe guardado contiene detalles del servidor escaneado
(huellas de certificado, cabeceras). Trátalo como corresponda; el `.gitignore`
del repositorio evita que un informe acabe versionado por descuido.

---

## Licencia

MIT. Ver [`LICENSE`](../../LICENSE). El registro de cambios está en
[`CHANGELOG.md`](../../CHANGELOG.md).

---

## Guías de extensión incluidas

Los manuales de extensión viven en [`docs/`](extender.md), cada uno en los
dos idiomas (su versión inglesa está en `docs/en/`, con el mismo nombre):

- [`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md)
- [`politicas.md`](politicas.md)
- [`politica-algoritmos.md`](politica-algoritmos.md)
- [`politica-vulnerabilidades.md`](politica-vulnerabilidades.md)
- [`politica-configuracion.md`](politica-configuracion.md)
- [`politica-puntuacion.md`](politica-puntuacion.md)
- [`politica-normativas.md`](politica-normativas.md)
- [`auditoria-integridad.md`](auditoria-integridad.md)
- [`plugins.md`](plugins.md)
- [`plugin-check.md`](plugin-check.md)
- [`plugin-fleet.md`](plugin-fleet.md)
- [`plugin-vulnerability.md`](plugin-vulnerability.md)
- [`uso-avanzado.md`](uso-avanzado.md)
- [`desarrollo.md`](desarrollo.md)
