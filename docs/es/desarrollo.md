# Manual de desarrollo

Volver al [manual](README.md) · relacionado: [uso avanzado](uso-avanzado.md) ·
[plugins](plugins.md) · [política de conformidad](politica-normativas.md) ·
[English](../en/desarrollo.md).

> El mapa del repositorio y las guías de usuario están en el [README](README.md);
> cada directorio tiene además su propio `README.md`.

## Estructura

```
web_crypto_checker/
├── cli.py             Línea de órdenes y códigos de salida
├── wizard.py          El asistente interactivo (--wizard)
├── targets.py         Análisis de objetivos (host:puerto, IPv6, URL, ficheros)
├── scanner.py         Orquestación: resuelve, enumera y monta el informe
├── assessment.py      Nota (A+…F), veredicto y hallazgos
├── strength.py        Fuerza de seguridad efectiva en bits (NIST SP 800-57)
├── policy.py          Carga y consulta de la política editable
├── vulnerabilities.py Motor de las reglas declarativas de vulnerabilidades
├── compliance.py      Evaluación contra las normativas de data/profiles/
├── compare.py         Comparar contra un informe anterior (--compare)
├── history.py         Serie histórica de notas (--history)
├── dns.py             Cliente DNS: CAA, DANE/TLSA, HTTPS/SVCB
├── dnssec.py          Validación DNSSEC hasta la raíz IANA
├── resolver.py        Resolver DNS iterativo propio (root hints)
├── http_layer.py      La capa HTTP: HSTS, CSP, cookies, redirección
├── mixed_content.py   Contenido mixto activo/pasivo
├── subresource_integrity.py   Subresource Integrity ausente
├── webclient.py       Cliente HTTP/1.1 en claro (OCSP y CRL lo comparten)
├── models.py          Dataclasses compartidas y serialización a JSON con redacción
├── i18n.py / messages.py   El traductor y el catálogo bilingüe
├── tls/               El motor TLS a mano (códec, sonda, enumeración, sondas activas)
├── quic/              El motor QUIC / HTTP-3 a mano (RFC 9000/9001)
├── pki/               Certificados, cadena, ROCA, CT, OCSP, CRL
├── crypto/            Primitivas propias (AES, GCM, ChaCha, ECDSA, Ed25519, RSA, X25519, DER…)
├── application/       Protocolos de aplicación: HTTP/2, HPACK, gRPC, wss, SSE, mTLS
├── reporting/         Un renderizador por formato (ocho)
├── plugins/           Comprobaciones que necesitan código (no una regla)
├── web/               La interfaz web (http.server, sin dependencias)
├── mcp/               La interfaz MCP (JSON-RPC sobre stdio, sin dependencias)
└── data/
    ├── algorithms.json  La política por defecto (algoritmos, reglas, umbrales)
    ├── profiles/        Las normativas, una por directorio, un fichero por edición
    ├── ct_logs.json     Los logs de Certificate Transparency conocidos
    └── i18n/            La superposición traducible de la política
```

Flujo de datos:

```
targets.py  ->  scanner.py  ->  tls/ · quic/ · pki/ · dns/ · application/   (red)
                     |
                     v
     assessment.py + strength.py + vulnerabilities.py + compliance.py       (juicio)
                     |            (+ policy.py, data/algorithms.json)
                     v
                 models.py                                            (TargetResult)
                     |
                     v
                reporting/*                                            (presentación)
```

Reglas de diseño que conviene respetar:

- **Cero dependencias en tiempo de ejecución.** Solo la biblioteca estándar de
  Python 3.9+. Los registros TLS, el motor QUIC, el cliente DNS y toda la
  criptografía necesaria para enumerar lo que un servidor ofrece están en el propio
  paquete —no salen de OpenSSL—, así que la misma sonda alcanza a un servidor viejo
  con el que un OpenSSL moderno se negaría a hablar.
- **Datos, no código.** Los algoritmos, las vulnerabilidades, la puntuación, los
  topes y las normativas viven en JSON editable. Si estás escribiendo el nombre de un
  algoritmo dentro de un `.py`, probablemente debería estar en `algorithms.json`. Lo
  que hay que **calcular** —y solo eso— es un plugin.
- **Los renderizadores no juzgan.** Reciben un `TargetResult` ya analizado y solo lo
  presentan. Toda la lógica de nota y veredicto vive en `assessment.py`.
- **Los errores de un objetivo no abortan el escaneo.** `scan_target` captura sus
  propias excepciones y devuelve un resultado con `status=error`, con el motivo, en
  vez de tumbar la ejecución. Un endpoint hostil o roto no se lleva por delante el
  resto del parque.

## Cobertura: dos puertas que no bajan

**Se miden dos cosas por separado, y responden a preguntas distintas.**

| Medición | Cómo | Qué responde | Cifra |
|---|---|---|---|
| Combinada (unit + lab) | `.coveragerc`, `fail_under = 100` | Cuánto del código ejecuta *algún* test | **100 %** |
| Solo el e2e del lab | `tools/e2e_floor.py` | Cuánto se ejecuta **contra servidores TLS de verdad** | **~98 %** (un trinquete por módulo) |

### La primera: 100 %, sin una sola exclusión

`.coveragerc` mide con `--branch` y exige `fail_under = 100`:
**100 % de sentencias y 100 % de ramas**, sin `exclude_also` ni `exclude_lines`. No
hay nada en ese fichero que le diga a coverage que mire hacia otro lado. Una
exclusión es un trozo de código que nadie ha ejecutado nunca, con una nota al lado
que dice que no hay que preocuparse; aquí no las hay, y ese es el objetivo. Un cambio
que deje de ejercitar un camino falla **al momento**, no un año después; bajar el
umbral pide una explicación en el mensaje del commit.

`source` en `.coveragerc` incluye **dos** árboles: el paquete `web_crypto_checker` y
`lab/` (el *runner* del laboratorio, `lab/audit.py`, que es código
y se prueba con la red *mockeada* en `tests/test_lab_audit.py`). Ambos al 100 %.

```bash
pip install coverage        # la única dependencia de desarrollo; la herramienta no tiene ninguna
python3 -m coverage run --branch --source=web_crypto_checker -m unittest discover -s tests -t .
python3 -m coverage report -m
```

La suite unitaria alcanza ese 100 % **sola**, sin Docker ni red:
`tests/fake_tls_server.py` levanta un servidor TLS mínimo y guionizable en
`127.0.0.1` —lee un `ClientHello` y responde con lo que se le diga: un `ServerHello`,
una alerta, un certificado o basura—, para llevar la sonda por todas sus ramas sin
una pila TLS de verdad.

### La segunda: el e2e a solas, un suelo que no baja

La cifra combinada mezcla los tests unitarios (contra dobles y vectores) con la
ejecución del *tool instrumentado dentro del laboratorio*, y `lab/coverage.sh` las
**funde** con `coverage combine` en una sola cifra —el `relative_files = True` de
`.coveragerc` es lo que permite que una corrida en el host y una dentro del
contenedor (donde el árbol vive en `/src`) produzcan los mismos nombres y se
fundan—.

Pero un porcentaje combinado no protege de que el laboratorio deje de ejercitar un
camino: los unitarios lo taparían y el 100 % no se movería. Por eso hay una
**segunda puerta independiente** sobre el e2e del lab **a solas**
(`tools/e2e_floor.py` +
`tests/e2e-coverage-floor.json`). Es un
**trinquete por módulo**: guarda cuántos ítems (sentencias + ramas) deja **sin
cubrir** el e2e hoy, y falla si algún módulo ejerce **menos** que antes.

```bash
( cd lab && docker compose up -d )   # el lab debe estar en pie
./lab/e2e-gate.sh                     # barre, funde con coverage combine, y exige el suelo
./lab/e2e-gate.sh --update            # re-fija el suelo (solo para código genuinamente unit-only)
```

El trinquete solo se **aprieta** solo (una corrida que cubra más) o se **sube a
mano**, y subirlo pide una razón en el commit, exactamente como bajar `fail_under`.
Añadir código que ningún escaneo puede alcanzar (superficie de importación, ramas de
error que solo se simulan) sube legítimamente el conteo sin cubrir de un módulo;
cuando pasa, se re-fija con `--update` y se dice por qué.

**El e2e no llega al 100 %, y no puede.** Hay ramas que **ningún servidor real
produce**: la verificación de firmas con vectores Ed25519/RSA-PSS/ECDSA, `CERT-ROCA`,
DANE/DNSSEC validado hasta la raíz IANA (no se puede forjar la clave de la raíz), la
verificación de SCT contra logs CT conocidos, el oráculo ROBOT positivo, los caminos
de error del parseo ASN.1/wire, y los cifrados que este OpenSSL ya no trae (RC4,
3DES, export, SSLv2). Eso es justo lo que cubren los unitarios; por eso el 100 % es
la **combinada**.

### El laboratorio

`lab/` es un conjunto de servidores web con **posturas conocidas**
en Docker, para probar de punta a punta contra servidores de verdad y no contra
dobles. Tiene dos mitades:

- **Servidores de protocolo** (`lab/docker-compose.yml`): un Caddy (TLS 1.2/1.3,
  HTTP/2, HTTP/3, wss y SSE), un nginx (TLS 1.2/1.3, sin HTTP/3), un backend de eco
  WebSocket y un `grpcbin` (gRPC sobre TLS). Se escanean con SNI `localhost`.
- **Laboratorio de auditoría** (bueno vs. malo): nginx sirviendo cada escenario en su
  puerto —válido, caducado, host equivocado, autofirmado, no confiable, firma SHA-1,
  cabeceras HTTP malas, HTTP en claro— con certificados generados solos por su propia
  CA de laboratorio. `lab/audit.py` escanea cada uno y **comprueba
  el veredicto y los hallazgos esperados**, imprimiendo PASS/FAIL y saliendo con
  código ≠ 0 si algo no cuadra. Es la mejor caza de falsos positivos y negativos.

`lab/e2e.sh` es el barrido completo que alimenta la segunda puerta: ejercita la CLI
por **cada formato** de informe y **cada perfil**, `--compare`/`--history`/`-f`/`-p`,
URLs, sondas `--active`, y monta la infraestructura que los caminos de red necesitan
—una pata DNS con `bind9` para CAA/TLSA/HTTPS, respuestas OCSP/CRL pre-firmadas y
cadena por AIA, endpoints hostiles y malformados para el manejo de error, un
responder QUIC construido con la propia cripto del tool, fixtures DNSSEC
capturados—. El detalle de cada pieza está en el README del lab.

Los tests de integración (`tests/test_lab.py`) **se saltan** si el laboratorio no
está en pie, de modo que la puerta habitual de CI (sin Docker) no se ve afectada.

## Que una línea se ejecute no quiere decir que alguien la mire

Coverage registra que el intérprete pasó por una línea, no que nadie se enteraría si
esa línea hiciera otra cosa. Un 100 % construido con líneas así no protege de nada,
así que hay una segunda pregunta y una herramienta que la responde
(`tools/mutation_gate.py`; su primo por fichero, para
pasadas rápidas a mano, es `tools/mutants.py`):

```bash
python3 tools/mutation_gate.py            # comprobar contra la línea base
python3 tools/mutation_gate.py --update   # anotar lo que sobrevive ahora
python3 tools/mutation_gate.py --only policy   # un módulo, mientras trabajas
```

Rompe el código a propósito, un cambio pequeño cada vez, y ejecuta los tests. Lo que
hace fallar a un test está **muerto**: alguien vigilaba. Lo que nadie nota
**sobrevive**, y es una línea que la suite visita sin mirar.

| El cambio | Y es un fallo de verdad |
|---|---|
| `<` pasa a `<=` | un error de uno en un límite |
| `==` pasa a `!=` | una condición invertida |
| `and` pasa a `or` | una guarda ensanchada |
| `0` pasa a `1` | un valor por defecto cambiado |
| `+` pasa a `-` | un desliz aritmético |
| **desaparece un `raise`** | un error tragado: entrada mala aceptada, política rota cargada, registro malformado leído como si tuviera sentido |
| **un `return` devuelve `None`** | una respuesta olvidada: quien la use se entera, quien la ignore nunca la usó |

Tres decisiones que conviene conocer, todas aprendidas equivocándose:

- **No hay mapa de fichero fuente a módulo de tests.** Cada mutante se enfrenta a la
  **suite entera**. Un mapa es una optimización que falla en la dirección que
  halaga: los vectores de una cifra no tienen por qué vivir en el módulo que lleva su
  nombre, así que un mutante de esa cifra lo juzgarían tests que no la tocan y saldría
  como «no notado». El paralelismo compra la velocidad que el mapa intentaba comprar.
- **El sandbox se compila con `-B`.** Un sandbox se reutiliza entre mutantes, y en un
  sistema de ficheros de *mtime* grueso una edición del mismo tamaño (`==`↔`!=`,
  `+0`↔`-0`, `and`↔`or`, un dígito por otro) deja intactos fecha y tamaño, así que
  CPython correría el `.pyc` viejo y la mutación **nunca se ejecutaría**. `-B` fuerza
  una compilación fresca cada vez.
- **Un superviviente se confirma con la máquina tranquila**, y el laboratorio tiene
  la última palabra: un candidato —algo que la suite unitaria no mató— se le pasa a
  `LabIntegrationTests` antes de escribirlo en la lista, para que «superviviente»
  signifique «no lo caza nada», no «no lo caza la mitad rápida».

Los supervivientes están listados en
`tests/mutation-baseline.json`; la lista **solo
puede encoger**, y el cierre falla en cuanto aparece uno nuevo o en cuanto uno de la
lista pasa a estar cazado (la lista ya no sería cierta). Cada superviviente está
además fijado por una aserción real en los `tests/test_mut_*.py`, cada una verificada
aplicando la mutación exacta con bytecode fresco.

## Ejecutar los tests

```bash
python3 -m unittest discover -s tests -t .     # todo
python3 -m unittest tests.test_assessment -v   # un módulo
python3 -m unittest tests.test_crypto.CurveTests.test_generator_is_on_the_curve
```

No hacen falta dependencias ni red. El inventario de qué prueba cada fichero está en
`tests/README.md`; dos merecen mención:

- **`tests/test_crypto.py`** compara las constantes de las curvas y los primos no
  contra una copia de sí mismas —eso no detectaría nada— sino contra sus **propiedades
  matemáticas**: que el generador está en la curva, que `n·G` es el punto del
  infinito, que los módulos son primos. Una errata en cualquier dígito hace fallar el
  test.
- **`tests/test_coverage_gates.py`** es el guardián de este capítulo: comprueba que
  `.coveragerc` sigue sin exclusiones y con ramas, que el suelo e2e y la base de
  mutación siguen vigentes, y que no hay tests duplicados.

## Dónde vive cada cosa

| | |
|---|---|
| `scanner.py` | El **orquestador**: qué se sondea, en qué orden, y qué se junta. No decide una nota |
| `assessment.py` | El **modelo de nota**: clasifica, calcula la letra, el veredicto y los hallazgos, con topes por condiciones nombradas. **No es ampliable por plugins** |
| `strength.py` | La **fuerza efectiva en bits**: el eslabón más débil entre las clases que el servidor usaría |
| `policy.py` + `data/algorithms.json` | Los **algoritmos, las reglas y los umbrales**: clasifica una versión, una suite, un grupo o una firma |
| `vulnerabilities.py` | El **motor** de las reglas declarativas de vulnerabilidades (`all`/`any`/`not`) |
| `compliance.py` + `data/profiles/` | La **conformidad** con cada normativa, una edición por fichero |
| `plugins/__init__.py` | Qué **es** un plugin: metadatos, tipos de retorno, la `ServerView` de solo lectura que recibe |
| `plugins/runner.py` | Cómo la respuesta de un plugin se convierte en resultado |
| `plugins/builtin/` | Las comprobaciones de serie, una por sujeto |

## Añadir una comprobación

Una comprobación vive en uno de dos sitios, y elegir bien es la mitad del trabajo.

- **Si se decide comparando algo que el servidor anuncia** —un nombre de algoritmo,
  una etiqueta de suite, una versión— es una **regla declarativa** en el JSON, sin
  código: los algoritmos y sus etiquetas en `data/algorithms.json`, y las
  vulnerabilidades como un árbol de condiciones (`all`/`any`/`not`) en el mismo
  fichero. Una normativa es un perfil en `data/profiles/`; ver
  [política de conformidad](politica-normativas.md).
- **Si tiene que *calcular* algo** —factorizar un módulo, restar dos fechas,
  correlacionar dos observaciones— es un **plugin**: ver [plugins](plugins.md), donde
  el contrato completo distingue lo que ve `check(server)` de lo que el *runner* hace
  con su respuesta.

Si dudas, prueba primero con una regla: no ejecuta código, la puede editar quien no
programa y no puede romper un escaneo. Las dos formas se prueban contra el
laboratorio.

## Las reglas de la casa

Cuatro cosas que el sistema garantiza, con un test que falla si se rompen:

1. **Un plugin roto no rompe un escaneo.** Lo que lance se captura y se informa como
   un hallazgo que lo nombra.
2. **Ningún plugin cambia la nota.** Recibe una `ServerView` de solo lectura de lo
   *observado* —nunca la puntuación, la nota ni el veredicto— y su resultado se añade
   **después** de puntuar. Un test escanea con todos los plugins y sin ninguno y
   exige que `score`, `grade` y `verdict` coincidan.
3. **No mirar no es no encontrar.** Si una comprobación no se pudo hacer, se dice
   (*no evaluado*); nunca se informa como «no afectado» ni como *pass*.
4. **Ninguna vulnerabilidad tiene trato de favor.** Renombrar una no cambia el
   análisis ni ninguno de los ocho informes, y ningún campo de la política pertenece
   a una sola entrada (`tests/test_no_privileged_vulnerability.py`).

## Añadir un formato de salida

Crear `reporting/mi_formato.py` con una función `render` y registrarlo en `FORMATS` y
`EXTENSIONS` de [`reporting/__init__.py`](../../web_crypto_checker/reporting/__init__.py).
Hay dos firmas a propósito: los formatos **humanos** (`console`, `text`, `html`)
reciben `(report, translator)` y se traducen al idioma del que escanea; los formatos
**máquina** (`json`, `csv`, `sarif`, `inventory`, `openmetrics`) reciben `(report)` y
mantienen sus claves y valores en inglés, porque son un contrato para otras
herramientas, no prosa para personas. Los tests de contrato en
`tests/test_reporting.py` recogen el formato nuevo automáticamente y exigen que
ninguno diga algo distinto del mismo escaneo.

## Estilo

```bash
pip install -e '.[dev]'
ruff check . && ruff format --check .
mypy web_crypto_checker
```

Líneas de 100 columnas, anotaciones de tipo en todas las funciones públicas,
`from __future__ import annotations` en todos los módulos (compatibilidad con Python
3.9, el intérprete más viejo que se declara soportar y que `tests/test_portability.py`
comprueba de verdad).

## La integración continua

`.gitlab-ci.yml` tiene tres etapas —`test`, `lint`, `package`— y
ocho trabajos:

| Trabajo | Qué hace |
|---|---|
| `tests` | La suite completa con cobertura, `fail_under = 100` |
| `tests:python3.9` | La misma suite en el intérprete más viejo soportado |
| `coverage:gates` | Los trinquetes: `.coveragerc` sin exclusiones, el suelo e2e y la base de mutación, y el propio cierre. Cuesta segundos, corre **en cada push** |
| `coverage:mutation` | El testing de mutación del paquete entero contra su base |
| `coverage:lab` | Levanta el laboratorio y hace **las dos** mediciones (la combinada al 100 % y el suelo e2e); son muchos contenedores, así que corre a mano o por planificación. Comparte guión con `make ci-lab` vía `lab/ci-lab.sh` |
| `lint` | `ruff` + `mypy` |
| `package` | Construye *wheel* y *sdist* y comprueba el *console script* |
| `release:dist` | La distribución pública, empaquetada por `tools/release.py`, que queda **fuera** del código cubierto (por eso no entra en la puerta del 100 %) |
