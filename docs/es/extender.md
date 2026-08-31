# `docs/` — manuales para extender la herramienta

El [README principal](README.md) explica cómo **usar** webServerCryptoChecker.

Hay dos subdirectorios:

- [`estandares/`](../estandares/README.md) — los documentos oficiales (NIST, BSI,
  BOE, ANSSI, IETF…) de los que salen los perfiles de conformidad, descargados
  de la web de su editor, con la URL de origen y la huella de cada uno.
- [`en/`](../en/README.md) — la documentación de usuario en inglés: el manual y
  estas mismas guías, traducidos, con el mismo nombre de fichero. Cada guía es
  **bilingüe**.

Estos manuales explican cómo **extenderlo**, y están escritos para que alguien
que no conoce el código pueda escribir un plugin o una política leyendo solo
esto.

> **¿Solo quieres entender por qué tu servidor sacó esa nota?** No necesitas
> ninguno de estos manuales: [`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md)
> es el sistema de puntuación completo y público, con un ejemplo calculado
> paso a paso.

| Quieres… | Entonces | Manual |
|---|---|---|
| Cambiar qué algoritmos son buenos o malos, o qué nota saca cada cosa | Una **política**. No se toca Python. | [`politica-algoritmos.md`](politica-algoritmos.md) |
| Detectar una vulnerabilidad conocida nueva | Casi siempre una **política**; solo si la detección necesita cálculo, un plugin. | [`politica-vulnerabilidades.md`](politica-vulnerabilidades.md) |
| Comprobar la capa HTTP o el comportamiento TLS | Una **comprobación** en código. | [`politica-configuracion.md`](politica-configuracion.md) |
| Medir contra una normativa (propia o publicada) | Una **política de normativa**. | [`politica-normativas.md`](politica-normativas.md) |
| Cambiar cómo se calcula la nota | Una **política**. | [`politica-puntuacion.md`](politica-puntuacion.md) |
| Comprobar algo que requiere **código**: aritmética, correlación, un formato que hay que analizar | Un **plugin**. | [`plugins.md`](plugins.md) |

> **La regla, en una frase:** si lo que quieres decir se puede escribir como un
> dato, escríbelo como un dato. El fichero de política se edita sin desplegar
> nada; un plugin hay que desplegarlo.

## Manuales de plugins

| Fichero | De qué trata |
|---|---|
| [`plugins.md`](plugins.md) | **Empieza aquí.** El contrato común a los dos tipos: dónde van los ficheros, qué metadatos hacen falta, qué recibe tu función, qué puede devolver, qué **no** puede hacer un plugin, y cómo probarlo. |
| [`plugin-check.md`](plugin-check.md) | Tipo `check`: mira **un** servidor —su TLS, su certificado, su capa HTTP—. Es el caso más común. |
| [`plugin-fleet.md`](plugin-fleet.md) | Tipo `fleet`: mira **todos** los servidores del escaneo a la vez, para lo que solo se ve comparando (un certificado compartido). |
| [`plugin-vulnerability.md`](plugin-vulnerability.md) | Tipo `vulnerability`: una vulnerabilidad conocida cuya detección no cabe en el fichero de política. |

## Manuales de políticas

| Fichero | De qué trata |
|---|---|
| [`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md) | **El sistema de puntuación, entero y público.** Cómo se llega de lo que ofrece un servidor a una letra, por qué pesa cada cosa lo que pesa, y la regla que impide que la nota y el veredicto se contradigan. |
| [`politicas.md`](politicas.md) | **Empieza aquí.** Qué es el fichero de política, dónde se busca, y las cosas que se pueden escribir en él. |
| [`politica-algoritmos.md`](politica-algoritmos.md) | Las clases de algoritmo (protocolos, suites de cifrado, grupos, firmas, certificado), sus categorías y las etiquetas de las suites. |
| [`politica-vulnerabilidades.md`](politica-vulnerabilidades.md) | La gramática de detección: por protocolo, por etiqueta de suite, y cómo se combinan. |
| [`politica-configuracion.md`](politica-configuracion.md) | Las comprobaciones que no son categorías de algoritmo: la capa HTTP (HSTS, CSP, cookies…), el comportamiento TLS y la higiene del certificado. |
| [`politica-puntuacion.md`](politica-puntuacion.md) | Pesos, escala de notas, **topes de nota** y bandas de fuerza de seguridad. |
| [`politica-normativas.md`](politica-normativas.md) | Perfiles de conformidad: los dos tipos, y una edición por fichero. |

## Uso avanzado y desarrollo

| Fichero | De qué trata |
|---|---|
| [`uso-avanzado.md`](uso-avanzado.md) | Comparar con un escaneo anterior, el fichero de inventario, mTLS, los controles en DNS (CAA, DANE/TLSA), el histórico y las sondas activas. |
| [`desarrollo.md`](desarrollo.md) | La estructura del código, la cobertura end-to-end y sus dos cierres, el *testing* de mutación, cómo añadir una comprobación o un formato de salida, y el estilo. |

## Auditoría

| Fichero | De qué trata |
|---|---|
| [`auditoria-integridad.md`](auditoria-integridad.md) | **¿Todo lo que afirma la herramienta sale de un documento?** Auditoría (2026-08-28) de los 14 perfiles y de la política base `algorithms.json` contra los documentos de `estandares/`: qué está respaldado, qué es metodología propia declarada (la puntuación), y el único hueco encontrado —3 vulnerabilidades sin `references`—. |
