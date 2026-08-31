# Cómo se calcula la nota

Volver al [manual](README.md) · relacionado: [puntuación y topes](politica-puntuacion.md) ·
[fichero de política](politicas.md) · [English](../en/como-se-calcula-la-nota.md).

Este documento es **el sistema de puntuación completo y público**. No hay nada
oculto: todos los números salen del fichero de política
[`web_crypto_checker/data/algorithms.json`](../../web_crypto_checker/data/algorithms.json),
que se puede leer y cambiar.

Si lo que quieres es **cambiar** esos números, ve a
[`politica-puntuacion.md`](politica-puntuacion.md). Esto explica **cómo
funciona** y **por qué**, que es lo que necesita alguien a quien le acaba de
llegar una C y quiere saber si es justa.

## De dónde salen estos números (y de dónde no)

Conviene separar dos cosas, porque tienen orígenes distintos:

- **Qué algoritmo es bueno o malo** — que TLS 1.0 sea *weak* o que un cifrado
  AEAD sea *recommended* — **sale de documentos**: Mozilla Server Side TLS,
  NIST SP 800-52 Rev. 2, IETF BCP 195 (RFC 9325), la retirada de TLS 1.0/1.1
  por el RFC 8996, POODLE para SSL 3.0, DROWN para SSL 2.0. Cada protocolo,
  grupo o firma lo dice en su `note` dentro del fichero, y el bloque `metadata`
  cita las referencias de la política.
- **Cómo esos juicios se convierten en una letra** — los pesos por clase
  (protocolo, cifrado y certificado 3; grupo 2; firma 1), la escala de notas
  (A+…F, con una E entre medias) y los topes— **es criterio propio de esta
  herramienta**, no está tomado de ningún documento externo. Es una
  metodología: legítima, pero una **elección**. Por eso está escrita entera
  aquí y justificada, para poder discutirla o cambiarla, no para confundirla
  con un requisito documentado.

La única cifra de puntuación que **sí** sale de un documento son las **bandas de
fuerza en bits**: son las de NIST SP 800-57 Part 1 Rev. 5. Los **nombres** de
esas bandas (rota, heredada, transitoria, aceptable, fuerte, máxima) son
presentación propia.

---

## Dos respuestas, no una

La herramienta da **dos cosas distintas** sobre cada servidor y conviene no
confundirlas:

| | Qué es | Para qué sirve |
|---|---|---|
| **La nota** (`A+` … `F`) | Un número comprimido en una letra. | Comparar, seguir en el tiempo, poner en un panel. |
| **El veredicto** (`secure`, `acceptable`, `weak`, `insecure`) | Un juicio sobre el estado. | Decidir si hay que actuar. |

Se calculan por caminos distintos a propósito: **un promedio alto no borra una
cosa rota**. La nota es una media ponderada; el veredicto es la peor categoría
que el servidor ofrece, sin promediar.

No pueden, aun así, contradecirse en lo peor: ofrecer algo `insecure` deja la
clase en la categoría `insecure`, lo que **a la vez** fija el veredicto en
`insecure` y dispara el tope `any_insecure_offered`, que baja la nota a `F`. Es
la misma condición mirada dos veces, así que letra y palabra coinciden cuando
más importa.

### La tabla de veredictos

| Veredicto | Cuándo |
|---|---|
| `secure` | Lo peor que ofrece es `recommended`. |
| `acceptable` | Lo peor es `acceptable`: nada débil ni inseguro, pero algo mejorable. |
| `weak` | Ofrece algo de categoría `weak`. |
| `insecure` | Ofrece algo de categoría `insecure`. |
| `unknown` | Se alcanzó el servidor pero la política no reconoce **nada** de lo que ofrece. |
| `error` | No se pudo escanear. |

Sobre `unknown`: si la política no clasifica ningún algoritmo del servidor, la
herramienta **no inventa una nota**. Devuelve `score` y `grade` a `null` y marca
el veredicto como `unknown`. Dar una `F` haría pensar que el servidor es
inseguro, y una `A` que es correcto; ninguna está respaldada por la evidencia.

Hay además dos casos que fuerzan `insecure` pase lo que pase: un transporte
**en claro** (HTTP sin cifrar) manda la nota a `0`/`F` y el veredicto a
`insecure` sin más aritmética, y un **certificado alternativo** que un
navegador rechaza también deja el veredicto en `insecure`.

---

## Los pasos

El cálculo es directo: categoría → peor miembro por clase → media ponderada →
letra → topes. **No hay una fase de modificadores** que sume o reste puntos
sueltos; lo que un servidor pierde por un hecho grave lo deciden los topes.

### 1. Cada algoritmo recibe una categoría

De las listas del fichero de política. Cada categoría vale unos puntos:

| Categoría | Puntos |
|---|---|
| `recommended` | 100 |
| `acceptable` | 80 |
| `weak` | 40 |
| `insecure` | 0 |
| `informational` | *no puntúa* |
| `unknown` | *no puntúa* |

**`unknown` no penaliza**, y es deliberado: los servidores ofrecen nombres que
nadie ha catalogado continuamente, y castigar por ellos trataría igual a quien
usa algo nuevo y bueno que a quien usa algo raro y malo. Sale en el informe como
«sin clasificar» para que alguien lo mire.

### 2. Cada clase se puntúa por **su peor miembro**

```
puntuación de la clase = mínimo de las puntuaciones de lo que ofrece
```

No es la media, y esto es lo que más sorprende. La razón es el propio protocolo:
**quien elige el algoritmo es el cliente**, entre los que el servidor ofrece. Un
servidor con doce cifrados excelentes y uno roto puede ser llevado al roto por
cualquier cliente mal configurado — o por quien esté en medio. Ofrecerlo es
permitirlo.

Las clases de TLS son las versiones de **protocolo**, las **suites de cifrado**,
los **grupos** de intercambio de claves, los **algoritmos de firma** y el
**certificado**. Una suite de cifrado se clasifica por sus **etiquetas de forma**
(`3des`, `cbc`, `rc4`, `aead`, `no-forward-secrecy`…) y se queda con la peor. El
certificado se juzga como un objeto único: la peor categoría entre la **fuerza de
su clave** y su **algoritmo de firma**.

### 3. Las clases se combinan con sus pesos

```json
"class_weights": { "protocol": 3, "cipher": 3, "certificate": 3, "group": 2, "signature": 1 }
```

```
base = Σ (puntuación de la clase × peso) / Σ pesos
```

No tienen que sumar nada en concreto; se normalizan dividiendo por la suma de los
pesos presentes. Una clase que no produce una categoría puntuable **sale del
divisor**: ni suma ni resta.

Un matiz honesto: las clases que hoy llevan una categoría que **mueve la letra**
son el protocolo, las suites de cifrado y el certificado. Los grupos de
intercambio y los algoritmos de firma se clasifican y se muestran en el informe,
alimentan la **fuerza de seguridad efectiva** y las **normativas de conformidad**,
y sus pesos están declarados en el fichero; el cálculo de la nota pondera hoy las
tres primeras clases.

### 4. El número se convierte en letra, y luego bajan los topes

```json
"grades": [
  {"min": 95, "grade": "A+"}, {"min": 90, "grade": "A"}, {"min": 80, "grade": "B"},
  {"min": 70, "grade": "C"}, {"min": 60, "grade": "D"}, {"min": 50, "grade": "E"},
  {"min": 0, "grade": "F"}
]
```

| Nota | Desde |
|---|---|
| `A+` | 95 |
| `A` | 90 |
| `B` | 80 |
| `C` | 70 |
| `D` | 60 |
| `E` | 50 |
| `F` | 0 |

Y después, **los topes**: condiciones que ponen un techo pase lo que pase con el
número.

| Si… | La nota no puede pasar de |
|---|---|
| Ofrece algo `insecure` (`any_insecure_offered`) | `F` |
| Habla SSL 2.0 (`sslv2_supported`) | `F` |
| Habla SSL 3.0 (`sslv3_supported`) | `F` |
| No ofrece TLS 1.2 ni 1.3 (`no_tls12_or_higher`) | `F` |
| Ofrece TLS 1.0 o 1.1 (`weak_protocol_supported`) | `C` |
| El certificado es inválido (`certificate_invalid`) | `F` |
| El certificado es autofirmado (`self_signed`) | `C` |

Los topes existen porque **un promedio miente**. Un servidor con veinte cosas
excelentes y una rota tiene una media muy buena y un problema muy grave.

> `certificate_invalid` cubre un abanico: caducado o aún no válido, el nombre no
> coincide, la cadena no llega a una raíz de confianza, el propósito del
> certificado no autoriza `serverAuth`, está revocado, la firma no verifica o la
> clave es vulnerable a ROCA. Cualquiera de ellos hace que un navegador rechace
> el certificado, así que la clase pasa a `insecure` y la nota a `F`.

Las vulnerabilidades conocidas (DROWN, POODLE, Sweet32, RC4, FREAK/Logjam,
BEAST…) se detectan y salen como **hallazgos** con su severidad, pero **no ponen
un tope por sí mismas**: lo que las castiga es la categoría del algoritmo o del
protocolo que las hace posibles, que ya está en las listas.

---

## Un ejemplo completo, calculado de verdad

Un servidor solo con TLS 1.2, que entre sus cifrados ofrece una suite 3DES, con
un certificado RSA de 2048 bits firmado con SHA-256:

```
clases:  protocol 80   cipher 40   certificate 100
pesos:   protocol  3   cipher  3   certificate   3

base = (80×3 + 40×3 + 100×3) / (3 + 3 + 3) = 660 / 9 = 73

73 está en la banda de C (≥ 70)
topes: ninguno se dispara (3DES es 'weak', no 'insecure', y no hay tope de débiles)
nota: C          veredicto: weak
```

Fíjate en que **la suite 3DES vale 40 y arrastra toda la clase de cifrado a 40**,
aunque el servidor ofrezca además cifrados AEAD perfectos. Ese es el paso 2, y es
el que más nota cuesta. El veredicto es `weak` porque `weak` es lo peor que hay
en la mesa; la nota se queda en C, no porque un tope la baje, sino porque la
media ya cae ahí.

Cambia un detalle y verás los topes morder:

- Si el mismo servidor **también hablara TLS 1.0**, `weak_protocol_supported`
  fijaría el techo en `C` — justo donde ya estaba.
- Si ofreciera una suite **RC4 o NULL**, esa clase de cifrado sería `insecure`
  (0 puntos), `any_insecure_offered` bajaría la nota a `F` y el veredicto pasaría
  a `insecure`.

Puedes reproducirlo con:

```bash
web-crypto-checker example.com --format json -o informe.json
```

El objeto `score_breakdown` del JSON trae las puntuaciones por clase
(`class_scores`), los pesos (`class_weights`), la base (`base_score`) y los topes
aplicados (`applied_caps`). **No hay aritmética que la herramienta no enseñe.**

---

## Qué hacer si no estás de acuerdo

Los números no son sagrados: son un fichero. La herramienta carga
[`web_crypto_checker/data/algorithms.json`](../../web_crypto_checker/data/algorithms.json)
y no hay una fase de modificadores ni una capa oculta; edita ahí
`scoring.class_weights`, `scoring.grades` o `scoring.grade_caps` y vuelve a
escanear.

Si tu organización considera que la firma debería pesar más, o que TLS 1.1 no
debería quedarse en C, cámbialo y documenta por qué. Lo único que no conviene es
cambiarlo a mitad de una serie histórica sin volver a escanear el parque: las
notas dejarían de ser comparables entre sí. El cómo se edita, con qué reglas y
qué comprueba el cargador está en [`politica-puntuacion.md`](politica-puntuacion.md)
y [`politicas.md`](politicas.md).
