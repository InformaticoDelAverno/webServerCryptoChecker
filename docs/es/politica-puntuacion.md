# Manual de política — puntuación, notas y topes

Volver al [manual](README.md) · relacionado: [cómo se calcula la nota](como-se-calcula-la-nota.md) ·
[fichero de política](politicas.md) · [English](../en/politica-puntuacion.md).

> Antes de esto, lee [`politicas.md`](politicas.md).

Aquí se decide **qué nota saca un servidor**. Es la parte con más consecuencias
del fichero: cambiar un peso cambia todos los informes.

---

## Cómo se calcula, en orden

1. **Cada clase saca una puntuación** a partir de las categorías de lo que el
   servidor ofrece, tomada en su **peor miembro**.
2. **Se combinan con los pesos** de `class_weights`.
3. **El número resultante se convierte en nota** con la escala de `grades`.
4. **Se aplican los topes**: una condición de `grade_caps` puede bajar la nota
   por mucho que el número diga otra cosa.

No hay un paso de **modificadores**: esta política no suma ni resta puntos
sueltos por hechos aislados. Lo que un servidor pierde por algo grave lo deciden
los topes. El veredicto (`secure`, `acceptable`, `weak`, `insecure`) se decide
**aparte** del número, a partir de la peor categoría ofrecida.

---

## Los pesos

```json
"class_weights": { "protocol": 3, "cipher": 3, "certificate": 3, "group": 2, "signature": 1 }
```

No tienen que sumar 100; se normalizan dividiendo por la suma de los pesos de las
clases que realmente puntúan. Una clase sin categoría puntuable sale del divisor.

Hoy las clases que llevan una categoría que **mueve la letra** son el
**protocolo**, las **suites de cifrado** y el **certificado**. Los **grupos** de
intercambio y las **firmas** se clasifican y se muestran, alimentan la fuerza de
seguridad efectiva y las normativas, y sus pesos están declarados en el fichero.

---

## La escala de notas

```json
"grades": [
  {"min": 95, "grade": "A+"},
  {"min": 90, "grade": "A"},
  {"min": 80, "grade": "B"},
  {"min": 70, "grade": "C"},
  {"min": 60, "grade": "D"},
  {"min": 50, "grade": "E"},
  {"min":  0, "grade": "F"}
]
```

Se recorre de arriba abajo y gana la primera cuyo `min` se alcanza. La lista **no
puede estar vacía**: sin escala no hay nota, y el cargador lo rechaza con
`policy has no grade scale`. A diferencia de otras herramientas, aquí una nota es
solo su umbral: no hay condiciones extra que cumplir para un `A+`.

---

## Los topes de nota

Un tope dice: **pase lo que pase con el número, esta nota no puede subir de ahí.**
Es un diccionario de condición → nota máxima:

```json
"grade_caps": {
  "any_insecure_offered": "F",
  "sslv2_supported": "F",
  "sslv3_supported": "F",
  "no_tls12_or_higher": "F",
  "weak_protocol_supported": "C",
  "certificate_invalid": "F",
  "self_signed": "C"
}
```

Existen porque un promedio miente. Un servidor con muchas cosas excelentes y una
rota tiene un promedio muy bueno y un problema muy grave. El tope corta esa
aritmética.

### Las condiciones

| Condición | Se cumple cuando |
|---|---|
| `any_insecure_offered` | Alguna clase evaluada queda en categoría `insecure`. |
| `sslv2_supported` | El servidor habla SSL 2.0. |
| `sslv3_supported` | El servidor habla SSL 3.0. |
| `no_tls12_or_higher` | No admite ni TLS 1.2 ni TLS 1.3. |
| `weak_protocol_supported` | Admite TLS 1.0 o TLS 1.1. |
| `certificate_invalid` | El certificado es inválido: caducado o aún no válido, el nombre no coincide, la cadena no llega a una raíz de confianza, el propósito no autoriza `serverAuth`, revocado, la firma no verifica o vulnerable a ROCA. |
| `self_signed` | El certificado es autofirmado. |

Cada condición solo muerde si su clave está en `grade_caps` con una nota máxima.
Cambiar el techo de una es cambiar su valor; borrar la clave es desactivar el
tope. Las vulnerabilidades no tienen un tope propio: se informan como hallazgos y
lo que las castiga es la categoría del algoritmo o del protocolo que las permite.

---

## Fuerza de seguridad efectiva

Aparte de la nota, la herramienta informa de **cuántos bits de seguridad
efectivos** tiene la conexión: el eslabón más débil de la cadena, el mínimo entre
las clases que llevan bits (cifrado, grupo, firma y clave del certificado). El
protocolo y la compresión no llevan bits y no entran.

```json
"security_strength": {
  "reference": "NIST SP 800-57 Part 1 Rev. 5",
  "symmetric": [ ["AES_256", 256], ["AES_128", 128], ["CHACHA20", 256], ["3DES", 112], ["RC4", 38], ["DES", 56], ["NULL", 0] ],
  "hash":      [ ["sha512", 256], ["sha384", 192], ["sha256", 128], ["sha224", 112], ["ed25519", 128], ["ed448", 224], ["sha1", 80], ["md5", 0] ],
  "asymmetric": {
    "rsa_thresholds": [[0, 0], [1024, 80], [2048, 112], [3072, 128], [7680, 192], [15360, 256]],
    "ec_divisor": 2,
    "named": {"Ed25519": 128, "Ed448": 224}
  },
  "levels": [ ... ]
}
```

- **`symmetric`** y **`hash`** son pares `palabra → bits` que se buscan en orden
  (lo más específico primero) dentro del nombre de la suite y del esquema de
  firma. El primero que aparece manda.
- **`asymmetric`** traduce la clave del certificado a bits: una curva con nombre
  (`named`), un campo EC dividido por `ec_divisor`, o un módulo RSA/DH por el
  mayor umbral de `rsa_thresholds` que no lo supere.
- **`levels`** son las bandas con las que se etiqueta el resultado; gana la más
  alta cuyo `min_bits` se alcanza.

| Banda | Desde | Qué significa |
|---|---|---|
| `broken` (rota) | 0 | Menos de 80 bits; sin protección real. |
| `legacy` (heredada) | 80 | 80 bits; NIST la prohíbe desde 2013. |
| `transitional` (transitoria) | 112 | 112 bits; aceptable hasta 2030 (NIST SP 800-57). |
| `acceptable` (aceptable) | 128 | 128 bits; la referencia moderna. |
| `strong` (fuerte) | 192 | 192 bits. |
| `top` (máxima) | 256 | 256 bits. |

Volver a ajustar cualquiera de estos números vuelve a ajustar el informe sin
tocar código.

---

## Antes de tocar nada de esto

Cambiar los pesos o los topes cambia **todos** los informes que produzcas, y los
históricos dejarán de ser comparables. Si mantienes una serie temporal:

1. Cambia la política en
   [`web_crypto_checker/data/algorithms.json`](../../web_crypto_checker/data/algorithms.json).
2. Vuelve a escanear el parque entero con la nueva.
3. Empieza la serie desde ahí, y anota por qué.

Y compruébalo escaneando: un fichero que no cuadra falla al cargar, y uno que
cuadra refleja ya el criterio nuevo.

```bash
web-crypto-checker example.com --format json -o prueba.json
```
