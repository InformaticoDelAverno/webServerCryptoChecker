# Manual de uso avanzado

Volver al [manual](README.md) · relacionado: [desarrollo](desarrollo.md) ·
[plugins](plugins.md) · [política de conformidad](politica-normativas.md) ·
[English](../en/uso-avanzado.md).

> Cada opción tiene además su ejemplo en el «Recetario» del [README](README.md).

Lo básico —un objetivo, una nota, un informe— está en el README. Aquí vive lo que
no se usa el primer día: comparar contra una auditoría anterior, escanear un parque
desde un fichero, y lo que la herramienta comprueba **sola** sin que nadie se lo
pida —mTLS, los controles que viven en DNS, la confianza del certificado— más las
sondas que solo se disparan **con permiso**.

## Comparar con un escaneo anterior

Un informe dice cómo está un servidor hoy. Lo que normalmente hace falta saber es
**qué ha cambiado**: qué apareció desde la última auditoría, qué se arregló y qué
empeoró en silencio tras una actualización de paquetes que nadie anunció.

`--compare` toma un informe JSON anterior como línea base
([`compare.py`](../../web_crypto_checker/compare.py)):

```bash
# Guardar la línea base
web-crypto-checker -f inventario.txt --format json -o base.json

# ... semanas después ...
web-crypto-checker -f inventario.txt --compare base.json
```

```
Changes since the baseline:
  example.com:443@192.0.2.10: regressed, grade A -> C
  example.com:443@192.0.2.10: NEW finding HTTP-MIXED-ACTIVE
  example.com:443@192.0.2.10: NEW vulnerability SWEET32
  example.com:443@192.0.2.10: now offers cipher TLS_RSA_WITH_3DES_EDE_CBC_SHA
  example.com:443@192.0.2.10: no longer offers protocol TLS 1.3
  example.com:443@192.0.2.10: certificate changed 4f2a… -> 9b71…
```

Se informa de, para cada endpoint (identificado por `host:puerto@dirección`):

- **Movimiento de nota**, indicando si mejoró o empeoró.
- **Hallazgos y vulnerabilidades nuevos y resueltos**, por **identificador**, no
  por texto: un hallazgo que reaparece no se confunde con uno nuevo, y cambiar la
  redacción de un mensaje no ensucia la comparación.
- **Algoritmos añadidos y retirados**, por clase (protocolo, cifrado…).
- **Cambio de la huella del certificado de hoja**: en un servidor que nadie
  reemitió, una huella nueva es motivo para parar y averiguar por qué. Cuenta como
  un cambio digno de una línea, pero **no** como una regresión por sí solo.
- **Endpoints nuevos** (`new endpoint`) y **endpoints que estaban en la base y ya
  no aparecen** (`gone from the scan`).

Un hallazgo o una vulnerabilidad **nuevos** marcan la comparación como
**regresión**; una nota que baja también. La comparación se hace sobre el JSON, así
que la línea base puede ser un artefacto guardado de una ejecución anterior de CI:
la herramienta no necesita almacenar nada, y `load_baseline` acepta tanto el JSON
«pelado» como uno envuelto en `{"report": …}`.

Con `--fail-on-regression` el proceso termina con **código 1** si algún endpoint
empeoró, aunque su estado absoluto siga siendo aceptable. Es la diferencia entre
«esto no cumple» y «esto ha empeorado», y en un parque grande la segunda es la que
se detecta a tiempo:

```yaml
# .gitlab-ci.yml — fallar el pipeline si algún servidor retrocede
web-audit:
  script:
    - web-crypto-checker -f inventario.txt --format json -o informe.json
                         --compare base.json --fail-on-regression
```

### Histórico: la serie, no solo el salto

`--compare` responde a «qué ha cambiado desde ese informe». Lo que no puede
responder es «desde cuándo pasa esto», porque una línea base es un solo punto.
`--history` acumula cada escaneo en un fichero —una línea JSON por endpoint y
ejecución— y, al terminar, muestra la **serie de notas** de cada endpoint del
escaneo actual ([`history.py`](../../web_crypto_checker/history.py)):

```bash
web-crypto-checker -f inventario.txt --history historico.jsonl
```

```
Grade history:
  web01.example.com [192.0.2.10]: A -> A -> B
  web02.example.com [192.0.2.11]: A+ -> A+ -> A+
  api.example.com [192.0.2.20]: C -> B -> A
```

Es **JSON Lines** y no un array, porque añadir a un array obliga a reescribir el
fichero entero, y un escaneo interrumpido a mitad de esa reescritura te deja **sin
histórico**. Cada línea guarda lo justo —momento, objetivo, IP, nota, puntuación,
veredicto y número de vulnerabilidades— para dibujar la tendencia sin arrastrar el
informe completo. `--history` y `--compare` son primos: usa el primero para vigilar
la deriva de todo el parque a lo largo del tiempo, y el segundo para el diff exacto
contra un punto concreto.

---

## Fichero de inventario y entrada estándar

Un objetivo por línea ([`targets.py`](../../web_crypto_checker/targets.py)). `#` inicia
un comentario. Lo que siga al primer token separado por espacios se usa como
**etiqueta** en el informe (hay un inventario de ejemplo listo para copiar en
[`examples/`](../../examples/README.md)):

```
# Inventario de producción
web01.example.com            frontend web
web02.example.com:8443       frontend web (puerto alterno)
https://api.example.com/health   API con ruta concreta
192.0.2.10                   base de datos
[2001:db8::1]:443            router de borde
example.com                  # solo comentario, sin etiqueta
```

```bash
web-crypto-checker -f inventario.txt
```

Se puede leer de la entrada estándar con `-f -`, que encaja con cualquier tubería
que produzca nombres de host:

```bash
awk '$1=="server_name"{print $2}' /etc/nginx/sites-enabled/*.conf \
    | web-crypto-checker -f -
```

Las formas de nombrar un objetivo —nombre, `host:puerto`, URL con esquema y ruta,
IPv4, IPv6 con o sin corchetes, `usuario@host` (el usuario se ignora)— son las
mismas en el fichero que en la línea de órdenes. Tres detalles que conviene
conocer:

- **`-f` se puede repetir** y se mezcla con los objetivos sueltos de la línea de
  órdenes; todo se junta en una sola lista.
- **Los duplicados se eliminan** (mismo host —sin distinguir mayúsculas— y mismo
  puerto), conservando la primera aparición para que su etiqueta y su ruta
  sobrevivan.
- **Una línea mal formada no aborta el fichero**: se avisa por `stderr` y se
  continúa, de modo que un inventario largo se escanea entero aunque una línea esté
  rota.

### Un host, varios puertos

Un host **sin puerto propio** se expande a **cada puerto de `-p`**, así que
«un host, varios puertos» produce un objetivo por puerto. Un host que trae su propio
puerto (`example.com:8443`) no se expande.

```bash
# Escanea el 443 y el 8443 de cada host que no nombre puerto
web-crypto-checker -f inventario.txt -p 443,8443
```

El **SNI** por defecto es el nombre del host; a una IP pelada no se le manda SNI
(RFC 6066 lo prohíbe), y `--sni NOMBRE` fuerza uno —lo que lleva a la sección
siguiente.

---

## Detrás de un balanceador o una CDN: una IP por dirección

Un dominio tras un balanceador o una CDN puede estar **configurado de forma
distinta en cada máquina** que responde. Por eso un objetivo no se resuelve a «una»
dirección: la herramienta resuelve **todas** las direcciones del host —IPv4 e IPv6—
y produce **un resultado por dirección**, como hacen SSL Labs o sslyze
([`scanner.py`](../../web_crypto_checker/scanner.py)). El SNI que viaja por el cable
sigue siendo el nombre del host, responda la dirección que responda, así que cada
copia detrás del balanceador se juzga por separado sin engañar a la negociación.

Cuando quieras auditar una máquina **concreta** por su dirección —el nodo que
sospechas que quedó sin actualizar— pásala como IP y **fuerza el SNI** con `--sni`,
porque una IP pelada no lo lleva y un servidor con *name-based virtual hosting*
presentaría el certificado equivocado (o ninguno):

```bash
# La dirección exacta, pero con el nombre que el servidor espera en el SNI
web-crypto-checker 192.0.2.10 --sni example.com
web-crypto-checker '[2001:db8::1]:443' --sni example.com
```

Es el análogo web de «saltar por un intermediario»: aquí no hay cliente ni túnel
que configurar —la herramienta abre sus propios *sockets*—, lo que hace falta es
**apuntar a la dirección correcta con el nombre correcto**.

---

## mTLS: autenticación por certificado de cliente

Un servidor que autentica a sus clientes con certificados manda un
`CertificateRequest` durante el *handshake*. La herramienta lo detecta **sola**, sin
opción que activar, en todo escaneo `https`
([`application/mtls.py`](../../web_crypto_checker/application/mtls.py)), y distingue dos
cosas que no son lo mismo:

| Estado | Qué significa |
|---|---|
| **Solicitado** (`requested`) | El servidor **pide** un certificado de cliente, pero completa el *handshake* sin él |
| **Exigido** (`required`) | El servidor **rechaza** con una alerta el *handshake* que se termina con un certificado vacío |

Saber cuál de los dos es importa: un servidor que «solicita» pero no «exige» deja
pasar a un cliente anónimo, que casi nunca es lo que su administrador cree haber
configurado. La sonda lo averigua **sin credenciales**: termina el *handshake* con
un certificado vacío y observa si el servidor lo acepta o lo rechaza. Funciona tanto
en TLS 1.3 —donde ambas cosas salen de un único *handshake*— como en TLS 1.2 —donde
el `CertificateRequest` viaja en claro en el primer *flight* del servidor—, así que
la exigencia se determina en cualquiera de las dos versiones. Un objetivo `http://`
no negocia certificados y no se sondea.

---

## Los controles que viven en DNS: CAA, DANE/TLSA y HTTPS/SVCB

No todo lo que protege un certificado está en el *handshake*. Tres controles viven
en **DNS**, y `getaddrinfo` no llega a ellos, así que la herramienta trae un
**cliente DNS propio** ([`dns.py`](../../web_crypto_checker/dns.py)) que arma cada
consulta a mano. También son **automáticos**: se comprueban en todo objetivo que
tenga un dominio (una IP pelada no tiene, y no se consulta).

| Control | RFC | Qué es |
|---|---|---|
| **CAA** | 8659 | Qué autoridades puede autorizar el dominio a **emitir** para él |
| **DANE/TLSA** | 6698 | El *pin* del certificado o la clave, en `_<puerto>._tcp.<host>` |
| **HTTPS/SVCB** | 9460 | El **ALPN**, el puerto alternativo y si el dominio publica **ECH** (SNI cifrado) |

Para DANE, la herramienta no se limita a mirar si el registro existe: contrasta la
**cadena presentada** contra los TLSA de forma **completa** —todos los usos (hoja o
anclaje CA, con la condición PKIX de los usos `PKIX-*`), ambos selectores
(certificado o clave pública) y los tres tipos de correspondencia (exacto, SHA-256,
SHA-512)—, no solo la forma común.

### Y todo se autentica por DNSSEC

Un registro en DNS sin firmar lo puede **falsificar** quien controle el camino: una
CAA falsa engañaría a una CA en el momento de emitir, un TLSA falso pinchado por un
atacante deshace el sentido de DANE. Por eso, cuando hay registros, la herramienta
**valida su firma DNSSEC hasta la clave raíz de IANA ella misma, en código**
([`dnssec.py`](../../web_crypto_checker/dnssec.py)) —verificando cada RRSIG y cada DS—,
en vez de fiarse del bit *authenticated data* de un *resolver*. Consulta con los
bits DO + *Checking Disabled* para que le entreguen los registros crudos, y obtiene
esos registros por un **resolver iterativo propio**
([`resolver.py`](../../web_crypto_checker/resolver.py)) que camina la delegación desde
las *root hints*, **sin pasar por ningún resolver recursivo de terceros**.

Dos consecuencias que aparecen en el informe:

- **Falla en cerrado.** Cualquier duda en la cadena → *no validado*, jamás un falso
  *validado*. `CaaInfo.dnssec_validated`, `DaneInfo.dnssec_validated` y
  `HttpsRecord.dnssec_validated` distinguen «genuino» de «podría estar manipulado».
- **La ausencia también se prueba.** Cuando no hay TLSA, la herramienta no se
  encoge de hombros: verifica la **negación autenticada** (NSEC/NSEC3) para que «no
  hay DANE» sea un hecho probado y no un registro que alguien pudo haber suprimido
  por el camino.

---

## Sondas activas (`--active`)

Todo lo anterior es **pasivo**: abre conexiones y lee lo que el servidor ofrece,
como lo haría un cliente cualquiera. `--active` añade sondas que **envían tráfico
manipulado y potencialmente disruptivo**, así que está desactivada por defecto y la
herramienta imprime un aviso de autorización al lanzarla:

```bash
web-crypto-checker example.com --active
```

Lo que añade ([`scanner.py`](../../web_crypto_checker/scanner.py),
[`tls/active.py`](../../web_crypto_checker/tls/active.py),
[`tls/robot.py`](../../web_crypto_checker/tls/robot.py)):

- **Heartbleed** (CVE-2014-0160) y **CCS injection** (CVE-2014-0224).
- El **oráculo ROBOT activo** (CVE-2017-13099), que confirma la superficie
  estática-RSA de Bleichenbacher que la detección pasiva solo sospecha.
- La **renegociación iniciada por el cliente**: insegura (CVE-2009-3555) si el
  servidor no exige el modo seguro, o merecedora de un aviso de bajo nivel
  (CVE-2011-1473) si la acepta.
- La **consulta real de revocación** (OCSP/CRL): con `--active`, la herramienta no
  solo lee lo que el certificado *anuncia* sobre revocación, sino que **pregunta**
  al *responder* OCSP y baja la CRL para saber si la hoja está revocada de verdad.

> ⚠️ Escanear un servidor que no es tuyo puede ser ilegal sin permiso, y estas
> sondas son ofensivas. Usa `--active` **solo** contra servidores que estés
> autorizado a probar.

---

## Confianza del certificado: `--ca-bundle` y `--no-trust`

Por defecto, la cadena del certificado se valida hasta una **raíz del almacén del
sistema**, con `NameConstraints`, `pathLenConstraint` y la vigencia de toda la ruta
([`pki/certificates.py`](../../web_crypto_checker/pki/certificates.py)). Dos opciones
cambian ese anclaje:

```bash
# Validar contra TUS raíces (una PKI interna) en vez del almacén del sistema
web-crypto-checker interno.example.com --ca-bundle ./raices.pem

# No validar la cadena contra ningún almacén (solo enumerar la criptografía)
web-crypto-checker example.com --no-trust
```

`--ca-bundle` es lo que necesitas para auditar servidores firmados por una **CA
corporativa** que el sistema no conoce: sin él saldrían como *no confiables* por un
motivo que no tiene nada que ver con su postura criptográfica. `--no-trust` desactiva
del todo la comprobación de confianza —útil cuando solo te interesan versiones,
suites y grupos, o cuando el objetivo es un servidor de laboratorio con un
certificado a propósito descabalado.

Cuando la cadena presentada no llega a una raíz de confianza pero podría estarle
faltando **solo un intermedio**, la herramienta lo **descarga por AIA** (la URL
`caIssuers` del propio certificado, como haría un navegador) y reconstruye la cadena.
Completar así nunca **confiere** confianza por su cuenta: un intermedio descargado
solo ayuda a alcanzar una raíz que ya estaba en el almacén.
