# `web_crypto_checker/data/` — lo editable

Datos, no código. Todo lo que se puede cambiar sin tocar Python vive aquí. Se
instala con el paquete (`pyproject.toml` declara `data/*.json`).

## Ficheros

| Fichero | Qué contiene |
|---|---|
| `algorithms.json` | La política: cómo se clasifica cada versión de TLS, cada suite de cifrado (por sus etiquetas), cada grupo y cada algoritmo de firma; los pesos de cada clase, la escala de notas, los **topes de nota**, las **vulnerabilidades conocidas** con su árbol de detección y la **fuerza de seguridad** (bits por algoritmo y bandas de nivel, NIST SP 800-57). Es el fichero que se edita para cambiar el criterio sin cambiar la herramienta. |
| `ct_logs.json` | El catálogo de **logs de Certificate Transparency** conocidos (RFC 6962): `log_id` → nombre, operador, estado y **clave pública** (SPKI), instantánea del *log list* v3 de Google. `ct.py` verifica con él la firma de los SCTs empotrados en un certificado. Para actualizarlo, re-descargar el *log list* de la fuente que indica el propio fichero; un SCT de un log ausente de aquí se informa como "no verificado", nunca como inválido. |

## Subdirectorios

| Directorio | Qué contiene |
|---|---|
| [`profiles/`](profiles/README.md) | Las normativas: un perfil por fichero (Mozilla, NIST, PCI…), que se evalúan contra lo que ofrece el servidor. |
| [`i18n/`](i18n/README.md) | Las traducciones de la prosa de la política, superpuestas por idioma sobre `algorithms.json` y casadas por identificador. |
