# `examples/` — ejemplos

## Ficheros

| Fichero | Qué es |
|---|---|
| `servers.txt` | Un inventario de ejemplo, con las formas de nombrar un objetivo (host, `host:puerto`, URL, IP, `[IPv6]:puerto`), etiquetas y comentarios. Sirve para copiarlo y editarlo: `web-crypto-checker -f examples/servers.txt`. |

Un objetivo por línea; `#` inicia un comentario; el primer token es el objetivo y
lo que le siga es su etiqueta en el informe. **No se aceptan credenciales**: esta
herramienta audita lo que un servidor web ofrece en abierto, así que un fichero de
inventario puede versionarse sin arrastrar secretos al historial.

Volver al [manual](../README.md).
