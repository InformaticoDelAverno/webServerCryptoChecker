# webServerCryptoChecker

Audit the cryptography **and the protocols** your web servers offer — TLS
versions, cipher suites, key exchange, signatures, the certificate, the HTTP
layer and every application protocol they expose — grade each server, check it
against the published standards, and see whether it is post-quantum ready.
Zero dependencies; the tool speaks English and Spanish (`--lang en|es`).

**→ [English manual](docs/en/README.md)**

---

Auditoría de la criptografía **y de los protocolos** que ofrecen tus servidores
web — versiones de TLS, suites de cifrado, intercambio de claves, firmas, el
certificado, la capa HTTP y todos los protocolos de aplicación que exponen — con
nota por servidor, conformidad con las normas publicadas y comprobación de si
está preparado para post-cuántico. Sin dependencias; la herramienta habla inglés
y español (`--lang en|es`).

**→ [Manual en español](docs/es/README.md)**

---

## Mapa del repositorio

| Ruta | Qué contiene |
|---|---|
| [`docs/`](docs/README.md) | Los dos manuales ([español](docs/es/README.md) e [inglés](docs/en/README.md)) y las guías de extensión, bilingües. |
| `web_crypto_checker/` | Todo el código de la herramienta. |
| `tests/` | La suite, con el 100 % de cobertura como puerta. **Interno.** |
| `lab/` | Un laboratorio Docker de servidores con posturas conocidas, para pruebas de integración reproducibles. **Interno.** |
| `tools/` | Utilidades de desarrollo fuera del producto: mutación, suelo de cobertura e2e, el motor de release y los ganchos de git. **Interno.** |
| `examples/` | Un inventario de ejemplo para copiar y editar. |
| `web-crypto-checker` | Un lanzador para usar la herramienta **sin instalarla**. |
| `Dockerfile`, `docker-compose.yml`, `.dockerignore` | La imagen, el arranque y el contexto de construcción de la **interfaz web**. |
| `Makefile` | Atajos de empaquetado, pruebas y las dos webs (producto y laboratorio). |
| `pyproject.toml` | Metadatos del paquete y la configuración de ruff y mypy. |
| `.coveragerc` | La configuración de cobertura, con `fail_under = 100` y **sin exclusiones**. |
| `.gitlab-ci.yml` | La CI: pruebas, lint, empaquetado y las puertas del laboratorio. |
| `.gitignore`, `LICENSE`, `CHANGELOG.md` | Exclusiones de git, licencia (MIT) y registro de cambios. |

---

License / Licencia: [MIT](LICENSE) · [Changelog](CHANGELOG.md)
