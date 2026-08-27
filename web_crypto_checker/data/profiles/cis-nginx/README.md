# `data/profiles/cis-nginx/` — CIS NGINX Benchmark

**Center for Internet Security**. The NGINX hardening baseline. v3.0.0 is TLS 1.3-only, requires OCSP stapling, and requires HSTS with a max-age of at least one year.

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `v3-0-0.json` | `cis-nginx@v3-0-0` | v3.0.0 (2025-11-04) | sí |

Añadir una edición es añadir un fichero aquí; con más de una, exactamente
una debe llevar `"current": true`.

> **Fuente**: CIS NGINX Benchmark v3.0.0: Rec. 4.1.4 'Ensure only modern TLS protocols are used', Rec. 4.1.5 'Disable weak ciphers', Rec. 4.1.7 'Ensure Online Certificate Status Protocol (OCSP) stapling is enabled', Rec. 4.1.8 'Ensure HTTP Strict Transport Security (HSTS) is enabled'.
>
> https://www.cisecurity.org/cis-benchmarks
