# `data/profiles/ens/` — ENS (Esquema Nacional de Seguridad)

**CCN (Spain)**. The Spanish public-sector baseline. TLS 1.2/1.3 with the Recomendado cipher suites of Tables 4-1/4-2, RSA >= 3000-bit certificates, 128-bit strength.

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `2022-05.json` | `ens@2022-05` | CCN-STIC-807, Mayo 2022; Real Decreto 311/2022 | sí |

Añadir una edición es añadir un fichero aquí; con más de una, exactamente
una debe llevar `"current": true`.

> **Fuente**: CCN-STIC-807 'Criptología de empleo en el ENS' (Mayo 2022) §4.1 TLS: ¶61 (TLS 1.2/1.3 only), ¶63 (no NULL/anon/unauthorised), Tabla 4-1 (TLS 1.2 authorised suites) and Tabla 4-2 (TLS 1.3 authorised suites); §3 tables 3-2 (RSA) and 3-4 (curves); ¶25 (SHA-1). Legal basis: RD 311/2022 (ENS) mp.com. Effective strength for category MEDIA/ALTA per the R category (≥128 bits).
>
> https://www.ccn-cert.cni.es/es/series-ccn-stic/800-guia-esquema-nacional-de-seguridad/513-ccn-stic-807-criptologia-de-empleo-en-el-ens.html
