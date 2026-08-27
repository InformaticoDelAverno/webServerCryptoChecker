# `data/profiles/nist-sp-800-131a/` — NIST SP 800-131A Rev. 2

**NIST**. Baseline transition rules: at least 112-bit security strength, no SHA-1 digital signatures, no three-key Triple DES after 2023.

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `rev-2-2019.json` | `nist-sp-800-131a@rev-2-2019` | Rev. 2, March 2019 | sí |

Añadir una edición es añadir un fichero aquí; con más de una, exactamente
una debe llevar `"current": true`.

> **Fuente**: NIST SP 800-131A Rev. 2, Transitioning the Use of Cryptographic Algorithms and Key Lengths: §3 (at least 112 bits of security strength), Table 1 (three-key TDEA disallowed after 2023), Table 8 (SHA-1 signature generation disallowed), Tables 2/4/5 (RSA/DSA/DH >= 2048, ECDSA/EdDSA >= 224).
>
> https://doi.org/10.6028/NIST.SP.800-131Ar2
