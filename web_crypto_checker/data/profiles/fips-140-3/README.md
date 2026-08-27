# `data/profiles/fips-140-3/` — FIPS 140-3 approved algorithms

**NIST**. Only FIPS-approved security functions. AES in any approved mode; NIST curves and RFC 7919 safe-prime groups; RSA/ECDSA/EdDSA signatures. Notably excludes ChaCha20-Poly1305, which has no NIST approval.

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `annex-a.json` | `fips-140-3@annex-a` | FIPS 140-3 Annex A, with SP 800-56A Rev. 3, FIPS 186-5 and SP 800-38D | sí |

Añadir una edición es añadir un fichero aquí; con más de una, exactamente
una debe llevar `"current": true`.

> **Fuente**: FIPS 140-3 Annex A (approved security functions); SP 800-56A Rev. 3 Appendix D (approved ECC curves: Table 24; approved FFC safe-prime groups: Table 26); FIPS 186-5 §1 (approved signatures RSA/ECDSA/EdDSA; DSA no longer approved for generation); SP 800-38D (GCM is an approved AEAD mode of AES).
>
> https://csrc.nist.gov/projects/cryptographic-module-validation-program
