# `data/profiles/anssi/` — ANSSI (règles cryptographiques)

**ANSSI (France)**. The French baseline, encoded by MECHANISM. ANSSI publishes numbered rules on primitives and key sizes, not a TLS cipher-suite list, so this profile encodes the rules rather than inventing a suite list.

## Ediciones

| Fichero | Selector | Edición | ¿En vigor? |
|---|---|---|---|
| `pg-083-v3-00.json` | `anssi@pg-083-v3-00` | ANSSI-PG-083 v3.00 (2026-03-20) | sí |

Añadir una edición es añadir un fichero aquí; con más de una, exactamente
una debe llevar `"current": true`.

> **Fuente**: ANSSI-PG-083 'Guide des mécanismes cryptographiques' v3.00: RegleTailleCleSym (>=128-bit symmetric), RegleTailleBlocSym (>=128-bit block), RegleHachage (>=256-bit hash; SHA-1 non-conformant), RegleMAC (>=96-bit tag), RegleFactorisation (RSA), RegleLogDiscretGFp (DH), RegleCourbeElliptiqueGFp (EC), §1.5 (no summary size table).
>
> https://cyber.gouv.fr/publications/mecanismes-cryptographiques
