# `docs/` — manuals for extending the tool

The [main README](README.md) explains how to **use** webServerCryptoChecker.

There is one subdirectory:

- `estandares/` — the official documents (NIST, BSI, BOE, ANSSI, IETF…) that the
  compliance profiles come from, downloaded from their publisher's website, with
  the source URL and the fingerprint of each one.

These manuals explain how to **extend it**, and they are written so that someone
who does not know the code can write a plugin or a policy by reading only this.
Each guide is **bilingual**: its Spanish version has the same file name, under
`docs/`.

> **Just want to understand why your server got that grade?** You do not need any
> of these manuals: [`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md) is
> the complete, public scoring system, with an example worked out step by step.

| You want to… | Then | Manual |
|---|---|---|
| Change which algorithms are good or bad, or what grade each thing gets | A **policy**. No Python is touched. | [`politica-algoritmos.md`](politica-algoritmos.md) |
| Detect a new known vulnerability | Almost always a **policy**; only if the detection needs computation, a plugin. | [`politica-vulnerabilidades.md`](politica-vulnerabilidades.md) |
| Check the HTTP layer or TLS behaviour | A **check** in code. | [`politica-configuracion.md`](politica-configuracion.md) |
| Measure against a standard (your own or a published one) | A **standards policy**. | [`politica-normativas.md`](politica-normativas.md) |
| Change how the grade is calculated | A **policy**. | [`politica-puntuacion.md`](politica-puntuacion.md) |
| Check something that requires **code**: arithmetic, correlation, a format that has to be parsed | A **plugin**. | [`plugins.md`](plugins.md) |

> **The rule, in one sentence:** if what you want to say can be written as data,
> write it as data. The policy file is edited without deploying anything; a
> plugin has to be deployed.

## Plugin manuals

| File | What it covers |
|---|---|
| [`plugins.md`](plugins.md) | **Start here.** The contract common to both types: where the files go, what metadata is needed, what your function receives, what it can return, what a plugin **cannot** do, and how to test it. |
| [`plugin-check.md`](plugin-check.md) | Type `check`: looks at **one** server — its TLS, its certificate, its HTTP layer. It is the commonest case. |
| [`plugin-fleet.md`](plugin-fleet.md) | Type `fleet`: looks at **all** the servers in the scan at once, for what is only visible by comparing (a shared certificate). |
| [`plugin-vulnerability.md`](plugin-vulnerability.md) | Type `vulnerability`: a known vulnerability whose detection does not fit in the policy file. |

## Policy manuals

| File | What it covers |
|---|---|
| [`como-se-calcula-la-nota.md`](como-se-calcula-la-nota.md) | **The scoring system, whole and public.** How you get from what a server offers to a letter, why each thing weighs what it weighs, and the rule that keeps the grade and the verdict from contradicting each other. |
| [`politicas.md`](politicas.md) | **Start here.** What the policy file is, where it is looked for, and the things that can be written in it. |
| [`politica-algoritmos.md`](politica-algoritmos.md) | The algorithm classes (protocols, cipher suites, groups, signatures, certificate), their categories and the cipher-suite tags. |
| [`politica-vulnerabilidades.md`](politica-vulnerabilidades.md) | The detection grammar: by protocol, by cipher-suite tag, and how they combine. |
| [`politica-configuracion.md`](politica-configuracion.md) | The checks that are not algorithm categories: the HTTP layer (HSTS, CSP, cookies…), TLS behaviour and certificate hygiene. |
| [`politica-puntuacion.md`](politica-puntuacion.md) | Weights, the grade scale, **grade caps** and security-strength bands. |
| [`politica-normativas.md`](politica-normativas.md) | Compliance profiles: the two kinds, and one edition per file. |

## Advanced use and development

| File | What it covers |
|---|---|
| [`uso-avanzado.md`](uso-avanzado.md) | Comparing with a previous scan, the inventory file, mTLS, the DNS-based controls (CAA, DANE/TLSA), history and active probes. |
| [`desarrollo.md`](desarrollo.md) | The layout of the code, the end-to-end coverage and its two floors, mutation testing, how to add a check or an output format, and the style. |

## Audit

| File | What it covers |
|---|---|
| [`auditoria-integridad.md`](auditoria-integridad.md) | **Does everything the tool claims come from a document?** Audit (2026-08-28) of the 14 profiles and of the base policy `algorithms.json` against the documents in `estandares/`: what is backed, what is our own declared methodology (the scoring), and the one gap found — 3 vulnerabilities with no `references`. |
