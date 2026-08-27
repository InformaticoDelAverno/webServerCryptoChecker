"""Message catalogs for the user interface, English and Spanish of Spain.

``MESSAGES[key] = {"en": ..., "es": ...}``. Keys are grouped by a dotted prefix
(``cli.`` for the command line, ``rep.`` for reports, ``ui.``/``wiz.`` for the
interactive wizard). Every key must carry both languages; ``tests/test_i18n.py``
enforces it, and enforces that the ``{placeholders}`` match across languages so
either renders with the same arguments.

Machine-readable report formats (json, csv, sarif, openmetrics) keep their
English enum values so downstream parsers are unaffected; only human-facing
prose is translated.
"""

from __future__ import annotations

from typing import Dict

MESSAGES: Dict[str, Dict[str, str]] = {
    # -- command line -------------------------------------------------------
    "cli.desc": {
        "en": "Audit the cryptography offered by web servers (TLS + the HTTP layer).",
        "es": "Audita la criptografía que ofrecen los servidores web (TLS + la capa HTTP).",
    },
    "cli.lang.help": {
        "en": "language for messages and reports (en, es); the default follows the system locale",
        "es": "idioma de los mensajes e informes (en, es); por defecto sigue el locale del sistema",
    },
    # -- report: verdicts (the human label for each models.Verdict value) ---
    "rep.verdict.secure": {"en": "secure", "es": "seguro"},
    "rep.verdict.acceptable": {"en": "acceptable", "es": "aceptable"},
    "rep.verdict.weak": {"en": "weak", "es": "débil"},
    "rep.verdict.insecure": {"en": "insecure", "es": "inseguro"},
    "rep.verdict.unknown": {"en": "unknown", "es": "desconocido"},
    "rep.verdict.error": {"en": "error", "es": "error"},
    # -- report: finding severities (models.Severity values) ----------------
    "rep.severity.critical": {"en": "critical", "es": "crítico"},
    "rep.severity.high": {"en": "high", "es": "alto"},
    "rep.severity.medium": {"en": "medium", "es": "medio"},
    "rep.severity.low": {"en": "low", "es": "bajo"},
    "rep.severity.info": {"en": "info", "es": "info"},
    # -- report: field labels ----------------------------------------------
    "rep.field.grade": {"en": "grade", "es": "nota"},
    "rep.field.verdict": {"en": "verdict", "es": "veredicto"},
    # -- command line: the wizard flag + its errors ------------------------
    "cli.wizard.help": {
        "en": "build a scan interactively, then run it (needs a terminal)",
        "es": "construir un escaneo de forma interactiva y ejecutarlo (necesita terminal)",
    },
    "cli.err.wizard_needs_tty": {
        "en": "error: --wizard needs an interactive terminal",
        "es": "error: --wizard necesita un terminal interactivo",
    },
    # -- shared prompt primitives (the wizard's ask/emit helpers) ----------
    "ui.default_label_all": {"en": "all", "es": "todas"},
    "ui.default_label_none": {"en": "none", "es": "ninguna"},
    "ui.multi_hint": {
        "en": "  Type numbers separated by commas (e.g. 1,3), 'a' = all, 'n' = none.",
        "es": "  Escribe números separados por comas (p. ej. 1,3), 'a' = todas, 'n' = ninguna.",
    },
    "ui.multi_prompt": {
        "en": "Selection [Enter = {label}]: ",
        "es": "Selección [Enter = {label}]: ",
    },
    "ui.multi_bad_token": {
        "en": "  '{token}' is not valid; use numbers between 1 and {n}, 'a' or 'n'.",
        "es": "  '{token}' no es válido; usa números entre 1 y {n}, 'a' o 'n'.",
    },
    "ui.yes_no_default_yes": {"en": "Y/n", "es": "S/n"},
    "ui.yes_no_default_no": {"en": "y/N", "es": "s/N"},
    "ui.yes_no_retry": {"en": "  Answer y or n.", "es": "  Responde s o n."},
    "ui.int_retry": {"en": "  Type a whole number.", "es": "  Escribe un número entero."},
    # -- wizard: header ----------------------------------------------------
    "wiz.title": {
        "en": "=== webServerCryptoChecker wizard ===",
        "es": "=== Asistente de webServerCryptoChecker ===",
    },
    "wiz.intro": {
        "en": "Answer a few questions; the wizard builds the command and offers to run it.",
        "es": "Responde unas preguntas; el asistente construye el comando y ofrece ejecutarlo.",
    },
    "wiz.default_hint": {
        "en": "Press Enter to accept the default shown in brackets.",
        "es": "Pulsa Intro para aceptar el valor por defecto entre corchetes.",
    },
    # -- wizard: targets ---------------------------------------------------
    "wiz.sec_targets": {"en": "-- Targets --", "es": "-- Objetivos --"},
    "wiz.target_prompt": {
        "en": "Hosts to scan, space-separated (example.com example.com:8443)",
        "es": "Servidores a escanear, separados por espacios (example.com example.com:8443)",
    },
    "wiz.inventory_prompt": {
        "en": "Or a file with one target per line ('-' for stdin)",
        "es": "O un fichero con un objetivo por línea ('-' para la entrada estándar)",
    },
    "wiz.no_target_hint": {
        "en": "  You gave neither hosts nor a file.",
        "es": "  No indicaste ni servidores ni un fichero.",
    },
    "wiz.target_reprompt": {"en": "Hosts to scan", "es": "Servidores a escanear"},
    "wiz.cancelled_no_target": {
        "en": "  Nothing to scan; cancelled.",
        "es": "  Nada que escanear; cancelado.",
    },
    "wiz.sni_prompt": {
        "en": "SNI server name to send (blank = the host name)",
        "es": "Nombre SNI a enviar (vacío = el nombre del servidor)",
    },
    "wiz.port_prompt": {
        "en": "Default port for hosts that name none",
        "es": "Puerto por defecto para los servidores que no lo indiquen",
    },
    # -- wizard: profiles --------------------------------------------------
    "wiz.sec_profiles": {"en": "-- Compliance profiles --", "es": "-- Perfiles de conformidad --"},
    "wiz.profiles_intro": {
        "en": ("Optionally measure each server against published standards (NIST, PCI DSS, ...)."),
        "es": (
            "Opcionalmente, mide cada servidor contra estándares publicados (NIST, PCI DSS, ...)."
        ),
    },
    "wiz.evaluate_prompt": {
        "en": "Profiles to evaluate (none = skip compliance):",
        "es": "Perfiles a evaluar (ninguno = omitir conformidad):",
    },
    # -- wizard: output ----------------------------------------------------
    "wiz.sec_output": {"en": "-- Output --", "es": "-- Salida --"},
    "wiz.format_prompt": {
        "en": "Report formats (none = console):",
        "es": "Formatos de informe (ninguno = consola):",
    },
    "wiz.write_file_gate": {
        "en": "Write the report to a file?",
        "es": "¿Escribir el informe a un fichero?",
    },
    "wiz.output_path_prompt": {"en": "Output path", "es": "Ruta de salida"},
    # -- wizard: scanning --------------------------------------------------
    "wiz.scanning_gate": {"en": "Adjust scanning options?", "es": "¿Ajustar opciones de escaneo?"},
    "wiz.sec_scanning": {"en": "-- Scanning --", "es": "-- Escaneo --"},
    "wiz.timeout_prompt": {"en": "Timeout in seconds", "es": "Tiempo de espera en segundos"},
    "wiz.concurrency_prompt": {"en": "Concurrent scans", "es": "Escaneos simultáneos"},
    # -- wizard: trust -----------------------------------------------------
    "wiz.trust_gate": {
        "en": "Change certificate trust settings?",
        "es": "¿Cambiar la confianza de certificados?",
    },
    "wiz.sec_trust": {"en": "-- Certificate trust --", "es": "-- Confianza de certificados --"},
    "wiz.no_trust_gate": {
        "en": "Skip trust verification entirely?",
        "es": "¿Omitir por completo la verificación de confianza?",
    },
    "wiz.ca_bundle_prompt": {
        "en": "CA bundle file (blank = the system store)",
        "es": "Fichero de CA de confianza (vacío = el almacén del sistema)",
    },
    # -- wizard: active probes ---------------------------------------------
    "wiz.active_warning": {
        "en": (
            "Active probes send crafted, possibly disruptive traffic; "
            "only against servers you may test."
        ),
        "es": (
            "Las sondas activas envían tráfico manipulado y posiblemente "
            "disruptivo; solo contra servidores que puedas probar."
        ),
    },
    "wiz.active_gate": {"en": "Enable active probes?", "es": "¿Activar las sondas activas?"},
    # -- wizard: history / compare -----------------------------------------
    "wiz.history_gate": {
        "en": "Track history or compare with a baseline?",
        "es": "¿Registrar histórico o comparar con una base?",
    },
    "wiz.sec_history": {"en": "-- History and compare --", "es": "-- Histórico y comparación --"},
    "wiz.history_prompt": {
        "en": "History file (blank = none)",
        "es": "Fichero de histórico (vacío = ninguno)",
    },
    "wiz.compare_prompt": {
        "en": "Baseline file to compare against (blank = none)",
        "es": "Fichero base con el que comparar (vacío = ninguno)",
    },
    "wiz.regression_gate": {
        "en": "Fail if any endpoint regressed?",
        "es": "¿Fallar si algún extremo empeoró?",
    },
    # -- wizard: plugins ---------------------------------------------------
    "wiz.plugins_gate": {"en": "Load detection plugins?", "es": "¿Cargar plugins de detección?"},
    "wiz.plugin_dir_prompt": {"en": "Plugin directory", "es": "Directorio de plugins"},
    # -- wizard: command + launch ------------------------------------------
    "wiz.command_header": {"en": "=== Command ===", "es": "=== Comando ==="},
    "wiz.command_save": {
        "en": "Save that command to run the same scan later without the wizard.",
        "es": "Guarda ese comando para repetir el mismo escaneo más tarde sin el asistente.",
    },
    "wiz.launch_gate": {"en": "Run it now?", "es": "¿Ejecutarlo ahora?"},
    "wiz.declined": {
        "en": "Not run. The command above is ready when you are.",
        "es": "No ejecutado. El comando de arriba está listo cuando quieras.",
    },
    # -- report: algorithm categories (models.Category values) --------------
    "rep.category.recommended": {"en": "recommended", "es": "recomendado"},
    "rep.category.acceptable": {"en": "acceptable", "es": "aceptable"},
    "rep.category.weak": {"en": "weak", "es": "débil"},
    "rep.category.insecure": {"en": "insecure", "es": "inseguro"},
    "rep.category.informational": {"en": "informational", "es": "informativo"},
    "rep.category.unknown": {"en": "unknown", "es": "desconocido"},
    # -- report: post-quantum readiness (models.PostQuantumStatus values) ----
    "rep.pq.enforced": {"en": "enforced", "es": "exigido"},
    "rep.pq.ready": {"en": "ready", "es": "preparado"},
    "rep.pq.not_ready": {"en": "not-ready", "es": "no preparado"},
    "rep.pq.unknown": {"en": "unknown", "es": "desconocido"},
    # -- report: certificate trust (models.TrustStatus values) --------------
    "rep.trust.trusted": {"en": "trusted", "es": "de confianza"},
    "rep.trust.untrusted": {"en": "untrusted", "es": "no confiable"},
    "rep.trust.self_signed": {"en": "self-signed", "es": "autofirmado"},
    "rep.trust.expired": {"en": "expired", "es": "caducado"},
    "rep.trust.not_yet_valid": {"en": "not-yet-valid", "es": "aún no válido"},
    "rep.trust.hostname_mismatch": {"en": "hostname-mismatch", "es": "nombre no coincide"},
    "rep.trust.incomplete": {"en": "incomplete", "es": "incompleta"},
    "rep.trust.not_checked": {"en": "not-checked", "es": "sin comprobar"},
    "rep.trust.unknown": {"en": "unknown", "es": "desconocido"},
    # -- report: compliance outcome (models.ComplianceStatus values) --------
    "rep.compliance.pass": {"en": "pass", "es": "cumple"},
    "rep.compliance.fail": {"en": "fail", "es": "falla"},
    "rep.compliance.not_assessed": {"en": "not-assessed", "es": "sin evaluar"},
    # -- report: console renderer -------------------------------------------
    "rep.con.header": {
        "en": "{tool} {version} — {total} endpoint(s), {reachable} reachable",
        "es": "{tool} {version} — {total} extremo(s), {reachable} accesible(s)",
    },
    "rep.con.error": {"en": "  error: {error}", "es": "  error: {error}"},
    "rep.con.na": {"en": "n/a", "es": "n/d"},
    "rep.con.security_strength": {
        "en": "  security strength: {bits}-bit ({label}), limited by {limiting}",
        "es": "  fuerza de seguridad: {bits} bits ({label}), limitada por {limiting}",
    },
    "rep.con.tls_versions": {
        "en": "  TLS versions: {versions}",
        "es": "  versiones TLS: {versions}",
    },
    "rep.con.none": {"en": "none", "es": "ninguna"},
    "rep.con.cipher_suites": {"en": "  cipher suites ({n}):", "es": "  suites de cifrado ({n}):"},
    "rep.con.key_exchange_groups": {
        "en": "  key exchange groups: {names}",
        "es": "  grupos de intercambio de claves: {names}",
    },
    "rep.con.post_quantum": {"en": "  post-quantum: {status}", "es": "  poscuántico: {status}"},
    "rep.con.signature_schemes": {
        "en": "  signature schemes: {schemes}",
        "es": "  esquemas de firma: {schemes}",
    },
    "rep.con.secure_renegotiation": {
        "en": "  secure renegotiation: {value}",
        "es": "  renegociación segura: {value}",
    },
    "rep.con.extended_master_secret": {
        "en": "  extended master secret: {value}",
        "es": "  secreto maestro extendido: {value}",
    },
    "rep.con.downgrade_protection": {
        "en": "  downgrade protection (SCSV): {value}",
        "es": "  protección ante degradación (SCSV): {value}",
    },
    "rep.con.session_resumption": {
        "en": "  session resumption: id {id}, ticket {ticket}",
        "es": "  reanudación de sesión: id {id}, ticket {ticket}",
    },
    "rep.con.ocsp_stapling": {"en": "  OCSP stapling: {value}", "es": "  grapado OCSP: {value}"},
    "rep.con.early_data": {
        "en": "  0-RTT (early data): {value}",
        "es": "  0-RTT (datos tempranos): {value}",
    },
    "rep.con.compression": {"en": "  compression: {value}", "es": "  compresión: {value}"},
    "rep.con.certificate": {"en": "  certificate: {subject}", "es": "  certificado: {subject}"},
    "rep.con.certificate_not_retrieved": {
        "en": "  certificate: not retrieved ({error})",
        "es": "  certificado: no obtenido ({error})",
    },
    "rep.con.cert_detail": {
        "en": (
            "    key {keydesc}, sig {sig}, trust {trust}, hostname match: {hostname}, "
            "chain signatures: {signatures}"
        ),
        "es": (
            "    clave {keydesc}, firma {sig}, confianza {trust}, coincide el nombre: {hostname}, "
            "firmas de la cadena: {signatures}"
        ),
    },
    "rep.con.key_bits": {"en": "{type} {bits}-bit", "es": "{type} {bits} bits"},
    "rep.con.revocation_summary": {
        "en": "    revocation/CT: {detail}",
        "es": "    revocación/CT: {detail}",
    },
    "rep.con.ct": {"en": "CT ({n} SCTs{verified})", "es": "CT ({n} SCTs{verified})"},
    "rep.con.ct_verified": {"en": ", {n} verified", "es": ", {n} verificados"},
    "rep.con.revocation": {"en": "    revocation: {detail}", "es": "    revocación: {detail}"},
    "rep.con.no_answer": {"en": "no answer", "es": "sin respuesta"},
    "rep.con.alternate_certificate": {
        "en": "  alternate certificate: {keydesc}, sig {sig}, trust {trust}",
        "es": "  certificado alternativo: {keydesc}, firma {sig}, confianza {trust}",
    },
    "rep.con.caa": {"en": "  CAA: {issuers}", "es": "  CAA: {issuers}"},
    "rep.con.caa_none": {
        "en": "  CAA: none (any CA may issue)",
        "es": "  CAA: ninguno (cualquier CA puede emitir)",
    },
    "rep.con.dane": {
        "en": "  DANE/TLSA: {n} record(s), {match}, {dnssec}",
        "es": "  DANE/TLSA: {n} registro(s), {match}, {dnssec}",
    },
    "rep.con.dane_matches": {"en": "certificate matches", "es": "el certificado coincide"},
    "rep.con.dane_mismatch": {"en": "certificate MISMATCH", "es": "el certificado NO COINCIDE"},
    "rep.con.dane_not_validated": {"en": "present, not validated", "es": "presente, sin validar"},
    "rep.con.dnssec_yes": {"en": "DNSSEC-authenticated", "es": "autenticado con DNSSEC"},
    "rep.con.dnssec_no": {"en": "not DNSSEC-authenticated", "es": "no autenticado con DNSSEC"},
    "rep.con.dnssec_unchecked": {"en": "DNSSEC not checked", "es": "DNSSEC sin comprobar"},
    "rep.con.dane_absent": {
        "en": "  DANE/TLSA: none published (DNSSEC-authenticated absence)",
        "es": "  DANE/TLSA: no publicado (ausencia autenticada con DNSSEC)",
    },
    "rep.con.https_rr": {"en": "  HTTPS RR: {detail}", "es": "  HTTPS RR: {detail}"},
    "rep.con.https_rr_published": {"en": "published", "es": "publicado"},
    "rep.con.https_rr_alpn": {"en": "alpn {names}", "es": "alpn {names}"},
    "rep.con.https_rr_ech": {"en": "ECH advertised", "es": "ECH anunciado"},
    "rep.con.https_rr_port": {"en": "port {port}", "es": "puerto {port}"},
    "rep.con.http_cleartext": {
        "en": "  http: CLEARTEXT (no TLS), {status}, server {server}",
        "es": "  http: EN CLARO (sin TLS), {status}, servidor {server}",
    },
    "rep.con.server_hidden": {"en": "hidden", "es": "oculto"},
    "rep.con.http": {
        "en": "  http: {status}, HSTS {hsts}, server {server}{http3}",
        "es": "  http: {status}, HSTS {hsts}, servidor {server}{http3}",
    },
    "rep.con.hsts_absent": {"en": "absent", "es": "ausente"},
    "rep.con.http3_advertised": {"en": ", HTTP/3 advertised", "es": ", HTTP/3 anunciado"},
    "rep.con.mixed_content": {
        "en": ", mixed content {active} active/{passive} passive",
        "es": ", contenido mixto {active} activo/{passive} pasivo",
    },
    "rep.con.http_not_measured": {
        "en": "  http: not measured ({error})",
        "es": "  http: sin medir ({error})",
    },
    "rep.con.http3_label": {"en": "  HTTP/3: {value}", "es": "  HTTP/3: {value}"},
    "rep.con.http3_reachable": {"en": "reachable", "es": "accesible"},
    "rep.con.http3_not_reachable": {"en": "not reachable", "es": "no accesible"},
    "rep.con.quic_parameters": {
        "en": "  QUIC parameters: {detail}",
        "es": "  parámetros QUIC: {detail}",
    },
    "rep.con.quic_idle": {"en": "idle {ms} ms", "es": "inactividad {ms} ms"},
    "rep.con.quic_bidi": {"en": "{n} bidi streams", "es": "{n} flujos bidi"},
    "rep.con.quic_cid": {"en": "CID limit {n}", "es": "límite de CID {n}"},
    "rep.con.quic_migration_disabled": {"en": "migration disabled", "es": "migración desactivada"},
    "rep.con.quic_versions": {
        "en": "  QUIC versions: {detail}",
        "es": "  versiones QUIC: {detail}",
    },
    "rep.con.none_recognised": {"en": "none recognised", "es": "ninguna reconocida"},
    "rep.con.none_advertised": {"en": "none advertised", "es": "ninguno anunciado"},
    "rep.con.websocket": {"en": "  WebSocket: {detail}", "es": "  WebSocket: {detail}"},
    "rep.con.supported": {"en": "supported", "es": "admitido"},
    "rep.con.ws_subprotocol": {"en": ", subprotocol {name}", "es": ", subprotocolo {name}"},
    "rep.con.ws_origin_enforced": {"en": ", Origin enforced", "es": ", Origin validado"},
    "rep.con.ws_origin_not_enforced": {
        "en": ", Origin not enforced (CSWSH)",
        "es": ", Origin sin validar (CSWSH)",
    },
    "rep.con.sse": {"en": "  SSE: {detail}", "es": "  SSE: {detail}"},
    "rep.con.sse_cross_origin": {"en": ", open cross-origin", "es": ", origen cruzado abierto"},
    "rep.con.sse_same_origin": {"en": ", same-origin", "es": ", mismo origen"},
    "rep.con.http2": {"en": "  HTTP/2: {detail}", "es": "  HTTP/2: {detail}"},
    "rep.con.http2_max_streams": {"en": ", max streams {n}", "es": ", máx flujos {n}"},
    "rep.con.mtls": {
        "en": "  client-certificate auth: {enforcement} (mTLS)",
        "es": "  autenticación con certificado de cliente: {enforcement} (mTLS)",
    },
    "rep.con.mtls_required": {"en": "required", "es": "requerida"},
    "rep.con.mtls_requested": {"en": "requested", "es": "solicitada"},
    "rep.con.grpc": {"en": "  gRPC: {value}", "es": "  gRPC: {value}"},
    "rep.con.finding": {
        "en": "  [{severity}] {title}: {items}",
        "es": "  [{severity}] {title}: {items}",
    },
    "rep.con.vuln": {
        "en": "  vuln [{severity}] {id}: {name}{evidence}",
        "es": "  vuln [{severity}] {id}: {name}{evidence}",
    },
    "rep.con.compliance": {
        "en": "  compliance {id}: {status}",
        "es": "  conformidad {id}: {status}",
    },
    "rep.con.violation": {"en": "    - {subject} ({reason})", "es": "    - {subject} ({reason})"},
    "rep.con.yes": {"en": "yes", "es": "sí"},
    "rep.con.no": {"en": "no", "es": "no"},
    "rep.con.unknown": {"en": "unknown", "es": "desconocido"},
    "rep.con.sig_verified": {"en": "verified", "es": "verificadas"},
    "rep.con.sig_invalid": {"en": "INVALID", "es": "INVÁLIDAS"},
    "rep.con.sig_unchecked": {"en": "unchecked", "es": "sin comprobar"},
    "rep.con.no_reneg": {
        "en": "NO (RFC 5746 unsupported)",
        "es": "NO (RFC 5746 no soportada)",
    },
    "rep.con.no_ems": {"en": "NO (RFC 7627 unsupported)", "es": "NO (RFC 7627 no soportada)"},
    "rep.con.no_scsv": {"en": "NO (RFC 7507 unsupported)", "es": "NO (RFC 7507 no soportada)"},
    "rep.con.compression_disabled": {"en": "disabled", "es": "desactivada"},
    "rep.con.compression_enabled": {"en": "ENABLED (CRIME)", "es": "ACTIVADA (CRIME)"},
    # -- report: plain text summary footer ----------------------------------
    "rep.txt.summary": {"en": "Summary", "es": "Resumen"},
    "rep.txt.counts": {
        "en": "  endpoints: {total}  reachable: {reachable}  failed: {failed}",
        "es": "  extremos: {total}  accesibles: {reachable}  fallidos: {failed}",
    },
    "rep.txt.average_score": {
        "en": "  average score: {score}",
        "es": "  puntuación media: {score}",
    },
    "rep.txt.grades": {"en": "  grades: {grades}", "es": "  notas: {grades}"},
    "rep.txt.vulnerable": {
        "en": "  vulnerable endpoints: {n}",
        "es": "  extremos vulnerables: {n}",
    },
    # -- report: HTML renderer ----------------------------------------------
    "rep.html.doc_title": {"en": "{tool} report", "es": "Informe de {tool}"},
    "rep.html.summary": {
        "en": "{total} endpoint(s), {reachable} reachable",
        "es": "{total} extremo(s), {reachable} accesible(s)",
    },
    "rep.html.error": {"en": "error: {error}", "es": "error: {error}"},
    "rep.html.grade": {"en": "grade {grade}", "es": "nota {grade}"},
    "rep.html.verdict": {"en": "verdict {verdict}", "es": "veredicto {verdict}"},
    "rep.html.tls_versions": {"en": "TLS versions: {versions}", "es": "versiones TLS: {versions}"},
    "rep.html.none": {"en": "none", "es": "ninguna"},
    "rep.html.certificate": {
        "en": "certificate: {subject} ({type}, {sig})",
        "es": "certificado: {subject} ({type}, {sig})",
    },
    "rep.html.certificate_not_retrieved": {
        "en": "certificate: not retrieved ({error})",
        "es": "certificado: no obtenido ({error})",
    },
    "rep.html.protocols_offered": {"en": "protocols offered:", "es": "protocolos ofrecidos:"},
    "rep.html.finding": {"en": "[{severity}] {title}", "es": "[{severity}] {title}"},
    "rep.html.compliance": {
        "en": "compliance {id}: {status}",
        "es": "conformidad {id}: {status}",
    },
    # -- command line: option help (--help) ---------------------------------
    "cli.h.targets": {
        "en": (
            "hosts to scan: example.com, example.com:8443, https://example.com/path, "
            "192.0.2.10, [2001:db8::1]:443"
        ),
        "es": (
            "servidores a escanear: example.com, example.com:8443, https://example.com/path, "
            "192.0.2.10, [2001:db8::1]:443"
        ),
    },
    "cli.h.port": {
        "en": "port, or comma-separated list, applied to hosts that name none (e.g. 443,8443)",
        "es": (
            "puerto, o lista separada por comas, para los servidores que no lo "
            "indiquen (p. ej. 443,8443)"
        ),
    },
    "cli.h.file": {
        "en": "read targets from a file, one per line ('-' for stdin); repeatable",
        "es": (
            "leer objetivos de un fichero, uno por línea ('-' para la entrada estándar); repetible"
        ),
    },
    "cli.h.sni": {
        "en": "server name to send instead of the host (useful when scanning by IP)",
        "es": "nombre de servidor a enviar en lugar del host (útil al escanear por IP)",
    },
    "cli.h.timeout": {
        "en": "per-connection timeout in seconds (default {default})",
        "es": "tiempo de espera por conexión en segundos (por defecto {default})",
    },
    "cli.h.concurrency": {
        "en": "how many targets to scan at once (default 1)",
        "es": "cuántos objetivos escanear a la vez (por defecto 1)",
    },
    "cli.h.format": {
        "en": "report format(s), comma-separated: {formats}",
        "es": "formato(s) de informe, separados por comas: {formats}",
    },
    "cli.h.output": {
        "en": "write the report to a file (a base name when several formats are asked for)",
        "es": "escribir el informe a un fichero (un nombre base cuando se piden varios formatos)",
    },
    "cli.h.profile": {
        "en": "evaluate each endpoint against a compliance profile (repeatable)",
        "es": "evaluar cada extremo contra un perfil de conformidad (repetible)",
    },
    "cli.h.list_profiles": {
        "en": "list the available compliance profiles and exit",
        "es": "listar los perfiles de conformidad disponibles y salir",
    },
    "cli.h.plugin_dir": {
        "en": "load detection plugins from a directory (repeatable)",
        "es": "cargar plugins de detección de un directorio (repetible)",
    },
    "cli.h.list_plugins": {
        "en": "list the plugins that would load, and exit",
        "es": "listar los plugins que se cargarían, y salir",
    },
    "cli.h.compare": {
        "en": "compare the scan against an earlier JSON report and show what changed",
        "es": "comparar el escaneo con un informe JSON anterior y mostrar qué cambió",
    },
    "cli.h.history": {
        "en": "append this scan to a history file and show each endpoint's grade over time",
        "es": (
            "añadir este escaneo a un fichero de histórico y mostrar la nota de cada "
            "extremo con el tiempo"
        ),
    },
    "cli.h.fail_on_regression": {
        "en": "exit non-zero if any endpoint regressed against the baseline (with --compare)",
        "es": (
            "salir con código distinto de cero si algún extremo empeoró respecto a la "
            "base (con --compare)"
        ),
    },
    "cli.h.active": {
        "en": (
            "run active probes that send crafted, possibly disruptive traffic "
            "(e.g. Heartbleed) -- only against servers you are authorised to test"
        ),
        "es": (
            "ejecutar sondas activas que envían tráfico manipulado y posiblemente "
            "disruptivo (p. ej. Heartbleed) -- solo contra servidores que estés "
            "autorizado a probar"
        ),
    },
    "cli.h.ca_bundle": {
        "en": "PEM file of trusted roots for chain validation (default: the system store)",
        "es": (
            "fichero PEM de raíces de confianza para validar la cadena (por defecto: "
            "el almacén del sistema)"
        ),
    },
    "cli.h.no_trust": {
        "en": "do not validate the certificate chain against any trust store",
        "es": "no validar la cadena de certificados contra ningún almacén de confianza",
    },
    "cli.h.version": {"en": "print the version and exit", "es": "imprimir la versión y salir"},
    # -- command line: metavars ---------------------------------------------
    "cli.mv.lang": {"en": "LANG", "es": "IDIOMA"},
    "cli.mv.path": {"en": "PATH", "es": "RUTA"},
    "cli.mv.seconds": {"en": "SECONDS", "es": "SEGUNDOS"},
    "cli.mv.n": {"en": "N", "es": "N"},
    "cli.mv.names": {"en": "NAMES", "es": "NOMBRES"},
    "cli.mv.id": {"en": "ID", "es": "ID"},
    "cli.mv.dir": {"en": "DIR", "es": "DIR"},
    "cli.mv.baseline": {"en": "BASELINE", "es": "BASE"},
    "cli.mv.port": {"en": "PORT", "es": "PUERTO"},
    # -- report: code-generated findings (title/desc/remediation) ------------
    # The finding id and Severity stay English (structural); only this prose is
    # translated, and it is built at scan time so every renderer -- machine ones
    # included -- carries it. Placeholders must match across languages.
    #
    # Certificate findings (assessment.py)
    "find.cert_expired.title": {
        "en": "Certificate has expired",
        "es": "El certificado ha caducado",
    },
    "find.cert_expired.desc": {
        "en": "The leaf certificate's validity period has ended.",
        "es": "El periodo de validez del certificado de entidad final ha terminado.",
    },
    "find.cert_not_yet_valid.title": {
        "en": "Certificate is not yet valid",
        "es": "El certificado aún no es válido",
    },
    "find.cert_not_yet_valid.desc": {
        "en": "The leaf certificate's validity period has not started.",
        "es": "El periodo de validez del certificado de entidad final aún no ha comenzado.",
    },
    "find.cert_hostname_mismatch.title": {
        "en": "Certificate name does not match the host",
        "es": "El nombre del certificado no coincide con el host",
    },
    "find.cert_hostname_mismatch.desc": {
        "en": "None of the certificate's names cover {host}.",
        "es": "Ninguno de los nombres del certificado cubre {host}.",
    },
    "find.cert_chain_expired.title": {
        "en": "A chain certificate is outside its validity",
        "es": "Un certificado de la cadena está fuera de su validez",
    },
    "find.cert_chain_expired.desc": {
        "en": (
            "The chain reaches a trusted root, but an intermediate certificate in the path "
            "is expired or not yet valid, so path validation fails."
        ),
        "es": (
            "La cadena llega a una raíz de confianza, pero un certificado intermedio de la ruta "
            "está caducado o aún no es válido, de modo que la validación de la ruta falla."
        ),
    },
    "find.cert_eku_no_server_auth.title": {
        "en": "Certificate is not issued for TLS server authentication",
        "es": "El certificado no está emitido para autenticación de servidor TLS",
    },
    "find.cert_eku_no_server_auth.desc": {
        "en": (
            "The certificate's ExtendedKeyUsage names other purposes and omits serverAuth, "
            "so browsers reject it for a TLS server."
        ),
        "es": (
            "El ExtendedKeyUsage del certificado nombra otros propósitos y omite serverAuth, "
            "así que los navegadores lo rechazan para un servidor TLS."
        ),
    },
    "find.cert_no_san.title": {
        "en": "Certificate has no Subject Alternative Name",
        "es": "El certificado no tiene Subject Alternative Name",
    },
    "find.cert_no_san.desc": {
        "en": (
            "The certificate carries no SAN, only a subject Common Name; modern browsers "
            "require a SAN and reject a certificate without one."
        ),
        "es": (
            "El certificado no lleva SAN, solo un Common Name en el sujeto; los navegadores "
            "modernos exigen un SAN y rechazan un certificado que no lo tenga."
        ),
    },
    "find.cert_validity_too_long.title": {
        "en": "Certificate validity period is too long",
        "es": "El periodo de validez del certificado es demasiado largo",
    },
    "find.cert_validity_too_long.desc": {
        "en": (
            "The certificate is valid for {days} days; since 2020 the CA/Browser Forum caps "
            "TLS certificates at {max_days} days and Safari and Chrome reject longer ones."
        ),
        "es": (
            "El certificado es válido durante {days} días; desde 2020 el CA/Browser Forum limita "
            "los certificados TLS a {max_days} días y Safari y Chrome rechazan los más largos."
        ),
    },
    "find.cert_untrusted.title": {
        "en": "Certificate does not chain to a trusted root",
        "es": "El certificado no encadena con una raíz de confianza",
    },
    "find.cert_untrusted.desc": {
        "en": (
            "The presented chain does not build to any certificate in the trust store, so a "
            "browser would refuse this server's identity."
        ),
        "es": (
            "La cadena presentada no construye hasta ningún certificado del almacén de confianza, "
            "así que un navegador rechazaría la identidad de este servidor."
        ),
    },
    "find.cert_revoked.title": {
        "en": "Certificate has been revoked",
        "es": "El certificado ha sido revocado",
    },
    "find.cert_revoked.desc": {
        "en": (
            "An OCSP responder or CRL reports this certificate as revoked, so no client "
            "should trust it -- whatever the strength of its key and cipher suites."
        ),
        "es": (
            "Un respondedor OCSP o una CRL informan de que este certificado está revocado, "
            "así que ningún cliente debería confiar en él, por muy fuertes que sean su clave "
            "y sus cifrados."
        ),
    },
    "find.ocsp_staple_invalid.title": {
        "en": "Stapled OCSP response is not trustworthy",
        "es": "La respuesta OCSP grapada no es de fiar",
    },
    "find.ocsp_staple_invalid.desc": {
        "en": (
            "The server stapled an OCSP response, but it is not authentic or is stale, so a "
            "client that relies on stapling cannot confirm the certificate's status."
        ),
        "es": (
            "El servidor grapó una respuesta OCSP, pero no es auténtica o está caducada, así que "
            "un cliente que confíe en el grapado no puede confirmar el estado del certificado."
        ),
    },
    "find.cert_chain_incomplete.title": {
        "en": "Server sent an incomplete certificate chain",
        "es": "El servidor envió una cadena de certificados incompleta",
    },
    "find.cert_chain_incomplete.desc": {
        "en": (
            "The server did not send an intermediate CA certificate; it was retrievable from "
            "the AIA caIssuers URL, but clients that do not perform that fetch (many, including "
            "some TLS libraries) will fail to build a trusted path."
        ),
        "es": (
            "El servidor no envió un certificado de CA intermedia; se pudo obtener de la URL "
            "caIssuers de AIA, pero los clientes que no hacen esa descarga (muchos, incluidas "
            "algunas bibliotecas TLS) no lograrán construir una ruta de confianza."
        ),
    },
    "find.cert_chain_contains_anchor.title": {
        "en": "Chain includes the root CA",
        "es": "La cadena incluye la CA raíz",
    },
    "find.cert_chain_contains_anchor.desc": {
        "en": (
            "The server sends the self-signed root certificate; clients already hold their "
            "trust anchors and ignore it, so it only wastes handshake bytes."
        ),
        "es": (
            "El servidor envía el certificado raíz autofirmado; los clientes ya tienen sus anclas "
            "de confianza y lo ignoran, así que solo malgasta bytes del handshake."
        ),
    },
    "find.cert_self_signed.title": {
        "en": "Certificate is self-signed",
        "es": "El certificado es autofirmado",
    },
    "find.cert_self_signed.desc": {
        "en": "The certificate is its own issuer, so no authority vouches for it.",
        "es": "El certificado es su propio emisor, así que ninguna autoridad responde por él.",
    },
    "find.cert_bad_signature.title": {
        "en": "Certificate chain signature does not verify",
        "es": "La firma de la cadena de certificados no verifica",
    },
    "find.cert_bad_signature.desc": {
        "en": (
            "A presented certificate is not validly signed by the next in the chain, so the "
            "chain was tampered with or mis-assembled."
        ),
        "es": (
            "Un certificado presentado no está válidamente firmado por el siguiente de la cadena, "
            "así que la cadena se manipuló o se ensambló mal."
        ),
    },
    "find.cert_roca.title": {
        "en": "Certificate key is ROCA-vulnerable",
        "es": "La clave del certificado es vulnerable a ROCA",
    },
    "find.cert_roca.desc": {
        "en": (
            "The RSA key bears the ROCA fingerprint (CVE-2017-15361, the Infineon RSALib "
            "flaw), so its private key can be recovered by factoring -- the certificate is "
            "effectively compromised."
        ),
        "es": (
            "La clave RSA lleva la huella de ROCA (CVE-2017-15361, el fallo de la RSALib de "
            "Infineon), así que su clave privada se puede recuperar factorizando: el certificado "
            "está comprometido a efectos prácticos."
        ),
    },
    "find.cert_weak_key.title": {
        "en": "Certificate uses a weak key",
        "es": "El certificado usa una clave débil",
    },
    "find.cert_weak_key.desc": {
        "en": "The {key_type} key is below current strength requirements.",
        "es": "La clave {key_type} está por debajo de los requisitos de fuerza actuales.",
    },
    "find.cert_weak_signature.title": {
        "en": "Certificate uses a weak signature",
        "es": "El certificado usa una firma débil",
    },
    "find.cert_weak_signature.desc": {
        "en": "The certificate is signed with {algorithm}.",
        "es": "El certificado está firmado con {algorithm}.",
    },
    "find.cert_chain_weak_signature.title": {
        "en": "A chain certificate uses a weak signature",
        "es": "Un certificado de la cadena usa una firma débil",
    },
    "find.cert_chain_weak_signature.desc": {
        "en": (
            "An intermediate CA in the chain is signed with a weak algorithm (MD5/SHA-1), which "
            "browsers reject -- the whole path is only as strong as its weakest signature."
        ),
        "es": (
            "Una CA intermedia de la cadena está firmada con un algoritmo débil (MD5/SHA-1), que "
            "los navegadores rechazan: la ruta entera es tan fuerte como su firma más débil."
        ),
    },
    "find.cert_leaf_is_ca.title": {
        "en": "Leaf certificate is marked as a CA",
        "es": "El certificado de entidad final está marcado como CA",
    },
    "find.cert_leaf_is_ca.desc": {
        "en": (
            "The end-entity certificate has BasicConstraints CA:TRUE, so it is a CA certificate "
            "being served as a leaf -- a misconfiguration browsers may reject."
        ),
        "es": (
            "El certificado de entidad final tiene BasicConstraints CA:TRUE, así que es un "
            "certificado de CA servido como hoja: una mala configuración que los navegadores "
            "pueden rechazar."
        ),
    },
    "find.cert_alternate_invalid.title": {
        "en": "A second (alternate) certificate is invalid",
        "es": "Un segundo certificado (alternativo) no es válido",
    },
    "find.cert_alternate_invalid.desc": {
        "en": (
            "The server also serves a {key_type} certificate that a browser would reject "
            "({reasons}); a client that negotiates that key type gets an insecure connection "
            "even though the default certificate is valid."
        ),
        "es": (
            "El servidor sirve también un certificado {key_type} que un navegador rechazaría "
            "({reasons}); un cliente que negocie ese tipo de clave obtiene una conexión insegura "
            "aunque el certificado por defecto sea válido."
        ),
    },
    "find.cert_alternate_weak.title": {
        "en": "A second (alternate) certificate is weak",
        "es": "Un segundo certificado (alternativo) es débil",
    },
    "find.cert_alternate_weak.desc": {
        "en": (
            "The server also serves a {key_type} certificate with weaknesses ({reasons}); a "
            "client that negotiates that key type gets the weaker certificate."
        ),
        "es": (
            "El servidor sirve también un certificado {key_type} con debilidades ({reasons}); un "
            "cliente que negocie ese tipo de clave obtiene el certificado más débil."
        ),
    },
    # Negotiation class findings (protocol/cipher x insecure/weak)
    "find.class.protocol.insecure.title": {
        "en": "Insecure protocol versions offered",
        "es": "Versiones de protocolo inseguras ofrecidas",
    },
    "find.class.protocol.insecure.desc": {
        "en": "The server offers {n} insecure protocol versions.",
        "es": "El servidor ofrece {n} versiones de protocolo inseguras.",
    },
    "find.class.protocol.weak.title": {
        "en": "Weak protocol versions offered",
        "es": "Versiones de protocolo débiles ofrecidas",
    },
    "find.class.protocol.weak.desc": {
        "en": "The server offers {n} weak protocol versions.",
        "es": "El servidor ofrece {n} versiones de protocolo débiles.",
    },
    "find.class.cipher.insecure.title": {
        "en": "Insecure cipher suites offered",
        "es": "Conjuntos de cifrado inseguros ofrecidos",
    },
    "find.class.cipher.insecure.desc": {
        "en": "The server offers {n} insecure cipher suites.",
        "es": "El servidor ofrece {n} conjuntos de cifrado inseguros.",
    },
    "find.class.cipher.weak.title": {
        "en": "Weak cipher suites offered",
        "es": "Conjuntos de cifrado débiles ofrecidos",
    },
    "find.class.cipher.weak.desc": {
        "en": "The server offers {n} weak cipher suites.",
        "es": "El servidor ofrece {n} conjuntos de cifrado débiles.",
    },
    # DANE / CAA / HTTPS (DNS-layer) findings
    "find.dane_not_dnssec.title": {
        "en": "DANE/TLSA record is not authenticated by DNSSEC",
        "es": "El registro DANE/TLSA no está autenticado por DNSSEC",
    },
    "find.dane_not_dnssec.desc": {
        "en": (
            "The domain publishes a DANE TLSA pin, but its DNSSEC chain does not validate to the "
            "root, so an on-path attacker can forge or strip it and a DANE client ignores it -- "
            "the pin gives no real protection."
        ),
        "es": (
            "El dominio publica un anclaje DANE TLSA, pero su cadena DNSSEC no valida hasta la "
            "raíz, así que un atacante en la ruta puede falsificarlo o suprimirlo y un cliente "
            "DANE lo ignora: el anclaje no da protección real."
        ),
    },
    "find.dane_not_dnssec.rem": {
        "en": (
            "Sign the zone with DNSSEC (a full chain to the root) so the TLSA record is "
            "authenticated."
        ),
        "es": (
            "Firma la zona con DNSSEC (una cadena completa hasta la raíz) para que el registro "
            "TLSA quede autenticado."
        ),
    },
    "find.dane_mismatch.title": {
        "en": "Certificate does not match the DANE/TLSA record",
        "es": "El certificado no coincide con el registro DANE/TLSA",
    },
    "find.dane_mismatch.desc": {
        "en": (
            "The domain publishes a DNSSEC-authenticated DANE TLSA pin for an end-entity "
            "certificate, but the certificate the server presented matches none of them; a "
            "DANE-validating client would refuse the connection (RFC 6698)."
        ),
        "es": (
            "El dominio publica un anclaje DANE TLSA autenticado por DNSSEC para un certificado de "
            "entidad final, pero el certificado que presentó el servidor no coincide con ninguno; "
            "un cliente que valide DANE rechazaría la conexión (RFC 6698)."
        ),
    },
    "find.dane_mismatch.rem": {
        "en": "Republish the TLSA record for the current certificate, or serve the pinned one.",
        "es": "Vuelve a publicar el registro TLSA del certificado actual, o sirve el anclado.",
    },
    "find.caa_not_dnssec.title": {
        "en": "CAA policy is not authenticated by DNSSEC",
        "es": "La política CAA no está autenticada por DNSSEC",
    },
    "find.caa_not_dnssec.desc": {
        "en": (
            "The domain publishes a CAA policy restricting which CAs may issue for it, but its "
            "zone is not DNSSEC-signed, so an attacker able to spoof DNS toward a certificate "
            "authority can strip or alter the policy and obtain a certificate it was meant to "
            "forbid (RFC 8659 recommends DNSSEC-signing CAA)."
        ),
        "es": (
            "El dominio publica una política CAA que restringe qué CA pueden emitir para él, pero "
            "su zona no está firmada con DNSSEC, así que un atacante capaz de falsear el DNS ante "
            "una autoridad de certificación puede suprimir o alterar la política y obtener un "
            "certificado que debía prohibir (RFC 8659 recomienda firmar CAA con DNSSEC)."
        ),
    },
    "find.caa_not_dnssec.rem": {
        "en": "Sign the zone with DNSSEC so the CAA policy a CA resolves is authentic.",
        "es": (
            "Firma la zona con DNSSEC para que la política CAA que resuelve una CA sea auténtica."
        ),
    },
    "find.caa_forbids_wildcard.title": {
        "en": "Wildcard certificate served against a CAA that forbids wildcards",
        "es": "Certificado comodín servido contra una CAA que prohíbe los comodines",
    },
    "find.caa_forbids_wildcard.desc": {
        "en": (
            "The domain's DNSSEC-authenticated CAA policy authorises no CA to issue wildcard "
            "certificates, yet the server presents a wildcard certificate -- a sign of "
            "mis-issuance, or of a policy tightened after issuance."
        ),
        "es": (
            "La política CAA del dominio, autenticada por DNSSEC, no autoriza a ninguna CA a "
            "emitir certificados comodín, y sin embargo el servidor presenta uno: señal de una "
            "emisión indebida, o de una política endurecida tras la emisión."
        ),
    },
    "find.caa_forbids_wildcard.rem": {
        "en": (
            "Reconcile the certificate and the policy: re-issue a non-wildcard certificate, or "
            "authorise a CA for wildcards in CAA."
        ),
        "es": (
            "Reconcilia el certificado y la política: reemite un certificado no comodín, o "
            "autoriza a una CA para comodines en la CAA."
        ),
    },
    "find.caa_forbids_issuance.title": {
        "en": "Certificate served against a CAA that forbids all issuance",
        "es": "Certificado servido contra una CAA que prohíbe toda emisión",
    },
    "find.caa_forbids_issuance.desc": {
        "en": (
            "The domain's DNSSEC-authenticated CAA policy authorises no CA to issue for it at all "
            "(an empty issue value), yet the server presents a certificate -- a sign of "
            "mis-issuance, or of a policy tightened after issuance so the certificate cannot be "
            "renewed."
        ),
        "es": (
            "La política CAA del dominio, autenticada por DNSSEC, no autoriza a ninguna CA a "
            "emitir para él (un valor issue vacío), y sin embargo el servidor presenta un "
            "certificado: señal de una emisión indebida, o de una política endurecida tras la "
            "emisión de modo que el certificado no puede renovarse."
        ),
    },
    "find.caa_forbids_issuance.rem": {
        "en": (
            "Reconcile the certificate and the policy: authorise the issuing CA in CAA, or "
            "investigate how a certificate was issued against the prohibition."
        ),
        "es": (
            "Reconcilia el certificado y la política: autoriza en la CAA a la CA emisora, o "
            "investiga cómo se emitió un certificado contra la prohibición."
        ),
    },
    "find.https_ech_not_dnssec.title": {
        "en": "ECH configuration is not authenticated by DNSSEC",
        "es": "La configuración ECH no está autenticada por DNSSEC",
    },
    "find.https_ech_not_dnssec.desc": {
        "en": (
            "The domain advertises Encrypted Client Hello in an HTTPS/SVCB record, but the record "
            "is not DNSSEC-signed, so an on-path attacker can strip it and force the client to "
            "fall back to sending the SNI in cleartext -- the SNI-privacy the ECH config promises "
            "is not guaranteed."
        ),
        "es": (
            "El dominio anuncia Encrypted Client Hello en un registro HTTPS/SVCB, pero el registro "
            "no está firmado con DNSSEC, así que un atacante en la ruta puede suprimirlo y forzar "
            "al cliente a enviar el SNI en claro: la privacidad de SNI que promete la "
            "configuración ECH no está garantizada."
        ),
    },
    "find.https_ech_not_dnssec.rem": {
        "en": (
            "Sign the zone with DNSSEC so the HTTPS record carrying the ECH config cannot be "
            "stripped or forged undetected."
        ),
        "es": (
            "Firma la zona con DNSSEC para que el registro HTTPS que lleva la configuración ECH no "
            "pueda suprimirse ni falsificarse sin ser detectado."
        ),
    },
    # TLS feature findings
    "find.tls_insecure_renegotiation.title": {
        "en": "No secure renegotiation",
        "es": "Sin renegociación segura",
    },
    "find.tls_insecure_renegotiation.desc": {
        "en": (
            "The server does not support secure renegotiation (RFC 5746), so if it renegotiates "
            "it is open to the plaintext prefix injection of CVE-2009-3555."
        ),
        "es": (
            "El servidor no admite renegociación segura (RFC 5746), así que si renegocia queda "
            "expuesto a la inyección de prefijo en claro de CVE-2009-3555."
        ),
    },
    "find.tls_insecure_renegotiation.rem": {
        "en": "Enable RFC 5746 secure renegotiation, or disable renegotiation.",
        "es": "Habilita la renegociación segura de RFC 5746, o deshabilita la renegociación.",
    },
    "find.tls_no_extended_master_secret.title": {
        "en": "No extended master secret",
        "es": "Sin extended master secret",
    },
    "find.tls_no_extended_master_secret.desc": {
        "en": (
            "The 1.2 server does not support the extended master secret (RFC 7627), which binds "
            "the master secret to the handshake and closes the Triple Handshake attack."
        ),
        "es": (
            "El servidor 1.2 no admite el extended master secret (RFC 7627), que ata el master "
            "secret al handshake y cierra el ataque Triple Handshake."
        ),
    },
    "find.tls_no_extended_master_secret.rem": {
        "en": "Enable the extended master secret (RFC 7627) extension.",
        "es": "Habilita la extensión extended master secret (RFC 7627).",
    },
    "find.tls_no_encrypt_then_mac.title": {
        "en": "CBC cipher suites without Encrypt-then-MAC",
        "es": "Conjuntos de cifrado CBC sin Encrypt-then-MAC",
    },
    "find.tls_no_encrypt_then_mac.desc": {
        "en": (
            "The 1.2 server negotiates CBC cipher suites but does not support Encrypt-then-MAC "
            "(RFC 7366), so those records use MAC-then-encrypt -- the construction the Lucky13 "
            "and related padding-oracle attacks target."
        ),
        "es": (
            "El servidor 1.2 negocia conjuntos de cifrado CBC pero no admite Encrypt-then-MAC "
            "(RFC 7366), así que esos registros usan MAC-then-encrypt: la construcción a la que "
            "apuntan Lucky13 y los ataques de oráculo de relleno afines."
        ),
    },
    "find.tls_no_encrypt_then_mac.rem": {
        "en": (
            "Prefer AEAD suites (AES-GCM, ChaCha20-Poly1305), or enable RFC 7366 Encrypt-then-MAC "
            "for the CBC suites."
        ),
        "es": (
            "Prefiere conjuntos AEAD (AES-GCM, ChaCha20-Poly1305), o habilita Encrypt-then-MAC de "
            "RFC 7366 para los conjuntos CBC."
        ),
    },
    "find.tls_no_fallback_scsv.title": {
        "en": "No downgrade protection",
        "es": "Sin protección contra degradación",
    },
    "find.tls_no_fallback_scsv.desc": {
        "en": (
            "The server accepts a downgraded handshake carrying TLS_FALLBACK_SCSV instead of "
            "refusing it (RFC 7507), so an attacker forcing a version fallback is not detected."
        ),
        "es": (
            "El servidor acepta un handshake degradado que lleva TLS_FALLBACK_SCSV en vez de "
            "rechazarlo (RFC 7507), así que un atacante que fuerce una caída de versión no se "
            "detecta."
        ),
    },
    "find.tls_no_fallback_scsv.rem": {
        "en": "Honour TLS_FALLBACK_SCSV and reject a downgraded handshake.",
        "es": "Respeta TLS_FALLBACK_SCSV y rechaza un handshake degradado.",
    },
    "find.tls_no_downgrade_sentinel.title": {
        "en": "No TLS 1.3 downgrade sentinel",
        "es": "Sin centinela de degradación de TLS 1.3",
    },
    "find.tls_no_downgrade_sentinel.desc": {
        "en": (
            "The server supports TLS 1.3 but omits the downgrade sentinel from "
            "ServerHello.random when it negotiates TLS 1.2 (RFC 8446 4.1.3), so an attacker "
            "forcing a 1.3 client down to 1.2 leaves no signal the client can reject."
        ),
        "es": (
            "El servidor admite TLS 1.3 pero omite el centinela de degradación de "
            "ServerHello.random cuando negocia TLS 1.2 (RFC 8446 4.1.3), así que un atacante que "
            "fuerce a un cliente 1.3 a bajar a 1.2 no deja ninguna señal que el cliente pueda "
            "rechazar."
        ),
    },
    "find.tls_no_downgrade_sentinel.rem": {
        "en": "Use a TLS stack that writes the RFC 8446 4.1.3 downgrade sentinel.",
        "es": "Usa una pila TLS que escriba el centinela de degradación de RFC 8446 4.1.3.",
    },
    "find.tls_no_cipher_preference.title": {
        "en": "Server honours the client's cipher order",
        "es": "El servidor respeta el orden de cifrado del cliente",
    },
    "find.tls_no_cipher_preference.desc": {
        "en": (
            "The 1.2 server takes the client's cipher preference instead of imposing its own, so "
            "an attacker who can steer the client's ClientHello can pull the connection onto the "
            "weakest cipher suite both sides support."
        ),
        "es": (
            "El servidor 1.2 toma la preferencia de cifrado del cliente en vez de imponer la "
            "suya, así que un atacante capaz de dirigir el ClientHello del cliente puede llevar la "
            "conexión al conjunto de cifrado más débil que ambos admiten."
        ),
    },
    "find.tls_no_cipher_preference.rem": {
        "en": "Configure the server to enforce its own cipher order (strongest first).",
        "es": "Configura el servidor para imponer su propio orden de cifrado (el más fuerte "
        "primero).",
    },
    "find.tls_grease_intolerant.title": {
        "en": "Server is GREASE-intolerant",
        "es": "El servidor es intolerante a GREASE",
    },
    "find.tls_grease_intolerant.desc": {
        "en": (
            "The server rejects a ClientHello carrying GREASE values (RFC 8701) that it is "
            "required to ignore, so it risks breaking as new TLS ciphers, groups or extensions "
            "are introduced."
        ),
        "es": (
            "El servidor rechaza un ClientHello que lleva valores GREASE (RFC 8701) que está "
            "obligado a ignorar, así que se arriesga a romperse a medida que se introducen nuevos "
            "cifrados, grupos o extensiones de TLS."
        ),
    },
    "find.tls_grease_intolerant.rem": {
        "en": "Use a TLS stack that ignores unknown (GREASE) values as RFC 8701 requires.",
        "es": "Usa una pila TLS que ignore los valores desconocidos (GREASE) como exige RFC 8701.",
    },
    "find.tls_weak_dh_params.title": {
        "en": "Weak Diffie-Hellman parameters",
        "es": "Parámetros Diffie-Hellman débiles",
    },
    "find.tls_weak_dh_params.desc": {
        "en": (
            "The server's DHE key exchange uses a {bits}-bit finite-field prime. Primes below "
            "2048 bits are weak, and a 1024-bit or smaller (export-grade) prime is within reach "
            "of precomputation (Logjam, CVE-2015-4000)."
        ),
        "es": (
            "El intercambio de claves DHE del servidor usa un primo de campo finito de {bits} "
            "bits. Los primos por debajo de 2048 bits son débiles, y uno de 1024 bits o menos "
            "(de grado exportación) está al alcance de la precomputación (Logjam, CVE-2015-4000)."
        ),
    },
    "find.tls_weak_dh_params.rem": {
        "en": "Use a 2048-bit or larger DH group, or disable DHE and prefer ECDHE.",
        "es": "Usa un grupo DH de 2048 bits o más, o deshabilita DHE y prefiere ECDHE.",
    },
    "find.tls_0rtt_enabled.title": {
        "en": "0-RTT early data enabled",
        "es": "Datos tempranos 0-RTT habilitados",
    },
    "find.tls_0rtt_enabled.desc": {
        "en": (
            "The TLS 1.3 server offers 0-RTT early data, which a network attacker can capture and "
            "replay (RFC 8446 appendix E.5); a replayed non-idempotent request can repeat its "
            "side effect."
        ),
        "es": (
            "El servidor TLS 1.3 ofrece datos tempranos 0-RTT, que un atacante de red puede "
            "capturar y reproducir (RFC 8446 apéndice E.5); una petición no idempotente "
            "reproducida puede repetir su efecto."
        ),
    },
    "find.tls_0rtt_enabled.rem": {
        "en": "Accept 0-RTT only for idempotent requests, or disable early data.",
        "es": "Acepta 0-RTT solo para peticiones idempotentes, o deshabilita los datos tempranos.",
    },
    "find.sslv2_export_ciphers.title": {
        "en": "SSL 2.0 with export ciphers",
        "es": "SSL 2.0 con cifrados de exportación",
    },
    "find.sslv2_export_ciphers.desc": {
        "en": (
            "The server speaks SSL 2.0 and offers 40-bit export ciphers, which turns DROWN "
            "(CVE-2016-0800) from possible into practical -- an attacker can decrypt a captured "
            "TLS_RSA session in hours."
        ),
        "es": (
            "El servidor habla SSL 2.0 y ofrece cifrados de exportación de 40 bits, lo que "
            "convierte DROWN (CVE-2016-0800) de posible en práctico: un atacante puede descifrar "
            "una sesión TLS_RSA capturada en horas."
        ),
    },
    "find.sslv2_export_ciphers.rem": {
        "en": "Disable SSL 2.0 entirely.",
        "es": "Deshabilita SSL 2.0 por completo.",
    },
    "find.ocsp_must_staple_violated.title": {
        "en": "Must-staple certificate is not stapled",
        "es": "Certificado must-staple sin grapar",
    },
    "find.ocsp_must_staple_violated.desc": {
        "en": (
            "The certificate is marked OCSP must-staple (RFC 7633) but the server did not staple "
            "a response, so clients that enforce it will refuse the connection."
        ),
        "es": (
            "El certificado está marcado como OCSP must-staple (RFC 7633) pero el servidor no "
            "grapó una respuesta, así que los clientes que lo exijan rechazarán la conexión."
        ),
    },
    "find.ocsp_must_staple_violated.rem": {
        "en": "Enable OCSP stapling, or reissue the certificate without must-staple.",
        "es": "Habilita el grapado OCSP, o reemite el certificado sin must-staple.",
    },
    "find.tls_compression.title": {
        "en": "TLS compression enabled (CRIME)",
        "es": "Compresión TLS habilitada (CRIME)",
    },
    "find.tls_compression.desc": {
        "en": (
            "The server agreed to compress the TLS record layer, which leaks secrets such as "
            "session cookies through the CRIME side channel (CVE-2012-4929)."
        ),
        "es": (
            "El servidor accedió a comprimir la capa de registro TLS, lo que filtra secretos como "
            "las cookies de sesión por el canal lateral CRIME (CVE-2012-4929)."
        ),
    },
    "find.tls_compression.rem": {
        "en": "Disable TLS-level compression.",
        "es": "Deshabilita la compresión a nivel de TLS.",
    },
    # HTTP-layer findings (http_layer.py)
    "find.http_csp_unsafe_inline.title": {
        "en": "CSP allows inline scripts",
        "es": "La CSP permite scripts en línea",
    },
    "find.http_csp_unsafe_inline.desc": {
        "en": (
            "The Content-Security-Policy lets scripts run inline ('unsafe-inline') with no nonce "
            "or hash to restrict them, so an injected <script> executes -- defeating most of the "
            "XSS protection a CSP is meant to provide."
        ),
        "es": (
            "La Content-Security-Policy deja ejecutar scripts en línea ('unsafe-inline') sin un "
            "nonce ni un hash que los restrinja, así que un <script> inyectado se ejecuta y anula "
            "casi toda la protección contra XSS que una CSP debería dar."
        ),
    },
    "find.http_csp_unsafe_inline.rem": {
        "en": (
            "Drop 'unsafe-inline' and allow specific scripts with a per-response nonce or a hash."
        ),
        "es": (
            "Quita 'unsafe-inline' y permite scripts concretos con un nonce por respuesta o un "
            "hash."
        ),
    },
    "find.http_csp_unsafe_eval.title": {
        "en": "CSP allows eval()",
        "es": "La CSP permite eval()",
    },
    "find.http_csp_unsafe_eval.desc": {
        "en": (
            "The Content-Security-Policy allows 'unsafe-eval', so string-to-code paths (eval, new "
            "Function, setTimeout(string)) run -- a wider attack surface for injected script."
        ),
        "es": (
            "La Content-Security-Policy permite 'unsafe-eval', así que las vías de cadena a código "
            "(eval, new Function, setTimeout(string)) se ejecutan: una superficie de ataque mayor "
            "para el script inyectado."
        ),
    },
    "find.http_csp_unsafe_eval.rem": {
        "en": "Remove 'unsafe-eval' and refactor code that compiles strings.",
        "es": "Elimina 'unsafe-eval' y refactoriza el código que compila cadenas.",
    },
    "find.http_csp_broad_script_src.title": {
        "en": "CSP allows scripts from any host",
        "es": "La CSP permite scripts desde cualquier host",
    },
    "find.http_csp_broad_script_src.desc": {
        "en": (
            "The script sources include an over-broad value (a bare wildcard, a scheme-only "
            "source, or data:), so a script from essentially any origin is allowed and the policy "
            "does little to contain XSS."
        ),
        "es": (
            "Las fuentes de scripts incluyen un valor demasiado amplio (un comodín a secas, una "
            "fuente de solo esquema, o data:), así que se permite un script de prácticamente "
            "cualquier origen y la política apenas contiene el XSS."
        ),
    },
    "find.http_csp_broad_script_src.rem": {
        "en": "List the specific origins scripts may load from instead of a wildcard or scheme.",
        "es": "Enumera los orígenes concretos desde los que pueden cargarse scripts en vez de un "
        "comodín o un esquema.",
    },
    "find.http_cleartext.title": {
        "en": "Unencrypted HTTP (no TLS)",
        "es": "HTTP sin cifrar (sin TLS)",
    },
    "find.http_cleartext.desc": {
        "en": (
            "The server answers over plain HTTP with no TLS at all, so every request and response "
            "-- credentials, cookies, tokens, page content -- travels in cleartext, open to any "
            "eavesdropper on the path and to tampering. Anything layered on it (a WebSocket, "
            "HTTP/2) is exposed the same way."
        ),
        "es": (
            "El servidor responde por HTTP en claro sin TLS alguno, así que cada petición y "
            "respuesta -- credenciales, cookies, tokens, contenido de la página -- viaja en "
            "claro, expuesta a cualquier fisgón de la ruta y a manipulación. Todo lo que se apoye "
            "encima (un WebSocket, HTTP/2) queda expuesto igual."
        ),
    },
    "find.http_cleartext.rem": {
        "en": "Serve the site over HTTPS and redirect HTTP to it, with HSTS.",
        "es": "Sirve el sitio por HTTPS y redirige HTTP hacia él, con HSTS.",
    },
    "find.http_no_hsts.title": {
        "en": "No HSTS",
        "es": "Sin HSTS",
    },
    "find.http_no_hsts.desc": {
        "en": (
            "The endpoint does not send a Strict-Transport-Security header, so a browser will "
            "still try plaintext HTTP and can be stripped down to it."
        ),
        "es": (
            "El endpoint no envía la cabecera Strict-Transport-Security, así que un navegador "
            "seguirá intentando HTTP en claro y puede ser degradado a él."
        ),
    },
    "find.http_no_hsts.rem": {
        "en": "Send Strict-Transport-Security with a max-age of at least 180 days.",
        "es": "Envía Strict-Transport-Security con un max-age de al menos 180 días.",
    },
    "find.http_weak_hsts.title": {
        "en": "Short HSTS max-age",
        "es": "max-age de HSTS demasiado corto",
    },
    "find.http_weak_hsts.desc": {
        "en": "HSTS is set but max-age={max_age} is under 180 days.",
        "es": "HSTS está puesto pero max-age={max_age} es inferior a 180 días.",
    },
    "find.http_weak_hsts.rem": {
        "en": "Raise the HSTS max-age to at least 15552000 (180 days).",
        "es": "Sube el max-age de HSTS a al menos 15552000 (180 días).",
    },
    "find.http_hsts_no_subdomains.title": {
        "en": "HSTS without includeSubDomains",
        "es": "HSTS sin includeSubDomains",
    },
    "find.http_hsts_no_subdomains.desc": {
        "en": (
            "HSTS is set but omits includeSubDomains, so subdomains are not covered by the policy "
            "(and it cannot be added to the browser preload list)."
        ),
        "es": (
            "HSTS está puesto pero omite includeSubDomains, así que los subdominios no quedan "
            "cubiertos por la política (y no puede añadirse a la lista de precarga del navegador)."
        ),
    },
    "find.http_hsts_no_subdomains.rem": {
        "en": "Add includeSubDomains to the Strict-Transport-Security header.",
        "es": "Añade includeSubDomains a la cabecera Strict-Transport-Security.",
    },
    "find.http_hsts_preload_ineligible.title": {
        "en": "HSTS preload token but the policy is ineligible",
        "es": "Token de precarga de HSTS pero la política no es elegible",
    },
    "find.http_hsts_preload_ineligible.desc": {
        "en": (
            "The HSTS header carries the preload token, but the policy does not meet the "
            "preload-list requirements (a max-age of at least one year and includeSubDomains), so "
            "the token is ignored and the site is not actually preloaded -- a false sense of "
            "protection for first, un-cached visits."
        ),
        "es": (
            "La cabecera HSTS lleva el token preload, pero la política no cumple los requisitos de "
            "la lista de precarga (un max-age de al menos un año e includeSubDomains), así que el "
            "token se ignora y el sitio no está realmente precargado: una falsa sensación de "
            "protección en las primeras visitas sin caché."
        ),
    },
    "find.http_hsts_preload_ineligible.rem": {
        "en": (
            "Set max-age to at least 31536000 and includeSubDomains, then submit the domain to the "
            "preload list."
        ),
        "es": (
            "Pon max-age a al menos 31536000 e includeSubDomains, y luego envía el dominio a la "
            "lista de precarga."
        ),
    },
    "find.http_no_https_redirect.title": {
        "en": "Cleartext HTTP is not redirected to HTTPS",
        "es": "El HTTP en claro no se redirige a HTTPS",
    },
    "find.http_no_https_redirect.desc": {
        "en": (
            "The server answers plain HTTP on port 80 without redirecting to HTTPS, so a "
            "browser's first, un-cached request travels in cleartext -- open to eavesdropping and "
            "to being kept on HTTP (SSL stripping) before HSTS can take effect."
        ),
        "es": (
            "El servidor responde por HTTP en claro en el puerto 80 sin redirigir a HTTPS, así "
            "que la primera petición sin caché de un navegador viaja en claro: expuesta a escucha "
            "y a quedarse en HTTP (SSL stripping) antes de que HSTS pueda surtir efecto."
        ),
    },
    "find.http_no_https_redirect.rem": {
        "en": (
            "Redirect all HTTP (port 80) traffic to HTTPS with a 301, and serve HSTS over the "
            "HTTPS response."
        ),
        "es": (
            "Redirige todo el tráfico HTTP (puerto 80) a HTTPS con un 301, y sirve HSTS en la "
            "respuesta HTTPS."
        ),
    },
    "find.http_subresource_no_sri.title": {
        "en": "Cross-origin subresource without Subresource Integrity",
        "es": "Subrecurso de origen cruzado sin Subresource Integrity",
    },
    "find.http_subresource_no_sri.desc": {
        "en": (
            "The page loads a script or stylesheet from another origin without an integrity "
            "attribute, so if that host (or the connection to it) is compromised its code runs in "
            "this page's origin with nothing to detect the tampering."
        ),
        "es": (
            "La página carga un script o una hoja de estilos de otro origen sin un atributo "
            "integrity, así que si ese host (o la conexión a él) se ve comprometido su código se "
            "ejecuta en el origen de esta página sin nada que detecte la manipulación."
        ),
    },
    "find.http_subresource_no_sri.rem": {
        "en": (
            'Add an integrity="sha384-..." (with crossorigin) attribute to cross-origin <script> '
            "and stylesheet <link> tags."
        ),
        "es": (
            'Añade un atributo integrity="sha384-..." (con crossorigin) a las etiquetas <script> '
            "y <link> de hojas de estilo de origen cruzado."
        ),
    },
    "find.http_cors_credentialed.title": {
        "en": "CORS reflects any origin with credentials",
        "es": "CORS refleja cualquier origen con credenciales",
    },
    "find.http_cors_credentialed.desc": {
        "en": (
            "The server echoed an arbitrary Origin in Access-Control-Allow-Origin and also sent "
            "Access-Control-Allow-Credentials: true, so any site a victim visits can read this "
            "origin's authenticated responses (their session included)."
        ),
        "es": (
            "El servidor reflejó un Origin arbitrario en Access-Control-Allow-Origin y además "
            "envió Access-Control-Allow-Credentials: true, así que cualquier sitio que visite la "
            "víctima puede leer las respuestas autenticadas de este origen (su sesión incluida)."
        ),
    },
    "find.http_cors_credentialed.rem": {
        "en": (
            "Never pair credentials with a reflected or dynamic origin; allow only a fixed list "
            "of trusted origins."
        ),
        "es": (
            "Nunca combines credenciales con un origen reflejado o dinámico; permite solo una "
            "lista fija de orígenes de confianza."
        ),
    },
    "find.http_cors_open.title": {
        "en": "CORS allows any origin to read responses",
        "es": "CORS permite a cualquier origen leer las respuestas",
    },
    "find.http_cors_open.desc": {
        "en": (
            "Access-Control-Allow-Origin is a wildcard or reflects any origin, so any site can "
            "read this endpoint's responses -- fine for genuinely public data, a leak if the "
            "responses are ever user-specific."
        ),
        "es": (
            "Access-Control-Allow-Origin es un comodín o refleja cualquier origen, así que "
            "cualquier sitio puede leer las respuestas de este endpoint: bien para datos "
            "genuinamente públicos, una fuga si las respuestas son alguna vez específicas del "
            "usuario."
        ),
    },
    "find.http_cors_open.rem": {
        "en": "Restrict Access-Control-Allow-Origin to the origins that need it.",
        "es": "Restringe Access-Control-Allow-Origin a los orígenes que lo necesiten.",
    },
    "find.http_xcto_ineffective.title": {
        "en": "X-Content-Type-Options is set but not 'nosniff'",
        "es": "X-Content-Type-Options está puesto pero no es 'nosniff'",
    },
    "find.http_xcto_ineffective.desc": {
        "en": (
            "The header is present but its value is not 'nosniff', so browsers still MIME-sniff "
            "responses -- the content-type confusion the header exists to stop is not actually "
            "prevented, and the header reads as protection that is not there."
        ),
        "es": (
            "La cabecera está presente pero su valor no es 'nosniff', así que los navegadores "
            "siguen haciendo MIME-sniffing de las respuestas: la confusión de content-type que la "
            "cabecera existe para evitar no se impide en realidad, y la cabecera aparenta una "
            "protección que no está."
        ),
    },
    "find.http_xcto_ineffective.rem": {
        "en": "Set X-Content-Type-Options: nosniff (exactly that value).",
        "es": "Pon X-Content-Type-Options: nosniff (exactamente ese valor).",
    },
    "find.http_xfo_ineffective.title": {
        "en": "X-Frame-Options is set to a value modern browsers ignore",
        "es": "X-Frame-Options tiene un valor que los navegadores modernos ignoran",
    },
    "find.http_xfo_ineffective.desc": {
        "en": (
            "The value is neither DENY nor SAMEORIGIN (e.g. the deprecated ALLOW-FROM), so "
            "Chrome, Firefox and Safari ignore it and the page can still be framed -- "
            "clickjacking is not prevented, and no CSP frame-ancestors covers it either."
        ),
        "es": (
            "El valor no es DENY ni SAMEORIGIN (p. ej. el obsoleto ALLOW-FROM), así que Chrome, "
            "Firefox y Safari lo ignoran y la página aún puede enmarcarse: no se impide el "
            "clickjacking, y tampoco lo cubre ninguna frame-ancestors de CSP."
        ),
    },
    "find.http_xfo_ineffective.rem": {
        "en": "Use X-Frame-Options: DENY or SAMEORIGIN, or a CSP frame-ancestors directive.",
        "es": "Usa X-Frame-Options: DENY o SAMEORIGIN, o una directiva frame-ancestors de CSP.",
    },
    "find.http_insecure_cookie.title": {
        "en": "Cookie without the Secure flag",
        "es": "Cookie sin el atributo Secure",
    },
    "find.http_insecure_cookie.desc": {
        "en": (
            "A cookie is set without Secure, so it can ride an accidental plaintext request and "
            "leak."
        ),
        "es": (
            "Se establece una cookie sin Secure, así que puede viajar en una petición en claro "
            "accidental y filtrarse."
        ),
    },
    "find.http_insecure_cookie.rem": {
        "en": "Add the Secure flag (and HttpOnly and SameSite) to every cookie.",
        "es": "Añade el atributo Secure (y HttpOnly y SameSite) a cada cookie.",
    },
    "find.http_cookie_no_httponly.title": {
        "en": "Cookie without HttpOnly",
        "es": "Cookie sin HttpOnly",
    },
    "find.http_cookie_no_httponly.desc": {
        "en": (
            "A cookie is set without HttpOnly, so client-side script can read it -- a session "
            "cookie so exposed is stealable through cross-site scripting."
        ),
        "es": (
            "Se establece una cookie sin HttpOnly, así que el script del lado del cliente puede "
            "leerla: una cookie de sesión así expuesta se puede robar mediante cross-site "
            "scripting."
        ),
    },
    "find.http_cookie_no_httponly.rem": {
        "en": "Add HttpOnly to cookies that scripts do not need to read.",
        "es": "Añade HttpOnly a las cookies que los scripts no necesiten leer.",
    },
    "find.http_cookie_weak_samesite.title": {
        "en": "Cookie without an effective SameSite",
        "es": "Cookie sin un SameSite efectivo",
    },
    "find.http_cookie_weak_samesite.desc": {
        "en": (
            "A cookie is set without SameSite (or with SameSite=None but no Secure), so it rides "
            "cross-site requests -- a CSRF exposure."
        ),
        "es": (
            "Se establece una cookie sin SameSite (o con SameSite=None pero sin Secure), así que "
            "viaja en peticiones de sitio cruzado: una exposición a CSRF."
        ),
    },
    "find.http_cookie_weak_samesite.rem": {
        "en": "Set SameSite=Lax or Strict (SameSite=None requires Secure).",
        "es": "Pon SameSite=Lax o Strict (SameSite=None requiere Secure).",
    },
    "find.http_cookie_prefix_invalid.title": {
        "en": "Cookie name prefix guarantee not met",
        "es": "No se cumple la garantía del prefijo del nombre de la cookie",
    },
    "find.http_cookie_prefix_invalid.desc": {
        "en": (
            "A cookie uses a __Secure- or __Host- name prefix but breaks its contract, so a "
            "browser rejects it: __Secure- requires Secure; __Host- also requires Path=/ and no "
            "Domain."
        ),
        "es": (
            "Una cookie usa un prefijo de nombre __Secure- o __Host- pero rompe su contrato, así "
            "que un navegador la rechaza: __Secure- requiere Secure; __Host- requiere además "
            "Path=/ y sin Domain."
        ),
    },
    "find.http_cookie_prefix_invalid.rem": {
        "en": (
            "Honour the prefix: __Secure- needs Secure; __Host- needs Secure, Path=/ and no Domain."
        ),
        "es": (
            "Respeta el prefijo: __Secure- necesita Secure; __Host- necesita Secure, Path=/ y "
            "sin Domain."
        ),
    },
    "find.http_mixed_active.title": {
        "en": "Active mixed content over http://",
        "es": "Contenido mixto activo por http://",
    },
    "find.http_mixed_active.desc": {
        "en": (
            "The HTTPS page loads active resources (scripts, stylesheets, iframes or form "
            "targets) over plain http://. Browsers block these -- breaking the page -- and where "
            "a browser does not, an on-path attacker can inject code into the page's own origin."
        ),
        "es": (
            "La página HTTPS carga recursos activos (scripts, hojas de estilo, iframes o destinos "
            "de formulario) por http:// en claro. Los navegadores los bloquean -- rompiendo la "
            "página -- y donde un navegador no lo hace, un atacante en la ruta puede inyectar "
            "código en el propio origen de la página."
        ),
    },
    "find.http_mixed_active.rem": {
        "en": (
            "Serve every subresource over https:// (a protocol-relative or relative URL also "
            "inherits the secure scheme)."
        ),
        "es": (
            "Sirve cada subrecurso por https:// (una URL relativa al protocolo o relativa también "
            "hereda el esquema seguro)."
        ),
    },
    "find.http_mixed_passive.title": {
        "en": "Passive mixed content over http://",
        "es": "Contenido mixto pasivo por http://",
    },
    "find.http_mixed_passive.desc": {
        "en": (
            "The HTTPS page loads images or media over plain http://. Browsers warn on or upgrade "
            "these; until fixed, the resources can be watched or swapped by an on-path attacker."
        ),
        "es": (
            "La página HTTPS carga imágenes o medios por http:// en claro. Los navegadores avisan "
            "de ellos o los actualizan; hasta que se corrija, un atacante en la ruta puede "
            "observarlos o sustituirlos."
        ),
    },
    "find.http_mixed_passive.rem": {
        "en": "Serve images and media over https:// as well.",
        "es": "Sirve también las imágenes y los medios por https://.",
    },
    # Missing security-header findings: distinct title each, shared desc/rem template.
    "find.http_no_csp.title": {
        "en": "No Content-Security-Policy",
        "es": "Sin Content-Security-Policy",
    },
    "find.http_no_xcto.title": {
        "en": "No X-Content-Type-Options: nosniff",
        "es": "Sin X-Content-Type-Options: nosniff",
    },
    "find.http_no_xfo.title": {
        "en": "No X-Frame-Options",
        "es": "Sin X-Frame-Options",
    },
    "find.http_no_referrer_policy.title": {
        "en": "No Referrer-Policy",
        "es": "Sin Referrer-Policy",
    },
    "find.missing_header.desc": {
        "en": "The response has no {header} header.",
        "es": "La respuesta no lleva la cabecera {header}.",
    },
    "find.missing_header.rem": {
        "en": "Send a {header} header.",
        "es": "Envía una cabecera {header}.",
    },
    # HTTP/2, SSE, WebSocket findings
    "find.http2_high_concurrency.title": {
        "en": "HTTP/2 permits many concurrent streams",
        "es": "HTTP/2 permite muchos flujos simultáneos",
    },
    "find.http2_high_concurrency.desc": {
        "en": (
            "The server advertises {advertised} concurrent streams; an unbounded or very high "
            "limit is what the Rapid Reset attack (CVE-2023-44487) amplifies into a DoS."
        ),
        "es": (
            "El servidor anuncia {advertised} flujos simultáneos; un límite ilimitado o muy alto "
            "es lo que el ataque Rapid Reset (CVE-2023-44487) amplifica hasta una denegación de "
            "servicio."
        ),
    },
    "find.http2_high_concurrency.rem": {
        "en": "Cap SETTINGS_MAX_CONCURRENT_STREAMS (e.g. 100-250); limit resets.",
        "es": "Limita SETTINGS_MAX_CONCURRENT_STREAMS (p. ej. 100-250); limita los reinicios.",
    },
    "find.http2_high_concurrency.no_limit": {
        "en": "no limit",
        "es": "sin límite",
    },
    "find.sse_reflected_origin.title": {
        "en": "Event stream reflects an arbitrary Origin",
        "es": "El flujo de eventos refleja un Origin arbitrario",
    },
    "find.sse_reflected_origin.desc": {
        "en": (
            "The SSE endpoint echoed a foreign Origin into Access-Control-Allow-Origin, so any "
            "site can open the stream in a visitor's browser and read it -- with credentials, "
            "that leaks the events cross-site."
        ),
        "es": (
            "El endpoint SSE reflejó un Origin ajeno en Access-Control-Allow-Origin, así que "
            "cualquier sitio puede abrir el flujo en el navegador de un visitante y leerlo: con "
            "credenciales, eso filtra los eventos entre sitios."
        ),
    },
    "find.sse_reflected_origin.rem": {
        "en": "Reflect Access-Control-Allow-Origin only for allow-listed origins.",
        "es": "Refleja Access-Control-Allow-Origin solo para orígenes de la lista permitida.",
    },
    "find.wss_open_origin.title": {
        "en": "WebSocket accepts a cross-site Origin",
        "es": "El WebSocket acepta un Origin de sitio cruzado",
    },
    "find.wss_open_origin.desc": {
        "en": (
            "The endpoint completed a WebSocket handshake for a foreign Origin, so a malicious "
            "page can open a socket in a victim's browser and ride their cookies -- cross-site "
            "WebSocket hijacking (CSWSH)."
        ),
        "es": (
            "El endpoint completó un handshake de WebSocket para un Origin ajeno, así que una "
            "página maliciosa puede abrir un socket en el navegador de una víctima y aprovechar "
            "sus cookies: secuestro de WebSocket entre sitios (CSWSH)."
        ),
    },
    "find.wss_open_origin.rem": {
        "en": "Validate the Origin header against an allow-list before upgrading.",
        "es": "Valida la cabecera Origin contra una lista permitida antes de actualizar.",
    },
    # Active-probe vulnerabilities (scanner.py); name/description, id/severity stay English.
    "find.heartbleed.name": {
        "en": "Heartbleed",
        "es": "Heartbleed",
    },
    "find.heartbleed.desc": {
        "en": "A malformed heartbeat makes the server return its own memory (CVE-2014-0160).",
        "es": "Un latido mal formado hace que el servidor devuelva su propia memoria "
        "(CVE-2014-0160).",
    },
    "find.ccs_injection.name": {
        "en": "OpenSSL CCS injection",
        "es": "Inyección CCS de OpenSSL",
    },
    "find.ccs_injection.desc": {
        "en": (
            "The server accepts an early ChangeCipherSpec, so a man-in-the-middle can force weak "
            "keys (CVE-2014-0224)."
        ),
        "es": (
            "El servidor acepta un ChangeCipherSpec temprano, así que un hombre en el medio puede "
            "forzar claves débiles (CVE-2014-0224)."
        ),
    },
    "find.robot.name": {
        "en": "ROBOT (Bleichenbacher oracle)",
        "es": "ROBOT (oráculo de Bleichenbacher)",
    },
    "find.robot.desc": {
        "en": (
            "The server's RSA key exchange distinguishes valid from invalid PKCS#1 padding, a "
            "Bleichenbacher oracle: a patient attacker can decrypt a recorded session or forge a "
            "signature with the server's key (ROBOT, 2017)."
        ),
        "es": (
            "El intercambio de claves RSA del servidor distingue el relleno PKCS#1 válido del "
            "inválido, un oráculo de Bleichenbacher: un atacante paciente puede descifrar una "
            "sesión grabada o falsificar una firma con la clave del servidor (ROBOT, 2017)."
        ),
    },
    "find.insecure_renegotiation.name": {
        "en": "Insecure client-initiated renegotiation",
        "es": "Renegociación insegura iniciada por el cliente",
    },
    "find.insecure_renegotiation.desc": {
        "en": (
            "The server renegotiates on client request without RFC 5746 secure renegotiation, so "
            "a man-in-the-middle can prefix chosen plaintext to the client's request "
            "(CVE-2009-3555)."
        ),
        "es": (
            "El servidor renegocia a petición del cliente sin la renegociación segura de RFC "
            "5746, así que un hombre en el medio puede anteponer texto en claro elegido a la "
            "petición del cliente (CVE-2009-3555)."
        ),
    },
    "find.client_renegotiation.name": {
        "en": "Client-initiated renegotiation allowed",
        "es": "Renegociación iniciada por el cliente permitida",
    },
    "find.client_renegotiation.desc": {
        "en": (
            "The server honours client-initiated renegotiation. It is secure (RFC 5746), but a "
            "client can force repeated expensive handshakes, an amplification surface for denial "
            "of service (CVE-2011-1473)."
        ),
        "es": (
            "El servidor atiende la renegociación iniciada por el cliente. Es segura (RFC 5746), "
            "pero un cliente puede forzar handshakes caros repetidos, una superficie de "
            "amplificación para la denegación de servicio (CVE-2011-1473)."
        ),
    },
}
