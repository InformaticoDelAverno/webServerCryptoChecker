"""A single self-contained HTML file: no external fonts, scripts or styles.

Nothing is fetched when the report is opened, so it leaks nothing to the network
and works offline. It adapts to the reader's light or dark theme.
"""

from __future__ import annotations

import html as _html

from ..i18n import Translator
from ..models import ScanReport, TargetResult
from .labels import category_label, compliance_label, severity_label, verdict_label
from .protocols import offered_protocols

_STYLE = (
    "body{font-family:system-ui,sans-serif;margin:2rem;background:#fff;color:#111}"
    "@media(prefers-color-scheme:dark){body{background:#111;color:#eee}}"
    ".endpoint{border:1px solid #8888;border-radius:8px;padding:1rem;margin:1rem 0}"
    ".grade{font-weight:bold}.finding{color:#c0392b}.vuln{color:#b9770e}"
    "ul{margin:.3rem 0}"
)


def _e(value: object) -> str:
    return _html.escape(str(value))


def _endpoint(result: TargetResult, t: Translator) -> str:
    address = f" [{_e(result.ip)}]" if result.ip and result.ip != result.target.host else ""
    parts = [f'<section class="endpoint"><h2>{_e(result.target.display_name)}{address}</h2>']
    if not result.ok:
        parts.append(f"<p>{_e(t('rep.html.error', error=result.error))}</p></section>")
        return "".join(parts)

    grade_txt = t("rep.html.grade", grade=result.grade or "n/a")
    verdict_txt = t("rep.html.verdict", verdict=verdict_label(t, result.verdict))
    parts.append(f'<p class="grade">{_e(grade_txt)} &mdash; {_e(verdict_txt)}</p>')
    supported = [protocol.name for protocol in result.protocols if protocol.supported]
    versions = ", ".join(supported) if supported else t("rep.html.none")
    parts.append(f"<p>{_e(t('rep.html.tls_versions', versions=versions))}</p>")

    cipher = result.assessment("cipher")
    if cipher is not None:
        items = "".join(
            f"<li>[{_e(category_label(t, a.category))}] {_e(a.name)}</li>"
            for a in cipher.algorithms
        )
        parts.append(f"<ul>{items}</ul>")

    certificate = result.certificate
    if certificate is not None:
        leaf = certificate.leaf
        if leaf is not None:
            parts.append(
                "<p>"
                + _e(
                    t(
                        "rep.html.certificate",
                        subject=leaf.subject,
                        type=leaf.key_type,
                        sig=leaf.signature_algorithm,
                    )
                )
                + "</p>"
            )
        else:
            parts.append(
                f"<p>{_e(t('rep.html.certificate_not_retrieved', error=certificate.error))}</p>"
            )

    offered = offered_protocols(result)
    if offered:
        items = "".join(f"<li>{_e(name)}</li>" for name in offered)
        parts.append(f"<p>{_e(t('rep.html.protocols_offered'))}</p><ul>{items}</ul>")

    for finding in result.findings:
        label = t("rep.html.finding", severity=severity_label(t, finding.severity),
                  title=finding.title)
        parts.append(f'<p class="finding">{_e(label)}</p>')
    for vulnerability in result.vulnerabilities:
        parts.append(f'<p class="vuln">{_e(vulnerability.id)}: {_e(vulnerability.name)}</p>')
    for compliance in result.compliance:
        parts.append(
            "<p>"
            + _e(
                t(
                    "rep.html.compliance",
                    id=compliance.profile_id,
                    status=compliance_label(t, compliance.status),
                )
            )
            + "</p>"
        )
    parts.append("</section>")
    return "".join(parts)


def render(report: ScanReport, t: Translator) -> str:
    sections = "".join(_endpoint(result, t) for result in report.results)
    summary = t(
        "rep.html.summary", total=report.summary.total, reachable=report.summary.succeeded
    )
    return (
        f'<!DOCTYPE html><html lang="{t.language}"><head><meta charset="utf-8">'
        f"<title>{_e(t('rep.html.doc_title', tool=report.tool))}</title>"
        f"<style>{_STYLE}</style></head><body>"
        f"<h1>{_e(report.tool)} {_e(report.version)}</h1>"
        f"<p>{_e(summary)}</p>"
        f"{sections}</body></html>"
    )
