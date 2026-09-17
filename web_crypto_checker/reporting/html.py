"""A single self-contained HTML file: no external fonts, scripts or styles.

Nothing is fetched when the report is opened, so it leaks nothing to the network
and works offline. It adapts to the reader's light or dark theme, prints cleanly,
and follows the same rich layout as the sibling tools: a summary of the whole run
(stat cards, the most widespread vulnerabilities, conformance by profile, a table
of every target) followed by one collapsible card per target with its overview,
certificate, standards conformance, algorithm ratings, offered protocols,
vulnerabilities and configuration findings.
"""

from __future__ import annotations

import html as _html
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from ..i18n import Translator
from ..models import (
    CATEGORY_ORDER,
    SEVERITY_ORDER,
    ClassAssessment,
    ComplianceResult,
    ComplianceStatus,
    Finding,
    PostQuantumStatus,
    ScanReport,
    ScanSummary,
    Severity,
    TargetResult,
    TlsCompressionStatus,
    Verdict,
)
from .labels import (
    category_label,
    post_quantum_label,
    severity_label,
    trust_label,
    verdict_label,
)
from .protocols import offered_protocols

__all__ = ["render"]

#: NIST security-strength band -> badge CSS class.
_STRENGTH_CLASSES = {
    "high": "recommended",
    "moderate": "acceptable",
    "legacy": "weak",
    "inadequate": "insecure",
}

#: Verdict -> badge CSS class.
_VERDICT_CLASSES = {
    Verdict.SECURE: "recommended",
    Verdict.ACCEPTABLE: "acceptable",
    Verdict.WEAK: "weak",
    Verdict.INSECURE: "insecure",
    Verdict.UNKNOWN: "unknown",
    Verdict.ERROR: "unknown",
}

#: Post-quantum status -> (label key, badge CSS class).
_PQ_CLASSES = {
    PostQuantumStatus.ENFORCED: "recommended",
    PostQuantumStatus.READY: "acceptable",
    PostQuantumStatus.NOT_READY: "weak",
    PostQuantumStatus.UNKNOWN: "info",
}


_STYLE = """
:root {
  color-scheme: light dark;
  --bg: #f5f6f8;
  --surface: #ffffff;
  --surface-alt: #f0f2f5;
  --border: #d9dee5;
  --text: #1b1f24;
  --muted: #5c6773;
  --accent: #2563eb;
  --ok: #17803d;
  --ok-bg: #e7f6ec;
  --acceptable: #1d4ed8;
  --acceptable-bg: #e6edfe;
  --weak: #a35a00;
  --weak-bg: #fdf0dc;
  --insecure: #b3261e;
  --insecure-bg: #fbe6e4;
  --unknown: #6b3fa0;
  --unknown-bg: #f0e9f9;
  --info: #55606d;
  --info-bg: #eceff3;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14171c;
    --surface: #1c2027;
    --surface-alt: #232830;
    --border: #333b46;
    --text: #e6e9ee;
    --muted: #9aa5b1;
    --accent: #7aa2f7;
    --ok: #4ade80; --ok-bg: #14301f;
    --acceptable: #7aa2f7; --acceptable-bg: #172136;
    --weak: #fbbf24; --weak-bg: #33260a;
    --insecure: #f87171; --insecure-bg: #3a1a18;
    --unknown: #c4a2f5; --unknown-bg: #271a38;
    --info: #9aa5b1; --info-bg: #242a32;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 0 1rem 4rem;
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
    "Helvetica Neue", Arial, sans-serif;
  font-size: 15px;
  line-height: 1.55;
}
.wrap { max-width: 1100px; margin: 0 auto; }
code, pre, .mono {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas,
    "Liberation Mono", monospace;
}
h1, h2, h3 { line-height: 1.25; margin: 0; }
h1 { font-size: 1.6rem; }
h2 { font-size: 1.2rem; margin-bottom: .75rem; }
h3 {
  font-size: .95rem;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: var(--muted);
  margin-bottom: .5rem;
  margin-top: 1.5rem;
}
h4 { margin: 0; font-size: .95rem; }
a { color: var(--accent); }
header.page {
  padding: 2rem 0 1.25rem;
  border-bottom: 1px solid var(--border);
  margin-bottom: 1.5rem;
}
header.page .meta { color: var(--muted); font-size: .875rem; margin-top: .5rem; }
header.page .meta span { margin-right: 1.25rem; white-space: nowrap; }
section { margin-bottom: 2rem; }
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1.25rem;
  margin-bottom: 1.5rem;
}
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: .75rem;
  margin-bottom: 1.5rem;
}
.stat {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: .9rem 1rem;
}
.stat .value { font-size: 1.75rem; font-weight: 650; line-height: 1.1; }
.stat .label {
  color: var(--muted);
  font-size: .8rem;
  text-transform: uppercase;
  letter-spacing: .05em;
  margin-top: .2rem;
}
.table-scroll { overflow-x: auto; -webkit-overflow-scrolling: touch; }
table { border-collapse: collapse; width: 100%; font-size: .9rem; }
th, td {
  text-align: left;
  padding: .5rem .65rem;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
th {
  font-size: .78rem;
  text-transform: uppercase;
  letter-spacing: .05em;
  color: var(--muted);
  font-weight: 600;
  white-space: nowrap;
}
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover { background: var(--surface-alt); }
.badge {
  display: inline-block;
  padding: .1rem .5rem;
  border-radius: 999px;
  font-size: .74rem;
  font-weight: 650;
  letter-spacing: .03em;
  white-space: nowrap;
}
.badge.recommended { color: var(--ok); background: var(--ok-bg); }
.badge.acceptable { color: var(--acceptable); background: var(--acceptable-bg); }
.badge.weak { color: var(--weak); background: var(--weak-bg); }
.badge.insecure { color: var(--insecure); background: var(--insecure-bg); }
.badge.unknown { color: var(--unknown); background: var(--unknown-bg); }
.badge.informational, .badge.info { color: var(--info); background: var(--info-bg); }
.badge.critical { color: #fff; background: var(--insecure); }
.badge.high { color: var(--insecure); background: var(--insecure-bg); }
.badge.medium { color: var(--weak); background: var(--weak-bg); }
.badge.low { color: var(--acceptable); background: var(--acceptable-bg); }
.grade {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 3rem;
  height: 3rem;
  border-radius: 10px;
  font-size: 1.5rem;
  font-weight: 700;
  padding: 0 .5rem;
}
.grade.g-Aplus, .grade.g-A { color: var(--ok); background: var(--ok-bg); }
.grade.g-B { color: var(--acceptable); background: var(--acceptable-bg); }
.grade.g-C, .grade.g-D { color: var(--weak); background: var(--weak-bg); }
.grade.g-F { color: #fff; background: var(--insecure); }
.grade.g-none { color: var(--info); background: var(--info-bg); }
details.profile { border: 1px solid var(--border); border-radius: 8px; margin-top: .6rem; }
details.profile > summary {
  cursor: pointer; padding: .6rem .9rem; display: flex; gap: .6rem;
  align-items: center; flex-wrap: wrap;
}
details.profile > summary::-webkit-details-marker { display: none; }
details.profile .conf-groups { padding: 0 .9rem .6rem; }
.conf-group { margin-top: .6rem; }
.conf-group h4 { color: var(--muted); font-size: .82rem; text-transform: uppercase; }
.conf-group ul { margin: .3rem 0; padding-left: 1.2rem; }
.target { margin-bottom: 1.5rem; }
.target > summary {
  cursor: pointer;
  list-style: none;
  padding: 1rem 1.25rem;
  display: flex;
  align-items: center;
  gap: 1rem;
  flex-wrap: wrap;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
}
.target[open] > summary { border-radius: 10px 10px 0 0; border-bottom: none; }
.target > summary::-webkit-details-marker { display: none; }
.target > summary:hover { background: var(--surface-alt); }
.target .name { font-size: 1.1rem; font-weight: 650; }
.target .sub { color: var(--muted); font-size: .85rem; }
.target .spacer { flex: 1 1 auto; }
.target .body {
  border: 1px solid var(--border);
  border-top: none;
  border-radius: 0 0 10px 10px;
  padding: 1.25rem;
  background: var(--surface);
}
.kv {
  display: grid;
  grid-template-columns: minmax(7rem, max-content) 1fr;
  gap: .3rem 1rem;
  font-size: .9rem;
  margin-bottom: 1rem;
}
.kv dt { color: var(--muted); }
.kv dd { margin: 0; overflow-wrap: anywhere; }
.finding {
  border-left: 3px solid var(--border);
  padding: .1rem 0 .1rem .9rem;
  margin-bottom: 1.1rem;
}
.finding.critical, .finding.high { border-left-color: var(--insecure); }
.finding.medium { border-left-color: var(--weak); }
.finding.low { border-left-color: var(--acceptable); }
.finding.info { border-left-color: var(--info); }
.finding .title { font-weight: 650; margin-left: .4rem; }
.finding p { margin: .4rem 0; }
.finding .fix { color: var(--muted); }
.finding ul { margin: .4rem 0; padding-left: 1.2rem; }
.finding li {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: .85rem;
  overflow-wrap: anywhere;
}
.tags { color: var(--muted); font-size: .8rem; }
.note { color: var(--muted); font-size: .85rem; }
.error { color: var(--insecure); font-weight: 600; }
ul.plain { margin: .4rem 0; padding-left: 1.2rem; }
footer {
  border-top: 1px solid var(--border);
  padding-top: 1rem;
  margin-top: 2rem;
  color: var(--muted);
  font-size: .82rem;
}
@media print {
  body { background: #fff; padding: 0; font-size: 11pt; }
  .card, .stat, .target > summary, .target .body { border-color: #bbb; break-inside: avoid; }
  .target > summary { background: #fff; }
  details { display: block; }
  details > summary { list-style: none; }
}
"""

_SCRIPT = """
document.addEventListener('click', function (event) {
  var action = event.target && event.target.dataset ? event.target.dataset.action : null;
  if (!action) return;
  var open = action === 'expand';
  document.querySelectorAll('details.target').forEach(function (node) { node.open = open; });
});
"""


def _e(value: object) -> str:
    """HTML-escape any value."""
    return _html.escape(str(value), quote=True)


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "target"


def _grade_class(grade: Optional[str]) -> str:
    if not grade:
        return "g-none"
    return "g-" + grade.replace("+", "plus")


def _badge(text: str, css_class: str) -> str:
    return f'<span class="badge {_e(css_class)}">{_e(text)}</span>'


# --------------------------------------------------------------------------- #
# Sections
# --------------------------------------------------------------------------- #


def _header(report: ScanReport, t: Translator) -> str:
    policy_name = report.policy.get("name", "policy")
    policy_version = report.policy.get("version", "?")
    return (
        '<header class="page"><div class="wrap">'
        f"<h1>{_e(report.tool)} &mdash; {_e(t('rep.html.audit_title'))}</h1>"
        '<div class="meta">'
        f"<span>{_e(t('rep.html.generated', when=report.finished_at or report.started_at))}</span>"
        f"<span>{_e(t('rep.html.targets_count', count=report.summary.total))}</span>"
        f"<span>{_e(t('rep.html.policy', name=policy_name, version=policy_version))}</span>"
        f"<span>{_e(report.tool)} {_e(report.version)}</span>"
        "</div></div></header>"
    )


def _stat(t: Translator, value: object, label_key: str, css_class: str = "") -> str:
    style = f' style="color: var(--{css_class})"' if css_class else ""
    return (
        f'<div class="stat"><div class="value"{style}>{_e(value)}</div>'
        f'<div class="label">{_e(t(label_key))}</div></div>'
    )


def _conf_group(t: Translator, label_key: str, names: List[str], css_class: str) -> str:
    if not names:
        return ""
    items = "".join(f"<li>{_e(name)}</li>" for name in names)
    return (
        f'<div class="conf-group"><h4>{_e(t(label_key))} '
        f'{_badge(str(len(names)), css_class)}</h4><ul>{items}</ul></div>'
    )


@dataclass
class _ProfileAgg:
    """How one compliance profile fared across the whole run."""

    name: str
    authority: str
    edition: str
    passed: List[str] = field(default_factory=list)
    failed: List[str] = field(default_factory=list)
    not_assessed: List[str] = field(default_factory=list)
    offenders: Dict[str, List[str]] = field(default_factory=dict)


def _aggregate_profiles(report: ScanReport) -> Dict[str, _ProfileAgg]:
    """profile_id -> aggregate, in first-seen order, from the per-target results."""
    profiles: Dict[str, _ProfileAgg] = {}
    for result in report.results:
        name = result.target.display_name
        for entry in result.compliance:
            agg = profiles.get(entry.profile_id)
            if agg is None:
                agg = _ProfileAgg(entry.name or entry.profile_id, entry.authority, entry.edition)
                profiles[entry.profile_id] = agg
            if entry.status is ComplianceStatus.PASS:
                agg.passed.append(name)
            elif entry.status is ComplianceStatus.NOT_ASSESSED:
                agg.not_assessed.append(name)
            else:
                agg.failed.append(name)
                offenders = sorted({v.subject for v in entry.violations if v.subject})
                if offenders:
                    agg.offenders[name] = offenders
    return profiles


def _conformance_by_profile(report: ScanReport, t: Translator) -> str:
    """One collapsible accordion per profile: how the whole run looks to each standard."""
    profiles = _aggregate_profiles(report)
    if not profiles:
        return ""

    blocks = []
    for agg in profiles.values():
        assessed = len(agg.passed) + len(agg.failed)
        css_class = "recommended" if not agg.failed and agg.passed else (
            "insecure" if not agg.passed else "acceptable"
        )
        meta = f" &middot; {_e(agg.authority)}" if agg.authority else ""
        edition = f' <span class="mono">{_e(agg.edition)}</span>' if agg.edition else ""
        fail_group = ""
        if agg.failed:
            items = "".join(
                f"<li>{_e(server)}"
                + (
                    ': <span class="mono">' + _e(", ".join(agg.offenders[server])) + "</span>"
                    if agg.offenders.get(server)
                    else ""
                )
                + "</li>"
                for server in agg.failed
            )
            fail_group = (
                '<div class="conf-group"><h4>'
                f'{_e(t("rep.html.conf_fail"))} {_badge(str(len(agg.failed)), "insecure")}'
                f"</h4><ul>{items}</ul></div>"
            )
        groups = (
            _conf_group(t, "rep.html.conf_conform", agg.passed, "recommended")
            + fail_group
            + _conf_group(t, "rep.html.conf_not_assessed", agg.not_assessed, "weak")
        )
        badge = _badge(
            t("rep.html.conf_summary", passed=len(agg.passed), total=assessed), css_class
        )
        blocks.append(
            f'<details class="profile"><summary>{_e(agg.name)}{meta}{edition} '
            f'{badge}</summary><div class="conf-groups">{groups}</div></details>'
        )
    return (
        f'<div class="card"><h2>{_e(t("rep.html.conformance_heading"))}</h2>'
        f'<p class="note">{_e(t("rep.html.conformance_intro"))}</p>'
        f'{"".join(blocks)}</div>'
    )


def _summary_section(report: ScanReport, t: Translator) -> str:
    summary: ScanSummary = report.summary
    cards = [
        _stat(t, summary.total, "rep.html.stat_targets"),
        _stat(t, summary.by_verdict.get(Verdict.SECURE.value, 0), "rep.html.stat_secure", "ok"),
        _stat(
            t,
            summary.by_verdict.get(Verdict.WEAK.value, 0)
            + summary.by_verdict.get(Verdict.INSECURE.value, 0),
            "rep.html.stat_need_action",
            "insecure",
        ),
        _stat(t, f"{summary.post_quantum_ready}/{summary.total}", "rep.html.stat_pq_ready"),
        _stat(t, summary.vulnerable, "rep.html.stat_cve", "insecure"),
        _stat(
            t,
            summary.average_score if summary.average_score is not None else "-",
            "rep.html.stat_avg_score",
        ),
    ]
    if summary.failed:
        cards.append(_stat(t, summary.failed, "rep.html.stat_unreachable", "weak"))

    rows = []
    for result in report.results:
        anchor = _slug(str(result.target))
        pq = _badge(post_quantum_label(t, result.post_quantum), _PQ_CLASSES[result.post_quantum])
        verdict_class = _VERDICT_CLASSES[result.verdict]
        trust = (
            _badge(trust_label(t, result.certificate.trust), "info")
            if result.certificate is not None
            else "-"
        )
        rows.append(
            "<tr>"
            f'<td><a href="#{_e(anchor)}">{_e(result.target.display_name)}</a></td>'
            f'<td><strong>{_e(result.grade or "-")}</strong></td>'
            f'<td>{_e(result.score if result.score is not None else "-")}</td>'
            f"<td>{_badge(verdict_label(t, result.verdict), verdict_class)}</td>"
            f"<td>{pq}</td>"
            f"<td>{trust}</td>"
            "</tr>"
        )

    widespread = ""
    if summary.by_vulnerability:
        filas = "".join(
            f'<tr><td class="mono">{_e(identifier)}</td>'
            f"<td>{_e(t('rep.html.count_of', count=count, total=summary.total))}</td></tr>"
            for identifier, count in list(summary.by_vulnerability.items())[:10]
        )
        widespread = (
            f'<div class="card"><h2>{_e(t("rep.html.widespread_heading"))}</h2>'
            '<div class="table-scroll"><table>'
            f"<thead><tr><th>{_e(t('rep.html.col_identifier'))}</th>"
            f"<th>{_e(t('rep.html.col_targets'))}</th></tr></thead>"
            f"<tbody>{filas}</tbody></table></div></div>"
        )

    return (
        '<section id="summary">'
        f'<div class="cards">{"".join(cards)}</div>'
        f"{widespread}"
        f"{_conformance_by_profile(report, t)}"
        f'<div class="card"><h2>{_e(t("rep.html.all_targets"))}</h2>'
        '<div class="table-scroll"><table>'
        f"<thead><tr><th>{_e(t('rep.html.col_target'))}</th><th>{_e(t('rep.field.grade'))}</th>"
        f"<th>{_e(t('rep.html.col_score'))}</th><th>{_e(t('rep.field.verdict'))}</th>"
        f"<th>{_e(t('rep.html.col_post_quantum'))}</th><th>{_e(t('rep.html.col_trust'))}</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div></div></section>"
    )


def _overview(result: TargetResult, t: Translator) -> str:
    entries: List[Tuple[str, str]] = []
    host = result.ip or result.target.host
    entries.append(
        (t("rep.html.address"), f'<span class="mono">{_e(host)}:{_e(result.target.port)}</span>')
    )
    strength = result.security_strength
    if strength is not None and strength.effective_bits is not None:
        entries.append(
            (
                t("rep.html.security_strength"),
                f"{_badge(strength.level_label, _STRENGTH_CLASSES.get(strength.level_id, 'info'))} "
                f"{_e(t('rep.html.n_bit', bits=strength.effective_bits))}",
            )
        )
    entries.append(
        (t("rep.html.post_quantum"), _e(post_quantum_label(t, result.post_quantum)))
    )
    compression = _e(t("rep.html.compression_" + result.compression.value))
    if result.compression is TlsCompressionStatus.ENABLED:
        compression = f'<span class="error">{compression}</span>'
    entries.append((t("rep.html.compression"), compression))
    if result.scanned_at:
        entries.append((t("rep.html.scanned_at"), _e(result.scanned_at)))
    entries.append((t("rep.html.duration"), f"{result.duration_ms} ms"))

    items = "".join(f"<dt>{_e(label)}</dt><dd>{value}</dd>" for label, value in entries)
    return f'<dl class="kv">{items}</dl>'


def _certificate_block(result: TargetResult, t: Translator) -> str:
    chain = result.certificate
    if chain is None:
        return ""
    leaf = chain.leaf
    if leaf is None:
        return (
            f"<h3>{_e(t('rep.html.certificate_heading'))}</h3>"
            f'<p class="note">{_e(t("rep.html.certificate_not_retrieved", error=chain.error))}</p>'
        )
    key = leaf.key_type
    if leaf.key_bits:
        key = t("rep.html.n_bit_key", type=leaf.key_type, bits=leaf.key_bits)
    elif leaf.curve:
        key = f"{leaf.key_type} ({leaf.curve})"
    entries: List[Tuple[str, str]] = [
        (t("rep.html.cert_subject"), f'<span class="mono">{_e(leaf.subject)}</span>'),
        (t("rep.html.cert_key"), _e(key)),
        (t("rep.html.cert_signature"), _e(leaf.signature_algorithm)),
        (t("rep.html.cert_trust"), _badge(trust_label(t, chain.trust), "info")),
    ]
    if leaf.sans:
        entries.append(
            (t("rep.html.cert_sans"), f'<span class="mono">{_e(", ".join(leaf.sans))}</span>')
        )
    items = "".join(f"<dt>{_e(label)}</dt><dd>{value}</dd>" for label, value in entries)
    return f"<h3>{_e(t('rep.html.certificate_heading'))}</h3><dl class=\"kv\">{items}</dl>"


def _algorithm_table(assessment: ClassAssessment, t: Translator) -> str:
    if not assessment.algorithms:
        return ""
    rows = []
    for algorithm in assessment.algorithms:
        rows.append(
            "<tr>"
            f"<td>{_badge(category_label(t, algorithm.category), algorithm.category.value)}</td>"
            f'<td class="mono">{_e(algorithm.name)}</td>'
            f'<td class="tags">{_e(", ".join(algorithm.tags))}</td>'
            f'<td class="note">{_e(algorithm.notes)}</td>'
            "</tr>"
        )
    title = _e(t("rep.html.class_" + assessment.key))
    if assessment.score is not None:
        title += f' <span class="note">({assessment.score}/100)</span>'
    return (
        f"<h3>{title}</h3>"
        '<div class="table-scroll"><table><thead><tr>'
        f"<th>{_e(t('rep.html.col_rating'))}</th><th>{_e(t('rep.html.col_algorithm'))}</th>"
        f"<th>{_e(t('rep.html.col_properties'))}</th><th>{_e(t('rep.html.col_notes'))}</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    )


def _protocols_block(result: TargetResult, t: Translator) -> str:
    offered = offered_protocols(result)
    if not offered:
        return ""
    items = "".join(f"<li>{_e(name)}</li>" for name in offered)
    return (
        f"<h3>{_e(t('rep.html.protocols_offered'))}</h3><ul class=\"plain\">{items}</ul>"
    )


def _compliance_block(result: TargetResult, t: Translator) -> str:
    """Per-standard conformance, independent of this tool's own grade."""
    if not result.compliance:
        return ""
    intro = ""
    strength = result.security_strength
    if strength is not None and strength.effective_bits is not None:
        limiting = ""
        if strength.limiting:
            limiting = " " + _e(
                t("rep.html.held_down_by", items=", ".join(strength.limiting[:3]))
            )
        intro = (
            '<p class="note"><strong>'
            f"{_e(t('rep.html.effective_strength_bits', bits=strength.effective_bits))}</strong> "
            f"({_e(strength.level_label)}). {_e(strength.level_description)}"
            f"{limiting} {_e(t('rep.html.source', ref=strength.reference))}.</p>"
        )

    rows = []
    for entry in result.compliance:
        rows.append(_compliance_row(entry, t))
    return (
        f"<h3>{_e(t('rep.html.conformance_section'))}</h3>"
        + intro
        + '<div class="table-scroll"><table><thead><tr>'
        f"<th>{_e(t('rep.html.col_result'))}</th><th>{_e(t('rep.html.col_standard'))}</th>"
        f"<th>{_e(t('rep.html.col_detail'))}</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    )


def _compliance_row(entry: ComplianceResult, t: Translator) -> str:
    passed = entry.status is ComplianceStatus.PASS
    if passed:
        badge = _badge(t("rep.html.badge_pass"), "recommended")
    elif entry.status is ComplianceStatus.NOT_ASSESSED:
        badge = _badge(t("rep.html.badge_not_assessed"), "weak")
    else:
        badge = _badge(t("rep.html.badge_fail"), "insecure")
    detail = f'<div class="note">{_e(entry.summary)}</div>' if entry.summary else ""
    if entry.status is ComplianceStatus.NOT_ASSESSED:
        detail += "".join(
            f'<p class="note">{_e(t("rep.html.not_assessed_reason", reason=reason))}</p>'
            for reason in entry.unverified
        )
    if not passed and entry.violations:
        items = "".join(
            f"<li>{_e(violation.subject)}</li>" for violation in entry.violations[:10]
        )
        if len(entry.violations) > 10:
            items += f"<li>{_e(t('rep.html.and_more', n=len(entry.violations) - 10))}</li>"
        reasons: List[str] = []
        for violation in entry.violations:
            if violation.reason and violation.reason not in reasons:
                reasons.append(violation.reason)
        detail += f"<ul>{items}</ul>"
        detail += "".join(f'<p class="note">{_e(reason)}</p>' for reason in reasons[:3])
    name = _e(entry.name)
    if entry.url:
        name = f'<a href="{_e(entry.url)}" rel="noreferrer">{name}</a>'
    authority = _e(entry.authority)
    if entry.edition:
        authority += f" &middot; {_e(entry.edition)}"
    return (
        "<tr>"
        f"<td>{badge}</td>"
        f"<td><strong>{name}</strong><div class=\"note\">{authority}</div></td>"
        f"<td>{detail}</td>"
        "</tr>"
    )


def _vulnerabilities_block(result: TargetResult, t: Translator) -> str:
    if not result.vulnerabilities:
        return ""
    blocks = []
    for match in sorted(result.vulnerabilities, key=lambda m: SEVERITY_ORDER.index(m.severity)):
        evidence = ""
        if match.evidence:
            evidence = "<ul>" + "".join(f"<li>{_e(item)}</li>" for item in match.evidence) + "</ul>"
        fix = (
            f'<p class="fix"><strong>{_e(t("rep.html.fix_label"))}</strong> '
            f"{_e(match.remediation)}</p>"
            if match.remediation
            else ""
        )
        references = (
            f'<p class="note">{_e(t("rep.html.see_label"))} {_e(", ".join(match.references))}</p>'
            if match.references
            else ""
        )
        description = f"<p>{_e(match.description)}</p>" if match.description else ""
        blocks.append(
            f'<div class="finding {_e(match.severity.value)}">'
            f'<h4><span class="badge {_e(match.severity.value)}">'
            f"{_e(severity_label(t, match.severity))}</span> "
            f"{_e(match.id)}: {_e(match.name)}</h4>"
            f"{description}{evidence}{fix}{references}"
            "</div>"
        )
    return f"<h3>{_e(t('rep.html.vulnerabilities_section'))}</h3>" + "".join(blocks)


def _findings_block(findings: Sequence[Finding], t: Translator) -> str:
    if not findings:
        return (
            f"<h3>{_e(t('rep.html.findings_section'))}</h3>"
            f'<p class="note">{_e(t("rep.html.no_issue"))}</p>'
        )
    blocks = []
    for finding in findings:
        severity = finding.severity.value
        items = ""
        if finding.items:
            items = "<ul>" + "".join(f"<li>{_e(item)}</li>" for item in finding.items) + "</ul>"
        fix = (
            f'<p class="fix"><strong>{_e(t("rep.html.fix_label"))}</strong> '
            f"{_e(finding.remediation)}</p>"
            if finding.remediation
            else ""
        )
        references = (
            f'<p class="note">{_e(t("rep.html.see_label"))} {_e(", ".join(finding.references))}</p>'
            if finding.references
            else ""
        )
        blocks.append(
            f'<div class="finding {_e(severity)}">'
            f"{_badge(severity_label(t, finding.severity), severity)}"
            f'<span class="title">{_e(finding.title)}</span>'
            f"<p>{_e(finding.description)}</p>{items}{fix}{references}</div>"
        )
    return f"<h3>{_e(t('rep.html.findings_section'))}</h3>" + "".join(blocks)


def _target_section(result: TargetResult, t: Translator) -> str:
    anchor = _slug(str(result.target))
    grade = result.grade or "-"
    verdict_class = _VERDICT_CLASSES[result.verdict]
    subtitle = str(result.target) if result.target.label else ""
    critical = sum(
        1 for f in result.findings if f.severity in {Severity.CRITICAL, Severity.HIGH}
    )
    finding_note = t("rep.html.finding_note", n=critical) if critical else ""

    summary = (
        "<summary>"
        f'<span class="grade {_grade_class(result.grade)}">{_e(grade)}</span>'
        "<span>"
        f'<span class="name">{_e(result.target.display_name)}</span><br>'
        f'<span class="sub">{_e(subtitle)}</span>'
        "</span>"
        '<span class="spacer"></span>'
        f"{_badge(verdict_label(t, result.verdict), verdict_class)}"
        f'<span class="sub">{_e(finding_note)}</span>'
        "</summary>"
    )

    if not result.ok:
        body = (
            '<div class="body"><p class="error">'
            f'{_e(t("rep.html.scan_failed", error=result.error or t("rep.html.unknown_error")))}'
            "</p></div>"
        )
        return f'<details class="target" id="{_e(anchor)}">{summary}{body}</details>'

    parts = [
        _overview(result, t),
        _certificate_block(result, t),
        _compliance_block(result, t),
    ]
    parts.extend(_algorithm_table(assessment, t) for assessment in result.assessments)
    parts.append(_protocols_block(result, t))
    parts.append(_vulnerabilities_block(result, t))
    parts.append(_findings_block(result.findings, t))
    body = f'<div class="body">{"".join(part for part in parts if part)}</div>'
    return f'<details class="target" id="{_e(anchor)}" open>{summary}{body}</details>'


def _legend(t: Translator) -> str:
    rows = [
        f"<tr><td>{_badge(category_label(t, category), category.value)}</td>"
        f'<td class="note">{_e(t("rep.html.legend_" + category.value))}</td></tr>'
        for category in CATEGORY_ORDER
    ]
    return (
        f'<section class="card"><h2>{_e(t("rep.html.legend_heading"))}</h2>'
        '<div class="table-scroll"><table><tbody>' + "".join(rows) + "</tbody></table></div>"
        f'<p class="note">{_e(t("rep.html.scoring"))}</p></section>'
    )


def render(report: ScanReport, t: Translator) -> str:
    """Render the report as a single self-contained HTML document."""
    targets = "".join(_target_section(result, t) for result in report.results)
    controls = (
        f'<p class="note"><a href="#" data-action="expand">{_e(t("rep.html.expand_all"))}</a> '
        f'&middot; <a href="#" data-action="collapse">{_e(t("rep.html.collapse_all"))}</a></p>'
        if len(report.results) > 1
        else ""
    )
    return (
        "<!DOCTYPE html>\n"
        f'<html lang="{_e(t.language)}"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{_e(t('rep.html.doc_title', tool=report.tool))}</title>"
        f"<style>{_STYLE}</style></head><body>"
        + _header(report, t)
        + '<div class="wrap">'
        + _summary_section(report, t)
        + f'<section><h2>{_e(t("rep.html.details_heading"))}</h2>{controls}{targets}</section>'
        + _legend(t)
        + "<footer>"
        + f"{_e(t('rep.html.footer_generated_by', tool=report.tool, version=report.version))} "
        + f"{_e(t('rep.html.footer_command'))} "
        + f'<span class="mono">{_e(report.command_line or "-")}</span>. '
        + _e(t("rep.html.footer_reflects"))
        + "</footer></div>"
        + f"<script>{_SCRIPT}</script>"
        + "</body></html>\n"
    )
