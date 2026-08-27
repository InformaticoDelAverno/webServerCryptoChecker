"""Human labels for the model enums, in the reader's language.

The machine formats serialise ``enum.value`` directly and stay English; the
human renderers (console, text, HTML) route the same value through here so a
``--lang es`` report reads ``seguro`` where the JSON keeps ``secure``. Each
helper is a single catalog lookup keyed on the enum value (hyphens folded to
underscores so ``not-ready`` becomes the key ``rep.pq.not_ready``).
"""

from __future__ import annotations

from ..i18n import Translator
from ..models import (
    Category,
    ComplianceStatus,
    PostQuantumStatus,
    Severity,
    TrustStatus,
    Verdict,
)


def _key(prefix: str, value: str) -> str:
    return prefix + value.replace("-", "_")


def verdict_label(t: Translator, verdict: Verdict) -> str:
    return t(_key("rep.verdict.", verdict.value))


def severity_label(t: Translator, severity: Severity) -> str:
    return t(_key("rep.severity.", severity.value))


def category_label(t: Translator, category: Category) -> str:
    return t(_key("rep.category.", category.value))


def compliance_label(t: Translator, status: ComplianceStatus) -> str:
    return t(_key("rep.compliance.", status.value))


def post_quantum_label(t: Translator, status: PostQuantumStatus) -> str:
    return t(_key("rep.pq.", status.value))


def trust_label(t: Translator, status: TrustStatus) -> str:
    return t(_key("rep.trust.", status.value))
