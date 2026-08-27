"""Loading and querying the editable policy in ``data/algorithms.json``.

Data, not code: which TLS version, cipher suite, group or signature is
recommended, weak or insecure lives in a JSON file, and so do the weights and
the grade scale. Changing the criterion is editing that file, on a server at
three in the morning if need be, not shipping a new release.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .i18n import DEFAULT_LANGUAGE
from .models import CATEGORY_ORDER, Category, Severity
from .tls.constants import cipher_suite_tags

_VALID_CATEGORIES = {category.value for category in Category}
_CONDITION_KEYS = {"protocol", "cipher_tag", "all", "any", "not"}


def _validate_detection(condition: Dict[str, Any], vulnerability_id: str) -> None:
    keys = _CONDITION_KEYS & set(condition)
    if len(keys) != 1:
        raise PolicyError(
            f"vulnerability {vulnerability_id}: each detection node needs exactly one of "
            f"{', '.join(sorted(_CONDITION_KEYS))}"
        )
    key = next(iter(keys))
    if key in ("all", "any"):
        for sub in condition[key]:
            _validate_detection(sub, vulnerability_id)
    elif key == "not":
        _validate_detection(condition["not"], vulnerability_id)


class PolicyError(Exception):
    """The policy file could not be read, parsed or validated."""


@dataclass
class Classification:
    """The policy's opinion of one algorithm, version or property."""

    category: Category
    tags: List[str] = field(default_factory=list)
    note: str = ""


def worst_category(categories: List[Category]) -> Optional[Category]:
    """The worst scored category present, or ``None`` if none are scored.

    Informational and unknown do not count: a server is graded on the things
    the policy actually has an opinion about, and 'the worst thing on offer' is
    what an attacker gets to negotiate.
    """
    scored = [category for category in categories if category in CATEGORY_ORDER]
    if not scored:
        return None
    return max(scored, key=CATEGORY_ORDER.index)


def default_policy_path() -> Path:
    return Path(__file__).resolve().parent / "data" / "algorithms.json"


def _category(value: str, context: str) -> Category:
    if value not in _VALID_CATEGORIES:
        raise PolicyError(f"{context}: '{value}' is not a valid category")
    return Category(value)


class Policy:
    """The algorithm database and scoring rules, loaded from JSON."""

    def __init__(self, data: Dict[str, Any]) -> None:
        self._metadata: Dict[str, Any] = data.get("metadata", {})

        self._category_scores: Dict[str, Optional[int]] = {}
        for name, spec in data.get("categories", {}).items():
            self._category_scores[name] = spec.get("score")

        self._protocols = self._index(data.get("protocols", []), "id", "protocol")
        self._groups = self._index(data.get("groups", []), "name", "group")
        self._signatures = self._index(data.get("signatures", []), "name", "signature")

        self._cipher_tag_categories: Dict[str, Category] = {}
        for tag, value in data.get("cipher_tag_categories", {}).items():
            self._cipher_tag_categories[tag] = _category(value, f"cipher tag '{tag}'")

        scoring = data.get("scoring", {})
        self._class_weights: Dict[str, int] = {
            key: int(weight) for key, weight in scoring.get("class_weights", {}).items()
        }
        self._grades: List[Dict[str, Any]] = list(scoring.get("grades", []))
        if not self._grades:
            raise PolicyError("policy has no grade scale")
        self._grade_caps: Dict[str, str] = dict(scoring.get("grade_caps", {}))
        self._grade_rank = {grade["grade"]: index for index, grade in enumerate(self._grades)}

        self._security_strength: Dict[str, Any] = dict(data.get("security_strength", {}))
        self._vulnerabilities: List[Dict[str, Any]] = list(data.get("vulnerabilities", []))
        for entry in self._vulnerabilities:
            try:
                Severity(entry["severity"])
            except ValueError as exc:
                raise PolicyError(f"vulnerability {entry['id']}: {exc}") from exc
            _validate_detection(entry["detection"], entry["id"])

    @staticmethod
    def _index(entries: List[Dict[str, Any]], key: str, context: str) -> Dict[str, Classification]:
        table: Dict[str, Classification] = {}
        for entry in entries:
            table[entry[key]] = Classification(
                category=_category(entry["category"], f"{context} '{entry[key]}'"),
                note=entry.get("note", ""),
            )
        return table

    @classmethod
    def load(cls, path: Optional[Path] = None, language: str = DEFAULT_LANGUAGE) -> Policy:
        """Load the policy, optionally overlaying a language's translatable prose.

        ``language`` other than English loads ``data/i18n/algorithms.<language>.json``
        and merges its prose (category labels, security-strength level labels and
        descriptions, and each vulnerability's name/description/remediation, plus the
        metadata prose) onto the loaded data, keyed by the same ids. A missing, broken
        or partial overlay silently falls back to English; ids, enum codes and
        algorithm names are never translated.
        """
        location = path or default_policy_path()
        try:
            text = location.read_text(encoding="utf-8")
        except OSError as exc:
            raise PolicyError(f"cannot read policy {location}: {exc}") from exc
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PolicyError(f"policy {location} is not valid JSON: {exc}") from exc
        overlay = _language_overlay(language)
        if overlay is not None:
            _apply_overlay_to_raw(data, overlay)
        return cls(data)

    # -- classification -------------------------------------------------- #

    def classify_protocol(self, protocol_id: str) -> Classification:
        return self._protocols.get(protocol_id) or Classification(Category.UNKNOWN)

    def classify_group(self, name: str) -> Classification:
        return self._groups.get(name) or Classification(Category.UNKNOWN)

    def classify_signature(self, name: str) -> Classification:
        return self._signatures.get(name) or Classification(Category.UNKNOWN)

    def classify_cipher(self, name: str) -> Classification:
        tags = cipher_suite_tags(name)
        categories = [
            self._cipher_tag_categories[tag] for tag in tags if tag in self._cipher_tag_categories
        ]
        return Classification(worst_category(categories) or Category.UNKNOWN, tags)

    # -- scoring --------------------------------------------------------- #

    def category_score(self, category: Category) -> Optional[int]:
        return self._category_scores.get(category.value)

    def class_weight(self, key: str) -> int:
        return self._class_weights.get(key, 0)

    def grade_for(self, score: int) -> str:
        return str(
            next(
                (grade["grade"] for grade in self._grades if score >= grade["min"]),
                self._grades[-1]["grade"],
            )
        )

    def grade_caps(self) -> Dict[str, str]:
        return dict(self._grade_caps)

    def vulnerabilities(self) -> List[Dict[str, Any]]:
        return [dict(entry) for entry in self._vulnerabilities]

    def security_strength(self) -> Dict[str, Any]:
        return self._security_strength

    def worse_grade(self, first: str, second: str) -> str:
        """The lower of two grades, by their position in the scale."""
        if self._grade_rank.get(second, 0) > self._grade_rank.get(first, 0):
            return second
        return first

    @property
    def metadata(self) -> Dict[str, Any]:
        return dict(self._metadata)


# --------------------------------------------------------------------------- #
# Language overlay (data-level i18n)
# --------------------------------------------------------------------------- #


def _language_overlay(language: str) -> Optional[Dict[str, Any]]:
    """The prose overlay for ``language`` (Spanish etc.), or None for English.

    Lives beside the bundled policy at ``data/i18n/algorithms.<language>.json`` and
    is keyed by stable identifiers (category key, level id, vulnerability id). It is
    defensive: a missing file, an unreadable one, invalid JSON or a non-object all
    return None so English stays the fallback, and a partial overlay is valid.
    """
    if language == DEFAULT_LANGUAGE:
        return None
    path = default_policy_path().parent / "i18n" / f"algorithms.{language}.json"
    if not path.is_file():
        return None
    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _overlay_fields(entry: Dict[str, Any], translation: Any, fields: Sequence[str]) -> None:
    """Copy each present, non-empty translated field onto ``entry`` in place."""
    if isinstance(translation, dict):
        for name in fields:
            if translation.get(name):
                entry[name] = translation[name]


def _overlay_by_id(entries: Any, translations: Any, fields: Sequence[str]) -> None:
    """Overlay a list of id-keyed dicts (e.g. vulnerabilities) by matching ``id``."""
    if not isinstance(entries, list) or not isinstance(translations, dict):
        return
    for entry in entries:
        if isinstance(entry, dict):
            _overlay_fields(entry, translations.get(entry.get("id")), fields)


def _apply_overlay_to_raw(raw: Dict[str, Any], overlay: Dict[str, Any]) -> None:
    """Swap the translatable prose in the raw policy for the overlay's, in place.

    Only human prose is touched; keys, ids, enum codes and algorithm names stay as
    written. Anything the overlay omits keeps its English text.
    """
    categories = overlay.get("categories") or {}
    for key, value in (raw.get("categories") or {}).items():
        if isinstance(value, dict):
            _overlay_fields(value, categories.get(key), ("label",))

    levels = overlay.get("security_strength_levels") or {}
    for level in (raw.get("security_strength") or {}).get("levels") or []:
        if isinstance(level, dict):
            _overlay_fields(level, levels.get(level.get("id")), ("label", "description"))

    _overlay_by_id(
        raw.get("vulnerabilities"),
        overlay.get("vulnerabilities"),
        ("name", "description", "remediation"),
    )

    metadata = overlay.get("metadata")
    if isinstance(metadata, dict) and isinstance(raw.get("metadata"), dict):
        _overlay_fields(raw["metadata"], metadata, ("name", "description"))
