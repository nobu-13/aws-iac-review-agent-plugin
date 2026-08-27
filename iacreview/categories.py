"""Loading and querying ``category_map.json``.

``iacreview/category_map.json`` is the single versioned mapping file
Requirement 14 AC4 asks for. It holds three things that would otherwise be
scattered across code: the closed Normalized_Category vocabulary, the cfn-lint
rule -> Category / FindingType / Severity mapping (Requirement 4 AC3-AC7, AC9),
and the cfn-guard rule category mapping. This module is the only reader of that
file, and no category name, level default, or rule prefix is duplicated in
Python anywhere.

Four decisions worth knowing before using the module:

**Reference order is data, not code.** A cfn-lint rule ID resolves through
``rule_overrides[<rule_id>]`` (exact match) -> ``prefix_rules[]`` (longest
prefix first) -> ``default``. Longest-prefix-first is what makes a future
``E30`` entry win over ``E3`` regardless of where either sits in the file, so
adding a narrower rule never requires reordering the array (design.md,
Normalized Category Vocabulary / 参照順序).

**An unknown rule ID is not an error.** cfn-lint ships new rules on its own
schedule, and a review must not fail because the mapping file has not caught up
yet. ``Z9999`` resolves to ``default.category`` with the Severity and
FindingType its *level* implies. Only a broken mapping file raises, as
:class:`~iacreview.errors.MappingFileError` (exit 1): that is a broken
installation, and continuing with a half-read vocabulary would silently change
what every Finding's ``Normalized_Category`` validation accepts.

**CRITICAL comes from ``blocks_deployment``, never from a hardcoded prefix.**
Requirement 4 AC5 names ``E0`` and ``E1`` as the initial deployment-blocking
set, but that is a conservative starting policy rather than a claim that only
those rules block a deploy. Expressing it as a per-rule flag in the mapping file
means the policy is tuned by editing data (design.md, CRITICAL override の表現).
Promotion applies only when ``level == "Error"``, so a Warning or an
Informational result can never become CRITICAL.

**Validation is strict about unknown keys.** A misspelled
``security_relevent`` would silently leave a security-relevant rule classified
as ``BestPractice``, which is exactly the kind of failure that never surfaces in
output. Unknown keys are therefore rejected rather than ignored.

Structural validation happens once, at load. Every accessor below can then
assume the shape it reads, which is why none of them re-check types.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Tuple

from iacreview import pathguard
from iacreview.errors import MappingFileError
from iacreview.finding import FINDING_TYPES, OTHER_CATEGORY, SEVERITIES

__all__ = [
    "DEFAULT_MAP_RELATIVE_PATH",
    "SUPPORTED_SCHEMA_MAJOR",
    "CFNLINT_LEVELS",
    "ERROR_LEVEL",
    "FALLBACK_LEVEL",
    "SECURITY_FINDING_TYPE",
    "CRITICAL_SEVERITY",
    "GUARD_FALLBACK_CATEGORY",
    "LevelDefault",
    "PrefixRule",
    "NO_PREFIX_MATCH",
    "CategoryDecision",
    "Classification",
    "CategoryMap",
    "load_map",
    "clear_cache",
    "classify_cfnlint",
]

#: Location of the bundled mapping file, relative to the plugin root. Resolved
#: through :func:`iacreview.pathguard.resolve_plugin_owned`, which contains it
#: to the plugin root and reports a missing file as ``MappingFileError``.
DEFAULT_MAP_RELATIVE_PATH = "iacreview/category_map.json"

#: MAJOR version of ``schema_version`` this module understands. design.md
#: (mapping file の versioning) bumps MAJOR on a breaking structural change, so
#: refusing an unknown MAJOR is safer than reading it with the wrong
#: expectations and mapping Findings to whatever happens to parse.
SUPPORTED_SCHEMA_MAJOR = 1

#: cfn-lint's three result levels, which are exactly the keys ``level_defaults``
#: must carry.
CFNLINT_LEVELS: Tuple[str, ...] = ("Error", "Warning", "Informational")

#: The one level that may be promoted to CRITICAL.
ERROR_LEVEL = "Error"

#: Level defaults applied to a level cfn-lint has never emitted before. See
#: :meth:`CategoryMap.cfnlint_level_default` for why this direction was chosen.
FALLBACK_LEVEL = "Informational"

#: ``FindingType`` that ``security_relevant`` forces (Requirement 4 AC9).
SECURITY_FINDING_TYPE = "Security"

#: ``Severity`` a deployment-blocking Error is promoted to.
CRITICAL_SEVERITY = "CRITICAL"

#: Category for a cfn-guard rule the mapping file does not know. ``Other`` is
#: correct here rather than ``TemplateQuality``: a Guard rule is a policy check,
#: and claiming it concerns template quality would be an assertion the mapping
#: file never made. ``Other`` also keeps the Finding out of dedup matching
#: (Requirement 14 AC3), which is the right outcome for an unmapped subject.
GUARD_FALLBACK_CATEGORY = OTHER_CATEGORY

# Permitted key sets, enforced at load time. Each mirrors the corresponding
# object in design.md's mapping file example.
_TOP_LEVEL_KEYS: Tuple[str, ...] = (
    "schema_version",
    "categories",
    "notes",
    "cfnlint",
    "cfnguard",
)
_TOP_LEVEL_REQUIRED: Tuple[str, ...] = ("schema_version", "categories", "cfnlint", "cfnguard")
_CFNLINT_KEYS: Tuple[str, ...] = ("level_defaults", "default", "prefix_rules", "rule_overrides")
_CFNGUARD_KEYS: Tuple[str, ...] = ("rule_categories", "rule_overrides")
_LEVEL_DEFAULT_KEYS: Tuple[str, ...] = ("finding_type", "severity")
_DEFAULT_KEYS: Tuple[str, ...] = ("category",)
_PREFIX_RULE_KEYS: Tuple[str, ...] = ("prefix", "category", "blocks_deployment")
_CFNLINT_OVERRIDE_KEYS: Tuple[str, ...] = (
    "category",
    "security_relevant",
    "blocks_deployment",
    "severity",
    "why_it_matters",
    "recommendation",
)
_GUARD_OVERRIDE_KEYS: Tuple[str, ...] = (
    "category",
    "finding_type",
    "severity",
    "why_it_matters",
    "recommendation",
)


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LevelDefault:
    """FindingType and Severity implied by a cfn-lint result level."""

    finding_type: str
    severity: str


@dataclass(frozen=True)
class PrefixRule:
    """One ``prefix_rules[]`` entry.

    ``category`` and ``blocks_deployment`` are ``Optional`` so that
    :data:`NO_PREFIX_MATCH` can stand in for "no entry matched" without the
    caller branching on ``None`` before reading the attributes. That keeps
    :func:`classify_cfnlint` a literal transcription of the design pseudocode,
    which accesses ``prefix.category`` unconditionally.
    """

    prefix: str
    category: Optional[str]
    blocks_deployment: Optional[bool]


#: Returned by :meth:`CategoryMap.cfnlint_prefix` when nothing matched.
NO_PREFIX_MATCH = PrefixRule("", None, None)


@dataclass(frozen=True)
class CategoryDecision:
    """What the mapping file says about one rule, independent of its level.

    ``finding_type`` and ``severity_override`` are ``None`` when the mapping
    file states nothing, meaning the caller keeps the value its level implies.
    They are not filled in with the level default here because a
    ``CategoryDecision`` is level-agnostic: the same rule can appear as an Error
    or a Warning. :func:`classify_cfnlint` is the function that combines the two.

    ``why_it_matters`` is ``""`` rather than ``None`` when the mapping file
    carries no text, so a caller can concatenate without a null check. An empty
    string means "no rule-specific wording"; the Source supplies its own.
    """

    category: str
    finding_type: Optional[str]
    severity_override: Optional[str]
    why_it_matters: str


@dataclass(frozen=True)
class Classification:
    """The final Category, FindingType and Severity for one cfn-lint result."""

    category: str
    finding_type: str
    severity: str


# ---------------------------------------------------------------------------
# Failure construction
# ---------------------------------------------------------------------------


def _fail(source: Path, field: str, reason: str) -> MappingFileError:
    """Build the one error class this module raises.

    ``field`` is a dotted path into the JSON document
    (``cfnlint.prefix_rules[2].prefix``) so a corrupt file can be located
    without re-reading it against the schema by hand.
    """
    return MappingFileError(
        "{0}: {1}: {2}".format(source, field, reason),
        remediation=(
            "The category mapping file ships with the plugin. Revert local "
            "edits to {0}, or reinstall the plugin.".format(source)
        ),
    )


def _type_name(value: object) -> str:
    return type(value).__name__


# ---------------------------------------------------------------------------
# Structural validation
# ---------------------------------------------------------------------------


def _require_object(source: Path, field: str, value: object) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise _fail(source, field, "expected an object, got {0}".format(_type_name(value)))
    for key in value:
        if not isinstance(key, str):
            raise _fail(source, field, "keys must be strings, got {0}".format(_type_name(key)))
    return value


def _require_keys(source: Path, field: str, payload: Dict[str, Any], required: Sequence[str]) -> None:
    for key in required:
        if key not in payload:
            raise _fail(source, _join(field, key), "required field is missing")


def _reject_unknown_keys(
    source: Path, field: str, payload: Dict[str, Any], permitted: Sequence[str]
) -> None:
    for key in sorted(payload):
        if key not in permitted:
            raise _fail(
                source,
                _join(field, key),
                "is not one of the permitted fields {0}".format(list(permitted)),
            )


def _join(field: str, key: str) -> str:
    return "{0}.{1}".format(field, key) if field else key


def _require_text(source: Path, field: str, value: object) -> str:
    if not isinstance(value, str):
        raise _fail(source, field, "expected a string, got {0}".format(_type_name(value)))
    if not value:
        raise _fail(source, field, "must not be empty")
    return value


def _require_bool(source: Path, field: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise _fail(source, field, "expected a boolean, got {0}".format(_type_name(value)))
    return value


def _require_enum(source: Path, field: str, value: object, permitted: Sequence[str]) -> str:
    text = _require_text(source, field, value)
    if text not in permitted:
        raise _fail(source, field, "{0!r} is not one of {1}".format(text, list(permitted)))
    return text


def _require_known_category(
    source: Path, field: str, value: object, categories: Sequence[str]
) -> str:
    """Require a category name declared in the file's own ``categories`` array.

    Checked against the file rather than against a constant in this module: the
    array is the authoritative vocabulary, so a rule pointing outside it is a
    contradiction inside one document.
    """
    text = _require_text(source, field, value)
    if text not in categories:
        raise _fail(
            source,
            field,
            "{0!r} is not declared in the categories array {1}".format(text, list(categories)),
        )
    return text


def _validate_schema_version(source: Path, value: object) -> str:
    version = _require_text(source, "schema_version", value)
    major_text = version.split(".", 1)[0]
    try:
        major = int(major_text)
    except ValueError:
        raise _fail(
            source,
            "schema_version",
            "expected a semver string, got {0!r}".format(version),
        ) from None
    if major != SUPPORTED_SCHEMA_MAJOR:
        raise _fail(
            source,
            "schema_version",
            "MAJOR version {0} is not supported by this plugin version "
            "(expected {1})".format(major, SUPPORTED_SCHEMA_MAJOR),
        )
    return version


def _validate_categories(source: Path, value: object) -> Tuple[str, ...]:
    if not isinstance(value, list):
        raise _fail(source, "categories", "expected a list, got {0}".format(_type_name(value)))
    if not value:
        raise _fail(source, "categories", "must declare at least one category")
    names: List[str] = []
    for index, item in enumerate(value):
        names.append(_require_text(source, "categories[{0}]".format(index), item))
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise _fail(source, "categories", "contains duplicates: {0}".format(duplicates))
    return tuple(names)


def _validate_level_defaults(source: Path, value: object) -> Dict[str, LevelDefault]:
    field = "cfnlint.level_defaults"
    payload = _require_object(source, field, value)
    _reject_unknown_keys(source, field, payload, CFNLINT_LEVELS)
    _require_keys(source, field, payload, CFNLINT_LEVELS)
    defaults: Dict[str, LevelDefault] = {}
    for level in CFNLINT_LEVELS:
        level_field = _join(field, level)
        entry = _require_object(source, level_field, payload[level])
        _reject_unknown_keys(source, level_field, entry, _LEVEL_DEFAULT_KEYS)
        _require_keys(source, level_field, entry, _LEVEL_DEFAULT_KEYS)
        defaults[level] = LevelDefault(
            finding_type=_require_enum(
                source, _join(level_field, "finding_type"), entry["finding_type"], FINDING_TYPES
            ),
            severity=_require_enum(
                source, _join(level_field, "severity"), entry["severity"], SEVERITIES
            ),
        )
    return defaults


def _validate_prefix_rules(
    source: Path, value: object, categories: Sequence[str]
) -> Tuple[PrefixRule, ...]:
    field = "cfnlint.prefix_rules"
    if not isinstance(value, list):
        raise _fail(source, field, "expected a list, got {0}".format(_type_name(value)))
    rules: List[PrefixRule] = []
    for index, item in enumerate(value):
        entry_field = "{0}[{1}]".format(field, index)
        entry = _require_object(source, entry_field, item)
        _reject_unknown_keys(source, entry_field, entry, _PREFIX_RULE_KEYS)
        _require_keys(source, entry_field, entry, ("prefix", "category"))
        blocks = entry.get("blocks_deployment")
        rules.append(
            PrefixRule(
                prefix=_require_text(source, _join(entry_field, "prefix"), entry["prefix"]),
                category=_require_known_category(
                    source, _join(entry_field, "category"), entry["category"], categories
                ),
                blocks_deployment=(
                    None
                    if blocks is None
                    else _require_bool(
                        source, _join(entry_field, "blocks_deployment"), blocks
                    )
                ),
            )
        )
    # Sorted once, at load, by descending prefix length. `sorted` is stable, so
    # entries of equal length keep their file order and lookup stays
    # deterministic (Requirement 16 AC11).
    rules.sort(key=lambda rule: len(rule.prefix), reverse=True)
    return tuple(rules)


def _validate_cfnlint_overrides(
    source: Path, value: object, categories: Sequence[str]
) -> Dict[str, Dict[str, Any]]:
    field = "cfnlint.rule_overrides"
    payload = _require_object(source, field, value)
    overrides: Dict[str, Dict[str, Any]] = {}
    for rule_id in sorted(payload):
        entry_field = _join(field, rule_id)
        if not rule_id:
            raise _fail(source, field, "rule ID keys must not be empty")
        entry = _require_object(source, entry_field, payload[rule_id])
        _reject_unknown_keys(source, entry_field, entry, _CFNLINT_OVERRIDE_KEYS)
        if "category" in entry:
            _require_known_category(
                source, _join(entry_field, "category"), entry["category"], categories
            )
        if "security_relevant" in entry:
            _require_bool(
                source, _join(entry_field, "security_relevant"), entry["security_relevant"]
            )
        if "blocks_deployment" in entry:
            _require_bool(
                source, _join(entry_field, "blocks_deployment"), entry["blocks_deployment"]
            )
        if "severity" in entry:
            _require_enum(source, _join(entry_field, "severity"), entry["severity"], SEVERITIES)
        for key in ("why_it_matters", "recommendation"):
            if key in entry:
                _require_text(source, _join(entry_field, key), entry[key])
        overrides[rule_id] = dict(entry)
    return overrides


def _validate_guard(
    source: Path, value: object, categories: Sequence[str]
) -> Tuple[Dict[str, str], Dict[str, Dict[str, Any]]]:
    field = "cfnguard"
    payload = _require_object(source, field, value)
    _reject_unknown_keys(source, field, payload, _CFNGUARD_KEYS)
    _require_keys(source, field, payload, _CFNGUARD_KEYS)

    categories_field = _join(field, "rule_categories")
    raw_categories = _require_object(source, categories_field, payload["rule_categories"])
    rule_categories: Dict[str, str] = {}
    for key in sorted(raw_categories):
        if not key:
            raise _fail(source, categories_field, "rule category keys must not be empty")
        rule_categories[key] = _require_known_category(
            source, _join(categories_field, key), raw_categories[key], categories
        )

    overrides_field = _join(field, "rule_overrides")
    raw_overrides = _require_object(source, overrides_field, payload["rule_overrides"])
    rule_overrides: Dict[str, Dict[str, Any]] = {}
    for rule_name in sorted(raw_overrides):
        entry_field = _join(overrides_field, rule_name)
        if not rule_name:
            raise _fail(source, overrides_field, "rule name keys must not be empty")
        entry = _require_object(source, entry_field, raw_overrides[rule_name])
        _reject_unknown_keys(source, entry_field, entry, _GUARD_OVERRIDE_KEYS)
        if "category" in entry:
            _require_known_category(
                source, _join(entry_field, "category"), entry["category"], categories
            )
        if "finding_type" in entry:
            _require_enum(
                source, _join(entry_field, "finding_type"), entry["finding_type"], FINDING_TYPES
            )
        if "severity" in entry:
            _require_enum(source, _join(entry_field, "severity"), entry["severity"], SEVERITIES)
        for key in ("why_it_matters", "recommendation"):
            if key in entry:
                _require_text(source, _join(entry_field, key), entry[key])
        rule_overrides[rule_name] = dict(entry)

    return rule_categories, rule_overrides


# ---------------------------------------------------------------------------
# CategoryMap
# ---------------------------------------------------------------------------


class CategoryMap:
    """A validated, read-only view of ``category_map.json``.

    Instances are produced by :func:`load_map`, never constructed from raw JSON
    by callers: the constructor takes already-validated pieces, so every
    accessor can read them without re-checking types.
    """

    def __init__(
        self,
        *,
        source_path: Path,
        schema_version: str,
        categories: Tuple[str, ...],
        notes: Dict[str, Any],
        level_defaults: Dict[str, LevelDefault],
        default_category: str,
        prefix_rules: Tuple[PrefixRule, ...],
        cfnlint_rule_overrides: Dict[str, Dict[str, Any]],
        guard_rule_categories: Dict[str, str],
        guard_rule_overrides: Dict[str, Dict[str, Any]],
    ) -> None:
        self.source_path = source_path
        self.schema_version = schema_version
        self.categories = categories
        self.notes = notes
        self._category_set: FrozenSet[str] = frozenset(categories)
        self._level_defaults = level_defaults
        self._default_category = default_category
        self._prefix_rules = prefix_rules
        self._cfnlint_rule_overrides = cfnlint_rule_overrides
        self._guard_rule_categories = guard_rule_categories
        self._guard_rule_overrides = guard_rule_overrides

    # -- vocabulary ---------------------------------------------------------

    def is_valid_category(self, name: str) -> bool:
        """Whether ``name`` is in the closed Normalized_Category set.

        This is the predicate :mod:`iacreview.finding` installs as its category
        validator, which is why it takes a plain string and returns a plain
        bool: a non-string or unknown value is a schema violation for the
        caller to report, not an exception from here.
        """
        return name in self._category_set

    # -- cfn-lint primitives (design.md pseudocode vocabulary) --------------

    def cfnlint_level_default(self, level: str) -> LevelDefault:
        """FindingType and Severity implied by ``level``.

        A level outside :data:`CFNLINT_LEVELS` falls back to
        :data:`FALLBACK_LEVEL` rather than raising. ``level`` comes from
        cfn-lint's JSON output, which is untrusted input from an external tool
        that may add a level in a future release; failing the whole review over
        it would be disproportionate. The fallback deliberately points at the
        *least* severe defaults, so an unrecognized level is never silently
        escalated, and since it is not ``"Error"`` it can never be promoted to
        CRITICAL either.
        """
        default = self._level_defaults.get(level)
        if default is None:
            return self._level_defaults[FALLBACK_LEVEL]
        return default

    def cfnlint_override(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """The ``rule_overrides`` entry for ``rule_id``, or ``None``.

        A copy is returned so a caller cannot mutate the loaded map, which is
        shared through the :func:`load_map` cache.
        """
        entry = self._cfnlint_rule_overrides.get(rule_id)
        return None if entry is None else dict(entry)

    def cfnlint_prefix(self, rule_id: str) -> PrefixRule:
        """Longest ``prefix_rules`` entry matching ``rule_id``.

        Returns :data:`NO_PREFIX_MATCH` when nothing matches. The entries were
        sorted by descending prefix length at load time, so the first match is
        the longest one.
        """
        for rule in self._prefix_rules:
            if rule_id.startswith(rule.prefix):
                return rule
        return NO_PREFIX_MATCH

    def cfnlint_default_category(self) -> str:
        """``cfnlint.default.category``: the Category of last resort."""
        return self._default_category

    def blocks_deployment(self, rule_id: str) -> bool:
        """Whether violating ``rule_id`` prevents the Template from deploying.

        Resolution order is ``rule_overrides[<rule_id>].blocks_deployment`` ->
        the matching ``prefix_rules`` entry -> ``False``. An explicit ``false``
        in an override therefore beats a ``true`` on its prefix, which is how
        ``E3002`` stays HIGH while other ``E3`` rules follow their prefix.

        Also the resolver :mod:`iacreview.finding` needs for Requirement 7 AC6,
        installed via ``set_blocks_deployment_resolver``.
        """
        entry = self._cfnlint_rule_overrides.get(rule_id)
        if entry is not None and entry.get("blocks_deployment") is not None:
            return bool(entry["blocks_deployment"])
        prefix_blocks = self.cfnlint_prefix(rule_id).blocks_deployment
        return bool(prefix_blocks)

    # -- public lookups -----------------------------------------------------

    def for_cfnlint_rule(self, rule_id: str) -> CategoryDecision:
        """What the mapping file says about a cfn-lint rule ID.

        An unknown rule ID yields ``default.category`` with no FindingType or
        Severity opinion, never an exception (design.md, Failure modes).
        """
        entry = self.cfnlint_override(rule_id) or {}
        prefix = self.cfnlint_prefix(rule_id)
        category = entry.get("category") or prefix.category or self._default_category
        return CategoryDecision(
            category=category,
            finding_type=SECURITY_FINDING_TYPE if entry.get("security_relevant") else None,
            severity_override=entry.get("severity"),
            why_it_matters=entry.get("why_it_matters", ""),
        )

    def for_guard_rule(
        self, rule_name: str, rule_category: Optional[str] = None
    ) -> CategoryDecision:
        """What the mapping file says about a cfn-guard rule.

        Resolution order: ``cfnguard.rule_overrides[<rule_name>]`` ->
        ``cfnguard.rule_categories[<rule_category>]`` when the caller knows the
        rule's category directory -> ``cfnguard.rule_categories[<rule_name>]``,
        which covers a caller that passes the category itself ->
        :data:`GUARD_FALLBACK_CATEGORY`.

        Args:
            rule_name: Guard rule name, for example
                ``"security_group_open_ingress"``.
            rule_category: The ``rules/<category>/`` directory the rule came
                from, for example ``"public-access"``. Optional because a rule
                override alone can decide the answer, but supplying it is what
                lets an un-overridden rule reach its directory's Category
                instead of falling back to ``Other``.
        """
        entry = self._guard_rule_overrides.get(rule_name) or {}
        category = entry.get("category")
        if category is None and rule_category is not None:
            category = self._guard_rule_categories.get(rule_category)
        if category is None:
            category = self._guard_rule_categories.get(rule_name)
        if category is None:
            category = GUARD_FALLBACK_CATEGORY
        return CategoryDecision(
            category=category,
            finding_type=entry.get("finding_type"),
            severity_override=entry.get("severity"),
            why_it_matters=entry.get("why_it_matters", ""),
        )


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

# The bundled map is read once per process. Every Finding validation resolves
# `is_valid_category` through it (see iacreview.finding), so re-reading the file
# per call would turn schema validation into repeated disk I/O. Only the default
# path is cached; an explicit path is always re-read, which is what tests of
# malformed files need.
_DEFAULT_MAP: Optional[CategoryMap] = None


def clear_cache() -> None:
    """Drop the cached bundled map.

    For tests that need the next :func:`load_map` call to hit the filesystem
    again. Production code has no reason to call this: the file is plugin-owned
    and does not change while the process runs.
    """
    global _DEFAULT_MAP
    _DEFAULT_MAP = None


def load_map(path: Optional[Path] = None) -> CategoryMap:
    """Load and validate a category mapping file.

    Args:
        path: Mapping file to read. ``None`` means the bundled
            :data:`DEFAULT_MAP_RELATIVE_PATH`, resolved inside the plugin root
            and cached. An explicit path is treated as plugin- or test-supplied
            and read directly; it is **not** a place to pass user input. A
            user-supplied path must go through
            :func:`iacreview.pathguard.resolve_within` first.

    Returns:
        A validated :class:`CategoryMap`. The cached instance is shared, so
        callers must not mutate what they read from it; the accessors that
        return dicts already hand back copies.

    Raises:
        MappingFileError: The file is missing, unreadable, not valid JSON,
            declares an unsupported ``schema_version`` MAJOR, or violates the
            expected structure. Exit code 1: a broken mapping file is a broken
            installation, and no part of the review can continue without the
            category vocabulary.
    """
    global _DEFAULT_MAP
    if path is not None:
        return _load_from(Path(path))
    if _DEFAULT_MAP is None:
        _DEFAULT_MAP = _load_from(pathguard.resolve_plugin_owned(DEFAULT_MAP_RELATIVE_PATH))
    return _DEFAULT_MAP


def _read_document(source: Path) -> Dict[str, Any]:
    """Read ``source`` and parse it as a JSON object.

    ``OSError`` covers a missing or unreadable file; ``ValueError`` covers both
    invalid JSON (``json.JSONDecodeError``) and a file that is not valid UTF-8
    (``UnicodeDecodeError``). Both surface as ``MappingFileError`` so no caller
    has to know which layer failed.
    """
    try:
        text = source.read_text(encoding="utf-8")
    except OSError as exc:
        raise _fail(source, "<file>", "cannot be read ({0})".format(exc)) from exc
    except ValueError as exc:
        raise _fail(source, "<file>", "is not valid UTF-8 ({0})".format(exc)) from exc

    try:
        document = json.loads(text)
    except ValueError as exc:
        raise _fail(source, "<file>", "is not valid JSON ({0})".format(exc)) from exc

    return _require_object(source, "<root>", document)


def _load_from(source: Path) -> CategoryMap:
    """Validate one mapping file and build a :class:`CategoryMap` from it."""
    document = _read_document(source)
    _reject_unknown_keys(source, "", document, _TOP_LEVEL_KEYS)
    _require_keys(source, "", document, _TOP_LEVEL_REQUIRED)

    schema_version = _validate_schema_version(source, document["schema_version"])
    categories = _validate_categories(source, document["categories"])
    notes = _require_object(source, "notes", document.get("notes", {}))

    cfnlint = _require_object(source, "cfnlint", document["cfnlint"])
    _reject_unknown_keys(source, "cfnlint", cfnlint, _CFNLINT_KEYS)
    _require_keys(source, "cfnlint", cfnlint, _CFNLINT_KEYS)

    level_defaults = _validate_level_defaults(source, cfnlint["level_defaults"])

    default_entry = _require_object(source, "cfnlint.default", cfnlint["default"])
    _reject_unknown_keys(source, "cfnlint.default", default_entry, _DEFAULT_KEYS)
    _require_keys(source, "cfnlint.default", default_entry, _DEFAULT_KEYS)
    default_category = _require_known_category(
        source, "cfnlint.default.category", default_entry["category"], categories
    )

    prefix_rules = _validate_prefix_rules(source, cfnlint["prefix_rules"], categories)
    cfnlint_rule_overrides = _validate_cfnlint_overrides(
        source, cfnlint["rule_overrides"], categories
    )
    guard_rule_categories, guard_rule_overrides = _validate_guard(
        source, document["cfnguard"], categories
    )

    return CategoryMap(
        source_path=source,
        schema_version=schema_version,
        categories=categories,
        notes=notes,
        level_defaults=level_defaults,
        default_category=default_category,
        prefix_rules=prefix_rules,
        cfnlint_rule_overrides=cfnlint_rule_overrides,
        guard_rule_categories=guard_rule_categories,
        guard_rule_overrides=guard_rule_overrides,
    )


# ---------------------------------------------------------------------------
# cfn-lint classification
# ---------------------------------------------------------------------------


def classify_cfnlint(
    rule_id: str, level: str, cmap: Optional[CategoryMap] = None
) -> Classification:
    """Classify one cfn-lint result into Category, FindingType and Severity.

    A transcription of the design pseudocode (design.md, security-relevance
    override の動作). The three rules it encodes:

    * ``security_relevant`` replaces the FindingType with ``Security``
      (Requirement 4 AC9) and leaves the Severity at its level default. An
      override that also wants a different Severity states ``severity``
      explicitly.
    * ``level == "Error"`` plus ``blocks_deployment`` promotes the Severity to
      ``CRITICAL`` (Requirement 4 AC5, Requirement 7 AC6). Because the level is
      part of the condition, a Warning or Informational result never becomes
      CRITICAL even when its rule blocks deployment.
    * Everything else follows ``level_defaults``: Error -> Validity / HIGH,
      Warning -> BestPractice / MEDIUM, Informational -> Informational / LOW
      (Requirement 4 AC3, AC4, AC6, AC7).

    Args:
        rule_id: cfn-lint rule ID, for example ``"E3002"``. An ID the mapping
            file does not know is classified from its level and the default
            Category, without raising.
        level: cfn-lint result level.
        cmap: Mapping file to consult. ``None`` loads the bundled one.

    Returns:
        The Classification for this result.

    Raises:
        MappingFileError: Only when ``cmap`` is ``None`` and the bundled
            mapping file cannot be loaded.
    """
    if cmap is None:
        cmap = load_map()

    base = cmap.cfnlint_level_default(level)
    entry = cmap.cfnlint_override(rule_id) or {}
    prefix = cmap.cfnlint_prefix(rule_id)

    category = entry.get("category") or prefix.category or cmap.cfnlint_default_category()
    finding_type = SECURITY_FINDING_TYPE if entry.get("security_relevant") else base.finding_type
    severity = entry.get("severity") or base.severity

    blocks = entry.get("blocks_deployment")
    if blocks is None:
        blocks = prefix.blocks_deployment
    if level == ERROR_LEVEL and blocks:
        severity = CRITICAL_SEVERITY

    return Classification(category=category, finding_type=finding_type, severity=severity)
