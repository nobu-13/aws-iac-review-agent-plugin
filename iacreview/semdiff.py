"""Semantic Diff of two parsed Templates (v1.1 Delta_Tool).

:func:`diff` compares the declared structure of a Base and a Head Template and
returns the observed changes as Change_Entries, together with the paths it could
not compare and the Semantic_Limitations of the comparison. It is a pure
function: no file is read and nothing is printed.

Only bounded documents are accepted
    :func:`diff` takes :class:`iacreview.deltaio.ParsedTemplate` values only.
    That type is produced after the structure check (Design 2-5), so the
    document has no reference cycle and its logical node count and depth are
    within the limits. Walking it as a tree, path by path, therefore terminates
    and costs at most the logical node count of each side. A subtree shared
    through a YAML alias is compared at every path where it appears.

What a Change_Entry is
    A change is reported once, at the deepest position where the two sides
    differ; ``added`` / ``removed`` is reported at the root of the subtree that
    exists on one side only (Design 3-2). Sections are compared in the units of
    Design 3-1: ``Resources`` by Logical ID (a different ``Type`` is one
    ``modified`` entry with ``type_changed`` and nothing below it), the entry
    sections by entry name, and the section-level and unknown keys as opaque
    values reported at the key itself. Paths are normalized with
    :func:`canonical_path` (``finding.canonical_template_path``, keeping a
    digit character ``int()`` refuses as a string).

Logical ID renames
    ``possible_logical_id_rename`` is attached to removed / added Resources of
    the same ``Type``. A Resource that exists on one side only but could not be
    compared (it is in ``uncompared_paths``) has no Change_Entry, yet it may be
    one end of a rename: it is listed in ``uncompared_rename_candidates`` and
    pairs by ``Type``, or with any Type when a duplicate key may hide its
    ``Type``. When the whole ``Resources`` section is not compared, every
    Logical ID present on one side only is listed. Both feed ``rename_hints``.

Normalization is a closed table (Design 2-4)
    Notation is compared after parsing (N-1, N-2). A YAML ``date`` is compared
    as its ISO string (N-3). A YAML timestamp with a time, a mapping with a
    non-string key, and a mapping that held a duplicate key are not compared:
    their paths go to ``uncompared_paths`` and the result is ``partial``. Any
    other difference, including one of scalar type (``80`` vs ``"80"``, ``1``
    vs ``1.0``, ``true`` vs ``1``), is a change (N-6).

Qualifiers and Limitations (Design 3-3)
    Each Change_Entry carries the Change_Qualifiers whose condition holds for
    the expression the change belongs to: the subtree at the change position on
    either side, and the intrinsic keys on the path to it. The
    Semantic_Limitations describe the whole comparison and are found by a walk
    that visits each object once. Neither changes ``structural_completeness``.

No values are returned
    The result holds section names, mapping keys, list indexes, resource
    ``Type`` strings and closed-set codes. Template scalar values never leave
    this module (Requirement 16 AC3). The keys are plain identifiers for
    in-process callers; anonymizing them for output is the job of the report
    builder.

Limits
    More Change_Entries than ``deltaschema.MAX_CHANGE_ENTRIES`` make the whole
    comparison fail with ``change_entry_limit_exceeded``: no partial list is
    returned (Requirement 14 AC6). The limit is read at call time.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Set, Tuple, Union

from iacreview import deltaschema
from iacreview.deltaio import Failure, ParsedTemplate, Shape
from iacreview.finding import canonical_template_path

__all__ = [
    "PathItem",
    "ResourceTypes",
    "ChangeEntry",
    "UncomparedPath",
    "SemanticDiffResult",
    "RESOURCES_SECTION",
    "ENTRY_SECTIONS",
    "SECTION_LEVEL_SECTIONS",
    "RESOURCE_ATTRIBUTES",
    "canonical_path",
    "diff",
]

#: A path element: a mapping key or a list index.
PathItem = Union[str, int]

#: The section compared by Logical ID.
RESOURCES_SECTION = "Resources"

#: The section whose entries carry a ``Condition`` attribute besides Resources.
OUTPUTS_SECTION = "Outputs"

#: Sections compared by entry name (Requirement 3 AC4).
ENTRY_SECTIONS: Tuple[str, ...] = ("Parameters", "Conditions", "Mappings", "Outputs", "Rules")

#: Sections reported at section level (Requirement 3 AC5).
SECTION_LEVEL_SECTIONS: Tuple[str, ...] = (
    "AWSTemplateFormatVersion",
    "Description",
    "Metadata",
    "Transform",
)

#: Resource Attributes compared path by path, besides ``Properties``
#: (Requirement 3 AC3). Any other key directly under a Resource is opaque.
RESOURCE_ATTRIBUTES: Tuple[str, ...] = (
    "DependsOn",
    "Condition",
    "DeletionPolicy",
    "UpdateReplacePolicy",
    "UpdatePolicy",
    "CreationPolicy",
    "Metadata",
)

#: Sections whose changes may affect other parts indirectly (Requirement 4 AC8).
_INDIRECT_SECTIONS: FrozenSet[str] = frozenset(("Parameters", "Mappings", "Conditions"))

#: Sections whose entries may carry a ``Condition`` attribute (Requirement 4 AC4).
_CONDITIONAL_ENTRY_SECTIONS: FrozenSet[str] = frozenset((RESOURCES_SECTION, OUTPUTS_SECTION))

_TYPE_KEY = "Type"
_PROPERTIES_KEY = "Properties"
_CONDITION_KEY = "Condition"
_REF_KEY = "Ref"
_FN_PREFIX = "Fn::"
_FN_IF = "Fn::If"
_FN_TRANSFORM = "Fn::Transform"
_EXTERNAL_FUNCTIONS: FrozenSet[str] = frozenset(("Fn::ImportValue", "Fn::GetAZs"))
_PSEUDO_PARAMETER_PREFIX = "AWS::"
_DYNAMIC_REFERENCE_MARKER = "{{resolve:"
_TRANSFORM_SECTION = "Transform"
_INCLUDE_TRANSFORM = "AWS::Include"
_NESTED_STACK_TYPE = "AWS::CloudFormation::Stack"
_RENAME_HINT = "possible_logical_id_rename"
_PRE_TRANSFORM = "pre_transform"
_TRANSFORM_LIMITATION = "transform_not_expanded"

# Qualifier bits collected during the walk.
_Q_EXPRESSION = 1
_Q_CONDITIONAL = 2
_Q_DYNAMIC = 4
_Q_EXTERNAL = 8
_Q_ALL_SCANNED = _Q_EXPRESSION | _Q_DYNAMIC | _Q_EXTERNAL
_QUALIFIER_BITS: Tuple[Tuple[int, str], ...] = (
    (_Q_EXPRESSION, "expression_unevaluated"),
    (_Q_CONDITIONAL, "conditional"),
    (_Q_DYNAMIC, "dynamic_reference_unresolved"),
    (_Q_EXTERNAL, "external_value"),
)


class _Missing:
    """Marks a key or index that one side does not have."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "<missing>"


_MISSING = _Missing()


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResourceTypes:
    """The ``Type`` of the Resource a change belongs to, per side.

    ``None`` on a side where the Resource does not exist or its ``Type`` is
    not a string.
    """

    base: Optional[str]
    head: Optional[str]


@dataclass(frozen=True)
class ChangeEntry:
    """One observed change. Holds no Template value.

    Attributes:
        section: The top-level section name.
        path: From the section name down, normalized by
            ``finding.canonical_template_path``.
        change: ``added``, ``removed`` or ``modified``.
        type_changed: The Resource ``Type`` differs; nothing below was paired.
        resource_type: Inside ``Resources``, the ``Type`` per side; else ``None``.
        qualifiers: Change_Qualifier codes in the documented order.
        hints: Hint codes in the documented order.
    """

    section: str
    path: Tuple[PathItem, ...]
    change: str
    type_changed: bool
    resource_type: Optional[ResourceTypes]
    qualifiers: Tuple[str, ...]
    hints: Tuple[str, ...]

    @property
    def entry(self) -> Optional[str]:
        """The Logical ID or entry name, for a section compared by entry."""
        if self.section in _ENTRY_UNIT_SECTIONS and len(self.path) > 1:
            name = self.path[1]
            return name if isinstance(name, str) else None
        return None


@dataclass(frozen=True)
class UncomparedPath:
    """A path left out of the comparison, and why (Design 4-1)."""

    path: Tuple[PathItem, ...]
    reason: str


@dataclass(frozen=True)
class SemanticDiffResult:
    """The analyzed Semantic Diff. The state fields follow from the content.

    Attributes:
        changes: Change_Entries in walk order (sections and keys ascending,
            list indexes ascending). Output order is decided by the report.
        uncompared_paths: Paths not compared, each listed once.
        semantic_limitations: Semantic_Limitation codes in the documented order.
        uncompared_rename_candidates: Logical IDs, sorted, that exist on one
            side only and were not compared (their Resource, or the whole
            ``Resources`` section, is in ``uncompared_paths``), so no
            Change_Entry can carry their hint. A rename to or from them cannot
            be ruled out (Requirement 4 AC13, Design 3-2).
    """

    changes: Tuple[ChangeEntry, ...]
    uncompared_paths: Tuple[UncomparedPath, ...]
    semantic_limitations: Tuple[str, ...]
    uncompared_rename_candidates: Tuple[str, ...] = ()

    @property
    def analysis_state(self) -> str:
        return "analyzed"

    @property
    def observation(self) -> str:
        return "changes_observed" if self.changes else "no_changes_observed"

    @property
    def structural_completeness(self) -> str:
        return "partial" if self.uncompared_paths else "complete"

    @property
    def rename_hints(self) -> FrozenSet[str]:
        """Logical IDs carrying ``possible_logical_id_rename``.

        The Change_Entries with the hint, and the uncompared one-sided
        Logical IDs of ``uncompared_rename_candidates``.
        """
        names: Set[str] = set(self.uncompared_rename_candidates)
        for change in self.changes:
            if _RENAME_HINT in change.hints and change.entry is not None:
                names.add(change.entry)
        return frozenset(names)


_ENTRY_UNIT_SECTIONS: FrozenSet[str] = frozenset((RESOURCES_SECTION,) + ENTRY_SECTIONS)


class _ChangeLimitExceeded(Exception):
    """More Change_Entries than the limit. Carries no data."""


# ---------------------------------------------------------------------------
# Scalars (Design 2-4 N-3, N-6)
# ---------------------------------------------------------------------------


def _is_timestamp(value: Any) -> bool:
    return isinstance(value, datetime.datetime)


def _scalar_key(value: Any) -> Tuple[str, Any]:
    """A typed key: equal keys mean equal scalars under N-3 and N-6."""
    if value is None:
        return ("null", None)
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, int):
        return ("int", value)
    if isinstance(value, float):
        # repr distinguishes 1.0 from 1 by type already, and makes NaN equal NaN.
        return ("float", repr(value))
    if isinstance(value, str):
        return ("str", value)
    if isinstance(value, datetime.date):
        return ("str", value.isoformat())
    if isinstance(value, bytes):
        return ("bytes", value)
    if isinstance(value, (set, frozenset)):
        return ("set", tuple(sorted(repr(_scalar_key(item)) for item in value)))
    # Unknown scalar types compare only to an identical repr of the same type.
    return (type(value).__name__, repr(value))


def _kind(value: Any) -> str:
    if isinstance(value, dict):
        return "mapping"
    if isinstance(value, list):
        return "list"
    if isinstance(value, tuple):
        return "tuple"
    return "scalar"


def _has_non_string_key(value: Any) -> bool:
    return isinstance(value, dict) and any(not isinstance(key, str) for key in value)


def _is_pseudo_parameter(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(_PSEUDO_PARAMETER_PREFIX)


def _is_condition_function(mapping: Any) -> bool:
    """Whether ``mapping`` has the form of the Condition function.

    The function is written ``{"Condition": "<name>"}``: one key, a string
    value. A ``Condition`` key in any other mapping (for example an IAM
    Statement's ``Condition: {StringEquals: ...}``) is ordinary data.
    """
    return (
        isinstance(mapping, dict)
        and len(mapping) == 1
        and isinstance(mapping.get(_CONDITION_KEY), str)
    )


def _is_intrinsic_key(key: Any, mapping: Any, attribute_level: bool) -> bool:
    """``Ref``, ``Fn::*``, or the Condition function (not the attribute).

    ``mapping`` is the mapping that holds ``key`` on one side.
    """
    if not isinstance(key, str):
        return False
    if key == _REF_KEY or key.startswith(_FN_PREFIX):
        return True
    return key == _CONDITION_KEY and not attribute_level and _is_condition_function(mapping)


def _resource_type(resource: Any) -> Optional[str]:
    if isinstance(resource, dict):
        value = resource.get(_TYPE_KEY)
        if isinstance(value, str):
            return value
    return None


def _has_condition_attribute(entry: Any) -> bool:
    return isinstance(entry, dict) and _CONDITION_KEY in entry


def _is_attribute_level(path: Tuple[PathItem, ...]) -> bool:
    """Whether keys of the mapping at ``path`` are Resource / Output attributes."""
    return len(path) == 2 and path[0] in _CONDITIONAL_ENTRY_SECTIONS


#: Stands in for a segment ``canonical_template_path`` would pass to ``int()``
#: although ``int()`` refuses it; not digit-only, so it is kept as a string.
_NON_DECIMAL_STAND_IN = "-"


def canonical_path(path: Sequence[Any]) -> Tuple[PathItem, ...]:
    """``finding.canonical_template_path`` that keeps every segment it cannot type.

    v1.0 turns a segment into an ``int`` when ``str.isdigit()`` holds, but
    ``isdigit()`` also accepts digit characters ``int()`` refuses (``"\\u00b2"``).
    Such a segment is kept as the string it is: it can only be a mapping key.
    Every other segment follows the v1.0 rule unchanged.
    """
    odd = [
        index
        for index, segment in enumerate(path)
        if isinstance(segment, str) and segment.isdigit() and not segment.isdecimal()
    ]
    if not odd:
        return tuple(canonical_template_path(path))
    probe = list(path)
    for index in odd:
        probe[index] = _NON_DECIMAL_STAND_IN
    canonical = canonical_template_path(probe)
    for index in odd:
        canonical[index] = path[index]
    return tuple(canonical)


def _canonical(path: Tuple[PathItem, ...]) -> Tuple[PathItem, ...]:
    return canonical_path(path)


# ---------------------------------------------------------------------------
# Qualifier scan of the subtree at a change position (Design 3-3)
# ---------------------------------------------------------------------------


def _scan_subtree(value: Any, path: Tuple[PathItem, ...]) -> int:
    """Qualifier bits found in ``value``, walked as a tree with a stack.

    The subtrees of different Change_Entries do not overlap, so the walks of
    one comparison together stay within the logical node count of each side.
    """
    if value is _MISSING:
        return 0
    found = 0
    stack: List[Tuple[Any, bool]] = [(value, _is_attribute_level(path))]
    while stack and found != _Q_ALL_SCANNED:
        current, attribute_level = stack.pop()
        if isinstance(current, dict):
            for key, child in current.items():
                if _is_intrinsic_key(key, current, attribute_level):
                    found |= _Q_EXPRESSION
                if key in _EXTERNAL_FUNCTIONS or (key == _REF_KEY and _is_pseudo_parameter(child)):
                    found |= _Q_EXTERNAL
                if isinstance(key, str) and _DYNAMIC_REFERENCE_MARKER in key:
                    found |= _Q_DYNAMIC
                stack.append((child, False))
        elif isinstance(current, (list, tuple)):
            stack.extend((child, False) for child in current)
        elif isinstance(current, str) and _DYNAMIC_REFERENCE_MARKER in current:
            found |= _Q_DYNAMIC
    return found


def _child_flags(
    flags: int,
    parent: Tuple[PathItem, ...],
    key: str,
    parents: Tuple[Any, Any],
    base: Any,
    head: Any,
) -> int:
    """Qualifier bits inherited by the child at ``parent + (key,)``.

    ``parents`` is the mapping at ``parent`` on the Base and Head side
    (``_MISSING`` where absent). The section and entry name (path positions 0
    and 1) are names, not expressions, so only keys from position 2 on are
    looked at.
    """
    if len(parent) < 2:
        return flags
    attribute_level = _is_attribute_level(parent)
    if any(_is_intrinsic_key(key, mapping, attribute_level) for mapping in parents):
        flags |= _Q_EXPRESSION
    if key == _FN_IF:
        flags |= _Q_CONDITIONAL
    if key in _EXTERNAL_FUNCTIONS or (
        key == _REF_KEY and (_is_pseudo_parameter(base) or _is_pseudo_parameter(head))
    ):
        flags |= _Q_EXTERNAL
    return flags


# ---------------------------------------------------------------------------
# Limitations: each object visited once (Design 2-5-3)
# ---------------------------------------------------------------------------


def _scan_limitations(doc: Any) -> Set[str]:
    found: Set[str] = set()
    if isinstance(doc, dict) and _TRANSFORM_SECTION in doc:
        found.add(_TRANSFORM_LIMITATION)
    seen: Set[int] = set()
    stack: List[Any] = [doc]
    while stack:
        current = stack.pop()
        if isinstance(current, (dict, list, tuple)):
            if id(current) in seen:
                continue
            seen.add(id(current))
        if isinstance(current, dict):
            for key, child in current.items():
                if key == _FN_TRANSFORM:
                    found.add(_TRANSFORM_LIMITATION)
                if key == _TYPE_KEY and isinstance(child, str) and child == _NESTED_STACK_TYPE:
                    found.add("nested_stack_not_compared")
                stack.append(key)
                stack.append(child)
        elif isinstance(current, (list, tuple, set, frozenset)):
            stack.extend(current)
        elif isinstance(current, str):
            if _DYNAMIC_REFERENCE_MARKER in current:
                found.add("dynamic_reference_unresolved")
            if current == _INCLUDE_TRANSFORM:
                found.add(_TRANSFORM_LIMITATION)
    return found


# ---------------------------------------------------------------------------
# The structural comparison
# ---------------------------------------------------------------------------


@dataclass
class _Raw:
    """A Change_Entry before hints and ``pre_transform`` are known."""

    section: str
    path: Tuple[PathItem, ...]
    change: str
    type_changed: bool
    resource_type: Optional[ResourceTypes]
    flags: int


class _Differ:
    """State of one comparison. Every walk uses an explicit stack."""

    def __init__(self, base: ParsedTemplate, head: ParsedTemplate) -> None:
        self._base = base
        self._head = head
        self._limit = deltaschema.MAX_CHANGE_ENTRIES
        self.changes: List[_Raw] = []
        self.uncompared: List[UncomparedPath] = []
        self._uncompared_seen: Set[Tuple[Tuple[PathItem, ...], str]] = set()
        #: One-sided Resources left uncompared: (Logical ID, "base" / "head",
        #: Type or ``None`` when it cannot be relied on).
        self.uncompared_one_sided: List[Tuple[str, str, Optional[str]]] = []
        #: The ``Resources`` section as a whole was not compared.
        self.resources_uncompared = False

    # -- recording -----------------------------------------------------------

    def _record_uncompared(self, path: Tuple[PathItem, ...], reason: str) -> None:
        canonical = _canonical(path)
        if (canonical, reason) not in self._uncompared_seen:
            self._uncompared_seen.add((canonical, reason))
            self.uncompared.append(UncomparedPath(path=canonical, reason=reason))

    def _emit(
        self,
        section: str,
        path: Tuple[PathItem, ...],
        change: str,
        base: Any,
        head: Any,
        flags: int,
        resource_type: Optional[ResourceTypes],
        type_changed: bool = False,
    ) -> None:
        flags |= _scan_subtree(base, path) | _scan_subtree(head, path)
        self.changes.append(
            _Raw(section, _canonical(path), change, type_changed, resource_type, flags)
        )
        if len(self.changes) > self._limit:
            raise _ChangeLimitExceeded()

    def _uncomparable(self, path: Tuple[PathItem, ...], base: Any, head: Any) -> bool:
        """Record and skip a position that must not be compared (Design 3-2)."""
        if (base is not _MISSING and self._base.marked.contains(base)) or (
            head is not _MISSING and self._head.marked.contains(head)
        ):
            self._record_uncompared(path, "duplicate_key")
            return True
        if _has_non_string_key(base) or _has_non_string_key(head):
            self._record_uncompared(path, "non_string_key")
            return True
        if _is_timestamp(base) or _is_timestamp(head):
            self._record_uncompared(path, "yaml_timestamp")
            return True
        return False

    def _note_one_sided(self, path: Tuple[PathItem, ...], base: Any, head: Any) -> None:
        """Keep an uncompared Resource that exists on one side only.

        It has no Change_Entry, but it may be one end of a rename. Its ``Type``
        is used only when the Resource mapping itself is not marked: a
        duplicate key may hide another ``Type``.
        """
        if (base is _MISSING) == (head is _MISSING) or not isinstance(path[1], str):
            return
        side, value, marked = (
            ("head", head, self._head.marked) if base is _MISSING else ("base", base, self._base.marked)
        )
        resource_type = None if marked.contains(value) else _resource_type(value)
        self.uncompared_one_sided.append((path[1], side, resource_type))

    # -- the generic walk ----------------------------------------------------

    def _walk(
        self,
        section: str,
        root: Tuple[PathItem, ...],
        base: Any,
        head: Any,
        flags: int,
        resource_type: Optional[ResourceTypes],
        collect: bool,
    ) -> bool:
        """Compare ``base`` and ``head`` below ``root``. Returns whether they differ.

        With ``collect`` the deepest differences are emitted as Change_Entries;
        without it (opaque comparison) only the answer is computed. Uncomparable
        positions are recorded either way.
        """
        changed = False
        stack: List[Tuple[Tuple[PathItem, ...], Any, Any, int]] = [(root, base, head, flags)]
        while stack:
            path, left, right, bits = stack.pop()
            if self._uncomparable(path, left, right):
                continue
            if left is _MISSING or right is _MISSING:
                changed = True
                if collect:
                    kind = "added" if left is _MISSING else "removed"
                    self._emit(section, path, kind, left, right, bits, resource_type)
                continue
            left_kind, right_kind = _kind(left), _kind(right)
            if left_kind == right_kind == "mapping":
                for key in sorted(set(left) | set(right), reverse=True):
                    child_left = left.get(key, _MISSING)
                    child_right = right.get(key, _MISSING)
                    stack.append(
                        (
                            path + (key,),
                            child_left,
                            child_right,
                            _child_flags(
                                bits, path, key, (left, right), child_left, child_right
                            ),
                        )
                    )
            elif left_kind == right_kind and left_kind in ("list", "tuple"):
                for index in reversed(range(max(len(left), len(right)))):
                    child_left = left[index] if index < len(left) else _MISSING
                    child_right = right[index] if index < len(right) else _MISSING
                    stack.append((path + (index,), child_left, child_right, bits))
            elif left_kind == right_kind == "scalar" and _scalar_key(left) == _scalar_key(right):
                continue
            else:
                changed = True
                if collect:
                    self._emit(section, path, "modified", left, right, bits, resource_type)
        return changed

    def _opaque(
        self,
        section: str,
        path: Tuple[PathItem, ...],
        base: Any,
        head: Any,
        flags: int,
        resource_type: Optional[ResourceTypes],
    ) -> None:
        """Compare as one value and report any difference at ``path`` itself."""
        if not self._walk(section, path, base, head, flags, resource_type, collect=False):
            return
        if base is _MISSING:
            kind = "added"
        elif head is _MISSING:
            kind = "removed"
        else:
            kind = "modified"
        self._emit(section, path, kind, base, head, flags, resource_type)

    # -- sections ------------------------------------------------------------

    def run(self) -> None:
        base_doc, head_doc = self._base.doc, self._head.doc
        duplicated = set(self._base.duplicate_sections) | set(self._head.duplicate_sections)
        sections: Set[str] = set()
        for doc in (base_doc, head_doc):
            for key in doc:
                if isinstance(key, str):
                    sections.add(key)
                else:
                    # A top-level key that is not a string cannot be named in a
                    # path; the document root is recorded, the string sections
                    # are still compared (as for a duplicate section).
                    self._record_uncompared((), "non_string_key")
        for section in sorted(sections):
            if section in duplicated:
                self._record_uncompared((section,), "duplicate_key")
                if section == RESOURCES_SECTION:
                    self.resources_uncompared = True
                continue
            base = base_doc.get(section, _MISSING)
            head = head_doc.get(section, _MISSING)
            if section in _ENTRY_UNIT_SECTIONS:
                self._entries(section, base, head)
            else:
                self._opaque(section, (section,), base, head, 0, None)

    def _entries(self, section: str, base: Any, head: Any) -> None:
        """A section compared entry by entry (Requirement 3 AC1, AC4)."""
        path: Tuple[PathItem, ...] = (section,)
        if self._uncomparable(path, base, head):
            if section == RESOURCES_SECTION:
                self.resources_uncompared = True
            return
        if not (isinstance(base, dict) and isinstance(head, dict)):
            self._opaque(section, path, base, head, 0, None)
            return
        for name in sorted(set(base) | set(head)):
            entry_base = base.get(name, _MISSING)
            entry_head = head.get(name, _MISSING)
            flags = 0
            if section in _CONDITIONAL_ENTRY_SECTIONS and (
                _has_condition_attribute(entry_base) or _has_condition_attribute(entry_head)
            ):
                flags = _Q_CONDITIONAL
            if section == RESOURCES_SECTION:
                types = ResourceTypes(_resource_type(entry_base), _resource_type(entry_head))
                self._resource((section, name), entry_base, entry_head, flags, types)
            else:
                self._walk(section, (section, name), entry_base, entry_head, flags, None, True)

    def _resource(
        self,
        path: Tuple[PathItem, ...],
        base: Any,
        head: Any,
        flags: int,
        types: ResourceTypes,
    ) -> None:
        """One Logical ID (Requirement 3 AC1-AC3, Design 3-1)."""
        section = RESOURCES_SECTION
        if self._uncomparable(path, base, head):
            self._note_one_sided(path, base, head)
            return
        if not (isinstance(base, dict) and isinstance(head, dict)):
            # Added, removed, or not a mapping on some side: one value.
            self._walk(section, path, base, head, flags, types, collect=True)
            return
        base_type = base.get(_TYPE_KEY, _MISSING)
        head_type = head.get(_TYPE_KEY, _MISSING)
        type_path = path + (_TYPE_KEY,)
        if not (base_type is _MISSING and head_type is _MISSING) and self._walk(
            section, type_path, base_type, head_type, flags, types, collect=False
        ):
            self._emit(section, path, "modified", base, head, flags, types, type_changed=True)
            return
        for key in sorted((set(base) | set(head)) - {_TYPE_KEY}):
            child_base = base.get(key, _MISSING)
            child_head = head.get(key, _MISSING)
            child_flags = _child_flags(flags, path, key, (base, head), child_base, child_head)
            child_path = path + (key,)
            if key == _PROPERTIES_KEY or key in RESOURCE_ATTRIBUTES:
                self._walk(section, child_path, child_base, child_head, child_flags, types, True)
            else:
                self._opaque(section, child_path, child_base, child_head, child_flags, types)


_OTHER_SIDE = {"base": "head", "head": "base"}


class _RenameEnds:
    """The Resources that exist on one side only, per side (Requirement 4 AC13).

    An end is a removed / added Resource Change_Entry or an uncompared
    one-sided Resource (Design 3-2). An end whose ``Type`` is unknown (``None``)
    pairs with every end on the other side; an end with a known ``Type`` pairs
    with the other side's ends of the same ``Type``.
    """

    def __init__(self, changes: List[_Raw], uncompared: List[Tuple[str, str, Optional[str]]]) -> None:
        self._types: Dict[str, Set[str]] = {"base": set(), "head": set()}
        self._any: Dict[str, bool] = {"base": False, "head": False}
        self._unknown: Dict[str, bool] = {"base": False, "head": False}
        for raw in changes:
            side = _rename_side(raw)
            if side is not None and raw.resource_type is not None:
                # A compared entry whose Type is not a string pairs with
                # nothing by Type (the v1.1 rule), but still is an end.
                self._add(side, getattr(raw.resource_type, side), wildcard=False)
        for _name, side, resource_type in uncompared:
            self._add(side, resource_type, wildcard=True)

    def _add(self, side: str, resource_type: Optional[str], *, wildcard: bool) -> None:
        self._any[side] = True
        if resource_type is not None:
            self._types[side].add(resource_type)
        elif wildcard:
            self._unknown[side] = True

    def pairs(self, side: str, resource_type: Optional[str], *, unknown_pairs: bool) -> bool:
        """Whether an end on ``side`` with ``resource_type`` has a counterpart.

        ``unknown_pairs`` lets an end of unknown ``Type`` pair with any end on
        the other side; it is set for uncompared ends only, so a Change_Entry
        whose ``Type`` is not a string keeps the v1.1 rule (same ``Type``).
        """
        other = _OTHER_SIDE[side]
        if self._unknown[other]:
            return True
        if resource_type is None:
            return unknown_pairs and self._any[other]
        return resource_type in self._types[other]


def _rename_side(raw: _Raw) -> Optional[str]:
    """``base`` for a removed Resource entry, ``head`` for an added one."""
    if raw.section != RESOURCES_SECTION or len(raw.path) != 2:
        return None
    if raw.change == "removed":
        return "base"
    if raw.change == "added":
        return "head"
    return None


def _uncompared_candidates(
    differ: "_Differ", ends: _RenameEnds, base_doc: Any, head_doc: Any
) -> Tuple[str, ...]:
    """Logical IDs without a Change_Entry that may be one end of a rename.

    When the whole ``Resources`` section was not compared, every Logical ID
    present on one side only is a candidate.
    """
    names: Set[str] = set()
    for name, side, resource_type in differ.uncompared_one_sided:
        if ends.pairs(side, resource_type, unknown_pairs=True):
            names.add(name)
    if differ.resources_uncompared:
        base = _resource_names(base_doc)
        head = _resource_names(head_doc)
        names.update(base ^ head)
    return tuple(sorted(names))


def _resource_names(doc: Any) -> Set[str]:
    """The string Logical IDs of ``doc``'s ``Resources`` mapping, if any."""
    resources = doc.get(RESOURCES_SECTION) if isinstance(doc, dict) else None
    if not isinstance(resources, dict):
        return set()
    return {name for name in resources if isinstance(name, str)}


def _finish(raw: _Raw, pre_transform: bool, ends: _RenameEnds) -> ChangeEntry:
    qualifiers = [code for bit, code in _QUALIFIER_BITS if raw.flags & bit]
    if pre_transform:
        qualifiers.append(_PRE_TRANSFORM)
    hints: Tuple[str, ...] = ()
    side = _rename_side(raw)
    if side is not None and raw.resource_type is not None:
        resource_type = getattr(raw.resource_type, side)
        if ends.pairs(side, resource_type, unknown_pairs=False):
            hints = (_RENAME_HINT,)
    return ChangeEntry(
        section=raw.section,
        path=raw.path,
        change=raw.change,
        type_changed=raw.type_changed,
        resource_type=raw.resource_type,
        # _QUALIFIER_BITS follows deltaschema.CHANGE_QUALIFIERS, which ends
        # with pre_transform, so this list is already in the documented order.
        qualifiers=tuple(qualifiers),
        hints=hints,
    )


def diff(base: ParsedTemplate, head: ParsedTemplate) -> Union[SemanticDiffResult, Failure]:
    """Compare two structurally checked Templates (Design 3-2).

    Args:
        base: The Base Template, as returned by ``deltaio.parse_template``.
        head: The Head Template, likewise.

    Returns:
        The :class:`SemanticDiffResult`, or a :class:`~iacreview.deltaio.Failure`
        with ``change_entry_limit_exceeded`` when there are more Change_Entries
        than ``deltaschema.MAX_CHANGE_ENTRIES``. No partial result is returned.

    Raises:
        TypeError: An argument is not a :class:`~iacreview.deltaio.ParsedTemplate`
            with a :class:`~iacreview.deltaio.Shape`, i.e. it did not pass the
            structure check. Such a document must not be walked as a tree.
    """
    for side in (base, head):
        if not isinstance(side, ParsedTemplate) or not isinstance(side.shape, Shape):
            raise TypeError("diff accepts only structure-checked ParsedTemplate values")
    differ = _Differ(base, head)
    try:
        differ.run()
    except _ChangeLimitExceeded:
        return Failure("change_entry_limit_exceeded", None, "template")

    limitations = _scan_limitations(base.doc) | _scan_limitations(head.doc)
    if any(raw.section in _INDIRECT_SECTIONS for raw in differ.changes):
        limitations.add("indirect_effects_not_evaluated")
    pre_transform = _TRANSFORM_LIMITATION in limitations
    ends = _RenameEnds(differ.changes, differ.uncompared_one_sided)
    changes = tuple(_finish(raw, pre_transform, ends) for raw in differ.changes)
    return SemanticDiffResult(
        changes=changes,
        uncompared_paths=tuple(differ.uncompared),
        semantic_limitations=tuple(
            code for code in deltaschema.SEMANTIC_LIMITATIONS if code in limitations
        ),
        uncompared_rename_candidates=_uncompared_candidates(differ, ends, base.doc, head.doc),
    )
