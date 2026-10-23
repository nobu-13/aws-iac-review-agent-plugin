"""Input side of the v1.1 Delta_Tool: read, parse, and structurally check inputs.

This is the only Delta module that reads files. It turns a Template path into a
:class:`ParsedTemplate` and a Review_Report path into a :class:`LoadedReport`,
or into a :class:`Failure` that names what went wrong with a failure Code from
:mod:`iacreview.deltaschema`.

Reading reuses the v1.0 readers unchanged
    ``template._read_text`` (Template) and ``template._read_bytes_toctou_safe``
    (Report) open the file once, check on that one descriptor that it is a
    contained regular file, and refuse it before reading when it is larger than
    ``template.MAX_TEMPLATE_BYTES``. They are private to :mod:`iacreview.template`;
    their behaviour is pinned by a contract test so that a change there fails a
    test instead of silently changing this module (Design 1-4).

Templates are parsed once, with duplicate keys found on the node graph
    The existing loaders keep the last value of a duplicate mapping key. To find
    duplicates without parsing twice, YAML goes through a subclass of the
    existing CloudFormation loader: the node graph is composed, scanned for
    mappings that repeat a string key, and then constructed. The subclass
    overrides ``construct_object`` only, so the object recorded for a duplicate
    mapping is the very object that ends up in the document (a tagged mapping
    records the whole tagged value). JSON uses ``object_pairs_hook``. Marked
    objects are held by strong reference in :class:`MarkedObjects`, so the
    ``id`` used to recognise them cannot be reused by another object while the
    document is alive. A duplicate top-level key is recorded by name instead of
    marking the whole document, so that only that section is left uncompared.
    When this single pass fails, the existing ``template.parse_template_text``
    is run to obtain the canonical failure; if it succeeds instead, the two
    parsers disagree and the result is ``parser_divergence``.

Structure is checked before anything walks the document as a tree
    YAML aliases build shared objects, so a 580-byte document can stand for a
    tree of over a billion nodes, and an alias can make a document refer to
    itself. :func:`check_structure` walks the document as a graph, expanding
    each container once and computing the tree's size and depth with saturating
    memoised sums, without recursion. It reports a cycle, then a visited-container
    count above the node limit (early stop), then depth, then the logical node
    count (Design 2-5).

No exception text is kept
    A :class:`Failure` holds the failure Code, the side, the input kind and at
    most an integer line and column. Parser messages can quote input content and
    are never stored or returned (Requirement 12 AC10).
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple, Type, Union

from iacreview import deltaschema, pathguard, template, yamlcfn
from iacreview.errors import (
    IacReviewError,
    InputNotFoundError,
    InputTooLargeError,
    InvalidArgumentsError,
    NotReviewableError,
    PathContainmentError,
    TemplateParseError,
    UnsafeArgumentError,
)

__all__ = [
    "Failure",
    "MarkedObjects",
    "ParsedDocument",
    "Shape",
    "ParsedTemplate",
    "LoadedReport",
    "read_template",
    "parse_template",
    "parse_document",
    "check_structure",
    "read_report",
    "parse_report_bytes",
    "load_guard_rule_names",
]

#: Input kinds used in :attr:`Failure.input`.
TEMPLATE_INPUT = "template"
REPORT_INPUT = "report"

#: PyYAML resolver tags of string keys and of the merge key ``<<``.
_STR_TAG = "tag:yaml.org,2002:str"
_MERGE_TAG = "tag:yaml.org,2002:merge"

#: Byte-order mark, stripped by the v1.0 empty-input check as well.
_BOM = "\ufeff"

#: Colours of the structure walk.
_WHITE, _GREY, _BLACK = 0, 1, 2


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Failure:
    """Why one input could not be used. Holds no text taken from the input.

    Attributes:
        code: A failure Code of :data:`iacreview.deltaschema.FAILURE_CODES`.
        side: ``"base"``, ``"head"``, or ``None`` when no side applies.
        input: ``"template"``, ``"report"`` or ``"output"``.
        line: 1-based line of a parse failure, when the parser gave one.
        column: 1-based column of a parse failure, when the parser gave one.
    """

    code: str
    side: Optional[str]
    input: str
    line: Optional[int] = None
    column: Optional[int] = None

    def __post_init__(self) -> None:
        if self.code not in deltaschema.FAILURE_CODE_TABLE:
            raise ValueError("unknown failure code: {0!r}".format(self.code))
        if self.side is not None and self.side not in deltaschema.SIDES:
            raise ValueError("unknown side: {0!r}".format(self.side))
        if self.input not in deltaschema.FAILURE_INPUTS:
            raise ValueError("unknown input kind: {0!r}".format(self.input))
        for name in ("line", "column"):
            value = getattr(self, name)
            if value is not None and _positive_int(value) is None:
                raise ValueError("{0} must be a positive int or None".format(name))

    @property
    def error_class(self) -> str:
        """The v1.0 ``error_class`` this Code maps onto."""
        return deltaschema.FAILURE_CODE_TABLE[self.code][0]

    @property
    def exit_code(self) -> int:
        """The v1.0 exit code this Code maps onto."""
        return deltaschema.FAILURE_CODE_TABLE[self.code][1]


class MarkedObjects:
    """Objects of a parsed document that came from a mapping with a duplicate key.

    Each object is held by strong reference. While it is held, CPython gives no
    other live object the same ``id``, so :meth:`contains` cannot mistake an
    unrelated object (for example a temporary dict built and dropped during
    construction) for a marked one. Keep this instance for as long as the
    document it describes.
    """

    __slots__ = ("_kept", "_ids")

    def __init__(self) -> None:
        self._kept: List[Any] = []
        self._ids: Set[int] = set()

    def keep(self, obj: Any) -> None:
        """Mark ``obj``. Marking the same object twice has no further effect."""
        if id(obj) not in self._ids:
            self._kept.append(obj)
            self._ids.add(id(obj))

    def discard(self, obj: Any) -> None:
        """Remove the mark from ``obj`` if it has one."""
        if id(obj) in self._ids:
            self._ids.discard(id(obj))
            self._kept = [kept for kept in self._kept if kept is not obj]

    def contains(self, obj: Any) -> bool:
        """Whether ``obj`` (an object of the document) is marked."""
        return id(obj) in self._ids

    def __len__(self) -> int:
        return len(self._kept)


@dataclass(frozen=True)
class ParsedDocument:
    """A parsed document before the reviewability and structure checks.

    Attributes:
        doc: The document, equal to what ``template.parse_template_text`` returns.
        fmt: ``"yaml"`` or ``"json"``.
        marked: Objects that came from a non-root mapping with a duplicate key.
        duplicate_sections: Top-level keys that occur more than once, sorted.
    """

    doc: Any
    fmt: str
    marked: MarkedObjects
    duplicate_sections: Tuple[str, ...]


@dataclass(frozen=True)
class Shape:
    """Size of a document seen as a tree, measured without expanding it.

    Attributes:
        nodes: Logical node count (every container and scalar, with alias
            shares counted once per position). Saturates at the node limit + 1.
        depth: Depth with the root at 1. Saturates at the depth limit + 1.
        containers: Distinct container objects visited.
    """

    nodes: int
    depth: int
    containers: int


@dataclass(frozen=True)
class ParsedTemplate:
    """A reviewable Template that passed the structure check.

    Only a document of this type may be walked as a tree: it has no cycle and
    its logical node count and depth are within the limits.
    """

    doc: Any
    fmt: str
    marked: MarkedObjects
    duplicate_sections: Tuple[str, ...]
    shape: Shape


@dataclass(frozen=True)
class LoadedReport:
    """A Review_Report parsed as JSON, not yet schema-checked.

    Attributes:
        obj: The parsed JSON value.
        sha256: Hex SHA-256 of the exact bytes read.
        size: Number of bytes read.
    """

    obj: Any
    sha256: str
    size: int


# ---------------------------------------------------------------------------
# Error conversion
# ---------------------------------------------------------------------------


def _positive_int(value: object) -> Optional[int]:
    """``value`` if it is a positive ``int`` (not ``bool``), else ``None``."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


def _position(exc: BaseException) -> Tuple[Optional[int], Optional[int]]:
    """The integer line and column a v1.0 parse error carries, if any."""
    return (_positive_int(getattr(exc, "line", None)), _positive_int(getattr(exc, "column", None)))


def _failure_from_error(exc: IacReviewError, side: Optional[str], kind: str) -> Failure:
    """Map a v1.0 exception onto a failure Code. Only the type is inspected."""
    if isinstance(exc, (InvalidArgumentsError, UnsafeArgumentError)):
        return Failure("invalid_arguments", side, kind)
    if isinstance(exc, InputTooLargeError):
        return Failure("template_too_large" if kind == TEMPLATE_INPUT else "report_too_large", side, kind)
    if isinstance(exc, InputNotFoundError):
        return Failure("input_not_found", side, kind)
    if isinstance(exc, PathContainmentError):
        return Failure("path_violation", side, kind)
    if kind == TEMPLATE_INPUT and isinstance(exc, NotReviewableError):
        return Failure("template_not_reviewable", side, kind)
    if isinstance(exc, TemplateParseError):
        line, column = _position(exc)
        code = "template_parse_failure" if kind == TEMPLATE_INPUT else "report_parse_failure"
        return Failure(code, side, kind, line, column)
    return Failure("unexpected", side, kind)


# ---------------------------------------------------------------------------
# Template: reading and single-pass parsing
# ---------------------------------------------------------------------------


def read_template(arg: str, root: Path, side: str) -> Union[ParsedTemplate, Failure]:
    """Resolve, read, parse and structurally check one Template.

    Args:
        arg: The path argument as given by the user. Untrusted.
        root: Workspace root the path must stay inside.
        side: ``"base"`` or ``"head"``.

    Returns:
        A :class:`ParsedTemplate`, or a :class:`Failure` for a path outside the
        root, a missing, non-regular or oversized file, invalid UTF-8, a parse
        failure, a non-reviewable document, or a structure check failure.
    """
    try:
        path = pathguard.resolve_within(arg, root)
    except IacReviewError as exc:
        return _failure_from_error(exc, side, TEMPLATE_INPUT)
    try:
        text = template._read_text(path)
    except TemplateParseError as exc:
        # The reader raises this only for bytes that are not UTF-8.
        line, column = _position(exc)
        return Failure("template_encoding_failure", side, TEMPLATE_INPUT, line, column)
    except IacReviewError as exc:
        return _failure_from_error(exc, side, TEMPLATE_INPUT)
    return parse_template(text, path, side)


def parse_template(text: str, path: Path, side: str) -> Union[ParsedTemplate, Failure]:
    """Parse ``text`` and accept it only if reviewable and structurally bounded.

    Args:
        text: Decoded Template text. Untrusted.
        path: Where the text came from; passed to the v1.0 parser for its own
            messages, which this module does not keep.
        side: ``"base"`` or ``"head"``.
    """
    parsed = parse_document(text, path, side)
    if isinstance(parsed, Failure):
        return parsed
    if not template.is_reviewable(parsed.doc):
        return Failure("template_not_reviewable", side, TEMPLATE_INPUT)
    shape = check_structure(parsed.doc, side)
    if isinstance(shape, Failure):
        return shape
    return ParsedTemplate(
        doc=parsed.doc,
        fmt=parsed.fmt,
        marked=parsed.marked,
        duplicate_sections=parsed.duplicate_sections,
        shape=shape,
    )


def parse_document(text: str, path: Path, side: Optional[str]) -> Union[ParsedDocument, Failure]:
    """Parse ``text`` in one pass, marking mappings that repeat a string key.

    The document equals what ``template.parse_template_text`` returns for the
    same text, and this function fails exactly when that one fails. It does not
    check reviewability or structure, and the document it returns may contain a
    cycle: do not compare or walk it before :func:`check_structure`.
    """
    if not text.strip().strip(_BOM):
        return _canonical_failure(text, path, side)
    fmt = template.detect_format(text)
    try:
        if fmt == "json":
            doc, marked, sections = _parse_json(text)
        else:
            doc, marked, sections = _parse_yaml(text)
    except Exception:  # noqa: BLE001 - untrusted input; the canonical parser explains it
        return _canonical_failure(text, path, side)
    return ParsedDocument(doc=doc, fmt=fmt, marked=marked, duplicate_sections=sections)


def _canonical_failure(text: str, path: Path, side: Optional[str]) -> Failure:
    """Ask the v1.0 parser why ``text`` fails; only its error type is used."""
    try:
        template.parse_template_text(text, path)
    except IacReviewError as exc:
        return _failure_from_error(exc, side, TEMPLATE_INPUT)
    return Failure("parser_divergence", side, TEMPLATE_INPUT)


def _parse_json(text: str) -> Tuple[Any, MarkedObjects, Tuple[str, ...]]:
    marked = MarkedObjects()
    duplicates: Dict[int, Tuple[str, ...]] = {}

    def hook(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        obj = dict(pairs)
        if len(obj) != len(pairs):
            seen: Set[str] = set()
            repeated: Set[str] = set()
            for key, _ in pairs:
                if key in seen:
                    repeated.add(key)
                seen.add(key)
            marked.keep(obj)
            duplicates[id(obj)] = tuple(sorted(repeated))
        return obj

    doc = json.loads(text, object_pairs_hook=hook)
    sections: Tuple[str, ...] = ()
    if isinstance(doc, dict) and marked.contains(doc):
        sections = duplicates[id(doc)]
        marked.discard(doc)
    return doc, marked, sections


def _parse_yaml(text: str) -> Tuple[Any, MarkedObjects, Tuple[str, ...]]:
    yaml = yamlcfn.import_yaml()
    loader = _dup_aware_loader_class()(text)
    try:
        node = loader.get_single_node()
        sections: Tuple[str, ...] = ()
        doc: Any = None
        if node is not None:
            duplicate_nodes, sections = _scan_duplicate_mappings(node, yaml)
            loader.watch(duplicate_nodes)
            doc = loader.construct_document(node)
        marked = loader.marked
    finally:
        loader.dispose()
    return doc, marked, sections


#: ``(base loader class, subclass)``. Rebuilt if the base loader is rebuilt.
_DUP_AWARE: Optional[Tuple[Type[Any], Type[Any]]] = None


def _dup_aware_loader_class() -> Type[Any]:
    global _DUP_AWARE
    base = yamlcfn.cfn_safe_loader()
    if _DUP_AWARE is None or _DUP_AWARE[0] is not base:
        _DUP_AWARE = (base, _build_dup_aware_loader(base))
    return _DUP_AWARE[1]


def _build_dup_aware_loader(base: Type[Any]) -> Type[Any]:
    """Subclass the existing loader. The base class and its registry are untouched."""

    class DupAwareLoader(base):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self.marked = MarkedObjects()
            self._watched: List[Any] = []
            self._watched_ids: Set[int] = set()

        def watch(self, nodes: List[Any]) -> None:
            # The node list keeps the nodes alive, so their ids stay unique.
            self._watched = list(nodes)
            self._watched_ids = {id(node) for node in self._watched}

        def construct_object(self, node: Any, deep: bool = False) -> Any:
            obj = super().construct_object(node, deep=deep)
            if id(node) in self._watched_ids:
                self.marked.keep(obj)
            return obj

    return DupAwareLoader


def _merge_sources(value_node: Any, yaml: Any) -> List[Any]:
    if isinstance(value_node, yaml.MappingNode):
        return [value_node]
    if isinstance(value_node, yaml.SequenceNode):
        return [item for item in value_node.value if isinstance(item, yaml.MappingNode)]
    return []


def _str_keys(node: Any, yaml: Any) -> List[str]:
    """The string keys a mapping node writes directly (merge sources excluded)."""
    return [
        key.value
        for key, _ in node.value
        if isinstance(key, yaml.ScalarNode) and key.tag == _STR_TAG
    ]


def _propagate_merge_marks(
    seeds: List[Any], dependents: Dict[int, List[Any]], root: Any
) -> Tuple[List[Any], int]:
    """Mark every mapping that merges, directly or through a chain, from a seed.

    A worklist visits each node at most once and each merge edge at most once,
    so the cost is linear in the number of nodes and merge edges whatever the
    order of the chain. The root is never marked as a whole, but marks still
    flow through it to the mappings that merge from it.

    Args:
        seeds: Nodes whose values are ambiguous (duplicate mappings, and the
            root when it repeats a key).
        dependents: For a node id, the mapping nodes that merge from that node.
        root: The document's root node.

    Returns:
        The newly marked non-root nodes, and the number of merge edges examined.
    """
    reached: Set[int] = {id(seed) for seed in seeds}
    worklist: List[Any] = list(seeds)
    newly: List[Any] = []
    edges = 0
    while worklist:
        source = worklist.pop()
        for dependent in dependents.get(id(source), ()):
            edges += 1
            if id(dependent) in reached:
                continue
            reached.add(id(dependent))
            worklist.append(dependent)
            if dependent is not root:
                newly.append(dependent)
    return newly, edges


def _inherited_root_keys(
    sources: List[Any], marked_ids: Set[int], merge_sources: Dict[int, List[Any]], root: Any, yaml: Any
) -> Set[str]:
    """String keys the root takes in through merge from an ambiguous source.

    Follows the merge chain of every marked source with an explicit stack, so a
    duplicate reached through ``<<: *b`` where ``b`` has ``<<: *a`` is recorded
    as well. The root's own repeated keys are recorded by the caller.
    """
    keys: Set[str] = set()
    seen: Set[int] = {id(root)}
    stack: List[Any] = [source for source in sources if id(source) in marked_ids]
    while stack:
        node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        keys.update(_str_keys(node, yaml))
        stack.extend(merge_sources.get(id(node), ()))
    return keys


def _scan_duplicate_mappings(root: Any, yaml: Any) -> Tuple[List[Any], Tuple[str, ...]]:
    """Find mapping nodes that repeat a string key, without recursion.

    Only keys whose resolved tag is ``str`` are compared; the merge key ``<<``
    is a YAML override, not a duplicate, and other keys (int, bool, null) are
    left to the comparison's non-string-key rule. A mapping that merges from a
    duplicate mapping, directly or through a chain of merges, inherits its
    ambiguous values, so it is marked as well.

    Returns:
        The non-root duplicate mapping nodes, and the sorted top-level keys that
        repeat or that the root inherits through merge from an ambiguous source
        (a root mapping is never marked as a whole).
    """
    seen: Set[int] = set()
    stack: List[Any] = [root]
    marked: List[Any] = []
    marked_ids: Set[int] = set()
    merges: List[Tuple[Any, List[Any]]] = []
    root_keys: Set[str] = set()
    while stack:
        node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, yaml.MappingNode):
            keys: Set[str] = set()
            repeated: Set[str] = set()
            sources: List[Any] = []
            for key_node, value_node in node.value:
                if isinstance(key_node, yaml.ScalarNode):
                    if key_node.tag == _STR_TAG:
                        if key_node.value in keys:
                            repeated.add(key_node.value)
                        keys.add(key_node.value)
                    elif key_node.tag == _MERGE_TAG:
                        sources.extend(_merge_sources(value_node, yaml))
                stack.append(key_node)
                stack.append(value_node)
            if repeated:
                if node is root:
                    root_keys.update(repeated)
                else:
                    marked.append(node)
                    marked_ids.add(id(node))
            if sources:
                merges.append((node, sources))
        elif isinstance(node, yaml.SequenceNode):
            stack.extend(node.value)

    dependents: Dict[int, List[Any]] = {}
    merge_sources: Dict[int, List[Any]] = {}
    for node, sources in merges:
        merge_sources[id(node)] = sources
        for source in sources:
            dependents.setdefault(id(source), []).append(node)
    seeds = list(marked) + ([root] if root_keys else [])
    newly, _ = _propagate_merge_marks(seeds, dependents, root)
    marked.extend(newly)
    marked_ids.update(id(node) for node in newly)
    root_sources = merge_sources.get(id(root), [])
    root_keys.update(_inherited_root_keys(root_sources, marked_ids, merge_sources, root, yaml))
    return marked, tuple(sorted(root_keys))


# ---------------------------------------------------------------------------
# Template: structure check (cycles, logical node count, depth)
# ---------------------------------------------------------------------------


def _is_container(value: Any) -> bool:
    # ``!!pairs`` and ``!!omap`` build lists of ``(key, value)`` tuples; a
    # tuple's value can hold an alias, so it is walked like a list.
    return isinstance(value, (dict, list, tuple))


def _children(value: Any) -> List[Any]:
    if isinstance(value, dict):
        return list(value.values())
    return list(value)


def _walk_structure(root: Any) -> Tuple[Optional[str], int, int, int]:
    """Walk ``root`` as a graph. Returns ``(failure_code, visited, nodes, depth)``.

    Every container is entered and left once (three colours, explicit stack).
    Size and depth are memoised per container and saturate at the limit + 1, so
    shared subtrees are summed, not walked. ``visited`` is the number of
    containers entered; on an early stop it is the node limit + 1.
    """
    if not _is_container(root):
        return None, 0, 1, 1
    node_cap = deltaschema.MAX_TEMPLATE_NODES
    depth_cap = deltaschema.MAX_TEMPLATE_DEPTH
    colour: Dict[int, int] = {}
    size: Dict[int, int] = {}
    depth: Dict[int, int] = {}
    visited = 0
    stack: List[Tuple[Any, bool]] = [(root, False)]
    while stack:
        current, leaving = stack.pop()
        key = id(current)
        if not leaving:
            state = colour.get(key, _WHITE)
            if state == _BLACK:
                continue
            if state == _GREY:
                return "template_alias_cycle", visited, 0, 0
            colour[key] = _GREY
            visited += 1
            if visited > node_cap:
                return "template_node_limit_exceeded", visited, 0, 0
            stack.append((current, True))
            for child in reversed(_children(current)):
                if _is_container(child):
                    child_state = colour.get(id(child), _WHITE)
                    if child_state == _GREY:
                        return "template_alias_cycle", visited, 0, 0
                    if child_state == _WHITE:
                        stack.append((child, False))
            continue
        total, deepest = 1, 1
        for child in _children(current):
            if _is_container(child):
                child_size, child_depth = size[id(child)], depth[id(child)]
            else:
                child_size, child_depth = 1, 1
            total = min(total + child_size, node_cap + 1)
            deepest = min(max(deepest, 1 + child_depth), depth_cap + 1)
        size[key], depth[key], colour[key] = total, deepest, _BLACK
    root_depth, root_size = depth[id(root)], size[id(root)]
    if root_depth > depth_cap:
        return "template_depth_limit_exceeded", visited, root_size, root_depth
    if root_size > node_cap:
        return "template_node_limit_exceeded", visited, root_size, root_depth
    return None, visited, root_size, root_depth


def check_structure(root: Any, side: Optional[str] = None) -> Union[Shape, Failure]:
    """Reject a cycle, too many logical nodes, or too much depth (Design 2-5).

    The order is fixed: a cycle found during the walk, then a visited-container
    count above ``MAX_TEMPLATE_NODES`` (the walk stops there), then depth, then
    the logical node count. Limits are read from :mod:`iacreview.deltaschema`
    at call time.
    """
    code, visited, nodes, depth = _walk_structure(root)
    if code is not None:
        return Failure(code, side, TEMPLATE_INPUT)
    return Shape(nodes=nodes, depth=depth, containers=visited)


# ---------------------------------------------------------------------------
# Review_Report
# ---------------------------------------------------------------------------


class _DuplicateKey(Exception):
    """A JSON object repeats a key. Carries no input text."""


class _NonFinite(Exception):
    """A JSON number is NaN or infinite. Carries no input text."""


def _reject_duplicate_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise _DuplicateKey()
    return obj


def _reject_constant(_: str) -> float:
    raise _NonFinite()


def _parse_finite_float(literal: str) -> float:
    value = float(literal)
    if not math.isfinite(value):
        raise _NonFinite()
    return value


def read_report(arg: str, root: Path, side: str) -> Union[LoadedReport, Failure]:
    """Resolve and read one Review_Report and parse it as strict JSON.

    The read reuses the v1.0 TOCTOU-safe reader (regular files only, refused
    before reading above ``template.MAX_TEMPLATE_BYTES``). Schema checks are
    not done here.
    """
    try:
        path = pathguard.resolve_within(arg, root)
    except IacReviewError as exc:
        return _failure_from_error(exc, side, REPORT_INPUT)
    try:
        raw = template._read_bytes_toctou_safe(path)
    except IacReviewError as exc:
        return _failure_from_error(exc, side, REPORT_INPUT)
    return parse_report_bytes(raw, side)


def parse_report_bytes(raw: bytes, side: Optional[str]) -> Union[LoadedReport, Failure]:
    """Decode ``raw`` as UTF-8 and parse it as JSON with no duplicate key and no
    non-finite number. The digest is taken over ``raw`` exactly as given."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return Failure("report_parse_failure", side, REPORT_INPUT)
    try:
        obj = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
            parse_float=_parse_finite_float,
        )
    except _DuplicateKey:
        return Failure("report_duplicate_json_key", side, REPORT_INPUT)
    except _NonFinite:
        return Failure("report_parse_failure", side, REPORT_INPUT)
    except json.JSONDecodeError as exc:
        return Failure(
            "report_parse_failure",
            side,
            REPORT_INPUT,
            _positive_int(exc.lineno),
            _positive_int(exc.colno),
        )
    except (ValueError, RecursionError):
        return Failure("report_parse_failure", side, REPORT_INPUT)
    return LoadedReport(obj=obj, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))


# ---------------------------------------------------------------------------
# Plugin data
# ---------------------------------------------------------------------------


def load_guard_rule_names() -> FrozenSet[str]:
    """Names of the Guard rules bundled with the Plugin (Design 10-1).

    These are the cfn-guard RuleIds the Delta_Report writes in plain form. The
    names come from the public ``cfnguard.load_rule_metadata`` over the bundled
    ``rules/`` tree, which is Plugin data, not user input. The module is
    imported here rather than at the top so that runs without a Report_Pair do
    not load it.

    Raises:
        MappingFileError: The bundled rule tree is unusable (a broken
            installation).
    """
    from iacreview import cfnguard

    return frozenset(cfnguard.load_rule_metadata(None).rule_names())
