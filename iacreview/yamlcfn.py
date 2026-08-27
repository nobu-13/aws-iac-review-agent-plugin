"""CloudFormation-aware YAML loading.

A CloudFormation Template is YAML plus a fixed set of local tags (``!Ref``,
``!GetAtt``, ...). Plain :class:`yaml.SafeLoader` refuses every one of them, so
this module derives a loader that understands exactly those tags and nothing
else.

Three decisions here are security decisions rather than convenience ones
(design.md, "Template 内容を評価しない", Requirement 9 AC7):

allowlist, not ``add_multi_constructor``
    Each permitted tag gets its own :meth:`add_constructor` registration. A
    multi-constructor registered on the ``"!"`` prefix would accept *any* local
    tag, including ones a future PyYAML or a hostile template invents. With an
    explicit allowlist, an unknown tag reaches ``SafeConstructor``'s
    "undefined" handler and raises ``yaml.constructor.ConstructorError``.
    Callers translate that into
    :class:`~iacreview.errors.TemplateParseError`; this module does not, because
    line and column extraction belongs with the other parse error handling in
    :mod:`iacreview.template`.

``SafeLoader`` base
    ``yaml.Loader`` / ``yaml.UnsafeLoader`` and the ``yaml.load()`` default
    loader construct arbitrary Python objects from tags such as
    ``!!python/object/apply:os.system``. Deriving from ``SafeLoader`` means those
    tags raise instead. Registering the CloudFormation tags on the *subclass*
    keeps ``yaml.SafeLoader`` itself untouched, so an unrelated ``safe_load``
    elsewhere in the process gains no new capability.

long-form conversion
    ``!Ref X`` is kept as ``{"Ref": "X"}`` and ``!GetAtt A.Arn`` as
    ``{"Fn::GetAtt": ["A", "Arn"]}``. The shorthand carries no information the
    long form lacks, and normalizing at parse time means downstream IAM and
    resource analysis sees one shape regardless of how the author wrote the
    template. Conversion is a rewrite of representation only: no value is
    resolved, evaluated, or executed.

PyYAML is imported inside the functions, not at module scope. Requirement 16
AC3 permits exactly one YAML dependency and the plugin is distributed as a
directory rather than an installed package, so PyYAML may legitimately be
absent. A JSON Template needs no YAML parser at all, so the failure is deferred
to the moment YAML is actually parsed (design.md, "JSON 入力のみの場合の縮退動作").
"""

from __future__ import annotations

import re
from types import ModuleType
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Tuple, Type

from iacreview.errors import ToolUnavailableError, ToolVersionError

__all__ = [
    "PYYAML_MIN_VERSION",
    "PYYAML_INSTALL_COMMAND",
    "SHORT_TAGS",
    "BARE_TAGS",
    "long_form_key",
    "import_yaml",
    "cfn_safe_loader",
    "load_yaml",
]

#: Minimum PyYAML version (design.md, 外部ツールの最低バージョン).
PYYAML_MIN_VERSION = "6.0"

#: Install command quoted in every PyYAML-related error message.
PYYAML_INSTALL_COMMAND = "pip install 'PyYAML>=6.0'"

#: CloudFormation shorthand tag names, without the leading ``!``.
#:
#: Listed in the order design.md enumerates them so the allowlist can be read
#: against the design without reordering. This tuple *is* the allowlist: a tag
#: absent from it is rejected by the loader.
SHORT_TAGS: Tuple[str, ...] = (
    "Ref",
    "GetAtt",
    "Sub",
    "If",
    "Not",
    "Equals",
    "And",
    "Or",
    "Join",
    "Select",
    "Split",
    "FindInMap",
    "Base64",
    "Cidr",
    "ImportValue",
    "GetAZs",
    "Transform",
    "Condition",
)

#: The two tags whose long form is *not* prefixed with ``Fn::``.
#:
#: ``{"Ref": ...}`` and ``{"Condition": ...}`` are what CloudFormation itself
#: accepts; ``{"Fn::Ref": ...}`` is not a valid template. Getting this wrong
#: would silently produce a document that no downstream analysis recognizes,
#: which is why the exception is data rather than an ``if`` in the constructor.
BARE_TAGS: FrozenSet[str] = frozenset({"Ref", "Condition"})

#: Separator between logical ID and attribute in ``!GetAtt Resource.Attribute``.
GETATT_SEPARATOR = "."

#: First ``major.minor[.patch]`` sequence in a version string.
_VERSION_PATTERN = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")

#: Cached loader class. Built once, on first use, because the class cannot be
#: defined before PyYAML is known to be importable.
_LOADER: Optional[Type[Any]] = None


def long_form_key(tag_name: str) -> str:
    """Return the long-form mapping key for a shorthand tag name.

    Args:
        tag_name: Tag name without the leading ``!``, for example ``"GetAtt"``.

    Returns:
        ``"Ref"`` or ``"Condition"`` for the two bare tags, otherwise
        ``"Fn::<tag_name>"``.
    """
    if tag_name in BARE_TAGS:
        return tag_name
    return "Fn::{0}".format(tag_name)


# ---------------------------------------------------------------------------
# Lazy PyYAML import and version check
# ---------------------------------------------------------------------------


def _parse_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Extract a comparable version tuple from ``text``, or ``None``.

    ``None`` means "unparseable", which callers treat as "continue anyway"
    rather than as a failure: refusing to run because a version string had an
    unexpected shape would be a worse outcome than running against a version
    that is almost certainly new enough.
    """
    match = _VERSION_PATTERN.search(text or "")
    if match is None:
        return None
    major, minor, patch = match.groups()
    return (int(major), int(minor), int(patch or 0))


def _assert_supported_version(yaml: ModuleType) -> None:
    """Verify ``yaml.__version__`` meets :data:`PYYAML_MIN_VERSION`.

    ``pyproject.toml`` already pins ``PyYAML>=6.0``, but the plugin is usually
    run from a checked-out directory rather than pip-installed, so nothing
    enforces that pin at run time. The check exists for that path.

    Raises:
        ToolVersionError: PyYAML is older than :data:`PYYAML_MIN_VERSION`.
    """
    required = _parse_version(PYYAML_MIN_VERSION)
    detected_text = str(getattr(yaml, "__version__", ""))
    detected = _parse_version(detected_text)
    if required is None or detected is None or detected >= required:
        return
    raise ToolVersionError(
        "PyYAML {0} is older than the required minimum {1}".format(
            detected_text, PYYAML_MIN_VERSION
        ),
        tool="PyYAML",
        required_min_version=PYYAML_MIN_VERSION,
        detected_version=detected_text,
        remediation="Upgrade PyYAML: {0}".format(PYYAML_INSTALL_COMMAND),
    )


def import_yaml() -> ModuleType:
    """Import PyYAML, reporting its absence as a structured error.

    Returns:
        The imported :mod:`yaml` module.

    Raises:
        ToolUnavailableError: PyYAML is not importable.
        ToolVersionError: PyYAML is older than :data:`PYYAML_MIN_VERSION`.
    """
    try:
        import yaml
    except ImportError as exc:
        raise ToolUnavailableError(
            "PyYAML is required to parse YAML Templates but is not installed",
            tool="PyYAML",
            required_min_version=PYYAML_MIN_VERSION,
            remediation="Install PyYAML: {0}".format(PYYAML_INSTALL_COMMAND),
        ) from exc
    _assert_supported_version(yaml)
    return yaml


# ---------------------------------------------------------------------------
# Tag constructors
# ---------------------------------------------------------------------------


def _split_getatt(value: str) -> List[str]:
    """Convert a ``!GetAtt`` scalar into its long-form list.

    ``"Bucket.Arn"`` becomes ``["Bucket", "Arn"]``. The split takes the *first*
    separator only, because a nested-stack attribute is written
    ``!GetAtt Stack.Outputs.Name`` and CloudFormation's long form for it is
    ``["Stack", "Outputs.Name"]``.

    A value with no separator is invalid CloudFormation, but this module does
    not judge template semantics -- cfn-lint reports that. It is wrapped in a
    one-element list so that ``Fn::GetAtt`` is a list in every case and
    consumers never have to handle both shapes.
    """
    logical_id, separator, attribute = value.partition(GETATT_SEPARATOR)
    if not separator:
        return [value]
    return [logical_id, attribute]


def _make_constructor(
    yaml: ModuleType, tag_name: str
) -> Callable[[Any, Any], Dict[str, Any]]:
    """Build the constructor function for one shorthand tag.

    The three node kinds cover every way a tag can be written:
    ``!Base64 value`` (scalar), ``!If [c, a, b]`` (sequence), and
    ``!Transform {Name: ...}`` (mapping). All three are accepted for every tag
    rather than only for the forms CloudFormation permits per function, because
    validating which shape belongs to ``Fn::If`` is cfn-lint's job; rejecting it
    here would turn a lint finding into a parse failure and hide every other
    finding in the file.

    ``deep=True`` on the container forms matters: without it PyYAML yields
    partially built children, and a nested ``!Ref`` inside ``!Equals`` would be
    an empty dict at the time this constructor returns.
    """
    key = long_form_key(tag_name)
    is_getatt = tag_name == "GetAtt"

    def construct(loader: Any, node: Any) -> Dict[str, Any]:
        value: Any
        if isinstance(node, yaml.ScalarNode):
            value = loader.construct_scalar(node)
            if is_getatt:
                value = _split_getatt(value)
        elif isinstance(node, yaml.SequenceNode):
            value = loader.construct_sequence(node, deep=True)
        elif isinstance(node, yaml.MappingNode):
            value = loader.construct_mapping(node, deep=True)
        else:
            # Unreachable with the node kinds PyYAML produces today. Raised as a
            # YAML error so that an added node kind surfaces as a parse failure
            # rather than as an AttributeError further downstream.
            raise yaml.constructor.ConstructorError(
                None,
                None,
                "unsupported node kind for tag !{0}".format(tag_name),
                node.start_mark,
            )
        return {key: value}

    construct.__name__ = "construct_{0}".format(tag_name.lower())
    construct.__doc__ = "Construct ``!{0}`` as ``{{{1!r}: ...}}``.".format(
        tag_name, key
    )
    return construct


def _build_loader(yaml: ModuleType) -> Type[Any]:
    """Define the ``SafeLoader`` subclass carrying the tag allowlist.

    ``add_constructor`` copies the inherited registry into the subclass on first
    use, so ``yaml.SafeLoader.yaml_constructors`` is left unmodified and code
    elsewhere in the process still sees ``!Ref`` as an unknown tag.
    """

    class CfnSafeLoader(yaml.SafeLoader):  # type: ignore[misc]
        """``SafeLoader`` that accepts the CloudFormation shorthand tags.

        Only the tags in :data:`SHORT_TAGS` are registered. Every other tag,
        including ``!!python/object/apply:os.system`` and any unknown local tag
        such as ``!Bogus``, raises ``yaml.constructor.ConstructorError``.
        """

    for tag_name in SHORT_TAGS:
        CfnSafeLoader.add_constructor(
            "!{0}".format(tag_name), _make_constructor(yaml, tag_name)
        )
    return CfnSafeLoader


def cfn_safe_loader() -> Type[Any]:
    """Return the CloudFormation-aware ``SafeLoader`` subclass.

    The class is built on first call and cached, so all callers share one
    registry and repeated parses do not rebuild it.

    Raises:
        ToolUnavailableError: PyYAML is not importable.
        ToolVersionError: PyYAML is older than :data:`PYYAML_MIN_VERSION`.
    """
    global _LOADER
    if _LOADER is None:
        _LOADER = _build_loader(import_yaml())
    return _LOADER


def load_yaml(text: str) -> Any:
    """Parse ``text`` as a CloudFormation YAML document.

    Args:
        text: YAML source. Untrusted content; nothing in it is executed.

    Returns:
        The parsed document, with shorthand tags converted to their long form.
        An empty document yields ``None``, which the caller rejects as not
        reviewable.

    Raises:
        ToolUnavailableError: PyYAML is not importable.
        ToolVersionError: PyYAML is older than :data:`PYYAML_MIN_VERSION`.
        yaml.YAMLError: ``text`` is not well-formed YAML, or it uses a tag
            outside :data:`SHORT_TAGS`. Callers convert this into
            :class:`~iacreview.errors.TemplateParseError`, which is where line
            and column are attached.
    """
    yaml = import_yaml()
    # An explicit SafeLoader-derived Loader, never yaml.load()'s default.
    return yaml.load(text, Loader=cfn_safe_loader())
