"""The Agent Review input boundary: validate and normalize agent-produced JSON.

Agent Review is the one Source that is not deterministic code (requirements.md
Assumption 6). design.md therefore hands its output across a file rather than a
function call: the host agent writes Findings as JSON, and
``run_iac_review.py --agent-findings <path>`` feeds that file through
:func:`load_agent_findings`, which is the only place agent output enters the
pipeline (design.md, Agent 出力の受け渡し方式).

Everything the agent writes is untrusted structured input, exactly like an
external tool's stdout. This module is the strict boundary design.md asks for,
and it enforces the third prohibition of The Deterministic / Agent Boundary:
**an agent cannot claim ``Confidence: Confirmed``**. A ``Confirmed`` entry is
not rejected but *demoted* to ``Likely`` with a warning on stderr (Requirement 7
AC10), because the observation is probably still worth reporting -- only its
certainty was overstated.

Two more corrections are applied for the same reason, that a recoverable
mistake should not cost the whole Finding:

``Normalized_Category`` outside the closed set becomes ``Other``
    Requirement 14 AC3. ``Other`` also removes the Finding from dedup matching,
    which :func:`iacreview.finding.is_dedup_eligible` already encodes.

a nullable field that was left out reads as ``null``
    ``Resource`` and ``SuggestedRemediation`` have exactly one meaning when
    absent, so requiring the agent to spell out ``null`` would only add a way
    to fail. ``ID`` is accepted and discarded: IDs are assigned over the sorted,
    deduplicated report (Requirement 7 AC1, AC15), so no value the agent could
    write here is usable.

Everything else is a schema violation, and a violation costs that Finding
alone: it is dropped and a StructuredError is recorded, while the remaining
Findings load normally (design.md, Error Handling / Failure mode マトリクス).
Only a problem with the *file* -- unreadable, not JSON, not the expected
envelope -- raises, because then there is no list of Findings to be partially
correct about. That raise is :class:`~iacreview.errors.SchemaViolationError`,
which design.md names for this failure mode in the ``iacreview.agentin``
component table; its ``exit_code`` is 4, the value the Error Handling matrix
assigns to a wholly invalid agent file. The matrix additionally labels the
``errors[]`` entry ``parse_failure`` while this exception reports
``schema_violation``. The component table wins: the file *is* JSON-shaped input
being checked against a schema, and a caller that needs to distinguish the two
whole-file causes reads the message, which keeps the decoder's position report.

**Why ``Source`` is checked rather than overwritten.** An entry in this file
claiming ``Source: ["cfn-lint"]`` is not a formatting slip: honouring it would
let agent reasoning enter the report attributed to a deterministic tool, and
merge into deterministic Findings as if two Sources had confirmed one issue.
Silently rewriting it would accept the same file while hiding the claim. So a
``Source`` other than ``["Agent Review"]`` is a violation, and the same rule
applies to each ``Evidence[].Source`` -- those values drive the Evidence
concatenation order when Findings merge (Requirement 14 AC11).

**Why every Evidence entry needs an ``Excerpt``.** The schema requires one
Excerpt somewhere on a non-Confirmed Finding (Requirement 7 AC11). This module
requires one per entry, which is what design.md's Layer 2 constraint 3 states
for agent output: each Evidence entry is one justification, and a justification
with nothing quoted from the Template is an assertion, not evidence.

Validation itself is not reimplemented here. :func:`iacreview.finding.from_dict`
owns the 13 fields, the closed value sets, ``additionalProperties: false``, and
the four structural constraints; this module normalizes an entry into the shape
that function accepts and reports what it says. The corrections above are
applied *before* that call, so a demoted Confidence and a fallen-back Category
are validated as the values that will reach the report.

Each correction is one function of ``(index, payload)`` called from
:func:`_finding_from_entry`, and every accepted Finding leaves through that same
function. Credential redaction of ``Excerpt`` (design.md, Open Design Decisions
O-11) attaches there, on the way out: :func:`iacreview.finding.redact_finding`
is applied to each accepted Finding, so no accepted agent Finding can carry an
Excerpt out of this module unredacted.

Redaction matters more here than anywhere else, because this is the only Source
that quotes Template text at all -- the deterministic three set ``Excerpt`` to
``None``, their ``RuleId`` being their evidence. The rule itself is not agent
input policy, though, so it lives with the field in
:mod:`iacreview.finding` and all four Sources apply it. Condition (a) of O-11
needs the reviewed Template's ``NoEcho`` Parameter names, which this module
never sees: it reads the agent's findings file, not the Template. The caller
therefore passes them, through the ``noecho_parameters`` argument of
:func:`load_agent_findings`, computed with
:func:`iacreview.finding.noecho_parameter_names`. Omitting them leaves condition
(a) unevaluated rather than silently satisfied.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Tuple

from iacreview import categories
from iacreview.errors import (
    InputNotFoundError,
    SchemaViolationError,
    os_error_detail,
)
from iacreview.finding import (
    AGENT_MAX_CONFIDENCE,
    AGENT_SOURCE,
    CONFIDENCES,
    CONFIRMED,
    OTHER_CATEGORY,
    UNASSIGNED_ID,
    Finding,
    from_dict,
    redact_finding,
    schema_violation,
)
from iacreview.source import StructuredError, display_path

__all__ = [
    "SOURCE_NAME",
    "FINDINGS_KEY",
    "SCHEMA_VERSION_KEY",
    "ENVELOPE_KEYS",
    "SUPPORTED_SCHEMA_MAJOR",
    "AGENT_CONFIDENCES",
    "DEMOTED_CONFIDENCE",
    "AGENT_SOURCE_LIST",
    "NULLABLE_FIELDS",
    "DEMOTION_WARNING",
    "findings_from_payload",
    "load_agent_findings",
]

#: Source name recorded on every Finding and StructuredError this module
#: produces. Agent output is attributed to one Source and only one.
SOURCE_NAME = AGENT_SOURCE

#: The ``Source`` list every accepted Finding carries.
AGENT_SOURCE_LIST: Tuple[str, ...] = (AGENT_SOURCE,)

#: Envelope key holding the array of Findings.
FINDINGS_KEY = "findings"

#: Optional envelope key declaring which schema the file was written against.
SCHEMA_VERSION_KEY = "schema_version"

#: The only keys an envelope object may carry. Unknown keys are rejected rather
#: than ignored: an agent that added one believes it supplied information, and
#: the report would silently not carry it.
ENVELOPE_KEYS: Tuple[str, ...] = (FINDINGS_KEY, SCHEMA_VERSION_KEY)

#: ``schema_version`` MAJOR this module understands, matching the Finding schema
#: version in design.md. A file declaring another MAJOR is refused whole: its
#: field meanings are by definition not the ones validated here.
SUPPORTED_SCHEMA_MAJOR = 1

#: Confidence values agent reasoning may claim (Requirement 7 AC10).
AGENT_CONFIDENCES: Tuple[str, ...] = tuple(c for c in CONFIDENCES if c != CONFIRMED)

#: What ``Confirmed`` is demoted to. The *highest* Confidence still open to an
#: agent, so the demotion weakens the claim as little as the rule allows. The
#: same ceiling ``dedup`` applies to a merged group, hence the shared constant.
DEMOTED_CONFIDENCE = AGENT_MAX_CONFIDENCE

#: Fields whose absence means ``null`` rather than a missing required field.
NULLABLE_FIELDS: Tuple[str, ...] = ("Resource", "SuggestedRemediation")

#: Stand-in ``ID`` used only to satisfy ``ID >= 1`` during validation. The
#: returned Finding carries :data:`~iacreview.finding.UNASSIGNED_ID` like every
#: Source's output; see :func:`_finding_from_entry`.
_VALIDATION_ID = 1

#: stderr text for a demoted ``Confirmed`` (Requirement 7 AC10). Names the entry
#: by index because an agent Finding has no ID and no rule ID to name it by.
DEMOTION_WARNING = (
    "agent finding {location}: Confidence {confirmed!r} is not available to "
    "Agent Review; recorded as {demoted!r}"
)


def _warn(message: str) -> None:
    """Emit a warning on stderr.

    stdout carries the report and must stay byte-identical between runs
    (Requirement 16 AC11), so diagnostics never go there.
    """
    print("warning: {0}".format(message), file=sys.stderr)


def _type_name(value: object) -> str:
    return type(value).__name__


def _entry_field(index: int, field: str = "") -> str:
    """Dotted path of ``field`` inside the ``index``-th Finding of the file."""
    location = "{0}[{1}]".format(FINDINGS_KEY, index)
    return "{0}.{1}".format(location, field) if field else location


def _prefixed(error: SchemaViolationError, index: int) -> SchemaViolationError:
    """Re-report a :mod:`iacreview.finding` violation against the file's shape.

    ``from_dict`` names the offending path within one Finding
    (``"Evidence[0].Detail"``). A reader of this file needs to know *which*
    Finding, so the path is re-rooted at ``findings[<index>]``.
    """
    field = getattr(error, "field", None) or "<finding>"
    reason = getattr(error, "reason", None) or str(error)
    return schema_violation(_entry_field(index, field), reason)


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------


def _file_violation(reason: str) -> SchemaViolationError:
    """Build the whole-file failure: nothing in this file is usable."""
    return schema_violation("<agent findings file>", reason)


def _check_schema_version(value: object) -> None:
    """Accept a ``schema_version`` whose MAJOR this module was written against.

    Only MAJOR is compared. A MINOR or PATCH difference means fields may have
    been added or wording clarified, which strict per-field validation already
    catches one Finding at a time; a MAJOR difference means the fields present
    do not mean what is validated here, and no per-Finding check would notice.
    """
    if value is None:
        return
    if not isinstance(value, str) or not value.strip():
        raise _file_violation(
            "{0} must be a version string, got {1}".format(
                SCHEMA_VERSION_KEY, _type_name(value)
            )
        )
    major = value.split(".", 1)[0].strip()
    if major != str(SUPPORTED_SCHEMA_MAJOR):
        raise _file_violation(
            "{0} {1!r} declares a major version this plugin does not "
            "implement; expected {2}.x.y".format(
                SCHEMA_VERSION_KEY, value, SUPPORTED_SCHEMA_MAJOR
            )
        )


def _entries_from_payload(payload: object) -> List[Any]:
    """Extract the array of Finding objects from either accepted envelope.

    Two shapes are accepted. A bare JSON array is the least an agent has to
    write to say "here are my Findings". An object with a ``findings`` key
    mirrors the Review_Report envelope, so a captured report section works as a
    benchmark fixture (design.md, Benchmark 再現性) without being reshaped.

    Raises:
        SchemaViolationError: The payload is neither shape, carries an unknown
            envelope key, declares an unsupported ``schema_version``, or its
            ``findings`` value is not an array.
    """
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        raise _file_violation(
            "expected a JSON array of findings or an object with a {0!r} key, "
            "got {1}".format(FINDINGS_KEY, _type_name(payload))
        )
    for key in sorted(payload):
        if key not in ENVELOPE_KEYS:
            raise _file_violation(
                "{0!r} is not one of the permitted top-level keys {1}".format(
                    key, list(ENVELOPE_KEYS)
                )
            )
    _check_schema_version(payload.get(SCHEMA_VERSION_KEY))
    if FINDINGS_KEY not in payload:
        raise _file_violation("required key {0!r} is missing".format(FINDINGS_KEY))
    entries = payload[FINDINGS_KEY]
    if not isinstance(entries, list):
        raise _file_violation(
            "{0} must be an array, got {1}".format(FINDINGS_KEY, _type_name(entries))
        )
    return entries


# ---------------------------------------------------------------------------
# One Finding
# ---------------------------------------------------------------------------


def _require_object(index: int, entry: object) -> Dict[str, Any]:
    if not isinstance(entry, dict):
        raise schema_violation(
            _entry_field(index),
            "expected an object, got {0}".format(_type_name(entry)),
        )
    for key in entry:
        if not isinstance(key, str):
            raise schema_violation(
                _entry_field(index),
                "keys must be strings, got {0}".format(_type_name(key)),
            )
    return dict(entry)


def _normalize_id(index: int, payload: Dict[str, Any]) -> None:
    """Discard any ``ID`` the agent supplied, keeping its shape checked.

    The report assigns IDs over the sorted, deduplicated Finding list, so a
    value here cannot be honoured. Its *type* is still checked: a string or an
    object in this field means the producer misread the schema, which is worth
    reporting rather than passing over in silence.
    """
    supplied = payload.get("ID")
    if supplied is not None and (isinstance(supplied, bool) or not isinstance(supplied, int)):
        raise schema_violation(
            _entry_field(index, "ID"),
            "expected an integer or null, got {0}; the report assigns IDs, so "
            "the value is not used".format(_type_name(supplied)),
        )
    payload["ID"] = _VALIDATION_ID


def _normalize_confidence(index: int, payload: Dict[str, Any]) -> None:
    """Demote ``Confirmed`` to ``Likely`` and say so on stderr.

    The third prohibition of design.md's Deterministic / Agent Boundary
    (Requirement 7 AC10). Any other value is left alone for
    :func:`iacreview.finding.from_dict` to accept or reject against
    :data:`~iacreview.finding.CONFIDENCES`.
    """
    if payload.get("Confidence") != CONFIRMED:
        return
    payload["Confidence"] = DEMOTED_CONFIDENCE
    _warn(
        DEMOTION_WARNING.format(
            location=_entry_field(index),
            confirmed=CONFIRMED,
            demoted=DEMOTED_CONFIDENCE,
        )
    )


def _normalize_category(index: int, payload: Dict[str, Any]) -> None:
    """Fall back to ``Other`` for a Category outside the closed set.

    Requirement 14 AC3. Absent, ``null``, and an unrecognized name are all
    "cannot be mapped to a Normalized_Category in the defined set" and all
    become ``Other``. A non-string value is not: that is a type error, and
    quietly reading a dict as ``Other`` would hide a producer bug.
    """
    supplied = payload.get("Normalized_Category")
    if supplied is not None and not isinstance(supplied, str):
        raise schema_violation(
            _entry_field(index, "Normalized_Category"),
            "expected a string or null, got {0}".format(_type_name(supplied)),
        )
    if supplied is not None and categories.load_map().is_valid_category(supplied):
        return
    payload["Normalized_Category"] = OTHER_CATEGORY


def _normalize_source(index: int, payload: Dict[str, Any]) -> None:
    """Require the Finding to be attributed to Agent Review, and only that.

    Absent means ``["Agent Review"]``: this file has exactly one possible
    Source, so stating it is a formality. Naming any other Source is refused
    rather than corrected; see the module docstring.
    """
    expected = list(AGENT_SOURCE_LIST)
    supplied = payload.get("Source")
    if supplied is None:
        payload["Source"] = expected
        return
    if not isinstance(supplied, list) or supplied != expected:
        raise schema_violation(
            _entry_field(index, "Source"),
            "an agent finding must be attributed to {0}, got {1!r}".format(
                expected, supplied
            ),
        )


def _normalize_evidence(index: int, payload: Dict[str, Any]) -> None:
    """Check each Evidence entry's Source and require its ``Excerpt``.

    Both checks are stricter than the Finding schema, and both are design.md's
    Layer 2 constraints on agent output rather than new rules: an Evidence entry
    attributed to a deterministic tool would misplace the Finding in merge
    order, and an entry with nothing quoted from the Template is not evidence.

    Structure beyond that is left to :func:`iacreview.finding.from_dict`; a
    value that is not a list of objects simply falls through to it.

    The list and its objects are rebuilt rather than edited: the caller's
    payload is the JSON it decoded, and a validator that rewrites its input
    would make the same call behave differently the second time.
    """
    entries = payload.get("Evidence")
    if not isinstance(entries, list):
        return
    rebuilt: List[Any] = []
    for position, entry in enumerate(entries):
        if not isinstance(entry, dict):
            rebuilt.append(entry)
            continue
        field = _entry_field(index, "Evidence[{0}]".format(position))
        normalized = dict(entry)
        source = normalized.get("Source")
        if source is None:
            normalized["Source"] = AGENT_SOURCE
        elif source != AGENT_SOURCE:
            raise schema_violation(
                "{0}.Source".format(field),
                "agent evidence must name {0!r}, got {1!r}".format(AGENT_SOURCE, source),
            )
        excerpt = normalized.get("Excerpt")
        if not isinstance(excerpt, str) or not excerpt:
            raise schema_violation(
                "{0}.Excerpt".format(field),
                "an agent finding must quote the Template content it drew the "
                "conclusion from",
            )
        rebuilt.append(normalized)
    payload["Evidence"] = rebuilt


def _finding_from_entry(
    index: int, entry: object, noecho_parameters: FrozenSet[str] = frozenset()
) -> Finding:
    """Validate and normalize one entry of the file into a Finding.

    Args:
        index: Position in the file's ``findings`` array, used in error paths.
        entry: The raw JSON value at that position.
        noecho_parameters: ``NoEcho`` Parameter names of the reviewed Template,
            for credential redaction (see the module docstring).

    Returns:
        A Finding that has passed :func:`iacreview.finding.validate`, carrying
        :data:`~iacreview.finding.UNASSIGNED_ID` like every Source's output.
        Validation runs against a placeholder ``ID`` because the schema's
        ``ID >= 1`` constraint describes a Finding that has been through report
        ID assignment, which happens after dedup; the placeholder is replaced
        immediately afterwards so nothing downstream can mistake it for an
        assigned ID.

        Redaction is applied after validation, not before: the Finding is
        validated as the agent wrote it, and the placeholder that replaces a
        credential-bearing Excerpt is non-empty, so the Excerpt requirement of
        Requirement 7 AC11 holds on both sides of the substitution.

    Raises:
        SchemaViolationError: The entry is unusable, with ``field`` rooted at
            ``findings[<index>]``. The caller drops this one entry.
    """
    payload = _require_object(index, entry)
    _normalize_id(index, payload)
    for field in NULLABLE_FIELDS:
        payload.setdefault(field, None)
    _normalize_confidence(index, payload)
    _normalize_category(index, payload)
    _normalize_source(index, payload)
    _normalize_evidence(index, payload)

    try:
        finding = from_dict(payload)
    except SchemaViolationError as exc:
        raise _prefixed(exc, index) from exc

    finding.ID = UNASSIGNED_ID
    return redact_finding(finding, noecho_parameters=noecho_parameters)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def findings_from_payload(
    payload: object, *, noecho_parameters: Iterable[str] = ()
) -> Tuple[List[Finding], List[StructuredError]]:
    """Validate an already-decoded agent findings payload.

    The whole of :func:`load_agent_findings` except reading the file, so every
    branch is reachable from a Python literal with no temporary file involved.

    Args:
        payload: The decoded JSON: an array of Finding objects, or an object
            with a ``findings`` key.
        noecho_parameters: ``NoEcho`` Parameter names of the reviewed Template,
            from :func:`iacreview.finding.noecho_parameter_names`. Supplying
            them enables condition (a) of the Excerpt redaction rule; the empty
            default leaves it unevaluated.

    Returns:
        ``(findings, errors)``. ``findings`` holds the accepted Findings in file
        order, each with :data:`~iacreview.finding.UNASSIGNED_ID`. ``errors``
        holds one StructuredError per dropped entry, with ``error_class``
        ``schema_violation`` and ``source`` ``Agent Review``. One bad entry
        never costs another: a file of ten Findings with one violation yields
        nine Findings and one error.

    Raises:
        SchemaViolationError: The payload as a whole is not an agent findings
            file. Nothing is returned in that case, because a payload whose
            envelope is unrecognized offers no array to be partially right
            about.
        MappingFileError: ``category_map.json`` is present but unusable, which
            is a broken installation rather than bad input.
    """
    entries = _entries_from_payload(payload)
    names = frozenset(noecho_parameters)
    findings: List[Finding] = []
    errors: List[StructuredError] = []
    for index, entry in enumerate(entries):
        try:
            findings.append(_finding_from_entry(index, entry, names))
        except SchemaViolationError as exc:
            errors.append(exc.to_structured_error(SOURCE_NAME))
    return findings, errors


def load_agent_findings(
    path: Path, *, noecho_parameters: Iterable[str] = ()
) -> Tuple[List[Finding], List[StructuredError]]:
    """Read and validate the agent findings file at ``path``.

    The single entry point for agent output (design.md, Components and
    Interfaces / ``iacreview.agentin``). Called once per run, outside the Source
    loop, and only when ``--agent-findings`` was given.

    Args:
        path: The file the agent wrote. Containment inside the workspace is the
            caller's responsibility, established with
            :func:`iacreview.pathguard.resolve_within` before calling; this
            function does no path validation of its own.
        noecho_parameters: ``NoEcho`` Parameter names of the reviewed Template,
            from :func:`iacreview.finding.noecho_parameter_names`. The caller
            has the parsed Template and this function does not, so the names
            arrive here rather than being derived; see
            :func:`findings_from_payload`.

    Returns:
        ``(findings, errors)`` as described in :func:`findings_from_payload`.

    Raises:
        InputNotFoundError: ``path`` cannot be opened or read.
        SchemaViolationError: The file is not valid UTF-8 JSON, or is not an
            agent findings file. The decoder's own position information is kept
            in the message, since it is the only clue to where a large
            generated file went wrong.
        MappingFileError: ``category_map.json`` is present but unusable.
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        # Named the way the report names a file, and the errno rendered without
        # the filename CPython appends: ``iac-review`` records this failure in
        # ``errors[]`` rather than raising, so the message reaches stdout, where
        # an absolute host path is forbidden (Requirement 16 AC11).
        raise InputNotFoundError(
            "agent findings file cannot be read: {0} ({1})".format(
                display_path(path), os_error_detail(exc)
            ),
            remediation="Check the path passed to --agent-findings.",
        ) from exc

    try:
        payload = json.loads(text)
    except ValueError as exc:
        # json.JSONDecodeError subclasses ValueError and reports line and
        # column in str(exc); UnicodeDecodeError from read_text lands here too.
        raise _file_violation("is not valid JSON ({0})".format(exc)) from exc

    return findings_from_payload(payload, noecho_parameters=noecho_parameters)
