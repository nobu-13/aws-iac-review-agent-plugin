"""Properties 15, 16, 17 and 21: what :mod:`iacreview.template` guarantees.

Four claims about the one place a Template file becomes a Python document, each
quantified over a generated input space rather than over a fixture:

* **15** the format a Template is written in does not change the review;
* **16** the reviewability predicate is exactly the condition Requirement 3 AC1
  states, on every document a parser can return;
* **17** no byte string reaches a caller as an unhandled exception, and a parse
  failure always says *what* failed and *where* (Requirement 3 AC6);
* **21** a tag outside the CloudFormation allowlist is refused, and nothing in
  the Template runs (Requirement 9 AC7).

What the existing tests already say, and is not repeated here
------------------------------------------------------------

``tests/unit/test_template.py`` pins the nine enumerated inputs of tasks.md 5.2
-- valid YAML, valid JSON, malformed YAML, malformed JSON, binary, truncated,
empty, no ``Resources``, empty ``Resources`` -- each against a fixture a reader
can open, and asserts the exact ``error_type`` and position where the fixture
fixes them unambiguously. It also settles format detection by content and the
predicate on twelve hand-picked documents.

``tests/unit/test_yamlcfn.py`` covers the loader from the other side: all 18
shorthand tags convert to long form, ``!!python/object`` and
``!!python/object/apply`` and ``!Bogus`` are refused, the allowlist does not leak
onto the shared ``yaml.SafeLoader``, and no multi-constructor is registered --
which is *why* an unknown tag has nowhere to go.

``tests/property/test_strategies_smoke.py`` establishes that the generators used
below are not vacuous: ``template_texts()`` round-trips to one document (Property
15's premise), ``arbitrary_input_bytes()`` reaches both a successful load and a
``parse_failure`` (so Property 17 exercises both branches), and
``unsupported_yaml_tag_texts()`` never emits a tag that is in fact allowlisted.

The properties here add the quantifier. A fixture says the loader handled the
nine inputs someone thought of; these say it handles the ones nobody did.

Property 21 needs more than an exception
----------------------------------------

"loading raises ``TemplateParseError``" is easy to satisfy for the wrong reason:
a loader that constructed the object and *then* rejected the document would pass
that assertion. So the refusal is observed through side-effect probes rather than
through the exception alone. Two of them wrap every load:

``_canary``
    A module-level function this file owns, named by a
    ``!!python/object/apply:`` tag in the document under load. Under a loader
    that constructs arbitrary Python objects, PyYAML imports the named module and
    calls the function; under a ``SafeLoader`` derivative it never resolves the
    name. ``test_the_canary_probe_fires_when_construction_is_allowed`` proves the
    probe is sensitive by making it fire, so the empty ``_CANARY_CALLS`` list in
    the property below is evidence rather than an assumption.

``_no_process_execution``
    Records calls to :func:`os.system`, :func:`os.popen`,
    :class:`subprocess.Popen` and :func:`subprocess.run` for the duration of the
    load. The classic YAML payload is a shell command, and this is what would see
    one.

Both probes *record* and never raise. Raising would be swallowed:
:func:`iacreview.template.parse_template_text` catches ``Exception`` broadly so
that untrusted input fails cleanly, and an ``AssertionError`` from inside a
constructor would come back out as a ``TemplateParseError`` -- the test would
pass while reporting exactly the thing it was watching for.

Out of scope
------------

``TemplateParseError.message`` interpolates the path it was given, so a caller
passing an absolute path gets an absolute host path in the message. Nothing here
asserts on message content; task 24.5 (``tests/negative/test_malformed_input.py``)
owns that leak and its fix.

Temporary directories come from :mod:`tempfile` inside the test body rather than
from the ``tmp_path`` fixture: a function-scoped fixture is created once for a
whole ``@given`` run, which Hypothesis reports as a health check failure, and
sharing one directory across examples would let one example's file decide the
next one's outcome.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple
from unittest import mock

import pytest
from hypothesis import given, settings

import strategies as S
from iacreview import iam, template
from iacreview.errors import (
    ERROR_CLASS_HIERARCHY,
    ERROR_CLASSES,
    STRUCTURED_ERROR_KEYS,
    IacReviewError,
    TemplateParseError,
)
from iacreview.finding import Finding, to_dict

# Property 15 serializes a document to YAML and Property 21 needs the loader, so
# the whole module needs PyYAML. It is the plugin's one runtime dependency; the
# skip exists for the JSON-only environment ``iacreview.yamlcfn`` is written to
# tolerate, where these four properties cannot be stated at all.
yaml = pytest.importorskip("yaml", reason="PyYAML is required for these properties")


# ---------------------------------------------------------------------------
# Property 15: YAML and JSON equivalence
# ---------------------------------------------------------------------------

#: ``Location.File`` both serializations are rewritten to before comparison.
#: Property 15 normalizes that field because it is the one place the file name is
#: *meant* to differ -- the same document written to ``app.yaml`` and to
#: ``app.json`` is two files -- and normalizing it is what makes the rest of the
#: Finding comparable.
NORMALIZED_FILE = "<template>"

#: The two names the pair is written to inside one temporary root. The extensions
#: disagree with each other but not with the content, so this also exercises
#: content-based format detection: the review has to reach the same Findings
#: without the extension having told it anything it could not see in the bytes.
YAML_NAME = "template.yaml"
JSON_NAME = "template.json"


def _file_normalized(f: Finding) -> Dict[str, Any]:
    """``f`` as a report-shaped dict with ``Location.File`` normalized.

    :func:`iacreview.finding.to_dict` rather than dataclass equality: it renders
    all 13 fields, so the comparison is no weaker, and a counterexample prints as
    a dict diff instead of as nested dataclass ``repr``.
    """
    payload = to_dict(f)
    payload["Location"]["File"] = NORMALIZED_FILE
    return payload


def _review(root: Path, name: str, text: str) -> Tuple[Any, str, List[Dict[str, Any]]]:
    """Write ``text`` to ``root/name``, review it, and report what came back.

    Returns ``(document, fmt, findings)``. The document and format are returned
    for triage: if the two serializations disagree, the failure is either in the
    serialization (the documents differ, which is the generator's problem and is
    what ``test_strategies_smoke.py`` guards) or in the review (the documents
    agree and the Findings do not, which is Property 15's subject).

    The IAM Source is used because it is the only Source that runs no external
    tool, so this property holds on a machine with neither cfn-lint nor cfn-guard
    installed. It reads the Template through the same
    :func:`iacreview.template.load_template` every other Source uses, which is
    the layer the property is actually about.
    """
    path = root / name
    path.write_text(text, encoding="utf-8")
    loaded = template.load_template(path)
    result = iam.run_and_normalize(path, workspace_root=root, loaded=loaded)
    return loaded.doc, loaded.fmt, [_file_normalized(f) for f in result.findings]


# Feature: aws-iac-review-agent-plugin, Property 15: *For any* Template document,
# reviewing its YAML serialization and reviewing its JSON serialization produce
# identical Findings after normalizing `Location.File`.
# deadline=None: each example writes two files and parses both, so the per-example
# wall clock depends on the machine's filesystem rather than on the plugin.
@settings(max_examples=100, deadline=None)
@given(S.template_texts())
def test_yaml_and_json_serializations_review_identically(pair: Tuple[str, str]) -> None:
    """The format a Template is written in is invisible to the review.

    Requirement 3 AC4 says both formats are accepted; this says accepting them
    means the same thing. The two texts come from one draw, so a difference in
    the output can only come from the loader or from a Source reading the
    document differently -- for instance a JSON string key surviving where YAML
    produced an ``int``, which is precisely the class of bug that makes a review
    depend on how the Template was written.

    Lists are compared, not sets: Requirement 7 AC15 orders the report, and two
    Findings that tie on every sort key would carry a format dependence through
    to stdout if their relative order differed here.
    """
    yaml_text, json_text = pair

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        yaml_document, yaml_format, yaml_findings = _review(root, YAML_NAME, yaml_text)
        json_document, json_format, json_findings = _review(root, JSON_NAME, json_text)

    assert (yaml_format, json_format) == template.TEMPLATE_FORMATS
    assert yaml_document == json_document
    assert yaml_findings == json_findings


# ---------------------------------------------------------------------------
# Property 16: Reviewability predicate
# ---------------------------------------------------------------------------


# Feature: aws-iac-review-agent-plugin, Property 16: *For any* parsed document,
# the reviewability predicate returns true if and only if the document is a
# mapping whose `Resources` key maps to a mapping containing at least one entry.
@settings(max_examples=100)
@given(S.documents())
def test_reviewability_is_exactly_a_non_empty_resources_mapping(document: Any) -> None:
    """Requirement 3 AC1 and AC5, read literally and compared to the code.

    ``expected`` is the property's own sentence transcribed into Python, one
    clause at a time, so what is being checked is the requirement rather than a
    second implementation of it. The section name comes from
    :data:`iacreview.template.RESOURCES_KEY`; nothing here spells ``"Resources"``.

    ``is`` rather than ``==`` on purpose: the predicate is documented as total and
    as returning a plain ``bool``, and ``1 == True`` would hide a truthy return
    value that a caller writing ``result is True`` would then read as false.

    ``documents()`` draws both halves -- a reviewable Template and every shape the
    predicate must reject, including the ``Resources: {}`` stub whose review would
    otherwise be indistinguishable from a clean one -- and the smoke test asserts
    each half lands where it should, so neither direction of the biconditional is
    vacuous here.
    """
    is_mapping = isinstance(document, dict)
    resources = document.get(template.RESOURCES_KEY) if is_mapping else None
    expected = is_mapping and isinstance(resources, dict) and len(resources) > 0

    assert template.is_reviewable(document) is expected


# ---------------------------------------------------------------------------
# Property 17: Safe failure on arbitrary input bytes
# ---------------------------------------------------------------------------

#: ``error_class`` of a parse failure, from the exception that declares it. The
#: value is a report-consumer contract, so it is read rather than written out.
PARSE_FAILURE_CLASS = TemplateParseError.error_class


def _assert_documented_failure(exc: IacReviewError, data: bytes) -> None:
    """Assert ``exc`` is one of the failures the plugin documents.

    Three claims, in the order Property 17 states them: the exception is a
    declared class, it carries an ``error_class`` from the closed set, and it
    renders to the fixed StructuredError shape a report consumer indexes without
    existence checks.

    ``data`` is only used in assertion messages, as ``repr`` of the bytes, so a
    counterexample can be reproduced by writing exactly those bytes to a file.
    """
    assert type(exc) in ERROR_CLASS_HIERARCHY, (
        "input {0!r} raised {1}, which is not a declared exception class".format(
            data, type(exc).__name__
        )
    )
    assert exc.error_class in ERROR_CLASSES

    structured = exc.to_structured_error(source="template")
    assert tuple(structured) == STRUCTURED_ERROR_KEYS
    assert structured["error_class"] in ERROR_CLASSES


def _assert_parse_failure_is_located(exc: IacReviewError, data: bytes) -> None:
    """Assert a parse failure says what failed and where (Requirement 3 AC6).

    Only ``TemplateParseError`` reports ``parse_failure``, so the class check is
    part of the claim: a different exception carrying that ``error_class`` would
    have no place to put the position.

    The position is always present because
    :mod:`iacreview.template` substitutes
    :data:`~iacreview.template.DEFAULT_LINE` /
    :data:`~iacreview.template.DEFAULT_COLUMN` when the underlying parser gives
    no mark -- PyYAML does not guarantee a ``problem_mark``, a plain
    ``ValueError`` from inside the JSON decoder has no ``lineno``, and a decode
    failure has no parser mark at all. The assertion is therefore on *usable*
    values, not on exact ones: which mark a scanner chooses is PyYAML's business,
    and ``tests/unit/test_template.py`` pins the exact positions on the fixtures
    where the input fixes them.
    """
    assert isinstance(exc, TemplateParseError)
    assert exc.error_type, "parse failure for {0!r} carries no error type".format(data)
    for name, value in (("line", exc.line), ("column", exc.column)):
        assert value is not None, "parse failure for {0!r} has no {1}".format(data, name)
        assert isinstance(value, int) and not isinstance(value, bool)
        assert value >= 1


# Feature: aws-iac-review-agent-plugin, Property 17: *For any* byte string written
# to an input file, loading that file either succeeds or raises a documented
# `IacReviewError` subclass carrying an `error_class`, and never propagates an
# unhandled exception; when the failure is a parse failure, the reported error
# carries a parse error type, a line number, and a column number.
# deadline=None: each example writes a file and reads it back, so the per-example
# wall clock is the filesystem's, not the plugin's.
@settings(max_examples=100, deadline=None)
@given(S.arbitrary_input_bytes())
def test_arbitrary_input_bytes_fail_as_a_documented_error(data: bytes) -> None:
    """Requirement 12 AC8 over the whole input space, not over three fixtures.

    The bytes are written to a file and loaded, which is what an entry point
    does; going through the file rather than through
    :func:`~iacreview.template.parse_template_text` is what puts the decode step
    -- the one that turns binary input into a located ``UnicodeDecodeError`` --
    inside the property.

    Anything that is not an ``IacReviewError`` is re-raised as an
    ``AssertionError`` naming the bytes. That branch is the "never propagates an
    unhandled exception" clause: without it a stray ``RecursionError`` would
    still fail the test, but as a traceback from library code rather than as a
    statement about which input broke the contract.

    Failure is the common outcome by a wide margin -- arbitrary bytes are almost
    never a Template -- so the successful branch below is reached only through the
    generator's seeded shapes. ``test_strategies_smoke.py`` is what guarantees it
    is reached at all; this test states what must hold when it is.
    """
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "input.yaml"
        path.write_bytes(data)

        try:
            loaded = template.load_template(path)
        except IacReviewError as exc:
            _assert_documented_failure(exc, data)
            if exc.error_class == PARSE_FAILURE_CLASS:
                _assert_parse_failure_is_located(exc, data)
            return
        except Exception as exc:  # noqa: BLE001 - this is the clause under test
            raise AssertionError(
                "input {0!r} propagated an unhandled {1}: {2}".format(
                    data, type(exc).__name__, exc
                )
            ) from exc

    # A successful load is the property's other branch, and it has to mean what
    # load_template promises: a reviewable document in a known format.
    assert loaded.fmt in template.TEMPLATE_FORMATS
    assert template.is_reviewable(loaded.doc)


# ---------------------------------------------------------------------------
# Property 21: Template content is never executed
# ---------------------------------------------------------------------------

#: Every call the canary received, as its argument tuples. Cleared before each
#: load; a non-empty list after one means Template content selected code and ran
#: it.
_CANARY_CALLS: List[Tuple[Any, ...]] = []


def _canary(*args: Any) -> str:
    """Probe target for Property 21. Records that it was called, and nothing else.

    Deliberately inert: it writes to a list in this process and has no effect a
    real payload would want. The point is not to be dangerous but to be
    *observable* -- if Template content can reach this function, it can reach
    :func:`os.system`, and the assertion that it did not is what makes "no
    constructor side effect is observable" a measurement rather than a hope.

    It records instead of raising because
    :func:`iacreview.template.parse_template_text` catches ``Exception`` broadly
    to keep untrusted input from escaping as a traceback: an exception raised
    here would be re-raised as a ``TemplateParseError`` and the test asserting
    that very exception would pass.
    """
    _CANARY_CALLS.append(args)
    return "canary"


def _canary_tag() -> str:
    """A ``!!python/object/apply:`` tag naming :func:`_canary`, with no arguments.

    ``__name__`` is read at run time rather than written out: pytest imports this
    file as a top-level module (there is no ``__init__.py`` under
    ``tests/property/``), and hard-coding the name would make the probe silently
    unresolvable -- and therefore vacuous -- if the layout or the import mode
    changed.
    """
    return "!!python/object/apply:{0}.{1} []".format(__name__, _canary.__name__)


#: Mapping key the canary tag is attached under. The name itself is arbitrary --
#: what matters is that :func:`_with_canary_first` writes the entry *before* the
#: drawn one, since PyYAML constructs a mapping's values in document order rather
#: than in key order.
CANARY_KEY = "Canary"

#: Where :func:`_with_canary_first` splices the canary in. Matches the shape
#: ``strategies.unsupported_yaml_tag_texts()`` builds; :func:`_with_canary_first`
#: asserts it is present, so a change to that generator surfaces as a failure
#: rather than as a probe that quietly stopped being inserted.
_PROPERTIES_MARKER = "    Properties:\n"


def _canary_document() -> str:
    """A minimal Template whose only unusual content is the canary tag."""
    return (
        "Resources:\n"
        "  A:\n"
        "    Type: AWS::S3::Bucket\n"
        "{0}"
        "      {1}: {2}\n".format(_PROPERTIES_MARKER, CANARY_KEY, _canary_tag())
    )


def _with_canary_first(text: str) -> str:
    """``text`` with the canary tag inserted ahead of the drawn tag.

    Order matters. PyYAML composes the whole node graph before constructing
    anything, then constructs a mapping's values in document order, so whichever
    unsupported tag comes first is the one that raises and the rest of the
    document is never constructed. With the drawn tag first the canary would
    never be reached and the probe would report nothing; putting the canary first
    means a loader willing to construct Python objects would call it before it
    ever got to the drawn tag.

    Both texts are instances of Property 21's quantifier -- each contains a tag
    outside the allowlist -- so the property is checked on the drawn document and
    on a document derived from it, not on a constant.
    """
    head, marker, tail = text.partition(_PROPERTIES_MARKER)
    assert marker, "generated text has no {0!r} section to splice into".format(
        _PROPERTIES_MARKER.strip()
    )
    return "{0}{1}      {2}: {3}\n{4}".format(
        head, marker, CANARY_KEY, _canary_tag(), tail
    )


@contextlib.contextmanager
def _no_process_execution() -> Iterator[List[str]]:
    """Record, rather than perform, any process launch attempted inside the block.

    The yielded list stays empty unless something called one of the four
    functions a YAML payload would use to run a command. Like the canary, the
    replacements record and return instead of raising, so that a launch cannot be
    laundered into the ``TemplateParseError`` the test is also asserting.

    ``subprocess.run`` and ``subprocess.Popen`` are patched on the module rather
    than on :mod:`iacreview.proc`: the point is to catch a call made from
    anywhere, including from inside PyYAML.
    """
    attempts: List[str] = []
    targets = (
        (os, "system"),
        (os, "popen"),
        (subprocess, "Popen"),
        (subprocess, "run"),
    )

    def recorder(name: str) -> Any:
        def record(*args: Any, **kwargs: Any) -> None:
            attempts.append("{0}({1!r})".format(name, args))
            return None

        return record

    with contextlib.ExitStack() as stack:
        for module, attribute in targets:
            stack.enter_context(
                mock.patch.object(
                    module, attribute, recorder("{0}.{1}".format(module.__name__, attribute))
                )
            )
        yield attempts


def _assert_refused_without_side_effect(text: str) -> None:
    """Load ``text`` and assert it was refused with nothing observable happening.

    The exception is asserted first because it is the property's first clause,
    then the two probes. ``parse_template_text`` is called directly rather than
    through ``load_template``: no file needs to exist for a tag to be refused,
    and keeping the filesystem out means a failure here can only be about
    construction.
    """
    del _CANARY_CALLS[:]

    with _no_process_execution() as attempts:
        with pytest.raises(TemplateParseError) as exc_info:
            template.parse_template_text(text, Path(YAML_NAME))

    assert _CANARY_CALLS == [], "template content called the canary: {0!r}".format(
        _CANARY_CALLS
    )
    assert attempts == [], "template content attempted to run: {0}".format(attempts)

    error = exc_info.value
    assert error.error_class == PARSE_FAILURE_CLASS
    assert error.error_type
    assert error.line is not None and error.column is not None


# Feature: aws-iac-review-agent-plugin, Property 21: *For any* Template containing
# a YAML tag outside the CloudFormation short-form allowlist, loading raises
# `TemplateParseError`, and no constructor side effect is observable.
@settings(max_examples=100)
@given(S.unsupported_yaml_tag_texts())
def test_unsupported_yaml_tags_are_refused_without_executing_anything(
    text: str,
) -> None:
    """Requirement 9 AC7: an untrusted Template selects no code to run.

    Two documents per example. The drawn one carries a tag generated *around*
    :data:`iacreview.yamlcfn.SHORT_TAGS`, so widening the allowlist cannot leave
    this test asserting that a now-legal tag is refused. The derived one carries
    the canary tag ahead of it, which is the case where a loader that constructed
    Python objects would be caught doing it -- see the module docstring on why
    that is worth more than the exception on its own.

    What refusal rests on is asserted elsewhere and not repeated:
    ``tests/unit/test_yamlcfn.py`` shows the allowlist is registered one tag at a
    time on a ``SafeLoader`` subclass with no multi-constructor, which is the
    structural reason an unlisted tag has no constructor to reach.
    """
    _assert_refused_without_side_effect(text)
    _assert_refused_without_side_effect(_with_canary_first(text))


#: A stand-in for one draw of ``strategies.unsupported_yaml_tag_texts()``, used
#: only to show that splicing the canary into that shape puts it ahead of the
#: drawn tag. ``!Bogus`` is the same tag ``tests/unit/test_yamlcfn.py`` uses for
#: "outside the allowlist".
_REPRESENTATIVE_DRAWN_TEXT = (
    "Resources:\n"
    "  A:\n"
    "    Type: AWS::S3::Bucket\n"
    "{0}"
    "      BucketName: !Bogus value\n".format(_PROPERTIES_MARKER)
)


def test_the_canary_probe_fires_when_construction_is_allowed() -> None:
    """The probe of Property 21 is sensitive: shown by making it fire.

    Not a property test. It exists because an empty ``_CANARY_CALLS`` proves
    nothing unless a non-empty one is reachable, and "the canary was never
    called" would otherwise be satisfied just as well by a misspelled tag, a
    module name that no longer resolves, or a probe spliced in behind a tag that
    fails first.

    Both documents Property 21 loads are shown to be probe-carrying: the canary
    on its own, and the canary spliced ahead of a drawn tag. The second is the
    one that could go wrong silently -- if construction reached the drawn tag
    first, the load would fail before the canary and the probe would report
    nothing whether or not construction was possible.

    ``yaml.UnsafeLoader`` appears here and nowhere else in the repository. It is
    what makes the demonstration possible: the documents are written in this file,
    their payload is :func:`_canary`, and the only effect of the call is an append
    to a list in this process. No untrusted input is involved, and
    :mod:`iacreview` reaches this loader on no code path -- ``yamlcfn`` derives
    its loader from ``SafeLoader`` and passes it explicitly on every parse.
    """
    documents = (_canary_document(), _with_canary_first(_REPRESENTATIVE_DRAWN_TEXT))

    for document in documents:
        del _CANARY_CALLS[:]
        try:
            # Deliberately permissive, to prove the probe would notice. Never do
            # this to input that came from outside the test suite. The drawn tag
            # is still unknown to this loader, so the load raises *after* the
            # canary has been constructed.
            with contextlib.suppress(yaml.YAMLError):
                yaml.load(document, Loader=yaml.UnsafeLoader)

            assert _CANARY_CALLS == [()], (
                "the canary tag in\n{0}\ndid not resolve to {1}; the probe in "
                "Property 21 would report nothing either".format(
                    document, _canary.__name__
                )
            )
        finally:
            del _CANARY_CALLS[:]

        # And the same document, through the plugin's loader, is refused.
        _assert_refused_without_side_effect(document)


def test_the_canary_module_is_importable_under_its_recorded_name() -> None:
    """The name in the canary tag is the one an importer would resolve.

    :func:`_canary_tag` builds the tag from ``__name__``. If this module were
    imported under a name that is not in :data:`sys.modules` -- a different
    pytest import mode, a package added under ``tests/property/`` -- the tag
    would fail to resolve for a reason unrelated to the allowlist, and Property
    21 would be asserting that an unresolvable name is unresolvable.
    """
    assert __name__ in sys.modules
    assert getattr(sys.modules[__name__], _canary.__name__) is _canary
