"""The whole review pipeline, end to end, checked against the published schema.

Requirement 12 AC2 asks for one thing that no other test module in this suite
provides: a run of the *full* pipeline over at least three sample Templates whose
output is then held against the Finding schema of Requirement 7 -- all required
fields present, and of the declared types. That is what this module does, and it
deliberately does nothing else.

The three inputs, all shipping with the plugin
----------------------------------------------

``examples/`` holds three examples, and each contributes one Template to the
pipeline:

1. ``examples/minimal-s3/template.yaml`` -- YAML, named directly, no findings.
2. ``examples/lambda-with-role/template.yaml`` -- YAML, named directly, findings.
   The only example that produces one, so it is what the per-field checks below
   actually have data to run on.
3. ``examples/cdk-synth-output/`` documents reviewing a synthesized CDK project
   and ships no cloud assembly, because a cloud assembly is a build artifact.
   :func:`synthesized_project` builds the layout that README describes in
   ``tmp_path`` -- a ``cdk.json`` beside a ``cdk.out/*.template.json`` -- with
   example 2's document re-serialized as JSON. That makes the third Template a
   third *pipeline path* rather than a third file with the same properties: the
   JSON reader instead of the YAML one, discovery of a directory target instead
   of a named file, and the synthesized Template group instead of the standalone
   one.

Every run enables every deterministic Source, and every run must exit 0 whether
or not cfn-lint and cfn-guard are installed -- the IAM detectors need no tool, so
something always reviews the Template (Requirement 4 AC12, Requirement 5 AC6).
The cases below therefore do not skip when a tool is absent; they assert instead
that an absent tool shows up as one ``tool_unavailable`` entry naming a tool that
really is missing. Two cases that compare against real tool output do skip
(Requirement 15 AC4).

What this module asserts, and what it leaves to its neighbours
--------------------------------------------------------------

Asserted here, and nowhere else:

*   **The Finding schema, field by field, on real pipeline output.**
    :func:`assert_finding_conforms` checks the 13 required keys, the JSON type of
    each, and the permitted values of the five enumerated fields, against a
    schema transcribed into this module from Requirement 7 and design.md's Data
    Models. It does not call :func:`iacreview.finding.from_dict`: that function is
    the implementation of the schema, and a test that validates output with the
    same code that produced it can only report that the code agrees with itself.
    ``test_examples.py`` and ``test_skill_iac_review.py`` both validate through
    ``from_dict``, which is the right check for what they are about; this module
    is the one place the *published* schema is stated independently.
    :func:`test_the_transcribed_schema_matches_the_shipped_definitions` then
    pins the transcription to the shipped constants, so the two descriptions
    cannot drift apart in silence.
*   **The report envelope's types, not just its key names.** Including the key
    set of each ``errors[]`` entry, which is a fixed output contract
    (:data:`iacreview.errors.STRUCTURED_ERROR_KEYS`) consumers index without
    existence checks.
*   **Summary counts against the findings they summarize.** ``tests/unit/
    test_report.py`` establishes these invariants for ``build_report`` on
    synthetic findings; the open question at this level is whether the document a
    consumer actually receives is internally consistent, which is a different
    claim and is checked in :func:`assert_summary_agrees_with_findings`.
*   **Serialization independence.** The synthesized JSON Template and its YAML
    source describe the same infrastructure, so they must attract the same
    findings.

Cross-referenced rather than repeated:

*   Which findings each example *should* produce, named detection by detection:
    ``tests/integration/test_examples.py``. This module asserts only that
    ``lambda-with-role`` produces at least one, because a schema check over zero
    findings proves nothing.
*   The orchestrator's behaviour matrix -- a failing Source, every Source
    failing, directory partitioning, the CDK confirmation gate, agent findings:
    ``tests/integration/test_skill_iac_review.py``.
*   Driving a tool into a chosen failure, and the structured error that results:
    ``tests/integration/test_fakebin_drives_sources.py`` and (Task 24.3)
    ``tests/integration/test_tool_unavailable.py``.
*   Findings measured against Ground_Truth: ``tests/integration/
    test_benchmark_cases.py``.

Subprocess coverage
-------------------

The entry point runs as a child process here, so its lines are counted only if
the child measures itself. ``tests/conftest.py`` owns that wiring;
:func:`test_a_child_process_inherits_the_coverage_environment` holds this module
to using it, since a hand-built child environment would drop out of the coverage
report without failing anything.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

import pytest

from iacreview import cdk, exitcodes, template
from iacreview.errors import STRUCTURED_ERROR_KEYS
from iacreview.finding import (
    CONFIDENCES,
    EVIDENCE_FIELDS,
    FINDING_FIELDS,
    FINDING_TYPES,
    LOCATION_FIELDS,
    SEVERITIES,
    SOURCES,
)
from iacreview.report import REPORT_KEYS, SCHEMA_VERSION, SUMMARY_KEYS, TOOL_KEYS

# tests/integration/test_pipeline_end_to_end.py -> tests/integration -> tests -> root
PLUGIN_ROOT: Path = Path(__file__).resolve().parents[2]

#: The entry point under test: one orchestrated review, one JSON document.
SCRIPT: Path = PLUGIN_ROOT / "skills" / "iac-review" / "scripts" / "run_iac_review.py"

#: The bundled category vocabulary, read as data rather than through
#: :mod:`iacreview.categories`. ``Normalized_Category``'s closed set is a list in
#: this file (Requirement 14 AC1); reading it here keeps the schema check
#: independent of the code that classifies findings, without copying the list
#: into a test where it would go stale.
CATEGORY_MAP_FILE: Path = PLUGIN_ROOT / "iacreview" / "category_map.json"

TIMEOUT_S = 300

MINIMAL_S3 = "examples/minimal-s3/template.yaml"
LAMBDA_WITH_ROLE = "examples/lambda-with-role/template.yaml"

#: Logical stack name of the synthesized Template built for case 3. Any name
#: works; a fixed one keeps the report bytes fixed.
SYNTHESIZED_STACK_NAME = "ExampleReportWriterStack"


# ---------------------------------------------------------------------------
# The Finding schema, transcribed from Requirement 7 and design.md
# ---------------------------------------------------------------------------

#: ``None`` stands for JSON ``null`` in the type tuples below, so a nullable
#: field reads as the union it is.
NULL = type(None)

#: The 13 required Finding fields (Requirement 7 AC1) and the JSON type each may
#: hold (design.md, Data Models / Finding schema). Ordered as the schema lists
#: them; :func:`test_the_transcribed_schema_matches_the_shipped_definitions`
#: checks that order too, since it is the order ``docs/finding-schema.md`` and the
#: dataclass both use.
FINDING_FIELD_TYPES: Tuple[Tuple[str, Tuple[type, ...]], ...] = (
    ("ID", (int,)),
    ("Normalized_Category", (str,)),
    ("FindingType", (str,)),
    ("Severity", (str,)),
    ("Confidence", (str,)),
    ("Source", (list,)),
    ("Resource", (str, NULL)),
    ("Location", (dict,)),
    ("Finding", (str,)),
    ("WhyItMatters", (str,)),
    ("Evidence", (list,)),
    ("Recommendation", (str,)),
    ("SuggestedRemediation", (str, NULL)),
)

#: ``Location``'s keys and their types. All four are always present in output:
#: a fixed key set is what lets a consumer index without existence checks.
LOCATION_FIELD_TYPES: Tuple[Tuple[str, Tuple[type, ...]], ...] = (
    ("File", (str,)),
    ("Line", (int, NULL)),
    ("Column", (int, NULL)),
    ("TemplatePath", (list, NULL)),
)

#: One ``Evidence`` entry's keys and their types.
EVIDENCE_FIELD_TYPES: Tuple[Tuple[str, Tuple[type, ...]], ...] = (
    ("Source", (str,)),
    ("Detail", (str,)),
    ("RuleId", (str, NULL)),
    ("Excerpt", (str, NULL)),
)

#: Fields whose string value carries meaning and may therefore not be empty.
#: ``Resource`` is included for its non-``null`` case: an empty logical ID would
#: collide with the ``""`` the report sort substitutes for a missing one.
NON_EMPTY_STRING_FIELDS: Tuple[str, ...] = (
    "Normalized_Category",
    "FindingType",
    "Severity",
    "Confidence",
    "Resource",
    "Finding",
    "WhyItMatters",
    "Recommendation",
)

#: Permitted ``FindingType`` values (Requirement 7 AC2).
FINDING_TYPE_VALUES: Tuple[str, ...] = (
    "Validity",
    "Security",
    "BestPractice",
    "Informational",
)

#: Permitted ``Severity`` values (Requirement 7 AC3).
SEVERITY_VALUES: Tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

#: Permitted ``Confidence`` values (Requirement 7 AC7).
CONFIDENCE_VALUES: Tuple[str, ...] = ("Confirmed", "Likely", "Contextual")

#: Permitted ``Source`` values (Requirement 7 AC13).
SOURCE_VALUES: Tuple[str, ...] = (
    "cfn-lint",
    "cfn-guard",
    "IAM Review",
    "Agent Review",
)

#: The seven top-level report keys (design.md, Review_Report schema).
ENVELOPE_KEYS: Tuple[str, ...] = (
    "schema_version",
    "target",
    "sources_enabled",
    "tools",
    "findings",
    "errors",
    "summary",
)

#: The ``summary`` keys (Requirement 7 AC16, AC17; Requirement 8 AC10).
SUMMARY_FIELD_KEYS: Tuple[str, ...] = (
    "total",
    "by_finding_type",
    "by_severity",
    "by_source",
    "by_template_group",
    "passed_all_checks",
)

#: The keys of one ``tools`` entry.
TOOL_ENTRY_KEYS: Tuple[str, ...] = ("name", "available", "version")

#: The two ``summary.by_template_group`` keys (Requirement 8 AC10).
TEMPLATE_GROUP_KEYS: Tuple[str, ...] = ("standalone", "synthesized")

#: Count dicts whose values sum to ``summary.total``. ``by_source`` is absent on
#: purpose: a Finding merged from two Sources is counted under both, so that one
#: sums higher (Requirement 14 AC12). It is checked per Source instead.
SUMMING_COUNT_KEYS: Tuple[str, ...] = (
    "by_finding_type",
    "by_severity",
    "by_template_group",
)

#: External tool per Source, for deciding whether an absent tool explains an
#: error entry. ``IAM Review`` is absent: its detectors are pure Python.
TOOL_BY_SOURCE = {"cfn-lint": "cfn-lint", "cfn-guard": "cfn-guard"}

#: ``error_class`` values a clean example may legitimately produce. Both are
#: about the environment rather than the Template: the tool is not installed, or
#: it is too old to use. Anything else is a defect and fails the case.
TOOL_ERROR_CLASSES = frozenset({"tool_unavailable", "tool_version"})

requires_cfn_lint = pytest.mark.skipif(
    shutil.which("cfn-lint") is None,
    reason="cfn-lint is not installed; the pipeline must remain usable without it",
)

requires_cfn_guard = pytest.mark.skipif(
    shutil.which("cfn-guard") is None,
    reason="cfn-guard is not installed; the pipeline must remain usable without it",
)


# ---------------------------------------------------------------------------
# Running the pipeline
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PipelineRun:
    """One end-to-end run of the entry point.

    Attributes:
        name: Case identifier, used as the parametrize ID.
        arguments: Arguments the entry point was given.
        workspace: Working directory of the run, which is the workspace root the
            report's paths are relative to.
        completed: The finished process, for its exit code and stderr.
        report: The parsed stdout document.
        expected_error_classes: ``error_class`` values this layout produces even
            when everything worked. Empty for a named Template. The CDK project
            produces two, both of them statements about the layout rather than
            failures: ``invalid_arguments`` records that synthesis was skipped
            because it was not confirmed (Requirement 8 AC5, quoted in
            ``examples/cdk-synth-output/README.md``), and
            ``no_reviewable_template`` names ``cdk.json`` -- a ``.json`` file that
            a directory walk reaches and that is not a Template, reported rather
            than silently dropped (Requirement 3 AC5).
    """

    name: str
    arguments: Tuple[str, ...]
    workspace: Path
    completed: "subprocess.CompletedProcess[str]"
    report: Dict[str, Any]
    expected_error_classes: frozenset


def child_environment(coverage_env: Dict[str, str]) -> Dict[str, str]:
    """The environment the entry point is started with.

    Args:
        coverage_env: The variables from the ``subprocess_coverage`` fixture.

    Returns:
        A copy of this process's environment with the coverage variables spliced
        in. They are already in :data:`os.environ` during a measured run, so the
        merge is a statement of intent rather than a repair: it keeps the child
        measured if this module ever narrows the environment it passes on.
    """
    env = dict(os.environ)
    env.update(coverage_env)
    return env


def run_pipeline(
    arguments: Sequence[str], workspace: Path, coverage_env: Dict[str, str]
) -> "subprocess.CompletedProcess[str]":
    """Run the ``iac-review`` entry point as a host agent would.

    Args:
        arguments: Arguments after the script path.
        workspace: Working directory, and therefore the workspace root.
        coverage_env: Coverage variables to pass to the child.

    Returns:
        The finished process, stdout and stderr decoded as text. Nothing is
        asserted here: the exit code and the document are what the cases examine.
    """
    return subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        cwd=str(workspace),
        env=child_environment(coverage_env),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
    )


def synthesized_project(directory: Path) -> Path:
    """Build the CDK project layout of ``examples/cdk-synth-output/README.md``.

    A ``cdk.json`` marks the directory as a CDK project, and one
    ``cdk.out/*.template.json`` stands for what ``cdk synth`` would have written.
    Its content is ``examples/lambda-with-role/template.yaml`` as the loader read
    it, serialized as JSON: intrinsic functions survive that round trip as data
    (``!Sub`` is ``{"Fn::Sub": ...}`` in the parsed document), so the result is
    the same infrastructure expressed in the other format.

    Nothing here runs ``cdk``, and the review below is not given
    ``--confirm-cdk-synth``: a synthesized Template already on disk is reviewed
    without confirmation, and no ``cdk`` process may start without it
    (Requirement 8 AC3, AC5).

    Args:
        directory: Directory to build the project in. Becomes the workspace root
            of the run.

    Returns:
        The workspace-relative path of the synthesized Template.
    """
    document = template.load_template(PLUGIN_ROOT / LAMBDA_WITH_ROLE).doc
    output_directory = directory / cdk.CDK_OUTPUT_DIRECTORY_NAME
    output_directory.mkdir(parents=True, exist_ok=True)
    relative = "{0}/{1}{2}".format(
        cdk.CDK_OUTPUT_DIRECTORY_NAME,
        SYNTHESIZED_STACK_NAME,
        cdk.SYNTHESIZED_TEMPLATE_SUFFIX,
    )
    (directory / relative).write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (directory / cdk.CDK_CONFIG_FILENAME).write_text(
        json.dumps({"app": "python3 app.py"}) + "\n", encoding="utf-8"
    )
    return relative


#: The three cases, in the order the module docstring introduces them.
CASE_NAMES: Tuple[str, ...] = (
    "minimal-s3",
    "lambda-with-role",
    "synthesized-cdk",
)


@pytest.fixture(scope="session")
def pipeline_runs(
    tmp_path_factory: pytest.TempPathFactory, subprocess_coverage: Dict[str, str]
) -> Dict[str, PipelineRun]:
    """Run the pipeline once per case, for the whole session.

    Session-scoped because a full review shells out to cfn-lint and cfn-guard per
    Template: the cases below read the same three documents rather than
    re-reviewing for each assertion.
    """
    project = tmp_path_factory.mktemp("cdk-project")
    synthesized_project(project)

    layouts: Tuple[Tuple[str, Tuple[str, ...], Path, frozenset], ...] = (
        ("minimal-s3", ("--target", MINIMAL_S3), PLUGIN_ROOT, frozenset()),
        ("lambda-with-role", ("--target", LAMBDA_WITH_ROLE), PLUGIN_ROOT, frozenset()),
        (
            "synthesized-cdk",
            ("--target", "."),
            project,
            frozenset({"invalid_arguments", "no_reviewable_template"}),
        ),
    )

    runs: Dict[str, PipelineRun] = {}
    for name, arguments, workspace, expected in layouts:
        completed = run_pipeline(arguments, workspace, subprocess_coverage)
        assert completed.stdout, "{0}: stdout was empty; stderr was: {1}".format(
            name, completed.stderr
        )
        runs[name] = PipelineRun(
            name=name,
            arguments=arguments,
            workspace=workspace,
            completed=completed,
            report=json.loads(completed.stdout),
            expected_error_classes=expected,
        )
    return runs


@pytest.fixture(scope="session")
def permitted_categories() -> Tuple[str, ...]:
    """The closed ``Normalized_Category`` set, read from the bundled map file."""
    payload = json.loads(CATEGORY_MAP_FILE.read_text(encoding="utf-8"))
    categories = payload["categories"]
    assert isinstance(categories, list) and categories
    return tuple(str(name) for name in categories)


# ---------------------------------------------------------------------------
# Schema checking, independent of the code that produced the report
# ---------------------------------------------------------------------------


def type_names(types: Sequence[type]) -> str:
    """Render a type tuple for an assertion message, with ``null`` for ``None``."""
    return " | ".join("null" if item is NULL else item.__name__ for item in types)


def assert_json_type(where: str, value: Any, permitted: Sequence[type]) -> None:
    """Assert ``value`` has one of the JSON types the schema declares.

    ``bool`` is rejected wherever ``int`` is expected: it is an ``int`` subclass
    in Python but a different JSON type, and ``"ID": true`` must not pass a check
    for an integer.
    """
    if bool not in permitted and isinstance(value, bool):
        raise AssertionError(
            "{0}: expected {1}, got the boolean {2!r}".format(
                where, type_names(permitted), value
            )
        )
    assert isinstance(value, tuple(permitted)), "{0}: expected {1}, got {2}".format(
        where, type_names(permitted), type(value).__name__
    )


def assert_enum(where: str, value: Any, permitted: Sequence[str]) -> None:
    assert value in permitted, "{0}: {1!r} is not one of {2}".format(
        where, value, list(permitted)
    )


def assert_fields(
    where: str, payload: Dict[str, Any], schema: Sequence[Tuple[str, Tuple[type, ...]]]
) -> None:
    """Assert ``payload`` holds exactly ``schema``'s keys, each of its type."""
    assert sorted(payload) == sorted(name for name, _ in schema), (
        "{0}: keys are {1}, expected {2}".format(
            where, sorted(payload), sorted(name for name, _ in schema)
        )
    )
    for name, types in schema:
        assert_json_type("{0}.{1}".format(where, name), payload[name], types)


def assert_finding_conforms(
    finding: Dict[str, Any], *, where: str, categories: Sequence[str]
) -> None:
    """Assert one Finding satisfies the schema of Requirement 7.

    Args:
        finding: One entry of the report's ``findings`` array.
        where: Prefix for assertion messages, naming the case and the entry.
        categories: The closed ``Normalized_Category`` set.

    The check is structural and value-based only: whether a Finding is *correct*
    about the Template is what ``test_examples.py`` and ``test_benchmark_cases.py``
    decide.
    """
    assert_fields(where, finding, FINDING_FIELD_TYPES)

    assert finding["ID"] >= 1, "{0}.ID: must start from 1".format(where)

    enumerated = (
        ("Normalized_Category", tuple(categories)),
        ("FindingType", FINDING_TYPE_VALUES),
        ("Severity", SEVERITY_VALUES),
        ("Confidence", CONFIDENCE_VALUES),
    )
    for name, permitted in enumerated:
        assert_enum("{0}.{1}".format(where, name), finding[name], permitted)

    for name in NON_EMPTY_STRING_FIELDS:
        value = finding[name]
        if isinstance(value, str):
            assert value, "{0}.{1}: must not be empty".format(where, name)

    sources = finding["Source"]
    assert sources, "{0}.Source: must name at least one source".format(where)
    repeated = "{0}.Source: repeats a source".format(where)
    assert len(set(sources)) == len(sources), repeated
    for index, source in enumerate(sources):
        assert_enum("{0}.Source[{1}]".format(where, index), source, SOURCE_VALUES)

    location = finding["Location"]
    assert_fields("{0}.Location".format(where), location, LOCATION_FIELD_TYPES)
    assert location["File"], "{0}.Location.File: must not be empty".format(where)
    if location["TemplatePath"] is not None:
        for index, segment in enumerate(location["TemplatePath"]):
            assert_json_type(
                "{0}.Location.TemplatePath[{1}]".format(where, index),
                segment,
                (str, int),
            )

    evidence = finding["Evidence"]
    assert evidence, "{0}.Evidence: must contain at least one entry".format(where)
    for index, entry in enumerate(evidence):
        prefix = "{0}.Evidence[{1}]".format(where, index)
        assert_fields(prefix, entry, EVIDENCE_FIELD_TYPES)
        assert_enum("{0}.Source".format(prefix), entry["Source"], SOURCE_VALUES)
        assert entry["Detail"], "{0}.Detail: must not be empty".format(prefix)
        assert entry["Source"] in sources, (
            "{0}.Source: {1!r} is not among the finding's sources {2}".format(
                prefix, entry["Source"], sources
            )
        )


def assert_summary_agrees_with_findings(report: Dict[str, Any], *, where: str) -> None:
    """Assert the ``summary`` counts are the findings they claim to summarize."""
    findings = report["findings"]
    summary = report["summary"]

    assert_fields(
        "{0}.summary".format(where),
        summary,
        (
            ("total", (int,)),
            ("by_finding_type", (dict,)),
            ("by_severity", (dict,)),
            ("by_source", (dict,)),
            ("by_template_group", (dict,)),
            ("passed_all_checks", (bool,)),
        ),
    )

    # Closed key sets, so a consumer indexes them without an existence check and
    # a report with no CRITICAL finding differs from one with two only in a
    # number.
    assert sorted(summary["by_finding_type"]) == sorted(FINDING_TYPE_VALUES)
    assert sorted(summary["by_severity"]) == sorted(SEVERITY_VALUES)
    assert sorted(summary["by_source"]) == sorted(SOURCE_VALUES)
    assert sorted(summary["by_template_group"]) == sorted(TEMPLATE_GROUP_KEYS)

    assert summary["total"] == len(findings), "{0}: total disagrees with findings".format(where)
    for key in SUMMING_COUNT_KEYS:
        assert sum(summary[key].values()) == summary["total"], (
            "{0}.summary.{1}: sums to {2}, expected {3}".format(
                where, key, sum(summary[key].values()), summary["total"]
            )
        )

    for value, count in summary["by_finding_type"].items():
        assert count == len([f for f in findings if f["FindingType"] == value])
    for value, count in summary["by_severity"].items():
        assert count == len([f for f in findings if f["Severity"] == value])
    for value, count in summary["by_source"].items():
        assert count == len([f for f in findings if value in f["Source"]]), (
            "{0}.summary.by_source[{1!r}] disagrees with the findings".format(
                where, value
            )
        )

    synthesized = report["target"]["cdk"]["synthesized_templates"]
    from_synthesized = [f for f in findings if f["Location"]["File"] in synthesized]
    assert summary["by_template_group"]["synthesized"] == len(from_synthesized)
    assert summary["by_template_group"]["standalone"] == len(findings) - len(
        from_synthesized
    )

    # Requirement 7 AC16: about findings, not about errors. A run in which a tool
    # was unavailable and nothing was found still passed the checks it ran.
    assert summary["passed_all_checks"] is (summary["total"] == 0)


def finding_identities(report: Dict[str, Any]) -> List[Tuple[Any, ...]]:
    """Each Finding reduced to what does not depend on the Template's file.

    Used to compare a review of a Template against a review of the same Template
    in the other serialization: everything except where the bytes were.
    """
    return sorted(
        (
            entry["Resource"],
            entry["Normalized_Category"],
            entry["FindingType"],
            entry["Severity"],
            entry["Confidence"],
            tuple(entry["Source"]),
            entry["Finding"],
            tuple(sorted(str(e["RuleId"]) for e in entry["Evidence"])),
        )
        for entry in report["findings"]
    )


def describe(report: Dict[str, Any]) -> str:
    """Render a report's findings and errors for an assertion message."""
    lines = [
        "{0} {1} {2} {3}: {4}".format(
            entry["Severity"],
            entry["FindingType"],
            ",".join(entry["Source"]),
            entry["Resource"],
            entry["Finding"],
        )
        for entry in report["findings"]
    ]
    lines.extend(
        "error {0}: {1}".format(entry["error_class"], entry["message"])
        for entry in report["errors"]
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# The transcription above, held to the shipped definitions
# ---------------------------------------------------------------------------


def test_the_transcribed_schema_matches_the_shipped_definitions() -> None:
    """The independent schema description and the implementation's must agree.

    Without this, the checks in this module could drift into describing a schema
    the plugin no longer emits -- and would then pass while asserting nothing
    about the real contract. With it, a change to either side is a failure here
    that names what moved, and the fix is to change both plus
    ``docs/finding-schema.md``.
    """
    assert tuple(name for name, _ in FINDING_FIELD_TYPES) == FINDING_FIELDS
    assert tuple(name for name, _ in LOCATION_FIELD_TYPES) == LOCATION_FIELDS
    assert tuple(name for name, _ in EVIDENCE_FIELD_TYPES) == EVIDENCE_FIELDS

    assert FINDING_TYPE_VALUES == FINDING_TYPES
    assert SEVERITY_VALUES == SEVERITIES
    assert CONFIDENCE_VALUES == CONFIDENCES
    assert SOURCE_VALUES == SOURCES

    assert ENVELOPE_KEYS == REPORT_KEYS
    assert SUMMARY_FIELD_KEYS == SUMMARY_KEYS
    assert TOOL_ENTRY_KEYS == TOOL_KEYS

    assert len(FINDING_FIELD_TYPES) == 13


# ---------------------------------------------------------------------------
# The pipeline: three Templates, one review each
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", CASE_NAMES)
def test_the_pipeline_reviews_every_template_and_exits_zero(
    case: str, pipeline_runs: Dict[str, PipelineRun]
) -> None:
    """Requirement 12 AC2: the full pipeline runs over each sample Template.

    Exit 0 regardless of which external tools are installed: the IAM detectors
    need none, so at least one Source always reviews the Template. A tool that is
    missing is reported in ``errors[]`` and does not fail the review
    (Requirement 4 AC12, Requirement 5 AC6).
    """
    run = pipeline_runs[case]

    assert run.completed.returncode == exitcodes.OK, run.completed.stderr
    assert "Traceback" not in run.completed.stderr, run.completed.stderr

    classes = {entry["error_class"] for entry in run.report["errors"]}
    unexplained = classes - run.expected_error_classes - TOOL_ERROR_CLASSES
    assert not unexplained, "{0}: unexpected errors:\n{1}".format(
        case, describe(run.report)
    )

    for entry in run.report["errors"]:
        if entry["error_class"] != "tool_unavailable":
            continue
        # An absent tool is the only thing this class may report here, so the
        # tool it names has to be genuinely missing from PATH.
        assert entry["tool"] in TOOL_BY_SOURCE, entry
        assert shutil.which(entry["tool"]) is None, entry
        assert entry["remediation"], entry


@pytest.mark.parametrize("case", CASE_NAMES)
def test_the_report_envelope_has_the_declared_shape(
    case: str, pipeline_runs: Dict[str, PipelineRun]
) -> None:
    """The seven top-level keys, their types, and the error entry contract."""
    run = pipeline_runs[case]
    report = run.report

    assert_fields(
        case,
        report,
        (
            ("schema_version", (str,)),
            ("target", (dict,)),
            ("sources_enabled", (list,)),
            ("tools", (list,)),
            ("findings", (list,)),
            ("errors", (list,)),
            ("summary", (dict,)),
        ),
    )
    assert report["schema_version"] == SCHEMA_VERSION

    assert_fields("{0}.target".format(case), report["target"], (("files", (list,)), ("cdk", (dict,))))
    assert_fields(
        "{0}.target.cdk".format(case),
        report["target"]["cdk"],
        (("detected", (bool,)), ("synthesized_templates", (list,))),
    )

    assert report["sources_enabled"], "a review with no source enabled is never meant"
    for index, source in enumerate(report["sources_enabled"]):
        assert_enum("{0}.sources_enabled[{1}]".format(case, index), source, SOURCE_VALUES)

    for index, tool in enumerate(report["tools"]):
        prefix = "{0}.tools[{1}]".format(case, index)
        assert_fields(
            prefix, tool, (("name", (str,)), ("available", (bool,)), ("version", (str, NULL)))
        )
        # A tool that is not on PATH cannot have been used, whatever else the
        # version check decided.
        if shutil.which(tool["name"]) is None:
            assert tool["available"] is False, prefix
        if not tool["available"]:
            assert tool["version"] is None, prefix

    for index, entry in enumerate(report["errors"]):
        prefix = "{0}.errors[{1}]".format(case, index)
        # A fixed key set: report consumers index these without existence checks.
        assert sorted(entry) == sorted(STRUCTURED_ERROR_KEYS), prefix
        assert isinstance(entry["error_class"], str) and entry["error_class"], prefix
        assert isinstance(entry["message"], str) and entry["message"], prefix
        assert isinstance(entry["stderr_head"], list), prefix
        assert len(entry["stderr_head"]) <= 5, prefix


@pytest.mark.parametrize("case", CASE_NAMES)
def test_every_finding_satisfies_the_finding_schema(
    case: str,
    pipeline_runs: Dict[str, PipelineRun],
    permitted_categories: Tuple[str, ...],
) -> None:
    """Requirement 12 AC2: all 13 fields present, of the declared types.

    Checked against this module's transcription of the schema rather than through
    ``iacreview.finding.from_dict`` -- see the module docstring on why validating
    output with the code that produced it proves less than it appears to.
    """
    report = pipeline_runs[case].report
    findings = report["findings"]

    for index, finding in enumerate(findings):
        assert_finding_conforms(
            finding,
            where="{0}.findings[{1}]".format(case, index),
            categories=permitted_categories,
        )

    # Requirement 7 AC1: the ID is a position in this report, so the sequence has
    # to be exactly 1..n for the numbering to mean anything.
    assert [entry["ID"] for entry in findings] == list(range(1, len(findings) + 1))


@pytest.mark.parametrize("case", CASE_NAMES)
def test_the_summary_counts_agree_with_the_findings(
    case: str, pipeline_runs: Dict[str, PipelineRun]
) -> None:
    """Requirement 7 AC16, AC17, on the document a consumer receives.

    ``tests/unit/test_report.py`` establishes these invariants for
    ``build_report``; the question here is whether the assembled report that
    reached stdout is self-consistent.
    """
    assert_summary_agrees_with_findings(pipeline_runs[case].report, where=case)


@pytest.mark.parametrize("case", CASE_NAMES)
def test_every_reported_location_names_a_template_that_was_reviewed(
    case: str, pipeline_runs: Dict[str, PipelineRun]
) -> None:
    """Requirement 16 AC11: relative paths only, and no host path on stdout."""
    run = pipeline_runs[case]
    report = run.report

    reviewed = set(report["target"]["files"]) | set(
        report["target"]["cdk"]["synthesized_templates"]
    )
    for entry in report["findings"]:
        path = entry["Location"]["File"]
        assert path in reviewed, "{0}: {1} is not among the reviewed templates {2}".format(
            case, path, sorted(reviewed)
        )

    for path in reviewed:
        assert not Path(path).is_absolute(), path
        assert ".." not in Path(path).parts, path
        assert "\\" not in path, path
        assert (run.workspace / path).is_file(), path

    assert str(run.workspace) not in run.completed.stdout
    assert str(PLUGIN_ROOT) not in run.completed.stdout


# ---------------------------------------------------------------------------
# The cases the schema check needs data from
# ---------------------------------------------------------------------------


def test_the_lambda_example_gives_the_schema_check_something_to_check(
    pipeline_runs: Dict[str, PipelineRun]
) -> None:
    """A schema check over an empty findings array asserts nothing.

    ``lambda-with-role`` is the one example that produces a finding -- its
    documented trust policy finding, pinned detection by detection in
    ``tests/integration/test_examples.py``. Here only its existence matters, so
    that the per-field checks above are known to have run on real output.
    """
    report = pipeline_runs["lambda-with-role"].report

    assert report["findings"], describe(report)
    assert report["summary"]["total"] >= 1
    assert report["summary"]["passed_all_checks"] is False


def test_the_clean_example_produces_a_well_formed_empty_report(
    pipeline_runs: Dict[str, PipelineRun]
) -> None:
    """The other end of the schema: an empty findings array is still a report.

    Which findings ``minimal-s3`` should produce, and why the answer is none, is
    ``test_examples.py``'s subject. What matters here is that a report with
    nothing in it still carries every summary key, so a consumer reads it the
    same way as any other.
    """
    report = pipeline_runs["minimal-s3"].report

    assert report["findings"] == [], describe(report)
    assert report["summary"]["total"] == 0
    assert report["summary"]["passed_all_checks"] is True
    assert sorted(report["summary"]) == sorted(SUMMARY_FIELD_KEYS)


@requires_cfn_lint
@requires_cfn_guard
def test_a_full_review_of_a_clean_example_needs_no_degraded_source(
    pipeline_runs: Dict[str, PipelineRun]
) -> None:
    """With every tool installed, a clean example reports nothing at all.

    The one case that requires the external tools: it is the only way to tell
    "every Source ran and found nothing" from "the Sources that ran found
    nothing". Skipped rather than failed where a tool is absent (Requirement 15
    AC4).
    """
    report = pipeline_runs["minimal-s3"].report

    assert report["errors"] == [], describe(report)
    assert report["findings"] == [], describe(report)
    assert [tool["available"] for tool in report["tools"]] == [True, True]
    assert report["target"]["files"] == [MINIMAL_S3]


# ---------------------------------------------------------------------------
# The synthesized Template: the third pipeline path
# ---------------------------------------------------------------------------


def test_the_synthesized_template_is_reviewed_as_synthesized_output(
    pipeline_runs: Dict[str, PipelineRun]
) -> None:
    """Requirement 8 AC1, AC5, AC10 as ``examples/cdk-synth-output`` documents it.

    A directory holding a ``cdk.json`` and a ``cdk.out/`` is reviewed without
    ``--confirm-cdk-synth``: the templates already synthesized are read, the
    skipped synthesis is recorded, and the exit code stays 0 because narrower
    coverage is not a failed review.
    """
    run = pipeline_runs["synthesized-cdk"]
    report = run.report
    expected = "{0}/{1}{2}".format(
        cdk.CDK_OUTPUT_DIRECTORY_NAME,
        SYNTHESIZED_STACK_NAME,
        cdk.SYNTHESIZED_TEMPLATE_SUFFIX,
    )

    assert report["target"]["cdk"]["detected"] is True
    assert report["target"]["cdk"]["synthesized_templates"] == [expected]
    assert report["target"]["files"] == []
    assert report["summary"]["by_template_group"]["standalone"] == 0
    assert report["summary"]["by_template_group"]["synthesized"] == report["summary"]["total"]

    skipped = [
        entry
        for entry in report["errors"]
        if entry["error_class"] == "invalid_arguments"
    ]
    assert len(skipped) == 1, describe(report)
    assert "cdk synth" in skipped[0]["message"]
    assert skipped[0]["remediation"]


def test_the_two_serializations_of_one_template_attract_the_same_findings(
    pipeline_runs: Dict[str, PipelineRun]
) -> None:
    """A finding is about infrastructure, not about how it was written down.

    The synthesized Template is ``examples/lambda-with-role/template.yaml``'s
    document as JSON, read by the other parser, discovered by a directory walk
    instead of named, and counted in the other Template group. None of that is
    something a review should be able to notice, so the two runs must produce the
    same findings once the file they point at is set aside.

    Both runs saw the same tools, so this holds whether or not cfn-lint and
    cfn-guard are installed.
    """
    yaml_report = pipeline_runs["lambda-with-role"].report
    json_report = pipeline_runs["synthesized-cdk"].report

    assert finding_identities(json_report) == finding_identities(yaml_report), (
        "YAML:\n{0}\n\nJSON:\n{1}".format(describe(yaml_report), describe(json_report))
    )
    assert json_report["summary"]["total"] == yaml_report["summary"]["total"]
    assert json_report["summary"]["by_severity"] == yaml_report["summary"]["by_severity"]
    assert json_report["summary"]["by_source"] == yaml_report["summary"]["by_source"]


# ---------------------------------------------------------------------------
# Subprocess coverage wiring
# ---------------------------------------------------------------------------


def test_a_child_process_inherits_the_coverage_environment(
    subprocess_coverage: Dict[str, str]
) -> None:
    """The entry point's lines are counted only if the child measures itself.

    ``tests/conftest.py`` decides what a child needs; this holds the runner in
    this module to passing all of it on. Meaningful in both directions: outside a
    ``--cov`` run the fixture is empty and the assertion is trivially true, which
    is correct -- there is no measurement for the child to join.
    """
    env = child_environment(subprocess_coverage)

    for name, value in subprocess_coverage.items():
        assert env[name] == value, name


def test_the_coverage_configuration_is_named_for_child_processes(
    subprocess_coverage: Dict[str, str]
) -> None:
    """``COVERAGE_PROCESS_START`` is set, and names a real configuration file.

    Skipped outside a measured run: there is nothing to configure then, and
    setting the variable anyway would ask an unrelated child process to start
    writing coverage data.
    """
    if not subprocess_coverage:
        pytest.skip("coverage is not being measured in this session")

    configured = os.environ.get("COVERAGE_PROCESS_START")
    assert configured, "the subprocess coverage wiring did not set the variable"
    assert Path(configured).is_file(), configured
    assert configured in child_environment(subprocess_coverage).values()
