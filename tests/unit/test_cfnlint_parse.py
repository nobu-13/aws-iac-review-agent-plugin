"""Field-by-field tests of the cfn-lint JSON -> Finding mapping.

Requirement 12 AC9 asks for tests that validate *all* parser output field
mappings between cfn-lint's JSON and the normalized Finding. That is what
:data:`FIELD_CASES` is: every fixture in ``tests/fixtures/tool_output/`` is
parsed, normalized, and then each of the 13 Finding fields is asserted
individually, so a regression names the field it broke instead of dumping two
dataclasses side by side.

The fixtures also carry the cases that only appear in real cfn-lint output and
are easy to get wrong:

``cfnlint_error.json``
    A resource-level ``E3002`` (HIGH: its mapping entry says it does not block
    deployment) next to a template-level ``E0000`` (CRITICAL via the ``E0``
    prefix, ``Resource`` ``None``, position reported as line 0).
``cfnlint_warning.json``
    ``W3037``, whose mapping override makes it ``Security`` / ``IAM`` with
    maintainer-written wording, next to a plain ``W3011`` that keeps cfn-lint's
    own wording.
``cfnlint_informational.json``
    A full ``I3013`` -- reachable only because the Source always passes ``-c I``
    (Requirement 4 AC8) -- next to a result carrying nothing but a level and an
    unknown rule ID, which exercises every fallback at once.
``cfnlint_empty.json`` / ``cfnlint_malformed.json``
    A clean template, and stdout that is not JSON at all.

Nothing here needs cfn-lint installed. The tests that do exercise
:func:`iacreview.cfnlint.run_and_normalize` end to end put a fake ``cfn-lint`` on
``PATH``, so they behave the same whether or not the real one is present.
"""

from __future__ import annotations

import dataclasses
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from iacreview import categories, finding
from iacreview.cfnlint import (
    NO_MESSAGE_TEXT,
    RECOMMENDATION_FALLBACK,
    SOURCE_NAME,
    STATS_KEYS,
    WHY_IT_MATTERS_FALLBACK,
    build_argv,
    finding_from_result,
    initial_stats,
    normalize_results,
    parse_output,
    run_and_normalize,
)
from iacreview.errors import TemplateParseError
from iacreview.finding import FINDING_FIELDS, UNASSIGNED_ID, to_dict
from iacreview.source import SourceResult, workspace_relative

TOOL_OUTPUT = Path(__file__).resolve().parents[1] / "fixtures" / "tool_output"

#: Workspace-relative path the fixtures report as ``Filename``.
FIXTURE_FILE = "templates/app.yaml"

#: Passed to the normalizer as the reviewed Template. Deliberately different
#: from :data:`FIXTURE_FILE` so a test can tell whether ``Location.File`` came
#: from cfn-lint's ``Filename`` or from the fallback.
REVIEWED_FILE = "templates/reviewed.yaml"

RULES_DOC = (
    "https://github.com/aws-cloudformation/cfn-lint/blob/main/docs/rules.md#"
)


def load_fixture(name: str) -> str:
    """Return the raw text of a tool output fixture, as captured stdout would be."""
    return (TOOL_OUTPUT / name).read_text(encoding="utf-8")


def normalize_fixture(name: str) -> List[finding.Finding]:
    """Parse and normalize one fixture with the bundled category mapping."""
    return normalize_results(
        parse_output(load_fixture(name)), template_file=REVIEWED_FILE
    )


def evidence(detail: str, rule_id: str) -> List[Dict[str, Any]]:
    """One Evidence entry as :func:`iacreview.finding.to_dict` renders it."""
    return [
        {
            "Source": SOURCE_NAME,
            "Detail": detail,
            "RuleId": rule_id,
            "Excerpt": None,
        }
    ]


def location(
    file: str,
    line: Optional[int],
    column: Optional[int],
    template_path: Optional[List[Any]],
) -> Dict[str, Any]:
    """One Location as :func:`iacreview.finding.to_dict` renders it."""
    return {
        "File": file,
        "Line": line,
        "Column": column,
        "TemplatePath": template_path,
    }


# ---------------------------------------------------------------------------
# The complete field mapping, one entry per result in the fixtures
# ---------------------------------------------------------------------------

E3002_EXPECTED: Dict[str, Any] = {
    "ID": UNASSIGNED_ID,
    "Normalized_Category": "TemplateQuality",
    "FindingType": "Validity",
    "Severity": "HIGH",
    "Confidence": "Confirmed",
    "Source": ["cfn-lint"],
    "Resource": "AppBucket",
    "Location": location(
        FIXTURE_FILE, 24, 7, ["Resources", "AppBucket", "Properties", "BucketName"]
    ),
    "Finding": "[E3002] Property BucketName should be of type String",
    "WhyItMatters": "Resource properties are invalid",
    "Evidence": evidence(
        "cfn-lint reported E3002 at Error level: Property BucketName should be "
        "of type String Reference: " + RULES_DOC + "E3002",
        "E3002",
    ),
    "Recommendation": "Making sure that resources properties are properly configured",
    "SuggestedRemediation": None,
}

E0000_EXPECTED: Dict[str, Any] = {
    "ID": UNASSIGNED_ID,
    "Normalized_Category": "TemplateQuality",
    "FindingType": "Validity",
    # The E0 prefix is recorded as deployment-blocking, and the level is Error,
    # so the HIGH default is promoted (Requirement 4 AC5, Requirement 7 AC6).
    "Severity": "CRITICAL",
    "Confidence": "Confirmed",
    "Source": ["cfn-lint"],
    # An empty Location.Path is a template-level finding, not resource "".
    "Resource": None,
    # cfn-lint reports line 0 when it cannot place the finding; the schema
    # expresses that as no position at all.
    "Location": location(FIXTURE_FILE, None, None, []),
    "Finding": "[E0000] Template format error: unsupported structure",
    "WhyItMatters": "Parsing error found when parsing the template",
    "Evidence": evidence(
        "cfn-lint reported E0000 at Error level: Template format error: "
        "unsupported structure Reference: " + RULES_DOC + "E0000",
        "E0000",
    ),
    "Recommendation": "Checks for JSON/YAML formatting errors in your template",
    "SuggestedRemediation": None,
}

W3037_EXPECTED: Dict[str, Any] = {
    "ID": UNASSIGNED_ID,
    # All four of these come from the mapping file's override, not from the
    # level defaults: category IAM, security_relevant -> Security, and the two
    # maintainer-written texts.
    "Normalized_Category": "IAM",
    "FindingType": "Security",
    "Severity": "MEDIUM",
    "Confidence": "Confirmed",
    "Source": ["cfn-lint"],
    "Resource": "AppRole",
    "Location": location(
        FIXTURE_FILE,
        61,
        11,
        [
            "Resources",
            "AppRole",
            "Properties",
            "Policies",
            0,
            "PolicyDocument",
            "Statement",
            0,
            "Action",
        ],
    ),
    "Finding": "[W3037] IAM action s3:GetObjectss does not exist",
    "WhyItMatters": (
        "An invalid or malformed IAM action prevents the policy from granting "
        "the intended access, or grants access that was not intended."
    ),
    "Evidence": evidence(
        "cfn-lint reported W3037 at Warning level: IAM action s3:GetObjectss "
        "does not exist Reference: " + RULES_DOC + "W3037",
        "W3037",
    ),
    "Recommendation": "Correct the IAM action name to a valid service action.",
    "SuggestedRemediation": None,
}

W3011_EXPECTED: Dict[str, Any] = {
    "ID": UNASSIGNED_ID,
    "Normalized_Category": "TemplateQuality",
    "FindingType": "BestPractice",
    "Severity": "MEDIUM",
    "Confidence": "Confirmed",
    "Source": ["cfn-lint"],
    "Resource": "AppBucket",
    "Location": location(FIXTURE_FILE, 12, 5, ["Resources", "AppBucket"]),
    "Finding": (
        "[W3011] Specifying an explicit name prevents updates that require "
        "replacement"
    ),
    "WhyItMatters": "Check DeletionPolicy on resources",
    "Evidence": evidence(
        "cfn-lint reported W3011 at Warning level: Specifying an explicit name "
        "prevents updates that require replacement Reference: "
        + RULES_DOC
        + "W3011",
        "W3011",
    ),
    "Recommendation": "Ensure resources have a DeletionPolicy when appropriate",
    "SuggestedRemediation": None,
}

I3013_EXPECTED: Dict[str, Any] = {
    "ID": UNASSIGNED_ID,
    "Normalized_Category": "TemplateQuality",
    "FindingType": "Informational",
    "Severity": "LOW",
    "Confidence": "Confirmed",
    "Source": ["cfn-lint"],
    "Resource": "AppBucket",
    "Location": location(FIXTURE_FILE, 12, 5, ["Resources", "AppBucket"]),
    "Finding": "[I3013] Consider adding a DeletionPolicy to this stateful resource",
    "WhyItMatters": (
        "Check resources with UpdateReplacePolicy/DeletionPolicy have both"
    ),
    "Evidence": evidence(
        "cfn-lint reported I3013 at Informational level: Consider adding a "
        "DeletionPolicy to this stateful resource Reference: "
        + RULES_DOC
        + "I3013",
        "I3013",
    ),
    "Recommendation": (
        "The default action when replacing/removing a resource is to delete it"
    ),
    "SuggestedRemediation": None,
}

#: A result with nothing but a level and a rule ID the mapping file has never
#: seen. Every optional field falls back, and no fallback is empty: the schema
#: requires text in Finding, WhyItMatters, Recommendation and Evidence.Detail.
I9999_EXPECTED: Dict[str, Any] = {
    "ID": UNASSIGNED_ID,
    "Normalized_Category": "TemplateQuality",
    "FindingType": "Informational",
    "Severity": "LOW",
    "Confidence": "Confirmed",
    "Source": ["cfn-lint"],
    "Resource": None,
    # No Location at all in the payload: no position, and no TemplatePath, which
    # is None rather than [] because cfn-lint stated nothing either way.
    "Location": location(FIXTURE_FILE, None, None, None),
    "Finding": "[I9999] " + NO_MESSAGE_TEXT,
    "WhyItMatters": WHY_IT_MATTERS_FALLBACK.format(
        level="Informational", finding_type="Informational", severity="LOW"
    ),
    "Evidence": evidence(
        "cfn-lint reported I9999 at Informational level: " + NO_MESSAGE_TEXT,
        "I9999",
    ),
    "Recommendation": RECOMMENDATION_FALLBACK.format(rule_id="I9999"),
    "SuggestedRemediation": None,
}

#: ``(case id, fixture, index within the fixture, expected 13 fields)``.
MAPPING_CASES = [
    ("E3002", "cfnlint_error.json", 0, E3002_EXPECTED),
    ("E0000", "cfnlint_error.json", 1, E0000_EXPECTED),
    ("W3037", "cfnlint_warning.json", 0, W3037_EXPECTED),
    ("W3011", "cfnlint_warning.json", 1, W3011_EXPECTED),
    ("I3013", "cfnlint_informational.json", 0, I3013_EXPECTED),
    ("I9999", "cfnlint_informational.json", 1, I9999_EXPECTED),
]

#: One parameter per (case, Finding field): 6 cases x 13 fields.
FIELD_CASES = [
    pytest.param(
        fixture, index, field_name, expected[field_name], id="{0}-{1}".format(case, field_name)
    )
    for case, fixture, index, expected in MAPPING_CASES
    for field_name in FINDING_FIELDS
]


@pytest.mark.parametrize(("fixture", "index", "field_name", "value"), FIELD_CASES)
def test_field_mapping(
    fixture: str, index: int, field_name: str, value: Any
) -> None:
    """Each of the 13 Finding fields matches the design's field table."""
    produced = to_dict(normalize_fixture(fixture)[index])
    assert produced[field_name] == value


def test_every_finding_field_is_covered() -> None:
    """The parametrization spans all 13 fields, so none is silently untested."""
    assert len(FINDING_FIELDS) == 13
    assert set(E3002_EXPECTED) == set(FINDING_FIELDS)


@pytest.mark.parametrize(("case", "fixture", "index", "expected"), MAPPING_CASES)
def test_whole_finding_matches(
    case: str, fixture: str, index: int, expected: Dict[str, Any]
) -> None:
    """No extra or missing keys beyond the 13 asserted above."""
    assert to_dict(normalize_fixture(fixture)[index]) == expected


# ---------------------------------------------------------------------------
# Schema conformance of what the mapping produces
# ---------------------------------------------------------------------------


@pytest.fixture()
def blocks_deployment_resolver() -> Any:
    """Install the mapping file's ``blocks_deployment`` resolver on the schema.

    Without it, :func:`iacreview.finding.validate` cannot check Requirement 7
    AC6 and lets ``Validity`` + ``CRITICAL`` stand. Installing it makes the
    ``E0000`` case prove that the promotion is backed by the mapping file rather
    than merely unchallenged.
    """
    finding.set_blocks_deployment_resolver(categories.load_map().blocks_deployment)
    yield
    finding.set_blocks_deployment_resolver(None)


@pytest.mark.parametrize(("case", "fixture", "index", "expected"), MAPPING_CASES)
def test_findings_pass_schema_validation_once_an_id_is_assigned(
    case: str,
    fixture: str,
    index: int,
    expected: Dict[str, Any],
    blocks_deployment_resolver: Any,
) -> None:
    """A normalized Finding is schema-legal as soon as the report assigns an ID.

    The Source leaves ``ID`` unassigned on purpose (IDs are sequential over the
    sorted report), which is the only reason ``validate`` cannot be called on the
    Finding as returned.
    """
    produced = normalize_fixture(fixture)[index]
    assert produced.ID == UNASSIGNED_ID
    finding.validate(dataclasses.replace(produced, ID=1))


# ---------------------------------------------------------------------------
# Empty and malformed output
# ---------------------------------------------------------------------------


def test_empty_output_yields_no_findings() -> None:
    """A clean template is zero findings, not an error (Requirement 4 AC13)."""
    assert parse_output(load_fixture("cfnlint_empty.json")) == []
    assert normalize_fixture("cfnlint_empty.json") == []


def test_malformed_output_is_a_parse_failure() -> None:
    """Truncated stdout discards the payload and reports ``parse_failure``."""
    with pytest.raises(TemplateParseError) as caught:
        parse_output(load_fixture("cfnlint_malformed.json"))
    error = caught.value
    assert error.error_class == "parse_failure"
    assert error.error_type == "JSONDecodeError"
    assert error.tool == "cfn-lint"
    assert error.line is not None and error.column is not None


# ---------------------------------------------------------------------------
# Location.File normalization
# ---------------------------------------------------------------------------


def _one_result(filename: Optional[str]) -> Any:
    raw = [
        {
            "Level": "Warning",
            "Message": "m",
            "Rule": {"Id": "W3011"},
        }
    ]
    if filename is not None:
        raw[0]["Filename"] = filename
    return parse_output(json.dumps(raw))[0]


def test_absolute_filename_inside_the_workspace_is_relativized(
    tmp_path: Path,
) -> None:
    """An absolute path never reaches the report (Requirement 16 AC11)."""
    produced = finding_from_result(
        _one_result(str(tmp_path / "templates" / "app.yaml")),
        template_file=REVIEWED_FILE,
        workspace_root=tmp_path,
    )
    assert produced.Location.File == "templates/app.yaml"


@pytest.mark.parametrize(
    "filename",
    [
        "/elsewhere/app.yaml",  # absolute, outside the workspace
        "../outside/app.yaml",  # climbs out of the workspace
        "",  # reported, but empty
        None,  # not reported at all
    ],
)
def test_unusable_filename_falls_back_to_the_reviewed_template(
    filename: Optional[str], tmp_path: Path
) -> None:
    """cfn-lint ran against one Template, so that Template is the safe answer."""
    produced = finding_from_result(
        _one_result(filename),
        template_file=REVIEWED_FILE,
        workspace_root=tmp_path,
    )
    assert produced.Location.File == REVIEWED_FILE


def test_workspace_relative_normalizes_separators(tmp_path: Path) -> None:
    """Output uses ``/`` regardless of the host, so reports compare byte for byte."""
    assert (
        workspace_relative(str(tmp_path / "a" / "b.yaml"), tmp_path) == "a/b.yaml"
    )
    assert workspace_relative("./a/b.yaml", tmp_path) == "a/b.yaml"


# ---------------------------------------------------------------------------
# The invocation
# ---------------------------------------------------------------------------


def test_build_argv_is_the_fixed_command() -> None:
    assert build_argv("templates/app.yaml") == [
        "cfn-lint",
        "-f",
        "json",
        "-c",
        "I",
        "--",
        "templates/app.yaml",
    ]


def test_build_argv_enables_informational_rules() -> None:
    """Requirement 4 AC8: without ``-c I`` the Informational mapping is dead code."""
    argv = build_argv("t.yaml")
    assert argv[argv.index("-c") + 1] == "I"


def test_build_argv_leaves_the_exit_code_threshold_at_its_default() -> None:
    """``--non-zero-exit-code`` would invalidate the exit status decoding."""
    assert "--non-zero-exit-code" not in build_argv("t.yaml")


def test_build_argv_puts_the_template_last_behind_a_terminator() -> None:
    """A filename starting with ``-`` can never be read as a flag."""
    argv = build_argv("-weird-name.yaml")
    assert argv[-2:] == ["--", "-weird-name.yaml"]


def test_build_argv_can_run_the_version_checked_binary() -> None:
    assert build_argv("t.yaml", executable="/opt/bin/cfn-lint")[0] == (
        "/opt/bin/cfn-lint"
    )


def test_initial_stats_carries_every_documented_key() -> None:
    stats = initial_stats()
    assert tuple(stats) == STATS_KEYS
    assert stats["informational_rules_enabled"] is True


# ---------------------------------------------------------------------------
# run_and_normalize
# ---------------------------------------------------------------------------


def _write_template(tmp_path: Path) -> Path:
    template = tmp_path / "templates" / "app.yaml"
    template.parent.mkdir(parents=True, exist_ok=True)
    template.write_text(
        "Resources:\n  AppBucket:\n    Type: AWS::S3::Bucket\n", encoding="utf-8"
    )
    return template


def _empty_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point ``PATH`` at a directory holding no tools, and return it."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("PATH", str(bin_dir))
    return bin_dir


def _fake_cfn_lint(
    bin_dir: Path,
    *,
    stdout: str = "[]",
    stderr: str = "",
    code: int = 0,
    sleep: float = 0.0,
    version: str = "cfn-lint 1.22.3",
) -> Path:
    """Install a fake ``cfn-lint`` that replays a fixed result.

    Written in Python and launched through an absolute interpreter path, so it
    needs nothing on ``PATH`` -- which matters because :mod:`iacreview.proc`
    hands the child a minimal environment.
    """
    script = bin_dir / "cfn-lint"
    script.write_text(
        "#!{interpreter}\n"
        "import sys, time\n"
        "if '--version' in sys.argv[1:]:\n"
        "    sys.stdout.write({version!r} + '\\n')\n"
        "    raise SystemExit(0)\n"
        "time.sleep({sleep!r})\n"
        "sys.stdout.write({stdout!r})\n"
        "sys.stderr.write({stderr!r})\n"
        "raise SystemExit({code!r})\n".format(
            interpreter=sys.executable,
            version=version,
            sleep=sleep,
            stdout=stdout,
            stderr=stderr,
            code=code,
        ),
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return script


def test_missing_tool_reports_one_error_and_no_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Requirement 4 AC10: name the tool and how to install it, and keep going."""
    template = _write_template(tmp_path)
    _empty_path(monkeypatch, tmp_path)

    result = run_and_normalize(template, workspace_root=tmp_path)

    assert isinstance(result, SourceResult)
    assert result.source == SOURCE_NAME
    assert result.findings == []
    assert len(result.errors) == 1
    error = result.errors[0]
    assert error["error_class"] == "tool_unavailable"
    assert error["source"] == SOURCE_NAME
    assert error["tool"] == "cfn-lint"
    assert error["required_min_version"] == "1.0.0"
    assert "pip install cfn-lint" in str(error["remediation"])
    assert tuple(result.stats) == STATS_KEYS
    # A standalone Skill exits 5 for an unavailable tool.
    assert result.exit_status() == 5


def test_findings_are_normalized_from_a_successful_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exit 2 means "Error findings reported", not "the tool failed"."""
    template = _write_template(tmp_path)
    _fake_cfn_lint(
        _empty_path(monkeypatch, tmp_path),
        stdout=load_fixture("cfnlint_error.json"),
        code=2,
    )

    result = run_and_normalize(template, workspace_root=tmp_path)

    assert result.errors == []
    assert [f.Evidence[0].RuleId for f in result.findings] == ["E3002", "E0000"]
    assert result.stats == {
        "tool_version": "1.22.3",
        "exit_code": 2,
        "results_parsed": 2,
        "rules_triggered": 2,
        "informational_rules_enabled": True,
    }
    assert result.exit_status() == 0


def test_clean_template_returns_an_empty_finding_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Requirement 4 AC13: zero findings, still attributed to cfn-lint."""
    template = _write_template(tmp_path)
    _fake_cfn_lint(_empty_path(monkeypatch, tmp_path), stdout="[]", code=0)

    result = run_and_normalize(template, workspace_root=tmp_path)

    assert result.source == SOURCE_NAME
    assert result.findings == []
    assert result.errors == []
    assert result.stats["exit_code"] == 0
    assert result.exit_status() == 0


def test_crash_is_reported_with_stderr_and_does_not_raise(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Requirement 4 AC12: exit 1 is an execution error, reported not raised."""
    template = _write_template(tmp_path)
    _fake_cfn_lint(
        _empty_path(monkeypatch, tmp_path),
        stdout="",
        stderr="Usage: cfn-lint [OPTIONS]\nboom\n",
        code=1,
    )

    result = run_and_normalize(template, workspace_root=tmp_path)

    assert result.findings == []
    assert len(result.errors) == 1
    error = result.errors[0]
    assert error["error_class"] == "tool_execution"
    assert error["exit_code"] == 1
    assert error["stderr_head"] == ["Usage: cfn-lint [OPTIONS]", "boom"]
    assert result.exit_status() == 6


def test_unknown_exit_status_still_reports_parsable_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """design.md's "その他" row: report the failure *and* what stdout yielded."""
    template = _write_template(tmp_path)
    _fake_cfn_lint(
        _empty_path(monkeypatch, tmp_path),
        stdout=load_fixture("cfnlint_warning.json"),
        stderr="unknown state\n",
        code=3,  # bit 0 is outside {2, 4, 8}
    )

    result = run_and_normalize(template, workspace_root=tmp_path)

    assert [f.Evidence[0].RuleId for f in result.findings] == ["W3037", "W3011"]
    assert [e["error_class"] for e in result.errors] == ["tool_execution"]
    assert result.stats["results_parsed"] == 2


def test_a_failed_run_with_unusable_stdout_reports_only_the_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing to salvage, and no second error about it.

    The exit status already said stdout is not evidence of anything, so a parse
    failure on that path adds no decision value the ``tool_execution`` error
    does not already carry.
    """
    template = _write_template(tmp_path)
    _fake_cfn_lint(
        _empty_path(monkeypatch, tmp_path),
        stdout=load_fixture("cfnlint_malformed.json"),
        stderr="crashed midway\n",
        code=1,
    )

    result = run_and_normalize(template, workspace_root=tmp_path)

    assert result.findings == []
    assert [e["error_class"] for e in result.errors] == ["tool_execution"]
    assert result.stats["results_parsed"] == 0
    assert result.exit_status() == 6


def test_output_structure_mismatch_discards_findings_and_exits_six(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unparsable stdout on a successful exit: ``parse_failure``, exit status 6.

    The error class stays ``parse_failure`` because that is what the report
    schema defines, while the *exit* code is 6 rather than the 4 that a
    template parse failure would use: here it is the tool's output that did not
    match, not the template.
    """
    template = _write_template(tmp_path)
    _fake_cfn_lint(
        _empty_path(monkeypatch, tmp_path),
        stdout=load_fixture("cfnlint_malformed.json"),
        code=2,
    )

    result = run_and_normalize(template, workspace_root=tmp_path)

    assert result.findings == []
    assert [e["error_class"] for e in result.errors] == ["parse_failure"]
    assert result.errors[0]["tool"] == "cfn-lint"
    assert result.exit_status() == 6


def test_timeout_is_reported_as_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hung tool is killed and reported; the pipeline is not blocked."""
    template = _write_template(tmp_path)
    _fake_cfn_lint(_empty_path(monkeypatch, tmp_path), sleep=5.0, code=0)
    # The real budget is 60 seconds; shortening it keeps the test quick without
    # changing the code path under test.
    monkeypatch.setattr("iacreview.cfnlint.TIMEOUT_S", 1)

    result = run_and_normalize(template, workspace_root=tmp_path)

    assert result.findings == []
    assert [e["error_class"] for e in result.errors] == ["tool_timeout"]
    assert result.exit_status() == 6


def test_a_template_outside_the_workspace_is_not_reviewed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A containment violation is raised, not folded into ``errors``.

    Reporting it as a Source error would claim a review happened on a file the
    plugin must not read.
    """
    from iacreview.errors import PathContainmentError

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.yaml"
    outside.write_text("Resources: {}\n", encoding="utf-8")
    _empty_path(monkeypatch, tmp_path)

    with pytest.raises(PathContainmentError):
        run_and_normalize(outside, workspace_root=workspace)


def test_the_fake_tool_receives_the_designed_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The argv that actually reaches the tool is the one design.md specifies."""
    template = _write_template(tmp_path)
    bin_dir = _empty_path(monkeypatch, tmp_path)
    recorded = tmp_path / "argv.json"
    script = bin_dir / "cfn-lint"
    script.write_text(
        "#!{interpreter}\n"
        "import json, sys\n"
        "if '--version' in sys.argv[1:]:\n"
        "    sys.stdout.write('cfn-lint 1.22.3\\n')\n"
        "    raise SystemExit(0)\n"
        "json.dump(sys.argv[1:], open({recorded!r}, 'w'))\n"
        "sys.stdout.write('[]')\n".format(
            interpreter=sys.executable, recorded=str(recorded)
        ),
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)

    run_and_normalize(template, workspace_root=tmp_path)

    argv = json.loads(recorded.read_text(encoding="utf-8"))
    assert argv[:5] == ["-f", "json", "-c", "I", "--"]
    assert Path(argv[5]) == template.resolve()
    assert os.path.isabs(argv[5])
