"""Unit tests for :mod:`iacreview.deltacli` (v1.1 Task 11).

* Argument checks before any input is read (exit 2, no stdout, no echo of the
  argument text): pairs, ``--declare`` rules, unknown Codes and ``all``,
  repeated options, empty / NUL / shell-metacharacter paths, other formats.
* Declarations recorded as ``declared_not_verified``; ``identifier_mode``.
* The Task 2 Template and Report fixtures through the CLI, against their
  hand-written expected values.
* Every row of the exit code table, and the order in which the first failure
  is chosen; one unanalyzable comparison does not hide the other.
* stdout holds the Delta_Report only; stderr holds built messages only, no
  traceback, no comparison summary, control and bidi characters replaced.
* Environment variables and stdin do not change the output bytes; no file is
  created; ``python3 -m iacreview.deltacli`` starts with ``PYTHONPATH``.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pytest

from iacreview import deltacli, deltareport, deltaschema, report, template
from iacreview.finding import Evidence, Finding, Location

REPO_ROOT = Path(__file__).resolve().parents[2]
DELTA = REPO_ROOT / "tests" / "fixtures" / "delta"
TEMPLATE_CASES = sorted(p.name for p in (DELTA / "templates").iterdir() if p.is_dir())
REPORT_CASES = sorted(p.name for p in (DELTA / "reports").iterdir() if p.is_dir())
ALL_REPORT_DECLARATIONS = [c for c in deltaschema.DECLARATION_CODES if c != "reports_match_templates"]

SIMPLE_BASE = "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n"
SIMPLE_HEAD = "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: CanaryBucketValue\n"


def _run(argv: Sequence[str]) -> Tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = deltacli.main(list(argv), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def _finding(text: str, resource: Optional[str], rule: str = "s3_bucket_encryption") -> Finding:
    return Finding(
        ID=0,
        Normalized_Category="Encryption",
        FindingType="Security",
        Severity="HIGH",
        Confidence="Confirmed",
        Source=["cfn-guard"],
        Resource=resource,
        Location=Location(File="base.yaml", TemplatePath=["Resources", resource or "X"]),
        Finding=text,
        WhyItMatters="CanaryWhy",
        Evidence=[Evidence(Source="cfn-guard", Detail="CanaryDetail", RuleId=rule)],
        Recommendation="CanaryRecommendation",
        SuggestedRemediation=None,
    )


def _report_text(findings: Sequence[Finding], files: Sequence[str] = ("base.yaml",)) -> str:
    meta = report.ReportMeta(
        files=tuple(files),
        sources_enabled=("cfn-lint", "cfn-guard", "IAM Review", "Network Review", "Secret Review", "Quality Review"),
        tools=(report.ToolStatus("cfn-guard", True, "3.2.1"), report.ToolStatus("cfn-lint", True, "1.46.0")),
    )
    return report.dump(report.build_report(list(findings), [], meta))


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "base.yaml").write_text(SIMPLE_BASE, encoding="utf-8")
    (tmp_path / "head.yaml").write_text(SIMPLE_HEAD, encoding="utf-8")
    (tmp_path / "base.json").write_text(_report_text([_finding("gone", "Bucket")]), encoding="utf-8")
    (tmp_path / "head.json").write_text(_report_text([]), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


TEMPLATES = ["--base-template", "base.yaml", "--head-template", "head.yaml"]
REPORTS = ["--base-report", "base.json", "--head-report", "head.json"]


def _declare(codes: Sequence[str]) -> List[str]:
    argv: List[str] = []
    for code in codes:
        argv += ["--declare", code]
    return argv


# ---------------------------------------------------------------------------
# Arguments (R1.1-R1.3, R2.2, R8.4)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--base-template", "missing.yaml"],
        ["--head-template", "missing.yaml"],
        ["--base-report", "missing.json"],
        ["--head-report", "missing.json"],
        ["--base-template", "a.yaml", "--head-template", "b.yaml", "--base-report", "a.json"],
        ["--base-template", "a.yaml", "--head-template", "b.yaml", "--declare", "reports_unmodified"],
        ["--base-report", "a.json", "--head-report", "b.json", "--declare", "reports_match_templates"],
        ["--base-report", "a.json", "--head-report", "b.json", "--declare", "all"],
        ["--base-report", "a.json", "--head-report", "b.json", "--declare", "CanaryUnknownCode"],
        ["--base-report", "a.json", "--head-report", "b.json", "--declare", "reports_unmodified,same_rule_set"],
        ["--base-template", "a.yaml", "--base-template", "c.yaml", "--head-template", "b.yaml"],
        ["--base-template", "a.yaml", "--head-template", "b.yaml", "--format", "markdown"],
        ["--base-template", "a.yaml", "--head-template", "b.yaml", "--format", "json", "--format", "json"],
        ["--base-template", "", "--head-template", "b.yaml"],
        ["--base-template", "a\x00.yaml", "--head-template", "b.yaml"],
        ["--base-template", "a;rm.yaml", "--head-template", "b.yaml"],
        ["--base-template", "$(id).yaml", "--head-template", "b.yaml"],
        ["--base-template", "a.yaml", "--head-template", "b|c.yaml"],
        ["--base-report", "a`x`.json", "--head-report", "b.json"],
        ["--base-template", "a.yaml", "--head-template", "b.yaml", "--CanaryUnknownOption"],
        ["CanaryPositional"],
    ],
)
def test_invalid_arguments_exit_2_before_reading(argv: List[str], workspace: Path) -> None:
    # None of the named files exist: reading one would give exit 3, not 2.
    code, out, err = _run(argv)
    assert code == 2
    assert out == ""
    assert err.startswith("deltacli: invalid_arguments: ")
    assert "Canary" not in err
    assert "Traceback" not in err


def test_help_goes_to_stderr(workspace: Path) -> None:
    code, out, err = _run(["--help"])
    assert code == 0 and out == ""
    assert "--plain-identifiers" in err and "--declare" in err


def test_declarations_are_recorded_not_verified(workspace: Path) -> None:
    code, out, _ = _run(TEMPLATES + REPORTS + _declare(["same_rule_set", "reports_unmodified", "same_rule_set"]))
    assert code == 0
    declarations = json.loads(out)["finding_delta"]["input_declarations"]
    assert declarations == {
        "declared": ["reports_unmodified", "same_rule_set"],
        "missing": [
            "same_plugin_version",
            "same_tool_configuration",
            "same_agent_findings_input",
            "reports_match_templates",
        ],
        "status": "declared_not_verified",
    }


def test_declarations_cannot_come_from_the_environment(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DELTA_DECLARE", ",".join(deltaschema.DECLARATION_CODES))
    monkeypatch.setenv("IACREVIEW_DECLARE", "all")
    _, out, _ = _run(REPORTS)
    built = json.loads(out)
    assert built["finding_delta"]["input_declarations"]["declared"] == []
    assert {e["classification"] for e in built["finding_delta"]["entries"]} == {"Unconfirmed"}


def test_resolved_needs_every_declaration(workspace: Path) -> None:
    _, out, _ = _run(REPORTS + _declare(ALL_REPORT_DECLARATIONS))
    assert [e["classification"] for e in json.loads(out)["finding_delta"]["entries"]] == ["Resolved"]
    _, out, _ = _run(REPORTS + _declare(ALL_REPORT_DECLARATIONS[:-1]))
    entry = json.loads(out)["finding_delta"]["entries"][0]
    assert entry["classification"] == "Unconfirmed"
    assert entry["missing_declarations"] == [ALL_REPORT_DECLARATIONS[-1]]


@pytest.mark.parametrize("flag, mode", [([], "anonymized"), (["--plain-identifiers"], "plain")])
def test_identifier_mode_is_recorded(flag: List[str], mode: str, workspace: Path) -> None:
    code, out, _ = _run(TEMPLATES + flag)
    assert code == 0
    built = json.loads(out)
    assert built["identifier_mode"] == mode
    bucket = built["semantic_diff"]["changes"][0]["path"][1]
    assert (bucket == "Bucket") == (mode == "plain")
    assert "CanaryBucketValue" not in out


def test_modes_template_only_report_only_and_both(workspace: Path) -> None:
    _, out, _ = _run(TEMPLATES)
    built = json.loads(out)
    assert built["semantic_diff"] is not None and built["finding_delta"] is None
    _, out, _ = _run(REPORTS)
    built = json.loads(out)
    assert built["semantic_diff"] is None and built["finding_delta"] is not None
    assert built["finding_delta"]["template_report_correspondence"] == "not_applicable"
    _, out, _ = _run(TEMPLATES + REPORTS)
    built = json.loads(out)
    assert built["semantic_diff"] is not None and built["finding_delta"] is not None
    assert built["inputs"]["base"]["template"] == {"path": "base.yaml", "format": "yaml"}
    assert built["inputs"]["head"]["report"]["path"] == "head.json"
    raw = (workspace / "head.json").read_bytes()
    assert built["inputs"]["head"]["report"]["sha256"] == hashlib.sha256(raw).hexdigest()


def test_absolute_path_inside_the_workspace_is_written_relative(workspace: Path) -> None:
    _, out, _ = _run(["--base-template", str(workspace / "base.yaml"), "--head-template", "head.yaml"])
    built = json.loads(out)
    assert built["inputs"]["base"]["template"]["path"] == "base.yaml"
    assert str(workspace) not in out


# ---------------------------------------------------------------------------
# --reviewed-template-path (R1.1, R1.3, R8.6; H-M1-1 approved, Design 8-2, 9-4)
#
# Expected, written before the implementation: the declaration is accepted
# only with both pairs and once; it is checked before any input is read; an
# empty / NUL / shell-metacharacter / absolute / drive / ``..`` value, or one
# that leaves the workspace through an existing symlink, exits 2 with no
# stdout and without echoing the argument; a path that does not exist is
# accepted. It is recorded as ``{path, status: declared_not_verified}`` after
# ``report.normalize_output_path``; without it the value is ``null``.
# ---------------------------------------------------------------------------

DECLARED = "--reviewed-template-path"


@pytest.mark.parametrize(
    "argv",
    [
        TEMPLATES + [DECLARED, "base.yaml"],
        REPORTS + [DECLARED, "base.yaml"],
        [DECLARED, "base.yaml"],
        TEMPLATES + REPORTS + [DECLARED, "base.yaml", DECLARED, "base.yaml"],
        TEMPLATES + REPORTS + [DECLARED, ""],
        TEMPLATES + REPORTS + [DECLARED, "Canary\x00.yaml"],
        TEMPLATES + REPORTS + [DECLARED, "Canary;rm.yaml"],
        TEMPLATES + REPORTS + [DECLARED, "$(Canary).yaml"],
        TEMPLATES + REPORTS + [DECLARED, "/tmp/Canary.yaml"],
        TEMPLATES + REPORTS + [DECLARED, "C:/Canary.yaml"],
        TEMPLATES + REPORTS + [DECLARED, "../Canary.yaml"],
        TEMPLATES + REPORTS + [DECLARED, "a/../../Canary.yaml"],
        TEMPLATES + REPORTS + [DECLARED, "a/../Canary.yaml"],
        TEMPLATES + REPORTS + [DECLARED, "\\..\\Canary.yaml"],
        TEMPLATES + REPORTS + [DECLARED, "."],
    ],
)
def test_reviewed_template_path_rejected_before_reading(argv: List[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # An empty workspace: reading any input would give exit 3, not 2.
    monkeypatch.chdir(tmp_path)
    code, out, err = _run(argv)
    assert code == 2
    assert out == ""
    assert err.startswith("deltacli: invalid_arguments: ")
    assert "Canary" not in err
    assert "Traceback" not in err


def test_reviewed_template_path_through_an_outward_symlink_is_rejected(
    workspace: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    outside = tmp_path_factory.mktemp("outside")
    (workspace / "CanaryOut").symlink_to(outside, target_is_directory=True)
    (workspace / "CanaryOutFile.yaml").symlink_to(outside / "missing.yaml")
    for declared in ("CanaryOut/template.yaml", "CanaryOutFile.yaml", "CanaryOut"):
        code, out, err = _run(TEMPLATES + REPORTS + [DECLARED, declared])
        assert (code, out) == (2, ""), declared
        assert err.startswith("deltacli: invalid_arguments: ") and "Canary" not in err


@pytest.mark.parametrize(
    "declared, recorded",
    [
        ("base.yaml", "base.yaml"),
        ("./stack//template.yaml", "stack/template.yaml"),
        ("not/there.yaml", "not/there.yaml"),
        ("stack\\template.yaml", "stack/template.yaml"),
    ],
)
def test_reviewed_template_path_is_recorded_not_verified(declared: str, recorded: str, workspace: Path) -> None:
    code, out, err = _run(TEMPLATES + REPORTS + [DECLARED, declared])
    assert (code, err) == (0, "")
    delta = json.loads(out)["finding_delta"]
    assert delta["reviewed_template_path"] == {"path": recorded, "status": "declared_not_verified"}
    assert '"verified"' not in json.dumps(delta)


def test_reviewed_template_path_inward_symlink_is_accepted_by_name(workspace: Path) -> None:
    (workspace / "link.yaml").symlink_to("base.yaml")
    code, out, _ = _run(TEMPLATES + REPORTS + _declare(deltaschema.DECLARATION_CODES) + [DECLARED, "link.yaml"])
    assert code == 0
    delta = json.loads(out)["finding_delta"]
    # Recorded and compared as given (no symlink resolution): the Reports name
    # base.yaml, so the declared name is not in either target.
    assert delta["reviewed_template_path"]["path"] == "link.yaml"
    assert delta["template_report_correspondence"] == "inconsistent"


def test_reviewed_template_path_absent_is_null(workspace: Path) -> None:
    _, out, _ = _run(TEMPLATES + REPORTS)
    assert json.loads(out)["finding_delta"]["reviewed_template_path"] is None
    _, out, _ = _run(REPORTS)
    assert json.loads(out)["finding_delta"]["reviewed_template_path"] is None


def test_reviewed_template_path_is_recorded_when_a_report_is_unanalyzable(workspace: Path) -> None:
    (workspace / "broken.json").write_text("{", encoding="utf-8")
    code, out, _ = _run(TEMPLATES + ["--base-report", "broken.json", "--head-report", "head.json", DECLARED, "base.yaml"])
    assert code == 4
    delta = json.loads(out)["finding_delta"]
    assert delta["analysis_state"] == "unanalyzable"
    assert delta["reviewed_template_path"] == {"path": "base.yaml", "status": "declared_not_verified"}


def test_reviewed_template_path_replaces_the_comparison_path(workspace: Path) -> None:
    # Both Templates are compared against the declared path: the Reports name
    # base.yaml, so declaring it makes the Head side (head.yaml) consistent too.
    argv = TEMPLATES + REPORTS + _declare(deltaschema.DECLARATION_CODES)
    _, out, _ = _run(argv)
    assert json.loads(out)["finding_delta"]["template_report_correspondence"] == "inconsistent"
    _, out, _ = _run(argv + [DECLARED, "base.yaml"])
    delta = json.loads(out)["finding_delta"]
    assert delta["template_report_correspondence"] == "consistent_by_name_only"
    assert [e["classification"] for e in delta["entries"]] == ["Resolved"]


def test_help_names_the_reviewed_template_path(workspace: Path) -> None:
    _, _, err = _run(["--help"])
    assert DECLARED in err
    assert "not verified" in err


# ---------------------------------------------------------------------------
# Task 2 fixtures through the CLI
# ---------------------------------------------------------------------------


def _copy_template_case(name: str, root: Path) -> Tuple[Dict[str, Any], str, str]:
    case = json.loads((DELTA / "templates" / name / "expected.json").read_text(encoding="utf-8"))
    inputs = case["inputs"]
    base = "base" + Path(inputs["base"]).suffix
    shutil.copyfile(DELTA / "templates" / name / inputs["base"], root / base)
    if "head_ref" in inputs:
        source = REPO_ROOT / inputs["head_ref"]
    else:
        source = DELTA / "templates" / name / inputs["head"]
    head = "head" + source.suffix
    shutil.copyfile(source, root / head)
    return case, base, head


@pytest.mark.parametrize("name", TEMPLATE_CASES)
def test_template_fixture_through_the_cli(name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case, base, head = _copy_template_case(name, tmp_path)
    for constant, value in case["limits"].items():
        monkeypatch.setattr(deltaschema, constant, value)
    monkeypatch.chdir(tmp_path)
    code, out, err = _run(["--base-template", base, "--head-template", head, "--plain-identifiers"])
    expected = case["expected"]
    diff = json.loads(out)["semantic_diff"]
    if expected["failure"] is None:
        assert code == 0 and err == ""
    else:
        assert code == deltaschema.FAILURE_CODE_TABLE[expected["failure"]["code"]][1]
        failure = dict(diff["failure"])
        assert failure.pop("error_index") == 0
        assert failure == expected["failure"]
        assert err.startswith("deltacli: ")
    for key in ("analysis_state", "observation", "structural_completeness"):
        assert diff[key] == expected[key]
    assert sorted(diff["semantic_limitations"]) == sorted(expected["semantic_limitations"])

    def norm(items: List[Dict[str, Any]]) -> List[str]:
        return sorted(
            json.dumps(
                dict(item, **{k: sorted(item[k]) for k in ("qualifiers", "hints") if k in item}), sort_keys=True
            )
            for item in items
        )

    assert norm(diff["changes"]) == norm(expected["changes"])
    assert norm(diff["uncompared_paths"]) == norm(expected["uncompared_paths"])


def _report_case_argv(name: str, root: Path) -> Tuple[Dict[str, Any], List[str]]:
    case = json.loads((DELTA / "reports" / name / "expected.json").read_text(encoding="utf-8"))
    argv: List[str] = []
    for side in ("base", "head"):
        shutil.copyfile(DELTA / "reports" / name / case["inputs"][side], root / (side + ".json"))
        argv += ["--{0}-report".format(side), side + ".json"]
    pair = case["template_pair"]
    if pair is not None:
        for side in ("base", "head"):
            target = root / pair[side]["workspace_path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            source = DELTA / "reports" / name / pair[side]["file"]
            if target.exists():
                # One workspace path for both sides needs one file for both.
                assert target.read_bytes() == source.read_bytes()
            shutil.copyfile(source, target)
        argv += ["--base-template", pair["base"]["workspace_path"], "--head-template", pair["head"]["workspace_path"]]
    return case, argv


def _entry_shape(entry: Dict[str, Any]) -> str:
    return json.dumps(
        {
            "observation": entry["observation"],
            "classification": entry["classification"],
            "reasons": sorted(entry["reasons"]),
            "match_stage": entry["match_stage"],
            "missing_declarations": sorted(entry["missing_declarations"]),
            "changes": sorted(entry["changes"]),
        },
        sort_keys=True,
    )


@pytest.mark.parametrize("name", REPORT_CASES)
def test_report_fixture_through_the_cli(name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case, argv = _report_case_argv(name, tmp_path)
    monkeypatch.chdir(tmp_path)
    expected = case["expected"]
    for mode, want in expected["by_declarations"].items():
        code, out, err = _run(argv + _declare(case["declarations"][mode]))
        # The ``unknown`` case gives an unparsable Head Template on purpose.
        assert code == (4 if expected["template_report_correspondence"] == "unknown" else 0), err
        delta = json.loads(out)["finding_delta"]
        assert delta["analysis_state"] == expected["analysis_state"]
        assert delta["template_report_correspondence"] == expected["template_report_correspondence"]
        assert delta["classification_completeness"] == want["classification_completeness"]
        got = Counter(_entry_shape(e) for e in delta["entries"])
        wanted = Counter(
            _entry_shape(dict(e, changes=e.get("changes", []), missing_declarations=e.get("missing_declarations", [])))
            for e in want["entries"]
        )
        assert got == wanted, mode


# ---------------------------------------------------------------------------
# Exit codes (R10.1-R10.6)
# ---------------------------------------------------------------------------


def _write(root: Path, name: str, text: str) -> None:
    (root / name).write_text(text, encoding="utf-8")


@pytest.mark.parametrize(
    "case, head_text, code, failure",
    [
        ("analyzed", SIMPLE_HEAD, 0, None),
        ("not_found", None, 3, "input_not_found"),
        ("parse", "Resources: [\n", 4, "template_parse_failure"),
        ("cycle", "Resources: &r\n  R: *r\n", 4, "template_alias_cycle"),
        ("not_reviewable", "Description: x\n", 8, "template_not_reviewable"),
        ("bytes", b"Resources:\n  R: \xff\n", 4, "template_encoding_failure"),
    ],
)
def test_exit_codes_for_templates(
    case: str, head_text: Any, code: int, failure: Optional[str], workspace: Path
) -> None:
    head = workspace / "h2.yaml"
    if isinstance(head_text, bytes):
        head.write_bytes(head_text)
    elif head_text is not None:
        head.write_text(head_text, encoding="utf-8")
    got, out, err = _run(["--base-template", "base.yaml", "--head-template", "h2.yaml"])
    assert got == code
    diff = json.loads(out)["semantic_diff"]
    if failure is None:
        assert diff["analysis_state"] == "analyzed" and err == ""
    else:
        assert diff["failure"]["code"] == failure
        assert json.loads(out)["errors"][0]["error_class"] == deltaschema.FAILURE_CODE_TABLE[failure][0]


def test_exit_code_path_violation(workspace: Path, tmp_path_factory: pytest.TempPathFactory) -> None:
    outside = tmp_path_factory.mktemp("outside") / "t.yaml"
    outside.write_text(SIMPLE_BASE, encoding="utf-8")
    code, out, _ = _run(["--base-template", str(outside), "--head-template", "head.yaml"])
    assert code == 7
    built = json.loads(out)
    assert built["inputs"]["base"]["template"]["path"] is None
    assert str(outside.parent) not in out
    code, out, _ = _run(["--base-template", "../t.yaml", "--head-template", "head.yaml"])
    assert code in (3, 7)


def test_exit_code_symlink_outside(workspace: Path, tmp_path_factory: pytest.TempPathFactory) -> None:
    outside = tmp_path_factory.mktemp("outside2") / "t.yaml"
    outside.write_text(SIMPLE_BASE, encoding="utf-8")
    (workspace / "link.yaml").symlink_to(outside)
    code, out, _ = _run(["--base-template", "link.yaml", "--head-template", "head.yaml"])
    assert code == 7
    assert json.loads(out)["semantic_diff"]["failure"]["code"] == "path_violation"


def test_exit_code_directory_input(workspace: Path) -> None:
    (workspace / "dir").mkdir()
    code, out, _ = _run(["--base-template", "dir", "--head-template", "head.yaml"])
    assert code == 7
    assert json.loads(out)["semantic_diff"]["failure"]["code"] == "path_violation"


@pytest.mark.parametrize(
    "constant, value, failure",
    [
        ("MAX_TEMPLATE_DEPTH", 2, "template_depth_limit_exceeded"),
        ("MAX_TEMPLATE_NODES", 3, "template_node_limit_exceeded"),
        ("MAX_CHANGE_ENTRIES", 0, "change_entry_limit_exceeded"),
    ],
)
def test_exit_code_limits(
    constant: str, value: int, failure: str, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(deltaschema, constant, value)
    code, out, _ = _run(TEMPLATES)
    assert code == 3
    built = json.loads(out)
    assert built["semantic_diff"]["failure"]["code"] == failure
    assert built["semantic_diff"]["changes"] == []
    assert built["errors"][0]["error_class"] == "input_too_large"


def test_exit_code_template_too_large(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(template, "MAX_TEMPLATE_BYTES", len(SIMPLE_BASE) - 1)
    code, out, _ = _run(TEMPLATES)
    assert code == 3
    assert json.loads(out)["semantic_diff"]["failure"] == {
        "side": "base",
        "input": "template",
        "code": "template_too_large",
        "error_index": 0,
    }


def test_exit_code_output_limit(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(deltaschema, "MAX_OUTPUT_BYTES", 100)
    code, out, err = _run(TEMPLATES + REPORTS)
    assert code == 3
    built = json.loads(out)
    assert built["semantic_diff"]["changes"] == [] and built["finding_delta"]["entries"] == []
    assert built["errors"][-1]["message"].startswith("output: output_size_limit_exceeded")
    assert "output_size_limit_exceeded" in err


@pytest.mark.parametrize(
    "text, code, failure",
    [
        ('{"a": 1, "a": 2}', 4, "report_duplicate_json_key"),
        ("{", 4, "report_parse_failure"),
        ('{"a": NaN}', 4, "report_parse_failure"),
        ("[]", 4, "report_schema_violation"),
        ('{"version": "2.1.0", "runs": []}', 4, "report_schema_violation"),
    ],
)
def test_exit_codes_for_reports(text: str, code: int, failure: str, workspace: Path) -> None:
    _write(workspace, "bad.json", text)
    got, out, _ = _run(["--base-report", "base.json", "--head-report", "bad.json"])
    assert got == code
    delta = json.loads(out)["finding_delta"]
    assert delta["analysis_state"] == "unanalyzable"
    assert delta["failure"]["code"] == failure and delta["failure"]["side"] == "head"
    assert delta["entries"] == []


def test_exit_code_report_finding_limit(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(deltaschema, "MAX_REPORT_FINDINGS", 0)
    code, out, _ = _run(REPORTS)
    assert code == 3
    assert json.loads(out)["finding_delta"]["failure"]["code"] == "report_finding_limit_exceeded"


def test_exit_code_report_too_large(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(template, "MAX_TEMPLATE_BYTES", 10)
    code, out, _ = _run(REPORTS)
    assert code == 3
    assert json.loads(out)["finding_delta"]["failure"]["code"] == "report_too_large"


def test_schema_violation_names_a_schema_field_only(workspace: Path) -> None:
    obj = json.loads(_report_text([_finding("x", "Bucket")]))
    obj["findings"][0]["Location"]["File"] = "/CanaryAbsolute/path.yaml"
    _write(workspace, "bad.json", json.dumps(obj))
    code, out, err = _run(["--base-report", "base.json", "--head-report", "bad.json"])
    assert code == 4
    assert "Canary" not in out and "Canary" not in err
    assert "findings[0]" in json.loads(out)["errors"][0]["message"]


def test_exit_code_order_is_base_template_first(workspace: Path) -> None:
    _write(workspace, "bad.json", "{")
    _write(workspace, "bad.yaml", "Resources: [\n")
    code, out, err = _run(
        ["--base-template", "missing.yaml", "--head-template", "bad.yaml", "--base-report", "bad.json", "--head-report", "head.json"]
    )
    assert code == 3  # input_not_found of the Base Template
    messages = [e["message"] for e in json.loads(out)["errors"]]
    assert messages[0].startswith("base template: input_not_found")
    assert messages[1].startswith("head template: template_parse_failure")
    assert messages[2].startswith("base report: report_parse_failure")
    assert [line.split(": ", 1)[1] for line in err.splitlines()] == messages


def test_exit_code_order_reports_after_templates(workspace: Path) -> None:
    _write(workspace, "bad.json", "{")
    code, _, _ = _run(TEMPLATES + ["--base-report", "base.json", "--head-report", "bad.json"])
    assert code == 4


def test_one_unanalyzable_comparison_keeps_the_other(workspace: Path) -> None:
    _write(workspace, "bad.yaml", "Resources: [\n")
    code, out, _ = _run(["--base-template", "base.yaml", "--head-template", "bad.yaml"] + REPORTS)
    assert code == 4
    built = json.loads(out)
    assert built["semantic_diff"]["analysis_state"] == "unanalyzable"
    delta = built["finding_delta"]
    assert delta["analysis_state"] == "analyzed"
    assert delta["template_report_correspondence"] == "unknown"
    assert [e["classification"] for e in delta["entries"]] == ["Ambiguous"]
    assert "template_report_mismatch" in delta["entries"][0]["reasons"]
    _write(workspace, "bad.json", "{")
    code, out, _ = _run(TEMPLATES + ["--base-report", "base.json", "--head-report", "bad.json"])
    built = json.loads(out)
    assert built["semantic_diff"]["analysis_state"] == "analyzed"
    assert built["semantic_diff"]["changes"]


def test_change_limit_makes_correspondence_unknown(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(deltaschema, "MAX_CHANGE_ENTRIES", 0)
    code, out, _ = _run(TEMPLATES + REPORTS + _declare(deltaschema.DECLARATION_CODES))
    assert code == 3
    delta = json.loads(out)["finding_delta"]
    assert delta["template_report_correspondence"] == "unknown"
    assert all(e["classification"] not in ("New", "Resolved") for e in delta["entries"])


def test_unexpected_exception_has_no_traceback(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*_: Any, **__: Any) -> Any:
        raise RuntimeError("CanaryExceptionText /CanaryHostPath")

    monkeypatch.setattr(deltareport, "render_delta_report", explode)
    code, out, err = _run(TEMPLATES)
    assert code == 1
    assert out == ""
    assert err == "deltacli: unexpected: RuntimeError\n"


# ---------------------------------------------------------------------------
# Channels (R5.11, R10.5, R12.10, R12.11, R12.13)
# ---------------------------------------------------------------------------


def test_stdout_is_the_delta_report_only_and_stderr_has_no_summary(workspace: Path) -> None:
    code, out, err = _run(TEMPLATES + REPORTS)
    assert code == 0
    assert out == deltareport.dump(json.loads(out))
    assert err == ""
    _write(workspace, "bad.yaml", "Resources: [\n")
    _, out, err = _run(["--base-template", "base.yaml", "--head-template", "bad.yaml"] + REPORTS)
    for word in ("changes_observed", "no_changes_observed", "Resolved", "New", "Unchanged", "complete"):
        assert word not in err
    assert all(line.startswith("deltacli: ") for line in err.splitlines())


@pytest.mark.parametrize(
    "raw, cleaned",
    [
        ("a\x1bb", "a\\u{001B}b"),
        ("a\u202eb", "a\\u{202E}b"),
        ("a\u2066b\u2069", "a\\u{2066}b\\u{2069}"),
        ("a\x85b\x7f", "a\\u{0085}b\\u{007F}"),
        ("tab\there", "tab\\u{0009}here"),
        ("path /etc/passwd", "path <path>"),
    ],
)
def test_stderr_sanitization(raw: str, cleaned: str) -> None:
    assert deltacli.sanitize_stderr(raw) == cleaned


def test_module_text_and_imports() -> None:
    import ast

    text = Path(deltacli.__file__).read_text(encoding="utf-8")
    assert "hypothesis" not in text and ".kiro" not in text
    assert "os.environ" not in text and "getenv" not in text and "sys.stdin" not in text
    forbidden = {"subprocess", "socket", "urllib", "http", "ssl", "ftplib", "smtplib", "asyncio", "os"}
    for node in ast.walk(ast.parse(text)):
        names: List[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [(node.module or "").split(".")[0]]
        for name in names:
            assert name not in forbidden, name
            assert name in {"__future__", "argparse", "io", "sys", "pathlib", "typing", "iacreview"}, name


# ---------------------------------------------------------------------------
# Child process: python -m, determinism, environment, files (R1.8, R1.10, R1.11, R11.1)
# ---------------------------------------------------------------------------


def _child(root: Path, argv: Sequence[str], extra_env: Optional[Dict[str, str]] = None, stdin: bytes = b"") -> subprocess.CompletedProcess:
    # The inherited environment keeps HOME, through which the interpreter finds
    # a user-site PyYAML; PYTHONPATH is the documented way to start the tool.
    env = dict(os.environ)
    env.update({"PYTHONPATH": str(REPO_ROOT), "PYTHONDONTWRITEBYTECODE": "1"})
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-m", "iacreview.deltacli"] + list(argv),
        cwd=str(root),
        env=env,
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )


def _files(root: Path) -> List[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*"))


def test_python_m_child_process_is_deterministic_and_reads_no_environment(workspace: Path) -> None:
    argv = TEMPLATES + REPORTS + _declare(["reports_unmodified"])
    before = _files(workspace)
    runs = [
        _child(workspace, argv, {"PYTHONHASHSEED": "0"}),
        _child(workspace, argv, {"PYTHONHASHSEED": "12345"}),
        _child(
            workspace,
            argv,
            {
                "PYTHONHASHSEED": "1",
                "LANG": "C",
                "LC_ALL": "C",
                "TZ": "Asia/Tokyo",
                "COLUMNS": "20",
                "IACREVIEW_PLAIN_IDENTIFIERS": "1",
                "DELTA_DECLARE": "all",
                "IACREVIEW_CONFIG": str(workspace / "config.json"),
            },
            stdin=b'{"declare": "all"}\n',
        ),
    ]
    for run in runs:
        assert run.returncode == 0, run.stderr
        assert run.stderr == b""
    assert runs[0].stdout == runs[1].stdout == runs[2].stdout
    assert json.loads(runs[0].stdout)["identifier_mode"] == "anonymized"
    assert _files(workspace) == before
    assert b"Traceback" not in runs[0].stderr


def test_python_m_child_process_failure_exit_code(workspace: Path) -> None:
    run = _child(workspace, ["--base-template", "base.yaml"])
    assert run.returncode == 2
    assert run.stdout == b""
    assert run.stderr.startswith(b"deltacli: invalid_arguments: ")
