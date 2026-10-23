"""Unit tests for :mod:`iacreview.reportcheck` (v1.1 Task 8).

* Schema (Design 9-1): the 7-key envelope, ``schema_version`` MAJOR 1, the
  shapes of ``target`` / ``sources_enabled`` / ``tools`` / ``errors``, the
  Finding count limit, ``finding.from_dict``, and field paths that never quote
  input content.
* Internal consistency (Design 9-2): ``rebuild_mismatch`` and
  ``dedup_invariant_violated`` on the Task 2 Report fixtures, and no failure on
  Reports equivalent to the 19 Reports of Task 0.1 (built in-process with the
  Plugin's own Sources and ``report.build_report`` instead of
  ``run_iac_review.py``).
* Comparable (Design 9-3): each row of the Source / tool table, the CDK
  condition, version equality, ``errors[]`` attribution, and the summary flag.
* Correspondence (Design 9-4): the four values; ``verified`` does not exist.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pytest

from iacreview import dedup, deltaio, deltaschema, netgraph, quality, report, reportcheck, secrets, template
from iacreview.deltaio import Failure, ParsedTemplate
from iacreview.finding import Evidence, Finding, Location
from iacreview.reportcheck import CheckedReport, ErrorRecord, ReportRejection, ToolRecord

REPO_ROOT = Path(__file__).resolve().parents[2]
DELTA_REPORTS = REPO_ROOT / "tests" / "fixtures" / "delta" / "reports"
REPORT_CASES = sorted(path.name for path in DELTA_REPORTS.iterdir() if path.is_dir())
DETERMINISTIC = ["cfn-lint", "cfn-guard", "IAM Review", "Network Review", "Secret Review", "Quality Review"]
FILE = "templates/app.yaml"


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _finding(
    resource: Optional[str] = "Bucket",
    category: str = "Encryption",
    source: str = "cfn-guard",
    rule: Optional[str] = "s3_bucket_encryption",
    text: str = "bucket encryption",
    file: str = FILE,
    severity: str = "HIGH",
) -> Finding:
    return Finding(
        ID=0,
        Normalized_Category=category,
        FindingType="Security",
        Severity=severity,
        Confidence="Confirmed",
        Source=[source],
        Resource=resource,
        Location=Location(File=file, TemplatePath=["Resources", resource or "X"]),
        Finding=text,
        WhyItMatters="why",
        Evidence=[Evidence(Source=source, Detail="detail", RuleId=rule)],
        Recommendation="fix",
        SuggestedRemediation=None,
    )


def _tools(**versions: Optional[str]) -> List[report.ToolStatus]:
    defaults: Dict[str, Optional[str]] = {"cfn-guard": "3.2.1", "cfn-lint": "1.46.0"}
    defaults.update(versions)
    return [report.ToolStatus(name, version is not None, version) for name, version in defaults.items()]


def _report(
    findings: Sequence[Finding] = (),
    *,
    files: Sequence[str] = (FILE,),
    sources: Sequence[str] = DETERMINISTIC,
    tools: Optional[Sequence[report.ToolStatus]] = None,
    errors: Sequence[Dict[str, Any]] = (),
    synthesized: Sequence[str] = (),
    synthesis: str = "not_applicable",
) -> Dict[str, Any]:
    meta = report.ReportMeta(
        files=tuple(files),
        sources_enabled=tuple(sources),
        tools=tuple(_tools() if tools is None else tools),
        cdk_detected=bool(synthesized) or synthesis != "not_applicable",
        synthesized_templates=tuple(synthesized),
        cdk_synthesis=synthesis,
    )
    return json.loads(report.dump(report.build_report(list(findings), list(errors), meta)))


def _checked(obj: Dict[str, Any], side: str = "base") -> CheckedReport:
    result = reportcheck.check_report(obj, side)
    assert isinstance(result, CheckedReport), result
    return result


def _rejected(obj: Any, side: str = "head") -> ReportRejection:
    result = reportcheck.check_report(obj, side)
    assert isinstance(result, ReportRejection), result
    return result


def _error(source: Optional[str], error_class: str = "tool_execution") -> Dict[str, Any]:
    return {
        "error_class": error_class,
        "source": source,
        "tool": None,
        "exit_code": None,
        "message": "CanaryErrorMessage",
        "required_min_version": None,
        "detected_version": None,
        "remediation": "CanaryRemediation",
        "stderr_head": ["CanaryStderr"],
    }


# ---------------------------------------------------------------------------
# Task 2 Report fixtures
# ---------------------------------------------------------------------------


def _fixture(case: str, side: str) -> Dict[str, Any]:
    expected = json.loads((DELTA_REPORTS / case / "expected.json").read_text(encoding="utf-8"))
    return json.loads((DELTA_REPORTS / case / expected["inputs"][side]).read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", REPORT_CASES)
def test_fixture_reports_pass_the_schema_and_record_integrity(case: str) -> None:
    """R2.10, R2.11: integrity failures are recorded, the Report is still usable."""
    expected = json.loads((DELTA_REPORTS / case / "expected.json").read_text(encoding="utf-8"))
    integrity = expected["expected"]["report_integrity"]
    for side in ("base", "head"):
        checked = _checked(_fixture(case, side), side)
        assert list(checked.integrity_failures) == integrity[side]


@pytest.mark.parametrize("case", [c for c in REPORT_CASES if c.startswith("correspondence_")])
def test_fixture_correspondence(case: str) -> None:
    """R8.6: consistent_by_name_only, inconsistent, unknown."""
    expected = json.loads((DELTA_REPORTS / case / "expected.json").read_text(encoding="utf-8"))
    pair = expected["template_pair"]
    templates = {
        side: deltaio.parse_template(
            (DELTA_REPORTS / case / pair[side]["file"]).read_text(encoding="utf-8"), Path("t"), side
        )
        for side in ("base", "head")
    }
    value = reportcheck.correspondence(
        templates["base"],
        templates["head"],
        _checked(_fixture(case, "base")),
        _checked(_fixture(case, "head")),
        (pair["base"]["workspace_path"], pair["head"]["workspace_path"]),
    )
    assert value == expected["expected"]["template_report_correspondence"]


# ---------------------------------------------------------------------------
# Reports equivalent to the 19 Reports of Task 0.1
# ---------------------------------------------------------------------------


def _review_targets() -> List[Path]:
    cases = sorted((REPO_ROOT / "benchmark" / "cases").iterdir())
    benchmark = [next(p for p in sorted(case.iterdir()) if p.name.startswith("template.")) for case in cases if case.is_dir()]
    examples = sorted((REPO_ROOT / "examples").glob("*/template.yaml"))
    return benchmark + examples


def test_there_are_nineteen_review_targets() -> None:
    assert len(_review_targets()) == 19


@pytest.mark.parametrize("path", _review_targets(), ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_reports_of_the_plugin_sources_are_consistent(path: Path) -> None:
    """F-2 / O-10: a Report built the way run_iac_review.py builds one is consistent."""
    rel = str(path.relative_to(REPO_ROOT))
    doc = template.parse_template_text(path.read_text(encoding="utf-8"), path)
    found: List[Finding] = []
    for module in (netgraph, secrets, quality):
        found.extend(module.review(doc, template_file=rel))
    obj = _report(
        dedup.deduplicate(found),
        files=[rel],
        sources=DETERMINISTIC,
        tools=_tools(),
    )
    checked = _checked(obj)
    assert checked.integrity_failures == ()
    assert len(checked.findings) == len(obj["findings"])


# ---------------------------------------------------------------------------
# Schema (Design 9-1)
# ---------------------------------------------------------------------------


def _valid() -> Dict[str, Any]:
    return _report([_finding(), _finding(resource="Queue", text="queue encryption")])


def test_valid_report_fields() -> None:
    checked = _checked(_valid())
    assert checked.schema_version == "1.0.0"
    assert checked.files == (FILE,)
    assert checked.sources_enabled == tuple(DETERMINISTIC)
    assert checked.tools == (ToolRecord("cfn-guard", True, "3.2.1"), ToolRecord("cfn-lint", True, "1.46.0"))
    assert checked.integrity_failures == ()
    assert [f.ID for f in checked.findings] == [1, 2]


@pytest.mark.parametrize("obj", [[], "x", None, 1, {"version": "2.1.0", "runs": []}])
def test_not_a_review_report_envelope(obj: Any) -> None:
    """R1.5, R2.6: SARIF and other envelopes are a schema violation."""
    rejection = _rejected(obj)
    assert rejection.failure.code == "report_schema_violation"
    assert (rejection.failure.error_class, rejection.failure.exit_code) == ("schema_violation", 4)
    assert rejection.failure.side == "head" and rejection.failure.input == "report"


@pytest.mark.parametrize("key", report.REPORT_KEYS)
def test_missing_key(key: str) -> None:
    obj = _valid()
    del obj[key]
    assert _rejected(obj).field == key


def test_extra_key_is_not_named() -> None:
    obj = _valid()
    obj["CanaryExtraKey"] = 1
    rejection = _rejected(obj)
    assert rejection.failure.code == "report_schema_violation" and rejection.field is None


@pytest.mark.parametrize("version", ["2.0.0", "0.9.0", "1", "1.0", "v1.0.0", 1, None, "1.0.0-rc1"])
def test_schema_version_major_must_be_one(version: Any) -> None:
    obj = _valid()
    obj["schema_version"] = version
    assert _rejected(obj).field == "schema_version"


@pytest.mark.parametrize("version", ["1.0.0", "1.2.3", "1.10.0"])
def test_schema_version_major_one_is_accepted(version: str) -> None:
    obj = _valid()
    obj["schema_version"] = version
    assert _checked(obj).schema_version == version


def _mutations() -> List[Tuple[str, Any, str]]:
    """(path to edit, new value, expected field)."""
    return [
        ("target", [], "target"),
        ("target.files", "app.yaml", "target.files"),
        ("target.files.0", 1, "target.files[0]"),
        ("target.files.0", "/abs/app.yaml", "target.files[0]"),
        ("target.files.0", "../app.yaml", "target.files[0]"),
        ("target.files.0", "C:/app.yaml", "target.files[0]"),
        ("target.cdk", {"detected": False}, "target.cdk"),
        ("target.cdk.detected", "no", "target.cdk.detected"),
        ("target.cdk.synthesis", "maybe", "target.cdk.synthesis"),
        ("target.cdk.synthesized_templates", ["cdk.out/../x.json"], "target.cdk.synthesized_templates[0]"),
        ("sources_enabled", "cfn-lint", "sources_enabled"),
        ("sources_enabled.0", "CanarySource", "sources_enabled[0]"),
        ("sources_enabled", ["cfn-lint", "cfn-lint"], "sources_enabled"),
        ("tools", {}, "tools"),
        ("tools.0", {"name": "x", "available": True}, "tools[0]"),
        ("tools.0.name", 3, "tools[0].name"),
        ("tools.0.available", "yes", "tools[0].available"),
        ("tools.0.version", 3, "tools[0].version"),
        ("tools.1.name", "cfn-guard", "tools"),
        ("errors", {}, "errors"),
        ("findings", {}, "findings"),
        ("summary", [], "summary"),
    ]


def _set(obj: Dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    current: Any = obj
    for part in parts[:-1]:
        current = current[int(part)] if isinstance(current, list) else current[part]
    last = parts[-1]
    if isinstance(current, list):
        current[int(last)] = value
    else:
        current[last] = value


@pytest.mark.parametrize("dotted,value,field", _mutations())
def test_shape_violations_name_a_schema_field(dotted: str, value: Any, field: str) -> None:
    """R2.8, R2.9"""
    obj = _valid()
    _set(obj, dotted, value)
    rejection = _rejected(obj)
    assert rejection.failure.code == "report_schema_violation"
    assert rejection.field == field
    assert "Canary" not in repr(rejection)


@pytest.mark.parametrize(
    "key,value",
    [
        ("error_class", "CanaryClass"),
        ("error_class", None),
        ("source", 1),
        ("message", None),
        ("exit_code", True),
        ("exit_code", "1"),
        ("stderr_head", "x"),
        ("stderr_head", [1]),
        ("remediation", 1),
    ],
)
def test_error_shape_violations(key: str, value: Any) -> None:
    obj = _report([_finding()], errors=[_error("cfn-lint")])
    obj["errors"][0][key] = value
    assert _rejected(obj).field == "errors[0].{0}".format(key)


def test_error_with_missing_key() -> None:
    obj = _report([_finding()], errors=[_error("cfn-lint")])
    del obj["errors"][0]["stderr_head"]
    assert _rejected(obj).field == "errors[0]"


def test_errors_keep_no_free_text() -> None:
    """R8.7: only error_class and source are kept."""
    checked = _checked(_report([_finding()], errors=[_error("cfn-lint"), _error(None, "unexpected")]))
    assert checked.errors == (ErrorRecord("tool_execution", "cfn-lint"), ErrorRecord("unexpected", None))
    assert "Canary" not in repr(checked)


@pytest.mark.parametrize(
    "edit,field",
    [
        (lambda f: f.update(Severity="SEVERE"), "findings[0].Severity"),
        (lambda f: f.update(ID=0), "findings[0].ID"),
        (lambda f: f.pop("Finding"), "findings[0].Finding"),
        (lambda f: f["Location"].update(File="/abs/app.yaml"), "findings[0].Location.File"),
        (lambda f: f["Location"].update(File="../app.yaml"), "findings[0].Location.File"),
        (lambda f: f["Location"].update(File="C:/app.yaml"), "findings[0].Location.File"),
        (lambda f: f["Evidence"][0].update(Source="CanarySource"), "findings[0].Evidence[0].Source"),
        (lambda f: f["Location"].update(TemplatePath=[True]), "findings[0].Location.TemplatePath[0]"),
        (lambda f: f.update(Normalized_Category="CanaryCategory"), "findings[0].Normalized_Category"),
    ],
)
def test_finding_violations_name_the_field(edit: Any, field: str) -> None:
    """R2.7, R2.9: the Finding is not dropped silently, and the path is schema-derived."""
    obj = _valid()
    edit(obj["findings"][0])
    result = reportcheck.check_report(obj, "base")
    assert isinstance(result, ReportRejection)
    assert result.failure.code == "report_schema_violation" and result.field == field
    assert "Canary" not in repr(result)


def test_unknown_finding_key_is_not_quoted() -> None:
    """``from_dict`` names an unknown key by itself; that key is input content."""
    obj = _valid()
    obj["findings"][1]["CanaryUnknownKey"] = 1
    rejection = _rejected(obj)
    assert rejection.field == "findings[1]"
    assert "Canary" not in repr(rejection)


def test_finding_that_is_not_an_object() -> None:
    obj = _valid()
    obj["findings"][0] = ["CanaryList"]
    assert _rejected(obj).field == "findings[0].Finding"


def test_finding_that_crashes_validation_fails_closed() -> None:
    obj = _valid()
    obj["findings"][0]["Source"] = [["unhashable"]]
    rejection = _rejected(obj)
    assert rejection.failure.code == "report_schema_violation"
    assert rejection.field is not None and rejection.field.startswith("findings[0]")


def test_unexpected_validation_exception_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(_: Any) -> Finding:
        raise TypeError("CanaryTypeError")

    monkeypatch.setattr(reportcheck.finding, "from_dict", explode)
    rejection = _rejected(_valid())
    assert (rejection.failure.code, rejection.field) == ("report_schema_violation", "findings[0]")
    assert "Canary" not in repr(rejection)


def test_broken_category_data_is_not_reported_as_bad_input(monkeypatch: pytest.MonkeyPatch) -> None:
    from iacreview.errors import MappingFileError

    def broken(_: Any) -> Finding:
        raise MappingFileError("broken installation")

    monkeypatch.setattr(reportcheck.finding, "from_dict", broken)
    with pytest.raises(MappingFileError):
        reportcheck.check_report(_valid())


def test_rebuild_that_raises_is_a_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_: Any) -> Dict[str, Any]:
        raise ValueError("refused")

    obj = _valid()
    monkeypatch.setattr(reportcheck.report, "build_report", refuse)
    assert _checked(obj).integrity_failures == ("rebuild_mismatch",)


def test_finding_count_at_the_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(deltaschema, "MAX_REPORT_FINDINGS", 2)
    assert len(_checked(_valid()).findings) == 2


def test_finding_count_above_the_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """R14.3: input_too_large before any Finding is validated."""
    monkeypatch.setattr(deltaschema, "MAX_REPORT_FINDINGS", 1)
    rejection = _rejected(_valid())
    assert rejection.failure.code == "report_finding_limit_exceeded"
    assert (rejection.failure.error_class, rejection.failure.exit_code) == ("input_too_large", 3)
    assert rejection.field == "findings"


def test_shipped_finding_limit_is_the_approved_value() -> None:
    assert deltaschema.MAX_REPORT_FINDINGS == 10000


# ---------------------------------------------------------------------------
# Internal consistency (Design 9-2)
# ---------------------------------------------------------------------------


def test_reordered_findings_are_a_rebuild_mismatch() -> None:
    obj = _valid()
    obj["findings"].reverse()
    for index, item in enumerate(obj["findings"], start=1):
        item["ID"] = index
    assert _checked(obj).integrity_failures == ("rebuild_mismatch",)


def test_id_gap_is_a_rebuild_mismatch() -> None:
    obj = _valid()
    obj["findings"][1]["ID"] = 5
    assert _checked(obj).integrity_failures == ("rebuild_mismatch",)


def test_duplicate_id_is_a_rebuild_mismatch() -> None:
    obj = _valid()
    obj["findings"][1]["ID"] = 1
    assert _checked(obj).integrity_failures == ("rebuild_mismatch",)


def test_summary_edit_is_a_rebuild_mismatch() -> None:
    obj = _valid()
    obj["summary"]["total"] = 3
    assert _checked(obj).integrity_failures == ("rebuild_mismatch",)


def test_summary_with_wrong_keys_is_a_rebuild_mismatch() -> None:
    obj = _valid()
    obj["summary"] = {}
    assert _checked(obj).integrity_failures == ("rebuild_mismatch",)


def test_unsorted_target_files_are_a_rebuild_mismatch() -> None:
    obj = _report([_finding()], files=[FILE, "templates/a.yaml"])
    obj["target"]["files"].reverse()
    assert _checked(obj).integrity_failures == ("rebuild_mismatch",)


def test_duplicated_dedup_identity_is_recorded() -> None:
    obj = _report([_finding(), _finding(rule="other_rule", text="second")])
    assert _checked(obj).integrity_failures == ("dedup_invariant_violated",)


def test_both_checks_can_fail_together() -> None:
    obj = _report([_finding(), _finding(rule="other_rule", text="second")])
    obj["summary"]["total"] = 9
    assert _checked(obj).integrity_failures == ("rebuild_mismatch", "dedup_invariant_violated")


def test_repeated_ineligible_identity_is_not_a_violation() -> None:
    obj = _report([_finding(resource=None, text="a"), _finding(resource=None, rule="r2", text="b")])
    assert _checked(obj).integrity_failures == ()


def test_check_report_does_not_modify_its_input() -> None:
    obj = _report([_finding()], errors=[_error("cfn-lint")])
    before = copy.deepcopy(obj)
    _checked(obj)
    assert obj == before


# ---------------------------------------------------------------------------
# Comparable (Design 9-3, R7.1)
# ---------------------------------------------------------------------------


def _pair(base: Dict[str, Any], head: Dict[str, Any]) -> Tuple[CheckedReport, CheckedReport]:
    return _checked(base, "base"), _checked(head, "head")


def _reasons(source: str, base: Dict[str, Any], head: Dict[str, Any], file: str = FILE) -> Tuple[str, ...]:
    checked_base, checked_head = _pair(base, head)
    return reportcheck.comparable_reasons(source, file, checked_base, checked_head)


SNC = ("source_not_comparable",)


@pytest.mark.parametrize("source", DETERMINISTIC + ["Agent Review"])
def test_comparable_when_recorded_conditions_hold(source: str) -> None:
    sources = DETERMINISTIC + ["Agent Review"]
    assert _reasons(source, _report(sources=sources), _report(sources=sources)) == ()


def test_source_outside_the_table_is_not_comparable() -> None:
    assert _reasons("CanarySource", _report(), _report()) == SNC


@pytest.mark.parametrize("source,tool", [("cfn-lint", "cfn-lint"), ("cfn-guard", "cfn-guard")])
def test_tool_unavailable_on_one_side(source: str, tool: str) -> None:
    head = _report(tools=_tools(**{tool: None}))
    assert _reasons(source, _report(), head) == SNC
    assert _reasons(source, head, _report()) == SNC


def test_tool_missing_from_tools() -> None:
    head = _report(tools=[report.ToolStatus("cfn-guard", True, "3.2.1")])
    assert _reasons("cfn-lint", _report(), head) == SNC
    assert _reasons("cfn-guard", _report(), head) == ()


def test_tool_version_mismatch() -> None:
    head = _report(tools=_tools(**{"cfn-lint": "1.47.0"}))
    assert _reasons("cfn-lint", _report(), head) == ("source_not_comparable", "tool_version_mismatch")
    assert _reasons("cfn-guard", _report(), head) == ()


def test_plugin_sources_do_not_depend_on_tools() -> None:
    head = _report(tools=_tools(**{"cfn-lint": None, "cfn-guard": None}))
    for source in ("IAM Review", "Network Review", "Secret Review", "Quality Review"):
        assert _reasons(source, _report(), head) == ()


def test_source_not_enabled() -> None:
    head = _report(sources=[s for s in DETERMINISTIC if s != "IAM Review"])
    assert _reasons("IAM Review", _report(), head) == SNC
    assert _reasons("Agent Review", _report(), _report()) == SNC


def test_error_attributed_to_the_source() -> None:
    head = _report(errors=[_error("cfn-lint")])
    assert _reasons("cfn-lint", _report(), head) == SNC
    assert _reasons("cfn-guard", _report(), head) == ()


def test_unattributed_error_affects_every_source() -> None:
    head = _report(errors=[_error(None, "unexpected")])
    for source in DETERMINISTIC:
        assert _reasons(source, _report(), head) == SNC


def test_template_not_reviewed_on_one_side() -> None:
    base = _report(files=[FILE, "templates/other.yaml"])
    assert _reasons("cfn-guard", base, _report(), "templates/other.yaml") == (
        "source_not_comparable",
        "template_not_reviewed",
    )
    assert _reasons("cfn-guard", base, _report(), FILE) == ()


def test_synthesized_template_counts_as_reviewed() -> None:
    synth = "cdk.out/Stack.template.json"
    base = _report(files=[], synthesized=[synth], synthesis="ran")
    assert _reasons("cfn-lint", base, base, synth) == ()


def test_cdk_synthesis_must_be_equal() -> None:
    synth = "cdk.out/Stack.template.json"
    base = _report(files=[synth], synthesized=[synth], synthesis="ran")
    head = _report(files=[synth], synthesized=[synth], synthesis="skipped_unconfirmed")
    assert _reasons("cfn-lint", base, head, synth) == SNC


def test_cdk_tool_version_matters_for_synthesized_templates_only() -> None:
    synth = "cdk.out/Stack.template.json"
    tools_a = _tools() + [report.ToolStatus("cdk", True, "2.100.0")]
    tools_b = _tools() + [report.ToolStatus("cdk", True, "2.101.0")]
    base = _report(files=[FILE], synthesized=[synth], synthesis="ran", tools=tools_a)
    head = _report(files=[FILE], synthesized=[synth], synthesis="ran", tools=tools_b)
    assert _reasons("IAM Review", base, head, synth) == ("source_not_comparable", "tool_version_mismatch")
    assert _reasons("IAM Review", base, head, FILE) == ()


def test_cdk_tool_missing_on_one_side() -> None:
    synth = "cdk.out/Stack.template.json"
    tools_a = _tools() + [report.ToolStatus("cdk", True, "2.100.0")]
    base = _report(files=[], synthesized=[synth], synthesis="ran", tools=tools_a)
    head = _report(files=[], synthesized=[synth], synthesis="ran")
    assert _reasons("cfn-lint", base, head, synth) == SNC


def test_summary_comparable_flag() -> None:
    """R7.10: errors empty, tools available, same names and versions."""
    def flag(base: Dict[str, Any], head: Dict[str, Any]) -> bool:
        return reportcheck.summary_comparable(*_pair(base, head))

    assert flag(_report(), _report()) is True
    assert flag(_report(), _report(errors=[_error("cfn-lint")])) is False
    assert flag(_report(tools=_tools(**{"cfn-lint": None})), _report(tools=_tools(**{"cfn-lint": None}))) is False
    assert flag(_report(), _report(tools=_tools(**{"cfn-guard": "3.3.0"}))) is False
    assert flag(_report(), _report(tools=[report.ToolStatus("cfn-lint", True, "1.46.0")])) is False
    assert flag(_report([_finding()]), _report()) is True  # passed_all_checks differs, flag does not


# ---------------------------------------------------------------------------
# Correspondence (Design 9-4, R8.6)
# ---------------------------------------------------------------------------

_TEMPLATE = "Resources:\n  Bucket: {Type: AWS::S3::Bucket}\n  Queue: {Type: AWS::SQS::Queue}\n"


def _template(text: str = _TEMPLATE) -> ParsedTemplate:
    parsed = deltaio.parse_template(text, Path("t.yaml"), "base")
    assert isinstance(parsed, ParsedTemplate)
    return parsed


def _correspond(
    base_report: Dict[str, Any],
    head_report: Dict[str, Any],
    base_t: Any = None,
    head_t: Any = None,
    paths: Optional[Tuple[str, str]] = (FILE, FILE),
) -> str:
    checked_base, checked_head = _pair(base_report, head_report)
    return reportcheck.correspondence(
        _template() if base_t is None else base_t,
        _template() if head_t is None else head_t,
        checked_base,
        checked_head,
        paths,
    )


def test_correspondence_not_applicable_without_template_pair() -> None:
    checked = _checked(_report())
    assert reportcheck.correspondence(None, None, checked, checked, None) == "not_applicable"


def test_correspondence_consistent_by_name_only() -> None:
    assert _correspond(_report([_finding()]), _report([_finding(resource="Queue")])) == "consistent_by_name_only"


def test_correspondence_ignores_findings_without_resource_and_of_other_files() -> None:
    head = _report(
        [_finding(resource=None), _finding(resource="Elsewhere", file="templates/other.yaml")],
        files=[FILE, "templates/other.yaml"],
    )
    assert _correspond(_report(), head) == "consistent_by_name_only"


def test_correspondence_inconsistent_when_path_not_in_target() -> None:
    assert _correspond(_report(), _report(), paths=(FILE, "templates/head.yaml")) == "inconsistent"


def test_correspondence_inconsistent_when_resource_is_not_a_logical_id() -> None:
    assert _correspond(_report(), _report([_finding(resource="Topic")])) == "inconsistent"


def test_correspondence_unknown_when_a_template_is_unanalyzable() -> None:
    failure = Failure("template_parse_failure", "head", "template")
    assert _correspond(_report(), _report([_finding(resource="Topic")]), head_t=failure) == "unknown"


def test_correspondence_normalizes_the_template_path() -> None:
    assert _correspond(_report(), _report(), paths=("./" + FILE, FILE)) == "consistent_by_name_only"
    assert _correspond(_report(), _report(), paths=("/abs/" + FILE, FILE)) == "inconsistent"


def test_correspondence_with_a_declared_path_still_checks_each_side_template() -> None:
    """H-M1-1 approved: a declared path is the comparison path of both sides
    (the CLI passes it twice); the Logical ID check still uses each side's own
    Template, and the path is compared after normalization only."""
    head_t = _template("Resources:\n  Bucket: {Type: AWS::S3::Bucket}\n")
    base = _report([_finding(resource="Queue")])
    assert _correspond(base, _report([_finding()]), head_t=head_t) == "consistent_by_name_only"
    assert _correspond(_report(), _report([_finding(resource="Queue")]), head_t=head_t) == "inconsistent"
    assert _correspond(_report(), _report(), paths=(FILE.upper(), FILE.upper())) == "inconsistent"


def test_correspondence_values_are_closed() -> None:
    assert "verified" not in deltaschema.TEMPLATE_REPORT_CORRESPONDENCE
