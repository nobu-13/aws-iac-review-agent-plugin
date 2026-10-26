"""Regression: Template / Report path correspondence stays fail-closed (v1.1 M1, A-2).

Requirements guarded
--------------------

v1.1 Requirement 8 AC4 / AC6, Requirement 7 AC2 / AC3 / AC5, Requirement 2
AC1, Requirement 12 AC12, Requirement 5 AC10, and Design 9-4: with a
Template_Pair and a Report_Pair, ``template_report_correspondence`` is
``consistent_by_name_only`` only when each side's workspace-relative Template
path is in that side's own Report ``target`` and every non-null ``Resource``
of a Finding on that path is a Logical ID of that Template. Anything else is
``inconsistent`` (or ``unknown`` when a Template is unanalyzable), and then no
one-sided entry is ``New`` or ``Resolved``, whatever is declared.

Expected values, written from the Requirements before the run
--------------------------------------------------------------

The workspace holds ``tpl.yaml`` (Logical IDs ``Bucket`` and ``Queue``). The
Base Report has Findings on ``Bucket`` / Encryption and ``Queue`` / Logging;
the Head Report on ``Bucket`` / Encryption and ``Bucket`` / Tagging. With a
consistent correspondence and all six declarations: ``Bucket`` / Encryption
``matched`` / ``Unchanged``, ``Queue`` / Logging ``base_only`` / ``Resolved``,
``Bucket`` / Tagging ``head_only`` / ``New``. Every other case below must give
``New`` = ``Resolved`` = 0 (the fail-closed invariant).

The same Template file is given for both sides, so the Semantic Diff is empty
and no rename hint can make an entry Ambiguous for another reason.
"""

from __future__ import annotations

import io
import json
import os
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pytest

from iacreview import deltacli, deltaschema, report
from iacreview.finding import Evidence, Finding, Location

TEMPLATE = (
    "Resources:\n"
    "  Bucket:\n    Type: AWS::S3::Bucket\n"
    "  Queue:\n    Type: AWS::SQS::Queue\n"
)
TPL = "tpl.yaml"
REPORT_DECLARATIONS = (
    "reports_unmodified",
    "same_plugin_version",
    "same_rule_set",
    "same_tool_configuration",
    "same_agent_findings_input",
)
ALL_DECLARATIONS = REPORT_DECLARATIONS + ("reports_match_templates",)
SOURCES = ("cfn-lint", "cfn-guard", "IAM Review", "Network Review", "Secret Review", "Quality Review")


def _finding(resource: Optional[str], category: str, file: str) -> Finding:
    return Finding(
        ID=0,
        Normalized_Category=category,
        FindingType="Security",
        Severity="HIGH",
        Confidence="Confirmed",
        Source=["cfn-guard"],
        Resource=resource,
        Location=Location(File=file, TemplatePath=["Resources", resource or "X"]),
        Finding="finding text",
        WhyItMatters="why",
        Evidence=[Evidence(Source="cfn-guard", Detail="detail", RuleId="s3_bucket_encryption")],
        Recommendation="recommendation",
        SuggestedRemediation=None,
    )


def _report(target: str, findings: Sequence[Tuple[Optional[str], str]]) -> Dict[str, Any]:
    meta = report.ReportMeta(
        files=(target,),
        sources_enabled=SOURCES,
        tools=(report.ToolStatus("cfn-guard", True, "3.2.1"), report.ToolStatus("cfn-lint", True, "1.46.0")),
    )
    return report.build_report([_finding(r, c, target) for r, c in findings], [], meta)


BASE_FINDINGS = (("Bucket", "Encryption"), ("Queue", "Logging"))
HEAD_FINDINGS = (("Bucket", "Encryption"), ("Bucket", "Tagging"))


@pytest.fixture
def ws(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "ws"
    root.mkdir()
    (root / TPL).write_text(TEMPLATE, encoding="utf-8")
    (tmp_path / "outside.yaml").write_text(TEMPLATE, encoding="utf-8")
    monkeypatch.chdir(root)
    return root


def _write_reports(
    root: Path,
    base_target: str = TPL,
    head_target: str = TPL,
    base_findings: Sequence[Tuple[Optional[str], str]] = BASE_FINDINGS,
    head_findings: Sequence[Tuple[Optional[str], str]] = HEAD_FINDINGS,
) -> None:
    (root / "base.json").write_text(report.dump(_report(base_target, base_findings)), encoding="utf-8")
    (root / "head.json").write_text(report.dump(_report(head_target, head_findings)), encoding="utf-8")


def _run(
    base_template: str, head_template: str, declarations: Sequence[str] = ALL_DECLARATIONS
) -> Tuple[int, Dict[str, Any], str]:
    argv = ["--base-template", base_template, "--head-template", head_template]
    argv += ["--base-report", "base.json", "--head-report", "head.json", "--plain-identifiers"]
    for code in declarations:
        argv += ["--declare", code]
    out, err = io.StringIO(), io.StringIO()
    code = deltacli.main(argv, stdout=out, stderr=err)
    return code, json.loads(out.getvalue()), err.getvalue()


def _classes(built: Dict[str, Any]) -> Dict[Tuple[Optional[str], str, str], Tuple[str, Tuple[str, ...]]]:
    shapes = {}
    for entry in built["finding_delta"]["entries"]:
        side = entry["base"] or entry["head"]
        key = (side["Resource"], side["Normalized_Category"], entry["observation"])
        shapes[key] = (entry["classification"], tuple(entry["reasons"]))
    return shapes


def _assert_fail_closed(built: Dict[str, Any]) -> None:
    """No New / Resolved; every one-sided entry is Ambiguous for the mismatch."""
    delta = built["finding_delta"]
    assert delta["analysis_state"] == "analyzed"
    counts = built["summary"]["finding_delta"]["by_classification"]
    assert counts["New"] == 0 and counts["Resolved"] == 0, counts
    one_sided = [e for e in delta["entries"] if e["observation"] != "matched"]
    assert one_sided
    for entry in one_sided:
        assert entry["classification"] == "Ambiguous", entry
        assert "template_report_mismatch" in entry["reasons"], entry


# ---------------------------------------------------------------------------
# 1. Normal case and the reports_match_templates declaration
# ---------------------------------------------------------------------------


def test_consistent_paths_give_new_and_resolved(ws: Path) -> None:
    _write_reports(ws)
    code, built, err = _run(TPL, TPL)
    assert (code, err) == (0, "")
    assert built["finding_delta"]["template_report_correspondence"] == "consistent_by_name_only"
    assert _classes(built) == {
        ("Bucket", "Encryption", "matched"): ("Unchanged", ()),
        ("Queue", "Logging", "base_only"): ("Resolved", ()),
        ("Bucket", "Tagging", "head_only"): ("New", ()),
    }


def test_missing_reports_match_templates_gives_unconfirmed(ws: Path) -> None:
    _write_reports(ws)
    code, built, _ = _run(TPL, TPL, REPORT_DECLARATIONS)
    assert code == 0
    assert built["finding_delta"]["template_report_correspondence"] == "consistent_by_name_only"
    for entry in built["finding_delta"]["entries"]:
        if entry["observation"] == "matched":
            continue
        assert entry["classification"] == "Unconfirmed"
        assert entry["missing_declarations"] == ["reports_match_templates"]


# ---------------------------------------------------------------------------
# 2. Spellings that resolve to the same workspace path
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("spelling", ["./tpl.yaml", "sub/../tpl.yaml", "absolute"])
def test_equivalent_spellings_are_normalized(spelling: str, ws: Path) -> None:
    (ws / "sub").mkdir()
    arg = str(ws / TPL) if spelling == "absolute" else spelling
    _write_reports(ws)
    code, built, _ = _run(arg, arg)
    assert code == 0
    assert built["inputs"]["base"]["template"]["path"] == TPL
    assert built["finding_delta"]["template_report_correspondence"] == "consistent_by_name_only"


# ---------------------------------------------------------------------------
# 3. / 4. One side's path or Resource does not match its own Report
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("side", ["base", "head"])
def test_path_missing_from_one_reports_target_is_inconsistent(side: str, ws: Path) -> None:
    targets = {"base_target": TPL, "head_target": TPL}
    targets[side + "_target"] = "other.yaml"
    _write_reports(ws, **targets)
    code, built, _ = _run(TPL, TPL)
    assert code == 0
    assert built["finding_delta"]["template_report_correspondence"] == "inconsistent"
    _assert_fail_closed(built)


def test_finding_resource_absent_from_the_template_is_inconsistent(ws: Path) -> None:
    _write_reports(ws, head_findings=HEAD_FINDINGS + (("Missing", "Logging"),))
    code, built, _ = _run(TPL, TPL)
    assert code == 0
    assert built["finding_delta"]["template_report_correspondence"] == "inconsistent"
    _assert_fail_closed(built)


# ---------------------------------------------------------------------------
# 5. Symlinks inside the workspace
# ---------------------------------------------------------------------------


def test_symlink_is_compared_by_its_resolved_path(ws: Path) -> None:
    (ws / "link.yaml").symlink_to(TPL)
    _write_reports(ws)
    code, built, _ = _run("link.yaml", "link.yaml")
    assert code == 0
    assert built["inputs"]["base"]["template"]["path"] == TPL
    assert built["finding_delta"]["template_report_correspondence"] == "consistent_by_name_only"


def test_symlink_name_in_the_report_target_is_inconsistent(ws: Path) -> None:
    (ws / "link.yaml").symlink_to(TPL)
    _write_reports(ws, base_target="link.yaml", head_target="link.yaml")
    code, built, _ = _run("link.yaml", "link.yaml")
    assert code == 0
    assert built["finding_delta"]["template_report_correspondence"] == "inconsistent"
    _assert_fail_closed(built)


# ---------------------------------------------------------------------------
# 6. Case and Unicode normalization differences are never equal
# ---------------------------------------------------------------------------


def test_case_difference_is_never_consistent(ws: Path) -> None:
    _write_reports(ws)
    code, built, _ = _run("TPL.yaml", "TPL.yaml")
    # Case-insensitive file system: the file is found under the other case;
    # case-sensitive: it is not found. Neither may count as the same path.
    assert built["finding_delta"]["template_report_correspondence"] in ("inconsistent", "unknown")
    _assert_fail_closed(built)


@pytest.mark.parametrize("variant", ["argument", "target"])
def test_unicode_normalization_difference_is_never_consistent(variant: str, ws: Path) -> None:
    nfc = unicodedata.normalize("NFC", "caf\u00e9.yaml")
    nfd = unicodedata.normalize("NFD", nfc)
    assert nfc != nfd
    (ws / nfc).write_text(TEMPLATE, encoding="utf-8")
    if variant == "argument":
        _write_reports(ws, base_target=nfc, head_target=nfc)
        code, built, _ = _run(nfd, nfd)
    else:
        _write_reports(ws, base_target=nfd, head_target=nfd)
        code, built, _ = _run(nfc, nfc)
    assert built["finding_delta"]["template_report_correspondence"] in ("inconsistent", "unknown")
    _assert_fail_closed(built)


# ---------------------------------------------------------------------------
# 7. Paths outside the workspace
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["traversal", "outward symlink"])
def test_template_outside_the_workspace_is_unknown(kind: str, ws: Path) -> None:
    if kind == "traversal":
        arg = "../outside.yaml"
    else:
        (ws / "out.yaml").symlink_to(ws.parent / "outside.yaml")
        arg = "out.yaml"
    _write_reports(ws)
    code, built, _ = _run(TPL, arg)
    assert code == deltaschema.FAILURE_CODE_TABLE["path_violation"][1]
    assert built["semantic_diff"]["failure"]["code"] == "path_violation"
    assert built["finding_delta"]["template_report_correspondence"] == "unknown"
    _assert_fail_closed(built)


# ---------------------------------------------------------------------------
# 8. An unanalyzable Template
# ---------------------------------------------------------------------------


def test_template_syntax_error_is_unknown(ws: Path) -> None:
    (ws / "broken.yaml").write_text("Resources: [unclosed\n", encoding="utf-8")
    _write_reports(ws, head_target="broken.yaml", head_findings=(("Bucket", "Tagging"),))
    code, built, _ = _run(TPL, "broken.yaml")
    assert code == deltaschema.FAILURE_CODE_TABLE["template_parse_failure"][1]
    assert built["finding_delta"]["template_report_correspondence"] == "unknown"
    _assert_fail_closed(built)


# ---------------------------------------------------------------------------
# 9. A raw ``target.files`` the tool would not have written
# ---------------------------------------------------------------------------


def test_hand_edited_target_spelling_is_a_rebuild_mismatch_and_inconsistent(ws: Path) -> None:
    _write_reports(ws)
    head = json.loads((ws / "head.json").read_text(encoding="utf-8"))
    head["target"]["files"] = ["./" + TPL]
    (ws / "head.json").write_text(json.dumps(head), encoding="utf-8")
    code, built, _ = _run(TPL, TPL)
    assert code == 0
    delta = built["finding_delta"]
    assert delta["report_integrity"]["head"]["failed_checks"] == ["rebuild_mismatch"]
    assert delta["template_report_correspondence"] == "inconsistent"
    _assert_fail_closed(built)


# ---------------------------------------------------------------------------
# 10. The invariant over every mismatching case at once
# ---------------------------------------------------------------------------


MISMATCHES: List[Dict[str, str]] = [
    {"base_target": "other.yaml"},
    {"head_target": "other.yaml"},
    {"base_target": "other.yaml", "head_target": "other.yaml"},
    {"base_target": "TPL.yaml", "head_target": "TPL.yaml"},
    {"base_target": "sub/tpl.yaml"},
]


@pytest.mark.parametrize("targets", MISMATCHES, ids=lambda t: ",".join("{0}={1}".format(k, v) for k, v in sorted(t.items())))
def test_no_mismatch_gives_new_or_resolved(targets: Dict[str, str], ws: Path) -> None:
    _write_reports(ws, **targets)
    for declarations in (ALL_DECLARATIONS, REPORT_DECLARATIONS, ()):
        code, built, _ = _run(TPL, TPL, declarations)
        assert code == 0
        assert built["finding_delta"]["template_report_correspondence"] == "inconsistent"
        counts = built["summary"]["finding_delta"]["by_classification"]
        assert counts["New"] == 0 and counts["Resolved"] == 0, (targets, declarations, counts)


def test_workspace_layout_is_unchanged_by_the_runs(ws: Path) -> None:
    _write_reports(ws)
    before = sorted(os.listdir(ws))
    _run(TPL, TPL)
    assert sorted(os.listdir(ws)) == before


# ---------------------------------------------------------------------------
# 11. --reviewed-template-path (H-M1-1 approved, R1.1, R1.3, R8.6, Design 9-4)
# ---------------------------------------------------------------------------
#
# Expected, written before the implementation. The workspace holds two
# checkouts ``base/stack/template.yaml`` and ``head/stack/template.yaml`` (the
# same Template text, so no rename hint), and Reports whose ``target`` and
# ``Location.File`` are ``stack/template.yaml``. ``stack/template.yaml`` does
# not exist in the workspace itself: a declared path need not exist.
#
# * Declared ``stack/template.yaml`` with all six declarations: the classes of
#   section 1 (Unchanged / Resolved / New).
# * Every case below: no New and no Resolved -- exit 2 with no stdout for an
#   argument the tool refuses, otherwise a fail-closed Delta_Report.

STACK = "stack/template.yaml"
BASE_TPL = "base/" + STACK
HEAD_TPL = "head/" + STACK
DECLARED = "--reviewed-template-path"
CONSISTENT_CLASSES = {
    ("Bucket", "Encryption", "matched"): ("Unchanged", ()),
    ("Queue", "Logging", "base_only"): ("Resolved", ()),
    ("Bucket", "Tagging", "head_only"): ("New", ()),
}


@pytest.fixture
def checkouts(ws: Path) -> Path:
    for side in ("base", "head"):
        (ws / side / "stack").mkdir(parents=True)
        (ws / side / STACK).write_text(TEMPLATE, encoding="utf-8")
    _write_reports(ws, base_target=STACK, head_target=STACK)
    return ws


def _declared_argv(declared: Sequence[str], declarations: Sequence[str] = ALL_DECLARATIONS) -> List[str]:
    argv = ["--base-template", BASE_TPL, "--head-template", HEAD_TPL]
    argv += ["--base-report", "base.json", "--head-report", "head.json", "--plain-identifiers"]
    for code in declarations:
        argv += ["--declare", code]
    for value in declared:
        argv += [DECLARED, value]
    return argv


def _run_declared(
    declared: Sequence[str], declarations: Sequence[str] = ALL_DECLARATIONS
) -> Tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = deltacli.main(_declared_argv(declared, declarations), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def _built_declared(declared: Sequence[str], declarations: Sequence[str] = ALL_DECLARATIONS) -> Dict[str, Any]:
    code, out, _ = _run_declared(declared, declarations)
    assert out, code
    return json.loads(out)


def _no_new_or_resolved(built: Dict[str, Any]) -> None:
    counts = built["summary"]["finding_delta"]["by_classification"]
    assert counts["New"] == 0 and counts["Resolved"] == 0, counts


def test_declared_path_positive_control(checkouts: Path) -> None:
    assert not (checkouts / STACK).exists()
    code, out, err = _run_declared([STACK])
    assert (code, err) == (0, "")
    built = json.loads(out)
    delta = built["finding_delta"]
    assert delta["template_report_correspondence"] == "consistent_by_name_only"
    assert delta["reviewed_template_path"] == {"path": STACK, "status": "declared_not_verified"}
    assert _classes(built) == CONSISTENT_CLASSES
    # The CLI Template paths are still recorded as they are.
    assert built["inputs"]["base"]["template"]["path"] == BASE_TPL
    assert built["inputs"]["head"]["template"]["path"] == HEAD_TPL


def test_undeclared_is_inconsistent(checkouts: Path) -> None:
    built = _built_declared([])
    assert built["finding_delta"]["template_report_correspondence"] == "inconsistent"
    assert built["finding_delta"]["reviewed_template_path"] is None
    _assert_fail_closed(built)


@pytest.mark.parametrize(
    "argv",
    [
        ["--base-report", "base.json", "--head-report", "head.json", DECLARED, STACK],
        ["--base-template", BASE_TPL, "--head-template", HEAD_TPL, DECLARED, STACK],
        _declared_argv([STACK, STACK]),
        _declared_argv([STACK, "other.yaml"]),
    ],
    ids=["no-template-pair", "no-report-pair", "twice-same", "twice-different"],
)
def test_declared_path_needs_both_pairs_and_one_value(argv: List[str], checkouts: Path) -> None:
    out, err = io.StringIO(), io.StringIO()
    assert deltacli.main(argv, stdout=out, stderr=err) == 2
    assert out.getvalue() == ""
    assert err.getvalue().startswith("deltacli: invalid_arguments: ")


CANARY_SEGMENT = "CnyDeclaredPathQz8"
REFUSED_VALUES = [
    "/" + CANARY_SEGMENT + "/" + STACK,
    "../" + CANARY_SEGMENT + ".yaml",
    "a/../../" + CANARY_SEGMENT + ".yaml",
    "\\..\\" + CANARY_SEGMENT + ".yaml",
    "C:\\" + CANARY_SEGMENT + ".yaml",
    "",
    CANARY_SEGMENT + "\x00.yaml",
    CANARY_SEGMENT + ";id.yaml",
    CANARY_SEGMENT + "$(id).yaml",
]


@pytest.mark.parametrize("value", REFUSED_VALUES)
def test_refused_declared_paths_exit_2_without_echo(value: str, checkouts: Path) -> None:
    code, out, err = _run_declared([value])
    assert (code, out) == (2, "")
    first, usage = err.split("\n", 1)
    assert first.startswith("deltacli: invalid_arguments: ")
    assert usage.startswith("usage: ")
    assert CANARY_SEGMENT.lower() not in err.lower()
    assert "Traceback" not in err


def test_declared_path_through_an_outward_symlink_exits_2(checkouts: Path) -> None:
    outside = checkouts.parent / "outside_dir"
    outside.mkdir()
    (checkouts / "escape").symlink_to(outside, target_is_directory=True)
    (checkouts / "escape.yaml").symlink_to(checkouts.parent / "outside.yaml")
    for value in ("escape/" + STACK, "escape.yaml"):
        code, out, err = _run_declared([value])
        assert (code, out) == (2, ""), value
        assert "escape" not in err


def test_declared_path_through_an_inward_symlink_is_compared_by_name(checkouts: Path) -> None:
    (checkouts / "alias").symlink_to(checkouts / "base", target_is_directory=True)
    built = _built_declared(["alias/" + STACK])
    delta = built["finding_delta"]
    assert delta["reviewed_template_path"]["path"] == "alias/" + STACK
    assert delta["template_report_correspondence"] == "inconsistent"
    _assert_fail_closed(built)


@pytest.mark.parametrize("value", ["other.yaml", "stack/other.yaml", BASE_TPL])
def test_wrong_declared_path_is_inconsistent(value: str, checkouts: Path) -> None:
    built = _built_declared([value])
    assert built["finding_delta"]["template_report_correspondence"] == "inconsistent"
    _assert_fail_closed(built)


@pytest.mark.parametrize("side", ["base", "head"])
def test_declared_path_missing_from_one_reports_target_is_inconsistent(side: str, checkouts: Path) -> None:
    targets = {"base_target": STACK, "head_target": STACK}
    targets[side + "_target"] = "stack/other.yaml"
    _write_reports(checkouts, **targets)
    built = _built_declared([STACK])
    assert built["finding_delta"]["template_report_correspondence"] == "inconsistent"
    _assert_fail_closed(built)


def test_declared_path_with_a_resource_absent_from_one_template_is_inconsistent(checkouts: Path) -> None:
    # The Head Template no longer has Queue, and the Head Report names it.
    (checkouts / HEAD_TPL).write_text("Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n", encoding="utf-8")
    meta_findings = HEAD_FINDINGS + (("Queue", "Logging"),)
    _write_reports(checkouts, base_target=STACK, head_target=STACK, head_findings=meta_findings)
    built = _built_declared([STACK])
    assert built["finding_delta"]["template_report_correspondence"] == "inconsistent"
    _assert_fail_closed(built)


def test_declared_path_with_an_unanalyzable_template_is_unknown(checkouts: Path) -> None:
    (checkouts / HEAD_TPL).write_text("Resources: [unclosed\n", encoding="utf-8")
    built = _built_declared([STACK])
    assert built["finding_delta"]["template_report_correspondence"] == "unknown"
    assert built["finding_delta"]["reviewed_template_path"] == {"path": STACK, "status": "declared_not_verified"}
    _assert_fail_closed(built)


def test_declared_path_with_a_rebuild_mismatch_report_is_ambiguous(checkouts: Path) -> None:
    head = json.loads((checkouts / "head.json").read_text(encoding="utf-8"))
    head["findings"].reverse()  # breaks the build_report order
    (checkouts / "head.json").write_text(json.dumps(head), encoding="utf-8")
    built = _built_declared([STACK])
    delta = built["finding_delta"]
    assert delta["template_report_correspondence"] == "consistent_by_name_only"
    assert delta["report_integrity"]["head"]["failed_checks"] == ["rebuild_mismatch"]
    _no_new_or_resolved(built)
    for entry in delta["entries"]:
        if entry["observation"] != "matched":
            assert entry["classification"] == "Ambiguous", entry
            assert "report_integrity_failed" in entry["reasons"], entry


def test_declared_path_without_reports_match_templates_is_unconfirmed(checkouts: Path) -> None:
    built = _built_declared([STACK], REPORT_DECLARATIONS)
    _no_new_or_resolved(built)
    for entry in built["finding_delta"]["entries"]:
        if entry["observation"] != "matched":
            assert entry["classification"] == "Unconfirmed", entry
            assert entry["reasons"] == ["input_declaration_absent"]
            assert entry["missing_declarations"] == ["reports_match_templates"]


def test_declared_path_with_a_tool_version_mismatch_is_not_comparable(checkouts: Path) -> None:
    head = _report(STACK, HEAD_FINDINGS)
    for tool in head["tools"]:
        if tool["name"] == "cfn-guard":
            tool["version"] = "3.3.0"
    (checkouts / "head.json").write_text(report.dump(head), encoding="utf-8")
    built = _built_declared([STACK])
    assert built["finding_delta"]["template_report_correspondence"] == "consistent_by_name_only"
    _no_new_or_resolved(built)
    for entry in built["finding_delta"]["entries"]:
        if entry["observation"] != "matched":
            assert entry["classification"] == "Ambiguous", entry
            assert "source_not_comparable" in entry["reasons"] and "tool_version_mismatch" in entry["reasons"]


@pytest.mark.parametrize("variant", ["case", "nfd-declared", "nfc-declared"])
def test_declared_path_case_and_unicode_differences_are_inconsistent(variant: str, checkouts: Path) -> None:
    nfc = unicodedata.normalize("NFC", "stack/caf\u00e9.yaml")
    nfd = unicodedata.normalize("NFD", nfc)
    if variant == "case":
        declared = STACK.upper()
    elif variant == "nfd-declared":
        _write_reports(checkouts, base_target=nfc, head_target=nfc)
        declared = nfd
    else:
        _write_reports(checkouts, base_target=nfd, head_target=nfd)
        declared = nfc
    built = _built_declared([declared])
    assert built["finding_delta"]["template_report_correspondence"] == "inconsistent"
    _assert_fail_closed(built)


BIDI_DECLARED = "stack/\u202etemplate\u2066.yaml"


def test_declared_path_with_bidi_characters_round_trips_and_stderr_stays_clean(checkouts: Path) -> None:
    code, out, err = _run_declared([BIDI_DECLARED])
    assert code == 0 and err == ""
    built = json.loads(out)
    assert built["finding_delta"]["reviewed_template_path"]["path"] == BIDI_DECLARED
    assert built["finding_delta"]["template_report_correspondence"] == "inconsistent"
    _no_new_or_resolved(built)
    # RC Blocker D-14: written as JSON escapes, never raw.
    assert '"stack/\\u202etemplate\\u2066.yaml"' in out
    assert not any(0x202A <= ord(c) <= 0x202E or 0x2066 <= ord(c) <= 0x2069 for c in out)
    code, out, err = _run_declared([BIDI_DECLARED, "x.yaml"])
    assert (code, out) == (2, "")
    assert not any(0x202A <= ord(c) <= 0x202E or 0x2066 <= ord(c) <= 0x2069 for c in err)


def test_no_mismatching_declaration_gives_new_or_resolved(checkouts: Path) -> None:
    for declared in ([], ["other.yaml"], [STACK.upper()], [BASE_TPL], [HEAD_TPL]):
        for declarations in (ALL_DECLARATIONS, REPORT_DECLARATIONS, ()):
            built = _built_declared(declared, declarations)
            _no_new_or_resolved(built)
