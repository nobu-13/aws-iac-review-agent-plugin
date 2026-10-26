"""Regression: hostile inputs to the Delta_Tool fail safely (v1.1 Task 12).

Requirements guarded
--------------------

v1.1 Requirement 12 AC17 (each case below), AC10 / AC11 / AC13 (stderr is built
by the tool and has control and bidirectional characters replaced), AC12 (no
absolute host path), Requirement 2 AC1 / AC2 (inputs are resolved inside the
workspace, arguments are checked before any input is read), and Requirement 8
AC7 (an input Report's ``errors[]`` strings are not copied).

Every case asserts the same boundary contract on top of its own expectation:

* the exit code is the one the failure Code maps to (Design 10-5), never 1;
* stdout is either empty (argument errors) or one Delta_Report, and the failed
  comparison holds no partial result;
* stderr holds only ``deltacli: `` lines, no traceback, no raw control or
  bidirectional character, and no path of the host.

Inputs are written to ``tmp_path``; the committed ``tests/fixtures/invalid/``
files are read in place and not copied into the repository.
"""

from __future__ import annotations

import dataclasses
import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pytest

from iacreview import deltacli, deltaschema, report
from iacreview.finding import Evidence, Finding, Location

REPO_ROOT = Path(__file__).resolve().parents[2]
INVALID = REPO_ROOT / "tests" / "fixtures" / "invalid"

SIMPLE = "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n"
SIMPLE_HEAD = SIMPLE + "    Properties:\n      BucketName: cnyvalueab12\n"
TEMPLATE_FILE = "templates/app.yaml"

#: C0 / C1 controls, DEL and the bidirectional controls stderr must not carry raw.
_UNSAFE = set(range(0x00, 0x20)) - {0x0A} | set(range(0x7F, 0xA0)) | set(range(0x202A, 0x202F)) | set(
    range(0x2066, 0x206A)
) | {0x200E, 0x200F, 0x061C}


def _run(argv: Sequence[str]) -> Tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = deltacli.main(list(argv), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def _assert_safe_stderr(err: str, root: Path) -> None:
    assert "Traceback" not in err
    usage = deltacli.build_parser().format_usage()
    if err.endswith(usage):
        # An argument error ends with the fixed usage text of the parser.
        err = err[: -len(usage)]
    for line in err.splitlines():
        assert line.startswith("deltacli: "), line
    assert not [hex(ord(c)) for c in err if ord(c) in _UNSAFE]
    assert str(root) not in err and str(root.resolve()) not in err


def _assert_failed(argv: Sequence[str], root: Path, part: str, code: str) -> Dict[str, Any]:
    """Run ``argv``; the ``part`` comparison failed with failure Code ``code``."""
    got, out, err = _run(argv)
    assert got == deltaschema.FAILURE_CODE_TABLE[code][1], (got, err)
    _assert_safe_stderr(err, root)
    built = json.loads(out)
    section = built[part]
    assert section["analysis_state"] == "unanalyzable"
    assert section["failure"]["code"] == code
    if part == "semantic_diff":
        assert section["changes"] == [] and section["uncompared_paths"] == []
    else:
        assert section["entries"] == []
    assert built["errors"] and built["errors"][0]["error_class"] == deltaschema.FAILURE_CODE_TABLE[code][0]
    assert str(root) not in out and str(root.resolve()) not in out
    return built


def _finding(resource: Optional[str], n: int = 0) -> Finding:
    return Finding(
        ID=0,
        Normalized_Category="Encryption",
        FindingType="Security",
        Severity="HIGH",
        Confidence="Confirmed",
        Source=["cfn-guard"],
        Resource=resource,
        Location=Location(File=TEMPLATE_FILE, TemplatePath=["Resources", resource or "X", "Properties", "P{0}".format(n)]),
        Finding="finding text",
        WhyItMatters="why",
        Evidence=[Evidence(Source="cfn-guard", Detail="detail", RuleId="s3_bucket_encryption")],
        Recommendation="recommendation",
        SuggestedRemediation=None,
    )


def _report_obj(findings: Sequence[Finding], errors: Sequence[Dict[str, Any]] = ()) -> Dict[str, Any]:
    meta = report.ReportMeta(
        files=(TEMPLATE_FILE,),
        sources_enabled=("cfn-lint", "cfn-guard", "IAM Review", "Network Review", "Secret Review", "Quality Review"),
        tools=(report.ToolStatus("cfn-guard", True, "3.2.1"), report.ToolStatus("cfn-lint", True, "1.46.0")),
    )
    return report.build_report(list(findings), list(errors), meta)


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "base.yaml").write_text(SIMPLE, encoding="utf-8")
    (workspace / "head.yaml").write_text(SIMPLE_HEAD, encoding="utf-8")
    (workspace / "base.json").write_text(report.dump(_report_obj([_finding("Bucket")])), encoding="utf-8")
    (workspace / "head.json").write_text(report.dump(_report_obj([])), encoding="utf-8")
    # Outside the workspace: what traversal and symlinks would reach.
    (tmp_path / "outside.yaml").write_text(SIMPLE + "# cnyoutsidecontent\n", encoding="utf-8")
    (tmp_path / "outside.json").write_text(report.dump(_report_obj([])), encoding="utf-8")
    monkeypatch.chdir(workspace)
    return workspace


def _files(root: Path) -> List[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*"))


# ---------------------------------------------------------------------------
# Paths: traversal, outward symlinks, non-regular files (R12.17, R2.1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("arg", ["../outside.yaml", "sub/../../outside.yaml", "./../outside.yaml"])
def test_path_traversal_is_a_path_violation(arg: str, root: Path) -> None:
    (root / "sub").mkdir()
    built = _assert_failed(["--base-template", arg, "--head-template", "head.yaml"], root, "semantic_diff", "path_violation")
    assert built["inputs"]["base"]["template"]["path"] is None
    assert "cnyoutsidecontent" not in json.dumps(built)


def test_absolute_path_outside_is_a_path_violation(root: Path) -> None:
    outside = str(root.parent / "outside.json")
    built = _assert_failed(["--base-report", outside, "--head-report", "head.json"], root, "finding_delta", "path_violation")
    assert outside not in json.dumps(built)


def test_absolute_template_path_outside_is_a_path_violation(root: Path) -> None:
    outside = str(root.parent / "outside.yaml")
    built = _assert_failed(
        ["--base-template", outside, "--head-template", "head.yaml"], root, "semantic_diff", "path_violation"
    )
    assert outside not in json.dumps(built)
    assert "cnyoutsidecontent" not in json.dumps(built)


def test_outward_symlink_is_a_path_violation(root: Path) -> None:
    (root / "link.yaml").symlink_to(root.parent / "outside.yaml")
    _assert_failed(["--base-template", "link.yaml", "--head-template", "head.yaml"], root, "semantic_diff", "path_violation")
    (root / "link.json").symlink_to(root.parent / "outside.json")
    _assert_failed(["--base-report", "link.json", "--head-report", "head.json"], root, "finding_delta", "path_violation")


def test_outward_symlinked_directory_is_a_path_violation(root: Path) -> None:
    (root / "linkdir").symlink_to(root.parent)
    _assert_failed(
        ["--base-template", "linkdir/outside.yaml", "--head-template", "head.yaml"], root, "semantic_diff", "path_violation"
    )


def test_directory_is_a_path_violation(root: Path) -> None:
    (root / "dir.yaml").mkdir()
    _assert_failed(["--base-template", "base.yaml", "--head-template", "dir.yaml"], root, "semantic_diff", "path_violation")
    _assert_failed(["--base-report", "base.json", "--head-report", "dir.yaml"], root, "finding_delta", "path_violation")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="the platform has no FIFO")
def test_fifo_is_refused_without_blocking(root: Path) -> None:
    os.mkfifo(str(root / "pipe.yaml"))
    env = dict(os.environ)
    env.update({"PYTHONPATH": str(REPO_ROOT), "PYTHONDONTWRITEBYTECODE": "1"})
    started = time.monotonic()
    # A child process with a timeout: a reader that opened the FIFO would block.
    run = subprocess.run(
        [sys.executable, "-m", "iacreview.deltacli", "--base-template", "pipe.yaml", "--head-template", "head.yaml"],
        cwd=str(root),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    assert time.monotonic() - started < 60
    assert run.returncode == 7, run.stderr
    built = json.loads(run.stdout)
    assert built["semantic_diff"]["failure"]["code"] == "path_violation"
    _assert_safe_stderr(run.stderr.decode("utf-8"), root)


# ---------------------------------------------------------------------------
# Limits: size and Finding count (R12.17, R14.1-R14.3)
# ---------------------------------------------------------------------------


def test_template_over_the_shipped_size_limit(root: Path) -> None:
    padding = deltaschema.MAX_TEMPLATE_BYTES + 1 - len(SIMPLE.encode("utf-8"))
    (root / "big.yaml").write_text(SIMPLE + "#" * (padding - 1) + "\n", encoding="utf-8")
    assert (root / "big.yaml").stat().st_size == deltaschema.MAX_TEMPLATE_BYTES + 1
    _assert_failed(["--base-template", "base.yaml", "--head-template", "big.yaml"], root, "semantic_diff", "template_too_large")


def test_report_over_the_shipped_size_limit(root: Path) -> None:
    text = report.dump(_report_obj([]))
    (root / "big.json").write_text(text + " " * (deltaschema.MAX_REPORT_BYTES + 1 - len(text)), encoding="utf-8")
    assert (root / "big.json").stat().st_size == deltaschema.MAX_REPORT_BYTES + 1
    _assert_failed(["--base-report", "base.json", "--head-report", "big.json"], root, "finding_delta", "report_too_large")


def test_finding_count_over_the_limit(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(deltaschema, "MAX_REPORT_FINDINGS", 2)
    two = [_finding("Bucket", 1), _finding("Queue", 2)]
    (root / "two.json").write_text(report.dump(_report_obj(two)), encoding="utf-8")
    code, out, _ = _run(["--base-report", "base.json", "--head-report", "two.json"])
    assert code == 0 and json.loads(out)["finding_delta"]["analysis_state"] == "analyzed"
    three = two + [_finding("Topic", 3)]
    (root / "three.json").write_text(report.dump(_report_obj(three)), encoding="utf-8")
    _assert_failed(
        ["--base-report", "base.json", "--head-report", "three.json"], root, "finding_delta", "report_finding_limit_exceeded"
    )


# ---------------------------------------------------------------------------
# tests/fixtures/invalid/*, Python object tag, alias bomb, cycles (R12.17)
# ---------------------------------------------------------------------------

#: Expected failure Code of each committed invalid fixture as the Head Template.
#: Every file of the directory must be listed (checked below).
INVALID_EXPECTED: Dict[str, str] = {
    "billion_laughs.yaml": "template_node_limit_exceeded",
    "binary_content.yaml": "template_encoding_failure",
    "bom_prefixed.json": "template_parse_failure",
    "empty_file.yaml": "template_parse_failure",
    "empty_resources.json": "template_not_reviewable",
    "malformed_syntax.json": "template_parse_failure",
    "malformed_syntax.yaml": "template_parse_failure",
    "no_resources.yaml": "template_not_reviewable",
    "python_object_tag.yaml": "template_parse_failure",
    "tab_indentation.yaml": "template_parse_failure",
    "truncated.yaml": "template_parse_failure",
    "unsupported_yaml_tag.yaml": "template_parse_failure",
}


def test_every_invalid_fixture_is_listed() -> None:
    names = sorted(p.name for p in INVALID.iterdir() if p.is_file() and p.name != ".gitkeep")
    assert names == sorted(INVALID_EXPECTED)


@pytest.mark.parametrize("name", sorted(INVALID_EXPECTED))
def test_invalid_fixture(name: str, root: Path) -> None:
    # The fixture's bytes are placed in the workspace, since a path outside it
    # is refused before it is read.
    (root / name).write_bytes((INVALID / name).read_bytes())
    started = time.monotonic()
    built = _assert_failed(
        ["--base-template", "base.yaml", "--head-template", name], root, "semantic_diff", INVALID_EXPECTED[name]
    )
    assert time.monotonic() - started < 10
    assert built["semantic_diff"]["failure"]["side"] == "head"


def test_python_object_tag_runs_nothing(root: Path) -> None:
    marker = root / "marker_created"
    (root / "tag.yaml").write_text(
        "Resources:\n  B:\n    Type: !!python/object/apply:os.system ['touch {0}']\n".format(marker.name),
        encoding="utf-8",
    )
    before = _files(root)
    _assert_failed(["--base-template", "base.yaml", "--head-template", "tag.yaml"], root, "semantic_diff", "template_parse_failure")
    assert not marker.exists()
    assert _files(root) == before


def test_alias_bomb_at_the_shipped_alias_budget_is_bounded(root: Path) -> None:
    (root / "bomb.yaml").write_bytes((INVALID / "billion_laughs.yaml").read_bytes())
    started = time.monotonic()
    _assert_failed(
        ["--base-template", "bomb.yaml", "--head-template", "head.yaml"], root, "semantic_diff", "template_node_limit_exceeded"
    )
    assert time.monotonic() - started < 5


@pytest.mark.parametrize(
    "text",
    [
        "Resources: &r\n  R: *r\n",
        "Resources:\n  R: &l\n    - *l\n",
        "Resources:\n  R:\n    Type: AWS::S3::Bucket\n    Properties: &p\n      Self: *p\n",
    ],
    ids=["mapping", "list", "inside-resource"],
)
def test_alias_cycle(text: str, root: Path) -> None:
    (root / "cycle.yaml").write_text(text, encoding="utf-8")
    _assert_failed(["--base-template", "base.yaml", "--head-template", "cycle.yaml"], root, "semantic_diff", "template_alias_cycle")


# ---------------------------------------------------------------------------
# Arguments: shell metacharacters (R12.17, R2.2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["--base-template", "base.yaml;touch pwned", "--head-template", "head.yaml"],
        ["--base-template", "base.yaml", "--head-template", "$(touch pwned).yaml"],
        ["--base-template", "`touch pwned`", "--head-template", "head.yaml"],
        ["--base-report", "base.json|touch pwned", "--head-report", "head.json"],
        ["--base-report", "base.json", "--head-report", "head.json&&touch pwned"],
        ["--base-report", "base.json", "--head-report", "head.json>pwned"],
        ["--base-report", "<pwned", "--head-report", "head.json"],
        ["--base-report", "base.json", "--head-report", "head.json", "--declare", "reports_unmodified;touch pwned"],
    ],
)
def test_shell_metacharacters_exit_2_and_run_nothing(argv: List[str], root: Path) -> None:
    before = _files(root)
    code, out, err = _run(argv)
    assert code == 2 and out == ""
    _assert_safe_stderr(err, root)
    assert "pwned" not in err
    assert _files(root) == before


# ---------------------------------------------------------------------------
# Control and bidirectional characters (R12.13)
# ---------------------------------------------------------------------------

INJECTED = "Cny\x1b[31mRed\u202eRtl\u2066Iso\x85Nel\x07Bel"


def test_control_and_bidi_in_contents(root: Path) -> None:
    (root / "inj.yaml").write_text(
        SIMPLE
        + '  "{0}":\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: "{0}"\n'.format(
            INJECTED.replace("\x1b", "\\e").replace("\x85", "\\N").replace("\x07", "\\a")
        ),
        encoding="utf-8",
    )
    head = _report_obj([_finding("Bucket")])
    head["findings"][0]["Finding"] = INJECTED
    (root / "inj.json").write_text(json.dumps(head), encoding="utf-8")
    argv = ["--base-template", "base.yaml", "--head-template", "inj.yaml", "--base-report", "base.json", "--head-report", "inj.json"]
    code, out, err = _run(argv)
    _assert_safe_stderr(err, root)
    # Anonymized by default: neither the injected identifier nor the value is written.
    assert "Cny" not in out
    assert not [c for c in out if ord(c) in _UNSAFE]
    code, out, err = _run(argv + ["--plain-identifiers"])
    _assert_safe_stderr(err, root)
    built = json.loads(out)
    # The plain identifier is escaped by the JSON serializer and round-trips.
    assert INJECTED in [c["path"][1] for c in built["semantic_diff"]["changes"]]
    assert not [c for c in out if 0x00 <= ord(c) < 0x20 and c != "\n"]


def test_control_and_bidi_in_a_file_name(root: Path) -> None:
    name = "a\x1bb\u202ec.yaml"
    (root / name).write_text("Resources: [\n", encoding="utf-8")
    code, out, err = _run(["--base-template", "base.yaml", "--head-template", name])
    assert code == 4
    _assert_safe_stderr(err, root)
    built = json.loads(out)
    assert built["inputs"]["head"]["template"]["path"] == name
    assert "\x1b" not in out


def test_stderr_replaces_control_characters_it_is_given() -> None:
    line = deltacli.sanitize_stderr("x\x1b\u202e\u2066\x85\x00y")
    assert not [c for c in line if ord(c) in _UNSAFE]


# ---------------------------------------------------------------------------
# Input Reports: absolute paths and errors[] strings (R12.12, R8.7)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "edit",
    [
        lambda obj: obj["findings"][0]["Location"].__setitem__("File", "/CnyHostDir/app.yaml"),
        lambda obj: obj["target"].__setitem__("files", ["/CnyHostDir/app.yaml"]),
        lambda obj: obj["target"]["cdk"].__setitem__("synthesized_templates", ["/CnyHostDir/cdk.out/a.json"]),
    ],
    ids=["Location.File", "target.files", "synthesized_templates"],
)
def test_absolute_path_in_an_input_report(edit: Any, root: Path) -> None:
    obj = _report_obj([_finding("Bucket")])
    edit(obj)
    (root / "abs.json").write_text(json.dumps(obj), encoding="utf-8")
    code, out, err = _run(["--base-report", "base.json", "--head-report", "abs.json"])
    assert code == 4
    assert "CnyHostDir" not in out and "CnyHostDir" not in err
    _assert_safe_stderr(err, root)
    assert json.loads(out)["finding_delta"]["failure"]["code"] == "report_schema_violation"


def test_input_report_errors_strings_are_not_written(root: Path) -> None:
    error = {
        "error_class": "tool_execution",
        "source": "cfn-lint",
        "tool": "cfn-lint",
        "exit_code": 2,
        "message": "failed at /CnyHostDir/x.yaml CnyMessageText",
        "required_min_version": "1.0.0",
        "detected_version": "0.1.0",
        "remediation": "CnyRemediationText",
        "stderr_head": ["/CnyHostDir/tool: CnyStderrText"],
    }
    (root / "errs.json").write_text(report.dump(_report_obj([], [error])), encoding="utf-8")
    for argv in (
        ["--base-report", "base.json", "--head-report", "errs.json"],
        ["--base-report", "errs.json", "--head-report", "errs.json", "--plain-identifiers"],
    ):
        code, out, err = _run(argv)
        assert code == 0
        for text in ("CnyHostDir", "CnyMessageText", "CnyRemediationText", "CnyStderrText"):
            assert text not in out and text not in err
        built = json.loads(out)
        assert built["inputs"]["head"]["report"]["error_summary"] == [{"error_class": "tool_execution", "source": "cfn-lint"}]
        assert built["errors"] == []


# ---------------------------------------------------------------------------
# A-3b: digit characters ``int()`` refuses (R10.4, R12.2)
# ---------------------------------------------------------------------------

_NON_DECIMAL = "\u00b2"
_ARABIC_123 = "\u0661\u0662\u0663"


def _digit_finding(path: List[Any]) -> Finding:
    return dataclasses.replace(_finding("Bucket"), Location=Location(File=TEMPLATE_FILE, TemplatePath=path))


def test_non_decimal_digit_key_in_templates_is_compared(root: Path) -> None:
    def body(value: str) -> str:
        return SIMPLE + '    Metadata:\n      "{0}": {1}\n      "{2}": b\n'.format(_NON_DECIMAL, value, _ARABIC_123)

    (root / "u_base.yaml").write_text(body("a"), encoding="utf-8")
    (root / "u_head.yaml").write_text(body("z"), encoding="utf-8")
    code, out, err = _run(["--base-template", "u_base.yaml", "--head-template", "u_head.yaml"])
    assert (code, err) == (0, "")
    built = json.loads(out)
    assert built["semantic_diff"]["analysis_state"] == "analyzed"
    assert len(built["semantic_diff"]["changes"]) == 1
    assert _NON_DECIMAL not in out and _ARABIC_123 not in out


def test_non_decimal_digit_segment_in_reports_is_compared(root: Path) -> None:
    path = ["Resources", "Bucket", "Metadata", _NON_DECIMAL, _ARABIC_123]
    obj = _report_obj([_digit_finding(path)])
    (root / "u.json").write_text(report.dump(obj), encoding="utf-8")
    code, out, err = _run(["--base-report", "u.json", "--head-report", "u.json"])
    assert (code, err) == (0, "")
    built = json.loads(out)
    assert built["finding_delta"]["analysis_state"] == "analyzed"
    assert [e["observation"] for e in built["finding_delta"]["entries"]] == ["matched"]
    assert _NON_DECIMAL not in out and _ARABIC_123 not in out


# ---------------------------------------------------------------------------
# A-5: display safety of path strings (R12.13, Design 10-3)
# ---------------------------------------------------------------------------

#: What a terminal or UI may interpret: C1, bidi controls and marks.
_DISPLAY_UNSAFE = set(range(0x80, 0xA0)) | set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {
    0x200E,
    0x200F,
    0x061C,
}
BIDI_NAME = "t\u202eu\u2066v\u200fw\x85x.yaml"
#: BIDI_NAME as a JSON string literal of the Delta_Report (D-14, lowercase hex).
_ESCAPED_BIDI_NAME = '"t\\u202eu\\u2066v\\u200fw\\u0085x.yaml"'


def _path_field_count(value: Any, wanted: str) -> int:
    """How many strings of ``value`` (keys and values) equal ``wanted``."""
    count = 0
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            stack.extend(current.keys())
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
        elif current == wanted:
            count += 1
    return count


def _scrub_paths(built: Dict[str, Any]) -> Dict[str, Any]:
    """Replace every value of a field that holds a workspace-relative path."""
    for side in ("base", "head"):
        side_input = built["inputs"][side]
        if side_input["template"] is not None:
            side_input["template"]["path"] = ""
        rep = side_input["report"]
        if rep is not None:
            rep["path"] = ""
            if rep["target"] is not None:
                rep["target"]["files"] = []
                rep["target"]["cdk"]["synthesized_templates"] = []
    delta_part = built["finding_delta"]
    if delta_part is not None:
        for entry in delta_part["entries"]:
            entry["key"]["File"] = ""
            for side in ("base", "head"):
                if entry[side] is not None:
                    entry[side]["File"] = ""
    return built


def test_bidi_and_c1_in_paths_appear_only_in_path_fields(root: Path) -> None:
    (root / BIDI_NAME).write_text(SIMPLE, encoding="utf-8")
    finding = dataclasses.replace(_finding("Bucket"), Location=Location(File=BIDI_NAME, TemplatePath=["Resources", "Bucket"]))
    meta = report.ReportMeta(
        files=(BIDI_NAME,),
        sources_enabled=("cfn-lint", "cfn-guard", "IAM Review", "Network Review", "Secret Review", "Quality Review"),
        tools=(report.ToolStatus("cfn-guard", True, "3.2.1"), report.ToolStatus("cfn-lint", True, "1.46.0")),
    )
    (root / "bidi_base.json").write_text(report.dump(report.build_report([finding], [], meta)), encoding="utf-8")
    (root / "bidi_head.json").write_text(report.dump(report.build_report([], [], meta)), encoding="utf-8")
    argv = ["--base-template", BIDI_NAME, "--head-template", BIDI_NAME, "--base-report", "bidi_base.json", "--head-report", "bidi_head.json"]
    code, out, err = _run(argv)
    assert code == 0, err
    _assert_safe_stderr(err, root)
    assert err == ""
    built = json.loads(out)
    # JSON is data: the path round-trips exactly, with C0 escaped by the serializer.
    assert built["inputs"]["base"]["template"]["path"] == BIDI_NAME
    assert built["inputs"]["base"]["report"]["target"]["files"] == [BIDI_NAME]
    assert [e["key"]["File"] for e in built["finding_delta"]["entries"]] == [BIDI_NAME]
    assert not [c for c in out if ord(c) < 0x20 and c != "\n"]
    # RC Blocker D-14: no raw bidi / C1 character; the path fields carry them
    # as JSON escapes, and nothing else does.
    assert not [hex(ord(c)) for c in out if ord(c) in _DISPLAY_UNSAFE]
    assert out.count(_ESCAPED_BIDI_NAME) == _path_field_count(built, BIDI_NAME)
    scrubbed = report.dump(_scrub_paths(built))
    assert not [hex(ord(c)) for c in scrubbed if ord(c) in _DISPLAY_UNSAFE]
    assert "\\u" not in scrubbed


#: One name per path field, each with other D-14 code points.
DECLARED_BIDI_NAME = "d\u202du\u2069\u200e\x9fx.yaml"
REPORT_BIDI_NAME = "r\u202a\u2067\u061c\x80y\u202c\u2068.yaml"


@pytest.mark.parametrize("plain", [False, True])
def test_bidi_and_c1_are_escaped_in_every_path_field(plain: bool, root: Path) -> None:
    """D-14: the Template path, the declared path, the Report ``target.files``
    and ``Location.File`` each carry the escapes and decode to the input."""
    (root / BIDI_NAME).write_text(SIMPLE, encoding="utf-8")
    finding = dataclasses.replace(
        _finding("Bucket"), Location=Location(File=REPORT_BIDI_NAME, TemplatePath=["Resources", "Bucket"])
    )
    meta = report.ReportMeta(
        files=(REPORT_BIDI_NAME,),
        sources_enabled=("cfn-lint", "cfn-guard", "IAM Review", "Network Review", "Secret Review", "Quality Review"),
        tools=(report.ToolStatus("cfn-guard", True, "3.2.1"), report.ToolStatus("cfn-lint", True, "1.46.0")),
    )
    (root / "bidi_base.json").write_text(report.dump(report.build_report([finding], [], meta)), encoding="utf-8")
    (root / "bidi_head.json").write_text(report.dump(report.build_report([], [], meta)), encoding="utf-8")
    argv = ["--base-template", BIDI_NAME, "--head-template", BIDI_NAME, "--base-report", "bidi_base.json"]
    argv += ["--head-report", "bidi_head.json", "--reviewed-template-path", DECLARED_BIDI_NAME]
    code, out, err = _run(argv + (["--plain-identifiers"] if plain else []))
    assert code == 0, err
    assert err == ""
    assert not [hex(ord(c)) for c in out if ord(c) in _DISPLAY_UNSAFE]
    built = json.loads(out)
    assert built["inputs"]["base"]["template"]["path"] == BIDI_NAME
    assert built["inputs"]["head"]["template"]["path"] == BIDI_NAME
    assert built["finding_delta"]["reviewed_template_path"]["path"] == DECLARED_BIDI_NAME
    assert built["inputs"]["base"]["report"]["target"]["files"] == [REPORT_BIDI_NAME]
    assert [e["key"]["File"] for e in built["finding_delta"]["entries"]] == [REPORT_BIDI_NAME]
    assert [e["base"]["File"] for e in built["finding_delta"]["entries"]] == [REPORT_BIDI_NAME]
    for name in (BIDI_NAME, DECLARED_BIDI_NAME, REPORT_BIDI_NAME):
        literal = json.dumps(name, ensure_ascii=True)
        assert literal.lower() == literal  # the escapes are lowercase hex
        assert out.count(literal) == _path_field_count(built, name) > 0, name
    # Bytes: the escapes are the only difference from report.dump.
    assert out == report.dump(built).translate(
        {code: "\\u{0:04x}".format(code) for code in _DISPLAY_UNSAFE}
    )


def test_bidi_identifiers_are_not_written_by_default(root: Path) -> None:
    name = "Cny\u202eRtl\u200fMark\u061cAlm\x85Nel"
    escaped = name.replace("\x85", "\\N")
    body = SIMPLE + '  "{0}":\n    Type: AWS::S3::Bucket\n'.format(escaped)
    (root / "bidi_ids.yaml").write_text(body, encoding="utf-8")
    finding = _finding(name)
    obj = _report_obj([finding])
    (root / "bidi_ids.json").write_text(report.dump(obj), encoding="utf-8")
    code, out, err = _run(
        ["--base-template", "base.yaml", "--head-template", "bidi_ids.yaml", "--base-report", "base.json", "--head-report", "bidi_ids.json"]
    )
    _assert_safe_stderr(err, root)
    assert "Cny" not in out
    assert not [hex(ord(c)) for c in out if ord(c) in _DISPLAY_UNSAFE]


def test_bidi_file_name_outside_the_workspace_keeps_stderr_safe(root: Path) -> None:
    (root.parent / BIDI_NAME).write_text(SIMPLE, encoding="utf-8")
    code, out, err = _run(["--base-template", "base.yaml", "--head-template", "../" + BIDI_NAME])
    assert code == 7
    _assert_safe_stderr(err, root)
    assert not [hex(ord(c)) for c in err if ord(c) in _DISPLAY_UNSAFE]
    assert json.loads(out)["semantic_diff"]["failure"]["code"] == "path_violation"


# ---------------------------------------------------------------------------
# Output size limit reached in stages (RC Blocker P0, R10.4, D-H15)
# ---------------------------------------------------------------------------


def _deep_list_template(offset: int, elements: int) -> str:
    """Canary keys around a list of ``elements`` integers; Head adds ``offset``."""
    keys = ["cnydeepkey{0:02d}".format(n) for n in range(20)]
    opening = "".join('{{"{0}": '.format(key) for key in keys)
    items = json.dumps(["cnydeepvalue{0}".format(n + offset) for n in range(elements)])
    return ('{"Resources": {"CnyDeepLogicalId": {"Type": "AWS::S3::Bucket", "Properties": '
            + opening + items + "}" * len(keys) + "}}}")


@pytest.mark.parametrize("stage", ["lower_bound", "serialization"])
@pytest.mark.parametrize("plain", [False, True])
def test_output_limit_in_stages_writes_only_the_minimal_report(
    stage: str, plain: bool, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from iacreview import deltareport

    (root / "deep_base.json").write_text(_deep_list_template(0, 40), encoding="utf-8")
    (root / "deep_head.json").write_text(_deep_list_template(1, 40), encoding="utf-8")
    argv = ["--base-template", "deep_base.json", "--head-template", "deep_head.json"]
    argv += ["--plain-identifiers"] if plain else []
    code, full, _ = _run(argv)
    assert code == 0
    size = len(full.encode("utf-8"))
    # 40 Change_Entries, path length 24 (Resources, Logical ID, Properties, 20 keys, index).
    bound = 40 * (deltareport._CHANGE_ENTRY_MIN_BYTES + deltareport._PATH_ITEM_MIN_BYTES * 24)
    assert bound < size
    limit = bound - 1 if stage == "lower_bound" else (bound + size) // 2
    monkeypatch.setattr(deltaschema, "MAX_OUTPUT_BYTES", limit)
    got, out, err = _run(argv)
    assert got == 3
    _assert_safe_stderr(err, root)
    assert err == "deltacli: output: output_size_limit_exceeded (limit {0})\n".format(limit)
    built = json.loads(out)
    assert built["semantic_diff"]["analysis_state"] == "unanalyzable"
    assert built["semantic_diff"]["changes"] == [] and built["semantic_diff"]["uncompared_paths"] == []
    assert built["semantic_diff"]["failure"]["code"] == "output_size_limit_exceeded"
    assert len(out.encode("utf-8")) < 4096
    for text in (out, err):
        assert "cny" not in text.lower()
