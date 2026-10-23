"""Compatibility of the v1.1 Delta_Tool with v1.0 (v1.1 Task 13).

Requirements guarded
--------------------

* v1.1 Requirement 13 AC2, Requirement 8 AC8, Requirement 15 AC7: the
  existing Skill scripts and the shared parser of ``iacreview/bootstrap.py``
  keep their argument sets. The Delta_Tool options (``--declare``,
  ``--plain-identifiers``, ``--base-report``) exit 2 on every Skill script,
  while the same argv without the new option parses: the rejection is caused
  by the new option alone. ``bootstrap.new_parser`` still defines exactly the
  options recorded in Task 0.2 (``-h``, ``--help``, ``--verbose``;
  ``docs/v2/v1.1-m0-measurement.md`` section 4, row 4).
* v1.1 Requirement 16 AC6, Requirement 1 AC8 / AC9: the new modules import
  only the standard library, PyYAML and ``iacreview``, and none of the
  process / network modules; checked on the AST.
* tasks.md 0-2 rule 5: the new modules do not contain the strings
  ``hypothesis`` and ``.kiro`` (two existing tests enforce the same on the
  whole package).
* v1.1 Requirement 16 AC1: the Core functions take parsed values and return
  structured results, callable directly with every file and process
  operation blocked, without changing their inputs.
"""

from __future__ import annotations

import ast
import builtins
import copy
import importlib.util
import io
import json
import os
import pathlib
import subprocess
import sys
import sysconfig
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, List, Set

import pytest

from iacreview import bootstrap, delta, deltacli, deltaio, deltareport, deltaschema, report, reportcheck, semdiff
from iacreview.deltareport import DeltaRequest, ReportInput, TemplateInput
from iacreview.finding import Evidence, Finding, Location

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The five existing Skills (tests/unit/test_skills.py ``SKILL_NAMES``).
SKILLS = ("cfn-guard-review", "cfn-lint-review", "cloudformation-review", "iac-review", "iam-review")
SKILL_SCRIPTS = sorted((REPO_ROOT / "skills").glob("*/scripts/*.py"))

#: Options of the Delta_Tool that no Skill script may accept.
NEW_OPTIONS = (
    ["--declare", "reports_unmodified"],
    ["--plain-identifiers"],
    ["--base-report", "x.json"],
)

#: Task 0.2 record of the options ``bootstrap.new_parser`` defines.
NEW_PARSER_OPTIONS = {"-h", "--help", "--verbose"}

#: The modules v1.1 adds under ``iacreview/``.
NEW_MODULES = ("delta", "deltacli", "deltaio", "deltareport", "deltaschema", "reportcheck", "semdiff")

#: R16.6 / R1.8: never imported by a new module, even from the standard library.
FORBIDDEN_IMPORTS = {"subprocess", "socket", "urllib", "http", "ssl", "ftplib", "smtplib", "asyncio"}

TEMPLATE_TEXT = "Resources:\n  App:\n    Type: AWS::S3::Bucket\n"


# ---------------------------------------------------------------------------
# Existing Skill scripts and the shared parser (R13.2, R8.8, R15.7)
# ---------------------------------------------------------------------------


def test_the_script_inventory_is_the_v10_one() -> None:
    assert sorted({p.parents[1].name for p in SKILL_SCRIPTS}) == sorted(SKILLS)
    assert len(SKILL_SCRIPTS) == 7


def _load_script(path: Path) -> ModuleType:
    name = "delta_compat_{0}_{1}".format(path.parents[1].name.replace("-", "_"), path.stem)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _options(parser: Any) -> Set[str]:
    return {option for action in parser._actions for option in action.option_strings}


@pytest.mark.parametrize("script", SKILL_SCRIPTS, ids=lambda p: p.name)
def test_script_parser_accepts_the_baseline_and_rejects_new_options(
    script: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_script(script)
    parser = module.build_parser()
    assert not _options(parser) & {"--declare", "--plain-identifiers", "--base-report", "--head-report"}
    parser.parse_args(["--target", "app.yaml"])
    for option in NEW_OPTIONS:
        with pytest.raises(SystemExit) as caught:
            module.build_parser().parse_args(["--target", "app.yaml"] + option)
        assert caught.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""


@pytest.mark.parametrize("option", NEW_OPTIONS, ids=lambda o: o[0])
@pytest.mark.parametrize("script", SKILL_SCRIPTS, ids=lambda p: p.name)
def test_script_process_exits_2_on_new_options(script: Path, option: List[str], tmp_path: Path) -> None:
    (tmp_path / "app.yaml").write_text(TEMPLATE_TEXT, encoding="utf-8")
    before = sorted(p.name for p in tmp_path.iterdir())
    run = subprocess.run(
        [sys.executable, str(script), "--target", "app.yaml"] + option,
        cwd=str(tmp_path),
        env=dict(os.environ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )
    assert run.returncode == 2, run.stderr
    assert run.stdout == b""
    assert b"Traceback" not in run.stderr
    assert sorted(p.name for p in tmp_path.iterdir()) == before


def test_new_parser_option_set_is_the_task_0_2_record() -> None:
    assert _options(bootstrap.new_parser("x", "y")) == NEW_PARSER_OPTIONS
    # Building the Delta_Tool parser does not change the shared one.
    delta_options = _options(deltacli.build_parser())
    assert {"--declare", "--plain-identifiers", "--base-report", "--head-report"} <= delta_options
    assert _options(bootstrap.new_parser("x", "y")) == NEW_PARSER_OPTIONS


# ---------------------------------------------------------------------------
# Imports and strings of the new modules (R16.6, R1.8, R1.9, 0-2 rule 5)
# ---------------------------------------------------------------------------


def _module_path(name: str) -> Path:
    return REPO_ROOT / "iacreview" / (name + ".py")


def _stdlib_dirs() -> List[Path]:
    paths = sysconfig.get_paths()
    return [Path(paths[key]).resolve() for key in ("stdlib", "platstdlib")]


def _is_stdlib(name: str) -> bool:
    if name in sys.builtin_module_names:
        return True
    spec = importlib.util.find_spec(name)
    if spec is None or spec.origin is None:
        return False
    if spec.origin in ("built-in", "frozen"):
        return True
    origin = Path(spec.origin).resolve()
    if "site-packages" in origin.parts or "dist-packages" in origin.parts:
        return False
    return any(base == origin or base in origin.parents for base in _stdlib_dirs())


def _imported_names(tree: ast.AST) -> Set[str]:
    names: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative import"
            names.add((node.module or "").split(".")[0])
    return names


def test_every_new_module_exists() -> None:
    for name in NEW_MODULES:
        assert _module_path(name).is_file(), name


@pytest.mark.parametrize("name", NEW_MODULES)
def test_new_module_imports(name: str) -> None:
    text = _module_path(name).read_text(encoding="utf-8")
    tree = ast.parse(text)
    imported = _imported_names(tree)
    assert not imported & FORBIDDEN_IMPORTS, imported & FORBIDDEN_IMPORTS
    for module in imported - {"__future__", "iacreview", "yaml"}:
        assert _is_stdlib(module), "{0} imports {1}".format(name, module)
    # No dynamic import that would bypass the check above.
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in ("__import__", "exec", "eval", "compile"), node.func.id
        if isinstance(node, ast.Attribute):
            assert node.attr not in ("import_module", "system", "popen", "spawnv", "execv"), node.attr


@pytest.mark.parametrize("name", NEW_MODULES)
def test_new_module_strings(name: str) -> None:
    text = _module_path(name).read_text(encoding="utf-8")
    assert "hypothesis" not in text
    assert ".kiro" not in text


def test_the_stdlib_check_tells_apart() -> None:
    assert _is_stdlib("json") and _is_stdlib("sys") and _is_stdlib("argparse")
    assert not _is_stdlib("yaml") and not _is_stdlib("pytest")


# ---------------------------------------------------------------------------
# Core functions are pure (R16.1)
# ---------------------------------------------------------------------------

FILE = "templates/app.yaml"
BASE_TEXT = "Resources:\n  App:\n    Type: AWS::S3::Bucket\n  Old:\n    Type: AWS::SQS::Queue\n"
HEAD_TEXT = "Resources:\n  App:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: x\n"


def _finding(resource: str, rule: str) -> Finding:
    return Finding(
        ID=0,
        Normalized_Category="Encryption",
        FindingType="Security",
        Severity="HIGH",
        Confidence="Confirmed",
        Source=["cfn-guard"],
        Resource=resource,
        Location=Location(File=FILE, TemplatePath=["Resources", resource]),
        Finding="t",
        WhyItMatters="w",
        Evidence=[Evidence(Source="cfn-guard", Detail="d", RuleId=rule)],
        Recommendation="r",
        SuggestedRemediation=None,
    )


def _report_obj(findings: List[Finding]) -> Dict[str, Any]:
    meta = report.ReportMeta(
        files=(FILE,),
        sources_enabled=("cfn-lint", "cfn-guard", "IAM Review", "Network Review", "Secret Review", "Quality Review"),
        tools=(report.ToolStatus("cfn-guard", True, "3.2.1"), report.ToolStatus("cfn-lint", True, "1.46.0")),
    )
    return report.build_report(findings, [], meta)


BASE_REPORT = _report_obj([_finding("App", "s3_bucket_encryption"), _finding("Old", "s3_bucket_encryption")])
HEAD_REPORT = _report_obj([_finding("App", "s3_bucket_encryption")])
DECLARATIONS = frozenset(deltaschema.DECLARATION_CODES)


def _core_pipeline(base_obj: Dict[str, Any], head_obj: Dict[str, Any]) -> Dict[str, Any]:
    base_t = deltaio.parse_template(BASE_TEXT, Path("base.yaml"), "base")
    head_t = deltaio.parse_template(HEAD_TEXT, Path("head.yaml"), "head")
    assert isinstance(base_t, deltaio.ParsedTemplate) and isinstance(head_t, deltaio.ParsedTemplate)
    diff = semdiff.diff(base_t, head_t)
    assert isinstance(diff, semdiff.SemanticDiffResult)
    base_r = reportcheck.check_report(base_obj, "base")
    head_r = reportcheck.check_report(head_obj, "head")
    assert isinstance(base_r, reportcheck.CheckedReport) and isinstance(head_r, reportcheck.CheckedReport)
    correspondence = reportcheck.correspondence(base_t, head_t, base_r, head_r, (FILE, FILE))
    result = delta.match_and_classify(
        base_r, head_r, declarations=DECLARATIONS, correspondence=correspondence, rename_hints=diff.rename_hints
    )
    request = DeltaRequest(
        templates=(TemplateInput(FILE, base_t), TemplateInput(FILE, head_t)),
        reports=(ReportInput("base.json", "0" * 64, base_r), ReportInput("head.json", "1" * 64, head_r)),
        semantic_diff=diff,
        finding_delta=result,
        declarations=DECLARATIONS,
        guard_rule_names=frozenset({"s3_bucket_encryption"}),
    )
    built = deltareport.build_delta_report(request)
    assert isinstance(built, dict)
    return built


def _blocked(*_: Any, **__: Any) -> Any:
    raise AssertionError("I/O or a process was attempted from a Core function")


def test_core_functions_are_callable_without_io(monkeypatch: pytest.MonkeyPatch) -> None:
    # The first call may load the Plugin's own data (the category map), as
    # v1.0 does once per process; the second call must not touch anything.
    first = _core_pipeline(copy.deepcopy(BASE_REPORT), copy.deepcopy(HEAD_REPORT))
    base_obj, head_obj = copy.deepcopy(BASE_REPORT), copy.deepcopy(HEAD_REPORT)
    for target, attribute in (
        (builtins, "open"),
        (io, "open"),
        (os, "open"),
        (os, "fdopen"),
        (os, "listdir"),
        (os, "scandir"),
        (os, "system"),
        (os, "popen"),
        (os, "getenv"),
        (pathlib.Path, "open"),
        (pathlib.Path, "read_text"),
        (pathlib.Path, "read_bytes"),
        (pathlib.Path, "write_text"),
        (pathlib.Path, "write_bytes"),
        (pathlib.Path, "resolve"),
        (pathlib.Path, "cwd"),
        (subprocess, "Popen"),
    ):
        monkeypatch.setattr(target, attribute, _blocked)
    monkeypatch.setattr(os, "environ", {})
    second = _core_pipeline(base_obj, head_obj)
    monkeypatch.undo()
    assert first == second
    # Inputs are not changed.
    assert base_obj == BASE_REPORT and head_obj == HEAD_REPORT
    assert first["semantic_diff"]["observation"] == "changes_observed"
    classes = sorted(e["classification"] for e in first["finding_delta"]["entries"])
    assert classes == ["Resolved", "Unchanged"]
    assert json.loads(deltareport.dump(first)) == first
