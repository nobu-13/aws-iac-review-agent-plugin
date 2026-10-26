"""Regression: no Template value, free text or (by default) identifier leaves the Delta_Tool.

Requirements guarded
--------------------

v1.1 Requirement 12 AC1, AC2, AC7, AC8, AC10, AC11, AC15, AC16, and AC18
(the canaries do not match a secret-scan pattern), and Requirement 8 AC7 for
the input Report's ``errors[]`` strings.

Method
------

A canary is a string that appears in exactly one position of the inputs.
Thirteen Template positions and thirteen Report positions (R12 AC15) each
carry one or more canaries of their own. Every run checks, before anything
else, that each canary it relies on really is in the input bytes, so a canary
that never reached the tool cannot pass vacuously.

With the default options no canary may appear in stdout, stderr, or any field
of any StructuredError in the Delta_Report. With ``--plain-identifiers`` the
identifier canaries may appear (that is what the option is for) but value and
free-text canaries still may not.

The canaries include strings that pass simple character-class checks:
lowercase alphanumeric only, PascalCase, and the CloudFormation logical name
form (R12 AC16), so anonymization cannot depend on what a string looks like.
They are short mixed-case words with no keyword a secret scan looks for
(R12 AC18).

C-1: v1.0's YAML parse error message carries the offending Template line. The
reproduction below pins that, so the canary check on a syntax error proves the
Delta_Tool does not reuse the message rather than proving nothing.

Stop condition (tasks.md Task 12): if any canary is found in an output, the
assertion message names the position. The test must not be changed to pass;
the finding is a new Security problem to report.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, NamedTuple, Sequence, Tuple

import pytest

from iacreview import deltacli, report, template
from iacreview.errors import STRUCTURED_ERROR_KEYS, TemplateParseError
from iacreview.finding import Evidence, Finding, Location

REPO_ROOT = Path(__file__).resolve().parents[2]

IDENTIFIER = "identifier"
VALUE = "value"


class Canary(NamedTuple):
    position: str
    text: str
    kind: str


# ---------------------------------------------------------------------------
# Template canaries: 13 positions (R12 AC15, Template list)
# ---------------------------------------------------------------------------

TEMPLATE_CANARIES: Tuple[Canary, ...] = (
    # T01 a Property value (lowercase alphanumeric only).
    Canary("T01 property value", "cnypropvalue42kq", VALUE),
    Canary("T01 property value", "CnyMapLeafBaseZa2", VALUE),
    Canary("T01 property value", "CnyMapLeafHeadZa3", VALUE),
    Canary("T01 property value", "CnyMetaBaseZb3", VALUE),
    Canary("T01 property value", "CnyMetaHeadZb4", VALUE),
    Canary("T01 property value", "CnyEnvBaseZc4", VALUE),
    Canary("T01 property value", "CnyEnvHeadZc5", VALUE),
    Canary("T01 property value", "CnyOutputBaseZd5", VALUE),
    Canary("T01 property value", "CnyOutputHeadZd6", VALUE),
    # T02 / T03 old and new value of a ``modified`` entry.
    Canary("T02 modified old value", "CnyModOldVa3Lp", VALUE),
    Canary("T03 modified new value", "CnyModNewVb4Mq", VALUE),
    # T04 the Default of a NoEcho Parameter (changed, so it is ``modified``).
    Canary("T04 NoEcho Default", "CnyNoEchoBaseRk5", VALUE),
    Canary("T04 NoEcho Default", "CnyNoEchoHeadRk6", VALUE),
    # T05 the reference string of a dynamic reference (changed).
    Canary("T05 dynamic reference", "CnyResolveBaseSt7", VALUE),
    Canary("T05 dynamic reference", "CnyResolveHeadSt8", VALUE),
    # T06 Logical IDs (PascalCase, logical name form).
    Canary("T06 Logical ID", "CanaryLogicalBucket", IDENTIFIER),
    Canary("T06 Logical ID", "CanaryFunction", IDENTIFIER),
    Canary("T06 Logical ID", "CanaryCustomResource", IDENTIFIER),
    # T07 Parameter / Mapping / Output names.
    Canary("T07 entry name", "CanaryParamName", IDENTIFIER),
    Canary("T07 entry name", "CanaryMappingName", IDENTIFIER),
    Canary("T07 entry name", "CanaryOutputName", IDENTIFIER),
    # T08 second- and third-level Mapping keys.
    Canary("T08 Mapping key", "CanaryMapSecondKey", IDENTIFIER),
    Canary("T08 Mapping key", "CanaryMapThirdKey", IDENTIFIER),
    # T09 a key under Metadata.
    Canary("T09 Metadata key", "CanaryMetadataKey", IDENTIFIER),
    # T10 a key of a map-typed Property.
    Canary("T10 map Property key", "CanaryEnvVarKey", IDENTIFIER),
    # T11 the name part of a Custom:: Resource Type.
    Canary("T11 Custom type", "CanaryCustomType", IDENTIFIER),
    # T12 a duplicate key and both of its values.
    Canary("T12 duplicate key", "CanaryDuplicateKey", IDENTIFIER),
    Canary("T12 duplicate value", "CnyDupFirstUv9", VALUE),
    Canary("T12 duplicate value", "CnyDupSecondUw0", VALUE),
    # T13 the line of a YAML syntax error (C-1).
    Canary("T13 YAML syntax error line", "CnySyntaxLineXy1", VALUE),
    # Not one of the 13 positions: a JSON syntax error, for the same reason.
    Canary("JSON syntax error", "CnyJsonBrokenXz2", VALUE),
)

TEMPLATE_POSITIONS = sorted({c.position.split(" ", 1)[0] for c in TEMPLATE_CANARIES if c.position[0] == "T"})

BASE_TEMPLATE = """\
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  CanaryParamName:
    Type: String
    NoEcho: true
    Default: CnyNoEchoBaseRk5
Mappings:
  CanaryMappingName:
    CanaryMapSecondKey:
      CanaryMapThirdKey: CnyMapLeafBaseZa2
Resources:
  CanaryLogicalBucket:
    Type: AWS::S3::Bucket
    Metadata:
      CanaryMetadataKey: CnyMetaBaseZb3
    Properties:
      BucketName: cnypropvalue42kq
  CanaryFunction:
    Type: AWS::Lambda::Function
    Properties:
      Description: CnyModOldVa3Lp
      Environment:
        Variables:
          CanaryEnvVarKey: CnyEnvBaseZc4
  CanaryCustomResource:
    Type: Custom::CanaryCustomType
    Properties:
      Reference: "{{resolve:ssm:CnyResolveBaseSt7}}"
Outputs:
  CanaryOutputName:
    Value: CnyOutputBaseZd5
"""

HEAD_TEMPLATE = """\
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  CanaryParamName:
    Type: String
    NoEcho: true
    Default: CnyNoEchoHeadRk6
Mappings:
  CanaryMappingName:
    CanaryMapSecondKey:
      CanaryMapThirdKey: CnyMapLeafHeadZa3
Resources:
  CanaryLogicalBucket:
    Type: AWS::S3::Bucket
    Metadata:
      CanaryMetadataKey: CnyMetaHeadZb4
    Properties:
      BucketName: cnypropvalue42kq
      CanaryDuplicateKey: CnyDupFirstUv9
      CanaryDuplicateKey: CnyDupSecondUw0
  CanaryFunction:
    Type: AWS::Lambda::Function
    Properties:
      Description: CnyModNewVb4Mq
      Environment:
        Variables:
          CanaryEnvVarKey: CnyEnvHeadZc5
  CanaryCustomResource:
    Type: Custom::CanaryCustomType
    Properties:
      Reference: "{{resolve:ssm:CnyResolveHeadSt8}}"
Outputs:
  CanaryOutputName:
    Value: CnyOutputHeadZd6
"""

BROKEN_YAML = """\
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: [CnySyntaxLineXy1, unclosed
"""

BROKEN_JSON = '{"Resources": {"CnyJsonBrokenXz2": {"Type": "AWS::S3::Bucket",\n'


# ---------------------------------------------------------------------------
# Report canaries: 13 positions (R12 AC15, Report list)
# ---------------------------------------------------------------------------

REPORT_CANARIES: Tuple[Canary, ...] = (
    Canary("R01 Resource", "CanaryResourceName", IDENTIFIER),
    Canary("R01 Resource", "CanaryGoneResource", IDENTIFIER),
    Canary("R01 Resource", "CanaryNewResource", IDENTIFIER),
    Canary("R02 TemplatePath key", "CanaryPathKey", IDENTIFIER),
    Canary("R03 Finding", "CnyFindingTextJa1", VALUE),
    Canary("R04 WhyItMatters", "CnyWhyTextJb2", VALUE),
    Canary("R05 Recommendation", "CnyRecommendTextJc3", VALUE),
    Canary("R06 SuggestedRemediation", "CnySuggestTextJd4", VALUE),
    Canary("R07 Evidence Detail", "CnyDetailTextJe5", VALUE),
    Canary("R08 Evidence Excerpt", "CnyExcerptTextJf6", VALUE),
    Canary("R09 RuleId outside the closed set", "CanaryRuleIdentifier", IDENTIFIER),
    Canary("R10 errors message", "CnyErrMessageHa1", VALUE),
    Canary("R10 errors remediation", "CnyErrRemedyHb2", VALUE),
    Canary("R11 errors stderr_head", "CnyErrStderrHc3", VALUE),
    Canary("R12 tools name outside the set", "CanaryToolName", IDENTIFIER),
    Canary("R13 tools version outside the pattern", "CanaryToolVersion", IDENTIFIER),
    # Not one of the 13 positions: a rejected Report's field value and a
    # malformed Report's text.
    Canary("rejected Report field", "CnyBadSeverityHd4", VALUE),
    Canary("malformed Report text", "CnyBrokenReportHe5", VALUE),
)

REPORT_POSITIONS = sorted({c.position.split(" ", 1)[0] for c in REPORT_CANARIES if c.position[0] == "R"})

TEMPLATE_FILE = "templates/app.yaml"


def _finding(resource: str) -> Finding:
    return Finding(
        ID=0,
        Normalized_Category="Encryption",
        FindingType="Security",
        Severity="HIGH",
        Confidence="Confirmed",
        Source=["cfn-guard"],
        Resource=resource,
        Location=Location(File=TEMPLATE_FILE, TemplatePath=["Resources", resource, "Properties", "CanaryPathKey"]),
        Finding="CnyFindingTextJa1",
        WhyItMatters="CnyWhyTextJb2",
        Evidence=[
            Evidence(Source="cfn-guard", Detail="CnyDetailTextJe5", RuleId="CanaryRuleIdentifier", Excerpt="CnyExcerptTextJf6")
        ],
        Recommendation="CnyRecommendTextJc3",
        SuggestedRemediation="CnySuggestTextJd4",
    )


def _input_error() -> Dict[str, Any]:
    return {
        "error_class": "tool_execution",
        "source": "cfn-lint",
        "tool": "cfn-lint",
        "exit_code": 2,
        "message": "cfn-lint failed CnyErrMessageHa1",
        "required_min_version": None,
        "detected_version": None,
        "remediation": "CnyErrRemedyHb2",
        "stderr_head": ["CnyErrStderrHc3"],
    }


def _report_text(resources: Sequence[str]) -> str:
    meta = report.ReportMeta(
        files=(TEMPLATE_FILE,),
        sources_enabled=("cfn-lint", "cfn-guard", "IAM Review", "Network Review", "Secret Review", "Quality Review"),
        tools=(
            report.ToolStatus("cfn-guard", True, "3.2.1"),
            report.ToolStatus("cfn-lint", True, "1.46.0"),
            report.ToolStatus("CanaryToolName", True, "CanaryToolVersion"),
        ),
    )
    return report.dump(report.build_report([_finding(r) for r in resources], [_input_error()], meta))


# ---------------------------------------------------------------------------
# Running and checking
# ---------------------------------------------------------------------------


def _run(argv: Sequence[str]) -> Tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = deltacli.main(list(argv), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    files = {
        "base.yaml": BASE_TEMPLATE,
        "head.yaml": HEAD_TEMPLATE,
        "broken.yaml": BROKEN_YAML,
        "broken.json": BROKEN_JSON,
        "base.json": _report_text(["CanaryResourceName", "CanaryGoneResource"]),
        "head.json": _report_text(["CanaryResourceName", "CanaryNewResource"]),
        "malformed.json": '{"CnyBrokenReportHe5": [\n',
    }
    rejected = json.loads(files["head.json"])
    rejected["findings"][0]["Severity"] = "CnyBadSeverityHd4"
    files["rejected.json"] = json.dumps(rejected)
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _inputs_text(root: Path) -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted(root.iterdir()) if p.is_file())


def _assert_embedded(canaries: Iterable[Canary], root: Path) -> None:
    text = _inputs_text(root)
    for canary in canaries:
        assert canary.text in text, "canary {0} ({1}) is not in the inputs".format(canary.text, canary.position)


def _structured_errors(stdout: str) -> List[Dict[str, Any]]:
    if not stdout:
        return []
    errors = json.loads(stdout)["errors"]
    for error in errors:
        assert set(error) == set(STRUCTURED_ERROR_KEYS)
    return errors


def _leaks(canaries: Iterable[Canary], channels: Dict[str, str]) -> List[str]:
    found: List[str] = []
    for canary in canaries:
        needle = canary.text.lower()
        for name, text in channels.items():
            if needle in text.lower():
                found.append("{0} ({1}) in {2}".format(canary.text, canary.position, name))
    return found


def _channels(stdout: str, stderr: str) -> Dict[str, str]:
    channels = {"stdout": stdout, "stderr": stderr}
    for n, error in enumerate(_structured_errors(stdout)):
        for key in STRUCTURED_ERROR_KEYS:
            channels["errors[{0}].{1}".format(n, key)] = json.dumps(error[key])
    return channels


ALL_CANARIES = TEMPLATE_CANARIES + REPORT_CANARIES
VALUE_CANARIES = tuple(c for c in ALL_CANARIES if c.kind == VALUE)
IDENTIFIER_CANARIES = tuple(c for c in ALL_CANARIES if c.kind == IDENTIFIER)

TEMPLATES = ["--base-template", "base.yaml", "--head-template", "head.yaml"]
REPORTS = ["--base-report", "base.json", "--head-report", "head.json"]
ALL_DECLARATIONS = [
    "--declare", "reports_unmodified",
    "--declare", "same_plugin_version",
    "--declare", "same_rule_set",
    "--declare", "same_tool_configuration",
    "--declare", "same_agent_findings_input",
]

#: Every run, named. Each one is checked with the default options and with
#: ``--plain-identifiers``.
RUNS: Dict[str, List[str]] = {
    "templates": TEMPLATES,
    "reports": REPORTS,
    "reports with declarations": REPORTS + ALL_DECLARATIONS,
    "both": TEMPLATES + REPORTS + ALL_DECLARATIONS + ["--declare", "reports_match_templates"],
    # H-M1-1 approved: the declared path is a workspace-relative path, written
    # in plain form like the other paths; no canary may come with it.
    "both with declared path": TEMPLATES
    + REPORTS
    + ALL_DECLARATIONS
    + ["--declare", "reports_match_templates", "--reviewed-template-path", TEMPLATE_FILE],
    "yaml syntax error": ["--base-template", "base.yaml", "--head-template", "broken.yaml"],
    "json syntax error": ["--base-template", "broken.json", "--head-template", "head.yaml"],
    "rejected report": ["--base-report", "base.json", "--head-report", "rejected.json"],
    "malformed report": ["--base-report", "malformed.json", "--head-report", "head.json"],
}


def test_canary_inventory() -> None:
    texts = [c.text for c in ALL_CANARIES]
    assert len(texts) == len(set(texts)), "a canary is reused"
    for a in texts:
        for b in texts:
            assert a == b or a.lower() not in b.lower(), (a, b)
    assert len(TEMPLATE_POSITIONS) == 13, TEMPLATE_POSITIONS
    assert len(REPORT_POSITIONS) == 13, REPORT_POSITIONS
    # R12 AC16: character classes that a naive filter would call safe.
    assert any(c.text.isalnum() and c.text.islower() for c in ALL_CANARIES)
    assert all(c.text.isalnum() for c in ALL_CANARIES)
    pascal = [c.text for c in IDENTIFIER_CANARIES]
    assert all(t[0].isupper() and t.isalnum() and len(t) <= 255 for t in pascal)


def test_c1_v10_parse_error_carries_the_line() -> None:
    # The behaviour the Delta_Tool must not reuse (Requirements C-1).
    with pytest.raises(TemplateParseError) as caught:
        template.parse_template_text(BROKEN_YAML, Path("broken.yaml"))
    assert "CnySyntaxLineXy1" in str(caught.value)


@pytest.mark.parametrize("name", sorted(RUNS))
def test_no_canary_with_default_options(name: str, workspace: Path) -> None:
    _assert_embedded(ALL_CANARIES, workspace)
    code, out, err = _run(RUNS[name])
    assert out, "no Delta_Report for {0}: exit {1}".format(name, code)
    leaks = _leaks(ALL_CANARIES, _channels(out, err))
    assert leaks == [], "STOP: canary in output (Task 12 stop condition): {0}".format(leaks)
    assert json.loads(out)["identifier_mode"] == "anonymized"


@pytest.mark.parametrize("name", sorted(RUNS))
def test_plain_identifiers_never_show_values_or_free_text(name: str, workspace: Path) -> None:
    code, out, err = _run(RUNS[name] + ["--plain-identifiers"])
    assert out, "no Delta_Report for {0}: exit {1}".format(name, code)
    leaks = _leaks(VALUE_CANARIES, _channels(out, err))
    assert leaks == [], "STOP: value canary in output (Task 12 stop condition): {0}".format(leaks)
    assert json.loads(out)["identifier_mode"] == "plain"


def test_plain_identifiers_do_show_identifiers(workspace: Path) -> None:
    # The option works, so the default-option checks above are not vacuous:
    # these identifiers reach the Delta_Report and are tokenized by default.
    # The duplicate key is not listed: Design 3-2 records the path of the
    # mapping that repeats it, not the key itself.
    _, out, _ = _run(RUNS["both"] + ["--plain-identifiers"])
    for text in (
        "CanaryLogicalBucket",
        "CanaryCustomType",
        "CanaryFunction",
        "CanaryEnvVarKey",
        "CanaryParamName",
        "CanaryMappingName",
        "CanaryMapSecondKey",
        "CanaryMapThirdKey",
        "CanaryOutputName",
        "CanaryMetadataKey",
        "CanaryCustomResource",
        "CanaryResourceName",
        "CanaryGoneResource",
        "CanaryNewResource",
        "CanaryPathKey",
    ):
        assert text in out, text


def test_comparisons_were_made(workspace: Path) -> None:
    _, out, _ = _run(RUNS["both"])
    built = json.loads(out)
    diff = built["semantic_diff"]
    assert diff["analysis_state"] == "analyzed"
    assert {c["change"] for c in diff["changes"]} >= {"modified"}
    assert diff["uncompared_paths"], "the duplicate key is not recorded"
    delta = built["finding_delta"]
    assert delta["analysis_state"] == "analyzed"
    assert {e["observation"] for e in delta["entries"]} == {"matched", "base_only", "head_only"}
    # R09, R12, R13 reach the output, as something other than the canary.
    tools = built["inputs"]["base"]["report"]["tools"]
    assert len(tools) == 3 and {t["name"] for t in tools} >= {"cfn-guard", "cfn-lint"}
    assert all(e["base"] is None or e["base"]["Evidence"][0]["RuleId"] for e in delta["entries"])
    for name in ("yaml syntax error", "json syntax error"):
        _, out, _ = _run(RUNS[name])
        assert json.loads(out)["semantic_diff"]["failure"]["code"] == "template_parse_failure"
    _, out, _ = _run(RUNS["rejected report"])
    assert json.loads(out)["finding_delta"]["failure"]["code"] == "report_schema_violation"
    _, out, _ = _run(RUNS["malformed report"])
    assert json.loads(out)["finding_delta"]["failure"]["code"] == "report_parse_failure"


def _child(root: Path, argv: Sequence[str]) -> "subprocess.CompletedProcess[bytes]":
    env = dict(os.environ)
    env.update({"PYTHONPATH": str(REPO_ROOT), "PYTHONDONTWRITEBYTECODE": "1"})
    return subprocess.run(
        [sys.executable, "-m", "iacreview.deltacli"] + list(argv),
        cwd=str(root),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )


@pytest.mark.parametrize("name", ["both", "yaml syntax error", "rejected report"])
def test_no_canary_in_a_child_process(name: str, workspace: Path) -> None:
    run = _child(workspace, RUNS[name])
    out = run.stdout.decode("utf-8")
    err = run.stderr.decode("utf-8")
    assert out
    assert "Traceback" not in err
    leaks = _leaks(ALL_CANARIES, _channels(out, err))
    assert leaks == [], "STOP: canary in output (Task 12 stop condition): {0}".format(leaks)


# ---------------------------------------------------------------------------
# A-3: digit-only canaries in a Report_Pair alone (R12.2, R12.15, R12.16, D-H11)
# ---------------------------------------------------------------------------

#: Digit-only TemplatePath segments. v1.0 records them as integers, so the
#: Report alone cannot say whether one is a list index or a mapping key; the
#: default output must not carry them. Long enough not to occur by chance in
#: other output text, and no secret-scan pattern matches digits alone.
DIGIT_MAPPING_KEY = "8675309004242771"
DIGIT_LIST_POSITION = "5550192837465001"
DIGIT_CANARIES = (DIGIT_MAPPING_KEY, DIGIT_LIST_POSITION)


def _digit_report_text() -> str:
    paths = (
        ["Mappings", "CanaryAcctMap", DIGIT_MAPPING_KEY, "Ami"],
        ["Resources", "CanaryResourceName", "Properties", "Items", DIGIT_LIST_POSITION],
    )
    findings = []
    for n, path in enumerate(paths):
        base = _finding("CanaryResourceName" if n else "CanaryGoneResource")
        findings.append(
            Finding(
                ID=0,
                Normalized_Category=base.Normalized_Category,
                FindingType=base.FindingType,
                Severity=base.Severity,
                Confidence=base.Confidence,
                Source=list(base.Source),
                Resource=None if n == 0 else base.Resource,
                Location=Location(File=TEMPLATE_FILE, TemplatePath=list(path)),
                Finding=base.Finding,
                WhyItMatters=base.WhyItMatters,
                Evidence=list(base.Evidence),
                Recommendation=base.Recommendation,
                SuggestedRemediation=base.SuggestedRemediation,
            )
        )
    meta = report.ReportMeta(
        files=(TEMPLATE_FILE,),
        sources_enabled=("cfn-lint", "cfn-guard", "IAM Review", "Network Review", "Secret Review", "Quality Review"),
        tools=(report.ToolStatus("cfn-guard", True, "3.2.1"), report.ToolStatus("cfn-lint", True, "1.46.0")),
    )
    return report.dump(report.build_report(findings, [], meta))


def _numbers_and_strings(value: Any) -> List[str]:
    found: List[str] = []
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            stack.extend(current.keys())
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
        elif isinstance(current, (int, str)) and not isinstance(current, bool):
            found.append(str(current))
    return found


def _digit_leaks(stdout: str, stderr: str) -> List[str]:
    built = json.loads(stdout)
    digests = [built["inputs"][side]["report"]["sha256"] for side in ("base", "head")]
    texts = [s for s in _numbers_and_strings(built) if s not in digests]
    leaks = []
    for canary in DIGIT_CANARIES:
        if any(canary in s for s in texts) or canary in stderr:
            leaks.append(canary)
        for n, error in enumerate(_structured_errors(stdout)):
            if canary in json.dumps(error):
                leaks.append("{0} in errors[{1}]".format(canary, n))
    return leaks


@pytest.mark.parametrize("declare", [False, True])
def test_no_digit_canary_from_a_report_pair_alone(declare: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    text = _digit_report_text()
    for canary in DIGIT_CANARIES:
        assert canary in text, canary
    (tmp_path / "digits.json").write_text(text, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    argv = ["--base-report", "digits.json", "--head-report", "digits.json"] + (ALL_DECLARATIONS if declare else [])
    code, out, err = _run(argv)
    assert code == 0, err
    built = json.loads(out)
    assert len(built["finding_delta"]["entries"]) == 2
    leaks = _digit_leaks(out, err)
    assert leaks == [], "STOP: digit canary in output: {0}".format(leaks)
    # Plain mode is for identifiers: the keys may appear, as strings.
    code, out, err = _run(argv + ["--plain-identifiers"])
    assert code == 0, err
    plain = json.loads(out)
    paths = [e["base"]["TemplatePath"] for e in plain["finding_delta"]["entries"]]
    assert sorted(p[-2] if p[0] == "Mappings" else p[-1] for p in paths) == sorted(DIGIT_CANARIES)


# ---------------------------------------------------------------------------
# H-M1-1 approved: --reviewed-template-path handling (R1.3, R12, Design 15)
# ---------------------------------------------------------------------------

#: Only ever given as part of a declared path; never in an input file.
DECLARED_PATH_CANARY = "CnyDeclaredArgVq7"


def test_declared_path_is_recorded_and_brings_no_canary(workspace: Path) -> None:
    _assert_embedded(ALL_CANARIES, workspace)
    code, out, err = _run(RUNS["both with declared path"])
    assert out and err == "", code
    built = json.loads(out)
    assert built["finding_delta"]["reviewed_template_path"] == {
        "path": TEMPLATE_FILE,
        "status": "declared_not_verified",
    }
    assert _leaks(ALL_CANARIES, _channels(out, err)) == []


@pytest.mark.parametrize(
    "value",
    [
        "../" + DECLARED_PATH_CANARY + ".yaml",
        "/" + DECLARED_PATH_CANARY + ".yaml",
        DECLARED_PATH_CANARY + ";x.yaml",
        DECLARED_PATH_CANARY + "\x00.yaml",
        "outward/" + DECLARED_PATH_CANARY + ".yaml",
    ],
)
def test_refused_declared_path_is_not_echoed(value: str, workspace: Path, tmp_path_factory: pytest.TempPathFactory) -> None:
    (workspace / "outward").symlink_to(tmp_path_factory.mktemp("outward_target"), target_is_directory=True)
    argv = RUNS["both"] + ["--reviewed-template-path", value]
    code, out, err = _run(argv)
    assert (code, out) == (2, "")
    assert DECLARED_PATH_CANARY.lower() not in err.lower()
    assert _leaks(ALL_CANARIES, _channels(out, err)) == []
    run = _child(workspace, argv) if "\x00" not in value else None
    if run is not None:
        assert run.returncode == 2 and run.stdout == b""
        assert DECLARED_PATH_CANARY.lower() not in run.stderr.decode("utf-8").lower()


# ---------------------------------------------------------------------------
# D-13 (RC Blocker P1): an integer of a Finding TemplatePath is shown as a list
# index only when the Finding is in the Template being walked and the index is
# inside the list there (R12.2, D-H11, HD-P4-1 (b))
# ---------------------------------------------------------------------------

#: ``Properties.Tags`` is a list of one element in this Template.
TAGS_TEMPLATE = (
    "Resources:\n"
    "  CanaryResourceName:\n"
    "    Type: AWS::S3::Bucket\n"
    "    Properties:\n"
    "      Tags:\n"
    "        - Key: a\n"
    "          Value: b\n"
)
OTHER_FILE = "other/elsewhere.yaml"
_TAGS = ["Resources", "CanaryResourceName", "Properties", "Tags"]
#: (File, TemplatePath): (b) out of range, the in-range control, (a) another file twice.
D13_LOCATIONS = (
    (TEMPLATE_FILE, _TAGS + [DIGIT_LIST_POSITION]),
    (TEMPLATE_FILE, _TAGS + ["0", "Key"]),
    (OTHER_FILE, _TAGS + ["0", "Key"]),
    (OTHER_FILE, _TAGS + [DIGIT_MAPPING_KEY]),
)


def _d13_report_text() -> str:
    base = _finding("CanaryResourceName")
    findings = [
        Finding(
            ID=0,
            Normalized_Category=base.Normalized_Category,
            FindingType=base.FindingType,
            Severity=base.Severity,
            Confidence=base.Confidence,
            Source=list(base.Source),
            Resource=base.Resource,
            Location=Location(File=file, TemplatePath=list(path)),
            Finding=base.Finding,
            WhyItMatters=base.WhyItMatters,
            Evidence=list(base.Evidence),
            Recommendation=base.Recommendation,
            SuggestedRemediation=base.SuggestedRemediation,
        )
        for file, path in D13_LOCATIONS
    ]
    meta = report.ReportMeta(
        files=(TEMPLATE_FILE, OTHER_FILE),
        sources_enabled=("cfn-lint", "cfn-guard", "IAM Review", "Network Review", "Secret Review", "Quality Review"),
        tools=(report.ToolStatus("cfn-guard", True, "3.2.1"), report.ToolStatus("cfn-lint", True, "1.46.0")),
    )
    return report.dump(report.build_report(findings, [], meta))


_D13_REPORTS = ["--base-report", "d13.json", "--head-report", "d13.json"] + ALL_DECLARATIONS + [
    "--declare",
    "reports_match_templates",
]
#: name: (argv, whether the Findings in TEMPLATE_FILE are in the walked Template)
D13_RUNS: Dict[str, Tuple[List[str], bool]] = {
    "cli path is the finding file": (["--base-template", TEMPLATE_FILE, "--head-template", TEMPLATE_FILE] + _D13_REPORTS, True),
    "declared path is the finding file": (
        ["--base-template", "tags_base.yaml", "--head-template", "tags_head.yaml"]
        + _D13_REPORTS
        + ["--reviewed-template-path", TEMPLATE_FILE],
        True,
    ),
    "no path is the finding file": (["--base-template", "tags_base.yaml", "--head-template", "tags_head.yaml"] + _D13_REPORTS, False),
}


@pytest.fixture
def d13_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "templates").mkdir()
    for name in (TEMPLATE_FILE, "tags_base.yaml", "tags_head.yaml"):
        (tmp_path / name).write_text(TAGS_TEMPLATE, encoding="utf-8")
    (tmp_path / "d13.json").write_text(_d13_report_text(), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _d13_paths(built: Dict[str, Any]) -> Dict[Tuple[str, int], List[Any]]:
    """Base TemplatePath of each entry by (File, length); lengths are distinct per File."""
    paths: Dict[Tuple[str, int], List[Any]] = {}
    for entry in built["finding_delta"]["entries"]:
        projection = entry["base"]
        paths[(projection["File"], len(projection["TemplatePath"]))] = projection["TemplatePath"]
    assert len(paths) == len(D13_LOCATIONS), sorted(paths)
    return paths


@pytest.mark.parametrize("name", sorted(D13_RUNS))
def test_no_digit_canary_from_an_unplaceable_template_path_integer(name: str, d13_workspace: Path) -> None:
    argv, walked = D13_RUNS[name]
    text = (d13_workspace / "d13.json").read_text(encoding="utf-8")
    for canary in DIGIT_CANARIES:
        assert canary in text, canary
    code, out, err = _run(argv)
    assert code == 0 and err == "", (code, err)
    leaks = _digit_leaks(out, err)
    assert leaks == [], "STOP: digit canary in output: {0}".format(leaks)
    paths = _d13_paths(json.loads(out))
    # (b) out of range and (a) another file: never an integer.
    for key in ((TEMPLATE_FILE, 5), (OTHER_FILE, 6), (OTHER_FILE, 5)):
        assert not any(isinstance(item, int) for item in paths[key]), (key, paths[key])
    # The in-range index of the walked Template stays an integer (positive control).
    assert (paths[(TEMPLATE_FILE, 6)][4] == 0) is walked, paths[(TEMPLATE_FILE, 6)]
    code, out, err = _run(argv + ["--plain-identifiers"])
    assert code == 0 and err == "", (code, err)
    plain = _d13_paths(json.loads(out))
    assert plain[(TEMPLATE_FILE, 5)][4] == DIGIT_LIST_POSITION
    assert plain[(OTHER_FILE, 5)][4] == DIGIT_MAPPING_KEY
    assert plain[(OTHER_FILE, 6)][4] == "0"
    assert plain[(TEMPLATE_FILE, 6)][4] == (0 if walked else "0")


def test_no_digit_canary_from_an_unplaceable_integer_in_a_child_process(d13_workspace: Path) -> None:
    for name in sorted(D13_RUNS):
        run = _child(d13_workspace, D13_RUNS[name][0])
        out, err = run.stdout.decode("utf-8"), run.stderr.decode("utf-8")
        assert run.returncode == 0 and err == "", (name, run.returncode, err)
        assert _digit_leaks(out, err) == [], name
