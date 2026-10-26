"""Property tests: the Delta_Report is a function of its inputs (v1.1 Task 13).

Requirements guarded
--------------------

v1.1 Requirement 11 AC1 (byte-identical stdout across runs, processes and
``PYTHONHASHSEED`` values), AC4 (Identifier_Tokens depend on the identifier
set only), AC5 (permuting ``findings[]`` / ``Evidence[]``), AC6 and
Requirement 3 AC8 (re-expression gives ``no_changes_observed``), AC7
(self-comparison), AC8 (swapping Base and Head), AC9 (no environment-derived
value in the output), and Requirement 6 AC10 / AC11 (matching is independent
of order; every Finding is in exactly one Delta_Entry).

The ``PYTHONHASHSEED`` part runs the tool in child processes with seeds 0, 1
and 12345, so it needs no change to the CI determinism job (tasks.md SR-2).

Inputs are built in temporary directories: Reports with ``report.build_report``
(so they are internally consistent unless a test breaks that on purpose), and
Templates from small generated documents or the Task 2 fixtures.
"""

from __future__ import annotations

import getpass
import io
import json
import os
import platform
import random
import re
import subprocess
import sys
import tempfile
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

import pytest
import yaml
from hypothesis import given, settings
from hypothesis import strategies as st

from iacreview import deltacli, report
from iacreview.finding import Evidence, Finding, Location

REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE_FIXTURES = REPO_ROOT / "tests" / "fixtures" / "delta" / "templates"
MAX_EXAMPLES = 60
FILE = "templates/app.yaml"
SOURCES = ("cfn-lint", "cfn-guard", "IAM Review", "Network Review", "Secret Review", "Quality Review")
REPORT_DECLARATIONS = (
    "reports_unmodified",
    "same_plugin_version",
    "same_rule_set",
    "same_tool_configuration",
    "same_agent_findings_input",
)
SWAP = {
    "added": "removed",
    "removed": "added",
    "head_only": "base_only",
    "base_only": "head_only",
    "New": "Resolved",
    "Resolved": "New",
}


# ---------------------------------------------------------------------------
# Running the tool
# ---------------------------------------------------------------------------


@contextmanager
def _workspace(files: Dict[str, str]) -> Iterator[Path]:
    previous = os.getcwd()
    with tempfile.TemporaryDirectory() as name:
        root = Path(name).resolve()
        for rel, text in files.items():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        os.chdir(str(root))
        try:
            yield root
        finally:
            os.chdir(previous)


def _main(argv: Sequence[str]) -> Tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = deltacli.main(list(argv), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def _run_on(files: Dict[str, str], argv: Sequence[str]) -> str:
    with _workspace(files):
        _, out, _ = _main(argv)
    assert out
    return out


def _declare(codes: Sequence[str]) -> List[str]:
    argv: List[str] = []
    for code in codes:
        argv += ["--declare", code]
    return argv


TEMPLATE_ARGS = ["--base-template", "base.yaml", "--head-template", "head.yaml"]
REPORT_ARGS = ["--base-report", "base.json", "--head-report", "head.json"]
SWAPPED_TEMPLATE_ARGS = ["--base-template", "head.yaml", "--head-template", "base.yaml"]
SWAPPED_REPORT_ARGS = ["--base-report", "head.json", "--head-report", "base.json"]


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

RESOURCES = (None, "Alpha", "Beta")
CATEGORIES = ("Encryption", "Logging", "Other")
EVIDENCE = (("cfn-guard", "s3_bucket_encryption"), ("cfn-guard", "s3_access_logging"), ("cfn-lint", "W3045"), ("cfn-guard", None))
PATHS = (None, ("Resources", "Alpha"), ("Resources", "Alpha", "Properties"))


@st.composite
def _findings(draw: Any) -> Finding:
    evidence = draw(st.lists(st.sampled_from(EVIDENCE), min_size=1, max_size=3, unique=True))
    category = draw(st.sampled_from(CATEGORIES))
    sources = sorted({source for source, _ in evidence}, key=SOURCES.index)
    if category == "Other":
        # ``Other`` cannot carry a merged Source list (finding.validate).
        evidence = [item for item in evidence if item[0] == sources[0]]
        sources = sources[:1]
    path = draw(st.sampled_from(PATHS))
    return Finding(
        ID=0,
        Normalized_Category=category,
        FindingType=draw(st.sampled_from(("Security", "BestPractice"))),
        Severity=draw(st.sampled_from(("HIGH", "LOW"))),
        Confidence="Confirmed",
        Source=sources,
        Resource=draw(st.sampled_from(RESOURCES)),
        Location=Location(File=FILE, TemplatePath=None if path is None else list(path)),
        Finding="text",
        WhyItMatters="why",
        Evidence=[Evidence(Source=s, Detail="d", RuleId=r) for s, r in evidence],
        Recommendation="fix",
        SuggestedRemediation=None,
    )


_finding_lists = st.lists(_findings(), max_size=6)


def _report_text(findings: Sequence[Finding]) -> str:
    meta = report.ReportMeta(
        files=(FILE,),
        sources_enabled=SOURCES,
        tools=(report.ToolStatus("cfn-guard", True, "3.2.1"), report.ToolStatus("cfn-lint", True, "1.46.0")),
    )
    return report.dump(report.build_report(list(findings), [], meta))


def _permuted(findings: Sequence[Finding], seed: int) -> List[Finding]:
    rng = random.Random(seed)
    out = []
    for f in findings:
        evidence = list(f.Evidence)
        rng.shuffle(evidence)
        out.append(Finding(**{**f.__dict__, "Evidence": evidence}))  # type: ignore[arg-type]
    rng.shuffle(out)
    return out


def _without_digests_and_ids(text: str) -> str:
    """The Delta_Report with the parts R11 AC5 lets differ blanked out."""
    built = json.loads(text)
    for side in ("base", "head"):
        part = built["inputs"][side]["report"]
        if part is not None:
            part["sha256"] = None
    for entry in built["finding_delta"]["entries"]:
        for side in ("base", "head"):
            if entry[side] is not None:
                entry[side]["ID"] = None
    return report.dump(built)


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

_scalars = st.one_of(
    st.text(alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", min_size=1, max_size=6),
    st.integers(min_value=-1000, max_value=1000),
    st.booleans(),
)
_KEYS = ("Name", "Size", "Flag", "Items", "Config", "Tags")
_values = st.recursive(
    _scalars,
    lambda inner: st.one_of(
        st.lists(inner, max_size=3),
        st.dictionaries(st.sampled_from(_KEYS), inner, max_size=3),
    ),
    max_leaves=8,
)


@st.composite
def _template_docs(draw: Any) -> Dict[str, Any]:
    names = draw(st.lists(st.sampled_from(("Alpha", "Beta", "Gamma", "Bucket1")), min_size=1, max_size=3, unique=True))
    resources: Dict[str, Any] = {}
    for name in names:
        resource: Dict[str, Any] = {"Type": draw(st.sampled_from(("AWS::S3::Bucket", "AWS::SQS::Queue", "Custom::Thing")))}
        properties = draw(st.dictionaries(st.sampled_from(_KEYS), _values, max_size=4))
        if properties:
            resource["Properties"] = properties
        resources[name] = resource
    doc: Dict[str, Any] = {"Resources": resources}
    if draw(st.booleans()):
        doc["Outputs"] = {"Out": {"Value": draw(_scalars)}}
    return doc


def _reordered(value: Any, rng: random.Random) -> Any:
    if isinstance(value, dict):
        keys = list(value)
        rng.shuffle(keys)
        return {k: _reordered(value[k], rng) for k in keys}
    if isinstance(value, list):
        return [_reordered(v, rng) for v in value]
    return value


def _change_shape(change: Dict[str, Any], swap: bool) -> str:
    kind = SWAP.get(change["change"], change["change"]) if swap else change["change"]
    types = change["resource_type"]
    if swap and types is not None:
        types = {"base": types["head"], "head": types["base"]}
    return json.dumps(
        {
            "change": kind,
            "path": change["path"],
            "section": change["section"],
            "resource_type": types,
            "type_changed": change["type_changed"],
            "qualifiers": sorted(change["qualifiers"]),
            "hints": sorted(change["hints"]),
        },
        sort_keys=True,
    )


def _entry_shape(entry: Dict[str, Any], swap: bool) -> str:
    def side(projection: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if projection is None:
            return None
        return dict(projection, ID=None)

    base, head = side(entry["base"]), side(entry["head"])
    absent_in_base, absent_in_head = entry["evidence_absent_in_base"], entry["evidence_absent_in_head"]
    observation, classification = entry["observation"], entry["classification"]
    if swap:
        base, head = head, base
        absent_in_base, absent_in_head = absent_in_head, absent_in_base
        observation = SWAP.get(observation, observation)
        classification = SWAP.get(classification, classification)
    return json.dumps(
        {
            "base": base,
            "head": head,
            "observation": observation,
            "classification": classification,
            "reasons": sorted(entry["reasons"]),
            "match_stage": entry["match_stage"],
            "missing_declarations": sorted(entry["missing_declarations"]),
            "changes": sorted(entry["changes"]),
            "evidence_absent_in_base": absent_in_base,
            "evidence_absent_in_head": absent_in_head,
        },
        sort_keys=True,
    )


def _analyzable_fixture_files() -> List[Path]:
    files = []
    for case in sorted(p for p in TEMPLATE_FIXTURES.iterdir() if p.is_dir()):
        expected = json.loads((case / "expected.json").read_text(encoding="utf-8"))
        if expected["expected"]["failure"] is None and not expected["limits"]:
            files.extend(sorted(p for p in case.iterdir() if p.name.startswith(("base.", "head."))))
    return files


ANALYZABLE_FIXTURE_FILES = _analyzable_fixture_files()


def _fixture_pairs() -> List[Path]:
    pairs = []
    for case in sorted(p for p in TEMPLATE_FIXTURES.iterdir() if p.is_dir()):
        expected = json.loads((case / "expected.json").read_text(encoding="utf-8"))
        if expected["expected"]["failure"] is None and not expected["limits"] and "head" in expected["inputs"]:
            pairs.append(case)
    return pairs


FIXTURE_PAIRS = _fixture_pairs()


def _fixture_files(case: Path) -> Dict[str, str]:
    inputs = json.loads((case / "expected.json").read_text(encoding="utf-8"))["inputs"]
    return {
        "base.yaml": (case / inputs["base"]).read_text(encoding="utf-8"),
        "head.yaml": (case / inputs["head"]).read_text(encoding="utf-8"),
    }


# ---------------------------------------------------------------------------
# A fixed, rich input for the byte-identity cases
# ---------------------------------------------------------------------------

RICH_BASE = """\
Parameters:
  Env:
    Type: String
    Default: dev
Conditions:
  IsProd: !Equals [!Ref Env, prod]
Resources:
  Zeta:
    Type: AWS::S3::Bucket
    Properties:
      Tags:
        - Key: a
          Value: b
  Alpha:
    Type: AWS::SQS::Queue
    Condition: IsProd
    Properties:
      DelaySeconds: 5
  Gone:
    Type: AWS::SNS::Topic
"""

RICH_HEAD = """\
Parameters:
  Env:
    Type: String
    Default: prod
Conditions:
  IsProd: !Equals [!Ref Env, prod]
Resources:
  Zeta:
    Type: AWS::S3::Bucket
    Properties:
      Tags:
        - Key: a
          Value: c
      BucketName: !Sub "${Env}-bucket"
  Alpha:
    Type: AWS::SQS::Queue
    Condition: IsProd
    Properties:
      DelaySeconds: 10
  Fresh:
    Type: AWS::SNS::Topic
"""


def _rich_files() -> Dict[str, str]:
    a = Finding(
        ID=0,
        Normalized_Category="Encryption",
        FindingType="Security",
        Severity="HIGH",
        Confidence="Confirmed",
        Source=["cfn-lint", "cfn-guard"],
        Resource="Zeta",
        Location=Location(File=FILE, TemplatePath=["Resources", "Zeta", "Properties"]),
        Finding="t",
        WhyItMatters="w",
        Evidence=[
            Evidence(Source="cfn-guard", Detail="d", RuleId="s3_bucket_encryption"),
            Evidence(Source="cfn-lint", Detail="d", RuleId="W3045"),
        ],
        Recommendation="r",
        SuggestedRemediation=None,
    )
    b = Finding(**{**a.__dict__, "Resource": "Gone", "Normalized_Category": "Logging", "Source": ["cfn-guard"],
                   "Evidence": [Evidence(Source="cfn-guard", Detail="d", RuleId="s3_access_logging")],
                   "Location": Location(File=FILE, TemplatePath=["Resources", "Gone"])})  # type: ignore[arg-type]
    c = Finding(**{**b.__dict__, "Resource": "Fresh", "Location": Location(File=FILE, TemplatePath=["Resources", "Fresh"])})  # type: ignore[arg-type]
    d = Finding(**{**b.__dict__, "Resource": None, "Normalized_Category": "Other",
                   "Location": Location(File=FILE, TemplatePath=None)})  # type: ignore[arg-type]
    return {
        "base.yaml": RICH_BASE,
        "head.yaml": RICH_HEAD,
        "base.json": _report_text([a, b, d]),
        "head.json": _report_text([a, c, d]),
    }


RICH_ARGV = TEMPLATE_ARGS + REPORT_ARGS + _declare(REPORT_DECLARATIONS)


# ---------------------------------------------------------------------------
# R11 AC1: byte identity in one process and across hash seeds
# ---------------------------------------------------------------------------


def test_rich_input_exercises_both_comparisons() -> None:
    built = json.loads(_run_on(_rich_files(), RICH_ARGV))
    assert built["semantic_diff"]["analysis_state"] == "analyzed"
    assert {c["change"] for c in built["semantic_diff"]["changes"]} == {"added", "removed", "modified"}
    assert {e["observation"] for e in built["finding_delta"]["entries"]} == {"matched", "base_only", "head_only"}


@pytest.mark.parametrize("mode", [[], ["--plain-identifiers"]], ids=["anonymized", "plain"])
def test_same_input_same_bytes_in_one_process(mode: List[str]) -> None:
    files = _rich_files()
    outputs = {_run_on(files, RICH_ARGV + mode) for _ in range(3)}
    assert len(outputs) == 1


def _child(root: Path, argv: Sequence[str], seed: str, extra: Optional[Dict[str, str]] = None) -> bytes:
    env = dict(os.environ)
    env.update({"PYTHONPATH": str(REPO_ROOT), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": seed})
    if extra:
        env.update(extra)
    run = subprocess.run(
        [sys.executable, "-m", "iacreview.deltacli"] + list(argv),
        cwd=str(root),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )
    assert run.returncode == 0, run.stderr
    assert run.stderr == b""
    return run.stdout


@pytest.mark.parametrize("mode", [[], ["--plain-identifiers"]], ids=["anonymized", "plain"])
def test_same_bytes_across_hash_seeds_and_processes(mode: List[str]) -> None:
    files = _rich_files()
    with _workspace(files) as root:
        _, in_process, _ = _main(RICH_ARGV + mode)
        children = [_child(root, RICH_ARGV + mode, seed) for seed in ("0", "1", "12345")]
    assert children[0] == children[1] == children[2]
    assert children[0] == in_process.encode("utf-8")


#: Both pairs with the declared path (H-M1-1 approved, R1.1, R8.6).
DECLARED_ARGV = RICH_ARGV + ["--declare", "reports_match_templates", "--reviewed-template-path", FILE]


@pytest.mark.parametrize("mode", [[], ["--plain-identifiers"]], ids=["anonymized", "plain"])
def test_declared_path_same_bytes_across_hash_seeds_and_processes(mode: List[str]) -> None:
    files = _rich_files()
    with _workspace(files) as root:
        _, in_process, _ = _main(DECLARED_ARGV + mode)
        children = [_child(root, DECLARED_ARGV + mode, seed) for seed in ("0", "1", "12345")]
    assert children[0] == children[1] == children[2]
    assert children[0] == in_process.encode("utf-8")
    delta = json.loads(in_process)["finding_delta"]
    assert delta["reviewed_template_path"] == {"path": FILE, "status": "declared_not_verified"}


# ---------------------------------------------------------------------------
# R11 AC9: no environment-derived value
# ---------------------------------------------------------------------------

_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")


def _strings_and_numbers(value: Any, skip_keys: Sequence[str] = ("sha256",)) -> Iterator[Any]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key not in skip_keys:
                yield key
                yield from _strings_and_numbers(child, skip_keys)
    elif isinstance(value, list):
        for child in value:
            yield from _strings_and_numbers(child, skip_keys)
    else:
        yield value


def test_no_environment_value_in_the_output() -> None:
    files = _rich_files()
    with _workspace(files) as root:
        _, out, _ = _main(RICH_ARGV)
        _, plain, _ = _main(RICH_ARGV + ["--plain-identifiers"])
        varied = _child(
            root,
            RICH_ARGV,
            "7",
            {"TZ": "Pacific/Chatham", "LANG": "C", "LC_ALL": "C", "USER": "someone-else", "LOGNAME": "someone-else"},
        )
    assert varied == out.encode("utf-8")
    forbidden = {str(root), str(Path(tempfile.gettempdir()).resolve()), platform.node(), getpass.getuser()}
    forbidden.discard("")
    pid = os.getpid()
    for text in (out, plain):
        values = list(_strings_and_numbers(json.loads(text)))
        for value in values:
            if isinstance(value, str):
                for word in forbidden:
                    assert word not in value, (word, value)
                assert not _TIMESTAMP.search(value), value
                assert not value.startswith("/"), value
            elif isinstance(value, int) and not isinstance(value, bool):
                assert value != pid


# ---------------------------------------------------------------------------
# R11 AC5, R6 AC10: permuting findings[] and Evidence[]
# ---------------------------------------------------------------------------


@settings(max_examples=MAX_EXAMPLES, deadline=None)
@given(_finding_lists, _finding_lists, st.integers(min_value=0, max_value=2**32 - 1), st.booleans())
def test_permuted_reports_give_the_same_output(base: List[Finding], head: List[Finding], seed: int, declared: bool) -> None:
    argv = REPORT_ARGS + (_declare(REPORT_DECLARATIONS) if declared else [])
    first = _run_on({"base.json": _report_text(base), "head.json": _report_text(head)}, argv)
    second = _run_on(
        {"base.json": _report_text(_permuted(base, seed)), "head.json": _report_text(_permuted(head, seed + 1))}, argv
    )
    assert _without_digests_and_ids(first) == _without_digests_and_ids(second)


def test_raw_permutation_of_findings_changes_only_digest_ids_and_integrity() -> None:
    # A Review_Report's findings[] has one order (report.build_report). A raw
    # permutation of the JSON array is a Report that fails the internal
    # consistency check: that is recorded, and the matching does not change.
    files = _rich_files()
    head = json.loads(files["head.json"])
    head["findings"].reverse()
    for f in head["findings"]:
        f["Evidence"].reverse()
    permuted = dict(files, **{"head.json": json.dumps(head, indent=2)})
    first = json.loads(_run_on(files, REPORT_ARGS))
    second = json.loads(_run_on(permuted, REPORT_ARGS))
    assert second["finding_delta"]["report_integrity"]["head"] == {"failed_checks": ["rebuild_mismatch"]}
    assert first["finding_delta"]["report_integrity"]["head"] == {"failed_checks": []}

    def shapes(built: Dict[str, Any]) -> Counter:
        return Counter(
            (e["observation"], e["match_stage"], json.dumps(dict(e["base"] or {}, ID=None), sort_keys=True),
             json.dumps(dict(e["head"] or {}, ID=None), sort_keys=True), tuple(e["changes"]))
            for e in built["finding_delta"]["entries"]
        )

    assert shapes(first) == shapes(second)


# A-4: R11 AC5 applies to permutations that keep a Report internally
# consistent; a raw permutation fails the consistency check, and then R2 AC10 /
# AC11 take precedence (Ambiguous, never New / Resolved). Expected values are
# written from those Requirements.


def _a4_finding(resource: str, category: str, severity: str, evidence: Sequence[Tuple[str, Optional[str]]]) -> Finding:
    return Finding(
        ID=0,
        Normalized_Category=category,
        FindingType="Security",
        Severity=severity,
        Confidence="Confirmed",
        Source=sorted({s for s, _ in evidence}, key=SOURCES.index),
        Resource=resource,
        Location=Location(File=FILE, TemplatePath=["Resources", resource]),
        Finding="text",
        WhyItMatters="why",
        Evidence=[Evidence(Source=s, Detail="d", RuleId=r) for s, r in evidence],
        Recommendation="fix",
        SuggestedRemediation=None,
    )


A4_BASE = [
    _a4_finding("Alpha", "Encryption", "HIGH", [("cfn-guard", "s3_bucket_encryption")]),
    _a4_finding("Beta", "Logging", "LOW", [("cfn-guard", "s3_access_logging")]),
]
A4_HEAD = [
    _a4_finding("Alpha", "Encryption", "HIGH", [("cfn-guard", "s3_bucket_encryption")]),
    _a4_finding("Alpha", "Logging", "MEDIUM", [("cfn-guard", "s3_access_logging")]),
    _a4_finding("Gamma", "Encryption", "LOW", [("cfn-lint", "W3045")]),
]


def _a4_shapes(built: Dict[str, Any]) -> Counter:
    return Counter(
        (
            e["observation"],
            e["match_stage"],
            json.dumps(dict(e["base"] or {}, ID=None), sort_keys=True),
            json.dumps(dict(e["head"] or {}, ID=None), sort_keys=True),
        )
        for e in built["finding_delta"]["entries"]
    )


def test_raw_reordered_findings_are_ambiguous_never_new_or_resolved() -> None:
    files = {"base.json": _report_text(A4_BASE), "head.json": _report_text(A4_HEAD)}
    argv = REPORT_ARGS + _declare(REPORT_DECLARATIONS) + ["--plain-identifiers"]
    first = json.loads(_run_on(files, argv))
    counts = Counter(e["classification"] for e in first["finding_delta"]["entries"])
    assert counts == Counter({"Unchanged": 1, "Resolved": 1, "New": 2})

    head = json.loads(files["head.json"])
    head["findings"].reverse()
    second = json.loads(_run_on(dict(files, **{"head.json": json.dumps(head, indent=2)}), argv))
    delta = second["finding_delta"]
    assert delta["report_integrity"]["head"]["failed_checks"] == ["rebuild_mismatch"]
    assert delta["report_integrity"]["base"]["failed_checks"] == []
    assert delta["classification_completeness"] == "partial"
    by_class = second["summary"]["finding_delta"]["by_classification"]
    assert by_class["New"] == 0 and by_class["Resolved"] == 0
    for entry in delta["entries"]:
        if entry["observation"] == "matched":
            assert entry["classification"] == "Unchanged"
        else:
            assert entry["classification"] == "Ambiguous"
            assert "report_integrity_failed" in entry["reasons"]
    # Matching itself does not depend on input order (R6.10).
    assert _a4_shapes(first) == _a4_shapes(second)


def test_consistent_evidence_permutation_changes_only_the_digest() -> None:
    findings = [
        _a4_finding("Alpha", "Encryption", "HIGH", [("cfn-guard", "s3_bucket_encryption"), ("cfn-lint", "W3045")]),
        _a4_finding("Beta", "Logging", "LOW", [("cfn-guard", "s3_access_logging"), ("cfn-guard", None)]),
    ]
    files = {"base.json": _report_text(findings[:1]), "head.json": _report_text(findings)}
    head = json.loads(files["head.json"])
    order = [f["Resource"] for f in head["findings"]]
    for f in head["findings"]:
        f["Evidence"].reverse()
    assert [f["Resource"] for f in head["findings"]] == order
    permuted = dict(files, **{"head.json": report.dump(head)})
    assert permuted["head.json"] != files["head.json"]
    argv = REPORT_ARGS + _declare(REPORT_DECLARATIONS)
    first = json.loads(_run_on(files, argv))
    second = json.loads(_run_on(permuted, argv))
    assert second["finding_delta"]["report_integrity"] == first["finding_delta"]["report_integrity"]
    assert second["finding_delta"]["report_integrity"]["head"]["failed_checks"] == []
    for built in (first, second):
        built["inputs"]["head"]["report"]["sha256"] = None
    assert report.dump(first) == report.dump(second)


# ---------------------------------------------------------------------------
# R11 AC6, R3 AC8: re-expression
# ---------------------------------------------------------------------------


@settings(max_examples=MAX_EXAMPLES, deadline=None)
@given(_template_docs(), st.integers(min_value=0, max_value=2**32 - 1), st.sampled_from((None, 1, 4)))
def test_yaml_and_json_re_expressions_have_no_changes(doc: Dict[str, Any], seed: int, indent: Optional[int]) -> None:
    rng = random.Random(seed)
    yaml_text = yaml.safe_dump(_reordered(doc, rng), sort_keys=False, default_flow_style=rng.choice((False, None)))
    json_text = json.dumps(_reordered(doc, rng), indent=indent)
    built = json.loads(_run_on({"base.yaml": yaml_text, "head.json": json_text}, ["--base-template", "base.yaml", "--head-template", "head.json"]))
    diff = built["semantic_diff"]
    assert diff["analysis_state"] == "analyzed", diff["failure"]
    assert diff["observation"] == "no_changes_observed"
    assert diff["changes"] == []


def test_notation_only_rewrites_have_no_changes() -> None:
    base = """\
# a comment
Parameters:
  Env: {Type: String}
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub '${Env}-x'
      Tags: &tags
        - {Key: k, Value: !Ref Env}
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      Tags: *tags
      QueueName: !GetAtt [Bucket, Arn]
"""
    head = json.dumps(
        {
            "Resources": {
                "Queue": {
                    "Properties": {
                        "QueueName": {"Fn::GetAtt": ["Bucket", "Arn"]},
                        "Tags": [{"Value": {"Ref": "Env"}, "Key": "k"}],
                    },
                    "Type": "AWS::SQS::Queue",
                },
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"Tags": [{"Key": "k", "Value": {"Ref": "Env"}}], "BucketName": {"Fn::Sub": "${Env}-x"}},
                },
            },
            "Parameters": {"Env": {"Type": "String"}},
        },
        indent=3,
    )
    built = json.loads(_run_on({"base.yaml": base, "head.json": head}, ["--base-template", "base.yaml", "--head-template", "head.json"]))
    assert built["semantic_diff"]["observation"] == "no_changes_observed"
    assert built["semantic_diff"]["changes"] == []


# ---------------------------------------------------------------------------
# R11 AC7: self-comparison
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", ANALYZABLE_FIXTURE_FILES, ids=lambda p: "{0}/{1}".format(p.parent.name, p.name))
def test_a_fixture_template_compared_with_itself(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    name = "t" + path.suffix
    built = json.loads(_run_on({name: text}, ["--base-template", name, "--head-template", name]))
    diff = built["semantic_diff"]
    assert diff["analysis_state"] == "analyzed", diff["failure"]
    assert diff["observation"] == "no_changes_observed"
    assert diff["changes"] == []


def test_enough_fixture_templates_are_self_compared() -> None:
    assert len(ANALYZABLE_FIXTURE_FILES) >= 40


@settings(max_examples=MAX_EXAMPLES, deadline=None)
@given(_finding_lists, st.booleans())
def test_a_report_compared_with_itself(findings: List[Finding], declared: bool) -> None:
    text = _report_text(findings)
    argv = ["--base-report", "r.json", "--head-report", "r.json"] + (_declare(REPORT_DECLARATIONS) if declared else [])
    delta = json.loads(_run_on({"r.json": text}, argv))["finding_delta"]
    assert delta["analysis_state"] == "analyzed"
    assert delta["observation"] == "no_changes_observed" or any(
        "duplicate_fingerprint" in e["reasons"] for e in delta["entries"]
    )
    for entry in delta["entries"]:
        if entry["observation"] != "matched":
            assert "duplicate_fingerprint" in entry["reasons"], entry
        else:
            assert entry["classification"] in ("Unchanged", "Ambiguous")
            assert entry["changes"] == []
    # R6 AC11: every Finding is in exactly one Delta_Entry, on each side.
    count = len(json.loads(text)["findings"])
    assert sum(e["base"] is not None for e in delta["entries"]) == count
    assert sum(e["head"] is not None for e in delta["entries"]) == count


# ---------------------------------------------------------------------------
# R11 AC4, AC8: swapping Base and Head
# ---------------------------------------------------------------------------


@settings(max_examples=MAX_EXAMPLES, deadline=None)
@given(_finding_lists, _finding_lists, st.booleans(), st.booleans())
def test_swapping_reports(base: List[Finding], head: List[Finding], declared: bool, plain: bool) -> None:
    files = {"base.json": _report_text(base), "head.json": _report_text(head)}
    extra = (_declare(REPORT_DECLARATIONS) if declared else []) + (["--plain-identifiers"] if plain else [])
    forward = json.loads(_run_on(files, REPORT_ARGS + extra))["finding_delta"]
    backward = json.loads(_run_on(files, SWAPPED_REPORT_ARGS + extra))["finding_delta"]
    # Tokens are compared as they are: an entry only lines up if every
    # Identifier_Token in it is the same in both runs.
    assert Counter(_entry_shape(e, swap=False) for e in forward["entries"]) == Counter(
        _entry_shape(e, swap=True) for e in backward["entries"]
    )


@pytest.mark.parametrize("case", FIXTURE_PAIRS, ids=lambda p: p.name)
@pytest.mark.parametrize("plain", [False, True], ids=["anonymized", "plain"])
def test_swapping_fixture_templates(case: Path, plain: bool) -> None:
    files = _fixture_files(case)
    extra = ["--plain-identifiers"] if plain else []
    forward = json.loads(_run_on(files, TEMPLATE_ARGS + extra))["semantic_diff"]
    backward = json.loads(_run_on(files, SWAPPED_TEMPLATE_ARGS + extra))["semantic_diff"]
    assert forward["observation"] == backward["observation"]
    assert sorted(forward["semantic_limitations"]) == sorted(backward["semantic_limitations"])
    assert Counter(_change_shape(c, swap=False) for c in forward["changes"]) == Counter(
        _change_shape(c, swap=True) for c in backward["changes"]
    )
    assert Counter(json.dumps(u, sort_keys=True) for u in forward["uncompared_paths"]) == Counter(
        json.dumps(u, sort_keys=True) for u in backward["uncompared_paths"]
    )


def test_enough_fixture_pairs_are_swapped() -> None:
    assert len(FIXTURE_PAIRS) >= 30


def test_swapping_the_rich_input_keeps_every_token() -> None:
    files = _rich_files()
    forward = json.loads(_run_on(files, RICH_ARGV))
    backward = json.loads(
        _run_on(files, SWAPPED_TEMPLATE_ARGS + SWAPPED_REPORT_ARGS + _declare(REPORT_DECLARATIONS))
    )
    assert Counter(_change_shape(c, swap=False) for c in forward["semantic_diff"]["changes"]) == Counter(
        _change_shape(c, swap=True) for c in backward["semantic_diff"]["changes"]
    )
    assert Counter(_entry_shape(e, swap=False) for e in forward["finding_delta"]["entries"]) == Counter(
        _entry_shape(e, swap=True) for e in backward["finding_delta"]["entries"]
    )
    # With the Template_Pair at other paths than the Reports' target the
    # one-sided Findings are Ambiguous; the Report_Pair alone gives New and
    # Resolved, which swap.
    classes = Counter(e["classification"] for e in forward["finding_delta"]["entries"])
    assert classes["Ambiguous"] == 2 and classes["New"] == classes["Resolved"] == 0
    alone = json.loads(_run_on(files, REPORT_ARGS + _declare(REPORT_DECLARATIONS)))["finding_delta"]
    swapped = json.loads(_run_on(files, SWAPPED_REPORT_ARGS + _declare(REPORT_DECLARATIONS)))["finding_delta"]
    assert Counter(e["classification"] for e in alone["entries"]) == Counter({"Unchanged": 2, "New": 1, "Resolved": 1})
    assert Counter(_entry_shape(e, swap=False) for e in alone["entries"]) == Counter(
        _entry_shape(e, swap=True) for e in swapped["entries"]
    )
