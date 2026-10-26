"""End to end: Reports from the existing orchestrator into the Delta_Tool (v1.1 Task 13).

Requirement guarded
-------------------

v1.1 Requirement 15 AC8: Base / Head Reports are generated with the existing
``run_iac_review.py`` from a Benchmark-derived Template pair, and the expected
Delta_Entries are asserted with and without Input_Declarations. The Benchmark
case itself is only read (its SHA-256 is checked before and after).

The pair
--------

Base is ``benchmark/cases/case-001-iam-wildcard/template.yaml`` unchanged. Its
Ground_Truth names two IAM Findings, on ``AdministratorManagedPolicy`` and on
``DeploymentRole``, both from the IAM detectors. Head is a copy edited in
``tmp_path``:

* ``AdministratorManagedPolicy`` and its Output: removed (fixed by removal);
* ``DeploymentRole``: unchanged;
* ``ExtraWildcardPolicy``: a new ``AWS::IAM::ManagedPolicy`` with ``Action:
  "*"`` on ``Resource: "*"``, inserted before ``Outputs`` (introduced).

A first draft narrowed the statement to ``s3:GetObject`` on
``arn:aws:s3:::example-bucket/*`` instead of removing it. The IAM detectors
still report that statement (``wildcard_resource``,
``sensitive_prefix_without_condition``), so the Base Finding was ``matched``
with ``changes: [Severity, Evidence]`` rather than removed: correct Delta
output for those Reports, but not the pair this test means to build. The edit
was changed to a removal; the expected Delta below did not change.

The Reports are generated with ``--sources iam-review`` only, so the result
does not depend on cfn-lint or cfn-guard being installed, and each side is
reviewed in its own workspace at the same relative path
(``stack/template.yaml``), as two revisions of one repository would be.

Expected, written from the Ground_Truth and the edit before the run
--------------------------------------------------------------------

Report_Pair, with all five Report declarations: ``AdministratorManagedPolicy``
``base_only`` / ``Resolved``; ``DeploymentRole`` ``matched`` (stage 1) /
``Unchanged``; ``ExtraWildcardPolicy`` ``head_only`` / ``New``. Without
declarations, or with one missing, the two one-sided entries are
``Unconfirmed`` with ``input_declaration_absent`` and the missing Codes.

Template_Pair: ``AdministratorManagedPolicy`` ``removed`` and
``ExtraWildcardPolicy`` ``added``, both ``AWS::IAM::ManagedPolicy``, so both
carry the hint ``possible_logical_id_rename`` (R4.13), and the Output
``AdministratorManagedPolicyArn`` ``removed``.

Both pairs at once: the two Templates live at different workspace paths, so
neither is in the other side's Report ``target``; correspondence is
``inconsistent`` and no Finding becomes ``New`` or ``Resolved``, whatever is
declared. The two one-sided Findings are on the hinted Logical IDs, so they
are Ambiguous for both reasons.

Both pairs, reviewed in one workspace (M1 A-6, scenario ii): each side is
reviewed from one root at the very path given to the Delta_Tool
(``base_ws/stack/template.yaml`` and ``head_ws/stack/template.yaml``). Each
Template is then in its own Report's ``target`` and every Finding ``Resource``
is a Logical ID of its Template, so correspondence is
``consistent_by_name_only`` (R8.6). But ``Location.File`` differs per side, so
no Identity_Key is shared (R6.1) and no Finding's file is in both ``target``
lists (R7.1): every Finding of either Report is its own one-sided entry,
``Ambiguous`` with ``source_not_comparable`` and ``template_not_reviewed``;
nothing is ``matched``, ``New`` or ``Resolved``, even the unchanged
``DeploymentRole``. This is the documented limit of combining the two pairs.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pytest

from iacreview import deltacli

PLUGIN_ROOT: Path = Path(__file__).resolve().parents[2]
ORCHESTRATOR = PLUGIN_ROOT / "skills" / "iac-review" / "scripts" / "run_iac_review.py"
CASE = PLUGIN_ROOT / "benchmark" / "cases" / "case-001-iam-wildcard" / "template.yaml"
STACK = "stack/template.yaml"

REPORT_DECLARATIONS = (
    "reports_unmodified",
    "same_plugin_version",
    "same_rule_set",
    "same_tool_configuration",
    "same_agent_findings_input",
)

#: (start, end) markers of the two blocks the Head removes; ``end`` is kept.
REMOVED_BLOCKS = (
    ("  # One statement, and it is the whole account", "  DeploymentRole:\n"),
    ("  AdministratorManagedPolicyArn:\n", "  DeploymentRoleArn:\n"),
)
EXTRA = """\
  ExtraWildcardPolicy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action: "*"
            Resource: "*"

"""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


CASE_SHA256_AT_IMPORT = _sha256(CASE)


def _head_text(base: str) -> str:
    text = base
    for start, end in REMOVED_BLOCKS:
        assert text.count(start) == 1 and text.count(end) == 1
        first, last = text.index(start), text.index(end)
        assert first < last
        text = text[:first] + text[last:]
    assert "  AdministratorManagedPolicy:\n" not in text and "!Ref AdministratorManagedPolicy" not in text
    assert text.count("\nOutputs:\n") == 1
    return text.replace("\nOutputs:\n", "\n" + EXTRA + "Outputs:\n")


def _review(workspace: Path, target: str = STACK) -> str:
    # The inherited environment keeps coverage wiring (tests/conftest.py).
    run = subprocess.run(
        [sys.executable, str(ORCHESTRATOR), "--target", target, "--sources", "iam-review"],
        cwd=str(workspace),
        env=dict(os.environ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )
    assert run.returncode == 0, run.stderr.decode("utf-8", "replace")
    return run.stdout.decode("utf-8")


@pytest.fixture(scope="module")
def pair(tmp_path_factory: pytest.TempPathFactory) -> Path:
    before = _sha256(CASE)
    root = tmp_path_factory.mktemp("delta_e2e")
    base_text = CASE.read_text(encoding="utf-8")
    for side, text in (("base", base_text), ("head", _head_text(base_text))):
        workspace = root / (side + "_ws")
        (workspace / "stack").mkdir(parents=True)
        (workspace / STACK).write_text(text, encoding="utf-8")
        (root / (side + ".json")).write_text(_review(workspace), encoding="utf-8")
    assert _sha256(CASE) == before
    return root


def _delta(root: Path, argv: Sequence[str], monkeypatch: pytest.MonkeyPatch) -> Tuple[int, Dict[str, Any], str]:
    monkeypatch.chdir(root)
    out, err = io.StringIO(), io.StringIO()
    code = deltacli.main(list(argv), stdout=out, stderr=err)
    return code, json.loads(out.getvalue()), err.getvalue()


REPORTS = ["--base-report", "base.json", "--head-report", "head.json"]
TEMPLATES = ["--base-template", "base_ws/" + STACK, "--head-template", "head_ws/" + STACK]


def _declare(codes: Sequence[str]) -> List[str]:
    argv: List[str] = []
    for code in codes:
        argv += ["--declare", code]
    return argv


def _resource(entry: Dict[str, Any]) -> Optional[str]:
    side = entry["base"] or entry["head"]
    return side["Resource"]


def _shape(entry: Dict[str, Any]) -> Tuple[Any, ...]:
    side = entry["base"] or entry["head"]
    return (
        _resource(entry),
        side["Normalized_Category"],
        entry["observation"],
        entry["classification"],
        tuple(entry["reasons"]),
        entry["match_stage"],
        tuple(entry["missing_declarations"]),
        tuple(entry["changes"]),
    )


def test_the_generated_reports_hold_the_ground_truth_findings(pair: Path) -> None:
    base = json.loads((pair / "base.json").read_text(encoding="utf-8"))
    head = json.loads((pair / "head.json").read_text(encoding="utf-8"))
    assert base["sources_enabled"] == head["sources_enabled"] == ["IAM Review"]
    assert sorted(f["Resource"] for f in base["findings"]) == ["AdministratorManagedPolicy", "DeploymentRole"]
    assert sorted(f["Resource"] for f in head["findings"]) == ["DeploymentRole", "ExtraWildcardPolicy"]
    assert base["errors"] == [] and head["errors"] == []


ONE_SIDED = {
    "AdministratorManagedPolicy": ("base_only", "Resolved"),
    "ExtraWildcardPolicy": ("head_only", "New"),
}


def _expected(declared: Sequence[str]) -> Counter:
    missing = tuple(c for c in REPORT_DECLARATIONS if c not in declared)
    shapes = [("DeploymentRole", "IAM", "matched", "Unchanged", (), 1, (), ())]
    for resource, (observation, classification) in ONE_SIDED.items():
        if missing:
            shapes.append((resource, "IAM", observation, "Unconfirmed", ("input_declaration_absent",), None, missing, ()))
        else:
            shapes.append((resource, "IAM", observation, classification, (), None, (), ()))
    return Counter(shapes)


@pytest.mark.parametrize(
    "declared",
    [list(REPORT_DECLARATIONS), [], list(REPORT_DECLARATIONS[:-1]), list(REPORT_DECLARATIONS[1:])],
    ids=["all", "none", "last-missing", "first-missing"],
)
def test_report_pair_with_and_without_declarations(
    declared: List[str], pair: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, built, err = _delta(pair, REPORTS + _declare(declared) + ["--plain-identifiers"], monkeypatch)
    assert code == 0 and err == ""
    delta = built["finding_delta"]
    assert delta["analysis_state"] == "analyzed"
    assert delta["observation"] == "changes_observed"
    assert delta["template_report_correspondence"] == "not_applicable"
    assert delta["classification_completeness"] == ("complete" if len(declared) == 5 else "partial")
    assert Counter(_shape(e) for e in delta["entries"]) == _expected(declared)
    assert built["inputs"]["base"]["report"]["sha256"] == _sha256(pair / "base.json")


def test_anonymized_output_has_the_same_classifications(pair: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _, plain, _ = _delta(pair, REPORTS + _declare(REPORT_DECLARATIONS) + ["--plain-identifiers"], monkeypatch)
    _, anonymized, _ = _delta(pair, REPORTS + _declare(REPORT_DECLARATIONS), monkeypatch)

    def classes(built: Dict[str, Any]) -> Counter:
        return Counter((e["observation"], e["classification"]) for e in built["finding_delta"]["entries"])

    assert classes(plain) == classes(anonymized)
    text = json.dumps(anonymized)
    for name in ("AdministratorManagedPolicy", "DeploymentRole", "ExtraWildcardPolicy"):
        assert name not in text


def test_template_pair(pair: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, built, err = _delta(pair, TEMPLATES + ["--plain-identifiers"], monkeypatch)
    assert code == 0 and err == ""
    diff = built["semantic_diff"]
    assert diff["analysis_state"] == "analyzed"
    assert diff["observation"] == "changes_observed"
    assert diff["structural_completeness"] == "complete"
    assert diff["semantic_limitations"] == [] and diff["uncompared_paths"] == []
    managed = "AWS::IAM::ManagedPolicy"
    rename = ("possible_logical_id_rename",)
    resources = sorted(
        (
            c["change"],
            json.dumps(c["path"]),
            c["resource_type"]["base"],
            c["resource_type"]["head"],
            tuple(c["qualifiers"]),
            tuple(c["hints"]),
        )
        for c in diff["changes"]
        if c["section"] == "Resources"
    )
    assert resources == sorted(
        [
            ("removed", json.dumps(["Resources", "AdministratorManagedPolicy"]), managed, None, (), rename),
            ("added", json.dumps(["Resources", "ExtraWildcardPolicy"]), None, managed, (), rename),
        ]
    )
    outputs = [(c["change"], c["path"]) for c in diff["changes"] if c["section"] != "Resources"]
    assert outputs == [("removed", ["Outputs", "AdministratorManagedPolicyArn"])]


#: In the order of ``deltaschema.AMBIGUOUS_REASONS``.
BOTH_REASONS = ("possible_logical_id_rename", "template_report_mismatch")


def test_both_pairs_at_different_paths_are_never_new_or_resolved(pair: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    argv = TEMPLATES + REPORTS + _declare(REPORT_DECLARATIONS + ("reports_match_templates",)) + ["--plain-identifiers"]
    code, built, _ = _delta(pair, argv, monkeypatch)
    assert code == 0
    delta = built["finding_delta"]
    assert delta["template_report_correspondence"] == "inconsistent"
    shapes = Counter(_shape(e) for e in delta["entries"])
    assert shapes == Counter(
        [
            ("DeploymentRole", "IAM", "matched", "Unchanged", (), 1, (), ()),
            ("AdministratorManagedPolicy", "IAM", "base_only", "Ambiguous", BOTH_REASONS, None, (), ()),
            ("ExtraWildcardPolicy", "IAM", "head_only", "Ambiguous", BOTH_REASONS, None, (), ()),
        ]
    )


def test_the_benchmark_case_is_untouched(pair: Path) -> None:
    assert _sha256(CASE) == CASE_SHA256_AT_IMPORT
    assert sorted(p.name for p in CASE.parent.iterdir()) == ["ground_truth.json", "template.yaml"]


@pytest.fixture(scope="module")
def one_workspace(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Both sides reviewed from one root, at the paths the Delta_Tool is given."""
    root = tmp_path_factory.mktemp("delta_e2e_one")
    base_text = CASE.read_text(encoding="utf-8")
    for side, text in (("base", base_text), ("head", _head_text(base_text))):
        path = root / (side + "_ws") / STACK
        path.parent.mkdir(parents=True)
        path.write_text(text, encoding="utf-8")
        (root / (side + ".json")).write_text(_review(root, side + "_ws/" + STACK), encoding="utf-8")
    return root


def test_both_pairs_reviewed_in_one_workspace_match_nothing(one_workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base = json.loads((one_workspace / "base.json").read_text(encoding="utf-8"))
    head = json.loads((one_workspace / "head.json").read_text(encoding="utf-8"))
    assert base["target"]["files"] == ["base_ws/" + STACK] and head["target"]["files"] == ["head_ws/" + STACK]
    findings = len(base["findings"]) + len(head["findings"])
    assert len(base["findings"]) >= 2 and len(head["findings"]) >= 2

    argv = TEMPLATES + REPORTS + _declare(REPORT_DECLARATIONS + ("reports_match_templates",)) + ["--plain-identifiers"]
    code, built, err = _delta(one_workspace, argv, monkeypatch)
    assert (code, err) == (0, "")
    delta = built["finding_delta"]
    assert delta["analysis_state"] == "analyzed"
    assert delta["template_report_correspondence"] == "consistent_by_name_only"
    entries = delta["entries"]
    assert len(entries) == findings
    assert [e for e in entries if e["observation"] == "matched"] == []
    for entry in entries:
        assert entry["classification"] == "Ambiguous", entry
        assert "source_not_comparable" in entry["reasons"] and "template_not_reviewed" in entry["reasons"], entry
    counts = built["summary"]["finding_delta"]["by_classification"]
    assert counts["New"] == counts["Resolved"] == counts["Unchanged"] == 0


# ---------------------------------------------------------------------------
# Both pairs with --reviewed-template-path (H-M1-1 approved, R1.1, R8.6)
# ---------------------------------------------------------------------------
#
# Expected, written before the implementation
#
# Two checkouts ``base_ws/`` and ``head_ws/`` hold ``stack/template.yaml``
# (same relative path, as two revisions of one repository). Each is reviewed
# from its own root, so both Reports have ``target.files`` ==
# ``["stack/template.yaml"]`` and ``Location.File`` == ``stack/template.yaml``.
# No Logical ID is added or removed, so the Semantic Diff gives no rename hint:
#
# * Base: ``PolicyA`` allows ``Action: "*"`` on ``Resource: "*"``; ``PolicyB``
#   allows ``sqs:SendMessage`` on one queue ARN (no IAM Finding).
# * Head: ``PolicyA`` narrowed to the ``PolicyB`` statement; ``PolicyB``
#   widened to the wildcard statement.
#
# With the six declarations and ``--reviewed-template-path
# stack/template.yaml``: correspondence ``consistent_by_name_only``,
# ``reviewed_template_path`` ``{"path": "stack/template.yaml", "status":
# "declared_not_verified"}``, ``PolicyA`` ``base_only`` / ``Resolved``,
# ``PolicyB`` ``head_only`` / ``New``, nothing else, no ``Ambiguous``.
# Without the declaration the same run is ``inconsistent`` and has no New /
# Resolved (the previous behaviour). Swapping Base and Head swaps New and
# Resolved (R11.8). With case-001 (a Logical ID removed and one added) the
# declaration does not override the rename hint: the one-sided entries stay
# ``Ambiguous`` with ``possible_logical_id_rename`` only.

WILDCARD = '          - Effect: Allow\n            Action: "*"\n            Resource: "*"\n'
NARROW = (
    "          - Effect: Allow\n"
    '            Action: "sqs:SendMessage"\n'
    '            Resource: "arn:aws:sqs:us-east-1:123456789012:example-queue"\n'
)


def _policies(a: str, b: str) -> str:
    head = '    Type: AWS::IAM::ManagedPolicy\n    Properties:\n      PolicyDocument:\n        Version: "2012-10-17"\n        Statement:\n'
    return 'AWSTemplateFormatVersion: "2010-09-09"\nResources:\n  PolicyA:\n' + head + a + "  PolicyB:\n" + head + b


DECLARED_PATH = ["--reviewed-template-path", STACK]
SIX = REPORT_DECLARATIONS + ("reports_match_templates",)


@pytest.fixture(scope="module")
def checkouts(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("delta_e2e_declared")
    for side, text in (("base", _policies(WILDCARD, NARROW)), ("head", _policies(NARROW, WILDCARD))):
        workspace = root / (side + "_ws")
        (workspace / "stack").mkdir(parents=True)
        (workspace / STACK).write_text(text, encoding="utf-8")
        (root / (side + ".json")).write_text(_review(workspace), encoding="utf-8")
    return root


def test_the_checkout_reports_hold_one_policy_finding_each(checkouts: Path) -> None:
    base = json.loads((checkouts / "base.json").read_text(encoding="utf-8"))
    head = json.loads((checkouts / "head.json").read_text(encoding="utf-8"))
    assert base["target"]["files"] == head["target"]["files"] == [STACK]
    assert [(f["Resource"], f["Location"]["File"]) for f in base["findings"]] == [("PolicyA", STACK)]
    assert [(f["Resource"], f["Location"]["File"]) for f in head["findings"]] == [("PolicyB", STACK)]


def test_declared_path_gives_new_and_resolved(checkouts: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    argv = TEMPLATES + REPORTS + _declare(SIX) + DECLARED_PATH + ["--plain-identifiers"]
    code, built, err = _delta(checkouts, argv, monkeypatch)
    assert (code, err) == (0, "")
    diff = built["semantic_diff"]
    assert diff["analysis_state"] == "analyzed"
    assert all(c["hints"] == [] for c in diff["changes"])
    delta = built["finding_delta"]
    assert delta["template_report_correspondence"] == "consistent_by_name_only"
    assert delta["reviewed_template_path"] == {"path": STACK, "status": "declared_not_verified"}
    assert delta["classification_completeness"] == "complete"
    assert Counter(_shape(e) for e in delta["entries"]) == Counter(
        [
            ("PolicyA", "IAM", "base_only", "Resolved", (), None, (), ()),
            ("PolicyB", "IAM", "head_only", "New", (), None, (), ()),
        ]
    )
    counts = built["summary"]["finding_delta"]["by_classification"]
    assert (counts["New"], counts["Resolved"], counts["Ambiguous"], counts["Unconfirmed"]) == (1, 1, 0, 0)


def test_declared_path_absent_keeps_the_fail_closed_result(checkouts: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, built, _ = _delta(checkouts, TEMPLATES + REPORTS + _declare(SIX) + ["--plain-identifiers"], monkeypatch)
    assert code == 0
    delta = built["finding_delta"]
    assert delta["template_report_correspondence"] == "inconsistent"
    assert delta["reviewed_template_path"] is None
    counts = built["summary"]["finding_delta"]["by_classification"]
    assert counts["New"] == counts["Resolved"] == 0


def test_declared_path_swapping_sides_swaps_new_and_resolved(checkouts: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    argv = ["--base-template", "head_ws/" + STACK, "--head-template", "base_ws/" + STACK]
    argv += ["--base-report", "head.json", "--head-report", "base.json"]
    code, built, _ = _delta(checkouts, argv + _declare(SIX) + DECLARED_PATH + ["--plain-identifiers"], monkeypatch)
    assert code == 0
    assert Counter(_shape(e) for e in built["finding_delta"]["entries"]) == Counter(
        [
            ("PolicyB", "IAM", "base_only", "Resolved", (), None, (), ()),
            ("PolicyA", "IAM", "head_only", "New", (), None, (), ()),
        ]
    )


def test_declared_path_does_not_override_the_rename_hint(pair: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    argv = TEMPLATES + REPORTS + _declare(SIX) + DECLARED_PATH + ["--plain-identifiers"]
    code, built, _ = _delta(pair, argv, monkeypatch)
    assert code == 0
    delta = built["finding_delta"]
    assert delta["template_report_correspondence"] == "consistent_by_name_only"
    rename = ("possible_logical_id_rename",)
    assert Counter(_shape(e) for e in delta["entries"]) == Counter(
        [
            ("DeploymentRole", "IAM", "matched", "Unchanged", (), 1, (), ()),
            ("AdministratorManagedPolicy", "IAM", "base_only", "Ambiguous", rename, None, (), ()),
            ("ExtraWildcardPolicy", "IAM", "head_only", "Ambiguous", rename, None, (), ()),
        ]
    )
