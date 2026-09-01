"""``benchmark/harness/run_benchmark.py`` run as a process, against real reviews.

``tests/unit/test_run_benchmark.py`` covers the harness's own logic in process.
This module runs the script the way a contributor and CI run it, and asserts the
three things only a real run can show: that the documented invocation produces
the documented document, that its bytes do not change between runs, and that the
exit code says what happened.

Two kinds of workspace are used, for two different questions.

**A synthetic workspace** (``tmp_path`` with a ``cases/`` tree written by the
test) answers questions about the harness: does a missed deterministic
expectation exit non-zero, does an agent-dependent one avoid the threshold, is a
malformed case one skipped case rather than a dead run. Its cases are reviewed
with the deterministic IAM detectors, which need nothing on PATH, so these run
wherever Python does. The workspace is ``tmp_path`` because the harness contains
every path inside its working directory -- which is also what makes
``--cases`` pointing outside it a testable refusal.

**The real ``benchmark/cases/``** answers the completion condition of Task 21.6:
``--cases benchmark/cases --mode combined`` exits 0 with every category ``PASS``.
That needs both external tools, and skips without them (Requirement 15 AC4): a
review missing a Source is a review whose missing findings mean something other
than a regression.
"""

from __future__ import annotations

import functools
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

import pytest

from benchmark.harness import metrics, run_benchmark
from iacreview import exitcodes

# tests/integration/test_benchmark_harness.py -> tests/integration -> tests -> root
PLUGIN_ROOT: Path = Path(__file__).resolve().parents[2]
HARNESS: Path = PLUGIN_ROOT / "benchmark" / "harness" / "run_benchmark.py"
REAL_CASES = "benchmark/cases"

TIMEOUT_S = 900

#: Executable each mode needs before its numbers mean anything. ``iam-only`` and
#: ``combined`` are absent: the IAM detectors are pure Python, and a combined run
#: whose external tools are missing still completes with the IAM Source.
EXTERNAL_TOOL_BY_MODE = {"cfn-lint-only": "cfn-lint", "cfn-guard-only": "cfn-guard"}

#: Both tools a full review uses.
EXTERNAL_TOOLS = ("cfn-lint", "cfn-guard")


# ---------------------------------------------------------------------------
# Templates the synthetic cases are built from
# ---------------------------------------------------------------------------

#: One resource, one defect the deterministic IAM detectors reach: Action "*" on
#: Resource "*". Reviewed with ``--mode iam-only`` it produces exactly one
#: finding, on ``AdminPolicy``, in the ``IAM`` category at ``CRITICAL``.
WILDCARD_TEMPLATE = """AWSTemplateFormatVersion: "2010-09-09"
Description: A synthetic case for the harness tests. Do not deploy this template.
Resources:
  AdminPolicy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      Description: Grants every action on every resource.
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Sid: AllowEverything
            Effect: Allow
            Action: "*"
            Resource: "*"
"""

#: No IAM at all, so the IAM detectors report nothing about it.
QUIET_TEMPLATE = """AWSTemplateFormatVersion: "2010-09-09"
Description: A synthetic case with no IAM resources.
Resources:
  NotificationTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Harness test topic
"""


# ---------------------------------------------------------------------------
# Building a synthetic workspace
# ---------------------------------------------------------------------------


def expectation(
    resource: Optional[str] = "AdminPolicy",
    normalized_category: str = "IAM",
    finding_type: str = "Security",
    severity: str = "CRITICAL",
    detection_class: str = metrics.DETERMINISTIC,
    detected_by: Sequence[str] = ("IAM Review",),
) -> Dict[str, Any]:
    return {
        "resource": resource,
        "normalized_category": normalized_category,
        "finding_type": finding_type,
        "severity": severity,
        "detection_class": detection_class,
        "detected_by": list(detected_by),
        "note": "A deliberate defect, or a deliberately absent one.",
    }


def write_case(
    workspace: Path,
    case_id: str,
    *,
    template: Optional[str] = WILDCARD_TEMPLATE,
    expectations: Sequence[Dict[str, Any]] = (),
    ground_truth_text: Optional[str] = None,
) -> Path:
    """Create one case under ``<workspace>/cases/`` and return its directory."""
    case_dir = workspace / "cases" / case_id
    case_dir.mkdir(parents=True)
    if template is not None:
        (case_dir / "template.yaml").write_text(template, encoding="utf-8")
    if ground_truth_text is None:
        ground_truth_text = json.dumps(
            {
                "schema_version": "1.0.0",
                "case_id": case_id,
                "template": "template.yaml",
                "description": "A synthetic case for the harness tests.",
                "authored_before_review": True,
                "expected_finding_count": len(expectations),
                "expected_findings": list(expectations),
                "expected_findings_agent_only": [],
                "expected_findings_human_review": [],
            },
            indent=2,
        )
    (case_dir / "ground_truth.json").write_text(ground_truth_text, encoding="utf-8")
    return case_dir


def run_harness(
    arguments: Sequence[str],
    cwd: Path,
    env: Optional[Dict[str, str]] = None,
) -> "subprocess.CompletedProcess[str]":
    """Run the harness as a process, the way a contributor runs it.

    ``cwd`` is the workspace root: the harness contains ``--cases`` inside it, and
    the review it starts resolves its target relative to it.

    ``env`` replaces the inherited environment. Only one test passes it, to make
    both external tools unreachable regardless of what the host has installed; the
    harness itself starts the review with an absolute interpreter path, so an empty
    ``PATH`` costs nothing else.
    """
    return subprocess.run(
        [sys.executable, str(HARNESS), *arguments],
        cwd=str(cwd),
        env=dict(os.environ) if env is None else env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
    )


def summary_of(completed: "subprocess.CompletedProcess[str]") -> Dict[str, Any]:
    """Parse the harness's stdout, with its stderr in the failure message."""
    assert completed.stdout, "stdout was empty; stderr was:\n{0}".format(
        completed.stderr
    )
    document = json.loads(completed.stdout)
    assert isinstance(document, dict)
    return document


def case_entry(summary: Dict[str, Any], case_id: str) -> Dict[str, Any]:
    matching = [entry for entry in summary["cases"] if entry["case_id"] == case_id]
    assert matching, "{0} is not in the summary".format(case_id)
    return matching[0]


def skip_unless_available(executables: Iterable[str]) -> None:
    """Skip rather than fail when an external tool is absent (Requirement 15 AC4)."""
    missing = sorted(name for name in executables if shutil.which(name) is None)
    if missing:
        pytest.skip(
            "{0} not installed; the plugin must remain usable without it".format(
                ", ".join(missing)
            )
        )


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    """An empty workspace with a ``cases/`` directory in it."""
    (tmp_path / "cases").mkdir()
    return tmp_path


# ---------------------------------------------------------------------------
# The documented invocation, against the real cases
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def real_combined_run() -> "subprocess.CompletedProcess[str]":
    """``--cases benchmark/cases --mode combined``, run once for this module.

    Both external tools are required. A run missing one measures a review with a
    Source that never ran, and its missed expectations would say nothing about
    the review's quality.
    """
    skip_unless_available(EXTERNAL_TOOLS)
    return run_harness(["--cases", REAL_CASES, "--mode", "combined"], PLUGIN_ROOT)


def test_the_documented_invocation_exits_zero_with_every_category_passing(
    real_combined_run: "subprocess.CompletedProcess[str]",
) -> None:
    """Task 21.6's completion condition, and what CI runs to catch a regression."""
    summary = summary_of(real_combined_run)

    assert summary["errors"] == [], real_combined_run.stderr
    assert summary["status"] == metrics.STATUS_PASS, real_combined_run.stderr
    failed = {
        name: entry
        for name, entry in summary["categories"].items()
        if entry["status"] == metrics.STATUS_FAIL
    }
    assert failed == {}, real_combined_run.stderr
    assert real_combined_run.returncode == exitcodes.OK, real_combined_run.stderr


def test_the_summary_has_the_documented_structure(
    real_combined_run: "subprocess.CompletedProcess[str]",
) -> None:
    """Every key the harness declares, and no key it does not."""
    summary = summary_of(real_combined_run)

    assert sorted(summary) == sorted(run_benchmark.SUMMARY_KEYS)
    assert summary["schema_version"] == run_benchmark.SCHEMA_VERSION
    assert summary["mode"] == "combined"
    assert summary["sources_evaluated"] == list(run_benchmark.ALL_SOURCES)
    assert summary["agent_findings_supplied"] is False
    # The default path: every Source disabling is applied at review time.
    assert summary["filter_only"] is False
    assert sorted(summary["metrics"]) == sorted(metrics.METRIC_KEYS)
    for name, entry in summary["categories"].items():
        assert sorted(entry) == sorted(metrics.CATEGORY_KEYS), name


def test_every_case_is_reported_once_in_sorted_order(
    real_combined_run: "subprocess.CompletedProcess[str]",
) -> None:
    """Discovered from the filesystem, so a case added later is measured."""
    summary = summary_of(real_combined_run)
    case_ids = [entry["case_id"] for entry in summary["cases"]]
    on_disk = sorted(
        path.name
        for path in (PLUGIN_ROOT / "benchmark" / "cases").iterdir()
        if (path / "ground_truth.json").is_file()
    )

    assert case_ids == on_disk
    assert case_ids == sorted(case_ids)
    for entry in summary["cases"]:
        assert sorted(entry) == sorted(run_benchmark.CASE_KEYS)
        assert entry["evaluated"] is True, entry
        assert entry["reason"] is None
        assert entry["template"] == "template.yaml"


def test_the_aggregate_is_the_sum_of_the_cases(
    real_combined_run: "subprocess.CompletedProcess[str]",
) -> None:
    """Namespacing per case makes pooling exact rather than approximate.

    Without it, two cases sharing a logical ID in one category would cross-match
    and the totals would drift from the per-case numbers -- in the direction that
    hides a missed expectation.
    """
    summary = summary_of(real_combined_run)
    evaluated = [entry for entry in summary["cases"] if entry["evaluated"]]

    for key in (
        "expected_count",
        "actual_count",
        "matched_count",
        "false_negative_count",
        "false_positive_count",
    ):
        assert summary["metrics"][key] == sum(
            entry["metrics"][key] for entry in evaluated
        ), key


def test_stdout_carries_no_absolute_path_and_no_host_detail(
    real_combined_run: "subprocess.CompletedProcess[str]",
) -> None:
    """Requirement 16 AC11, on the two values most likely to leak.

    The plugin root appears in every path the harness touches, and the working
    directory is the workspace root, so either one showing up in stdout would
    mean a resolved path reached the output.
    """
    stdout = real_combined_run.stdout

    assert str(PLUGIN_ROOT) not in stdout
    assert os.path.expanduser("~") not in stdout


# ---------------------------------------------------------------------------
# The four modes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", sorted(run_benchmark.MODE_NAMES))
def test_every_mode_runs_and_reports_the_sources_it_measured(
    workspace: Path, mode: str
) -> None:
    """All four modes of design.md's Source subset table execute.

    A single-Source mode also *disables* the other Sources at review time, so the
    mode has to name its Source the way the orchestrator's ``--sources`` spells
    it. A mode whose spelling were wrong would fail argument validation in the
    child and show up here as an unevaluated case.
    """
    if mode in EXTERNAL_TOOL_BY_MODE:
        skip_unless_available([EXTERNAL_TOOL_BY_MODE[mode]])
    write_case(workspace, "case-001-wildcard", expectations=[expectation()])

    completed = run_harness(["--cases", "cases", "--mode", mode], workspace)
    summary = summary_of(completed)

    assert summary["errors"] == [], completed.stderr
    assert case_entry(summary, "case-001-wildcard")["evaluated"] is True
    assert summary["mode"] == mode
    assert summary["sources_evaluated"] == list(
        run_benchmark.MODES[mode].sources_evaluated
    )
    assert completed.returncode == exitcodes.OK, completed.stderr


def test_a_single_source_mode_evaluates_only_what_that_source_should_find(
    workspace: Path,
) -> None:
    """Requirement 11 AC10, AC11: both sides are filtered, by Source.

    The case declares one expectation attributed to ``IAM Review`` and one
    attributed to ``cfn-guard``. Measured as ``iam-only``, only the first is
    evaluated -- cfn-guard is not blamed for it, and the IAM detectors are not
    blamed for cfn-guard's.
    """
    write_case(
        workspace,
        "case-001-wildcard",
        expectations=[
            expectation(resource="AdminPolicy", detected_by=("IAM Review",)),
            expectation(
                resource="AbsentBucket",
                normalized_category="Encryption",
                severity="HIGH",
                detected_by=("cfn-guard",),
            ),
        ],
    )

    completed = run_harness(["--cases", "cases", "--mode", "iam-only"], workspace)
    summary = summary_of(completed)
    entry = case_entry(summary, "case-001-wildcard")

    assert entry["metrics"]["expected_count"] == 1
    assert entry["metrics"]["matched_count"] == 1
    assert entry["status"] == metrics.STATUS_PASS
    assert list(entry["categories"]) == ["IAM"]
    assert completed.returncode == exitcodes.OK, completed.stderr


# ---------------------------------------------------------------------------
# --filter-only: the same numbers, obtained the other way
# ---------------------------------------------------------------------------
#
# Task 21.7's completion condition. A single-Source mode can disable the other
# Sources at review time or let them run and filter the result, and the two must
# measure the same thing -- if they disagree, one of them is wrong about what that
# Source contributes, which is a fact about the pipeline and not about the harness.
# Measured over the real cases, because a synthetic case measures what the test
# wrote rather than what the review does.


@functools.lru_cache(maxsize=None)
def real_run(mode: str, filter_only: bool) -> "subprocess.CompletedProcess[str]":
    """One run over ``benchmark/cases``, cached for this module.

    Both external tools are required on either path. The filtered path reviews with
    every Source enabled, so a run missing one measures a different review than the
    default path does, and the comparison would be between two different things.
    """
    skip_unless_available(EXTERNAL_TOOLS)
    arguments = ["--cases", REAL_CASES, "--mode", mode]
    if filter_only:
        arguments.append("--filter-only")
    return run_harness(arguments, PLUGIN_ROOT)


@pytest.mark.parametrize("mode", ["cfn-guard-only", "cfn-lint-only", "iam-only"])
def test_disabling_a_source_and_filtering_for_it_measure_the_same_thing(
    mode: str,
) -> None:
    """Requirement 11 AC10, as a measurement rather than an assumption.

    A Finding keeps every Source that reached it, so filtering a combined report to
    one Source recovers that Source's Findings. The comparison is over the whole
    document, which pins the pooled metrics, every category, every per-case number
    and the verdict at once; ``filter_only`` is the one key that is allowed to
    differ, and it is the key that records which path ran.

    ``cfn-guard-only`` is the mode carrying the weight here: the test below shows it
    measures a non-empty expectation set, so the equality is not two rows of zeroes.
    """
    default = real_run(mode, False)
    filtered = real_run(mode, True)

    first = summary_of(default)
    second = summary_of(filtered)

    assert first["filter_only"] is False
    assert second["filter_only"] is True
    assert dict(first, filter_only=True) == second, filtered.stderr
    assert default.returncode == filtered.returncode == exitcodes.OK, filtered.stderr


def test_the_equivalence_is_measured_over_a_non_empty_expectation_set() -> None:
    """Guards the test above from passing on nothing.

    ``cfn-guard`` is attributed the majority of the benchmark's expectations, so if
    its filtered measurement were empty -- the shape an absent tool produces -- the
    equality would still hold and mean nothing.
    """
    summary = summary_of(real_run("cfn-guard-only", True))

    assert summary["metrics"]["expected_count"] > 0
    assert summary["metrics"]["matched_count"] > 0
    assert summary["status"] == metrics.STATUS_PASS


def test_filter_only_is_accepted_and_redundant_for_combined(workspace: Path) -> None:
    """Accepted rather than refused, because the flag is what a mode sweep uses.

    ``combined`` enables every Source on either path, so the flag changes nothing
    for it. Rejecting it would force a caller looping over the modes to special-case
    one of them, which is exactly the loop the flag exists for. ``--verbose`` says it
    changed nothing.
    """
    write_case(workspace, "case-001-wildcard", expectations=[expectation()])

    default = run_harness(["--cases", "cases", "--mode", "combined"], workspace)
    filtered = run_harness(
        ["--cases", "cases", "--mode", "combined", "--filter-only", "--verbose"],
        workspace,
    )

    assert dict(summary_of(default), filter_only=True) == summary_of(filtered)
    assert default.returncode == filtered.returncode == exitcodes.OK, filtered.stderr
    assert "--filter-only changes nothing" in filtered.stderr


def test_the_summary_records_which_path_produced_it(workspace: Path) -> None:
    """A stored single-Source summary cannot be read without knowing the path.

    The filtered path can report an empty measurement where an external tool was
    absent; the default path reports that same situation as an unevaluated case. The
    numbers alone do not distinguish them.
    """
    write_case(workspace, "case-001-wildcard", expectations=[expectation()])

    default = run_harness(["--cases", "cases", "--mode", "iam-only"], workspace)
    filtered = run_harness(
        ["--cases", "cases", "--mode", "iam-only", "--filter-only"], workspace
    )

    assert summary_of(default)["filter_only"] is False
    assert summary_of(filtered)["filter_only"] is True
    assert sorted(summary_of(filtered)) == sorted(run_benchmark.SUMMARY_KEYS)


def test_filter_only_on_an_unevaluated_case_still_reports_the_flag(
    workspace: Path,
) -> None:
    """The key is present in every run, like every other key of the summary."""
    write_case(workspace, "case-001-broken", ground_truth_text="{")

    completed = run_harness(
        ["--cases", "cases", "--mode", "iam-only", "--filter-only"], workspace
    )
    summary = summary_of(completed)

    assert summary["filter_only"] is True
    assert summary["errors"] == [
        {
            "case_id": "case-001-broken",
            "reason": run_benchmark.MALFORMED_GROUND_TRUTH,
        }
    ]
    assert completed.returncode == run_benchmark.CASE_NOT_EVALUATED, completed.stderr


def without_external_tools() -> Dict[str, str]:
    """The inherited environment with an empty ``PATH``.

    Makes cfn-lint and cfn-guard unreachable whatever the host has installed, so the
    test below asserts the same thing on a developer machine and in CI. Nothing else
    in the run needs ``PATH``: the harness starts the review with
    ``sys.executable``.
    """
    env = dict(os.environ)
    env["PATH"] = ""
    return env


def test_an_absent_tool_reads_differently_on_the_two_paths(workspace: Path) -> None:
    """The one place the two paths are not interchangeable, end to end.

    A case expecting one cfn-guard finding, measured as ``cfn-guard-only`` with
    cfn-guard unreachable:

    * the default path disables the other Sources, so the review has nothing left to
      run, fails, and the case is recorded unevaluated -- exit 10, the code for an
      incomplete run, and the reason names the environment;
    * ``--filter-only`` gets a combined review that succeeded on the IAM Source and
      filters it to cfn-guard, which yields nothing -- exit 9, the code for a
      regression, for a case that never had a chance.

    The numbers cannot tell those apart, so the harness says which it is on stderr.
    """
    write_case(
        workspace,
        "case-001-guard",
        expectations=[
            expectation(
                resource="AdminPolicy",
                normalized_category="Encryption",
                severity="HIGH",
                detected_by=("cfn-guard",),
            )
        ],
    )
    env = without_external_tools()

    default = run_harness(
        ["--cases", "cases", "--mode", "cfn-guard-only"], workspace, env
    )
    filtered = run_harness(
        ["--cases", "cases", "--mode", "cfn-guard-only", "--filter-only"],
        workspace,
        env,
    )

    assert default.returncode == run_benchmark.CASE_NOT_EVALUATED, default.stderr
    assert summary_of(default)["errors"] == [
        {"case_id": "case-001-guard", "reason": run_benchmark.REVIEW_FAILED}
    ]

    assert filtered.returncode == run_benchmark.BENCHMARK_FAILURE, filtered.stderr
    assert summary_of(filtered)["errors"] == []
    assert summary_of(filtered)["status"] == metrics.STATUS_FAIL
    assert "--filter-only measured cfn-guard" in filtered.stderr
    assert "not a regression" in filtered.stderr
    # stderr only: which tools the host installed is not part of what is measured.
    assert "cfn-guard" not in json.dumps(summary_of(filtered)["errors"])


def test_the_benchmark_readme_documents_the_flag_and_the_field() -> None:
    """The runner's only user-facing documentation, kept from drifting from it."""
    readme = (PLUGIN_ROOT / "benchmark" / "README.md").read_text(encoding="utf-8")

    assert "--filter-only" in readme
    assert "filter_only" in readme


def test_an_unknown_mode_is_rejected(workspace: Path) -> None:
    completed = run_harness(["--cases", "cases", "--mode", "everything"], workspace)

    assert completed.returncode == exitcodes.INVALID_ARGUMENTS
    assert completed.stdout == ""


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("extra", [[], ["--filter-only"]], ids=["default", "filtered"])
def test_two_runs_over_the_same_cases_are_byte_identical(
    workspace: Path, extra: Sequence[str]
) -> None:
    """Requirement 16 AC11. A benchmark whose output drifts cannot show a change.

    Byte comparison rather than a parsed comparison: a float's last digit, a key
    order that follows insertion order, or a timing field would all survive a
    comparison of parsed documents.

    Both paths, because ``--filter-only`` adds a key to the document and reviews
    with a different set of Sources. Neither is environment-dependent: the key comes
    from argv, and what the review reports about its own execution stays on stderr.
    """
    write_case(workspace, "case-001-wildcard", expectations=[expectation()])
    write_case(
        workspace,
        "case-002-quiet",
        template=QUIET_TEMPLATE,
        expectations=[],
    )
    arguments = ["--cases", "cases", "--mode", "iam-only", *extra]

    first = run_harness(arguments, workspace)
    second = run_harness(arguments, workspace)

    assert first.stdout == second.stdout
    assert first.returncode == second.returncode == exitcodes.OK, first.stderr


def test_verbose_does_not_change_stdout(workspace: Path) -> None:
    """``--verbose`` widens stderr only, so a diagnostic cannot alter a number."""
    write_case(workspace, "case-001-wildcard", expectations=[expectation()])

    quiet = run_harness(["--cases", "cases", "--mode", "iam-only"], workspace)
    verbose = run_harness(
        ["--cases", "cases", "--mode", "iam-only", "--verbose"], workspace
    )

    assert quiet.stdout == verbose.stdout
    assert len(verbose.stderr) > len(quiet.stderr)


def test_stdout_is_json_and_stderr_is_prose(workspace: Path) -> None:
    """Requirement 16 AC10, with a case that has something to warn about."""
    write_case(workspace, "case-001-wildcard", expectations=[expectation()])
    write_case(workspace, "case-002-broken", ground_truth_text="{")

    completed = run_harness(
        ["--cases", "cases", "--mode", "iam-only", "--verbose"], workspace
    )

    json.loads(completed.stdout)
    assert "warning" in completed.stderr
    assert not completed.stderr.lstrip().startswith("{")


# ---------------------------------------------------------------------------
# The pass/fail rule, end to end
# ---------------------------------------------------------------------------


def test_a_missed_deterministic_expectation_exits_non_zero(workspace: Path) -> None:
    """Requirement 11 AC7, and the reason CI runs this at all.

    The case expects a ``Backup`` finding on a resource the template does not even
    have, classed ``deterministic``. Nothing can detect it, so the category fails
    and the process exits :data:`run_benchmark.BENCHMARK_FAILURE`.
    """
    write_case(
        workspace,
        "case-001-missed",
        expectations=[
            expectation(),
            expectation(
                resource="AbsentTable",
                normalized_category="Backup",
                severity="MEDIUM",
            ),
        ],
    )

    completed = run_harness(["--cases", "cases", "--mode", "iam-only"], workspace)
    summary = summary_of(completed)
    entry = case_entry(summary, "case-001-missed")

    assert entry["categories"]["Backup"]["status"] == metrics.STATUS_FAIL
    assert entry["categories"]["Backup"]["deterministic_detection_rate"] == "0.0"
    assert entry["categories"]["IAM"]["status"] == metrics.STATUS_PASS
    assert entry["status"] == metrics.STATUS_FAIL
    assert summary["status"] == metrics.STATUS_FAIL
    assert completed.returncode == run_benchmark.BENCHMARK_FAILURE, completed.stderr


def test_a_missed_agent_dependent_expectation_does_not_fail_the_run(
    workspace: Path,
) -> None:
    """Requirement 11 AC8: measured, with no threshold applied.

    Agent findings are never generated during a run, so an ``agent-dependent``
    expectation with no fixture behind it is always undetected. Failing on it
    would make every CI run red.
    """
    write_case(
        workspace,
        "case-001-agent",
        expectations=[
            expectation(
                resource="AdminPolicy",
                normalized_category="TemplateQuality",
                finding_type="BestPractice",
                severity="MEDIUM",
                detection_class=metrics.AGENT_DEPENDENT,
                detected_by=("Agent Review",),
            )
        ],
    )

    completed = run_harness(["--cases", "cases", "--mode", "combined"], workspace)
    summary = summary_of(completed)
    entry = case_entry(summary, "case-001-agent")
    category = entry["categories"]["TemplateQuality"]

    assert category["detection_rate"] == "0.0"
    assert category["deterministic_expected_count"] == 0
    assert category["deterministic_detection_rate"] == metrics.NOT_APPLICABLE
    assert category["status"] == metrics.STATUS_INFO
    assert entry["status"] == metrics.STATUS_INFO
    assert completed.returncode == exitcodes.OK, completed.stderr


def test_a_deterministic_expectation_still_decides_a_mixed_case(
    workspace: Path,
) -> None:
    """One category held to the threshold, one not, in the same case.

    Measured as ``combined``, so both expectations are in scope: a single-Source
    mode would filter the agent-attributed one out, which is the subject of the
    filtering test above rather than of this one.
    """
    write_case(
        workspace,
        "case-001-mixed",
        expectations=[
            expectation(),
            expectation(
                resource="AdminPolicy",
                normalized_category="TemplateQuality",
                finding_type="BestPractice",
                severity="LOW",
                detection_class=metrics.AGENT_DEPENDENT,
                detected_by=("Agent Review",),
            ),
        ],
    )

    completed = run_harness(["--cases", "cases", "--mode", "combined"], workspace)
    entry = case_entry(summary_of(completed), "case-001-mixed")

    assert entry["categories"]["IAM"]["status"] == metrics.STATUS_PASS
    assert entry["categories"]["TemplateQuality"]["status"] == metrics.STATUS_INFO
    assert entry["status"] == metrics.STATUS_PASS
    assert completed.returncode == exitcodes.OK, completed.stderr


# ---------------------------------------------------------------------------
# Agent findings arrive as a fixture, never generated
# ---------------------------------------------------------------------------


def agent_finding(
    resource: str = "AdminPolicy",
    normalized_category: str = "TemplateQuality",
    template: str = "cases/case-001-agent/template.yaml",
) -> Dict[str, Any]:
    """One agent finding, in the shape ``--agent-findings`` accepts."""
    return {
        "Normalized_Category": normalized_category,
        "FindingType": "BestPractice",
        "Severity": "MEDIUM",
        "Confidence": "Likely",
        "Source": ["Agent Review"],
        "Resource": resource,
        "Location": {
            "File": template,
            "Line": None,
            "Column": None,
            "TemplatePath": ["Resources", resource],
        },
        "Finding": "The policy grants more than the stack appears to need.",
        "WhyItMatters": "Excess permissions widen the blast radius of a compromise.",
        "Evidence": [
            {
                "Source": "Agent Review",
                "Detail": "No resource in the template requires every action.",
                "RuleId": None,
                "Excerpt": 'Action: "*"',
            }
        ],
        "Recommendation": "Scope the policy to the actions the stack uses.",
        "SuggestedRemediation": None,
    }


def test_an_agent_dependent_expectation_is_met_by_a_fixture(workspace: Path) -> None:
    """The only way agent findings enter a benchmark run.

    Generating them during the run would make the harness non-deterministic, so
    they are supplied as a fixed file per case. With the fixture in place the
    expectation is detected; without it, the previous test shows it is reported as
    undetected and not failed.
    """
    write_case(
        workspace,
        "case-001-agent",
        expectations=[
            expectation(
                resource="AdminPolicy",
                normalized_category="TemplateQuality",
                finding_type="BestPractice",
                severity="MEDIUM",
                detection_class=metrics.AGENT_DEPENDENT,
                detected_by=("Agent Review",),
            )
        ],
    )
    fixtures = workspace / "agent"
    fixtures.mkdir()
    (fixtures / "case-001-agent.json").write_text(
        json.dumps([agent_finding()]), encoding="utf-8"
    )

    completed = run_harness(
        [
            "--cases",
            "cases",
            "--mode",
            "combined",
            "--agent-findings",
            "agent",
        ],
        workspace,
    )
    summary = summary_of(completed)
    category = case_entry(summary, "case-001-agent")["categories"]["TemplateQuality"]

    assert summary["agent_findings_supplied"] is True
    assert category["matched_count"] == 1
    assert category["detection_rate"] == "100.0"
    assert category["severity_accuracy"] == "100.0"
    assert completed.returncode == exitcodes.OK, completed.stderr


def test_a_case_with_no_fixture_is_still_evaluated(workspace: Path) -> None:
    """An agent fixture directory need not hold a file for every case."""
    write_case(workspace, "case-001-wildcard", expectations=[expectation()])
    (workspace / "agent").mkdir()

    completed = run_harness(
        ["--cases", "cases", "--mode", "iam-only", "--agent-findings", "agent"],
        workspace,
    )
    summary = summary_of(completed)

    assert summary["agent_findings_supplied"] is True
    assert case_entry(summary, "case-001-wildcard")["evaluated"] is True
    assert completed.returncode == exitcodes.OK, completed.stderr


# ---------------------------------------------------------------------------
# A broken case is one skipped case
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "case_kwargs,reason",
    [
        ({"ground_truth_text": "{ truncated"}, run_benchmark.MALFORMED_GROUND_TRUTH),
        ({"ground_truth_text": "[]"}, run_benchmark.MALFORMED_GROUND_TRUTH),
        (
            {"ground_truth_text": json.dumps({"template": "template.yaml"})},
            run_benchmark.MALFORMED_GROUND_TRUTH,
        ),
        ({"template": None}, run_benchmark.MISSING_TEMPLATE),
    ],
)
def test_a_broken_case_is_recorded_and_the_others_are_still_measured(
    workspace: Path, case_kwargs: Dict[str, Any], reason: str
) -> None:
    """Untrusted input, safe failure: the run continues and says what it skipped.

    Aborting on the first broken case would make one bad file hide the state of
    every other case, which is the opposite of what a benchmark is for.
    """
    write_case(workspace, "case-001-good", expectations=[expectation()])
    write_case(workspace, "case-002-broken", **case_kwargs)

    completed = run_harness(["--cases", "cases", "--mode", "iam-only"], workspace)
    summary = summary_of(completed)

    assert summary["errors"] == [{"case_id": "case-002-broken", "reason": reason}]
    broken = case_entry(summary, "case-002-broken")
    assert broken["evaluated"] is False
    assert broken["reason"] == reason
    assert broken["metrics"] is None
    assert broken["status"] is None
    # The good case is measured all the same.
    assert case_entry(summary, "case-001-good")["status"] == metrics.STATUS_PASS
    # Incomplete rather than failed: nothing measured regressed.
    assert summary["status"] == metrics.STATUS_PASS
    assert completed.returncode == run_benchmark.CASE_NOT_EVALUATED, completed.stderr


def test_a_ground_truth_naming_a_template_outside_its_case_is_refused(
    workspace: Path,
) -> None:
    """Path traversal through the one field that names a file.

    The template a case names is untrusted input. A ``..`` in it is rejected as a
    malformed case, and the file it pointed at is never read.
    """
    secret = workspace / "outside.yaml"
    secret.write_text(QUIET_TEMPLATE, encoding="utf-8")
    write_case(
        workspace,
        "case-001-traversal",
        ground_truth_text=json.dumps(
            {
                "schema_version": "1.0.0",
                "case_id": "case-001-traversal",
                "template": "../../outside.yaml",
                "description": "Names a file outside its own directory.",
                "authored_before_review": True,
                "expected_finding_count": 0,
                "expected_findings": [],
                "expected_findings_agent_only": [],
                "expected_findings_human_review": [],
            }
        ),
    )

    completed = run_harness(["--cases", "cases", "--mode", "iam-only"], workspace)
    summary = summary_of(completed)

    assert summary["errors"] == [
        {
            "case_id": "case-001-traversal",
            "reason": run_benchmark.MALFORMED_GROUND_TRUTH,
        }
    ]
    assert "outside.yaml" not in completed.stdout
    assert completed.returncode == run_benchmark.CASE_NOT_EVALUATED


def test_a_directory_that_is_not_a_case_is_ignored(workspace: Path) -> None:
    """A partially created case, or a directory of shared fixtures."""
    write_case(workspace, "case-001-good", expectations=[expectation()])
    (workspace / "cases" / "notes").mkdir()
    (workspace / "cases" / "notes" / "README.md").write_text("", encoding="utf-8")

    completed = run_harness(
        ["--cases", "cases", "--mode", "iam-only", "--verbose"], workspace
    )
    summary = summary_of(completed)

    assert [entry["case_id"] for entry in summary["cases"]] == ["case-001-good"]
    assert summary["errors"] == []
    assert "notes" in completed.stderr
    assert completed.returncode == exitcodes.OK, completed.stderr


def test_an_empty_cases_directory_measures_nothing_and_succeeds(
    workspace: Path,
) -> None:
    """Nothing to measure is not a failure: it is a directory with no cases yet."""
    completed = run_harness(["--cases", "cases"], workspace)
    summary = summary_of(completed)

    assert summary["cases"] == []
    assert summary["metrics"]["detection_rate"] == metrics.NOT_APPLICABLE
    assert summary["status"] == metrics.STATUS_INFO
    assert completed.returncode == exitcodes.OK, completed.stderr


# ---------------------------------------------------------------------------
# Argument validation (Requirement 16 AC7, AC8)
# ---------------------------------------------------------------------------


def test_cases_pointing_outside_the_workspace_is_refused(workspace: Path) -> None:
    """The containment rule, on the one path the harness walks.

    ``--cases`` decides which files are read, so a value escaping the working
    directory is refused before anything is read -- exit 7, and stdout stays
    empty because no measurement happened.
    """
    outside = workspace.parent / "outside-cases"
    (outside / "case-001-x").mkdir(parents=True, exist_ok=True)
    (outside / "case-001-x" / "ground_truth.json").write_text("{}", encoding="utf-8")

    completed = run_harness(["--cases", str(outside)], workspace)

    assert completed.returncode == exitcodes.PATH_VIOLATION, completed.stderr
    assert completed.stdout == ""
    assert "path" in completed.stderr.lower()


def test_cases_reaching_outside_through_a_parent_reference_is_refused(
    workspace: Path,
) -> None:
    completed = run_harness(["--cases", "../.."], workspace)

    assert completed.returncode == exitcodes.PATH_VIOLATION, completed.stderr
    assert completed.stdout == ""


def test_a_cases_path_carrying_a_shell_metacharacter_is_refused(
    workspace: Path,
) -> None:
    """Requirement 16 AC6: no user value is ever joined into a command string."""
    completed = run_harness(["--cases", "cases; rm -rf /"], workspace)

    assert completed.returncode == exitcodes.INVALID_ARGUMENTS, completed.stderr
    assert completed.stdout == ""


def test_an_absent_cases_directory_is_reported_as_input_not_found(
    workspace: Path,
) -> None:
    completed = run_harness(["--cases", "absent"], workspace)

    assert completed.returncode == exitcodes.INPUT_NOT_FOUND, completed.stderr
    assert completed.stdout == ""


def test_a_cases_path_that_is_a_file_is_an_argument_error(workspace: Path) -> None:
    (workspace / "cases.json").write_text("{}", encoding="utf-8")

    completed = run_harness(["--cases", "cases.json"], workspace)

    assert completed.returncode == exitcodes.INVALID_ARGUMENTS, completed.stderr
    assert completed.stdout == ""


def test_an_agent_findings_path_that_is_a_file_is_an_argument_error(
    workspace: Path,
) -> None:
    (workspace / "agent.json").write_text("[]", encoding="utf-8")

    completed = run_harness(
        ["--cases", "cases", "--agent-findings", "agent.json"], workspace
    )

    assert completed.returncode == exitcodes.INVALID_ARGUMENTS, completed.stderr
    assert completed.stdout == ""


def test_cases_is_required(workspace: Path) -> None:
    completed = run_harness([], workspace)

    assert completed.returncode == exitcodes.INVALID_ARGUMENTS
    assert completed.stdout == ""
    assert "--cases" in completed.stderr


def test_an_unknown_flag_is_refused(workspace: Path) -> None:
    completed = run_harness(["--cases", "cases", "--threshold", "80"], workspace)

    assert completed.returncode == exitcodes.INVALID_ARGUMENTS
    assert completed.stdout == ""


def test_help_goes_to_stderr_and_leaves_stdout_clean(workspace: Path) -> None:
    """stdout is a machine-readable channel; usage text is not part of it."""
    completed = run_harness(["--help"], workspace)

    assert completed.returncode == exitcodes.OK
    assert completed.stdout == ""
    assert "--cases" in completed.stderr


# ---------------------------------------------------------------------------
# main() in process
# ---------------------------------------------------------------------------
#
# The same runs again, in this process rather than a child. Two reasons: the exit
# code is read as a return value rather than inferred from a process status, and
# the harness's own code is visible to coverage, which cannot follow a subprocess.
# ``main`` returns instead of raising SystemExit precisely so this is possible.


def call_main(
    arguments: Sequence[str], workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> int:
    """Run ``main`` in this process, with ``workspace`` as the working directory."""
    monkeypatch.chdir(workspace)
    return run_benchmark.main(list(arguments))


def test_main_returns_ok_and_prints_the_summary(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    write_case(workspace, "case-001-good", expectations=[expectation()])

    code = call_main(["--cases", "cases", "--mode", "iam-only"], workspace, monkeypatch)
    captured = capsys.readouterr()

    assert code == exitcodes.OK, captured.err
    assert json.loads(captured.out)["status"] == metrics.STATUS_PASS


def test_main_returns_the_regression_code_for_a_missed_expectation(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    write_case(
        workspace,
        "case-001-missed",
        expectations=[expectation(resource="AbsentPolicy")],
    )

    code = call_main(["--cases", "cases", "--mode", "iam-only"], workspace, monkeypatch)
    captured = capsys.readouterr()

    assert code == run_benchmark.BENCHMARK_FAILURE, captured.err
    assert json.loads(captured.out)["status"] == metrics.STATUS_FAIL


def test_main_returns_the_incomplete_code_when_a_case_was_skipped(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    write_case(workspace, "case-001-good", expectations=[expectation()])
    write_case(workspace, "case-002-broken", ground_truth_text="not json")
    # A directory that is not a case at all: named on stderr under --verbose, and
    # not an error, because it may be a partially created case or shared fixtures.
    (workspace / "cases" / "scratch").mkdir()

    code = call_main(
        ["--cases", "cases", "--mode", "iam-only", "--verbose"], workspace, monkeypatch
    )
    captured = capsys.readouterr()

    assert code == run_benchmark.CASE_NOT_EVALUATED, captured.err
    assert "scratch" in captured.err
    assert json.loads(captured.out)["errors"] == [
        {
            "case_id": "case-002-broken",
            "reason": run_benchmark.MALFORMED_GROUND_TRUTH,
        }
    ]


def test_main_reports_an_expectation_missing_a_comparison_field(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """An expectation the comparison cannot read is a malformed case, not a miss.

    ``ground_truth.schema.json`` forbids it and ``tests/unit/test_ground_truth.py``
    enforces the schema, so reaching this means the case was never validated. It
    still must not take the run down.
    """
    entry = expectation()
    del entry["normalized_category"]
    write_case(workspace, "case-001-nocategory", expectations=[entry])

    code = call_main(["--cases", "cases", "--mode", "iam-only"], workspace, monkeypatch)
    captured = capsys.readouterr()

    assert code == run_benchmark.CASE_NOT_EVALUATED, captured.err
    assert json.loads(captured.out)["errors"] == [
        {
            "case_id": "case-001-nocategory",
            "reason": run_benchmark.MALFORMED_GROUND_TRUTH,
        }
    ]


def test_main_ignores_a_case_directory_symlinked_out_of_the_cases_tree(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """A case directory that is not really in the benchmark tree is refused.

    The template field cannot express this: the escape happens one level above the
    file it names. Recorded against the case rather than aborting, so the rest of
    the tree is still measured.
    """
    write_case(workspace, "case-001-good", expectations=[expectation()])
    elsewhere = workspace / "elsewhere" / "case-002-outside"
    elsewhere.mkdir(parents=True)
    (elsewhere / "template.yaml").write_text(WILDCARD_TEMPLATE, encoding="utf-8")
    (elsewhere / "ground_truth.json").write_text("{}", encoding="utf-8")
    (workspace / "cases" / "case-002-outside").symlink_to(
        elsewhere, target_is_directory=True
    )

    code = call_main(["--cases", "cases", "--mode", "iam-only"], workspace, monkeypatch)
    captured = capsys.readouterr()

    assert code == run_benchmark.CASE_NOT_EVALUATED, captured.err
    assert json.loads(captured.out)["errors"] == [
        {"case_id": "case-002-outside", "reason": run_benchmark.UNSAFE_CASE_PATH}
    ]


def test_main_uses_the_agent_fixture_of_the_matching_case_only(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """One fixture per case, named after it. A case without one is unaffected."""
    write_case(workspace, "case-001-agent", expectations=[expectation()])
    write_case(workspace, "case-002-quiet", template=QUIET_TEMPLATE)
    fixtures = workspace / "agent"
    fixtures.mkdir()
    (fixtures / "case-001-agent.json").write_text("[]", encoding="utf-8")

    code = call_main(
        [
            "--cases",
            "cases",
            "--mode",
            "iam-only",
            "--agent-findings",
            "agent",
            "--verbose",
        ],
        workspace,
        monkeypatch,
    )
    captured = capsys.readouterr()
    summary = json.loads(captured.out)

    assert code == exitcodes.OK, captured.err
    assert summary["agent_findings_supplied"] is True
    assert all(entry["evaluated"] for entry in summary["cases"])


@pytest.mark.parametrize(
    "arguments,code",
    [
        (["--cases", "absent"], exitcodes.INPUT_NOT_FOUND),
        (["--cases", "cases.json"], exitcodes.INVALID_ARGUMENTS),
        (["--cases", "cases", "--agent-findings", "cases.json"], exitcodes.INVALID_ARGUMENTS),
        (["--cases", "cases; ls"], exitcodes.INVALID_ARGUMENTS),
        (["--cases", "../.."], exitcodes.PATH_VIOLATION),
        ([], exitcodes.INVALID_ARGUMENTS),
        (["--help"], exitcodes.OK),
    ],
)
def test_main_returns_the_documented_code_for_a_rejected_invocation(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    arguments: Sequence[str],
    code: int,
) -> None:
    """Requirement 16 AC7, AC8, and no benchmark verdict for a run that never ran.

    ``--help`` is in the table for that last reason: it returns 0 without
    measuring anything, and must not be given a PASS or a FAIL.
    """
    (workspace / "cases.json").write_text("{}", encoding="utf-8")

    returned = call_main(arguments, workspace, monkeypatch)
    captured = capsys.readouterr()

    assert returned == code, captured.err
    assert captured.out == ""


def test_the_harness_does_not_read_stdin(workspace: Path) -> None:
    """Requirement 16 AC9: non-interactive, so a closed stdin changes nothing."""
    write_case(workspace, "case-001-good", expectations=[expectation()])

    completed = subprocess.run(
        [sys.executable, str(HARNESS), "--cases", "cases", "--mode", "iam-only"],
        cwd=str(workspace),
        env=dict(os.environ),
        input="",
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
    )

    assert completed.returncode == exitcodes.OK, completed.stderr
    assert json.loads(completed.stdout)["status"] == metrics.STATUS_PASS


# ---------------------------------------------------------------------------
# v0.8.0: diagnostics, the new modes, and --agent-runs (Requirement 19)
# ---------------------------------------------------------------------------


def test_the_summary_carries_a_diagnostics_block(workspace: Path) -> None:
    """Requirement 19 AC3: diagnostics appear per case and in aggregate."""
    write_case(workspace, "case-001-wildcard", expectations=[expectation()])

    completed = run_harness(["--cases", "cases", "--mode", "iam-only"], workspace)
    summary = summary_of(completed)

    assert sorted(summary["diagnostics"]) == sorted(metrics.DIAGNOSTIC_KEYS)
    entry = case_entry(summary, "case-001-wildcard")
    assert sorted(entry["diagnostics"]) == sorted(metrics.DIAGNOSTIC_KEYS)


def test_a_case_declaring_no_diagnostic_expectation_reports_not_applicable(
    workspace: Path,
) -> None:
    """Requirement 19 AC6: N/A, not 0, and the key is always present."""
    write_case(workspace, "case-001-wildcard", expectations=[expectation()])

    completed = run_harness(["--cases", "cases", "--mode", "iam-only"], workspace)
    diagnostics = summary_of(completed)["diagnostics"]

    assert diagnostics["remediation_accuracy"] == metrics.NOT_APPLICABLE
    assert diagnostics["human_intervention_count"] == metrics.NOT_APPLICABLE


def test_human_intervention_count_aggregates_declared_values(workspace: Path) -> None:
    """A case declaring the expectation has it echoed and summed (Requirement 19 AC3)."""
    ground_truth = json.dumps(
        {
            "schema_version": "1.0.0",
            "case_id": "case-001-wildcard",
            "template": "template.yaml",
            "description": "A synthetic case declaring a human-intervention count.",
            "authored_before_review": True,
            "expected_finding_count": 1,
            "expected_findings": [expectation()],
            "expected_findings_agent_only": [],
            "expected_findings_human_review": [],
            metrics.HUMAN_INTERVENTION_EXPECTATION_FIELD: 2,
        },
        indent=2,
    )
    write_case(workspace, "case-001-wildcard", ground_truth_text=ground_truth)

    completed = run_harness(["--cases", "cases", "--mode", "iam-only"], workspace)
    summary = summary_of(completed)

    assert case_entry(summary, "case-001-wildcard")["diagnostics"][
        "human_intervention_count"
    ] == 2
    assert summary["diagnostics"]["human_intervention_count"] == 2
    # A diagnostic never changes the verdict.
    assert completed.returncode == exitcodes.OK, completed.stderr


def test_agent_only_reads_the_reserved_array_and_is_informational(
    workspace: Path,
) -> None:
    """Requirement 19 AC1: agent-only measures the reserved array, empty in v0.1.

    With an empty ``expected_findings_agent_only`` the case measures nothing and
    reports INFO, and the run exits 0: the deterministic expectations are not
    pulled in, so a wildcard IAM defect the review would flag does not make this
    mode fail.
    """
    write_case(workspace, "case-001-wildcard", expectations=[expectation()])

    completed = run_harness(["--cases", "cases", "--mode", "agent-only"], workspace)
    summary = summary_of(completed)

    assert summary["mode"] == "agent-only"
    assert summary["sources_evaluated"] == ["Agent Review"]
    assert case_entry(summary, "case-001-wildcard")["status"] == metrics.STATUS_INFO
    assert completed.returncode == exitcodes.OK, completed.stderr


def test_human_review_never_fails_even_when_it_declares_expectations(
    workspace: Path,
) -> None:
    """Requirement 19 AC1: human-review is informational, never thresholded.

    Its reserved array names a deterministic expectation the pipeline never
    produces here (no agent findings, no matching Source), yet the run exits 0:
    the mode is not held to a threshold, so it cannot turn a human-review
    expectation into a FAIL.
    """
    human_expectation = expectation(
        resource="ManualReviewItem",
        normalized_category="Other",
        finding_type="BestPractice",
        severity="LOW",
        detected_by=("Agent Review",),
    )
    ground_truth = json.dumps(
        {
            "schema_version": "1.0.0",
            "case_id": "case-001-wildcard",
            "template": "template.yaml",
            "description": "A synthetic case with a human-review expectation.",
            "authored_before_review": True,
            "expected_finding_count": 0,
            "expected_findings": [],
            "expected_findings_agent_only": [],
            "expected_findings_human_review": [human_expectation],
        },
        indent=2,
    )
    write_case(workspace, "case-001-wildcard", ground_truth_text=ground_truth)

    completed = run_harness(["--cases", "cases", "--mode", "human-review"], workspace)
    summary = summary_of(completed)

    assert summary["mode"] == "human-review"
    assert summary["status"] == metrics.STATUS_INFO
    assert completed.returncode == exitcodes.OK, completed.stderr


def test_review_time_is_reported_on_stderr_never_in_stdout(workspace: Path) -> None:
    """Requirement 19 AC2: Review Time is a diagnostic, kept out of the summary."""
    write_case(workspace, "case-001-wildcard", expectations=[expectation()])

    completed = run_harness(
        ["--cases", "cases", "--mode", "iam-only", "--verbose"], workspace
    )

    assert "review time" in completed.stderr
    assert "review time" not in completed.stdout
    assert "review_time" not in completed.stdout


def test_agent_runs_below_one_is_rejected(workspace: Path) -> None:
    write_case(workspace, "case-001-wildcard", expectations=[expectation()])

    completed = run_harness(
        ["--cases", "cases", "--mode", "agent-only", "--agent-runs", "0"], workspace
    )

    assert completed.returncode == exitcodes.INVALID_ARGUMENTS
    assert completed.stdout == ""


def test_the_new_modes_are_byte_identical_between_runs(workspace: Path) -> None:
    """Requirement 16 AC11 holds for the modes v0.8.0 added."""
    write_case(workspace, "case-001-wildcard", expectations=[expectation()])

    for mode in ("agent-only", "human-review"):
        first = run_harness(["--cases", "cases", "--mode", mode], workspace)
        second = run_harness(["--cases", "cases", "--mode", mode], workspace)
        assert first.stdout == second.stdout, mode


# ---------------------------------------------------------------------------
# v0.9.0: structured Review Time on stderr (Requirement 21)
# ---------------------------------------------------------------------------


def test_timing_report_emits_structured_json_on_stderr(workspace: Path) -> None:
    """Requirement 21 AC1: --timing-report writes a per-case + aggregate JSON
    document to stderr."""
    write_case(workspace, "case-001-wildcard", expectations=[expectation()])

    completed = run_harness(
        ["--cases", "cases", "--mode", "iam-only", "--timing-report"], workspace
    )
    assert completed.returncode == exitcodes.OK, completed.stderr

    # The last JSON object on stderr is the timing report.
    document = json.loads(completed.stderr.strip().splitlines()[-1])
    assert sorted(document) == sorted(run_benchmark.TIMING_KEYS)
    assert document["unit"] == "seconds"
    assert document["aggregate"]["case_count"] == len(document["cases"])
    for entry in document["cases"]:
        assert sorted(entry) == sorted(run_benchmark.TIMING_CASE_KEYS)


def test_timing_report_never_appears_on_stdout(workspace: Path) -> None:
    """Requirement 21 AC2: no timing value reaches the byte-identical summary."""
    write_case(workspace, "case-001-wildcard", expectations=[expectation()])

    completed = run_harness(
        ["--cases", "cases", "--mode", "iam-only", "--timing-report"], workspace
    )
    summary = summary_of(completed)

    assert "timing" not in summary
    assert "unit" not in summary
    assert "seconds" not in completed.stdout


def test_timing_report_does_not_change_stdout(workspace: Path) -> None:
    """Requirement 21 AC2: the summary is byte-identical with and without the flag."""
    write_case(workspace, "case-001-wildcard", expectations=[expectation()])

    without = run_harness(["--cases", "cases", "--mode", "iam-only"], workspace)
    with_flag = run_harness(
        ["--cases", "cases", "--mode", "iam-only", "--timing-report"], workspace
    )

    assert without.stdout == with_flag.stdout
    assert without.returncode == with_flag.returncode == exitcodes.OK


def test_timing_report_does_not_affect_the_verdict(workspace: Path) -> None:
    """Requirement 21 AC3: Review Time never changes PASS/FAIL."""
    write_case(workspace, "case-001-wildcard", expectations=[expectation()])

    without = summary_of(run_harness(["--cases", "cases", "--mode", "iam-only"], workspace))
    with_flag = summary_of(
        run_harness(
            ["--cases", "cases", "--mode", "iam-only", "--timing-report"], workspace
        )
    )

    assert without["status"] == with_flag["status"]


# ---------------------------------------------------------------------------
# v0.9.0: the measurement cases exercise the reserved modes and diagnostics
# (Requirement 22 AC2-AC6). Scoped to case-201 / case-202 in a tmp cases dir so
# the tests need no external tool: both templates are DynamoDB / SNS only, which
# the deterministic Sources handle in pure Python.
# ---------------------------------------------------------------------------

AGENT_ONLY_CASE = "case-201-agent-only-oversized-policy"
HUMAN_REVIEW_CASE = "case-202-human-review-naming-convention"


def _measurement_workspace(tmp_path: Path) -> Path:
    """A cases dir holding copies of the two v0.9.0 measurement cases.

    Copied rather than pointed at ``benchmark/cases`` so the run covers only
    these two -- the defect cases would need cfn-lint and cfn-guard, and these do
    not -- and so the harness contains every path inside ``tmp_path``.
    """
    source = PLUGIN_ROOT / "benchmark" / "cases"
    cases = tmp_path / "cases"
    cases.mkdir()
    for name in (AGENT_ONLY_CASE, HUMAN_REVIEW_CASE):
        shutil.copytree(source / name, cases / name)
    findings = tmp_path / "agent-findings"
    findings.mkdir()
    shutil.copy(
        PLUGIN_ROOT / "benchmark" / "agent-findings" / "{0}.json".format(AGENT_ONLY_CASE),
        findings / "{0}.json".format(AGENT_ONLY_CASE),
    )
    return tmp_path


def test_agent_only_case_measures_the_reserved_array_against_the_fixture(
    tmp_path: Path,
) -> None:
    """Requirement 22 AC2/AC6: the agent-only mode evaluates
    expected_findings_agent_only against a fixed fixture, matching the declared
    expectation."""
    workspace = _measurement_workspace(tmp_path)

    completed = run_harness(
        ["--cases", "cases", "--mode", "agent-only", "--agent-findings", "agent-findings"],
        workspace,
    )
    summary = summary_of(completed)
    entry = case_entry(summary, AGENT_ONLY_CASE)

    assert entry["evaluated"] is True
    assert entry["metrics"]["expected_count"] == 1
    assert entry["metrics"]["matched_count"] == 1
    assert entry["metrics"]["detection_rate"] == "100.0"
    assert completed.returncode == exitcodes.OK, completed.stderr


def test_agent_only_case_reports_the_remediation_and_intervention_diagnostics(
    tmp_path: Path,
) -> None:
    """Requirement 22 AC4: the declared diagnostics report a value, not N/A."""
    workspace = _measurement_workspace(tmp_path)

    completed = run_harness(
        ["--cases", "cases", "--mode", "agent-only", "--agent-findings", "agent-findings"],
        workspace,
    )
    diagnostics = case_entry(summary_of(completed), AGENT_ONLY_CASE)["diagnostics"]

    assert diagnostics["remediation_accuracy"] == "100.0"
    assert diagnostics["human_intervention_count"] == 1


def test_human_review_case_is_informational_and_never_fails(tmp_path: Path) -> None:
    """Requirement 22 AC3: a non-empty human-review array is measured but never
    thresholded."""
    workspace = _measurement_workspace(tmp_path)

    completed = run_harness(["--cases", "cases", "--mode", "human-review"], workspace)
    summary = summary_of(completed)
    entry = case_entry(summary, HUMAN_REVIEW_CASE)

    assert entry["metrics"]["expected_count"] == 1
    assert entry["status"] == metrics.STATUS_INFO
    assert summary["status"] == metrics.STATUS_INFO
    assert completed.returncode == exitcodes.OK, completed.stderr


def test_agent_runs_records_one_duration_per_run_for_the_agent_case(
    tmp_path: Path,
) -> None:
    """Requirement 21 AC4: --agent-runs N carries N per-run durations for the
    agent-only case, and the summary is unaffected."""
    workspace = _measurement_workspace(tmp_path)

    completed = run_harness(
        [
            "--cases",
            "cases",
            "--mode",
            "agent-only",
            "--agent-findings",
            "agent-findings",
            "--agent-runs",
            "2",
            "--timing-report",
        ],
        workspace,
    )
    assert completed.returncode == exitcodes.OK, completed.stderr

    timing = json.loads(completed.stderr.strip().splitlines()[-1])
    agent_entry = next(
        entry for entry in timing["cases"] if entry["case_id"] == AGENT_ONLY_CASE
    )
    assert len(agent_entry["runs"]) == 2


def test_the_bundled_measurement_cases_do_not_change_the_combined_verdict(
    tmp_path: Path,
) -> None:
    """Requirement 22 AC5: the measurement cases carry empty expected_findings,
    so combined mode reports them clean and the verdict stays PASS/INFO."""
    workspace = _measurement_workspace(tmp_path)

    completed = run_harness(["--cases", "cases", "--mode", "combined"], workspace)
    summary = summary_of(completed)

    for name in (AGENT_ONLY_CASE, HUMAN_REVIEW_CASE):
        entry = case_entry(summary, name)
        assert entry["metrics"]["false_positive_count"] == 0, name
    assert summary["status"] in (metrics.STATUS_PASS, metrics.STATUS_INFO)
    assert completed.returncode == exitcodes.OK, completed.stderr
