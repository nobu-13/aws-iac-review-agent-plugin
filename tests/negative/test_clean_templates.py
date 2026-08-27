"""The false-positive counting rule, and the clean templates it is applied to.

The testing steering rule asks for a negative test: correct infrastructure must
not attract findings. Requirement 12 AC3-AC6 turns that into something
countable, and design.md's Testing Strategy states the count as
``count_false_positives``. This module implements that function and is the only
place in the suite that does.

**What this module owns**: the rule that decides whether a reported Finding is a
false positive. Three filters, in the order design.md composes them -- an
agent-only Finding is out of scope (AC5), a Finding whose ``FindingType`` is
``Informational`` or ``BestPractice`` *and* whose ``Severity`` is LOW or INFO is
excluded (AC6), and what remains counts when ground truth does not declare it.
The excluded classes are the interesting part: the exclusion exists so that
``-c I`` (design.md, cfn-lint 節) and the IAM coverage-gap disclosures cannot
fail a negative test, and it is narrow on purpose, so a ``BestPractice`` +
MEDIUM Finding still counts.

**What this module does not own, and does not repeat**:

- ``tests/integration/test_examples.py`` pins the exact finding count of both
  ``examples/`` templates.
- ``tests/integration/test_benchmark_cases.py`` compares every benchmark case,
  the clean ones included, against its own ground truth.
- ``tests/unit/test_ground_truth.py`` validates the case files themselves.

Those three already establish that the reviews are quiet where they should be.
Re-running them here would add nothing, so the clean cases appear below only for
the three conditions that need a genuinely empty finding set: no HIGH or
CRITICAL from a deterministic Source, nothing outside ground truth, and
``passed_all_checks``.

**Why defect cases appear in a negative test module.** The exclusion rule's
branches cannot be reached from a clean template: ``case-101`` and ``case-102``
produce no Finding of any class, so nothing there exercises "excluded" versus
"counted". The branches are exercised on real review output instead --
``case-007`` reports ``BestPractice`` + LOW, ``case-010`` reports
``BestPractice`` + MEDIUM, and ``tests/fixtures/valid/iam_unresolvable_values.yaml``
reports the ``Informational`` + INFO ``unresolvable_value`` disclosure -- each
handed to the counter with a deliberately **empty** expectation set, which
isolates the classification decision from the detection question those cases
were built to ask. Alongside them, one parametrized case walks the whole
``FindingType`` x ``Severity`` grid with synthetic Findings, so all twenty
combinations are pinned rather than the four the real inputs happen to reach.

**``examples/lambda-with-role/template.yaml`` is not used as a clean input.** It
reports one HIGH IAM finding on the trust policy Lambda requires, which
``examples/README.md`` argues is correct and must not be silenced, so a blanket
"no HIGH from a deterministic Source" assertion would fail on it. It appears
below in the one role it can hold honestly: proof that the exclusion rule is
narrow enough to leave that finding counted.

**Relation to ``benchmark/harness/metrics.py``.** The two notions of a false
positive deliberately differ, and neither is wrong. ``metrics.compute`` counts
every unmatched Finding, because precision describes the whole report; this
module's count applies AC5 and AC6 first, so it is a subset. The keys differ
too: ``metrics`` matches on resource, ``FindingType`` and
``Normalized_Category``, while design.md's pseudocode for this rule compares
resource and ``Normalized_Category`` only. On the clean cases the difference
cannot change a verdict -- ground truth is empty, so every deterministic Finding
counts under either key -- and the subset relation is asserted on real output at
the end of the module rather than left as a claim.

Skips rather than failures where an external tool is absent (Requirement 15
AC4). The IAM detectors need nothing on PATH, which is why the counting rule's
own cases and the ``unresolvable_value`` case assert unconditionally.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple

import pytest

from benchmark.harness import metrics
from iacreview import exitcodes
from iacreview.finding import (
    AGENT_SOURCE,
    FINDING_TYPES,
    SEVERITIES,
    Evidence,
    Finding,
    Location,
    from_dict,
    to_dict,
)
from iacreview.report import REPORT_KEYS

# tests/negative/test_clean_templates.py -> tests/negative -> tests -> root
PLUGIN_ROOT: Path = Path(__file__).resolve().parents[2]
CASES_DIR: Path = PLUGIN_ROOT / "benchmark" / "cases"

#: The orchestrator, which is how a template is reviewed.
SCRIPT: Path = PLUGIN_ROOT / "skills" / "iac-review" / "scripts" / "run_iac_review.py"

TIMEOUT_S = 180

#: The two clean cases Requirement 12 AC3 asks for. Named rather than
#: discovered: a negative test whose input set could shrink to nothing by a
#: renamed directory would keep passing while measuring nothing.
CLEAN_CASES: List[str] = ["case-101-clean-web-tier", "case-102-clean-data-tier"]

#: External tools a full review uses. ``IAM Review`` needs none.
EXTERNAL_TOOLS: Tuple[str, ...] = ("cfn-lint", "cfn-guard")

#: Severities Requirement 12 AC4 forbids a deterministic Source from reporting
#: on a negative test template.
FORBIDDEN_SEVERITIES: FrozenSet[str] = frozenset(("HIGH", "CRITICAL"))

#: ``FindingType`` values AC6's exclusion applies to.
EXCLUDABLE_FINDING_TYPES: Tuple[str, ...] = ("Informational", "BestPractice")

#: ``Severity`` values AC6's exclusion applies to.
EXCLUDABLE_SEVERITIES: Tuple[str, ...] = ("LOW", "INFO")

#: The excluded classes, exactly as design.md's ``_EXCLUDED`` writes them. Kept
#: as a literal so that a change to the rule is a visible change to this set,
#: and cross-checked against the AND of the two tuples above by the first test
#: below -- AC6 is a conjunction, and a set built by product could not be read
#: as evidence of that.
EXCLUDED_CLASSES: FrozenSet[Tuple[str, str]] = frozenset(
    (
        ("Informational", "LOW"),
        ("Informational", "INFO"),
        ("BestPractice", "LOW"),
        ("BestPractice", "INFO"),
    )
)

#: Real inputs for the classes a clean template never produces. Each is reviewed
#: with the one Source that reports the class, so the case needs at most one
#: external tool.
TAGGING_CASE = "case-007-missing-tags"
BACKUP_CASE = "case-010-missing-deletion-protection"

#: A template whose every IAM value is beyond static resolution, so the IAM
#: Source reports ``Informational`` + INFO coverage gaps and nothing else.
UNRESOLVABLE_TEMPLATE = "tests/fixtures/valid/iam_unresolvable_values.yaml"

#: The example carrying one documented HIGH IAM finding. See the module
#: docstring: used here only to show the exclusion rule leaves it counted.
LAMBDA_WITH_ROLE = "examples/lambda-with-role/template.yaml"

#: ``RuleId`` of the IAM coverage-gap disclosure Requirement 12 AC6 has to
#: exclude (condition (e)).
UNRESOLVABLE_RULE_ID = "unresolvable_value"

#: A deployment-blocking cfn-lint rule, per ``iacreview/category_map.json``.
#: Carried by every synthetic Finding below so that the ``Validity`` + CRITICAL
#: corner of the grid is a Finding the schema accepts (Requirement 7 AC6) rather
#: than one that has to be skipped.
BLOCKING_RULE_ID = "E3001"


# ---------------------------------------------------------------------------
# The counting rule (Requirement 12 AC3-AC6; design.md, Negative test の判定)
# ---------------------------------------------------------------------------


def is_deterministic(finding: Dict[str, Any]) -> bool:
    """Whether ``finding`` was reached by something other than agent reasoning.

    Requirement 12 AC4 and AC5 are about deterministic Sources, so a Finding
    only ``Agent Review`` reported is outside the count. A merged Finding that
    ``Agent Review`` shares with a deterministic Source stays in scope: a
    deterministic Source did report it.
    """
    sources = finding["Source"]
    return not (AGENT_SOURCE in sources and len(sources) == 1)


def is_excluded_class(finding: Dict[str, Any]) -> bool:
    """Whether AC6 excludes ``finding`` from the false positive count.

    The conjunction, not the union: ``BestPractice`` + MEDIUM is not excluded.
    """
    return (finding["FindingType"], finding["Severity"]) in EXCLUDED_CLASSES


def expected_keys(
    ground_truth: Sequence[Dict[str, Any]]
) -> FrozenSet[Tuple[Optional[str], str]]:
    """The ``(resource, normalized_category)`` pairs ground truth declares.

    design.md's key for this rule. Narrower than
    :func:`benchmark.harness.metrics.match_key`, which also compares
    ``FindingType``; see the module docstring on why the two differ and where it
    could matter.
    """
    return frozenset(
        (entry["resource"], entry["normalized_category"]) for entry in ground_truth
    )


def outside_ground_truth(
    findings: Sequence[Dict[str, Any]], ground_truth: Sequence[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Deterministic Findings ground truth does not declare (Requirement 12 AC5).

    AC5's own question, before AC6's exclusion is applied. Separated from
    :func:`false_positives` so that the two conditions fail separately: a
    template that starts reporting an excluded-class Finding is a change worth
    seeing even though it is not a false positive.
    """
    expected = expected_keys(ground_truth)
    return [
        finding
        for finding in findings
        if is_deterministic(finding)
        and (finding["Resource"], finding["Normalized_Category"]) not in expected
    ]


def false_positives(
    findings: Sequence[Dict[str, Any]], ground_truth: Sequence[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """The Findings :func:`count_false_positives` counts.

    Returns the Findings rather than only their number so a failure names what
    appeared. The three filters and their order are design.md's.
    """
    return [
        finding
        for finding in outside_ground_truth(findings, ground_truth)
        if not is_excluded_class(finding)
    ]


def count_false_positives(
    findings: Sequence[Dict[str, Any]], ground_truth: Sequence[Dict[str, Any]]
) -> int:
    """design.md's ``count_false_positives``, to its stated signature.

    Args:
        findings: The ``findings`` array of a Review_Report.
        ground_truth: The ``expected_findings`` array of a case.

    Returns:
        How many deterministic Findings are neither declared by ground truth nor
        excluded by Requirement 12 AC6.
    """
    return len(false_positives(findings, ground_truth))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def skip_unless_available(executables: Iterable[str]) -> None:
    """Skip rather than fail when an external tool is absent (Requirement 15 AC4)."""
    missing = sorted(name for name in executables if shutil.which(name) is None)
    if missing:
        pytest.skip(
            "{0} not installed; the plugin must remain usable without it".format(
                ", ".join(missing)
            )
        )


def review(arguments: Sequence[str]) -> Dict[str, Any]:
    """Review with the orchestrator and return the parsed Review_Report.

    Run as a subprocess from the plugin root, as a user runs it and as the
    integration modules run it. ``errors == []`` is asserted here because every
    case in this module needs a review that completed: a Source that never ran
    reports no Finding, and silence from a Source that failed would look exactly
    like the silence a negative test is trying to confirm.
    """
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        cwd=str(PLUGIN_ROOT),
        env=dict(os.environ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
    )

    assert completed.stdout, "stdout was empty; stderr was: {0}".format(
        completed.stderr
    )
    report = json.loads(completed.stdout)
    assert completed.returncode == exitcodes.OK, completed.stderr
    assert sorted(report) == sorted(REPORT_KEYS)
    assert report["errors"] == [], completed.stderr
    for entry in report["findings"]:
        from_dict(entry)
    return report


def load_ground_truth(name: str) -> Dict[str, Any]:
    return json.loads(
        (CASES_DIR / name / "ground_truth.json").read_text(encoding="utf-8")
    )


def case_target(name: str) -> str:
    """Workspace-relative path of a case's template."""
    return "benchmark/cases/{0}/{1}".format(name, load_ground_truth(name)["template"])


def describe(findings: Sequence[Dict[str, Any]]) -> str:
    """Render findings for an assertion message."""
    return "\n".join(
        "{0} {1} {2} {3} {4}: {5}".format(
            entry["Severity"],
            entry["FindingType"],
            entry["Normalized_Category"],
            ",".join(entry["Source"]),
            entry["Resource"],
            entry["Finding"],
        )
        for entry in findings
    )


def rule_ids(findings: Sequence[Dict[str, Any]]) -> List[str]:
    """Every ``Evidence[].RuleId`` in ``findings``, sorted and de-duplicated."""
    return sorted(
        {
            str(evidence["RuleId"])
            for finding in findings
            for evidence in finding["Evidence"]
            if evidence["RuleId"] is not None
        }
    )


def synthetic_finding(
    *,
    finding_type: str = "Security",
    severity: str = "HIGH",
    resource: Optional[str] = "DataBucket",
    category: str = "Encryption",
    sources: Sequence[str] = ("cfn-lint",),
    confidence: str = "Confirmed",
    excerpt: Optional[str] = None,
) -> Dict[str, Any]:
    """A schema-valid Finding dict, varying only in what a test is about.

    Round-tripped through :func:`iacreview.finding.from_dict`, so a combination
    the Finding schema rejects fails here rather than silently becoming input the
    counting rule would never see in a real report.
    """
    finding = Finding(
        ID=1,
        Normalized_Category=category,
        FindingType=finding_type,
        Severity=severity,
        Confidence=confidence,
        Source=list(sources),
        Resource=resource,
        Location=Location(
            File="template.yaml",
            Line=None,
            Column=None,
            TemplatePath=["Resources", resource] if resource else None,
        ),
        Finding="[{0}] A synthetic finding.".format(BLOCKING_RULE_ID),
        WhyItMatters="Stated so the Finding is complete; nothing reads it here.",
        Evidence=[
            Evidence(
                Source=sources[0],
                Detail="synthetic evidence",
                RuleId=BLOCKING_RULE_ID,
                Excerpt=excerpt,
            )
        ],
        Recommendation="Nothing; this Finding exists to be counted or excluded.",
        SuggestedRemediation=None,
    )
    payload = to_dict(finding)
    from_dict(payload)
    return payload


def expectation(
    resource: Optional[str] = "DataBucket",
    normalized_category: str = "Encryption",
    finding_type: str = "Security",
    severity: str = "HIGH",
) -> Dict[str, Any]:
    """One ``expected_findings`` entry, in ground truth's snake_case spelling."""
    return {
        "resource": resource,
        "normalized_category": normalized_category,
        "finding_type": finding_type,
        "severity": severity,
        "detection_class": metrics.DETERMINISTIC,
        "detected_by": ["cfn-lint"],
        "note": "Declared, so a Finding matching it is not a false positive.",
    }


@pytest.fixture(scope="module")
def clean_reports() -> Dict[str, Dict[str, Any]]:
    """One full review per clean case, shared by every case that reads them.

    Both external tools are required and their absence skips: Requirement 12 AC4
    is a claim about cfn-lint, cfn-guard and the IAM detectors together, and a
    review missing one of them would answer a narrower question while looking
    like the same green test.
    """
    skip_unless_available(EXTERNAL_TOOLS)
    return {name: review(["--target", case_target(name)]) for name in CLEAN_CASES}


# ---------------------------------------------------------------------------
# The rule itself: (c) the exclusion, (d) its narrowness
# ---------------------------------------------------------------------------


def test_the_excluded_classes_are_the_conjunction_of_the_two_sets() -> None:
    """Requirement 12 AC6 is an AND, and this is where that is stated.

    Every excluded class also has to be a class that exists: a typo in
    :data:`EXCLUDED_CLASSES` would otherwise exclude nothing and go unnoticed,
    because a rule that excludes nothing only ever over-counts.
    """
    conjunction = {
        (finding_type, severity)
        for finding_type in EXCLUDABLE_FINDING_TYPES
        for severity in EXCLUDABLE_SEVERITIES
    }

    assert EXCLUDED_CLASSES == conjunction
    for finding_type, severity in EXCLUDED_CLASSES:
        assert finding_type in FINDING_TYPES
        assert severity in SEVERITIES


@pytest.mark.parametrize("severity", SEVERITIES)
@pytest.mark.parametrize("finding_type", FINDING_TYPES)
def test_a_finding_class_is_counted_unless_the_rule_excludes_it(
    finding_type: str, severity: str
) -> None:
    """All twenty classes, so no branch of AC6 is left to the real inputs.

    The Findings below differ in nothing but ``FindingType`` and ``Severity``,
    and none is declared by ground truth, so the count is the rule's verdict on
    the class and on nothing else.
    """
    finding = synthetic_finding(finding_type=finding_type, severity=severity)

    counted = count_false_positives([finding], [])

    excluded = (finding_type, severity) in EXCLUDED_CLASSES
    assert counted == (0 if excluded else 1), (finding_type, severity)


@pytest.mark.parametrize("severity", EXCLUDABLE_SEVERITIES)
@pytest.mark.parametrize("finding_type", EXCLUDABLE_FINDING_TYPES)
def test_an_informational_or_bestpractice_low_or_info_finding_is_excluded(
    finding_type: str, severity: str
) -> None:
    """Condition (c), stated as its own case.

    This is what lets the entry point pass ``-c I`` and lets the IAM Source
    disclose its coverage gaps: both produce Findings in these four classes, and
    neither may fail a negative test (design.md, cfn-lint 節 and IAM 節).
    """
    finding = synthetic_finding(finding_type=finding_type, severity=severity)

    assert is_excluded_class(finding) is True
    assert false_positives([finding], []) == []
    # AC5's question is answered separately, and the answer is different: the
    # Finding *is* outside ground truth. It is excluded, not absent.
    assert outside_ground_truth([finding], []) == [finding]


def test_a_bestpractice_medium_finding_is_counted_as_a_false_positive() -> None:
    """Condition (d): the exclusion is a conjunction, so MEDIUM stays in.

    design.md calls this intended strictness. A ``BestPractice`` Finding is a
    recommendation, but at MEDIUM the rule set is asserting that a reader should
    act, and a negative test template is one where nothing needs acting on.
    """
    finding = synthetic_finding(finding_type="BestPractice", severity="MEDIUM")

    assert is_excluded_class(finding) is False
    assert count_false_positives([finding], []) == 1


@pytest.mark.parametrize(
    "finding_type", [name for name in FINDING_TYPES if name not in EXCLUDABLE_FINDING_TYPES]
)
def test_a_low_or_info_finding_of_another_type_is_still_counted(
    finding_type: str,
) -> None:
    """The other half of the conjunction: LOW alone does not exclude.

    ``Security`` + LOW and ``Validity`` + LOW are Findings a clean template
    should not attract either, and reading AC6 as "LOW or INFO is excluded"
    would silence both.
    """
    for severity in EXCLUDABLE_SEVERITIES:
        finding = synthetic_finding(finding_type=finding_type, severity=severity)
        assert count_false_positives([finding], []) == 1, (finding_type, severity)


def test_a_finding_ground_truth_declares_is_not_a_false_positive() -> None:
    """The expected set is what the count is measured against.

    Matched on resource and ``Normalized_Category``, which is design.md's key
    for this rule: a Finding whose severity or type differs from the
    expectation's is a severity or classification question, and
    ``tests/integration/test_benchmark_cases.py`` is where it is asked.
    """
    finding = synthetic_finding(resource="DataBucket", category="Encryption")

    assert count_false_positives([finding], [expectation()]) == 0
    assert count_false_positives([finding], [expectation(resource="OtherBucket")]) == 1
    assert (
        count_false_positives([finding], [expectation(normalized_category="Logging")])
        == 1
    )


def test_a_template_level_finding_compares_on_a_null_resource() -> None:
    """``Resource: null`` on both sides, so a declared one is not a false positive.

    Both documents spell a template-level entry as JSON ``null``, and the rule
    compares the values as they arrive, so the two agree without either side
    being stringified.
    """
    finding = synthetic_finding(resource=None, category="TemplateQuality")

    assert (
        count_false_positives(
            [finding], [expectation(resource=None, normalized_category="TemplateQuality")]
        )
        == 0
    )
    assert count_false_positives([finding], []) == 1


def test_an_agent_only_finding_is_outside_the_count() -> None:
    """Requirement 12 AC5 counts deterministic Sources.

    Agent reasoning is not reproducible between runs, so counting it would make
    a negative test report a different number for the same template.
    """
    finding = synthetic_finding(
        sources=(AGENT_SOURCE,),
        confidence="Likely",
        finding_type="BestPractice",
        severity="MEDIUM",
        excerpt="DataBucket:\n  Type: AWS::S3::Bucket",
    )

    assert is_deterministic(finding) is False
    assert count_false_positives([finding], []) == 0


def test_a_finding_an_agent_shares_with_a_deterministic_source_is_counted() -> None:
    """A merged Finding carries every Source that reached it (Requirement 14 AC12).

    A deterministic Source did report it, so AC5 applies. Excluding it because
    an agent also reported it would let a merge hide a false positive.
    """
    finding = synthetic_finding(
        sources=("cfn-lint", AGENT_SOURCE),
        confidence="Likely",
        finding_type="BestPractice",
        severity="MEDIUM",
        excerpt="DataBucket:\n  Type: AWS::S3::Bucket",
    )

    assert is_deterministic(finding) is True
    assert count_false_positives([finding], []) == 1


def test_no_finding_at_all_is_no_false_positive() -> None:
    """The clean-case outcome, stated on the rule rather than on a review."""
    assert count_false_positives([], []) == 0
    assert false_positives([], []) == []


# ---------------------------------------------------------------------------
# (a), (b), (f): the two clean cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", CLEAN_CASES)
def test_a_clean_case_declares_no_expected_finding(name: str) -> None:
    """The input assumption of everything below, asserted rather than trusted.

    An expectation added to one of these cases would turn the assertions that
    follow into weaker statements without breaking any of them, so the emptiness
    of the expected set is checked in its own right.
    """
    ground_truth = load_ground_truth(name)

    assert ground_truth["expected_findings"] == []
    assert ground_truth["expected_finding_count"] == 0
    assert ground_truth["authored_before_review"] is True


@pytest.mark.parametrize("name", CLEAN_CASES)
def test_no_deterministic_source_reports_high_or_critical_on_a_clean_case(
    name: str, clean_reports: Dict[str, Dict[str, Any]]
) -> None:
    """Condition (a) / Requirement 12 AC4.

    Asserted on the severities rather than on the whole finding list, because
    this is the condition that would survive a future clean case gaining a
    declared low-severity expectation.
    """
    report = clean_reports[name]

    serious = [
        finding
        for finding in report["findings"]
        if is_deterministic(finding) and finding["Severity"] in FORBIDDEN_SEVERITIES
    ]

    assert serious == [], describe(serious)
    for severity in sorted(FORBIDDEN_SEVERITIES):
        assert report["summary"]["by_severity"][severity] == 0


@pytest.mark.parametrize("name", CLEAN_CASES)
def test_a_clean_case_reports_nothing_outside_its_ground_truth(
    name: str, clean_reports: Dict[str, Dict[str, Any]]
) -> None:
    """Condition (b) / Requirement 12 AC5, and the task's completion condition.

    Both are asserted, in both strengths: AC5 counts every deterministic Finding
    ground truth does not declare, and the completion condition counts the ones
    AC6 leaves after its exclusion. On these two cases the two numbers coincide
    at zero, and stating both is what makes that a fact rather than an artefact
    of the exclusion.
    """
    report = clean_reports[name]
    ground_truth = load_ground_truth(name)["expected_findings"]

    undeclared = outside_ground_truth(report["findings"], ground_truth)

    assert undeclared == [], describe(undeclared)
    assert count_false_positives(report["findings"], ground_truth) == 0


@pytest.mark.parametrize("name", CLEAN_CASES)
def test_a_clean_case_passes_all_checks(
    name: str, clean_reports: Dict[str, Dict[str, Any]]
) -> None:
    """Condition (f) / Requirement 7 AC16, on the templates it describes.

    ``passed_all_checks`` is the one field a reader consults instead of counting
    the findings array, so a negative test is where it has to be true.
    """
    report = clean_reports[name]

    assert report["findings"] == [], describe(report["findings"])
    assert report["summary"]["total"] == 0
    assert report["summary"]["passed_all_checks"] is True


def test_passed_all_checks_is_not_a_constant() -> None:
    """Otherwise condition (f) would hold for any template at all.

    ``tests/unit/test_report.py`` states the rule on built reports; this checks
    it end to end on a template that does report something, so the flag on the
    clean cases is evidence about the templates rather than about the field.
    """
    report = review(["--target", UNRESOLVABLE_TEMPLATE, "--sources", "iam-review"])

    assert report["findings"] != []
    assert report["summary"]["passed_all_checks"] is False


# ---------------------------------------------------------------------------
# (c), (d), (e) on real review output
# ---------------------------------------------------------------------------


def test_the_real_unresolvable_value_disclosure_is_excluded() -> None:
    """Condition (e), on the Findings the IAM Source actually emits.

    Every value in the fixture is beyond static resolution, so the review
    reports coverage gaps and nothing else. design.md's IAM section chose
    ``Informational`` + INFO + ``Confirmed`` for them precisely so AC6 excludes
    them: disclosing that a location was not examined must not read as a
    vulnerability, and must not fail a negative test either.

    Handed an empty expectation set on purpose. These Findings are outside any
    ground truth, so the zero below is the exclusion rule at work rather than a
    match.
    """
    report = review(["--target", UNRESOLVABLE_TEMPLATE, "--sources", "iam-review"])
    findings = report["findings"]

    assert UNRESOLVABLE_RULE_ID in rule_ids(findings)
    disclosures = [
        finding
        for finding in findings
        if any(
            evidence["RuleId"] == UNRESOLVABLE_RULE_ID for evidence in finding["Evidence"]
        )
    ]
    assert disclosures != []
    for finding in disclosures:
        assert finding["Source"] == ["IAM Review"]
        assert finding["FindingType"] == "Informational"
        assert finding["Severity"] == "INFO"
        assert is_deterministic(finding) is True
        assert is_excluded_class(finding) is True

    assert outside_ground_truth(findings, []) == findings
    assert count_false_positives(findings, []) == 0


def test_a_real_bestpractice_low_finding_is_excluded() -> None:
    """Condition (c) on real output, for the ``BestPractice`` half of the rule.

    ``case-007`` is a defect case, and its own expectations are checked in
    ``tests/integration/test_benchmark_cases.py``. What it contributes here is
    three genuine ``BestPractice`` + LOW Findings from a deterministic Source;
    handing them to the counter with no expectations isolates the classification
    decision from the detection question the case exists to ask.
    """
    skip_unless_available(["cfn-guard"])
    findings = review(["--target", case_target(TAGGING_CASE), "--sources", "cfn-guard"])[
        "findings"
    ]

    assert findings != []
    for finding in findings:
        assert (finding["FindingType"], finding["Severity"]) == ("BestPractice", "LOW")
        assert is_deterministic(finding) is True

    assert len(outside_ground_truth(findings, [])) == len(findings)
    assert count_false_positives(findings, []) == 0


def test_a_real_bestpractice_medium_finding_is_counted() -> None:
    """Condition (d) on real output: the exclusion does not reach MEDIUM.

    Same construction as the LOW case above, one severity higher, and the
    outcome is the opposite. If AC6 were read as a union rather than a
    conjunction, these Findings would vanish from the count and this is where
    that would show.
    """
    skip_unless_available(["cfn-guard"])
    findings = review(["--target", case_target(BACKUP_CASE), "--sources", "cfn-guard"])[
        "findings"
    ]

    assert findings != []
    for finding in findings:
        assert (finding["FindingType"], finding["Severity"]) == (
            "BestPractice",
            "MEDIUM",
        )
        assert is_excluded_class(finding) is False

    assert count_false_positives(findings, []) == len(findings)


def test_a_real_high_severity_finding_is_never_excluded() -> None:
    """The exclusion rule is narrow, on the one finding that proves it matters.

    ``examples/lambda-with-role`` reports a HIGH IAM finding on the trust policy
    Lambda requires. ``examples/README.md`` argues that finding is correct and
    the example keeps the working policy rather than silencing the review, so it
    is the natural check that no filter in this module can make a HIGH Finding
    disappear. It is deliberately not used as a clean input anywhere above.
    """
    findings = review(["--target", LAMBDA_WITH_ROLE, "--sources", "iam-review"])[
        "findings"
    ]

    assert len(findings) == 1, describe(findings)
    finding = findings[0]
    assert finding["Severity"] == "HIGH"
    assert is_deterministic(finding) is True
    assert is_excluded_class(finding) is False
    assert count_false_positives(findings, []) == 1


# ---------------------------------------------------------------------------
# Agreement with the benchmark's own notion of a false positive
# ---------------------------------------------------------------------------


def test_the_negative_count_is_a_subset_of_the_benchmark_count() -> None:
    """The two definitions differ, and the direction of the difference is fixed.

    ``metrics`` counts every unmatched Finding, because precision describes the
    whole report; this module applies AC5 and AC6 first. So the negative test
    can never report a false positive the benchmark would not, and the
    disagreement is exactly the Findings AC6 excludes -- here, the IAM coverage
    gaps: two by the benchmark's count, none by this one.
    """
    findings = review(["--target", UNRESOLVABLE_TEMPLATE, "--sources", "iam-review"])[
        "findings"
    ]

    benchmark_count = metrics.compute([], findings)["false_positive_count"]

    assert benchmark_count == len(findings)
    assert count_false_positives(findings, []) == 0
    assert count_false_positives(findings, []) <= benchmark_count


def test_the_two_counts_agree_where_no_class_is_excluded() -> None:
    """With nothing to exclude, the two definitions produce the same number.

    Which is the point of asserting both: the subset relation above is a
    consequence of AC6, not of the two rules measuring different things.
    """
    skip_unless_available(["cfn-guard"])
    findings = review(["--target", case_target(BACKUP_CASE), "--sources", "cfn-guard"])[
        "findings"
    ]

    benchmark_count = metrics.compute([], findings)["false_positive_count"]

    assert count_false_positives(findings, []) == benchmark_count


@pytest.mark.parametrize("name", CLEAN_CASES)
def test_the_two_counts_agree_on_a_clean_case(
    name: str, clean_reports: Dict[str, Dict[str, Any]]
) -> None:
    """On the negative test inputs themselves, the two rules cannot diverge.

    Ground truth is empty and no Finding was reported, so the narrower key
    design.md gives this rule and the three-field key ``metrics`` uses reach the
    same answer. Stated so that a future clean case gaining a Finding is
    reported by both.
    """
    report = clean_reports[name]
    ground_truth = load_ground_truth(name)["expected_findings"]

    assert count_false_positives(report["findings"], ground_truth) == 0
    assert (
        metrics.compute(ground_truth, report["findings"])["false_positive_count"] == 0
    )
