"""Benchmark cases reviewed by the real tools, and compared with their ground truth.

``tests/unit/test_ground_truth.py`` checks that the case files are well formed.
This module asks the question those files exist to ask: does a review of the
template actually report what the case says it should?

That is the benchmark's own question, and Task 21.5's ``metrics.py`` will answer
it as a set of numbers. The value of asking it here as well, before the harness
exists, is that a *test* fails loudly on the specific case and the specific
expectation, in CI, whereas a metric drops quietly from 100% to 90%. The two are
not redundant: the harness measures, this asserts.

The assertions are exact in both directions, which is the part that matters:

**Every deterministic expectation must be met.** ``benchmark/README.md`` holds
deterministic expectations to a 100% detection rate, so a missed one is a
failure here rather than a slightly lower number. It is also how these cases
earn their place -- ``case-001`` found a real bug in ``_parse_resolved`` on its
first run, which no clean example could have surfaced because no clean template
makes ``iam_policy_no_star_star`` fire.

**Nothing else may be reported.** A case declares its defects in full, so a
finding the ground truth does not list is a false positive. Asserting on the
exact set means a rule that becomes noisier fails here, and the failure names the
resource and category that appeared.

Findings are compared on the harness's match key -- resource logical ID,
``FindingType`` and ``Normalized_Category`` -- with ``Severity``, ``Confidence``
and ``Source`` checked separately once a pair has matched, exactly as the design
separates detection from severity accuracy. Finding text is never compared.

Skips rather than failures where a tool is absent (Requirement 15 AC4): a case
whose expectations are all attributed to cfn-guard cannot be evaluated without
cfn-guard, and the plugin has to stay usable without it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

import pytest

from iacreview import exitcodes
from iacreview.finding import from_dict
from iacreview.report import REPORT_KEYS

# tests/integration/test_benchmark_cases.py -> tests/integration -> tests -> root
PLUGIN_ROOT: Path = Path(__file__).resolve().parents[2]
CASES_DIR: Path = PLUGIN_ROOT / "benchmark" / "cases"

#: The orchestrator, which is how a case is reviewed.
SCRIPT: Path = PLUGIN_ROOT / "skills" / "iac-review" / "scripts" / "run_iac_review.py"

TIMEOUT_S = 180

CFN_LINT = "cfn-lint"
CFN_GUARD = "cfn-guard"

#: Source name -> the executable it needs. ``IAM Review`` is absent because the
#: detectors are pure Python and need nothing on PATH.
EXTERNAL_TOOL_BY_SOURCE = {CFN_LINT: "cfn-lint", CFN_GUARD: "cfn-guard"}

#: Every executable a full review uses.
EXTERNAL_TOOLS = frozenset(EXTERNAL_TOOL_BY_SOURCE.values())

#: The match key of ``benchmark/harness/metrics.py``: resource, FindingType,
#: Normalized_Category. Severity is deliberately excluded.
MatchKey = Tuple[str, str, str]


def case_ids() -> List[str]:
    """Case directory names, sorted. Also the pytest parameter IDs."""
    if not CASES_DIR.is_dir():
        return []
    return sorted(path.name for path in CASES_DIR.iterdir() if path.is_dir())


def load_ground_truth(name: str) -> Dict[str, Any]:
    return json.loads(
        (CASES_DIR / name / "ground_truth.json").read_text(encoding="utf-8")
    )


def review(arguments: Sequence[str]) -> Dict[str, Any]:
    """Review with the orchestrator and return the parsed Review_Report.

    Run from the plugin root as a subprocess, which is how a user runs it and how
    ``tests/integration/test_examples.py`` runs it. What is asserted here is that
    the review *completed*: exit ``OK``, no source failed, and the template
    parsed. Findings do not change the exit code -- a report full of violations is
    a successful review -- so ``OK`` is the right expectation even for a defect
    case. A degraded review would make a missing finding ambiguous between "the
    rule did not fire" and "the tool never ran", which is precisely the confusion
    ``case-001`` was created to resolve.
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


def match_key_of_finding(finding: Dict[str, Any]) -> MatchKey:
    resource = finding["Resource"]
    return (
        "" if resource is None else str(resource),
        str(finding["FindingType"]),
        str(finding["Normalized_Category"]),
    )


def match_key_of_expectation(entry: Dict[str, Any]) -> MatchKey:
    resource = entry["resource"]
    return (
        "" if resource is None else str(resource),
        str(entry["finding_type"]),
        str(entry["normalized_category"]),
    )


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


def skip_unless_available(executables: Iterable[str]) -> None:
    """Skip rather than fail when an external tool is absent (Requirement 15 AC4)."""
    missing = sorted(name for name in executables if shutil.which(name) is None)
    if missing:
        pytest.skip(
            "{0} not installed; the plugin must remain usable without it".format(
                ", ".join(missing)
            )
        )


@pytest.fixture(scope="module")
def reports() -> Dict[str, Dict[str, Any]]:
    """One full review per case, shared by every case in this module.

    Reviewing is a subprocess launch plus two external tools, so it is done once
    per case rather than once per assertion. The reviews are read-only and
    deterministic, so sharing them cannot let one case affect another.

    Both external tools are required, and their absence skips every case that
    uses this fixture rather than degrading it. A review missing a tool is a
    review with a ``tool_unavailable`` warning in ``errors[]`` and a Source that
    never ran, and the exact set of findings from such a review answers a
    different question than the one these assertions ask. The single-Source cases
    at the end of the module do not take this fixture, so the IAM detectors are
    still exercised with no external tool present at all.
    """
    skip_unless_available(EXTERNAL_TOOLS)

    collected: Dict[str, Dict[str, Any]] = {}
    for name in case_ids():
        ground_truth = load_ground_truth(name)
        target = "benchmark/cases/{0}/{1}".format(name, ground_truth["template"])
        collected[name] = review(["--target", target])
    return collected


# ---------------------------------------------------------------------------
# The reviews complete
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", case_ids())
def test_reviewing_a_case_completes_without_a_source_failure(
    name: str, reports: Dict[str, Dict[str, Any]]
) -> None:
    """No degraded review, so a missing finding can only mean a quiet rule.

    ``review`` already asserts ``errors == []``; this states it as its own case so
    that a tool failure is reported as a tool failure rather than as a set of
    missing expectations.
    """
    report = reports[name]

    assert report["errors"] == []
    assert report["target"]["files"] == [
        "benchmark/cases/{0}/{1}".format(name, load_ground_truth(name)["template"])
    ]


@pytest.mark.parametrize("name", case_ids())
def test_no_case_template_provokes_a_cfn_lint_error(
    name: str, reports: Dict[str, Dict[str, Any]]
) -> None:
    """``benchmark/README.md``: a case template has no cfn-lint ``Error``.

    A syntax or schema error stops cfn-lint analysing the rest of the template,
    so the case's other defects would go unmeasured. ``Validity`` is the
    ``FindingType`` an ``Error``-level cfn-lint rule maps to, per
    ``iacreview/category_map.json``.
    """
    skip_unless_available([EXTERNAL_TOOL_BY_SOURCE[CFN_LINT]])

    validity = [
        entry
        for entry in reports[name]["findings"]
        if entry["FindingType"] == "Validity"
    ]

    assert validity == [], describe(validity)


# ---------------------------------------------------------------------------
# Ground truth versus the review
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", case_ids())
def test_every_deterministic_expectation_is_detected(
    name: str, reports: Dict[str, Dict[str, Any]]
) -> None:
    """The 100% rule. A missed deterministic expectation is a failure, not a number.

    When this fails, the disagreement is classified before anything is edited:
    ``benchmark/README.md`` lists the categories, and only a mistake in the
    expectations justifies changing ``ground_truth.json``.
    """
    expectations = [
        entry
        for entry in load_ground_truth(name)["expected_findings"]
        if entry["detection_class"] == "deterministic"
    ]
    if not expectations:
        pytest.skip("{0} declares no deterministic expectation".format(name))

    findings = reports[name]["findings"]
    reported = [match_key_of_finding(entry) for entry in findings]

    missed = [
        entry
        for entry in expectations
        if match_key_of_expectation(entry) not in reported
    ]

    assert missed == [], "not detected in {0}: {1}\nreported:\n{2}".format(
        name,
        [entry["note"] for entry in missed],
        describe(findings),
    )


@pytest.mark.parametrize("name", case_ids())
def test_a_case_reports_nothing_its_ground_truth_does_not_declare(
    name: str, reports: Dict[str, Dict[str, Any]]
) -> None:
    """Findings outside ground truth are false positives.

    Every case is written so that the resources carrying its defects are
    otherwise correctly configured, which is what makes this assertion possible:
    the expected set is the complete set.
    """
    ground_truth = load_ground_truth(name)

    expected = {
        match_key_of_expectation(entry)
        for entry in ground_truth["expected_findings"]
    }
    findings = reports[name]["findings"]

    unexpected = [
        entry for entry in findings if match_key_of_finding(entry) not in expected
    ]

    assert unexpected == [], "not declared by {0}:\n{1}".format(
        name, describe(unexpected)
    )


@pytest.mark.parametrize("name", case_ids())
def test_a_case_reports_exactly_the_expected_number_of_findings(
    name: str, reports: Dict[str, Dict[str, Any]]
) -> None:
    """``expected_finding_count`` is a count of reported findings, not of defects.

    Checked separately from the set comparison above so that a duplicate -- two
    findings sharing a match key, which deduplication should have merged -- is
    caught. The set comparison alone would not see it.
    """
    ground_truth = load_ground_truth(name)

    findings = reports[name]["findings"]

    assert len(findings) == ground_truth["expected_finding_count"], describe(findings)


@pytest.mark.parametrize("name", case_ids())
def test_matched_findings_carry_the_expected_severity(
    name: str, reports: Dict[str, Dict[str, Any]]
) -> None:
    """Severity accuracy, kept apart from detection on purpose.

    Severity is outside the match key, so a wrong severity is reported here and
    does not also present as a missed detection.
    """
    ground_truth = load_ground_truth(name)

    by_key = {
        match_key_of_finding(entry): entry for entry in reports[name]["findings"]
    }

    mismatched = []
    for entry in ground_truth["expected_findings"]:
        finding = by_key.get(match_key_of_expectation(entry))
        if finding is None:
            continue  # Reported by the detection test, not here.
        if finding["Severity"] != entry["severity"]:
            mismatched.append(
                "{0}: expected {1}, got {2}".format(
                    entry["resource"], entry["severity"], finding["Severity"]
                )
            )

    assert mismatched == [], mismatched


@pytest.mark.parametrize("name", case_ids())
def test_matched_findings_carry_the_expected_sources(
    name: str, reports: Dict[str, Dict[str, Any]]
) -> None:
    """``detected_by`` is what the harness filters a single-Source mode on.

    An expectation naming a Source that does not in fact reach the finding would
    make that mode report a false negative, so the claim is asserted rather than
    left as documentation. The comparison is exact: a Source that stopped
    reaching a finding, and one that started, are both worth knowing about.
    """
    ground_truth = load_ground_truth(name)

    by_key = {
        match_key_of_finding(entry): entry for entry in reports[name]["findings"]
    }

    mismatched = []
    for entry in ground_truth["expected_findings"]:
        finding = by_key.get(match_key_of_expectation(entry))
        if finding is None:
            continue
        if finding["Source"] != entry["detected_by"]:
            mismatched.append(
                "{0}: expected {1}, got {2}".format(
                    entry["resource"], entry["detected_by"], finding["Source"]
                )
            )

    assert mismatched == [], mismatched


@pytest.mark.parametrize("name", case_ids())
def test_matched_findings_carry_the_expected_confidence(
    name: str, reports: Dict[str, Dict[str, Any]]
) -> None:
    """``confidence`` is optional in ground truth; where stated, it is checked.

    A deterministic finding claims ``Confirmed`` because a rule either matched or
    did not. The security steering rule keeps the four finding classes distinct,
    and ``Confidence`` is where that distinction lives.
    """
    ground_truth = load_ground_truth(name)

    by_key = {
        match_key_of_finding(entry): entry for entry in reports[name]["findings"]
    }

    mismatched = []
    for entry in ground_truth["expected_findings"]:
        if "confidence" not in entry:
            continue
        finding = by_key.get(match_key_of_expectation(entry))
        if finding is None:
            continue
        if finding["Confidence"] != entry["confidence"]:
            mismatched.append(
                "{0}: expected {1}, got {2}".format(
                    entry["resource"], entry["confidence"], finding["Confidence"]
                )
            )

    assert mismatched == [], mismatched


# ---------------------------------------------------------------------------
# The single-Source claims in detected_by
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", case_ids())
def test_cfn_guard_alone_reaches_the_expectations_attributed_to_it(name: str) -> None:
    """A ``cfn-guard`` attribution has to hold with cfn-guard running alone.

    This is the ``--mode cfn-guard-only`` question Task 21.6 will ask of the
    harness. Asking it here checks the attribution itself: an expectation listing
    a Source that only reaches the finding because another Source also did would
    make that mode report a false negative.
    """
    skip_unless_available([EXTERNAL_TOOL_BY_SOURCE[CFN_GUARD]])

    expectations = [
        entry
        for entry in load_ground_truth(name)["expected_findings"]
        if CFN_GUARD in entry["detected_by"]
    ]
    if not expectations:
        pytest.skip("{0} attributes nothing to cfn-guard".format(name))

    target = "benchmark/cases/{0}/{1}".format(
        name, load_ground_truth(name)["template"]
    )
    report = review(["--target", target, "--sources", "cfn-guard"])
    reported = [match_key_of_finding(entry) for entry in report["findings"]]

    missed = [
        entry
        for entry in expectations
        if match_key_of_expectation(entry) not in reported
    ]

    assert missed == [], "cfn-guard alone missed: {0}\nreported:\n{1}".format(
        [entry["note"] for entry in missed], describe(report["findings"])
    )


@pytest.mark.parametrize("name", case_ids())
def test_the_iam_detectors_alone_reach_the_expectations_attributed_to_them(
    name: str,
) -> None:
    """The same question for ``IAM Review``, which needs no external tool."""
    expectations = [
        entry
        for entry in load_ground_truth(name)["expected_findings"]
        if "IAM Review" in entry["detected_by"]
    ]
    if not expectations:
        pytest.skip("{0} attributes nothing to IAM Review".format(name))

    target = "benchmark/cases/{0}/{1}".format(
        name, load_ground_truth(name)["template"]
    )
    report = review(["--target", target, "--sources", "iam-review"])
    reported = [match_key_of_finding(entry) for entry in report["findings"]]

    missed = [
        entry
        for entry in expectations
        if match_key_of_expectation(entry) not in reported
    ]

    assert missed == [], "IAM Review alone missed: {0}\nreported:\n{1}".format(
        [entry["note"] for entry in missed], describe(report["findings"])
    )


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", case_ids())
def test_reviewing_a_case_twice_produces_byte_identical_output(name: str) -> None:
    """Requirement 16 AC11, on the inputs the benchmark will report numbers from.

    A benchmark whose input varies between runs cannot show a regression, so the
    determinism guarantee is asserted on the case templates and not only on the
    examples.
    """
    skip_unless_available(EXTERNAL_TOOLS)
    ground_truth = load_ground_truth(name)
    target = "benchmark/cases/{0}/{1}".format(name, ground_truth["template"])

    first = review(["--target", target])
    second = review(["--target", target])

    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
