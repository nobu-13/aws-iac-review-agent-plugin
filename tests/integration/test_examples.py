"""The ``examples/`` directory, reviewed by the plugin that ships with it.

Task 19.1 asks for two things from these templates: that every one of them can be
loaded and reviewed without an exception, and that they are usable as the input to
the end-to-end integration test of Task 24.1. This module checks the first
directly and protects the second, because an example that quietly starts
reporting findings is no longer the clean sample the rest of the suite treats it
as.

That second part is a **negative test** in the sense the testing steering rule
gives the term: the interesting result is silence. Well-formed infrastructure must
not attract findings, so the assertions here are exact rather than bounded --
``minimal-s3`` reports nothing at all, and ``lambda-with-role`` reports exactly
one finding, whose three underlying detections are named. An exact expectation
fails when a rule becomes noisier *and* when it becomes quieter, which a
``<= n`` bound would not.

The one finding is not a defect in the example. It is the trust policy AWS
documents for a Lambda execution role, reported by three deterministic detectors
that see a service principal with no ``Condition``. ``examples/README.md``
explains why the recommended condition keys cannot be applied to a Lambda
execution role, and why the example keeps the working policy instead of silencing
the review. :data:`LAMBDA_TRUST_POLICY_DETECTIONS` is that argument in executable
form: if the detectors change their mind about this policy, this test says so.

Skips rather than failures where a tool is absent (Requirement 15 AC4): the
plugin has to stay usable without cfn-lint and cfn-guard, so a test that needs
them says so and steps aside. The IAM detectors need no external tool, which is
why the per-source cases below can assert unconditionally.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import pytest

from iacreview import cdk, exitcodes, template
from iacreview.finding import from_dict
from iacreview.report import REPORT_KEYS

# tests/integration/test_examples.py -> tests/integration -> tests -> plugin root
PLUGIN_ROOT: Path = Path(__file__).resolve().parents[2]
EXAMPLES_DIR: Path = PLUGIN_ROOT / "examples"

#: The orchestrator, which is how a user reviews an example.
SCRIPT: Path = PLUGIN_ROOT / "skills" / "iac-review" / "scripts" / "run_iac_review.py"

TIMEOUT_S = 180

#: The example directories, pinned. A renamed or deleted example is reported here
#: rather than by silently contributing no test cases -- and
#: ``skills/cfn-guard-review/SKILL.md`` cites ``minimal-s3/template.yaml`` by
#: path, so the name is part of the documentation.
EXPECTED_EXAMPLE_DIRECTORIES = ["cdk-synth-output", "lambda-with-role", "minimal-s3"]

#: Reviewable templates under ``examples/``, relative to the plugin root.
#: ``cdk-synth-output`` holds none: a cloud assembly is a build artifact, and the
#: structure steering rule keeps generated output out of the repository.
EXPECTED_EXAMPLE_TEMPLATES = [
    "examples/lambda-with-role/template.yaml",
    "examples/minimal-s3/template.yaml",
]

MINIMAL_S3 = "examples/minimal-s3/template.yaml"
LAMBDA_WITH_ROLE = "examples/lambda-with-role/template.yaml"

#: The three detections that merge into ``lambda-with-role``'s single finding.
#: All three describe one statement: ``lambda.amazonaws.com`` may call
#: ``sts:AssumeRole`` and nothing bounds when. They arrive as one Finding because
#: deduplication joins by resource and category (Requirement 14 AC5).
LAMBDA_TRUST_POLICY_DETECTIONS = [
    "cross_service_missing_condition",
    "privesc_broad_trust",
    "sensitive_prefix_without_condition",
]

requires_cfn_lint = pytest.mark.skipif(
    shutil.which("cfn-lint") is None,
    reason="cfn-lint is not installed; the plugin must remain usable without it",
)

requires_cfn_guard = pytest.mark.skipif(
    shutil.which("cfn-guard") is None,
    reason="cfn-guard is not installed; the plugin must remain usable without it",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def review(
    arguments: Sequence[str], *, path_entries: Optional[Sequence[Path]] = None
) -> Dict[str, Any]:
    """Review with the orchestrator and return the parsed Review_Report.

    Run as a subprocess from the plugin root, which is how the examples are
    documented to be reviewed: the paths in the report are then exactly the paths
    written in ``examples/README.md``.

    Args:
        arguments: Arguments after the script path.
        path_entries: ``PATH`` for the child. ``None`` inherits the caller's.

    Returns:
        The report. The exit code and the emptiness of ``errors[]`` are asserted
        here, because every case in this module expects a review that completed.
    """
    env = dict(os.environ)
    if path_entries is not None:
        env["PATH"] = os.pathsep.join(str(entry) for entry in path_entries)

    completed = subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        cwd=str(PLUGIN_ROOT),
        env=env,
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
    # A clean example must not need a degraded review to look clean: no source
    # may have failed, and no template may have failed to parse.
    assert report["errors"] == [], completed.stderr
    for entry in report["findings"]:
        from_dict(entry)
    return report


def rule_ids(finding: Dict[str, Any]) -> List[str]:
    """The ``RuleId`` of every Evidence entry, sorted."""
    return sorted(
        str(evidence["RuleId"])
        for evidence in finding["Evidence"]
        if evidence["RuleId"] is not None
    )


def describe(findings: Sequence[Dict[str, Any]]) -> str:
    """Render findings for an assertion message."""
    return "\n".join(
        "{0} {1} {2} {3}: {4}".format(
            entry["Severity"],
            entry["FindingType"],
            ",".join(entry["Source"]),
            entry["Resource"],
            entry["Finding"],
        )
        for entry in findings
    )


# ---------------------------------------------------------------------------
# The directory itself
# ---------------------------------------------------------------------------


def test_the_expected_examples_are_present() -> None:
    directories = sorted(
        path.name for path in EXAMPLES_DIR.iterdir() if path.is_dir()
    )

    assert directories == EXPECTED_EXAMPLE_DIRECTORIES


def test_the_expected_example_templates_are_present() -> None:
    templates = sorted(
        str(path.relative_to(PLUGIN_ROOT).as_posix())
        for path in EXAMPLES_DIR.rglob("template.yaml")
    )

    assert templates == EXPECTED_EXAMPLE_TEMPLATES


def test_no_synthesized_output_is_committed_under_examples() -> None:
    """The structure steering rule: generated artifacts are not committed.

    ``examples/cdk-synth-output/`` documents the ``cdk synth`` flow without
    shipping a cloud assembly. A checked-in one would be a template that no
    longer matches any source, and it would be reviewed as though it did.
    """
    generated = [
        str(path.relative_to(PLUGIN_ROOT).as_posix())
        for path in EXAMPLES_DIR.rglob("*")
        if path.name == cdk.CDK_OUTPUT_DIRECTORY_NAME
        or path.name.endswith(cdk.SYNTHESIZED_TEMPLATE_SUFFIX)
    ]

    assert generated == []


def test_the_cdk_example_quotes_the_synthesis_warning_verbatim() -> None:
    """One wording for the risk, stated in :data:`iacreview.cdk.SYNTH_WARNING`.

    Requirement 8 AC4 has the host agent show the user this warning before
    ``cdk synth`` may run. The documentation quotes the constant rather than
    paraphrasing it, so the reader and the run-time diagnostic cannot describe
    the risk differently.
    """
    readme = (EXAMPLES_DIR / "cdk-synth-output" / "README.md").read_text(
        encoding="utf-8"
    )

    # Quoted as a line-wrapped Markdown blockquote, so drop the quote markers and
    # compare on whitespace-collapsed text.
    unquoted = " ".join(line.lstrip("> ") for line in readme.splitlines())
    collapsed = " ".join(unquoted.split())
    assert " ".join(cdk.SYNTH_WARNING.split()) in collapsed
    assert "SYNTH_WARNING" in readme


# ---------------------------------------------------------------------------
# Every example loads and is reviewable (Task 19.1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("relative", EXPECTED_EXAMPLE_TEMPLATES)
def test_each_example_template_loads_and_is_reviewable(relative: str) -> None:
    loaded = template.load_template(PLUGIN_ROOT / relative)

    assert loaded.fmt == "yaml"
    assert template.is_reviewable(loaded.doc)
    assert loaded.doc["Resources"]


@pytest.mark.parametrize("relative", EXPECTED_EXAMPLE_TEMPLATES)
def test_no_example_names_a_literal_account_id(relative: str) -> None:
    """Pseudo parameters instead of literals (security steering rule).

    A 12-digit account ID copied out of an example is both a disclosure and a
    finding waiting to happen: ``cross_account_principal`` looks for exactly
    that shape.
    """
    text = (PLUGIN_ROOT / relative).read_text(encoding="utf-8")

    for token in text.replace(":", " ").replace('"', " ").split():
        assert not (
            len(token) == 12 and token.isdigit()
        ), "{0} contains what looks like an account ID: {1}".format(relative, token)


# ---------------------------------------------------------------------------
# Negative test: the deterministic IAM detectors
# ---------------------------------------------------------------------------


def test_minimal_s3_has_nothing_for_the_iam_detectors_to_report() -> None:
    report = review(["--target", MINIMAL_S3, "--sources", "iam-review"])

    assert report["findings"] == []
    assert report["summary"]["passed_all_checks"] is True


def test_lambda_with_role_reports_only_its_documented_trust_policy_finding() -> None:
    """The one expected finding, named detection by detection.

    See the module docstring and ``examples/README.md``: the trust policy is the
    one Lambda requires, and the condition keys the finding recommends are not
    populated by Lambda when it assumes an execution role. The example keeps the
    working policy, so this test pins the finding rather than wishing it away.
    """
    report = review(["--target", LAMBDA_WITH_ROLE, "--sources", "iam-review"])

    findings = report["findings"]
    assert len(findings) == 1, describe(findings)

    finding = findings[0]
    assert finding["Resource"] == "ReportWriterRole"
    assert finding["Source"] == ["IAM Review"]
    assert finding["Confidence"] == "Confirmed"
    assert finding["FindingType"] == "Security"
    assert finding["Severity"] == "HIGH"
    assert finding["Normalized_Category"] == "IAM"
    assert rule_ids(finding) == LAMBDA_TRUST_POLICY_DETECTIONS
    assert finding["Location"]["TemplatePath"] == [
        "Resources",
        "ReportWriterRole",
        "Properties",
        "AssumeRolePolicyDocument",
        "Statement",
        0,
    ]
    # The least-privilege permissions policy is reported by nothing: one action,
    # one fully qualified ARN, no wildcard, no unresolved value to disclose.
    assert "ReadReportDestination" not in json.dumps(report["findings"])


# ---------------------------------------------------------------------------
# Negative test: the bundled Guard rules and cfn-lint
# ---------------------------------------------------------------------------


@requires_cfn_guard
@pytest.mark.parametrize("relative", EXPECTED_EXAMPLE_TEMPLATES)
def test_no_bundled_guard_rule_is_violated_by_an_example(relative: str) -> None:
    """Requirement 12 AC3: the rule set stays quiet on compliant templates.

    Both examples are written against the bundled rules -- encryption, public
    access, logging, tagging -- so a violation here means either the example
    regressed or a rule started reporting a shape it should accept.
    """
    report = review(["--target", relative, "--sources", "cfn-guard"])

    assert report["findings"] == [], describe(report["findings"])
    # A clean run still reports how much was evaluated, so an empty result cannot
    # be mistaken for a rule set that never ran (Requirement 5 AC4).
    assert report["summary"]["passed_all_checks"] is True


@requires_cfn_lint
@pytest.mark.parametrize("relative", EXPECTED_EXAMPLE_TEMPLATES)
def test_cfn_lint_reports_nothing_on_an_example(relative: str) -> None:
    """Informational rules included: the entry point passes ``-c I``.

    An example is a template a reader will copy, so it should be clean at every
    level cfn-lint checks, not only at Error level.
    """
    report = review(["--target", relative, "--sources", "cfn-lint"])

    assert report["findings"] == [], describe(report["findings"])


# ---------------------------------------------------------------------------
# Negative test: the whole review
# ---------------------------------------------------------------------------


@requires_cfn_lint
@requires_cfn_guard
def test_the_full_review_of_minimal_s3_finds_nothing() -> None:
    report = review(["--target", MINIMAL_S3])

    assert report["findings"] == [], describe(report["findings"])
    assert report["summary"]["total"] == 0
    assert report["summary"]["passed_all_checks"] is True
    assert report["target"]["files"] == [MINIMAL_S3]
    assert report["target"]["cdk"] == {
        "detected": False,
        "synthesis": "not_applicable",
        "synthesized_templates": [],
    }


@requires_cfn_lint
@requires_cfn_guard
def test_the_full_review_of_lambda_with_role_finds_only_the_trust_policy() -> None:
    report = review(["--target", LAMBDA_WITH_ROLE])

    findings = report["findings"]
    assert len(findings) == 1, describe(findings)
    assert findings[0]["Source"] == ["IAM Review"]
    assert rule_ids(findings[0]) == LAMBDA_TRUST_POLICY_DETECTIONS
    assert report["summary"]["by_source"]["cfn-lint"] == 0
    assert report["summary"]["by_source"]["cfn-guard"] == 0
    assert report["summary"]["by_severity"]["CRITICAL"] == 0


@requires_cfn_lint
@requires_cfn_guard
def test_reviewing_the_whole_examples_directory_is_clean_apart_from_that() -> None:
    """One review over ``examples/``, which is how Task 24.1 will use it.

    A directory target also exercises the walk: ``cdk-synth-output`` contributes
    no template, and its README is not mistaken for one.
    """
    report = review(["--target", "examples"])

    assert sorted(report["target"]["files"]) == EXPECTED_EXAMPLE_TEMPLATES
    assert report["target"]["cdk"]["detected"] is False

    findings = report["findings"]
    assert len(findings) == 1, describe(findings)
    assert findings[0]["Location"]["File"] == LAMBDA_WITH_ROLE
    assert report["summary"]["by_template_group"] == {
        "standalone": 1,
        "synthesized": 0,
    }
