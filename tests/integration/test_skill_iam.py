"""The ``iam-review`` Skill end to end, through its two entry points (Task 18.4).

Both scripts are run as subprocesses, because that is how a client invokes them:
the exit code, the split between stdout and stderr, and the ``sys.path``
bootstrap only exist in a real process. The four groups match the four things
Task 18.4 asks the Skill to promise:

(a) every Finding ``run_iam_scan.py`` emits carries ``Confidence: "Confirmed"``
    (Requirement 7 AC9), in a report whose Findings satisfy the shared schema;
(b) ``extract_policies.py`` emits design.md's Layer 2 input JSON, with the
    documented key structure and nothing else on stdout;
(c) its ``deterministic_findings_summary`` reports exactly what Layer 1 detected,
    so the Agent is told what it must not restate (Requirement 2 AC14, AC15);
(d) a Template with no IAM yields zero Findings and exit 0, with the
    informational message Requirement 6 AC12 asks for on stderr.

Expected values are computed from the fixtures through
:mod:`iacreview.iam.detectors` -- Layer 1 itself -- rather than copied from a
previous run of the scripts, so a change in what the detectors find fails the
comparison instead of silently redefining it. The detectors' own positive and
negative cases live in ``tests/unit/test_iam_detectors.py``; what is under test
here is the wiring between them and stdout.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence

import pytest

# tests/integration/test_skill_iam.py -> tests/integration -> tests -> plugin root
PLUGIN_ROOT: Path = Path(__file__).resolve().parents[2]
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from iacreview import categories, exitcodes, finding as finding_module, iam, report, template
from iacreview.iam import detectors, locate
from iacreview.iam.intrinsics import ResolutionContext

SKILL: Path = PLUGIN_ROOT / "skills" / "iam-review"
RUN_IAM_SCAN: Path = SKILL / "scripts" / "run_iam_scan.py"
EXTRACT_POLICIES: Path = SKILL / "scripts" / "extract_policies.py"

#: Fixture paths are workspace-relative, because that is how they are passed to
#: the scripts and how the report must report them back.
#:
#: Dangerous IAM across several policy kinds.
DANGEROUS = "tests/fixtures/security/iam_dangerous_policies.yaml"

#: All nine ``PolicyKind`` values.
ALL_KINDS = "tests/fixtures/valid/iam_all_policy_kinds.yaml"

#: ``Fn::ImportValue``, a ``Ref`` to a defaulted parameter, and a policy document
#: written as a JSON string.
UNRESOLVABLE = "tests/fixtures/valid/iam_unresolvable_values.yaml"

#: Templates with no IAM-relevant resource, in both input formats.
NO_IAM = (
    "tests/fixtures/valid/minimal_compliant_template.yaml",
    "tests/fixtures/valid/minimal_template.json",
)

#: A Template that does not parse.
MALFORMED = "tests/fixtures/invalid/malformed_syntax.yaml"

#: A file with no ``Resources`` mapping.
NO_RESOURCES = "tests/fixtures/invalid/no_resources.yaml"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class Run:
    """One subprocess invocation, with stdout parsed if it is JSON."""

    def __init__(self, completed: "subprocess.CompletedProcess[str]") -> None:
        self.exit_code = completed.returncode
        self.stdout = completed.stdout
        self.stderr = completed.stderr

    @property
    def payload(self) -> Dict[str, Any]:
        """stdout decoded as JSON. Fails the test if stdout is not JSON."""
        assert self.stdout, "expected JSON on stdout, got nothing"
        return json.loads(self.stdout)


def invoke(script: Path, *args: str) -> Run:
    """Run ``script`` with the plugin root as the working directory.

    The working directory is the workspace root the scripts contain paths
    against, so fixture paths are given relative to it exactly as a client would
    give them.
    """
    completed = subprocess.run(
        [sys.executable, str(script), *args],
        cwd=str(PLUGIN_ROOT),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return Run(completed)


def scan(target: str) -> Run:
    return invoke(RUN_IAM_SCAN, "--target", target)


def extract(target: str) -> Run:
    return invoke(EXTRACT_POLICIES, "--target", target)


def layer1_findings(target: str) -> List[Any]:
    """Layer 1's own output for ``target``, computed without the scripts."""
    path = PLUGIN_ROOT / target
    doc = template.load_template(path.resolve()).doc
    return detectors.scan_sites(
        locate.find_policy_documents(doc),
        template_file=target,
        context=ResolutionContext.from_template(doc),
    ).findings


def rule_ids(findings: Sequence[Any]) -> List[str]:
    """``Evidence[0].RuleId`` of each Layer 1 Finding."""
    return [f.Evidence[0].RuleId for f in findings]


def evidence_rule_ids(payload: Dict[str, Any]) -> List[str]:
    """Every ``RuleId`` recorded in every Finding of a report."""
    return [
        entry["RuleId"]
        for item in payload["findings"]
        for entry in item["Evidence"]
    ]


# ---------------------------------------------------------------------------
# (a) run_iam_scan.py: Confirmed findings only
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("target", [DANGEROUS, ALL_KINDS, UNRESOLVABLE])
def test_every_finding_is_confirmed_and_attributed_to_iam_review(target: str) -> None:
    result = scan(target)

    assert result.exit_code == exitcodes.OK
    payload = result.payload
    assert payload["findings"], "fixture is expected to produce findings"
    for item in payload["findings"]:
        # Requirement 7 AC9: deterministic IAM pattern matching is Confirmed, and
        # this script emits nothing else -- Layer 2 findings arrive through
        # iac-review, never from here.
        assert item["Confidence"] == "Confirmed"
        assert item["Source"] == ["IAM Review"]
        assert item["Normalized_Category"] == "IAM"


@pytest.mark.parametrize("target", [DANGEROUS, ALL_KINDS, UNRESOLVABLE, *NO_IAM])
def test_report_is_valid_json_and_every_finding_satisfies_the_schema(
    target: str,
) -> None:
    payload = scan(target).payload

    assert sorted(payload) == sorted(report.REPORT_KEYS)
    assert payload["schema_version"] == report.SCHEMA_VERSION
    assert payload["sources_enabled"] == ["IAM Review"]
    # No external tool is launched, so there is no availability to report.
    assert payload["tools"] == []
    assert payload["errors"] == []
    assert payload["target"]["files"] == [target]

    for item in payload["findings"]:
        finding_module.validate(finding_module.from_dict(item))


def test_findings_are_numbered_from_one_and_sorted_by_severity() -> None:
    findings = scan(DANGEROUS).payload["findings"]

    assert [item["ID"] for item in findings] == list(range(1, len(findings) + 1))
    ranks = [finding_module.SEVERITIES.index(item["Severity"]) for item in findings]
    assert ranks == sorted(ranks)


def test_merged_findings_keep_every_detector_rule_id() -> None:
    # Findings are deduplicated per Template, which for a single Source merges
    # the detectors that matched one resource. The merge must preserve every
    # detector's Evidence: that is what answers "why is this CRITICAL".
    payload = scan(DANGEROUS).payload
    expected = rule_ids(layer1_findings(DANGEROUS))

    # Compared as sets, not multisets: a detector may record a second Evidence
    # entry under its own rule ID, as cross_account_principal does when an
    # sts:ExternalId condition mitigates it (Requirement 6 AC10).
    assert set(evidence_rule_ids(payload)) == set(expected)
    assert len(payload["findings"]) < len(expected), "merging is expected here"


def test_unresolvable_values_are_disclosed_as_informational_not_security() -> None:
    payload = scan(UNRESOLVABLE).payload
    disclosures = [
        item
        for item in payload["findings"]
        if any(
            entry["RuleId"] in ("unresolvable_value", "malformed_policy_document")
            for entry in item["Evidence"]
        )
    ]

    assert disclosures, "the fixture holds values that cannot be resolved"
    for item in disclosures:
        # A value that could not be evaluated is a coverage gap, not a risk, so
        # it is disclosed without asserting anything about its safety.
        assert item["FindingType"] == "Informational"
        assert item["Severity"] == "INFO"


def test_two_targets_share_one_report() -> None:
    result = invoke(RUN_IAM_SCAN, "--target", DANGEROUS, "--target", ALL_KINDS)
    payload = result.payload

    assert result.exit_code == exitcodes.OK
    assert payload["target"]["files"] == sorted([DANGEROUS, ALL_KINDS])
    assert payload["summary"]["total"] == len(payload["findings"])


def test_verbose_does_not_change_stdout() -> None:
    quiet = scan(DANGEROUS)
    verbose = invoke(RUN_IAM_SCAN, "--target", DANGEROUS, "--verbose")

    assert quiet.stdout == verbose.stdout
    assert quiet.stderr == ""
    assert "policy sites" in verbose.stderr


# ---------------------------------------------------------------------------
# (b) extract_policies.py: the Layer 2 input JSON
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("target", [DANGEROUS, ALL_KINDS, UNRESOLVABLE, *NO_IAM])
def test_inventory_has_the_documented_key_structure(target: str) -> None:
    result = extract(target)
    payload = result.payload

    assert result.exit_code == exitcodes.OK
    # design.md's spelling, written out here rather than read from the module, so
    # renaming a key in the implementation fails the published contract.
    assert sorted(payload) == [
        "attached_to",
        "deterministic_findings_summary",
        "policy_sites",
    ]
    assert sorted(payload) == sorted(iam.LAYER2_KEYS)

    for site in payload["policy_sites"]:
        # Key *sets*, not order: serialization sorts keys so that the bytes are a
        # function of the content (Requirement 16 AC11).
        assert sorted(site) == sorted(iam.POLICY_SITE_KEYS)
        assert isinstance(site["logical_id"], str) and site["logical_id"]
        assert site["kind"] in [kind.value for kind in locate.PolicyKind]
        assert site["json_path"].startswith("Resources.")
        assert site["statement_count"] == len(site["has_conditions"])
        for key in ("actions", "resources", "principals", "unresolvable_locations"):
            assert all(isinstance(text, str) for text in site[key])

    assert all(
        isinstance(referrers, list) for referrers in payload["attached_to"].values()
    )
    for entry in payload["deterministic_findings_summary"]:
        assert sorted(entry) == sorted(iam.SUMMARY_FINDING_KEYS)


def test_inventory_matches_the_shared_generator() -> None:
    # The script is a thin wrapper: its stdout must be the shared function's
    # output verbatim, so the Agent's view and the tested contract are one thing.
    doc = template.load_template((PLUGIN_ROOT / ALL_KINDS).resolve()).doc
    expected = iam.extract_policy_sites(doc, template_file=ALL_KINDS)

    assert extract(ALL_KINDS).payload == expected


def test_inventory_is_byte_identical_between_runs_and_verbose_modes() -> None:
    first = extract(ALL_KINDS)
    second = extract(ALL_KINDS)
    verbose = invoke(EXTRACT_POLICIES, "--target", ALL_KINDS, "--verbose")

    assert first.stdout == second.stdout == verbose.stdout
    assert first.stderr == ""
    assert "policy sites" in verbose.stderr


def test_unresolvable_locations_are_named_per_site() -> None:
    payload = extract(UNRESOLVABLE).payload
    located = [
        path
        for site in payload["policy_sites"]
        for path in site["unresolvable_locations"]
    ]

    assert located, "the fixture holds values that cannot be resolved"
    for path in located:
        assert path.startswith("Resources.")


def test_attached_to_names_the_resources_that_reference_each_owner() -> None:
    payload = extract(ALL_KINDS).payload
    attached = payload["attached_to"]
    owners = {site["logical_id"] for site in payload["policy_sites"]}

    assert set(attached) == owners
    # The fixture's AWS::IAM::Policy points at the Role through
    # `Roles: [!Ref AppExecutionRole]`, and that attachment is what tells the
    # Agent whose permissions the Role's policy really confers.
    assert "AppStandalonePolicy" in attached["AppExecutionRole"]


# ---------------------------------------------------------------------------
# (c) deterministic_findings_summary agrees with Layer 1
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("target", [DANGEROUS, ALL_KINDS, UNRESOLVABLE])
def test_summary_reports_exactly_what_layer_one_detected(target: str) -> None:
    summary = extract(target).payload["deterministic_findings_summary"]
    expected = [
        {"rule": f.Evidence[0].RuleId, "resource": f.Resource, "severity": f.Severity}
        for f in layer1_findings(target)
    ]

    assert summary == expected


def test_summary_covers_every_rule_the_scan_reported() -> None:
    # The two entry points must agree: a rule the scan reported but the summary
    # omitted would be a finding the Agent could restate as its own
    # (Requirement 2 AC14, AC15).
    scanned = {
        rule for rule in evidence_rule_ids(scan(DANGEROUS).payload)
    } - {"unresolvable_value", "malformed_policy_document"}
    summarized = {
        entry["rule"]
        for entry in extract(DANGEROUS).payload["deterministic_findings_summary"]
    }

    assert scanned == summarized


def test_summary_carries_no_prose_for_the_agent_to_paraphrase() -> None:
    for entry in extract(DANGEROUS).payload["deterministic_findings_summary"]:
        assert set(entry) == {"rule", "resource", "severity"}


# ---------------------------------------------------------------------------
# (d) a Template with no IAM
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("target", NO_IAM)
def test_template_without_iam_yields_no_findings_and_exit_zero(target: str) -> None:
    result = scan(target)
    payload = result.payload

    assert result.exit_code == exitcodes.OK
    assert payload["findings"] == []
    assert payload["errors"] == []
    assert payload["summary"]["total"] == 0
    assert payload["summary"]["passed_all_checks"] is True
    # Requirement 6 AC12: zero findings *with an informational message*, which is
    # a different result from a Template whose policies were examined and found
    # narrow. The report envelope has no field for it, so it is on stderr.
    assert detectors.NO_IAM_RESOURCES_MESSAGE in result.stderr


@pytest.mark.parametrize("target", NO_IAM)
def test_template_without_iam_yields_an_empty_inventory(target: str) -> None:
    result = extract(target)
    payload = result.payload

    assert result.exit_code == exitcodes.OK
    assert payload["policy_sites"] == []
    assert payload["attached_to"] == {}
    assert payload["deterministic_findings_summary"] == []


def test_template_with_narrow_policies_reports_no_informational_message() -> None:
    # ALL_KINDS does contain IAM, so the absence of the message distinguishes
    # "examined and clean" from "nothing to examine" even when both would
    # otherwise look alike to a reader of stderr.
    assert detectors.NO_IAM_RESOURCES_MESSAGE not in scan(ALL_KINDS).stderr


# ---------------------------------------------------------------------------
# Argument and failure handling, shared by both scripts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("script", [RUN_IAM_SCAN, EXTRACT_POLICIES])
def test_missing_target_exits_two_with_empty_stdout(script: Path) -> None:
    result = invoke(script)

    assert result.exit_code == exitcodes.INVALID_ARGUMENTS
    assert result.stdout == ""
    assert "--target" in result.stderr


@pytest.mark.parametrize("script", [RUN_IAM_SCAN, EXTRACT_POLICIES])
def test_target_outside_the_workspace_exits_seven_with_empty_stdout(
    script: Path,
) -> None:
    result = invoke(script, "--target", "../outside.yaml")

    assert result.exit_code == exitcodes.PATH_VIOLATION
    assert result.stdout == ""
    assert "path" in result.stderr.lower()


@pytest.mark.parametrize("script", [RUN_IAM_SCAN, EXTRACT_POLICIES])
def test_missing_target_file_exits_three_with_empty_stdout(script: Path) -> None:
    result = invoke(script, "--target", "tests/fixtures/valid/absent.yaml")

    assert result.exit_code == exitcodes.INPUT_NOT_FOUND
    assert result.stdout == ""


@pytest.mark.parametrize("script", [RUN_IAM_SCAN, EXTRACT_POLICIES])
def test_help_exits_zero_and_keeps_stdout_free_of_usage_text(script: Path) -> None:
    result = invoke(script, "--help")

    assert result.exit_code == exitcodes.OK
    assert result.stdout == ""
    assert "usage" in result.stderr


def test_unparsable_template_reports_the_failure_in_the_report() -> None:
    result = scan(MALFORMED)

    assert result.exit_code == exitcodes.PARSE_FAILURE
    payload = result.payload
    assert payload["findings"] == []
    assert [error["error_class"] for error in payload["errors"]] == ["parse_failure"]
    assert payload["errors"][0]["source"] == "IAM Review"
    # No Template was reviewed, so none is claimed under target.files.
    assert payload["target"]["files"] == []


def test_template_without_resources_exits_eight_with_an_error_entry() -> None:
    result = scan(NO_RESOURCES)

    assert result.exit_code == exitcodes.NO_REVIEWABLE_TEMPLATE
    assert [error["error_class"] for error in result.payload["errors"]] == [
        "no_reviewable_template"
    ]


@pytest.mark.parametrize("target", [MALFORMED, NO_RESOURCES])
def test_extract_policies_writes_nothing_to_stdout_on_failure(target: str) -> None:
    # The inventory object has no errors[] key, and an Agent handed a partly
    # populated inventory would reason about a Template it had only partly seen.
    result = extract(target)

    assert result.exit_code != exitcodes.OK
    assert result.stdout == ""
    assert result.stderr != ""


def test_neither_script_reads_stdin() -> None:
    # stdin is closed by `invoke`; a script that read it would fail rather than
    # produce a report. Asserted explicitly because Requirement 16 AC9 is about
    # behaviour that is invisible when it holds.
    for script in (RUN_IAM_SCAN, EXTRACT_POLICIES):
        result = invoke(script, "--target", ALL_KINDS)
        assert result.exit_code == exitcodes.OK
        assert result.stdout


# ---------------------------------------------------------------------------
# SKILL.md: the Layer 2 instructions this Skill is responsible for
# ---------------------------------------------------------------------------


SKILL_MD_TEXT = (SKILL / "SKILL.md").read_text(encoding="utf-8")


def test_skill_md_declares_the_five_layer_two_constraints() -> None:
    # Task 18.4 requires the constraints design.md places on Layer 2 to be stated
    # where the host Agent reads them. The structural checks every Skill's SKILL.md
    # shares live in tests/unit/test_skills.py; these are this Skill's own content.
    text = SKILL_MD_TEXT
    assert "deterministic_findings_summary" in text
    for phrase in (
        "Never claim `Confidence: \"Confirmed\"`",
        "non-empty `Excerpt`",
        "Phrase the finding as a possibility",
        "closed set",
    ):
        assert phrase in text
    assert '`["Agent Review"]`' in text
    # Constraint 5: the closed Category set is spelled out, so the Agent does not
    # have to guess which names are permitted (Requirement 14 AC1, AC3).
    for category in categories.load_map().categories:
        assert "`{0}`".format(category) in text


def test_skill_md_documents_the_agent_findings_envelope() -> None:
    text = SKILL_MD_TEXT
    assert '"schema_version": "1.0.0"' in text
    assert '"findings"' in text
    for confidence in ("Likely", "Contextual"):
        assert confidence in text


def test_skill_md_records_the_layer_two_limitations() -> None:
    text = SKILL_MD_TEXT
    for phrase in (
        "unresolvable_value",
        "IAM Access Analyzer",
        "No AWS API calls",
        "Resource-based policy coverage is a fixed list",
    ):
        assert phrase in text
