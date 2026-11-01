"""CI check of the Remediation Evidence Chain tests (Phase 2 M2 WP1).

    python3 .github/scripts/chain_ci_check.py --junit JUNIT_XML --expected tests/fixtures/chain_replay/expected.json

Source: docs/v2/phase2/m2/wp0/m2-work-plan.md §4 (the M2 CI job, independent of the M1 job) and
m2-acceptance-test-matrix.md (M2-01..M2-07, TC-00). Reads the JUnit report of ``tests/unit/test_chain_*.py``
and the expected file, and fails unless every required test ran and passed, nothing was skipped, the
expected file is well formed and the chain validator's source digest is the one the expected digests
were reviewed for. It never updates the expected file. It does not read or change the M1 expected
values (``tests/fixtures/evidence_replay/``) or the M1 check.

Exit codes (disjoint from ``evidence_ci_check.py`` 10-20 and the reserved chain codes 31-34):

==  =========================  ===============================================================
0   OK
40  CHECK_ERROR                the check could not run (unreadable JUnit or expected file)
41  EXPECTED_INVALID           the expected file is not ``iacreview.chain.replay-expected/1``
42  TEST_FAILURES              a test failed or errored, or the report has no test case
43  REQUIRED_TEST_MISSING      a required test did not run, or any chain test was skipped
44  SOURCE_MISMATCH            the chain validator source differs from the reviewed one
==  =========================  ===============================================================

Standard library only, plus the repository's own ``iacreview.chain`` (read for its source digest).
Writes a summary to ``$GITHUB_STEP_SUMMARY`` when set: digests and test names only, no path or content.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Sequence

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_FORMAT = "iacreview.chain.replay-expected/1"
GATE_EXPECTED_FORMAT = "iacreview.chain.replay-expected-gate/1"
GATE_EXPECTED_NAME = "expected-gate.json"  # next to --expected (WP2, D2-4: a separate anchor file)
GATE_SCENARIOS = {"gate-complete": "COMPLETE", "gate-not-proven": "NOT_PROVEN", "gate-broken": "BROKEN"}
EXIT = {"OK": 0, "CHECK_ERROR": 40, "EXPECTED_INVALID": 41, "TEST_FAILURES": 42, "REQUIRED_TEST_MISSING": 43, "SOURCE_MISMATCH": 44}
ORDER = ("EXPECTED_INVALID", "SOURCE_MISMATCH", "TEST_FAILURES", "REQUIRED_TEST_MISSING")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

#: Tests that must run and pass (file::function, parametrized cases folded). Fixed here, not read from
#: the test files, so that deleting a test fails this check.
REQUIRED_TESTS = (
    "tests/unit/test_chain_manifest.py::test_tc_01_01_valid_manifests_are_accepted",
    "tests/unit/test_chain_manifest.py::test_tc_01_02_key_order_and_whitespace_do_not_change_the_digest",
    "tests/unit/test_chain_manifest.py::test_tc_01_03_schema_violations_are_manifest_invalid",
    "tests/unit/test_chain_manifest.py::test_tc_01_03_strict_json_violations_are_manifest_invalid",
    "tests/unit/test_chain_manifest.py::test_tc_01_04_api_artifact_cannot_be_chosen",
    "tests/unit/test_chain_manifest.py::test_tc_01_05_unsafe_locator_text_is_outside_the_root",
    "tests/unit/test_chain_manifest.py::test_tc_01_05_a_symbolic_link_directory_is_outside_the_root",
    "tests/unit/test_chain_manifest.py::test_tc_01_06_a_manifest_over_the_size_limit_is_unreadable",
    "tests/unit/test_chain_links.py::test_tc_02_01_a_correct_chain_links_subject_and_contract",
    "tests/unit/test_chain_links.py::test_tc_02_02_a_head_that_does_not_descend_from_the_base_is_broken",
    "tests/unit/test_chain_links.py::test_tc_02_03_a_config_commit_after_the_base_is_broken",
    "tests/unit/test_chain_links.py::test_tc_02_08_a_contract_only_in_the_head_is_never_read",
    "tests/unit/test_chain_links.py::test_tc_02_09_hooks_filters_textconv_and_fsmonitor_never_run",
    "tests/unit/test_chain_links.py::test_tc_03_01_02_a_recomputed_report_is_linked_whatever_its_decision",
    "tests/unit/test_chain_links.py::test_tc_03_04_a_forged_decision_with_consistent_digests_is_broken",
    "tests/unit/test_chain_links.py::test_tc_03_08_a_missing_tool_makes_the_recomputation_unavailable",
    "tests/unit/test_chain_links.py::test_tc_03_09_a_validator_object_outside_the_schema_is_report_invalid",
    "tests/unit/test_chain_links.py::test_tc_03_10_one_identity_field_changed_is_linked_and_only_diagnosed",
    "tests/unit/test_chain_links.py::test_tc_03_11_an_identity_change_with_a_stale_digest_is_broken",
    "tests/unit/test_chain_links.py::test_tc_03_12_the_identity_diagnostic_stays_out_of_the_payload",
    "tests/unit/test_chain_links.py::test_tc_02_05_literal_a_one_byte_change_of_the_approved_contract_in_git",
    "tests/unit/test_chain_links.py::test_tc_05_03_literal_raw_and_store_manifest_rewritten_consistently",
    "tests/unit/test_chain_links.py::test_tc_04_02_errors_next_to_the_referenced_finding_are_incomplete",
    "tests/unit/test_chain_links.py::test_tc_04_08_the_chain_never_reads_the_pass_flag",
    "tests/unit/test_chain_links.py::test_tc_05_02_a_changed_raw_byte_fails_the_m1_integrity",
    "tests/unit/test_chain_links.py::test_tc_05_05_evidence_of_another_repository_is_broken",
    "tests/unit/test_chain_status.py::test_tc_06_01_every_combination_of_link_statuses_composes_by_the_rule",
    "tests/unit/test_chain_status.py::test_tc_06_04_an_error_inside_a_link_check_is_never_a_pass",
    "tests/unit/test_chain_status.py::test_tc_06_05_a_review_with_errors_keeps_the_chain_from_complete",
    "tests/unit/test_chain_status.py::test_tc_06_07_the_reserved_exit_codes_do_not_collide",
    "tests/unit/test_chain_replay.py::test_tc_07_01_four_runs_give_the_expected_payload_digest",
    "tests/unit/test_chain_replay.py::test_tc_07_01_four_runs_agree_and_keep_the_link_order",
    "tests/unit/test_chain_isolation.py::test_tc_00_01_the_m1_expected_values_and_sources_are_unchanged",
    "tests/unit/test_chain_isolation.py::test_tc_00_03_nothing_outside_the_chain_package_imports_it",
    "tests/unit/test_chain_mutations.py::test_every_chain_mutant_is_killed_in_an_isolated_copy",
    # WP2 (M2-08..M2-10, gate anchor)
    "tests/unit/test_chain_gate.py::test_tc_08_03_the_array_order_and_the_page_split_do_not_matter",
    "tests/unit/test_chain_gate.py::test_tc_08_04_a_forged_decision_is_broken",
    "tests/unit/test_chain_gate.py::test_tc_08_06_a_self_declared_approval_is_never_an_approval",
    "tests/unit/test_chain_gate.py::test_tc_08_07_a_source_outside_the_manifest_list_is_missing",
    "tests/unit/test_chain_gate.py::test_tc_08_11_a_missing_page_is_incomplete",
    "tests/unit/test_chain_gate.py::test_tc_08_11_the_page_sequence_rule",
    "tests/unit/test_chain_gate.py::test_tc_08_13_one_review_id_with_two_contents_is_a_conflict",
    "tests/unit/test_chain_gate.py::test_tc_08_15_conflicting_reviews_at_the_same_time_are_ambiguous",
    "tests/unit/test_chain_gate.py::test_tc_08_17_the_decision_table",
    "tests/unit/test_chain_gate.py::test_tc_08_18_login_avatar_and_email_never_leave_the_store",
    "tests/unit/test_chain_gate.py::test_tc_08_21_a_dismissal_acts_on_its_own_review_only",
    # WP2 review N2-2 / N2-3 (wp2-gate-record-decision-table.md G-02..G-13)
    "tests/unit/test_chain_gate.py::test_g_02_an_absent_record_file_is_missing_not_a_missing_raw",
    "tests/unit/test_chain_gate.py::test_g_04_a_record_outside_the_schema_is_invalid_not_a_self_declaration",
    "tests/unit/test_chain_gate.py::test_g_05_a_self_declaration_next_to_a_real_approval_is_not_hidden",
    "tests/unit/test_chain_gate.py::test_g_07_a_record_presented_twice_is_invalid_and_each_copy_is_compared",
    "tests/unit/test_chain_gate.py::test_g_09_a_reviewer_the_complete_raw_does_not_have_is_broken",
    "tests/unit/test_chain_gate.py::test_g_09_a_merge_decision_of_another_pull_is_broken",
    "tests/unit/test_chain_gate.py::test_g_10_g_11_a_record_whose_raw_cannot_be_read_is_never_broken_by_the_record",
    "tests/unit/test_chain_gate.py::test_g_13_a_record_left_out_is_missing_not_broken",
    "tests/unit/test_chain_gate.py::test_g_one_bad_record_among_good_ones_decides_the_gate",
    "tests/unit/test_chain_gate.py::test_g_several_bad_records_keep_every_cause",
    # WP2 final review items 3 and 4 (G-13a, G-05)
    "tests/unit/test_chain_gate.py::test_g_13a_the_primary_cause_is_not_doubled_by_a_secondary_missing_code",
    "tests/unit/test_chain_gate.py::test_g_05_the_three_self_declaration_forms",
    "tests/unit/test_chain_gate.py::test_g_05_other_fields_and_undefined_wording_are_not_self_declarations",
    "tests/unit/test_chain_gate.py::test_tc_09_02_an_approval_of_an_old_head_only_is_not_proven_not_broken",
    "tests/unit/test_chain_gate.py::test_tc_09_04_a_pr_head_after_the_chain_head_is_broken",
    "tests/unit/test_chain_gate.py::test_tc_09_11_a_record_that_moves_an_old_approval_to_the_head_is_broken",
    "tests/unit/test_chain_gate.py::test_tc_09_12_outstanding_changes_old_approvals_and_missing_pages_have_their_own_codes",
    "tests/unit/test_chain_gate.py::test_tc_10_02_the_authors_own_approval_is_recorded_but_not_counted",
    "tests/unit/test_chain_gate.py::test_tc_10_05_an_outstanding_change_request_is_never_complete",
    "tests/unit/test_chain_gate.py::test_tc_10_06_author_association_decides_nothing",
    "tests/unit/test_chain_gate.py::test_tc_10_07_a_full_chain_is_complete_and_claims_nothing_more",
    "tests/unit/test_chain_gate.py::test_tc_10_11_a_chain_without_gate_records_keeps_the_wp1_shape",
    "tests/unit/test_chain_gate_replay.py::test_gate_anchor_scenarios_meet_the_specification",
    "tests/unit/test_chain_gate_replay.py::test_gate_anchor_four_runs_give_the_expected_payload_digest",
)


class CheckError(Exception):
    pass


class Outcome:
    def __init__(self) -> None:
        self.failures: List[tuple] = []
        self.values: Dict[str, object] = {}

    def fail(self, name: str, message: str) -> None:
        self.failures.append((name, message))

    @property
    def exit_code(self) -> int:
        names = {n for n, _ in self.failures}
        for name in ORDER:
            if name in names:
                return EXIT[name]
        return 0


def check_expected(path: Path, out: Outcome) -> Optional[Dict[str, object]]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise CheckError("expected file {0} is unreadable".format(path.name)) from None
    problems = []
    if not isinstance(doc, dict) or set(doc) != {"expected_format", "validator_source_sha256", "scenarios", "note"}:
        problems.append("keys")
    elif doc["expected_format"] != EXPECTED_FORMAT or not _SHA256.match(str(doc["validator_source_sha256"])):
        problems.append("format or validator digest")
    elif not isinstance(doc["scenarios"], dict) or set(doc["scenarios"]) != {"sc01", "sc02"}:
        problems.append("scenarios")
    else:
        for name, entry in sorted(doc["scenarios"].items()):
            if (not isinstance(entry, dict) or set(entry) != {"chain_status", "manifest_sha256", "payload_sha256"}
                    or not _SHA256.match(str(entry["manifest_sha256"])) or not _SHA256.match(str(entry["payload_sha256"]))
                    or entry["chain_status"] not in ("BROKEN", "INCOMPLETE", "NOT_PROVEN", "COMPLETE")):
                problems.append(name)
    if problems:
        out.fail("EXPECTED_INVALID", "expected file problems: {0}".format(", ".join(problems)))
        return None
    return doc


def check_gate_expected(path: Path, wp1: Dict[str, object], out: Outcome) -> Optional[Dict[str, object]]:
    """The separate gate anchor: its own format, the three scenarios, and the same validator digest as the WP1 anchor."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        out.fail("EXPECTED_INVALID", "gate expected file {0} is missing or unreadable".format(path.name))
        return None
    problems = []
    if not isinstance(doc, dict) or set(doc) != {"expected_format", "validator_source_sha256", "scenarios", "note"}:
        problems.append("keys")
    elif doc["expected_format"] != GATE_EXPECTED_FORMAT or doc["validator_source_sha256"] != wp1["validator_source_sha256"]:
        problems.append("format or validator digest (must equal the WP1 anchor's)")
    elif not isinstance(doc["scenarios"], dict) or set(doc["scenarios"]) != set(GATE_SCENARIOS):
        problems.append("scenarios")
    else:
        for name, entry in sorted(doc["scenarios"].items()):
            if (not isinstance(entry, dict) or set(entry) != {"chain_status", "manifest_sha256", "payload_sha256"}
                    or not _SHA256.match(str(entry["manifest_sha256"])) or not _SHA256.match(str(entry["payload_sha256"]))
                    or entry["chain_status"] != GATE_SCENARIOS[name]):
                problems.append(name)
    if problems:
        out.fail("EXPECTED_INVALID", "gate expected file problems: {0}".format(", ".join(problems)))
        return None
    return doc


def check_source(expected: Dict[str, object], out: Outcome) -> None:
    sys.path.insert(0, str(ROOT))
    from iacreview.chain import validator

    current = validator.validator_source_sha256()
    out.values["validator_source_sha256"] = current
    if current != expected["validator_source_sha256"]:
        out.fail("SOURCE_MISMATCH", "chain validator source {0} != reviewed {1}".format(current, expected["validator_source_sha256"]))


def _node_id(case: ET.Element) -> str:
    cls, name = case.get("classname", ""), case.get("name", "")
    return "{0}.py::{1}".format(cls.replace(".", "/"), name.split("[", 1)[0])


def check_junit(path: Path, out: Outcome) -> None:
    try:
        tree = ET.parse(str(path))
    except (OSError, ET.ParseError):
        raise CheckError("JUnit report {0} is unreadable".format(path.name)) from None
    cases = list(tree.getroot().iter("testcase"))
    if not cases:
        out.fail("TEST_FAILURES", "the JUnit report has no test case")
        return
    seen: Dict[str, List[str]] = {}
    for case in cases:
        state = "passed"
        for child in case:
            if child.tag in ("failure", "error"):
                state = child.tag
            elif child.tag == "skipped" and state == "passed":
                state = "skipped"
        seen.setdefault(_node_id(case), []).append(state)
    failed = sorted(n for n, s in seen.items() if "failure" in s or "error" in s)
    if failed:
        out.fail("TEST_FAILURES", "{0} test(s) failed: {1}".format(len(failed), ", ".join(failed[:5])))
    skipped = sorted(n for n, s in seen.items() if "skipped" in s)
    if skipped:
        out.fail("REQUIRED_TEST_MISSING", "chain tests may not be skipped: {0}".format(", ".join(skipped[:5])))
    missing = [t for t in REQUIRED_TESTS if t not in seen]
    if missing:
        out.fail("REQUIRED_TEST_MISSING", "required tests did not run: {0}".format(", ".join(missing[:5])))
    out.values.update(test_cases=len(cases), skipped=len(skipped), required=len(REQUIRED_TESTS))


def summary(out: Outcome, expected: Optional[Dict[str, object]]) -> str:
    verdict = "FAILED (exit {0})".format(out.exit_code) if out.exit_code else "PASS for the checks this job runs"
    lines = ["## M2 remediation evidence chain (CI)", "", "* verdict: **{0}**".format(verdict),
             "* scope: WP1 (manifest, reason codes, chain status, five links) and WP2 (gate records, GV-1..GV-4, gate anchor)",
             "* WP2: gate records (GV-1..GV-4) are evaluated; COMPLETE means only that the evidence chain's references agree",
             "* approval authority, rule enforcement, merge permission and capture authenticity stay NOT_PROVEN",
             "* independent of the M1 evidence-integrity job; the M1 expected values are not read here", "",
             "| value | observed |", "| --- | --- |"]
    for key in ("validator_source_sha256", "test_cases", "required", "skipped", "gate_scenarios"):
        if key in out.values:
            lines.append("| {0} | `{1}` |".format(key, out.values[key]))
    scenarios = expected.get("scenarios") if expected else None
    if isinstance(scenarios, dict):
        for name, entry in sorted(scenarios.items()):
            lines.append("| expected {0} | `{1}` `{2}` |".format(name, entry["chain_status"], entry["payload_sha256"]))
    lines += ["", "### Failures", ""] + (["* {0}: {1}".format(n, m) for n, m in out.failures] or ["* none"])
    return "\n".join(lines) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="CI check of the M2 chain tests")
    parser.add_argument("--junit", required=True)
    parser.add_argument("--expected", required=True)
    args = parser.parse_args(argv)
    out = Outcome()
    expected: Optional[Dict[str, object]] = None
    try:
        expected = check_expected(Path(args.expected), out)
        if expected is not None:
            check_source(expected, out)
            gate = check_gate_expected(Path(args.expected).with_name(GATE_EXPECTED_NAME), expected, out)
            if gate is not None:
                out.values["gate_scenarios"] = len(gate["scenarios"])  # type: ignore[arg-type]
        check_junit(Path(args.junit), out)
    except CheckError as exc:
        sys.stderr.write("chain check error: {0}\n".format(exc))
        return EXIT["CHECK_ERROR"]
    text = summary(out, expected)
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(text)
    sys.stdout.write(text)
    return out.exit_code


if __name__ == "__main__":
    sys.exit(main())
