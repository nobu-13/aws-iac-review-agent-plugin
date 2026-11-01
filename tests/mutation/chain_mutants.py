"""Mutation harness for the Remediation Evidence Chain (Phase 2 M2: WP1 MU2-01..20, WP2 MU2-21..29 and MU2-33..62). Not a test module.

    python3 tests/mutation/chain_mutants.py [--json OUT]

Same method as ``tests/mutation/evidence_mutants.py`` (M1): for each mutant, copy the plugin files the
kill tests need into a fresh temporary directory, apply the mutant's text edits to the *copy* (the work
tree is never changed), run the mutant's kill tests there and record whether they failed (killed). A
baseline run of every kill test on the unmutated copy must pass first. Each edit must match its source
exactly once. Source of the mutant list: docs/v2/phase2/m2/wp0/m2-acceptance-test-matrix.md §13.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[2]
C = "iacreview/chain/"
U = "tests/unit/"
M = U + "test_chain_manifest.py::"
L = U + "test_chain_links.py::"
S = U + "test_chain_status.py::"
R = U + "test_chain_replay.py::"
G = U + "test_chain_gate.py::"


@dataclass(frozen=True)
class Mutant:
    mutant_id: str
    condition: str
    edits: Tuple[Tuple[str, str, str], ...]  # (file, exact old text, new text)
    kill_tests: Tuple[str, ...]
    expected_failure: str


MUTANTS: Tuple[Mutant, ...] = (
    Mutant("MU2-01", "the manifest's unknown-key check is removed",
           ((C + "manifest.py", "    if not isinstance(value, dict) or set(value) != set(keys):",
             "    if not isinstance(value, dict) or not set(keys) <= set(value):"),),
           (M + "test_tc_01_03_schema_violations_are_manifest_invalid",),
           "an unknown key at any level must be manifest_invalid"),
    Mutant("MU2-02", "the locator containment check is removed",
           ((C + "manifest.py", '    return all(seg not in (".", "..") and _SEGMENT.match(seg) is not None for seg in value.split("/"))',
             "    return True"),),
           (M + "test_tc_01_05_unsafe_locator_text_is_outside_the_root",),
           "a locator with .., an absolute path or a backslash must be locator_outside_root"),
    Mutant("MU2-03", "canonicalization keeps the input key order",
           ((C + "manifest.py", "    return hashlib.sha256(remediation_report.canonical(value)).hexdigest()",
             '    return hashlib.sha256(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")).hexdigest()'),),
           (M + "test_tc_01_02_key_order_and_whitespace_do_not_change_the_digest",),
           "a reordered manifest must have the same digest"),
    Mutant("MU2-04", "the base -> head ancestry check is inverted",
           ((C + "links.py", "        if not gitsnap.is_ancestor(ctx.repo, base, head):", "        if gitsnap.is_ancestor(ctx.repo, base, head):"),),
           (L + "test_tc_02_01_a_correct_chain_links_subject_and_contract",
            L + "test_tc_02_02_a_head_that_does_not_descend_from_the_base_is_broken"),
           "a correct chain must link and a reversed subject must be BROKEN"),
    Mutant("MU2-05", "the contract is read from the head instead of the config commit",
           ((C + "links.py", "        entry = gitsnap.commit_snapshot(ctx.repo, config).entries.get(path)",
             '        entry = gitsnap.commit_snapshot(ctx.repo, ctx.doc["subject"]["head_commit"]).entries.get(path)'),),
           (L + "test_tc_02_08_a_contract_only_in_the_head_is_never_read",),
           "a contract present only in the head must be contract_blob_missing"),
    Mutant("MU2-06", "the contract is not compared with the verification report",
           ((C + "links.py", "    if ctx.report is not None:\n        trust = ctx.report", "    if False:\n        trust = ctx.report"),),
           (L + "test_tc_02_07_a_report_naming_another_contract_digest_is_broken",),
           "a report naming another contract digest must be contract_mismatch_with_report"),
    Mutant("MU2-07", "the verification is not recomputed (the report is trusted)",
           ((C + "links.py", "    again, unavailable = recompute(ctx)", '    again, unavailable = ctx.report["payload"], None'),),
           (L + "test_tc_03_04_a_forged_decision_with_consistent_digests_is_broken",),
           "a forged VERIFIED with consistent digests must be payload_digest_mismatch"),
    Mutant("MU2-08", "a VERIFIED decision links the verification by itself",
           ((C + "links.py", '    res.observed["execution_mode"] = payload["execution_mode"]\n',
             '    res.observed["execution_mode"] = payload["execution_mode"]\n    if payload["decision"] == "VERIFIED":\n        return res\n'),),
           (L + "test_tc_03_04_a_forged_decision_with_consistent_digests_is_broken",),
           "the decision must never raise the link status"),
    Mutant("MU2-09", "a recomputation without its tools is LINKED",
           ((C + "links.py", '    if again is None:\n        res.add("recompute_unavailable")\n        return res',
             "    if again is None:\n        return res"),),
           (L + "test_tc_03_08_a_missing_tool_makes_the_recomputation_unavailable",),
           "a missing cfn-guard must be recompute_unavailable (NOT_PROVEN)"),
    Mutant("MU2-10", "the review's errors[] is not checked",
           ((C + "links.py", "    if checked.errors:\n", "    if False:\n"),),
           (L + "test_tc_04_02_errors_next_to_the_referenced_finding_are_incomplete",),
           "a review with errors[] must be review_report_has_errors"),
    Mutant("MU2-11", "review completeness is decided by the summary's pass flag",
           ((C + "links.py", "    for code in review_evidence_complete(checked):",
             '    for code in ([] if obj["summary"].get("passed_all' + '_checks") is False else review_evidence_complete(checked)):'),),
           (L + "test_tc_04_02_errors_next_to_the_referenced_finding_are_incomplete", L + "test_tc_04_08_the_chain_never_reads_the_pass_flag"),
           "the pass flag must never be read"),
    Mutant("MU2-12", "the finding digest is not compared",
           ((C + "links.py", '        if mf.canonical_sha256(raw) != ref_f["finding_sha256"]:', "        if False:"),),
           (L + "test_tc_04_05_a_changed_finding_is_broken",),
           "a changed finding must be finding_digest_mismatch"),
    Mutant("MU2-13", "the M1 integrity result is ignored",
           ((C + "links.py", '    if result["overall_status"] != "PASS":', "    if False:"),),
           (L + "test_tc_05_02_a_changed_raw_byte_fails_the_m1_integrity",),
           "a changed raw byte must be integrity_not_pass"),
    Mutant("MU2-14", "the repository of the evidence is not compared",
           ((C + "links.py", '            if not isinstance(repo, str) or repository_id(repo) != ctx.doc["repository_id"]:', "            if False:"),),
           (L + "test_tc_05_05_evidence_of_another_repository_is_broken",),
           "evidence of another repository must be repository_mismatch"),
    Mutant("MU2-15", "INCOMPLETE and NOT_PROVEN swap priority",
           ((C + "status.py", "_RANK: Dict[str, int] = {BROKEN: 3, INCOMPLETE: 2, NOT_PROVEN: 1}",
             "_RANK: Dict[str, int] = {BROKEN: 3, INCOMPLETE: 1, NOT_PROVEN: 2}"),),
           (S + "test_tc_06_01_every_combination_of_link_statuses_composes_by_the_rule",),
           "INCOMPLETE must outrank NOT_PROVEN"),
    Mutant("MU2-16", "NOT_PRESENT counts as LINKED",
           ((C + "status.py", "        if value == LINKED:\n            continue", "        if value in (LINKED, NOT_PRESENT):\n            continue"),),
           (S + "test_tc_06_01_every_combination_of_link_statuses_composes_by_the_rule",),
           "a link that is not present must keep the chain from COMPLETE"),
    Mutant("MU2-17", "an error inside a link check passes silently",
           ((C + "validator.py", '        res = lk.LinkResult(link)\n        res.add("link_check_error")\n        return res',
             "        return lk.LinkResult(link)"),),
           (S + "test_tc_06_04_an_error_inside_a_link_check_is_never_a_pass",),
           "an exception must be link_check_error (INCOMPLETE)"),
    Mutant("MU2-18", "a VERIFIED decision hides an incomplete review in the chain status",
           ((C + "validator.py", '    statuses = {r["link"]: r["status"] for r in links}\n',
             '    statuses = {r["link"]: r["status"] for r in links}\n'
             '    if any(r.observed.get("decision") == "VERIFIED" for r in results):\n        statuses["review"] = st.LINKED\n'),),
           (S + "test_tc_06_05_a_review_with_errors_keeps_the_chain_from_complete",),
           "an incomplete review must keep the chain INCOMPLETE whatever the decision"),
    Mutant("MU2-19", "the payload carries the run time",
           ((C + "validator.py", '        "chain_status": chain,\n', '        "chain_status": chain,\n        "generated_at": repr(time.time()),\n'),),
           (R + "test_tc_07_01_four_runs_agree_and_keep_the_link_order",),
           "four runs must give the same payload digest"),
    Mutant("MU2-20", "the link order is not fixed",
           ((C + "validator.py", "    return [out[name] for name in st.LINKS]", "    return sorted(out.values(), key=lambda r: r.status)"),),
           (R + "test_tc_07_01_four_runs_agree_and_keep_the_link_order",),
           "the links must be in the fixed order"),
    # --- WP2 (m2-acceptance-test-matrix.md rev2 §13, §13-2). MU2-30..32 belong to WP4.
    Mutant("MU2-21", "a presented gate record is not compared with the regeneration",
           ((C + "gate.py", "        if mf.canonical_sha256(rec) != mf.canonical_sha256(regenerated):", "        if False:"),),
           (G + "test_tc_08_04_a_forged_decision_is_broken",), "a forged decision must be gate_record_mismatch"),
    Mutant("MU2-22", "a record outside the schema is read as a record",
           ((C + "gate.py", "        if not record_schema_ok(rec):\n            if states_an_approval(rec):",
             "        if False:\n            if states_an_approval(rec):"),),
           (G + "test_tc_08_06_a_self_declared_approval_is_never_an_approval",), "a self-declaration must be approval_self_declared_only"),
    Mutant("MU2-23", "the actor reference is the raw user id instead of the pseudonym",
           ((C + "gate.py", '    return "u:" + hashlib.sha256(str(user_id).encode("ascii")).hexdigest()[:12]', '    return "u:" + str(user_id)'),),
           (G + "test_tc_09_01_approval_contract_and_pr_head_agree",), "records must carry the u:<12 hex> pseudonym"),
    Mutant("MU2-24", "the approval commit is not compared with the head",
           ((C + "gate.py", "        effective = [r for r in distinct if r.deciding is not None and r.deciding.commit_id == head]",
             "        effective = list(distinct)"),),
           (G + "test_tc_09_02_an_approval_of_an_old_head_only_is_not_proven_not_broken",), "an old-head approval must not count"),
    Mutant("MU2-25", "a confirmed PR head mismatch is lowered to NOT_PROVEN",
           ((C + "gate.py", '        add("staleness", "pr_head_mismatch")', '        add("staleness", "approval_revision_unverifiable")'),),
           (G + "test_tc_09_04_a_pr_head_after_the_chain_head_is_broken",), "a PR head after the chain head must be BROKEN"),
    Mutant("MU2-26", "a missing pull answer passes staleness",
           ((C + "gate.py", '        add("staleness", "approval_revision_unverifiable")\n    elif facts.pr_head != head:',
             "        pass\n    elif facts.pr_head != head:"),),
           (G + "test_tc_09_07_without_the_pr_head_staleness_is_not_proven",), "no pull answer must be NOT_PROVEN"),
    Mutant("MU2-27", "the PR author's own approval counts",
           ((C + "gate.py", "    distinct = [r for r in approved if facts.pr_author is not None and r.user_id != facts.pr_author]",
             "    distinct = list(approved)"),),
           (G + "test_tc_10_02_the_authors_own_approval_is_recorded_but_not_counted",), "a self-approval must be separation_of_duty_not_shown"),
    Mutant("MU2-28", "a COMMENTED review counts as an approval",
           ((C + "gate.py", 'DECIDING = ("APPROVED", "CHANGES_REQUESTED")', 'DECIDING = ("APPROVED", "CHANGES_REQUESTED", "COMMENTED")'),
            (C + "gate.py", '    decided = "approved" if last.state == "APPROVED" else "changes_requested"',
             '    decided = "approved" if last.state in ("APPROVED", "COMMENTED") else "changes_requested"')),
           (G + "test_tc_10_04_no_approval_is_not_proven",), "a comment must not be an approval"),
    Mutant("MU2-29", "merge enforcement disappears from not_claimed",
           ((C + "status.py", '    "merge_enforcement",\n', ""),),
           (S + "test_tc_06_07_not_claimed_is_always_the_seven_items", G + "test_tc_10_07_a_full_chain_is_complete_and_claims_nothing_more"),
           "not_claimed must always hold merge_enforcement"),
    Mutant("MU2-33", "the aggregation follows the API array order",
           ((C + "gate.py", "    for _, review in sorted(by_id.values(), key=lambda x: x[1].review_id):", "    for _, review in by_id.values():"),
            (C + "gate.py", "    deciding = sorted((r for r in ordering if r.state in DECIDING), key=lambda r: r.key)",
             "    deciding = [r for r in ordering if r.state in DECIDING]")),
           (G + "test_tc_08_03_the_array_order_and_the_page_split_do_not_matter",), "the result must not depend on the array order"),
    Mutant("MU2-34", "a dismissed review is read as the approval it was",
           ((C + "gate.py", "    return Review(rid, state, uid, submitted, commit, assoc if assoc in ASSOCIATIONS else None)",
             '    return Review(rid, "APPROVED" if state == "DISMISSED" else state, uid, submitted, commit, assoc if assoc in ASSOCIATIONS else None)'),),
           (G + "test_tc_10_04_no_approval_is_not_proven", G + "test_tc_08_21_a_dismissal_acts_on_its_own_review_only"),
           "a dismissed review must not be an approval"),
    Mutant("MU2-35", "a later COMMENTED review resets the reviewer to none",
           ((C + "gate.py", "    last = deciding[-1]\n", '    last = deciding[-1]\n    if any(r.state == "COMMENTED" and r.key > last.key for r in reviews):\n        return none\n'),),
           (G + "test_tc_08_17_the_decision_table",), "R-02: a comment after an approval keeps the approval"),
    Mutant("MU2-36", "a PENDING review counts as an approval",
           ((C + "gate.py", "    return Review(rid, state, uid, submitted, commit, assoc if assoc in ASSOCIATIONS else None)",
             '    return Review(rid, "APPROVED" if state == "PENDING" else state, uid, submitted or "2026-12-31T00:00:00Z", commit, assoc if assoc in ASSOCIATIONS else None)'),),
           (G + "test_tc_10_04_no_approval_is_not_proven",), "a pending review must not be an approval"),
    Mutant("MU2-37", "a duplicated page number is accepted",
           ((C + "gate.py", "    if len(set(indexes)) != len(indexes):  # E-5 duplicate", "    if False:  # E-5 duplicate"),),
           (G + "test_tc_08_12_a_duplicated_page_number_is_a_duplicate", G + "test_tc_08_11_the_page_sequence_rule"),
           "a duplicated page must be review_capture_duplicate"),
    Mutant("MU2-38", "a gap in the page numbers is accepted",
           ((C + "gate.py", "    if list(indexes) != list(range(1, len(indexes) + 1)):  # E-5 gap", "    if False:  # E-5 gap"),),
           (G + "test_tc_08_11_the_page_sequence_rule",), "a missing page must be review_capture_incomplete (not left to M1 V5 alone)"),
    Mutant("MU2-39", "the later of two conflicting reviews wins",
           ((C + "gate.py", '            agg.integrity.append("review_capture_duplicate" if seen[0] == canon else "review_conflict")\n            agg.usable = False\n            continue',
             "            by_id[review.review_id] = (canon, review)\n            continue"),),
           (G + "test_tc_08_13_one_review_id_with_two_contents_is_a_conflict",), "conflicting reviews must be review_conflict"),
    Mutant("MU2-40", "evidence the manifest does not name is used",
           ((C + "gate.py", "        named = [m for m in members if m[0] in listed]", "        named = list(members)"),
            (C + "gate.py", '        elif src["store_revision"] != revision or not set(src["evidence_ids"]) <= listed:',
             '        elif src["store_revision"] != revision:')),
           (G + "test_tc_08_07_a_source_outside_the_manifest_list_is_missing",), "unlisted evidence must be gate_source_missing"),
    Mutant("MU2-41", "GV-2 requires an author_association",
           ((C + "gate.py", '    approved = [r for r in reviewers if r.state == "approved"]\n',
             '    approved = [r for r in reviewers if r.state == "approved" and r.author_association in ("OWNER", "MEMBER", "COLLABORATOR")]\n'),),
           (G + "test_tc_10_06_author_association_decides_nothing",), "author_association must decide nothing"),
    Mutant("MU2-42", "conflicting reviews at the same time are decided silently",
           ((C + "gate.py", "        if len(states) > 1:  # R-10, R-23", "        if False:  # R-10, R-23"),),
           (G + "test_tc_08_15_conflicting_reviews_at_the_same_time_are_ambiguous",), "same-time conflicts must be review_order_ambiguous"),
    Mutant("MU2-43", "approval authority is shown when the accounts are separate",
           ((C + "gate.py", '    res.observed["approval_authority"] = st.NOT_PROVEN',
             '    res.observed["approval_authority"] = "SHOWN" if not aspects["account_separation"] else st.NOT_PROVEN'),),
           (G + "test_tc_10_01_another_account_approving_the_head_is_linked_but_not_authority",), "approval authority must stay NOT_PROVEN"),
    Mutant("MU2-44", "the validator identity shape is not checked (WP1 N-5)",
           ((C + "links.py", '    if validator_identity_problems(payload.get(_VALIDATOR_KEY)):\n        res.add("report_invalid")\n        return',
             "    if False:\n        res.add(\"report_invalid\")\n        return"),),
           (L + "test_tc_03_09_a_validator_object_outside_the_schema_is_report_invalid",), "a bad validator object must be report_invalid"),
    Mutant("MU2-45", "the validator identity diagnostic leaks into the payload (WP1 N-5)",
           ((C + "links.py", "    res.diagnostics.append(identity_diagnostic(payload[_VALIDATOR_KEY], again[_VALIDATOR_KEY] if again is not None else None))\n",
             "    res.diagnostics.append(identity_diagnostic(payload[_VALIDATOR_KEY], again[_VALIDATOR_KEY] if again is not None else None))\n"
             '    res.observed["validator_identity_check"] = res.diagnostics[-1]["code"]\n'),),
           (L + "test_tc_03_12_the_identity_diagnostic_stays_out_of_the_payload",), "the diagnostic must stay out of the payload"),
    Mutant("MU2-46", "an approval of any recorded commit counts",
           ((C + "gate.py", "        effective = [r for r in distinct if r.deciding is not None and r.deciding.commit_id == head]",
             "        effective = [r for r in distinct if r.deciding is not None and r.deciding.commit_id is not None]"),),
           (G + "test_tc_09_02_an_approval_of_an_old_head_only_is_not_proven_not_broken",), "an old-head approval must not count"),
    Mutant("MU2-47", "an old approval is BROKEN (R2-1 over-reaction)",
           ((C + "gate.py", '                add("revision_binding", "approval_on_previous_head_only")', '                add("revision_binding", "gate_binds_other_commit")'),),
           (G + "test_tc_09_02_an_approval_of_an_old_head_only_is_not_proven_not_broken",), "an old approval must be NOT_PROVEN, not BROKEN"),
    Mutant("MU2-48", "a misrecorded approval revision is not reported",
           ((C + "gate.py", '            if rec["kind"] == "candidate_review" and rec["binds_to"]["commit"] != regenerated["binds_to"]["commit"]:',
             "            if False:"),),
           (G + "test_tc_09_11_a_record_that_moves_an_old_approval_to_the_head_is_broken",), "a forged revision must be approval_revision_misrecorded"),
    Mutant("MU2-49", "a dismissal clears every review of the reviewer",
           ((C + "gate.py", "    none = ReviewerState(uid, \"none\", None, latest_assoc)\n",
             "    none = ReviewerState(uid, \"none\", None, latest_assoc)\n    if any(r.state == \"DISMISSED\" for r in ordering):\n        return none\n"),),
           (G + "test_tc_08_17_the_decision_table",), "R-06: a dismissal before an approval must not clear the approval"),
    Mutant("MU2-50", "a later dismissed review is ignored",
           ((C + "gate.py", '    if any(r.state == "DISMISSED" and r.key > last.key for r in ordering):  # R-20', "    if False:  # R-20"),),
           (G + "test_tc_08_19_a_later_dismissed_review_makes_the_reviewer_unknown",), "R-20 must be review_dismissal_effect_unknown"),
    # --- WP2 review N2-2 / N2-3 (docs/v2/phase2/m2/wp2/wp2-gate-record-decision-table.md G-02..G-13; proposed matrix §13 rows)
    Mutant("MU2-51", "a record the raw gives is left out without a code",
           ((C + "gate.py", '  # G-13: left out, nothing contradicted\n            add("integrity", "gate_record_missing")',
             "  # G-13: left out, nothing contradicted\n            pass"),),
           (G + "test_g_13_a_record_left_out_is_missing_not_broken",), "a left-out record must be gate_record_missing"),
    Mutant("MU2-52", "a record left out is BROKEN although nothing is contradicted (rev1 N2-2)",
           ((C + "gate.py", '  # G-13: left out, nothing contradicted\n            add("integrity", "gate_record_missing")',
             '  # G-13: left out, nothing contradicted\n            add("integrity", "gate_record_mismatch")'),),
           (G + "test_g_13_a_record_left_out_is_missing_not_broken",), "a left-out record must be INCOMPLETE, not BROKEN"),
    Mutant("MU2-53", "a record the complete raw contradicts is not BROKEN",
           ((C + "gate.py", '            if rec["kind"] in facts.complete:  # G-09', "            if False:  # G-09"),),
           (G + "test_g_09_a_reviewer_the_complete_raw_does_not_have_is_broken",), "a ghost reviewer must be gate_record_mismatch"),
    Mutant("MU2-54", "every schema violation is a self-declaration (rev1 N2-3)",
           ((C + "gate.py", "            if states_an_approval(rec):  # G-05 self-declaration", "            if True:  # G-05 self-declaration"),),
           (G + "test_g_04_a_record_outside_the_schema_is_invalid_not_a_self_declaration",), "a schema violation must be gate_record_invalid"),
    Mutant("MU2-55", "a real approval hides a self-declaration",
           ((C + "gate.py", "    if self_declared:  # G-05, whatever the other records show",
             "    if self_declared and not backed_approval:  # G-05, whatever the other records show"),),
           (G + "test_g_05_a_self_declaration_next_to_a_real_approval_is_not_hidden",), "a self-declaration must never be hidden"),
    Mutant("MU2-56", "a record presented twice is accepted",
           ((C + "gate.py", "        if key in keys:  # G-07", "        if False:  # G-07"),),
           (G + "test_g_07_a_record_presented_twice_is_invalid_and_each_copy_is_compared",), "a repeated record must be gate_record_invalid"),
    Mutant("MU2-57", "an absent record file is reported as a missing raw source",
           ((C + "gate.py", '"gate_record_missing" if exc.kind == "missing" else "gate_record_invalid"',
             '"gate_source_missing" if exc.kind == "missing" else "gate_record_invalid"'),),
           (G + "test_g_02_an_absent_record_file_is_missing_not_a_missing_raw",), "an absent record must be gate_record_missing"),
    Mutant("MU2-58", "any presented review record stands in for a raw-backed approval (rev1 GV-4)",
           ((C + "gate.py", "    if self_declared and not backed_approval:  # an approval record the raw backs",
             '    if self_declared and not any(rec["kind"] == "candidate_review" for _, rec in presented):  # an approval record the raw backs'),),
           (G + "test_tc_08_06_a_self_declared_approval_is_never_an_approval",), "GV-4 needs a raw-backed approval record"),
    Mutant("MU2-59", "a good record hides the codes of the bad ones",
           ((C + "gate.py", "    for code in read.codes:\n", "    for code in (read.codes if not read.good else []):\n"),),
           (G + "test_g_one_bad_record_among_good_ones_decides_the_gate",), "one bad record must decide the gate"),
    # --- WP2 final review items 3 and 4 (decision table G-13a, G-05; proposed, Human approval pending)
    Mutant("MU2-60", "the secondary left-out record of an unusable entry gets its own code (doubles the primary cause)",
           ((C + "gate.py", "        if count > read.unusable.get(kind, 0):  # G-13", "        if count > 0:  # G-13"),),
           (G + "test_g_13a_the_primary_cause_is_not_doubled_by_a_secondary_missing_code",), "a secondary effect must add no code"),
    Mutant("MU2-61", "any key that starts with approv is a self-declaration (rev2 rule, false positives)",
           ((C + "gate.py", "    return any(isinstance(value.get(k), (str, list)) and len(value[k]) > 0 for k in APPROVER_KEYS)",
             '    return any(str(k).lower().startswith("approv") for k in value)'),),
           (G + "test_g_05_other_fields_and_undefined_wording_are_not_self_declarations",), "a non-approval field must not be a self-declaration"),
    Mutant("MU2-62", "a self-declaration in place of a record hides the left-out record (status becomes weaker)",
           ((C + "gate.py", "                out.self_declared = True\n",
             '                out.self_declared = True\n                out.unusable[str(entry.get("kind"))] = out.unusable.get(str(entry.get("kind")), 0) + 1\n'),),
           (G + "test_g_13a_the_primary_cause_is_not_doubled_by_a_secondary_missing_code",), "a self-declaration must never weaken the gate"),
)

COPY = ("iacreview", "skills", "rules", "tests/unit", "tests/conftest.py", "tests/remediation_bench", "tests/fixtures/chain_replay",
        "tests/fixtures/evidence_replay", "benchmark/remediation", "plugin.json", "pyproject.toml", ".github/scripts/evidence_ci_check.py")


def _copy_tree(dest: Path) -> None:
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache", ".mypy_cache")
    for rel in COPY:
        src, dst = ROOT / rel, dest / rel
        if not src.exists():
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(str(src), str(dst), ignore=ignore, symlinks=True)
        else:
            shutil.copyfile(str(src), str(dst))


def edit_problems(m: Mutant, root: Path = ROOT) -> List[str]:
    out = []
    for f, old, _ in m.edits:
        n = (root / f).read_text(encoding="utf-8").count(old)
        if n != 1:
            out.append("{0}: {1} matches {2} times in {3}".format(m.mutant_id, old[:50], n, f))
    return out


def _apply(m: Mutant, root: Path) -> None:
    for f, old, new in m.edits:
        path = root / f
        text = path.read_text(encoding="utf-8")
        assert text.count(old) == 1, (m.mutant_id, f)
        path.write_text(text.replace(old, new), encoding="utf-8")


def _pytest(root: Path, tests: Sequence[str]) -> Tuple[int, str, str]:
    # As the M1 harness: the copy is first on the path, and the parent's coverage run does not measure the copy.
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(root))
    env.pop("COV_CORE_SOURCE", None)
    out = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-x", *tests], cwd=str(root), env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1800, check=False)
    return out.returncode, out.stdout.decode("utf-8", "replace")[-4000:], out.stderr.decode("utf-8", "replace")[-2000:]


def run(mutants: Sequence[Mutant] = MUTANTS) -> Dict[str, object]:
    tests = sorted({t for m in mutants for t in m.kill_tests})
    with tempfile.TemporaryDirectory(prefix="chain-mutants-") as tmp:
        base = Path(tmp) / "baseline"
        _copy_tree(base)
        code, out, err = _pytest(base, tests)
        result: Dict[str, object] = {"baseline": {"exit_code": code, "tests": len(tests)}, "mutants": []}
        if code != 0:
            result["baseline"]["output"] = out + err  # type: ignore[index]
            result.update(total=len(mutants), killed=0)
            return result
        records = []
        for m in mutants:
            work = Path(tmp) / m.mutant_id
            _copy_tree(work)
            _apply(m, work)
            mcode, mout, _ = _pytest(work, m.kill_tests)
            # Killed only by a failing test (exit 1), not by a crash or a collection error.
            records.append({"mutant_id": m.mutant_id, "condition": m.condition, "exit_code": mcode, "killed": mcode == 1,
                            "expected_failure": m.expected_failure})
            shutil.rmtree(str(work), ignore_errors=True)
        result["mutants"] = records
        result.update(total=len(records), killed=sum(1 for r in records if r["killed"]))
        return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Phase 2 M2 WP1 chain mutation harness")
    parser.add_argument("--json", help="write the result as JSON to this new file")
    args = parser.parse_args(argv)
    problems = [p for m in MUTANTS for p in edit_problems(m)]
    if problems:
        print("\n".join(problems))
        return 2
    result = run()
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.json:
        with open(args.json, "x", encoding="utf-8") as handle:
            handle.write(text + "\n")
    print("baseline exit {0}; killed {1} / {2}".format(result["baseline"]["exit_code"], result["killed"], result["total"]))  # type: ignore[index]
    return 0 if result["baseline"]["exit_code"] == 0 and result["killed"] == result["total"] else 1  # type: ignore[index]


if __name__ == "__main__":
    sys.exit(main())
