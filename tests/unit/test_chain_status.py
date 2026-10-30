"""M2-06: Chain Status composition and fail-closed behaviour (Phase 2 M2 WP1).

Source: docs/v2/phase2/m2/wp0/m2-acceptance-test-matrix.md (TC-06-01..TC-06-07), m2-schemas.md rev1 §3, §4.
The composition rule is checked exhaustively against an independent reference written here; the
integration cases run the whole validator on synthetic chains.
"""

from __future__ import annotations

import copy
import importlib.util
import itertools
import json
from pathlib import Path
from typing import Dict, Mapping

import pytest

import chain_synth as cs
from iacreview import exitcodes
from iacreview.chain import links as lk
from iacreview.chain import status as st
from iacreview.chain import validator
from iacreview.remediation import rschema

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    cs.block_network(monkeypatch)


def reference(statuses: Mapping[str, str]) -> str:
    """The rule as the spec states it, written independently of the implementation."""
    values = [statuses.get(link) for link in st.LINKS]
    if all(v == "LINKED" for v in values):
        return "COMPLETE"
    if "BROKEN" in values:
        return "BROKEN"
    if any(v in ("INCOMPLETE", "NOT_PRESENT") or v is None for v in values):
        return "INCOMPLETE"
    return "NOT_PROVEN"


def test_tc_06_01_every_combination_of_link_statuses_composes_by_the_rule() -> None:
    count = complete = 0
    for combo in itertools.product(st.LINK_STATUSES, repeat=len(st.LINKS)):
        statuses = dict(zip(st.LINKS, combo))
        got = st.compose(statuses)
        assert got == reference(statuses), statuses
        count += 1
        complete += got == st.COMPLETE
        if "NOT_PRESENT" in combo:
            assert got in (st.BROKEN, st.INCOMPLETE)
    assert count == 5 ** 6 == 15625 and complete == 1


def test_tc_06_02_all_links_linked_is_complete_and_exit_zero() -> None:
    chain = st.compose({link: st.LINKED for link in st.LINKS})
    assert chain == st.COMPLETE and st.exit_code_for(chain) == 0


@pytest.mark.parametrize("link", st.LINKS)
@pytest.mark.parametrize("value,expected,code", [("BROKEN", "BROKEN", 33), ("INCOMPLETE", "INCOMPLETE", 32),
                                                 ("NOT_PROVEN", "NOT_PROVEN", 31), ("NOT_PRESENT", "INCOMPLETE", 32)])
def test_tc_06_03_one_link_off_gives_the_rule_status_and_exit_code(link: str, value: str, expected: str, code: int) -> None:
    statuses = {name: st.LINKED for name in st.LINKS}
    statuses[link] = value
    chain = st.compose(statuses)
    assert chain == expected and st.exit_code_for(chain) == code


def test_tc_06_04_missing_unknown_and_extra_links_are_never_complete() -> None:
    all_linked = {name: st.LINKED for name in st.LINKS}
    for link in st.LINKS:
        missing = dict(all_linked)
        del missing[link]
        assert st.compose(missing) == st.INCOMPLETE
        unknown = dict(all_linked, **{link: "PASS"})
        assert st.compose(unknown) == st.INCOMPLETE
    assert st.compose(dict(all_linked, extra=st.LINKED)) == st.INCOMPLETE
    assert st.link_status(["not_a_known_code"]) == st.INCOMPLETE
    assert st.exit_code_for("SOMETHING_ELSE") == st.EXIT_CODES[st.INCOMPLETE]


@pytest.fixture(scope="module")
def chain(tmp_path_factory: pytest.TempPathFactory) -> cs.Chain:
    return cs.Chain(tmp_path_factory.mktemp("status"), "C02", "IngestRole", cs.cached_review("sc02"))


def _linked_gate(ctx: lk.Context) -> lk.LinkResult:
    """Stands in for a gate link WP2 would find LINKED, so that the other five links decide."""
    return lk.LinkResult("gate")


def test_tc_06_03_a_real_chain_in_wp1_is_incomplete_because_of_the_gate(chain: cs.Chain) -> None:
    result = validator.validate(chain.path, chain.setup.repo)
    links = {entry["link"]: entry for entry in result["payload"]["links"]}
    assert [e["link"] for e in result["payload"]["links"]] == list(st.LINKS)
    assert {k: v["status"] for k, v in links.items()} == {
        "subject": "LINKED", "contract": "LINKED", "review": "LINKED", "verification": "LINKED",
        "gate": "INCOMPLETE", "github": "LINKED"}
    assert links["gate"]["codes"] == ["gate_record_missing"]
    assert result["payload"]["chain_status"] == st.INCOMPLETE and validator.exit_code(result) == 32


def test_tc_06_03_gate_records_are_not_evaluated_before_wp2(chain: cs.Chain) -> None:
    doc = copy.deepcopy(chain.doc)
    record = cs.write(chain.root, "gate/agent-says-approved.json", b'{"approved_by": "agent"}')
    doc["gate_records"] = [{"locator": record, "sha256": cs.sha256(b'{"approved_by": "agent"}'), "kind": "candidate_review"}]
    result = validator.validate(cs.write_manifest(chain.root, doc, "gate-manifest.json"), chain.setup.repo)
    gate = next(e for e in result["payload"]["links"] if e["link"] == "gate")
    assert (gate["status"], gate["codes"]) == ("NOT_PROVEN", ["gate_evaluation_not_implemented"])
    assert result["payload"]["chain_status"] != st.COMPLETE


def test_tc_06_04_an_error_inside_a_link_check_is_never_a_pass(chain: cs.Chain, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(ctx: lk.Context) -> lk.LinkResult:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(lk, "check_gate", _linked_gate)
    monkeypatch.setattr(lk, "check_review", boom)
    result = validator.validate(chain.path, chain.setup.repo)
    review = next(e for e in result["payload"]["links"] if e["link"] == "review")
    assert (review["status"], review["codes"]) == ("INCOMPLETE", ["link_check_error"])
    assert result["payload"]["chain_status"] == st.INCOMPLETE and validator.exit_code(result) == 32


def test_tc_06_04_an_unreadable_repository_is_never_a_pass(chain: cs.Chain, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lk, "check_gate", _linked_gate)
    result = validator.validate(chain.path, tmp_path)  # not a git work tree
    statuses = {e["link"]: (e["status"], e["codes"]) for e in result["payload"]["links"]}
    assert statuses["subject"] == ("INCOMPLETE", ["link_check_error"])
    assert statuses["contract"] == ("INCOMPLETE", ["link_check_error"])
    assert statuses["verification"] == ("NOT_PROVEN", ["recompute_unavailable"])
    assert result["payload"]["chain_status"] == st.INCOMPLETE


def _misread_chain(chain: cs.Chain, review: bytes, name: str) -> Path:
    doc = copy.deepcopy(chain.doc)
    obj = json.loads(review)
    refs = [cs.finding_ref(review, "IngestRole")] if obj["findings"] else [
        {"finding_id": 1, "identity_key_sha256": "0" * 64, "finding_sha256": "0" * 64}]
    doc["review"] = {"review_report": {"locator": cs.write(chain.root, "variants/" + name, review), "sha256": cs.sha256(review)},
                     "finding_refs": refs}
    return cs.write_manifest(chain.root, doc, name.replace(".json", "-manifest.json"))


def test_tc_06_05_a_review_with_errors_keeps_the_chain_from_complete(chain: cs.Chain, monkeypatch: pytest.MonkeyPatch) -> None:
    """A consumer that misreads the pass flag picks a review that did not fully run: the chain stays INCOMPLETE."""
    monkeypatch.setattr(lk, "check_gate", _linked_gate)
    review = cs.cached_review("sc02", "base", without_tools=True)
    result = validator.validate(_misread_chain(chain, review, "misread-with-finding.json"), chain.setup.repo)
    links = {e["link"]: e for e in result["payload"]["links"]}
    assert links["verification"]["status"] == "LINKED" and links["verification"]["observed"]["decision"] == "VERIFIED"
    assert links["review"]["status"] == "INCOMPLETE"
    assert all(links[n]["status"] == "LINKED" for n in st.LINKS if n != "review")
    assert result["payload"]["chain_status"] == st.INCOMPLETE and validator.exit_code(result) == 32


def test_tc_06_05_a_true_pass_flag_with_errors_and_no_finding_is_never_complete(chain: cs.Chain, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lk, "check_gate", _linked_gate)
    review = cs.cached_review("sc01", "fixed", ("cfn-lint",), without_tools=True)
    assert json.loads(review)["summary"]["passed_all_checks"] is True
    result = validator.validate(_misread_chain(chain, review, "misread-no-finding.json"), chain.setup.repo)
    review_link = next(e for e in result["payload"]["links"] if e["link"] == "review")
    assert "review_report_has_errors" in review_link["codes"]
    assert result["payload"]["chain_status"] in (st.BROKEN, st.INCOMPLETE)  # finding_missing makes it BROKEN


def test_tc_06_06_a_rewritten_pass_flag_breaks_the_review_link(chain: cs.Chain, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lk, "check_gate", _linked_gate)
    review = cs.cached_review("sc02", "base", without_tools=True)
    manifest = _misread_chain(chain, review, "flag-rewritten.json")
    target = chain.root / "variants" / "flag-rewritten.json"
    obj = json.loads(target.read_bytes())
    obj["summary"]["passed_all_checks"] = True  # the manifest's digest is left as it was
    target.write_text(json.dumps(obj), encoding="utf-8")
    result = validator.validate(manifest, chain.setup.repo)
    review_link = next(e for e in result["payload"]["links"] if e["link"] == "review")
    assert review_link["status"] == "BROKEN" and "review_digest_mismatch" in review_link["codes"]
    assert result["payload"]["chain_status"] == st.BROKEN and validator.exit_code(result) == 33


def _evidence_ci_exit_codes() -> Dict[str, int]:
    spec = importlib.util.spec_from_file_location("evidence_ci_check_codes", ROOT / ".github" / "scripts" / "evidence_ci_check.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[spec.name] = module  # dataclasses in the script need their module registered
    spec.loader.exec_module(module)
    return dict(module.EXIT)


def test_tc_06_07_the_reserved_exit_codes_do_not_collide() -> None:
    chain_codes = set(st.EXIT_CODES.values()) - {0} | {st.EXIT_INPUT_INVALID}
    assert chain_codes == {31, 32, 33, 34}
    assert not chain_codes & set(exitcodes.EXIT_CODES.values())
    assert not chain_codes & set(rschema.DECISION_EXIT_CODES.values())
    assert not chain_codes & set(_evidence_ci_exit_codes().values())


def test_tc_06_07_not_claimed_is_always_the_seven_items(chain: cs.Chain, tmp_path: Path) -> None:
    assert st.NOT_CLAIMED == ("approval_counted_by_rules", "approver_permission", "capture_authenticity", "human_identity",
                              "issuer_pinning", "merge_enforcement", "runtime_behavior")
    for path in (chain.path, tmp_path / "absent.json"):
        assert validator.validate(path, chain.setup.repo)["payload"]["not_claimed"] == list(st.NOT_CLAIMED)


def test_every_reason_code_is_traceable() -> None:
    """Each code names its links, the status it forces, its cause and what stays unproven."""
    for code, entry in st.REASONS.items():
        assert entry.status in (st.BROKEN, st.INCOMPLETE, st.NOT_PROVEN), code
        assert entry.links and set(entry.links) <= set(st.LINKS) | {"manifest"}, code
        assert entry.cause and entry.unproven, code


def test_every_code_the_package_emits_is_in_the_catalog() -> None:
    import re

    package = Path(lk.__file__).resolve().parent
    emitted = set()
    for path in package.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        emitted |= set(re.findall(r'\.add\("([a-z_]+)"\)', text))
        emitted |= set(re.findall(r'ManifestError\("([a-z_]+)"', text))
        emitted |= set(re.findall(r'else "([a-z_]+)"\)', text))
        emitted |= set(re.findall(r'add\("([a-z_]+)" if', text))
    assert emitted and emitted <= set(st.REASONS), sorted(emitted - set(st.REASONS))
    for code in emitted:
        assert st.REASONS[code].links
