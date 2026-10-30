"""M2-02..M2-05: the subject, contract, verification, review and GitHub-evidence links (Phase 2 M2 WP1).

Source: docs/v2/phase2/m2/wp0/m2-acceptance-test-matrix.md (TC-02-*, TC-03-*, TC-04-*, TC-05-*).
The case repositories are the frozen Phase 1 cases (C01, C02, C05) built by casegen; the GitHub answers
are synthetic and stored in an M1 store. Each negative test changes one thing and checks the link's
status and reason code. Files are never changed in place: a variant is written under another locator.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import pytest

import chain_synth as cs
from iacreview import reportcheck
from iacreview.chain import links as lk
from iacreview.chain import manifest as mf
from iacreview.chain import status as st
from iacreview.remediation import gitsnap
from iacreview.remediation import report as remediation_report


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    cs.block_network(monkeypatch)


@pytest.fixture(scope="module")
def c02(tmp_path_factory: pytest.TempPathFactory) -> cs.Chain:
    return cs.Chain(tmp_path_factory.mktemp("c02"), "C02", "IngestRole", cs.cached_review("sc02"))


@pytest.fixture(scope="module")
def c01(tmp_path_factory: pytest.TempPathFactory) -> cs.Chain:
    return cs.Chain(tmp_path_factory.mktemp("c01"), "C01", "OrdersTable", cs.cached_review("sc01"), with_github=False)


@pytest.fixture(scope="module")
def c05(tmp_path_factory: pytest.TempPathFactory) -> cs.Chain:
    return cs.Chain(tmp_path_factory.mktemp("c05"), "C05", "OrdersTable", cs.cached_review("sc01"), with_github=False)


def context(chain: cs.Chain, doc: Optional[Dict[str, Any]] = None) -> Tuple[lk.Context, lk.LinkResult]:
    ctx = lk.Context(root=chain.root, repo=gitsnap.check_repo(chain.setup.repo), doc=copy.deepcopy(doc or chain.doc))
    loaded = lk.LinkResult("verification")
    lk.load_report(ctx, loaded)
    return ctx, loaded


def variant(chain: cs.Chain, name: str, data: bytes) -> str:
    return cs.write(chain.root, "variants/" + name, data)


def report_obj(chain: cs.Chain) -> Dict[str, Any]:
    return json.loads(chain.verification.decode("ascii"))


def reseal(obj: Dict[str, Any]) -> bytes:
    obj["metadata"]["payload_sha256"] = hashlib.sha256(remediation_report.canonical(obj["payload"])).hexdigest()
    return remediation_report.serialize(obj).encode("ascii")


def with_verification(chain: cs.Chain, name: str, data: bytes) -> Dict[str, Any]:
    """The chain's manifest pointing at a consistent copy of ``data`` (file digest and payload digest updated)."""
    doc = copy.deepcopy(chain.doc)
    doc["verification"]["report"] = {"locator": variant(chain, name, data), "sha256": cs.sha256(data)}
    try:
        doc["verification"]["payload_sha256"] = mf.canonical_sha256(json.loads(data.decode("ascii"))["payload"])
    except ValueError:
        pass
    return doc


# ===================================================================================== M2-02 subject / contract


def test_tc_02_01_a_correct_chain_links_subject_and_contract(c02: cs.Chain) -> None:
    ctx, _ = context(c02)
    assert c02.setup.config_rev == c02.setup.base  # config == base is the allowed edge
    subject, contract = lk.check_subject(ctx), lk.check_contract(ctx)
    assert (subject.status, subject.codes) == (st.LINKED, [])
    assert (contract.status, contract.codes) == (st.LINKED, [])


def test_tc_02_02_a_head_that_does_not_descend_from_the_base_is_broken(c02: cs.Chain) -> None:
    doc = copy.deepcopy(c02.doc)
    doc["subject"] = {"base_commit": c02.setup.head, "head_commit": c02.setup.base}
    res = lk.check_subject(context(c02, doc)[0])
    assert res.status == st.BROKEN and "base_not_ancestor_of_head" in res.codes


def test_tc_02_03_a_config_commit_after_the_base_is_broken(c02: cs.Chain) -> None:
    doc = copy.deepcopy(c02.doc)
    doc["contract"]["config_commit"] = c02.setup.head
    res = lk.check_contract(context(c02, doc)[0])
    assert res.status == st.BROKEN and "config_not_ancestor_of_base" in res.codes


def test_tc_02_04_an_unknown_commit_is_incomplete(c02: cs.Chain) -> None:
    doc = copy.deepcopy(c02.doc)
    doc["subject"]["head_commit"] = "0" * 40
    res = lk.check_subject(context(c02, doc)[0])
    assert (res.status, res.codes) == (st.INCOMPLETE, ["revision_not_found"])


def test_tc_02_05_a_contract_with_another_digest_is_broken(c02: cs.Chain) -> None:
    changed = (c02.setup.repo / c02.setup.contract_path).read_bytes() + b"#"
    doc = copy.deepcopy(c02.doc)
    doc["contract"]["contract_sha256"] = cs.sha256(changed)
    res = lk.check_contract(context(c02, doc)[0])
    assert (res.status, res.codes) == (st.BROKEN, ["contract_digest_mismatch"])


def test_tc_02_06_a_report_about_another_base_is_a_subject_mismatch(c02: cs.Chain) -> None:
    ctx, _ = context(c02)
    assert ctx.report is not None
    ctx.report["payload"]["subject"]["base"]["commit"] = "1" * 40
    res = lk.check_subject(ctx)
    assert (res.status, res.codes) == (st.BROKEN, ["subject_mismatch"])


def test_tc_02_07_a_report_naming_another_contract_digest_is_broken(c02: cs.Chain) -> None:
    ctx, _ = context(c02)
    assert ctx.report is not None
    ctx.report["payload"]["trust"]["contract_sha256"] = "9" * 64
    res = lk.check_contract(ctx)
    assert (res.status, res.codes) == (st.BROKEN, ["contract_mismatch_with_report"])


def test_tc_02_08_a_contract_only_in_the_head_is_never_read(tmp_path: Path) -> None:
    chain = cs.Chain(tmp_path, "C02", "IngestRole", None, with_github=False)
    repo = cs.casegen.Repo.__new__(cs.casegen.Repo)
    repo.path = chain.setup.repo
    repo.git("checkout", "-q", chain.setup.head)
    repo.write(".iac-remediation/contracts/only-in-head.yaml", (chain.setup.repo / chain.setup.contract_path).read_text(encoding="utf-8"))
    new_head = repo.commit("contract only in the head")
    doc = copy.deepcopy(chain.doc)
    doc["subject"]["head_commit"] = new_head
    doc["contract"]["contract_path"] = ".iac-remediation/contracts/only-in-head.yaml"
    res = lk.check_contract(context(chain, doc)[0])
    assert res.status == st.INCOMPLETE and res.codes == ["contract_blob_missing"]


def test_tc_02_09_hooks_filters_textconv_and_fsmonitor_never_run(tmp_path: Path) -> None:
    chain = cs.Chain(tmp_path, "C02", "IngestRole", None, with_github=False)
    marker = tmp_path / "marker"
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    script = "#!/bin/sh\ntouch '{0}'\nexit 0\n".format(marker)
    for name in ("post-checkout", "pre-commit", "post-index-change", "reference-transaction", "fsmonitor"):
        (hooks / name).write_text(script, encoding="utf-8")
        (hooks / name).chmod(stat.S_IRWXU)
    cfg = [("core.hooksPath", str(hooks)), ("core.fsmonitor", str(hooks / "fsmonitor")),
           ("filter.mk.clean", str(hooks / "fsmonitor")), ("filter.mk.smudge", str(hooks / "fsmonitor")),
           ("diff.mk.textconv", str(hooks / "fsmonitor"))]
    for key, value in cfg:
        subprocess.run(["git", "-C", str(chain.setup.repo), "config", key, value], check=True)
    (chain.setup.repo / ".git" / "info").mkdir(exist_ok=True)
    (chain.setup.repo / ".git" / "info" / "attributes").write_text("* filter=mk diff=mk\n", encoding="utf-8")
    ctx, loaded = context(chain)
    assert lk.check_subject(ctx).status == st.LINKED and lk.check_contract(ctx).status == st.LINKED
    assert not marker.exists()


# ===================================================================================== M2-03 verification


@pytest.mark.parametrize("fixture,decision", [("c01", "VERIFIED"), ("c02", "VERIFIED"), ("c05", "BLOCKED")])
def test_tc_03_01_02_a_recomputed_report_is_linked_whatever_its_decision(request: pytest.FixtureRequest, fixture: str, decision: str) -> None:
    chain = request.getfixturevalue(fixture)
    ctx, loaded = context(chain)
    res = lk.check_verification(ctx, loaded)
    assert (res.status, res.codes) == (st.LINKED, [])
    assert res.observed == {"decision": decision, "execution_mode": "local_preview", "validator_identity": "NOT_PROVEN"}


def test_tc_03_03_a_local_import_that_the_recomputation_reproduces_is_linked(c02: cs.Chain) -> None:
    doc = copy.deepcopy(c02.doc)
    doc["verification"]["acquisition"] = "local_import"
    ctx, loaded = context(c02, doc)
    assert lk.check_verification(ctx, loaded).status == st.LINKED


def test_tc_03_03_a_report_from_another_validator_identity_is_still_linked(c02: cs.Chain) -> None:
    obj = report_obj(c02)
    obj["payload"]["validator"] = {"name": "x", "plugin_version": "0.0.0", "source_sha256": "0" * 64, "python": "3.13"}
    ctx, loaded = context(c02, with_verification(c02, "other-validator.json", reseal(obj)))
    assert lk.check_verification(ctx, loaded).status == st.LINKED


def test_tc_03_04_a_forged_decision_with_consistent_digests_is_broken(c05: cs.Chain) -> None:
    obj = report_obj(c05)
    assert obj["payload"]["decision"] == "BLOCKED"
    obj["payload"].update(decision="VERIFIED", exit_code=0, next_action="human_review", violations=[])
    doc = with_verification(c05, "forged-verified.json", reseal(obj))
    ctx, loaded = context(c05, doc)
    assert loaded.codes == []  # the file, its metadata and the manifest agree with one another
    res = lk.check_verification(ctx, loaded)
    assert (res.status, res.codes) == (st.BROKEN, ["payload_digest_mismatch"])
    assert res.observed["decision"] == "VERIFIED"  # observed, never trusted


def test_tc_03_05_a_wrong_metadata_digest_is_broken(c02: cs.Chain) -> None:
    obj = report_obj(c02)
    obj["metadata"]["payload_sha256"] = "0" * 64
    data = remediation_report.serialize(obj).encode("ascii")
    ctx, loaded = context(c02, with_verification(c02, "bad-metadata.json", data))
    res = lk.check_verification(ctx, loaded)
    assert res.status == st.BROKEN and res.codes == ["metadata_digest_mismatch"]


def test_tc_03_06_a_report_about_another_subject_is_broken(c02: cs.Chain) -> None:
    obj = report_obj(c02)
    obj["payload"]["subject"]["head"]["commit"] = c02.setup.base
    ctx, loaded = context(c02, with_verification(c02, "other-subject.json", reseal(obj)))
    res = lk.check_verification(ctx, loaded)
    assert res.status == st.BROKEN and "report_subject_mismatch" in res.codes


def test_tc_03_06_a_report_file_with_another_digest_is_broken(c02: cs.Chain) -> None:
    doc = copy.deepcopy(c02.doc)
    doc["verification"]["report"]["sha256"] = "0" * 64
    ctx, loaded = context(c02, doc)
    res = lk.check_verification(ctx, loaded)
    assert (res.status, res.codes) == (st.BROKEN, ["verification_digest_mismatch"])


def test_tc_03_06_a_missing_report_file_is_incomplete(c02: cs.Chain) -> None:
    doc = copy.deepcopy(c02.doc)
    doc["verification"]["report"]["locator"] = "artifacts/absent.json"
    ctx, loaded = context(c02, doc)
    res = lk.check_verification(ctx, loaded)
    assert (res.status, res.codes) == (st.INCOMPLETE, ["verification_artifact_missing"])


@pytest.mark.parametrize("data", [b"{not json", b'{"report_kind": "remediation_verification"}', b"[]"])
def test_tc_03_07_an_unusable_report_is_incomplete(c02: cs.Chain, data: bytes) -> None:
    doc = copy.deepcopy(c02.doc)
    doc["verification"]["report"] = {"locator": variant(c02, "broken-{0}.json".format(cs.sha256(data)[:8]), data), "sha256": cs.sha256(data)}
    ctx, loaded = context(c02, doc)
    res = lk.check_verification(ctx, loaded)
    assert (res.status, res.codes) == (st.INCOMPLETE, ["report_invalid"])


def _path_with(tmp: Path, names: Tuple[str, ...], fake: Optional[Tuple[str, str]] = None) -> str:
    import shutil

    bin_dir = tmp / "bin"
    bin_dir.mkdir()
    for name in names:
        real = shutil.which(name)
        assert real is not None, name
        os.symlink(real, str(bin_dir / name))
    if fake is not None:
        target = bin_dir / fake[0]
        target.write_text(fake[1], encoding="utf-8")
        target.chmod(stat.S_IRWXU)
    return str(bin_dir)


def test_tc_03_08_a_missing_tool_makes_the_recomputation_unavailable(c02: cs.Chain, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", _path_with(tmp_path, ("git", "cfn-lint")))
    ctx, loaded = context(c02)
    res = lk.check_verification(ctx, loaded)
    assert (res.status, res.codes) == (st.NOT_PROVEN, ["recompute_unavailable"])


def test_tc_03_08_another_tool_version_makes_the_recomputation_unavailable(c02: cs.Chain, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", _path_with(tmp_path, ("git", "cfn-guard"), ("cfn-lint", "#!/bin/sh\necho 'cfn-lint 0.0.1'\n")))
    ctx, loaded = context(c02)
    res = lk.check_verification(ctx, loaded)
    assert (res.status, res.codes) == (st.NOT_PROVEN, ["recompute_unavailable"])


# ===================================================================================== M2-04 review


def review_doc(chain: cs.Chain, review: bytes, name: str, resource: str) -> Dict[str, Any]:
    doc = copy.deepcopy(chain.doc)
    refs = [cs.finding_ref(review, resource)] if json.loads(review)["findings"] else [
        {"finding_id": 1, "identity_key_sha256": "0" * 64, "finding_sha256": "0" * 64}]
    doc["review"] = {"review_report": {"locator": variant(chain, name, review), "sha256": cs.sha256(review)}, "finding_refs": refs}
    return doc


def review_of(chain: cs.Chain, doc: Dict[str, Any]) -> lk.LinkResult:
    ctx, _ = context(chain, doc)
    lk.check_contract(ctx)  # provides the contract's Resource for the observation
    return lk.check_review(ctx)


def test_tc_04_01_a_complete_review_with_the_referenced_finding_is_linked(c02: cs.Chain) -> None:
    res = review_of(c02, c02.doc)
    assert (res.status, res.codes) == (st.LINKED, [])
    assert res.observed == {"finding_resource_matches_contract": True}


def test_tc_04_01_a_finding_on_another_resource_is_only_observed(c01: cs.Chain) -> None:
    review = cs.cached_review("sc01")
    res = review_of(c01, review_doc(c01, review, "other-resource.json", "OrdersFunctionRole"))
    assert res.status == st.LINKED and res.observed == {"finding_resource_matches_contract": False}


def test_tc_04_02_errors_with_no_finding_and_a_true_pass_flag_are_never_linked(c02: cs.Chain) -> None:
    review = cs.cached_review("sc01", "fixed", ("cfn-lint",), without_tools=True)
    doc_obj = json.loads(review)
    assert doc_obj["findings"] == [] and doc_obj["summary"]["passed_all_checks"] is True and len(doc_obj["errors"]) >= 1
    res = review_of(c02, review_doc(c02, review, "errors-no-finding.json", "IngestRole"))
    assert "review_report_has_errors" in res.codes and res.status != st.LINKED
    # finding_refs needs one reference (schema); with no finding it is also finding_missing (BROKEN)
    assert res.status == st.BROKEN and "finding_missing" in res.codes


def test_tc_04_02_errors_next_to_the_referenced_finding_are_incomplete(c02: cs.Chain) -> None:
    review = cs.cached_review("sc02", "base", without_tools=True)
    doc_obj = json.loads(review)
    assert doc_obj["findings"] and doc_obj["errors"] and doc_obj["summary"]["passed_all_checks"] is False
    res = review_of(c02, review_doc(c02, review, "errors-with-finding.json", "IngestRole"))
    assert res.status == st.INCOMPLETE
    assert set(res.codes) == {"review_report_has_errors", "review_tool_unavailable"}


def _checked(tools: Tuple[reportcheck.ToolRecord, ...], errors: Tuple[reportcheck.ErrorRecord, ...] = ()) -> reportcheck.CheckedReport:
    return reportcheck.CheckedReport("1.0.0", ("infra/template.yaml",), (), False, "not_applicable", ("cfn-lint",), tools, errors, (), ())


def test_tc_04_03_an_unavailable_or_absent_tool_is_never_complete() -> None:
    assert lk.review_evidence_complete(_checked((reportcheck.ToolRecord("cfn-lint", False, None),))) == ["review_tool_unavailable"]
    assert lk.review_evidence_complete(_checked(())) == ["review_tool_unavailable"]
    assert lk.review_evidence_complete(_checked((reportcheck.ToolRecord("cfn-lint", True, "1.46.0"),))) == []
    assert lk.review_evidence_complete(_checked((reportcheck.ToolRecord("cfn-lint", True, "1.46.0"),),
                                               (reportcheck.ErrorRecord("tool_unavailable", "cfn-guard"),))) == ["review_report_has_errors"]


def test_tc_04_04_a_reference_to_an_absent_finding_is_broken(c02: cs.Chain) -> None:
    doc = copy.deepcopy(c02.doc)
    doc["review"]["finding_refs"][0]["finding_id"] = 99
    res = review_of(c02, doc)
    assert (res.status, res.codes) == (st.BROKEN, ["finding_missing"])


def test_tc_04_05_a_changed_finding_is_broken(c02: cs.Chain) -> None:
    raw = next(f for f in json.loads(c02.review or b"")["findings"] if f["Resource"] == "IngestRole")
    severity = dict(raw, Severity="LOW")
    doc = copy.deepcopy(c02.doc)
    doc["review"]["finding_refs"][0]["finding_sha256"] = mf.canonical_sha256(severity)
    res = review_of(c02, doc)
    assert (res.status, res.codes) == (st.BROKEN, ["finding_digest_mismatch"])
    doc["review"]["finding_refs"][0]["finding_sha256"] = mf.canonical_sha256(raw)
    doc["review"]["finding_refs"][0]["identity_key_sha256"] = lk.identity_key_sha256(dict(raw, Resource="OtherRole"))
    res = review_of(c02, doc)
    assert (res.status, res.codes) == (st.BROKEN, ["identity_key_mismatch"])


def test_tc_04_06_an_unusable_or_absent_review_report(c02: cs.Chain) -> None:
    obj = json.loads(c02.review or b"")
    obj["schema_version"] = "2.0.0"
    data = json.dumps(obj).encode()
    res = review_of(c02, review_doc(c02, data, "schema-2.json", "IngestRole"))
    assert (res.status, res.codes) == (st.INCOMPLETE, ["review_report_invalid"])
    doc = copy.deepcopy(c02.doc)
    doc["review"]["review_report"]["locator"] = "artifacts/absent-review.json"
    assert review_of(c02, doc).codes == ["review_artifact_missing"]
    doc = copy.deepcopy(c02.doc)
    doc["review"]["review_report"]["sha256"] = "0" * 64
    res = review_of(c02, doc)
    assert (res.status, res.codes) == (st.BROKEN, ["review_digest_mismatch"])


def test_tc_04_06_an_internally_inconsistent_review_report_is_invalid(c02: cs.Chain) -> None:
    obj = json.loads(c02.review or b"")
    obj["summary"]["total"] = 7  # the summary no longer rebuilds from the findings
    res = review_of(c02, review_doc(c02, json.dumps(obj).encode(), "rebuild-mismatch.json", "IngestRole"))
    assert (res.status, res.codes) == (st.INCOMPLETE, ["review_report_invalid"])


def test_tc_04_07_no_review_is_not_present(c02: cs.Chain) -> None:
    doc = copy.deepcopy(c02.doc)
    doc["review"] = None
    res = review_of(c02, doc)
    assert res.status == st.NOT_PRESENT and res.codes == []


def test_tc_04_08_the_chain_never_reads_the_pass_flag() -> None:
    package = Path(lk.__file__).resolve().parent
    flag = "passed_all" + "_checks"
    offenders = [p.name for p in package.glob("*.py") if flag in p.read_text(encoding="utf-8")]
    assert offenders == []
    assert "reportcheck.check_report(" in Path(lk.__file__).read_text(encoding="utf-8")


# ===================================================================================== M2-05 github


def github_of(chain: cs.Chain, doc: Optional[Dict[str, Any]] = None) -> lk.LinkResult:
    return lk.check_github(context(chain, doc)[0])


def test_tc_05_01_a_valid_store_revision_is_linked(c02: cs.Chain) -> None:
    res = github_of(c02)
    assert (res.status, res.codes) == (st.LINKED, [])
    assert res.observed == {"capture_authenticity": "NOT_PROVEN"}


def test_tc_05_02_a_changed_raw_byte_fails_the_m1_integrity(c02: cs.Chain) -> None:
    gh = cs.make_store(c02.root, c02.setup.base, c02.setup.head, locator="store-raw-changed")
    raw = sorted((c02.root / "store-raw-changed" / gh["revision"]).glob("*.raw"))[0]
    raw.chmod(0o600)
    data = bytearray(raw.read_bytes())
    data[0] ^= 0x01
    raw.write_bytes(bytes(data))
    doc = copy.deepcopy(c02.doc)
    doc["github_evidence"] = gh
    res = github_of(c02, doc)
    assert res.status == st.INCOMPLETE and "integrity_not_pass" in res.codes


def test_tc_05_03_another_store_manifest_is_broken(c02: cs.Chain) -> None:
    doc = copy.deepcopy(c02.doc)
    doc["github_evidence"]["manifest_sha256"] = "0" * 64
    res = github_of(c02, doc)
    assert (res.status, res.codes) == (st.BROKEN, ["store_manifest_mismatch"])


def test_tc_05_04_an_absent_evidence_id_is_incomplete(c02: cs.Chain) -> None:
    doc = copy.deepcopy(c02.doc)
    doc["github_evidence"]["evidence_ids"] = doc["github_evidence"]["evidence_ids"] + ["cap-chain-9999-p001"]
    res = github_of(c02, doc)
    assert res.status == st.INCOMPLETE and "evidence_id_missing" in res.codes
    doc = copy.deepcopy(c02.doc)
    doc["github_evidence"]["revision"] = "rev-0009"
    assert github_of(c02, doc).codes == ["evidence_id_missing"]
    doc = copy.deepcopy(c02.doc)
    doc["github_evidence"]["store_locator"] = "no-such-store"
    assert github_of(c02, doc).codes == ["evidence_id_missing"]
    assert not (c02.root / "no-such-store").exists()  # the check does not create a store


def test_tc_05_05_evidence_of_another_repository_is_broken(c02: cs.Chain) -> None:
    gh = cs.make_store(c02.root, c02.setup.base, c02.setup.head, repo=cs.OTHER_REPO, locator="store-other-repo")
    doc = copy.deepcopy(c02.doc)
    doc["github_evidence"] = gh
    res = github_of(c02, doc)
    assert (res.status, res.codes) == (st.BROKEN, ["repository_mismatch"])


def test_tc_05_06_an_incomplete_capture_is_incomplete(c02: cs.Chain) -> None:
    gh = cs.make_store(c02.root, c02.setup.base, c02.setup.head, locator="store-incomplete", incomplete=True)
    doc = copy.deepcopy(c02.doc)
    doc["github_evidence"] = gh
    res = github_of(c02, doc)
    assert res.status == st.INCOMPLETE and "capture_incomplete" in res.codes


def test_no_github_evidence_is_not_present(c01: cs.Chain) -> None:
    res = github_of(c01)
    assert res.status == st.NOT_PRESENT and res.codes == []


# ===================================================================================== WP1 final audit: N-5 (validator identity)


def _with_validator(c02: cs.Chain, change: Any) -> bytes:
    obj = report_obj(c02)
    change(obj["payload"]["validator"])
    return reseal(obj)


VALIDATOR_SCHEMA_VIOLATIONS = [
    ("unknown key", lambda v: v.__setitem__("extra", "x")),
    ("missing name", lambda v: v.pop("name")),
    ("missing python", lambda v: v.pop("python")),
    ("name not a string", lambda v: v.__setitem__("name", 7)),
    ("plugin_version an integer", lambda v: v.__setitem__("plugin_version", 110)),
    ("source digest not 64 hex", lambda v: v.__setitem__("source_sha256", "abc")),
    ("source digest upper case", lambda v: v.__setitem__("source_sha256", "A" * 64)),
    ("python not X.Y", lambda v: v.__setitem__("python", "3")),
    ("python a number", lambda v: v.__setitem__("python", 3.9)),
    ("validator a string", "anything"),
    ("validator null", None),
]


@pytest.mark.parametrize("label,change", VALIDATOR_SCHEMA_VIOLATIONS, ids=[x[0] for x in VALIDATOR_SCHEMA_VIOLATIONS])
def test_tc_03_09_a_validator_object_outside_the_schema_is_report_invalid(c02: cs.Chain, label: str, change: Any) -> None:
    obj = report_obj(c02)
    if callable(change):
        change(obj["payload"]["validator"])
    else:
        obj["payload"]["validator"] = change
    data = reseal(obj)  # every digest agrees: only the shape of payload.validator is wrong
    ctx, loaded = context(c02, with_verification(c02, "validator-schema-{0}.json".format(label.replace(" ", "-")), data))
    res = lk.check_verification(ctx, loaded)
    assert (res.status, res.codes) == (st.INCOMPLETE, ["report_invalid"])
    assert ctx.report is None  # nothing else is compared against an unusable report


@pytest.mark.parametrize("key,value", [("name", "another/validator"), ("plugin_version", "9.9.9"), ("plugin_version", None),
                                       ("source_sha256", "0" * 64), ("python", "3.13")])
def test_tc_03_10_one_identity_field_changed_is_linked_and_only_diagnosed(c02: cs.Chain, key: str, value: Any) -> None:
    data = _with_validator(c02, lambda v: v.__setitem__(key, value))
    ctx, loaded = context(c02, with_verification(c02, "identity-{0}-{1}.json".format(key, cs.sha256(repr(value).encode())[:6]), data))
    res = lk.check_verification(ctx, loaded)
    assert (res.status, res.codes) == (st.LINKED, [])
    assert res.observed["validator_identity"] == "NOT_PROVEN"
    [diag] = res.diagnostics
    assert diag == {"link": "verification", "code": "validator_identity_differs", "fields": [key],
                    "authenticity": "NOT_PROVEN", "implementation_equivalence": "NOT_PROVEN"}


def test_tc_03_10_the_unchanged_identity_is_diagnosed_as_matching(c02: cs.Chain) -> None:
    ctx, loaded = context(c02)
    res = lk.check_verification(ctx, loaded)
    assert [d["code"] for d in res.diagnostics] == ["validator_identity_matches"] and res.diagnostics[0]["fields"] == []


@pytest.mark.parametrize("stale,code", [("metadata", "metadata_digest_mismatch"), ("manifest_payload", "payload_digest_mismatch"),
                                        ("manifest_file", "verification_digest_mismatch")])
def test_tc_03_11_an_identity_change_with_a_stale_digest_is_broken(c02: cs.Chain, stale: str, code: str) -> None:
    obj = report_obj(c02)
    obj["payload"]["validator"]["python"] = "3.13"
    data = remediation_report.serialize(obj).encode("ascii") if stale == "metadata" else reseal(obj)
    doc = with_verification(c02, "identity-stale-{0}.json".format(stale), data)
    if stale == "manifest_payload":
        doc["verification"]["payload_sha256"] = c02.doc["verification"]["payload_sha256"]
    if stale == "manifest_file":
        doc["verification"]["report"]["sha256"] = cs.sha256(c02.verification)
    ctx, loaded = context(c02, doc)
    res = lk.check_verification(ctx, loaded)
    assert res.status == st.BROKEN and code in res.codes


def test_tc_03_12_the_identity_diagnostic_stays_out_of_the_payload(c02: cs.Chain) -> None:
    from iacreview.chain import validator

    same = validator.validate(c02.path, c02.setup.repo)
    data = _with_validator(c02, lambda v: v.__setitem__("python", "3.13"))
    path = cs.write_manifest(c02.root, with_verification(c02, "identity-python-run.json", data), "identity-manifest.json")
    other = validator.validate(path, c02.setup.repo)
    links = [{e["link"]: e for e in r["payload"]["links"]} for r in (same, other)]
    assert links[0]["verification"] == links[1]["verification"]  # same status, codes and observations
    assert same["payload"]["chain_status"] == other["payload"]["chain_status"]
    assert [d["code"] for d in same["metadata"]["diagnostics"]] == ["validator_identity_matches"]
    assert [d["code"] for d in other["metadata"]["diagnostics"]] == ["validator_identity_differs"]
    text = json.dumps(other["payload"])
    assert "validator_identity_differs" not in text and "3.13" not in text


def test_tc_03_12_without_a_recomputation_the_identity_is_not_compared(c02: cs.Chain, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", _path_with(tmp_path, ("git", "cfn-lint")))
    ctx, loaded = context(c02)
    res = lk.check_verification(ctx, loaded)
    assert res.codes == ["recompute_unavailable"] and [d["code"] for d in res.diagnostics] == ["validator_identity_not_compared"]


def test_every_diagnostic_code_is_in_the_catalog_and_never_a_reason() -> None:
    import re

    text = Path(lk.__file__).read_text(encoding="utf-8")
    emitted = set(re.findall(r'"(validator_identity_[a-z_]+)"', text))
    assert emitted == set(st.DIAGNOSTICS)
    assert not set(st.DIAGNOSTICS) & set(st.REASONS)


# ===================================================================================== WP1 final audit: N-6 (attack conditions as specified)


def test_tc_02_05_literal_a_one_byte_change_of_the_approved_contract_in_git(tmp_path: Path) -> None:
    """The contract at the config commit is changed by one byte in git; the manifest keeps the approved digest."""
    chain = cs.Chain(tmp_path, "C02", "IngestRole", None, with_github=False)
    repo = cs.casegen.Repo.__new__(cs.casegen.Repo)
    repo.path = chain.setup.repo
    approved = (chain.setup.repo / chain.setup.contract_path).read_bytes()
    repo.git("checkout", "-q", chain.setup.base)
    changed = bytearray(approved)
    index = changed.index(b"v1")  # one byte of the profile id text
    changed[index + 1] = ord("2")
    (chain.setup.repo / chain.setup.contract_path).write_bytes(bytes(changed))
    config = repo.commit("contract changed by one byte")
    repo.git("cherry-pick", "--allow-empty", chain.setup.head)
    head = repo.git("rev-parse", "HEAD")
    doc = copy.deepcopy(chain.doc)
    doc["subject"] = {"base_commit": config, "head_commit": head}
    doc["contract"]["config_commit"] = config  # the manifest's contract_sha256 is the approved one, unchanged
    ctx, _ = context(chain, doc)
    assert lk.check_subject(ctx).codes == ["subject_mismatch"]  # the old report names the old subject
    res = lk.check_contract(ctx)
    assert res.status == st.BROKEN and "contract_digest_mismatch" in res.codes
    assert "config_not_ancestor_of_base" not in res.codes  # the ancestry is intact: only the content changed


def test_tc_05_03_literal_raw_and_store_manifest_rewritten_consistently(c02: cs.Chain) -> None:
    """Raw bytes, the envelope and the store MANIFEST are rewritten so that M1 verification passes again."""
    from iacreview.evidence import envelope as m1_env
    from iacreview.evidence import integrity as m1_integrity
    from iacreview.evidence import store as m1_store

    gh = cs.make_store(c02.root, c02.setup.base, c02.setup.head, locator="store-consistent-rewrite")
    rev = c02.root / "store-consistent-rewrite" / gh["revision"]
    for path in rev.iterdir():
        path.chmod(0o600)
    raw_path = next(p for p in sorted(rev.glob("*.raw")) if b'"state": "open"' in p.read_bytes())  # the pull answer
    eid = raw_path.name[: -len(".raw")]
    raw = raw_path.read_bytes().replace(b'"open"', b'"shut"')
    assert raw != raw_path.read_bytes()
    raw_path.write_bytes(raw)
    env_path = rev / (eid + ".envelope.json")
    envelope = json.loads(env_path.read_bytes())
    envelope["raw_content_sha256"], envelope["raw_content_length"] = m1_env.sha256_hex(raw), len(raw)
    env_bytes = m1_env.canonical_bytes(envelope)
    env_path.write_bytes(env_bytes)
    manifest_path = rev / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_bytes())
    for entry in manifest["entries"]:
        if entry["evidence_id"] == eid:
            entry.update(raw_sha256=m1_env.sha256_hex(raw), raw_length=len(raw),
                         envelope_sha256=m1_env.sha256_hex(env_bytes), envelope_length=len(env_bytes))
    manifest_path.write_bytes(m1_store.manifest_bytes(manifest))
    store = m1_store.EvidenceStore(c02.root / "store-consistent-rewrite", c02.root)
    assert m1_integrity.validate(store, gh["evidence_ids"], m1_integrity.Requirement("API", None, True))["overall_status"] == "PASS"
    doc = copy.deepcopy(c02.doc)
    doc["github_evidence"] = gh  # the chain manifest keeps the digest of the original store MANIFEST
    res = github_of(c02, doc)
    assert (res.status, res.codes) == (st.BROKEN, ["store_manifest_mismatch"])
