"""M2-01: Chain Manifest schema, canonical form and locator safety (Phase 2 M2 WP1).

Source: docs/v2/phase2/m2/wp0/m2-acceptance-test-matrix.md (TC-01-01..TC-01-06), m2-schemas.md rev1 §1.
No git repository and no network are needed: a manifest that fails here stops before any link runs.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

import pytest

import chain_synth as cs
from iacreview.chain import manifest as mf
from iacreview.chain import status as st
from iacreview.chain import validator

H40 = "a" * 40
H64 = "b" * 64


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    cs.block_network(monkeypatch)


def valid_doc() -> Dict[str, Any]:
    return {
        "manifest_format": "iacreview.chain.manifest/1",
        "chain_id": "chain-unit-0001",
        "repository_id": "r:0123456789ab",
        "subject": {"base_commit": H40, "head_commit": "c" * 40},
        "contract": {"config_commit": H40, "contract_path": ".iac-remediation/contracts/x.yaml", "contract_sha256": H64},
        "review": {"review_report": {"locator": "artifacts/review-report.json", "sha256": H64},
                   "finding_refs": [{"finding_id": 1, "identity_key_sha256": H64, "finding_sha256": H64}]},
        "verification": {"report": {"locator": "artifacts/remediation-report.json", "sha256": H64},
                         "payload_sha256": H64, "acquisition": "local_recompute"},
        "gate_records": [{"locator": "gate/contract-approval.json", "sha256": H64, "kind": "contract_approval"}],
        "github_evidence": {"store_locator": "evidence-store", "revision": "rev-0001", "manifest_sha256": H64,
                            "evidence_ids": ["cap-chain-0001-p001"]},
    }


def write(root: Path, doc: Any, name: str = "chain-manifest.json") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def codes_of(path: Path) -> Tuple[List[str], str, int]:
    result = validator.validate(path, path.parent)
    payload = result["payload"]
    return payload["manifest_codes"], payload["chain_status"], validator.exit_code(result)


# --- TC-01-01 / TC-01-02 -------------------------------------------------------------------------


@pytest.mark.parametrize("variant", ["review", "no_review", "no_github"])
def test_tc_01_01_valid_manifests_are_accepted(tmp_path: Path, variant: str) -> None:
    doc = valid_doc()
    if variant == "no_review":
        doc["review"] = None
    if variant == "no_github":
        doc["github_evidence"] = None
    loaded = mf.load(write(tmp_path, doc))
    assert loaded.doc == doc and len(loaded.sha256) == 64


def test_tc_01_02_key_order_and_whitespace_do_not_change_the_digest(tmp_path: Path) -> None:
    doc = valid_doc()
    a = mf.load(write(tmp_path / "a", doc))
    reordered = dict(reversed(list(doc.items())))
    reordered["subject"] = dict(reversed(list(doc["subject"].items())))
    path = tmp_path / "b" / "chain-manifest.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(reordered, indent=7, separators=(" ,  ", " :  ")) + "\n\n", encoding="utf-8")
    b = mf.load(path)
    assert a.sha256 == b.sha256


# --- TC-01-03 / TC-01-04 -------------------------------------------------------------------------


def _set(path: Tuple[Any, ...], value: Any) -> Callable[[Dict[str, Any]], None]:
    def edit(doc: Dict[str, Any]) -> None:
        target = doc
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
    return edit


def _drop(path: Tuple[Any, ...]) -> Callable[[Dict[str, Any]], None]:
    def edit(doc: Dict[str, Any]) -> None:
        target = doc
        for key in path[:-1]:
            target = target[key]
        del target[path[-1]]
    return edit


INVALID: List[Tuple[str, Callable[[Dict[str, Any]], None]]] = [
    ("unknown top key", _set(("extra",), 1)),
    ("unknown subject key", _set(("subject", "decision"), "VERIFIED")),
    ("unknown review ref key", _set(("review", "finding_refs", 0, "note"), "x")),
    ("unknown github key", _set(("github_evidence", "approved_by"), "someone")),
    ("missing chain_id", _drop(("chain_id",))),
    ("missing verification acquisition", _drop(("verification", "acquisition"))),
    ("wrong format", _set(("manifest_format",), "iacreview.chain.manifest/2")),
    ("short commit", _set(("subject", "base_commit"), "a" * 39)),
    ("upper-case hex", _set(("subject", "head_commit"), "A" * 40)),
    ("sha256 too short", _set(("contract", "contract_sha256"), "b" * 63)),
    ("repository id format", _set(("repository_id",), "owner/repo")),
    ("type: finding id string", _set(("review", "finding_refs", 0, "finding_id"), "F-0001")),
    ("type: finding id bool", _set(("review", "finding_refs", 0, "finding_id"), True)),
    ("finding id zero", _set(("review", "finding_refs", 0, "finding_id"), 0)),
    ("empty finding refs", _set(("review", "finding_refs"), [])),
    ("duplicate finding id", _set(("review", "finding_refs"), [{"finding_id": 1, "identity_key_sha256": H64, "finding_sha256": H64}] * 2)),
    ("duplicate evidence id", _set(("github_evidence", "evidence_ids"), ["cap-chain-0001-p001"] * 2)),
    ("bad evidence id", _set(("github_evidence", "evidence_ids"), ["X"])),
    ("unknown gate kind", _set(("gate_records", 0, "kind"), "agent_statement")),
    ("unknown acquisition", _set(("verification", "acquisition"), "trust_me")),
    ("revision format", _set(("github_evidence", "revision"), "rev-1")),
    ("gate records not a list", _set(("gate_records",), {})),
    ("contract path traversal", _set(("contract", "contract_path"), "../contract.yaml")),
]


@pytest.mark.parametrize("name,edit", INVALID, ids=[n for n, _ in INVALID])
def test_tc_01_03_schema_violations_are_manifest_invalid(tmp_path: Path, name: str, edit: Callable[[Dict[str, Any]], None]) -> None:
    doc = copy.deepcopy(valid_doc())
    edit(doc)
    codes, chain, code = codes_of(write(tmp_path, doc))
    assert codes == ["manifest_invalid"] and chain == st.BROKEN and code == st.EXIT_INPUT_INVALID


@pytest.mark.parametrize("text", [
    '{"a": 1, "a": 2}',
    '{"x": NaN}',
    '{"x": Infinity}',
    '{"x": 1.5}',
])
def test_tc_01_03_strict_json_violations_are_manifest_invalid(tmp_path: Path, text: str) -> None:
    path = tmp_path / "chain-manifest.json"
    path.write_text(text, encoding="utf-8")
    codes, chain, code = codes_of(path)
    assert codes == ["manifest_invalid"] and chain == st.BROKEN and code == 34


def test_tc_01_03_duplicate_key_inside_the_manifest_is_refused(tmp_path: Path) -> None:
    text = json.dumps(valid_doc())
    text = text.replace('"chain_id": "chain-unit-0001"', '"chain_id": "chain-unit-0001", "chain_id": "chain-unit-0002"', 1)
    path = tmp_path / "chain-manifest.json"
    path.write_text(text, encoding="utf-8")
    assert codes_of(path)[0] == ["manifest_invalid"]


def test_tc_01_04_api_artifact_cannot_be_chosen(tmp_path: Path) -> None:
    doc = valid_doc()
    doc["verification"]["acquisition"] = "api_artifact"
    codes, chain, code = codes_of(write(tmp_path, doc))
    assert codes == ["manifest_invalid"] and chain == st.BROKEN and code == 34


# --- TC-01-05 ------------------------------------------------------------------------------------


@pytest.mark.parametrize("locator", ["../outside.json", "/etc/passwd", "artifacts\\r.json", "a/\x00b.json", "a//b.json",
                                     "./a.json", "a/./b.json", "", "a/../b.json"])
def test_tc_01_05_unsafe_locator_text_is_outside_the_root(tmp_path: Path, locator: str) -> None:
    doc = valid_doc()
    doc["verification"]["report"]["locator"] = locator
    codes, chain, code = codes_of(write(tmp_path, doc))
    assert codes == ["locator_outside_root"] and chain == st.BROKEN and code == 34


def test_tc_01_05_a_symbolic_link_directory_is_outside_the_root(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "remediation-report.json").write_text("{}", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    os.symlink(str(outside), str(root / "artifacts"))
    codes, _, code = codes_of(write(root, valid_doc()))
    assert codes == ["locator_outside_root"] and code == 34


def test_tc_01_05_a_symbolic_link_file_is_outside_the_root(tmp_path: Path) -> None:
    outside = tmp_path / "secret.json"
    outside.write_text("{}", encoding="utf-8")
    root = tmp_path / "root"
    (root / "artifacts").mkdir(parents=True)
    os.symlink(str(outside), str(root / "artifacts" / "remediation-report.json"))
    codes, _, _ = codes_of(write(root, valid_doc()))
    assert codes == ["locator_outside_root"]


def test_tc_01_05_a_symbolic_link_store_is_outside_the_root(tmp_path: Path) -> None:
    (tmp_path / "elsewhere").mkdir()
    root = tmp_path / "root"
    root.mkdir()
    os.symlink(str(tmp_path / "elsewhere"), str(root / "evidence-store"))
    assert codes_of(write(root, valid_doc()))[0] == ["locator_outside_root"]


def test_tc_01_05_a_linked_manifest_is_not_read(tmp_path: Path) -> None:
    real = write(tmp_path / "real", valid_doc())
    root = tmp_path / "root"
    root.mkdir()
    os.symlink(str(real), str(root / "chain-manifest.json"))
    codes, chain, code = codes_of(root / "chain-manifest.json")
    assert codes == ["locator_outside_root"] and chain == st.BROKEN and code == 34


# --- TC-01-06 ------------------------------------------------------------------------------------


def test_tc_01_06_a_manifest_over_the_size_limit_is_unreadable(tmp_path: Path) -> None:
    doc = valid_doc()
    doc["chain_id"] = "x" * (mf.MAX_MANIFEST_BYTES + 1)
    codes, chain, code = codes_of(write(tmp_path, doc))
    assert codes == ["manifest_unreadable"] and chain == st.BROKEN and code == 34


def test_tc_01_06_a_too_deep_document_is_invalid(tmp_path: Path) -> None:
    deep: Any = 1
    for _ in range(mf.MAX_DEPTH + 2):
        deep = [deep]
    doc = valid_doc()
    doc["review"] = deep
    assert codes_of(write(tmp_path, doc))[0] == ["manifest_invalid"]


def test_tc_01_06_a_very_deep_document_does_not_raise(tmp_path: Path) -> None:
    path = tmp_path / "chain-manifest.json"
    path.write_text("[" * 100000 + "]" * 100000, encoding="utf-8")
    assert codes_of(path)[0] == ["manifest_invalid"]


def test_tc_01_06_non_utf8_bytes_are_invalid(tmp_path: Path) -> None:
    path = tmp_path / "chain-manifest.json"
    path.write_bytes(b'{"chain_id": "\xff\xfe"}')
    assert codes_of(path)[0] == ["manifest_invalid"]


def test_tc_01_06_a_missing_manifest_is_unreadable(tmp_path: Path) -> None:
    codes, chain, code = codes_of(tmp_path / "absent.json")
    assert codes == ["manifest_unreadable"] and chain == st.BROKEN and code == 34


def test_tc_01_06_a_directory_in_place_of_the_manifest_is_refused(tmp_path: Path) -> None:
    (tmp_path / "chain-manifest.json").mkdir()
    codes, chain, _ = codes_of(tmp_path / "chain-manifest.json")
    assert codes in (["manifest_unreadable"], ["locator_outside_root"]) and chain == st.BROKEN


def test_an_unusable_manifest_evaluates_no_link(tmp_path: Path) -> None:
    result = validator.validate(write(tmp_path, {"x": 1}), tmp_path)
    assert result["payload"]["links"] == [] and result["payload"]["manifest_sha256"] is None
    assert result["payload"]["not_claimed"] == list(st.NOT_CLAIMED)
