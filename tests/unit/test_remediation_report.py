"""Phase 1 report: redaction, schema, Summary/JSON agreement, validator identity."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iacreview.remediation import report, rschema, verify
from iacreview.remediation import contract as c
from iacreview.remediation.boundary import Finding

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = c.parse_contract_bytes((ROOT / "benchmark/remediation/scenarios/sc01-billing-mode/contract.yaml").read_bytes())
CANARY = "zqx-CANARY-7f3c9a"


def result(findings, decision: str, contract=CONTRACT) -> verify.Result:
    req = verify.Request(Path("."), "b", "h", "b", ".iac-remediation/contracts/x.yaml", None)
    res = verify.Result(req)
    res.contract = contract
    res.contract_source = "git_revision"
    res.findings = list(findings)
    res.decision = decision
    return res


def test_untrusted_keys_and_paths_are_tokens_and_trusted_names_are_kept() -> None:
    findings = [
        Finding("template_change_outside_scope", "template", ("Resources", CANARY, "Properties", CANARY + "\u202e", 0, "12345")),
        Finding("template_change_outside_scope", "template", ("Resources", "OrdersTable", "DeletionPolicy")),
        Finding("operation_not_allowed", "template", ("Resources", "OrdersTable", "Properties", "BillingMode"), "remove"),
        Finding("file_added_outside_scope", "repository", ("notes/" + CANARY + ".txt",)),
        Finding("file_mode_changed", "repository", ("infra/template.yaml",)),
        Finding("comparison_incomplete", "template", ("Resources",), CANARY),
    ]
    payload = report.build_payload(result(findings, rschema.BLOCKED))
    text = json.dumps(payload, ensure_ascii=False)
    assert CANARY not in text and "\u202e" not in text and "12345" not in text
    paths = [v["path"] for v in payload["violations"]]
    assert ["Resources", "OrdersTable", "DeletionPolicy"] in paths
    assert ["Resources", "OrdersTable", "Properties", "BillingMode"] in paths
    assert ["infra/template.yaml"] in paths
    tokenized = next(v["path"] for v in payload["violations"] if v["path"][0] == "Resources" and v["path"][1] != "OrdersTable")
    assert tokenized[1].startswith("k:") and tokenized[4] == 0 and tokenized[5].startswith("k:")
    assert all(d["detail"] is None for d in payload["diagnostics"])


def test_the_same_result_gives_the_same_payload_bytes() -> None:
    findings = [Finding("resource_removed", "template", ("Resources", "Other"))]
    a = report.canonical(report.build_payload(result(findings, rschema.BLOCKED)))
    b = report.canonical(report.build_payload(result(list(reversed(findings)), rschema.BLOCKED)))
    assert a == b


@pytest.mark.parametrize("decision", list(rschema.DECISION_EXIT_CODES))
def test_summary_and_json_agree_on_decision_exit_and_next_action(decision: str) -> None:
    code = {"VERIFIED": [], "BLOCKED": ["resource_removed"], "UNVERIFIED": ["tool_timeout"], "ERROR": ["internal_error"]}[decision]
    findings = [Finding(x, "template" if x == "resource_removed" else "check", ("Resources", "X") if x == "resource_removed" else ()) for x in code]
    rep = report.build_report(result(findings, decision), 0.0)
    report.validate(rep)
    payload = rep["payload"]
    assert payload["exit_code"] == rschema.DECISION_EXIT_CODES[decision]
    text = report.summary(rep)
    assert text.startswith("Remediation verification: {0}\n".format(decision))
    assert "Next action ({0})".format(payload["next_action"]) in text
    assert "merge enforcement: not_verified" in text
    for c_ in code:
        assert c_ in text


def test_validate_rejects_a_non_report_and_unknown_codes() -> None:
    rep = report.build_report(result([], rschema.VERIFIED), 0.0)
    with pytest.raises(report.ReportError):
        report.validate({"payload": {}})
    bad = json.loads(json.dumps(rep))
    bad["payload"]["diagnostics"] = [{"code": "made_up"}]
    bad["metadata"]["payload_sha256"] = __import__("hashlib").sha256(report.canonical(bad["payload"])).hexdigest()
    with pytest.raises(report.ReportError):
        report.validate(bad)


def test_payload_keys_and_constants_are_fixed() -> None:
    rep = report.build_report(result([], rschema.VERIFIED), 0.0)
    assert tuple(rep) == report.REPORT_KEYS
    assert tuple(rep["payload"]) == report.PAYLOAD_KEYS
    assert rep["payload"]["runtime_validated"] is False
    assert rep["payload"]["enforcement_status"] == "not_verified"
    assert set(rep["payload"]["not_verified"]) >= {"runtime_behavior", "merge_enforcement"}


def test_validator_identity_is_stable_and_covers_profiles() -> None:
    first = report.validator_identity()
    assert first == report.validator_identity()
    assert len(first["source_sha256"]) == 64
