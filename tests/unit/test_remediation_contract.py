"""Phase 1 contract loader: strict YAML, closed schema, profile narrowing only."""

from __future__ import annotations

from pathlib import Path

import pytest

from iacreview.remediation import contract as c
from iacreview.remediation import profiles

ROOT = Path(__file__).resolve().parents[2]
SC01 = (ROOT / "benchmark/remediation/scenarios/sc01-billing-mode/contract.yaml").read_text(encoding="utf-8")
SC02 = (ROOT / "benchmark/remediation/scenarios/sc02-iam-preserve/contract.yaml").read_text(encoding="utf-8")
CANARY = "zqx-CANARY-7f3c9a"


def load(text: str) -> c.Contract:
    return c.parse_contract_bytes(text.encode("utf-8"))


def bind(text: str) -> profiles.Profile:
    return c.bind_profile(load(text), profiles.load_all())


def reason(text: str) -> str:
    with pytest.raises(c.ContractError) as info:
        bind(text)
    assert CANARY not in str(info.value)
    return info.value.reason


def test_the_fixture_contracts_load_and_bind() -> None:
    sc01 = load(SC01)
    assert sc01.resource == "OrdersTable"
    assert [e.property for e in sc01.allowed_edits] == ["BillingMode", "ProvisionedThroughput"]
    assert bind(SC01).profile_id == "dynamodb-billing-mode-v1"
    sc02 = load(SC02)
    assert sc02.parameters == {"required_statement_sid": "ReadInput"}
    assert bind(SC02).profile_id == "iam-inline-policy-overbroad-v1"


@pytest.mark.parametrize(
    "old,new,expected",
    [
        ('task_id: "repair-orders-table"\n', 'task_id: &a "repair-orders-table"\nx: *a\n', "anchor_not_allowed"),
        ('task_id: "repair-orders-table"\n', 'task_id: !!str "repair-orders-table"\n', "tag_not_allowed"),
        ('task_id: "repair-orders-table"\n', 'task_id: "repair-orders-table"\ntask_id: "x"\n', "duplicate_key"),
        ('task_id: "repair-orders-table"\n', 'task_id: "repair-orders-table"\napproved_by: "security-lead"\n', "unknown_key"),
        ('task_id: "repair-orders-table"\n', 'task_id: "repair-orders-table"\n{0}: "{0}"\n'.format("zqxCANARY"), "unknown_key"),
        ('profile_version: "1"\n', "profile_version: 1\n", "non_string_scalar"),
        ('profile_version: "1"\n', 'profile_version: "2"\n', "profile_version_mismatch"),
        ('contract_schema_version: "0.1.0"\n', 'contract_schema_version: "9.9.9"\n', "unsupported_schema_version"),
        ('      property: "BillingMode"\n', '      property: "*"\n', "invalid_value"),
        ('      property: "BillingMode"\n', '      property: "Billing*"\n', "invalid_value"),
        ('      property: "BillingMode"\n', '      property: "KeySchema"\n', "edit_not_permitted_by_profile"),
        ('      operations: ["add", "replace"]\n', '      operations: []\n', "non_empty_list_required"),
        ('      operations: ["add", "replace"]\n', '      operations: ["add", "add"]\n', "duplicate_item"),
        ('      operations: ["add", "replace"]\n', '      operations: ["rename"]\n', "invalid_value"),
        ('      operations: ["remove"]\n', '      operations: ["remove"]\n    - resource: "OrdersFunctionRole"\n      property: "BillingMode"\n      operations: ["add"]\n', "one_resource_per_contract"),
        ('    - "billing-mode-consistent"\n', '    - "something-else"\n', "unknown_outcome"),
        ('    - "outside-allowed-edits-unchanged"\n', '    - "billing-mode-consistent"\n', "unknown_invariant"),
        ('    - "profile-guard"\n', "", "mandatory_check_missing"),
        ('  template_path: "infra/template.yaml"\n', '  template_path: "../infra/template.yaml"\n', "invalid_path"),
        ('  template_path: "infra/template.yaml"\n', '  template_path: "/etc/template.yaml"\n', "invalid_path"),
        ('  template_path: "infra/template.yaml"\n', '  template_path: "infra/./template.yaml"\n', "invalid_path"),
        ('  template_path: "infra/template.yaml"\n', '  template_path: "infra\\\\template.yaml"\n', "invalid_path"),
        ('  template_path: "infra/template.yaml"\n', '  template_path: "infra/template.sh"\n', "invalid_path"),
        ('  template_path: "infra/template.yaml"\n', '  template_path: "infra/t\\u202emplate.yaml"\n', "invalid_path"),
    ],
)
def test_invalid_contracts_are_rejected_with_a_closed_reason(old: str, new: str, expected: str) -> None:
    assert SC01.count(old) == 1
    assert reason(SC01.replace(old, new)) == expected


def test_the_sc02_parameter_must_match_the_profile() -> None:
    assert reason(SC02.replace('required_statement_sid: "ReadInput"', 'required_statement_sid: "Read Input"')) == "invalid_value"
    assert reason(SC02.replace('  parameters:\n    required_statement_sid: "ReadInput"\n', "  parameters: {}\n")) == "parameters_do_not_match_profile"
    assert reason(SC02.replace('    required_statement_sid: "ReadInput"\n', "")) == "non_string_scalar"
    assert reason(SC02.replace("    - \"required-statement-preserved\"\n", "")) == "mandatory_invariant_missing"


@pytest.mark.parametrize(
    "raw",
    [b"\xff\xfe", b"a: 1\n---\nb: 2\n", b"[unclosed", b"x" * (64 * 1024 + 1), b"a: \x00"],
    ids=["not-utf8", "two-documents", "parse-error", "too-large", "nul"],
)
def test_malformed_bytes_fail_closed(raw: bytes) -> None:
    with pytest.raises(c.ContractError):
        c.parse_contract_bytes(raw)


def test_an_unknown_profile_is_its_own_code() -> None:
    with pytest.raises(c.ContractError) as info:
        bind(SC01.replace('profile_id: "dynamodb-billing-mode-v1"', 'profile_id: "unknown-v1"'))
    assert info.value.code == "profile_unknown"


def test_render_contract_round_trips() -> None:
    contract = load(SC02)
    fields = {
        "contract_id": contract.contract_id,
        "profile_id": contract.profile_id,
        "profile_version": contract.profile_version,
        "task_id": contract.task_id,
        "template_path": contract.template_path,
        "allowed_edits": [{"resource": e.resource, "property": e.property, "operations": sorted(e.operations)} for e in contract.allowed_edits],
        "required_outcomes": list(contract.required_outcomes),
        "preserve_invariants": list(contract.preserve_invariants),
        "parameters": dict(contract.parameters),
        "required_checks": list(contract.required_checks),
    }
    again = load(c.render_contract(fields))
    assert again == contract


def test_profiles_are_well_formed_and_pinned() -> None:
    shipped = profiles.load_all()
    assert sorted(shipped) == ["dynamodb-billing-mode-v1", "iam-inline-policy-overbroad-v1"]
    for prof in shipped.values():
        assert prof.tools == {"cfn-lint": "1.46.0", "cfn-guard": "3.2.1"}
        assert set(prof.mandatory_checks) == {"cfn-lint", "profile-guard"}
        assert len(prof.digest) == 64
        assert "when" not in [line.split()[0] for line in prof.rules_path.read_text().splitlines() if line.startswith("rule")]
