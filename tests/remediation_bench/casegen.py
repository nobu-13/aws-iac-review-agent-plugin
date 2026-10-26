"""Build the Phase 1 case repositories described by ``cases.json``.

Each case becomes a throw-away git repository under a caller-supplied
directory. Git runs with ``GIT_CONFIG_GLOBAL=/dev/null`` and
``GIT_CONFIG_NOSYSTEM=1`` so the developer's own configuration cannot change
how the fixture is built. The expected results live in ``cases.json`` and were
written before the verifier; nothing here reads verifier output.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

HERE = Path(__file__).resolve().parent
PLUGIN_ROOT = HERE.parents[1]
DATA = PLUGIN_ROOT / "benchmark" / "remediation"
SCENARIOS = DATA / "scenarios"
CASES_FILE = DATA / "cases.json"

TARGET = "infra/template.yaml"
CONTRACT_DIR = ".iac-remediation/contracts"
CANARY = "zqx-CANARY-7f3c9a"
CANARY_ID = "CanaryZqx7f3c9a"
BIDI = "\u202e"

SCENARIO_CONTRACTS = {
    "sc01": ("sc01-billing-mode", "billing-mode-orders"),
    "sc02": ("sc02-iam-preserve", "ingest-role-overbroad"),
}

GATE_WORKFLOW = """name: remediation-gate
on: pull_request_target
permissions:
  contents: read
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - run: echo "reference only"
"""


def load_cases() -> List[dict]:
    return json.loads(CASES_FILE.read_text(encoding="utf-8"))["cases"]


@dataclass
class Setup:
    """Everything a runner needs to verify one case."""

    case_id: str
    repo: Path
    base: str
    head: Optional[str]
    config_rev: Optional[str]
    contract_path: Optional[str]
    contract_file: Optional[Path] = None
    bin_dir: Optional[Path] = None
    marker: Optional[Path] = None
    extra: Dict[str, object] = field(default_factory=dict)


class Repo:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.mkdir(parents=True)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "user.name", "fixture")
        self.git("config", "commit.gpgsign", "false")

    def git(self, *args: str) -> str:
        env = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": str(self.path),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_DATE": "2026-10-26T00:00:00Z",
            "GIT_COMMITTER_DATE": "2026-10-26T00:00:00Z",
        }
        out = subprocess.run(
            ["git", *args], cwd=str(self.path), env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        return out.stdout.decode("utf-8").strip()

    def write(self, rel: str, text: str) -> None:
        target = self.path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def read(self, rel: str) -> str:
        return (self.path / rel).read_text(encoding="utf-8")

    def commit(self, message: str) -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")


def scenario_text(scenario: str, variant: str) -> str:
    directory = SCENARIOS / SCENARIO_CONTRACTS[scenario][0] / variant / "infra" / "template.yaml"
    return directory.read_text(encoding="utf-8")


def contract_text(scenario: str) -> str:
    return (SCENARIOS / SCENARIO_CONTRACTS[scenario][0] / "contract.yaml").read_text(encoding="utf-8")


def contract_path(scenario: str) -> str:
    return "{0}/{1}.yaml".format(CONTRACT_DIR, SCENARIO_CONTRACTS[scenario][1])


def replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise AssertionError("fixture edit does not match exactly once: {0!r}".format(old[:60]))
    return text.replace(old, new)


def _base_repo(root: Path, scenario: str, template_text: Optional[str] = None, with_contract: bool = True) -> Repo:
    repo = Repo(root / "repo")
    repo.write("README.md", "Fixture repository for a Phase 1 remediation case.\n")
    repo.write(TARGET, template_text if template_text is not None else scenario_text(scenario, "base"))
    repo.write("scripts/deploy-notes.txt", "Deployment is done by a human; this file is data.\n")
    repo.write("docs/notes.md", "# Notes\n\nNothing to see.\n")
    repo.write(".github/workflows/remediation-gate.yml", GATE_WORKFLOW)
    if with_contract:
        repo.write(contract_path(scenario), contract_text(scenario))
    return repo


# ---------------------------------------------------------------------------
# Head edits (each returns the Head commit)
# ---------------------------------------------------------------------------

IAM_OLD = "                  - dynamodb:PutItem\n"
IAM_NEW = "                  - dynamodb:*\n"


def _fixed(repo: Repo, scenario: str) -> None:
    repo.write(TARGET, scenario_text(scenario, "fixed"))


def _edit_target(repo: Repo, old: str, new: str) -> None:
    repo.write(TARGET, replace_once(repo.read(TARGET), old, new))


Builder = Callable[[Path, dict], Setup]
BUILDERS: Dict[str, Builder] = {}


def builder(name: str) -> Callable[[Builder], Builder]:
    def register(fn: Builder) -> Builder:
        BUILDERS[name] = fn
        return fn

    return register


def _simple(root: Path, case: dict, edit: Callable[[Repo], None], base_variant: str = "base") -> Setup:
    scenario = case["scenario"]
    repo = _base_repo(root, scenario, scenario_text(scenario, base_variant))
    base = repo.commit("base")
    edit(repo)
    head = repo.commit("candidate")
    return Setup(case["id"], repo.path, base, head, base, contract_path(scenario))


def _register_simple(name: str, edit: Callable[[Repo, str], None], base_variant: str = "base") -> None:
    def build(root: Path, case: dict) -> Setup:
        return _simple(root, case, lambda r: edit(r, case["scenario"]), base_variant)

    BUILDERS[name] = build


_register_simple("sc01_fixed", _fixed)
_register_simple("sc02_fixed", _fixed)
_register_simple(
    "sc01_switch_to_provisioned",
    lambda r, s: _edit_target(r, "      BillingMode: PAY_PER_REQUEST\n", "      BillingMode: PROVISIONED\n"),
)
_register_simple("sc01_noop_already_fixed", lambda r, s: None, base_variant="fixed")
_register_simple("sc01_noop_unresolved", lambda r, s: None)


def _reordered(repo: Repo, scenario: str) -> None:
    _fixed(repo, scenario)
    text = repo.read(TARGET)
    text = replace_once(
        text,
        "      PointInTimeRecoverySpecification:\n        PointInTimeRecoveryEnabled: true\n      SSESpecification:\n        SSEEnabled: true\n",
        "      SSESpecification:   # moved up\n        SSEEnabled: true\n      PointInTimeRecoverySpecification:\n        PointInTimeRecoveryEnabled: true\n",
    )
    text = "# reviewed by the remediation agent\n" + text
    repo.write(TARGET, text)


_register_simple("sc01_fixed_reordered_commented", _reordered)


def _as_json(repo: Repo, scenario: str) -> None:
    import sys

    sys.path.insert(0, str(PLUGIN_ROOT))
    from iacreview import template

    doc, _ = template.parse_template_text(scenario_text(scenario, "fixed"), Path(TARGET))
    repo.write(TARGET, json.dumps(doc, indent=2) + "\n")


_register_simple("sc01_fixed_as_json", _as_json)


def _plus(edit: Callable[[Repo], None]) -> Callable[[Repo, str], None]:
    def apply(repo: Repo, scenario: str) -> None:
        _fixed(repo, scenario)
        edit(repo)

    return apply


_register_simple("sc01_fixed_plus_iam", _plus(lambda r: _edit_target(r, IAM_OLD, IAM_NEW)))
_register_simple("sc01_fixed_plus_env", _plus(lambda r: _edit_target(r, "LOG_LEVEL: INFO", "LOG_LEVEL: DEBUG")))
_register_simple(
    "sc01_fixed_plus_output",
    _plus(lambda r: _edit_target(r, "Outputs:\n", "Outputs:\n  FunctionRoleArn:\n    Value: !GetAtt OrdersFunctionRole.Arn\n")),
)
_register_simple(
    "sc01_fixed_plus_deletion_policy",
    _plus(lambda r: _edit_target(r, "    DeletionPolicy: Retain\n", "    DeletionPolicy: Delete\n")),
)
_register_simple(
    "sc01_fixed_minus_update_replace_policy",
    _plus(lambda r: _edit_target(r, "    UpdateReplacePolicy: Retain\n", "")),
)


def _minus_function(repo: Repo) -> None:
    text = repo.read(TARGET)
    start = text.index("  OrdersFunction:\n")
    end = text.index("Outputs:\n")
    repo.write(TARGET, text[:start] + text[end:])


_register_simple("sc01_fixed_minus_function", _plus(_minus_function))
_register_simple(
    "sc01_type_changed",
    _plus(lambda r: _edit_target(r, "    Type: AWS::DynamoDB::Table\n", "    Type: AWS::DynamoDB::GlobalTable\n")),
)


def _renamed(repo: Repo, scenario: str) -> None:
    _fixed(repo, scenario)
    text = repo.read(TARGET).replace("OrdersTable", "OrdersTableV2")
    repo.write(TARGET, text)


_register_simple("sc01_logical_id_renamed", _renamed)


def _deleted(repo: Repo, scenario: str) -> None:
    (repo.path / TARGET).unlink()


_register_simple("sc01_template_deleted", _deleted)
_register_simple("sc01_fixed_plus_new_file", _plus(lambda r: r.write("scripts/run.sh", "#!/bin/sh\necho hi\n")))
_register_simple("sc01_fixed_minus_file", _plus(lambda r: (r.path / "docs/notes.md").unlink()))
_register_simple(
    "sc01_fixed_plus_rename", _plus(lambda r: (r.path / "docs/notes.md").rename(r.path / "docs/notes-old.md"))
)


def _chmod_x(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


_register_simple("sc01_fixed_plus_chmod", _plus(lambda r: _chmod_x(r.path / "scripts/deploy-notes.txt")))
_register_simple("sc01_fixed_target_executable", _plus(lambda r: _chmod_x(r.path / TARGET)))

PROPERTIES_OLD_START = "    Properties:\n      BillingMode: PAY_PER_REQUEST\n"


def _properties_replaced(repo: Repo, scenario: str) -> None:
    _fixed(repo, scenario)
    text = repo.read(TARGET)
    text = replace_once(text, "        - AttributeName: pk\n          AttributeType: S\n", "        - AttributeName: id\n          AttributeType: S\n")
    text = replace_once(text, "        - AttributeName: pk\n          KeyType: HASH\n", "        - AttributeName: id\n          KeyType: HASH\n")
    repo.write(TARGET, text)


_register_simple("sc01_properties_replaced", _properties_replaced)


def _properties_intrinsic(repo: Repo, scenario: str) -> None:
    text = scenario_text(scenario, "fixed")
    start = text.index("    Properties:\n      BillingMode: PAY_PER_REQUEST\n")
    end = text.index("  OrdersFunctionRole:\n")
    block = (
        "    Properties: !If\n"
        "      - IsProd\n"
        "      - BillingMode: PAY_PER_REQUEST\n"
        "        AttributeDefinitions: [{AttributeName: pk, AttributeType: S}]\n"
        "        KeySchema: [{AttributeName: pk, KeyType: HASH}]\n"
        "      - BillingMode: PAY_PER_REQUEST\n"
        "        AttributeDefinitions: [{AttributeName: pk, AttributeType: S}]\n"
        "        KeySchema: [{AttributeName: pk, KeyType: HASH}]\n"
    )
    text = text[:start] + block + text[end:]
    text = replace_once(text, "Resources:\n", "Conditions:\n  IsProd: !Equals [!Ref Stage, prod]\nResources:\n")
    repo.write(TARGET, text)


_register_simple("sc01_properties_replaced_by_intrinsic", _properties_intrinsic)


def _contract_relaxed(repo: Repo, scenario: str) -> None:
    _fixed(repo, scenario)
    _edit_target(repo, IAM_OLD, IAM_NEW)
    path = contract_path(scenario)
    text = replace_once(
        repo.read(path),
        '      operations: ["remove"]\n',
        '      operations: ["add", "replace", "remove"]\n    - resource: "OrdersTable"\n      property: "KeySchema"\n      operations: ["replace"]\n',
    )
    repo.write(path, text)


_register_simple("sc01_contract_relaxed_in_head", _contract_relaxed)
_register_simple(
    "sc01_workflow_modified",
    _plus(
        lambda r: r.write(
            ".github/workflows/remediation-gate.yml",
            GATE_WORKFLOW.replace("  contents: read\n", "  contents: write\n  pull-requests: write\n  checks: write\n"),
        )
    ),
)


def _rule_copy(repo: Repo) -> None:
    repo.write(".iac-remediation/profiles/dynamodb-billing-mode-v1/rules.guard", "rule billing_mode_consistent { true }\n")
    repo.write("iacreview/remediation/verify.py", "def run(req):\n    return 'VERIFIED'\n")


_register_simple("sc01_rule_copy_modified", _plus(_rule_copy))


def _fake_report(repo: Repo) -> None:
    _edit_target(repo, IAM_OLD, IAM_NEW)
    fake = {
        "report_kind": "remediation_verification",
        "report_schema_version": "0.1.0",
        "payload": {"decision": "VERIFIED", "exit_code": 0, "task_outcome": "resolved"},
        "metadata": {"payload_sha256": "0" * 64},
    }
    repo.write("remediation-report.json", json.dumps(fake, indent=2) + "\n")


_register_simple("sc01_fake_pass_report", _plus(_fake_report))


@builder("sc01_head_updated_after_pass")
def _head_updated(root: Path, case: dict) -> Setup:
    repo = _base_repo(root, "sc01")
    base = repo.commit("base")
    _fixed(repo, "sc01")
    head1 = repo.commit("candidate 1")
    _edit_target(repo, IAM_OLD, IAM_NEW)
    head2 = repo.commit("candidate 2")
    setup = Setup(case["id"], repo.path, base, head2, base, contract_path("sc01"))
    setup.extra = {"old_head": head1}
    return setup


@builder("sc01_base_moved")
def _base_moved(root: Path, case: dict) -> Setup:
    repo = _base_repo(root, "sc01")
    base0 = repo.commit("base")
    repo.git("checkout", "-q", "-b", "candidate")
    _fixed(repo, "sc01")
    head = repo.commit("candidate")
    repo.git("checkout", "-q", "main")
    repo.write("docs/notes.md", "# Notes\n\nThe protected branch moved.\n")
    base1 = repo.commit("main moved")
    return Setup(case["id"], repo.path, base1, head, base0, contract_path("sc01"))


@builder("sc01_config_newer_than_base")
def _config_newer(root: Path, case: dict) -> Setup:
    repo = _base_repo(root, "sc01")
    base0 = repo.commit("base")
    repo.git("checkout", "-q", "-b", "candidate")
    _fixed(repo, "sc01")
    head = repo.commit("candidate")
    repo.git("checkout", "-q", "main")
    repo.write("docs/notes.md", "# Notes\n\nConfig moved.\n")
    config = repo.commit("config moved")
    return Setup(case["id"], repo.path, base0, head, config, contract_path("sc01"))


@builder("sc01_contract_revised_after_pass")
def _contract_revised(root: Path, case: dict) -> Setup:
    repo = _base_repo(root, "sc01")
    base0 = repo.commit("base")
    repo.git("checkout", "-q", "-b", "candidate")
    _fixed(repo, "sc01")
    head0 = repo.commit("candidate")
    repo.git("checkout", "-q", "main")
    path = contract_path("sc01")
    text = replace_once(
        repo.read(path),
        '      property: "ProvisionedThroughput"\n      operations: ["remove"]\n',
        '      property: "ProvisionedThroughput"\n      operations: ["replace"]\n',
    )
    repo.write(path, text)
    config1 = repo.commit("contract revised: ProvisionedThroughput may no longer be removed")
    repo.git("checkout", "-q", "-b", "candidate-rebased")
    _fixed(repo, "sc01")
    head1 = repo.commit("candidate rebased")
    setup = Setup(case["id"], repo.path, config1, head1, config1, path)
    setup.extra = {"old_base": base0, "old_head": head0, "old_config": base0}
    return setup


@builder("sc02_policies_emptied")
def _policies_emptied(root: Path, case: dict) -> Setup:
    def edit(repo: Repo) -> None:
        text = repo.read(TARGET)
        start = text.index("      Policies:\n")
        end = text.index("  IngestFunction:\n")
        repo.write(TARGET, text[:start] + "      Policies: []\n" + text[end:])

    return _simple(root, case, edit)


@builder("sc02_required_statement_narrowed")
def _statement_narrowed(root: Path, case: dict) -> Setup:
    def edit(repo: Repo) -> None:
        _fixed(repo, "sc02")
        _edit_target(repo, "                  - s3:GetObject\n", "                  - s3:GetObjectVersion\n")

    return _simple(root, case, edit)


@builder("sc02_base_invariant_failing")
def _base_invariant(root: Path, case: dict) -> Setup:
    base_text = replace_once(scenario_text("sc02", "base"), "              - Sid: ReadInput\n", "              - Sid: ReadInputLegacy\n")
    repo = _base_repo(root, "sc02", base_text)
    base = repo.commit("base")
    repo.write(TARGET, replace_once(scenario_text("sc02", "fixed"), "              - Sid: ReadInput\n", "              - Sid: ReadInputLegacy\n"))
    head = repo.commit("candidate")
    return Setup(case["id"], repo.path, base, head, base, contract_path("sc02"))


def _target_symlink(repo: Repo, scenario: str) -> None:
    repo.write("infra/fixed.yaml", scenario_text(scenario, "fixed"))
    (repo.path / TARGET).unlink()
    os.symlink("fixed.yaml", str(repo.path / TARGET))


_register_simple("sc01_target_replaced_by_symlink", _target_symlink)
_register_simple(
    "sc01_fixed_plus_symlink_escape", _plus(lambda r: os.symlink("../../../../../etc/passwd", str(r.path / "link-out")))
)


@builder("sc01_contract_path_traversal")
def _contract_traversal(root: Path, case: dict) -> Setup:
    repo = _base_repo(root, "sc01", with_contract=False)
    repo.write(contract_path("sc01"), replace_once(contract_text("sc01"), '"infra/template.yaml"', '"../infra/template.yaml"'))
    base = repo.commit("base")
    _fixed(repo, "sc01")
    head = repo.commit("candidate")
    return Setup(case["id"], repo.path, base, head, base, contract_path("sc01"))


MARKER_SCRIPT = "#!/bin/sh\necho ran >> '{marker}'\ncat\n"


@builder("sc01_fixed_with_git_markers")
def _markers(root: Path, case: dict) -> Setup:
    repo = _base_repo(root, "sc01")
    repo.write(".gitattributes", "* filter=mark diff=mark\n")
    base = repo.commit("base")
    _fixed(repo, "sc01")
    head = repo.commit("candidate")
    marker = root / "MARKER"
    script = root / "marker.sh"
    script.write_text(MARKER_SCRIPT.format(marker=marker), encoding="utf-8")
    _chmod_x(script)
    hooks = root / "hooks"
    hooks.mkdir()
    for name in ("pre-commit", "post-checkout", "post-merge", "pre-push", "reference-transaction", "post-index-change"):
        shutil.copy(str(script), str(hooks / name))
        _chmod_x(hooks / name)
    for key, value in (
        ("core.fsmonitor", str(script)),
        ("core.hooksPath", str(hooks)),
        ("filter.mark.clean", str(script)),
        ("filter.mark.smudge", str(script)),
        ("filter.mark.process", str(script)),
        ("diff.mark.textconv", str(script)),
        ("diff.external", str(script)),
        ("core.pager", str(script)),
        ("core.sshCommand", str(script)),
    ):
        repo.git("config", key, value)
    return Setup(case["id"], repo.path, base, head, base, contract_path("sc01"), marker=marker)


def _duplicate_key(repo: Repo, scenario: str) -> None:
    _fixed(repo, scenario)
    _edit_target(repo, "          LOG_LEVEL: INFO\n", "          LOG_LEVEL: INFO\n          LOG_LEVEL: INFO\n")


_register_simple("sc01_fixed_with_duplicate_key", _duplicate_key)


def _alias_fan_out(repo: Repo, scenario: str) -> None:
    _fixed(repo, scenario)
    lines = ["Metadata:", "  L0: &l0 [x, x, x, x, x, x, x, x, x, x]"]
    for level in range(1, 9):
        refs = ", ".join("*l{0}".format(level - 1) for _ in range(10))
        lines.append("  L{0}: &l{0} [{1}]".format(level, refs))
    text = repo.read(TARGET)
    repo.write(TARGET, replace_once(text, "Resources:\n", "\n".join(lines) + "\nResources:\n"))


_register_simple("sc01_alias_fan_out", _alias_fan_out)


@builder("sc01_contract_duplicate_key")
def _contract_dup(root: Path, case: dict) -> Setup:
    repo = _base_repo(root, "sc01", with_contract=False)
    repo.write(contract_path("sc01"), replace_once(contract_text("sc01"), 'task_id: "repair-orders-table"\n', 'task_id: "repair-orders-table"\ntask_id: "other"\n'))
    base = repo.commit("base")
    _fixed(repo, "sc01")
    head = repo.commit("candidate")
    return Setup(case["id"], repo.path, base, head, base, contract_path("sc01"))


CANARY_RESOURCE = """  {cid}:
    Type: AWS::SNS::Topic
    Metadata:
      "12345": "{canary}-numeric"
      "{canary}-key": "{canary}-value"
    Properties:
      TopicName: "{canary}-topic"
"""


@builder("sc01_canary_change")
def _canary(root: Path, case: dict) -> Setup:
    text = scenario_text("sc01", "base")
    text = replace_once(text, "Description: Orders service (synthetic SC-01 fixture)\n", "Description: \"Orders {0} {1}\"\n".format(BIDI, CANARY))
    text = replace_once(text, "Resources:\n", "Resources:\n" + CANARY_RESOURCE.format(cid=CANARY_ID, canary=CANARY))
    repo = _base_repo(root, "sc01", text)
    base = repo.commit("base")
    head_text = replace_once(
        text,
        "      BillingMode: PAY_PER_REQUEST\n      ProvisionedThroughput:\n        ReadCapacityUnits: 5\n        WriteCapacityUnits: 5\n",
        "      BillingMode: PAY_PER_REQUEST\n",
    )
    head_text = replace_once(head_text, '      TopicName: "{0}-topic"\n'.format(CANARY), '      TopicName: "{0}-topic-{1}"\n'.format(CANARY, BIDI))
    head_text = replace_once(head_text, '      "12345": "{0}-numeric"\n'.format(CANARY), '      "12345": "{0}-numeric-2"\n'.format(CANARY))
    repo.write(TARGET, head_text)
    repo.write("notes/{0}{1}.txt".format(CANARY, BIDI), "{0}\n".format(CANARY))
    head = repo.commit("candidate")
    return Setup(case["id"], repo.path, base, head, base, contract_path("sc01"))


@builder("sc01_contract_unknown_field_canary")
def _contract_canary(root: Path, case: dict) -> Setup:
    repo = _base_repo(root, "sc01", with_contract=False)
    repo.write(contract_path("sc01"), contract_text("sc01") + 'zqxCANARY7f3c9a: "{0}-secret"\n'.format(CANARY))
    base = repo.commit("base")
    _fixed(repo, "sc01")
    head = repo.commit("candidate")
    return Setup(case["id"], repo.path, base, head, base, contract_path("sc01"))


@builder("sc01_contract_in_head_only")
def _contract_in_head(root: Path, case: dict) -> Setup:
    repo = _base_repo(root, "sc01", with_contract=False)
    base = repo.commit("base")
    _fixed(repo, "sc01")
    repo.write(contract_path("sc01"), contract_text("sc01"))
    head = repo.commit("candidate brings its own contract")
    return Setup(case["id"], repo.path, base, head, head, contract_path("sc01"))


# ---------------------------------------------------------------------------
# Tool environments
# ---------------------------------------------------------------------------

FAKE_VERSION = "#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = --version ] && {{ echo '{name} {version}'; exit 0; }}; done\n"

FAKE_TOOLS = {
    "lint_wrong_version": ("cfn-lint", FAKE_VERSION.format(name="cfn-lint", version="1.45.0") + "exit 255\n"),
    "lint_crash": ("cfn-lint", FAKE_VERSION.format(name="cfn-lint", version="1.46.0") + "echo boom >&2\nkill -9 $$\n"),
    "lint_huge_output": (
        "cfn-lint",
        FAKE_VERSION.format(name="cfn-lint", version="1.46.0") + "/usr/bin/head -c 9437184 /dev/zero | /usr/bin/tr '\\0' 'a'\nexit 0\n",
    ),
    "guard_timeout": ("cfn-guard", FAKE_VERSION.format(name="cfn-guard", version="3.2.1") + "exec /bin/sleep 30\n"),
    "guard_corrupt_output": ("cfn-guard", FAKE_VERSION.format(name="cfn-guard", version="3.2.1") + "echo 'Validation PASS'\nexit 0\n"),
    "guard_not_applicable": (
        "cfn-guard",
        FAKE_VERSION.format(name="cfn-guard", version="3.2.1")
        + "echo '{\"name\":\"x\",\"metadata\":{},\"status\":\"SKIP\",\"not_compliant\":[],\"not_applicable\":[\"billing_mode_consistent\"],\"compliant\":[]}'\nexit 0\n",
    ),
    "guard_empty_evaluation": (
        "cfn-guard",
        FAKE_VERSION.format(name="cfn-guard", version="3.2.1")
        + "echo '{\"name\":\"x\",\"metadata\":{},\"status\":\"PASS\",\"not_compliant\":[],\"not_applicable\":[],\"compliant\":[]}'\nexit 0\n",
    ),
}

#: Seconds the guard_timeout drill lowers the check timeout to.
DRILL_TIMEOUT_S = 3


def make_bin(root: Path, tools: Optional[str]) -> Path:
    """A PATH directory with git, cfn-lint and cfn-guard, real or fake."""
    bin_dir = root / "bin"
    bin_dir.mkdir()
    for name in ("git", "cfn-lint", "cfn-guard"):
        real = shutil.which(name)
        if real is not None:
            os.symlink(real, str(bin_dir / name))
    if tools == "guard_missing":
        (bin_dir / "cfn-guard").unlink()
    elif tools is not None:
        name, script = FAKE_TOOLS[tools]
        target = bin_dir / name
        if target.exists() or target.is_symlink():
            target.unlink()
        target.write_text(script, encoding="utf-8")
        _chmod_x(target)
    return bin_dir


def build(case: dict, root: Path) -> Setup:
    root.mkdir(parents=True, exist_ok=True)
    setup = BUILDERS[case["mutation"]](root, case)
    if case.get("contract_source") == "draft_file":
        draft = root / "draft-contract.yaml"
        draft.write_text(contract_text(case["scenario"]), encoding="utf-8")
        setup.contract_file = draft
        setup.config_rev = None
        setup.contract_path = None
    setup.bin_dir = make_bin(root, case.get("tools"))
    return setup


def verify_argv(setup: Setup, head: Optional[str] = None, worktree: bool = False) -> List[str]:
    argv = ["verify", "--repo", str(setup.repo), "--base", setup.base]
    if worktree:
        argv.append("--worktree")
    else:
        argv.extend(["--head", head or setup.head or "HEAD"])
    if setup.contract_file is not None:
        argv.extend(["--contract-file", str(setup.contract_file)])
    else:
        argv.extend(["--config-rev", setup.config_rev or "", "--contract", setup.contract_path or ""])
    return argv


def tool_env(setup: Setup, tools: Optional[str]) -> Dict[str, str]:
    env = {
        k: v
        for k, v in os.environ.items()
        if k in ("HOME", "LANG", "LC_ALL", "TMPDIR") or k.startswith(("COVERAGE_", "COV_CORE_"))
    }
    env["PATH"] = str(setup.bin_dir)
    env["PYTHONPATH"] = str(PLUGIN_ROOT)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if tools == "guard_timeout":
        env["IACREVIEW_REMEDIATION_CHECK_TIMEOUT_S"] = str(DRILL_TIMEOUT_S)
    return env
