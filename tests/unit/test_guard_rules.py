"""Structural checks for the bundled cfn-guard rule set.

Requirement 5 AC2 requires at least one Guard rule per category, and AC8 requires
one directory per category so that a new rule file can be added without touching
existing rule files. Those properties are only useful if they are enforced, so
this module walks ``rules/`` and verifies the conventions declared in design.md
(cfn-guard Integration):

* six category directories, each holding at least one ``.guard`` file
* ``<lowercase_snake_case>.guard`` file names
* one rule per file, named exactly after the file
* a ``<<...>>`` custom message, which becomes ``SuggestedRemediation`` (AC3)

It also walks the ``_meta.json`` sidecars that carry the severity metadata
cfn-guard itself does not have (design.md, "Severity の付与方式"). The exhaustive
join test is what makes the contributor workflow safe: adding a ``.guard`` file
without adding its ``_meta.json`` entry fails in CI instead of silently falling
back to ``BestPractice`` / ``MEDIUM``.

The last test runs cfn-guard itself so that a rule with valid-looking text but
invalid Guard syntax cannot reach main. It is skipped where cfn-guard is not
installed, because the plugin must remain usable without it.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

# tests/unit/test_guard_rules.py -> tests/unit -> tests -> plugin root
PLUGIN_ROOT: Path = Path(__file__).resolve().parents[2]
RULES_DIR: Path = PLUGIN_ROOT / "rules"
VALID_TEMPLATE: Path = (
    PLUGIN_ROOT / "tests" / "fixtures" / "valid" / "minimal_compliant_template.yaml"
)

# Requirement 5 AC2: Encryption, Public Access, Logging, Tagging, IAM, Backup.
CATEGORY_DIRECTORIES = [
    "encryption",
    "public-access",
    "iam",
    "logging",
    "backup",
    "tagging",
]

# The rule set declared by design.md. Pinned so that a rule file which is
# deleted or renamed is reported rather than silently dropping test cases.
EXPECTED_GUARD_FILES = [
    "backup/asg_multi_az.guard",
    "backup/dynamodb_pitr.guard",
    "backup/ec2_ebs_optimized.guard",
    "backup/lambda_dlq.guard",
    "backup/lambda_timeout.guard",
    "backup/rds_backup_retention.guard",
    "backup/rds_deletion_protection.guard",
    "backup/rds_multi_az.guard",
    "backup/s3_deletion_policy.guard",
    "backup/s3_versioning_enabled.guard",
    "backup/secrets_rotation.guard",
    "encryption/dynamodb_encryption.guard",
    "encryption/ebs_volume_encrypted.guard",
    "encryption/efs_encryption.guard",
    "encryption/elasticache_encryption.guard",
    "encryption/kinesis_encryption.guard",
    "encryption/logs_group_encrypted.guard",
    "encryption/rds_storage_encrypted.guard",
    "encryption/redshift_encryption.guard",
    "encryption/s3_bucket_encryption.guard",
    "encryption/sns_topic_encrypted.guard",
    "encryption/sqs_queue_encrypted.guard",
    "iam/iam_policy_no_star_star.guard",
    "logging/alb_access_logging.guard",
    "logging/cloudtrail_enabled.guard",
    "logging/logs_retention_set.guard",
    "logging/s3_access_logging.guard",
    "logging/vpc_flow_logs.guard",
    "public-access/alb_https_only.guard",
    "public-access/cloudfront_https.guard",
    "public-access/ec2_imdsv2_required.guard",
    "public-access/rds_publicly_accessible.guard",
    "public-access/s3_public_access_block.guard",
    "public-access/security_group_open_ingress.guard",
    "tagging/required_tags.guard",
]

_RULE_DECLARATION = re.compile(r"^rule\s+([A-Za-z0-9_]+)", re.MULTILINE)
_LOWER_SNAKE_CASE = re.compile(r"^[a-z][a-z0-9_]*$")

META_FILENAME = "_meta.json"

# The closed Normalized_Category vocabulary (design.md, Normalized Category
# Vocabulary). Duplicated here rather than imported because iacreview/
# category_map.json is the authoritative copy and is introduced by a later task;
# tests/unit/test_categories.py will assert the two agree.
NORMALIZED_CATEGORIES = frozenset(
    {
        "IAM",
        "Encryption",
        "PublicAccess",
        "Logging",
        "Tagging",
        "Availability",
        "Backup",
        "NetworkSecurity",
        "DataProtection",
        "TemplateQuality",
        "Other",
    }
)

FINDING_TYPES = frozenset({"Security", "Validity", "BestPractice", "Informational"})
SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})

# Per-rule entries carry these keys. `normalized_category` stays optional: it is
# only present where a rule leaves its category default, which the sidecar
# resolution order allows.
REQUIRED_RULE_KEYS = ("severity", "why_it_matters", "recommendation")
OPTIONAL_RULE_KEYS = ("normalized_category", "finding_type")

# The single rule that overrides its category default (design.md: an ingress rule
# open to the internet is a network boundary problem, not object exposure).
NORMALIZED_CATEGORY_OVERRIDES = {
    "security_group_open_ingress": "NetworkSecurity",
    "rds_deletion_protection": "Availability",
    "s3_versioning_enabled": "DataProtection",
    "ec2_imdsv2_required": "DataProtection",
    "rds_multi_az": "Availability",
    "vpc_flow_logs": "NetworkSecurity",
    "dynamodb_pitr": "DataProtection",
    "secrets_rotation": "DataProtection",
    "lambda_dlq": "Availability",
    "lambda_timeout": "Availability",
    "asg_multi_az": "Availability",
    "ec2_ebs_optimized": "Availability",
}

# cfn-guard reports an unparseable rule file on stderr and exits 5. Both signals
# are checked because the exit code alone is not documented as stable.
_PARSE_ERROR_MARKERS = ("Parser Error", "Parsing error handling rule file")
_PARSE_ERROR_EXIT_CODE = 5


def _guard_files() -> list[Path]:
    return sorted(RULES_DIR.rglob("*.guard"))


def _relative_guard_paths() -> list[str]:
    return [path.relative_to(RULES_DIR).as_posix() for path in _guard_files()]


def _rule_names(text: str) -> list[str]:
    return _RULE_DECLARATION.findall(text)


def _meta_files() -> list[Path]:
    return sorted(RULES_DIR.rglob(META_FILENAME))


def _relative_meta_paths() -> list[str]:
    return [path.relative_to(RULES_DIR).as_posix() for path in _meta_files()]


def _load_meta(meta_file: Path) -> dict[str, Any]:
    return json.loads(meta_file.read_text(encoding="utf-8"))


def _meta_rules(meta_file: Path) -> dict[str, Any]:
    return _load_meta(meta_file).get("rules", {})


def test_plugin_root_matches_the_shared_fixture(plugin_root: Path) -> None:
    # Guards against the module level constant drifting from conftest.
    assert PLUGIN_ROOT == plugin_root


def test_rules_directory_exists() -> None:
    assert RULES_DIR.is_dir()


def test_bundled_rule_set_matches_the_expected_file_list() -> None:
    assert _relative_guard_paths() == EXPECTED_GUARD_FILES


@pytest.mark.parametrize("category", CATEGORY_DIRECTORIES)
def test_category_directory_exists(category: str) -> None:
    assert (RULES_DIR / category).is_dir()


@pytest.mark.parametrize("category", CATEGORY_DIRECTORIES)
def test_category_has_at_least_one_guard_file(category: str) -> None:
    # Requirement 5 AC2.
    assert sorted((RULES_DIR / category).glob("*.guard")) != []


@pytest.mark.parametrize("guard_file", _guard_files(), ids=_relative_guard_paths())
def test_guard_file_name_is_lower_snake_case(guard_file: Path) -> None:
    assert _LOWER_SNAKE_CASE.match(guard_file.stem), guard_file.name


@pytest.mark.parametrize("guard_file", _guard_files(), ids=_relative_guard_paths())
def test_guard_file_declares_exactly_one_rule(guard_file: Path) -> None:
    names = _rule_names(guard_file.read_text(encoding="utf-8"))
    assert len(names) == 1, f"expected one rule declaration, found {names}"


@pytest.mark.parametrize("guard_file", _guard_files(), ids=_relative_guard_paths())
def test_rule_name_matches_file_name(guard_file: Path) -> None:
    # The rule name is the join key for the _meta.json sidecars and for
    # Evidence[0].RuleId, so it has to be derivable from the file name.
    names = _rule_names(guard_file.read_text(encoding="utf-8"))
    assert names == [guard_file.stem]


@pytest.mark.parametrize("guard_file", _guard_files(), ids=_relative_guard_paths())
def test_rule_carries_a_custom_message(guard_file: Path) -> None:
    # Requirement 5 AC3: the custom message is the remediation guidance.
    text = guard_file.read_text(encoding="utf-8")
    assert "<<" in text and ">>" in text


@pytest.mark.parametrize("category", CATEGORY_DIRECTORIES)
def test_category_has_a_meta_sidecar(category: str) -> None:
    assert (RULES_DIR / category / META_FILENAME).is_file()


def test_meta_sidecars_are_one_per_category() -> None:
    # A sidecar in a nested or unexpected directory would never be consulted,
    # because resolution looks at the rule file's own directory only.
    expected = sorted(f"{category}/{META_FILENAME}" for category in CATEGORY_DIRECTORIES)
    assert _relative_meta_paths() == expected


@pytest.mark.parametrize("meta_file", _meta_files(), ids=_relative_meta_paths())
def test_meta_sidecar_has_the_expected_shape(meta_file: Path) -> None:
    meta = _load_meta(meta_file)

    assert set(meta) == {"schema_version", "category", "normalized_category", "default", "rules"}
    assert re.match(r"^\d+\.\d+\.\d+$", meta["schema_version"]), meta["schema_version"]
    # The category field is the directory name so that a copied sidecar is
    # reported instead of quietly describing the wrong rule set.
    assert meta["category"] == meta_file.parent.name
    assert meta["normalized_category"] in NORMALIZED_CATEGORIES
    assert isinstance(meta["rules"], dict)

    default = meta["default"]
    assert set(default) == {"finding_type", "severity"}
    assert default["finding_type"] in FINDING_TYPES
    assert default["severity"] in SEVERITIES


@pytest.mark.parametrize("guard_file", _guard_files(), ids=_relative_guard_paths())
def test_every_rule_name_resolves_in_its_meta_sidecar(guard_file: Path) -> None:
    # Requirement 5 AC8: adding a rule file means adding one sidecar entry. This
    # is the check that turns a forgotten entry into a CI failure rather than a
    # silent fallback to BestPractice / MEDIUM.
    meta_file = guard_file.parent / META_FILENAME
    assert meta_file.is_file(), f"missing {META_FILENAME} next to {guard_file.name}"

    rules = _meta_rules(meta_file)
    declared = _rule_names(guard_file.read_text(encoding="utf-8"))
    for rule_name in declared:
        assert rule_name in rules, (
            f"{rule_name} is declared in {guard_file.name} but has no entry in "
            f"{meta_file.relative_to(RULES_DIR).as_posix()}"
        )


@pytest.mark.parametrize("meta_file", _meta_files(), ids=_relative_meta_paths())
def test_meta_sidecar_has_no_entry_without_a_rule_file(meta_file: Path) -> None:
    # The reverse direction of the join: a leftover entry from a deleted or
    # renamed rule is dead metadata and hides the rename.
    rule_files = {path.stem for path in meta_file.parent.glob("*.guard")}
    assert set(_meta_rules(meta_file)) <= rule_files


def _rule_entries() -> list[tuple[Path, str, dict[str, Any]]]:
    entries: list[tuple[Path, str, dict[str, Any]]] = []
    for meta_file in _meta_files():
        for rule_name, entry in sorted(_meta_rules(meta_file).items()):
            entries.append((meta_file, rule_name, entry))
    return entries


def _rule_entry_ids() -> list[str]:
    return [f"{meta_file.parent.name}/{rule_name}" for meta_file, rule_name, _ in _rule_entries()]


@pytest.mark.parametrize(
    ("meta_file", "rule_name", "entry"), _rule_entries(), ids=_rule_entry_ids()
)
def test_rule_entry_carries_resolvable_metadata(
    meta_file: Path, rule_name: str, entry: dict[str, Any]
) -> None:
    assert set(entry) <= set(REQUIRED_RULE_KEYS) | set(OPTIONAL_RULE_KEYS), sorted(entry)
    for key in REQUIRED_RULE_KEYS:
        assert key in entry, f"{rule_name} is missing {key}"

    assert entry["severity"] in SEVERITIES
    if "finding_type" in entry:
        assert entry["finding_type"] in FINDING_TYPES
    if "normalized_category" in entry:
        assert entry["normalized_category"] in NORMALIZED_CATEGORIES

    for key in ("why_it_matters", "recommendation"):
        # These strings are reported verbatim, so an empty value would surface as
        # a Finding with no explanation.
        assert isinstance(entry[key], str) and entry[key].strip(), key


@pytest.mark.parametrize(
    ("meta_file", "rule_name", "entry"), _rule_entries(), ids=_rule_entry_ids()
)
def test_normalized_category_override_matches_the_design(
    meta_file: Path, rule_name: str, entry: dict[str, Any]
) -> None:
    # Only rules that genuinely belong to a different category may override it,
    # and the override is pinned so that a stray one is reported.
    expected = NORMALIZED_CATEGORY_OVERRIDES.get(rule_name)
    assert entry.get("normalized_category") == expected


def test_valid_template_fixture_exists() -> None:
    assert VALID_TEMPLATE.is_file()


@pytest.mark.skipif(
    shutil.which("cfn-guard") is None,
    reason="cfn-guard is not installed; rule syntax cannot be verified here",
)
def test_cfn_guard_parses_every_bundled_rule() -> None:
    argv = [
        "cfn-guard",
        "validate",
        "--rules",
        str(RULES_DIR),
        "--data",
        str(VALID_TEMPLATE),
        "--output-format",
        "json",
        "--type",
        "CFNTemplate",
        "--show-summary",
        "none",
    ]
    completed = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    combined = completed.stdout + completed.stderr
    for marker in _PARSE_ERROR_MARKERS:
        assert marker not in combined, combined
    assert completed.returncode != _PARSE_ERROR_EXIT_CODE, combined
