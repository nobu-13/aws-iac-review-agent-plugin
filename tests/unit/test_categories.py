"""Checks for the versioned category mapping file and its loader.

``iacreview/category_map.json`` is the single versioned mapping file required by
Requirement 14 AC4, and its ``categories`` array is the only place the closed
Normalized_Category vocabulary (Requirement 14 AC1, AC2, AC3) is declared. Code
never re-declares those names, so if this file is malformed or its vocabulary
drifts, every Finding's ``Normalized_Category`` validation silently changes
meaning. The two checks here are therefore the floor: the file parses, and the
vocabulary is exactly the 11 entries design.md specifies, in that order.

The expected list is spelled out literally rather than derived from the file so
that the assertion has an independent reference to compare against; reading the
same file twice would pass no matter what it contained.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# tests/unit/test_categories.py -> tests/unit -> tests -> plugin root
PLUGIN_ROOT: Path = Path(__file__).resolve().parents[2]
CATEGORY_MAP: Path = PLUGIN_ROOT / "iacreview" / "category_map.json"

# Requirement 14 AC2's ten categories plus AC3's residual `Other`, in the order
# design.md (Normalized Category Vocabulary and the Mapping File) declares them.
EXPECTED_CATEGORIES = [
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
]


def _load_category_map() -> dict[str, Any]:
    return json.loads(CATEGORY_MAP.read_text(encoding="utf-8"))


def test_category_map_file_exists() -> None:
    assert CATEGORY_MAP.is_file()


def test_category_map_parses_as_json() -> None:
    # Reported separately from the vocabulary check so that a syntax error is
    # distinguishable from a content change.
    assert isinstance(_load_category_map(), dict)


def test_categories_match_the_closed_set_exactly() -> None:
    # Order-sensitive equality: the array is the authoritative vocabulary, and an
    # added, removed, or renamed entry has to be a deliberate, reviewed change.
    assert _load_category_map()["categories"] == EXPECTED_CATEGORIES


# ---------------------------------------------------------------------------
# Loader and classification (Task 7.2)
# ---------------------------------------------------------------------------
#
# The classification tests below run against the *bundled* mapping file rather
# than against a fixture, because the assertions they make (E0/E1 Errors are
# CRITICAL, E3002 is not, W3037 is Security) are statements about the shipped
# policy, not about the loader. A fixture would keep passing after the real file
# changed. Tests that need a shape the bundled file does not have -- a longer
# competing prefix, a corrupt document -- write their own file into `tmp_path`,
# derived from the bundled one so that exactly one thing differs from valid.

import copy

import pytest

from iacreview import categories
from iacreview.errors import MappingFileError


@pytest.fixture(scope="module")
def bundled_map() -> categories.CategoryMap:
    return categories.load_map()


def _valid_document() -> dict[str, Any]:
    """A known-valid mapping document, safe to mutate."""
    return copy.deepcopy(_load_category_map())


def _write_map(tmp_path: Path, document: object) -> Path:
    target = tmp_path / "category_map.json"
    target.write_text(json.dumps(document), encoding="utf-8")
    return target


# --- (a) longest prefix wins ------------------------------------------------


@pytest.mark.parametrize("insert_at_front", [True, False])
def test_longer_prefix_wins_regardless_of_file_order(
    tmp_path: Path, insert_at_front: bool
) -> None:
    # `E3` is already declared as TemplateQuality without blocks_deployment. A
    # narrower `E30` is added pointing somewhere else, and the array order is
    # varied to show that only prefix length decides, so adding a narrower rule
    # never requires reordering the file.
    document = _valid_document()
    narrow = {"prefix": "E30", "category": "Encryption", "blocks_deployment": True}
    rules = document["cfnlint"]["prefix_rules"]
    if insert_at_front:
        rules.insert(0, narrow)
    else:
        rules.append(narrow)

    cmap = categories.load_map(_write_map(tmp_path, document))

    assert cmap.for_cfnlint_rule("E3010").category == "Encryption"
    # One digit further from the narrow prefix: `E3` still applies.
    assert cmap.for_cfnlint_rule("E3110").category == "TemplateQuality"
    # blocks_deployment is taken from the same winning entry, not from `E3`.
    assert categories.classify_cfnlint("E3010", "Error", cmap).severity == "CRITICAL"
    assert categories.classify_cfnlint("E3110", "Error", cmap).severity == "HIGH"


def test_exact_rule_override_beats_a_matching_longer_prefix(tmp_path: Path) -> None:
    # Reference order puts rule_overrides above prefix_rules, so E3002's own
    # `blocks_deployment: false` has to survive a blocking `E30` prefix.
    document = _valid_document()
    document["cfnlint"]["prefix_rules"].append(
        {"prefix": "E30", "category": "Encryption", "blocks_deployment": True}
    )
    cmap = categories.load_map(_write_map(tmp_path, document))

    result = categories.classify_cfnlint("E3002", "Error", cmap)
    assert (result.category, result.severity) == ("TemplateQuality", "HIGH")


# --- (b) deployment-blocking Errors become CRITICAL -------------------------


@pytest.mark.parametrize("rule_id", ["E0000", "E0001", "E1001", "E1010"])
def test_deployment_blocking_error_is_critical(
    bundled_map: categories.CategoryMap, rule_id: str
) -> None:
    # Requirement 4 AC5 / Requirement 7 AC6.
    result = categories.classify_cfnlint(rule_id, "Error", bundled_map)
    assert result.severity == "CRITICAL"
    assert result.finding_type == "Validity"
    assert bundled_map.blocks_deployment(rule_id) is True


# The rule IDs the cfn-lint 1.46.0 catalogue survey (Task 9.1) added as
# deployment-blocking, listed literally so the assertion has a reference
# independent of the file it checks. The criteria and the reason for each entry
# are recorded in docs/finding-schema.md.
SURVEYED_BLOCKING_RULES = [
    "E2002",
    "E2003",
    "E2010",
    "E3001",
    "E3003",
    "E3004",
    "E3005",
    "E3006",
    "E3007",
    "E3010",
    "E3015",
    "E3035",
    "E3036",
    "E3038",
    "E3055",
    "E6002",
    "E6004",
    "E6005",
    "E6010",
    "E7010",
    "E8002",
    "E8003",
    "E8004",
    "E8005",
    "E8006",
    "E8007",
]


@pytest.mark.parametrize("rule_id", SURVEYED_BLOCKING_RULES)
def test_surveyed_blocking_rule_is_critical_at_error_level(
    bundled_map: categories.CategoryMap, rule_id: str
) -> None:
    # Each of these reaches CRITICAL through its own `rule_overrides` entry
    # rather than through a prefix, so the assertion fails if an entry is
    # dropped, renamed, or flipped to false.
    result = categories.classify_cfnlint(rule_id, "Error", bundled_map)
    assert result.severity == "CRITICAL"
    assert result.finding_type == "Validity"
    assert bundled_map.blocks_deployment(rule_id) is True


def test_surveyed_blocking_rules_match_the_mapping_file() -> None:
    # Guards against the two silent drifts the parametrized test above cannot
    # see: a rule marked in the file but never reviewed here, and an entry added
    # to the survey list without being written into the file.
    overrides = _load_category_map()["cfnlint"]["rule_overrides"]
    marked = {
        rule_id
        for rule_id, entry in overrides.items()
        if entry.get("blocks_deployment") is True
    }
    assert marked == set(SURVEYED_BLOCKING_RULES)


# --- (c) a non-blocking Error keeps the level default ----------------------


@pytest.mark.parametrize("rule_id", ["E3002", "E2001", "E4001", "E8001"])
def test_non_blocking_error_is_high(
    bundled_map: categories.CategoryMap, rule_id: str
) -> None:
    # Requirement 4 AC3, AC4. E3002 reaches HIGH through an explicit
    # `blocks_deployment: false`; the others through an unset prefix flag.
    result = categories.classify_cfnlint(rule_id, "Error", bundled_map)
    assert (result.finding_type, result.severity) == ("Validity", "HIGH")
    assert bundled_map.blocks_deployment(rule_id) is False


# --- (d) security-relevant rules become Security ---------------------------


@pytest.mark.parametrize(
    ("rule_id", "expected_category"),
    [("W3037", "IAM"), ("W2501", "DataProtection"), ("W1011", "DataProtection")],
)
def test_security_relevant_rule_overrides_finding_type_only(
    bundled_map: categories.CategoryMap, rule_id: str, expected_category: str
) -> None:
    # Requirement 4 AC9: FindingType becomes Security, while Severity stays at
    # the Warning level default. An override that also raised the Severity would
    # have to say so explicitly, so MEDIUM here is the contract, not an accident.
    result = categories.classify_cfnlint(rule_id, "Warning", bundled_map)
    assert result.finding_type == "Security"
    assert result.severity == "MEDIUM"
    assert result.category == expected_category
    assert bundled_map.for_cfnlint_rule(rule_id).finding_type == "Security"
    assert bundled_map.for_cfnlint_rule(rule_id).why_it_matters


# The rule IDs the cfn-lint 1.46.0 Warning / Informational survey (Task 9.2)
# marked `security_relevant`, listed literally so the drift check below has a
# reference independent of the file it checks. The criteria and the evidence per
# rule are recorded in docs/finding-schema.md.
SURVEYED_SECURITY_RULES = [
    "W1011",
    "W1051",
    "W2010",
    "W2501",
    "W3037",
    "W3663",
    "W3687",
]

# Severity a `security_relevant` rule keeps at each level, from
# `cfnlint.level_defaults`. `security_relevant` moves the FindingType only, so
# these are the values the Severity must still show (Requirement 4 AC9).
LEVEL_DEFAULT_SEVERITY = {"Warning": "MEDIUM", "Informational": "LOW"}

# The level a rule ID is emitted at follows its first character. Both levels are
# exercised for every marked rule regardless, because the mapping file records
# no level and a future `I` rule must classify as Security with LOW just as a
# `W` rule classifies as Security with MEDIUM.
NATURAL_LEVEL_BY_PREFIX = {"E": "Error", "W": "Warning", "I": "Informational"}


def _security_relevant_rule_ids() -> list[str]:
    """Every rule ID the bundled mapping file marks `security_relevant`.

    Read from the file rather than from the list above so that adding an entry
    to the file extends the coverage below automatically. The drift check keeps
    the two in agreement.
    """
    overrides = _load_category_map()["cfnlint"]["rule_overrides"]
    return sorted(
        rule_id
        for rule_id, entry in overrides.items()
        if entry.get("security_relevant") is True
    )


def test_security_relevant_rules_match_the_mapping_file() -> None:
    # Guards the two silent drifts the parametrized tests cannot see: a rule
    # marked in the file but never reviewed here, and an entry added to the
    # survey list without being written into the file.
    assert _security_relevant_rule_ids() == SURVEYED_SECURITY_RULES


@pytest.mark.parametrize("rule_id", _security_relevant_rule_ids())
@pytest.mark.parametrize("level", ["Warning", "Informational"])
def test_every_security_relevant_rule_classifies_as_security(
    bundled_map: categories.CategoryMap, rule_id: str, level: str
) -> None:
    # Task 9.2's completion condition: every rule ID carrying
    # `security_relevant` yields FindingType `Security` (Requirement 4 AC9), at
    # either level the flag can be reached from. The Severity stays at the level
    # default, which is what makes an Informational security rule LOW rather
    # than silently escalated.
    result = categories.classify_cfnlint(rule_id, level, bundled_map)
    assert result.finding_type == "Security"
    assert result.severity == LEVEL_DEFAULT_SEVERITY[level]
    assert result.severity != "CRITICAL"


@pytest.mark.parametrize("rule_id", _security_relevant_rule_ids())
def test_every_security_relevant_rule_classifies_at_its_own_level(
    bundled_map: categories.CategoryMap, rule_id: str
) -> None:
    # The same assertion against the level the rule is actually emitted at, so
    # the coverage above cannot pass on a hypothetical level alone.
    level = NATURAL_LEVEL_BY_PREFIX[rule_id[0]]
    result = categories.classify_cfnlint(rule_id, level, bundled_map)
    assert result.finding_type == "Security"
    assert result.severity == LEVEL_DEFAULT_SEVERITY[level]


@pytest.mark.parametrize("rule_id", _security_relevant_rule_ids())
def test_every_security_relevant_rule_carries_reviewer_facing_text(
    bundled_map: categories.CategoryMap, rule_id: str
) -> None:
    # A Security Finding a reader cannot act on is not much use, and these are
    # the fixed strings the deterministic Source emits verbatim. The Category
    # has to be a real one and must not be the TemplateQuality default: a rule
    # whose state creates an exposure belongs to the area it exposes.
    entry = _load_category_map()["cfnlint"]["rule_overrides"][rule_id]
    assert entry["why_it_matters"].strip()
    assert entry["recommendation"].strip()
    assert bundled_map.is_valid_category(entry["category"])
    assert entry["category"] != "TemplateQuality"


@pytest.mark.parametrize(
    ("rule_id", "expected_category"),
    [
        ("W1051", "DataProtection"),
        ("W2010", "DataProtection"),
        ("W3663", "IAM"),
        ("W3687", "NetworkSecurity"),
    ],
)
def test_surveyed_security_rule_takes_its_reviewed_category(
    bundled_map: categories.CategoryMap, rule_id: str, expected_category: str
) -> None:
    # The Category is the reviewed judgement per rule, not a prefix outcome, so
    # it is asserted literally. W3687 is NetworkSecurity rather than
    # PublicAccess because the rule says nothing about the CIDR reached (see the
    # public_access_vs_network_security note in the mapping file).
    assert bundled_map.for_cfnlint_rule(rule_id).category == expected_category


@pytest.mark.parametrize("rule_id", _security_relevant_rule_ids())
def test_security_relevance_does_not_imply_deployment_blocking(
    bundled_map: categories.CategoryMap, rule_id: str
) -> None:
    # The two flags are independent, and none of the surveyed security rules is
    # an Error, so none of them may pick up a blocking flag from a prefix.
    assert bundled_map.blocks_deployment(rule_id) is False


@pytest.mark.parametrize(
    ("level", "expected_type", "expected_severity"),
    [
        ("Error", "Validity", "HIGH"),
        ("Warning", "BestPractice", "MEDIUM"),
        ("Informational", "Informational", "LOW"),
    ],
)
def test_level_defaults_apply_to_a_rule_without_an_override(
    bundled_map: categories.CategoryMap,
    level: str,
    expected_type: str,
    expected_severity: str,
) -> None:
    # Requirement 4 AC3, AC4, AC6, AC7 on a rule the mapping file says nothing
    # about beyond its prefix.
    result = categories.classify_cfnlint("E2001", level, bundled_map)
    assert (result.finding_type, result.severity) == (expected_type, expected_severity)


# --- (e) an unknown rule ID falls back instead of raising ------------------


@pytest.mark.parametrize("rule_id", ["Z9999", "E9999", "W9999", "I9999", ""])
def test_unknown_rule_id_falls_back_without_raising(
    bundled_map: categories.CategoryMap, rule_id: str
) -> None:
    # cfn-lint adds rules on its own schedule; a review must not fail because
    # the mapping file has not caught up (design.md, Failure modes).
    assert bundled_map.for_cfnlint_rule(rule_id).category == "TemplateQuality"
    result = categories.classify_cfnlint(rule_id, "Error", bundled_map)
    assert (result.category, result.finding_type, result.severity) == (
        "TemplateQuality",
        "Validity",
        "HIGH",
    )


def test_unknown_level_falls_back_to_the_least_severe_defaults(
    bundled_map: categories.CategoryMap,
) -> None:
    # A level cfn-lint has never emitted is untrusted external input. It must
    # not escalate, and since it is not "Error" it cannot reach CRITICAL either.
    result = categories.classify_cfnlint("E0000", "Catastrophe", bundled_map)
    assert (result.finding_type, result.severity) == ("Informational", "LOW")


# --- (f) only Error may be promoted to CRITICAL ---------------------------


@pytest.mark.parametrize("rule_id", ["E0000", "E1001", "W3037", "W2501", "I3011", "Z9999"])
@pytest.mark.parametrize("level", ["Warning", "Informational"])
def test_warning_and_informational_are_never_critical(
    bundled_map: categories.CategoryMap, rule_id: str, level: str
) -> None:
    # `level == "Error"` is part of the promotion condition, so even a rule
    # flagged as deployment-blocking stays at its level default here.
    assert categories.classify_cfnlint(rule_id, level, bundled_map).severity != "CRITICAL"


# --- (g) a broken mapping file is a MappingFileError ----------------------
#
# Every case starts from the valid bundled document and breaks exactly one
# thing, so a failure names the defect rather than "the file is bad". All of
# them are exit code 1: a corrupt mapping file is a broken installation, and the
# category vocabulary is not optional for any later stage.


def _drop_categories(document: dict[str, Any]) -> None:
    del document["categories"]


def _empty_categories(document: dict[str, Any]) -> None:
    document["categories"] = []


def _duplicate_category(document: dict[str, Any]) -> None:
    document["categories"].append("IAM")


def _unsupported_schema_major(document: dict[str, Any]) -> None:
    document["schema_version"] = "2.0.0"


def _non_semver_schema_version(document: dict[str, Any]) -> None:
    document["schema_version"] = "one"


def _drop_a_level_default(document: dict[str, Any]) -> None:
    del document["cfnlint"]["level_defaults"]["Informational"]


def _unknown_severity(document: dict[str, Any]) -> None:
    document["cfnlint"]["level_defaults"]["Error"]["severity"] = "URGENT"


def _unknown_finding_type(document: dict[str, Any]) -> None:
    document["cfnlint"]["level_defaults"]["Error"]["finding_type"] = "Vulnerability"


def _undeclared_default_category(document: dict[str, Any]) -> None:
    document["cfnlint"]["default"]["category"] = "Typo"


def _undeclared_prefix_category(document: dict[str, Any]) -> None:
    document["cfnlint"]["prefix_rules"][0]["category"] = "Encription"


def _prefix_rule_without_prefix(document: dict[str, Any]) -> None:
    del document["cfnlint"]["prefix_rules"][0]["prefix"]


def _non_boolean_blocks_deployment(document: dict[str, Any]) -> None:
    document["cfnlint"]["prefix_rules"][0]["blocks_deployment"] = "true"


def _misspelled_override_key(document: dict[str, Any]) -> None:
    # The case that motivates rejecting unknown keys: a typo here would
    # otherwise leave W3037 silently classified as BestPractice.
    entry = document["cfnlint"]["rule_overrides"]["W3037"]
    entry["security_relevent"] = entry.pop("security_relevant")


def _unknown_top_level_key(document: dict[str, Any]) -> None:
    document["cfnguard_rules"] = {}


def _drop_cfnguard(document: dict[str, Any]) -> None:
    del document["cfnguard"]


def _undeclared_guard_category(document: dict[str, Any]) -> None:
    document["cfnguard"]["rule_categories"]["encryption"] = "Cryptography"


def _cfnlint_not_an_object(document: dict[str, Any]) -> None:
    document["cfnlint"] = []


BROKEN_DOCUMENT_CASES = [
    ("missing_categories", _drop_categories),
    ("empty_categories", _empty_categories),
    ("duplicate_category", _duplicate_category),
    ("unsupported_schema_major", _unsupported_schema_major),
    ("non_semver_schema_version", _non_semver_schema_version),
    ("missing_level_default", _drop_a_level_default),
    ("unknown_severity", _unknown_severity),
    ("unknown_finding_type", _unknown_finding_type),
    ("undeclared_default_category", _undeclared_default_category),
    ("undeclared_prefix_category", _undeclared_prefix_category),
    ("prefix_rule_without_prefix", _prefix_rule_without_prefix),
    ("non_boolean_blocks_deployment", _non_boolean_blocks_deployment),
    ("misspelled_override_key", _misspelled_override_key),
    ("unknown_top_level_key", _unknown_top_level_key),
    ("missing_cfnguard", _drop_cfnguard),
    ("undeclared_guard_category", _undeclared_guard_category),
    ("cfnlint_not_an_object", _cfnlint_not_an_object),
]


@pytest.mark.parametrize(
    "mutate", [case[1] for case in BROKEN_DOCUMENT_CASES], ids=[case[0] for case in BROKEN_DOCUMENT_CASES]
)
def test_structurally_broken_mapping_file_raises(tmp_path: Path, mutate: Any) -> None:
    document = _valid_document()
    mutate(document)
    with pytest.raises(MappingFileError):
        categories.load_map(_write_map(tmp_path, document))


@pytest.mark.parametrize(
    ("case", "content"),
    [
        ("not_json", b"{ this is not json"),
        ("empty_file", b""),
        ("json_array", b"[]"),
        ("json_string", b'"category_map"'),
        ("invalid_utf8", b'{"schema_version": "1.0.0", "categories": ["\xff\xfe"]}'),
    ],
)
def test_unparseable_mapping_file_raises(tmp_path: Path, case: str, content: bytes) -> None:
    target = tmp_path / "category_map.json"
    target.write_bytes(content)
    with pytest.raises(MappingFileError):
        categories.load_map(target)


def test_missing_mapping_file_raises(tmp_path: Path) -> None:
    with pytest.raises(MappingFileError):
        categories.load_map(tmp_path / "absent.json")


# --- vocabulary and cfn-guard lookups -------------------------------------


@pytest.mark.parametrize("name", EXPECTED_CATEGORIES)
def test_every_declared_category_is_valid(
    bundled_map: categories.CategoryMap, name: str
) -> None:
    assert bundled_map.is_valid_category(name) is True


@pytest.mark.parametrize("name", ["", "iam", "Encription", "TemplateQuality ", "Unknown"])
def test_undeclared_category_is_rejected(
    bundled_map: categories.CategoryMap, name: str
) -> None:
    # Case-sensitive and whitespace-sensitive: `finding.validate` uses this
    # predicate as the closed-set check, so a near-miss must not pass.
    assert bundled_map.is_valid_category(name) is False


def test_guard_rule_override_wins_over_its_directory_category(
    bundled_map: categories.CategoryMap,
) -> None:
    # An open ingress rule lives under rules/public-access/ but is a network
    # boundary issue, so the override reclassifies it (design.md, PublicAccess
    # vs NetworkSecurity).
    decision = bundled_map.for_guard_rule("security_group_open_ingress", "public-access")
    assert decision.category == "NetworkSecurity"


@pytest.mark.parametrize(
    ("rule_category", "expected"),
    [
        ("encryption", "Encryption"),
        ("public-access", "PublicAccess"),
        ("iam", "IAM"),
        ("logging", "Logging"),
        ("backup", "Backup"),
        ("tagging", "Tagging"),
    ],
)
def test_guard_rule_takes_its_directory_category(
    bundled_map: categories.CategoryMap, rule_category: str, expected: str
) -> None:
    assert bundled_map.for_guard_rule("some_rule", rule_category).category == expected
    # A caller that passes the category itself resolves the same way.
    assert bundled_map.for_guard_rule(rule_category).category == expected


def test_unmapped_guard_rule_falls_back_to_other(
    bundled_map: categories.CategoryMap,
) -> None:
    # `Other` rather than TemplateQuality, and it also keeps the Finding out of
    # dedup matching (Requirement 14 AC3).
    assert bundled_map.for_guard_rule("brand_new_rule").category == "Other"
    assert bundled_map.for_guard_rule("brand_new_rule", "brand-new").category == "Other"


# --- loader behaviour -----------------------------------------------------


def test_bundled_map_is_cached_per_process() -> None:
    # Every Finding validation resolves is_valid_category through this map, so
    # repeated loads must not mean repeated disk reads.
    assert categories.load_map() is categories.load_map()


def test_clear_cache_forces_a_reload() -> None:
    first = categories.load_map()
    categories.clear_cache()
    try:
        assert categories.load_map() is not first
    finally:
        categories.clear_cache()


def test_returned_override_is_a_copy(bundled_map: categories.CategoryMap) -> None:
    # The cached map is shared; a caller mutating a lookup result must not be
    # able to change how later classifications behave.
    entry = bundled_map.cfnlint_override("W3037")
    assert entry is not None
    entry["category"] = "Other"
    assert bundled_map.for_cfnlint_rule("W3037").category == "IAM"
