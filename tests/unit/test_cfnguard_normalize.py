"""Unit tests for cfn-guard Finding normalization and execution.

Five groups, matching the contracts Task 11.2 adds on top of the parsing already
covered by ``test_cfnguard_parse.py``:

(a) Every violated check in the captured fixture becomes a Finding with all 13
    fields of Requirement 7 AC1 populated, and the compliant capture produces
    none.
(b) FindingType, Severity and Normalized_Category come from the ``_meta.json``
    sidecars, including a rule that overrides its category's Normalized_Category
    (``security_group_open_ingress`` -> ``NetworkSecurity``).
(c) ``rules_evaluated`` / ``rules_passed`` (Requirement 5 AC4) are read from
    cfn-guard's own output when it reports them, and derived from the rule
    declaration count when it does not.
(d) The result does not depend on the order ``rules_dirs`` was given in
    (design.md O-10).
(e) :func:`~iacreview.cfnguard.run_and_normalize` reports a missing tool, a tool
    failure and a timeout as errors rather than exceptions, and keeps the review
    going for a broken sidecar (Requirement 5 AC5, AC6).

Groups (a) to (d) run with cfn-guard absent: they drive the pure functions with
the verbatim cfn-guard 3.2.1 captures in ``tests/fixtures/tool_output/``. Group
(e) needs a process, and uses a fake ``cfn-guard`` on a stubbed ``PATH`` that
replays one of those captures, so the subprocess, exit status and argv handling
are real while the tool is not required. The one test that does require the real
binary, the end-to-end order independence check in (d), is skipped when it is
absent.
"""

from __future__ import annotations

import dataclasses
import shutil
import stat
import sys
from pathlib import Path
from typing import Dict, List, Optional

import pytest

from iacreview import finding as finding_module
from iacreview.cfnguard import (
    FALLBACK_FINDING_TYPE,
    FALLBACK_SEVERITY,
    FINDING_FALLBACK_TEXT,
    RULES_COUNT_FROM_DECLARATIONS,
    RULES_COUNT_FROM_OUTPUT,
    SOURCE_NAME,
    STATS_KEYS,
    RawResult,
    build_argv,
    count_rules,
    finding_from_result,
    initial_stats,
    load_rule_metadata,
    normalize_results,
    parse_output,
    parse_records,
    resolve_rules_dirs,
    run_and_normalize,
    sort_results,
)
from iacreview.errors import PathContainmentError
from iacreview.finding import FINDING_FIELDS, Finding
from iacreview.source import SourceResult

TOOL_OUTPUT = Path(__file__).resolve().parents[1] / "fixtures" / "tool_output"
VALID_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "valid"

#: Exit code cfn-guard 3.2.1 was observed to return for rule violations. Used to
#: drive the fake tool through the violations path; nothing under test reads the
#: value (Requirement 5 AC7).
VIOLATIONS_EXIT_CODE = 19

#: Template path this Source reports in ``Location.File``.
TEMPLATE_FILE = "templates/app.yaml"

#: The nine rules the violations capture reports, in the order this Source emits
#: them: sorted by rule name (see :func:`sort_results`).
EXPECTED_RULE_ORDER = [
    "rds_backup_retention",
    "rds_deletion_protection",
    "rds_publicly_accessible",
    "rds_storage_encrypted",
    "required_tags",
    "s3_access_logging",
    "s3_bucket_encryption",
    "s3_public_access_block",
    "security_group_open_ingress",
]


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def violations_stdout() -> str:
    """Real stdout from a run with nine violated rules."""
    return (TOOL_OUTPUT / "cfnguard_violations.json").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def pass_stdout() -> str:
    """Real stdout from a run where every applicable rule passed."""
    return (TOOL_OUTPUT / "cfnguard_pass.json").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def malformed_stdout() -> str:
    """Real stdout that is not the expected JSON structure."""
    return (TOOL_OUTPUT / "cfnguard_malformed.txt").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def bundled_metadata():
    """Rule metadata for the bundled rule set, read once for the module."""
    return load_rule_metadata()


@pytest.fixture(scope="module")
def violation_findings(violations_stdout: str, bundled_metadata) -> List[Finding]:
    """Findings normalized from the violations capture."""
    return normalize_results(
        parse_output(violations_stdout),
        template_file=TEMPLATE_FILE,
        metadata=bundled_metadata,
    )


def by_rule(findings: List[Finding], rule_name: str) -> Finding:
    """The single Finding carrying ``rule_name`` as its Evidence RuleId."""
    matches = [f for f in findings if f.Evidence[0].RuleId == rule_name]
    assert len(matches) == 1, "expected one finding for {0}".format(rule_name)
    return matches[0]


def raw(
    rule_name: str = "s3_bucket_encryption",
    *,
    resource: Optional[str] = "PlainBucket",
    template_path: tuple = ("Resources", "PlainBucket", "Properties"),
    provided_value: Optional[str] = None,
    expected_value: Optional[str] = None,
    custom_message: Optional[str] = None,
    error_message: Optional[str] = None,
    context: Optional[str] = None,
) -> RawResult:
    """Build a :class:`RawResult` for a case the captures do not contain."""
    return RawResult(
        rule_name=rule_name,
        resource=resource,
        template_path=template_path,
        provided_value=provided_value,
        expected_value=expected_value,
        custom_message=custom_message,
        error_message=error_message,
        context=context,
    )


def write_template(root: Path, body: Optional[str] = None) -> Path:
    """Write the Template the fake tool is nominally invoked against."""
    template = root / TEMPLATE_FILE
    template.parent.mkdir(parents=True, exist_ok=True)
    template.write_text(
        body
        or "Resources:\n  PlainBucket:\n    Type: AWS::S3::Bucket\n"
        "    Properties:\n      BucketName: plain-bucket\n",
        encoding="utf-8",
    )
    return template


def empty_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point ``PATH`` at a directory holding no tools, and return it."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("PATH", str(bin_dir))
    return bin_dir


def fake_cfn_guard(
    bin_dir: Path,
    *,
    stdout: str = "",
    stderr: str = "",
    code: int = 0,
    sleep: float = 0.0,
    version: str = "cfn-guard 3.2.1",
) -> Path:
    """Install a fake ``cfn-guard`` that replays a fixed result.

    Written in Python and launched through an absolute interpreter path, so it
    needs nothing on ``PATH`` -- which matters because :mod:`iacreview.proc`
    hands the child a minimal environment.
    """
    script = bin_dir / "cfn-guard"
    script.write_text(
        "#!{interpreter}\n"
        "import sys, time\n"
        "if '--version' in sys.argv[1:]:\n"
        "    sys.stdout.write({version!r} + '\\n')\n"
        "    raise SystemExit(0)\n"
        "time.sleep({sleep!r})\n"
        "sys.stdout.write({stdout!r})\n"
        "sys.stderr.write({stderr!r})\n"
        "raise SystemExit({code!r})\n".format(
            interpreter=sys.executable,
            version=version,
            sleep=sleep,
            stdout=stdout,
            stderr=stderr,
            code=code,
        ),
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return script


def write_rule_dir(
    directory: Path,
    rule_name: str,
    property_name: str,
    *,
    normalized_category: str = "Tagging",
    severity: str = "LOW",
    meta: bool = True,
) -> Path:
    """Write a one-rule category directory, with or without its sidecar."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "{0}.guard".format(rule_name)).write_text(
        "let buckets = Resources.*[ Type == 'AWS::S3::Bucket' ]\n"
        "\n"
        "rule {rule} when %buckets !empty {{\n"
        "  %buckets.Properties.{prop} exists\n"
        "    << The {prop} property is required by a local policy. "
        "Add it to the bucket. >>\n"
        "}}\n".format(rule=rule_name, prop=property_name),
        encoding="utf-8",
    )
    if meta:
        (directory / "_meta.json").write_text(
            '{{"schema_version": "1.0.0", "category": "{category}",\n'
            ' "normalized_category": "{normalized}",\n'
            ' "default": {{"finding_type": "BestPractice", "severity": "{sev}"}},\n'
            ' "rules": {{"{rule}": {{"severity": "{sev}"}}}}}}\n'.format(
                category=directory.name,
                normalized=normalized_category,
                sev=severity,
                rule=rule_name,
            ),
            encoding="utf-8",
        )
    return directory


#: A record shaped like output from a cfn-guard version that reports violations
#: but omits ``compliant`` and ``not_applicable``. Both are optional in
#: ``parse_records``, and their absence is what makes the evaluated-rule count
#: unobtainable from the output.
COUNTS_ABSENT_STDOUT = """
{
  "name": "templates/app.yaml",
  "status": "FAIL",
  "not_compliant": [
    {
      "Rule": {
        "name": "s3_bucket_encryption",
        "checks": [
          {
            "Clause": {
              "Unary": {
                "context": " %s3_buckets[*].Properties.BucketEncryption EXISTS  ",
                "messages": {
                  "custom_message": " Server-side encryption is not configured. Add BucketEncryption. ",
                  "error_message": "Check was not compliant as property [BucketEncryption] is missing."
                },
                "check": {
                  "UnResolved": {
                    "value": {
                      "traversed_to": {
                        "path": "/Resources/PlainBucket/Properties",
                        "value": {"BucketName": "plain-bucket"}
                      },
                      "remaining_query": "BucketEncryption"
                    }
                  }
                }
              }
            }
          }
        ]
      }
    }
  ]
}
"""


# ---------------------------------------------------------------------------
# (a) One Finding per violated check, all 13 fields populated
# ---------------------------------------------------------------------------


def test_every_violated_check_becomes_one_finding(
    violation_findings: List[Finding],
) -> None:
    assert [f.Evidence[0].RuleId for f in violation_findings] == EXPECTED_RULE_ORDER


@pytest.mark.parametrize("rule_name", EXPECTED_RULE_ORDER)
def test_finding_carries_all_thirteen_fields(
    violation_findings: List[Finding], rule_name: str
) -> None:
    """Requirement 7 AC1: every field present, and the whole Finding valid."""
    found = by_rule(violation_findings, rule_name)
    payload = finding_module.to_dict(found)
    assert tuple(payload) == FINDING_FIELDS
    # ID is assigned by the report, so validate a copy that has one.
    finding_module.validate(dataclasses.replace(found, ID=1))


def test_missing_property_violation_is_mapped_field_by_field(
    violation_findings: List[Finding],
) -> None:
    """The Unary / UnResolved shape: a property that is not there at all."""
    found = by_rule(violation_findings, "s3_bucket_encryption")
    assert found.Resource == "PlainBucket"
    assert found.Location.File == TEMPLATE_FILE
    assert found.Location.Line is None
    assert found.Location.Column is None
    assert found.Location.TemplatePath == [
        "Resources",
        "PlainBucket",
        "Properties",
        "BucketEncryption",
    ]
    assert found.Finding == (
        "[s3_bucket_encryption] Server-side encryption is not configured on "
        "this S3 bucket."
    )
    assert "the queried property is not present" in found.Evidence[0].Detail
    assert found.SuggestedRemediation is not None
    assert found.SuggestedRemediation.startswith("Server-side encryption")
    assert found.SuggestedRemediation.endswith("aws:kms).")


def test_resolved_comparison_reports_provided_and_expected(
    violation_findings: List[Finding],
) -> None:
    """The Binary / Resolved shape: design.md's ``provided: <v>, expected: <e>``."""
    detail = by_rule(violation_findings, "rds_storage_encrypted").Evidence[0].Detail
    assert "provided: false, expected: true" in detail


def test_negated_clause_does_not_claim_provided_equals_expected(
    violation_findings: List[Finding],
) -> None:
    """``CidrIp != "0.0.0.0/0"`` reports the same value on both sides.

    Rendering that as "expected: 0.0.0.0/0" would state the opposite of the
    rule, so the detail says what the check rejects and quotes the clause
    cfn-guard printed, which carries the ``not EQUALS`` operator.
    """
    detail = (
        by_rule(violation_findings, "security_group_open_ingress").Evidence[0].Detail
    )
    assert "provided: 0.0.0.0/0, which the check requires it not to be" in detail
    assert "expected: 0.0.0.0/0" not in detail
    assert "not EQUALS" in detail


@pytest.mark.parametrize("rule_name", EXPECTED_RULE_ORDER)
def test_confidence_source_and_excerpt_are_constant(
    violation_findings: List[Finding], rule_name: str
) -> None:
    """Requirement 7 AC8 / AC13: Confirmed, cfn-guard, and no excerpt."""
    found = by_rule(violation_findings, rule_name)
    assert found.Confidence == "Confirmed"
    assert found.Source == [SOURCE_NAME]
    assert len(found.Evidence) == 1
    assert found.Evidence[0].Source == SOURCE_NAME
    assert found.Evidence[0].Excerpt is None


def test_finding_text_takes_only_the_first_sentence(
    violation_findings: List[Finding],
) -> None:
    """The remediation half of a rule message belongs in SuggestedRemediation."""
    found = by_rule(violation_findings, "rds_backup_retention")
    assert found.Finding == (
        "[rds_backup_retention] Automated backups are not configured on this "
        "RDS DB instance."
    )
    assert found.SuggestedRemediation is not None
    assert "Set BackupRetentionPeriod" in found.SuggestedRemediation


def test_compliant_capture_yields_no_findings(
    pass_stdout: str, bundled_metadata
) -> None:
    """Requirement 5 AC4: zero violations is an empty list, not an error."""
    assert parse_output(pass_stdout) == []
    assert (
        normalize_results(
            parse_output(pass_stdout),
            template_file=TEMPLATE_FILE,
            metadata=bundled_metadata,
        )
        == []
    )


def test_rule_without_a_message_falls_back_for_every_text_field(
    bundled_metadata,
) -> None:
    """A rule with no ``<<...>>`` message and no sidecar entry still validates."""
    found = finding_from_result(
        raw("unknown_local_rule", custom_message=None),
        template_file=TEMPLATE_FILE,
        metadata=bundled_metadata,
    )
    assert found.Finding == "[unknown_local_rule] {0}".format(FINDING_FALLBACK_TEXT)
    assert "unknown_local_rule" in found.WhyItMatters
    assert "Change the template" in found.Recommendation
    assert found.SuggestedRemediation is None
    finding_module.validate(dataclasses.replace(found, ID=1))


def test_absent_property_path_yields_no_resource_and_no_template_path(
    bundled_metadata,
) -> None:
    """An UnResolvedContext failure has no template location of its own."""
    found = finding_from_result(
        raw(resource=None, template_path=()),
        template_file=TEMPLATE_FILE,
        metadata=bundled_metadata,
    )
    assert found.Resource is None
    assert found.Location.TemplatePath is None


def test_sidecar_recommendation_wins_over_the_rule_message(
    violation_findings: List[Finding],
) -> None:
    """Recommendation prefers the wording written for this plugin's report."""
    found = by_rule(violation_findings, "security_group_open_ingress")
    assert found.Recommendation.startswith("Restrict CidrIp or CidrIpv6")
    assert found.SuggestedRemediation != found.Recommendation


# ---------------------------------------------------------------------------
# (b) FindingType / Severity / Normalized_Category from _meta.json
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rule_name,finding_type,severity,category",
    [
        ("s3_bucket_encryption", "Security", "HIGH", "Encryption"),
        ("rds_storage_encrypted", "Security", "HIGH", "Encryption"),
        ("s3_public_access_block", "Security", "CRITICAL", "PublicAccess"),
        ("rds_publicly_accessible", "Security", "CRITICAL", "PublicAccess"),
        ("security_group_open_ingress", "Security", "HIGH", "NetworkSecurity"),
        ("s3_access_logging", "Security", "MEDIUM", "Logging"),
        ("rds_backup_retention", "BestPractice", "MEDIUM", "Backup"),
        ("rds_deletion_protection", "BestPractice", "MEDIUM", "Backup"),
        ("required_tags", "BestPractice", "LOW", "Tagging"),
    ],
)
def test_classification_comes_from_the_sidecar(
    violation_findings: List[Finding],
    rule_name: str,
    finding_type: str,
    severity: str,
    category: str,
) -> None:
    """cfn-guard has no severity; every one of these comes from ``_meta.json``."""
    found = by_rule(violation_findings, rule_name)
    assert (found.FindingType, found.Severity, found.Normalized_Category) == (
        finding_type,
        severity,
        category,
    )


def test_rule_entry_overrides_its_category_normalized_category(
    violation_findings: List[Finding],
) -> None:
    """``security_group_open_ingress`` sits in ``public-access`` and is not one.

    Its directory declares ``PublicAccess``; the rule entry declares
    ``NetworkSecurity``, which is the per-rule override design.md calls out.
    """
    open_ingress = by_rule(violation_findings, "security_group_open_ingress")
    same_directory = by_rule(violation_findings, "s3_public_access_block")
    assert open_ingress.Normalized_Category == "NetworkSecurity"
    assert same_directory.Normalized_Category == "PublicAccess"


def test_unknown_rule_takes_the_hardcoded_fallback(bundled_metadata) -> None:
    """A rule no scanned directory declares is classified conservatively."""
    found = finding_from_result(
        raw("rule_from_nowhere"),
        template_file=TEMPLATE_FILE,
        metadata=bundled_metadata,
    )
    assert found.FindingType == FALLBACK_FINDING_TYPE
    assert found.Severity == FALLBACK_SEVERITY
    assert found.Normalized_Category == "Other"


def test_user_supplied_rule_directory_supplies_its_own_metadata(
    tmp_path: Path,
) -> None:
    """A sidecar next to a user rule classifies that rule, not the bundled set."""
    directory = write_rule_dir(
        tmp_path / "policies" / "local",
        "local_versioning_required",
        "VersioningConfiguration",
        normalized_category="DataProtection",
        severity="HIGH",
    )
    metadata = load_rule_metadata(resolve_rules_dirs([directory], tmp_path))
    assert metadata.errors == ()
    found = finding_from_result(
        raw("local_versioning_required"),
        template_file=TEMPLATE_FILE,
        metadata=metadata,
    )
    assert found.Severity == "HIGH"
    assert found.Normalized_Category == "DataProtection"
    assert found.FindingType == "BestPractice"


# ---------------------------------------------------------------------------
# (c) rules_evaluated / rules_passed (Requirement 5 AC4)
# ---------------------------------------------------------------------------


def test_counts_are_read_from_the_output_of_a_failing_run(
    violations_stdout: str,
) -> None:
    """Nine violated plus two skipped is the eleven bundled rules."""
    assert count_rules(parse_records(violations_stdout)) == (11, 0, 2)


def test_counts_are_read_from_the_output_of_a_clean_run(pass_stdout: str) -> None:
    """Four passed plus seven skipped is the same eleven rules."""
    assert count_rules(parse_records(pass_stdout)) == (11, 4, 7)


def test_counts_are_unobtainable_without_compliant_or_not_applicable() -> None:
    """Only failures are visible, so the evaluated count would be wrong."""
    records = parse_records(COUNTS_ABSENT_STDOUT)
    assert len(records) == 1
    assert count_rules(records) is None


def test_counts_are_unobtainable_from_no_records() -> None:
    assert count_rules([]) is None


def test_fallback_counts_rule_declarations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bundled_metadata
) -> None:
    """The declaration count stands in, and stats say so."""
    template = write_template(tmp_path)
    fake_cfn_guard(
        empty_path(monkeypatch, tmp_path),
        stdout=COUNTS_ABSENT_STDOUT,
        code=VIOLATIONS_EXIT_CODE,
    )
    result = run_and_normalize(template, workspace_root=tmp_path)
    assert result.errors == []
    assert len(result.findings) == 1
    assert result.stats["rules_evaluated"] == bundled_metadata.rule_count
    assert result.stats["rules_passed"] == bundled_metadata.rule_count - 1
    assert result.stats["rules_not_applicable"] is None
    assert result.stats["rules_evaluated_source"] == RULES_COUNT_FROM_DECLARATIONS


def test_exit_zero_with_unreadable_stdout_falls_back_without_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bundled_metadata
) -> None:
    """Exit 0 is the tool's own guarantee; only the counts degrade."""
    template = write_template(tmp_path)
    fake_cfn_guard(empty_path(monkeypatch, tmp_path), stdout="", code=0)
    result = run_and_normalize(template, workspace_root=tmp_path)
    assert result.errors == []
    assert result.findings == []
    assert result.stats["rules_evaluated"] == bundled_metadata.rule_count
    assert result.stats["rules_passed"] == bundled_metadata.rule_count
    assert result.stats["rules_evaluated_source"] == RULES_COUNT_FROM_DECLARATIONS
    assert result.exit_status() == 0


def test_initial_stats_carries_every_documented_key() -> None:
    stats = initial_stats()
    assert tuple(stats) == STATS_KEYS
    assert stats["violations_parsed"] == 0
    assert stats["rules_evaluated"] is None


# ---------------------------------------------------------------------------
# (d) rules_dirs order independence (design.md O-10)
# ---------------------------------------------------------------------------


def test_resolve_rules_dirs_is_order_independent(tmp_path: Path) -> None:
    first = write_rule_dir(tmp_path / "a", "a_rule", "Tags")
    second = write_rule_dir(tmp_path / "b", "b_rule", "VersioningConfiguration")
    assert resolve_rules_dirs([first, second], tmp_path) == resolve_rules_dirs(
        [second, first], tmp_path
    )


def test_resolve_rules_dirs_always_starts_with_the_bundled_rules(
    tmp_path: Path, plugin_root: Path
) -> None:
    """Requirement 10 AC1: the bundled rule set needs no configuration."""
    extra = write_rule_dir(tmp_path / "a", "a_rule", "Tags")
    roots = resolve_rules_dirs([extra], tmp_path)
    assert roots[0] == plugin_root / "rules"
    assert roots[1:] == [extra]
    assert resolve_rules_dirs(None, tmp_path) == [plugin_root / "rules"]


def test_resolve_rules_dirs_drops_repeats(tmp_path: Path, plugin_root: Path) -> None:
    """cfn-guard evaluates a rule once per ``--rules``, so a repeat would double."""
    extra = write_rule_dir(tmp_path / "a", "a_rule", "Tags")
    assert resolve_rules_dirs([extra, extra], tmp_path) == [
        plugin_root / "rules",
        extra,
    ]


def test_resolve_rules_dirs_drops_the_bundled_root_named_explicitly(
    plugin_root: Path,
) -> None:
    """Naming the bundled rules as a user directory must not double every rule.

    Reachable only when the plugin is installed inside the workspace, which is
    the case for this repository itself: the workspace root *is* the plugin root,
    so ``rules`` resolves as a user-supplied directory there.
    """
    assert resolve_rules_dirs(["rules"], plugin_root) == [plugin_root / "rules"]


def test_resolve_rules_dirs_rejects_a_directory_outside_the_workspace(
    tmp_path: Path,
) -> None:
    outside = tmp_path.parent / "{0}-outside".format(tmp_path.name)
    write_rule_dir(outside, "a_rule", "Tags")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with pytest.raises(PathContainmentError):
        resolve_rules_dirs([outside], workspace)


def test_build_argv_matches_the_design_command_line(tmp_path: Path) -> None:
    argv = build_argv("/w/app.yaml", ["/w/rules", "/w/extra"])
    assert argv == [
        "cfn-guard",
        "validate",
        "--data",
        "/w/app.yaml",
        "--rules",
        "/w/rules",
        "--rules",
        "/w/extra",
        "--output-format",
        "json",
        "--type",
        "CFNTemplate",
        "--show-summary",
        "none",
    ]


def test_build_argv_does_not_use_the_structured_flag() -> None:
    argv = build_argv("/w/app.yaml", ["/w/rules"])
    assert "--structured" not in argv
    assert "-z" not in argv


def test_build_argv_can_run_the_version_checked_binary() -> None:
    argv = build_argv("/w/app.yaml", ["/w/rules"], executable="/opt/bin/cfn-guard")
    assert argv[0] == "/opt/bin/cfn-guard"


def test_build_argv_rejects_an_empty_rules_list() -> None:
    from iacreview.errors import InvalidArgumentsError

    with pytest.raises(InvalidArgumentsError):
        build_argv("/w/app.yaml", [])


def test_sort_results_is_independent_of_input_order(violations_stdout: str) -> None:
    results = parse_output(violations_stdout)
    assert [r.rule_name for r in sort_results(results)] == EXPECTED_RULE_ORDER
    assert sort_results(list(reversed(results))) == sort_results(results)


def test_sort_results_orders_repeats_of_one_rule_by_resource() -> None:
    """A rule that fires on several resources needs the tie-breaker."""
    later = raw("required_tags", resource="Zeta", template_path=("Resources", "Zeta"))
    earlier = raw("required_tags", resource="Alpha", template_path=("Resources", "Alpha"))
    assert [r.resource for r in sort_results([later, earlier])] == ["Alpha", "Zeta"]


def test_normalize_results_is_independent_of_input_order(
    violations_stdout: str, bundled_metadata
) -> None:
    results = parse_output(violations_stdout)
    forward = normalize_results(
        results, template_file=TEMPLATE_FILE, metadata=bundled_metadata
    )
    backward = normalize_results(
        list(reversed(results)), template_file=TEMPLATE_FILE, metadata=bundled_metadata
    )
    assert forward == backward


@pytest.mark.skipif(
    shutil.which("cfn-guard") is None,
    reason="cfn-guard is not installed; the end-to-end run cannot be made here",
)
def test_two_rule_directories_in_either_order_produce_the_same_result(
    tmp_path: Path,
) -> None:
    """The one check that exercises the real ``--rules`` ordering.

    The two rule names sort in the opposite order to their directories, so a
    result that followed the command line would come out reversed.
    """
    template = write_template(tmp_path)
    first = write_rule_dir(
        tmp_path / "policies" / "aaa", "zzz_local_rule", "VersioningConfiguration"
    )
    second = write_rule_dir(
        tmp_path / "policies" / "zzz", "aaa_local_rule", "ObjectLockEnabled"
    )

    forward = run_and_normalize(template, [first, second], workspace_root=tmp_path)
    backward = run_and_normalize(template, [second, first], workspace_root=tmp_path)

    assert forward.errors == []
    rule_ids = [f.Evidence[0].RuleId for f in forward.findings]
    assert "aaa_local_rule" in rule_ids
    assert "zzz_local_rule" in rule_ids
    assert rule_ids == sorted(rule_ids)
    assert forward.findings == backward.findings
    assert forward.stats == backward.stats


# ---------------------------------------------------------------------------
# (e) Execution: errors are reported, not raised
# ---------------------------------------------------------------------------


def test_missing_tool_reports_one_error_and_no_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Requirement 5 AC5: name the tool, how to install it, and keep going."""
    template = write_template(tmp_path)
    empty_path(monkeypatch, tmp_path)
    result = run_and_normalize(template, workspace_root=tmp_path)
    assert isinstance(result, SourceResult)
    assert result.source == SOURCE_NAME
    assert result.findings == []
    assert len(result.errors) == 1
    error = result.errors[0]
    assert error["error_class"] == "tool_unavailable"
    assert error["source"] == SOURCE_NAME
    assert error["tool"] == "cfn-guard"
    assert error["required_min_version"] == "3.0.0"
    assert tuple(result.stats) == STATS_KEYS
    assert result.stats["rules_evaluated"] is None
    # A standalone Skill exits 5 for an unavailable tool.
    assert result.exit_status() == 5


def test_violations_run_is_normalized_and_counted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, violations_stdout: str
) -> None:
    """A non-zero exit whose stdout parses is a set of violations, not a failure."""
    template = write_template(tmp_path)
    fake_cfn_guard(
        empty_path(monkeypatch, tmp_path),
        stdout=violations_stdout,
        code=VIOLATIONS_EXIT_CODE,
    )
    result = run_and_normalize(template, workspace_root=tmp_path)
    assert result.errors == []
    assert [f.Evidence[0].RuleId for f in result.findings] == EXPECTED_RULE_ORDER
    assert result.stats == {
        "tool_version": "3.2.1",
        "exit_code": VIOLATIONS_EXIT_CODE,
        "violations_parsed": 9,
        "rules_evaluated": 11,
        "rules_passed": 0,
        "rules_not_applicable": 2,
        "rules_evaluated_source": RULES_COUNT_FROM_OUTPUT,
    }
    assert all(f.Location.File == TEMPLATE_FILE for f in result.findings)
    assert result.exit_status() == 0


def test_clean_run_reports_the_rules_evaluated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pass_stdout: str
) -> None:
    """Requirement 5 AC4: zero violations, with the count of rules evaluated."""
    template = write_template(tmp_path)
    fake_cfn_guard(empty_path(monkeypatch, tmp_path), stdout=pass_stdout, code=0)
    result = run_and_normalize(template, workspace_root=tmp_path)
    assert result.source == SOURCE_NAME
    assert result.findings == []
    assert result.errors == []
    assert result.stats["rules_evaluated"] == 11
    assert result.stats["rules_passed"] == 4
    assert result.stats["rules_not_applicable"] == 7
    assert result.stats["rules_evaluated_source"] == RULES_COUNT_FROM_OUTPUT
    assert result.exit_status() == 0


def test_unreadable_stdout_on_a_nonzero_exit_is_a_tool_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, malformed_stdout: str
) -> None:
    """Requirement 5 AC6 and 15 AC7: exit code plus the first stderr lines."""
    template = write_template(tmp_path)
    fake_cfn_guard(
        empty_path(monkeypatch, tmp_path),
        stdout=malformed_stdout,
        stderr="Parser Error\nline two\n",
        code=5,
    )
    result = run_and_normalize(template, workspace_root=tmp_path)
    assert result.findings == []
    assert len(result.errors) == 1
    error = result.errors[0]
    assert error["error_class"] == "tool_execution"
    assert error["exit_code"] == 5
    assert error["stderr_head"] == ["Parser Error", "line two"]
    # The run did not finish, so no count of evaluated rules is claimed.
    assert result.stats["rules_evaluated"] is None
    assert result.exit_status() == 6


def test_timeout_is_reported_as_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Requirement 5 AC1 bounds one Template; exceeding it is not an exception."""
    template = write_template(tmp_path)
    fake_cfn_guard(empty_path(monkeypatch, tmp_path), sleep=5.0, code=0)
    # The real budget is 60 seconds; shortening it keeps the test quick without
    # changing the code path under test.
    monkeypatch.setattr("iacreview.cfnguard.TIMEOUT_S", 1)
    result = run_and_normalize(template, workspace_root=tmp_path)
    assert result.findings == []
    assert [e["error_class"] for e in result.errors] == ["tool_timeout"]
    # ``argv[0]`` is the version-checked binary's absolute path, but the error
    # names the tool: iacreview.proc reports the basename, so no host path
    # reaches the report (Requirement 16 AC11).
    assert result.errors[0]["tool"] == "cfn-guard"
    assert str(tmp_path) not in str(result.errors[0]["message"])
    assert result.exit_status() == 6


def test_broken_sidecar_is_reported_and_the_review_continues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, violations_stdout: str
) -> None:
    """A category with no usable ``_meta.json`` degrades; it does not stop the run."""
    template = write_template(tmp_path)
    write_rule_dir(
        tmp_path / "policies" / "local", "local_rule", "Tags", meta=False
    )
    fake_cfn_guard(
        empty_path(monkeypatch, tmp_path),
        stdout=violations_stdout,
        code=VIOLATIONS_EXIT_CODE,
    )
    result = run_and_normalize(
        template, [tmp_path / "policies" / "local"], workspace_root=tmp_path
    )
    assert [f.Evidence[0].RuleId for f in result.findings] == EXPECTED_RULE_ORDER
    assert len(result.errors) == 1
    assert result.errors[0]["error_class"] == "parse_failure"
    assert result.errors[0]["source"] == SOURCE_NAME


def test_template_outside_the_workspace_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A path that cannot be reviewed is not folded into ``errors``."""
    outside = write_template(tmp_path)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    empty_path(monkeypatch, tmp_path)
    with pytest.raises(PathContainmentError):
        run_and_normalize(outside, workspace_root=workspace)


def test_tool_info_is_reused_when_supplied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pass_stdout: str
) -> None:
    """An orchestrator checks ``--version`` once and passes the ToolInfo on."""
    from iacreview.toolcheck import ToolInfo

    template = write_template(tmp_path)
    script = fake_cfn_guard(
        empty_path(monkeypatch, tmp_path), stdout=pass_stdout, code=0
    )
    tool = ToolInfo(name="cfn-guard", path=str(script), version="3.9.9")
    result = run_and_normalize(template, None, tool, workspace_root=tmp_path)
    assert result.stats["tool_version"] == "3.9.9"
    assert result.errors == []


def test_metadata_is_reused_when_supplied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, violations_stdout: str
) -> None:
    """The sidecars are read once per run, or once per orchestration."""
    template = write_template(tmp_path)
    fake_cfn_guard(
        empty_path(monkeypatch, tmp_path),
        stdout=violations_stdout,
        code=VIOLATIONS_EXIT_CODE,
    )
    metadata = load_rule_metadata()
    result = run_and_normalize(template, workspace_root=tmp_path, metadata=metadata)
    severities: Dict[str, str] = {
        f.Evidence[0].RuleId or "": f.Severity for f in result.findings
    }
    assert severities["s3_public_access_block"] == "CRITICAL"
