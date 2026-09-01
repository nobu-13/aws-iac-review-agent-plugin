"""Checks for ``tests/property/strategies.py``: the generators themselves.

Task 22.1's completion condition is that every strategy draws 100 examples
without raising and that ``finding_lists()`` output is usable by
:func:`iacreview.dedup.deduplicate`. That is the floor. A generator can satisfy
it and still make all 31 downstream property tests worthless in three ways this
file rules out.

**A strategy that produces nothing usable.** Every "valid" generator is drawn
against the validator its consumers rely on -- :func:`iacreview.finding.validate`
for Findings, :func:`iacreview.template.is_reviewable` for Templates,
:func:`iacreview.pathguard.assert_no_shell_metacharacters` for safe strings --
and every "invalid" generator is drawn against the same validator and required to
*fail* it. A rejection strategy that quietly generated legal values would let a
property about rejection pass without ever testing a rejection.

**A strategy that produces one shape.** ``@given`` over a constant passes 100
identical examples and reports full success. Each vocabulary strategy is
therefore required to reach *every* member of its closed set over a bounded
number of draws, and the structural strategies are required to vary in the
dimension their properties turn on: ``finding_lists`` must sometimes contain a
mergeable pair, ``locations`` must produce both positioned and unpositioned
Locations, ``templates`` must produce Templates with and without IAM resources.

**A vocabulary copied instead of imported.** The severities, finding types,
confidences, sources, categories and detection classes the strategies draw from
are compared against their owning modules. A value added to
``category_map.json`` or to :data:`iacreview.finding.SEVERITIES` must widen what
these strategies generate, not leave a stale copy behind -- the same discipline
``tests/unit/test_ground_truth.py`` applies to the ground truth schema.

Vocabulary coverage is checked by exhausting a strategy over a fixed number of
draws with a fixed :class:`hypothesis.seed`, rather than by reading the tuple the
strategy was built from: reading the input would assert that the module knows the
vocabulary, and drawing from it asserts that the generator actually emits it.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import pytest
from hypothesis import HealthCheck, assume, given, seed, settings
from hypothesis import strategies as st

import strategies as S
from benchmark.harness import metrics
from iacreview import categories, errors, exitcodes, pathguard, template, yamlcfn
from iacreview import finding as fmod
from iacreview.dedup import dedup_key, deduplicate
from iacreview.errors import IacReviewError, PathContainmentError, UnsafeArgumentError
from iacreview.finding import (
    AGENT_SOURCE,
    CONFIDENCES,
    CONFIRMED,
    CRITICAL_SEVERITY,
    FINDING_TYPES,
    SEVERITIES,
    SOURCES,
    Finding,
)
from iacreview.iam import detectors, intrinsics, locate
from iacreview.report import REPORT_KEYS, ReportMeta, build_report

# design.md fixes 100 iterations per property test; the smoke checks use the same
# number, since Task 22.1's completion condition is stated in those terms.
SMOKE = settings(
    max_examples=S.MAX_EXAMPLES,
    # These checks write files, spawn no processes but do touch the filesystem,
    # and run on whatever machine CI provides. A wall-clock deadline would make
    # them fail for being slow rather than for being wrong.
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)

#: Draws used by the coverage checks. Large enough that a strategy over a closed
#: set of at most eleven members reaches all of them with room to spare, small
#: enough to stay cheap; the fixed seed keeps it from being a coin flip.
COVERAGE_DRAWS = 300


def _exported_strategy_names() -> Tuple[str, ...]:
    """Names in ``strategies.__all__`` that are strategy factories.

    Discovered rather than listed, so a strategy added for a later property is
    covered by the two generic checks below without anyone remembering to
    register it here. A member that is not callable (:data:`strategies.RESOURCE_POOL`)
    or that returns something other than a strategy
    (:func:`strategies.dump_yaml`) is skipped.
    """
    names = []
    for name in S.__all__:
        candidate = getattr(S, name)
        if not callable(candidate):
            continue
        try:
            produced = candidate()
        except TypeError:
            continue
        if isinstance(produced, st.SearchStrategy):
            names.append(name)
    return tuple(sorted(names))


EXPORTED_STRATEGIES: Tuple[str, ...] = _exported_strategy_names()


def _collect(strategy: st.SearchStrategy[Any], key: Callable[[Any], Any]) -> Set[Any]:
    """Draw :data:`COVERAGE_DRAWS` values and return ``key`` over each.

    A plain loop over :func:`hypothesis.strategies.SearchStrategy.example` would
    warn (and would be slow); driving one ``@given`` test and accumulating into a
    set is the supported way to ask "what can this produce".
    """
    seen: Set[Any] = set()

    @settings(max_examples=COVERAGE_DRAWS, deadline=None, database=None)
    @seed(20250826)
    @given(strategy)
    def collect(value: Any) -> None:
        seen.add(key(value))

    collect()
    return seen


# ---------------------------------------------------------------------------
# Every exported strategy draws, and draws more than one thing
# ---------------------------------------------------------------------------


def test_the_module_exports_the_strategies_task_22_1_names() -> None:
    """The names design.md and Task 22.1 name are the ones exported."""
    required = {
        "findings",
        "finding_lists",
        "templates",
        "policy_documents",
        "paths",
        "exit_codes",
        "stderr_texts",
        "expected_actual_pairs",
    }
    assert required <= set(S.__all__)
    assert required <= set(EXPORTED_STRATEGIES)


@pytest.mark.parametrize("name", EXPORTED_STRATEGIES)
def test_every_exported_strategy_draws_the_required_examples(name: str) -> None:
    """Task 22.1's completion condition, applied to every exported strategy.

    100 draws, no exception. Strategies are discovered from ``__all__``, so a
    generator added later is covered without being registered here.
    """
    drawn: List[Any] = []

    @settings(max_examples=S.MAX_EXAMPLES, deadline=None, database=None)
    @seed(20250826)
    @given(getattr(S, name)())
    def draw(value: Any) -> None:
        drawn.append(value)

    draw()
    assert len(drawn) >= 1


@pytest.mark.parametrize("name", EXPORTED_STRATEGIES)
def test_every_exported_strategy_produces_more_than_one_value(name: str) -> None:
    """A constant strategy would make every property that uses it vacuous.

    ``@given`` over a constant runs 100 identical examples and reports success,
    which is the failure mode this check exists for. Values are fingerprinted by
    ``repr`` because not all of them are hashable.
    """
    fingerprints = _collect(getattr(S, name)(), repr)
    assert len(fingerprints) > 1


# ---------------------------------------------------------------------------
# Vocabularies are imported, not restated
# ---------------------------------------------------------------------------


def test_severity_strategy_covers_the_severity_vocabulary() -> None:
    assert _collect(S.severities(), lambda v: v) == set(SEVERITIES)


def test_finding_type_strategy_covers_the_finding_type_vocabulary() -> None:
    assert _collect(S.finding_types(), lambda v: v) == set(FINDING_TYPES)


def test_confidence_strategy_covers_the_confidence_vocabulary() -> None:
    assert _collect(S.confidences(), lambda v: v) == set(CONFIDENCES)


def test_category_strategy_covers_the_closed_category_set() -> None:
    """The closed set of Property 2, as ``category_map.json`` declares it."""
    assert _collect(S.categories_pool(), lambda v: v) == set(categories.load_map().categories)


def test_source_lists_cover_every_source_and_both_halves_of_property_6() -> None:
    drawn = _collect(S.source_lists(), lambda names: tuple(names))
    assert {name for names in drawn for name in names} == set(SOURCES)
    assert any(AGENT_SOURCE in names for names in drawn)
    assert any(AGENT_SOURCE not in names for names in drawn)


def test_source_subsets_reach_the_empty_and_the_full_subset() -> None:
    drawn = _collect(S.source_subsets(), lambda names: tuple(names))
    assert () in drawn
    assert tuple(fmod.sorted_sources(SOURCES)) in drawn


def test_cfnlint_level_strategy_is_the_categories_module_vocabulary() -> None:
    assert _collect(S.cfnlint_levels(), lambda v: v) == set(categories.CFNLINT_LEVELS)


def test_expectation_detection_classes_are_the_harness_vocabulary() -> None:
    drawn = _collect(S.expectations(), lambda item: item["detection_class"])
    assert drawn == set(metrics.DETECTION_CLASSES)


def test_shell_metacharacter_strategy_uses_the_pathguard_set() -> None:
    """Every rejected character is generated, and the set is pathguard's own."""
    drawn = _collect(
        S.strings_with_shell_metacharacters(),
        lambda text: frozenset(set(text) & pathguard.SHELL_METACHARACTERS),
    )
    assert set().union(*drawn) == pathguard.SHELL_METACHARACTERS


def test_structured_errors_carry_the_declared_key_set() -> None:
    drawn = _collect(S.structured_errors(), lambda payload: tuple(sorted(payload)))
    assert drawn == {tuple(sorted(errors.STRUCTURED_ERROR_KEYS))}


def test_structured_error_classes_stay_inside_the_closed_set() -> None:
    drawn = _collect(S.structured_errors(), lambda payload: payload["error_class"])
    assert drawn == set(errors.ERROR_CLASSES)


def test_defined_exit_codes_are_the_exit_code_table() -> None:
    assert _collect(S.defined_exit_codes(), lambda v: v) == set(exitcodes.EXIT_CODES.values())


def test_external_id_condition_key_matches_the_detector_spelling() -> None:
    """The Template spelling and the key the detector matches on are one key."""
    condition = S.external_id_condition()
    keys = [key for block in condition.values() for key in block]
    assert [key.lower() for key in keys] == [detectors.EXTERNAL_ID_CONDITION_KEY]


def test_blocking_rule_ids_are_resolved_from_the_mapping_file() -> None:
    """Non-empty, and every member blocks deployment according to the map.

    An empty result would silently stop every ``CRITICAL`` Finding from being
    generated, and no downstream property would notice.
    """
    cmap = categories.load_map()
    drawn = _collect(S.blocking_rule_ids(), lambda v: v)
    assert drawn
    assert all(cmap.blocks_deployment(rule_id) for rule_id in drawn)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


@SMOKE
@given(S.findings())
def test_findings_pass_finding_validate(f: Finding) -> None:
    fmod.validate(f)


@SMOKE
@given(S.findings())
def test_findings_respect_the_confidence_source_rule(f: Finding) -> None:
    """Property 6's rule, enforced by construction rather than filtered for."""
    if AGENT_SOURCE in f.Source:
        assert f.Confidence != CONFIRMED
    else:
        assert f.Confidence == CONFIRMED


@SMOKE
@given(S.findings())
def test_critical_findings_carry_a_deployment_blocking_rule_id(f: Finding) -> None:
    """Every ``CRITICAL`` Finding, not only the ``Validity`` ones.

    The reason is in the strategies module docstring: a merge can raise Severity
    to ``CRITICAL`` while keeping ``Validity``, and the justification has to have
    been present in the inputs.
    """
    if f.Severity != CRITICAL_SEVERITY:
        return
    cmap = categories.load_map()
    rule_ids = [entry.RuleId for entry in f.Evidence if entry.RuleId]
    assert any(cmap.blocks_deployment(rule_id) for rule_id in rule_ids)


@SMOKE
@given(S.finding_lists())
def test_finding_lists_are_valid_and_deduplicable(items: List[Finding]) -> None:
    """Task 22.1's completion condition: the list is dedup's input, and valid."""
    for f in items:
        fmod.validate(f)
    merged = deduplicate(items)
    assert len(merged) <= len(items)


@SMOKE
@given(S.finding_lists())
def test_deduplicated_lists_still_build_a_report(items: List[Finding]) -> None:
    """The merge output has to survive the output boundary, not only ``dedup``.

    ``build_report`` validates every Finding after numbering it, so a strategy
    whose merges produce something the schema rejects fails here rather than in
    the middle of Properties 12 and 13.
    """
    report = build_report(deduplicate(items), [], ReportMeta())
    assert tuple(sorted(report)) == tuple(sorted(REPORT_KEYS))
    assert report["summary"]["total"] == len(report["findings"])


def test_finding_lists_do_produce_merges() -> None:
    """The small ``Resource`` pool has to actually collide.

    Without collisions ``deduplicate`` would take its pass-through path on every
    example and Properties 3, 4, 5 and 11 would be testing nothing.
    """
    merged_something = _collect(
        S.finding_lists(min_size=2),
        lambda items: len(deduplicate(items)) < len(items),
    )
    assert True in merged_something


def test_finding_lists_include_unmatched_findings() -> None:
    """Both exclusions from matching occur: ``Other``, and no ``Resource``.

    Property 11 is about exactly these, so a list that never held one would make
    it vacuous.
    """
    kinds = _collect(
        S.finding_lists(min_size=1),
        lambda items: (
            any(f.Resource is None for f in items),
            any(f.Normalized_Category == fmod.OTHER_CATEGORY for f in items),
        ),
    )
    assert any(no_resource for no_resource, _ in kinds)
    assert any(other for _, other in kinds)


@SMOKE
@given(S.mergeable_finding_groups())
def test_mergeable_groups_always_merge_to_one_finding(group: List[Finding]) -> None:
    keys = {dedup_key(f) for f in group}
    assert len(keys) == 1 and None not in keys
    assert len(deduplicate(group)) == 1


@SMOKE
@given(S.finding_payloads())
def test_finding_payloads_round_trip_through_from_dict(payload: Dict[str, Any]) -> None:
    assert tuple(sorted(payload)) == tuple(sorted(fmod.FINDING_FIELDS))
    fmod.validate(fmod.from_dict(payload))


@SMOKE
@given(S.invalid_findings())
def test_invalid_findings_are_rejected_by_validate(f: Finding) -> None:
    with pytest.raises(errors.SchemaViolationError):
        fmod.validate(f)


def test_invalid_findings_cover_every_declared_violation() -> None:
    """Each breakage is reached, so no branch of the generator is dead code."""
    fields = _collect(
        S.invalid_findings(),
        lambda f: _violated_field(f),
    )
    assert len(fields) >= 6


def _violated_field(f: Finding) -> str:
    """The ``field`` of the violation ``f`` carries."""
    try:
        fmod.validate(f)
    except errors.SchemaViolationError as exc:
        return str(getattr(exc, "field", "unknown"))
    return "none"


@SMOKE
@given(S.locations())
def test_locations_are_schema_valid_and_vary_in_position(location: Any) -> None:
    assert not location.File.startswith("/")
    assert (location.Line is None) == (location.Column is None)


def test_locations_produce_both_positioned_and_unpositioned_values() -> None:
    drawn = _collect(S.locations(), lambda location: location.Line is None)
    assert drawn == {True, False}


def test_template_paths_keep_a_numeric_logical_id_as_a_key() -> None:
    """[Correction] C-9's exception is generated, not only described.

    A digit-only segment at index 1 is a logical ID and stays a ``str``; a
    digit-only segment anywhere else is a sequence index and is an ``int``.
    Both shapes have to occur or the correction is untested.
    """
    drawn = _collect(
        S.locations(),
        lambda location: _template_path_shape(location.TemplatePath),
    )
    assert "numeric-logical-id" in drawn
    assert "integer-index" in drawn
    assert "absent" in drawn


def _template_path_shape(path: Optional[List[Any]]) -> str:
    if path is None:
        return "absent"
    if len(path) > 1 and isinstance(path[1], str) and path[1].isdigit():
        return "numeric-logical-id"
    if any(isinstance(segment, int) for segment in path):
        return "integer-index"
    return "plain"


def test_findings_reach_the_redaction_marker_and_real_excerpts() -> None:
    """Property 7 has a redaction branch; the generator has to reach it."""
    drawn = _collect(
        S.findings(),
        lambda f: frozenset(
            "redacted" if entry.Excerpt == fmod.REDACTED_EXCERPT else "quoted"
            for entry in f.Evidence
            if entry.Excerpt
        ),
    )
    assert any("redacted" in kinds for kinds in drawn)
    assert any("quoted" in kinds for kinds in drawn)


# ---------------------------------------------------------------------------
# Report inputs
# ---------------------------------------------------------------------------


@SMOKE
@given(S.finding_lists(), st.lists(S.structured_errors(), max_size=2), S.report_metas())
def test_report_metas_build_a_report(
    items: List[Finding], failures: List[Dict[str, Any]], meta: Any
) -> None:
    report = build_report(deduplicate(items), failures, meta)
    assert len(report["errors"]) == len(failures)


def test_report_metas_reach_both_template_groups() -> None:
    drawn = _collect(S.report_metas(), lambda meta: bool(meta.synthesized_templates))
    assert drawn == {True, False}


@SMOKE
@given(S.stderr_texts())
def test_stderr_texts_stay_within_the_transcription_bound(text: str) -> None:
    """The input side of Property 23: any text, bounded output.

    ``_head_lines`` also redacts each retained line through
    ``redact_stderr_line`` -- absolute host paths (Task 34, Requirement 18 AC2)
    and, from v0.9.0, labeled process identifiers and recognized timestamps
    (Requirement 20) -- which is a separate concern with its own tests. To keep
    this smoke check about the 5-line *bound* alone, the example is restricted to
    text whose lines redact to themselves, so ``stderr_head`` equals the raw
    leading lines.
    """
    expected = text.splitlines()[: errors.STDERR_HEAD_MAX_LINES]
    assume(all(errors.redact_stderr_line(line) == line for line in expected))
    structured = errors.ToolExecutionError("tool failed", stderr=text).to_structured_error()
    head = structured["stderr_head"]
    assert len(head) <= errors.STDERR_HEAD_MAX_LINES
    assert head == expected


def test_stderr_texts_span_the_transcription_bound() -> None:
    """Fewer lines than the bound, exactly the bound, and more than it."""
    drawn = _collect(S.stderr_texts(), lambda text: len(text.splitlines()))
    limit = errors.STDERR_HEAD_MAX_LINES
    assert any(count < limit for count in drawn)
    assert limit in drawn
    assert any(count > limit for count in drawn)


@SMOKE
@given(S.exit_codes())
def test_exit_codes_are_integers_over_the_whole_range(code: int) -> None:
    assert isinstance(code, int) and not isinstance(code, bool)


def test_exit_codes_reach_negative_zero_and_large_values() -> None:
    drawn = _collect(S.exit_codes(), lambda code: (code < 0, code == 0, code > 255))
    assert any(negative for negative, _, _ in drawn)
    assert any(zero for _, zero, _ in drawn)
    assert any(large for _, _, large in drawn)


# ---------------------------------------------------------------------------
# Templates and documents
# ---------------------------------------------------------------------------


@SMOKE
@given(S.templates())
def test_templates_are_reviewable(document: Dict[str, Any]) -> None:
    assert template.is_reviewable(document)


@SMOKE
@given(S.unreviewable_documents())
def test_unreviewable_documents_are_not_reviewable(document: Any) -> None:
    assert not template.is_reviewable(document)


def test_templates_vary_in_iam_content() -> None:
    """Some Templates have policy sites and some have none (Requirement 6 AC12)."""
    drawn = _collect(S.templates(), lambda doc: bool(locate.find_policy_documents(doc)))
    assert drawn == {True, False}


@SMOKE
@given(S.template_texts())
def test_template_texts_parse_back_to_one_document(pair: Tuple[str, str]) -> None:
    """Property 15's premise: the two serializations hold the same document."""
    yaml_text, json_text = pair
    yaml_document, yaml_format = template.parse_template_text(yaml_text, Path("app.yaml"))
    json_document, json_format = template.parse_template_text(json_text, Path("app.json"))
    assert (yaml_format, json_format) == ("yaml", "json")
    assert yaml_document == json_document
    assert template.is_reviewable(yaml_document)


@SMOKE
@given(data=S.arbitrary_input_bytes())
def test_arbitrary_bytes_either_load_or_fail_as_a_declared_error(
    tmp_path_factory: Any, data: bytes
) -> None:
    """Property 17's input side: no unhandled exception from any byte string."""
    path = tmp_path_factory.mktemp("bytes") / "input.yaml"
    path.write_bytes(data)
    try:
        template.load_template(path)
    except IacReviewError as exc:
        assert exc.to_structured_error()["error_class"] in errors.ERROR_CLASSES


def test_arbitrary_bytes_reach_both_outcomes() -> None:
    """Random bytes alone would almost never parse; the seeded shapes do."""
    drawn = _collect(S.arbitrary_input_bytes(), _load_outcome)
    assert "loaded" in drawn
    assert "parse_failure" in drawn


def _load_outcome(data: bytes) -> str:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "input.yaml"
        path.write_bytes(data)
        try:
            template.load_template(path)
        except IacReviewError as exc:
            return str(exc.to_structured_error()["error_class"])
        return "loaded"


@SMOKE
@given(S.unsupported_yaml_tag_texts())
def test_unsupported_tags_are_refused_by_the_loader(text: str) -> None:
    """Property 21's input side: a tag outside the allowlist never constructs."""
    with pytest.raises(errors.TemplateParseError):
        template.parse_template_text(text, Path("app.yaml"))


def test_unsupported_tag_texts_never_use_an_allowlisted_tag() -> None:
    drawn = _collect(S.unsupported_yaml_tag_texts(), _tag_of)
    assert drawn
    assert not (drawn & set(yamlcfn.SHORT_TAGS))


def _tag_of(text: str) -> str:
    marker = "BucketName: !"
    start = text.index(marker) + len(marker)
    return text[start:].split(" ", 1)[0]


@SMOKE
@given(S.credential_templates())
def test_credential_templates_trigger_noecho_redaction(
    pair: Tuple[Dict[str, Any], str]
) -> None:
    """The secret sits at a location :mod:`iacreview.finding` recognizes."""
    document, secret = pair
    assert fmod.noecho_parameter_names(document)
    assert secret in S.dump_yaml(document)


# ---------------------------------------------------------------------------
# IAM
# ---------------------------------------------------------------------------


@SMOKE
@given(S.policy_documents())
def test_policy_documents_are_walkable_by_the_detectors(document: Dict[str, Any]) -> None:
    wrapped = {
        "Resources": {"A": {"Type": "AWS::IAM::ManagedPolicy",
                            "Properties": {"PolicyDocument": document}}}
    }
    sites = locate.find_policy_documents(wrapped)
    assert sites and all(site.has_policy_document for site in sites)
    target = detectors.PolicyTarget.from_site(sites[0], template_file="app.yaml")
    assert target.statements


def test_policy_documents_cover_the_four_statement_elements() -> None:
    """Action, Resource, Principal and Condition all vary (Task 22.1)."""
    drawn = _collect(S.policy_documents(), _statement_shapes)
    assert any("principal" in shape for shape in drawn)
    assert any("condition" in shape for shape in drawn)
    assert any("action-list" in shape for shape in drawn)
    assert any("action-star" in shape for shape in drawn)
    assert any("single-statement-mapping" in shape for shape in drawn)


def _statement_shapes(document: Dict[str, Any]) -> frozenset:
    statement = document["Statement"]
    shapes = set()
    if isinstance(statement, dict):
        shapes.add("single-statement-mapping")
        statements = [statement]
    else:
        statements = statement
    for entry in statements:
        if "Principal" in entry:
            shapes.add("principal")
        if "Condition" in entry:
            shapes.add("condition")
        if isinstance(entry["Action"], list):
            shapes.add("action-list")
        if entry["Action"] == "*" or "*" in entry["Action"]:
            shapes.add("action-star")
    return frozenset(shapes)


@SMOKE
@given(S.same_account_principals())
def test_same_account_principals_classify_as_same_account(value: Any) -> None:
    assert intrinsics.classify_principal(value) is intrinsics.PrincipalClass.SAME_ACCOUNT


@SMOKE
@given(S.cross_account_principals())
def test_cross_account_principals_classify_as_cross_account(value: Any) -> None:
    unwrapped = value["AWS"] if isinstance(value, dict) else value
    assert intrinsics.classify_principal(unwrapped) is intrinsics.PrincipalClass.CROSS_ACCOUNT


@SMOKE
@given(S.cross_account_statements())
def test_cross_account_statements_carry_no_condition(statement: Dict[str, Any]) -> None:
    """Property 27 adds the condition itself, so the input must not have one."""
    assert "Principal" in statement
    assert "Condition" not in statement


@SMOKE
@given(S.star_action_star_resource_documents())
def test_star_documents_always_hold_an_allow_on_everything(
    document: Dict[str, Any]
) -> None:
    statements = document["Statement"]
    assert any(
        entry.get("Effect") == "Allow"
        and "*" in _as_list(entry.get("Action"))
        and "*" in _as_list(entry.get("Resource"))
        for entry in statements
    )


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


@SMOKE
@given(S.iam_templates(document=S.star_action_star_resource_documents()))
def test_star_documents_reach_the_detector_through_every_site_kind(
    document: Dict[str, Any]
) -> None:
    """Property 28's premise: the wildcard grant is found wherever it is written."""
    sites = locate.find_policy_documents(document)
    assert sites
    findings_found = [
        found
        for site in sites
        for found in detectors.star_action_star_resource(
            detectors.PolicyTarget.from_site(site, template_file="app.yaml")
        ).findings
    ]
    assert findings_found


def test_iam_templates_cover_the_site_kinds_they_claim() -> None:
    kinds = _collect(
        S.iam_templates(),
        lambda doc: frozenset(site.kind for site in locate.find_policy_documents(doc)),
    )
    reached = set().union(*kinds) if kinds else set()
    assert locate.PolicyKind.TRUST_POLICY in reached
    assert locate.PolicyKind.INLINE_ROLE_POLICY in reached
    assert locate.PolicyKind.MANAGED_POLICY in reached
    assert locate.PolicyKind.RESOURCE_POLICY in reached


# ---------------------------------------------------------------------------
# Paths, arguments, temporary files
# ---------------------------------------------------------------------------


@SMOKE
@given(S.strings_with_shell_metacharacters())
def test_unsafe_strings_are_rejected(value: str) -> None:
    with pytest.raises(UnsafeArgumentError):
        pathguard.assert_no_shell_metacharacters(value)


@SMOKE
@given(S.strings_without_shell_metacharacters())
def test_safe_strings_are_accepted(value: str) -> None:
    pathguard.assert_no_shell_metacharacters(value)


@SMOKE
@given(value=S.relative_paths())
def test_relative_paths_resolve_inside_their_root(tmp_path_factory: Any, value: str) -> None:
    root = tmp_path_factory.mktemp("root")
    target = root / value
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("Resources:\n  A:\n    Type: AWS::S3::Bucket\n")
    resolved = pathguard.resolve_within(value, root)
    # ``Path.is_relative_to`` is 3.9+, but ``relative_to`` is the portable form
    # and raises where containment does not hold, which is what is asserted.
    resolved.resolve().relative_to(root.resolve())


@SMOKE
@given(value=S.paths_escaping_root())
def test_escaping_paths_are_refused_as_containment_violations(
    tmp_path_factory: Any, value: str
) -> None:
    root = tmp_path_factory.mktemp("root")
    with pytest.raises(PathContainmentError):
        pathguard.resolve_within(value, root)


def test_paths_strategy_spans_contained_escaping_and_unsafe_candidates() -> None:
    drawn = _collect(S.paths(), _path_kind)
    assert {"escaping", "unsafe"} <= drawn


def _path_kind(value: str) -> str:
    if set(value) & pathguard.SHELL_METACHARACTERS:
        return "unsafe"
    if value.startswith("/") or value.split("/")[:1] == [".."]:
        return "escaping"
    return "other"


@SMOKE
@given(S.temp_file_suffixes())
def test_temp_file_suffixes_are_accepted_and_cleaned_up(suffix: str) -> None:
    """Property 22's premise: the suffix does not itself defeat the helper."""
    with pathguard.secure_temp_file(suffix) as path:
        assert path.exists()
        created = path
    assert not created.exists()


@SMOKE
@given(S.invalid_argument_vectors())
def test_invalid_argument_vectors_are_lists_of_strings(argv: List[str]) -> None:
    assert all(isinstance(item, str) for item in argv)


def test_invalid_argument_vectors_include_an_unsafe_value() -> None:
    """One of Property 20's cases is a metacharacter in an otherwise valid argv."""
    drawn = _collect(
        S.invalid_argument_vectors(),
        lambda argv: any(set(item) & pathguard.SHELL_METACHARACTERS for item in argv),
    )
    assert True in drawn


@SMOKE
@given(S.failure_classes())
def test_failure_classes_are_declared_error_classes(name: str) -> None:
    assert name in errors.ERROR_CLASSES


@SMOKE
@given(layout=S.cdk_layouts())
def test_cdk_layouts_are_writable_directory_descriptions(
    tmp_path_factory: Any, layout: Dict[str, Any]
) -> None:
    root = tmp_path_factory.mktemp("cdk")
    for relative, content in layout.items():
        target = root / relative
        if content is None:
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    assert root.exists()


def test_cdk_layouts_cover_all_four_marker_combinations() -> None:
    drawn = _collect(
        S.cdk_layouts(),
        lambda layout: ("cdk.json" in layout, "cdk.out" in layout),
    )
    assert drawn == {(False, False), (False, True), (True, False), (True, True)}


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------


@SMOKE
@given(S.expectations())
def test_expectations_have_a_match_key_and_a_severity(item: Dict[str, Any]) -> None:
    assert len(metrics.match_key(item)) == 3
    assert metrics.severity_of(item) in SEVERITIES


@SMOKE
@given(S.expected_actual_pairs())
def test_expected_actual_pairs_are_computable(
    pair: Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]
) -> None:
    expected, actual = pair
    result = metrics.compute(expected, actual)
    assert tuple(result) == metrics.METRIC_KEYS


@SMOKE
@given(S.expected_actual_pairs(exact=True, min_size=1))
def test_exact_pairs_are_exact(
    pair: Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]
) -> None:
    """The ``exact`` branch has to be exact, or Property 30 tests nothing."""
    expected, actual = pair
    result = metrics.compute(expected, actual)
    assert result["detection_rate"] == "100.0"
    assert result["precision"] == "100.0"
    assert result["recall"] == "100.0"
    assert result["false_positive_count"] == 0


def test_expected_actual_pairs_produce_misses_and_false_positives() -> None:
    """The inexact branch has to be inexact often enough to matter."""
    drawn = _collect(
        S.expected_actual_pairs(exact=False),
        lambda pair: _outcome_shape(metrics.compute(*pair)),
    )
    assert any("false-negative" in shape for shape in drawn)
    assert any("false-positive" in shape for shape in drawn)
    assert any("matched" in shape for shape in drawn)


def _outcome_shape(result: Dict[str, Any]) -> frozenset:
    shapes = set()
    if result["false_negative_count"]:
        shapes.add("false-negative")
    if result["false_positive_count"]:
        shapes.add("false-positive")
    if result["matched_count"]:
        shapes.add("matched")
    return frozenset(shapes)


@SMOKE
@given(S.detection_rates())
def test_detection_rates_are_percentages_or_none(value: Optional[float]) -> None:
    assert value is None or 0.0 <= value <= 100.0
    assert metrics.format_percentage(value) == metrics.NOT_APPLICABLE or float(
        metrics.format_percentage(value)
    ) <= 100.0


def test_detection_rates_reach_the_pass_fail_boundary() -> None:
    """Property 31 turns at exactly 100 percent, so 100.0 has to be generated."""
    drawn = _collect(S.detection_rates(), lambda value: value)
    assert None in drawn
    assert 100.0 in drawn
    assert any(value is not None and value < 100.0 for value in drawn)


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


@SMOKE
@given(S.templates())
def test_dump_helpers_round_trip(document: Dict[str, Any]) -> None:
    assert yamlcfn.load_yaml(S.dump_yaml(document)) == document
    assert json.loads(S.dump_json(document)) == document
