# Delta_Tool acceptance fixtures (v1.1)

Fixtures for the v1.1 Semantic Diff and Finding Delta. Every expected value
was written by hand from the v1.1 Requirements and Design **before** the
Delta_Tool was implemented, and none was generated from the tool's output
(Requirements R15.3). When an implementation disagrees with a fixture, find
the cause (implementation bug, fixture bug, or a gap in the requirements)
before changing either side.

`tests/unit/test_delta_fixtures_inventory.py` checks that this directory,
the case table below, and the Requirements items R15.4 / R15.5 / R15.6 agree.

## Layout

```text
tests/fixtures/delta/
  templates/<case>/   base.{yaml,json}  head.{yaml,json}  expected.json
  reports/<case>/     base.json  head.json  expected.json  [template files]
```

One case is one directory. The Base side is always `base.*` and the Head side
is always `head.*`, except `templates/billion_laughs_reference`, whose Head is
`tests/fixtures/invalid/billion_laughs.yaml` referenced by path
(`inputs.head_ref`) rather than copied.

## Expected values

Identifiers are written in plain form. Identifier_Token values (`id-000001`
and so on) never appear in an expected value: a test maps plain identifiers to
Tokens itself.

Every list in an expected value is compared as a set unless stated otherwise:
the order of `changes`, `uncompared_paths`, `entries`, `qualifiers`, `hints`,
`semantic_limitations`, `reasons`, `missing_declarations` and the Evidence
difference lists carries no meaning here. Output order is a separate
requirement (R11.3) checked by its own tests.

### Template cases (`templates/<case>/expected.json`)

| Key | Meaning |
| --- | --- |
| `inputs` | `base` / `head` file names, or `head_ref` for a referenced fixture |
| `limits` | Limit constants a test sets with `monkeypatch` before the run (for example `{"MAX_TEMPLATE_NODES": 17}`); empty means the shipped limits |
| `expected.analysis_state`, `observation`, `structural_completeness`, `semantic_limitations` | The four state fields of R5.1 |
| `expected.failure` | `null`, or `{side, input, code}` with a failure Code of Design 10-5 |
| `expected.uncompared_paths` | `{path, reason}`; `path` starts at the section name. A path is listed once and stands for the same path on both sides |
| `expected.changes` | Change_Entries: `section`, `path`, `change`, `type_changed`, `resource_type` (`{base, head}` inside `Resources`, otherwise `null`), `qualifiers`, `hints` |
| `expected.shapes` | Optional. Logical node count, depth (root = 1) and distinct container count per side, counted by hand without the limits |

Paths use mapping keys as strings and list indexes as integers.

### Report cases (`reports/<case>/expected.json`)

| Key | Meaning |
| --- | --- |
| `declarations` | Declaration sets the case is run with: `all` only (R15.5 matching cases), or `all` / `none` / `one_missing` (R15.6 classification cases) |
| `template_pair` | `null`, or the Template file of each side in this directory and the workspace-relative path it is placed at |
| `edits` | Hand edits applied to a Report after `report.build_report` |
| `expected.report_integrity` | Failed check names per side (Design 9-2) |
| `expected.comparable` | The `comparable` summary flag (R7.10) |
| `expected.template_report_correspondence` | R8.6 value |
| `expected.by_declarations.<mode>` | `observation`, `classification_completeness` and `entries` for that declaration set |

A Delta_Entry names each present side by the Finding's `Finding` text, which
is unique within a Report. A test maps that label to the Finding's `ID` in the
fixture file. `match_stage` is `null` for an entry that is not `matched`.
`changes` uses the field names `Severity`, `FindingType`, `Confidence`,
`Source`, `Location.TemplatePath` and `Evidence` (R6.13). Evidence difference
elements are `{Source, RuleId, source_comparable}`.

## How the Reports were made

Each Report was assembled with the existing v1.0 `report.build_report` from
hand-written Findings and serialized with `report.dump`, so an unedited Report
passes the internal-consistency checks. All Findings point at
`templates/app.yaml` (or `templates/other.yaml` where noted). Defaults unless a
case says otherwise: `sources_enabled` holds the six deterministic Sources,
`tools` holds `cfn-guard 3.2.1` and `cfn-lint 1.46.0`, both available, and
`errors[]` is empty.

Hand edits after `build_report` (also listed in each case's `edits`):

| Case | Edit |
| --- | --- |
| `match_reordered_findings_and_evidence` | Head: `findings[]` reversed and every `Evidence[]` reversed; each Finding keeps its ID |
| `classify_integrity_id_gap` | Head: the last Finding's `ID` raised by 1 (IDs 1, 3) |
| `classify_integrity_order_violation` | Head: the first two `findings[]` swapped, IDs renumbered 1..n in the new order |
| `classify_integrity_summary_mismatch` | Head: `summary.by_severity.LOW` raised by 1 |

Other per-case inputs are built rather than edited: a tool recorded with
`available: false` and a matching `tool_unavailable` error
(`classify_tool_unavailable`, `match_non_comparable_evidence_removed`), a
Source removed from `sources_enabled` and its tool from `tools`
(`classify_source_not_enabled`), `cfn-lint 1.47.0` on the Head
(`classify_tool_version_mismatch`), an error attributed to `cfn-lint`
(`classify_error_attributed`) or to no Source (`classify_error_unattributed`),
a second Template in the Base `target.files` only
(`classify_template_not_reviewed`), and `Agent Review` enabled on both sides
(`classify_agent_review_only`).

## Interpretation notes

These notes record how an expected value follows from the requirements where
the requirement text leaves a detail open. They are fixture conventions, not
new requirements.

- **Change position.** A change is reported at the deepest differing position;
  `added` / `removed` at the root of the subtree (Design 3-2). Two mappings are
  compared key by key, so `{Ref: X}` against `{Fn::Sub: Y}` gives a `removed`
  entry under `Ref` and an `added` entry under `Fn::Sub`.
- **Qualifiers look at the expression a change belongs to.** A qualifier
  applies when its condition holds for either side's value at the change
  position, or for an intrinsic function whose key appears in the change path.
  So a change under `Fn::Equals` or `Fn::If` carries `expression_unevaluated`,
  and the removed `Ref` of `AWS::Region` carries `external_value`
  (Requirements R5 state table: `!Ref AWS::Region` to `!Sub "${AWS::Region}"`).
  `external_value` requires `Fn::ImportValue`, `Fn::GetAZs`, or a `Ref` to an
  `AWS::` pseudo parameter (R4.6); a `${AWS::Region}` inside `Fn::Sub` alone
  does not add it.
- **`conditional`** is attached to a change inside a Resource or Output that
  has a `Condition` attribute on either side, or below an `Fn::If` (R4.4). A
  change inside the `Conditions` section is not conditional by itself.
- **Duplicate keys.** The mapping holding the duplicate is not compared and
  its path is listed (R2.5). For a mapping written with a tag (`!Sub {x: 1,
  x: 2}`), the whole tagged value is listed (Design 2-2-1). For a mapping
  shared through an alias, every path at which it appears is listed. For a
  duplicate top-level key, only that section is listed, and the rest of the
  document is compared.
- **`tool_version_mismatch`** is added only when the tool is available on both
  sides with different versions. A tool recorded as unavailable gives
  `source_not_comparable` alone.
- **`template_not_reviewed`** is added to `source_not_comparable` when the
  Finding's file is missing from one Report's `target` (Design 7-1).
- **Required declarations.** Without a Template_Pair, `New` / `Resolved` need
  the five Report declarations; with one, `reports_match_templates` as well
  (R8.4). `missing_declarations` lists the missing Codes.
- **Template_Pair with Report_Pair.** The correspondence cases place one
  Template at `templates/app.yaml` and use it for both sides, because a
  Finding's file has to be in both Reports' `target` to be Comparable (R7.1)
  and each Template's path has to be in its own Report's `target` (R8.6).

## Cases

### Templates (R15.4)

| Case | Covers |
| --- | --- |
| `templates/alias_forward_reference` | R2.12 an undefined forward alias is an ordinary parse failure (Design F-15) |
| `templates/aws_include` | R15.4 AWS::Include; R4.7; R4.8 |
| `templates/billion_laughs_reference` | R15.4 `tests/fixtures/invalid/billion_laughs.yaml` under the shipped alias budget; R14.6 |
| `templates/cdk_synth_format` | R15.4 CDK synth format; R4.14 CDK-generated content is not dropped |
| `templates/condition_changed` | R15.4 Condition change; R4.4 conditional present / absent |
| `templates/cycle_inside_resource` | R15.4 alias cycle: inside a Resource; R2.12 |
| `templates/cycle_inside_short_tag` | R2.12 a cycle inside a short tag is an ordinary parse failure (Design F-15) |
| `templates/cycle_list` | R15.4 alias cycle: list; R2.12 |
| `templates/cycle_mapping` | R15.4 alias cycle: mapping; R2.12 |
| `templates/depth_limit_boundary` | R15.4 depth at the limit and limit + 1; R14.6 |
| `templates/duplicate_key_alias_shared_yaml` | R15.4 duplicate key: mapping shared through an alias; R2.5 |
| `templates/duplicate_key_deep_yaml` | R15.4 duplicate key: deep level; R2.5 |
| `templates/duplicate_key_in_resource_yaml` | R15.4 duplicate key: inside a Resource; R2.5 |
| `templates/duplicate_key_in_tag_yaml` | R15.4 duplicate key: mapping inside a tag; R2.5; Design 2-2-1 tagged node |
| `templates/duplicate_key_json` | R15.4 duplicate key: JSON (section name and inside a Resource); R2.5 |
| `templates/duplicate_key_section_yaml` | R15.4 duplicate key: section name; R2.5 |
| `templates/duplicate_key_with_other_change_yaml` | R15.4 duplicate key together with another change; R5.4 |
| `templates/dynamic_reference_changed` | R15.4 dynamic reference string change; R4.5 |
| `templates/dynamic_reference_unchanged` | R15.4 dynamic reference without change; R4.8 |
| `templates/fn_if_changed` | R15.4 change inside Fn::If; R4.4 |
| `templates/import_value` | R15.4 Fn::ImportValue; R4.3; R4.6 |
| `templates/intrinsic_equivalent_rewrite` | R15.4 equivalent intrinsic rewrite; R3.10; R4.3; R4.6 |
| `templates/list_order_changed` | R15.4 list order change; R3.12 |
| `templates/logical_id_rename` | R15.4 Logical ID rename; R4.13 |
| `templates/nested_stack` | R15.4 Nested Stack; R4.8; R4.12 |
| `templates/no_resources` | R15.4 no Resources; R2.4 |
| `templates/node_limit_boundary` | R15.4 logical node count at the limit and limit + 1; R14.6 |
| `templates/normalization_non_string_key` | R15.4 non-string mapping key (Design N-5) |
| `templates/normalization_unquoted_date` | R15.4 unquoted date (Design N-3) |
| `templates/normalization_yaml_timestamp` | R15.4 timestamp with time (Design N-4) |
| `templates/notation_anchor_alias` | R15.4 notation: anchors and aliases; R3.8 |
| `templates/notation_comments_and_quoting` | R15.4 notation: comments, whitespace, YAML quoting; R3.8 |
| `templates/notation_key_order` | R15.4 notation: mapping key order; R3.8 |
| `templates/notation_short_vs_long_form` | R15.4 notation: short form vs long form; R3.9 |
| `templates/notation_yaml_vs_json` | R15.4 notation: YAML vs JSON; R3.8 |
| `templates/parameter_default_changed` | R15.4 Parameter Default change; R4.10; R4.11 |
| `templates/property_changed` | R15.4 Property change; R3.3 |
| `templates/resource_added_removed` | R15.4 Resource added and removed; R3.1 |
| `templates/resource_attribute_changed` | R15.4 Resource Attribute change; R3.3 |
| `templates/resource_type_changed` | R15.4 Resource Type change; R3.2 |
| `templates/scalar_type_difference` | R15.4 scalar type difference; R3.11; Design N-6 |
| `templates/section_level_changes` | R3.4 entry-level sections; R3.5 section-level sections; R3.6 unknown top-level key |
| `templates/syntax_error_yaml` | R15.4 syntax error; R2.4; R5.9 |
| `templates/transform_changed` | R15.4 Transform with change; R4.7 |
| `templates/transform_unchanged` | R15.4 Transform without change; R4.8 |

### Reports for matching (R15.5)

| Case | Covers |
| --- | --- |
| `reports/match_dedup_identity_duplicated` | R15.5 duplicated dedup-eligible Identity_Key; Design E-7; R2.10; R2.11 |
| `reports/match_duplicate_fingerprint` | R15.5 duplicated Fingerprint; Design E-6; R6.7 |
| `reports/match_evidence_partially_removed` | R15.5 part of a dedup-eligible Finding's Evidence removed; R6.13; R6.14 |
| `reports/match_identical_reports` | R15.5 identical Reports; R6.4; R6.5; R6.9 |
| `reports/match_merged_and_single_source` | R15.5 merged Finding against a single-Source Finding; R6.4; R6.13 |
| `reports/match_non_comparable_evidence_removed` | R15.5 only the Evidence of a non-Comparable Source removed; R6.13 |
| `reports/match_null_resource_evidence_changed` | R15.5 Resource null, one to one, only Evidence changed; R6.6; R6.7 |
| `reports/match_null_resource_none_matches` | R15.5 Resource null, Base 1 / Head 2, neither with the same Fingerprint; Design E-5 |
| `reports/match_null_resource_one_of_two_matches` | R15.5 Resource null, Base 1 / Head 2, one with the same Fingerprint; Design E-4 |
| `reports/match_null_resource_same_fingerprint` | R15.5 Resource null, one to one, same Fingerprint; R6.5 |
| `reports/match_null_resource_templatepath_changed` | R15.5 Resource null, one to one, only TemplatePath changed; R6.6; R6.7 |
| `reports/match_other_category_multiple` | R15.5 several Other Findings on the same Resource; R6.5 |
| `reports/match_reordered_findings_and_evidence` | R15.5 only the order of findings[] and Evidence[] differs; R6.10 |
| `reports/match_templatepath_and_evidence_changed` | R15.5 TemplatePath and Evidence both changed; R6.4; R6.13 |

### Reports for classification (R15.6)

| Case | Covers |
| --- | --- |
| `reports/classify_agent_review_only` | R15.6 Finding whose only Source is Agent Review; R7.2 |
| `reports/classify_error_attributed` | R15.6 errors[] entry attributed to a Source; R7.1 |
| `reports/classify_error_unattributed` | R15.6 errors[] entry without a Source; R7.1 |
| `reports/classify_integrity_id_gap` | R15.6 internal consistency failure: ID gap; R2.10; R2.11 |
| `reports/classify_integrity_order_violation` | R15.6 internal consistency failure: order; R2.10; R2.11 |
| `reports/classify_integrity_summary_mismatch` | R15.6 internal consistency failure: summary; R2.10; R2.11 |
| `reports/classify_recorded_conditions_met` | R15.6 head_only / base_only meeting the recorded conditions; R7.3; R7.4 |
| `reports/classify_source_not_enabled` | R15.6 Source not in sources_enabled; R7.1; R7.2 |
| `reports/classify_template_not_reviewed` | R15.6 Template not reviewed on one side; R7.2 |
| `reports/classify_tool_unavailable` | R15.6 Finding gone because the tool was unavailable; R7.2; R7.5 |
| `reports/classify_tool_version_mismatch` | R15.6 tools[].version mismatch; R7.1; R7.2 |
| `reports/correspondence_consistent_by_name_only` | R15.6 template_report_correspondence consistent_by_name_only; R8.6 |
| `reports/correspondence_inconsistent` | R15.6 template_report_correspondence inconsistent; R8.6; R7.2 |
| `reports/correspondence_unknown` | R15.6 template_report_correspondence unknown; R8.6; R7.2 |
