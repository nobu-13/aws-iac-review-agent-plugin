# Delta_Report Schema (v1.1 Delta_Tool)

This document is the reference for the JSON that the v1.1 Delta_Tool writes to
stdout: the Delta_Report. It covers every key, every closed set of values, what
each state means, and what a result does not mean.

The Delta_Tool compares a Base and a Head CloudFormation Template (the Semantic
Diff) and/or a Base and a Head Review_Report (the Finding Delta). It is a
comparison tool, not a quality gate: no field asserts that anything improved,
was fixed, is safe, or passed.

The closed sets below are checked against the module constants in
`iacreview/deltaschema.py` and `iacreview/deltareport.py` by
`tests/unit/test_delta_schema_doc.py`. Each list marked `closed-set` is the
documented order of that set.

## Running the tool

```text
PYTHONPATH=<plugin_root> python3 -m iacreview.deltacli [options]
```

Run it from the workspace root; every path must resolve inside it.

Examples (from the workspace root, with the Plugin root on `PYTHONPATH`): a
Semantic Diff of two Templates, then a Finding Delta of two Review_Reports
with the five Report declarations.

```text
python3 -m iacreview.deltacli --base-template base/template.yaml --head-template head/template.yaml

python3 -m iacreview.deltacli --base-report base.json --head-report head.json \
  --declare reports_unmodified --declare same_plugin_version --declare same_rule_set \
  --declare same_tool_configuration --declare same_agent_findings_input
```

To make the two Reports, review each revision with `run_iac_review.py` from
its own checkout, at the same relative path, so that `Location.File` and
`target` agree on both sides:

```text
(cd checkout-base && python3 <plugin_root>/skills/iac-review/scripts/run_iac_review.py --target stack/template.yaml > ../base.json)
(cd checkout-head && python3 <plugin_root>/skills/iac-review/scripts/run_iac_review.py --target stack/template.yaml > ../head.json)
```

Compare the Reports as a Report_Pair alone, or both pairs in one run with
`--reviewed-template-path`, which declares the path at which both Reports
reviewed the Template. Copy each checkout's Template into the workspace (or
run from a directory that holds both checkouts) and give the six declarations:

```text
python3 -m iacreview.deltacli \
  --base-template checkout-base/stack/template.yaml --head-template checkout-head/stack/template.yaml \
  --base-report base.json --head-report head.json \
  --declare reports_unmodified --declare same_plugin_version --declare same_rule_set \
  --declare same_tool_configuration --declare same_agent_findings_input \
  --declare reports_match_templates \
  --reviewed-template-path stack/template.yaml
```

Without `--reviewed-template-path`, each Template path (here
`checkout-base/stack/template.yaml`) must be in its own Report's `target`,
which a Report made in its own checkout never satisfies, so one run with both
pairs gives no `New` or `Resolved` (see "Known limitations").

The declared path is a declaration, not a verification. It is recorded as
`reviewed_template_path` with the status `declared_not_verified`; the file at
that path is not read and need not exist. The tool does not check that the
Templates given are the ones the Reports reviewed. The declaration only
replaces the path that the Template / Report correspondence check compares
with each Report's `target` (and on which Findings are checked against the
Template's Logical IDs); it is compared as a string after normalization (`/`
separators, `.` and empty segments removed), so a different letter case,
Unicode normalization (NFC / NFD) or symlink name gives `inconsistent`. Report
integrity, Comparable, the required declarations (including
`reports_match_templates`), rename hints and the limits apply unchanged, so a
doubtful input still gives `Unconfirmed` or `Ambiguous`, never `New` or
`Resolved`. The value is refused (exit 2, before any input is read) when it is
empty, contains a NUL character or a shell metacharacter, is absolute, has a
drive or a `..` segment, or leaves the workspace through an existing path
element such as a symlink.

What these commands gave on a scratch workspace in which the Head adds an
`AWS::IAM::ManagedPolicy` allowing `*` on `*`, removes an `AWS::IAM::Role`
that had the same, and keeps a role that may pass any role (Reports made with
`--sources iam-review`; the first eight runs exited 0):

| Run | Result |
| --- | --- |
| Template_Pair | `analyzed`, `changes_observed`, `complete`; one `added` (`AWS::IAM::ManagedPolicy`) and one `removed` (`AWS::IAM::Role`) Change_Entry under `Resources`, each Logical ID a Token. |
| Report_Pair, no `--declare` | `Unchanged` 1 (stage 1); `Unconfirmed` 2 with `input_declaration_absent` and the five Report Codes in `missing_declarations`. |
| Report_Pair, five declarations | `New` 1, `Resolved` 1, `Unchanged` 1; `classification_completeness` `complete`, `comparable` `true`, `template_report_correspondence` `not_applicable`. |
| Both pairs, six declarations, no `--reviewed-template-path` | `template_report_correspondence` `inconsistent`; `Unchanged` 1, `Ambiguous` 2 with `template_report_mismatch`. |
| Both pairs, six declarations, `--reviewed-template-path stack/template.yaml` | `template_report_correspondence` `consistent_by_name_only`, `reviewed_template_path` `{"path": "stack/template.yaml", "status": "declared_not_verified"}`; `New` 1, `Resolved` 1, `Unchanged` 1, `classification_completeness` `complete`. The `New` Finding's `Resource` and the `added` Change_Entry carry the same Token. |
| The same with Base and Head swapped | `New` and `Resolved` swap. |
| The same without `--declare reports_match_templates` | `consistent_by_name_only`; `Unchanged` 1, `Unconfirmed` 2 with `reports_match_templates` in `missing_declarations`. |
| The same with `--reviewed-template-path stack/other.yaml` | `inconsistent`; `Unchanged` 1, `Ambiguous` 2 with `template_report_mismatch`. |
| `--reviewed-template-path` with a Report_Pair only, or with `../stack/template.yaml` | Exit 2, fixed message and usage on stderr, no Delta_Report. |
| `--base-report` alone | Exit 2, usage on stderr, no Delta_Report. |
| `--base-template ../outside.yaml` | Exit 7; the Semantic Diff is `unanalyzable` with failure Code `path_violation`. |

Running the same command twice gives the same bytes (SHA-256 compared).

For a pair with no Logical ID added or removed (`tests/integration/test_delta_end_to_end.py`:
the Base allows `*` on `*` in `PolicyA` only and the Head in `PolicyB` only),
both pairs with the six declarations and `--reviewed-template-path
stack/template.yaml` give `consistent_by_name_only`, `Resolved` 1 (`PolicyA`)
and `New` 1 (`PolicyB`), and no `Ambiguous`; swapping Base and Head swaps them.
`reviewed_template_path` is `{"path": "stack/template.yaml", "status":
"declared_not_verified"}`. When a Logical ID is removed and another of the
same Resource Type is added, the declaration does not override the rename
hint: those Findings stay `Ambiguous` with `possible_logical_id_rename`.

| Option | Meaning |
| --- | --- |
| `--base-template PATH`, `--head-template PATH` | The Template_Pair. Both or neither. |
| `--base-report PATH`, `--head-report PATH` | The Report_Pair (Review_Report JSON from `run_iac_review.py`). Both or neither. |
| `--declare CODE` | One Input_Declaration per occurrence, from the Unverified_Assumption set. Repeatable. |
| `--format json` | The only format (the default). |
| `--plain-identifiers` | Write identifiers in plain form. Values and free text are still never written. |
| `--reviewed-template-path PATH` | With both pairs only, once: the workspace-relative path at which both Reports reviewed the Template. Declared, not verified; the file is not read. |
| `--verbose` | Accepted for consistency with the other entry points; changes nothing. |

Exit 2 with no Delta_Report, before any input is read, when: a pair is given on
one side only; no pair is given; `--declare` is given without a Report_Pair;
`--declare reports_match_templates` is given without a Template_Pair; a Code is
outside the set (including `all`); a path option or `--format` is given twice; a path is empty or
contains a NUL character or a shell metacharacter (`;`, `|`, `&`, `$`, a
backtick, `>`, `<`); `--reviewed-template-path` is given without both pairs,
twice, or with a value refused as described above. stderr then holds a fixed
message and the usage line, not the argument text.

Declarations come from the command line only. The tool reads no environment
variable, no configuration file and no stdin, starts no process, opens no
network connection and writes no file. (The Python interpreter may still
write its own bytecode cache under the Plugin's `iacreview/__pycache__`; set
`PYTHONDONTWRITEBYTECODE=1` to prevent it.)

## Envelope

<!-- closed-set: ENVELOPE_KEYS -->
- `delta_schema_version`: Always `1.0.0` in this version. Independent of the Review_Report `schema_version`.
- `scope`: Always `declared_template`.
- `identifier_mode`: `anonymized` (default) or `plain` (`--plain-identifiers` was given).
- `inputs`: Per-side input metadata: `{"base": SideInputs, "head": SideInputs}`.
- `semantic_diff`: The Semantic Diff, or `null` without a Template_Pair.
- `finding_delta`: The Finding Delta, or `null` without a Report_Pair.
- `errors`: StructuredErrors (the v1.0 9-key object), in exit order.
- `summary`: Counts per closed-set value.

The file is serialized exactly like the v1.0 Review_Report: sorted keys, two
space indentation, UTF-8, a trailing newline. One addition: C1 control
characters and the bidirectional controls listed under "Known limitations"
are written as `\uXXXX` escapes inside strings; the decoded values are the
same, and output without these characters is byte-identical to the v1.0
serialization. Identical input bytes and
arguments give identical output bytes across runs, processes and
`PYTHONHASHSEED` values. The output holds no time, host name, process ID,
absolute path, user name, random value or environment-derived value.

### SideInputs

<!-- closed-set: SIDE_INPUT_KEYS -->
- `template`: `{path, format}` or `null` without a Template_Pair.
- `report`: The Report metadata or `null` without a Report_Pair.

<!-- closed-set: TEMPLATE_INPUT_KEYS -->
- `path`: Workspace-relative `/`-separated path, or `null` when the argument did not resolve inside the workspace.
- `format`: `yaml` or `json`, or `null` when the Template is unanalyzable.

<!-- closed-set: REPORT_INPUT_KEYS -->
- `path`: Workspace-relative path, or `null` when it did not resolve.
- `sha256`: Hex SHA-256 of the exact bytes read, or `null` when nothing was read.
- `schema_version`: The Report `schema_version`, or `null` when the Report was rejected.
- `target`: `{files, cdk: {detected, synthesis, synthesized_templates}}` as the Report records it, or `null`.
- `sources_enabled`: The Report `sources_enabled`, or `null`.
- `tools`: `[{name, available, version}]` with `name` and `version` written by the rules of "Plain values and Identifier_Tokens", or `null`.
- `error_summary`: `[{error_class, source}]`, one per Report `errors[]` entry, or `null`. The `message`, `remediation` and `stderr_head` of the input errors are never copied.

A rejected Report keeps `path` and `sha256`; the other keys are `null`.

## Semantic Diff

<!-- closed-set: SEMANTIC_DIFF_KEYS -->
- `analysis_state`: `analyzed` or `unanalyzable`.
- `observation`: `changes_observed` or `no_changes_observed`; `null` only when `unanalyzable`.
- `structural_completeness`: `complete` or `partial`; `null` only when `unanalyzable`.
- `semantic_limitations`: Semantic_Limitation Codes, in the documented order.
- `uncompared_paths`: `[{path, reason}]`: positions left out of the comparison.
- `changes`: Change_Entries.
- `failure`: `null`, or `{side, input, code, error_index}` when `unanalyzable`.

`complete` means every part of both declared Templates was compared. It does
not mean that the deployed stacks are equivalent: no result of this tool,
including `complete` with `no_changes_observed`, implies equivalence after
deployment. Semantic_Limitations and Change_Qualifiers do not change
`structural_completeness`; they describe what a comparison of the declared
structure cannot determine.

An `unanalyzable` Semantic Diff has no Change_Entry and no uncompared path. It
is unanalyzable when either Template cannot be read, parsed or accepted, has a
YAML alias cycle, exceeds a limit, or when the comparison exceeds the
Change_Entry limit. Changes are never inferred from one side.

### Change_Entry

<!-- closed-set: CHANGE_ENTRY_KEYS -->
- `section`: The top-level section name (or its Token).
- `path`: From the section name down. Strings are keys; integers are list indexes.
- `change`: A change kind.
- `type_changed`: `true` when a Resource `Type` differs; nothing below it is paired.
- `resource_type`: `{base, head}` inside `Resources` (`null` on a side without the Resource), else `null`.
- `qualifiers`: Change_Qualifier Codes, in the documented order.
- `hints`: Hint Codes.

<!-- closed-set: UNCOMPARED_PATH_KEYS -->
- `path`: The position, from the section name down. An empty list is the document root.
- `reason`: An uncompared reason.

A change is reported once, at the deepest position where the two sides
differ; `added` and `removed` are reported at the root of the subtree that
exists on one side only. Only direct changes are reported: a Resource is not
`modified` because a Parameter, Mapping or Condition it references changed.

### Closed sets of the Semantic Diff

<!-- closed-set: ANALYSIS_STATES -->
- `analyzed`: The comparison ran to the end.
- `unanalyzable`: An input or a limit stopped it; see `failure`.

<!-- closed-set: OBSERVATIONS -->
- `changes_observed`: At least one Change_Entry (Semantic Diff), or at least one Delta_Entry that is not `matched` or has non-empty `changes` (Finding Delta).
- `no_changes_observed`: None of the above. Not a proof that nothing changed.

<!-- closed-set: STRUCTURAL_COMPLETENESS -->
- `complete`: No uncompared path.
- `partial`: At least one uncompared path.

<!-- closed-set: CHANGE_KINDS -->
- `added`: Present on the Head side only.
- `removed`: Present on the Base side only.
- `modified`: Present on both sides with a different value or kind.

<!-- closed-set: CHANGE_QUALIFIERS -->
- `expression_unevaluated`: The changed subtree, or a key on the way to it, contains `Ref`, an `Fn::` function or the Condition function. The expression was compared unevaluated.
- `conditional`: The change belongs to a Resource or Output with a `Condition` attribute on either side, or is inside `Fn::If`.
- `dynamic_reference_unresolved`: The changed subtree contains a string with `{{resolve:`.
- `external_value`: The changed subtree contains `Fn::ImportValue`, `Fn::GetAZs` or a `Ref` to an `AWS::` pseudo parameter.
- `pre_transform`: The Semantic_Limitation `transform_not_expanded` applies; every Change_Entry carries it.

<!-- closed-set: SEMANTIC_LIMITATIONS -->
- `transform_not_expanded`: Either side has a top-level `Transform`, `Fn::Transform` or `AWS::Include`. The Templates were compared before expansion.
- `indirect_effects_not_evaluated`: A Change_Entry is in `Parameters`, `Mappings` or `Conditions`. Effects on what references them are not evaluated.
- `dynamic_reference_unresolved`: Either side contains a string with `{{resolve:`, changed or not.
- `nested_stack_not_compared`: Either side has `AWS::CloudFormation::Stack`. Only its declared Properties are compared, not the child Template.

<!-- closed-set: CHANGE_HINTS -->
- `possible_logical_id_rename`: A removed and an added Resource have the same `Type`. Both carry the hint; they are not paired.

<!-- closed-set: UNCOMPARED_REASONS -->
- `duplicate_key`: The mapping at this position repeats a key on a side (a repeated section name leaves the whole section out). Neither the key nor its values are written.
- `non_string_key`: The mapping at this position has a key that is not a string.
- `yaml_timestamp`: A YAML timestamp with a time is at this position.

## Finding Delta

<!-- closed-set: FINDING_DELTA_KEYS -->
- `analysis_state`: `analyzed` or `unanalyzable`.
- `observation`: As for the Semantic Diff; `null` only when `unanalyzable`.
- `classification_completeness`: `complete` or `partial`; `null` only when `unanalyzable`.
- `report_authenticity`: Always `unverified`.
- `report_integrity`: `{base: {failed_checks}, head: {failed_checks}}`, or `null` when `unanalyzable`.
- `input_declarations`: `{declared, missing, status}`. `status` is always `declared_not_verified`.
- `unverified_assumptions`: Every Unverified_Assumption, whatever was declared. `reports_match_templates` is listed only with a Template_Pair.
- `template_report_correspondence`: A correspondence value, or `null` when `unanalyzable`.
- `reviewed_template_path`: `null` without `--reviewed-template-path`, otherwise `{path, status}` with the normalized declared path and `status` always `declared_not_verified`. Recorded also when `unanalyzable`. A declaration, not a verification.
- `comparable`: The summary flag: `true` only when both Reports have empty `errors[]`, every tool is available and both Reports list the same tools with the same versions. It does not look at `passed_all_checks`. `null` when `unanalyzable`.
- `entries`: Delta_Entries.
- `failure`: `null`, or `{side, input, code, error_index}` when `unanalyzable`.

A Finding Delta is unanalyzable when either Report cannot be read or parsed,
is not the 7-key Review_Report of schema MAJOR 1 in the shapes
`run_iac_review.py` produces, has a Finding that does not validate, or has
more Findings than the limit. A failed internal-consistency check does not
make it unanalyzable; it is recorded and stops New / Resolved.

### Delta_Entry

<!-- closed-set: DELTA_ENTRY_KEYS -->
- `observation`: An Entry_Observation.
- `classification`: A Delta_Classification.
- `reasons`: Ambiguous / Unconfirmed reasons, in the documented order.
- `missing_declarations`: For `Unconfirmed`, the missing declaration Codes.
- `key`: The Identity_Key `{File, Resource, Normalized_Category}`.
- `match_stage`: `1` or `2` for a matched entry, else `null`.
- `base`: The Base Finding_Projection, or `null`.
- `head`: The Head Finding_Projection, or `null`.
- `changes`: For a matched entry, the differing fields among `Severity`, `FindingType`, `Confidence`, `Source`, `Location.TemplatePath`, `Evidence`.
- `evidence_absent_in_head`: Evidence elements of the Base Finding missing from the Head Finding.
- `evidence_absent_in_base`: Evidence elements of the Head Finding missing from the Base Finding.

<!-- closed-set: PROJECTION_KEYS -->
- `ID`: The Finding `ID` in its own Report. With the Report `sha256`, it finds the full Finding.
- `File`: `Location.File`.
- `Resource`: The Logical ID (Token), or `null`.
- `Normalized_Category`: The Category.
- `FindingType`: As in the Report.
- `Severity`: As in the Report.
- `Confidence`: As in the Report.
- `Source`: As in the Report.
- `TemplatePath`: The canonical `Location.TemplatePath` with keys replaced, or `null`.
- `Evidence`: `[{Source, RuleId}]`, sorted.

<!-- closed-set: EVIDENCE_KEYS -->
- `Source`: The Evidence Source.
- `RuleId`: The rule ID (plain or Token), or `null`.

<!-- closed-set: EVIDENCE_DELTA_KEYS -->
- `Source`: The Evidence Source.
- `RuleId`: The rule ID (plain or Token), or `null`.
- `source_comparable`: Whether that Source is Comparable for the file.

The Finding text, `WhyItMatters`, `Recommendation`, `SuggestedRemediation`,
Evidence `Detail` and `Excerpt` are never written.

### Matching

Findings are matched only within one Identity_Key `(Location.File, Resource,
Normalized_Category)`; a `null` Resource is a value of its own.

1. Stage 1: a dedup-eligible Identity_Key with exactly one Finding on each side is matched, whatever else differs.
2. Stage 2: a Base and a Head Finding are matched when their Fingerprints `(Identity_Key, FindingType, TemplatePath, (Source, RuleId) multiset)` are equal and that Fingerprint occurs once among the unmatched Findings of each side.

There is no further stage: no similarity, text or partial-field matching. A
Finding left over while the same Identity_Key has unmatched Findings on both
sides, or whose Fingerprint repeats on its side, is `unmatched` and
`Ambiguous`. Only a Finding with no candidate left on the other side is
`head_only` / `base_only`.

`Unchanged` means that this procedure matched the two Findings. It does not
mean that they share a root cause. Stage 1 pairs by a coarse key, so a Base
and a Head Finding with different causes can be matched, and their Evidence
difference then compares the Evidence of two different problems. Stage 2
pairs equal Fingerprints, so its Evidence difference is empty. An Evidence
difference is an observed difference: it is not classified and does not show
that a problem was resolved or introduced. A Base Finding merged from several
problems can lose one of them on the Head side and stay `Unchanged`, with the
loss visible only as an Evidence difference. Mis-pairing can hide a New or a
Resolved (under-reporting); it cannot create one.

### Classification

A `head_only` / `base_only` Finding is classified by the first rule that
applies:

1. `Ambiguous` with every reason that applies: a Source of the Finding is not Comparable for its file; the Finding has only `Agent Review` as Source; its Resource carries `possible_logical_id_rename`; a Report failed an internal-consistency check; `template_report_correspondence` is `inconsistent` or `unknown`. Declarations do not override this rule.
2. `Unconfirmed` with `input_declaration_absent` when a required declaration is missing. Every Unverified_Assumption is required; `reports_match_templates` only with a Template_Pair.
3. `New` (`head_only`) or `Resolved` (`base_only`).

A Source is Comparable for a file when, in both Reports, the file is in
`target.files` or `target.cdk.synthesized_templates`, the Source is in
`sources_enabled`, every tool it depends on is available with the same version
on both sides, and no `errors[]` entry is attributed to it or unattributed.
`cfn-lint` depends on the tool `cfn-lint`, `cfn-guard` on `cfn-guard`; the
Plugin's own Sources depend on no tool (their version is the
`same_plugin_version` declaration). For a synthesized file, both Reports must
record the same `target.cdk.synthesis`, and a `cdk` tool entry must match.

`Resolved` means: the matching procedure found no corresponding Head Finding,
the recorded conditions held, and the user declared every required
Input_Declaration. It means nothing more. In particular it is not evidence
that a problem was fixed.

### Closed sets of the Finding Delta

<!-- closed-set: DELTA_CLASSIFICATIONS -->
- `New`: A `head_only` Finding that meets every rule above.
- `Resolved`: A `base_only` Finding that meets every rule above.
- `Unchanged`: A matched pair.
- `Unconfirmed`: A one-sided Finding whose required declarations are missing.
- `Ambiguous`: Not uniquely matched, or a recorded condition does not hold.

<!-- closed-set: ENTRY_OBSERVATIONS -->
- `matched`: Paired by stage 1 or 2.
- `head_only`: Only on the Head side, with no candidate on the Base side.
- `base_only`: Only on the Base side, with no candidate on the Head side.
- `unmatched`: Not paired while candidates remain, or a repeated Fingerprint.

<!-- closed-set: CLASSIFICATION_COMPLETENESS -->
- `complete`: Every Delta_Entry is `New`, `Resolved` or `Unchanged`.
- `partial`: At least one Delta_Entry is `Unconfirmed` or `Ambiguous`.

<!-- closed-set: AMBIGUOUS_REASONS -->
- `identity_undetermined`: The Identity_Key has unmatched Findings on both sides.
- `duplicate_fingerprint`: The Fingerprint occurs more than once on the Finding's side.
- `source_not_comparable`: A Source of the Finding is not Comparable for its file.
- `tool_version_mismatch`: A tool the Source depends on has different versions.
- `template_not_reviewed`: The file is missing from a Report's `target`.
- `non_deterministic_source`: The only Source is `Agent Review`.
- `possible_logical_id_rename`: The Finding's Resource carries the rename hint.
- `report_integrity_failed`: A Report failed an internal-consistency check.
- `template_report_mismatch`: The correspondence is `inconsistent` or `unknown`.

<!-- closed-set: UNCONFIRMED_REASONS -->
- `input_declaration_absent`: A required Input_Declaration is missing.

<!-- closed-set: UNVERIFIED_ASSUMPTIONS -->
- `reports_unmodified`: Both Reports are the unmodified output of `run_iac_review.py`.
- `same_plugin_version`: Both Reports come from the same Plugin version, including its detectors.
- `same_rule_set`: The cfn-guard rule set (bundled `rules/` and `--rules-dir`) is the same.
- `same_tool_configuration`: The configuration of cfn-lint and the other tools is the same.
- `same_agent_findings_input`: `--agent-findings` was given the same way.
- `reports_match_templates`: The Reports were generated from the compared Templates (Template_Pair only).

The Input_Declaration Codes accepted by `--declare` are the same set. A
declaration is recorded as declared, not verified: it never turns an
Unverified_Assumption into a checked fact.

<!-- closed-set: INPUT_DECLARATION_STATUSES -->
- `declared_not_verified`: The fixed status of the recorded declarations.

<!-- closed-set: TEMPLATE_REPORT_CORRESPONDENCE -->
- `inconsistent`: A comparison path is not in its Report `target`, or a non-null Finding `Resource` on that path is not a Logical ID of that side's Template. The comparison path is the declared `--reviewed-template-path` on both sides, otherwise each Template's own workspace-relative path.
- `unknown`: A Template, or the Template comparison, is unanalyzable.
- `consistent_by_name_only`: Neither of the above. Not a proof that the Report was generated from the Template.
- `not_applicable`: No Template_Pair. There is no `verified` value.

<!-- closed-set: REPORT_INTEGRITY_CHECKS -->
- `rebuild_mismatch`: Rebuilding the Report with `report.build_report` gives different bytes (ID numbering, Finding order or summary).
- `dedup_invariant_violated`: A dedup-eligible Identity_Key occurs more than once.

These checks are not tamper detection.

<!-- closed-set: MATCH_STAGES -->
- `1`: Identity (dedup-eligible, one Finding on each side).
- `2`: Fingerprint (equal and unique on each side).

## Errors and exit codes

Each failure is one StructuredError (`error_class`, `source`, `tool`,
`exit_code`, `message`, `required_min_version`, `detected_version`,
`remediation`, `stderr_head`). `source`, `tool`, `exit_code`, the two version
keys are `null` and `stderr_head` is empty. `message` and `remediation` are
built from the side, the input kind, the failure Code, an integer line and
column, a schema-derived field path and a limit value only. They never contain
parser text or input content. Example: `head template: template_parse_failure
at line 7, column 1`.

<!-- closed-set: FAILURE_KEYS -->
- `side`: `base`, `head`, or `null` (the comparison or the output).
- `input`: `template`, `report` or `output`.
- `code`: A failure Code.
- `error_index`: Index of the StructuredError in `errors`.

<!-- closed-set: SIDES -->
- `base`: The Before side.
- `head`: The After side.

<!-- closed-set: FAILURE_INPUTS -->
- `template`: A Template or the Template comparison.
- `report`: A Review_Report.
- `output`: The serialized Delta_Report.

<!-- closed-set: FAILURE_CODES -->
- `invalid_arguments`: `invalid_arguments`, exit 2.
- `input_not_found`: `input_not_found`, exit 3.
- `path_violation`: `path_violation`, exit 7.
- `template_too_large`: `input_too_large`, exit 3.
- `report_too_large`: `input_too_large`, exit 3.
- `report_finding_limit_exceeded`: `input_too_large`, exit 3.
- `template_node_limit_exceeded`: `input_too_large`, exit 3.
- `template_depth_limit_exceeded`: `input_too_large`, exit 3.
- `change_entry_limit_exceeded`: `input_too_large`, exit 3.
- `output_size_limit_exceeded`: `input_too_large`, exit 3.
- `template_parse_failure`: `parse_failure`, exit 4.
- `template_encoding_failure`: `parse_failure`, exit 4.
- `template_alias_cycle`: `parse_failure`, exit 4.
- `template_not_reviewable`: `no_reviewable_template`, exit 8.
- `report_parse_failure`: `schema_violation`, exit 4.
- `report_duplicate_json_key`: `schema_violation`, exit 4.
- `report_schema_violation`: `schema_violation`, exit 4.
- `parser_divergence`: `unexpected`, exit 1.
- `unexpected`: `unexpected`, exit 1.

`template_parse_failure` includes the existing YAML alias reference limit.
`template_alias_cycle` is a YAML alias that makes the document refer to itself.
A symlink as the last path element that reaches the reader is
`input_not_found`.

Exit 0 when every requested comparison is `analyzed`, whatever was observed or
classified. Otherwise the exit code is that of the first failure in this
order: Base Template, Head Template, Template comparison, Base Report, Head
Report, output. The other comparison is still written in full.

An unexpected exception is reported on stderr by its type name only, with no
traceback, exits 1 and writes no Delta_Report.

### Limits

| Constant | Value | Failure Code |
| --- | --- | --- |
| `MAX_TEMPLATE_BYTES` | 5 MiB (5242880) | `template_too_large` |
| `MAX_REPORT_BYTES` | 5 MiB (5242880) | `report_too_large` |
| `MAX_REPORT_FINDINGS` | 10000 | `report_finding_limit_exceeded` |
| `MAX_TEMPLATE_DEPTH` | 64 | `template_depth_limit_exceeded` |
| `MAX_TEMPLATE_NODES` | 3000000 (logical nodes, alias shares counted per position) | `template_node_limit_exceeded` |
| `MAX_CHANGE_ENTRIES` | 200000 | `change_entry_limit_exceeded` |
| `MAX_OUTPUT_BYTES` | 128 MiB (134217728) | `output_size_limit_exceeded` |

Exceeding a limit makes the comparison `unanalyzable`; no partial result is
written. Over `MAX_OUTPUT_BYTES` the minimal Delta_Report is written instead:
`inputs` and every error, the `output_size_limit_exceeded` error, and each
requested comparison `unanalyzable` with no entry. These are input limits, not
performance guarantees.

## Summary

<!-- closed-set: SUMMARY_KEYS -->
- `semantic_diff`: Counts over the Semantic Diff (zero without one).
- `finding_delta`: Counts over the Finding Delta (zero without one).
- `errors`: Number of StructuredErrors.

<!-- closed-set: SUMMARY_SEMANTIC_DIFF_KEYS -->
- `changes`: Number of Change_Entries.
- `by_change_kind`: Per change kind.
- `by_qualifier`: Per Change_Qualifier (Change_Entries carrying it).
- `by_hint`: Per hint.
- `by_semantic_limitation`: 1 for each Semantic_Limitation present, else 0.
- `uncompared_paths`: Number of uncompared paths.
- `by_uncompared_reason`: Per uncompared reason.

<!-- closed-set: SUMMARY_FINDING_DELTA_KEYS -->
- `entries`: Number of Delta_Entries.
- `by_classification`: Per Delta_Classification.
- `by_observation`: Per Entry_Observation.
- `by_reason`: Per Ambiguous and Unconfirmed reason (Delta_Entries carrying it).
- `by_match_stage`: Per match stage (`1`, `2`).

Every value of every closed set is present, with 0 when absent.

## Order

Change_Entries are sorted by section, then path (integers before strings),
then change kind in the documented order, then the remaining fields.
Uncompared paths are sorted by path, then reason. Delta_Entries are sorted by
classification and observation in the documented order, then `File`,
`Resource` (`null` first), `Normalized_Category`, the Base and Head
Fingerprints, the Base and Head `ID`. Evidence lists are sorted by `Source`,
then `RuleId` (`null` first). All sorting uses the output values, so Tokens,
not the original identifiers, decide the order.

Matching does not depend on input order. The order guarantee of v1.1
Requirement 11 AC5 covers reorders that preserve internal consistency: the
Report keeps the order that `report.build_report` gives and passes every
check of Requirement 2 AC10 (for example, the order of the Findings before the
Report is built, or the order of `Evidence[]` where it does not change the
`findings[]` order). Such a reorder changes only the Report digest and the
per-side `ID` values. A reorder that breaks internal consistency, such as a
reorder of the raw `findings[]` of a built Report, falls under Requirement 2
AC10 and AC11 instead: it fails the `rebuild_mismatch` check, which is
recorded in `report_integrity`, and every one-sided entry becomes `Ambiguous`
with `report_integrity_failed`.

## Plain values and Identifier_Tokens

By default, every string taken from a Template or a Report is replaced by an
Identifier_Token unless it belongs to one of the closed sets below at that
position. Template scalar values, Finding free text and input error text are
never written in any mode.

Written in plain form:

- Path position 0: a top-level section name.
- Path position 2 below `Resources`, `Parameters`, `Outputs`, `Rules`: the attribute names listed below.
- Path position 2 and deeper: an Intrinsic Function name.
- List indexes (integers), when the Template of that side is analyzed and the walk places the integer inside a list (`0 <= index < length`). For a Finding `TemplatePath`, only when the Finding's `Location.File` is that side's comparison path (the `--reviewed-template-path` value, else that Template's workspace-relative path).
- A Resource Type matching `AWS::[A-Za-z0-9]+::[A-Za-z0-9]+` as a whole. A `Custom::` Type keeps the prefix and the name is replaced. Any other Type is replaced.
- `Normalized_Category` when it is in the Category set.
- `RuleId`: for Source `cfn-lint`, a value matching `[EWI][0-9]{4}`; for `cfn-guard`, the name of a bundled Guard rule; for `IAM Review`, an IAM detector name. Every other RuleId, including those of Network, Quality and Secret Review, is replaced.
- `tools[].name` in the plain tool set; `tools[].version` matching the v1.0 version pattern (digits, dots) as a whole.
- `FindingType`, `Severity`, `Confidence`, `Source`, error classes and the Delta_Tool's own closed sets.
- Workspace-relative file paths (Template, Report, `Location.File`, `target`, `reviewed_template_path.path`) and the Report digest.

Position 1 (a Logical ID or an entry name) is always replaced.

<!-- closed-set: TOP_LEVEL_SECTIONS -->
- `AWSTemplateFormatVersion`: Section.
- `Description`: Section.
- `Metadata`: Section.
- `Parameters`: Section.
- `Rules`: Section.
- `Mappings`: Section.
- `Conditions`: Section.
- `Transform`: Section.
- `Resources`: Section.
- `Outputs`: Section.

<!-- closed-set: RESOURCE_PLAIN_KEYS -->
- `Type`: Resource key.
- `Properties`: Resource key.
- `DependsOn`: Resource Attribute.
- `Condition`: Resource Attribute.
- `DeletionPolicy`: Resource Attribute.
- `UpdateReplacePolicy`: Resource Attribute.
- `UpdatePolicy`: Resource Attribute.
- `CreationPolicy`: Resource Attribute.
- `Metadata`: Resource Attribute.

<!-- closed-set: PARAMETER_ATTRIBUTES -->
- `AllowedPattern`: Parameter attribute.
- `AllowedValues`: Parameter attribute.
- `ConstraintDescription`: Parameter attribute.
- `Default`: Parameter attribute.
- `Description`: Parameter attribute.
- `MaxLength`: Parameter attribute.
- `MaxValue`: Parameter attribute.
- `MinLength`: Parameter attribute.
- `MinValue`: Parameter attribute.
- `NoEcho`: Parameter attribute.
- `Type`: Parameter attribute.

<!-- closed-set: OUTPUT_ATTRIBUTES -->
- `Condition`: Output attribute.
- `Description`: Output attribute.
- `Export`: Output attribute.
- `Value`: Output attribute.

<!-- closed-set: RULE_ATTRIBUTES -->
- `Assertions`: Rule attribute.
- `RuleCondition`: Rule attribute.

<!-- closed-set: INTRINSIC_NAMES -->
- `Condition`: Intrinsic.
- `Fn::And`: Intrinsic.
- `Fn::Base64`: Intrinsic.
- `Fn::Cidr`: Intrinsic.
- `Fn::Equals`: Intrinsic.
- `Fn::FindInMap`: Intrinsic.
- `Fn::GetAZs`: Intrinsic.
- `Fn::GetAtt`: Intrinsic.
- `Fn::If`: Intrinsic.
- `Fn::ImportValue`: Intrinsic.
- `Fn::Join`: Intrinsic.
- `Fn::Not`: Intrinsic.
- `Fn::Or`: Intrinsic.
- `Fn::Select`: Intrinsic.
- `Fn::Split`: Intrinsic.
- `Fn::Sub`: Intrinsic.
- `Fn::Transform`: Intrinsic.
- `Ref`: Intrinsic.

<!-- closed-set: PLAIN_TOOL_NAMES -->
- `cfn-lint`: Tool.
- `cfn-guard`: Tool.
- `cdk`: Tool.

Property names, Mapping keys and every other mapping key are replaced.

### Identifier_Token format

The strings replaced in one Delta_Report are sorted by Unicode code point and
numbered in one namespace: `id-000001`, `id-000002`, ... (at least six digits,
more when there are more strings). The same string gets the same Token
wherever it appears: Base and Head, Semantic Diff and Finding Delta, a
Change_Entry path and a Finding `TemplatePath` (when the Template of that
side is analyzed; see the limits below).

<!-- closed-set: IDENTIFIER_MODES -->
- `anonymized`: The default. Identifiers are Tokens.
- `plain`: `--plain-identifiers`. Path keys, Logical IDs, entry names, Finding `Resource` and Resource Types are written as they are. RuleIds, tool names and versions, Categories and error sources outside their closed sets stay Tokens.

With `plain`, an integer of a Finding `TemplatePath` that cannot be placed under a list is written as its decimal string.

### Limits of anonymization

- A Token is stable only within one Delta_Report. The same identifier gets a different Token in another Delta_Report.
- Equal Tokens reveal equal identifiers.
- Token numbers follow the code point order of the replaced strings, so they reveal that order.
- Structure is not hidden: sections, depth, list indexes, counts, `AWS::` Resource Types, Categories and change kinds are written.
- Workspace-relative paths of the Template and Report files and `Location.File` are written.
- The Report digest lets anyone holding the same file confirm that it was the input.
- A digit-only mapping key below the entry level is a list index in the canonical path form. In a Semantic Diff path the Templates are walked along the path, and the key is written as a Token of the original key. A Finding `TemplatePath` is walked the same way in the analyzed Template of its side (Base Finding in the Base Template, Head Finding in the Head Template), and only when the Finding's `Location.File` is that side's comparison path. An integer that the walk cannot place inside a list, including an index past the end of the list and a position absent from that Template, is written as a Token, and so is every integer of a Finding whose `Location.File` is another file.
- With a Report_Pair alone, or when the Template of that side is not analyzed, a Finding `TemplatePath` has no Template to walk. A list index cannot be told from a digit-only mapping key there (v1.0 records both as integers), so no integer is shown to be a list index: every integer of that `TemplatePath` is written as the Token of its decimal string (the string itself in plain mode), and a digit-only key is never written in plain form by default. List indexes are therefore not visible in that case.

### Keys never present

<!-- closed-set: FORBIDDEN_KEYS -->
- `improved`: Not asserted.
- `fixed`: Not asserted.
- `passed`: Not asserted.
- `passed_all_checks`: Not used as a signal.
- `safe`: Not asserted.
- `secure`: Not asserted.
- `resolved`: Evidence differences are not labelled.
- `unchanged`: Not a comparison-level status; `Unchanged` is a Delta_Classification only.
- `verified`: Nothing about the inputs is verified.

## Python API

The Core functions take parsed values and return structured results without
I/O. `semdiff.diff` returns a `SemanticDiffResult` and
`delta.match_and_classify` returns a `FindingDeltaResult`; both hold plain
identifiers for in-process callers and no Template value. Every output channel
goes through `deltareport.build_delta_report` / `deltareport.render_delta_report`,
which apply the rules above. Within `delta_schema_version` MAJOR 1, the schema,
the closed sets and these functions change only by addition.

stderr messages and help text are not stable interfaces.

## Known limitations

- The Semantic Diff compares the declared Templates only. Intrinsic functions, Conditions, Transforms, Macros, dynamic references, Parameter values and nested stacks are not evaluated.
- The only notation equivalences are YAML / JSON format, key order, whitespace, comments, quoting, anchors and aliases, and the short / long form of intrinsics. `Fn::GetAtt` in string and list form, list reordering and scalar type differences (`80` and `"80"`) are reported as changes. CDK-generated content is compared as ordinary content.
- Matching uses stages 1 and 2 only. A Finding that is not dedup-eligible becomes `Ambiguous` when its Fingerprint changes.
- Mis-pairing can make a Finding `Unchanged` that would otherwise be New or Resolved.
- Report authenticity and the correspondence between Reports and Templates are not verified. Declarations are not verification.
- The Report size limit is 5 MiB and the Finding limit is 10000.
- Large YAML Templates are dominated by parsing time. The cost of building the YAML document is not limited beyond the existing limits.
- The existing YAML alias reference limit does not bound the expanded size; the logical node limit does.
- The safety of the external tools that produced the input Reports (cfn-lint, cfn-guard, cdk) is not covered.
- Markdown output and Git ref inputs are not available.
- The v1.1 tests have been run locally on Python 3.9 only. Python 3.11 / 3.13 and the GitHub CI matrix are not verified yet.
- A JSON Template nested deeper than `MAX_TEMPLATE_DEPTH` always fails, but the failure Code depends on the Python version, because the existing JSON parser stops with `RecursionError` at a version-dependent depth. In a local measurement, Python 3.9 gave `template_depth_limit_exceeded` (exit 3) up to about 1,000 levels and `template_parse_failure` (exit 4) beyond; Python 3.13 gave `template_depth_limit_exceeded` up to about 10,000 levels and `template_parse_failure` beyond. The exact depth also depends on the call stack. Python 3.11 behaves like 3.9 in CI for the tested depth (2,000); Python 3.12 behaves like 3.13 in a local measurement (9,000 levels decode); other versions are not measured. Both results are fail-closed and deterministic on one Python version. Independently of v1.1, the v1.0 Review refuses JSON nested deeper than 512 levels as a parse failure on every Python version.
- A Template path, a Report path or a `--reviewed-template-path` value that is a symlink loop gives `invalid_arguments` (exit 2) on every Python version: the existing path check detects the loop itself where `Path.resolve` no longer does (Python 3.13). No file is read.
- With a Template_Pair and a Report_Pair in one run and no `--reviewed-template-path`, `New` and `Resolved` do not appear. Each Template path must be in its own Report's `target`, and Findings are matched and compared only on the same `Location.File`; two revisions read in one workspace sit at different paths, so one of these always fails and the one-sided entries are `Ambiguous`. Review both revisions at the same relative path in two checkouts and declare that path with `--reviewed-template-path`. The declaration is not verified: the tool cannot tell whether the Templates given are the ones the Reports reviewed, beyond the Logical ID check. A Report_Pair alone has no rename hint and no Template / Report check, so a renamed Logical ID can appear as `Resolved` plus `New`.
- Template / Report path correspondence is a string comparison of workspace-relative paths after `./`, `..` and symlinks are resolved. A Report recorded under a symlink name, a different letter case or a different Unicode normalization (NFC / NFD) gives `inconsistent` (or `unknown` when the file is then not found), and a path outside the workspace gives `unknown` with exit 7. None of these produces `New` or `Resolved`.
- The byte-identity of v1.1 Requirement 11 AC5 holds only for reorders that preserve internal consistency (the `report.build_report` order). A raw reorder of a built Report's `findings[]` fails `rebuild_mismatch` and makes the one-sided entries `Ambiguous` (see "Order").
- With a Report_Pair alone, for a side whose Template is unanalyzable, and for a Finding whose `Location.File` is not that side's comparison path, every integer of a Finding `TemplatePath` is written as a Token (its decimal string in plain mode), and list indexes are not shown. A digit-only mapping key such as an account ID is therefore not written in plain form by default.
- Display safety: the JSON output is data. File paths are written as given, except that C1 control characters (U+0080 to U+009F), the bidirectional controls U+202A to U+202E and U+2066 to U+2069, and U+200E, U+200F and U+061C are written as JSON `\uXXXX` escapes (lower-case hex). The value after `json.loads` is unchanged, so a program that decodes the JSON and prints a path can still show these characters: escape them again before showing decoded values to people. Other characters, including other invisible or confusable Unicode characters, are written as they are. stderr carries no input-derived string and replaces C0 / C1 control characters, DEL and the same bidirectional characters with `\u{XXXX}`. There is no Markdown output.
- `MAX_OUTPUT_BYTES` is checked while the output is serialized: the tool first compares a lower bound of the output size (from the number of Change_Entries and uncompared paths and their path lengths) with the limit and, when the bound already exceeds it, writes the minimal Delta_Report without rendering; otherwise it stops serializing as soon as the limit is passed. Memory and time still grow with the number of Change_Entries and uncompared paths up to that point. In a local measurement (macOS, Python 3.9, one machine; not a guarantee), the two inputs that had used about 2.3 and 2.9 GiB when the limit was checked only after full serialization ended in `output_size_limit_exceeded` with a maximum RSS of 250 and 521 MiB, and inputs built so that the lower bound stays just under the limit used about 0.7 to 0.75 GiB and 14 to 16 seconds. The result is fail-closed: no partial Delta_Report is written.
