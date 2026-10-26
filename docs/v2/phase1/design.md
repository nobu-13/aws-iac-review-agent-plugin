# Phase 1 Design — Bounded Remediation Verifier

Status: implemented on branch `feature/phase1-bounded-remediation` (not released, no version change).
Requirements: [requirements.md](requirements.md). AC mapping: [ac-traceability.json](ac-traceability.json).

## 1. Shape

```text
trusted config revision ──► Contract + Profile ─┐
                                                 ├─► verify ─► Remediation_Verification_Report (JSON)
Base commit ─┐                                   │            └► human Summary (explain)
             ├─ Git Snapshot Adapter (read-only) ┘
Head commit / worktree ┘
```

All code is new and lives in `iacreview/remediation/`. It reuses, without
changing their behaviour:

| Reused | For |
| --- | --- |
| `deltaio.parse_template` | the bounded YAML/JSON parser, duplicate-key marks, alias DAG and node/depth limits |
| `semdiff.diff` | the typed-path structural comparison (string keys vs list indexes kept apart) |
| `cfnlint.build_argv`, `cfnlint.parse_output`, `cfnlint.decode_cfnlint_exit` | the fixed cfn-lint invocation and strict output parser |
| `toolcheck.extract_version` | version text parsing |
| `pathguard.secure_temp_file`, `pathguard.install_temp_file_cleanup` | 0600 temporary files removed on exit and on signal |
| `proc` (`_validate_argv`, `_minimal_env`, process-group termination) | through one additive function `proc.run_bounded` (§6) |

The only edits to existing modules are `proc.run_bounded` (additive) and the
OBS-1 fix in `cdk._is_contained` (separate commit).

Profile Guard rules live in `iacreview/remediation/profiles/`, not in `rules/`:
`rules/` is the default rule set of `cfn-guard-review` and `iac-review`, and a
profile rule there would change every existing review and the 34-case Benchmark.

## 2. Contract

Strict YAML (`contract.py`): one document, no anchors/aliases, no explicit tags,
no duplicate keys, no unknown keys at any level, ≤ 64 KiB, string values only
where strings are expected. Grammar:

```yaml
contract_schema_version: "0.1.0"
contract_id: <id>            # ^[a-z0-9][a-z0-9-]{0,63}$
profile_id: <profile id>     # must be a shipped profile
profile_version: "1"         # must equal the shipped profile's version
task_id: <id>
target:
  template_path: <repo-relative POSIX path>   # no "..", no leading "/", no "\", no NUL/control chars
scope:
  allowed_edits:             # non-empty, finite
    - resource: <Logical ID> # ^[A-Za-z0-9]{1,255}$ (the CloudFormation Logical ID charset)
      property: <name>       # ^[A-Za-z0-9]{1,255}$, must be one the profile allows
      operations: [add|replace|remove, ...]   # non-empty, no duplicates, subset of the profile's
intent:
  required_outcomes: [<outcome id>, ...]       # non-empty subset of the profile's
  preserve_invariants: [<invariant id>, ...]   # must contain every mandatory invariant of the profile
  parameters: {<name>: <value>}                # exactly the profile's declared parameters
verification:
  required_checks: [cfn-lint, profile-guard]   # must contain every mandatory check of the profile
```

Phase 1 limits: all `allowed_edits` name the same Logical ID, at most one entry
per property, and wildcards do not exist in the grammar (a `*` fails the regex).

Approval is not a field. `init` writes a draft; a contract is *approved* when it
is read from a git revision (`--config-rev`) that the Runner binds to the Base.
`approved_by` or any other self-description is an unknown key and is rejected.

## 3. Trust binding (§5.3 of the work package)

`verify` takes `--repo`, `--base`, `--head` (or `--worktree`), `--config-rev`
and `--contract` (a path inside the config revision). Before anything is
compared:

1. every revision is resolved with `git rev-parse --verify --end-of-options <rev>^{commit}`;
2. `config_commit` must be an ancestor of, or equal to, `base_commit`
   (`git merge-base --is-ancestor`), otherwise `UNVERIFIED config_not_ancestor_of_base`.
   This excludes a contract that only the candidate carries, including
   `--config-rev <head>`;
3. `base_commit` must be an ancestor of `head_commit`, otherwise
   `UNVERIFIED base_not_ancestor_of_head`. With that, `base..head` is exactly the
   candidate's own change, and when the protected branch moves the result is
   stale until the candidate is updated and verified again;
4. the contract bytes are read from the config tree, never from Head or the
   working tree. Their SHA-256, the profile digest, every rule digest and the
   validator digest go into the report.

`--contract-file <path>` (a draft on disk) is accepted for preview only: the
result can never be `VERIFIED` or `BLOCKED`; it is `UNVERIFIED contract_not_approved`,
and the would-be findings are listed under `preview`.

## 4. Snapshot Adapter (`gitsnap.py`)

Git is run through `proc.run_bounded` with an argv array, the minimal
environment, no shell and these global options on every call:

```text
git --no-pager --no-optional-locks --literal-pathspecs -C <repo>
    -c core.fsmonitor=false -c core.hooksPath=/dev/null -c protocol.allow=never
    -c core.untrackedCache=false -c diff.external= -c core.pager=cat
```

Only plumbing is used: `rev-parse`, `merge-base --is-ancestor`, `ls-tree -r -z
--full-tree`, `cat-file -s` / `cat-file blob` (no `--filters`, no `--textconv`),
and for worktree preview `ls-files -z -s` and `ls-files -z -o --exclude-standard`.
None of them runs hooks, clean/smudge filters, textconv or external diff, and
`protocol.allow=never` stops a partial clone from fetching. The marker test
(case C21d) configures every one of those to touch a marker file and asserts the
marker never appears.

A snapshot is the map `path → (mode, object id)` of the whole tree. The worktree
preview builds the same map from the index entries and untracked, non-ignored
files, hashing each file's raw bytes as a git blob in Python (files read with
`O_NOFOLLOW`, symlinks hashed by their link text, gitlinks taken from the
index). Ignored files are not inspected and the report says so. Raw bytes are
compared without eol conversion or filters, which can only add differences
(fail closed). The worktree snapshot is hashed again after the checks; a
different hash is `UNVERIFIED snapshot_changed`.

Limits: 200,000 tree entries, 64 MiB of listing output, the target Template
≤ `template.MAX_TEMPLATE_BYTES` (5 MiB, the v1.0 limit), each git call 60 s.

## 5. Boundary (`boundary.py`)

Repository level, on the two snapshots: every path other than
`target.template_path` must have the same `(mode, oid)` on both sides; else
`file_added_outside_scope` / `file_removed_outside_scope` /
`file_modified_outside_scope` / `file_mode_changed`. Renames are a removal plus
an addition. Symlinks (120000) and gitlinks (160000) are compared the same way.
The target must be a regular file (100644) on both sides with the same mode:
`target_template_removed`, `target_not_regular_file`, `file_mode_changed`.

Template level, on `semdiff.diff(base, head)`: a Change_Entry is allowed only if

* section is `Resources`, `path[1]` is the contract's Logical ID (exact `str`),
  the Resource `Type` is unchanged and equal on both sides,
* `path[2] == "Properties"` and `path[3]` is an allowed property (exact `str`,
  length ≥ 4, so a change at `Properties` itself or at the Resource is a
  `parent_replaced`),
* the property-level operation is allowed: absent→present `add`,
  present→absent `remove`, present on both `replace` (changes below a property
  are the property's `replace`).

Everything else is `template_change_outside_scope`, with
`resource_added` / `resource_removed` / `resource_type_changed` for whole
Resources. Typed paths come from `semdiff`; display strings are never parsed back.

Incomplete or unsupported comparisons are `UNVERIFIED`: any `uncompared_paths`
(`comparison_incomplete`), a parse/structure failure (`template_not_comparable`),
`transform_not_expanded`, and on an *allowed* change a `conditional` /
`dynamic_reference_unresolved` / `external_value` / `pre_transform` qualifier
or an `Fn::If` anywhere in the allowed property on either side
(`unsupported_construct`). `expression_unevaluated` alone (an `Fn::Sub` or
`Fn::GetAtt` in the changed subtree) is not unsupported: the outcome rules and
the statement comparison read the declared structure, and a rule that needs a
literal fails on an expression. A contract whose Resource is missing in Base or
has another Type is `UNVERIFIED target_resource_missing` (a nested-stack target
lands here).

`semdiff` normalizes paths with `finding.canonical_template_path`, which turns
a digit mapping key (`"0"`) into an int. The boundary recovers the typing by
walking both documents (`boundary.typed_path`): mapping positions become
`str`, list positions `int`. Only exact `str` equality with the contract's
names allows a change, so an int can never widen the scope.

## 6. Checks (`checks.py`)

| Check | Run on | PASS only if |
| --- | --- | --- |
| `cfn-lint` | Head | cfn-lint == profile pin; exit decodes as OK; output parses; no `Error` result |
| `profile-guard` | Base and Head, one projection each | cfn-guard == profile pin; exit 0 or 19; records parse; every required rule is in `compliant` and in neither `not_compliant` nor `not_applicable` |

The Guard input is a projection built from the parsed Template by Python:
`{"Target": <the contract's Resource or absent>, "Params": <contract parameters>}`,
written to a 0600 temporary JSON file. Rules have no rule-level `when`, so an
absent target is a FAIL, not a SKIP.

`required-statement-preserved` (SC-02) is Guard (statement with the Sid exists
and allows) **and** a Core comparison that the statement's parsed value is equal
on Base and Head. `outside-allowed-edits-unchanged` is the Boundary of §5.

cfn-guard output is read by `checks.parse_guard_record`, not by
`cfnguard.parse_records`: the v1.0 parser extracts every violated clause for
Findings and rejects shapes the profile rules produce (`Block` from `some`,
`InResolved`, an unresolved query at the root). The verifier needs only which
named rules passed, failed or were skipped, so it reads the record envelope
strictly (exactly the cfn-guard 3.2 keys, rule names of a fixed shape, status
consistent with the lists, nothing below `Rule.name`); anything else is
`OUTPUT_INVALID`. The Target is always present in the projection (`{}` when
absent) so a missing Resource is a FAIL below `/Target`.

Output digests: cfn-guard's raw output with the temp-file name replaced;
cfn-lint's parsed results without the per-file result `Id`.

Every tool call goes through `proc.run_bounded(argv, timeout_s=60, max_output_bytes=8 MiB)`:
stdout/stderr are read incrementally, the process group is killed on timeout or
on the cap, and the result carries `timed_out` / `output_exceeded`. Tool output
is never copied into the report: only exit codes, counts, rule names from the
profile, cfn-lint rule IDs matching `^[EWI][0-9]{4}$`, and SHA-256 digests.
CPU and RSS are not limited (documented residual risk).
`IACREVIEW_REMEDIATION_CHECK_TIMEOUT_S` may lower (never raise) the 60 s
timeout; a lower value can only produce `TIMEOUT` (UNVERIFIED).

Tool states: `PASS`, `FAIL`, `TOOL_UNAVAILABLE`, `VERSION_MISMATCH`, `TIMEOUT`,
`FAILED`, `OUTPUT_INVALID`, `OUTPUT_TOO_LARGE`, `NOT_PASSED` (SKIP / not
applicable / empty), `NOT_RUN`. Only `PASS` counts. There is no N/A pass.

## 7. Decision (`decide.py`)

```text
ERROR      contract_invalid, profile_unknown, invalid_arguments, revision_not_found, internal_error
BLOCKED    any Boundary violation; outcome FAIL on Head; invariant PASS→FAIL; cfn-lint FAIL
UNVERIFIED trust not established; comparison incomplete/unsupported; any tool state other than PASS/FAIL;
           invariant FAIL on Base; outcome not evaluated on Base; snapshot changed
VERIFIED   none of the above
```

Representative value: `ERROR > BLOCKED > UNVERIFIED > VERIFIED`; every
diagnostic is kept. Trust is established first: binding failures stop before
Boundary and checks; a draft contract caps the decision at `UNVERIFIED`.

`task_outcome`: `resolved` (Base FAIL, Head PASS for every required outcome),
`already_satisfied` (Base PASS and Head PASS; not counted as a fix),
`not_resolved` (any Head FAIL), `not_evaluated` (otherwise).
`runtime_validated` is always `false`.

Exit codes of `verify`: `VERIFIED` 0, `BLOCKED` 20, `UNVERIFIED` 21, `ERROR` 22.
`iacreview/exitcodes.py` is not touched. `init` and `explain` exit 0 on success
(not a verdict) and 22 on invalid input; `explain --check-binding` exits 21 when
the report does not match the current revisions, contract, profile or validator.

## 8. Report (`report.py`)

`Remediation_Verification_Report`, a new schema (see
[verification-report-schema.md](verification-report-schema.md)):

```json
{"report_kind": "remediation_verification", "report_schema_version": "0.1.0",
 "payload": {...deterministic...}, "metadata": {"generated_at", "run_id", "duration_ms", "payload_sha256"}}
```

The payload is serialized with sorted keys, `ensure_ascii`, fixed separators,
so the same inputs, contract, profile, validator and tool versions give
byte-identical payloads; metadata is excluded. No Template value, tool output,
traceback or untrusted key is written: keys that are not named by the trusted
contract or a closed vocabulary (section names, resource attribute names) are
written as `k:<12 hex of SHA-256>`, repository paths other than the target as
`p:<12 hex>`. Only one disclosure mode exists in Phase 1 (redacted).

`execution_mode` is `local_preview` unless `--execution-mode trusted_ci` is given
by the gate workflow; the flag records how it was run and proves nothing by
itself. `enforcement_status` is always `not_verified` in the CLI output: Merge
enforcement is shown by GitHub evidence (handoff.md), not by the verifier.

`explain` validates the report shape, prints the human Summary (decision,
outcome, violations, missing evidence, next action) and never re-decides.

## 9. Kiro Skill

The Skill ships no script: a script under `skills/*/scripts/` would join the
v1.0 script inventory, whose tests require the Review_Report CLI options. It
calls the package CLI with `PYTHONPATH=<plugin_root>`, as the v1.1 Delta_Tool
does.


`skills/iac-remediation-verify/` is one thin Skill: it tells the agent to run
`init` (draft), stop for human approval of the contract, make one candidate
edit inside the scope, run `verify --worktree` (preview) and `explain`, then stop.
It may not edit the contract, profiles, rules, validator or CI files, and it
never treats its own preview as approval. The five existing Skills are unchanged.

## 10. CI reference

* `.github/workflows/ci.yml` keeps the six-environment matrix; Phase 1 tests run
  inside the existing pytest job.
* `docs/v2/phase1/ci/remediation-gate.yml` is the consumer Trusted Gate
  reference: `pull_request_target`, `permissions: contents: read`, checks out
  the **base** commit only, checks out the validator at a pinned commit into a
  separate directory, fetches the PR head as git objects only (no checkout),
  runs no PR code, passes SHAs (not branch names or titles) as argv, and runs
  the verifier with the contract from the base revision. Required check +
  ruleset/CODEOWNERS settings are listed in [handoff.md](handoff.md).
* A gate on this repository's own PRs would run the validator under
  development; it is not claimed as an independent gate.
