# Remediation_Verification_Report 0.1.0

A new schema, separate from Review_Report 1.0.0 and Delta_Report. Produced by
`python3 -m iacreview.remediation verify`; read by `explain`. Defined in code by
`iacreview/remediation/report.py` (`REPORT_KEYS`, `PAYLOAD_KEYS`,
`METADATA_KEYS`) and `iacreview/remediation/rschema.py` (closed vocabularies).

```json
{
  "report_kind": "remediation_verification",
  "report_schema_version": "0.1.0",
  "payload": { "...": "deterministic" },
  "metadata": {"generated_at": "...Z", "run_id": "...", "duration_ms": 0, "payload_sha256": "<hex>"}
}
```

`metadata.payload_sha256` is the SHA-256 of the payload serialized with sorted
keys, ASCII escapes and `(",", ":")` separators. It detects edits; it does not
authenticate the report. Only a required check re-run by the trusted gate is
evidence.

## payload

| Key | Type | Meaning |
| --- | --- | --- |
| `decision` | `VERIFIED` \| `BLOCKED` \| `UNVERIFIED` \| `ERROR` | representative value, `ERROR > BLOCKED > UNVERIFIED > VERIFIED` |
| `exit_code` | 0 \| 20 \| 21 \| 22 | the `verify` exit code for `decision` |
| `task_outcome` | `resolved` \| `already_satisfied` \| `not_resolved` \| `not_evaluated` | from the required outcomes on Base and Head; `already_satisfied` is not a fix |
| `next_action` | `human_review` \| `revise_candidate` \| `supply_missing_evidence` \| `fix_invocation_or_contract` | per decision |
| `execution_mode` | `local_preview` \| `trusted_ci` | how it was run, as given; proves nothing alone |
| `enforcement_status` | `not_verified` | always: merge enforcement is shown on GitHub, not by the verifier |
| `runtime_validated` | `false` | always |
| `preview_only` | bool | true when the contract came from `--contract-file` |
| `stage_reached` | `start` \| `contract_loaded` \| `trust_established` \| `boundary_checked` \| `checks_run` | how far the pipeline got |
| `subject` | object | `repository_id`; `base` and `head` (`kind`, `commit`, `tree`, `snapshot_sha256`); `target_template` (`path`, blob ids, SHA-256 of both sides, Head format) |
| `trust` | object | `contract_source`, `approved`, `approval_binding`, `trusted_config_commit`, `contract_path`, `contract_sha256`, `contract_id`, `task_id`, `profile_id`, `profile_version`, `profile_sha256`, `rules` (file, SHA-256), `allowed_edits` |
| `validator` | object | `name`, `plugin_version`, `source_sha256` (digest of `iacreview/**` code and profiles), `python` |
| `tools` | list | `name`, `required_version`, `observed_version`, `state` |
| `violations` | list | entries whose code forces BLOCKED |
| `diagnostics` | list | every other entry (UNVERIFIED / ERROR codes) |
| `outcomes` | list | `outcome_id`, `base`, `head` state |
| `invariants` | list | `invariant_id`, `base`, `head` state |
| `checks` | list | `check_id`, `side`, `state`, `exit_code`, `input_sha256`, `output_sha256`, `counts`, `rule_ids`, `rule_states` |
| `not_verified` | list | `runtime_behavior`, `effective_iam_permissions`, `resource_replacement`, `deployment`, `merge_enforcement` |
| `snapshot_notes` | list | e.g. `ignored_files_not_inspected`, `worktree_parent:<sha>` |

Violation / diagnostic entry: `{"code", "scope", "path", "detail", "forces"}`.
`code` is a key of `rschema.CODES`; `scope` one of `repository`, `template`,
`trust`, `check`, `outcome`, `invariant`, `contract`, `git`, `snapshot`,
`verification`, `validator`; `detail` a closed word or `null`.

## Disclosure

One mode (redacted). In `path`:

* list indexes are integers;
* section names, Resource attribute names and the names in the contract
  (its Logical ID and properties) are written as they are;
* every other mapping key is `k:` + the first 12 hex digits of its SHA-256;
* repository paths other than the target are `p:` + 12 hex digits.

No Template value, tool message, tool output, traceback, absolute host path or
contract text appears. Tool output is represented by `output_sha256` (cfn-guard:
raw output with the temp-file name replaced; cfn-lint: the parsed results
without the per-run result Id).

## Compatibility

Review_Report (`SCHEMA_VERSION = "1.0.0"`, 7 keys), the 13 Finding fields,
StructuredError, Delta_Report and `iacreview/exitcodes.py` are unchanged.
