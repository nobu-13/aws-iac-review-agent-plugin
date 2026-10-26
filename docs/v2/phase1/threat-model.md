# Phase 1 Threat Model

Scope: `iacreview/remediation/`, the Skill `iac-remediation-verify`, and the
reference gate `docs/v2/phase1/ci/remediation-gate.yml`. The verifier reads
untrusted repository content and must not let it decide its own acceptance.

## Assets

1. The decision: a candidate the contract does not allow must not be VERIFIED.
2. The approved contract, profiles, rules and validator code.
3. Confidentiality of the input: Template values, keys and file names may hold
   secrets; the host environment holds credentials.
4. The host: running the verifier must not run candidate code.

## Actors

| Actor | Can | Cannot (assumed) |
| --- | --- | --- |
| Remediation agent (Kiro or other) | edit the working tree, commit on a branch, write any file in the PR, write a fake report, add workflows | push to the protected branch, approve its own PR as code owner, change rulesets |
| PR author (untrusted fork or member) | same as the agent | same |
| Maintainer / code owner | approve contracts by merging them to the protected branch | — (trusted) |
| Repository admin | bypass rulesets | — out of scope: an admin who bypasses is not stopped by any of this |

If one identity holds the agent role and admin or code-owner rights, there is
no enforced boundary against it (work package section 4). The CLI cannot see
this; the gate evidence must name the actors used.

## Threats and controls

| # | Threat | Control | Test / evidence |
| --- | --- | --- | --- |
| T1 | Candidate widens the contract in its own PR | contract read from `--config-rev` only; config must be an ancestor of Base; the edited contract file is an out-of-scope change | C11, C24b, `test_remediation_contract.py` |
| T2 | Self-made approval (`approved_by`, digest list, approval file) | approval is not a field; unknown keys rejected; trust comes from the revision binding | `test_invalid_contracts_are_rejected_with_a_closed_reason[...approved_by...]`, C24a |
| T3 | Edit outside scope in the same file (IAM, env vars, Outputs, policies, attributes) | Template boundary over `semdiff` typed paths; exact str match; property-level operations | C05–C08, C10, `test_remediation_boundary.py` |
| T4 | Edit outside the file (scripts, workflows, rules, renames, modes, symlinks, submodules) | whole-tree `(mode, oid)` comparison | C09, C12, C13, C21a/b |
| T5 | Look-alike names, numeric keys, prefix/case tricks, parent replacement | typed paths recovered from both documents; parent changes are `parent_replaced` | `test_changes_outside_the_edits_are_blocked`, `test_a_numeric_string_key_is_not_a_list_index` |
| T6 | Fix that only makes the finding disappear (delete Resource, rename, empty Policies, SKIP) | outcome rules without rule-level `when`; empty Target fails; invariants on Base and Head; Core statement equality | C08, C15 family, C18, C19 |
| T7 | Forged PASS report / stale evidence | `verify` reads no report; `explain` validates shape and digest but states it proves nothing; `--check-binding` detects changed revisions, contract, profile or validator; the gate re-runs | C13, C14, C15c, `test_explain_rejects_edited_or_forged_reports` |
| T8 | Missing, wrong-version, hanging, crashing or chatty tools | exact version pins; `run_bounded` 60 s / 8 MiB; process group killed; every non-PASS state is UNVERIFIED | C16, C17, C18, `test_remediation_checks.py` |
| T9 | Code execution while reading the repository | git plumbing only, argv arrays, `-c` overrides for fsmonitor, hooks, external diff, pager, transports; worktree files read with `O_NOFOLLOW` | C21d marker test (commit and worktree mode), `test_snapshots_run_no_hook_...` |
| T10 | Revision text as an option or range (`--upload-pack=`, `a..b`) | regex before git; `--end-of-options`; ranges refused | `test_revision_text_is_validated_before_git_sees_it` |
| T11 | Parser abuse: duplicate keys, alias fan-out, deep nesting, huge files | v1.1 `deltaio.parse_template` (DAG, node/depth limits, duplicate marks); 5 MiB Template, 64 KiB contract, 4 MiB report | C22, `test_malformed_bytes_fail_closed` |
| T12 | Leak of values, keys, paths, bidi, tool output or tracebacks | report carries codes, digests, trusted names, `k:`/`p:` tokens only; no tool text; CLI catches every exception | C23, `test_untrusted_keys_and_paths_are_tokens...`, `test_an_internal_exception_fails_closed_without_detail` |
| T13 | Credentials reaching tools | `proc._minimal_env` allowlist; no AWS API anywhere | `test_run_bounded_does_not_pass_credentials` |
| T14 | Gate runs PR code with a token | `pull_request_target` from base; base and pinned validator checked out; head fetched as objects; `contents: read`; no `${{ }}` in `run:`; pinned action SHAs | `test_remediation_gate_workflow.py` (static); GitHub run: H-ENV |
| T15 | Check-name spoofing, skipped job, head swap, missing protection | required check + ruleset + CODEOWNERS + up-to-date branches; head SHA equality step | GitHub only: H-ENV tests G1–G8 (WAITING_HUMAN) |
| T16 | Moving Base hides other changes | Base must be an ancestor of Head; config an ancestor of Base | C15a, C15b |

## Residual risks (accepted for Phase 1, stated in the report)

* CPU and RSS of cfn-lint and cfn-guard are not limited (wall clock and output
  only). macOS has no enforceable RSS limit for children without a sandbox.
* cfn-lint / cfn-guard themselves read the Template; a parser bug in them is
  outside this boundary. The verifier passes them a projection or a temp copy,
  never a repository path.
* The worktree preview is a convenience: ignored files and submodule contents
  are not inspected, and a local user controls the verifier.
* A contract path chosen per PR selects among approved contracts; Phase 1's
  gate fixes the path in the workflow.
* Same-named checks from another workflow and admin bypass are prevented only
  by GitHub settings that this repository cannot set for a consumer.
* `semdiff` paths turn digit keys into ints; the verifier recovers the type by
  walking both documents and stops (`comparison_incomplete`,
  `path_type_ambiguous`) when the original key is not unique, so a guessed
  type never allows a change.
* A directory review that cannot read one candidate (a symlink cycle, a
  symlinked file) still exits 0 and lists it in `errors[]` (v1.0 behaviour);
  `summary.passed_all_checks` does not look at `errors[]`.
