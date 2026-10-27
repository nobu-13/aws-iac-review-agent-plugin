# Option A — the required check published by a dedicated GitHub App

Status: **adopted as an optional reference implementation; not deployed**.
Follows [gate-check-provenance.md](gate-check-provenance.md) Option A.

Decisions (Human, after the spike review):

1. Option A is an **optional reference implementation** of the CI gate.
2. The App is not required for Local or Kiro use, and it is not a product
   dependency. The verifier (`iacreview/remediation/`) and the Skills are
   unchanged and run without it.
3. H-ENV keeps its pins: `pinned_commit` `a24fb3f`, validator `5412a73`.
4. The H-ENV helper's trust boundary is not relaxed to accept later commits.
   H-ENV runs are made from `a24fb3f`; the helper's `check-targets` refuses
   any other branch head, by design.

Nothing on GitHub has been created or changed: no App, key, installation,
environment, secret, variable, event policy, workflow or ruleset. Section 7
lists the Human steps in order, with a rollback for each.

| File | Role |
| --- | --- |
| `docs/v2/phase1/ci/spike/remediation-gate-app.yml` | base-branch workflow: `verify` job, separate `publish` job |
| `docs/v2/phase1/ci/spike/gate_outputs.py` | verify job: derives its outputs from the report and cross-checks them |
| `docs/v2/phase1/ci/spike/publish_check.py` | publish job: checks the run context, decides the conclusion, creates and confirms the check run |
| `tests/unit/test_spike_app_publisher.py`, `tests/unit/test_spike_gate_outputs.py` | fake Checks API, local HTTP servers for redirects, real verifier reports (C01, C05) |
| `.agents/tasks/phase1/henv/phase1_henv_owner.py` `classify_app_check()` | evidence rule for the App check (local helper) |

Both scripts use the standard library only. All tests are offline; none of
this was observed on GitHub.

## 1. Architecture

```text
pull_request_target (workflow file and GITHUB_SHA from the default branch)
 ├─ job verify    GITHUB_TOKEN contents: read, no secrets, no environment
 │    base commit as subject; PR head fetched as git objects only
 │    validator @ VALIDATOR_COMMIT (5412a73) → report
 │    gate_outputs.py @ GATE_SCRIPTS_COMMIT → outputs from the report:
 │      exit_code, decision, head_sha, payload_sha256 (empty if inconsistent)
 │    report uploaded as artifact "remediation-report"
 └─ job publish   needs: verify, if: always(), environment remediation-publisher
      permissions: {} (GITHUB_TOKEN has no scopes)
      publish_check.py @ GATE_SCRIPTS_COMMIT (sparse checkout, nothing else)
      create-github-app-token (pinned SHA): this repository, checks: write
      publish_check.py:
        refuse unless the run is the base gate            → exit 2, nothing posted
        target = event payload pull_request.head.sha
        conclusion = success only for a consistent VERIFIED run, else failure
        POST /repos/{repo}/check-runs  (no redirects)
        confirm the response: same name, head, conclusion, external_id,
          status completed, app.id = REMEDIATION_APP_ID   → else exit 4
Ruleset: required check remediation-gate/verified, expected source = the App
```

Separation of duties:

* The validator (`verify`) decides. It never sees the App key or a token
  other than its read-only `GITHUB_TOKEN`. It is the only job that touches
  untrusted bytes, and it runs only pinned code.
* The publisher (`publish`) reports. It touches no PR bytes and runs one
  pinned script. It cannot turn a failure into success; it can only
  confirm a consistent VERIFIED run or publish `failure`.

Two pins, both set by the Human at deployment:

* `VALIDATOR_COMMIT` = `5412a73` (the verifier of the H-ENV runs).
* `GATE_SCRIPTS_COMMIT` = the approved commit that holds
  `docs/v2/phase1/ci/spike/`. The checked-in value is all zeros, so an
  unpinned copy fails at checkout and never publishes.

## 2. What the publisher trusts

| Input | Source | Treatment |
| --- | --- | --- |
| `GITHUB_EVENT_NAME`, `GITHUB_REF`, `GITHUB_WORKFLOW_REF`, `GITHUB_REPOSITORY`, `RUNNER_ENVIRONMENT`, run id / attempt | set by the runner; a workflow cannot overwrite `GITHUB_*` / `RUNNER_*` | must be `pull_request_target`, `refs/heads/<default>`, `<repo>/.github/workflows/remediation-gate.yml@refs/heads/<default>`, `github-hosted`; otherwise nothing is posted (exit 2) |
| Event payload (`GITHUB_EVENT_PATH`) | written by the runner | action `opened` / `synchronize` / `reopened`; `repository.full_name` and `pull_request.base.repo.full_name` = this repository; `pull_request.base.ref` = default branch; size ≤ 25 MiB; otherwise exit 2 |
| Target SHA | event payload `pull_request.head.sha` only | 40 lowercase hex; never taken from a job output or a workflow `env` value |
| `needs.verify.result` | GitHub | closed set; must be `success` with exit 0, `failure` with 20 / 21 / 22 |
| `needs.verify.outputs.*` | `gate_outputs.py`, from the report | evidence, not instruction: `success` needs exit 0, decision `VERIFIED`, verified head = event head, 64-hex digest; anything else is `failure` |
| `REMEDIATION_APP_ID` | repository variable | must equal the `app.id` of the created check run |
| GitHub's response | API | status 201, ≤ 1 MiB JSON, echoes the request, created by the App; otherwise exit 4 |

All patterns use `fullmatch`. The tests found that `re.match` with `^…$`
accepts a trailing newline (`"<digest>\n"` was published as `success`); the
spike scripts and `classify_app_check()` were fixed and regression tests
added.

`gate_outputs.py` takes the head, decision and exit code **from the report**,
recomputes the payload digest, and requires `trusted_ci`, a git-revision
contract, and (for VERIFIED) head, base, trusted config commit and contract
path equal to the event's. Any disagreement writes empty outputs and fails
the job; the publisher then posts `failure`. It does not import `iacreview`.

Failure behaviour:

| Situation | Publisher | Required check | Merge |
| --- | --- | --- | --- |
| VERIFIED, consistent | `success`, exit 0 | success | needs review as well |
| BLOCKED / UNVERIFIED / ERROR | `failure`, exit 0 | failure | blocked |
| verify cancelled / skipped / outputs missing or inconsistent | `failure`, exit 0 | failure | blocked |
| not the base gate (other event, workflow, ref, runner) | nothing, exit 2 | missing | blocked |
| config invalid (token, app id, URL, name) | nothing, exit 2 | missing | blocked |
| API error, timeout, redirect, non-201 | exit 3 | missing | blocked |
| response not confirming the request | exit 4, job fails | a check may exist; it can be an App `success` only if the publisher asked for one (a consistent VERIFIED run) | as for that check; the failed job is the signal to investigate |

## 3. Threat model

Defended, given section 3.2:

| Attack | Result |
| --- | --- |
| PR adds a workflow with a job named `verify` / `remediation-gate/verified` (G3, G6) | its check comes from GitHub Actions (15368), not the App; it does not satisfy the rule |
| PR workflow references `environment: remediation-publisher` | the branch policy is evaluated against `refs/pull/<n>/merge`; no secret |
| PR edits the gate workflow (G10) | `pull_request_target` runs the default-branch copy |
| Old success reused after a push (G7) | the check is bound to the event head; the new head has no App check until its own run |
| `workflow_dispatch` / `push` / another workflow on `main` reaching the key | the publisher refuses: event and workflow ref are checked (exit 2); the event policy in section 7 allows only `pull_request_target` for the gate file |
| Verify outputs claiming another head, a forged digest, or a decision that contradicts the exit code | `failure` |
| Token sent elsewhere by a redirect | redirects refused (a plain urllib opener forwards `Authorization` on 302; shown by a control test) |
| Re-run of an old attempt | a new check on that old head only; `external_id` records the attempt |

### 3.1 Not defended

1. Repository owner and admins: they can change `main`, the environment, the
   secret, the event policy, the App and the ruleset. A workflow on `main`
   can exfiltrate the key. A protects against PR authors, not administrators.
2. App key compromise: anyone with the key can post `success` on any head.
   Mitigation only: no local copy, one-repository installation, `checks`
   write in the token, rotation, revocation (section 8).
3. Validator compromise: a bug or parser exploit (cfn-lint, cfn-guard, YAML)
   inside `verify` can write a self-consistent forged report and outputs. A
   proves where the check came from, not that the decision is correct. The
   report artifact and `external_id` digest let a reviewer re-run the
   verifier and compare.
4. Collaborators who can land reviewed changes on `main`: the environment
   trusts the default branch. Code-owner review of `.github/` stays necessary.
5. Availability: without the event policy (section 7, step H7) the gate stops
   running on 2026-12-02 and every PR stays blocked (fail closed).
6. Dependabot-triggered runs: whether they receive environment secrets was
   not verified. If not, the check is missing and the PR is blocked.
7. GitHub (Actions, Checks, rulesets, environments) is trusted.

### 3.2 Assumptions

Default-branch-only deployment policy with admin bypass disabled; the key
only as the environment secret; the App installed on this repository only;
`CODEOWNERS` covering `.github/`; ruleset without bypass actors; both pins
set; the event policy in place.

## 4. G1–G10 with A (owner account only)

| ID | Check provenance | Merge part |
| --- | --- | --- |
| G1 | provable: App `success`, `external_id` names the run and digest; `classify_app_check()` | NOT_PROVEN: owner cannot approve own PR |
| G2, G4, G5 | provable: App `failure` from the base gate | NOT_PROVEN: review also missing |
| G3, G6 | provable: the spoof `verify` is not the required check; the only App check is `failure` | NOT_PROVEN |
| G10 | provable as G2; a PR workflow requesting the environment being refused is a further scenario (not written) | NOT_PROVEN |
| G7 | provable: new head `failure`, old head's `success` stays on the old SHA | NOT_PROVEN |
| G8 | NOT_PROVEN: needs a merge | — |
| G9 | NOT_PROVEN: needs a ruleset change | — |

"Provable" means the rule is implemented and tested offline. AC27's check
part becomes provable; AC28 and G-P1-4's merge part stay NOT VERIFIED without
a second account. `classify_app_check()` treats two App checks on one head
(for example after a re-run) as FAILED; that is conservative and may need a
"latest attempt" rule after the first real run.

## 5. App permissions

| Item | Value |
| --- | --- |
| Repository permissions | Checks: Read and write; **Commit statuses: Read and write**; Metadata: Read (mandatory) |
| Why Commit statuses | GitHub's ruleset documentation: an expected-source app "must be installed in the repository with the statuses:write permission, must have recently submitted a check run, and must be associated with a pre-existing required status check in the ruleset". The publisher never writes a commit status |
| Token | the workflow requests `permission-checks: write` only, so the minted token lacks `statuses`. Repository-scoped by default (no `owner` / `repositories`), ≤ 1 h, revoked at job end |
| Not requested | Contents, Pull requests, Actions, Administration, organization or account permissions |
| Webhook | inactive |
| Installable by | only this account; installed on `iac-remediation-gate-demo` only |
| Private key | environment secret `REMEDIATION_APP_PRIVATE_KEY` of `remediation-publisher`; the downloaded `.pem` is deleted after upload |
| Client ID, App ID | repository variables `REMEDIATION_APP_CLIENT_ID`, `REMEDIATION_APP_ID` (not secrets) |

Not verified: whether the ruleset UI or API accepts an App without
`statuses:write` (the documentation says it must have it; we follow it).

## 6. `pull_request_target` and the 2026-12-02 enforcement

* GitHub's default event policy blocks `pull_request_target` in public
  repositories without an applicable event policy. It runs in evaluate mode
  now and is enforced on **2026-12-02** (date moved from 2026-11-02; the
  changelog's editor's note of 2026-10-21 and the current "About Actions
  policies" and "Securely using pull_request_target" pages agree).
* It applies to the existing gate as well. Without an explicit policy the
  current `remediation-gate.yml` stops running on that date, the required
  `verify` check never appears, and every PR on the demo stays blocked
  (fail closed). This is independent of Option A.
* Repository-level Actions policies are available for public repositories
  (Settings → Actions → Policies). Evaluate mode for user-defined policies
  is GitHub Enterprise Cloud only, so on the demo the policy is active as
  soon as it is saved.
* Recommended policy: target only `.github/workflows/remediation-gate.yml`,
  allow only `pull_request_target`. Besides keeping the gate running, it
  stops a later `workflow_dispatch` or `push` trigger on that file from
  starting it.
* The gate never checks out the PR head with `actions/checkout`
  (`allow-unsafe-pr-checkout` is not used). It fetches the head as git
  objects and never executes it; GitHub notes that `git fetch` is outside the
  checkout protection, so this remains a reviewed property of the workflow.
* Not verified: whether a workflow-targeted policy is "applicable" for every
  other `pull_request_target` workflow in the repository (the demo has none).

## 7. Human GitHub operations, in order, with rollback

Before H1, record the current state (read-only):
`gh api repos/nobu-13/iac-remediation-gate-demo/rulesets/25921565 > ruleset-25921565.before.json`,
the SHA of the demo `main`, and the published gate file's SHA-256. The
rollback restores exactly these.

| # | Operation | Check after | Rollback |
| --- | --- | --- | --- |
| H1 | Approve and push the plugin branch containing the gate scripts; set `GATE_SCRIPTS_COMMIT` to that commit in the App workflow | the commit is visible on GitHub | delete the remote branch (none of the later steps have run) |
| H2 | Create the App: webhook inactive; Checks R/W, Commit statuses R/W; only this account. Note App ID and Client ID | App settings show exactly these permissions | delete the App |
| H3 | Generate a private key (`.pem`), keep it outside any repository | one key listed | delete the key |
| H4 | Install the App on `iac-remediation-gate-demo` only | installation lists one repository | uninstall |
| H5 | Create environment `remediation-publisher`: deployment branches = selected, `main` only; no reviewers or wait timer; "Allow administrators to bypass configured protection rules" off | environment page shows the policy | delete the environment |
| H6 | Add environment secret `REMEDIATION_APP_PRIVATE_KEY` (the `.pem` contents); delete the local `.pem`. Add repository variables `REMEDIATION_APP_CLIENT_ID`, `REMEDIATION_APP_ID` | secret listed under the environment, not under repository secrets | delete secret and variables |
| H7 | Settings → Actions → Policies: new policy, active, target `.github/workflows/remediation-gate.yml`, allow event `pull_request_target` only. **Needed before 2026-12-02 even if A is not deployed** | a new PR still starts the gate; policy insights show no block | delete the policy (after 2026-12-02 the gate then stops) |
| H8 | Land the App workflow on demo `main` as `.github/workflows/remediation-gate.yml`. Ruleset 25921565 has no bypass and needs a code-owner approval the owner cannot give, so: set the ruleset to Disabled, push the one commit, set it back to Active. Merge nothing in that window | `main` moved by one commit; ruleset JSON equals the `.before.json` | disable the ruleset, revert the commit, re-enable; compare with `.before.json` |
| H9 | Open one fresh correct PR (or push to an existing scenario branch) so the App submits `remediation-gate/verified` | Checks API on the PR head: name, `app.id` = App ID, `external_id` `<run>.<attempt>:<digest>`, conclusion matches the gate | close the PR |
| H10 | Ruleset 25921565: add required check `remediation-gate/verified`, save; then set its source to the App; then remove `verify` (15368). Keep strict, code-owner review, no bypass | ruleset API shows only `remediation-gate/verified` with `integration_id` = App ID | restore `required_status_checks` from `.before.json` |
| H11 | Approve a new H-ENV targets revision for Option A (expected ruleset and gate file change) and run the evidence step | `classify_app_check()` PROVEN for G1–G7, G10 check parts | — |

Stop points: the Agent stops before H1. H8 and H10 change the ruleset and
need explicit approval each time.

Full rollback (reverse order, so that no PR waits for a check that can no
longer appear): restore the ruleset's required check (H10) → restore the
gate workflow on `main` (H8) → delete the environment (H5, removes the
secret) and variables (H6) → uninstall the App (H4) → delete its keys (H3)
→ delete the App (H2). Keep the event policy (H7) unless the gate is
retired. Done when `owner-preflight` with the unchanged H-ENV targets passes
again (ruleset rules, `main`, `CODEOWNERS`, gate file and contract equal the
published ones).

## 8. Maintenance

* Rotation (suggested every 6–12 months, a policy choice): generate a new
  key, replace the secret, delete the old key. 3 operations.
* Key compromise: delete the key in the App settings (no new tokens can be
  minted; existing tokens expire within an hour), suspend the installation,
  then rotate. While no valid key exists every PR is blocked.
* Keep action SHAs and both pins current; changing a pin is a workflow change
  on `main` (H8 again).

About 11 Human operations for the first setup, two of them ruleset changes;
roughly 30–60 minutes (estimate, not measured).

## 9. Local and Kiro without the App

`git diff 5412a73 -- iacreview skills` is empty. The verifier CLI and the
`iac-remediation-verify` Skill have no GitHub dependency, and their tests
pass unchanged. Local and Kiro runs produce the same report; only
`execution_mode` differs.

## 10. Observations outside the spike

* The deployed reference gate (`docs/v2/phase1/ci/remediation-gate.yml`)
  runs `set -u` under GitHub's default `bash -e`, so a failing `verify`
  ends the step before `explain` writes the job Summary. The step still
  fails with the verifier's exit code (the decision is unaffected); only the
  Summary is missing for BLOCKED / UNVERIFIED / ERROR. Not changed: it is
  the file published on the demo `main`. The App workflow uses `set +e`.
* Whether step outputs written before a step fails reach `needs.*.outputs`
  was not verified on GitHub. If they do not, the publisher posts `failure`
  for a correct BLOCKED run too — still fail closed.

## 11. Sources

* Checks API (GitHub Apps only): <https://docs.github.com/en/rest/checks/runs>
* Installation tokens: <https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app>
* `actions/create-github-app-token`: <https://github.com/actions/create-github-app-token>
* Environments and deployment branch policies: <https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments>
* Rulesets, required status checks and expected source: <https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets>
* Default variables (`GITHUB_*` cannot be overwritten; `GITHUB_REF` and `GITHUB_WORKFLOW_REF`): <https://docs.github.com/en/actions/reference/workflows-and-actions/variables>
* 2025-12-08 `pull_request_target` / environment change: <https://github.blog/changelog/2025-11-07-actions-pull_request_target-and-environment-branch-protections-changes/>
* Default `pull_request_target` rule, enforced 2026-12-02: <https://github.blog/changelog/2026-09-17-workflow-execution-protections-in-github-actions-generally-available/>, <https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/actions-policies/about-actions-policies>, <https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target>
* Repository-level Actions policies: <https://docs.github.com/en/actions/how-tos/administer/control-workflow-execution>
