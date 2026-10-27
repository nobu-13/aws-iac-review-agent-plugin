# Spike: Option A — the required check published by a dedicated GitHub App

Status: **spike, not deployed**. Follows
[gate-check-provenance.md](gate-check-provenance.md) Option A. Nothing on
GitHub was created or changed: no App, key, installation, environment,
secret, event policy, workflow or ruleset. The GitHub App is **not** a
product dependency; the verifier (`iacreview/remediation/`) is unchanged and
runs without it.

Artifacts (prototype, offline-tested only):

| File | Role |
| --- | --- |
| `docs/v2/phase1/ci/spike/remediation-gate-app.yml` | base-branch workflow with a `verify` job and a separate `publish` job |
| `docs/v2/phase1/ci/spike/publish_check.py` | publisher: maps the verify job's result to one check run, standard library only |
| `tests/unit/test_spike_app_publisher.py` | 32 tests against a fake Checks API |
| `.agents/tasks/phase1/henv/phase1_henv_owner.py` `classify_app_check()` | evidence rule for the App check (local helper, 66 helper tests) |

## 1. Minimal architecture

```text
pull_request_target (workflow file and GITHUB_SHA from the default branch)
 ├─ job verify    GITHUB_TOKEN contents: read, no secrets, no environment
 │    base commit as subject, PR head fetched as git objects only,
 │    pinned validator → exit_code, head_sha, payload_sha256 (job outputs)
 └─ job publish   needs: verify, if: always(), environment remediation-publisher
      permissions: {}  (GITHUB_TOKEN has no scopes)
      sparse checkout of publish_check.py at the pinned validator SHA
      create-github-app-token (pinned SHA) → installation token,
        this repository only, checks: write
      POST /repos/{repo}/check-runs
        name        remediation-gate/verified
        head_sha    github.event.pull_request.head.sha
        conclusion  success only if verify result = success AND exit 0
                    AND verified head = event head AND digest is 64 hex
        external_id <run_id>.<run_attempt>:<payload_sha256>
Ruleset: required check remediation-gate/verified, expected source = the App
```

Separation of duties:

* Validator (`verify`) decides. It never sees the App key or token. It is the
  only job that touches untrusted bytes, and it runs only pinned code.
* Publisher (`publish`) reports. It touches no PR bytes and runs one pinned
  script. It cannot change the decision: any missing, malformed or
  inconsistent input gives `failure` (fail closed); invalid configuration
  posts nothing and exits 2, which leaves the required check missing and the
  PR blocked.

Why the key does not reach untrusted code (official behaviour, sources in §8):

* Checks write is only available to GitHub Apps; a workflow's `GITHUB_TOKEN`
  creates check runs as GitHub Actions (app 15368), which no longer matches
  the required source.
* The key is an **environment** secret. Environment secrets are released
  only to jobs that reference the environment and pass its deployment branch
  policy. Since 2025-12-08 the policy is evaluated against the default branch
  for `pull_request_target` and against `refs/pull/<n>/merge` for
  `pull_request`, so a workflow added by a PR cannot obtain it. A repository
  secret would be wrong here: same-repository `pull_request` runs receive
  repository secrets.
* The installation token is minted inside `publish`, restricted to the
  repository and `checks: write`, masked, expires after at most one hour and
  is revoked by the action at job end. It is never a job output.
* The `verify` and `publish` jobs run on separate ephemeral runners.

## 2. Threat model

Defended (assuming §2.2 holds):

| Attack | Result with A |
| --- | --- |
| PR adds a workflow with a job named `verify` / `remediation-gate/verified` (G3, G6) | its check comes from app 15368, not the App; does not satisfy the rule |
| PR workflow references `environment: remediation-publisher` | branch policy rejects `refs/pull/<n>/merge`; no secret |
| PR edits the gate workflow (G10) | `pull_request_target` runs the default-branch copy |
| Success from an older head reused after a push (G7) | the check is bound to `head_sha`; the new head has no App check until its own run |
| `verify` reports a different head than the event | publisher concludes `failure` |
| Missing / cancelled / skipped verify job | `failure` (or nothing posted) |
| Re-run of an old attempt | new check on that old head only; `external_id` records the attempt |

Not defended (stated limits):

1. Repository owner and admins. They can change `main` workflows (ruleset
   has no bypass, but they can edit the ruleset), the environment, the
   secret and the App. A workflow on `main` can exfiltrate the key. A is a
   control against PR authors, not against administrators.
2. App key compromise. Anyone with the key can mint a token and post
   `success` on any head. Mitigation only: no local copy kept, App
   installed on one repository, `checks: write` only, rotation, revocation.
3. Validator compromise. A bug or parser exploit (cfn-lint, cfn-guard, YAML)
   inside `verify` can write forged outputs; the publisher trusts `verify`
   outputs by design. A proves **where** the check came from, not that the
   decision is correct. The digest in `external_id` lets a reviewer re-run
   the verifier and compare.
4. Collaborators who can merge reviewed changes to `main` (the environment
   trusts everything on the default branch, including future workflows and
   `workflow_dispatch` there). Code-owner review of `.github/` remains
   necessary.
5. Availability, not integrity: GitHub's default policy that blocks
   `pull_request_target` on public repositories is in evaluate mode now and
   is enforced from **2026-12-02** (moved from 2026-11-02). Without an
   explicit allowlist for `.github/workflows/remediation-gate.yml` the gate
   stops running, no App check appears and every PR stays blocked (fail
   closed). The alternative, a `workflow_run` trigger, is more complex
   (`pull_requests` is empty for fork PRs) and was not prototyped.
6. Dependabot-triggered runs: whether they receive environment secrets was
   **not verified**. If not, the check is missing and the PR is blocked.
7. GitHub itself (Actions, Checks, rulesets) is trusted.

### 2.2 Assumptions that must hold

Default-branch-only deployment policy, admin bypass of environment rules
disabled, key held only as the environment secret, App installed on this
repository only, `CODEOWNERS` covering `.github/`, ruleset without bypass
actors, and the validator SHA pinned in the workflow.

## 3. G1–G10 with A (owner account only)

| ID | Check provenance | Merge part |
| --- | --- | --- |
| G1 | PROVABLE: App check `success`, `external_id` links run and digest; `classify_app_check()` | NOT_PROVEN: owner cannot approve own PR |
| G2, G4, G5 | PROVABLE: App check `failure` from the base workflow | NOT_PROVEN: review also missing |
| G3, G6 | PROVABLE: spoof `verify` exists but is not the required check; the only App check is `failure` | NOT_PROVEN (same reason) |
| G10 | PROVABLE as G2; additionally a PR workflow requesting the environment can be shown to be refused (not yet a scenario) | NOT_PROVEN |
| G7 | PROVABLE: App check on the new head is `failure`, the old head's `success` stays on the old SHA | NOT_PROVEN |
| G8 | NOT_PROVEN: needs a merge to move `main` | — |
| G9 | NOT_PROVEN: needs a ruleset change | — |

A turns AC27 from FAILED (spoofable check) into provable for the check part.
AC28 (a non-bypass, write-only actor) stays NOT VERIFIED without a second
account. G-P1-4 still needs the merge part, which A does not change.

"PROVABLE" means the rule is implemented and tested offline; none of it was
observed on GitHub.

## 4. App permissions and secret handling

| Item | Value |
| --- | --- |
| Repository permissions | Checks: Read and write. Metadata: Read (mandatory) |
| Possibly needed | Commit statuses: Read and write — GitHub's ruleset text says the expected-source app "must be installed with the statuses:write permission". Whether Checks write alone is listed is **not verified**; add it only if the ruleset UI does not offer the App. The publisher never uses it |
| Not requested | Contents, Pull requests, Actions, Administration, any organization or account permission |
| Webhook | disabled (the App receives no events) |
| Installable by | only this account; installed on the demo repository only |
| Private key | environment secret `REMEDIATION_APP_PRIVATE_KEY` of `remediation-publisher`; the downloaded `.pem` deleted afterwards |
| Client ID | variable `REMEDIATION_APP_CLIENT_ID` (not secret) |
| Token | minted per job, repository-scoped, `checks: write`, ≤ 1 h, revoked at job end |

Nothing is written to logs, reports or the repository; the secret scan
covers the prototype files.

## 5. Setup, operation count, maintenance

Human operations (GitHub UI; estimate, not measured):

| # | Operation |
| --- | --- |
| 1 | Create the App (name, homepage, webhook off, permissions from §4, "only this account") |
| 2 | Generate a private key (downloads `.pem`), note the Client ID |
| 3 | Install the App on `iac-remediation-gate-demo` only |
| 4 | Create environment `remediation-publisher`; deployment branches: `main` only |
| 5 | Deselect "Allow administrators to bypass configured protection rules" |
| 6 | Add environment secret `REMEDIATION_APP_PRIVATE_KEY`; delete the local `.pem` |
| 7 | Add variable `REMEDIATION_APP_CLIENT_ID` |
| 8 | Actions event policy: allow `pull_request_target` for `.github/workflows/remediation-gate.yml` (needed before 2026-12-02) |
| 9 | Put the App workflow on demo `main` with `VALIDATOR_COMMIT` and the publisher ref pinned. With ruleset 25921565 (no bypass, code-owner review, single account) this needs a temporary ruleset change — a separate approval |
| 10 | Open a PR once so the App submits a check (the expected source requires a recent check run) |
| 11 | Ruleset: replace required check `verify` / 15368 with `remediation-gate/verified` / the App |
| 12 | Re-run `owner-preflight` / `owner-evidence` with the updated expected rules |

About 12 operations, roughly 30–60 minutes the first time. Maintenance:

* Rotation (suggested every 6–12 months, a policy choice): generate a new
  key, replace the secret, delete the old key — 3 operations.
* Revocation: delete the key in the App settings (immediate for new tokens;
  existing tokens expire within an hour), or suspend / uninstall the App.
  While revoked, every PR is blocked (fail closed).
* Keep the pinned action SHAs and validator SHA current.
* Watch the 2026-12-02 event-policy enforcement.

## 6. Local and Kiro use without the App

The App lives only in the CI reference configuration. `git diff 5412a73 --
iacreview skills` is empty, the verifier CLI and the `iac-remediation-verify`
Skill have no GitHub dependency, and the existing CLI and Skill tests pass
unchanged (see the spike report for commands). Local and Kiro runs produce
the same report; only `execution_mode` differs (`local` vs `trusted_ci`).

## 7. Recommendation

| Choice | Effect | Cost |
| --- | --- | --- |
| Implement A as the **reference** CI configuration (recommended) | closes the check-name spoof; AC27 check part provable; product stays App-free | §5 operations; one key to manage; event-policy allowlist |
| B (organization "Require workflows to pass") | no key; binds to the workflow file | needs an organization; plan availability not verified; not usable for a personal repository |
| Shrink to documentation (C) | no setup | AC27 stays FAILED; merge enforcement relies on human review of workflow changes |

Recommendation: keep A as an optional reference implementation (workflow +
publisher script + tests + this document), document B for organizations, and
do not make the App a product requirement. Deploying A on the demo is worth
doing only if G-P1-4's check part must be shown on GitHub in Phase 1; it
needs operations 1–12, including a temporary ruleset change.

## 8. Sources

* Checks API (GitHub Apps only): <https://docs.github.com/en/rest/checks/runs>
* Installation tokens: <https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app>
* `actions/create-github-app-token`: <https://github.com/actions/create-github-app-token>
* Environments and deployment branch policies: <https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments>
* Rulesets, required status checks and expected source: <https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets>
* 2025-12-08 `pull_request_target` / environment change: <https://github.blog/changelog/2025-11-07-actions-pull_request_target-and-environment-branch-protections-changes/>
* Default `pull_request_target` rule, enforcement 2026-12-02 (editor's note of 2026-10-21; "About Actions policies" still shows 2026-11-02): <https://github.blog/changelog/2026-09-17-workflow-execution-protections-in-github-actions-generally-available/>
