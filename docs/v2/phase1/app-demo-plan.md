# Option A on a new synthetic demo repository: plan, evidence, rollback

Status: **planned, nothing on GitHub created or changed**. Supersedes the
in-place plan of [spike-app-publisher.md](spike-app-publisher.md) §7, which
would have disabled the legacy ruleset.

## 1. Decisions (Human)

1. Option A is an optional reference implementation.
2. The verifier stays at validator `5412a73`.
3. The H-ENV baseline stays at `a24fb3f`; its trust conditions are not relaxed.
4. The App publisher's commit is a separate pin.
5. The legacy demo's ruleset `25921565` is neither disabled nor changed.
6. The legacy demo's `main` (`786425b`) is not changed.
7. The App private key is never stored under git.

So the App gate is tested on a **new** public repository whose first commit
already contains the App workflow. The legacy demo is only read.

## 2. Pins

| Target | Value | Checked by |
| --- | --- | --- |
| Validator (verifier code run by the gate) | `5412a73` | fixed in the helper and in the App workflow (`VALIDATOR_COMMIT`) |
| H-ENV baseline (legacy demo runs) | `a24fb3f`, validator `5412a73` | the helper stops if `henv-targets.json` changes |
| Gate scripts (`gate_outputs.py`, `publish_check.py`, workflow template) | `f77a58c` on its own branch `phase1/app-gate-scripts` | blob ids of the three files recorded in `appdemo-targets.json`; the commit must descend from `5412a73` and change only `docs/` and `tests/` after it; no `.agents/` / `.kiro/` in its tree |
| Legacy demo | `nobu-13/iac-remediation-gate-demo`, ruleset `25921565`, `main` `786425b` | every command naming it is refused; the legacy owner-preflight (read-only) runs before every changing step |

PR #8's branch is not moved: the gate scripts are pushed to a new branch.

## 3. Initialization order

```text
local        app-targets → app-prepare → app-simulate          (no network)
plugin repo  app-push-scripts        new branch phase1/app-gate-scripts @ f77a58c
GitHub UI    register the App (no repository needed yet), generate one key outside git
new repo     app-publish             public repo + main (App workflow included)   ── W0 starts
GitHub UI    install the App on the new repository only
new repo     app-environment         remediation-publisher: main only, no admin bypass
new repo     app-secrets             environment secret (stdin) + 2 repository variables
GitHub UI    Actions policy          allow pull_request_target for the gate file only
new repo     app-bootstrap           g0-bootstrap + g9-probe PRs → first App check
new repo     app-protect             ruleset: required check from the App           ── W0 ends
new repo     app-scenarios           G1–G6, G3S, G10 PRs
new repo     app-push-update         G7
new repo     app-steal               G11 (last)
read-only    app-evidence            after each of the last four
```

Why this order:

* The App's settings do not depend on the repository; installing does.
* The environment, the secret and the variables must exist before the first
  PR, or the bootstrap gate run cannot publish.
* The Actions policy must exist before the first PR: a repository created
  after the 2026-09-17 GA may not get the evaluate-mode grace period (not
  verified), and the gate must not depend on it.
* The ruleset comes last because its expected source needs an App that "must
  have recently submitted a check run" (GitHub documentation). The bootstrap
  PR produces that check through the real gate; no check is posted by hand.

## 4. Bootstrap

`app-bootstrap` opens two PRs while no ruleset exists:

* **G0 `g0-bootstrap`**: the correct fix. The base gate runs, the publisher
  posts `remediation-gate/verified` = success. This is the App's first check
  run and proves the App/environment/secret chain end to end before any
  protection depends on it.
* **G9 `g9-probe`**: IAM widened. The App posts failure, and the PR is still
  mergeable, because nothing requires the check yet. After `app-protect` the
  same PR is BLOCKED. This gives G9 ("without the required check the violating
  PR becomes mergeable") without changing any ruleset.

`app-protect` then:

1. requires a completed App check on the G0 head no older than
   `bootstrap_max_age_minutes` (60);
2. records G0 and G9's merge state and `isRequired` while unprotected
   (`app-w0-views.json`), and stops if G9 is not MERGEABLE;
3. creates the ruleset with `integration_id` = the App id in one call and
   reads it back. Any difference stops the step with the rollback.

If GitHub rejects `integration_id` in the create call (not verified), the
step stops. A two-step fallback (create with any source, then set the App)
would open a window in which any same-named check satisfies the rule; it
needs its own approval and is not automated.

## 5. Unprotected period W0

W0 runs from `app-publish` (main pushed) to `app-protect` (ruleset active).
Target: under 60 minutes. During W0, `main` has no protection and only the
owner has write access.

Do not, during W0:

* merge any PR (including G0, which is mergeable), or push to `main`;
* push branches other than `g0-bootstrap` and `g9-probe`, or open other PRs;
* add collaborators, deploy keys, webhooks, other Apps or repository-level secrets;
* change the workflow, the environment, the variables or the App's permissions;
* approve workflow runs of fork PRs (public repository: anyone may open one);
* create the ruleset by any route other than `app-protect`.

`app-state` flags a merged PR, a moved `main`, repository secrets or extra
rulesets, and every later step stops on them. If W0 was broken, archive the
repository and start over with a new name. The legacy demo is unaffected
either way.

## 6. Scenarios and expected results (fixed before any run)

The App demo ruleset requires a PR but **no approval**, so with one account a
BLOCKED merge state can only come from the required check. Nothing is ever
merged; G1's CLEAN state is read, not used.

| ID | Branch | Change | App check | Merge state | Impostors |
| --- | --- | --- | --- | --- | --- |
| G0 | g0-bootstrap | correct fix (W0) | success | mergeable | — |
| G9 | g9-probe | IAM widened, opened in W0 | failure | MERGEABLE in W0, BLOCKED after | — |
| G1 | g1-correct-fix | correct fix | success, required | CLEAN | — |
| G2 | g2-iam-widened | IAM widened | failure, required | BLOCKED | — |
| G3 | g3-check-spoof | PR workflow with passing jobs `verify` and `remediation-gate/verified` | failure | BLOCKED | Actions checks of the same name, **not required** |
| G3S | g3s-status-spoof | PR workflow sets commit status `remediation-gate/verified` = success with `GITHUB_TOKEN` | failure | BLOCKED | status of the same name, **not required** |
| G4 | g4-fake-report | forged VERIFIED report file | failure | BLOCKED | — |
| G5 | g5-contract-relaxed | contract relaxed in the PR + KeySchema change | failure | BLOCKED | — |
| G6 | g6-skip-spoof | skipped job named `remediation-gate/verified` | failure | BLOCKED | skipped Actions check, **not required** |
| G7 | g1 + one commit | IAM widened after G1 succeeded | failure on the new head; old head keeps success | BLOCKED | — |
| G10 | g10-gate-edited | PR edits the gate (relaxed contract, write permissions, publisher replaced) | failure (the base gate runs) | BLOCKED | — |
| G11 | g11-publisher-steal | PR workflow on `pull_request` and `push` asks for `remediation-publisher` and tries to post an App success | failure | BLOCKED | every `steal.yml` job refused before any step |
| G8 | — | base moved | NOT_PROVEN: needs a merge | | |

`app-simulate` runs the pinned gate offline (validator `5412a73`,
`gate_outputs.py` and the publisher's decision from `f77a58c`) on every
prepared head, with the same report hand-off as the workflow (`verify
--output <dir>/remediation-report.json`, then `gate_outputs.py` reads that
file). A scenario passes only if the verifier wrote a decision report,
`gate_outputs.py` accepted it, the decision is the expected one **and** the
report carries the expected cause codes (below). A failure caused by a
missing or refused report is the gate failing closed, not the scenario's
evidence, and fails the simulation.

| ID | Decision | Cause codes required |
| --- | --- | --- |
| G0, G1 | VERIFIED | none (any code fails) |
| G2, G9 | BLOCKED | `template_change_outside_scope` (IAM edit) |
| G3, G3S, G6, G11 | BLOCKED | `file_added_outside_scope` (PR workflow file) |
| G4 | BLOCKED | `file_added_outside_scope`, `template_change_outside_scope` |
| G5 | BLOCKED | `file_modified_outside_scope` and one of `template_change_outside_scope` / `operation_not_allowed` / `parent_replaced` |
| G10 | BLOCKED | `file_modified_outside_scope`, `file_added_outside_scope`, `template_change_outside_scope` |

Before running, it checks that the interpreter imports PyYAML 6.0.3 and that
cfn-lint 1.46.0 and cfn-guard are on PATH (the workflow's pins); otherwise it
stops without simulating. Every step that pushes (`app-push-scripts`,
`app-publish`, `app-bootstrap`, `app-scenarios`, `app-push-update`,
`app-steal`) refuses unless the saved result passed for all scenarios with
the same validator, gate-scripts pin, demo `main` and scenario heads. The
simulation runs the verifier on the local Python (3.9 here); the workflow uses
3.11 — a difference the GitHub run covers.

## 7. Evidence

Per scenario, `app-evidence` stores raw API data and classifies four parts.
A scenario is PROVEN only if every part is PROVEN; any FAILED part makes it
FAILED.

| Part | PROVEN when | Source |
| --- | --- | --- |
| gate | the run is the base gate: event `pull_request_target`, gate path, recorded on the PR head, base checked out, validator `5412a73` and gate scripts `f77a58c` checked out, `HEAD_SHA` = PR head, trusted contract only, token `Contents: read, Metadata: read`; verify step as expected | Actions run, per-job logs |
| app_check | exactly one check named `remediation-gate/verified` from the App on the head; `external_id` `<run>.<attempt>:<digest>` names that gate run; the downloaded report's recomputed digest equals it; conclusion as expected | Checks API, report artifact |
| required | every same-named check run or status **not** from the App has `isRequired = false`; the App's check has `isRequired = true`; merge state as expected | GraphQL `isRequired(pullRequestNumber:)`, `mergeStateStatus` |
| steal (G11) | every `steal.yml` run concluded and no job executed any step; every App check on the head names a gate run | Actions runs and jobs |

What shows that a fake check cannot satisfy the required check:

* **Same name, other source** (G3, G3S, G6): the impostor exists on the head
  with `isRequired = false`, the App's check is the required one, and the
  merge state is BLOCKED. If GitHub reports `isRequired = true` for an
  impostor, the scenario is FAILED and Option A's claim is not shown.
* **Same name, same App** (G11): the only way is the App key. G11 tries to
  get it from a PR workflow on `pull_request` and `push`; the environment
  must refuse both (no step runs, no token, no App check naming a non-gate
  run). Anyone who already holds the key can post a same-App success; that
  stays a limit (`same_app_with_key`), not a pass.

Recorded as NOT_PROVEN with the reason: G8 (needs a merge), AC28 (needs a
write-only second account), admin bypass (needs a merge attempt),
`same_app_with_key`.

Not verified until the run: whether `isRequired` honours the expected source;
whether `POST /rulesets` accepts `integration_id` directly; whether
`user/installations` reports the permissions as planned; whether step outputs
of a failed step reach the publisher (if not, BLOCKED runs still publish
failure).

## 8. Rollback

| Step | Rollback | After rollback |
| --- | --- | --- |
| app-push-scripts | `git push origin --delete phase1/app-gate-scripts` | the App workflow can no longer check out its scripts (fails closed) |
| App registration | App settings → Advanced → Delete GitHub App | all its keys and installations go with it |
| key | App settings → delete the key; delete the local `.pem` | no new tokens; existing ones expire within 1 h |
| app-publish | Settings → Archive (reversible) or delete by hand | nothing else depends on the repository |
| install | Settings → Applications → uninstall | publish fails (exit 3), PRs blocked |
| app-environment | `gh api -X DELETE repos/<demo>/environments/remediation-publisher` | the secret is deleted with it |
| app-secrets | `gh secret delete … --env remediation-publisher`, `gh variable delete …` | publish fails closed |
| Actions policy | delete the policy | after 2026-12-02 the gate stops (fail closed) |
| app-bootstrap / app-scenarios / app-steal | close the PRs, delete the branches | — |
| app-protect | `gh api -X DELETE repos/<demo>/rulesets/<id>` | the repository is unprotected again; stop using it |

Full teardown, after the evidence is accepted (separate approval): close all
PRs → archive the App demo → uninstall the App → delete its key → delete the
App → delete the scripts branch. Done when `app-preflight` shows the
repository archived or absent and the legacy owner-preflight still passes.

Key compromise (G11 FAILED, a key seen anywhere else, or doubt): delete the
key in the App settings first, suspend the installation, then rotate. Treat
every App check after the exposure as unproven.

Failure during a step: each step re-reads the state and skips what is done,
so it can be re-run. A step never overwrites a remote branch that moved and
never force-pushes.

## 9. Legacy demo vs App demo

| | Legacy demo | App demo |
| --- | --- | --- |
| Repository | `nobu-13/iac-remediation-gate-demo` (unchanged) | `nobu-13/iac-remediation-app-gate-demo` (new) |
| Workflow on `main` | `remediation-gate.yml`, one job `verify` | App workflow from the first commit: `verify` + `publish` |
| Required check | `verify` from GitHub Actions (15368) | `remediation-gate/verified` from the App |
| Reviews | code-owner review, 1 approval | PR required, 0 approvals (to attribute BLOCKED to the check) |
| Protection set up | after `main`, by `demo-protect` | after the bootstrap App check, by `app-protect` (W0 in between) |
| Secrets | none | App key as environment secret (`main` only, no admin bypass) |
| Pins | validator `5412a73` | validator `5412a73` + gate scripts `f77a58c` |
| Same-name spoof (G3/G6) | satisfies the rule (AC27 FAILED) | expected not required (G3, G3S, G6) |
| Same-App spoof | n/a | needs the key; G11 tests that a PR cannot get it |
| G1 mergeability | not observable (own approval impossible) | CLEAN, read only |
| Check vs review attribution | not possible | possible (no review rule) |
| G9 | NOT_PROVEN (ruleset change) | before/after the planned ruleset creation |
| G8, AC28 | NOT_PROVEN | NOT_PROVEN |
| Evidence of "required" | rollup only | GraphQL `isRequired` per check / status |
| Helper | `phase1_henv.py`, `phase1_henv_owner.py` | `phase1_appdemo.py` (legacy is read-only) |
| `pull_request_target` policy (2026-12-02) | still needed for the legacy gate | created before the first PR |

## 10. Automation

`phase1_appdemo.py` (local, under `.agents/`, not committed) runs every step
except four that GitHub only offers in the UI or that hold the key: App
registration, key generation, installation, and the Actions policy. Each
changing step runs the legacy guard and the App demo state check first, then
prints TARGET / CHANGE / ROLLBACK and requires the target name typed back.
Without `--execute` it changes nothing. The key reaches `gh secret set` on
stdin from a file outside any git work tree; the helper never prints or
copies it. 75 offline tests cover the targets, pins, legacy refusal, payloads,
the key handling, the classification and the offline gate run.
