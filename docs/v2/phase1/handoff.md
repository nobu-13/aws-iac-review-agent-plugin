# Phase 1 H-ENV — external steps for a human

Everything Phase 1 can do without human credentials is done and recorded in
[implementation-evidence.md](implementation-evidence.md). The steps below need
GitHub or Kiro access that the agent session does not have (its sandbox blocks
`gh` configuration and pushes; installing a Power changes global Kiro
settings). Run them from a normal terminal. None of them merges, tags,
releases, changes a version, force-pushes or touches AWS.

The helper `.agents/tasks/phase1/henv/phase1_henv.py` runs the GitHub and
Kiro-preparation steps. It is kept out of the repository because its targets
file names the maintainer's account. Properties (tested by
`.agents/tasks/phase1/henv/test_phase1_henv.py` with a fake `gh` and local
bare remotes):

* targets are fixed in `henv-targets.json` (exact keys, full pinned SHA, demo
  repository ≠ plugin repository); `check-targets` refuses a branch that is not
  at the pinned commit or a tree that contains `.agents/` or `.kiro/`;
* dry run by default; `--execute` to act; protection and repository creation
  print TARGET / CHANGE / ROLLBACK and require the target name typed back;
* each step checks state first (re-runnable); the first failing command stops
  it; a missing human prerequisite (no `gh` login, no admin access, owner
  instead of test actor, wrong permission) exits 3 with `WAITING_HUMAN`;
* argv arrays only; tokens are never printed or saved (`gh` keeps them);
  outputs go to `.agents/tasks/phase1/henv/out/`;
* no merge, tag, release, force push or repository deletion exists in it.

## Fixed targets

| Item | Value |
| --- | --- |
| Plugin repository / remote | `nobu-13/aws-iac-review-agent-plugin` / `origin` |
| Branch | `feature/phase1-bounded-remediation`, from tag `v1.1.0` (`a275408`) |
| Pinned commit | the `pinned_commit` of `henv-targets.json` (the final commit of this hand-off; it is also printed by `check-targets`) |
| Published files | `out/published-files.txt` written by `check-targets` (`git diff --name-only v1.1.0 <pinned>`) |
| PR | new **draft** PR into `main`; must not be merged |
| Demo consumer repository | `nobu-13/iac-remediation-gate-demo` (new, public, synthetic content only) |
| Gate validator | checked out by commit `pinned_commit`, never by branch name |
| Required check | `verify` from GitHub Actions (app id 15368 — confirm it in the ruleset UI) |

## Roles

| Role | Who | Used for |
| --- | --- | --- |
| Owner / admin | `nobu-13` | push the plugin branch, open the draft PR, create the demo repository, add the ruleset, approve as code owner |
| Test actor | a second GitHub account, collaborator on the demo repository with **write** only (no admin, no maintain, not a bypass actor) | push scenario branches and open their PRs (`demo-scenarios`, `demo-push-update`) |

Without the test actor, AC27 / AC28 / G-P1-4 stay WAITING_HUMAN.

<a id="g-ci"></a>
## A. Development CI on the plugin repository (AC02–AC04, G-P1-5)

This is the existing `.github/workflows/ci.yml` (six environments). It tests
the plugin; it is **not** the trusted gate and proves no merge enforcement.

```sh
cd .agents/tasks/phase1/henv
python3 phase1_henv.py check-targets
python3 phase1_henv.py status
python3 phase1_henv.py push-branch              # dry run
python3 phase1_henv.py push-branch --execute    # pushes <pinned>:refs/heads/feature/... (fast-forward only)
python3 phase1_henv.py open-pr --execute        # gh pr create --draft
# after CI finishes:
python3 phase1_henv.py ci-evidence --run-id <run id> --execute
```

Expected: all six test jobs green; per job the pytest summary `N passed,
M skipped` with 0 failed and Benchmark 34/34. On Ubuntu the APFS-only skip in
`test_remediation_security.py` should run. Report the run id and the six
summary lines (`out/ci-run-<id>-summary.txt`).

Rollback: close the draft PR; optionally `git push origin --delete feature/phase1-bounded-remediation`.

<a id="demo-scenarios"></a>
## B. Trusted gate on the demo consumer repository (AC25–AC28, C14, C24, G-P1-4)

The demo repository holds only synthetic files: the SC-01 base Template, the
approved contract, `CODEOWNERS` and the gate from
`docs/v2/phase1/ci/remediation-gate.yml` with the validator pinned to the
pinned commit. The gate runs on `pull_request_target`, so the gate file,
contract path and validator pin always come from the base branch; a PR cannot
change which trusted revision is used (G5, G10 test that).

```sh
python3 phase1_henv.py demo-prepare                 # local only; needs step A pushed
python3 phase1_henv.py demo-publish --execute       # owner; typed confirmation
python3 phase1_henv.py demo-protect                 # shows TARGET / CHANGE / ROLLBACK
python3 phase1_henv.py demo-protect --execute       # owner; typed confirmation
# in the GitHub UI: invite the test actor with Write; accept as the test actor
gh auth switch                                      # to the test actor
python3 phase1_henv.py demo-scenarios --execute     # refuses the owner and any permission other than write
# wait until the gate ran on every PR; owner approves g1 as code owner in the UI
python3 phase1_henv.py demo-push-update --execute   # G7, as the test actor
gh auth switch                                      # back to the owner
python3 phase1_henv.py demo-move-base --execute     # G8: opens a PR only
python3 phase1_henv.py demo-evidence --execute      # check runs, apps, workflow runs, merge state
```

Ruleset (`out/demo-ruleset.json`, before/after saved): no deletion, no force
push, PR required with 1 approval, code-owner review, stale approvals
dismissed, last-push approval, required check `verify` (GitHub Actions) with
"branches must be up to date", **no bypass actors**. `CODEOWNERS` covers
`.github/`, `.iac-remediation/` and itself.

| ID | Action | Expected | Covers |
| --- | --- | --- | --- |
| G1 | `g1-correct-fix` | gate success; mergeable only after the code owner approves; **do not merge** | AC28 (positive), C01 |
| G2 | `g2-iam-widened` | gate failure (BLOCKED); not mergeable | AC28, C05 |
| G3 | `g3-workflow-spoof` (PR adds a `pull_request` workflow whose job `verify` passes) | real gate failure; record both `verify` check runs (app, workflow run, conclusion) and whether the PR is still blocked; code-owner review required | AC27 check-name spoof, C24 |
| G4 | `g4-fake-report` | gate failure; the forged report has no effect | AC19, C13 |
| G5 | `g5-contract-relaxed` | gate failure; contract read from base; code-owner review required | AC06, C11 |
| G6 | `g6-skip-spoof` (PR adds a workflow whose job `verify` is skipped) | real gate failure; record how the skipped check is shown and that the PR stays blocked | AC27 job skip, C24 |
| G7 | `demo-push-update`: second commit on g1 widening IAM | a new gate run on the new head SHA fails; the earlier success does not apply to it | AC18, AC27 head update, C14 |
| G8 | `demo-move-base`: unrelated PR against main | only after it is merged (see "Additional approval") does G1 show "out of date"; then an update re-runs the gate | AC27 base update, C15a |
| G9 | in the ruleset UI, temporarily remove the required check; observe G2's merge state; restore and save `demo-rulesets-after.json` again | shows that a red CI alone does not block a merge | AC28, work package §9 |
| G10 | `g10-gate-edited` (PR edits the gate's contract path, validator pin and permissions, adds a relaxed contract) | the base gate runs (workflow run path/SHA from base), result failure | AC25, AC26, C12 |

What to record for AC25 / AC26 from `demo-evidence.json`: for each gate run
the event `pull_request_target`, the workflow run's head SHA (the base
branch), and in the run log the `Check out the base revision` ref, the
validator commit and the "PR head moved" check.

If G3 or G6 shows that a same-named check from a PR workflow satisfies the
requirement, that is a finding to report, not to work around: alternatives
(organization "required workflows", a dedicated GitHub App check, a GitHub
Team/Enterprise plan) need a decision (work package §9.2). Until the rows
are filled, `enforcement_status` stays `not_verified` and AC27 / AC28 /
G-P1-4 stay WAITING_HUMAN.

### Additional approval (not granted; demo repository only)

* **Merging G8's PR** into the demo repository's `main`, needed to move the
  base. It is a merge in an isolated synthetic repository.
* **A merge attempt on G2 / G3 / G6** as the test actor, to show the refusal
  itself rather than the merge state. Expected to be refused; if one is not
  refused, the demo repository is the only one affected.

Neither is scripted. Plugin repository merges are not part of H-ENV at all.

Rollback: delete the ruleset (`gh api -X DELETE repos/nobu-13/iac-remediation-gate-demo/rulesets/<id>`),
close the PRs, archive or delete the demo repository in the UI.

<a id="kiro"></a>
## C. Kiro Power run (AC34–AC36, G-P1-3 Kiro part)

```sh
python3 phase1_henv.py kiro-prepare --execute   # out/kiro/sc01, out/kiro/sc02 with KIRO-STEPS.txt
```

1. Clone the plugin at the pinned commit into a separate directory
   (`git clone … && git checkout <pinned>`); install that directory as the
   Power, or install from GitHub at the pinned commit. Record the source and
   the commit Kiro shows.
2. Open `out/kiro/sc01` as a **new** Kiro workspace. Follow `KIRO-STEPS.txt`:
   * ask Kiro to draft the contract with `iac-remediation-verify` → it runs
     `init` and stops; **you** approve by committing the draft;
   * ask Kiro to make the fix and verify against `main` → one edit,
     `verify --worktree --config-rev main --contract …`, `explain`, stop;
     keep its report as `kiro-report.json`;
   * without touching files, run the same `verify` yourself with the CLI
     from the pinned clone → `cli-report.json`;
   * `python3 phase1_henv.py kiro-compare --reports out/kiro/sc01/kiro-report.json out/kiro/sc01/cli-report.json --execute`
     compares the payloads (metadata ignored). Equal payloads need the same
     Python minor version (it is part of the validator identity); a
     difference is listed by key.
3. Repeat in `out/kiro/sc02` (`--parameter required_statement_sid=ReadInput`).
   Then ask Kiro to also change the Lambda environment variable "while it is
   there": expected BLOCKED, and Kiro neither edits the contract nor retries.
4. Write your own start/end times per step into `out/kiro/author-times.txt`.
   A third party's times go into a separate file; they are not mixed.

If the Power install cannot load the Skill (for example the description
limit), stop and report it; do not change global Kiro settings to work around
it.

## What to send back

`out/ci-run-<id>-summary.txt` and the run id; `out/demo-evidence.json`,
`out/demo-rulesets-after.json` and the G1–G10 observations; the two
`kiro-compare.json` results and the time files. Nothing from `out/` is
committed.
