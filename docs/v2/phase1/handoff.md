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
| Test actor | a second GitHub account with **write** only (no admin, no maintain, not a bypass actor) — **does not exist**; the owner-run plan in B replaces it, and the items only it could show stay NOT VERIFIED | `demo-scenarios`, `demo-push-update` (kept, unused) |

Without the test actor, AC28 and the merge parts of AC27 / G-P1-4 stay NOT VERIFIED.

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

State before this step (done by the maintainer): demo repository
`nobu-13/iac-remediation-gate-demo` published with the gate pinned to the
validator commit, and ruleset **25921565** active on `main`. Both are kept as
they are: nothing below changes the ruleset, the required check, CODEOWNERS,
or any existing branch.

There is no second GitHub account, so the scenarios run as the **owner**
with a separate command set, `.agents/tasks/phase1/henv/phase1_henv_owner.py`.
The test-actor command `phase1_henv.py demo-scenarios` keeps refusing the
owner and anything but write-only permission.

```sh
cd .agents/tasks/phase1/henv
python3 phase1_henv_owner.py owner-preflight                    # read-only
python3 phase1_henv_owner.py owner-scenarios --execute          # 7 branches + "[owner-run]" PRs
python3 phase1_henv_owner.py owner-evidence --wait-minutes 30 --execute
python3 phase1_henv_owner.py owner-push-update --execute        # G7, after G1 is green
python3 phase1_henv_owner.py owner-evidence --wait-minutes 30 --execute
```

`owner-preflight` runs before every changing step and stops it unless the
identity is the owner, ruleset 25921565 is active with no bypass actors and
the published rules, and the remote `main`, `CODEOWNERS`, gate file and
contract equal the published ones. `owner-scenarios` only creates branches
that do not exist (never overwrites one at another commit) and opens PRs; it
never merges or approves. `owner-evidence` waits for the gate runs and writes
`out/owner-evidence.json` and `out/owner-evidence.md`: per scenario the PR
head and base, the status rollup, the check runs on the head, each gate run's
event, workflow path, run SHA, step conclusions and log facts (validator pin,
trusted contract path, no relaxed contract, PR head SHA), and the merge
state. Each G is then classified by rules fixed in the code before any run:

| ID | PROVEN when | Merge part (owner run) |
| --- | --- | --- |
| G1 | gate `verify` step success from the base gate; a successful `verify` appears in the PR status rollup | NOT_PROVEN: the owner is the only code owner and cannot approve their own PR |
| G2, G4, G5, G10 | gate fails at the verify step only, run from the base gate (event `pull_request_target`, gate path, run SHA ≠ PR head, pinned validator, trusted contract, no relaxed contract) | NOT_PROVEN: review is always missing, so BLOCKED cannot be attributed to the check |
| G3, G6 | as above; FAILED if the PR's own same-named `verify` makes the rollup look successful / skipped without the gate's failure | NOT_PROVEN while two `verify` results exist |
| G7 | after `owner-push-update`, the newest gate run (new head SHA in its log) fails and an earlier run succeeded | — |
| G8 | always NOT_PROVEN: moving `main` needs a merge | — |
| G9 | always NOT_PROVEN: needs a ruleset change | — |

FAILED means the observation contradicts the expectation (for example the
gate failed in an install step, or a spoof satisfied the rollup). It is
reported as a finding, not retried around.

### Result of the first owner run

G1–G6 and G10 ran. The gate decided correctly from the base workflow; the
helper's run-SHA rule was wrong (fixed); G3 / G6 showed that a PR workflow can
produce a same-named `verify` check. **Stop before G7** until a decision on
[gate-check-provenance.md](gate-check-provenance.md). The next step is only
the read-only `owner-evidence` re-run (it now links check runs to their
workflow runs by check suite).

### Not verifiable with the owner alone (NOT VERIFIED)

* AC28: a write-only, non-bypass actor cannot merge a violating PR and can
  satisfy the checks of a correct one — needs a second account.
* G1 positive mergeability — needs a code-owner approval by someone other than
  the PR author.
* Whether a BLOCKED merge state comes from the required check or from the
  missing review.
* Admin bypass behaviour — needs a merge attempt.
* G8 (base move) and G9 (required check removed) — need a merge and a ruleset
  change, neither approved.

These keep AC27 (partly), AC28 and G-P1-4 at WAITING_HUMAN / NOT VERIFIED
whatever the owner run shows. A merge attempt or a ruleset change on the
demo repository would each be a separate approval, demo repository only.

Rollback of this step: close the `[owner-run]` PRs in the UI. Branches are
left in place (deleting them is not part of this step).

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

`out/owner-evidence.md` (and the `.json`), the two `kiro-compare.json`
results (`out/kiro/sc01/`, `out/kiro/sc02/`) and `out/kiro/author-times.txt`.
Nothing from `out/` is committed.
