# Phase 1 H-ENV — external steps for a human

Everything Phase 1 could do without human credentials is done and recorded in
[implementation-evidence.md](implementation-evidence.md). The steps below need
GitHub or Kiro access the agent does not have (the agent sandbox blocks `gh`
configuration and pushes, and installing a Power changes global Kiro
settings). Run them from a normal terminal. None of them merges, tags,
releases, changes a version, force-pushes or touches AWS.

A local helper performs steps 1–6 with dry-run by default, typed confirmation
before any settings change, a state check before every step (re-runnable),
and output written only under `.agents/tasks/phase1/henv/out/` (not
committed): `.agents/tasks/phase1/henv/phase1_henv.py`. It is kept out of the
repository because it hard-codes the maintainer's account and demo repository.

Fixed targets:

| Item | Value |
| --- | --- |
| Plugin repository | `nobu-13/aws-iac-review-agent-plugin` |
| Branch | `feature/phase1-bounded-remediation` (from tag `v1.1.0` = `a275408`) |
| PR | new **draft** PR into `main`, title "Phase 1: bounded remediation verifier (draft, do not merge)" |
| Demo consumer repository | `nobu-13/iac-remediation-gate-demo` (new, public, synthetic content only) |
| Required check | `verify` from GitHub Actions (app id 15368 — confirm in the ruleset UI) |

<a id="g-ci"></a>
## Step 1–2: push the branch and open a draft PR (AC02–AC04, AC25 local part, G-P1-5)

```sh
cd .agents/tasks/phase1/henv
python3 phase1_henv.py status
python3 phase1_henv.py push-branch            # dry run
python3 phase1_henv.py push-branch --execute  # git push -u origin feature/phase1-bounded-remediation (no force)
python3 phase1_henv.py open-pr --execute      # gh pr create --draft
```

The existing `.github/workflows/ci.yml` runs the six-environment matrix
(Ubuntu / macOS × Python 3.9 / 3.11 / 3.13) on the PR; the Phase 1 tests are
part of its pytest step. When it finishes:

```sh
python3 phase1_henv.py ci-evidence --run-id <run id> --execute
```

Expected: every job green; per job, pytest `N passed, M skipped, 0 failed`
(the APFS-only skip in `test_remediation_security.py` should not appear on
Ubuntu), Benchmark 34/34. Report the run id and per-job counts back.

Rollback: close the draft PR; delete the remote branch with
`git push origin --delete feature/phase1-bounded-remediation` if wanted.

<a id="demo-scenarios"></a>
## Step 3–6: demo consumer repository and the merge-enforcement tests (AC25–AC28, C14, C24, G-P1-4)

Prerequisites: step 1 done (the gate checks out the pushed validator commit);
a **second GitHub account** (test actor) with write access to the demo
repository and no admin or bypass rights. Without it AC28 stays
`not_verified`.

```sh
python3 phase1_henv.py demo-prepare            # local only: main + 6 scenario branches
python3 phase1_henv.py demo-publish --execute  # gh repo create (public) + push main
python3 phase1_henv.py demo-protect            # prints the ruleset and the rollback command
python3 phase1_henv.py demo-protect --execute  # POST ruleset (typed confirmation)
gh auth switch                                 # to the test actor
python3 phase1_henv.py demo-scenarios --execute
# wait for the gate runs, then:
python3 phase1_henv.py demo-evidence --execute
```

Ruleset applied to `main` (before/after saved by the helper): no deletion, no
force push, pull request required with 1 approval, code-owner review, stale
approvals dismissed, last-push approval, required check `verify` (GitHub
Actions) with "branches must be up to date", no bypass actors. `CODEOWNERS`
covers `.github/`, `.iac-remediation/` and itself.

Tests and what to record (from `demo-evidence.json` and the PR pages):

| ID | Branch / action | Expected |
| --- | --- | --- |
| G1 | `g1-correct-fix` | gate `verify` success; PR not mergeable until the code owner approves; after approval mergeable (do **not** merge) |
| G2 | `g2-iam-widened` | gate failure (BLOCKED); merge blocked |
| G3 | `g3-workflow-spoof` (adds a `pull_request` workflow with a passing job `verify`) | real gate failure; record whether GitHub shows two `verify` checks and whether merge is still blocked; code-owner review required for `.github/` |
| G4 | `g4-fake-report` | gate failure; the forged report changes nothing |
| G5 | `g5-contract-relaxed` | gate failure (contract read from base); code-owner review required |
| G6 | `g6-skip-spoof` (adds a workflow whose job `verify` is skipped) | real gate failure; record how the skipped check is shown and that merge stays blocked |
| G7 | push a second commit to `g1-correct-fix` that widens IAM | a new gate run on the new head fails; the earlier success no longer applies |
| G8 | merge an unrelated commit into `main` while G1 is green | G1 needs updating ("up to date" rule); after update the gate re-runs |
| G9 | as the owner, temporarily remove the required check from the ruleset, observe G2 becomes mergeable, restore | shows that the CI result alone does not block a merge without the setting |

Merge attempts are deliberately not scripted. If you want the strongest
evidence for G2/G3/G6, attempt a merge by hand as the test actor and record
the refusal; never merge G1.

What is enforced and what is not is decided by these results: until they
exist, `enforcement_status` in every report stays `not_verified` and AC27 /
AC28 / G-P1-4 are WAITING_HUMAN. If G3 or G6 shows that a same-named check
from a PR workflow satisfies the requirement, that is a finding to report,
not to work around: the alternatives (organization "required workflows",
a dedicated GitHub App check) need a decision (work package section 9.2).

Rollback: delete the ruleset (`gh api -X DELETE repos/nobu-13/iac-remediation-gate-demo/rulesets/<id>`),
close the PRs, archive or delete the demo repository by hand.

<a id="kiro"></a>
## Step 7: Kiro Power run (AC34–AC36, G-P1-3 Kiro part)

1. Open a **new, empty** Kiro workspace (not this repository).
2. Install the plugin as a Power from the pushed branch
   (`https://github.com/nobu-13/aws-iac-review-agent-plugin`, ref
   `feature/phase1-bounded-remediation`), or from a local clone at that commit.
   Record the Power source and commit shown by Kiro.
3. Create the SC-01 sample: copy
   `benchmark/remediation/scenarios/sc01-billing-mode/base/infra/template.yaml`
   to `infra/template.yaml`, `git init`, commit.
4. Ask Kiro: "Use iac-remediation-verify to draft a contract for OrdersTable
   with the dynamodb-billing-mode-v1 profile." Check that it runs `init`, stops,
   and asks you to approve. Commit the draft yourself as the approval.
5. Ask Kiro to make the fix and verify it. Expected: one edit, `verify
   --worktree` with `--config-rev main`, `explain`, then it stops with
   VERIFIED; it must not edit the contract or retry.
6. Run the same `verify --worktree` command yourself in a terminal and compare
   `metadata.payload_sha256` of the two reports (AC36).
7. Repeat with SC-02 (`--parameter required_statement_sid=ReadInput`). Then
   ask Kiro to also change the Lambda environment variable "while it is there"
   and confirm the result is BLOCKED and that Kiro does not weaken the contract.
8. Save the two reports and a short transcript under
   `.agents/tasks/phase1/kiro/` (not committed).

If Kiro's Power install cannot load the Skill (for example the description
limit), stop and report it; do not edit global settings to work around it.
