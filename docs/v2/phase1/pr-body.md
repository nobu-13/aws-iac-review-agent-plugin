## Phase 1: bounded remediation verifier — DRAFT, do not merge

Adds an unreleased verifier that checks one candidate fix to a CloudFormation
Template against a human-approved remediation contract
(`python3 -m iacreview.remediation init | verify | explain`), one thin Skill
(`iac-remediation-verify`), two profiles, 53 pre-fixed cases and the public
Phase 1 spec under `docs/v2/phase1/`.

* No version change, no release. Review_Report, Finding, Delta_Report, the five
  Skills, existing CLIs and `iacreview/exitcodes.py` are unchanged.
* Existing modules touched: `iacreview/proc.py` (additive `run_bounded`) and the
  OBS-1 fix in `iacreview/cdk.py` (separate commit).
* Tests touched: `tests/unit/test_skills.py` gains the new Skill in the closed
  discovery list; nothing else in existing tests changed.

What this PR's CI shows: the six-environment matrix with the Phase 1 tests.
What it does not show: merge enforcement. That is tested on a separate demo
repository (`docs/v2/phase1/handoff.md`), because a gate on this repository's
own PRs would run the validator under development.

Evidence: `docs/v2/phase1/implementation-evidence.md`.
