# Phase 1 Tasks

Status legend: `done` (implemented and verified locally), `waiting` (needs
the H-ENV steps in [handoff.md](handoff.md)), `not done`.

| WP | Task | Status | Output |
| --- | --- | --- | --- |
| WP0 | Record v1.1.0 baseline (tag commit, tools, gates) | done | implementation-evidence.md |
| WP0 | Branch `feature/phase1-bounded-remediation` from `v1.1.0`; keep `.agents/` untouched | done | — |
| WP0 | OBS-1: skip symlink cycles in directory discovery on every Python version | done | `iacreview/cdk.py`, `tests/regression/test_discovery_symlink_loop.py`, commit `c96896c` |
| WP0 | Threat model and change list | done | threat-model.md, design.md section 1 |
| WP1 | Scenarios, contracts and 53 cases with expected values before code | done | `benchmark/remediation/` |
| WP1 | Contract / Snapshot / Report design | done | design.md, verification-report-schema.md |
| WP1 | AC map | done | ac-traceability.json |
| WP2 | `proc.run_bounded` (timeout, output cap, group kill) | done | `iacreview/proc.py` |
| WP2 | Contract loader, profiles, Git snapshot adapter, boundary, checks, decision, report, CLI | done | `iacreview/remediation/` |
| WP2 | SC-01 vertical slice: fix, overreach, fake evidence, Head update | done | C01, C05, C13, C14 |
| WP3 | SC-02, error paths, disclosure, resource limits | done | C02, C16–C23 |
| WP3 | Kiro Skill `iac-remediation-verify` | done (document) / waiting (Kiro run) | `skills/iac-remediation-verify/SKILL.md` |
| WP3 | Human Summary (`explain`) | done | `report.summary` |
| WP4 | Reference trusted gate and static checks | done | `docs/v2/phase1/ci/` |
| WP4 | Existing six-environment CI with the Phase 1 tests | waiting | needs push (H-ENV step 1) |
| WP4 | Required check, ruleset, CODEOWNERS, spoof / skip / head-update / actor tests | waiting | H-ENV steps 3–6 |
| WP5 | A/B/C/D comparison over all cases | done | evaluation.md |
| WP5 | Effort measurement (author) | done | evaluation.md |
| WP5 | Effort measurement (third party) | not done | Phase 2 Community Pilot |
| WP5 | Clean-checkout reproduction | done | implementation-evidence.md |
| WP5 | Final gates and report | done (local) / waiting (CI) | implementation-evidence.md |

Out of scope and not started: generic agent runner, retry loop, AWS calls,
deploy, merge, release, version change, Power registry submission.
