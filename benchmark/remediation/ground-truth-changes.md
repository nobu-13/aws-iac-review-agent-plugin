# Ground-truth changes after implementation

`cases.json` was written before the verifier. Two entries were found wrong
while running the cases. Each was checked against the work package text
before anything changed. No expectation was changed to match the verifier
without that check, and no assertion was removed. The review was done by the
author agent; an **independent review has not been done** and is listed for
the human review of Phase 1.

## C22a — expected value changed

| | Before | After |
| --- | --- | --- |
| decision / exit | `UNVERIFIED` / 21 | `BLOCKED` / 20 |
| required codes | `comparison_incomplete` | `comparison_incomplete`, `check_failed` |
| class | evidence_insufficient | unchanged |

Case: the Head Template repeats the key `LOG_LEVEL`.

Requirement text it is checked against (work package):

* §6.1: "同時発生時は `ERROR > BLOCKED > UNVERIFIED > VERIFIED` の順で代表値を決め、診断を省略しない。"
* §8 C22: "duplicate key・Alias循環 / fan-out・解析限界 → 非0、部分比較を合格にしない"
* §6.1: BLOCKED includes "必須検査の確定FAIL".

Observation: cfn-lint 1.46.0 (the pinned required check) reports an Error on
the duplicate key, which is a definite required-check failure, while the
semantic comparison is incomplete. Under §6.1 the representative value is
BLOCKED and the incomplete comparison is still reported. §8 C22 requires
non-zero and no acceptance, which both values satisfy. The first expectation
ignored the priority rule; the requirement did not change.

Would the old value be reachable without weakening anything? Only by ignoring
cfn-lint's result, which would contradict §6.1. Rejected.

## C15c — fixture builder changed, expected value unchanged

| | Before | After |
| --- | --- | --- |
| builder | deleted the whole `ProvisionedThroughput` edit from the revised contract | narrows its operations from `["remove"]` to `["replace"]` |
| expected | `BLOCKED` / 20 / `operation_not_allowed` / old evidence stale | unchanged |

Requirement text: §8 C15 "Base / 承認設定 / RuleのRevision変更 → 再検証またはUNVERIFIED";
the case summary written with the expectation: "the approved contract is then
revised to forbid removing ProvisionedThroughput".

Observation: deleting the edit makes the removal out of scope
(`template_change_outside_scope`), not a forbidden operation; the builder did
not implement what the summary and the expected code describe. Narrowing the
operations does. The decision, exit code and stale-evidence check were
already right with either builder; only the code differed.

## How to re-check

```sh
python3 tests/remediation_bench/run_cases.py --only C22a,C15c
```

Both cases also run in `tests/integration/test_remediation_cases.py`.
