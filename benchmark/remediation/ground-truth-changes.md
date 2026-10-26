# Ground-truth changes after implementation

`cases.json` was written before the verifier. Two entries were found wrong
while running the cases; each was checked against the work package text before
anything changed. No expectation was changed to match the verifier without that
check, and no assertion was removed.

## C22a (expected value changed)

* Before: `UNVERIFIED` / exit 21 / codes `[comparison_incomplete]`.
* After: `BLOCKED` / exit 20 / codes `[comparison_incomplete, check_failed]`.
* Why the old value was wrong: the duplicate `LOG_LEVEL` key makes cfn-lint
  1.46.0 report an Error on Head, a definite required-check failure. The work
  package fixes the representative value as `ERROR > BLOCKED > UNVERIFIED >
  VERIFIED` (§6.1), so a definite failure outranks the incomplete comparison.
  The case family's required observation (C22: non-zero, a partial comparison
  is never accepted) holds either way, and `comparison_incomplete` is still
  required to be reported.

## C15c (fixture builder changed, expected value unchanged)

* The case says the revised contract "forbids removing ProvisionedThroughput".
  The first builder deleted the whole ProvisionedThroughput edit, which makes
  the removal out of scope (`template_change_outside_scope`) rather than a
  forbidden operation. The builder now narrows the edit's operations to
  `["replace"]`, which is what the summary describes; the expected
  `operation_not_allowed` is unchanged.
