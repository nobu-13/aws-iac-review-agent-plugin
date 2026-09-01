# cfn-lint contribution measurement series

This directory is a measurement series, not a set of ground-truth cases. It
records how many findings cfn-lint contributes to a review, pinned to a stated
cfn-lint version, and reports the number **informationally**: it is never turned
into a PASS or FAIL (Requirement 19 AC5).

## Why it is separate from `benchmark/cases/`

The ground-truth cases under `benchmark/cases/` have a pass/fail contract that
must not depend on which cfn-lint rule catalogue happens to be installed. cfn-lint
ships new rules between versions, so counting its raw findings as a threshold
would make the same template pass on one machine and fail on another. That
measurement still has value -- it says how much cfn-lint is finding over time --
so it lives here, apart from the contract, and is only ever reported.

## What it measures

`run_contribution.py` reviews every template in `templates/` with the cfn-lint
Source alone (`iacreview.cfnlint.run_and_normalize`) and prints one JSON document
on stdout:

- the cfn-lint version the numbers were produced against, so a later run can tell
  a rule-catalogue change from a template change;
- per template and in aggregate, the count of findings cfn-lint reported, broken
  down by severity;
- never a threshold, never a pass/fail verdict. The exit status is `0` on a
  successful measurement and non-zero only when cfn-lint could not be run at all.

## Running it

```
python3 benchmark/cfn-lint-contribution/run_contribution.py \
    --templates benchmark/cfn-lint-contribution/templates
```

cfn-lint must be installed and on `PATH`. When it is absent the series cannot be
measured, and the script says so on stderr and exits non-zero -- it does not
report a zero contribution, which would be indistinguishable from a review that
found nothing.

## Determinism

The stdout document is a function of the templates and the installed cfn-lint
version alone. It carries no wall-clock time, no absolute host path, and no other
environment-dependent value, the same contract the ground-truth harness's stdout
holds (Requirement 16 AC11). The pinned cfn-lint version *is* in the output, on
purpose: it is the one environment value the series is measuring.
