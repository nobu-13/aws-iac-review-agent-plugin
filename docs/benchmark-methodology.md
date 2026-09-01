# Benchmark Methodology

This document defines what the benchmark measures, how each number is computed,
and what a given number does and does not license a reader to conclude. It is
the reference behind the figures `benchmark/harness/run_benchmark.py` prints.

> **Status.** Everything defined below as implemented is implemented: the twelve
> cases, the matching rule, the five measured metrics, the pass/fail rule, the
> four Source subset modes and both ways of applying one. Three metrics are
> defined here and deliberately not implemented in v0.1, and are marked as such.
> One check this document relies on is owed rather than done: see
> [Ground truth is authored first](#ground-truth-is-authored-first).

## This document and `benchmark/README.md`

Two documents describe the benchmark, and the split is deliberate rather than
incidental.

| | `benchmark/README.md` | `docs/benchmark-methodology.md` |
| --- | --- | --- |
| Audience | Someone running the benchmark or adding a case | Someone reading its output, or deciding whether to trust it |
| Sits next to | The cases it describes | The rest of the project's reference documentation |
| Owns | The CLI, the exit codes, the field-by-field `ground_truth.json` reference, the procedure for adding a case, the two rules a contributor must not break | The definitions with their symbols, the boundary conditions, the identities between metrics, the rounding behaviour, the deferred metrics, and the limits of the current measurement |
| Answers | "How do I run this, and what do I write in a case?" | "What does this number mean, and how far does it generalize?" |

Where both must state the same fact -- that severity is outside the match key,
for instance -- the README states it in one sentence and this document gives the
reason. Nothing is defined in both places with different words. `benchmark/README.md`
carries a pointer to this document, and this document points back for anything
operational.

The third source is the code: `benchmark/harness/metrics.py` is the whole of the
arithmetic, and its docstrings state the same seven decisions this document
explains. `tests/unit/test_metrics.py`, `tests/unit/test_run_benchmark.py` and
`tests/property/test_prop_benchmark.py` (Properties 30 and 31) pin them.

## What the benchmark measures

The benchmark and the test suite ask different questions, and the distinction is
the point of keeping them apart.

- `tests/` asks whether the plugin behaves as specified. A failure there is a
  defect.
- `benchmark/` asks how much of a known set of defects the review actually finds,
  and how much noise it produces alongside. A number there is a measurement.

A benchmark case is a directory holding a deliberately flawed -- or deliberately
clean -- CloudFormation template and a `ground_truth.json` stating what the
review is expected to report about it. The harness runs the review, matches its
Findings against those expectations, and reports counts, rates and a verdict.

Two properties make the measurement reproducible:

1. **The harness is deterministic.** It runs no agent. Agent Findings are never
   generated during a run; they are accepted only as a fixed fixture supplied
   with `--agent-findings`. Two runs over the same cases print byte-identical
   stdout.
2. **Nothing environment-dependent enters the output.** No timing, no absolute
   path, no tool version, and no Finding text. This is the same constraint the
   Review_Report is under (Requirement 16 AC11), and it is why Review Time is a
   deferred metric rather than an easy addition.

## Ground truth

### The format

`benchmark/ground_truth.schema.json`, written against JSON Schema draft 2020-12,
is the authority on the format, and `benchmark/README.md` documents it field by
field. Three decisions in it are methodological rather than operational.

**`authored_before_review` is a declaration, not a measurement.** Every case
carries `"authored_before_review": true`. Its meaning is the rule in the next
section; its verification is discussed there.

**`expected_findings_agent_only` and `expected_findings_human_review` are
reserved, present, and empty.** Both arrays are `required` and neither carries a
`maxItems` constraint (Requirement 11 AC12). A future `agent-only` or
`human-review` mode can populate them without changing the format of any
existing case, and without a schema change. In v0.1 they are always empty.

**The benchmark defines no vocabulary of its own.** `normalized_category`,
`finding_type`, `severity`, `confidence` and `detected_by` draw on the plugin's
closed sets, from `iacreview/category_map.json` and `iacreview/finding.py`. A
test fails if the schema and the plugin ever disagree, so the benchmark cannot
measure against a category the report cannot emit.

### Ground truth is authored first

**Expected values are written from the defects deliberately placed in the
template, before any review is run against it. Ground truth is never
reverse-engineered from review output** (Requirement 11 AC14, AC15).

This is the assumption every number in this document rests on. A
`ground_truth.json` produced by running the review and transcribing its output
measures nothing at all: detection rate becomes 100% by construction, and a
defect the review missed disappears from the expectations along with it, so the
one thing worth detecting is the one thing that cannot be. The order of work is
therefore fixed, and `benchmark/README.md` states it as a procedure.

The declaration cannot be verified from the file. Two weaker checks stand behind
it:

1. Review of a new case checks the declaration explicitly, against the case's
   `description` and its template.
2. CI checks that a case's `ground_truth.json` appears in the same commit as its
   `template.yaml`, or in an earlier one.

**The second check is not implemented.** Task 21.6 recorded it as owed, and it is
still owed: no CI workflow performs it today, so the commit-ordering evidence is
currently available to a human reviewer running `git log` and to nobody else.
This is a real gap in the guarantee, not a formality. Until it exists, the
declaration is worth exactly as much as the review that accepted it.

Neither check can establish the stronger claim, which is about intent rather than
about file timestamps. A contributor determined to work backwards can commit both
files together. The checks raise the cost of doing so accidentally, which is the
failure mode they are aimed at.

When a review disagrees with ground truth, the expectations are not edited to
match the output. The disagreement is classified first -- an implementation bug,
a mistake in the expectations, a gap in the requirements, agent
non-determinism, or a difference between external tool versions -- and only a
mistake in the expectations justifies editing `ground_truth.json`.

### Granularity

**One expected finding is one resource and one `Normalized_Category`.**

The granularity is not a stylistic choice about how to write expectations. It is
forced by deduplication, which merges Findings on exactly that pair: logical
resource ID plus `Normalized_Category` (Requirement 14). Two Sources reporting
the same category of problem on the same resource produce one Finding carrying
both Sources, not two Findings. The report is therefore incapable of emitting
more than one Finding per pair, and `expected_finding_count` counts at the same
granularity for the arithmetic below to mean anything.

The consequence worth stating explicitly: writing one expectation per underlying
defect would make a *correct* review look as though it had missed something. A
role whose inline policy grants `Action: "*"` on `Resource: "*"` and also carries
an unrestricted `iam:PassRole` is one expected finding in the `IAM` category, not
two -- the defects are two, the reportable finding is one.

Two classes of Finding are excluded from merging and so behave differently:
Findings in the `Other` category, and Findings with `"resource": null`. Ground
truth for those uses one entry per reported Finding.

## Matching

### The match key

A reported Finding counts as an expected one when the two agree on three fields:

```text
match_key(item) = (resource logical ID, FindingType, Normalized_Category)
```

A `"resource": null` expectation and a `Resource: null` Finding both compare as
the empty string in the first position, so a template-level expectation matches
by the rule rather than by both sides happening to stringify the same way.

Nothing else is compared. **Finding text is never compared as a string.**
Requirement 11 AC9 legislates this for `agent-dependent` expectations; the design
applies it to every expectation, so the benchmark holds exactly one notion of
"the same finding". Pinning wording would make every rephrasing read as a
regression while measuring nothing about detection.

### Why severity is outside the key

Severity is deliberately not part of the match key. It is measured separately, as
Severity Accuracy (Requirement 11 AC6).

If a severity mismatch made a Finding count as missed, a single mistake would be
charged twice: once against Detection Rate, because the problem would read as
undetected, and once against Severity Accuracy, because it was rated wrong. The
two metrics would stop being independent, and the more informative reading --
"the review found this and mis-rated it" -- would be indistinguishable from "the
review did not find this at all", which calls for a completely different fix.

With severity outside the key, detection is about whether the problem was seen
and severity accuracy is about whether it was rated correctly. The identity in
[Detection Rate and Recall](#detection-rate-and-recall-are-equal-here) is a
direct consequence.

Severity is compared for equality only, never ranked. Severity is comparable
across Findings only within one `FindingType` (Requirement 7 AC5), and the match
key already fixes `FindingType`, so a matched pair is always comparable -- but
nothing here needs a ranking, and introducing one would invite "close enough"
scoring, which Severity Accuracy is not.

### One-to-one matching and its tie-break

Matching is one to one: an expectation consumes at most one Finding, and a
Finding satisfies at most one expectation. Without this, one Finding could
satisfy several expectations sharing a match key and drive Detection Rate above
what was actually reported.

Duplicate match keys are unusual but possible, so the tie-break is fixed rather
than left to chance:

- **Expectations are consumed in the order `ground_truth.json` writes them.**
  Ground truth's array order is the tie-break, which is why editing that order is
  a semantic edit.
- **Findings within one match key are consumed in the order of their own
  canonical JSON**, not in report order. Report order is already deterministic
  (`report.sort_findings`), so this costs nothing in practice. It matters because
  Severity Accuracy asks a question about a *particular* matched Finding: with
  two candidates sharing a match key but differing in `Severity`, "whichever came
  first in the report" would make the metric an artefact of sort order.

Permuting the report therefore changes no metric. That is Property 30's
neighbourhood, and `tests/unit/test_metrics.py` pins the first-come consumption
on a fixture with duplicate keys.

### Per-case isolation

The pooled, top-level metrics prefix each resource with its case ID before
matching. Two cases using the same logical ID cannot satisfy each other's
expectations, which would otherwise turn a common name such as `DataBucket` into
a source of accidental matches across the whole suite.

## Metrics

### Symbols

For one evaluated set of expectations and one evaluated set of Findings -- both
already narrowed by `--mode` and, for a per-category figure, by category:

| Symbol | Meaning |
| --- | --- |
| `E` | Expectations under evaluation. Its size is written `\|E\|` |
| `A` | Findings under evaluation. Its size is written `\|A\|` |
| `TP` | Expectations matched one-to-one by a Finding |
| `FN` | `\|E\| - TP`. Expectations no Finding matched |
| `FP` | `\|A\| - TP`. Findings no expectation claimed |
| `SM` | Matched pairs whose reported `Severity` equals the expected `severity` |

### The five measured metrics

| Metric | Definition | Output | Requirement |
| --- | --- | --- | --- |
| Detection Rate | `TP / \|E\| * 100` | Percentage string, one decimal place | 11 AC5 |
| False Positive count | `FP` | Integer | 11 AC5 |
| Precision | `TP / (TP + FP) * 100` | Percentage string, one decimal place | 11 AC5 |
| Recall | `TP / (TP + FN) * 100` | Percentage string, one decimal place | 11 AC5 |
| Severity Accuracy | `SM / TP * 100` | Percentage string, one decimal place | 11 AC6 |

False Negative count (`FN`) is reported alongside them as an integer. The
steering rule's metric list names it, and a rate over three expectations and a
rate over three hundred read identically once formatted, so every count is
reported next to the percentage derived from it: `expected_count`,
`actual_count`, `matched_count`, `false_negative_count`, `false_positive_count`
and `severity_match_count`.

Reading them together:

- **Detection Rate** answers "of the defects we know are there, how many were
  reported?" It is the metric the pass/fail rule is built on.
- **False Positive count** and **Precision** answer "how much of what was
  reported was not asked for?" Precision is the rate; the count is what a reader
  needs in order to judge whether the rate is worth acting on.
- **Severity Accuracy** answers "of the defects that were reported, how many were
  rated as expected?" It is conditional on detection: a review that reports
  nothing has no severity accuracy, rather than a bad one.

### Boundary conditions

Every percentage has a denominator that can be zero, and every one of those cases
means something specific.

| Condition | Effect |
| --- | --- |
| `\|E\| == 0` | Detection Rate = `"N/A"`, Recall = `"N/A"`. Nothing was expected, so detection is not a question about this input |
| `TP + FP == 0` | Precision = `"N/A"`. No Finding was reported at all |
| `TP == 0` | Severity Accuracy = `"N/A"`. Nothing was detected, so nothing was rated |

**`"N/A"` means "not measured", and is distinct from `"0.0"`, which means
"measured, and nothing was found".** Collapsing the two would make a clean case
-- which expects nothing and finds nothing -- indistinguishable from a total
detection failure. The clean cases `case-101` and `case-102` are exactly this
situation: they report `"N/A"` for all four rates and `INFO` as their status.

### Rounding: one decimal place, half to even

Percentages leave the harness as **strings**, formatted with `"{:.1f}"`, never as
numbers. A float's repr is the one place where byte-identical output between runs
can quietly fail to hold, and a report containing `66.66666666666667` claims
precision the benchmark does not have.

`"{:.1f}"` rounds **half to even** -- banker's rounding -- so a value sitting
exactly on a boundary does not round the way a reader expecting "half up" would
predict:

| `TP` / `\|E\|` | Exact value | Formatted | Half-up would give |
| --- | --- | --- | --- |
| 1 / 16 | `6.25` | `"6.2"` | `"6.3"` |
| 3 / 16 | `18.75` | `"18.8"` | `"18.8"` |
| 5 / 16 | `31.25` | `"31.2"` | `"31.3"` |
| 7 / 16 | `43.75` | `"43.8"` | `"43.8"` |

The boundary is reachable only when the percentage is *exactly* representable as
a binary float with two decimal places, which for a denominator under 100 means a
denominator that is a multiple of 16. Every other ratio -- `2/3` giving
`66.66666666666666`, for instance -- is not on a boundary at all, and its
formatted value is decided by the float's actual value rather than by the
tie-break rule.

This is documented rather than corrected. A metric's third decimal place is not
information the benchmark claims to carry, and switching to `decimal` or to
explicit half-up rounding would add a dependency-free but non-trivial amount of
code to change a digit that no reader should be reading.

**The rounding never affects a verdict.** `category_status` compares the
unformatted float against `100.0`, and `100.0` is not a tie, so no pass or fail
turns on the last digit of a string. Property 31 asserts the threshold against
the float for this reason.

### Detection Rate and Recall are equal here

`FN` is defined as `|E| - TP`, so `TP + FN` is `|E|`, so:

```text
Recall = TP / (TP + FN) = TP / |E| = Detection Rate
```

**The two metrics are numerically equal in this design, always.** Requirement 11
AC5 asks for both, so both are reported, and `metrics.compute` computes Recall
from `TP / (TP + FN)` rather than aliasing it -- the definition is what is
implemented, and the equality is what follows.

The equality is a consequence of the matching rule, not a coincidence. It would
stop holding under a definition that counted "detected, but with the wrong
severity" as a false negative, because `FN` would then exceed `|E| - TP` while
Detection Rate stayed where it was. That is precisely the double penalty
[keeping severity out of the match key](#why-severity-is-outside-the-key) avoids,
so this design does not adopt it.

A reader comparing these figures against a benchmark from elsewhere should check
which definition that benchmark uses before treating its Recall as comparable to
this one.

## Pass and fail

The verdict is per `Normalized_Category`, and only `deterministic` expectations
are held to a threshold.

| Category contains | Rule | Status |
| --- | --- | --- |
| A `deterministic` expectation, all of them detected | Threshold applied and met | `PASS` |
| A `deterministic` expectation that was missed | Threshold applied and failed (Requirement 11 AC7) | `FAIL` |
| Only `agent-dependent` expectations | No threshold (Requirement 11 AC8) | `INFO` |
| Nothing measurable | No threshold to apply | `INFO` |

The threshold is 100%, not a tunable number. A `deterministic` expectation is one
reachable by cfn-lint, cfn-guard or deterministic IAM pattern matching, which
means it is reachable on every run or on none; anything less than complete
detection of that set is a regression with a specific cause, and a threshold
below 100% would be a decision to tolerate one.

`agent-dependent` expectations are measured and reported with no threshold, at
any detection rate. **Agent output is not deterministic, so a threshold on it
would make CI flaky rather than informative**: the same code would pass and fail
on alternate runs, and the signal would be discarded within a week. Requirement
11 AC8 makes this a requirement rather than a preference.

The `deterministic` subset is matched against the category's *whole* Finding set,
not against a subset of it. Nothing marks a Finding as deterministically reached,
and the question asked is whether the problem was reported at all.

Only detection numbers are restated for the `deterministic` subset. A precision
computed against a subset of the expectations would count every agent-dependent
detection as a false positive, which is not what precision means anywhere else.

### Clean cases carry the opposite expectation

A clean case (`case-101` upwards) expects nothing, so its Detection Rate is
`"N/A"` and its status is `INFO`. The claim being tested is the inverse one: a
review that reports a `HIGH` or `CRITICAL` Finding from a deterministic Source on
a correct template is producing false positives. `tests/negative/test_clean_templates.py`
asserts that, over the same case directories, using the false-positive counting
rule of Requirement 12 AC3-AC6 -- which is narrower than `FP` above, because it
excludes agent-only Findings and the `Informational`/`BestPractice` at `LOW`/`INFO`
classes. The two notions of a false positive differ deliberately and neither is
wrong: `FP` describes the whole report, because that is what precision is about.

## Exit codes 9 and 10

The harness reports its verdict as a process exit code, and two of its codes are
outside `iacreview/exitcodes.py`:

| Exit code | Name | Meaning |
| --- | --- | --- |
| 9 | `BENCHMARK_FAILURE` | A category failed: a `deterministic` expectation was not detected |
| 10 | `CASE_NOT_EVALUATED` | Nothing measured failed, but a case could not be evaluated, so the run is incomplete |

Codes 0, 1, 2, 3 and 7 are the plugin's own, imported from
`iacreview.exitcodes` so the harness cannot drift from them.

**Why 9 and 10 are not in the plugin's table.** That table enumerates the
plugin's failure classes -- invalid arguments, input not found, parse failure,
tool unavailable, tool execution failure, path violation, no reviewable template,
unexpected -- and `tests/unit/test_exitcodes.py` pins it closed at nine values.
A benchmark regression is not one of those classes. It is not a failure of the
plugin at all in the sense the table means: the plugin ran correctly and produced
a worse answer than it used to. Adding a tenth value to a table every entry point
shares, for a condition only the harness can reach, would make every Skill's
documented exit codes include one it can never return.

The distinction CI needs is between "the review got worse" and "the plugin
crashed", and separate numeric ranges are what make that legible in a build log
without parsing stdout. 10 is separate from 9 for the same reason one level down:
an unevaluated case is usually a fact about the environment -- an absent external
tool, a case directory that is not readable -- and calling for a different
response than a genuine regression.

## Source subset modes

Requirement 11 AC10 and AC11 ask for measurement restricted to one Source. A
single-Source mode narrows the measurement from both sides at once: only that
Source's expectations are evaluated, filtered on `detected_by`, and only Findings
carrying that Source are counted, filtered on the Finding's `Source` list. A
Finding several Sources reached carries all of them, so it stays in scope in each
of their modes.

| `--mode` | Sources | Expectations evaluated |
| --- | --- | --- |
| `combined` (default) | cfn-lint, cfn-guard, IAM Review | All |
| `cfn-lint-only` | cfn-lint | Those whose `detected_by` names cfn-lint |
| `cfn-guard-only` | cfn-guard | Those whose `detected_by` names cfn-guard |
| `iam-only` | IAM Review | Those whose `detected_by` names IAM Review |

### `--filter-only`, and why the two paths agree

A mode can be applied at two different points, and the two answer subtly
different questions:

- **By default**, the mode is applied twice: the review is started with that
  Source alone, and its result is filtered to that Source as well. What is
  measured is the Source **in isolation**, as a user running only that Source
  would see it.
- **With `--filter-only`**, the mode is applied once, to the result. The review
  runs with every Source enabled, exactly as `combined` does, and only the filter
  narrows it. What is measured is the Source's **contribution to a full review**,
  and one review per case then serves every mode.

They produce identical numbers, because a Finding keeps every Source that reached
it and merging never discards one. That is what makes per-Source attribution
usable after the fact, which is Requirement 11 AC10.

The equality is measured rather than assumed. `tests/integration/test_benchmark_harness.py`
compares the two paths over the real cases; a disagreement would mean one of them
is wrong about what a Source contributes, which is a fact about the pipeline
rather than about the harness. Measured over the twelve cases, on the versions in
[Current measurement](#current-measurement):

| `--mode` | Default path | `--filter-only` | Status |
| --- | --- | --- | --- |
| `cfn-lint-only` | 0 / 0 expectations, `N/A` | 0 / 0 expectations, `N/A` | `INFO`, no expectations |
| `cfn-guard-only` | 17 / 17 | 17 / 17 | `PASS` |
| `iam-only` | 5 / 5 | 5 / 5 | `PASS` |
| `combined` | 21 / 21 | 21 / 21 | `PASS` |

`--filter-only` has no effect on `combined`, which enables every Source either
way. It is accepted there rather than refused, so a sweep over the modes needs no
special case.

### The absent-tool asymmetry

The two paths differ in one way, and it is not in the numbers. **When an external
tool is absent, the two report the same missing detections under different exit
codes, and only one of them is honest about the cause.**

| | Default path | `--filter-only` |
| --- | --- | --- |
| What happens | The single-Source review has nothing able to run, so the review fails | The review succeeds; the absent tool's Findings are simply not in it |
| What the harness records | The case is unevaluated | The Source's expectations are unmatched |
| Exit code | 10, `CASE_NOT_EVALUATED` | 9, `BENCHMARK_FAILURE` |
| How CI reads it | An incomplete run, attributed to the environment | A regression |

The `--filter-only` reading is wrong about the cause, and it is wrong in the
direction that wastes a maintainer's time: a red build blaming the review for
something the environment did. Two things mitigate it, neither of which changes
the exit code. The harness names the absent tool on stderr for that case, and the
summary's `filter_only` field records which path produced the numbers, so the
combination of exit 9 and `"filter_only": true` is identifiable after the fact.

The practical guidance: **treat exit 9 from a `--filter-only` run as
inconclusive until the tools on PATH are confirmed.** The default path is the one
to trust for a verdict, and `--filter-only` is for a sweep across modes where the
tools are known to be present.

## Deferred metrics

Three metrics the steering rule lists were defined here and not implemented in
v0.1. **v0.8.0 implemented two of them as diagnostics** (Requirement 19 AC3);
one remains deferred from the summary because it cannot enter a byte-identical
document. `metrics.DEFERRED_METRICS` names the one that remains, and a test
asserts its name appears both there and in `benchmark/README.md`.

All three are **diagnostics**: they are reported and never turned into a PASS or
FAIL, so they leave the pass/fail contract and the deterministic Sources'
reproducibility untouched (Requirement 19 AC7). The two implemented ones appear
in the summary under `diagnostics`, per case and in aggregate; a case that
declares no expectation for one records it as `N/A` rather than `0` or an absent
key (Requirement 19 AC6), so the block is the same shape whatever the cases
declared.

### Review Time

Still deferred from the summary.

**Definition.** Wall-clock time to review one template, with the deterministic
phase and the agent phase measured separately, since only one of them is under
the plugin's control.

**Why it stays out of the summary.** It is the one metric that cannot enter the
harness's stdout at all. Review Time is environment-dependent by construction --
it varies with the machine, the Python version, the external tool versions, and
the load on the box -- and both the Review_Report and the benchmark summary must
stay byte-identical between runs over the same input (Requirement 16 AC11). A
timing figure in stdout would break that on the first run. So v0.8.0 measures it
and reports it on **stderr** (a verbose diagnostic), the second output stream
design.md's Determinism Design reserves for environment-dependent metadata, and
never in stdout (Requirement 19 AC2). It is measured, not omitted; it is simply
kept off the byte-identical channel.

### Remediation Accuracy

Implemented as a diagnostic in v0.8.0.

**Definition.** The share of matched Findings whose `SuggestedRemediation`
satisfies the case's declared remediation expectation. The match is a
case-insensitive substring test rather than string equality, so a report that
phrases the remediation more fully than the expectation still counts -- the same
reason Finding text is never compared verbatim.

**How it is computed.** From the ground truth alone, so it is deterministic and
belongs in the byte-identical summary. An expectation declares its remediation in
an optional `expected_remediation` field; a case that declares none records
`remediation_accuracy: "N/A"`. Every v0.1 case declares none, so the figure is
`N/A` throughout until a case opts in. Read Only by default is untouched: nothing
is patched or re-reviewed, unlike the second-review-pass design once sketched
for it.

The **aggregate** Remediation Accuracy is the unweighted mean of the per-case
rates that are not `N/A`, not a pool of the underlying cleared/declared counts.
A case declaring one remediation and a case declaring ten therefore weigh
equally in the aggregate. This is a deliberate choice -- the diagnostic answers
"how well does the review remediate a typical case?" rather than "how many
individual remediations were right?" -- and it is stated here because the two
readings give different numbers. Human Intervention Count aggregates differently
(it sums the declared counts) because a count is additive across cases in a way a
rate is not.

### Human Intervention Count

Implemented as a diagnostic in v0.8.0.

**Definition.** The number of human decisions a case declares it needs.

**How it is computed.** A property of a review *session*, so it is a per-case
declaration rather than something read off the findings: an optional top-level
`expected_human_intervention_count` field. The diagnostic echoes the declared
count and the aggregate sums the declared counts; a case that declares none
records `human_intervention_count: "N/A"`. Every v0.1 case declares none. This is
a recording of a stated expectation, not an instrumented measurement of a live
workflow, which keeps it deterministic and CI-friendly.

## Modes and repeat runs

v0.8.0 adds two `--mode` values that read the reserved ground-truth arrays
without a schema-version bump (Requirement 19 AC1). `agent-only` measures the
Agent Review Source, reading `expected_findings_agent_only`. `human-review`
reads `expected_findings_human_review` and is informational: it names findings
the pipeline is not expected to produce, so it is never held to a threshold and
cannot make a run fail. Both reserved arrays are empty in every v0.1 case, so
both modes measure nothing there.

`--agent-runs N` reviews each case N times and reports the Agent Source's
variation across runs as a stderr diagnostic (Requirement 19 AC4) -- the v0.2
candidate below, now available as an opt-in diagnostic. The deterministic
Sources are still evaluated exactly once per case: only `agent-only` repeats, and
the summary is computed from the first run, so the deterministic benchmark output
stays reproducible (Requirement 19 AC7).

## cfn-lint contribution series

`benchmark/cfn-lint-contribution/` measures how many findings cfn-lint
contributes, pinned to a stated cfn-lint version, and reports the count
informationally -- never thresholded (Requirement 19 AC5). It is kept apart from
the ground-truth cases so their pass/fail contract does not depend on the
installed cfn-lint rule catalogue, which gains rules between releases. Its output
records the cfn-lint version the counts were produced against, the one
environment value the series exists to measure; everything else that varies by
host is kept out, so two runs against one cfn-lint version print the same bytes.

## Bounding agent non-determinism

The harness is deterministic because it never invokes an agent. That resolves
reproducibility and leaves the question it was standing in for unanswered:
**this benchmark does not measure the Agent Semantic Review layer's detection
ability at all.**

What v0.1 does:

- `agent-dependent` expectations are evaluated and reported with no threshold
  (Requirement 11 AC8).
- Agent Findings enter only through `--agent-findings <dir>`, as one fixed file
  per case. A fixture is a recording of one agent run, so a figure computed from
  it describes that recording, not the agent.
- Without a fixture, a case's `agent-dependent` expectations are reported as
  undetected. Since no threshold applies, this lowers no verdict -- but it does
  mean a `combined` run's headline Detection Rate is a statement about the
  deterministic Sources only.

The v0.2 candidate, recorded here rather than implemented (design.md, O-9):
**run the agent over each case N times and report the variation, not a point
estimate.** A per-case detection rate would become a range or a distribution over
N runs, and the reported figure would carry N alongside it. This measures the
agent's stability as well as its accuracy, which is the property that actually
matters for a review tool -- an agent that finds a defect one run in three is a
different proposition from one that finds it every time, and a single run cannot
tell them apart. It stays out of v0.1 because it needs a decision about where the
N runs happen (not in CI, which must stay deterministic and cheap) and about how
a distribution is reported without breaking byte-identical output.

Until then, the honest reading of an `agent-dependent` figure in this benchmark is
that it describes a fixture.

## Current measurement

Measured by running the harness over the twelve cases in this repository. These
figures are a snapshot for orientation, not a contract: the pass/fail rule is the
contract, and it is asserted by the test suite.

| Item | Value |
| --- | --- |
| Cases | 12 (`case-001` to `case-010` defect, `case-101` and `case-102` clean) |
| Expectations, `combined` | 21, all `deterministic` |
| Expectations by Source | 17 name cfn-guard, 5 name IAM Review, 1 names both, 0 name cfn-lint |
| Categories exercised | 7: `Backup`, `Encryption`, `IAM`, `Logging`, `NetworkSecurity`, `PublicAccess`, `Tagging` |
| Python | 3.9.6 |
| cfn-lint | 1.46.0 |
| cfn-guard | 3.2.1 |

```text
python3 benchmark/harness/run_benchmark.py --cases benchmark/cases --mode combined
```

| Mode | `TP` / `\|E\|` | `\|A\|` | `FP` | Detection Rate | Precision | Severity Accuracy | Status | Exit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `combined` | 21 / 21 | 21 | 0 | `"100.0"` | `"100.0"` | `"100.0"` | `PASS` | 0 |
| `cfn-guard-only` | 17 / 17 | 17 | 0 | `"100.0"` | `"100.0"` | `"100.0"` | `PASS` | 0 |
| `iam-only` | 5 / 5 | 5 | 0 | `"100.0"` | `"100.0"` | `"100.0"` | `PASS` | 0 |
| `cfn-lint-only` | 0 / 0 | 0 | 0 | `"N/A"` | `"N/A"` | `"N/A"` | `INFO` | 0 |

All seven categories are `PASS`; both clean cases are `INFO` with `"N/A"` across
the board and no Finding of any kind. `errors` is empty. Every figure above is
identical with and without `--filter-only`.

**What 100.0 across the board does and does not mean.** It means every defect
these twelve templates were built around is currently detected, at the expected
severity, with no undeclared Finding alongside. It is a regression baseline: any
future change that stops one of these detections turns a category `FAIL` and the
exit code 9. It does **not** mean the review detects defects of these categories
in general, and it does not mean the review is free of false positives on
arbitrary templates. See the limitations below.

## Known limitations

### The sample is twelve cases

Ten defect cases and two clean ones, covering the ten categories Requirement 11
AC2 enumerates at roughly one case each.

What this licenses: a claim that a specific detection worked on a specific
template, and a regression signal when it stops working. That is the benchmark's
primary job, and twelve cases do it.

What it does not license: any statement about detection rate on templates the
project did not write, any per-category rate with meaningful precision -- a
category with two expectations moves in 50-point steps -- or any conclusion about
false positive rate, which is measured on two clean templates. A published
"100% detection rate" from this suite would be a statement about twelve files.

### `cfn-lint-only` measures nothing

No expectation in any case names cfn-lint in `detected_by`, so the
`cfn-lint-only` mode evaluates an empty expectation set: `"N/A"` for every rate,
`INFO` status, exit 0. The mode runs and reports; it just has nothing to report
about.

This is deliberate, and the reason is worth stating because the alternative looks
attractive. A cfn-lint expectation would tie the case's pass/fail to the
**installed cfn-lint rule catalogue** rather than to the rule the case exists to
measure. cfn-lint's catalogue changes between releases -- a new informational
rule, a changed level, a rule split in two -- and any of those would flip a case
that is nominally about, say, backup retention. Since a case may report nothing
its ground truth does not declare, the coupling would run both ways: the case
would fail either for missing a cfn-lint Finding it no longer produces, or for
producing one the ground truth does not list.

cfn-lint's normalization is therefore covered elsewhere, and covered thoroughly:
`tests/unit/` pins the exit-code decoding, the rule-ID-to-category mapping, the
level-to-severity mapping and the `blocks_deployment` / `security_relevant`
classifications against fixtures, and `tests/integration/` runs cfn-lint over the
`examples/` templates. What is missing is only the benchmark's kind of evidence:
an end-to-end measurement of how much of a known defect set cfn-lint contributes.

**Owed to the roadmap** (Task 21.3 raised it): a way to measure cfn-lint's
contribution without coupling a case to the catalogue. The plausible shape is a
separate case series pinned to a stated cfn-lint version, evaluated `INFO` rather
than thresholded, so a catalogue change shows up as a changed measurement instead
of a failed build.

### One rule clause is not exercised

`rules/backup/rds_backup_retention.guard` has two clauses: `BackupRetentionPeriod`
must exist, and where it exists it must be at least 7. `case-006-missing-backup`
exercises the second, twice -- a value of `0` and a value of `3` -- and not the
first.

Omitting an absent `BackupRetentionPeriod` from any case is deliberate: it draws
an informational cfn-lint Finding (`I3013`), and a case may report nothing its
ground truth does not declare, so covering that clause would tie `case-006` to
the cfn-lint catalogue in exactly the way the previous limitation describes.

**Nothing else exercises the clause either.** `tests/unit/test_guard_rules.py`
checks the rule file structurally -- that it declares one rule, names it after
the file, carries a custom message and parses under cfn-guard -- which
establishes that the clause is syntactically live, not that it fires. No test or
case currently presents cfn-guard with an RDS instance declaring no
`BackupRetentionPeriod` at all. This is a genuine coverage gap, recorded rather
than closed: closing it needs a home for a template that draws a cfn-lint
informational Finding on purpose, which is the same missing piece the
`cfn-lint-only` limitation describes.

### The clean cases cannot exercise the false-positive rule's branches

`case-101` and `case-102` produce **no Finding of any class**. That is the
strongest possible outcome for a negative test, and it means those two cases
cannot distinguish "excluded from the false positive count" from "counted": there
is nothing there to classify.

The branches of the counting rule are therefore covered without a case.
`tests/negative/test_clean_templates.py` walks the whole `FindingType` x
`Severity` grid with **synthetic** Findings, so all twenty combinations are
pinned rather than the handful real output happens to reach, and it hands real
output from three non-clean inputs -- `case-007` (`BestPractice` + `LOW`),
`case-010` (`BestPractice` + `MEDIUM`) and an IAM fixture reporting
`Informational` + `INFO` coverage gaps -- to the counter with a deliberately
empty expectation set, which isolates the classification decision from the
detection question those inputs were built to ask.

Synthetic coverage is weaker than a case: it establishes that the rule classifies
correctly, not that a real review ever produces the class. The three real inputs
close most of that gap, and what remains open is that no *clean* template in this
repository produces a Finding at all, so the rule's exclusion has never had to
protect one.

### The measurement depends on external tool versions

Every figure in [Current measurement](#current-measurement) was produced with
cfn-lint 1.46.0 and cfn-guard 3.2.1. A different version can change what is
reported, and the benchmark has no mechanism to pin either: both are found on
PATH (Requirement 15 AC1 forbids bundling them). Requirement 10 AC3 places
version differences outside the plugin's compatibility guarantee. When a figure
here disagrees with a local run, the installed tool versions are the first thing
to compare.

### Agent detection is unmeasured

See [Bounding agent non-determinism](#bounding-agent-non-determinism). Every
expectation in the current cases is `deterministic`, so no figure in this
repository describes agent detection at all -- not even badly.
