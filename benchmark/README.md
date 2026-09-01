# Benchmark

This directory measures review quality. It is not part of the test suite: the
tests under `tests/` ask whether the plugin behaves as specified, while the
benchmark asks how much of a known set of defects the review actually finds, and
how much noise it produces on top.

Each case is a directory holding a template and the expected outcome for it:

```text
benchmark/
  ground_truth.schema.json          the format of every ground_truth.json
  cases/
    case-001-iam-wildcard/
      template.yaml                 a syntactically valid template with deliberate defects
      ground_truth.json             what the review is expected to report
    ...
    case-101-clean-web-tier/        a clean template, used as a negative case
    case-102-clean-data-tier/
  harness/                          runner and metric computation
```

> **Status.** The runner, the metric computation, the ten defect cases and the two
> clean cases are in place, as are both ways of measuring one Source
> (`--filter-only`). The assertion that the clean cases stay quiet arrives with
> Task 24.4. Cases are discovered from the filesystem, so a case added later is
> measured without editing the harness.

This file is the operator's guide: how to run the benchmark, what each option and
exit code does, what every field of a `ground_truth.json` means, and how to add a
case. `docs/benchmark-methodology.md` is the methodology reference next to it: the
metric definitions with their symbols and boundary conditions, why the matching
rule is shaped the way it is, the rounding behaviour, the deferred metrics, and
what the current twelve-case measurement does and does not license a reader to
conclude. Facts both files need are stated in one sentence here and explained
there, rather than defined twice.

## Running it

```sh
python3 benchmark/harness/run_benchmark.py --cases benchmark/cases --mode combined
```

Run it from the repository root: the working directory is the workspace root, and
every path the harness is given is resolved inside it. One JSON document goes to
stdout, human-readable diagnostics go to stderr, and the exit code is the verdict.

| Option | Meaning |
| --- | --- |
| `--cases DIR` | Directory of case directories. Every subdirectory holding a `ground_truth.json` is one case; anything else is ignored. Required. |
| `--mode MODE` | `combined` (default), `cfn-lint-only`, `cfn-guard-only`, or `iam-only`. See below. |
| `--filter-only` | Select the mode's Source by filtering a full review instead of also disabling the other Sources at review time. One review per case for a sweep over several modes. See below. |
| `--agent-findings DIR` | Directory of fixed agent finding fixtures, one `<case_id>.json` per case. |
| `--verbose` | More diagnostics on stderr. Never changes stdout. |

| Exit code | Meaning |
| --- | --- |
| 0 | Every category passed or was informational, and every case was evaluated |
| 1 | A bug in the harness, or an incomplete plugin directory |
| 2 | A missing, unknown, or unsafe argument |
| 3 | `--cases` or `--agent-findings` does not exist |
| 7 | A path resolved outside the workspace root |
| 9 | A category failed: a `deterministic` expectation was not detected |
| 10 | Nothing measured failed, but a case could not be evaluated, so the run is incomplete |

9 and 10 are outside the plugin's own exit code table on purpose. A benchmark
regression is not one of the plugin's failure classes, and CI has to be able to
tell "the review got worse" from "the plugin crashed".

Two runs over the same cases print byte-identical stdout. Nothing
environment-dependent goes into it: no timing, no absolute path, no tool version,
and no message from the review. A degraded review -- one whose external tool was
missing -- is reported on stderr, and its missing findings show up as missed
expectations.

### Source subset modes

A single-Source mode narrows the measurement from both sides: only that Source
runs, only the expectations attributing themselves to it are evaluated, and only
the findings carrying it are counted. A finding that several Sources reached
carries all of them, so it stays in scope in each of their modes.

| `--mode` | Sources enabled | Expectations evaluated |
| --- | --- | --- |
| `combined` | cfn-lint, cfn-guard, IAM Review | all of them |
| `cfn-lint-only` | cfn-lint | those whose `detected_by` names cfn-lint |
| `cfn-guard-only` | cfn-guard | those whose `detected_by` names cfn-guard |
| `iam-only` | IAM Review | those whose `detected_by` names IAM Review |

### Two ways to measure one Source

A single-Source mode applies the mode twice by default: the review is started with
that Source alone, and its result is filtered to that Source as well. What is
measured is the Source **in isolation**, the way a user running only that Source
would see it.

`--filter-only` applies the mode once, to the result. The review runs with every
Source enabled, exactly as `combined` does, and only the filter narrows it. What is
measured is the Source's **contribution to a full review**, and one review per case
serves every mode:

```sh
for mode in cfn-lint-only cfn-guard-only iam-only combined; do
  python3 benchmark/harness/run_benchmark.py --cases benchmark/cases \
    --mode "$mode" --filter-only
done
```

The two produce identical numbers, because a finding keeps every Source that
reached it. `tests/integration/test_benchmark_harness.py` measures the equality over
the real cases rather than assuming it: a disagreement would mean one of the two is
wrong about what the Source contributes, which is a fact about the pipeline.

They differ in one way, and it is not in the numbers. When cfn-lint or cfn-guard is
absent, the default path leaves its single-Source review with nothing able to run,
the review fails, and the case is recorded unevaluated -- exit 10, attributed to the
environment. `--filter-only` gets a successful review from which that Source is
simply missing, so its expectations read as missed -- exit 9, which is the code for
a regression. The harness names the absent tool on stderr for that case, and the
summary's `filter_only` field records which path produced it. `--filter-only` has no
effect on `combined`, which enables every Source either way; it is accepted there
rather than refused, so a sweep over the modes needs no special case.

### Agent findings

Agent findings are never generated during a benchmark run. They are read from
`--agent-findings <dir>` as one fixed file per case, named after the case
directory, holding either a JSON array of findings or an object with a `findings`
key. Without a fixture, a case's `agent-dependent` expectations are simply
reported as undetected, which no threshold applies to.

### The output

```text
{
  "schema_version": "1.0.0",
  "mode": "combined",
  "sources_evaluated": ["cfn-lint", "cfn-guard", "IAM Review"],
  "filter_only": false,
  "agent_findings_supplied": false,
  "cases": [ { "case_id": ..., "metrics": {...}, "categories": {...}, "status": ... } ],
  "metrics": {...},
  "categories": {...},
  "status": "PASS",
  "errors": []
}
```

The top-level `metrics` and `categories` pool every evaluated case, with each
resource prefixed by its case ID so that two cases using the same logical ID
cannot satisfy each other's expectations. `errors` lists the cases that were not
evaluated, each as a case ID and one of `unsafe_case_path`,
`malformed_ground_truth`, `missing_template` or `review_failed`. A broken case is
recorded and skipped; the remaining cases are still measured.

## Methodology rules

Two rules decide whether the numbers this directory produces mean anything.
Both are stated here because both are easy to break by accident and neither is
fully machine-checkable.

### Ground truth is not derived from review output

**Expected values are defined first, from the defects deliberately placed in the
template. Ground truth is never reverse-engineered from what a review reported.**

A `ground_truth.json` written by running the review and transcribing its
findings measures nothing: detection rate becomes 100% by construction, and a
missed defect disappears from the expectations along with it. The order of work
is therefore fixed:

1. Decide which defects the case is about, and write them into `template.yaml`.
2. Write `ground_truth.json` from that intent, naming the resource, category,
   type and severity each defect should surface as.
3. Only then run the review, and treat any disagreement as a finding about the
   plugin, the expectations, or the requirements, to be resolved deliberately.

Every case declares `"authored_before_review": true`. The declaration cannot be
verified from the file, so two weaker checks stand behind it: CI requires
`ground_truth.json` to appear in the same commit as its `template.yaml` or in an
earlier one, and review of a new case checks the declaration explicitly.

When a review disagrees with ground truth, the expectations are not edited to
match the output. The disagreement is classified first: an implementation bug, a
mistake in the expectations, a gap in the requirements, agent non-determinism, or
a difference between external tool versions. Only a mistake in the expectations
justifies editing `ground_truth.json`, and the reason belongs in the commit
message.

### One finding is one resource and one category

**The report's granularity is one finding per resource per
`Normalized_Category`,** because deduplication merges findings on exactly that
pair: logical resource ID plus `Normalized_Category`. Two Sources reporting the
same category of problem on the same resource produce one finding carrying both
Sources, not two findings.

Ground truth is written at that same granularity, and `expected_finding_count`
counts at it:

- A bucket that is both unencrypted and publicly readable is **two** expected
  findings: one `Encryption`, one `PublicAccess`.
- A role whose inline policy grants `Action: "*"` on `Resource: "*"` and an
  unrestricted `iam:PassRole` is **one** expected finding on that role in the
  `IAM` category, listing every Source expected to reach it, not one entry per
  statement.
- A template-level problem belonging to no single resource is one entry with
  `"resource": null`.

Writing one entry per underlying defect instead would make a correct review look
as though it had missed something, since the report can only ever emit one
finding for the pair.

Two categories are excluded from merging and so behave differently: findings in
the `Other` category and findings with `"resource": null` always stay separate in
the report. Ground truth for those still uses one entry per reported finding.

## The Ground_Truth format

`ground_truth.schema.json` is written against **JSON Schema draft 2020-12**. The
draft is chosen deliberately: it is the current IETF draft, it is what the design
document specifies for this file, `$defs` and `$ref` cover everything this format
needs, and the vocabulary used here (`type`, `enum`, `const`, `required`,
`additionalProperties`, `pattern`, `minItems`, `uniqueItems`) is supported by
every draft-07-or-later validator, so the file can be checked by whatever tool a
contributor already has.

The plugin does **not** depend on a JSON Schema validation library. Runtime
dependencies stay at PyYAML alone, and the tests validate ground truth against
this schema with a small checker written on the standard library. The schema is
therefore also a document: each field carries a `description` explaining why it
exists.

### Case fields

| Field | Meaning |
| --- | --- |
| `schema_version` | Version of this format. Independent of the plugin version and of the report's `schema_version`. |
| `case_id` | Equal to the case directory name. `case-001` to `case-099` are defect cases; `case-101` upwards are clean cases. |
| `template` | Template file name, relative to the case directory. No path separators. |
| `description` | The template's contents and its deliberate defects, in prose. |
| `authored_before_review` | Always `true`. See the methodology rule above. |
| `expected_finding_count` | Number of entries in `expected_findings`, counted at one-resource-one-category granularity. |
| `expected_findings` | The expectations themselves. |
| `expected_findings_agent_only` | Reserved for a future mode. Present and empty in v0.1. |
| `expected_findings_human_review` | Reserved for a future mode. Present and empty in v0.1. |

The two reserved arrays are `required` so that adding a benchmark mode later
does not change the format of existing cases, and they carry no `maxItems`
constraint so that such a mode can populate them without a schema change.

### Expected finding fields

| Field | Meaning |
| --- | --- |
| `resource` | Logical ID the finding is about, or `null` for a template-level finding. |
| `normalized_category` | Expected `Normalized_Category`. |
| `finding_type` | Expected `FindingType`. |
| `severity` | Expected `Severity`. |
| `confidence` | Expected `Confidence`. Optional; see below. |
| `detection_class` | `deterministic` or `agent-dependent`. |
| `detected_by` | Sources expected to report the finding. |
| `note` | Which defect in the template this entry stands for. |

The vocabularies for `normalized_category`, `finding_type`, `severity`,
`confidence` and `detected_by` are the plugin's own closed sets, from
`iacreview/category_map.json` and `iacreview/finding.py`. The benchmark defines
no vocabulary of its own, and a test fails if the schema and the plugin ever
disagree.

`confidence` is optional because it follows from `detection_class`: a
deterministic finding is `Confirmed`, and an agent-dependent one is at best
`Likely`, since `Confirmed` is closed to agent reasoning. State it when the case
means to pin it. Together with `finding_type` it expresses the four classes of
finding the project distinguishes:

| Class | Expressed as |
| --- | --- |
| Confirmed issue | `confidence: "Confirmed"` |
| Likely risk | `confidence: "Likely"` |
| Contextual recommendation | `confidence: "Contextual"` |
| Informational | `finding_type: "Informational"` |

### Example

```json
{
  "schema_version": "1.0.0",
  "case_id": "case-001-iam-wildcard",
  "template": "template.yaml",
  "description": "An IAM role with a policy granting Action \"*\" on Resource \"*\", plus an unrestricted iam:PassRole statement.",
  "authored_before_review": true,
  "expected_finding_count": 2,
  "expected_findings": [
    {
      "resource": "AdminRole",
      "normalized_category": "IAM",
      "finding_type": "Security",
      "severity": "CRITICAL",
      "detection_class": "deterministic",
      "detected_by": ["IAM Review", "cfn-guard"],
      "note": "Action \"*\" with Resource \"*\" in the inline policy."
    },
    {
      "resource": "DeployRole",
      "normalized_category": "IAM",
      "finding_type": "Security",
      "severity": "CRITICAL",
      "detection_class": "deterministic",
      "detected_by": ["IAM Review"],
      "note": "iam:PassRole with Resource \"*\"."
    }
  ],
  "expected_findings_agent_only": [],
  "expected_findings_human_review": []
}
```

## How expectations are matched

A reported finding counts as the expected one when the two agree on **resource
logical ID, `FindingType` and `Normalized_Category`**. Nothing else is compared,
and finding text is never compared as a string.

Severity is deliberately outside the match key. If a severity mismatch made a
finding count as missed, the same mistake would lower detection rate and severity
accuracy at once; keeping it out means detection is about whether the problem was
seen and severity accuracy is about whether it was rated correctly.

Matching is one to one. When several expectations share a match key, actual
findings are consumed in the order the expectations are written, so the result
does not depend on the order the review happens to emit findings in.

A finding with `"resource": null` matches on the empty string in the first
position.

## Metrics

The metrics below are computed from the fields above, by `harness/metrics.py`.
Percentages are emitted as strings with one decimal place, so that
floating-point formatting cannot make two runs differ, and as `"N/A"` where the
denominator is zero.

| Metric | Definition |
| --- | --- |
| Detection Rate | matched expectations / all evaluated expectations |
| Recall | matched expectations / (matched + missed) |
| Precision | matched findings / all evaluated findings |
| False Negative | expectations with no matching finding |
| False Positive | findings matching no expectation |
| Severity Accuracy | matched findings whose severity equals the expectation / matched findings |

Detection Rate and Recall are numerically equal under these definitions, because
a detected finding with the wrong severity is not counted as a false negative.
Both are reported because both are asked for; the equality is a consequence of
the matching rule, not a coincidence, and `docs/benchmark-methodology.md` records
it.

Three further metrics were defined but not computed in v0.1. v0.8.0 implemented
two of them as diagnostics (Requirement 19 AC3); one remains deferred, because
it cannot enter a byte-identical document:

| Metric | Definition | Status |
| --- | --- | --- |
| Review Time | Wall-clock time to review one template, deterministic and agent phases separated | Deferred from the summary. Measured and reported on **stderr** (a verbose diagnostic), never in stdout, which must stay byte-identical between runs. |
| Remediation Accuracy | Share of matched findings whose `SuggestedRemediation` satisfies the case's declared remediation expectation | Implemented as a diagnostic. `N/A` for a case declaring no `expected_remediation`, which is every v0.1 case. Never affects PASS or FAIL. |
| Human Intervention Count | Number of human decisions a case declares it needs | Implemented as a diagnostic. `N/A` for a case declaring no `expected_human_intervention_count`, which is every v0.1 case. Never affects PASS or FAIL. |

Both implemented diagnostics appear in the summary under `diagnostics`, per case
and in aggregate, and are also present on each case entry. A case that declares
neither expectation records both as `N/A` (Requirement 19 AC6), so the block is
the same shape whatever the cases measured.

### Modes

`--mode` selects which Source is measured. Beyond the four Source-subset modes
(`combined`, `cfn-lint-only`, `cfn-guard-only`, `iam-only`), v0.8.0 adds two that
read the reserved ground-truth arrays (Requirement 19 AC1):

| Mode | Measures | Expectation array | Thresholded |
| --- | --- | --- | --- |
| `agent-only` | The Agent Review Source alone | `expected_findings_agent_only` | Yes |
| `human-review` | Expectations only a human reviewer is expected to reach | `expected_findings_human_review` | No (informational) |

`human-review` is never held to a threshold: its expectations name findings the
pipeline is not expected to produce, so it reports `INFO` and cannot make a run
fail. Both reserved arrays are empty in every v0.1 case, so both modes measure
nothing there rather than measuring the wrong thing.

`--agent-runs N` reviews each case N times and reports the Agent Source's
variation across runs as a stderr diagnostic (Requirement 19 AC4). The
deterministic Sources are evaluated exactly once whatever N is: only `agent-only`
repeats, and the summary is computed from the first run.

### cfn-lint contribution series

`benchmark/cfn-lint-contribution/` is a separate measurement series, not a
ground-truth case set. It records how many findings cfn-lint contributes, pinned
to the installed cfn-lint version, and reports the count informationally --
never as a threshold (Requirement 19 AC5). It is kept apart from the
ground-truth cases so their pass/fail contract does not depend on the installed
cfn-lint rule catalogue. See `benchmark/cfn-lint-contribution/README.md`.

## Pass and fail

Expectations classed `deterministic` must all be detected: a category whose
deterministic detection rate is below 100% fails, and the harness exits non-zero
so CI catches the regression.

Expectations classed `agent-dependent` are measured and reported without a
threshold. Agent output is not deterministic, so a threshold on it would make CI
flaky rather than informative. Agent findings are never generated during a
benchmark run; the harness accepts them only as a fixed fixture, which keeps the
harness itself deterministic.

Clean cases (`case-101` upwards) carry the opposite expectation: a review that
reports a `HIGH` or `CRITICAL` finding from a deterministic Source on a clean
template is producing false positives. `tests/negative/` asserts this, using the
same case directories.

## Adding a case

1. Create `benchmark/cases/case-<NNN>-<slug>/`.
2. Write `template.yaml`. Keep it small, and keep it **syntactically valid** with
   no cfn-lint `Error`: a syntax error stops cfn-lint from analysing the rest of
   the template, so the other defects in the case would go unmeasured. Keep every
   resource that is not carrying a defect fully compliant with the bundled rules,
   because a case may report nothing its ground truth does not declare. That
   includes cfn-lint's informational rules: declaring `DeletionPolicy` on a
   stateful resource, and stating a property cfn-lint expects rather than relying
   on its default, keeps a case measuring its own category instead of the
   installed cfn-lint rule catalogue.
3. Write `ground_truth.json` from the defects you placed, before running any
   review. Set `authored_before_review` to `true` and commit it together with the
   template, or before it.
4. Run the benchmark and classify every disagreement rather than editing
   expectations to match output.

A new review rule, whether a `.guard` file or review logic in `iacreview/`,
arrives with at least one case that makes it fire. Otherwise nothing measures
whether it keeps working.

Two constraints apply to everything in this directory:

- **No credentials, and no real AWS account IDs.** Benchmark templates are
  untrusted input by design, and they are also published. Use placeholder
  account IDs such as `123456789012` and never a value copied from a real
  account, key, or token.
- **Benchmark templates stay here.** `examples/` holds small, correct templates
  for users to read and copy. Templates with deliberate defects belong under
  `benchmark/cases/` only, so nobody copies one into a real stack by mistake.
