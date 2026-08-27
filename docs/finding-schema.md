# Finding Schema

This document is the reference for the normalized Finding produced by
`aws-iac-review-agent-plugin`.

Every review Source — cfn-lint, cfn-guard, IAM Review, and Agent Review —
produces its own shape of output and normalizes to the one shape described here.
A consumer that reads this document can read the `findings` array of any Skill's
stdout without knowing which Sources ran.

Two files in the repository are authoritative. Where this document disagrees with
either of them, they win:

- `iacreview/finding.py` — the 13 fields, the five closed value sets, the four
  orderings, and `validate`, which is the one function that decides whether an
  instance of the shape is legal.
- `iacreview/category_map.json` — the `Normalized_Category` vocabulary and the
  per-rule classification data recorded by the two cfn-lint surveys at the end of
  this document.

The schema is versioned as a whole. A report's `schema_version` is the version of
the report envelope *and* the Finding together; this release emits `1.0.0`
(`iacreview.report.SCHEMA_VERSION`). MAJOR is bumped on a breaking change, and
the CHANGELOG records it.

## The five closed value sets

Each of the five is a closed set. A value outside it is a schema violation, not
an extension point: `validate` rejects it, and `from_dict` rejects it when
reading structured input such as an agent-produced Findings file.

### `FindingType`

What kind of problem the Finding is about. Exactly one value per Finding
(Requirement 7 AC2).

| Value | Meaning |
| --- | --- |
| `Validity` | The Template is not correct CloudFormation. It may fail to deploy, or deploy differently from what it appears to say. |
| `Security` | The Template's configuration exposes something: a credential, wider access than it appears to grant, or a reachable attack surface. |
| `BestPractice` | The Template deploys and is not an exposure, but deviates from AWS or project guidance. |
| `Informational` | An observation carrying no assertion that anything is wrong. |

Two orderings over these values exist, and they are deliberately different:

- **Schema order** — `Validity`, `Security`, `BestPractice`, `Informational`.
  The enumeration order of `finding.FINDING_TYPES`, used only for presentation
  and for the fixed key set of `summary.by_finding_type`.
- **Merge priority** — `Security` > `Validity` > `BestPractice` >
  `Informational` (`finding.FINDING_TYPE_ORDER`, Requirement 14 AC10). Used when
  deduplication merges Findings whose types differ. `Security` outranks
  `Validity` here because an exposure that also happens to be a Template defect
  is reported as the exposure.

### `Severity`

How serious the Finding is **within its `FindingType`** (Requirement 7 AC3, AC4).

| Value | Rank | Reading |
| --- | --- | --- |
| `CRITICAL` | 4 | The most serious outcome this FindingType admits. |
| `HIGH` | 3 | Serious within this FindingType. |
| `MEDIUM` | 2 | Worth addressing. |
| `LOW` | 1 | Minor. |
| `INFO` | 0 | Recorded, not a defect. |

The rank column is `finding.SEVERITY_ORDER`. It is used for the merge maximum
(Requirement 14 AC8) and for the descending report sort (Requirement 7 AC15); it
is **not** a global importance score. See
[Severity is comparable only within one FindingType](#severity-is-comparable-only-within-one-findingtype).

`Validity` + `CRITICAL` is restricted: it is permitted only when the reported
condition makes the Template undeployable, which is decided by the
`blocks_deployment` flag in `category_map.json` (Requirement 7 AC6). The survey
that populated that flag, and the criteria it applied, are recorded in
[cfn-lint `blocks_deployment` classification](#cfn-lint-blocks_deployment-classification).

### `Confidence`

How the Finding was arrived at, and therefore how strongly it may be phrased
(Requirement 7 AC7-AC12).

| Value | Rank | Meaning | Assigned by | Wording |
| --- | --- | --- | --- | --- |
| `Confirmed` | 2 | A deterministic tool or a deterministic pattern match established this as fact. | cfn-lint, cfn-guard, IAM Review | May be stated as fact. |
| `Likely` | 1 | Agent reasoning identified a probable risk. | Agent Review | Phrased as a possibility. Must not assert that a vulnerability exists (Requirement 7 AC12). |
| `Contextual` | 0 | A context-dependent recommendation. Not a problem in every environment. | Agent Review | As above. |

`Confirmed` is closed to agent reasoning (Requirement 7 AC10). Two mechanisms
enforce it, and neither relaxes the schema rule:

- `iacreview.agentin` **demotes** a `Confirmed` entry in an agent Findings file
  to `Likely` and warns on stderr, rather than dropping the entry. The
  observation may still be worth reporting; only its certainty was overstated.
- `iacreview.dedup` caps a merged Confidence at
  `finding.AGENT_MAX_CONFIDENCE` (= `Likely`) when `Agent Review` is in the
  merged `Source` union. See
  [Merged Confidence is capped, not merely maximized](#merged-confidence-is-capped-not-merely-maximized).

The rank column is `finding.CONFIDENCE_ORDER`.

### `Normalized_Category`

What the Finding is about. A closed set of 11 members: the 10 categories
Requirement 14 AC2 names plus `Other` from AC3. The authoritative list is the
`categories` array of `iacreview/category_map.json`.

| Value | Subject |
| --- | --- |
| `IAM` | Permission design in IAM policies, roles, users, groups, trust policies, and resource-based policies. |
| `Encryption` | Encryption at rest, encryption in transit, KMS key usage. |
| `PublicAccess` | Reachability from the internet or from all AWS accounts. |
| `Logging` | Access logs, audit logs, flow logs and their enablement. |
| `Tagging` | Presence of required tags. |
| `Availability` | Multi-AZ, redundancy, single points of failure. |
| `Backup` | Backup configuration, retention periods, deletion protection. |
| `NetworkSecurity` | Security Group, NACL, and VPC boundary design that is not `PublicAccess`. |
| `DataProtection` | Data retention, versioning, deletion prevention, handling of sensitive data. |
| `TemplateQuality` | Syntax, property validity, deprecated constructs, Template structure. |
| `Other` | An Agent Review Finding that maps to nothing above. Excluded from deduplication matching. |

`PublicAccess` and `NetworkSecurity` are separated by one rule, recorded as the
`public_access_vs_network_security` note in `category_map.json`: **reachability
from the internet (`0.0.0.0/0`) or from all AWS accounts (`Principal: "*"`) is
`PublicAccess`**; every other network boundary concern is `NetworkSecurity`. The
rule applies identically to cfn-guard rules and cfn-lint rules, so the two
Sources cannot map the same subject to different categories.

`Other` is a residual, not a category. It means "mapped to nothing in the closed
set", so two `Other` Findings share no subject; that is why they never merge.
Only Agent Review reaches it through category fallback, and an unmapped cfn-guard
rule name also lands there (`categories.GUARD_FALLBACK_CATEGORY`).

### `Source`

Which review Source detected the Finding (Requirement 7 AC13). The field is an
array, because a merged Finding names every Source that detected it.

| Value | Rank | What it is | Confidence it may claim |
| --- | --- | --- | --- |
| `cfn-lint` | 0 | cfn-lint results, normalized. | `Confirmed` |
| `cfn-guard` | 1 | cfn-guard rule violations against the bundled `rules/`. | `Confirmed` |
| `IAM Review` | 2 | The deterministic IAM pattern matching in `iacreview.iam`. | `Confirmed` |
| `Agent Review` | 3 | Findings an agent produced by semantic reasoning. | `Likely`, `Contextual` |

The rank column is `finding.SOURCE_ORDER`, and it is the one order in which
`Source` lists and `Evidence` lists appear. Deterministic Sources come before
`Agent Review` so that every rule of the form "take the first Source" prefers
deterministic wording over agent wording, which also keeps report text
byte-stable across runs (Requirement 16 AC11).

## The 13 fields

The field set is closed and fixed. `to_dict` writes all 13 keys on every Finding,
including the ones whose value is `null`, so a consumer can index without
existence checks; `from_dict` rejects an unknown key rather than ignoring it.
`finding.FINDING_FIELDS` is derived from the dataclass definition, so the
documented list cannot drift from the implementation.

Order below is schema order, which is also the order of the JSON Schema
`required` list in design.md.

| # | Field | JSON type | Nullable | Constraint |
| --- | --- | --- | --- | --- |
| 1 | `ID` | integer | no | `>= 1`. Sequential within one report, assigned after sorting. |
| 2 | `Normalized_Category` | string | no | One of the 11 categories above. |
| 3 | `FindingType` | string | no | One of the 4 FindingTypes above. |
| 4 | `Severity` | string | no | One of the 5 Severities above. |
| 5 | `Confidence` | string | no | One of the 3 Confidences above. |
| 6 | `Source` | array of string | no | At least 1 entry, no duplicates, sorted in `SOURCE_ORDER`. |
| 7 | `Resource` | string | **yes** | CloudFormation logical resource ID. Non-empty when present. `null` for a template-level Finding. |
| 8 | `Location` | object | no | `File` required; see below. |
| 9 | `Finding` | string | no | Non-empty. What was detected. |
| 10 | `WhyItMatters` | string | no | Non-empty. Why the detected state matters. |
| 11 | `Evidence` | array of object | no | At least 1 entry; see below. |
| 12 | `Recommendation` | string | no | Non-empty. What to do about it. |
| 13 | `SuggestedRemediation` | string | **yes** | A concrete change proposal, or `null`. Never applied automatically. |

An empty string is not an accepted spelling of "absent" in any nullable text
field: `Resource`, `SuggestedRemediation`, `Evidence[].RuleId` and
`Evidence[].Excerpt` accept `null` or a non-empty string. Two spellings of "no
value" would make otherwise identical reports differ byte for byte.

### `ID`

A sequential integer starting at 1, numbered across the whole report and assigned
**after** sorting (Requirement 7 AC1). It is therefore a property of a Finding's
position in this report, not an identity a Source carries in: the same underlying
issue can hold a different `ID` in two reports, and `ID` is not a stable
cross-report key. Use `(Resource, Normalized_Category)` for that.

Internally, a Finding that has not yet been numbered carries
`finding.UNASSIGNED_ID` (= 0), which `validate` rejects. That value exists only
between deduplication and report assembly and never appears in output.

### `Resource`

The logical resource ID the Finding is about, or `null` when the Finding is
template-level and has no resource context — a malformed section, an unused
Parameter, an `Outputs` problem.

`null` has two consequences worth knowing: such a Finding is excluded from
deduplication matching (Requirement 14 AC6), and it sorts **first** within its
Severity run in the report (see below).

### `Location`

Where in the reviewed Template the Finding was detected.

| Key | JSON type | Nullable | Constraint |
| --- | --- | --- | --- |
| `File` | string | no | Non-empty, workspace-relative, `/`-separated. Never an absolute host path. |
| `Line` | integer | yes | `>= 1`. `null` for a Source that reports no line. |
| `Column` | integer | yes | `>= 1`. `null` for a Source that reports no column. |
| `TemplatePath` | array | yes | Path into the Template document. Items are `string` (mapping key) or `integer` (sequence index). |

`File` is relative so that a report does not disclose the reviewer's directory
layout and stays byte-identical across machines (Requirement 16 AC11). An
absolute path is **refused** rather than repaired: relativizing needs the
workspace root, which is known to the Source that recorded the path
(`iacreview.source.workspace_relative`), not to report assembly.

`Line` and `Column` are populated only by Sources that have a position. cfn-lint
does; cfn-guard reports none by design, and IAM Review works on the parsed
document. Deduplication prefers the `Location` that carries a `Line`, because a
line number makes the Finding navigable in an editor.

#### `Location.TemplatePath` canonical form

`TemplatePath` has one canonical spelling: **sequence indices are `int`, mapping
keys are `str`.** This is design.md [Correction] C-9, and the single
implementation is `finding.canonical_template_path`.

The reason is that the Sources arrive at the segments differently. cfn-lint hands
over a list that already distinguishes keys from indices, while cfn-guard writes
a `/`-separated string and IAM Review a `.`-separated one, in which an index is
indistinguishable from a key until it is inspected. Without one canonical form,
`["Resources", "R", "Policies", 0]` and `["Resources", "R", "Policies", "0"]`
would name the same statement in two spellings, and two Sources reporting one
position would look like two positions — to a reader, to a report diff, and to
any comparison of Locations.

A digit-only string segment therefore becomes an `int` **except at index 1**.
Index 1 is a member name of a top-level Template section (a logical resource ID,
a Parameter name, an Output name); all of those sections are mappings, and a
logical ID consisting only of digits is legal CloudFormation, so converting it
would address a position that does not exist. Canonicalization is applied once,
to the assembled path, not per fragment.

### `Evidence`

Why the Finding is claimed, per Source. At least one entry; a merged Finding
carries every detecting Source's entries, concatenated in `SOURCE_ORDER`.

| Key | JSON type | Nullable | Constraint |
| --- | --- | --- | --- |
| `Source` | string | no | One of the 4 Sources. Required. |
| `Detail` | string | no | Non-empty. What this Source observed. Required. |
| `RuleId` | string | yes | The rule that fired, for example `E3002` or a cfn-guard rule name. |
| `Excerpt` | string | yes | Verbatim Template content that led to the conclusion. |

`Excerpt` is mandatory on at least one entry whenever `Confidence` is not
`Confirmed` (Requirement 7 AC11): a conclusion drawn by reasoning has to point at
what it was drawn from. Deterministic Sources leave it `null`, because their
`RuleId` already identifies the check that fired.

`Excerpt` is also the only field that reproduces Template text verbatim, so it is
the only field through which a credential written into a Template could reach the
report. When the quoted location may hold one, the text is replaced by the fixed
string

```text
[redacted: this location may contain a credential value]
```

(`finding.REDACTED_EXCERPT`) and a sentence naming the reason is appended to that
entry's `Detail`. The field is replaced rather than dropped, so redaction cannot
turn a credential into a schema violation. Redaction fires on two conditions: the
location references a Parameter declared `NoEcho: true`, or a credential-detection
cfn-lint rule (`W1011`, `W2501`) reported it. Key names that merely *suggest* a
secret do not trigger it in v0.1. `docs/security-model.md` records that decision
and its trade-off.

### `Finding`, `WhyItMatters`, `Recommendation`

Three non-empty strings, and three distinct jobs: what was detected, why that
matters, what to do about it. When `Confidence` is not `Confirmed`, `Finding`
must be phrased as a potential risk and must not state that a vulnerability
exists (Requirement 7 AC12).

In a merged Finding all three are taken from the same member — the
highest-ranked Source's — so that the description, its rationale and its advice
stay consistent with one another.

### `SuggestedRemediation`

A concrete change proposal, or `null`. It is **never applied automatically**:
this plugin performs read-only review and proposes no change it also makes.
cfn-guard rules supply it from their custom message (`<<`); Agent Review supplies
generated text.

## Constraints JSON Schema cannot express

`finding.validate` enforces four constraints beyond the JSON Schema. All four are
checked at the output boundary, so a Finding that reaches a consumer has been
checked against the schema this document describes.

| # | Constraint | Basis |
| --- | --- | --- |
| 1 | `Confidence == "Confirmed"` requires `Agent Review` **not** to be in `Source`. | Requirement 7 AC10 |
| 2 | `Confidence != "Confirmed"` requires at least one `Evidence` entry with an `Excerpt`. | Requirement 7 AC11 |
| 3 | `FindingType == "Validity"` with `Severity == "CRITICAL"` requires Evidence carrying a `RuleId` whose `blocks_deployment` flag is set. | Requirement 7 AC6 |
| 4 | `Normalized_Category == "Other"` cannot carry a merged `Source` list. | Requirement 14 AC3 |

Constraint 4 is an integrity check rather than a rule about content: a Source
produces single-Source Findings, so more than one `Source` entry means the
Finding came out of a merge, and an `Other` Finding is never eligible to be
merged. Its presence would prove the exclusion had been bypassed.

Validation stops at the first violation, naming the offending field path
(`Evidence[1].Detail`) and the reason. It also requires `ID >= 1`, which is why
it runs after report ID assignment and not before.

## Reading a report

### Severity is comparable only within one FindingType

`FindingType` and `Severity` are independent axes. `FindingType` says what kind
of problem this is; `Severity` says how serious it is *within that kind*
(Requirement 7 AC4, AC5). **Do not compare Severity across FindingTypes.**

A worked pair from design.md:

| | Finding A | Finding B |
| --- | --- | --- |
| Detected | `E3002: Invalid Property Resources/MyBucket/Properties/Encryped` | The bucket has no `PublicAccessBlockConfiguration` and its policy allows `Principal: "*"` |
| `FindingType` | `Validity` | `Security` |
| `Severity` | `HIGH` | `CRITICAL` |
| `Normalized_Category` | `TemplateQuality` | `PublicAccess` |
| Reading | High on the Validity axis. The deployment probably fails; nothing is exposed. | Top of the Security axis. Data is public. |

Collapsing the two axes into one would force one of two errors: calling `E3002`
`CRITICAL` puts a typo and a data exposure at the same urgency, and holding
public access at `HIGH` buries a real exposure among syntax errors. This is also
why Requirement 7 AC6 restricts `Validity` + `CRITICAL` to a Template that
cannot be deployed at all — `E0000` (unparsable Template) qualifies, a
property-level error does not.

**So: filter by `FindingType` first, then read `Severity` within it.** Because
the report is sorted by Severity descending, a `Validity` / `HIGH` Finding
appears *after* a `Security` / `CRITICAL` one. That is intended, and it is not a
statement that the second is more urgent than every `Validity` Finding below it.

### Report order and `ID`

Findings are sorted by this key (`iacreview.report`):

```text
(-severity_rank, Resource or "", Normalized_Category, Finding, canonical_json_without_ID)
```

Requirement 7 AC15 specifies the first two components: Severity descending, then
resource logical ID ascending. design.md adds `Normalized_Category` and the
Finding description as tie-breakers, and the implementation appends one more, the
Finding's own content rendered as canonical JSON with `ID` removed. That last
component exists because `(Resource, Normalized_Category)` is exactly the
deduplication key: any two Findings still tied after three components are two
Findings that deduplication deliberately did not merge, and an undefined order
between them cannot be byte-identical across runs (Requirement 16 AC11). `ID` is
excluded from it because `ID` is what sorting is about to decide.

`Resource: null` substitutes `""`, which sorts before every logical ID, so
template-level Findings come first within their Severity run. The substitution is
unambiguous because a present `Resource` is always non-empty.

`ID` is then assigned sequentially from 1 over the sorted sequence.

### The summary counters

`summary` carries six keys, always all of them, and every counter object is
pre-filled with zeros across its whole closed value set. The key set of a report
is therefore the same whichever Sources ran, and a report with no `CRITICAL`
Findings differs from one with two only in the number.

| Key | Value | Sums to `total`? |
| --- | --- | --- |
| `total` | Number of entries in `findings`. | — |
| `by_finding_type` | Count per `FindingType`, 4 keys. | yes |
| `by_severity` | Count per `Severity`, 5 keys. | yes |
| `by_source` | Count per `Source`, 4 keys. | **no — may exceed it** |
| `by_template_group` | Count per template group: `standalone`, `synthesized`. | yes |
| `passed_all_checks` | `true` exactly when `findings` is empty. | — |

**`by_source` counts a Finding once per Source that detected it.** As soon as one
Finding has been merged from two Sources, the values of `by_source` sum to more
than `total` (Requirement 14 AC12). This is intended and is not an inconsistency
to reconcile: `by_source` answers "how much did each Source contribute", not "how
do the findings partition". `by_finding_type`, `by_severity` and
`by_template_group` each hold one value per Finding and do sum to `total`.

`by_template_group` separates Templates the user named directly (`standalone`)
from Templates produced by `cdk synth` (`synthesized`), which is what
Requirement 8 AC10 asks for. A Finding whose file appears in neither list counts
as `standalone`: that is what the user pointed at, and claiming CDK provenance
would be a stronger statement than the evidence supports.

**`passed_all_checks` says nothing about `errors`.** It is `true` exactly when
`findings` is empty, and it stays `true` when a Source failed to run. A review in
which cfn-guard was unavailable found no issues, which is not the same claim as
"there are none" — the `errors` array is what tells a reader which of the two
happened. Read both.

### The report envelope is seven keys

The envelope is closed at exactly the seven keys of `iacreview.report.REPORT_KEYS`:

```text
schema_version, target, sources_enabled, tools, findings, errors, summary
```

There is no `stats` key in it, and that is a decision rather than an omission: no
counter is common to all Sources (cfn-lint counts parsed results, cfn-guard
counts violations and rule files, IAM Review counts policy sites) and the values
are not uniformly numeric. A flat `stats` inside the envelope would have a key
set that depended on which Sources ran, which is the opposite of what the
envelope is for.

design.md [Correction] C-10 pins when a Skill may add a key *beside* the
envelope: only where an acceptance criterion makes a counter part of the
**result** rather than a diagnostic. Exactly one criterion does, Requirement 5
AC4 (report the number of rules evaluated on a clean run), so exactly one Skill
does:

| Skill | stdout top-level keys |
| --- | --- |
| `cfn-guard-review` | the 7 envelope keys **+ `stats`** (`stats.rules_evaluated`, `stats.rules_passed`, per Template path) |
| `cfn-lint-review`, `iam-review`, `cloudformation-review`, `iac-review` | the 7 envelope keys, and nothing else |

A report produced by the `iac-review` orchestrator therefore has **no `stats`
key**. Every other counter is a diagnostic and goes to stderr under `--verbose`.

## Deduplication: what one Finding stands for

### The granularity rule

**One Finding is one resource and one `Normalized_Category`.** Deduplication
merges on exactly that pair — logical resource ID plus `Normalized_Category`
(Requirement 14 AC5) — so two Sources reporting the same category of problem on
the same resource produce one Finding carrying both Sources, not two Findings.

The key is deliberately coarse. cfn-lint's "invalid IAM action name" and IAM
Review's "`Action: "*"` on `Resource: "*"`" merge into one entry when they land on
the same role, even though they are different problems. All Evidence survives the
merge, so nothing is lost except the count — but the count is exactly what a
reader must not over-interpret: **a Finding count is a count of affected
resource-category pairs, not of root causes.**

`benchmark/README.md` states the same rule, because the benchmark's
`expected_finding_count` values and its matching rule are only meaningful at this
granularity (Requirement 11 AC3). Ground truth is authored at it, and a reported
Finding matches an expected one when the two agree on resource logical ID,
`FindingType` and `Normalized_Category`.

### What never merges

Two kinds of Finding match nothing, pass through unmodified (Requirement 14
AC13), and always stay separate entries:

- **`Normalized_Category == "Other"`** (Requirement 14 AC3). `Other` means
  "mapped to nothing in the closed set", so two `Other` Findings on one resource
  share no subject. Merging them would fuse two unrelated problems into one entry
  carrying the higher Severity and both Evidence lists — a Finding whose text
  describes one problem and whose Severity comes from another.
- **`Resource == null`** (Requirement 14 AC6). A template-level Finding has no
  resource key to match on.

Neither case matches the other, either: two `null`-resource Findings are two
entries. The predicate is `finding.is_dedup_eligible`, defined once and used both
by `dedup` and by the `validate` rule that detects a bypassed exclusion.

### The merge laws

When two or more Findings share the key, one entry replaces them:

| Field | Rule | Basis |
| --- | --- | --- |
| `Severity` | Maximum (`CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `INFO`). | Requirement 14 AC8 |
| `Confidence` | Maximum (`Confirmed` > `Likely` > `Contextual`), **then capped**; see below. | Requirement 14 AC9 + Requirement 7 AC10 |
| `FindingType` | Highest merge priority (`Security` > `Validity` > `BestPractice` > `Informational`). | Requirement 14 AC10 |
| `Evidence` | Every Source's entries concatenated in `SOURCE_ORDER`; original order kept within a Source. | Requirement 14 AC11 |
| `Source` | Union of all detecting Sources, sorted in `SOURCE_ORDER`. | Requirement 14 AC12 |
| `Resource`, `Normalized_Category` | Identical by construction — they are the key. | — |
| `Location` | The member carrying a `Line`, otherwise the highest-ranked Source's. | design judgement |
| `Finding`, `WhyItMatters`, `Recommendation` | The highest-ranked Source's, all three from the same member. | design judgement |
| `SuggestedRemediation` | The first non-`null` in Source order, otherwise `null`. | design judgement |

The result depends on the group's *contents*, never on the order the Sources ran
in, which is what makes byte-identical output possible (Requirement 16 AC11).
Deduplication is also idempotent: re-running it on its own output changes
nothing.

### Merged Confidence is capped, not merely maximized

Requirement 14 AC9 says the merged `Confidence` is the maximum. Applied together
with the `Source` union of AC12, that is not literally achievable: merging a
`Confirmed` deterministic Finding with a `Likely` agent Finding would produce
`Confidence: "Confirmed"` on a Finding whose `Source` contains `Agent Review`,
which Requirement 7 AC10 forbids and `validate` rejects.

The resolution is design.md [Correction] C-8. The maximum is taken as AC9 says,
and is then **capped at `finding.AGENT_MAX_CONFIDENCE` (= `Likely`) when
`Agent Review` is in the merged `Source` union.** `Contextual` is already below
the ceiling and passes through, so the cap only ever weakens a `Confirmed`. The
schema constraint is not relaxed in exchange.

Read a capped Finding this way: `Confidence` is the strength of the Finding's
claim *as a whole*, and a claim resting partly on agent reasoning does not get to
call itself confirmed. Nothing is lost — the deterministic Sources are still
named in `Source`, and the Evidence that justified `Confirmed` is still in the
entry for a reader to weigh. One side effect is worth noting: because the capped
value is not `Confirmed`, structural constraint 2 switches on, and the merged
Finding must carry an `Excerpt`. An agent Finding always has one, so a merge that
triggers the cap always satisfies it.

## Layer 1 conservatism, and what it means for a Finding

The deterministic layer reports the shape of a configuration, not a per-service
table of what each AWS service honours. A Finding can therefore be correct about
the Template while its `Recommendation` is not actionable for that particular
service.

The bundled example is the clearest case. `iacreview.iam`'s
`cross_service_missing_condition` detector reports a service principal that may
call `sts:AssumeRole` with no `Condition` bounding when — including in a Lambda
execution role's trust policy, which is the trust policy AWS documents. The
condition keys the detector recommends (`aws:SourceAccount`, `aws:SourceArn`,
`aws:PrincipalOrgID`) only bind if the calling service populates them, and AWS
does not document that for Lambda assuming an execution role. Adding one there
does not harden the role; it stops the function from being created.

This asymmetry is deliberate. Encoding a per-service table of honoured condition
keys into a Layer 1 detector would make the detector's correctness depend on data
that changes outside this repository, and being silent would hide the
unconditioned principal from readers for whom it *is* a real confused-deputy
exposure. Reporting the shape and leaving the judgement to the reader is why the
Finding is `Security` / `HIGH` rather than a claim that the role is exploitable —
and it is why `Confidence: Confirmed` is honest here: what was confirmed is the
policy shape, not its exploitability. `examples/README.md` carries the full
analysis, and the limitation applies to any service that does not support the
confused-deputy condition keys.

## Errors are reported beside findings, not instead of them

A failed Source does not fail the review. `errors` carries one StructuredError
per failure, in the order the orchestrator collected them (not sorted — the first
entry is the failure that stopped its Source, and that position is information).
Every StructuredError carries all nine keys of
`iacreview.errors.STRUCTURED_ERROR_KEYS`, `null` where a key does not apply:

```text
error_class, source, tool, exit_code, message,
required_min_version, detected_version, remediation, stderr_head
```

`error_class` is a closed set of 11 values that consumers may switch on:
`invalid_arguments`, `input_not_found`, `parse_failure`, `tool_unavailable`,
`tool_version`, `tool_execution`, `tool_timeout`, `path_violation`,
`no_reviewable_template`, `schema_violation`, `unexpected`. `stderr_head` is
capped at the first 5 lines of the tool's stderr, which bounds both the noise and
the disclosure surface.

Because `passed_all_checks` ignores `errors`, a report with an empty `findings`
array and a non-empty `errors` array means "the Sources that ran found nothing",
not "the Template is clean".

## cfn-lint `blocks_deployment` classification

`iacreview/category_map.json` records, per cfn-lint rule ID, whether violating
that rule prevents a deployment. The flag is the only thing that promotes a
cfn-lint result to `CRITICAL`, and only for `Error`-level results
(Requirement 4 AC5, Requirement 7 AC6). A `Warning` or `Informational` result
never reaches `CRITICAL`, whatever the flag says.

### Survey scope

| Item | Value |
| --- | --- |
| cfn-lint version surveyed | **1.46.0** |
| Command used | `cfn-lint --list-rules` |
| Rules in the catalogue | **267** (201 `E`, 47 `W`, 19 `I`) |
| Rules in scope for this survey | **201** `Error`-level rules |
| `E3xxx` rules examined individually | **123** |
| Covered by the `E0` / `E1` prefix rules already | **45** (6 `E0`, 39 `E1`) |
| Marked `blocks_deployment: true` by this survey | **26** |

`Warning` and `Informational` rules are out of scope: the promotion condition
includes `level == "Error"`, so a flag on them could never take effect.

### Criteria

A rule is marked `blocks_deployment: true` only when **all** of the following
hold. When any of them is uncertain, the rule is left unmarked and its
`Error`-level results are reported as `HIGH`.

1. **Decidable from the Template alone.** The reported condition does not depend
   on account state, region availability, service quotas that vary per account,
   or anything discoverable only at runtime.
2. **A successful deployment is impossible.** Either CloudFormation rejects the
   Template while processing it (`ValidateTemplate`, `CreateStack`,
   `CreateChangeSet`), or the affected resource's Create request is certainly
   rejected, so the stack cannot reach a deployed state.
3. **The rule has a single, unambiguous failure condition.** Parent or aggregate
   rules that report many different underlying causes are not marked, because
   only some of those causes block a deployment and the rule ID alone cannot
   tell them apart.

### Rules marked `blocks_deployment: true`

**Template-format rejections — CloudFormation refuses to process the Template**

| Rule | Condition reported |
| --- | --- |
| `E2002` | Parameter `Type` is not a recognized CloudFormation parameter type |
| `E2003` | Parameter name is not alphanumeric |
| `E2010` | The Template exceeds the maximum number of Parameters |
| `E3001` | A `Resources` member is structurally invalid, for example missing `Type` |
| `E3004` | Resources are circularly dependent through `DependsOn`, `Ref`, `Sub`, or `GetAtt` |
| `E3005` | `DependsOn` names a resource that does not exist in the Template |
| `E3006` | The resource type is not a recognized CloudFormation resource type |
| `E3007` | A resource and a parameter, or two resources, share a name |
| `E3010` | The Template exceeds the maximum number of Resources |
| `E3015` | A resource's `Condition` is not defined in the `Conditions` section |
| `E3035` | `DeletionPolicy` has a value outside the allowed set |
| `E3036` | `UpdateReplacePolicy` has a value outside the allowed set |
| `E3038` | `AWS::Serverless::*` resources are used without the Serverless transform, so the types are unrecognized |
| `E3055` | `CreationPolicy` is not a valid configuration |
| `E6002` | An `Outputs` member is missing a required property such as `Value` |
| `E6004` | An Output name is not alphanumeric |
| `E6005` | An Output's `Condition` is not defined in the `Conditions` section |
| `E6010` | The Template exceeds the maximum number of Outputs |
| `E7010` | The Template exceeds the maximum number of Mappings |
| `E8002` | A referenced Condition is not defined in the `Conditions` section |
| `E8003` | `Fn::Equals` is not a list of exactly two elements |
| `E8004` | `Fn::And` is not a list of two elements |
| `E8005` | `Fn::Not` is not a list of one element |
| `E8006` | `Fn::Or` is not a list of two elements |
| `E8007` | `Condition` does not reference another Condition |

**Resource creation rejections — the provider cannot create the resource**

| Rule | Condition reported |
| --- | --- |
| `E3003` | A property the resource schema declares as required is missing |

Plus the 45 rules already covered by the `E0` and `E1` prefix entries, which
report a Template that cannot be parsed, transformed, or resolved at all.

### Rules deliberately not marked, and why

| Rules | Reason |
| --- | --- |
| `E3002` | Explicitly `false`. In cfn-lint 1.x this is the parent rule for a broad range of resource-schema failures, and it is reported against a registry schema that can lag behind the service, so a property the provider accepts can still be flagged. It fails criterion 3, and the design (`design.md`, O-2 / C-2) fixes it at `false` |
| `E2001`, `E4001`, `E7001`, `E8001` | Aggregate section-level rules covering several unrelated conditions (criterion 3) |
| `E3025`, `E3062`, `E3617`, `E3620`, `E3621`, `E3628`, `E3635`, `E3641`, `E3647`, `E3652`, `E3667`, `E3670`, `E3672`, `E3675`, `E3694` | Instance and node type validation from pricing-API data, which is region- and snapshot-dependent (criterion 1) |
| `E2531`, `E2533`, `E2530` | Lambda runtime deprecation and end-of-life, which depends on the date rather than the Template (criterion 1) |
| `E1150`–`E1156`, `E3031`, `E3041`, `E3503` | Identifier and pattern format heuristics, where a non-matching value can still be a valid deployment input (criterion 2) |
| `E3040` | Read-only properties are not sent to the provider. This causes drift, not a failed deployment (criterion 2) |
| `E3012` | Primitive type mismatch. CloudFormation coerces some scalar types, so not every reported mismatch is rejected (criterion 2) |
| `E3014`, `E3017`, `E3018`, `E3020`, `E3021`, `E3058` | Schema `oneOf` / `anyOf` / dependency constraints. Most do block a deployment, but the underlying schemas vary in how strictly providers enforce them, so each needs individual verification before being marked |
| `E2015` | An out-of-range parameter `Default` is not reached when the caller supplies an explicit value, so the deployment can still succeed (criterion 2) |
| `E2011` | Parameter name length. cfn-lint applies its own handling of the maximum, which was not confirmed to match CloudFormation's enforcement (criterion 2) |
| `E3019`, `E3024`, `E3039`, `E3047` and other resource-specific consistency rules | Strong candidates that require per-rule verification against the service API before being marked. Left for a later revision rather than assumed |
| `E5001` | Module processing, which happens before the Template CloudFormation receives |

## cfn-lint `security_relevant` classification

`iacreview/category_map.json` records, per cfn-lint rule ID, whether the state
the rule reports is a security exposure. When the flag is set, the Finding
receives `FindingType: "Security"` instead of the type its level would imply
(Requirement 4 AC9, Requirement 14 AC4).

The flag moves the `FindingType` only. The `Severity` stays at the level default
— `MEDIUM` for a `Warning`, `LOW` for an `Informational` — so a rule that also
warrants a different Severity has to state `severity` explicitly in the same
override. Nothing here can reach `CRITICAL`: that promotion requires
`level == "Error"`, and no `Error`-level rule is marked security-relevant.

Because `FindingType` and `Severity` are separate axes, a `Security` Finding at
`MEDIUM` is not comparable to a `Validity` Finding at `HIGH`. Filter by
`FindingType` first, then read the Severity within it.

### Survey scope

| Item | Value |
| --- | --- |
| cfn-lint version surveyed | **1.46.0** |
| Command used | `cfn-lint --list-rules` |
| Rules in the catalogue | **267** (201 `E`, 47 `W`, 19 `I`) |
| Rules in scope for this survey | **66** (47 `Warning`, 19 `Informational`) |
| Marked `security_relevant: true` | **7** (3 initial, 4 added by this survey) |

`Error`-level rules are out of scope. An `Error` already carries
`FindingType: "Validity"` at `HIGH` or `CRITICAL`, and the cfn-lint rules that
report a genuine security state are all `Warning`-level in this catalogue.

Each candidate was judged against the rule's implementation in the installed
cfn-lint package, not against its one-line summary. Two candidates were rejected
on that basis alone (`W2511`, `W3045`), because the shortdesc suggests a broader
check than the code performs.

### Criteria

A rule is marked `security_relevant: true` only when **all** of the following
hold. When any of them is uncertain, the rule is left unmarked and its results
are reported under the `FindingType` its level implies.

1. **The reported state is itself the exposure.** A credential becomes readable,
   or access is granted more widely than the Template appears to grant. It is
   not enough that the reported state makes a future exposure more likely.
2. **Every instance the rule reports is an exposure.** A rule that also fires on
   a safe configuration is not marked, because the rule ID alone would then
   assert `Security` about a Finding that is not one.
3. **No dependency on time or account state.** A condition that depends on the
   current date, on a deprecation schedule, or on an account's runtime state is
   not marked: it describes an unpatched or ageing configuration rather than an
   exposure decidable from the Template.
4. **Exposure, not breakage.** A rule whose reported state causes access to be
   *denied* is not marked. A broken policy is a correctness problem, and marking
   it `Security` would inflate the `Security` FindingType with findings that
   have no attacker-reachable consequence.

Criterion 4 is why the three initial rules are worth re-reading: `W3037`
(invalid IAM action) is retained as specified in the design, and its recorded
`why_it_matters` covers both directions of the mismatch it reports.

### Rules marked `security_relevant: true`

**Credential exposure — a secret becomes readable**

| Rule | Level | Category | State reported, and why it is an exposure |
| --- | --- | --- | --- |
| `W1011` | `Warning` | `DataProtection` | A secret-valued resource property is supplied by `Ref` to a Parameter. The value is stored in plaintext in the Template and in stack history. *(initial value, retained)* |
| `W2501` | `Warning` | `DataProtection` | A password property is a plain string, or its Parameter is not `NoEcho`, so the value is displayed by the console and the API. *(initial value, retained)* |
| `W2010` | `Warning` | `DataProtection` | A `NoEcho` Parameter is referenced from `Metadata`, `Outputs`, or resource `Metadata`. `NoEcho` does not mask those sections, so the value is returned in plaintext by `DescribeStacks` to anyone who can read the stack. |
| `W1051` | `Warning` | `DataProtection` | A `{{resolve:secretsmanager:...}}` dynamic reference is used in a field that expects a secret *ARN* (`SecretArn`, `SecretsManagerSecretId`, and four related fields). The reference resolves at deploy time, so the plaintext secret is stored in the resource configuration where an identifier was expected. The rule matches those field names exactly, so it does not fire on the ordinary, correct use of a dynamic reference. |

**Access wider than the Template appears to grant**

| Rule | Level | Category | State reported, and why it is an exposure |
| --- | --- | --- | --- |
| `W3037` | `Warning` | `IAM` | An IAM action is not a valid `service:action`. The policy does not grant what was intended, or grants what was not intended. *(initial value, retained)* |
| `W3663` | `Warning` | `IAM` | An `AWS::Lambda::Permission` has a `SourceArn` carrying no account ID — an S3 bucket ARN — and no `SourceAccount`. An S3 ARN does not identify an account, so a bucket of that name in *any* account satisfies the permission. This is the confused-deputy case `SourceAccount` exists to close. |
| `W3687` | `Warning` | `NetworkSecurity` | `FromPort` and `ToPort` are set alongside an `IpProtocol` outside `tcp` / `udp` / `icmp`, including `-1` (all protocols). The port range is silently ignored, so a rule that reads as one open port opens every port the protocol reaches. |

`W3687` is `NetworkSecurity` rather than `PublicAccess` because the rule reports
nothing about the CIDR or Security Group reached; see the
`public_access_vs_network_security` note in `iacreview/category_map.json`.

### Rules deliberately not marked, and why

| Rules | Reason |
| --- | --- |
| `W2511` | Its summary reads "Check IAM Resource Policies syntax", but the implementation checks one thing: whether `PolicyDocument.Version` is the legacy `2008-10-17`. The legacy version limits which policy features are available; it does not by itself grant or expose anything (criterion 1) |
| `W3045` | Fires on *any* `AccessControl` value on an S3 bucket, including `Private`. It is a deprecation warning in favour of bucket policies, so most instances are not exposures (criterion 2) |
| `I3510` | An IAM statement's `Resource` ARN does not match the ARN format its `Action` requires, and the rule returns early when the Resource is `*`, a `Ref`, or a dynamic reference. The reported state therefore denies access rather than granting it (criterion 4) |
| `W2531`, `W2533`, `I2530` | Lambda runtime deprecation and end-of-life. Real risk, but the condition depends on the current date and the rule asserts no specific vulnerability (criterion 3) |
| `W3690`, `W3691` | Deprecated RDS engine versions, for the same reason as the Lambda runtime rules (criterion 3) |
| `I3042` | Hardcoded partition, region, or account in an ARN. By default only the *partition* position is checked, and a hardcoded account ID is a portability concern here. Cross-account grants are the subject of the IAM Review Source, which evaluates the Principal in context (criterion 1) |
| `I3011`, `W3011`, `I3013` | Missing `DeletionPolicy` / `UpdateReplacePolicy` and missing retention periods. These risk data loss, not disclosure or unauthorized access. They belong to `Backup` and `Availability` (criterion 1) |
| `W2030`, `W2031`, `W3034`, `I2003` | Parameter value and `AllowedPattern` constraints. A constraint that does not match is an input-validation defect in the Template, not an exposure decidable from it (criterion 1) |
| `W3010` | Hardcoded Availability Zone. An availability concern |
| `W1001`, `W1019`, `W1020`, `W1028`, `W1030`–`W1040`, `W1100`, `W2001`, `W2002`, `W2506`, `W3002`, `W3005`, `W3660`, `W3688`, `W3689`, `W3693`, `W4001`, `W4005`, `W6001`, `W7001`, `W8001`, `W8003` | Template quality, function correctness, and resource-consistency warnings with no security consequence |
| `I1002`, `I1003`, `I1022`, `I2010`, `I2011`, `I3010`, `I3012`, `I3037`, `I3100`, `I6010`, `I6011`, `I7002`, `I7010` | Template limits, style, and legacy instance generations |

Several of these — notably `I3510` and the deprecation rules — are the kind of
finding the Agent Semantic Review layer is better placed to judge, because the
decision needs the surrounding context that a rule ID cannot carry.

### Known Limitations (security relevance)

Task 27.1 transcribes these into the README `Known Limitations` section together
with the list below.

- The `Security` FindingType is assigned conservatively from cfn-lint results.
  Only 7 of the 66 `Warning` and `Informational` rules are marked, so a
  security-relevant condition that cfn-lint reports under a rule not on the list
  appears as `BestPractice` or `Informational` rather than `Security`. The
  cfn-guard, IAM Review, and Agent Review Sources cover security conditions
  independently of this list.
- The survey covers the cfn-lint **1.46.0** catalogue. A rule added by a newer
  cfn-lint is classified from its level and never as `Security`.
- End-of-life Lambda runtimes and deprecated RDS engine versions are reported,
  but as `BestPractice` rather than `Security`, because the condition depends on
  the current date rather than on the Template.

### Known Limitations (draft for README)

Task 27.1 transcribes this into the README `Known Limitations` section.

- The `CRITICAL` Severity is assigned conservatively. Only cfn-lint rules whose
  reported condition is verified to make a deployment impossible are promoted,
  so some genuinely deployment-blocking errors are reported as `HIGH` rather
  than `CRITICAL`. `HIGH` is never assigned in place of a lower Severity, so no
  finding is understated by this policy.
- The survey covers the cfn-lint **1.46.0** catalogue. A newer cfn-lint may add
  rules the mapping file does not know; those are classified from their level
  and reported as `HIGH` at `Error` level, never `CRITICAL`.
- `E3002` results are reported as `HIGH` even though many of them do block a
  deployment, because the rule ID alone does not identify which underlying
  schema failure occurred.
