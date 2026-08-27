---
name: cloudformation-review
description: >-
  Reviews the design of a CloudFormation template (YAML or JSON) by reasoning
  over deterministically extracted facts: the resource inventory, the Ref /
  Fn::GetAtt reference graph, DependsOn edges, Parameters and Conditions, the
  Availability Zone and Subnet properties of each resource, and a summary of
  what the deterministic review sources already reported. Use this skill when
  the user asks whether a template is well designed, whether resources are
  wired together sensibly, whether a workload is exposed to a single point of
  failure or a single Availability Zone, how severe an already reported issue
  is in the context of this particular template, or which AWS best practices
  the template does not follow. Do not use this skill to validate syntax,
  resource property types, intrinsic functions, or deployability; do not use it
  to check organizational policy compliance such as mandatory encryption,
  logging, tagging, or backup; and do not use it for IAM policy risk analysis.
  Those are handled by cfn-lint-review, cfn-guard-review, and iam-review
  respectively, and this skill must not restate what they already report. This
  skill runs no external tool and produces non-deterministic findings that are
  never Confirmed.
---

# CloudFormation Design Review

This is the plugin's only agent-reasoning review skill. `scripts/extract_facts.py`
extracts the facts; the review itself is your reasoning, performed by following
this document, and its result is a findings JSON file that the deterministic
pipeline then validates and merges.

## Purpose

Judge the *design* of a CloudFormation template. The scope is exactly four
concerns, and nothing else belongs here:

1. **Cross-resource relationships.** Risks that only exist in the relation
   between two or more resources, and that no single-resource check can see. For
   example: a Lambda function's execution role granting far more access to a
   bucket in the same template than the function's purpose needs; a queue with
   no consumer; a resource wired to a parameter whose default points somewhere
   unintended.
2. **Architectural risk.** Single points of failure, single Availability Zone
   placement, missing redundancy, scalability limits, deployment ordering that
   depends on `DependsOn` where a data dependency was meant.
3. **Contextual severity assessment.** How much a reported condition matters in
   *this* template. A permissive setting in a template whose description says it
   is a throwaway development stack is not the same finding as the same setting
   in a production data store.
4. **Best practice reasoning.** AWS design recommendations that are not encoded
   as a rule anywhere, and therefore cannot be checked deterministically.

### The boundary you must not cross

The plugin assigns every review concern to either deterministic code or agent
reasoning, and the deterministic side wins wherever it can decide. The following
are already covered, and a finding you produce about any of them is a duplicate
that the plugin's deduplication may not catch, because your wording will differ:

| Already covered by | Concerns |
| --- | --- |
| the template loader | YAML and JSON syntax, parse error position, whether the file is a reviewable template |
| cfn-lint (`cfn-lint-review`) | CloudFormation syntax, intrinsic function form, unresolved `Ref` targets, resource property types, required properties, allowed values, Parameters / Outputs / Mappings / Conditions consistency, deprecated and redundant constructs |
| cfn-guard (`cfn-guard-review`) | the bundled organizational policies: mandatory encryption, prohibited public access, mandatory logging, mandatory tags, mandatory backup |
| the deterministic IAM checks (`iam-review`) | `Action: "*"` with `Resource: "*"`, wildcard actions, wildcard resources, `Principal: "*"`, known privilege escalation action names, cross-account principals and the conditions that bound them |
| the plugin's Python core | category assignment, severity and confidence of deterministic findings, deduplication, merging, sorting, ID assignment, summary counts |

Two consequences follow:

- Do not re-implement any of the above (Requirement 2 AC14, AC15). If a check
  can be performed reliably by cfn-lint or cfn-guard, it is delegated to that
  tool by design, and repeating it as agent reasoning replaces a `Confirmed`
  result with a weaker one.
- Do not rewrite a deterministic finding's severity, confidence, finding type,
  or category. You add your own findings; you never edit theirs. A contextual
  severity judgement is expressed as your own finding, and it can only ever
  raise the merged severity, never lower it.

`deterministic_findings_summary` in the facts file tells you what has already
been reported for this template. Read it first and treat every entry as closed.

## When to use this skill

Use it when the deterministic checks have run and the remaining question is
whether the design is sound: comprehensive design review, architecture review,
"is this production ready", "what would you improve", or a contextual severity
question about a finding another skill produced.

Do not use it:

- to lint a template, validate resource properties, or answer "will this
  deploy" - use `cfn-lint-review`;
- to check compliance with the bundled policy rules - use `cfn-guard-review`;
- to analyze IAM policies, trust policies, or resource-based policies - use
  `iam-review`, which performs the deterministic pass and has its own agent
  reasoning layer for contextual IAM risk;
- to produce one aggregated report over several sources - use `iac-review`.

Running this skill on a template that has not been through cfn-lint and
cfn-guard is allowed and independent (Requirement 2 AC9), but the facts file
will then carry no deterministic findings to avoid restating, so check the
`deterministic_sources` array before assuming silence means cleanliness.

## Input

One CloudFormation template per run, plus any reports from the deterministic
skills that already ran:

```bash
python3 skills/cloudformation-review/scripts/extract_facts.py \
  --target templates/app.yaml \
  --deterministic-report reports/cfn-lint.json \
  --deterministic-report reports/cfn-guard.json
```

- `--target PATH` (required, exactly one): the template. It must resolve inside
  the workspace root, which is the process working directory.
- `--deterministic-report PATH` (optional, repeatable): a JSON report from
  `cfn-lint-review`, `cfn-guard-review`, `iam-review`, or `iac-review`. Any
  document that is a `{"findings": [...]}` object or a bare array of findings is
  accepted. The option order does not change the output. Findings attributed to
  `Agent Review` in such a report are ignored; a previous agent run is not a
  deterministic result.
- `--verbose` (optional): more diagnostics on stderr. It never changes stdout.

The script writes the facts JSON to stdout and nothing else. Read that JSON, not
the raw template, as the basis of your reasoning: it presents intrinsic
functions in their long form (`{"Ref": "X"}`), so nothing has to be inferred
from YAML shorthand. You may still open the template file to quote exact lines
for `Evidence[].Excerpt`.

### The facts JSON

Top-level keys, always all of them:

| Key | Contents |
| --- | --- |
| `schema_version` | Schema version of this document, `"1.0.0"`. |
| `target` | `file` (workspace-relative path), `format` (`yaml` or `json`), `description` (the template's own `Description`, the usual evidence for intended environment). |
| `parameters` | Per parameter: `name`, `type`, `default`, `has_default`, `no_echo`, `allowed_values`, and `referenced_by` (logical IDs of the resources that use it). |
| `conditions` | Per condition: `name` and its unevaluated `definition`. |
| `resources` | Per resource, in template order: `logical_id`, `type`, `condition`, `properties` (every declared property name, with bounded values), and `availability`. |
| `references` | The resource-to-resource graph: `from`, `to`, `kind` (`Ref`, `Fn::GetAtt`, or `Fn::Sub`), `attribute`, `json_path`. |
| `depends_on` | `DependsOn` edges as `from` / `to` pairs. |
| `deterministic_reports` | Workspace-relative paths of the reports that were summarized. |
| `deterministic_sources` | Per deterministic source: `findings_summarized` and `computed_in_process`. |
| `deterministic_findings_summary` | Per already-reported finding: `source`, `rule`, `resource`, `category`, `severity`. No prose, on purpose: the entry exists to tell you the issue is taken, not to be paraphrased. |

Each `resources[].availability` entry names an Availability Zone or Subnet
related property that occurs anywhere in the resource body, with its
`json_path`, its bounded `value`, and `item_count` (the number of elements when
the value is a list, else `null`). That count is the usual evidence for a
single-Availability-Zone risk; whether a given count is adequate is your
judgement, not the script's.

Values reproduced from the template are bounded: strings are cut at 200
characters with `... [truncated]`, sequences at 10 elements with an
`... [omitted: N more items]` element, mappings at 20 keys with an
`__omitted__` key, and anything nested deeper than ten levels is replaced by a
placeholder naming its shape and size. A `NoEcho` parameter's `Default` and
`AllowedValues` are replaced by a redaction placeholder; the plugin does not
copy a value the template author marked sensitive into its output.

## Output

Write your findings as a JSON file inside the workspace, then hand it to the
orchestrator:

```bash
python3 skills/iac-review/scripts/run_iac_review.py \
  --target templates/app.yaml --agent-findings .agent-findings.json
```

The file is validated strictly (`iacreview/agentin.py`) and is the only way
agent output enters a report. Accepted envelopes:

```json
{
  "schema_version": "1.0.0",
  "findings": [ { "...": "one finding object" } ]
}
```

or a bare array of finding objects. `schema_version` is optional; `findings` and
`schema_version` are the only permitted top-level keys, and any other key
rejects the whole file.

One finding, with every field that matters here:

```json
{
  "Normalized_Category": "Availability",
  "FindingType": "BestPractice",
  "Severity": "MEDIUM",
  "Confidence": "Likely",
  "Source": ["Agent Review"],
  "Resource": "AppDatabase",
  "Location": {
    "File": "templates/app.yaml",
    "Line": null,
    "Column": null,
    "TemplatePath": ["Resources", "AppDatabase", "Properties", "MultiAZ"]
  },
  "Finding": "MultiAZ is false and the instance is placed in a subnet group that lists one subnet, so a single Availability Zone outage may take the database offline.",
  "WhyItMatters": "A database that exists in one Availability Zone is a single point of failure for every component that depends on it.",
  "Evidence": [
    {
      "Source": "Agent Review",
      "Detail": "AppDatabase declares MultiAZ: false and AppSubnetGroup lists one subnet",
      "RuleId": null,
      "Excerpt": "AppDatabase:\n  Type: AWS::RDS::DBInstance\n  Properties:\n    MultiAZ: false"
    }
  ],
  "Recommendation": "Set MultiAZ to true and give the subnet group a subnet in at least two Availability Zones.",
  "SuggestedRemediation": null
}
```

Rules the validator enforces on your output:

1. **Nothing already in `deterministic_findings_summary`.** Requirement 2 AC14
   and AC15. Not machine-checkable, and therefore entirely on you.
2. **`Confidence` is `Likely` or `Contextual`.** `Confirmed` is closed to agent
   reasoning (Requirement 7 AC10). A `Confirmed` entry is not rejected but
   demoted to `Likely`, with a warning on stderr; write the honest value
   instead. Use `Likely` when the facts make the risk probable, `Contextual`
   when it depends on information the template does not state.
3. **Every `Evidence` entry carries a non-empty `Excerpt`** quoting the template
   content the conclusion was drawn from (Requirement 7 AC11). An entry without
   one is a schema violation and that finding is dropped. `Evidence[].Source`
   must be `"Agent Review"`, like `Source`, which must be exactly
   `["Agent Review"]`; naming a deterministic source is refused, not corrected.
4. **Phrase the finding as a potential risk** (Requirement 7 AC12). "may",
   "appears to", "is broader than the function seems to need". Never assert that
   a vulnerability exists, and never claim a consequence you cannot see in the
   facts.
5. **`Normalized_Category` comes from the closed set**: `IAM`, `Encryption`,
   `PublicAccess`, `Logging`, `Tagging`, `Availability`, `Backup`,
   `NetworkSecurity`, `DataProtection`, `TemplateQuality`, `Other`. Anything
   else falls back to `Other`, which also removes the finding from
   deduplication, so choose deliberately.

Also: `FindingType` is one of `Validity`, `Security`, `BestPractice`,
`Informational`, and `Severity` one of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`,
`INFO`, comparable only among findings of the same `FindingType`.
`Location.File` must be the workspace-relative template path. `Resource` and
`SuggestedRemediation` may be omitted and read as `null`. Any `ID` you supply is
discarded, because IDs are assigned over the sorted, deduplicated report.

`extract_facts.py` exit codes, from the plugin's shared table: `0` success,
`2` invalid arguments, `3` input file not found, `4` the template does not parse
or a supplied report is not a findings document, `5` PyYAML is missing or too
old for a YAML target, `7` a path outside the workspace, `8` the file is not a
reviewable template, `1` internal error. On any failure stdout stays empty and
the reason is on stderr.

## Limitations

- **This skill does not re-implement checks that cfn-lint or cfn-guard perform**
  (Requirement 2 AC14). It has no rule set, no resource specification, and no
  policy language, and it is not a substitute for either tool.
- **Its output is non-deterministic.** Two runs over the same template may
  produce different findings, different wording, and different severities. Only
  `extract_facts.py` is deterministic: identical input gives byte-identical
  facts. Benchmark expectations therefore cannot be written against exact
  strings from this skill.
- **It cannot produce `Confidence: Confirmed`.** Every finding from this skill
  is `Likely` or `Contextual`, and one that claims otherwise is demoted.
- **It runs no external tool.** `extract_facts.py` never invokes cfn-lint,
  cfn-guard, or `cdk`, so `findings_summarized: 0` for cfn-lint or cfn-guard in
  `deterministic_sources` means "no report was supplied, or that report was
  empty", never "the template is clean". Only the source marked
  `computed_in_process` was actually evaluated during this run.
- **It calls no AWS API.** Nothing outside the template is inspected: existing
  roles, buckets, VPCs, account-level settings, Service Quotas, and the real
  Availability Zones of a region are all invisible. A `Ref` to a parameter whose
  value arrives at deploy time is a fact about the template, not about the
  deployment.
- **Facts are bounded, so absence in the facts is not absence in the template.**
  A value past the truncation limits appears as a placeholder. Where a
  placeholder is the basis of a conclusion, open the template before asserting
  anything.
- **The reference graph covers `Ref`, `Fn::GetAtt`, and `Fn::Sub` substitutions
  only.** A relationship expressed as a literal name, an ARN string, or an
  `Fn::ImportValue` from another stack is not an edge. `DependsOn` entries and
  references naming something that is not a resource of this template are
  omitted; cfn-lint reports those.
- **Conditions are not evaluated.** Which branch applies depends on parameter
  values supplied at deploy time, so both branches of an `Fn::If` are present in
  the facts and neither is marked as taken.
- **One template per run.** Cross-stack and cross-template relationships are out
  of scope for v0.1, including nested stacks referenced by `TemplateURL`.
- **The plugin does not apply your remediation.** `SuggestedRemediation` is a
  proposal for a human to review; nothing in this plugin edits a template or
  touches an AWS account.

## Dependencies

- **Python 3.9 or newer.** The only requirement for `extract_facts.py`.
- **PyYAML** (declared in `pyproject.toml`), needed to read a YAML template. A
  JSON template needs nothing beyond the standard library. If PyYAML is missing,
  a YAML target fails with exit code `5` and a message naming the missing
  library.
- **No external command-line tool.** Unlike `cfn-lint-review`,
  `cfn-guard-review`, and `iac-review`, this skill executes no external
  runtime dependency, which is why it works wherever Python does.
- **No network access, no AWS credentials, no MCP server.** The script reads the
  files named on its command line and writes JSON to stdout.
- **Optional: the other review skills.** They are not required for this skill to
  run, but their reports feed `--deterministic-report`, and the reasoning here is
  better when they have run first. `iac-review` is what merges your findings with
  theirs.
