---
name: iam-review
description: >-
  Analyzes the IAM policies of a CloudFormation template (YAML or JSON) in two
  layers: a deterministic scan that reports wildcard permissions, privilege
  escalation, unrestricted iam:PassRole and sts:AssumeRole, missing
  confused-deputy conditions, and cross-account or wildcard principals as
  Confirmed findings; and an inventory of every policy site that lets the agent
  reason about least privilege and excessive authority pattern matching cannot
  decide. Use it when a template has IAM roles, inline or managed
  policies, trust or resource-based policies such as an S3 bucket or KMS key
  policy, or an AWS::Lambda::Permission, and the user asks about permissions,
  privilege escalation, least privilege, cross-account access, or IAM security.
  Do not use it for syntax and property validation, for Guard policy rules, or
  for design review; those belong to cfn-lint-review,
  cfn-guard-review, and cloudformation-review. Use iac-review when the user
  wants one report covering all concerns. Requires Python 3.9+ and no external
  tool.
---

# IAM Review

## Purpose

This skill answers one question about a CloudFormation template: what do its IAM
policies allow, and which of those grants are dangerous?

It answers in two layers, and the split is deliberate. Requirement 6 enumerates
the action names, values, and structures that make a policy dangerous, so those
checks are decided by code and never by reasoning. What the enumeration cannot
decide - whether a policy that matches no dangerous pattern is still wider than
its workload needs - is left to the agent, with the template's policies handed
to it as structured data.

| Layer | Runs | Confidence | Covers |
| --- | --- | --- | --- |
| Layer 1, deterministic | `scripts/run_iam_scan.py` | `Confirmed` | 15 detectors over enumerated action names, wildcard values, principal classes, and missing conditions |
| Layer 2, agent reasoning | the host agent, over `scripts/extract_policies.py` output | `Likely` or `Contextual` | distance from least privilege, authority spread across resources, organizational policy concerns |

Layer 1 needs no agent. Layer 2 needs no template parsing. Either can be used
without the other.

### Layer 1 detectors

`star_action_star_resource`, `wildcard_action`, `wildcard_resource`,
`sensitive_prefix_without_condition`, `passrole_unrestricted`,
`assumerole_unrestricted`, `privesc_policy_mutation`, `privesc_lambda_passrole`,
`privesc_broad_trust`, `cross_service_missing_condition`,
`cross_account_principal`, `principal_star`, `dangerous_s3_combo`,
`dangerous_ec2_passrole`, `dangerous_lambda_combo`.

Every detector runs against every policy site, so the report states how much was
checked regardless of what matched.

### Policy sites examined

Inline role policies, trust policies (`AssumeRolePolicyDocument`), permissions
boundary references, managed policies, standalone `AWS::IAM::Policy` documents,
inline user and group policies, resource-based policies
(`AWS::S3::BucketPolicy`, `AWS::KMS::Key`, `AWS::SQS::QueuePolicy`,
`AWS::SNS::TopicPolicy`, `AWS::ECR::Repository`,
`AWS::SecretsManager::ResourcePolicy`), and `AWS::Lambda::Permission`.

## When to use this skill

Select this skill when:

- the template defines `AWS::IAM::Role`, `AWS::IAM::Policy`,
  `AWS::IAM::ManagedPolicy`, `AWS::IAM::User`, or `AWS::IAM::Group`;
- the template attaches a resource-based policy to a bucket, key, queue, topic,
  repository, or secret;
- the user asks about permissions, wildcards in policies, privilege escalation,
  `iam:PassRole`, trust policies, cross-account access, or least privilege;
- a security review of a template needs its IAM posture stated separately from
  its syntax and its policy compliance.

Do not select this skill when:

- the question is whether the template is syntactically valid or its resource
  properties are correct: use `cfn-lint-review`;
- the question is whether the template satisfies an organizational rule such as
  mandatory encryption, logging, tagging, or backup: use `cfn-guard-review`;
- the question is about architecture, cross-resource design, or availability:
  use `cloudformation-review`;
- the user wants a single report covering syntax, policy compliance, IAM, and
  design together: use `iac-review`, which runs this skill's shared code
  directly.

## Input

Both scripts take a path to one CloudFormation template file, YAML or JSON,
relative to the current working directory. Neither accepts a directory: finding
templates in a tree and telling synthesized CDK output from ordinary input
belongs to `iac-review`.

Layer 1, deterministic findings for one template:

```bash
python3 skills/iam-review/scripts/run_iam_scan.py --target templates/app.yaml
```

Several templates in one report:

```bash
python3 skills/iam-review/scripts/run_iam_scan.py --target templates/app.yaml --target templates/data.yaml
```

Layer 2 input, the policy inventory the agent reasons over:

```bash
python3 skills/iam-review/scripts/extract_policies.py --target templates/app.yaml
```

| Option | Script | Meaning |
| --- | --- | --- |
| `--target PATH` | both | Template file to read. Required. Repeatable in `run_iam_scan.py`; accepted once in `extract_policies.py`, whose output names no file. |
| `--verbose` | both | Extra diagnostics on stderr. Never changes stdout. |

Paths are resolved and required to stay inside the current working directory.
Symbolic links are followed before the check, so a link inside the workspace
that points outside it is refused. Neither script reads stdin, prompts, or
writes any file.

## Output

Both scripts write JSON to stdout and nothing else. Diagnostics, warnings, and
error messages go to stderr. For one template, stdout is byte-identical between
runs and identical with and without `--verbose`.

### `run_iam_scan.py`: a review report

Top-level stdout keys, in the order they are serialized: `errors`, `findings`,
`schema_version`, `sources_enabled`, `summary`, `target`, `tools`. That is the
Review_Report envelope and nothing beside it. Per-run counters (policy sites
found, statements examined, detectors evaluated) are diagnostics here, not
results, so they go to stderr under `--verbose`; the one Skill that carries a
counter on stdout is `cfn-guard-review`, which Requirement 5 AC4 obliges to
report its evaluated-rule count as part of the result.

A normalized report whose `findings[]` entries all carry
`Source: ["IAM Review"]` and `Confidence: "Confirmed"`. Each finding has the
13 fields of the shared schema (see `docs/finding-schema.md`): `ID`,
`Normalized_Category`, `FindingType`, `Severity`, `Confidence`, `Source`,
`Resource`, `Location`, `Finding`, `WhyItMatters`, `Evidence`,
`Recommendation`, `SuggestedRemediation`.

Two kinds of finding are reported that are not risks, and they are labelled
`FindingType: "Informational"` with `Severity: "INFO"`:

- `unresolvable_value`: a value produced by `Fn::ImportValue`, `Fn::GetAtt`, or
  a `Ref` to a deploy-time parameter, which the checks could not evaluate. The
  finding discloses that the location is not covered by the `Confirmed`
  findings. It does not claim the value is dangerous.
- `malformed_policy_document`: a property that should hold a policy document but
  holds a string or a list, so no statement could be examined. `cfn-lint` is
  what reports this as an error; this skill records only that it did not look.

When several detectors match the same resource, their findings are merged into
one entry that keeps the highest severity and every detector's `Evidence`, so
the report gives all of the reasons behind a severity rather than repeating the
resource once per rule.

When the template contains no IAM-related resource at all, `findings` is empty,
the exit code is 0, and the informational message Requirement 6 AC12 asks for is
written to stderr. That is a different result from a template whose policies
were examined and found narrow, which also yields an empty `findings` but no
message.

### `extract_policies.py`: the Layer 2 inventory

An object with exactly three keys:

```json
{
  "policy_sites": [
    {
      "logical_id": "AppExecutionRole",
      "kind": "inline_role_policy",
      "json_path": "Resources.AppExecutionRole.Properties.Policies.0.PolicyDocument",
      "statement_count": 3,
      "actions": ["s3:GetObject", "s3:PutObject", "logs:CreateLogStream"],
      "resources": ["arn:aws:s3:::${AppBucket}/*", "*"],
      "principals": [],
      "has_conditions": [false, false, true],
      "unresolvable_locations": ["Resources.AppExecutionRole.Properties.Policies.0.PolicyDocument.Statement.1.Resource"]
    }
  ],
  "attached_to": {
    "AppExecutionRole": ["AppFunction"]
  },
  "deterministic_findings_summary": [
    { "rule": "wildcard_resource", "resource": "AppExecutionRole", "severity": "HIGH" }
  ]
}
```

- `policy_sites[]` holds one entry per policy document or `Lambda::Permission`
  found, in template order. `actions`, `resources`, and `principals` are the
  candidate strings the deterministic code derived, not raw template values: an
  `Fn::Sub` appears with its substitutions still written as `${Name}`, and a
  value nothing could be derived from is absent from those lists and named in
  `unresolvable_locations` instead. `has_conditions` has one boolean per
  examined statement, in the same order `statement_count` counts.
- `attached_to` maps each policy owner to the other resources whose bodies
  reference it, which is how much authority the policy actually confers.
- `deterministic_findings_summary[]` names what Layer 1 already reported, by
  rule, resource, and severity. It carries no prose, on purpose.

`policy_sites: []` with an empty summary is a valid answer: the template holds
no IAM policy.

### Exit codes

| Code | Meaning | stdout |
| --- | --- | --- |
| 0 | The review ran. Zero findings is a success, not a failure. | JSON |
| 1 | Unexpected internal error; the trace is on stderr. | empty |
| 2 | Argument validation failed: no `--target`, unknown flag, or a shell metacharacter in a path. | empty |
| 3 | A target path does not exist or cannot be read. | empty |
| 4 | A template could not be parsed as YAML or JSON. | `run_iam_scan.py`: a report whose `errors[]` describes the failure. `extract_policies.py`: empty. |
| 7 | A target path resolves outside the workspace root. | empty |
| 8 | A template holds no non-empty `Resources` mapping. | as for 4 |

Codes 5 and 6 are reserved for external tool failures and cannot occur here.

### Layer 2: what the agent may add, and how

Read `extract_policies.py` output and reason about what pattern matching cannot
decide: whether the actions a role holds match the work the resources in
`attached_to` perform, whether authority is spread so that one compromised
component reaches another, and whether a policy that matched no detector is
still wider than the workload needs.

Five constraints apply to every finding produced this way. They are not style
preferences; a finding that breaks one of the first three is rejected or
corrected when it is loaded, with a message on stderr.

1. **Do not restate `deterministic_findings_summary`.** Anything listed there is
   already reported with `Confidence: "Confirmed"`. Re-reporting it adds a
   duplicate with a weaker confidence. Reasoning *about* a listed finding is
   welcome when it adds context the rule could not have (why this particular
   wildcard is reachable from the internet, for example), as long as the new
   finding says something the summary entry does not.
2. **Never claim `Confidence: "Confirmed"`.** Agent findings carry `"Likely"` or
   `"Contextual"` (Requirement 7 AC10). A `"Confirmed"` value is demoted to
   `"Likely"` with a warning rather than rejected, but the finding then no
   longer says what was written.
3. **Give every `Evidence[]` entry a non-empty `Excerpt`.** The excerpt is the
   template content the conclusion rests on (Requirement 7 AC11). An evidence
   entry with nothing quoted from the template is an assertion, not evidence,
   and it is refused.
4. **Phrase the finding as a possibility.** Write "this policy may allow ...",
   "this grant appears wider than ...", "an attacker who obtained these
   credentials could ...". Do not write that a vulnerability exists
   (Requirement 7 AC12). The deterministic layer is what states facts.
5. **Choose `Normalized_Category` from the closed set**: `IAM`, `Encryption`,
   `PublicAccess`, `Logging`, `Tagging`, `Availability`, `Backup`,
   `NetworkSecurity`, `DataProtection`, `TemplateQuality`, or `Other` when none
   fits. Most findings from this skill are `IAM`. A value outside the set is
   read as `Other`, which also removes the finding from deduplication matching.

Also keep severity honest: `Severity` is comparable only among findings sharing
a `FindingType`, and `CRITICAL` on a contextual finding claims more certainty
than the confidence supports.

### The agent findings file

Layer 2 findings enter a report through a JSON file passed to
`iac-review --agent-findings <path>`. This skill's scripts do not read it; the
format is documented here because this is where Layer 2's instructions live.

Either envelope is accepted:

```json
{ "schema_version": "1.0.0", "findings": [ { "...": "..." } ] }
```

```json
[ { "...": "..." } ]
```

Rules the loader enforces:

- The object form permits exactly two top-level keys, `findings` and
  `schema_version`. Any other key fails the whole file, because an agent that
  added one believed it was supplying information the report would not carry.
- `schema_version`, when present, must declare major version 1.
- `Source` must be exactly `["Agent Review"]`. Omitting it means the same thing
  and is accepted. Naming any other source fails that finding: agent reasoning
  attributed to a deterministic tool would merge into deterministic findings as
  if two sources had confirmed one issue.
- Each `Evidence[]` entry must be an object with `Source` (`"Agent Review"`, or
  omitted) and `Detail`, and a non-empty `Excerpt`. `RuleId` is optional and is
  usually `null` for an agent finding.
- `Confidence` must be `"Likely"` or `"Contextual"`. `"Confirmed"` is demoted to
  `"Likely"` and warned about.
- `Normalized_Category` outside the closed set becomes `Other`.
- `Resource` and `SuggestedRemediation` may be omitted; absent reads as `null`.
  `Resource: null` means the finding matches no other finding and is reported on
  its own.
- `ID` is accepted and discarded. Identifiers are assigned over the sorted,
  deduplicated report.
- Every other field is required: `FindingType`, `Severity`, `Location`
  (`File`, `Line`, `Column`, `TemplatePath`), `Finding`, `WhyItMatters`,
  `Recommendation`.

A finding that violates any of these is dropped, an entry naming it is added to
the report's `errors[]`, and the remaining findings load normally. Only a
problem with the file itself - unreadable, not JSON, not one of the two
envelopes - stops the whole file from loading, and the review then continues
without agent findings.

One complete example:

```json
{
  "schema_version": "1.0.0",
  "findings": [
    {
      "Normalized_Category": "IAM",
      "FindingType": "Security",
      "Severity": "MEDIUM",
      "Confidence": "Contextual",
      "Source": ["Agent Review"],
      "Resource": "AppExecutionRole",
      "Location": {
        "File": "templates/app.yaml",
        "Line": null,
        "Column": null,
        "TemplatePath": ["Resources", "AppExecutionRole", "Properties", "Policies", 0, "PolicyDocument", "Statement", 0]
      },
      "Finding": "This role may hold broader write authority than the function attached to it appears to need: it allows s3:PutObject and s3:DeleteObject on the whole application bucket, while the function is described as a read path.",
      "WhyItMatters": "Credentials obtained from the function would be able to overwrite or remove objects other components depend on, which turns a read-path compromise into data loss.",
      "Evidence": [
        {
          "Source": "Agent Review",
          "Detail": "The role's inline policy grants write and delete on the bucket, and attached_to lists only AppReaderFunction.",
          "RuleId": null,
          "Excerpt": "Action: [s3:GetObject, s3:PutObject, s3:DeleteObject]\nResource: arn:aws:s3:::${AppBucket}/*"
        }
      ],
      "Recommendation": "Confirm whether the attached function writes to this bucket. If it only reads, narrow the policy to s3:GetObject and move the write path to its own role.",
      "SuggestedRemediation": null
    }
  ]
}
```

## Limitations

- **Unresolvable values are disclosed, not judged.** When `Fn::ImportValue`,
  `Fn::GetAtt`, or a `Ref` to a deploy-time parameter decides an `Action`,
  `Resource`, or `Principal`, the value cannot be known before deployment. Such
  a location is reported as an `unresolvable_value` coverage gap and is never
  called dangerous. A parameter `Default` is deliberately not trusted, because
  it is overridden at deploy time; a parameter with `AllowedValues` is checked
  against all of its values instead.
- **No reachability analysis.** This skill does not compute effective
  permissions the way IAM Access Analyzer does. It examines statements, not the
  access a whole account graph permits, so it cannot say whether a granted
  action is reachable in practice.
- **No AWS API calls.** Nothing outside the template is consulted. A role,
  managed policy, permissions boundary, or SCP that exists in the account but
  not in the template is not evaluated, and a `PermissionsBoundary` given as an
  ARN is recorded as a site without its document being read.
- **Resource-based policy coverage is a fixed list.** The resource types listed
  under Purpose are the ones examined in v0.1. Other services that carry
  resource-based policies exist and are not yet covered; a policy on such a
  resource is silently out of scope rather than reported.
- **Layer 2 output is not reproducible.** Agent findings vary between runs and
  cannot be `Confirmed`. Only `run_iam_scan.py` output is byte-stable for a
  given template.
- **`Severity` is relative within a `FindingType`.** A `HIGH` security finding
  and a `HIGH` best-practice finding are not comparable.
- **Checks other tools own are not reimplemented.** Whether a policy document is
  the type CloudFormation expects, whether a rule such as mandatory encryption
  is satisfied, and whether the template deploys at all are questions for
  `cfn-lint-review` and `cfn-guard-review`.

## Dependencies

- **Python 3.9 or newer**, on `PATH` as `python3`. Required.
- **PyYAML 6.0 or newer**, for template parsing. Required.
- **No external review tool.** Unlike `cfn-lint-review` and
  `cfn-guard-review`, this skill launches no external executable, so it cannot
  fail with exit code 5 or 6 and reports no `tools[]` entry. The detectors are
  the plugin's own code.
- **No AWS credentials, no network access.** The scripts read the template files
  named with `--target` and nothing else, and they write only to stdout and
  stderr.
- Shared modules under `iacreview/` do the work, the same modules `iac-review`
  calls, so a finding does not depend on which skill produced it.
