# Examples

Small, well-formed templates, and the CDK flow that produces one. Everything
here is meant to pass review: these are the samples to copy from, and the
baseline for checking that the plugin stays quiet on templates that are already
in order.

Templates with deliberate defects are **not** here. They live under
`benchmark/cases/`, each beside the ground truth that says what it is supposed to
report. Keeping the two apart is what lets a test assert "this directory produces
(almost) nothing" without listing exceptions.

| Example | What it shows |
| --- | --- |
| [`minimal-s3/template.yaml`](minimal-s3/template.yaml) | The smallest S3 bucket the bundled rules consider well configured: encrypted, private, access-logged, tagged. |
| [`lambda-with-role/template.yaml`](lambda-with-role/template.yaml) | A Lambda function whose execution role allows one action on one ARN. |
| [`cdk-synth-output/README.md`](cdk-synth-output/README.md) | How to review a CDK application after it has been synthesized. |

Review any of them from the plugin root:

```sh
python3 skills/iac-review/scripts/run_iac_review.py \
  --target examples/minimal-s3/template.yaml
```

## What the review reports

Measured with cfn-lint 1.46.0 and cfn-guard 3.2.1, all sources enabled. The
numbers are asserted in `tests/integration/test_examples.py`, so an example that
starts reporting something new fails the test suite rather than drifting quietly.

| Example | Findings |
| --- | --- |
| `minimal-s3/template.yaml` | none; `summary.passed_all_checks` is `true` |
| `lambda-with-role/template.yaml` | one, HIGH, on the execution role's trust policy |

### The one finding on `lambda-with-role`

The IAM detectors report the trust policy of `ReportWriterRole`, merging three
detections into one finding: `cross_service_missing_condition`,
`privesc_broad_trust` and `sensitive_prefix_without_condition`. All three say the
same thing in different words -- the policy lets a named AWS service call
`sts:AssumeRole` and carries no `Condition` bounding when.

The finding is correct about the template and its recommendation is not
actionable here, which is worth understanding before copying either the template
or the fix:

- The trust policy is the one AWS documents for a Lambda execution role. A
  function needs `lambda.amazonaws.com` to be able to assume its role, and the
  documented policy has no condition.
- The recommended keys -- `aws:SourceAccount`, `aws:SourceArn`,
  `aws:PrincipalOrgID` -- only bind if the calling service populates them. AWS
  documents that per service, and does not document it for Lambda assuming an
  execution role. Lambda checks that it can assume the role when the function is
  created, so a condition it never satisfies does not harden the role: it stops
  the function from being created at all.
- The detectors are Layer 1: deterministic, and deliberately conservative. They
  report the shape of the policy, not a per-service table of which condition keys
  are honoured. Reporting the unconditioned service principal and leaving the
  judgement to the reader is the intended behaviour, and it is why the finding is
  `Security` / `HIGH` rather than a claim that the role is exploitable.

The example therefore keeps the working trust policy and the finding, rather than
adding a condition that would silence the review and break the deployment. The
same asymmetry applies to any service that does not support the confused-deputy
condition keys; it is recorded as a known limitation.

### Two things the examples avoid, and why

- **No wildcards in a `Resource`.** `wildcard_resource` reports any `*` in an
  allowed resource. Hand-written CloudWatch Logs permissions need one, because a
  log stream name is chosen at invocation time and the ARN has to end in
  `:log-stream:*`. `lambda-with-role` takes log delivery from the AWS managed
  policy `AWSLambdaBasicExecutionRole` instead, which keeps that tradeoff in one
  named place. Write the statement by hand and expect a MEDIUM finding.
- **No literal account IDs or ARNs.** ARNs are built with `AWS::Partition`,
  `AWS::Region` and `AWS::AccountId`, so nothing here names a real account. A
  literal 12-digit account ID in a `Principal` is what
  `cross_account_principal` looks for, and a copied-in account number is a
  finding waiting to happen.

## Deploying an example

Both templates deploy as they are, given their parameters:

```sh
aws cloudformation deploy \
  --template-file examples/minimal-s3/template.yaml \
  --stack-name example-minimal-s3 \
  --parameter-overrides \
      AccessLogBucketName=my-existing-log-bucket \
      OwnerName=platform-team
```

```sh
aws cloudformation deploy \
  --template-file examples/lambda-with-role/template.yaml \
  --stack-name example-lambda-with-role \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides OwnerName=platform-team
```

`minimal-s3` needs an existing bucket to deliver its access logs to, whose bucket
policy allows `logging.s3.amazonaws.com` to write there. `lambda-with-role`
expects the SSM parameter `/example/report-writer/destination` to exist; without
it the function deploys and its single permission is unused.

Neither is created for you, and neither is deployed by this plugin: the review is
read-only, and nothing here calls an AWS API.
