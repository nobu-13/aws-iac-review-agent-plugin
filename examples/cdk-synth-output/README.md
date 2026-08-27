# Reviewing a synthesized CDK application

This plugin reviews CloudFormation. A CDK application becomes reviewable once it
has been synthesized into CloudFormation, so the flow is:

```text
CDK source  ->  cdk synth  ->  cdk.out/*.template.json  ->  review
```

The plugin joins that pipeline at the third arrow. It reads the templates under
`cdk.out/`; it does not read the TypeScript, Python or Java that produced them,
and it does not reconstruct the constructs behind a resource.

This directory holds no `cdk.out/` of its own. A cloud assembly is a build
artifact: it is regenerated from the source on every synth, it can be several
megabytes, and a checked-in copy is a template that no longer matches the code
beside it. Point the review at your own project instead.

## The plugin never synthesizes on its own

`cdk synth` is not a read-only operation. Running it executes the application's
code and its dependencies' lifecycle scripts, which is why nothing in this
plugin starts it unless you say so explicitly. The warning is stated once in
`iacreview/cdk.py` as `SYNTH_WARNING`, and everything that mentions the risk
quotes that constant:

> cdk synth executes this project's own code and the lifecycle scripts of its
> dependencies. This plugin provides no sandboxing for that execution: the synth
> process runs with your full user privileges. Review CDK source you do not
> trust only after inspecting it.

So, if `cdk.out/` is missing or stale, produce it yourself, with your project's
own toolchain, having read the warning above:

```sh
cd path/to/your/cdk/app
cdk synth
```

You are then in the situation the rest of this file describes: a directory with a
`cdk.json` and a `cdk.out/` beside it.

## Reviewing what has already been synthesized

Point `--target` at the project directory. Synthesized templates are found under
`cdk.out/`, and reported separately from templates you wrote by hand:

```sh
python3 skills/iac-review/scripts/run_iac_review.py --target path/to/your/cdk/app
```

```json
{
  "target": {
    "files": ["path/to/your/cdk/app/templates/legacy.yaml"],
    "cdk": {
      "detected": true,
      "synthesized_templates": ["path/to/your/cdk/app/cdk.out/MyStack.template.json"]
    }
  }
}
```

Or name one template directly, which is the shortest way to review a single
stack:

```sh
python3 skills/iac-review/scripts/run_iac_review.py \
  --target path/to/your/cdk/app/cdk.out/MyStack.template.json
```

Either way the review is the same one the handwritten examples in this directory's
siblings get: cfn-lint, the bundled cfn-guard rules and the deterministic IAM
detectors, merged into one report.

Two notes on the output:

- Reviewing a CDK project without `--confirm-cdk-synth` adds one
  `invalid_arguments` entry to `errors[]`, recording that synthesis was skipped
  and that only the templates already under `cdk.out/` were read. The exit code
  stays `0`: narrower coverage is not a failed review. If `cdk.out/` is empty,
  there is nothing to review and the exit code is `8`
  (`NO_REVIEWABLE_TEMPLATE`).
- Every path in the report is relative to the directory you ran the command
  from, and every `--target` must resolve inside it.

## Reading findings against CDK source

A finding names the logical ID CloudFormation uses, which for CDK is the
construct path with the hash CDK appends -- `MyStackMyBucketF68F3FF0`, not
`MyBucket`. To get from there back to the code:

- `cdk.out/tree.json` maps logical IDs to construct paths.
- The template's `Metadata` section carries an `aws:cdk:path` entry per resource.

Fix the construct, synthesize again, review again. Editing a template under
`cdk.out/` fixes nothing: the next synth overwrites it.

## What this flow does not cover

- **Constructs and their defaults.** A finding describes the synthesized
  resource. Which L2 construct or which prop produced it is not something the
  review can tell you; `aws:cdk:path` is the way back.
- **Assets.** Lambda bundles, Docker images and file assets under `cdk.out/` are
  not inspected. Only `*.template.json` is read.
- **Stack dependencies and pipelines.** Each template is reviewed on its own.
  Cross-stack references appear as unresolved values rather than as links.
- **Anything decided at deploy time.** Parameters, `Fn::ImportValue` and
  context lookups have no value during the review. The IAM detectors report such
  a position as informational rather than guessing what it becomes.
