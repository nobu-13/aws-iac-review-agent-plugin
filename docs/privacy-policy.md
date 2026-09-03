# Privacy Policy

_Last updated: 2026-09-03_

This Privacy Policy describes how the `aws-iac-review-agent-plugin` package
handles data. It reflects the plugin's actual behaviour, which is enforced by
the design documented in [`security-model.md`](security-model.md) and pinned by
the test suite.

## Summary

This plugin does not collect, store, or transmit any personal data or telemetry.
It runs locally, reads only the Infrastructure as Code you point it at, and
writes its result to standard output. It contacts no AWS API and no external
service of its own.

## What the plugin processes

- **Input templates.** CloudFormation templates (YAML or JSON) and synthesized
  CDK output under `cdk.out/` that you supply with `--target`. These are read
  from your local workspace and treated as untrusted input.
- **External tool output.** The output of cfn-lint, cfn-guard, and, only behind
  the explicit `--confirm-cdk-synth` flag, the AWS CDK CLI. These tools run
  locally as subprocesses.

The plugin's own deterministic code processes this data entirely on the machine
where it runs.

## What the plugin does not do

- **No telemetry or analytics.** No usage data, metrics, or diagnostics are sent
  anywhere.
- **No network calls of its own.** The plugin calls no AWS API — there is no AWS
  SDK dependency — and opens no connection to any service. cfn-lint, cfn-guard,
  and `cdk synth` are local subprocesses.
- **No storage of your data.** Nothing is written to your workspace. The review
  report is written to standard output and is yours to keep or discard.
- **No credential handling.** AWS credentials are withheld from every child
  process through an environment allowlist. No credential is read, logged, or
  transmitted. See [`security-model.md`](security-model.md).
- **No automatic action.** The plugin is read-only. It creates, modifies, or
  deletes no AWS resource, deploys nothing, and applies no remediation.

## Data you send to third parties

The core review flow sends nothing to third parties. Two boundaries are worth
naming so you can reason about your own data flow:

- **Host agent reasoning.** The agent-reasoning Skills (`cloudformation-review`,
  `iam-review` layer 2) are interpreted by whichever host agent runtime loaded
  the package. When that host agent reasons over the extracted facts, the facts
  leave this plugin's control and are subject to the host agent's own privacy
  terms. This plugin's deterministic code performs no such transmission.
- **Optional MCP.** MCP is not a dependency and no `mcp.json` ships in the
  plugin. If you configure an MCP server yourself, a template path or template
  content sent to that server leaves this plugin's control at that point. See
  [`mcp/README.md`](mcp/README.md) for the per-server record of purpose,
  permissions, network access, credentials, and data sent externally.

In both cases the transmission is performed by software outside this plugin,
under your configuration, and is governed by that software's privacy terms.

## Changes to this policy

Material changes to how the plugin handles data are recorded in
[`../CHANGELOG.md`](../CHANGELOG.md) and reflected here with an updated date.

## Contact

Questions about this policy, or about how the plugin handles data, can be raised
through the channels listed in the README's Support section and in
[`../CONTRIBUTING.md`](../CONTRIBUTING.md). Report a suspected security or privacy
vulnerability privately rather than as a public issue.
