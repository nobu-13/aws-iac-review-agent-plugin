# MCP Configuration (Opt-In)

This directory holds an optional MCP configuration example and the record of
what a configured MCP server means for the security of a review
(Requirement 1 AC8, Requirement 9 AC8).

`docs/security-model.md` states the boundary between the host agent and an MCP
server process. This file is the per-server record: for each server you decide
to configure, it says what that server is for and what it does with the
boundary. If the two documents ever disagree, this one describes the
configuration you actually loaded.

## MCP Is Not a Dependency

No `mcp.json` ships in the plugin root (Requirement 1 AC7), and every core
capability works fully without one (Requirement 10 AC4):

| Capability | Needs MCP |
| --- | --- |
| cfn-lint execution and Finding normalization | No |
| cfn-guard execution against the bundled rules | No |
| IAM review (deterministic detectors) | No |
| Skill-based Agent Review | No |
| Unified report generation | No |

The plugin's deterministic code never opens an MCP connection. Nothing under
`iacreview/` speaks the protocol, imports a client, or reads `mcp.json`. Only
the host agent runtime does, and only if you put a configuration in front of
it. Adding a server therefore cannot make a review faster or more accurate on
its own; it adds a capability the agent may use while reasoning.

MCP enhancement is a roadmap candidate in this project's plan. It is entirely
yours to configure, and the default posture is no server at all.

## Optional: MCP for Agent Review (v0.3.0)

v0.3.0 added `skills/cloudformation-review/scripts/build_prompt.py`, which turns
a template's deterministic facts into a structured review prompt. That prompt is
the natural payload for an MCP server that reaches a language model: the server
sends the prompt, the model returns findings, and those findings are fed back
through `iac-review --agent-findings`.

The plugin does not ship such a server and does not open the connection. The
division of labour is deliberate:

| Step | Who does it | MCP involved |
| --- | --- | --- |
| Extract deterministic facts | `extract_facts.py` (plugin) | No |
| Build the review prompt | `build_prompt.py` (plugin) | No |
| Send the prompt to a model | host agent, or an MCP server you configure | Optional |
| Validate and merge the findings | `iac-review` (plugin) | No |

Because the prompt is a deterministic function of the facts, the two model-free
steps are reproducible regardless of whether a model is ever called. If you
configure an MCP server for the reasoning step, record it below like any other
server: what it sends externally is the prompt, which embeds the template facts,
so a template's resource names and property values leave your environment the
moment that call is made. Treat that as data sent externally and decide
accordingly.

## Before You Add a Server

A server is worth adding only when it does something the plugin cannot, and the
project's technical policy requires that value to be stated rather than assumed.
Three questions, in order:

1. **What can the agent not do today?** If the gap is deterministic analysis,
   the answer is a cfn-guard rule under `rules/` or a Python detector, not a
   server. Deterministic work belongs in deterministic code.
2. **Does the server send Template content anywhere?** Templates are the input
   this plugin treats as untrusted, but they are also *your* infrastructure
   description. A server that transmits them off the machine changes the review
   from a local operation into a disclosure.
3. **Can you fill in all nine items below from the server's own documentation
   and source?** If an item cannot be established, record it as unknown and
   treat the server as unsuitable until it can. A guess in a security record is
   worse than a blank.

## The Example File

`mcp.json.example` in this directory is the configuration shape, ready to copy:

```json
{
  "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
  "mcpServers": {
    "example-stdio-server": {
      "type": "stdio",
      "command": "<your-mcp-server-executable>",
      "args": [
        "<first-argument>",
        "<second-argument>"
      ]
    }
  }
}
```

> **Status.** No concrete MCP server is named here. The command and the
> arguments are placeholders, and the file is a template rather than a runnable
> configuration. Naming a third-party server would mean asserting its
> permissions, its network behaviour and its data handling in a security
> document without having verified any of them, and the plugin needs no server
> to work. Replace the placeholders with a server you have evaluated yourself
> against the nine items below.

To use it:

1. Copy the file to the plugin root as `mcp.json`. The runtime reads it from
   the root of the package, never from `docs/`.
2. Replace the server key, `command`, and `args` with real values. Keep
   `"type": "stdio"` (or set the transport your server actually uses;
   see below).
3. Restart the host agent so the package is loaded again.

Two consequences of copying it, both intended:

- `tests/unit/test_manifest.py::test_no_mcp_json_at_plugin_root` will fail while
  the copy is present. That test pins Requirement 1 AC7, which forbids the
  *shipped package* from containing an `mcp.json`. Your local copy is your
  configuration, not part of the package, and the test failing is the check
  doing its job.
- If you work in a clone of this repository, do not commit the copy. It is
  local configuration, and on the transports that accept `headers` it is a
  plausible place for a token to end up in version control.

Copied verbatim and unedited, the example fails to start, because
`<your-mcp-server-executable>` is not on `PATH`. That failure is the behaviour
described under [Failure Behaviour](#failure-behaviour): the runtime skips the
entry and the review continues.

## Per-Server Record

The nine items below are what has to be known about a server before it is
configured. The text under each explains what the item means and what is true
of this plugin regardless of which server you pick. What is specific to your
server is yours to fill in, using the template at the end.

### Purpose

Why the server is configured at all: the capability the agent gains, and the
review question that capability answers.

State it narrowly. "Looking up the current property schema of an AWS resource
type while explaining a Finding" is a purpose that can be checked against what
the server does. "AWS help" is not, and a purpose too broad to check is a
purpose that cannot be revoked when the server stops matching it.

Nothing the plugin reports depends on this. Findings from cfn-lint, cfn-guard
and the deterministic IAM detectors are produced without the server; a server
can only inform the agent's reasoning, which is already reported at
`Confidence: Likely` or `Contextual`.

### Required Permissions

The permissions the server process needs, which are the permissions of whatever
account starts the host agent.

An MCP server started over stdio is a child of the agent runtime, so it runs as
you, with your filesystem access, your network access, and any credential your
environment already holds. The plugin has no say in this. Record the narrowest
set the server genuinely needs, and prefer a server that needs no AWS
permission at all, since v0.1 calls no AWS API and a read-only review has no
reason to acquire one.

The plugin's own restraint does not extend here. `iacreview.proc` runs the
external tools it starts (cfn-lint, cfn-guard, `cdk synth`) with an environment
allowlist of `PATH`, `HOME`, `LANG`, `LC_ALL`, `TMPDIR`, `AWS_REGION` and
`AWS_DEFAULT_REGION`, so that `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`AWS_SESSION_TOKEN` and `AWS_PROFILE` never reach a child. **An MCP server is
not one of those children.** It is started by the host agent, through a code
path this plugin does not participate in, and it inherits whatever environment
that runtime gives it. Do not read the plugin's credential handling as covering
your servers.

### Network Access

Whether the server talks to the network, and to where.

| Transport | Endpoint | Note |
| --- | --- | --- |
| `stdio` | None required by the transport | The process may still make its own outbound requests. The transport being local says nothing about the program |
| `streamable-http` | The `url` you configure | Agent Plugins 1.0.0 requires HTTPS for a remote, non-loopback endpoint |
| `sse` | The `url` you configure | Legacy HTTP+SSE. Same HTTPS requirement |

Record loopback and remote separately, and record the destination host for a
remote one. A review that runs in CI against a remote server has a dependency
on that host being reachable, which is a second reason to prefer local.

### Credentials

**Agent Plugins 1.0.0 defines no portable credential mechanism for MCP.** There
is no OAuth flow and no portable secret reference in the package format.

A `headers` entry on an HTTP transport is **visible data, not a secret store**.
It is a string in a JSON file that ships or sits inside the package directory,
readable by anything that can read the file, and it belongs in no repository.
Passing a credential to a server therefore depends on client-specific machinery
such as environment variables, which is by definition not portable: a
configuration that works in one client may hold no credential in another.

The conservative reading, and the one this project follows: a server that needs
a credential to be useful is a server whose configuration cannot be shared
portably. Record which credential the server needs, where it comes from, and
who can read it in that location. If the answer is "a token in `mcp.json`",
that is a finding about your setup, not a configuration step.

### Data Sent Externally

What leaves the machine, and to whom.

The candidates are the Template path, the Template content, Finding text, and
whatever the agent quotes from a Template while asking a question. A Template
carries account structure, resource names, network layout and sometimes
hardcoded values that should not have been there in the first place. Treat
Template content reaching a server as disclosure to that server's operator, and
record it as such.

The plugin's own outbound data is nothing: v0.1 makes no network request and
calls no AWS API. Any external transmission during a review is either the host
agent's model traffic or a server you configured.

### Failure Behaviour

If a server cannot start, Agent Plugins 1.0.0 has the runtime skip that entry
and continue loading the rest of the package. Skills, `plugin.json` and the
other servers are unaffected.

The plugin's core review functionality is unaffected too (Requirement 10 AC4,
AC5). cfn-lint, cfn-guard, IAM review and report generation do not consult the
server and cannot notice it missing. Where a review would have used it, expect
a warning from the host agent and a review that continues with skill-only
capabilities, which is the same result as never having configured one.

There is no fallback to arrange and none to configure. This is the practical
argument for keeping MCP opt-in: a capability whose absence degrades nothing is
a capability that can be removed the moment it stops being trustworthy.

### Data Flow Direction

Two directions, both between the host agent and the server:

```text
Host Agent  ---- Template path, Template content, questions ---->  MCP Server
Host Agent  <---- tool results, resources, prompts --------------  MCP Server
```

The plugin is not on either arrow. Its deterministic components read Templates
from disk, run external tools through `iacreview.proc`, and write a report to
stdout; none of that passes through an MCP server, and no server response
reaches a Finding except by way of the agent, where it arrives as agent
reasoning and is validated by `iacreview.agentin` like any other agent output.
A server cannot inject a `Confirmed` Finding, and it cannot claim
`Source: cfn-lint`.

What crosses the first arrow leaves this plugin's control at that point. The
redaction rules that keep a credential out of a Finding's `Evidence` apply to
the report, not to a Template the agent chose to quote to a server.

### stdio Transport Notation

For `stdio`, `command` is **one executable token** and every argument goes in
the `args` array (Requirement 15 AC5). This is the same rule the plugin follows
for its own subprocesses: an argv array, no shell, and no string that a shell
could reinterpret.

```json
"command": "server-executable",
"args": ["--flag", "value"]
```

Not this, which makes the whole line one executable name containing spaces:

```json
"command": "server-executable --flag value"
```

Path resolution, per the schema and the specification:

| Form | Meaning |
| --- | --- |
| A bare name | Resolved against `PATH` by the runtime |
| A `./`-relative path | Relative to the plugin root, for an executable bundled in the package |
| `${PLUGIN_ROOT}` | The plugin's own directory |
| `${PLUGIN_DATA}` | The plugin's client-provided data directory |

`env` may not define `PLUGIN_ROOT` or `PLUGIN_DATA`; the schema rejects those
names so that the placeholders cannot be redefined. `cwd`, if set, must be
plugin-relative or rooted at one of the two placeholders.

This package bundles no executable and none of these paths is used by anything
shipped. `tests/unit/test_manifest.py` asserts that no compiled binary exists
anywhere in the repository, so a `./`-relative `command` in your configuration
refers to something you added.

The transport must be explicit in every entry (Requirement 1 AC9). The schema
enforces it: `type` is a required constant of `stdio`, `streamable-http`, or
`sse`, and each transport accepts only its own keys, so a `command` on an HTTP
entry or a `url` on a stdio entry is a validation error rather than a silently
ignored field.

### Agent-to-Server Security Boundary

The boundary is between the **host agent runtime** and the **MCP server
process**, and this plugin sits on neither side of it.

| Property | Where it stands |
| --- | --- |
| Who starts the process | The host agent runtime. Not the plugin |
| Trust of the server's output | Untrusted. It reaches a Finding only as agent reasoning, validated by `iacreview.agentin`, capped at `Likely` or `Contextual` |
| Credential isolation | None is provided by the package format. The process inherits the runtime's environment, and the plugin's `INHERITED_ENV_VARS` allowlist does not apply |
| Containment | None. Path containment (`iacreview.pathguard`) constrains this plugin's own file access, not a separate process's |
| Sandboxing | None. A server runs with your full user privileges, like `cdk synth` does |
| Failure | Isolated to the entry. The rest of the package loads |

The comparison with `cdk synth` is the useful one. Both are arbitrary code
running as you, with no sandbox this plugin can provide. The difference is
consent: `cdk synth` requires `--confirm-cdk-synth` on every invocation and
prints a warning either way, whereas an MCP server you configured starts with
the agent and keeps running. The configuration file is the whole of the
consent, which is why it is worth reading the server's source before writing it.

## Recording Your Own Server

Copy this table into your own notes, or into a fork of this file, and fill it in
per server. An unfilled row is a reason not to configure the server yet.

| Item | Your server |
| --- | --- |
| Purpose | |
| Required permissions | |
| Network access | |
| Credentials | |
| Data sent externally | |
| Failure behaviour | |
| Data flow direction | |
| stdio transport notation | |
| Agent-to-server boundary | |

## Related Documents

| Document | What it covers |
| --- | --- |
| `docs/security-model.md` | The plugin's trust boundaries, read-only posture, and the MCP boundary in the context of the other seven |
| `docs/architecture.md` | Why `extensions` is unused in v0.1, and the portable core / client-specific split |
| `docs/finding-schema.md` | `Confidence` and `Source`, which bound what agent reasoning informed by a server can claim |
