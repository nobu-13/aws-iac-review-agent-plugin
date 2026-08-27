# Contributing

Thanks for considering a contribution.

This project reviews AWS Infrastructure as Code by combining deterministic static
analysis with agent semantic review. Two properties matter more than feature
count, and most of the conventions below exist to protect one of them:

- **The deterministic part stays deterministic.** Same input, byte-identical
  output. A contribution that introduces a timestamp, an absolute host path, or
  an unordered iteration into the report breaks a stated requirement.
- **Every input is untrusted.** Templates under review may be hostile. Parsing
  one must never execute it, leak the environment, or read outside the
  workspace.

Read `docs/architecture.md` for how a review is put together, and
`docs/security-model.md` for what the plugin defends against.

## Development environment setup

### Prerequisite tool versions

| Tool | Minimum | Check | Install (macOS) | Install (Linux) |
| --- | --- | --- | --- | --- |
| Python 3 | 3.9 | `python3 --version` | `brew install python@3.11` | distribution package, or `pyenv` |
| PyYAML | 6.0 | `python3 -c "import yaml; print(yaml.__version__)"` | `pip install 'PyYAML>=6.0'` | same |
| cfn-lint | 1.0.0 | `cfn-lint --version` | `pip install cfn-lint` | `pip install cfn-lint` |
| cfn-guard | 3.0.0 | `cfn-guard --version` | `brew install cloudformation-guard`, or the official install script | the official install script, or `cargo install cfn-guard` |
| AWS CDK CLI | 2.0.0 | `cdk --version` | `npm install -g aws-cdk` | `npm install -g aws-cdk` |

Python 3.9 is the floor because the plugin targets the system interpreter on
supported platforms. Code must run on 3.9, so no `match` statement, no
`X | Y` annotations at run time, and no `tomllib`.

The CDK CLI is optional. It is needed only to work on the `--confirm-cdk-synth`
path; everything else runs without it.

Windows is out of scope for v0.1. Use macOS or Linux, or a Linux container.

### Setting up

```sh
git clone <your fork> aws-iac-review-agent-plugin
cd aws-iac-review-agent-plugin
python3 -m pip install 'PyYAML>=6.0'
python3 -m pip install -e '.[dev]'
```

The last command installs the test dependencies declared in `pyproject.toml`
under `[project.optional-dependencies] dev`: `pytest`, `pytest-cov` and a pinned
`hypothesis`. Nothing under `iacreview/` or `skills/` imports any of them.

If a tool installed with `pip install --user` is not on your `PATH`, put its
script directory on `PATH` in your shell profile. Do not hard-code such a path
into source, tests, or documentation.

The plugin is not published to PyPI. `pyproject.toml` exists for dependency
declaration and test configuration only; the plugin is distributed as a
directory.

### Repository layout

| Path | Contents |
| --- | --- |
| `plugin.json` | the Agent Plugins 1.0.0 manifest, treated as a public interface |
| `iacreview/` | the deterministic Python core: parsing, normalization, dedup, path containment, process execution |
| `skills/<name>/SKILL.md` | one Skill per responsibility, plus its `scripts/` entry points |
| `rules/<category>/` | cfn-guard rules and their `_meta.json` sidecars |
| `benchmark/cases/` | templates with deliberate defects, plus ground truth |
| `examples/` | small, correct templates for users to read |
| `tests/` | `unit/`, `integration/`, `negative/`, `property/`, `regression/`, `fakebin/` |
| `docs/` | architecture, security model, benchmark methodology, Finding schema |

Two separations are load-bearing. Templates with deliberate defects live under
`benchmark/cases/` and never under `examples/`, so nobody copies a broken
template into a real stack. Kiro-specific material lives under `.kiro/` and
`docs/kiro-power.md`, so the portable core loads in any Agent Plugins 1.0.0
compliant client.

## Coding standards

Deterministic components are Python 3. That covers template parsing, cfn-lint
and cfn-guard output parsing, IAM policy analysis, Finding normalization,
deduplication, and benchmark aggregation. Shell is limited to simple invocation
wrappers with no conditional data processing.

**Python**

- Explicit type annotations on every public function signature.
- Small functions, single responsibility, explicit exceptions. Prefer a readable
  name over a comment explaining an unclear one.
- Standard library plus PyYAML. See "Proposing a dependency" below.
- No absolute host paths, timestamps, or environment values in stdout. Sort
  every directory walk and set iteration; serialize JSON with `sort_keys=True`.
- Machine-readable JSON on stdout, human-readable diagnostics on stderr.
- Validate arguments before doing any other work, and exit with the documented
  non-zero code on failure. Entry points are non-interactive and never read
  prompts from stdin.
- Never build a shell command by string concatenation. Pass an argument list,
  and route every subprocess through `iacreview.proc`. A property test scans the
  shipped code and fails if any other module spawns a process.
- Resolve every input path through `iacreview.pathguard` rather than using it
  directly.

**Skills**

Each `SKILL.md` is English, ASCII, and carries front matter with `name` (equal to
its directory name) and `description`. See the Skill contribution guide below.

**Documentation**

`README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `LICENSE` and everything under
`docs/` are written in English. Japanese supplementary documents are welcome
alongside the English original with an identifying suffix such as `README.ja.md`;
they never replace it.

Do not describe an unimplemented capability as available. Planned work belongs in
the README Roadmap section.

**`ruff` and `mypy` are recommended, not required.** They are useful locally:

```sh
ruff check iacreview
mypy iacreview
```

Neither is a dependency of the plugin, and neither gates a contribution. Where
continuous integration runs them, it treats their output as a warning. The type
annotations this project asks for can be written without `mypy` installed.

## Testing procedures

### Commands

```sh
# the whole suite
python3 -m pytest

# one layer
python3 -m pytest tests/unit
python3 -m pytest tests/integration
python3 -m pytest tests/negative
python3 -m pytest tests/property
python3 -m pytest tests/regression

# one file, or one test
python3 -m pytest tests/unit/test_dedup.py
python3 -m pytest tests/unit/test_dedup.py -k idempotent

# coverage, with the gate the project holds itself to
python3 -m pytest --cov=iacreview --cov=benchmark/harness --cov-fail-under=80

# determinism under hash randomization
PYTHONHASHSEED=random python3 -m pytest tests/property

# the benchmark; every category must report PASS
python3 benchmark/harness/run_benchmark.py --cases benchmark/cases --mode combined
```

`pyproject.toml` sets `addopts = "-q --strict-markers"`, so `pytest` is already
quiet. Adding a second `-q` suppresses the summary line as well, which is rarely
what you want.

cfn-lint and cfn-guard must be resolvable on `PATH` for the integration tests
that invoke them. Tests that cover a missing or broken tool do not uninstall
anything: they replace `PATH` with a directory under `tests/fakebin/`.

### What to write

| Change | Tests it arrives with |
| --- | --- |
| New or changed deterministic function | unit tests, including the boundary and error cases |
| New entry point behaviour | an integration test running it as a real subprocess |
| A universal claim ("for any Finding list...") | a named property test under `tests/property/` |
| A fixed defect | a regression test that fails before the fix |
| A security-relevant change | a regression test, without exception |
| A new cfn-guard rule or new review logic | at least one benchmark case that makes it fire |

Unit tests and property tests complement each other. A property states the
invariant; a unit test pins the specific example a reader can follow.

Do not use a mock or fabricated data to make a test pass. If a test cannot be
written against real behaviour, the design is the thing to discuss.

### Ground truth discipline

Ground truth is authored **from the defects deliberately placed in a benchmark
template, before any review is run against that template**. Deriving expected
values from observed review output is prohibited: it turns the benchmark into a
record of current behaviour, which can no longer detect a regression in it.

In practice:

1. Write `benchmark/cases/case-<NNN>-<slug>/template.yaml` with the defects you
   intend to measure. Keep it small and syntactically valid, and keep every
   resource that is not carrying a defect fully compliant, so the case measures
   its own category rather than the installed rule catalogue.
2. Write `ground_truth.json` from those defects. Set `authored_before_review` to
   `true`.
3. Commit `ground_truth.json` together with the template, or in an earlier
   commit. The commit order is the one part of this a reviewer can check
   mechanically, and it is a deterrent rather than a proof; the declaration is
   yours to honour.
4. Then run the benchmark, and classify every disagreement instead of editing
   expectations to match output.

`benchmark/README.md` documents the ground-truth format, the matching rules and
the pass/fail thresholds. Benchmark templates carry no credentials and no real
AWS account IDs; use a placeholder such as `123456789012`.

**Any new Guard rule or new review logic arrives with at least one benchmark
template that exercises it.** Otherwise nothing measures whether it keeps
working.

### When a test fails

Never weaken a requirement to make a test pass. Classify the failure first, and
say which class it is in the pull request:

| Class | What it means | What to do |
| --- | --- | --- |
| Implementation Bug | the code does not do what the requirement says | fix the code, and add a regression test that fails before the fix |
| Test Bug | the test asserts something the requirement does not say | fix the test, and record why the assertion was wrong |
| Missing Requirement | behaviour is genuinely undefined | raise it for discussion before writing either side; a requirement change is not a side effect of a test fix |
| Agent nondeterminism | the failure comes from agent output varying between runs | evaluate agent output structurally, not by string equality; pin agent findings as a fixture so the pipeline stays testable |
| Tool version difference | cfn-lint or cfn-guard behaves differently than assumed | record the versions in the pull request, and prefer a fixture over an assertion about the installed catalogue |

A failure you cannot place in one of these classes is not yet understood.

### Pinning a property-test counterexample

`hypothesis` prints a falsifying example when a property fails. That example is
the valuable output, and it does not survive in the property test alone: the
generator may not draw it again, and the `.hypothesis/` database is local and not
committed. Real defects in this repository were found this way, and the
counterexample for each is pinned as a case under `tests/regression/`.

The workflow:

1. Copy the falsifying example from the `hypothesis` output.
2. Add a test under `tests/regression/` that reproduces it as a plain,
   deterministic case, with no generator involved. Confirm it fails against the
   unfixed code.
3. Fix the defect. The regression test now passes.
4. **Keep the property test.** The regression test pins the one input; the
   property keeps searching for the next one. Neither replaces the other.

Each file under `tests/regression/` opens with a module docstring stating which
property or report found it, what the defect was, why it mattered, and what the
fix was. `test_sec_symlink_loop.py` is the model to follow. Security cases are
named `test_sec_<topic>.py`.

## Guard rule contribution guide

### Directory structure and naming

```text
rules/
  backup/
    _meta.json
    rds_backup_retention.guard
    rds_deletion_protection.guard
  encryption/
    _meta.json
    rds_storage_encrypted.guard
    s3_bucket_encryption.guard
  iam/
  logging/
  public-access/
  tagging/
```

There are six category directories, each holding exactly one `_meta.json` and one
or more `.guard` files. Conventions, all of them enforced by
`tests/unit/test_guard_rules.py`:

| Convention | Detail |
| --- | --- |
| File name | `<rule_name>.guard`, lower snake case, typically `<resource>_<property>` (`s3_bucket_encryption`) |
| One rule per file | exactly one `rule` declaration |
| Rule name equals file stem | the rule name is the join key for the `_meta.json` sidecar and for `Evidence[0].RuleId` |
| Custom message | every rule carries a `<< ... >>` message holding the remediation guidance |
| Header comment | the category, the requirement it implements, what it matches, and any known limitation |
| Sidecar location | one `_meta.json` per category directory, next to the rules it describes; a nested one would never be consulted |
| Sidecar shape | `schema_version`, `category` (equal to the directory name), `normalized_category`, `default`, `rules` |
| Rule entry | `severity`, `why_it_matters`, `recommendation`, and optionally `normalized_category` and `finding_type` to override the category default |

### Adding a rule

1. **Create a new `.guard` file** in the appropriate category directory. Do not
   edit an existing rule file. An existing rule is referenced by name in
   findings, in `_meta.json`, and in benchmark ground truth, so changing what it
   matches changes the meaning of results already recorded against it.
2. **Add exactly one entry to that directory's `_meta.json`**, keyed by the rule
   name, carrying the severity and the two prose fields. Without the entry the
   finding would silently fall back to the category default.
3. **Add a benchmark case** under `benchmark/cases/` whose template makes the new
   rule fire, with ground truth authored from the defects first (Requirement 11
   AC16).
4. **The coverage test catches what you forgot.** `test_guard_rules.py` walks
   every `.guard` file and asserts the rule name resolves in the sidecar, that no
   sidecar entry lacks a rule file, and that cfn-guard parses every bundled rule.
   A forgotten `_meta.json` entry fails the suite rather than degrading quietly.
   The same module holds an explicit list of the bundled rule
   files, so a new rule also means one line there; that list is what makes an
   accidentally added or deleted rule visible in review.

A new category directory additionally needs its `normalized_category` to be one
of the closed vocabulary in `iacreview/category_map.json`. If the category you
want does not map to an existing Normalized_Category, raise it before writing
the rule: the vocabulary is closed on purpose, and extending it affects
deduplication.

## Skill contribution guide

Each Skill is one responsibility. The five shipped Skills are
`cfn-lint-review`, `cfn-guard-review`, `iam-review`, `cloudformation-review` and
`iac-review`. Do not duplicate one Skill's logic in another; share it through
`iacreview/`.

```text
skills/<skill-name>/
  SKILL.md
  scripts/<entry_point>.py
```

`SKILL.md` requirements, enforced by `tests/unit/test_skills.py`:

- YAML front matter with `name` equal to the directory name, and a `description`
  stating both what the Skill can do and when to select it. Where a sibling Skill
  covers an adjacent job, the description names it, so an agent choosing between
  them has the boundary in front of it.
- Exactly one top-level heading, then these level-2 sections in this order:
  `Purpose`, `When to use this skill`, `Input`, `Output`, `Limitations`,
  `Dependencies`. None may be empty.
- English, ASCII only.
- `Dependencies` names Python and every external tool the Skill invokes, and
  states that the tool is an external run-time dependency not contained in the
  plugin package. A Skill that launches no tool says so.
- Documented exit codes exist in the shared exit-code table, and a
  tool-launching Skill documents the tool-failure codes.
- Every advertised entry point exists under `scripts/`, and every script under
  `scripts/` is advertised.
- `Output` states that stdout carries JSON only, with keys inside the shared
  contract.

Scripts hold deterministic work only. Do not encode agent judgement in a script,
and do not move deterministic logic into prose that an agent has to re-derive.
Guidance for the agent belongs in `SKILL.md`; anything a tool can decide belongs
in code.

A new Skill also needs its name added to the expected list in
`tests/unit/test_skills.py`, and integration coverage for its entry points.

## Security issue handling

**Report a suspected vulnerability privately. Do not open a public issue, and do
not open a pull request, for an unfixed vulnerability.** Use the repository's
private reporting channel and allow time for a fix and a release before any
public description.

Include what you have: the affected version or commit, the input that triggers
the behaviour, what happens, and what you expected. A crafted template that
demonstrates the problem is the most useful thing you can send, and it is also
untrusted input, so describe it rather than asking anyone to run it blind.

**Never put a credential in this repository or in a report.** No access key,
secret key, session token, API key, password, or MCP secret in code, logs, tests,
examples, benchmark templates, documentation, issues, or pull requests. Use
placeholder account IDs such as `123456789012`. If a real credential has been
committed anywhere, treat it as compromised and rotate it; removing the commit
is not sufficient.

Things that are in scope as security issues, because the plugin's stated
boundaries cover them: escaping path containment, executing content from a
template being reviewed, leaking environment or host details into output,
building a shell command from untrusted input, and an unhandled exception on
malformed input. `docs/security-model.md` states each claim and names the test
that pins it.

Things the plugin does not do, by design, and will not start doing: creating,
changing, or deleting AWS resources; deploying; applying a remediation
automatically; changing account settings. Review is read-only. A contribution
that adds a write path to AWS is out of scope for v0.1.

**A security-relevant change arrives with a regression test.** That is not a
guideline; it is Requirement 12 AC12. Put it under `tests/regression/` following
the conventions above, and say in the pull request which behaviour it pins.

Findings must rest on evidence. Do not assert that a vulnerability exists on
inference alone, and do not inflate severity. Keep the distinction between a
confirmed issue, a likely risk, a context-dependent recommendation, and something
informational.

## Pull request process

1. **Open an issue first** for anything beyond a small fix: a new rule, a new
   Skill, a requirement question, or a dependency. It is cheaper to align on
   scope before the code exists. A security issue goes through the private
   channel instead.
2. **Branch from the default branch** in your fork. One concern per branch.
3. **Keep the change scoped.** No unrelated reformatting, no drive-by
   refactoring, no generated artifacts, no temporary files. A reviewer should be
   able to see the whole change at once.
4. **Run the checks locally** before opening the pull request:

   ```sh
   python3 -m pytest
   python3 benchmark/harness/run_benchmark.py --cases benchmark/cases --mode combined
   ```

   The suite passes with no failures, and every benchmark category reports
   `PASS`. Where continuous integration is configured, it runs the same commands
   across the supported Python versions and both supported operating systems,
   plus a coverage gate at 80 percent and a secret scan.
5. **Describe the change** in the pull request:

   - what it changes and why;
   - which requirement or acceptance criterion it addresses;
   - what you tested, and the versions of cfn-lint and cfn-guard you tested
     against;
   - for a failing test you touched, which class of failure it was;
   - for a new rule or new review logic, which benchmark case exercises it;
   - for a security-relevant change, which regression test pins it;
   - for a new dependency, the five answers below.
6. **Update the documentation in the same pull request.** A behaviour change that
   leaves `README.md`, `docs/` or a `SKILL.md` describing the old behaviour is
   not finished. User-visible changes are recorded in `CHANGELOG.md`, in
   particular breaking changes, Finding schema changes, Skill changes, dependency
   changes and security fixes.
7. **Respond to review by pushing commits.** Do not force-push over a review in
   progress unless a maintainer asks.

A change is done when the requirement is met, the acceptance criteria are met,
tests exist and pass, errors are handled, the security impact has been
considered, the documentation is updated, and nothing unrelated came along.

### Proposing a dependency

The deterministic components depend on the Python standard library plus at most
one YAML parsing dependency. That is Requirement 16 AC3, and it is the reason
this project is portable.

Development and test dependencies are **not** subject to that constraint
(Requirement 16 AC4). `pytest`, `pytest-cov` and `hypothesis` are declared
separately in `pyproject.toml` and nothing in `iacreview/` or `skills/` imports
them. Proposing a dev or test dependency is an ordinary discussion. Proposing a
**run-time** dependency conflicts with a stated requirement, so it needs the
requirement changed first, not merely a convincing pull request.

Either way, a pull request that adds a dependency answers these five questions in
its description, from the project's technical policy:

1. Can this be done with standard functionality?
2. Is it genuinely necessary?
3. Is it maintained?
4. Does it carry a security risk?
5. Does it harm portability?

Pin the version rather than using an open range, and prefer a well-known,
actively maintained package. Saving a few lines of code is not a reason to add a
dependency. `docs/architecture.md` carries the same interpretation of AC3 and
AC4, and explains why each current dev dependency earned its place; read it
before proposing one.

## Licensing of contributions

This project is licensed under the Apache License 2.0; see `LICENSE`.

**By submitting a contribution, you agree that it is licensed under Apache-2.0**,
under the terms of Section 5 of that license: a contribution you intentionally
submit for inclusion in this work is provided under the license terms, without
any additional conditions, unless you state otherwise explicitly.

Only contribute code you have the right to contribute. Do not paste code from a
source under an incompatible license, and do not paste code whose license you
have not checked. If a contribution derives from third-party work, say so and
name the license, so the attribution in `NOTICE` can be kept accurate.

Source files carry no license header; Apache-2.0 does not require one.
