"""Structural tests for the continuous integration workflow and its helpers.

``.github/workflows/ci.yml`` is the only place where the repository's gates are
actually enforced against a clean machine, and it is the one file no test can
observe running. So it is asserted the way ``tests/unit/test_root_docs.py``
asserts the root documents: parsed, and compared against the implementation
wherever the workflow restates something the implementation already knows.

What that means concretely, and why it is worth the indirection:

- the lowest Python version in the matrix is compared against
  ``requires-python`` in ``pyproject.toml``, so raising the floor in one place
  without the other fails here
- the ``--cov=`` arguments are compared against
  ``[tool.coverage.run] source``, so a package added to the measured set but not
  to the CI command cannot make the 80 percent gate measure a subset
- the ``cfn-lint`` and ``cfn-guard`` pins are compared against
  ``iacreview.toolcheck.TOOL_REQUIREMENTS``, so CI cannot install a version the
  plugin itself would reject
- the job that runs the determinism property is compared against the file that
  actually carries the ``Property 14`` tag comment, rather than against a path
  typed out here

The three helper scripts under ``.github/scripts/`` are covered here too. They
are not importable as a package -- ``.github`` is not a legal module name -- so
they are loaded by path. Their pure logic is exercised directly with injected
data: the Ground_Truth order check is given fixed commit answers rather than a
repository with fixture commits, which keeps it testable in a checkout that has
no git metadata at all.

Covers:
- Task 28.1           : the workflow, its matrix, its four gates and its helpers
- Task 28.2           : the advisory ``ruff`` / ``mypy`` job, and the pinned
                        ``lint`` extra it installs (Requirement 16 AC5)
- Requirement 12 AC1  : the 80 percent coverage floor is enforced by CI
- Requirement 11 AC7  : the benchmark runs and a FAIL category fails the build
- Requirement 9 AC1   : a secret scan runs over the repository
- Requirement 11 AC14, AC15 : Ground_Truth commit order is checked
- Requirement 10 AC3  : the deterministic components run on both operating
                        systems, and Property 14 also runs with a randomized
                        hash seed (Requirement 16 AC11)

Gates and the one advisory job
------------------------------

The "no gate swallows a failure" assertions are parametrized over
:data:`GATE_JOBS` rather than over every job in the workflow, because Task 28.2's
lint job is *meant* to be able to fail. Its ``continue-on-error`` case sits
directly after them, and
``test_every_job_is_either_a_gate_or_the_advisory_lint_job`` closes the gap the
split opens: a job that is in neither set -- and therefore has no assertion about
what its failure means -- fails that test.

The same split runs through the dependency assertions. :func:`declared_specs`
reads the run-time dependency and the ``dev`` extra, the specifiers a gate cannot
run without; :func:`lint_specs` reads the ``lint`` extra separately, and it is
asserted that no gate job installs it.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import pytest
import yaml

# tests/unit/test_ci.py -> tests/unit -> tests -> repository root
REPO_ROOT: Path = Path(__file__).resolve().parents[2]

WORKFLOW_PATH: Path = REPO_ROOT / ".github" / "workflows" / "ci.yml"
SCRIPTS_DIR: Path = REPO_ROOT / ".github" / "scripts"
SECRET_SCANNER_PATH: Path = SCRIPTS_DIR / "scan_secrets.py"
ORDER_CHECKER_PATH: Path = SCRIPTS_DIR / "check_ground_truth_order.py"
INSTALLER_PATH: Path = SCRIPTS_DIR / "install_cfn_guard.py"

PYPROJECT_PATH: Path = REPO_ROOT / "pyproject.toml"
CASES_DIR: Path = REPO_ROOT / "benchmark" / "cases"
PROPERTY_TESTS_DIR: Path = REPO_ROOT / "tests" / "property"

#: The job that runs the test suite and the benchmark across the matrix.
MATRIX_JOB = "test"

#: The job that re-runs Property 14 with ``PYTHONHASHSEED=random``.
DETERMINISM_JOB = "determinism"

#: The job that runs the two repository-wide checks.
HYGIENE_JOB = "repository-hygiene"

#: Jobs whose failure must fail the workflow. Task 28.2's lint job is
#: deliberately not one of them.
GATE_JOBS: Tuple[str, ...] = (MATRIX_JOB, DETERMINISM_JOB, HYGIENE_JOB)

#: The advisory ``ruff`` / ``mypy`` job (Task 28.2). Not a gate: its findings are
#: a report, and design.md's Dependency Strategy keeps both tools optional.
LINT_JOB = "lint"

#: The three interpreter versions design.md's Portability Design requires CI to
#: cover ("CI で 3.9 / 3.11 / 3.13 の 3 バージョンをテストし").
EXPECTED_PYTHON_VERSIONS: Tuple[str, ...] = ("3.9", "3.11", "3.13")

#: Runner label prefixes for the two supported operating systems. Prefixes
#: rather than exact labels because the Python 3.9 slot on macOS runs on the
#: Intel image: ``macos-latest`` is arm64 and upstream publishes no darwin-arm64
#: CPython 3.9. Requirement 10 AC3 asks for macOS and Linux, not for one
#: specific image.
LINUX_PREFIX = "ubuntu-"
MACOS_PREFIX = "macos-"

#: Requirement 12 AC1.
COVERAGE_FLOOR = 80

#: The tag comment that marks the implementation of Property 14, in the form
#: design.md's "Correctness Properties (実装規約)" fixes.
PROPERTY_14_TAG = "Feature: aws-iac-review-agent-plugin, Property 14:"

#: Ways a shell command can turn a non-zero exit into a pass. None may appear in
#: a gate job: the completion condition of Task 28.1 is that coverage below the
#: floor, a benchmark FAIL and a detected secret each fail CI.
FAILURE_SWALLOWING_FRAGMENTS: Tuple[str, ...] = ("|| true", "|| :", "set +e", "; true")

#: A pinned action reference: ``owner/repo@<40 hex>``.
PINNED_ACTION_PATTERN = re.compile(r"^[^@]+@[0-9a-f]{40}$")

#: The account ID ``benchmark/README.md`` fixes as the only one benchmark
#: templates may contain. AWS's documentation placeholder, so it names no real
#: account, and the secret scan must stay quiet about it.
PLACEHOLDER_ACCOUNT_ID = "123456789012"


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_script(path: Path) -> ModuleType:
    """Import a helper script by path.

    ``.github/scripts/`` cannot be a package: ``.github`` is not a legal
    identifier, and moving the scripts somewhere importable would put CI-only
    tooling into either the plugin package or the benchmark harness, neither of
    which ships it.
    """
    name = "ci_script_{0}".format(path.stem)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, "cannot load {0}".format(path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def workflow() -> Dict[str, Any]:
    """The parsed workflow.

    Parsing it here is also the syntax check Task 28.1 asks for: a malformed
    ``ci.yml`` fails every test in this module rather than being discovered by a
    pushed commit.
    """
    assert WORKFLOW_PATH.is_file(), "Task 28.1: {0} is missing".format(WORKFLOW_PATH)
    document = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(document, dict), "the workflow must be a YAML mapping"
    return document


@pytest.fixture(scope="module")
def workflow_text() -> str:
    """The raw workflow text, for the assertions about how it is written."""
    return WORKFLOW_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def scanner() -> ModuleType:
    """The secret scanner module."""
    return load_script(SECRET_SCANNER_PATH)


@pytest.fixture(scope="module")
def order_checker() -> ModuleType:
    """The Ground_Truth commit order checker module."""
    return load_script(ORDER_CHECKER_PATH)


@pytest.fixture(scope="module")
def installer() -> ModuleType:
    """The cfn-guard installer module."""
    return load_script(INSTALLER_PATH)


# ---------------------------------------------------------------------------
# Reading the workflow
# ---------------------------------------------------------------------------


def job_of(workflow: Dict[str, Any], name: str) -> Dict[str, Any]:
    """One job, or an assertion failure naming the missing job."""
    jobs = workflow.get("jobs")
    assert isinstance(jobs, dict), "the workflow declares no jobs"
    assert name in jobs, "the workflow has no job {0!r}; it has {1}".format(
        name, sorted(jobs)
    )
    job = jobs[name]
    assert isinstance(job, dict), "job {0!r} is not a mapping".format(name)
    return job


def steps_of(workflow: Dict[str, Any], name: str) -> List[Dict[str, Any]]:
    """The steps of one job."""
    steps = job_of(workflow, name).get("steps")
    assert isinstance(steps, list) and steps, "job {0!r} has no steps".format(name)
    return [step for step in steps if isinstance(step, dict)]


def flowed(command: str) -> str:
    """A shell command with line continuations joined and whitespace collapsed.

    A ``run:`` block is written over several lines with trailing backslashes, so
    a search for ``python3 -m pytest --cov-fail-under=80`` would otherwise
    depend on where the author happened to wrap.
    """
    joined = re.sub(r"\\\s*\n", " ", command)
    return " ".join(joined.split())


def run_commands(workflow: Dict[str, Any], name: str) -> List[str]:
    """Every ``run`` command of one job, flowed."""
    return [
        flowed(step["run"])
        for step in steps_of(workflow, name)
        if isinstance(step.get("run"), str)
    ]


def all_run_commands(workflow: Dict[str, Any]) -> List[str]:
    """Every ``run`` command of every job, flowed."""
    commands: List[str] = []
    for name in workflow.get("jobs", {}):
        commands.extend(run_commands(workflow, name))
    return commands


def uses_references(workflow: Dict[str, Any]) -> List[str]:
    """Every ``uses`` value in the workflow."""
    references: List[str] = []
    for name in workflow.get("jobs", {}):
        for step in steps_of(workflow, name):
            reference = step.get("uses")
            if isinstance(reference, str):
                references.append(reference)
    return references


def workflow_env(workflow: Dict[str, Any]) -> Dict[str, str]:
    """The workflow-level ``env`` mapping, values as strings."""
    env = workflow.get("env") or {}
    assert isinstance(env, dict), "workflow env must be a mapping"
    return {str(key): str(value) for key, value in env.items()}


def matrix_of(workflow: Dict[str, Any], name: str) -> Dict[str, Any]:
    """The ``strategy.matrix`` of one job."""
    strategy = job_of(workflow, name).get("strategy") or {}
    matrix = strategy.get("matrix")
    assert isinstance(matrix, dict), "job {0!r} declares no matrix".format(name)
    return matrix


def matrix_combinations(matrix: Dict[str, Any]) -> Set[Tuple[str, str]]:
    """The ``(os, python-version)`` pairs a matrix expands to.

    Implements the part of GitHub's expansion this workflow uses: the cross
    product of the two lists, minus ``exclude``, plus ``include`` entries that
    name both keys. Computed rather than transcribed so that the assertions below
    describe the jobs that will really run.
    """
    operating_systems = [str(value) for value in matrix.get("os", [])]
    versions = [str(value) for value in matrix.get("python-version", [])]
    combinations = {
        (system, version) for system in operating_systems for version in versions
    }
    for entry in matrix.get("exclude", []) or []:
        combinations.discard((str(entry.get("os")), str(entry.get("python-version"))))
    for entry in matrix.get("include", []) or []:
        if "os" in entry and "python-version" in entry:
            combinations.add(
                (str(entry["os"]), str(entry["python-version"]))
            )
    return combinations


# ---------------------------------------------------------------------------
# Reading the implementation the workflow has to agree with
# ---------------------------------------------------------------------------


def pyproject_text() -> str:
    """``pyproject.toml`` as text.

    Read with regular expressions rather than a TOML library, the same way
    ``tests/unit/test_root_docs.py`` does it: ``tomllib`` arrived in 3.11, this
    repository supports 3.9, and ``tomli`` is not a dependency a test justifies
    (steering/tech.md).
    """
    return PYPROJECT_PATH.read_text(encoding="utf-8")


def array_values(field: str) -> Tuple[str, ...]:
    """The strings of a single-line TOML array named ``field``."""
    match = re.search(
        r"^{0}\s*=\s*\[(?P<items>[^\]]*)\]".format(re.escape(field)),
        pyproject_text(),
        re.MULTILINE,
    )
    assert match is not None, "pyproject.toml has no single-line {0} array".format(
        field
    )
    return tuple(
        item.strip().strip("\"'")
        for item in match.group("items").split(",")
        if item.strip()
    )


def coverage_sources() -> Tuple[str, ...]:
    """``[tool.coverage.run] source`` of ``pyproject.toml``."""
    return array_values("source")


def declared_specs() -> Tuple[str, ...]:
    """Every requirement specifier CI has to install *for a gate to run*.

    The run-time dependency plus the ``dev`` extra. Requirement 16 AC3 keeps the
    first at one entry; this reads both lists rather than assuming their length.

    The ``lint`` extra is deliberately excluded. It is read by :func:`lint_specs`
    and asserted separately, because the two sets carry different obligations:
    a missing ``dev`` specifier means a gate cannot run, while a missing ``ruff``
    means an advisory job reports nothing. Folding ``lint`` in here would make
    ``test_every_declared_dependency_is_installed_by_ci`` demand that the gate
    jobs install a tool design.md classifies as optional -- which is the opposite
    of what "not a required dependency" means.
    """
    return array_values("dependencies") + array_values("dev")


def lint_specs() -> Tuple[str, ...]:
    """The ``lint`` extra of ``pyproject.toml`` (Task 28.2).

    ``array_values`` matches by field name at the start of a line, so ``dev`` and
    ``lint`` resolve to their own arrays even though both sit under
    ``[project.optional-dependencies]``. Both are written on one line, which is
    the shape that regular expression can read.
    """
    return array_values("lint")


def requires_python_floor() -> str:
    """The lowest version ``requires-python`` allows, as ``major.minor``."""
    match = re.search(
        r"^requires-python\s*=\s*[\"']>=\s*(?P<version>\d+\.\d+)", pyproject_text(), re.MULTILINE
    )
    assert match is not None, "pyproject.toml declares no '>=' requires-python"
    return match.group("version")


def version_tuple(version: str) -> Tuple[int, ...]:
    """A dotted numeric version as a comparable tuple, padded to three parts."""
    parts = [int(part) for part in re.findall(r"\d+", version)][:3]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def tool_minimum(name: str) -> str:
    """The minimum version :mod:`iacreview.toolcheck` enforces for a tool."""
    from iacreview.toolcheck import TOOL_REQUIREMENTS

    return TOOL_REQUIREMENTS[name].min_version


def property_14_test_file() -> Path:
    """The test file carrying the Property 14 tag comment.

    Located by the tag rather than by name so that renaming the file updates this
    module for free, and so that the workflow is asserted to run the test that
    really implements the property.
    """
    matches = [
        path
        for path in sorted(PROPERTY_TESTS_DIR.rglob("test_*.py"))
        if PROPERTY_14_TAG in path.read_text(encoding="utf-8")
    ]
    assert len(matches) == 1, (
        "expected exactly one file under tests/property/ carrying {0!r}; "
        "found {1}".format(PROPERTY_14_TAG, [str(path) for path in matches])
    )
    return matches[0]


# ---------------------------------------------------------------------------
# The workflow exists and is shaped as expected
# ---------------------------------------------------------------------------


def test_workflow_file_exists() -> None:
    """Task 28.1: the workflow ships at the conventional path.

    Separate from every other test here so a missing file reports once.
    """
    assert WORKFLOW_PATH.is_file(), "Task 28.1 requires .github/workflows/ci.yml"


@pytest.mark.parametrize("name", GATE_JOBS)
def test_workflow_declares_gate_job(workflow: Dict[str, Any], name: str) -> None:
    """Each gate job is present."""
    assert job_of(workflow, name)


def test_workflow_runs_on_pull_requests(workflow: Dict[str, Any]) -> None:
    """The gates run before a change lands, not only after.

    ``on`` is parsed by PyYAML 1.1 rules as the boolean ``True``, so the key is
    looked up both ways rather than assumed.
    """
    triggers = workflow.get("on", workflow.get(True))
    assert isinstance(triggers, dict) and "pull_request" in triggers


def test_workflow_permissions_are_read_only(workflow: Dict[str, Any]) -> None:
    """steering/security.md: the CI token gets no write scope.

    Nothing here publishes or commits, and a read-only token is the difference
    between a compromised third-party step being a nuisance and it being able to
    push.
    """
    assert workflow.get("permissions") == {"contents": "read"}


# ---------------------------------------------------------------------------
# The matrix (design.md, Portability Design; Requirement 10 AC3)
# ---------------------------------------------------------------------------


def test_matrix_covers_exactly_the_three_python_versions(
    workflow: Dict[str, Any]
) -> None:
    """design.md fixes 3.9 / 3.11 / 3.13, and no fourth version is silently added."""
    combinations = matrix_combinations(matrix_of(workflow, MATRIX_JOB))
    versions = sorted({version for _, version in combinations}, key=version_tuple)
    assert versions == sorted(EXPECTED_PYTHON_VERSIONS, key=version_tuple)


def test_lowest_matrix_python_version_is_the_declared_floor(
    workflow: Dict[str, Any]
) -> None:
    """The matrix tests the oldest interpreter ``pyproject.toml`` claims to support.

    Read from ``requires-python`` rather than restated, because a floor that is
    claimed but never exercised is the one that breaks.
    """
    combinations = matrix_combinations(matrix_of(workflow, MATRIX_JOB))
    lowest = min((version for _, version in combinations), key=version_tuple)
    assert version_tuple(lowest) == version_tuple(requires_python_floor())


@pytest.mark.parametrize("version", EXPECTED_PYTHON_VERSIONS)
def test_each_python_version_runs_on_both_operating_systems(
    workflow: Dict[str, Any], version: str
) -> None:
    """Requirement 10 AC3: three versions on Linux *and* on macOS.

    Asserted per version so a dropped combination names the version. Matched by
    runner-label prefix, because the 3.9 slot on macOS uses the Intel image:
    ``macos-latest`` is arm64 and there is no darwin-arm64 CPython 3.9 to install.
    """
    combinations = matrix_combinations(matrix_of(workflow, MATRIX_JOB))
    systems = {system for system, candidate in combinations if candidate == version}
    assert any(system.startswith(LINUX_PREFIX) for system in systems), (
        "Python {0} runs on no Linux runner; it runs on {1}".format(version, sorted(systems))
    )
    assert any(system.startswith(MACOS_PREFIX) for system in systems), (
        "Python {0} runs on no macOS runner; it runs on {1}".format(version, sorted(systems))
    )


def test_matrix_uses_only_supported_operating_systems(
    workflow: Dict[str, Any]
) -> None:
    """Windows is out of scope for v0.1 (design.md, Open Design Decisions O-6).

    A Windows runner appearing here would be a scope change disguised as a
    configuration change, and its failures would be reported as defects.
    """
    combinations = matrix_combinations(matrix_of(workflow, MATRIX_JOB))
    unsupported = sorted(
        system
        for system, _ in combinations
        if not system.startswith((LINUX_PREFIX, MACOS_PREFIX))
    )
    assert not unsupported, "unsupported runner labels in the matrix: {0}".format(
        unsupported
    )


def test_the_matrix_does_not_stop_at_the_first_failure(
    workflow: Dict[str, Any]
) -> None:
    """``fail-fast: false``: "3.9 only" and "macOS only" are answerable.

    With the default, one failing combination cancels the rest and the log cannot
    distinguish a version-specific defect from an OS-specific one.
    """
    strategy = job_of(workflow, MATRIX_JOB).get("strategy") or {}
    assert strategy.get("fail-fast") is False


# ---------------------------------------------------------------------------
# Gate 1: the test suite and the coverage floor (Requirement 12 AC1)
# ---------------------------------------------------------------------------


def pytest_commands(workflow: Dict[str, Any]) -> List[str]:
    """Every command that runs the test suite."""
    return [
        command for command in all_run_commands(workflow) if "-m pytest" in command
    ]


def coverage_command(workflow: Dict[str, Any]) -> str:
    """The single command that enforces the coverage floor."""
    matches = [
        command
        for command in pytest_commands(workflow)
        if "--cov-fail-under" in command
    ]
    assert len(matches) == 1, (
        "expected exactly one coverage-gated pytest command; found {0}".format(matches)
    )
    return matches[0]


def test_a_step_runs_pytest(workflow: Dict[str, Any]) -> None:
    """The suite runs at all, and through ``python3`` as the documentation says."""
    assert any(
        "python3 -m pytest" in command for command in pytest_commands(workflow)
    )


def test_the_coverage_gate_is_the_floor_requirement_12_ac1_states(
    workflow: Dict[str, Any]
) -> None:
    """Requirement 12 AC1: at least 80 percent line coverage, enforced."""
    assert "--cov-fail-under={0}".format(COVERAGE_FLOOR) in coverage_command(workflow)


def test_the_coverage_gate_measures_every_source_pyproject_declares(
    workflow: Dict[str, Any]
) -> None:
    """The gate covers the whole measured surface.

    ``[tool.coverage.run] source`` is the declaration of what is measured. A
    package added there but not to this command would leave the floor computed
    over a subset, and the number CI reports would not be the number
    ``CONTRIBUTING.md`` tells a contributor to reproduce.
    """
    command = coverage_command(workflow)
    missing = [
        source
        for source in coverage_sources()
        if "--cov={0}".format(source) not in command
    ]
    assert not missing, "the CI coverage command omits {0}".format(missing)


def test_the_coverage_gated_command_runs_in_the_matrix_job(
    workflow: Dict[str, Any]
) -> None:
    """The floor is enforced on every version and both operating systems.

    Enforcing it in a single-platform job would leave a 3.9-only or macOS-only
    regression outside the gate.
    """
    assert any(
        "--cov-fail-under" in command
        for command in run_commands(workflow, MATRIX_JOB)
    )


# ---------------------------------------------------------------------------
# Gate 2: the benchmark (Requirement 11 AC7)
# ---------------------------------------------------------------------------


def benchmark_command(workflow: Dict[str, Any]) -> str:
    """The single command that runs the benchmark harness."""
    matches = [
        command
        for command in all_run_commands(workflow)
        if "run_benchmark.py" in command
    ]
    assert len(matches) == 1, (
        "expected exactly one benchmark command; found {0}".format(matches)
    )
    return matches[0]


def test_a_step_runs_the_benchmark_harness(workflow: Dict[str, Any]) -> None:
    """Requirement 11 AC7 is enforced by running the harness, which exits 9 on FAIL."""
    assert "benchmark/harness/run_benchmark.py" in benchmark_command(workflow)


def test_the_benchmark_runs_in_combined_mode(workflow: Dict[str, Any]) -> None:
    """Task 28.1 names ``--mode combined``: every Source measured together."""
    assert "--mode combined" in benchmark_command(workflow)


def test_the_benchmark_runs_against_the_committed_cases(
    workflow: Dict[str, Any]
) -> None:
    """The ``--cases`` directory named by CI is the one in the repository."""
    assert "--cases benchmark/cases" in benchmark_command(workflow)
    assert CASES_DIR.is_dir(), "benchmark/cases is missing"


def test_the_benchmark_verdict_is_not_reinterpreted(workflow: Dict[str, Any]) -> None:
    """The harness's exit code is the verdict; the step does not post-process it.

    ``benchmark.harness.run_benchmark`` exits 9 for a FAIL category and 10 for a
    case it could not measure, both outside the plugin's own exit code table so
    that CI can tell them apart. Piping the output through anything that returns
    its own status would discard that.
    """
    command = benchmark_command(workflow)
    assert "|" not in command, (
        "the benchmark command pipes its output, which replaces its exit "
        "status: {0!r}".format(command)
    )


# ---------------------------------------------------------------------------
# Gate 3: the secret scan (Requirement 9 AC1)
# ---------------------------------------------------------------------------


def test_the_secret_scanner_ships_with_the_repository() -> None:
    """The scan is a repository script, not a third-party action.

    Design's security table assigns Requirement 9 AC1 to CI. Keeping the rules
    here means the allowlist that exempts a placeholder is reviewed in the pull
    request that adds the placeholder, and the scan needs no network access and
    no dependency.
    """
    assert SECRET_SCANNER_PATH.is_file(), "Task 28.1 requires a secret scanner"


def test_a_step_runs_the_secret_scanner(workflow: Dict[str, Any]) -> None:
    """Requirement 9 AC1: CI scans the repository for credentials."""
    relative = SECRET_SCANNER_PATH.relative_to(REPO_ROOT).as_posix()
    assert any(relative in command for command in all_run_commands(workflow))


def test_the_secret_scanner_reports_an_aws_access_key_id(scanner: ModuleType) -> None:
    """The key ID shape steering/security.md lists first.

    The literal is assembled at run time so that this file does not itself carry
    a string the scanner reports -- which is the same reason the repository's own
    placeholders are allowlisted rather than deleted.
    """
    line = "AKIA" + "IOSFODNN7ABCDEFG"
    findings = scanner.scan_text("x.yaml", line)
    assert [finding.rule for finding in findings] == ["aws_access_key_id"]


#: Test vectors for the scanner, each carrying the inline exemption marker.
#: They are credential-shaped by construction -- that is the point of them -- and
#: this file is itself scanned by ``test_the_repository_contains_no_secret``. The
#: marker is how a line that is genuinely not a credential opts out, so using it
#: here is both the fix and a demonstration.
@pytest.mark.parametrize(
    ("description", "line"),
    [
        ("aws secret access key", "aws_secret_access_key = " + "A" * 40),  # secret-scan:allow
        ("aws session token", "AWS_SESSION_TOKEN=" + "B" * 60),  # secret-scan:allow
        ("private key block", "-----BEGIN RSA PRIVATE KEY-----"),  # secret-scan:allow
        ("yaml password", "  MasterUserPassword: h0rsebatterystaple"),  # secret-scan:allow
        ("python password", 'password = "h0rsebatterystaple"'),  # secret-scan:allow
        ("dotenv password", "DB_PASSWORD=h0rsebatterystaple"),  # secret-scan:allow
        ("json api key", '  "api_key": "abcd1234efgh5678",'),  # secret-scan:allow
        ("mcp secret", '  "MCP_SECRET_TOKEN": "abcd1234efgh5678"'),  # secret-scan:allow
        ("credentials in a url", "https://u:h0rsebattery@example.internal/x.git"),  # secret-scan:allow
    ],
)
def test_the_secret_scanner_reports_each_credential_class(
    scanner: ModuleType, description: str, line: str
) -> None:
    """steering/security.md's list: AWS keys, session tokens, API keys,
    passwords, MCP secrets.

    Parametrized so a rule lost in a refactor names the class it covered.
    """
    assert scanner.scan_text("x.yaml", line), "not detected: {0}".format(description)


@pytest.mark.parametrize(
    ("description", "line"),
    [
        ("placeholder account id", "arn:aws:iam::{0}:role/deploy".format(PLACEHOLDER_ACCOUNT_ID)),
        ("documented variable name", "AWS_SECRET_ACCESS_KEY is withheld from children"),
        ("unresolved reference", "  MasterUserPassword: !Ref DatabasePassword"),
        ("obvious placeholder", '  password: "EXAMPLE_PLACEHOLDER_VALUE"'),
        ("python tuple unpacking", "document, secret = template"),
        ("computed value", 'password = _parameter(facts, "DatabasePassword")'),
        ("short value", "password: abc"),
    ],
)
def test_the_secret_scanner_stays_quiet_about_non_credentials(
    scanner: ModuleType, description: str, line: str
) -> None:
    """False positives are what turn a gate off, so they are pinned as tests.

    The placeholder account ID matters most: ``123456789012`` appears throughout
    ``benchmark/`` and ``examples/`` by design, and a scanner that reported it
    would be suppressed within a week.
    """
    assert scanner.scan_text("x.yaml", line) == [], "false positive: {0}".format(
        description
    )


def test_the_secret_scanner_honours_an_inline_exemption(scanner: ModuleType) -> None:
    """An escape hatch that stays visible in the diff.

    A suppression file drifts out of sight; a marker on the line is read by
    whoever reviews the line.
    """
    line = 'password = "h0rsebatterystaple"  # {0}'.format(  # secret-scan:allow
        scanner.INLINE_ALLOW_MARKER
    )
    assert scanner.scan_text("x.py", line) == []


def test_the_secret_scanner_reports_a_finding_without_quoting_it(
    scanner: ModuleType
) -> None:
    """steering/security.md: no credential value reaches a log.

    A CI log is public on a public repository, so the report gives the location
    and the rule and nothing else.
    """
    # Named ``value`` rather than ``secret``: the scanner reads this file too,
    # and ``secret = "..."`` is a finding by its own rules -- correctly so.
    value = "h0rsebatterystaple"
    line = 'password = "{0}"'.format(value)  # secret-scan:allow
    rendered = scanner.scan_text("x.py", line)[0].render()
    assert value not in rendered


def test_the_repository_contains_no_secret(scanner: ModuleType) -> None:
    """Requirement 9 AC1, asserted against the repository itself.

    The same check CI runs. Having it here means a credential committed by
    accident fails the local test run too, rather than only after a push.
    """
    findings, _mode, scanned = scanner.scan(REPO_ROOT)
    assert findings == [], "\n".join(finding.render() for finding in findings)
    assert scanned > 0, "the scan examined no file"


# ---------------------------------------------------------------------------
# Gate 4: Ground_Truth commit order (Requirement 11 AC14, AC15)
# ---------------------------------------------------------------------------


class FakeHistory:
    """Fixed answers to the two questions the order check asks of git.

    Injected instead of building fixture commits: the comparison is what has
    rules in it, and it can be exercised exactly in a checkout with no git
    metadata at all.
    """

    def __init__(
        self,
        added: Dict[str, Optional[str]],
        ancestors: Iterable[Tuple[str, str]] = (),
    ) -> None:
        self.added = added
        self.ancestors = set(ancestors)

    def added_commit(self, relative_path: str) -> Optional[str]:
        return self.added.get(relative_path)

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        return (ancestor, descendant) in self.ancestors


def a_case(order_checker: ModuleType) -> Any:
    """One case's pair of paths, for the classification tests."""
    return order_checker.CasePaths(
        case_id="case-001-iam-wildcard",
        ground_truth="benchmark/cases/case-001-iam-wildcard/ground_truth.json",
        template="benchmark/cases/case-001-iam-wildcard/template.yaml",
    )


def test_the_order_checker_ships_with_the_repository() -> None:
    """Task 28.1: the check is a Python script, not shell.

    steering/tech.md puts conditional logic and data processing in Python; this
    reads JSON, resolves two paths per case and compares commit ancestry.
    """
    assert ORDER_CHECKER_PATH.is_file(), "Task 28.1 requires the order checker"


def test_a_step_checks_ground_truth_commit_order(workflow: Dict[str, Any]) -> None:
    """Requirement 11 AC14, AC15 get a machine check, not only a document."""
    relative = ORDER_CHECKER_PATH.relative_to(REPO_ROOT).as_posix()
    assert any(relative in command for command in all_run_commands(workflow))


def test_the_order_check_job_checks_out_full_history(
    workflow: Dict[str, Any]
) -> None:
    """``fetch-depth: 0``: a shallow clone has no add-commit to compare.

    Asserted on the job that runs the check rather than on the workflow at
    large, so moving the step to a job without full history fails here.
    """
    relative = ORDER_CHECKER_PATH.relative_to(REPO_ROOT).as_posix()
    job_names = [
        name
        for name in workflow["jobs"]
        if any(relative in command for command in run_commands(workflow, name))
    ]
    assert job_names, "no job runs the order checker"
    for name in job_names:
        checkouts = [
            step
            for step in steps_of(workflow, name)
            if isinstance(step.get("uses"), str)
            and step["uses"].startswith("actions/checkout@")
        ]
        assert checkouts, "job {0!r} does not check out the repository".format(name)
        for step in checkouts:
            assert (step.get("with") or {}).get("fetch-depth") == 0, (
                "job {0!r} needs fetch-depth: 0 to read commit history".format(name)
            )


def test_a_ground_truth_in_the_same_commit_passes(
    order_checker: ModuleType
) -> None:
    """The normal case: one commit adds a case's template and its expectations."""
    case = a_case(order_checker)
    history = FakeHistory({case.ground_truth: "aaa", case.template: "aaa"})
    verdict = order_checker.classify(case, history)
    assert verdict.verdict == order_checker.VERDICT_SAME_COMMIT


def test_a_ground_truth_in_an_earlier_commit_passes(
    order_checker: ModuleType
) -> None:
    """Expectations committed first are exactly what AC14 asks for."""
    case = a_case(order_checker)
    history = FakeHistory(
        {case.ground_truth: "older", case.template: "newer"},
        ancestors=[("older", "newer")],
    )
    verdict = order_checker.classify(case, history)
    assert verdict.verdict == order_checker.VERDICT_EARLIER_COMMIT


def test_a_ground_truth_in_a_later_commit_is_a_violation(
    order_checker: ModuleType
) -> None:
    """Expectations added after the template are what AC15 warns about.

    Ancestry decides it, not timestamps: a rebase or a skewed clock can give an
    ancestor a later commit date than its descendant.
    """
    case = a_case(order_checker)
    history = FakeHistory(
        {case.ground_truth: "newer", case.template: "older"},
        ancestors=[("older", "newer")],
    )
    verdict = order_checker.classify(case, history)
    assert verdict.verdict == order_checker.VERDICT_LATER_COMMIT


def test_an_unresolvable_ground_truth_is_not_reported_as_a_pass(
    order_checker: ModuleType
) -> None:
    """A file with no add-commit means "not verified", which is not "verified"."""
    case = a_case(order_checker)
    history = FakeHistory({case.ground_truth: None, case.template: "aaa"})
    verdict = order_checker.classify(case, history)
    assert verdict.verdict == order_checker.VERDICT_GROUND_TRUTH_UNTRACKED


def test_an_unresolvable_template_is_not_reported_as_a_pass(
    order_checker: ModuleType
) -> None:
    """The mirror image, so neither side can go unchecked silently."""
    case = a_case(order_checker)
    history = FakeHistory({case.ground_truth: "aaa", case.template: None})
    verdict = order_checker.classify(case, history)
    assert verdict.verdict == order_checker.VERDICT_TEMPLATE_UNTRACKED


def test_a_clean_run_exits_zero(order_checker: ModuleType) -> None:
    """Two verified cases and nothing else is a pass."""
    case = a_case(order_checker)
    verdicts = [
        order_checker.Verdict(case, order_checker.VERDICT_SAME_COMMIT, "a", "a"),
        order_checker.Verdict(case, order_checker.VERDICT_EARLIER_COMMIT, "a", "b"),
    ]
    assert order_checker.exit_code_for(verdicts) == order_checker.EXIT_OK


def test_an_unverifiable_case_does_not_exit_zero(order_checker: ModuleType) -> None:
    """Unknown is a failure: a check that saw nothing has verified nothing.

    The alternative -- passing when history is unavailable -- would make the gate
    silently useless on a shallow clone, which is the situation most likely to
    hide a late Ground_Truth.
    """
    case = a_case(order_checker)
    verdicts = [
        order_checker.Verdict(
            case, order_checker.VERDICT_GROUND_TRUTH_UNTRACKED, None, "a"
        )
    ]
    assert order_checker.exit_code_for(verdicts) == order_checker.EXIT_UNAVAILABLE


def test_a_violation_outranks_an_unverifiable_case(order_checker: ModuleType) -> None:
    """With both present, the exit code reports the one that names a defect."""
    case = a_case(order_checker)
    verdicts = [
        order_checker.Verdict(
            case, order_checker.VERDICT_GROUND_TRUTH_UNTRACKED, None, "a"
        ),
        order_checker.Verdict(case, order_checker.VERDICT_LATER_COMMIT, "b", "a"),
    ]
    assert order_checker.exit_code_for(verdicts) == order_checker.EXIT_VIOLATION


def test_discovery_pairs_every_case_with_the_template_it_names(
    order_checker: ModuleType
) -> None:
    """The template comes from the ``template`` field, not from a fixed name.

    ``benchmark/harness/run_benchmark.py`` resolves that field, so it names the
    file whose commit matters. Every v0.1 case happens to say ``template.yaml``;
    a case that said otherwise would still be checked.
    """
    cases = order_checker.discover_cases(REPO_ROOT, CASES_DIR)
    assert cases, "no benchmark case was discovered"
    for case in cases:
        assert (REPO_ROOT / case.ground_truth).is_file(), case.case_id
        assert (REPO_ROOT / case.template).is_file(), case.case_id


def test_discovery_covers_every_case_directory(order_checker: ModuleType) -> None:
    """One pair per case, so no case can drop out of the check unnoticed."""
    expected = sorted(
        path.name
        for path in CASES_DIR.iterdir()
        if path.is_dir() and (path / "ground_truth.json").is_file()
    )
    found = sorted(
        case.case_id for case in order_checker.discover_cases(REPO_ROOT, CASES_DIR)
    )
    assert found == expected


def test_a_template_field_with_a_path_separator_is_rejected(
    order_checker: ModuleType
) -> None:
    """The field is untrusted input: ``../`` must not become a path git is given.

    Same rejection ``run_benchmark.template_path`` makes, for the same reason.
    """
    with pytest.raises(order_checker.CaseError):
        order_checker.template_name({"template": "../../etc/passwd"}, "case-x")


def test_a_missing_template_field_is_rejected(order_checker: ModuleType) -> None:
    """An absent field is a malformed case, not a case with no template."""
    with pytest.raises(order_checker.CaseError):
        order_checker.template_name({}, "case-x")


# ---------------------------------------------------------------------------
# Property 14 with a randomized hash seed (Requirement 16 AC11)
# ---------------------------------------------------------------------------


def test_exactly_one_property_test_implements_property_14() -> None:
    """design.md's implementation convention: one tag comment per property.

    Also the precondition for the next test: the workflow is asserted to run the
    file that carries the tag, so the tag has to identify one file.
    """
    assert property_14_test_file().is_file()


def test_a_separate_job_randomizes_the_hash_seed(workflow: Dict[str, Any]) -> None:
    """Task 28.1: ``PYTHONHASHSEED=random`` in a job of its own.

    With a fixed seed, an accidental dependency on set or dict iteration order
    passes; the randomized seed is what turns Property 14 into a claim about the
    input alone.
    """
    env = job_of(workflow, DETERMINISM_JOB).get("env") or {}
    assert str(env.get("PYTHONHASHSEED")) == "random"


def test_the_randomized_seed_job_runs_the_property_14_test(
    workflow: Dict[str, Any]
) -> None:
    """It runs the test that carries the tag, located by the tag.

    Naming the path here instead would let the workflow keep running a renamed or
    deleted file's path and pass.
    """
    relative = property_14_test_file().relative_to(REPO_ROOT).as_posix()
    commands = run_commands(workflow, DETERMINISM_JOB)
    assert any(relative in command for command in commands), (
        "the {0!r} job does not run {1}; it runs {2}".format(
            DETERMINISM_JOB, relative, commands
        )
    )


# ---------------------------------------------------------------------------
# Nothing swallows a failure (Task 28.1 completion condition)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", GATE_JOBS)
def test_a_gate_job_is_not_allowed_to_fail(
    workflow: Dict[str, Any], name: str
) -> None:
    """``continue-on-error`` on a gate would make the gate advisory.

    Task 28.2 adds a lint job that *is* advisory; it is not in
    :data:`GATE_JOBS`, so it can be added without touching this.
    """
    job = job_of(workflow, name)
    assert not job.get("continue-on-error", False)
    for step in steps_of(workflow, name):
        assert not step.get("continue-on-error", False), (
            "step {0!r} of job {1!r} is continue-on-error".format(
                step.get("name"), name
            )
        )


@pytest.mark.parametrize("name", GATE_JOBS)
def test_no_gate_command_discards_a_non_zero_exit(
    workflow: Dict[str, Any], name: str
) -> None:
    """No ``|| true`` and no ``set +e``: the exit status is the verdict."""
    for command in run_commands(workflow, name):
        offenders = [
            fragment
            for fragment in FAILURE_SWALLOWING_FRAGMENTS
            if fragment in command
        ]
        assert not offenders, "job {0!r} swallows a failure with {1}: {2!r}".format(
            name, offenders, command
        )


# ---------------------------------------------------------------------------
# The advisory lint job (Task 28.2; Requirement 16 AC5)
# ---------------------------------------------------------------------------


def test_the_workflow_declares_the_advisory_lint_job(workflow: Dict[str, Any]) -> None:
    """Task 28.2: ``ruff`` and ``mypy`` run somewhere.

    Recommending them in ``CONTRIBUTING.md`` and never running them is how a
    recommendation becomes fiction.
    """
    assert job_of(workflow, LINT_JOB)


def test_the_lint_job_is_allowed_to_fail(workflow: Dict[str, Any]) -> None:
    """The completion condition of Task 28.2.

    ``continue-on-error`` at job level is what keeps a lint finding out of the
    workflow's verdict. Without it, ``ruff`` and ``mypy`` would gate every
    contribution, which design.md's Dependency Strategy explicitly declines: they
    are recommended, not required.
    """
    assert job_of(workflow, LINT_JOB).get("continue-on-error") is True


def test_the_lint_job_is_not_a_gate() -> None:
    """It is absent from :data:`GATE_JOBS`, so the gate assertions still bite.

    Stated as a test rather than left implicit: adding ``lint`` to that tuple
    would make ``test_a_gate_job_is_not_allowed_to_fail`` contradict the test
    above, and this names which of the two is wrong.
    """
    assert LINT_JOB not in GATE_JOBS


def test_every_job_is_either_a_gate_or_the_advisory_lint_job(
    workflow: Dict[str, Any]
) -> None:
    """No fourth category, and no job outside the two sets of assertions here.

    A job added later is either gated by
    ``test_a_gate_job_is_not_allowed_to_fail`` or declared advisory. One that is
    neither would be a job whose failure semantics nothing in this file checks.
    """
    known = set(GATE_JOBS) | {LINT_JOB}
    unclassified = sorted(set(workflow.get("jobs", {})) - known)
    assert not unclassified, (
        "these jobs are neither a gate nor the advisory lint job: {0}".format(
            unclassified
        )
    )


def test_the_lint_job_runs_ruff(workflow: Dict[str, Any]) -> None:
    """Task 28.2 names ``ruff check``."""
    commands = run_commands(workflow, LINT_JOB)
    assert any(command.startswith("ruff check") for command in commands), (
        "the {0!r} job runs no 'ruff check'; it runs {1}".format(LINT_JOB, commands)
    )


def test_the_lint_job_type_checks_the_shipped_package(
    workflow: Dict[str, Any]
) -> None:
    """Task 28.2 names ``mypy iacreview``.

    Scoped to the package rather than the repository: ``tests/`` inserts the
    plugin root into ``sys.path`` before importing, and a type checker reads that
    as errors that say nothing about the plugin.
    """
    commands = run_commands(workflow, LINT_JOB)
    assert any("mypy iacreview" in command for command in commands), (
        "the {0!r} job does not run 'mypy iacreview'; it runs {1}".format(
            LINT_JOB, commands
        )
    )


def test_the_lint_job_keeps_the_real_exit_codes(workflow: Dict[str, Any]) -> None:
    """Advisory by declaration, not by ``|| true``.

    The distinction matters: ``continue-on-error`` reports the step's true status
    and merely excludes it from the verdict, while ``|| true`` would make the job
    green whether the tools found anything or not, leaving the log as the only
    record.
    """
    for command in run_commands(workflow, LINT_JOB):
        offenders = [
            fragment
            for fragment in FAILURE_SWALLOWING_FRAGMENTS
            if fragment in command
        ]
        assert not offenders, (
            "the advisory job hides a result with {0}: {1!r}".format(
                offenders, command
            )
        )


def test_a_ruff_finding_does_not_hide_the_type_report(
    workflow: Dict[str, Any]
) -> None:
    """Both tools report in one run.

    A failing step skips the steps after it, and job-level
    ``continue-on-error`` does not change that -- it only keeps the workflow
    green. So the ``ruff`` step carries its own ``continue-on-error``; otherwise
    a style finding would mean the run answers only one of the two questions.
    """
    steps = steps_of(workflow, LINT_JOB)
    ruff_steps = [
        step
        for step in steps
        if isinstance(step.get("run"), str) and "ruff check" in step["run"]
    ]
    assert ruff_steps, "no step runs ruff"
    mypy_index = next(
        (
            index
            for index, step in enumerate(steps)
            if isinstance(step.get("run"), str) and "mypy " in step["run"]
        ),
        None,
    )
    assert mypy_index is not None, "no step runs mypy"
    for step in ruff_steps:
        if steps.index(step) < mypy_index:
            assert step.get("continue-on-error") is True, (
                "step {0!r} precedes the mypy step and would abort the job "
                "before it".format(step.get("name"))
            )


# ---------------------------------------------------------------------------
# What CI installs (Requirement 15, Requirement 16 AC3, AC4)
# ---------------------------------------------------------------------------


def test_every_declared_dependency_is_installed_by_ci(
    workflow: Dict[str, Any]
) -> None:
    """The specifiers CI installs are the ones ``pyproject.toml`` declares.

    Compared verbatim against the workflow's ``env`` values, so adding a test
    dependency to the ``dev`` extra without adding it to CI fails here rather
    than as an ``ImportError`` in one matrix job.
    """
    values = set(workflow_env(workflow).values())
    missing = [spec for spec in declared_specs() if spec not in values]
    assert not missing, (
        "the workflow does not install these specifiers from pyproject.toml: "
        "{0}".format(missing)
    )


def test_each_declared_dependency_is_referenced_by_an_install_step(
    workflow: Dict[str, Any]
) -> None:
    """The pinned specifiers are actually used, not merely declared.

    An ``env`` entry nothing references is a specifier that looks installed and
    is not.
    """
    env = workflow_env(workflow)
    specs = set(declared_specs())
    variables = [name for name, value in env.items() if value in specs]
    commands = " ".join(all_run_commands(workflow))
    unused = [
        name for name in variables if "${" + name + "}" not in commands
    ]
    assert not unused, "declared but never installed: {0}".format(unused)


def test_the_lint_extra_declares_both_tools() -> None:
    """Task 28.2: ``[project.optional-dependencies] lint`` names ``ruff`` and ``mypy``."""
    names = {spec.split("==")[0].split(">")[0].strip().lower() for spec in lint_specs()}
    assert {"ruff", "mypy"} <= names, "the lint extra declares {0}".format(sorted(names))


def test_the_lint_extra_is_pinned_exactly() -> None:
    """steering/tech.md: pinned versions rather than open ranges.

    Same reasoning as the ``cfn-lint`` pin. A floating linter acquires rules on
    an upstream release, and the run that acquires them reports them against
    whichever change happens to be open at the time.
    """
    unpinned = [spec for spec in lint_specs() if "==" not in spec]
    assert not unpinned, "the lint extra must pin exactly: {0}".format(unpinned)


def test_the_lint_extra_is_not_part_of_the_required_dependency_set() -> None:
    """``lint`` is not folded into what the gates install.

    Requirement 16 AC3 keeps the run-time dependency at PyYAML alone, and
    design.md's Dependency Strategy keeps ``ruff`` and ``mypy`` optional. This
    pins the reading of ``pyproject.toml`` those two statements imply: adding a
    tool to ``lint`` must not put it in :func:`declared_specs`, where every entry
    is a specifier a gate job is required to install.
    """
    overlap = sorted(set(lint_specs()) & set(declared_specs()))
    assert not overlap, (
        "these lint specifiers leaked into the required dependency set: "
        "{0}".format(overlap)
    )


def test_the_dev_and_lint_extras_resolve_to_different_arrays() -> None:
    """Both extras are read unambiguously despite sharing a table.

    ``array_values`` matches a field name at the start of a line, so ``dev`` and
    ``lint`` cannot resolve to each other; and both are single-line arrays, which
    is the only shape it can read. A future edit that wraps either array across
    lines fails here rather than silently narrowing what
    ``test_every_declared_dependency_is_installed_by_ci`` checks.
    """
    dev = array_values("dev")
    lint = lint_specs()
    assert dev and lint
    assert not set(dev) & set(lint)


def test_the_lint_job_installs_the_pinned_lint_extra(
    workflow: Dict[str, Any]
) -> None:
    """The advisory job installs the versions ``pyproject.toml`` pins.

    Otherwise a contributor and CI would run different linters, and the findings
    CI reports would not be the ones ``ruff check iacreview`` reproduces locally.
    """
    env = workflow_env(workflow)
    specs = set(lint_specs())
    variables = [name for name, value in env.items() if value in specs]
    installed = {env[name] for name in variables}
    missing = sorted(specs - installed)
    assert not missing, (
        "the workflow declares no env value for these lint specifiers: "
        "{0}".format(missing)
    )
    commands = " ".join(run_commands(workflow, LINT_JOB))
    unused = [name for name in variables if "${" + name + "}" not in commands]
    assert not unused, (
        "declared but not installed by the {0!r} job: {1}".format(LINT_JOB, unused)
    )


def test_no_gate_job_installs_a_lint_tool(workflow: Dict[str, Any]) -> None:
    """The gates run on a machine with neither tool available.

    This is what makes "optional" verifiable rather than a claim. If a gate job
    installed ``ruff``, an outage of that package would take the test suite down
    with it, and the dependency would be required in everything but name.
    """
    tools = sorted(
        spec.split("==")[0].strip().lower() for spec in lint_specs()
    )
    for name in GATE_JOBS:
        commands = " ".join(run_commands(workflow, name)).lower()
        offenders = [tool for tool in tools if tool in commands]
        assert not offenders, (
            "gate job {0!r} references the optional lint tools {1}".format(
                name, offenders
            )
        )


def test_the_cfn_lint_pin_satisfies_the_enforced_minimum(
    workflow: Dict[str, Any]
) -> None:
    """CI installs a cfn-lint the plugin will accept.

    The floor is read from ``iacreview.toolcheck``, which is what raises
    ``ToolVersionError`` at run time. Pinning below it would make every job fail
    on the tool check instead of on a defect.
    """
    pinned = workflow_env(workflow)["CFN_LINT_VERSION"]
    assert version_tuple(pinned) >= version_tuple(tool_minimum("cfn-lint"))


def test_the_cfn_lint_pin_is_exact(workflow: Dict[str, Any]) -> None:
    """steering/tech.md: pinned versions rather than open ranges.

    A floating cfn-lint changes the rule catalogue under the benchmark, and a
    benchmark whose expectations move with an upstream release measures nothing.
    """
    command = " ".join(all_run_commands(workflow))
    assert "cfn-lint==" in command, (
        "cfn-lint must be installed with '==', not a range: {0!r}".format(command)
    )


def test_the_cfn_guard_pin_satisfies_the_enforced_minimum(
    installer: ModuleType
) -> None:
    """The installer's pinned release clears ``toolcheck``'s floor too."""
    assert version_tuple(installer.CFN_GUARD_VERSION) >= version_tuple(
        tool_minimum("cfn-guard")
    )


def test_a_step_installs_cfn_guard(workflow: Dict[str, Any]) -> None:
    """cfn-guard is on ``PATH`` before the suite runs.

    Without it the cfn-guard Source is unavailable, several integration tests
    skip and the benchmark records unevaluated cases -- a green run that measured
    less than it claims.
    """
    relative = INSTALLER_PATH.relative_to(REPO_ROOT).as_posix()
    assert any(relative in command for command in run_commands(workflow, MATRIX_JOB))


def test_the_cfn_guard_installer_verifies_a_digest(installer: ModuleType) -> None:
    """Each pinned asset carries a SHA-256, and it is a SHA-256.

    The upstream installer is a ``curl | sh`` of a script on a mutable branch
    that fetches the latest release. Pinning the tag and checking the digest is
    what makes the download reproducible and tamper-evident.
    """
    assert installer.ASSETS
    for key, asset in installer.ASSETS.items():
        assert re.fullmatch(r"[0-9a-f]{64}", asset.sha256), key


def test_the_installer_pins_an_asset_for_every_runner_in_the_matrix(
    workflow: Dict[str, Any], installer: ModuleType
) -> None:
    """Every runner the workflow uses has a cfn-guard build pinned for it.

    The Intel macOS job is the case worth catching: it exists because there is no
    darwin-arm64 CPython 3.9, and it needs a different cfn-guard asset than
    ``macos-latest``. A matrix entry with no matching asset would fail at install
    time on a pushed commit.
    """
    combinations = matrix_combinations(matrix_of(workflow, MATRIX_JOB))
    for system, _version in sorted(combinations):
        if system.startswith(LINUX_PREFIX):
            expected = ("linux", "x86_64")
        elif system.endswith("-intel"):
            expected = ("darwin", "x86_64")
        else:
            expected = ("darwin", "aarch64")
        assert expected in installer.ASSETS, (
            "runner {0!r} needs a pinned cfn-guard asset for {1}".format(
                system, expected
            )
        )


def test_the_installer_rejects_an_unknown_platform(installer: ModuleType) -> None:
    """An unpinned platform fails loudly rather than guessing an asset name."""
    with pytest.raises(installer.InstallError):
        installer.asset_for("Windows", "x86_64")


def test_the_installer_refuses_a_non_https_download(installer: ModuleType) -> None:
    """The transport is asserted, not assumed.

    A digest check protects the content; refusing plain HTTP keeps the request
    itself off an unencrypted channel.
    """
    with pytest.raises(installer.InstallError):
        installer.download("http://example.internal/asset.tar.gz", Path("unused"))


def test_the_cdk_cli_is_not_installed_by_ci(workflow: Dict[str, Any]) -> None:
    """Requirement 10 AC1: the CDK CLI is optional, and CI shows that it is.

    The core review flow must work without it. Installing it in CI would mean the
    only environment that ever exercises the no-CDK path is a contributor's
    laptop.
    """
    commands = " ".join(all_run_commands(workflow))
    assert "aws-cdk" not in commands


# ---------------------------------------------------------------------------
# How the workflow references third-party code
# ---------------------------------------------------------------------------


def test_every_action_is_pinned_to_a_commit_sha(workflow: Dict[str, Any]) -> None:
    """A moved tag cannot change what runs.

    An action runs with access to the workflow's token and its checkout, so a tag
    that can be repointed is a supply-chain dependency with no version.
    """
    unpinned = [
        reference
        for reference in uses_references(workflow)
        if not PINNED_ACTION_PATTERN.match(reference)
    ]
    assert not unpinned, "these actions are not pinned to a SHA: {0}".format(unpinned)


def test_every_action_is_first_party(workflow: Dict[str, Any]) -> None:
    """Only ``actions/*``, so there is one publisher to trust.

    Everything else this workflow needs is a repository script or a pinned
    release download, both of which are reviewable here.
    """
    third_party = sorted(
        {
            reference.split("@", 1)[0]
            for reference in uses_references(workflow)
            if not reference.startswith("actions/")
        }
    )
    assert not third_party, "non first-party actions in use: {0}".format(third_party)


def test_the_shell_is_stated_explicitly(workflow: Dict[str, Any]) -> None:
    """One shell on both operating systems, so a step behaves the same on each."""
    defaults = workflow.get("defaults") or {}
    assert (defaults.get("run") or {}).get("shell") == "bash"
