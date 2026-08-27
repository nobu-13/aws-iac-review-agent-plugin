"""Property 14: stdout of the review entry point is a function of its input.

Requirement 16 AC11 states the whole contract in one sentence: invoked twice with
identical input, a script produces byte-identical stdout carrying no timestamp, no
absolute host path and no other environment-dependent value. design.md's
Determinism Design lists the fourteen sources of non-determinism that statement
rules out -- dict key order, set iteration order, directory traversal order,
Python's hash randomization, the process locale, and so on -- and every one of
them is a property of the *process*, not of a function. So this file tests the
process.

``tests/integration/test_skill_iac_review.py`` already pins the same three
invocations for one hand-written Template
(``test_repeated_runs_produce_byte_identical_stdout``). What this file adds is the
quantifier: the same three invocations over generated Templates and generated
agent findings, plus two dimensions that a single fixed example cannot express --
a varying ``PYTHONHASHSEED``, and an assertion that names the host values which
must not appear.

Everything runs out of process, and why
---------------------------------------

There is no in-process half. Two reasons, and they are independent:

``PYTHONHASHSEED`` is read once, by the interpreter, at start-up.
    ``str`` hashing is seeded before any of our code exists, so a test that
    called :func:`main` could not vary the seed at all. The completion condition
    of this property -- the result does not change when the seed varies -- is
    only observable across fresh interpreters, so the seed is passed in the
    child's environment and two distinct fixed values are compared
    (:data:`HASH_SEEDS`). Fixed rather than ``random``, so a counterexample is
    reproducible; CI additionally runs the whole suite under
    ``PYTHONHASHSEED=random``, which varies the *parent's* seed as well.

The property is about bytes, and in-process capture has no bytes.
    :func:`iacreview.report.configure_stdout` pins the stream's encoding to UTF-8
    and its newline to ``\\n``, and it deliberately returns ``False`` for a stream
    that cannot be reconfigured -- which is exactly what a test capturing
    :data:`sys.stdout` into a :class:`io.StringIO` hands it. An in-process run
    would therefore compare *strings that skipped the encoding step*, and the
    encoding step is the half of Requirement 16 AC11 that ``LANG`` and the host
    platform could otherwise break. :func:`subprocess.run` is called without
    ``text=True`` here for the same reason: what is compared is ``bytes``.

The cost is four child processes per example, four hundred for the run. It is
affordable only because of the Source choice below; see
:data:`SOURCE_ARGUMENTS`.

The four invocations
--------------------

======================  ==================================================
``first``               seed A, no ``--verbose``. The reference bytes.
``second``              seed A, no ``--verbose``. Identical input, identical
                        environment: the literal reading of "invoked twice".
``verbose``             seed A, ``--verbose``. design.md: "``--verbose`` の有無
                        は stdout を変えない".
``reseeded``            seed B, no ``--verbose``. The hash randomization row of
                        the Determinism Design table.
======================  ==================================================

``second`` is not redundant with ``reseeded``. A defect that made stdout depend on
the seed *deterministically* (an unsorted ``set`` of strings reaching the output)
fails only ``reseeded``; a defect that made it genuinely random fails ``second``
too, and a comparison that always varied the seed could not tell the two apart.
Both comparisons are cheap, and their diagnosis differs, so both are made.

What is scoped in, and what is scoped out
-----------------------------------------

The property is quantified over Templates and over agent finding input "for any
*fixed* configuration of Source availability". The configuration fixed here is
**the IAM Source alone** (:data:`SOURCE_ARGUMENTS`): it reads the Template in
process and starts nothing, so the property runs on a machine with neither
cfn-lint nor cfn-guard installed, pays no tool start-up cost per example, and
cannot fail for a reason that belongs to an external tool's output ordering. The
tool-driven configurations are covered deterministically elsewhere --
``tests/integration/test_skill_cfn_guard.py`` for cfn-guard's rule ordering,
``tests/integration/test_fakebin_drives_sources.py`` for a pinned cfn-lint
output -- and a tool's own version-to-version differences are outside
Requirement 10 AC3 (``docs/architecture.md``).

Also scoped out: a **parse failure reached through a standalone Skill**. A
``TemplateParseError`` message carries the path it was given, so a Skill handed an
absolute path puts an absolute path in ``errors[].message``. The orchestrator
tested here does not: it loads every Template by its workspace-relative path (see
the ``run_iac_review.py`` module docstring, "No host path is introduced into
stdout"), and the remaining leak is owned by Task 24.5. Generated input is
serialized by :func:`strategies.dump_yaml` and therefore always parses, so this
file does not exercise that path at all.

Reading a failure
-----------------

A byte difference is a real defect, and the diff is the diagnosis: the assertion
messages carry the first differing line of the two reports rather than four
kilobytes of JSON. Which comparison failed says what kind of defect it is -- an
unstable ordering (``second``), a diagnostic leaking into stdout (``verbose``), or
a hash-order dependency (``reseeded``) -- and a host value appearing in stdout is
the environment-dependence half of the same requirement.
"""

from __future__ import annotations

import copy
import getpass
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import strategies as S
from iacreview import exitcodes
from iacreview.finding import AGENT_SOURCE
from iacreview.report import REPORT_KEYS

#: The entry point under test, relative to the plugin root. The orchestrator
#: rather than a single-Source Skill: it is the entry point whose stdout a
#: consumer reads without knowing which Sources ran, so it is the one whose bytes
#: have to be a function of the input alone.
SCRIPT = Path("skills") / "iac-review" / "scripts" / "run_iac_review.py"

#: Source selection for every invocation. The IAM Source needs no external tool,
#: so the property holds its meaning on a machine with none installed and costs
#: no tool start-up per example. ``iam-review`` is the hyphenated alias, spelled
#: the way a caller assembling a command line would (the canonical name contains
#: a space).
SOURCE_ARGUMENTS: Tuple[str, ...] = ("--sources", "iam-review")

#: Name of the generated Template inside the workspace. It matches one of the
#: ``Location.File`` values :func:`strategies.locations` draws, so a generated
#: agent Finding sometimes lands in the same bucket as the IAM Findings and the
#: merge path is exercised rather than only the pass-through path.
TEMPLATE_NAME = "app.yaml"

#: Name of the generated agent findings file inside the workspace.
AGENT_FINDINGS_NAME = "agent-findings.json"

#: ``Evidence[].Excerpt`` written into an agent Finding that has none.
#: :mod:`iacreview.agentin` requires one per entry -- a justification quoting
#: nothing is an assertion, not evidence -- so an entry drawn without an Excerpt
#: would be rejected, and this file wants the *accepted* path exercised too.
AGENT_EXCERPT_FALLBACK = 'Action: "*"'

#: Two hash seeds, compared against each other. Distinct, and both fixed: a
#: property whose examples were seeded randomly could not be replayed from a
#: counterexample. ``"0"`` disables randomization, the other enables it with a
#: known value, so the pair differs in exactly the way the Determinism Design
#: table promises does not matter.
HASH_SEEDS: Tuple[str, str] = ("0", "12345")

#: Environment variables set for every child, holding values that exist nowhere
#: in the input. Any of them appearing on stdout is an environment-dependent
#: value in the sense of Requirement 16 AC11. ``AWS_PROFILE`` is included because
#: it is the shape of variable a review of AWS infrastructure is most likely to
#: read by accident; its value is an obvious placeholder and not a credential
#: (steering/security.md).
SENTINEL_ENVIRONMENT: Dict[str, str] = {
    "IAC_REVIEW_DETERMINISM_SENTINEL": "sentinel-must-not-reach-stdout",
    "AWS_PROFILE": "sentinel-profile-must-not-reach-stdout",
}

#: Shortest host-derived value asserted on. A shorter string cannot be
#: distinguished from a coincidence in generated Template text, and a false
#: failure would teach a reader to weaken the assertion.
MIN_HOST_VALUE_LENGTH = 4

#: An ISO-8601 date *and* time, in extended or basic form. The time part is
#: required: a bare date is not a timestamp, and ``"2012-10-17"`` -- the IAM
#: policy language version -- legitimately appears in Template content and in the
#: Evidence quoted from it.
ISO_8601_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}|\d{8}T\d{6}"
)

#: Per-invocation timeout. Generous: an example that hits it has hung, and the
#: property's whole runtime is four hundred invocations of a script that takes
#: well under a second.
TIMEOUT_S = 120


# ---------------------------------------------------------------------------
# Input generation
# ---------------------------------------------------------------------------


def as_agent_entry(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Rewrite a Finding payload into the shape :mod:`iacreview.agentin` accepts.

    :func:`strategies.finding_payloads` draws Findings for *any* Source, and the
    agent input boundary accepts exactly ``["Agent Review"]`` -- attributing agent
    reasoning to a deterministic tool is a violation, not a formatting slip. A
    payload drawn as-is is therefore usually rejected, which exercises only the
    ``errors[]`` half of the intake. This rewrite produces the other half.

    Three fields are changed and nothing else: ``Source``, each
    ``Evidence[].Source``, and each missing ``Evidence[].Excerpt``. ``Confidence``
    is deliberately left alone even when it says ``Confirmed``: the boundary
    demotes that to ``Likely`` with a warning (Requirement 7 AC10), and the
    demotion is a stdout-visible transformation worth generating.
    ``Location.File`` is pointed at the reviewed Template so the entry shares a
    dedup bucket with the IAM Findings, and the ordering and numbering under test
    therefore run over a mixed set rather than over one Source's output. An actual
    *merge* of an agent and an IAM Finding needs both to agree on ``Resource`` and
    on a non-``Other`` category, which happens rarely here; the merge itself is
    what Properties 3, 4 and 5 quantify over.

    Args:
        payload: A Finding as :func:`iacreview.finding.to_dict` renders it.

    Returns:
        A new payload; the input is not modified.
    """
    entry = copy.deepcopy(payload)
    entry["Source"] = [AGENT_SOURCE]
    entry["Location"]["File"] = TEMPLATE_NAME
    entry["Evidence"] = [
        dict(
            evidence,
            Source=AGENT_SOURCE,
            Excerpt=evidence["Excerpt"] or AGENT_EXCERPT_FALLBACK,
        )
        for evidence in entry["Evidence"]
    ]
    return entry


def agent_entries() -> st.SearchStrategy[List[Dict[str, Any]]]:
    """The ``findings`` array of a generated agent findings file.

    Both halves of the intake, mixed within one file: entries the boundary
    accepts (:func:`as_agent_entry`) and entries it rejects one at a time
    (:func:`strategies.finding_payloads` unchanged, whose ``Source`` names a
    deterministic tool). A rejected entry becomes an ``errors[]`` entry, which is
    on stdout as well and has to be as stable as a Finding is.
    """
    accepted = S.finding_payloads().map(as_agent_entry)
    return st.lists(st.one_of(accepted, S.finding_payloads()), max_size=3)


def reviewable_templates() -> st.SearchStrategy[Dict[str, Any]]:
    """Templates to review: with IAM content and without.

    :func:`strategies.templates` reaches the Requirement 6 AC12 case -- a Template
    with no IAM at all, whose report has an empty ``findings`` array -- and an
    empty report is a legitimate but weak example to compare bytes of.
    :func:`strategies.iam_templates` puts a policy document at one of the sites
    :mod:`iacreview.iam.locate` recognizes, so the IAM detectors have something to
    report and the ordering, numbering and merging of real Findings is what the
    comparison covers. Drawing both keeps the quantifier ("for any Template")
    honest while making most examples substantial.
    """
    return st.one_of(S.templates(), S.iam_templates())


# ---------------------------------------------------------------------------
# Fixtures and invocation
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def workspace(tmp_path_factory: Any) -> Path:
    """One workspace directory, reused by every example.

    Module-scoped on purpose. A function-scoped fixture combined with ``@given``
    is a Hypothesis health-check failure -- and rightly so, since it would be
    created once and shared by all hundred examples anyway. Every example
    overwrites both files it uses, and ``--target`` names the Template directly
    rather than scanning the directory, so nothing an example leaves behind can
    reach the next one's report.
    """
    return tmp_path_factory.mktemp("determinism")


def run_entry_point(
    plugin_root: Path,
    workspace: Path,
    *,
    seed: str,
    verbose: bool,
    agent_findings: Optional[str],
) -> "subprocess.CompletedProcess[bytes]":
    """Run the entry point once and return the completed process, undecoded.

    Args:
        plugin_root: Plugin root, used to locate the script.
        workspace: Working directory, which is the workspace root the script
            resolves ``--target`` inside and relativizes report paths against.
        seed: Value for ``PYTHONHASHSEED`` in the child's environment.
        verbose: Whether to pass ``--verbose``.
        agent_findings: Workspace-relative agent findings file, or ``None`` to
            run without ``--agent-findings``.

    Returns:
        The completed process with ``bytes`` stdout and stderr. Not decoded: the
        property is about bytes, and letting :mod:`subprocess` decode would hide
        the encoding of the stream under test.

    Note:
        The environment is built from :data:`os.environ` so the coverage
        variables ``tests/conftest.py`` sets survive into the child, then the
        seed and the sentinels are written over it. stdin is
        :data:`subprocess.DEVNULL`: Requirement 16 AC9 says the script never
        reads it, and a script that did would hang here rather than inherit the
        test runner's stdin.
    """
    arguments = [str(plugin_root / SCRIPT), "--target", TEMPLATE_NAME]
    arguments.extend(SOURCE_ARGUMENTS)
    if agent_findings is not None:
        arguments.extend(["--agent-findings", agent_findings])
    if verbose:
        arguments.append("--verbose")

    env = dict(os.environ)
    env.update(SENTINEL_ENVIRONMENT)
    env["PYTHONHASHSEED"] = seed

    return subprocess.run(
        [sys.executable, *arguments],
        cwd=str(workspace),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=TIMEOUT_S,
    )


# ---------------------------------------------------------------------------
# Oracles
# ---------------------------------------------------------------------------


def host_derived_values(workspace: Path) -> List[str]:
    """Values that exist only because of *this* host, in one list.

    Everything design.md's Determinism Design table names as environment-derived
    and can be observed from the test process: the workspace root (both as given
    and symlink-resolved, which differ under macOS's ``/var`` -> ``/private/var``
    link), the home directory, the temporary directory, the interpreter, the host
    name, the user name, and the sentinel environment values.

    Args:
        workspace: The directory the child ran in.

    Returns:
        The values, de-duplicated, sorted, and filtered to those at least
        :data:`MIN_HOST_VALUE_LENGTH` characters long. Sorted so a failure names
        the same value on every run.
    """
    candidates: List[str] = [
        str(workspace),
        str(workspace.resolve()),
        str(Path.home()),
        tempfile.gettempdir(),
        sys.executable,
        str(Path(sys.executable).parent),
        platform.node(),
    ]
    candidates.extend(SENTINEL_ENVIRONMENT.values())
    try:
        candidates.append(getpass.getuser())
    except Exception:  # noqa: BLE001 - no password entry and no USER: skip it
        pass
    return sorted(
        {
            value
            for value in candidates
            if value and len(value) >= MIN_HOST_VALUE_LENGTH
        }
    )


def path_valued_strings(report: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Every report field that names a file, as ``(field, value)`` pairs.

    These are the fields an absolute path would reach first, so they are checked
    structurally in addition to being covered by :func:`host_derived_values`: a
    path that is absolute is a defect even when it happens to name no directory
    of this host.
    """
    pairs: List[Tuple[str, str]] = []
    target = report["target"]
    for index, value in enumerate(target["files"]):
        pairs.append(("target.files[{0}]".format(index), value))
    for index, value in enumerate(target["cdk"]["synthesized_templates"]):
        pairs.append(
            ("target.cdk.synthesized_templates[{0}]".format(index), value)
        )
    for finding in report["findings"]:
        pairs.append(
            ("findings[{0}].Location.File".format(finding["ID"]),
             finding["Location"]["File"])
        )
    return pairs


def first_difference(left: bytes, right: bytes) -> str:
    """Describe where two report payloads first differ, in one short line.

    A whole-report diff is unreadable in a Hypothesis failure report, and the
    interesting part is invariably one line. Falls back to a byte offset when the
    payloads are not decodable text, which would itself be the defect.
    """
    try:
        left_lines = left.decode("utf-8").splitlines()
        right_lines = right.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        offset = next(
            (i for i, (a, b) in enumerate(zip(left, right)) if a != b),
            min(len(left), len(right)),
        )
        return "undecodable output differs at byte {0}".format(offset)

    for number, (a, b) in enumerate(zip(left_lines, right_lines), start=1):
        if a != b:
            return "line {0}: {1!r} != {2!r}".format(number, a, b)
    return "line counts differ: {0} != {1}".format(len(left_lines), len(right_lines))


# ---------------------------------------------------------------------------
# The property
# ---------------------------------------------------------------------------


# Feature: aws-iac-review-agent-plugin, Property 14: For any Template and for any
# fixed configuration of Source availability and Agent finding input, two
# successive invocations of the review entry point produce byte-identical stdout;
# and that stdout contains no absolute host path, no ISO-8601 timestamp, and no
# value derived from the host environment.
@settings(max_examples=S.MAX_EXAMPLES, deadline=None)
@given(
    document=reviewable_templates(),
    agent_payloads=agent_entries(),
    with_agent_findings=st.booleans(),
)
def test_stdout_is_a_function_of_the_input_alone(
    plugin_root: Path,
    workspace: Path,
    document: Dict[str, Any],
    agent_payloads: List[Dict[str, Any]],
    with_agent_findings: bool,
) -> None:
    """**Validates: Requirements 10.3, 16.11**

    ``deadline=None`` because an example is four child processes: Hypothesis's
    default per-example deadline of 200 ms measures process start-up here, not
    the code under test, and it would flake on a loaded machine long before it
    caught a real slowdown.

    The four invocations are compared against ``first`` rather than pairwise: any
    two of them being equal to it makes them equal to each other, and the failure
    then names which dimension moved.
    """
    template_text = S.dump_yaml(document)
    agent_text = json.dumps({"findings": agent_payloads}, sort_keys=True)
    (workspace / TEMPLATE_NAME).write_text(template_text, encoding="utf-8")
    # Written on every example, used only on some: the workspace contents are
    # then a function of the example rather than of the example history.
    (workspace / AGENT_FINDINGS_NAME).write_text(agent_text, encoding="utf-8")
    agent_argument = AGENT_FINDINGS_NAME if with_agent_findings else None

    def invoke(*, seed: str, verbose: bool) -> "subprocess.CompletedProcess[bytes]":
        return run_entry_point(
            plugin_root,
            workspace,
            seed=seed,
            verbose=verbose,
            agent_findings=agent_argument,
        )

    seed_a, seed_b = HASH_SEEDS
    first = invoke(seed=seed_a, verbose=False)
    second = invoke(seed=seed_a, verbose=False)
    verbose = invoke(seed=seed_a, verbose=True)
    reseeded = invoke(seed=seed_b, verbose=False)
    runs = (("second", second), ("verbose", verbose), ("reseeded", reseeded))

    # A review of a generated Template always has something to report on, so an
    # empty or non-zero run would make every comparison below vacuously true.
    assert first.returncode == exitcodes.OK, first.stderr.decode(
        "utf-8", "replace"
    )
    assert first.stdout, "stdout was empty; stderr was: {0}".format(
        first.stderr.decode("utf-8", "replace")
    )
    report = json.loads(first.stdout.decode("utf-8"))
    assert sorted(report) == sorted(REPORT_KEYS)

    for name, run in runs:
        assert run.returncode == first.returncode, (
            "{0} exited {1}, the reference run exited {2}".format(
                name, run.returncode, first.returncode
            )
        )
        assert run.stdout == first.stdout, "{0} changed stdout: {1}".format(
            name, first_difference(first.stdout, run.stdout)
        )

    stdout_text = first.stdout.decode("utf-8")
    input_text = template_text + agent_text
    for value in host_derived_values(workspace):
        if value in input_text:
            # The input may legitimately name anything; what the property forbids
            # is stdout carrying a host value the input did not supply.
            continue
        assert value not in stdout_text, (
            "stdout carries the host-derived value {0!r}".format(value)
        )

    timestamp = ISO_8601_TIMESTAMP.search(stdout_text)
    assert timestamp is None, "stdout carries the timestamp {0!r}".format(
        timestamp.group(0) if timestamp else ""
    )

    for field, value in path_valued_strings(report):
        # Both spellings of "absolute": a POSIX root, and a Windows drive
        # segment, which :func:`iacreview.report.normalize_output_path` refuses
        # separately because ``PurePosixPath`` does not consider it absolute.
        absolute = value.startswith("/") or value.split("/")[0].endswith(":")
        assert not absolute, (
            "{0} is not a workspace-relative path: {1!r}".format(field, value)
        )
