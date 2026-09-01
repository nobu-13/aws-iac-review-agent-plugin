"""Properties 24 and 25: the Source loop survives failure, and the CDK gate holds.

Both properties are about what the orchestrator does when something goes wrong,
so both are asserted against ``skills/iac-review/scripts/run_iac_review.py``
itself rather than against a helper it calls. The entry point is imported and
``main()`` is called in-process (:data:`_ENTRY_POINT`), which is what makes the
two observations these properties need possible at all: a recorded process start
(Property 25) and a Source made to fail on demand (Property 24) are only visible
from inside the process that would have done them.

What the example tests already own, and this module does not repeat
------------------------------------------------------------------

``tests/integration/test_skill_iac_review.py``
    The orchestrated run as a host agent performs it -- a real subprocess, real
    cfn-guard, the ``tests/fakebin`` cfn-lint -- for one failing Source, for
    every Source failing, for the two Template groups, and for the merged agent
    Findings. Its ``test_no_cdk_process_is_started_without_confirmation`` is the
    single-layout ancestor of Property 25 and the source of the recording
    technique used here.

``tests/integration/test_tool_unavailable.py`` and
``tests/integration/test_fakebin_drives_sources.py``
    The four tool situations driven through ``PATH`` for all three tools, with
    real subprocesses: that an absent binary really produces
    ``tool_unavailable``, a crashing one ``tool_execution``, a hanging one
    ``tool_timeout``. Those tests establish that the *classes* are produced by
    the real world; this module takes the classes as given and quantifies over
    which Sources carry them.

``tests/unit/test_cdk_detect.py``
    :mod:`iacreview.cdk` on its own, including the confirmed synth with every
    route to a subprocess replaced.

``tests/integration/test_cdk.py`` (Task 24.6)
    The enumerated CDK layout matrix from the integration side. This module owns
    the quantified statement over layouts; that one owns the named cases.

Property 24: how each failure class is injected
-----------------------------------------------

The property quantifies over *which* Sources fail and over *what kind* of
failure, so the injection has to be per Source and per class -- and it has to be
cheap enough to run 100 times. Driving ``tests/fakebin`` through ``PATH`` would
satisfy the first requirement for cfn-lint and cfn-guard only (the IAM Source has
no external tool and the agent intake reads a file), and would spend two
subprocesses per example on tools whose behaviour ``test_tool_unavailable.py``
has already pinned. The injection is therefore made at the seam the orchestrator
itself uses, one per class, choosing the seam where the real failure actually
surfaces:

``tool_unavailable``
    At :func:`iacreview.toolcheck.require_known_tool`, which is where an absent
    binary is discovered in production: ``IacReview._verify_tools`` catches it,
    records one ``errors[]`` entry, and leaves the Source out of ``specs`` so it
    is never called. For the IAM Source and the agent -- neither of which has a
    tool to be missing -- the class is injected at their own seam instead, and is
    frankly synthetic there: what it exercises is the loop's handling of an
    ``error_class``, which is what the property is stated over.

``tool_execution`` and ``tool_timeout``
    At the Source's ``run_and_normalize``, in *both* shapes the orchestrator
    accepts, drawn per example as ``via_raise``. Returning a
    :class:`~iacreview.source.SourceResult` whose ``errors`` list holds the entry
    is what the real Sources do (see :func:`iacreview.cfnlint.run_and_normalize`:
    a failed ``proc.run`` becomes a returned error, never an exception); raising
    an :class:`~iacreview.errors.IacReviewError` is the other branch of
    ``IacReview.collect``'s ``try``. One entry per failed Source is required of
    both.

``unexpected``
    A bare :class:`RuntimeError` from ``run_and_normalize``. This is the class
    that tests :func:`run_iac_review.unexpected_error`, whose entry names the
    exception **type** only -- the message and traceback go to stderr, so that an
    exception nobody in this plugin wrote cannot carry a host path into stdout
    (Requirement 16 AC11). The assertion therefore checks that the injected
    message text is absent from the report and present on stderr.

The succeeding Sources are stubbed too, for one reason: the property is about the
orchestration, and letting the real Sources run would make the outcome depend on
whether cfn-lint and cfn-guard are installed on the machine running the test.
``require_known_tool`` is replaced for the same reason -- on a machine without
cfn-lint, an un-injected ``tool_unavailable`` entry would appear for a Source the
example never asked to fail. Each stub Source returns one Finding on a
:data:`~tests.property.strategies.RESOURCE_POOL` resource of its own, so no two
Sources' Findings share a dedup key and "retains every Finding produced by the
Sources that did not fail" is decidable by comparing sets. The agent's Finding is
the one on ``Resource: None``, which Requirement 14 AC6 keeps out of matching
entirely.

Two divergences between the property text and the implementation, both recorded
rather than papered over:

*"exits with code 0 when at least one Source succeeded"* is read as **at least
one deterministic Source** succeeded. ``IacReview.exit_code`` consults
``self.succeeded``, which only the three Sources that review a Template can
enter; agent Findings are an intake, not a review, and a run whose every
deterministic Source failed reports the failure class (5, 6 or 1) even when the
agent supplied Findings. Requirement 2 AC10 speaks of *sub-skills* and
Property 24 validates Requirements 4 AC12 and 5 AC6, both about external tools,
so the narrower reading is the one the acceptance criteria support. The
alternative reading is not simply dropped: the exit code is asserted as an
equivalence in the narrow reading, and its non-zero value is pinned to
:data:`iacreview.source.SOURCE_ERROR_EXIT_CODES` for the injected class, so a
change in either direction fails here.

*The agent intake did not survive an undeclared exception.* Injecting the
``unexpected`` class into ``Agent Review`` made ``main()`` return
:data:`~iacreview.exitcodes.UNEXPECTED` with **no report at all**, because
``IacReview._load_agent_findings`` caught only
:class:`~iacreview.errors.IacReviewError` while ``IacReview.collect`` catches
bare ``Exception`` for exactly this reason. That is an implementation gap against
Requirement 2 AC10 -- ``cloudformation-review``'s output reaches the orchestrated
run through this intake, so a defect there ended the whole review instead of
costing the agent's Findings. It was fixed in ``run_iac_review.py`` by mirroring
the Source loop's handling; this property is what fails if the asymmetry returns.

Property 25: observing that no ``cdk`` process starts
-----------------------------------------------------

An absence claim needs an observation channel, and the channel needs proof that
it observes. Three layers, in increasing strength:

*Statically*, :func:`_unconfirmed_gate_violations` parses
:func:`iacreview.cdk.synth_if_confirmed` and reports any reference to ``proc``,
``subprocess`` or ``shutil`` inside its ``if not confirmed:`` branch, or a branch
that does not end in a ``return``. Nothing there can start a process, for *every*
layout rather than for the sampled ones -- which is the only way to cover a
"for any input directory layout" quantifier. The orchestrator holds no second
copy of the decision: it passes ``confirmed`` straight through.

*Dynamically*, :func:`subprocess.run` is replaced by a recorder for the duration
of each ``main()`` call and every ``argv`` it receives is captured. Recording
under :mod:`subprocess` rather than under :func:`iacreview.proc.run` is one layer
lower than the integration test's assertion, so a call that bypassed the wrapper
would still be seen; Property 19's static scan is what rules out the remaining
routes (``os.system`` and friends). The run is restricted to the IAM Source, so
*no* process is legitimate and the assertion can be the strongest available one:
the recorded list is empty. The filesystem is compared before and after as well,
since a synth's observable effect is a written ``cdk.out``.

*As a control*, the same recorder is then shown to record a synth: with
``iacreview.cdk``'s tool lookup replaced, :func:`iacreview.cdk.synth_if_confirmed`
is called with ``confirmed=True`` on the same directory, and the recorder must
hold exactly one invocation of ``cdk synth``. Without this the empty-list
assertion above would also pass against a recorder wired to nothing. No child
process is started on that path either -- ``subprocess.run`` is still the
recorder -- so the project's ``app.py`` never executes.

Settings
--------

Both tests carry ``deadline=None``. Each example builds a workspace, writes
files and runs the whole entry point, so per-example wall-clock time is a
property of the filesystem and of the interpreter rather than of the code under
test, and the default 200 ms deadline would turn a loaded machine into a test
failure.
"""

from __future__ import annotations

import ast
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterator,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
)

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import strategies as S
from iacreview import agentin, categories, cdk, cfnguard, cfnlint, exitcodes, iam, netgraph, pathguard, secrets
from iacreview.errors import (
    IacReviewError,
    ToolExecutionError,
    ToolTimeoutError,
    ToolUnavailableError,
)
from iacreview.finding import (
    AGENT_MAX_CONFIDENCE,
    AGENT_SOURCE,
    CONFIRMED,
    CRITICAL_SEVERITY,
    FINDING_TYPES,
    OTHER_CATEGORY,
    SEVERITIES,
    SOURCES,
    UNASSIGNED_ID,
    Evidence,
    Finding,
    Location,
    from_dict,
    to_dict,
)
from iacreview.report import SCHEMA_VERSION
from iacreview.source import SOURCE_ERROR_EXIT_CODES, SourceResult
from iacreview.toolcheck import CFN_GUARD, CFN_LINT, ToolInfo

# ---------------------------------------------------------------------------
# The entry point under test
# ---------------------------------------------------------------------------

#: The orchestrator, relative to the plugin root.
_SCRIPT = Path("skills") / "iac-review" / "scripts" / "run_iac_review.py"


def _import_entry_point() -> ModuleType:
    """Import the orchestrator as a module so ``main()`` can be called here.

    Imported at module scope rather than through a fixture: a function-scoped
    fixture is set up once per *test*, not once per example, and Hypothesis
    refuses the combination. The module name is unique to this file so that the
    copy ``tests/integration/test_skill_iac_review.py`` imports stays separate --
    two modules under one name in :data:`sys.modules` would make whichever loaded
    second silently reuse the first.
    """
    path = pathguard.plugin_root() / _SCRIPT
    spec = importlib.util.spec_from_file_location(
        "run_iac_review_prop_orchestration", path
    )
    assert spec is not None and spec.loader is not None, path
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_ENTRY_POINT: ModuleType = _import_entry_point()

#: Documented exit codes. An entry point returning anything else is a defect
#: :class:`iacreview.bootstrap.EntryPointOutcome` is supposed to catch.
_DOCUMENTED_EXIT_CODES: FrozenSet[int] = frozenset(exitcodes.EXIT_CODES.values())


# ---------------------------------------------------------------------------
# Shared workspace material
# ---------------------------------------------------------------------------

#: The reviewed Template. One file, so "exactly one error entry naming each
#: failed Source" is exactly what the report must show: a per-Template failure
#: class would produce one entry per Template, and a tool verification failure
#: one per run, and with a single Template the two counts coincide.
_TEMPLATE_FILE = "app.yaml"

_TEMPLATE_BODY = """\
Resources:
  Queue:
    Type: AWS::SQS::Queue
"""

#: Where the agent's Findings are handed in.
_AGENT_FILE = "agent.json"

#: Message text carried by every injected failure. Asserted *absent* from the
#: report for the ``unexpected`` class, so it has to be distinctive.
_INJECTED = "injected failure for the orchestration property"

#: Version reported by the stubbed tool lookup. Never compared against a real
#: banner; it only has to be a parsable, plausible value.
_STUB_VERSION = "9.9.9"

#: The Sources the orchestrator *runs*, in collection order. ``Agent Review`` is
#: not one of them: its Findings arrive as a file, once per run.
_DETERMINISTIC_SOURCES: Tuple[str, ...] = tuple(
    name for name in SOURCES if name != AGENT_SOURCE
)

#: Source -> the ``run_and_normalize`` owner whose attribute is replaced.
_SOURCE_MODULES: Dict[str, ModuleType] = {
    cfnlint.SOURCE_NAME: cfnlint,
    cfnguard.SOURCE_NAME: cfnguard,
    iam.SOURCE_NAME: iam,
    netgraph.SOURCE_NAME: netgraph,
    secrets.SOURCE_NAME: secrets,
}

#: Executable -> the Source whose tool it is, as ``_verify_tools`` pairs them.
_EXECUTABLE_SOURCES: Dict[str, str] = {
    CFN_LINT: cfnlint.SOURCE_NAME,
    CFN_GUARD: cfnguard.SOURCE_NAME,
}

#: Source -> the ``Resource`` its Finding names. Each Source gets a distinct
#: resource (and ``Agent Review`` gets ``None``) so that no two stub Findings
#: ever merge: a Finding with no resource never merges (Requirement 14 AC6), and
#: neither do two Findings on different resources, so every Source's Finding
#: stays identifiable in the report regardless of how many Sources ran.
_SOURCE_RESOURCES: Tuple[Optional[str], ...] = ("A", "B", "C", "D", "E", None)
assert len(_SOURCE_RESOURCES) == len(SOURCES), (
    "one distinct resource per Source is needed so stub Findings never merge"
)
_RESOURCE_FOR_SOURCE: Dict[str, Optional[str]] = dict(zip(SOURCES, _SOURCE_RESOURCES))

#: Vocabulary values the stub Findings carry, taken from the imported closed sets
#: rather than written out. Which ``FindingType`` is irrelevant to both
#: properties; the ``Severity`` is any value other than ``CRITICAL``, whose use
#: obliges the Finding to carry a deployment-blocking ``RuleId``
#: (Requirement 7 AC6) -- a constraint that has nothing to do with orchestration
#: and would only add a reason for these stubs to be rejected. The category is
#: likewise anything but the residual ``Other``, which Requirement 14 AC3 keeps
#: out of dedup matching.
_FINDING_TYPE = FINDING_TYPES[0]
_SEVERITY = next(name for name in SEVERITIES if name != CRITICAL_SEVERITY)


def _category() -> str:
    """A ``Normalized_Category`` from the mapping file, never the residual one."""
    return next(
        name for name in categories.load_map().categories if name != OTHER_CATEGORY
    )


def _stub_finding(source: str) -> Finding:
    """The one Finding the stub for ``source`` produces.

    Attributed to ``source`` alone and placed on that Source's own resource, so
    the report's Findings say which stubs ran.
    """
    agent = source == AGENT_SOURCE
    excerpt = _TEMPLATE_BODY if agent else None
    return Finding(
        ID=UNASSIGNED_ID,
        Normalized_Category=_category(),
        FindingType=_FINDING_TYPE,
        Severity=_SEVERITY,
        Confidence=AGENT_MAX_CONFIDENCE if agent else CONFIRMED,
        Source=[source],
        Resource=_RESOURCE_FOR_SOURCE[source],
        Location=Location(File=_TEMPLATE_FILE, Line=None, Column=None, TemplatePath=None),
        Finding="{0} reported one issue for this property test.".format(source),
        WhyItMatters="The orchestration must keep this finding in the report.",
        Evidence=[
            Evidence(
                Source=source,
                Detail="Produced by the stub for {0}.".format(source),
                RuleId=None,
                Excerpt=excerpt,
            )
        ],
        Recommendation="No action: this finding exists to be counted.",
        SuggestedRemediation=None,
    )


def _agent_payload() -> Dict[str, Any]:
    """The ``--agent-findings`` file contents, as one accepted agent Finding.

    Built by rendering the same :func:`_stub_finding` through
    :func:`iacreview.finding.to_dict`, so the file is valid against the schema
    the intake enforces without a second hand-written copy of it. On the success
    path the real :func:`iacreview.agentin.load_agent_findings` parses this: the
    agent Source is only stubbed when the example injects a failure into it.
    """
    return {
        agentin.SCHEMA_VERSION_KEY: SCHEMA_VERSION,
        agentin.FINDINGS_KEY: [to_dict(_stub_finding(AGENT_SOURCE))],
    }


def _make_workspace(base: Path) -> Path:
    """Create the Property 24 workspace: one Template and one agent file."""
    workspace = base / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / _TEMPLATE_FILE).write_text(_TEMPLATE_BODY, encoding="utf-8")
    (workspace / _AGENT_FILE).write_text(
        json.dumps(_agent_payload(), indent=2) + "\n", encoding="utf-8"
    )
    return workspace


@contextmanager
def _in_directory(directory: Path) -> Iterator[None]:
    """Run the block with ``directory`` as the process working directory.

    The workspace root of every entry point is ``Path.cwd()``, so a review of a
    generated workspace has to run from it. ``monkeypatch.chdir`` would be the
    usual way; the fixture is function-scoped and cannot be combined with
    ``@given``, hence the explicit context manager (the pattern
    ``tests/property/test_prop_pathguard.py`` establishes).
    """
    previous = Path.cwd()
    os.chdir(str(directory))
    try:
        yield
    finally:
        os.chdir(str(previous))


def _run_main(
    workspace: Path, argv: Sequence[str]
) -> Tuple[int, Optional[Dict[str, Any]], str]:
    """Call ``main(argv)`` from ``workspace`` and collect all three channels.

    Returns:
        ``(exit_code, report_or_None, stderr_text)``. The report is ``None`` when
        stdout stayed empty, which is itself part of the contract: a failure the
        report cannot describe leaves stdout untouched.

    Note:
        :func:`iacreview.bootstrap.run_entry_point` reads :data:`sys.stdout` at
        call time, so redirection is honoured;
        :func:`iacreview.report.configure_stdout` returns ``False`` for a
        :class:`io.StringIO` instead of failing on it.
    """
    out = io.StringIO()
    err = io.StringIO()
    with _in_directory(workspace):
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = _ENTRY_POINT.main(list(argv))
    text = out.getvalue()
    return code, (json.loads(text) if text.strip() else None), err.getvalue()


@contextmanager
def _replaced(owner: Any, name: str, value: Any) -> Iterator[None]:
    """Set ``owner.name`` to ``value`` for the duration of the block.

    The ``monkeypatch`` fixture's job, done by hand for the reason given in
    :func:`_in_directory`.
    """
    original = getattr(owner, name)
    setattr(owner, name, value)
    try:
        yield
    finally:
        setattr(owner, name, original)


# ---------------------------------------------------------------------------
# Property 24: the injections
# ---------------------------------------------------------------------------

#: Failure class -> the exception carrying it. Keyed by the classes' own
#: ``error_class`` values, so the table cannot disagree with
#: :data:`iacreview.errors.ERROR_CLASSES` or with what
#: ``strategies.failure_classes()`` draws.
_EXCEPTION_FOR_CLASS: Dict[str, Callable[..., IacReviewError]] = {
    ToolUnavailableError.error_class: ToolUnavailableError,
    ToolExecutionError.error_class: ToolExecutionError,
    ToolTimeoutError.error_class: ToolTimeoutError,
}

#: The class of an exception no Source declared. ``IacReviewError`` itself
#: carries it, and so does the entry the orchestrator records for a bare
#: exception (``run_iac_review.unexpected_error``).
_UNEXPECTED_CLASS: str = IacReviewError.error_class


def _stub_source(
    name: str, failing: Sequence[str], failure_class: str, via_raise: bool
) -> Callable[..., SourceResult]:
    """Build the ``run_and_normalize`` replacement for one Source.

    Args:
        name: The Source this stub stands in for.
        failing: Sources the example injected a failure into.
        failure_class: The injected class.
        via_raise: Whether a failure is raised or returned in ``errors``. Ignored
            for :data:`_UNEXPECTED_CLASS`, which is a bare exception by
            definition -- a returned ``errors`` entry is a *declared* failure and
            would not test :func:`run_iac_review.unexpected_error` at all.

    Returns:
        A callable accepting the Template path plus whatever the orchestrator
        bound into its ``functools.partial`` (``tool``, ``workspace_root``,
        ``rules_dirs``, ``metadata``, ``loaded``).
    """

    def call(template: Any, *args: Any, **kwargs: Any) -> SourceResult:
        if name not in failing:
            return SourceResult(source=name, findings=[_stub_finding(name)])
        if failure_class == _UNEXPECTED_CLASS:
            raise RuntimeError("{0}: {1}".format(name, _INJECTED))
        error = _EXCEPTION_FOR_CLASS[failure_class](
            "{0}: {1}".format(name, _INJECTED)
        )
        if via_raise:
            raise error
        return SourceResult(
            source=name, findings=[], errors=[error.to_structured_error(name)]
        )

    return call


def _stub_tool_lookup(
    failing: Sequence[str], failure_class: str
) -> Callable[[str], ToolInfo]:
    """Build the :func:`iacreview.toolcheck.require_known_tool` replacement.

    Two jobs. It injects ``tool_unavailable`` where that class is the production
    seam -- ``IacReview._verify_tools`` records the entry and drops the Source
    from ``specs`` -- and it makes every other example independent of whether
    cfn-lint and cfn-guard are installed on this machine. Without the second
    job, a host without cfn-lint would add an ``errors[]`` entry for a Source the
    example never asked to fail, and the property would fail for a reason that
    has nothing to do with the orchestration.
    """

    def require(executable: str) -> ToolInfo:
        source = _EXECUTABLE_SOURCES.get(executable)
        if failure_class == ToolUnavailableError.error_class and source in failing:
            raise ToolUnavailableError(
                "{0}: {1}".format(executable, _INJECTED),
                tool=executable,
                remediation="Install {0}.".format(executable),
            )
        # The path is never used: run_and_normalize is stubbed, so nothing is
        # executed. sys.executable is used rather than an invented path so the
        # value is at least a real file.
        return ToolInfo(name=executable, path=sys.executable, version=_STUB_VERSION)

    return require


def _stub_agent_intake(
    failure_class: str, via_raise: bool
) -> Callable[..., Tuple[List[Finding], List[Dict[str, Any]]]]:
    """Build the :func:`iacreview.agentin.load_agent_findings` replacement.

    Installed only when ``Agent Review`` is among the failing Sources. The
    orchestrated form of the ``cloudformation-review`` sub-skill is this intake --
    the agent's Findings arrive as a file -- so "that sub-skill failed" is
    expressed here.
    """

    def load(path: Any, **kwargs: Any) -> Tuple[List[Finding], List[Dict[str, Any]]]:
        if failure_class == _UNEXPECTED_CLASS:
            raise RuntimeError("{0}: {1}".format(AGENT_SOURCE, _INJECTED))
        error = _EXCEPTION_FOR_CLASS[failure_class](
            "{0}: {1}".format(AGENT_SOURCE, _INJECTED)
        )
        if via_raise:
            raise error
        return [], [error.to_structured_error(AGENT_SOURCE)]

    return load


@contextmanager
def _injected(failing: Sequence[str], failure_class: str, via_raise: bool) -> Iterator[None]:
    """Replace every Source seam for the duration of one example."""
    with contextlib.ExitStack() as stack:
        stack.enter_context(
            _replaced(
                _ENTRY_POINT,
                "require_known_tool",
                _stub_tool_lookup(failing, failure_class),
            )
        )
        for name, module in _SOURCE_MODULES.items():
            stack.enter_context(
                _replaced(
                    module,
                    "run_and_normalize",
                    _stub_source(name, failing, failure_class, via_raise),
                )
            )
        if AGENT_SOURCE in failing:
            stack.enter_context(
                _replaced(
                    agentin,
                    "load_agent_findings",
                    _stub_agent_intake(failure_class, via_raise),
                )
            )
        yield


def _identified_findings(report: Dict[str, Any]) -> Set[Tuple[Tuple[str, ...], Optional[str]]]:
    """The report's Findings as ``(Source tuple, Resource)`` pairs."""
    return {
        (tuple(entry["Source"]), entry["Resource"]) for entry in report["findings"]
    }


#: Observed by the Property 24 test, read by the measurement test below.
_OBSERVED_FAILURES: Set[Tuple[str, str]] = set()
_OBSERVED_SUBSET_SIZES: Set[int] = set()


# Feature: aws-iac-review-agent-plugin, Property 24: *For any* subset of Sources injected to fail and *for any* failure class among tool-unavailable, tool-execution-failure, timeout, and unexpected exception, the resulting Review_Report contains exactly one error entry naming each failed Source, retains every Finding produced by the Sources that did not fail, and the entry point exits with code 0 when at least one Source succeeded.
@settings(max_examples=100, deadline=None)
@given(
    failing=st.one_of(
        S.source_subsets(),
        # The two boundary subsets, drawn explicitly. Both are legitimate
        # members of "any subset" and both decide a branch nothing else
        # reaches: every Source failing is the only way into the non-zero
        # exit code, and every deterministic Source failing while the agent
        # succeeds is the case the exit-code reading turns on. An unbiased
        # draw over subsets of four reaches a 3- or 4-element subset rarely,
        # which would leave those branches to chance -- the same reason
        # ``strategies.exit_codes()`` samples the interesting integers
        # alongside the unrestricted ones.
        st.sampled_from((list(_DETERMINISTIC_SOURCES), list(SOURCES))),
    ),
    failure_class=S.failure_classes(),
    via_raise=st.booleans(),
)
def test_orchestration_survives_partial_source_failure(
    tmp_path_factory: pytest.TempPathFactory,
    failing: List[str],
    failure_class: str,
    via_raise: bool,
) -> None:
    """**Validates: Requirements 2.10, 4.12, 5.6, 10.5**

    One Template, one agent findings file, four Sources, and a drawn subset of
    them made to fail in a drawn way. The three clauses of the property are the
    three assertion groups below; see the module docstring for how each failure
    class is injected and for the two divergences from a literal reading of the
    exit-code clause.

    The empty subset is drawn as well (``source_subsets`` includes it) and is not
    a degenerate case: it is the run in which nothing fails, and it is what makes
    the "retains every Finding" clause meaningful -- it fixes the full set the
    other examples are compared against.
    """
    workspace = _make_workspace(tmp_path_factory.mktemp("orchestration"))
    _OBSERVED_FAILURES.update((name, failure_class) for name in failing)
    _OBSERVED_SUBSET_SIZES.add(len(failing))

    with _injected(failing, failure_class, via_raise):
        code, report, stderr = _run_main(
            workspace,
            ["--target", _TEMPLATE_FILE, "--agent-findings", _AGENT_FILE],
        )

    # A report exists on every path: a failed Source is a fact the report states,
    # not a reason to withhold it.
    assert report is not None, stderr

    # Clause 1: exactly one error entry naming each failed Source, and no entry
    # naming anything else. Sorted rather than ordered: the property counts
    # entries per Source and the recording order is _verify_tools first, then
    # the Source loop, then the intake.
    assert sorted(entry["source"] for entry in report["errors"]) == sorted(failing)
    assert all(
        entry["error_class"] == failure_class for entry in report["errors"]
    ), report["errors"]

    # Clause 2: every Finding of every Source that did not fail is still there,
    # and no Finding of one that did.
    survivors = [name for name in SOURCES if name not in failing]
    assert _identified_findings(report) == {
        ((name,), _RESOURCE_FOR_SOURCE[name]) for name in survivors
    }
    for entry in report["findings"]:
        from_dict(entry)
    assert [entry["ID"] for entry in report["findings"]] == list(
        range(1, len(report["findings"]) + 1)
    )
    assert report["summary"]["total"] == len(report["findings"])

    # Clause 3: exit 0 while at least one Source that reviews a Template
    # succeeded; otherwise the code the injected class justifies.
    reviewed = [name for name in _DETERMINISTIC_SOURCES if name not in failing]
    assert code in _DOCUMENTED_EXIT_CODES
    if reviewed:
        assert code == exitcodes.OK
    else:
        assert code == SOURCE_ERROR_EXIT_CODES[failure_class]

    # Requirement 16 AC11 for the class that carries an exception nobody here
    # wrote: the message and the traceback are stderr's business, and the report
    # names the exception type instead.
    if failing and failure_class == _UNEXPECTED_CLASS:
        assert _INJECTED not in json.dumps(report)
        assert RuntimeError.__name__ in json.dumps(report)
        assert _INJECTED in stderr


# ---------------------------------------------------------------------------
# Property 25: the confirmation gate
# ---------------------------------------------------------------------------

#: The gate. Named so the static check fails loudly if it is renamed rather than
#: silently finding nothing to inspect.
_GATE_FUNCTION = "synth_if_confirmed"

#: The parameter the gate branches on.
_GATE_PARAMETER = "confirmed"

#: Names whose appearance inside the unconfirmed branch would mean a process
#: could be started there: the plugin's wrapper, the standard library module
#: under it, and the ``PATH`` lookup that precedes both.
_PROCESS_NAMES: FrozenSet[str] = frozenset({"proc", "subprocess", "shutil"})


def _unconfirmed_gate_violations() -> List[str]:
    """Every way :func:`iacreview.cdk.synth_if_confirmed` could start a process
    on the unconfirmed path.

    Returns:
        Human-readable descriptions, empty when the branch is structurally
        incapable of it. A missing function or a missing ``if not confirmed:``
        gate is itself reported: the check has to fail when it can no longer see
        what it was written to see, rather than pass on an empty search.
    """
    source = Path(cdk.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=cdk.__file__)
    function = next(
        (
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == _GATE_FUNCTION
        ),
        None,
    )
    if function is None:
        return ["{0} is not defined in {1}".format(_GATE_FUNCTION, cdk.__name__)]

    branch = None
    for node in ast.walk(function):
        test = getattr(node, "test", None)
        if (
            isinstance(node, ast.If)
            and isinstance(test, ast.UnaryOp)
            and isinstance(test.op, ast.Not)
            and isinstance(test.operand, ast.Name)
            and test.operand.id == _GATE_PARAMETER
        ):
            branch = node
            break
    if branch is None:
        return [
            "{0} has no `if not {1}:` branch".format(_GATE_FUNCTION, _GATE_PARAMETER)
        ]

    violations: List[str] = []
    for statement in branch.body:
        for node in ast.walk(statement):
            if isinstance(node, ast.Name) and node.id in _PROCESS_NAMES:
                violations.append(
                    "{0}:{1}: the unconfirmed branch references {2}".format(
                        _GATE_FUNCTION, node.lineno, node.id
                    )
                )
    if not isinstance(branch.body[-1], ast.Return):
        violations.append(
            "the unconfirmed branch of {0} does not return, so execution "
            "continues into the synth".format(_GATE_FUNCTION)
        )
    return violations


#: Static, so evaluated once: parsing the module on each of the 100 examples
#: would measure the parser rather than the gate.
_GATE_VIOLATIONS: List[str] = _unconfirmed_gate_violations()


@contextmanager
def _recorded_process_starts() -> Iterator[List[List[str]]]:
    """Replace :func:`subprocess.run` with a recorder and yield what it saw.

    One layer below :func:`iacreview.proc.run`, so an invocation that bypassed
    the wrapper is recorded too. Nothing is executed: the recorder returns a
    successful :class:`subprocess.CompletedProcess` with empty streams, which
    lets the code under test continue on its normal path instead of failing on a
    raise -- and which is why ``cdk.json``'s ``app`` command never runs.
    """
    calls: List[List[str]] = []
    original = subprocess.run

    def recorder(*args: Any, **kwargs: Any) -> Any:
        argv = args[0] if args else kwargs.get("args")
        calls.append([str(token) for token in argv])
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")

    subprocess.run = recorder  # type: ignore[assignment]
    try:
        yield calls
    finally:
        subprocess.run = original  # type: ignore[assignment]


def _cdk_invocations(calls: Sequence[Sequence[str]]) -> List[Sequence[str]]:
    """The recorded invocations of the CDK CLI, by the executable's basename."""
    return [
        argv for argv in calls if argv and os.path.basename(str(argv[0])) == cdk.CDK
    ]


def _materialize(layout: Dict[str, Any], workspace: Path) -> None:
    """Create ``layout`` under ``workspace``: ``None`` means "a directory"."""
    workspace.mkdir(parents=True, exist_ok=True)
    for relative, content in sorted(layout.items()):
        path = workspace / relative
        if content is None:
            path.mkdir(parents=True, exist_ok=True)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(content), encoding="utf-8")


def _fake_cdk_binary(base: Path) -> Path:
    """A file named ``cdk``, for the control's :class:`~iacreview.toolcheck.ToolInfo`.

    The recorder identifies a CDK invocation by the basename of ``argv[0]``,
    because that is what production passes: :func:`iacreview.cdk.synth_if_confirmed`
    puts the *version-checked path* there rather than the bare name. The control
    therefore needs a path ending in ``cdk`` for its recorded argv to have the
    shape the property is stated about.

    Created outside the reviewed workspace, so it does not disturb the
    before/after comparison, and never executed: ``subprocess.run`` is the
    recorder for the whole control block, so the file's contents do not matter.
    The execute bit does -- :func:`iacreview.proc.run` resolves ``argv[0]`` with
    :func:`shutil.which` before it calls out, and an absolute path that is not
    executable resolves to ``None`` there.
    """
    directory = base / "bin"
    directory.mkdir(parents=True, exist_ok=True)
    binary = directory / cdk.CDK
    binary.write_text("", encoding="utf-8")
    binary.chmod(0o700)
    return binary


def _tree(root: Path) -> Set[str]:
    """Every path under ``root``, workspace-relative, for a before/after diff."""
    return {
        str(path.relative_to(root)).replace(os.sep, "/")
        for path in root.rglob("*")
    }


#: Files and directories drawn *around* the CDK markers, so that "any input
#: directory layout" is more than the four marker combinations.
#: ``strategies.cdk_layouts()`` models exactly those four (times a standalone
#: Template) and a run over it alone exhausts its 8 values long before 100
#: examples; these five entries multiply the space by 32 and each adds a shape
#: the gate has to survive: a file that is not a candidate at all, a reviewable
#: Template deeper in the tree, a candidate that will not parse, an excluded
#: directory, and -- the interesting one -- **a second CDK project nested below
#: the target**, which must not be synthesized either.
_NOISE_ENTRIES: Dict[str, Optional[str]] = {
    "notes.txt": "nothing reviewable here\n",
    "templates/nested.yaml": _TEMPLATE_BODY,
    "broken.yaml": "Resources:\n  A:\n   - [\n",
    "sub/{0}".format(cdk.CDK_CONFIG_FILENAME): '{"app": "python3 app.py"}\n',
    "node_modules": None,
}

#: The one noise entry that is itself reviewable, so the test can decide whether
#: the run had anything to review.
_NOISE_TEMPLATE = "templates/nested.yaml"


def _noise() -> st.SearchStrategy[Dict[str, Optional[str]]]:
    """Any subset of :data:`_NOISE_ENTRIES`, as a layout mapping."""
    return st.lists(
        st.sampled_from(sorted(_NOISE_ENTRIES)),
        unique=True,
        max_size=len(_NOISE_ENTRIES),
    ).map(lambda names: {name: _NOISE_ENTRIES[name] for name in names})


#: Observed by the Property 25 test, read by the measurement test below.
_OBSERVED_LAYOUTS: Set[Tuple[bool, bool]] = set()
_OBSERVED_NOISE: Set[str] = set()


# Feature: aws-iac-review-agent-plugin, Property 25: *For any* input directory layout, including layouts containing `cdk.json` and layouts containing a `cdk.out` directory, running the review without the explicit confirmation flag never invokes the `cdk` executable.
@settings(max_examples=100, deadline=None)
@given(markers=S.cdk_layouts(), noise=_noise())
def test_cdk_synth_is_never_invoked_without_confirmation(
    tmp_path_factory: pytest.TempPathFactory,
    markers: Dict[str, Any],
    noise: Dict[str, Any],
) -> None:
    """**Validates: Requirements 8.3, 8.4, 8.5**

    ``cdk synth`` runs the project's own code and its dependencies' lifecycle
    scripts with the invoking user's full privileges, and nothing in this plugin
    sandboxes it (Requirement 8 AC11). This test failing would therefore be a
    security finding rather than a regression.

    The layout is drawn in two parts. ``markers`` covers all four combinations of
    ``cdk.json`` and ``cdk.out/`` -- the dimension the property names -- and
    ``noise`` surrounds them with the shapes described at
    :data:`_NOISE_ENTRIES`, including a nested CDK project that is not the
    target. The measurement test below asserts that all four marker combinations
    and every noise entry were reached.

    Each example runs the whole entry point with only the IAM Source enabled, so
    every process start is illegitimate and the assertion can be that *no*
    process started at all -- a stronger statement than "no ``cdk`` process",
    which is then also asserted in the property's own terms.
    """
    layout: Dict[str, Any] = dict(markers)
    layout.update(noise)
    workspace = tmp_path_factory.mktemp("cdk-gate") / "workspace"
    _materialize(layout, workspace)
    # Detection is per target directory, so only the marker at the target root
    # makes this a CDK project; the nested one is just an unreviewable .json
    # candidate, and it must not be synthesized either.
    has_config = cdk.CDK_CONFIG_FILENAME in markers
    has_synthesized = any(
        name.endswith(cdk.SYNTHESIZED_TEMPLATE_SUFFIX) for name in layout
    )
    _OBSERVED_LAYOUTS.add((has_config, cdk.CDK_OUTPUT_DIRECTORY_NAME in markers))
    _OBSERVED_NOISE.update(noise)

    before = _tree(workspace)
    with _recorded_process_starts() as started:
        code, report, stderr = _run_main(
            workspace, ["--target", ".", "--sources", iam.SOURCE_NAME]
        )

    # The property, and the stronger fact that establishes it here.
    assert _cdk_invocations(started) == []
    assert started == []
    # Nothing was written either: a synth's observable effect is a cloud
    # assembly, and a run that produced no process produced no files.
    assert _tree(workspace) == before
    # The gate is structurally incapable of reaching a process, for every layout
    # rather than for the sampled ones. Static, so computed once at import.
    assert _GATE_VIOLATIONS == []

    assert code in _DOCUMENTED_EXIT_CODES
    assert report is not None, stderr
    assert report["target"]["cdk"]["detected"] is has_config

    reviewable = (
        _TEMPLATE_FILE in layout or has_synthesized or _NOISE_TEMPLATE in layout
    )
    if reviewable:
        assert code == exitcodes.OK
        assert report["target"]["cdk"]["synthesized_templates"] == sorted(
            name
            for name in layout
            if name.endswith(cdk.SYNTHESIZED_TEMPLATE_SUFFIX)
        )
    else:
        # A CDK project with nothing synthesized and no permission to synthesize
        # has nothing to review (Requirement 8 AC5). Which of the two input
        # failures is reported depends on whether a candidate existed and failed
        # to parse (``broken.yaml``, ``cdk.json``) or there was no candidate at
        # all, and that distinction belongs to Requirement 3 rather than here.
        # What this property needs is the narrower fact: the failure is about the
        # input. A tool exit code would mean something was started.
        assert code in (exitcodes.PARSE_FAILURE, exitcodes.NO_REVIEWABLE_TEMPLATE)

    if has_config:
        # Requirement 8 AC4, AC5: the skipped synthesis is recorded rather than
        # silent, and the warning the host agent must show the user is stated.
        assert any(
            cdk.SYNTH_NOT_CONFIRMED_NOTICE in str(entry["message"])
            for entry in report["errors"]
        )
        assert cdk.SYNTH_WARNING in stderr

        # The control: the same recorder, shown to record a synth. Without it the
        # empty-list assertion above would also hold for a recorder wired to
        # nothing. The tool lookup is replaced because the CDK CLI need not be
        # installed for the channel to be verifiable, and subprocess.run is still
        # the recorder, so no project code runs here either.
        tool = ToolInfo(
            name=cdk.CDK, path=str(_fake_cdk_binary(workspace.parent)), version=_STUB_VERSION
        )
        with _recorded_process_starts() as control:
            with _replaced(cdk, "require_known_tool", lambda name: tool):
                with contextlib.redirect_stderr(io.StringIO()):
                    cdk.synth_if_confirmed(workspace, True)
        assert len(_cdk_invocations(control)) == 1
        assert control[0][1:] == [cdk.SYNTH_SUBCOMMAND]


# ---------------------------------------------------------------------------
# Measurement: what the two properties actually reached
# ---------------------------------------------------------------------------


def test_the_two_properties_reached_every_generated_case() -> None:
    """Non-vacuity measurement for the two tests above, not a property.

    A property over "any subset of Sources" and "any failure class" is only worth
    what its generation reached, and the same holds for "any input directory
    layout". Both tests record what they saw; this reads the records and requires
    every Source to have failed at least once, every failure class to have been
    injected at least once, an example in which nothing failed and one in which
    everything did, and all four CDK layout combinations.

    Skipped rather than failed when the records are empty, which happens when the
    property tests were deselected (``-k`` on this name alone). Their own
    assertions are what make each *example* non-vacuous; this is about coverage
    across examples.
    """
    if not _OBSERVED_FAILURES or not _OBSERVED_LAYOUTS:
        pytest.skip("the property tests above did not run in this selection")

    # The Source-to-resource table stays a bijection: two Sources sharing a
    # resource would merge their Findings and Property 24's second clause would
    # be comparing a set it cannot distinguish.
    assert len(_SOURCE_RESOURCES) == len(SOURCES)
    assert len(set(_RESOURCE_FOR_SOURCE.values())) == len(SOURCES)

    failed_sources = {name for name, _ in _OBSERVED_FAILURES}
    injected_classes = {failure for _, failure in _OBSERVED_FAILURES}
    assert failed_sources == set(SOURCES)
    # Every class ``strategies.failure_classes()`` draws is one this module knows
    # how to inject; a fifth would have raised a KeyError in the test above.
    assert injected_classes == set(_EXCEPTION_FOR_CLASS) | {_UNEXPECTED_CLASS}
    assert {0, len(_DETERMINISTIC_SOURCES), len(SOURCES)} <= _OBSERVED_SUBSET_SIZES

    assert _OBSERVED_LAYOUTS == {
        (False, False),
        (False, True),
        (True, False),
        (True, True),
    }
    assert _OBSERVED_NOISE == set(_NOISE_ENTRIES)
