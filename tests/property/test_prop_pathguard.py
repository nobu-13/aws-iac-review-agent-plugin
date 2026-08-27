"""Properties 18 and 19: path containment, and the absence of a shell.

These two properties are the plugin's whole answer to hostile input reaching a
path or an argument vector, so what they add over the example tests matters more
here than elsewhere.

What the example tests already own, and this module does not repeat
--------------------------------------------------------------------

``tests/unit/test_pathguard.py``
    The eight cases design.md names one at a time: an accepted relative and
    absolute path, ``../`` escape, ``a/../../b`` escape, *one* symlink pointing
    outside, the ``/workspace-evil`` versus ``/workspace`` prefix trap, a
    filename holding a metacharacter, and a missing path. Plus the plugin-root
    variants of the same reasoning.

``tests/unit/test_proc.py``
    The wrapper's behaviour at its own boundary: argv validation, the
    environment allowlist (no credential variable reaches a child), closed
    stdin, and the reporting rules of Requirement 16 AC11.

``tests/regression/test_sec_symlink_loop.py``
    The counterexample this file's Property 18 test found, pinned as two plain
    examples (steering/testing.md, Requirement 12 AC11).

What this module owns
---------------------

**Property 18** quantifies over candidate strings *and* over roots, and the
candidate space includes ten symlink shapes that a single example cannot cover.
``strategies.paths_escaping_root`` deliberately generates no symlinked candidate
-- a link has to exist on disk -- so :func:`_build_workspace` builds them here:
a file link out of the root, the same with a *relative* link target, a directory
link out, a directory link that stays in, a two-hop chain out, a two-hop chain
that stays in, a link **outside** the root pointing back **in**, a dangling link
inside, a dangling link pointing out, and a symlink loop. Every example checks
all ten plus one drawn from ``strategies.paths()``, so no shape depends on
Hypothesis happening to sample it.

Three of those shapes are traps that a plausible implementation gets wrong in
opposite directions. The link **outside** pointing **in** must be *accepted*:
its resolved form is a file inside the root, so a check on the candidate string
would reject a legitimate path. The dangling link pointing **out** must be
*rejected* even though the target does not exist, so containment has to be
decided before existence. And the loop shape is the case where the standard
library raises something neither the caller nor the module documented -- which is
what it did, until the diagnosis in ``tests/regression/test_sec_symlink_loop.py``.

Roots are drawn in two spellings, the directory itself and a symlink to it. That
is not decoration: pytest's temporary directory lives under ``/var`` on macOS,
which is a symlink to ``/private/var``, so a root and a target given in
different spellings are the normal case rather than the exotic one -- the reason
every ``workspace_root()`` in this repository resolves. A root that does not
exist is ``tests/unit/test_pathguard.py``'s case; a root that is itself a
symlink loop is the regression test's.

**Property 19** has three clauses and the third needs care.

The first two are one equivalence -- raises *if and only if* the value intersects
the metacharacter set -- asserted as a single ``is`` comparison so neither
direction can be satisfied alone. The set comes from
:data:`iacreview.pathguard.SHELL_METACHARACTERS` via
``strategies.strings_with_shell_metacharacters``, so adding a character to the
module widens both the generator and the oracle at once and no literal ``";"``
appears in this file.

The third clause is universally quantified over *every external tool invocation
the plugin constructs*, and no single runtime observation can establish a
statement of that shape. It is established in two halves that together cover the
quantifier:

*statically*, :func:`_process_spawning_violations` parses every shipped
    ``.py`` file with :mod:`ast` and reports any ``shell=`` keyword whose value
    is not the literal ``False``, any import of :mod:`subprocess` or :mod:`pty`
    outside :mod:`iacreview.proc`, and any ``os.system`` / ``os.popen`` /
    ``os.exec*`` / ``os.spawn*`` call anywhere; :func:`_shipped_shell_scripts`
    closes the remaining gap, since a shell wrapper could build a command by
    concatenation with no Python syntax tree to show it. An empty result from
    both is what makes "every invocation goes through
    :func:`iacreview.proc.run`" a fact about the code rather than a claim in a
    docstring;

*dynamically*, the three real argv builders (:func:`iacreview.cfnlint.build_argv`,
    :func:`iacreview.cfnguard.build_argv`, :func:`iacreview.cdk.build_synth_argv`)
    are fed a path that came out of :func:`iacreview.pathguard.resolve_within`,
    handed to :func:`iacreview.proc.run`, and what :func:`subprocess.run`
    actually received is captured and compared token by token.

Asserting the clause by searching the source *text* for ``shell=True`` was the
obvious alternative and is strictly weaker: it cannot see a value passed through
a variable, it matches inside comments and docstrings -- of which this repository
has many that discuss ``shell=True`` precisely because it is forbidden -- and it
says nothing about what the call actually received. The AST half is immune to all
three, and the capture half observes the real call. Neither half alone is enough:
the capture sees one call site, and the AST cannot see what a list contains at run
time.

No child process is started. ``subprocess.run`` is replaced for the duration of
the capture, so ``argv[0]`` only has to *resolve*; :data:`sys.executable` is used
for that, which needs no ``PATH`` lookup and no external tool to be installed.
The replacement is done with a context manager rather than the ``monkeypatch``
fixture because a function-scoped fixture is set up once for the whole test, not
once per example, and Hypothesis rejects the combination outright.

Both tests carry ``deadline=None``. Each example creates directories, files and
symlinks, so per-example wall-clock time is a property of the filesystem rather
than of the code under test, and the default 200 ms deadline would turn a loaded
disk into a test failure.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Dict, FrozenSet, Iterator, List, Tuple

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import strategies as S
from iacreview import cdk, cfnguard, cfnlint, pathguard, proc
from iacreview.errors import (
    ERROR_CLASSES,
    IacReviewError,
    PathContainmentError,
    UnsafeArgumentError,
)

#: Body of every file the layout creates. Content is irrelevant to both
#: properties; the file only has to exist, because containment is checked before
#: existence and the accept branch needs a target that is there.
TEMPLATE_BODY = "Resources:\n  A:\n    Type: AWS::S3::Bucket\n"

#: Directories a candidate from ``strategies.relative_paths()`` can name: up to
#: two segments drawn from ``("templates", "nested", ".")``, where ``"."``
#: collapses. Pre-created so that a drawn contained candidate reaches the accept
#: branch instead of stopping at "the file is not there".
_PLAIN_DIRECTORIES: Tuple[str, ...] = (
    "",
    "templates",
    "nested",
    "templates/templates",
    "templates/nested",
    "nested/templates",
    "nested/nested",
)

#: File names ``strategies.relative_paths()`` ends its paths with.
_PLAIN_FILES: Tuple[str, ...] = ("app.yaml", "stack.json")

# Verdicts of the independent oracle, in the precedence
# :func:`iacreview.pathguard.resolve_within` documents.
UNSAFE = "unsafe"
INVALID = "invalid"
OUTSIDE = "outside"
MISSING = "missing"
INSIDE = "inside"


# ---------------------------------------------------------------------------
# Property 18: the filesystem layout and the oracle
# ---------------------------------------------------------------------------


def _build_workspace(base: Path) -> Tuple[Path, Dict[str, str]]:
    """Create a workspace, an outside directory, and every symlink shape.

    Args:
        base: An empty directory to build in.

    Returns:
        ``(root, candidates)`` where ``root`` is the workspace directory and
        ``candidates`` maps a shape name to the candidate string that exercises
        it. The shape name is only used to label an assertion failure.

    Note:
        ``base / "workspace-evil"`` is created unconditionally: a sibling whose
        name has the root's name as a string prefix is the case a ``startswith``
        containment check accepts and a component comparison rejects, and it has
        to exist for the absolute candidate naming it to be more than a missing
        path.
    """
    root = base / "workspace"
    for directory in _PLAIN_DIRECTORIES:
        target_dir = root / directory if directory else root
        target_dir.mkdir(parents=True, exist_ok=True)
        for file_name in _PLAIN_FILES:
            (target_dir / file_name).write_text(TEMPLATE_BODY, encoding="utf-8")

    outside = base / "outside"
    outside.mkdir()
    secret = outside / "secret.yaml"
    secret.write_text(TEMPLATE_BODY, encoding="utf-8")

    evil = base / "workspace-evil"
    evil.mkdir()
    (evil / "evil.yaml").write_text(TEMPLATE_BODY, encoding="utf-8")

    candidates: Dict[str, str] = {}

    # (1) A file link inside the root whose target is outside it. The candidate
    # string holds no "..", so only resolution reveals the escape.
    (root / "templates" / "link_out.yaml").symlink_to(secret)
    candidates["file_link_out"] = "templates/link_out.yaml"

    # (2) The same escape written as a *relative* link target, which is stored in
    # the link itself and never appears in the candidate string.
    os.symlink("../../outside/secret.yaml", str(root / "templates" / "rel_out.yaml"))
    candidates["file_link_out_relative_target"] = "templates/rel_out.yaml"

    # (3) A directory link out of the root: the candidate traverses the link
    # rather than naming it, so containment cannot be decided on the last
    # component alone.
    (root / "via_dir").symlink_to(outside, target_is_directory=True)
    candidates["dir_link_out"] = "via_dir/secret.yaml"

    # (4) A directory link that stays inside the root. Must be accepted: a check
    # that refused every traversal of a link would reject this.
    (root / "alias").symlink_to(root / "templates", target_is_directory=True)
    candidates["dir_link_in"] = "alias/app.yaml"

    # (5) A two-hop chain out of the root. Resolving one level would stop at
    # hop_out_2, which is inside the root, and wrongly accept it.
    (root / "hop_out_2.yaml").symlink_to(secret)
    (root / "hop_out_1.yaml").symlink_to(root / "hop_out_2.yaml")
    candidates["link_chain_out"] = "hop_out_1.yaml"

    # (6) A two-hop chain that stays inside.
    (root / "hop_in_2.yaml").symlink_to(root / "templates" / "app.yaml")
    (root / "hop_in_1.yaml").symlink_to(root / "hop_in_2.yaml")
    candidates["link_chain_in"] = "hop_in_1.yaml"

    # (7) A link *outside* the root pointing back *in*. The candidate is an
    # absolute path outside the root, and its resolved form is a file inside it,
    # so the property requires acceptance.
    (outside / "into.yaml").symlink_to(root / "templates" / "app.yaml")
    candidates["outside_link_pointing_in"] = str(outside / "into.yaml")

    # (8) A dangling link inside the root: contained, but nothing to read.
    (root / "dangling_in.yaml").symlink_to(root / "absent.yaml")
    candidates["dangling_link_in"] = "dangling_in.yaml"

    # (9) A dangling link pointing out. Rejected as a containment violation
    # rather than as a missing file, which is why resolve_within checks
    # containment first.
    (root / "dangling_out.yaml").symlink_to(outside / "absent.yaml")
    candidates["dangling_link_out"] = "dangling_out.yaml"

    # (10) A symlink loop. Nothing here resolves; the requirement is only that
    # the failure is a documented one. See
    # tests/regression/test_sec_symlink_loop.py.
    (root / "loop_a").symlink_to(root / "loop_b")
    (root / "loop_b").symlink_to(root / "loop_a")
    candidates["symlink_loop"] = "loop_a"

    # The prefix trap, as an absolute candidate.
    candidates["name_prefix_sibling"] = str(evil / "evil.yaml")

    return root, candidates


def _real(path: Path) -> str:
    """``path`` with every symlink expanded, as a string.

    :func:`os.path.realpath` rather than :meth:`pathlib.Path.resolve`: the latter
    is what :mod:`iacreview.pathguard` calls, and an oracle sharing the
    implementation's normalization would agree with it by construction.
    """
    return os.path.realpath(str(path))


def _is_inside(child: str, root: str) -> bool:
    """Whether ``child`` is ``root`` or below it, compared component by component.

    Both arguments must already be fully resolved. Comparing ``parts`` rather
    than string prefixes is what makes ``/workspace-evil`` not inside
    ``/workspace``; it is also the definition of "inside" the property uses, and
    it shares no code with :meth:`pathlib.Path.relative_to`, which the
    implementation uses.
    """
    child_parts = PurePosixPath(child).parts
    root_parts = PurePosixPath(root).parts
    return child_parts[: len(root_parts)] == root_parts


def _verdict(candidate: str, root: Path) -> str:
    """What ``resolve_within(candidate, root)`` is required to do.

    Derived from the filesystem with :mod:`os.path`, in the precedence
    :func:`iacreview.pathguard.resolve_within` documents: the metacharacter check
    runs before anything touches the filesystem, an unusable string before
    normalization, containment before existence.

    Returns:
        One of :data:`UNSAFE`, :data:`INVALID`, :data:`OUTSIDE`, :data:`MISSING`,
        :data:`INSIDE`. The last one is the only verdict that permits a return
        value.
    """
    if set(candidate) & pathguard.SHELL_METACHARACTERS:
        return UNSAFE
    if not candidate.strip() or "\0" in candidate:
        # A blank candidate would resolve to the root itself; a NUL byte cannot
        # reach a syscall at all.
        return INVALID
    root_real = _real(root)
    candidate_real = os.path.realpath(os.path.join(root_real, candidate))
    if not _is_inside(candidate_real, root_real):
        return OUTSIDE
    if not os.path.exists(candidate_real):
        return MISSING
    return INSIDE


def _assert_resolution_is_contained(candidate: str, root: Path, label: str) -> str:
    """Assert Property 18 for one candidate and return the oracle's verdict.

    An exception that is not an :class:`~iacreview.errors.IacReviewError` is left
    to propagate: the property allows a raise or a contained return, and an
    undeclared exception type is neither -- it is the shape of failure that
    reaches the caller as a traceback instead of as a documented exit code
    (Requirement 16 AC7, AC8).
    """
    verdict = _verdict(candidate, root)
    context = (label, candidate, str(root), verdict)

    try:
        resolved = pathguard.resolve_within(candidate, root)
    except UnsafeArgumentError:
        assert verdict == UNSAFE, context
        return verdict
    except PathContainmentError:
        assert verdict == OUTSIDE, context
        return verdict
    except IacReviewError as exc:
        # Contained, but unusable for another reason: empty, unnormalizable, or
        # absent. The property constrains only the containment decision, so the
        # class is not pinned here -- but it may not be a containment violation
        # when the resolved form is inside the root, and it must be one of the
        # plugin's own error classes.
        assert verdict in (INVALID, MISSING), context + (type(exc).__name__,)
        assert exc.error_class in ERROR_CLASSES, context
        return verdict

    assert verdict == INSIDE, context
    assert resolved.is_absolute(), context
    assert _is_inside(str(resolved), _real(root)), context
    # Returned already normalized, so the caller cannot reintroduce the escape by
    # resolving it a second time.
    assert str(resolved) == _real(resolved), context
    assert str(resolved) == os.path.realpath(
        os.path.join(_real(root), candidate)
    ), context
    return verdict


# Feature: aws-iac-review-agent-plugin, Property 18: *For any* candidate path string and *for any* root directory, path resolution either raises `PathContainmentError` or returns an absolute path whose filesystem-resolved form is inside the filesystem-resolved root, including when the candidate traverses a symbolic link.
@settings(max_examples=100, deadline=None)
@given(candidate=S.paths(), root_via_symlink=st.booleans())
def test_path_resolution_stays_inside_the_root(
    tmp_path_factory: pytest.TempPathFactory, candidate: str, root_via_symlink: bool
) -> None:
    """**Validates: Requirements 1.3, 9.5, 15.3**

    Each example checks the drawn candidate and all eleven fixed shapes against
    one freshly built workspace, under one of the two root spellings. Checking
    the fixed shapes every time rather than sampling them is what makes the
    symlink half of the property non-vacuous: the assertion at the end requires
    the example to have reached the accept branch, a containment violation, and a
    contained-but-unusable path, so a layout that stopped producing any of the
    three would fail here rather than pass quietly.

    ``tmp_path_factory`` rather than ``tmp_path``: a function-scoped fixture is
    created once per test, not once per example, and Hypothesis refuses that
    combination. ``mktemp`` gives each example its own directory, which matters
    because the shapes create symlinks by fixed name.
    """
    base = tmp_path_factory.mktemp("containment")
    root, candidates = _build_workspace(base)

    if root_via_symlink:
        spelling = base / "root-link"
        spelling.symlink_to(root, target_is_directory=True)
    else:
        spelling = root

    verdicts = {
        _assert_resolution_is_contained(value, spelling, label)
        for label, value in candidates.items()
    }
    verdicts.add(_assert_resolution_is_contained(candidate, spelling, "drawn"))

    assert {INSIDE, OUTSIDE, MISSING} <= verdicts


# ---------------------------------------------------------------------------
# Property 19: the metacharacter set, and the argv that reaches subprocess
# ---------------------------------------------------------------------------

#: Files whose ``.py`` contents make up the shipped plugin. ``tests/`` is
#: excluded on purpose: a test may start a process however it likes, and this
#: file does exactly that.
_SHIPPED_DIRECTORIES: Tuple[str, ...] = ("iacreview", "skills", "benchmark")

#: The one module allowed to import :mod:`subprocess`, relative to the plugin
#: root. Property 19's argv clause is a statement about every invocation, and it
#: is only checkable in one place if there is only one place.
_PROCESS_FUNNEL = "iacreview/proc.py"

#: Modules whose import means the importer can start a process.
_PROCESS_MODULES: FrozenSet[str] = frozenset({"subprocess", "pty"})

#: :mod:`os` members that start a process without :mod:`subprocess`, several of
#: which take a command *string* and hand it to a shell.
_OS_PROCESS_FUNCTIONS: FrozenSet[str] = frozenset(
    {
        "system",
        "popen",
        "execl",
        "execle",
        "execlp",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnv",
        "spawnve",
        "spawnvp",
        "posix_spawn",
        "posix_spawnp",
        "forkpty",
    }
)


def _shipped_sources() -> List[Tuple[str, ast.AST]]:
    """Every shipped ``.py`` file, parsed, with its plugin-relative path."""
    root = pathguard.plugin_root()
    parsed: List[Tuple[str, ast.AST]] = []
    for directory in _SHIPPED_DIRECTORIES:
        for path in sorted((root / directory).rglob("*.py")):
            relative = path.relative_to(root).as_posix()
            parsed.append(
                (relative, ast.parse(path.read_text(encoding="utf-8"), filename=relative))
            )
    return parsed


def _process_spawning_violations() -> List[str]:
    """Every way the shipped code could reach a shell or bypass the funnel.

    Reported rather than asserted here so the test owns the assertion and a
    failure names every offending site at once.

    Returns:
        Human-readable descriptions, empty when the code is clean. Three
        findings are looked for: a ``shell=`` keyword whose value is not the
        literal ``False``, an import of a process-starting module outside
        :data:`_PROCESS_FUNNEL`, and an ``os`` call from
        :data:`_OS_PROCESS_FUNCTIONS` anywhere.
    """
    violations: List[str] = []
    for relative, tree in _shipped_sources():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg != "shell":
                        continue
                    value = keyword.value
                    if not (
                        isinstance(value, ast.Constant) and value.value is False
                    ):
                        violations.append(
                            "{0}:{1}: shell= is not the literal False".format(
                                relative, node.lineno
                            )
                        )
                function = node.func
                if (
                    isinstance(function, ast.Attribute)
                    and isinstance(function.value, ast.Name)
                    and function.value.id == "os"
                    and function.attr in _OS_PROCESS_FUNCTIONS
                ):
                    violations.append(
                        "{0}:{1}: os.{2} starts a process outside {3}".format(
                            relative, node.lineno, function.attr, _PROCESS_FUNNEL
                        )
                    )
            if relative == _PROCESS_FUNNEL:
                continue
            if isinstance(node, ast.Import):
                names = {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                names = {(node.module or "").split(".")[0]}
            else:
                continue
            for name in names & _PROCESS_MODULES:
                violations.append(
                    "{0}:{1}: imports {2} outside {3}".format(
                        relative, node.lineno, name, _PROCESS_FUNNEL
                    )
                )
    return violations


def _shipped_shell_scripts() -> List[str]:
    """Shell scripts under the shipped directories, which should be none.

    The AST scan reads Python. A shell wrapper is the one place the plugin could
    build a command by concatenation with no Python syntax tree to show it, so
    the ``.py`` scan only closes Property 19's "for any invocation" quantifier
    while this list is empty. Requirement 16 AC2 permits a shell script as a
    plain invocation wrapper, so a future one is not a defect -- but it would need
    its own check, and this assertion is what would say so.
    """
    root = pathguard.plugin_root()
    found: List[str] = []
    for directory in _SHIPPED_DIRECTORIES:
        for pattern in ("*.sh", "*.bash", "*.zsh"):
            found.extend(
                path.relative_to(root).as_posix()
                for path in (root / directory).rglob(pattern)
            )
    return sorted(found)


def _funnel_passes_shell_false() -> bool:
    """Whether :data:`_PROCESS_FUNNEL` still calls ``subprocess.run(shell=False)``.

    :func:`_process_spawning_violations` returning nothing is only meaningful
    while the funnel exists: a refactor that deleted the single
    ``subprocess.run`` call would satisfy the violation check vacuously.
    """
    for relative, tree in _shipped_sources():
        if relative != _PROCESS_FUNNEL:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            if not (
                isinstance(function, ast.Attribute)
                and isinstance(function.value, ast.Name)
                and function.value.id == "subprocess"
                and function.attr == "run"
            ):
                continue
            for keyword in node.keywords:
                if (
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is False
                ):
                    return True
    return False


#: Computed once at import: parsing every shipped file on each of the 100
#: examples would make the test's runtime about the size of the repository. The
#: facts are static, so one evaluation is all they need.
_SPAWNING_VIOLATIONS: List[str] = _process_spawning_violations()
_FUNNEL_IS_INTACT: bool = _funnel_passes_shell_false()
_SHELL_SCRIPTS: List[str] = _shipped_shell_scripts()


@contextmanager
def _captured_subprocess_run() -> Iterator[List[Tuple[Tuple[Any, ...], Dict[str, Any]]]]:
    """Replace :func:`subprocess.run` with a recorder for the duration.

    :mod:`iacreview.proc` does ``import subprocess`` and calls
    ``subprocess.run``, so replacing the attribute on the module object is what
    that call resolves to. No child is started, which is the point: the property
    is about what the wrapper *passes*, and an external tool does not have to be
    installed for that to be observable.

    Yields:
        The list of ``(args, kwargs)`` the recorder was called with.
    """
    calls: List[Tuple[Tuple[Any, ...], Dict[str, Any]]] = []
    original = subprocess.run

    def recorder(*args: Any, **kwargs: Any) -> Any:
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(
            args=args[0] if args else kwargs.get("args"),
            returncode=0,
            stdout="",
            stderr="",
        )

    subprocess.run = recorder  # type: ignore[assignment]
    try:
        yield calls
    finally:
        subprocess.run = original  # type: ignore[assignment]


def _plugin_argvs(
    template_path: Path, rules_dir: Path, executable: str
) -> List[Tuple[str, List[str]]]:
    """Every argv the plugin builds for an external tool, from its real builders.

    The builders are called rather than imitated: an argv written out here would
    only prove that a list literal in this file is a list. ``executable`` is
    substituted for the bare tool name so the invocation resolves without
    cfn-lint, cfn-guard or the CDK CLI being installed -- the same parameter
    :func:`iacreview.cfnlint.run_and_normalize` uses to pass the version-checked
    absolute path.

    ``cdk synth`` takes no user-supplied token at all, which is itself part of
    the claim, so it is included and its argv is expected to hold no path.
    """
    return [
        ("cfn-lint", cfnlint.build_argv(template_path, executable=executable)),
        (
            "cfn-guard",
            cfnguard.build_argv(template_path, [rules_dir], executable=executable),
        ),
        ("cdk", cdk.build_synth_argv(executable=executable)),
    ]


# Feature: aws-iac-review-agent-plugin, Property 19: *For any* string containing at least one character from the set `;`, `|`, `&`, `$`, backtick, `>`, `<`, the argument validator raises `UnsafeArgumentError`; and *for any* string containing none of those characters, it does not raise. Additionally, *for any* external tool invocation constructed by the plugin, the subprocess is spawned with `shell=False` and the argument vector is a list whose elements are never concatenated from user input.
@settings(max_examples=100, deadline=None)
@given(
    value=st.one_of(
        S.strings_with_shell_metacharacters(),
        S.strings_without_shell_metacharacters(),
        S.paths(),
        st.text(max_size=12),
    ),
    name=S.relative_paths(),
)
def test_shell_metacharacters_are_rejected_and_argv_reaches_the_child_as_a_list(
    tmp_path_factory: pytest.TempPathFactory, value: str, name: str
) -> None:
    """**Validates: Requirements 9.4, 16.6**

    The first assertion is the equivalence, in both directions at once: a value
    that intersects the set must be refused and a value that does not must be
    accepted, so neither a validator that rejects everything nor one that rejects
    nothing survives. ``value`` is drawn from four generators -- guaranteed
    unsafe, guaranteed safe, the full path space, and arbitrary text -- so both
    sides of the equivalence are reached in every run.

    The remaining assertions follow one user-supplied path through the whole
    chain the plugin actually uses: ``resolve_within`` on a relative candidate,
    then each real argv builder, then :func:`iacreview.proc.run`, then the
    ``subprocess.run`` call itself. What is checked there is that the token the
    user supplied arrives as *one whole element* of a list. That is the precise
    negation of "concatenated from user input": if any builder joined the path to
    a neighbouring flag, or interpolated it into a command string, the captured
    vector would differ from the built one element by element, or would hold an
    element that merely contains the path.
    """
    intersects = bool(set(value) & pathguard.SHELL_METACHARACTERS)
    try:
        pathguard.assert_no_shell_metacharacters(value)
        raised = False
    except UnsafeArgumentError:
        raised = True
    assert raised is intersects, value

    # Every invocation goes through one wrapper, and no shipped file can reach a
    # shell another way. Static, so evaluated once at import; asserted here
    # because it is one clause of this property and not a property of its own.
    assert _SPAWNING_VIOLATIONS == []
    assert _FUNNEL_IS_INTACT
    assert _SHELL_SCRIPTS == []

    root = tmp_path_factory.mktemp("argv")
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(TEMPLATE_BODY, encoding="utf-8")
    rules_dir = root / "rules"
    rules_dir.mkdir()

    # The path as a Source obtains it: user-supplied, containment-checked,
    # absolute.
    resolved = pathguard.resolve_within(name, root)
    user_token = str(resolved)

    for tool, argv in _plugin_argvs(resolved, rules_dir, executable=sys.executable):
        with _captured_subprocess_run() as calls:
            result = proc.run(argv, timeout_s=30)

        assert result.exit_code == 0
        assert len(calls) == 1, tool
        args, kwargs = calls[0]

        passed = args[0] if args else kwargs["args"]
        assert isinstance(passed, list), (tool, type(passed).__name__)
        assert all(isinstance(token, str) for token in passed), tool
        # Absent would also satisfy the property, since False is the default;
        # the wrapper states it explicitly, so the explicit value is asserted.
        assert kwargs.get("shell", False) is False, tool

        # argv[0] is replaced by the resolved absolute path of the same
        # executable, and nothing else is touched.
        assert os.path.isabs(passed[0]), tool
        assert os.path.basename(passed[0]) == os.path.basename(argv[0]), tool
        assert passed[1:] == list(argv[1:]), tool

        occurrences = [token for token in passed if user_token in token]
        if tool == "cdk":
            # No user-supplied value in this command at all.
            assert occurrences == [], tool
        else:
            # Present, exactly once, and as the whole element rather than as a
            # substring of a longer one.
            assert occurrences == [user_token], (tool, occurrences)
